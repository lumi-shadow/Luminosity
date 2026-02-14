use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal, Read};
use std::str::FromStr;

use sha3::{Digest, Keccak256};
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcTransactionConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::{commitment_config::CommitmentConfig, hash::hash as solana_sha256};
use solana_transaction_status::{EncodedConfirmedTransactionWithStatusMeta, UiTransactionEncoding};
use spl_concurrent_merkle_tree::concurrent_merkle_tree::ConcurrentMerkleTree;

// This binary is intentionally "low ceremony":
// - It reads the relayer `/logs` JSON from stdin
// - Reconstructs the same Keccak-based Merkle tree the relayer cache uses
// - Prints the root + sibling path for a given leaf index
//
// Usage:
//   curl -s http://<RELAYER_HOST>:<PORT>/logs | cargo run --bin merkle_debug -- <LEAF_INDEX>
//
// Optional on-chain verification:
//   curl -s http://<RELAYER_HOST>:<PORT>/logs | cargo run --bin merkle_debug -- <LEAF_INDEX> <RPC_URL> <MERKLE_TREE_PUBKEY>
//
// Full local mode (NO relayer needed):
//   cargo run --bin merkle_debug -- <LEAF_INDEX> <RPC_URL> <PROGRAM_ID> [MAX_SIGS]
const MERKLE_TREE_DEPTH: usize = 24;
const SPL_TREE_DATA_OFFSET: usize = 56;
const SPL_TREE_MAX_DEPTH: usize = 24;
const SPL_TREE_MAX_BUFFER_SIZE: usize = 1024;

fn decode_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str.trim()).expect("invalid hex");
    bytes.try_into().expect("expected 32 bytes")
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

struct CacheTree {
    leaves: HashMap<u32, [u8; 32]>,
    occupied: Vec<HashSet<u32>>,
    zero_hashes: Vec<[u8; 32]>,
}

impl CacheTree {
    fn new(depth: usize) -> Self {
        let mut zero_hashes = Vec::with_capacity(depth + 1);
        zero_hashes.push([0u8; 32]); // empty leaf
        for lvl in 0..depth {
            let z = zero_hashes[lvl];
            zero_hashes.push(keccak256(&[z.as_ref(), z.as_ref()].concat()));
        }
        let mut occupied = Vec::with_capacity(depth + 1);
        for _ in 0..=depth {
            occupied.push(HashSet::new());
        }
        Self {
            leaves: HashMap::new(),
            occupied,
            zero_hashes,
        }
    }

    fn ingest_leaf(&mut self, leaf_index_0: u32, commitment: [u8; 32], depth: usize) {
        if commitment == [0u8; 32] {
            return;
        }
        self.leaves.insert(leaf_index_0, commitment);
        for lvl in 0..=depth {
            self.occupied[lvl].insert(leaf_index_0 >> lvl);
        }
    }

    fn node_hash(
        &self,
        level: usize,
        index: u32,
        memo: &mut HashMap<(usize, u32), [u8; 32]>,
    ) -> [u8; 32] {
        if let Some(v) = memo.get(&(level, index)) {
            return *v;
        }
        if !self.occupied[level].contains(&index) {
            return self.zero_hashes[level];
        }
        let v = if level == 0 {
            *self.leaves.get(&index).unwrap_or(&self.zero_hashes[0])
        } else {
            let left = self.node_hash(level - 1, index * 2, memo);
            let right = self.node_hash(level - 1, index * 2 + 1, memo);
            keccak256(&[left.as_ref(), right.as_ref()].concat())
        };
        memo.insert((level, index), v);
        v
    }

    fn merkle_path_and_root(&self, leaf_index_0: u32, depth: usize) -> (Vec<[u8; 32]>, [u8; 32]) {
        let mut memo: HashMap<(usize, u32), [u8; 32]> = HashMap::new();
        let mut path = Vec::with_capacity(depth);
        let mut idx = leaf_index_0;
        let mut cur = self.node_hash(0, idx, &mut memo);

        for lvl in 0..depth {
            let sibling_idx = idx ^ 1;
            let sibling_hash = self.node_hash(lvl, sibling_idx, &mut memo);
            path.push(sibling_hash);

            let parent = if (idx & 1) == 1 {
                keccak256(&[sibling_hash.as_ref(), cur.as_ref()].concat())
            } else {
                keccak256(&[cur.as_ref(), sibling_hash.as_ref()].concat())
            };
            cur = parent;
            idx >>= 1;
        }

        (path, cur)
    }
}

/// Anchor instruction discriminator = first 8 bytes of sha256("global:<name>")
fn anchor_discriminator(name: &str) -> [u8; 8] {
    let preimage = format!("global:{}", name);
    let h = solana_sha256(preimage.as_bytes()).to_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

/// Try to parse an Anchor `deposit` instruction and extract the commitment.
/// Layout: [8-byte discriminator][commitment: [u8;32]][amount: u64][encrypted_note: Vec<u8>]...
fn parse_deposit_ix_commitment(ix_data: &[u8], deposit_disc: &[u8; 8]) -> Option<[u8; 32]> {
    if ix_data.len() < 8 + 32 {
        return None;
    }
    if &ix_data[0..8] != deposit_disc {
        return None;
    }
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&ix_data[8..40]);
    Some(commitment)
}

/// Extract all `deposit` instruction commitments from a decoded transaction for our program.
fn extract_deposit_commitments_from_tx(
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    program_id: &Pubkey,
    deposit_disc: &[u8; 8],
) -> Vec<[u8; 32]> {
    let Some(vtx) = tx.transaction.transaction.decode() else {
        return vec![];
    };
    let mut out = Vec::new();
    match &vtx.message {
        solana_sdk::message::VersionedMessage::Legacy(m) => {
            for ix in &m.instructions {
                let pid = m.account_keys.get(ix.program_id_index as usize);
                if pid != Some(program_id) {
                    continue;
                }
                if let Some(c) = parse_deposit_ix_commitment(&ix.data, deposit_disc) {
                    out.push(c);
                }
            }
        }
        solana_sdk::message::VersionedMessage::V0(m) => {
            for ix in &m.instructions {
                let pid = m.account_keys.get(ix.program_id_index as usize);
                if pid != Some(program_id) {
                    continue;
                }
                if let Some(c) = parse_deposit_ix_commitment(&ix.data, deposit_disc) {
                    out.push(c);
                }
            }
        }
    }
    out
}

/// Fetch the current Merkle tree Pubkey from the pool state PDA.
/// (Same layout assumption as relayer: merkle_tree Pubkey is at bytes [8..40].)
fn current_merkle_tree_pubkey(rpc: &RpcClient, program_id: &Pubkey) -> Pubkey {
    let (pool_state_pda, _) = Pubkey::find_program_address(&[b"pool"], program_id);
    let pool_account = rpc
        .get_account(&pool_state_pda)
        .expect("failed to fetch pool_state PDA");
    assert!(pool_account.data.len() >= 40, "pool_state data too short");
    Pubkey::new_from_array(pool_account.data[8..40].try_into().unwrap())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 && args.len() != 4 && args.len() != 5 {
        eprintln!(
            "Usage:\n  (stdin)  curl -s http://<RELAYER>/logs | {0} <LEAF_INDEX> [RPC_URL MERKLE_TREE_PUBKEY]\n  (rpc)    {0} <LEAF_INDEX> <RPC_URL> <PROGRAM_ID> [MAX_SIGS]\n",
            args.get(0).unwrap_or(&"merkle_debug".into())
        );
        std::process::exit(2);
    }
    let leaf_index: u32 = args[1].parse().expect("invalid leaf_index");

    // Read JSON from stdin ONLY when it's actually piped (not an interactive terminal),
    // otherwise we'd block forever waiting for EOF.
    let mut input = String::new();
    let mut stdin = std::io::stdin();
    let stdin_is_terminal = stdin.is_terminal();
    if !stdin_is_terminal {
        stdin
            .read_to_string(&mut input)
            .expect("failed to read stdin");
    }

    // Source of commitments:
    // - If stdin has JSON: use cached_commitments[] from /logs
    // - Else: build from RPC by parsing deposit instructions sequentially
    let (tree, min_idx, max_idx, rpc_for_check, tree_for_check) = if !input.trim().is_empty() {
        let v: serde_json::Value =
            serde_json::from_str(&input).expect("failed to parse JSON from stdin");
        let commitments = v
            .get("cached_commitments")
            .and_then(|x| x.as_array())
            .ok_or("missing cached_commitments[]")
            .unwrap();

        let mut tree = CacheTree::new(MERKLE_TREE_DEPTH);
        let mut min_idx: Option<u32> = None;
        let mut max_idx: Option<u32> = None;

        for item in commitments {
            let idx = item
                .get("leaf_index")
                .and_then(|x| x.as_u64())
                .expect("cached_commitments[].leaf_index missing") as u32;
            let hex = item
                .get("commitment_hex")
                .and_then(|x| x.as_str())
                .expect("cached_commitments[].commitment_hex missing");
            let comm = decode_32(hex);
            tree.ingest_leaf(idx, comm, MERKLE_TREE_DEPTH);
            min_idx = Some(min_idx.map(|m| m.min(idx)).unwrap_or(idx));
            max_idx = Some(max_idx.map(|m| m.max(idx)).unwrap_or(idx));
        }

        // Optional on-chain check args in stdin mode: (LEAF_INDEX, RPC_URL, MERKLE_TREE_PUBKEY)
        let rpc_url = args.get(2).cloned();
        let tree_pk = args.get(3).cloned();
        (tree, min_idx, max_idx, rpc_url, tree_pk)
    } else {
        // RPC mode: (LEAF_INDEX, RPC_URL, PROGRAM_ID, [MAX_SIGS])
        if args.len() < 4 {
            if stdin_is_terminal {
                eprintln!("stdin is a terminal (no JSON provided) and RPC args not provided");
            } else {
                eprintln!("stdin was empty and RPC args not provided");
            }
            std::process::exit(2);
        }
        let rpc_url = args[2].clone();
        let program_id = Pubkey::from_str(&args[3]).expect("invalid PROGRAM_ID");
        let max_sigs: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(5_000);

        eprintln!(
            "[merkle_debug] mode=rpc leaf_index={} max_sigs={}",
            leaf_index, max_sigs
        );
        eprintln!("[merkle_debug] rpc_url={}", rpc_url);
        eprintln!("[merkle_debug] program_id={}", program_id);

        let rpc = RpcClient::new(rpc_url.clone());
        let merkle_tree = current_merkle_tree_pubkey(&rpc, &program_id);
        eprintln!("[merkle_debug] current_merkle_tree={}", merkle_tree);

        let deposit_disc = anchor_discriminator("deposit");
        let mut sig_infos = Vec::new();
        let mut before: Option<solana_sdk::signature::Signature> = None;
        let mut page = 0usize;
        while sig_infos.len() < max_sigs {
            page += 1;
            let remaining = max_sigs - sig_infos.len();
            let limit = remaining.min(1_000);
            let cfg = GetConfirmedSignaturesForAddress2Config {
                limit: Some(limit),
                before,
                until: None,
                commitment: Some(CommitmentConfig::confirmed()),
            };
            eprintln!(
                "[merkle_debug] fetching signatures page={} have={} limit={} before={}",
                page,
                sig_infos.len(),
                limit,
                before
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "None".into())
            );
            let batch = rpc
                .get_signatures_for_address_with_config(&merkle_tree, cfg)
                .expect("get_signatures_for_address failed");
            if batch.is_empty() {
                eprintln!("[merkle_debug] signatures page={} empty -> done", page);
                break;
            }
            before =
                solana_sdk::signature::Signature::from_str(&batch[batch.len() - 1].signature).ok();
            sig_infos.extend(batch);
            if before.is_none() {
                eprintln!("[merkle_debug] before=None -> done");
                break;
            }
        }
        eprintln!(
            "[merkle_debug] fetched signatures total={}",
            sig_infos.len()
        );

        let mut deposits_in_order: Vec<[u8; 32]> = Vec::new();
        let mut fetched_txs = 0usize;
        let mut tx_errors = 0usize;
        for (i, sig_info) in sig_infos.into_iter().rev().enumerate() {
            if i % 250 == 0 {
                eprintln!(
                    "[merkle_debug] tx_scan progress i={} fetched_txs={} deposits_found={} tx_errors={}",
                    i, fetched_txs, deposits_in_order.len(), tx_errors
                );
            }
            let signature = solana_sdk::signature::Signature::from_str(&sig_info.signature)
                .expect("bad signature");
            let cfg = RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Base64),
                max_supported_transaction_version: Some(0),
                commitment: Some(CommitmentConfig::confirmed()),
            };
            let tx = match rpc.get_transaction_with_config(&signature, cfg) {
                Ok(t) => {
                    fetched_txs += 1;
                    t
                }
                Err(_) => {
                    tx_errors += 1;
                    continue;
                }
            };
            let cs = extract_deposit_commitments_from_tx(&tx, &program_id, &deposit_disc);
            for c in cs {
                deposits_in_order.push(c);
            }
        }
        eprintln!(
            "[merkle_debug] tx_scan done fetched_txs={} tx_errors={} deposits_raw={}",
            fetched_txs,
            tx_errors,
            deposits_in_order.len()
        );
        deposits_in_order.dedup();
        eprintln!(
            "[merkle_debug] deposits deduped deposits={}",
            deposits_in_order.len()
        );

        let mut tree = CacheTree::new(MERKLE_TREE_DEPTH);
        for (i, comm) in deposits_in_order.into_iter().enumerate() {
            tree.ingest_leaf(i as u32, comm, MERKLE_TREE_DEPTH);
        }
        eprintln!(
            "[merkle_debug] built cache_tree leaves={}",
            tree.leaves.len()
        );
        let min_idx = if tree.leaves.is_empty() {
            None
        } else {
            Some(0)
        };
        let max_idx = tree.leaves.keys().copied().max();
        (
            tree,
            min_idx,
            max_idx,
            Some(rpc_url),
            Some(merkle_tree.to_string()),
        )
    };

    println!("cached_leaves: {}", tree.leaves.len());
    println!(
        "leaf_index_range: {:?}..={:?}",
        min_idx.unwrap_or(0),
        max_idx.unwrap_or(0)
    );
    if !tree.leaves.contains_key(&leaf_index) {
        eprintln!(
            "leaf_index {} is not present in cached_commitments[]",
            leaf_index
        );
        std::process::exit(2);
    }

    let leaf = tree.leaves.get(&leaf_index).copied().unwrap();
    let (path, root) = tree.merkle_path_and_root(leaf_index, MERKLE_TREE_DEPTH);

    println!("leaf_index: {}", leaf_index);
    println!("leaf(commitment): {}", hex::encode(leaf));
    println!("root_hex: {}", hex::encode(root));
    println!("path_len: {}", path.len());
    println!("path0: {}", hex::encode(path[0]));
    println!("path1: {}", hex::encode(path[1]));
    println!("path2: {}", hex::encode(path[2]));
    println!("path3: {}", hex::encode(path[3]));

    // Optional on-chain check: is this root currently valid (in the CMT root buffer)?
    if let (Some(rpc_url), Some(tree_pubkey)) = (rpc_for_check, tree_for_check) {
        let rpc = RpcClient::new(rpc_url.to_string());
        let tree_pk = Pubkey::from_str(&tree_pubkey).expect("invalid MERKLE_TREE_PUBKEY");
        let acc = rpc
            .get_account(&tree_pk)
            .expect("failed to fetch tree account");
        let data = acc.data;

        let struct_size = std::mem::size_of::<
            ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
        >();
        let start = SPL_TREE_DATA_OFFSET;
        let end = start + struct_size;
        assert!(
            data.len() >= end,
            "tree account too small: len={} need_end={}",
            data.len(),
            end
        );
        let slice = &data[start..end];
        let tree = bytemuck::try_from_bytes::<
            ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
        >(slice)
        .expect("failed to deserialize ConcurrentMerkleTree");

        let active_index = tree.active_index as usize;
        let current_root = tree.change_logs[active_index].root;
        let in_root_buffer = tree.change_logs.iter().any(|cl| cl.root == root);

        println!();
        println!("--- on-chain check ---");
        println!("merkle_tree: {}", tree_pk);
        println!("tree.active_index: {}", tree.active_index);
        println!("tree.buffer_size: {}", tree.buffer_size);
        println!("tree.current_root: {}", hex::encode(current_root));
        println!("cache_root == current_root? {}", root == current_root);
        println!("cache_root in change_logs buffer? {}", in_root_buffer);
    }
}
