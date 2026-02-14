use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use groth16_solana::groth16::Groth16Verifier;
use num_bigint::BigUint;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcTransactionConfig;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::hash::hash as solana_sha256;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta;
use solana_transaction_status::UiTransactionEncoding;
use tempfile::Builder;

// Pull in the on-chain verifying key constant directly.
// This ensures the local verifier uses the exact VK that would be compiled into the program.
mod onchain_vk {
    include!("../../../programs/solana-privacy-pool/src/verifying_key.rs");
}

const MERKLE_TREE_DEPTH: usize = 24;
// const SPL_TREE_DATA_OFFSET: usize = 56;
// const SPL_TREE_MAX_DEPTH: usize = 24;
// const SPL_TREE_MAX_BUFFER_SIZE: usize = 1024;

// Circuit artifacts are stored at the repo root.
// (This binary is compiled from the `relayer/` crate; use repo-root-relative defaults.)
const DEFAULT_WASM: &str = "circuit-out/withdraw/circom/withdraw_js/withdraw.wasm";
const DEFAULT_WITNESS_JS: &str = "circuit-out/withdraw/circom/withdraw_js/generate_witness.js";
const DEFAULT_ZKEY: &str = "circuit-out/withdraw/withdraw_final.zkey";
const DEFAULT_SNARKJS_CLI: &str = "node_modules/snarkjs/build/cli.cjs";
const DEFAULT_VK_JSON: &str = "circuit-out/withdraw/verification_key.json";

#[derive(Debug)]
struct AppError(String);

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl StdError for AppError {}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError(e.to_string())
    }
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn anchor_discriminator(name: &str) -> [u8; 8] {
    let preimage = format!("global:{}", name);
    let h = solana_sha256(preimage.as_bytes()).to_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

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

fn current_merkle_tree_pubkey(rpc: &RpcClient, program_id: &Pubkey) -> Pubkey {
    let (pool_state_pda, _) = Pubkey::find_program_address(&[b"pool"], program_id);
    let pool_account = rpc
        .get_account(&pool_state_pda)
        .expect("failed to fetch pool_state PDA");
    assert!(pool_account.data.len() >= 40, "pool_state data too short");
    Pubkey::new_from_array(pool_account.data[8..40].try_into().unwrap())
}

fn u256_be32_from_dec_str(s: &str) -> Result<[u8; 32], AppError> {
    let n: BigUint = s
        .parse::<BigUint>()
        .map_err(|_| AppError("non-decimal coordinate".into()))?;
    let mut out = [0u8; 32];
    let b = n.to_bytes_be();
    if b.len() > 32 {
        return Err(AppError("coordinate exceeds 32 bytes".into()));
    }
    out[32 - b.len()..].copy_from_slice(&b);
    Ok(out)
}

fn bn254_fq_modulus() -> BigUint {
    BigUint::parse_bytes(
        // BN254 base field modulus (Fq). Note: this is NOT the scalar field (Fr) modulus.
        b"21888242871839275222246405745257275088696311157297823662689037894645226208583",
        10,
    )
    .unwrap()
}

fn u256_be32_from_biguint(n: &BigUint) -> Result<[u8; 32], AppError> {
    let mut out = [0u8; 32];
    let b = n.to_bytes_be();
    if b.len() > 32 {
        return Err(AppError("coordinate exceeds 32 bytes".into()));
    }
    out[32 - b.len()..].copy_from_slice(&b);
    Ok(out)
}

fn g1_negate_y_be(y_be32: &[u8; 32]) -> Result<[u8; 32], AppError> {
    let y = BigUint::from_bytes_be(y_be32);
    if y == BigUint::from(0u8) {
        return Ok([0u8; 32]);
    }
    let p = bn254_fq_modulus();
    let y_neg = (&p - (y % &p)) % &p;
    u256_be32_from_biguint(&y_neg)
}

fn split_u128_be16_be16(bytes32: &[u8; 32]) -> (String, String) {
    let hi = BigUint::from_bytes_be(&bytes32[0..16]).to_str_radix(10);
    let lo = BigUint::from_bytes_be(&bytes32[16..32]).to_str_radix(10);
    (hi, lo)
}

struct CacheTree {
    leaves: HashMap<u32, [u8; 32]>,
    occupied: Vec<HashSet<u32>>,
    zero_hashes: Vec<[u8; 32]>,
}

impl CacheTree {
    fn new(depth: usize) -> Self {
        let mut zero_hashes = Vec::with_capacity(depth + 1);
        zero_hashes.push([0u8; 32]);
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

#[derive(Debug, Deserialize)]
struct Groth16ProofJson {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VkJson {
    // We only need alpha to prove a mismatch
    vk_alpha_1: Vec<String>,
    // Also check IC vector
    #[serde(rename = "IC")]
    ic: Vec<Vec<String>>,
}

fn parse_json_file<T: for<'de> Deserialize<'de>>(path: &std::path::Path) -> Result<T, AppError> {
    let bytes = std::fs::read(path).map_err(|e| AppError(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| AppError(e.to_string()))
}

fn parse_note(note: &str) -> Result<(u64, String, String), AppError> {
    // Format: p1vacy-<amount_sol>-<nullifier_hex_64><secret_hex_64>
    // Example: p1vacy-1-<128 hex chars>
    let note = note.trim();
    let mut parts = note.splitn(3, '-');
    let prefix = parts
        .next()
        .ok_or_else(|| AppError("note missing prefix".into()))?;
    if prefix != "p1vacy" {
        return Err(AppError(format!("unexpected note prefix: {}", prefix)));
    }
    let amount_sol_str = parts
        .next()
        .ok_or_else(|| AppError("note missing amount".into()))?;
    let payload = parts
        .next()
        .ok_or_else(|| AppError("note missing payload".into()))?;

    let amount_sol: u64 = amount_sol_str
        .parse()
        .map_err(|_| AppError("note amount is not an integer".into()))?;
    let amount_lamports = amount_sol
        .checked_mul(1_000_000_000)
        .ok_or_else(|| AppError("amount overflow".into()))?;

    if payload.len() != 128 {
        return Err(AppError(format!(
            "note payload must be 128 hex chars (got {})",
            payload.len()
        )));
    }
    let nullifier_hex = payload[0..64].to_string();
    let secret_hex = payload[64..128].to_string();
    // Validate hex
    let _ =
        hex::decode(&nullifier_hex).map_err(|_| AppError("note nullifier is not hex".into()))?;
    let _ = hex::decode(&secret_hex).map_err(|_| AppError("note secret is not hex".into()))?;
    Ok((amount_lamports, nullifier_hex, secret_hex))
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Two modes:
    //
    // 1) Raw args:
    //   proof_local_check <RPC_URL> <PROGRAM_ID> <NULLIFIER_HEX32> <SECRET_HEX32> <AMOUNT_LAMPORTS_U64> <RECIPIENT_PUBKEY> <FEE_LAMPORTS_U64> [MAX_SIGS]
    //
    // 2) Note mode:
    //   proof_local_check --note <NOTE> --recipient <PUBKEY> [--fee <LAMPORTS>] [--rpc <RPC_URL>] [--program <PROGRAM_ID>] [--max-sigs <N>]
    let args: Vec<String> = std::env::args().collect();
    let (rpc_url, program_id, nullifier_hex, secret_hex, amount, recipient, fee, max_sigs) =
        if let Some(note) = arg_value(&args, "--note") {
            let recipient = arg_value(&args, "--recipient")
                .ok_or_else(|| AppError("missing --recipient".into()))?;
            let fee: u64 = arg_value(&args, "--fee")
                .as_deref()
                .unwrap_or("0")
                .parse()
                .map_err(|_| AppError("invalid --fee".into()))?;
            let rpc_url = arg_value(&args, "--rpc").unwrap_or_else(|| {
                "https://api.mainnet-beta.solana.com".into()
            });
            let program_id = arg_value(&args, "--program")
                .unwrap_or_else(|| "p1VaCyyfzodMni1tSYhvUFd3MyGB6sb6NRFWPixXD54".into());
            let max_sigs: usize = arg_value(&args, "--max-sigs")
                .as_deref()
                .unwrap_or("50000")
                .parse()
                .map_err(|_| AppError("invalid --max-sigs".into()))?;

            let (amount, nullifier_hex, secret_hex) = parse_note(&note)?;
            (
                rpc_url,
                program_id,
                nullifier_hex,
                secret_hex,
                amount,
                recipient,
                fee,
                max_sigs,
            )
        } else {
            if args.len() < 8 {
                eprintln!(
                    "Usage:\n  {} <RPC_URL> <PROGRAM_ID> <NULLIFIER_HEX32> <SECRET_HEX32> <AMOUNT_LAMPORTS_U64> <RECIPIENT_PUBKEY> <FEE_LAMPORTS_U64> [MAX_SIGS]\n  {} --note <NOTE> --recipient <PUBKEY> [--fee <LAMPORTS>] [--rpc <RPC_URL>] [--program <PROGRAM_ID>] [--max-sigs <N>]\n",
                    args.get(0).unwrap_or(&"proof_local_check".into()),
                    args.get(0).unwrap_or(&"proof_local_check".into()),
                );
                std::process::exit(2);
            }
            let rpc_url = args[1].clone();
            let program_id = args[2].clone();
            let nullifier_hex = args[3].clone();
            let secret_hex = args[4].clone();
            let amount: u64 = args[5].parse()?;
            let recipient = args[6].clone();
            let fee: u64 = args[7].parse()?;
            let max_sigs: usize = args.get(8).and_then(|s| s.parse().ok()).unwrap_or(50_000);
            (
                rpc_url,
                program_id,
                nullifier_hex,
                secret_hex,
                amount,
                recipient,
                fee,
                max_sigs,
            )
        };

    let rpc_url = rpc_url;
    let program_id = Pubkey::from_str(&program_id)
        .map_err(|e| AppError(format!("Invalid PROGRAM_ID pubkey '{}': {}", program_id, e)))?;
    let recipient = Pubkey::from_str(&recipient)
        .map_err(|e| AppError(format!("Invalid recipient pubkey '{}': {}", recipient, e)))?;

    println!("[check] rpc_url={}", rpc_url);
    println!("[check] program_id={}", program_id);

    let nullifier_bytes: [u8; 32] = hex::decode(&nullifier_hex)
        .map_err(|e| AppError(format!("Invalid nullifier hex: {}", e)))?
        .try_into()
        .map_err(|_| AppError("nullifier must be 32 bytes".into()))?;
    let secret_bytes: [u8; 32] = hex::decode(&secret_hex)
        .map_err(|e| AppError(format!("Invalid secret hex: {}", e)))?
        .try_into()
        .map_err(|_| AppError("secret must be 32 bytes".into()))?;

    let nullifier_hash = keccak256(&nullifier_bytes);
    // Two-layer: noteHash = keccak256(nullifier || secret), commitment = keccak256(noteHash || amountLE8 || assetIdLE4)
    let note_hash = keccak256(&[nullifier_bytes.as_ref(), secret_bytes.as_ref()].concat());
    let commitment = {
        let amount_le8 = amount.to_le_bytes();
        let asset_id_le4 = 0u32.to_le_bytes(); // default asset_id=0 for this check tool
        keccak256(&[note_hash.as_ref(), &amount_le8, &asset_id_le4].concat())
    };
    println!("[check] nullifier_hash={}", hex::encode(nullifier_hash));
    println!("[check] commitment={}", hex::encode(commitment));

    // Build sequential deposit list from tx history for the current tree, then compute path/root.
    let rpc = RpcClient::new(rpc_url.to_string());
    let merkle_tree = current_merkle_tree_pubkey(&rpc, &program_id);
    println!("[check] current_merkle_tree={}", merkle_tree);

    let deposit_disc = anchor_discriminator("deposit");
    let mut sig_infos = Vec::new();
    let mut before: Option<solana_sdk::signature::Signature> = None;
    while sig_infos.len() < max_sigs {
        let remaining = max_sigs - sig_infos.len();
        let limit = remaining.min(1_000);
        let cfg = GetConfirmedSignaturesForAddress2Config {
            limit: Some(limit),
            before,
            until: None,
            commitment: Some(CommitmentConfig::confirmed()),
        };
        let batch = rpc.get_signatures_for_address_with_config(&merkle_tree, cfg)?;
        if batch.is_empty() {
            break;
        }
        before = solana_sdk::signature::Signature::from_str(&batch[batch.len() - 1].signature).ok();
        sig_infos.extend(batch);
        if before.is_none() {
            break;
        }
    }
    println!(
        "[check] scanned signatures={} (max_sigs={})",
        sig_infos.len(),
        max_sigs
    );

    let mut deposits_in_order: Vec<[u8; 32]> = Vec::new();
    for sig_info in sig_infos.into_iter().rev() {
        let signature = solana_sdk::signature::Signature::from_str(&sig_info.signature)?;
        let cfg = RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Base64),
            max_supported_transaction_version: Some(0),
            commitment: Some(CommitmentConfig::confirmed()),
        };
        let tx = match rpc.get_transaction_with_config(&signature, cfg) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let cs = extract_deposit_commitments_from_tx(&tx, &program_id, &deposit_disc);
        for c in cs {
            deposits_in_order.push(c);
        }
    }
    deposits_in_order.dedup();
    println!("[check] deposits_found={}", deposits_in_order.len());

    let mut tree = CacheTree::new(MERKLE_TREE_DEPTH);
    let mut found_leaf: Option<u32> = None;
    for (i, c) in deposits_in_order.into_iter().enumerate() {
        let idx = i as u32;
        if c == commitment {
            found_leaf = Some(idx);
        }
        tree.ingest_leaf(idx, c, MERKLE_TREE_DEPTH);
    }
    let leaf_index =
        found_leaf.ok_or_else(|| AppError("commitment not found in scanned deposits".into()))?;
    println!("[check] leaf_index={}", leaf_index);

    let (path32, root_bytes) = tree.merkle_path_and_root(leaf_index, MERKLE_TREE_DEPTH);
    println!("[check] root_hex={}", hex::encode(root_bytes));

    // Build circuit input.json
    let (root_hi, root_lo) = split_u128_be16_be16(&root_bytes);
    let (nul_hi, nul_lo) = split_u128_be16_be16(&nullifier_hash);
    let (rec_hi, rec_lo) = split_u128_be16_be16(&recipient.to_bytes());

    let mut path_elements: Vec<Vec<u8>> = Vec::with_capacity(MERKLE_TREE_DEPTH);
    for s in &path32 {
        path_elements.push(s.to_vec());
    }
    let mut path_indices: Vec<u32> = Vec::with_capacity(MERKLE_TREE_DEPTH);
    for i in 0..MERKLE_TREE_DEPTH {
        path_indices.push(((leaf_index >> i) & 1) as u32);
    }

    let input_json = serde_json::json!({
        "rootHi": root_hi,
        "rootLo": root_lo,
        "nullifierHashHi": nul_hi,
        "nullifierHashLo": nul_lo,
        "recipientHi": rec_hi,
        "recipientLo": rec_lo,
        "relayerFee": fee.to_string(),
        "amountVal": amount.to_string(),
        "nullifier": nullifier_bytes.to_vec(),
        "secret": secret_bytes.to_vec(),
        "amount": amount.to_le_bytes().to_vec(),
        "pathElements": path_elements,
        "pathIndices": path_indices,
    });

    let dir = Builder::new().prefix("proof_local_check").tempdir()?;
    let input_path = dir.path().join("input.json");
    let witness_path = dir.path().join("witness.wtns");
    let proof_path = dir.path().join("proof.json");
    let public_path = dir.path().join("public.json");
    std::fs::write(&input_path, serde_json::to_vec_pretty(&input_json)?)?;

    // Resolve artifacts relative to the repo root, not the `relayer/` directory.
    // `CARGO_MANIFEST_DIR` for this binary points to `<repo>/relayer`.
    let relayer_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = relayer_dir
        .parent()
        .ok_or_else(|| AppError("Failed to determine repo root from CARGO_MANIFEST_DIR".into()))?
        .to_path_buf();

    let wasm = std::env::var("WITHDRAW_WASM_PATH")
        .unwrap_or_else(|_| repo_root.join(DEFAULT_WASM).display().to_string());
    let witness_js = std::env::var("WITHDRAW_WITNESS_JS")
        .unwrap_or_else(|_| repo_root.join(DEFAULT_WITNESS_JS).display().to_string());
    let zkey = std::env::var("WITHDRAW_ZKEY_PATH")
        .unwrap_or_else(|_| repo_root.join(DEFAULT_ZKEY).display().to_string());
    let snarkjs_cli = std::env::var("SNARKJS_CLI")
        .unwrap_or_else(|_| repo_root.join(DEFAULT_SNARKJS_CLI).display().to_string());
    let vk_json = std::env::var("WITHDRAW_VK_JSON")
        .unwrap_or_else(|_| repo_root.join(DEFAULT_VK_JSON).display().to_string());

    println!("[check] generating witness...");
    let w = std::process::Command::new("node")
        .args(&[
            &witness_js,
            &wasm,
            input_path.to_str().unwrap(),
            witness_path.to_str().unwrap(),
        ])
        .output()?;
    if !w.status.success() {
        return Err(Box::new(AppError(format!(
            "witness generation failed: {}",
            String::from_utf8_lossy(&w.stderr)
        ))));
    }

    println!("[check] proving with snarkjs (groth16 prove) ...");
    let p = std::process::Command::new("node")
        .args(&[
            &snarkjs_cli,
            "groth16",
            "prove",
            &zkey,
            witness_path.to_str().unwrap(),
            proof_path.to_str().unwrap(),
            public_path.to_str().unwrap(),
        ])
        .output()?;
    if !p.status.success() {
        return Err(Box::new(AppError(format!(
            "snarkjs prove failed: {}",
            String::from_utf8_lossy(&p.stderr)
        ))));
    }

    let proof: Groth16ProofJson = parse_json_file(&proof_path)?;
    let public: Vec<String> = parse_json_file(&public_path)?;
    if public.len() != 8 {
        return Err(Box::new(AppError(format!(
            "public.json expected 8 signals, got {}",
            public.len()
        ))));
    }
    println!("[check] public.json: {:?}", public);

    // Sanity check: snarkjs verify with the circuit verification_key.json.
    println!("[check] verifying with snarkjs (groth16 verify) ...");
    let v = std::process::Command::new("node")
        .args(&[
            &snarkjs_cli,
            "groth16",
            "verify",
            &vk_json,
            public_path.to_str().unwrap(),
            proof_path.to_str().unwrap(),
        ])
        .output()?;
    if !v.status.success() {
        return Err(Box::new(AppError(format!(
            "snarkjs verify failed. This strongly suggests VK/ZKey mismatch.\ncmd: node {} groth16 verify {} {} {}\nstderr: {}\nstdout: {}",
            snarkjs_cli,
            vk_json,
            public_path.display(),
            proof_path.display(),
            String::from_utf8_lossy(&v.stderr),
            String::from_utf8_lossy(&v.stdout),
        ))));
    }
    println!("[check] snarkjs verify: OK");

    // -------------------------------------------------------------------------
    // 🔍 DIAGNOSTIC: Compare JSON VK, ZKEY VK, and Rust VK (all three sources)
    // -------------------------------------------------------------------------
    {
        println!("----------------------------------------------------------------");
        println!("🔍 DIAGNOSTIC: Checking for Verifying Key Mismatch (3-way comparison)...");

        // 1. Parse the JSON file
        let vk_json_path = std::path::PathBuf::from(&vk_json);
        let vk_json_struct: VkJson = parse_json_file(&vk_json_path)
            .map_err(|e| AppError(format!("Failed to parse VK JSON: {}", e)))?;
        let json_alpha_x = u256_be32_from_dec_str(&vk_json_struct.vk_alpha_1[0])?;

        // 2. Extract VK from .zkey using snarkjs
        println!("[check] Extracting VK from .zkey file...");
        let zkey_vk_path = dir.path().join("zkey_vk.json");
        let extract_vk = std::process::Command::new("node")
            .args(&[
                &snarkjs_cli,
                "zkey",
                "export",
                "verificationkey",
                &zkey,
                zkey_vk_path.to_str().unwrap(),
            ])
            .output()?;

        let zkey_alpha_x = if extract_vk.status.success() {
            let zkey_vk_struct: VkJson = parse_json_file(&zkey_vk_path)
                .map_err(|e| AppError(format!("Failed to parse ZKEY VK JSON: {}", e)))?;
            Some(u256_be32_from_dec_str(&zkey_vk_struct.vk_alpha_1[0])?)
        } else {
            println!(
                "[check] ⚠️  Warning: Failed to extract VK from .zkey: {}",
                String::from_utf8_lossy(&extract_vk.stderr)
            );
            None
        };

        // 3. Extract Alpha G1 X-coordinate from Rust Constant
        let rust_alpha_full = &onchain_vk::VERIFYINGKEY.vk_alpha_g1;
        let rust_alpha_x = &rust_alpha_full[0..32];

        println!("JSON VK Alpha_X: {}", hex::encode(&json_alpha_x));
        if let Some(ref zkey_x) = zkey_alpha_x {
            println!("ZKEY VK Alpha_X: {}", hex::encode(zkey_x));
        } else {
            println!("ZKEY VK Alpha_X: <extraction failed>");
        }
        println!("RUST VK Alpha_X: {}", hex::encode(&rust_alpha_x));

        // Compare all three
        let mut mismatches = Vec::new();
        if json_alpha_x != rust_alpha_x {
            mismatches.push("JSON vs RUST");
        }
        if let Some(ref zkey_x) = zkey_alpha_x {
            if zkey_x != &json_alpha_x {
                mismatches.push("ZKEY vs JSON");
            }
            if zkey_x != rust_alpha_x {
                mismatches.push("ZKEY vs RUST");
            }
        }

        if !mismatches.is_empty() {
            println!("\nCRITICAL MISMATCH DETECTED");
            println!("Mismatches found: {}", mismatches.join(", "));
            println!("The verifying keys do NOT match across sources.");
            println!("This explains why 'snarkjs verify' works but the Rust verifier fails.");
            println!("To fix: Regenerate 'verifying_key.rs' using the current 'verification_key.json' or '.zkey'.");
            println!("----------------------------------------------------------------");
            return Err(Box::new(AppError(format!(
                "Verifying Key Mismatch: {}",
                mismatches.join(", ")
            ))));
        } else {
            println!("\nAll VK Alpha_X values match. Keys appear consistent across all sources.");

            // Also check IC vector length and ALL elements
            println!("[check] Checking IC vector...");
            println!("JSON IC length: {}", vk_json_struct.ic.len());
            println!("RUST IC length: {}", onchain_vk::VERIFYINGKEY.vk_ic.len());
            if vk_json_struct.ic.len() != onchain_vk::VERIFYINGKEY.vk_ic.len() {
                println!("IC vector length mismatch!");
                return Err(Box::new(AppError("IC vector length mismatch".into())));
            }

            // Compare ALL IC elements
            let mut ic_mismatches = Vec::new();
            for i in 0..vk_json_struct
                .ic
                .len()
                .min(onchain_vk::VERIFYINGKEY.vk_ic.len())
            {
                let json_ic_x = u256_be32_from_dec_str(&vk_json_struct.ic[i][0])?;
                let rust_ic_x = &onchain_vk::VERIFYINGKEY.vk_ic[i][0..32];
                if json_ic_x != rust_ic_x {
                    ic_mismatches.push(i);
                    if ic_mismatches.len() <= 3 {
                        println!(
                            "IC[{}] X mismatch: JSON={} RUST={}",
                            i,
                            hex::encode(&json_ic_x),
                            hex::encode(rust_ic_x)
                        );
                    }
                }
            }

            if !ic_mismatches.is_empty() {
                println!(
                    "IC vector has {} mismatches at indices: {:?}",
                    ic_mismatches.len(),
                    ic_mismatches
                );
                return Err(Box::new(AppError(format!(
                    "IC vector mismatch: {} elements differ",
                    ic_mismatches.len()
                ))));
            }

            // Show first element for confirmation
            let json_ic0_x = u256_be32_from_dec_str(&vk_json_struct.ic[0][0])?;
            let rust_ic0_x = &onchain_vk::VERIFYINGKEY.vk_ic[0][0..32];
            println!("JSON IC[0] X: {}", hex::encode(&json_ic0_x));
            println!("RUST IC[0] X: {}", hex::encode(rust_ic0_x));
            println!("All {} IC elements match.", vk_json_struct.ic.len());
            println!("----------------------------------------------------------------");
        }
    }
    // -------------------------------------------------------------------------

    // Convert public signals (decimal strings) to 32-byte BE field elements.
    let mut pub_inputs = [[0u8; 32]; 8];
    for (i, s) in public.iter().enumerate() {
        pub_inputs[i] = u256_be32_from_dec_str(s)?;
        println!("[check] pub_inputs[{}] = {}", i, hex::encode(pub_inputs[i]));
    }

    // Also reconstruct public inputs the way the on-chain program does (for comparison)
    let to_field_element = |slice: &[u8]| -> [u8; 32] {
        let mut element = [0u8; 32];
        let start = 32 - slice.len();
        element[start..].copy_from_slice(slice);
        element
    };
    let mut fee_be = [0u8; 32];
    fee_be[24..].copy_from_slice(&fee.to_be_bytes());
    let mut amount_be = [0u8; 32];
    amount_be[24..].copy_from_slice(&amount.to_be_bytes());
    let rec_bytes = recipient.to_bytes();
    let onchain_pub_inputs: [[u8; 32]; 8] = [
        to_field_element(&root_bytes[0..16]),
        to_field_element(&root_bytes[16..32]),
        to_field_element(&nullifier_hash[0..16]),
        to_field_element(&nullifier_hash[16..32]),
        to_field_element(&rec_bytes[0..16]),
        to_field_element(&rec_bytes[16..32]),
        fee_be,
        amount_be,
    ];
    println!("[check] Comparing public inputs:");
    for i in 0..8 {
        let match_str = if pub_inputs[i] == onchain_pub_inputs[i] {
            "MATCH"
        } else {
            "MISMATCH"
        };
        println!(
            "[check]   [{}] snarkjs={} onchain={} {}",
            i,
            hex::encode(pub_inputs[i]),
            hex::encode(onchain_pub_inputs[i]),
            match_str
        );
    }

    // Try groth16-solana verification with a few formatting variants to pinpoint what's wrong.
    // (A must be -A for many verifiers; B may come in either [c0,c1] or [c1,c0] order depending on producer.)
    println!("[check] verifying with groth16-solana + verifying_key.rs (trying variants) ...");

    let mut last_err: Option<String> = None;
    let variants = [
        (true, true, "A=-A, B=(c1||c0) from pi_b[0][1]/[0]"),
        (true, false, "A=-A, B=(c1||c0) from pi_b[0][0]/[1]"),
        (false, true, "A=A,  B=(c1||c0) from pi_b[0][1]/[0]"),
        (false, false, "A=A,  B=(c1||c0) from pi_b[0][0]/[1]"),
    ];

    let mut ok_variant: Option<&'static str> = None;
    for (negate_a, swap_b, label) in variants {
        // Build proof blobs for this variant
        let ax = u256_be32_from_dec_str(&proof.pi_a[0])?;
        let ay = u256_be32_from_dec_str(&proof.pi_a[1])?;
        let ay_used = if negate_a { g1_negate_y_be(&ay)? } else { ay };

        let (bx_c1, bx_c0, by_c1, by_c0) = if swap_b {
            (
                u256_be32_from_dec_str(&proof.pi_b[0][1])?,
                u256_be32_from_dec_str(&proof.pi_b[0][0])?,
                u256_be32_from_dec_str(&proof.pi_b[1][1])?,
                u256_be32_from_dec_str(&proof.pi_b[1][0])?,
            )
        } else {
            (
                u256_be32_from_dec_str(&proof.pi_b[0][0])?,
                u256_be32_from_dec_str(&proof.pi_b[0][1])?,
                u256_be32_from_dec_str(&proof.pi_b[1][0])?,
                u256_be32_from_dec_str(&proof.pi_b[1][1])?,
            )
        };

        let cx = u256_be32_from_dec_str(&proof.pi_c[0])?;
        let cy = u256_be32_from_dec_str(&proof.pi_c[1])?;

        let mut proof_a = [0u8; 64];
        proof_a[0..32].copy_from_slice(&ax);
        proof_a[32..64].copy_from_slice(&ay_used);
        let mut proof_b = [0u8; 128];
        proof_b[0..32].copy_from_slice(&bx_c1);
        proof_b[32..64].copy_from_slice(&bx_c0);
        proof_b[64..96].copy_from_slice(&by_c1);
        proof_b[96..128].copy_from_slice(&by_c0);
        let mut proof_c = [0u8; 64];
        proof_c[0..32].copy_from_slice(&cx);
        proof_c[32..64].copy_from_slice(&cy);

        // Debug: Print proof component sizes and first few bytes
        println!("[check]   Variant '{}':", label);
        println!("[check]     proof_a[0..4] = {:?}", &proof_a[0..4]);
        println!("[check]     proof_b[0..4] = {:?}", &proof_b[0..4]);
        println!("[check]     proof_c[0..4] = {:?}", &proof_c[0..4]);

        // Use const-generic API (matches on-chain program)
        let mut verifier = match Groth16Verifier::<8>::new(
            &proof_a,
            &proof_b,
            &proof_c,
            &pub_inputs,
            &onchain_vk::VERIFYINGKEY,
        ) {
            Ok(v) => {
                println!("[check]     verifier.new: OK");
                v
            }
            Err(e) => {
                let err_msg = format!("{label}: verifier.new failed: {e:?}");
                println!("[check]     {}", err_msg);
                last_err = Some(err_msg);
                continue;
            }
        };

        match verifier.verify() {
            Ok(_) => {
                println!("[check]     verify: OK");
                ok_variant = Some(label);
                break;
            }
            Err(e) => {
                let err_msg = format!("{label}: verify failed: {e:?}");
                println!("[check]     {}", err_msg);
                last_err = Some(err_msg);
            }
        }
    }

    println!("[check] tempdir={}", dir.path().display());

    if let Some(label) = ok_variant {
        println!("OK: groth16-solana verified ({})", label);
        return Ok(());
    }

    Err(Box::new(AppError(format!(
        "groth16-solana verification failed for all variants. Last error: {}",
        last_err.unwrap_or_else(|| "<none>".into())
    ))))
}
