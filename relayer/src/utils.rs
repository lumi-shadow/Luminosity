use crate::error::AppError;
use crate::error::AppResult;
use crate::types::IndexerProofResponse;
use crate::types::{ProgressTx, RelayProgressEvent};
use crate::{SPL_TREE_DATA_OFFSET, SPL_TREE_MAX_BUFFER_SIZE, SPL_TREE_MAX_DEPTH};
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{hash::hash as solana_sha256, pubkey::Pubkey};
use spl_concurrent_merkle_tree::concurrent_merkle_tree::ConcurrentMerkleTree;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use tracing::warn;

// ---------------------------------------------------------------------
// Relayer fee helpers
// ---------------------------------------------------------------------

/// Returns configured fee bps if set, else `None` (caller can fall back).
pub fn relayer_fee_bps_from_env() -> Option<u64> {
    env::var("RELAYER_FEE_BPS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Compute relayer fee in lamports for a given `amount_lamports`.
///
/// Priority:
/// - If `RELAYER_FEE_BPS` is set -> fee = ceil(amount * bps / 10_000), min 1 when amount>0.
/// - Else default to `DEFAULT_RELAYER_FEE_BPS` (25 bps = 0.25%).
pub fn compute_relayer_fee_lamports(amount_lamports: u64) -> u64 {
    if amount_lamports == 0 {
        return 0;
    }
    if let Some(bps) = relayer_fee_bps_from_env() {
        // ceil(amount * bps / 10_000)
        let num = (amount_lamports as u128)
            .saturating_mul(bps as u128)
            .saturating_add(9_999);
        let fee = (num / 10_000) as u64;
        return fee.max(1);
    }
    // Default: 25 bps (0.25%)
    let bps = crate::constants::DEFAULT_RELAYER_FEE_BPS;
    let num = (amount_lamports as u128)
        .saturating_mul(bps as u128)
        .saturating_add(9_999);
    let fee = (num / 10_000) as u64;
    fee.max(1)
}

pub fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub fn relayer_tmpdir() -> std::path::PathBuf {
    // Prefer tmpfs if available. Override via RELAYER_TMPDIR.
    let mut opts: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(v) = env::var("RELAYER_TMPDIR") {
        let v = v.trim();
        if !v.is_empty() {
            opts.push(std::path::PathBuf::from(v));
        }
    }
    opts.push(std::path::PathBuf::from("/dev/shm"));
    opts.push(std::env::temp_dir());

    for p in opts {
        if p.is_dir() {
            return p;
        }
    }
    std::env::temp_dir()
}

pub async fn progress(tx: &Option<ProgressTx>, stage: &'static str, message: impl Into<String>) {
    if let Some(tx) = tx {
        let _ = tx
            .send(RelayProgressEvent {
                kind: "progress",
                stage,
                message: message.into(),
                ts_ms: now_ms(),
                data: None,
            })
            .await;
    }
}

// ---------------------------------------------------------------------
// BN254 / Groth16 helper math
// ---------------------------------------------------------------------

pub fn u256_be32_from_dec_str(s: &str) -> Result<[u8; 32], AppError> {
    let n: BigUint = s
        .parse::<BigUint>()
        .map_err(|_| AppError::Internal("snarkjs produced non-decimal coordinates".into()))?;
    u256_be32_from_biguint(&n)
}

fn bn254_fq_modulus() -> BigUint {
    // BN254 base field modulus (a.k.a. alt_bn128 Fq)
    // 21888242871839275222246405745257275088696311157297823662689037894645226208583
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088696311157297823662689037894645226208583",
        10,
    )
    .expect("bn254 modulus parse")
}

fn u256_be32_from_biguint(n: &BigUint) -> Result<[u8; 32], AppError> {
    let mut out = [0u8; 32];
    let b = n.to_bytes_be();
    if b.len() > 32 {
        return Err(AppError::Internal(
            "bn254 coordinate exceeds 32 bytes".into(),
        ));
    }
    out[32 - b.len()..].copy_from_slice(&b);
    Ok(out)
}

pub fn g1_negate_y_be(y_be32: &[u8; 32]) -> Result<[u8; 32], AppError> {
    let y = BigUint::from_bytes_be(y_be32);
    if y == BigUint::from(0u8) {
        return Ok([0u8; 32]);
    }
    let p = bn254_fq_modulus();
    let y_neg = (&p - (y % &p)) % &p;
    u256_be32_from_biguint(&y_neg)
}

pub fn split_u128_be16_be16(bytes32: &[u8; 32]) -> (String, String) {
    let hi = BigUint::from_bytes_be(&bytes32[0..16]).to_str_radix(10);
    let lo = BigUint::from_bytes_be(&bytes32[16..32]).to_str_radix(10);
    (hi, lo)
}

// ---------------------------------------------------------------------
// Misc helpers moved from `main.rs`
// ---------------------------------------------------------------------

#[allow(dead_code)]
pub fn tree_changelog_path_and_root(
    rpc: &RpcClient,
    merkle_tree: &Pubkey,
    leaf_index_0: u32,
) -> AppResult<(Vec<String>, String)> {
    let acc = rpc
        .get_account(merkle_tree)
        .map_err(|e| AppError::BadGateway(e.to_string()))?;
    let data = acc.data;
    let tree_struct_size =
        std::mem::size_of::<ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>>();
    let start = SPL_TREE_DATA_OFFSET;
    let end = start + tree_struct_size;
    if data.len() < end {
        return Err(AppError::Internal(format!(
            "Merkle tree account too small for expected struct (len={} need_end={})",
            data.len(),
            end
        )));
    }
    let tree_bytes = &data[start..end];
    let _tree = bytemuck::try_from_bytes::<
        ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
    >(tree_bytes)
    .map_err(|_| {
        AppError::Internal("Failed to deserialize ConcurrentMerkleTree from account".into())
    })?;

    Err(AppError::BadRequest(format!(
        "Cannot derive Merkle proof from on-chain changelog. Need off-chain indexer/cache. leaf_index={}",
        leaf_index_0
    )))
}

pub fn parse_first_json_value<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    // Some external tools occasionally append extra bytes/log lines after a JSON blob.
    // Parse the first JSON value and ignore trailing whitespace / NULs.
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<T>();
    let v = stream
        .next()
        .ok_or_else(|| "empty JSON".to_string())?
        .map_err(|e| e.to_string())?;
    let used = stream.byte_offset();
    let trailing = &bytes[used..];
    let ok_trailing = trailing.iter().all(|b| b.is_ascii_whitespace() || *b == 0);
    if !ok_trailing {
        warn!(
            "Non-whitespace trailing bytes after JSON (len={} used={} trailing={})",
            bytes.len(),
            used,
            trailing.len()
        );
    }
    Ok(v)
}

pub fn merkle_root_from_witness(
    leaf: [u8; 32],
    path_elements: &Vec<Vec<u8>>,
    path_indices: &Vec<u32>,
) -> Result<[u8; 32], AppError> {
    if path_elements.len() != path_indices.len() {
        return Err(AppError::Internal(
            "pathElements/pathIndices length mismatch".into(),
        ));
    }
    let mut cur = leaf;
    for (i, (sib, bit)) in path_elements.iter().zip(path_indices.iter()).enumerate() {
        if sib.len() != 32 {
            return Err(AppError::Internal(format!(
                "pathElements[{i}] is {} bytes (expected 32)",
                sib.len()
            )));
        }
        let mut sib32 = [0u8; 32];
        sib32.copy_from_slice(sib);
        let (left, right) = if *bit == 0 {
            (cur, sib32)
        } else {
            (sib32, cur)
        };
        cur = keccak256(&[left.as_ref(), right.as_ref()].concat());
    }
    Ok(cur)
}

pub fn spent_shard_pda(program_id: &Pubkey, amm: &Pubkey, shard_index: u32) -> Pubkey {
    Pubkey::find_program_address(
        &[b"spent", amm.as_ref(), &shard_index.to_le_bytes()],
        program_id,
    )
    .0
}

/// Simple Keccak‑256 wrapper returning a fixed‑size array.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn parse_http_base(base: &str) -> Result<(String, u16, String), AppError> {
    // Minimal parser for URLs like:
    // - http://127.0.0.1:8787
    // - http://localhost:8787/prefix
    //
    // NOTE: We intentionally do NOT support https here (no TLS deps).
    let b = base.trim().trim_end_matches('/');
    let b = b
        .strip_prefix("http://")
        .ok_or_else(|| AppError::BadRequest("INDEXER_URL must start with http://".into()))?;
    let (hostport, prefix) = match b.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p.trim_matches('/'))),
        None => (b, String::new()),
    };
    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| AppError::BadRequest("INDEXER_URL port is invalid".into()))?;
            (h.to_string(), port)
        }
        None => (hostport.to_string(), 80),
    };
    Ok((host, port, prefix))
}

fn http_dechunk(body: &[u8]) -> Result<Vec<u8>, AppError> {
    // Tiny chunked decoder (hyper may use chunked encoding).
    let mut i = 0usize;
    let mut out = Vec::new();
    loop {
        let line_end = body[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| AppError::Internal("invalid chunked encoding (missing CRLF)".into()))?;
        let line = &body[i..i + line_end];
        i += line_end + 2;
        let line_str = std::str::from_utf8(line)
            .map_err(|_| AppError::Internal("chunk size not utf8".into()))?;
        let size_hex = line_str.split(';').next().unwrap_or("");
        let size = usize::from_str_radix(size_hex.trim(), 16)
            .map_err(|_| AppError::Internal("invalid chunk size".into()))?;
        if size == 0 {
            break;
        }
        if i + size > body.len() {
            return Err(AppError::Internal(
                "invalid chunked encoding (chunk overruns body)".into(),
            ));
        }
        out.extend_from_slice(&body[i..i + size]);
        i += size;
        if body.get(i..i + 2) != Some(b"\r\n") {
            return Err(AppError::Internal(
                "invalid chunked encoding (missing chunk CRLF)".into(),
            ));
        }
        i += 2;
    }
    Ok(out)
}

#[derive(Debug)]
pub enum IndexerProofLookup {
    Found(IndexerProofResponse),
    NotFound(String),
    Unavailable(String),
}

pub fn fetch_indexer_proof(
    indexer_url: &str,
    commitment_hex: &str,
    admin_token: &str,
) -> Result<IndexerProofLookup, AppError> {
    fetch_indexer_proof_inner(indexer_url, commitment_hex, admin_token, true)
}

fn fetch_indexer_proof_inner(
    indexer_url: &str,
    commitment_hex: &str,
    admin_token: &str,
    allow_self_heal: bool,
) -> Result<IndexerProofLookup, AppError> {
    let (host, port, prefix) = parse_http_base(indexer_url)?;
    let path = format!("{}/proof/0x{}", prefix, commitment_hex);
    let addr = format!("{}:{}", host, port);

    let timeout_secs = env::var("INDEXER_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2);

    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| AppError::BadGateway(format!("indexer connect failed: {e}")))?;
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(timeout_secs)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(timeout_secs)));

    let admin_token = admin_token.trim();
    if admin_token.is_empty() {
        return Err(AppError::Internal("admin token is empty".into()));
    }
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json\r\nAuthorization: Bearer {}\r\n\r\n",
        path, host, admin_token
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| AppError::BadGateway(format!("indexer write failed: {e}")))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| AppError::BadGateway(format!("indexer read failed: {e}")))?;

    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            AppError::BadGateway("indexer response missing header/body separator".into())
        })?;
    let (head, body_raw) = buf.split_at(split + 4);
    let head_str = std::str::from_utf8(head)
        .map_err(|_| AppError::BadGateway("indexer response headers not utf8".into()))?;
    let status_line = head_str.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| AppError::BadGateway("indexer response missing status code".into()))?;

    let is_chunked = head_str
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    let body = if is_chunked {
        http_dechunk(body_raw)?
    } else {
        body_raw.to_vec()
    };

    match status {
        200 => {
            let v: IndexerProofResponse = serde_json::from_slice(&body)
                .map_err(|e| AppError::BadGateway(format!("indexer returned invalid json: {e}")))?;
            Ok(IndexerProofLookup::Found(v))
        }
        403 => {
            // IP not allowlisted. Try to self-register, then retry once.
            if !allow_self_heal {
                return Ok(IndexerProofLookup::Unavailable(format!(
                    "indexer returned 403 after allowlist self-heal: {}",
                    indexer_body_snippet(&body)
                )));
            }
            indexer_allowlist_self(indexer_url, admin_token, timeout_secs)?;
            fetch_indexer_proof_inner(indexer_url, commitment_hex, admin_token, false)
        }
        404 => Ok(IndexerProofLookup::NotFound(indexer_body_snippet(&body))),
        503 => Ok(IndexerProofLookup::Unavailable(indexer_body_snippet(&body))),
        _ => Ok(IndexerProofLookup::Unavailable(format!(
            "unexpected status {}: {}",
            status,
            indexer_body_snippet(&body)
        ))),
    }
}

fn indexer_allowlist_self(
    indexer_url: &str,
    admin_token: &str,
    timeout_secs: u64,
) -> Result<(), AppError> {
    let (host, port, prefix) = parse_http_base(indexer_url)?;
    let path = format!("{}/admin/allowlist/self", prefix);
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| AppError::BadGateway(format!("indexer connect failed: {e}")))?;
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(timeout_secs)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(timeout_secs)));

    let admin_token = admin_token.trim();
    if admin_token.is_empty() {
        return Err(AppError::Internal("admin token is empty".into()));
    }
    let body = b"{}";
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAuthorization: Bearer {}\r\n\r\n",
        path,
        host,
        body.len(),
        admin_token
    );
    stream
        .write_all(req.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|e| AppError::BadGateway(format!("indexer write failed: {e}")))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| AppError::BadGateway(format!("indexer read failed: {e}")))?;
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            AppError::BadGateway("indexer response missing header/body separator".into())
        })?;
    let (head, body_raw) = buf.split_at(split + 4);
    let head_str = std::str::from_utf8(head)
        .map_err(|_| AppError::BadGateway("indexer response headers not utf8".into()))?;
    let status_line = head_str.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| AppError::BadGateway("indexer response missing status code".into()))?;
    let is_chunked = head_str
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    let body = if is_chunked {
        http_dechunk(body_raw)?
    } else {
        body_raw.to_vec()
    };
    if status != 200 {
        return Err(AppError::BadGateway(format!(
            "indexer allowlist self failed ({status}): {}",
            indexer_body_snippet(&body)
        )));
    }
    Ok(())
}

pub fn indexer_body_snippet(body: &[u8]) -> String {
    const MAX: usize = 400;
    let s = String::from_utf8_lossy(body).trim().to_string();
    if s.len() <= MAX {
        s
    } else {
        format!("{}…", &s[..MAX])
    }
}

/// Two-layer asset commitment matching circuits + on-chain program:
///   Layer 1: noteHash   = keccak256(nullifier || secret)
///   Layer 2: commitment = keccak256(noteHash || amountLE8 || assetIdLE4)
pub fn compute_commitment(
    nullifier_hex: &str,
    secret_hex: &str,
    amount: u64,
    asset_id: u32,
) -> Result<[u8; 32], AppError> {
    let nullifier = hex::decode(nullifier_hex)
        .map_err(|_| AppError::BadRequest("Invalid hex in nullifier".into()))?;
    let secret = hex::decode(secret_hex)
        .map_err(|_| AppError::BadRequest("Invalid hex in secret".into()))?;

    if nullifier.len() != 32 || secret.len() != 32 {
        return Err(AppError::BadRequest(
            "nullifier or secret is not 32 bytes".into(),
        ));
    }

    // Layer 1: noteHash = keccak256(nullifier || secret)
    let note_hash = keccak256(
        &[nullifier.as_slice(), secret.as_slice()].concat(),
    );

    // Layer 2: commitment = keccak256(noteHash || amountLE8 || assetIdLE4)
    let mut amount_le8 = [0u8; 8];
    amount_le8.copy_from_slice(&amount.to_le_bytes());
    let mut asset_id_le4 = [0u8; 4];
    asset_id_le4.copy_from_slice(&asset_id.to_le_bytes());

    Ok(keccak256(
        &[
            note_hash.as_slice(),
            &amount_le8,
            &asset_id_le4,
        ]
        .concat(),
    ))
}

/// Two-layer liquidity commitment matching circuits + on-chain program:
///   Layer 1: noteHash   = keccak256(nullifier || secret)
///   Layer 2: commitment = keccak256(noteHash || sharesLE8 || poolIdLE4)
pub fn compute_commitment_liquidity(
    nullifier_hex: &str,
    secret_hex: &str,
    shares: u64,
    pool_id: u32,
) -> Result<[u8; 32], AppError> {
    let nullifier = hex::decode(nullifier_hex)
        .map_err(|_| AppError::BadRequest("Invalid hex in nullifier".into()))?;
    let secret = hex::decode(secret_hex)
        .map_err(|_| AppError::BadRequest("Invalid hex in secret".into()))?;
    if nullifier.len() != 32 || secret.len() != 32 {
        return Err(AppError::BadRequest(
            "nullifier or secret is not 32 bytes".into(),
        ));
    }

    // Layer 1: noteHash = keccak256(nullifier || secret)
    let note_hash = keccak256(
        &[nullifier.as_slice(), secret.as_slice()].concat(),
    );

    // Layer 2: commitment = keccak256(noteHash || sharesLE8 || poolIdLE4)
    let mut shares_le8 = [0u8; 8];
    shares_le8.copy_from_slice(&shares.to_le_bytes());
    let mut pool_id_le4 = [0u8; 4];
    pool_id_le4.copy_from_slice(&pool_id.to_le_bytes());

    Ok(keccak256(
        &[
            note_hash.as_slice(),
            &shares_le8,
            &pool_id_le4,
        ]
        .concat(),
    ))
}

pub fn associated_token_address(
    authority: &Pubkey,
    mint: &Pubkey,
    token_program_id: &Pubkey,
    associated_token_program_id: &Pubkey,
) -> Pubkey {
    let (ata, _) = Pubkey::find_program_address(
        &[authority.as_ref(), token_program_id.as_ref(), mint.as_ref()],
        associated_token_program_id,
    );
    ata
}

pub fn registry_asset_id_for_mint(
    rpc: &RpcClient,
    program_id: Pubkey,
    mint: &Pubkey,
) -> AppResult<u32> {
    let (registry_pda, _) = Pubkey::find_program_address(&[b"registry"], &program_id);
    let acc = rpc
        .get_account(&registry_pda)
        .map_err(|e| AppError::BadGateway(format!("Failed to fetch registry: {e}")))?;
    let data = acc.data;
    // Registry layout (programs/solana-privacy-pool/src/state.rs):
    // 8 disc
    // is_initialized(1)
    // assets: Vec<(mint(32), asset_id(4))> => 4 + n*(32+4)
    // mints_by_asset_id: Vec<Pubkey>       => 4 + n*32
    // pools: Vec<(pool(32), pool_id(4))>   => 4 + n*(32+4)
    // pools_by_id: Vec<Pubkey>             => 4 + n*32
    // bump(1)
    if data.len() < 8 + 1 + 4 {
        return Err(AppError::Internal("Registry account too small".into()));
    }

    let mut off = 8usize;
    off += 1; // is_initialized
    let assets_len = u32::from_le_bytes(
        data[off..off + 4]
            .try_into()
            .map_err(|_| AppError::Internal("Registry truncated before assets len".into()))?,
    ) as usize;
    off += 4;

    let needed = off
        .checked_add(assets_len.saturating_mul(32 + 4))
        .ok_or_else(|| AppError::Internal("Registry assets vec overflow".into()))?;
    if data.len() < needed {
        return Err(AppError::Internal(format!(
            "Registry assets vec truncated (len={} need_at_least={})",
            data.len(),
            needed
        )));
    }

    for _ in 0..assets_len {
        let m = Pubkey::new_from_array(data[off..off + 32].try_into().unwrap());
        off += 32;
        let id = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;
        if &m == mint {
            return Ok(id);
        }
    }

    Err(AppError::BadRequest(format!(
        "Mint not registered in Registry: {}",
        mint
    )))
}

pub fn registry_pool_id_for_pool(
    rpc: &RpcClient,
    program_id: Pubkey,
    pool: &Pubkey,
) -> AppResult<u32> {
    let (registry_pda, _) = Pubkey::find_program_address(&[b"registry"], &program_id);
    let acc = rpc
        .get_account(&registry_pda)
        .map_err(|e| AppError::BadGateway(format!("Failed to fetch registry: {e}")))?;
    let data = acc.data;

    if data.len() < 8 + 1 + 4 {
        return Err(AppError::Internal("Registry account too small".into()));
    }
    let mut off = 8usize;
    off += 1; // is_initialized

    let assets_len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    let assets_bytes = assets_len
        .checked_mul(32 + 4)
        .ok_or_else(|| AppError::Internal("Registry assets vec overflow".into()))?;
    if data.len() < off + assets_bytes {
        return Err(AppError::Internal("Registry assets vec truncated".into()));
    }
    off += assets_bytes;

    if data.len() < off + 4 {
        return Err(AppError::Internal(
            "Registry truncated before mints_by_asset_id".into(),
        ));
    }
    let mints_len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    let mints_bytes = mints_len
        .checked_mul(32)
        .ok_or_else(|| AppError::Internal("Registry mints_by_asset_id overflow".into()))?;
    if data.len() < off + mints_bytes {
        return Err(AppError::Internal(
            "Registry mints_by_asset_id truncated".into(),
        ));
    }
    off += mints_bytes;

    if data.len() < off + 4 {
        return Err(AppError::Internal("Registry truncated before pools".into()));
    }
    let pools_len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    let needed = off + pools_len.saturating_mul(32 + 4);
    if data.len() < needed {
        return Err(AppError::Internal(format!(
            "Registry pools vec truncated (len={} need_at_least={})",
            data.len(),
            needed
        )));
    }

    for _ in 0..pools_len {
        let p = Pubkey::new_from_array(data[off..off + 32].try_into().unwrap());
        off += 32;
        let id = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;
        if &p == pool {
            return Ok(id);
        }
    }

    Err(AppError::BadRequest(format!(
        "Pool not registered in Registry: {}",
        pool
    )))
}

/// Anchor instruction discriminator = first 8 bytes of sha256("global:<name>")
pub fn anchor_discriminator(name: &str) -> [u8; 8] {
    let preimage = format!("global:{}", name);
    let h = solana_sha256(preimage.as_bytes()).to_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

pub fn current_merkle_tree_pubkey(rpc: &RpcClient, program_id: &Pubkey) -> AppResult<Pubkey> {
    let (amm_pda, _) = Pubkey::find_program_address(&[b"amm"], program_id);
    let amm_account = rpc
        .get_account(&amm_pda)
        .map_err(|e| AppError::BadGateway(e.to_string()))?;

    const MERKLE_TREE_OFF: usize = 8 + 32 + 32;
    const MERKLE_TREE_END: usize = MERKLE_TREE_OFF + 32;

    if amm_account.data.len() < MERKLE_TREE_END {
        return Err(AppError::Internal(format!(
            "AMM account data too short (len={} need_at_least={})",
            amm_account.data.len(),
            MERKLE_TREE_END
        )));
    }

    Ok(Pubkey::new_from_array(
        amm_account.data[MERKLE_TREE_OFF..MERKLE_TREE_END]
            .try_into()
            .map_err(|_| AppError::Internal("Failed to parse AMM.merkle_tree pubkey".into()))?,
    ))
}

pub fn tree_changelog_contains_root(
    rpc: &RpcClient,
    merkle_tree: &Pubkey,
    root: [u8; 32],
) -> AppResult<bool> {
    let acc = rpc
        .get_account(merkle_tree)
        .map_err(|e| AppError::BadGateway(e.to_string()))?;
    let data = acc.data;
    let tree_struct_size =
        std::mem::size_of::<ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>>();
    let start = SPL_TREE_DATA_OFFSET;
    let end = start + tree_struct_size;
    if data.len() < end {
        return Err(AppError::Internal(format!(
            "Merkle tree account too small for expected struct (len={} need_end={})",
            data.len(),
            end
        )));
    }
    let tree_bytes = &data[start..end];
    let tree = bytemuck::try_from_bytes::<
        ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
    >(tree_bytes)
    .map_err(|_| {
        AppError::Internal("Failed to deserialize ConcurrentMerkleTree from account".into())
    })?;
    Ok(tree.change_logs.iter().any(|cl| cl.root == root))
}
