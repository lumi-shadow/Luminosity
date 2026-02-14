use crate::constants::MAX_ENCRYPTED_BLOB_HEX_LEN;
use crate::error::AppError;
use crate::validation::ensure_len_le;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

#[derive(Debug, Deserialize, Clone)]
pub struct EncryptedRequest {
    /// Hex-encoded ECIES ciphertext of the browser payload (nullifier/secret/amount/recipient/fee).
    pub encrypted_blob: String,
}

pub type RelayRequest = EncryptedRequest;

impl EncryptedRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        let s = self.encrypted_blob.trim();
        if s.is_empty() {
            return Err(AppError::BadRequest("encrypted_blob is required".into()));
        }
        ensure_len_le("encrypted_blob", s, MAX_ENCRYPTED_BLOB_HEX_LEN)?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct RelayProgressEvent {
    pub kind: &'static str,  // "progress" | "result" | "error"
    pub stage: &'static str, // stable stage identifier
    pub message: String,
    pub ts_ms: u128,
    pub data: Option<Value>,
}

pub type ProgressTx = mpsc::Sender<RelayProgressEvent>;

/// Browser-side payload (encrypted_blob decrypts into this).
/// NOTE: Browser does NOT generate any proofs; enclave does.
#[derive(Debug, Clone, Deserialize)]
pub struct BrowserInputs {
    pub nullifier: String, // hex-encoded 32 bytes
    pub secret: String,    // hex-encoded 32 bytes
    pub amount: u64,       // lamports
    /// Recipient SPL TokenAccount pubkey (base58). This is the public input bound in-circuit.
    pub recipient: String,
    pub fee: u64, // lamports
    /// SPL mint pubkey (base58) for the asset being withdrawn.
    pub mint: String,
    /// Deprecated/unsupported: previously used for WSOL->SOL "unwrap" convenience on withdraw.
    /// The relayer no longer performs WSOL wrapping/unwrapping (tx size constraints).
    #[serde(default)]
    pub sol_destination: Option<String>,
}

/// Browser-side payload for share-based liquidity withdrawals.
#[derive(Debug, Clone, Deserialize)]
pub struct BrowserLiquidityInputs {
    pub nullifier: String,       // hex-encoded 32 bytes
    pub secret: String,          // hex-encoded 32 bytes
    pub shares: u64,             // LP shares to redeem
    pub recipient_owner: String, // base58 pubkey (wallet)
    /// Must be 0 for now (program enforces TokenRelayerFeeNotSupported).
    pub fee: u64,
    /// Pool mints (base58). Relayer will canonicalize ordering.
    pub mint_a: String,
    pub mint_b: String,
}

#[derive(Debug, Deserialize)]
pub struct IndexerProofResponse {
    #[serde(rename = "commitment_hex")]
    #[allow(dead_code)]
    pub commitment_hex: String,
    pub leaf_index: u32,
    #[serde(rename = "leaf_hex")]
    pub leaf_hex: String,
    pub root_hex: String,
    pub siblings_hex: Vec<String>,
    pub path_bits: Vec<u8>,
    pub depth: usize,
}
