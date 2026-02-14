//! API types + small shared structs.
//!
//! We separate these from `engine.rs` so the handlers stay readable.

use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;

// ---------------------------------------------------------------------
// Input validation helpers (spam protection)
// ---------------------------------------------------------------------
const MAX_PUBKEY_B58_LEN: usize = 64; // base58 pubkeys are ~32-44 chars; keep some slack.
const MAX_HEX_32_STR_LEN: usize = 2 + 64; // optional "0x" + 32 bytes hex
const MAX_BASE64_STR_LEN: usize = 2048; // generous cap; prevents huge JSON strings

fn ensure_len_le(field: &str, s: &str, max: usize) -> Result<(), AppError> {
    if s.len() > max {
        return Err(AppError::BadRequest(format!(
            "{field} too long: {} chars (max {max})",
            s.len()
        )));
    }
    Ok(())
}

fn ensure_hex32_len(field: &str, s: &str) -> Result<(), AppError> {
    let t = s.trim();
    ensure_len_le(field, t, MAX_HEX_32_STR_LEN)?;
    let t = t.trim_start_matches("0x");
    if t.len() != 64 {
        return Err(AppError::BadRequest(format!(
            "{field} must be 32-byte hex (64 chars), got {} chars",
            t.len()
        )));
    }
    // Validate that it is actually hex (and exactly 32 bytes).
    let mut out = [0u8; 32];
    hex::decode_to_slice(t, &mut out)
        .map_err(|_| AppError::BadRequest(format!("{field} must be valid hex")))?;
    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("too many requests: {0}")]
    TooManyRequests(String),
    #[error("bad gateway: {0}")]
    BadGateway(String),
}

impl AppError {
    pub fn status_code(&self) -> axum::http::StatusCode {
        match self {
            AppError::BadRequest(_) => axum::http::StatusCode::BAD_REQUEST,
            AppError::Forbidden(_) => axum::http::StatusCode::FORBIDDEN,
            AppError::Unavailable(_) => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            AppError::TooManyRequests(_) => axum::http::StatusCode::TOO_MANY_REQUESTS,
            AppError::BadGateway(_) => axum::http::StatusCode::BAD_GATEWAY,
        }
    }
}

#[derive(Serialize)]
pub struct ErrorBody {
    pub error: String,
}

pub type ApiResult<T> = Result<axum::Json<T>, (axum::http::StatusCode, axum::Json<ErrorBody>)>;

pub fn api_err<T>(e: AppError) -> ApiResult<T> {
    Err((
        e.status_code(),
        axum::Json(ErrorBody {
            error: e.to_string(),
        }),
    ))
}

#[derive(Debug, Clone)]
pub struct PoolAccount {
    #[allow(dead_code)]
    pub amm: Pubkey,
    pub mint_a: Pubkey,
    pub mint_b: Pubkey,
    pub vault_a: Pubkey,
    pub vault_b: Pubkey,
    pub reserve_a: u64,
    pub reserve_b: u64,
}

#[derive(Deserialize, Debug)]
pub struct QuoteRequest {
    /// Optional pool PDA pubkey (base58).
    ///
    /// If omitted/empty, the swap engine will derive the pool PDA from `mint_in`/`mint_out`
    /// using the on-chain seed scheme.
    #[serde(default)]
    pub pool: Option<String>,
    /// Input mint pubkey (base58).
    pub mint_in: String,
    /// Output mint pubkey (base58).
    pub mint_out: String,
    /// Amount in base units (u64).
    pub amount_in: u64,
}

impl QuoteRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        // Cheap "size first" guards to avoid pathological allocations in parsing.
        ensure_len_le("mint_in", self.mint_in.trim(), MAX_PUBKEY_B58_LEN)?;
        ensure_len_le("mint_out", self.mint_out.trim(), MAX_PUBKEY_B58_LEN)?;
        if let Some(p) = self.pool.as_deref() {
            let p = p.trim();
            if !p.is_empty() {
                ensure_len_le("pool", p, MAX_PUBKEY_B58_LEN)?;
            }
        }
        // Avoid obviously pointless quotes.
        if self.amount_in == 0 {
            return Err(AppError::BadRequest("amount_in must be > 0".into()));
        }
        Ok(())
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct QuoteResponse {
    /// Output amount in base units (u64).
    pub amount_out: u64,
    /// Spread applied to the quote, in basis points.
    ///
    /// This is the swap engine's quoting policy (LP protection). Larger trades / wider oracle
    /// confidence / staler prices can increase this number.
    pub spread_bps: u64,
    /// Inventory skew applied to the quote, in basis points.
    ///
    /// Positive means we improved the price for trades that *increase* the currently scarce asset.
    /// Negative means we worsened the price for trades that *decrease* the scarce asset.
    pub skew_bps: i64,
    /// Total signed bps delta applied to oracle mid for this quote.
    ///
    /// This is the actual delta used for the oracle-mid pricing step:
    /// - typically negative (spread/LP protection)
    /// - can be slightly positive when `rebalance_bonus_bps > 0` is applied
    pub policy_delta_bps: i64,
    /// Additional *positive* quoting bonus applied (in bps) to incentivize trades that
    /// move the pool closer to the oracle ("rebalancing incentive").
    ///
    /// This is separate from `skew_bps` (inventory skew) and is **0** when not applied.
    pub rebalance_bonus_bps: u64,
    /// Whether the implied trade price passes oracle band checks.
    pub price_ok: bool,
    /// Raw oracle details (optional; useful for debugging).
    pub oracle_details: Option<OracleDetails>,
}

#[derive(Serialize, Debug, Clone)]
pub struct OracleDetails {
    pub price_in: i64,
    pub conf_in: u64,
    pub expo_in: i32,
    pub price_out: i64,
    pub conf_out: u64,
    pub expo_out: i32,
    /// Oracle publish_time age (seconds) for debugging.
    pub age_in_secs: i64,
    pub age_out_secs: i64,
    /// USD-value imbalance in bps: (value_b - value_a)/(value_a+value_b) * 10_000
    pub imbalance_bps: i64,
}

#[derive(Deserialize, Debug)]
pub struct ExecuteRequest {
    /// Optional pool PDA pubkey (base58). If omitted, we derive it from `mint_in/mint_out`.
    #[serde(default)]
    pub pool: Option<String>,
    pub mint_in: String,
    pub mint_out: String,
    pub amount_in: u64,
    /// Minimum acceptable output amount (base units).
    ///
    /// Slippage tolerance is implemented by the client setting this below the last quoted output.
    /// The engine always executes at the **current** quote output and will reject if
    /// `current_quote_out < amount_out`.
    pub amount_out: u64,

    /// Commitment (previous leaf) to replace.
    pub previous_commitment_hex: String,

    /// (RECOMMENDED) Input note plaintext (asset note) used to bind `amount_in` to the commitment.
    ///
    /// Without this, a malicious client could submit a real `previous_commitment_hex` but lie about
    /// `amount_in`, potentially tricking the engine into signing an inconsistent reserve update.
    ///
    /// Format (must match frontend/relayer):
    ///   luminocity-asset-<mint>-<amount_base_units>-<nullifier_hex><secret_hex>
    #[serde(default)]
    pub input_note: Option<String>,

    /// (Engine-issued notes mode) Symmetric AES-256-GCM key (base64, 32 bytes).
    ///
    /// The engine uses this to encrypt the newly issued output note before publishing it
    /// on-chain (SwapEvent.encrypted_note). The client should persist this key locally so it can
    /// decrypt the ciphertext later.
    #[serde(default)]
    pub note_key_base64: Option<String>,

    /// (Engine-issued notes mode v2) Recipient X25519 public key (base64, 32 bytes).
    ///
    /// If provided, the engine will encrypt the note using an ephemeral X25519 keypair and publish:
    ///   eph_pub(32) || nonce(12) || ct+tag
    ///
    /// This supports deterministic recovery by deriving the X25519 private key from a wallet signature.
    #[serde(default)]
    pub note_pubkey_base64: Option<String>,

    /// (Optional, deprecated) New pool reserves in canonical order (pool.mint_a, pool.mint_b).
    ///
    /// The swap-engine computes reserves itself. These are ignored if provided.
    #[serde(default)]
    #[allow(dead_code)]
    pub new_reserve_a: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    pub new_reserve_b: Option<u64>,
}

impl ExecuteRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        ensure_len_le("mint_in", self.mint_in.trim(), MAX_PUBKEY_B58_LEN)?;
        ensure_len_le("mint_out", self.mint_out.trim(), MAX_PUBKEY_B58_LEN)?;
        if let Some(p) = self.pool.as_deref() {
            let p = p.trim();
            if !p.is_empty() {
                ensure_len_le("pool", p, MAX_PUBKEY_B58_LEN)?;
            }
        }
        if self.amount_in == 0 {
            return Err(AppError::BadRequest("amount_in must be > 0".into()));
        }
        // Slippage min_out can be 0 (caller says "any out"), so don't reject amount_out==0.
        ensure_hex32_len("previous_commitment_hex", &self.previous_commitment_hex)?;
        if let Some(s) = self.note_key_base64.as_deref() {
            ensure_len_le("note_key_base64", s.trim(), MAX_BASE64_STR_LEN)?;
        }
        if let Some(s) = self.note_pubkey_base64.as_deref() {
            ensure_len_le("note_pubkey_base64", s.trim(), MAX_BASE64_STR_LEN)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct ExecuteResponse {
    pub signature: String,
    /// Output amount that was actually executed (base units).
    #[serde(default)]
    pub amount_out: Option<u64>,
    /// Newly issued output note (plaintext). Returned for UX; ciphertext is also published on-chain.
    #[serde(default)]
    pub note: Option<String>,
    /// Base64 ciphertext that was published on-chain in SwapEvent.encrypted_note.
    #[serde(default)]
    pub encrypted_note_base64: Option<String>,
}

/// Response from tree-indexer `/proof/:commitment`
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct IndexerProofResponse {
    pub commitment_hex: String,
    pub leaf_index: u32,
    pub leaf_hex: String,
    pub root_hex: String,
    pub siblings_hex: Vec<String>,
    pub path_bits: Vec<u8>,
    pub depth: usize,
}

/// Must match `programs/solana-privacy-pool/src/types.rs::RfqSwapUpdate`
#[derive(Debug, Clone, Copy)]
pub struct RfqSwapUpdate {
    pub root: [u8; 32],
    pub previous_leaf: [u8; 32],
    pub new_leaf: [u8; 32],
    pub index: u32,
    pub new_reserve_a: u64,
    pub new_reserve_b: u64,
}
