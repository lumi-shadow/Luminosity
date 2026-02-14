//! Client for `tree-indexer` HTTP API.
//!
//! We currently only need:
//! - `/proof/:commitment` to obtain:
//!   - the **on-chain root** (not the mirror root)
//!   - siblings for Merkle proof
//!   - leaf index
//!
//! The indexer is treated as the primary source of truth for proofs/roots.

use crate::http_client::{http_get_json, http_post_json, parse_http_base};
use crate::types::{AppError, IndexerProofResponse};
use hex::FromHex;

pub struct IndexerClient {
    host: String,
    port: u16,
    prefix: String,
    admin_token: String,
}

impl IndexerClient {
    pub fn new(base: &str, admin_token: String) -> Result<Self, AppError> {
        let (host, port, prefix) = parse_http_base(base)?;
        Ok(Self {
            host,
            port,
            prefix,
            admin_token,
        })
    }

    pub fn get_proof_by_commitment_hex(
        &self,
        commitment_hex: &str,
    ) -> Result<IndexerProofResponse, AppError> {
        // The indexer accepts either `0x...` or raw hex. We normalize to `0x...`.
        let commitment_hex = commitment_hex.trim_start_matches("0x");
        let path = format!("{}/proof/0x{}", self.prefix, commitment_hex);
        let mut did_self_heal = false;
        let (mut status, mut body) =
            http_get_json(&self.host, self.port, &path, Some(&self.admin_token))?;
        if status == 403 {
            // IP not allowlisted. Try to self-register, then retry once.
            self.allowlist_self()?;
            did_self_heal = true;
            (status, body) = http_get_json(&self.host, self.port, &path, Some(&self.admin_token))?;
        }
        if status != 200 {
            let msg = String::from_utf8_lossy(&body).to_string();
            let hint = if did_self_heal {
                " (after allowlist self-heal)"
            } else {
                ""
            };
            return Err(AppError::BadGateway(format!(
                "indexer /proof failed ({status}){hint}: {msg}"
            )));
        }
        serde_json::from_slice::<IndexerProofResponse>(&body)
            .map_err(|e| AppError::BadGateway(format!("indexer JSON parse failed: {e}")))
    }

    fn allowlist_self(&self) -> Result<(), AppError> {
        let path = format!("{}/admin/allowlist/self", self.prefix);
        let (status, body) = http_post_json(&self.host, self.port, &path, Some(&self.admin_token), b"{}")?;
        if status != 200 {
            let msg = String::from_utf8_lossy(&body).to_string();
            return Err(AppError::BadGateway(format!(
                "indexer allowlist self failed ({status}): {msg}"
            )));
        }
        Ok(())
    }
}

/// Parse a 32-byte hex string into `[u8; 32]`.
///
/// This is used for:
/// - commitments (leaves)
/// - roots
/// - proof siblings
pub fn hex32(s: &str) -> Result<[u8; 32], AppError> {
    let s = s.trim_start_matches("0x");
    let v = Vec::from_hex(s).map_err(|e| AppError::BadRequest(format!("invalid hex: {e}")))?;
    if v.len() != 32 {
        return Err(AppError::BadRequest(format!(
            "expected 32 bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}
