use crate::constants::{MAX_HEX_32_STR_LEN, MAX_PUBKEY_B58_LEN};
use crate::error::AppError;
use crate::types::{BrowserInputs, BrowserLiquidityInputs};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

pub fn ensure_len_le(field: &str, s: &str, max: usize) -> Result<(), AppError> {
    if s.len() > max {
        return Err(AppError::BadRequest(format!(
            "{field} too long: {} chars (max {max})",
            s.len()
        )));
    }
    Ok(())
}

pub fn ensure_hex32_len(field: &str, s: &str) -> Result<(), AppError> {
    let t = s.trim();
    ensure_len_le(field, t, MAX_HEX_32_STR_LEN)?;
    let t = t.trim_start_matches("0x");
    if t.len() != 64 {
        return Err(AppError::BadRequest(format!(
            "{field} must be 32-byte hex (64 chars), got {} chars",
            t.len()
        )));
    }
    Ok(())
}

pub fn ensure_pubkey_len(field: &str, s: &str) -> Result<(), AppError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(AppError::BadRequest(format!("{field} is required")));
    }
    ensure_len_le(field, t, MAX_PUBKEY_B58_LEN)
}

pub fn validate_browser_inputs(x: &BrowserInputs) -> Result<(), AppError> {
    ensure_hex32_len("nullifier", &x.nullifier)?;
    ensure_hex32_len("secret", &x.secret)?;
    ensure_pubkey_len("recipient", &x.recipient)?;
    ensure_pubkey_len("mint", &x.mint)?;
    if x.amount == 0 {
        return Err(AppError::BadRequest("amount must be > 0".into()));
    }
    // Semantic parse checks (not just length).
    let _ = Pubkey::from_str(x.recipient.trim())
        .map_err(|_| AppError::BadRequest("Invalid recipient pubkey".into()))?;
    let _ = Pubkey::from_str(x.mint.trim())
        .map_err(|_| AppError::BadRequest("Invalid mint pubkey".into()))?;
    // Ensure hex actually decodes to 32 bytes (prevents pathological strings).
    let n = hex::decode(x.nullifier.trim_start_matches("0x"))
        .map_err(|_| AppError::BadRequest("Invalid hex in nullifier".into()))?;
    if n.len() != 32 {
        return Err(AppError::BadRequest("nullifier must be 32 bytes".into()));
    }
    let s = hex::decode(x.secret.trim_start_matches("0x"))
        .map_err(|_| AppError::BadRequest("Invalid hex in secret".into()))?;
    if s.len() != 32 {
        return Err(AppError::BadRequest("secret must be 32 bytes".into()));
    }
    Ok(())
}

pub fn validate_browser_liquidity_inputs(x: &BrowserLiquidityInputs) -> Result<(), AppError> {
    ensure_hex32_len("nullifier", &x.nullifier)?;
    ensure_hex32_len("secret", &x.secret)?;
    ensure_pubkey_len("recipient_owner", &x.recipient_owner)?;
    ensure_pubkey_len("mint_a", &x.mint_a)?;
    ensure_pubkey_len("mint_b", &x.mint_b)?;
    if x.shares == 0 {
        return Err(AppError::BadRequest("shares must be > 0".into()));
    }
    // Program currently enforces TokenRelayerFeeNotSupported for liquidity withdraws.
    if x.fee != 0 {
        return Err(AppError::BadRequest(
            "fee must be 0 for liquidity withdraw".into(),
        ));
    }
    let _ = Pubkey::from_str(x.recipient_owner.trim())
        .map_err(|_| AppError::BadRequest("Invalid recipient_owner pubkey".into()))?;
    let mint_a = Pubkey::from_str(x.mint_a.trim())
        .map_err(|_| AppError::BadRequest("Invalid mint_a pubkey".into()))?;
    let mint_b = Pubkey::from_str(x.mint_b.trim())
        .map_err(|_| AppError::BadRequest("Invalid mint_b pubkey".into()))?;
    if mint_a == mint_b {
        return Err(AppError::BadRequest("mint_a and mint_b must differ".into()));
    }
    let n = hex::decode(x.nullifier.trim_start_matches("0x"))
        .map_err(|_| AppError::BadRequest("Invalid hex in nullifier".into()))?;
    if n.len() != 32 {
        return Err(AppError::BadRequest("nullifier must be 32 bytes".into()));
    }
    let s = hex::decode(x.secret.trim_start_matches("0x"))
        .map_err(|_| AppError::BadRequest("Invalid hex in secret".into()))?;
    if s.len() != 32 {
        return Err(AppError::BadRequest("secret must be 32 bytes".into()));
    }
    Ok(())
}
