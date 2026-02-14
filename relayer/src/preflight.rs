use crate::constants::MAX_DECRYPTED_JSON_BYTES;
use crate::error::{AppError, AppResult};
use crate::metrics;
use crate::state::AppState;
use crate::types::{BrowserInputs, BrowserLiquidityInputs, EncryptedRequest};
use crate::validation::{validate_browser_inputs, validate_browser_liquidity_inputs};
use ecies::decrypt;
use solana_sdk::program_pack::Pack;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use std::sync::Arc;

pub async fn spam_guard_before_job(state: &Arc<AppState>) -> AppResult<()> {
    // Spam/backlog guard (avoid unbounded job memory growth / DoS).
    let max_jobs = std::env::var("RELAYER_MAX_JOBS_IN_MEMORY")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2_000) as usize;
    let jobs_len = state.jobs.read().await.len();
    if jobs_len >= max_jobs {
        return Err(AppError::TooManyRequests(format!(
            "relayer job backlog too large (jobs_in_memory={} max={})",
            jobs_len, max_jobs
        )));
    }
    Ok(())
}

/// Fail-fast user payload preflight (no proving, no RPC).
pub fn preflight_user_payload_withdraw(
    state: &Arc<AppState>,
    payload: &EncryptedRequest,
) -> AppResult<BrowserInputs> {
    payload.validate()?;
    let encrypted_bytes = hex::decode(payload.encrypted_blob.trim())
        .map_err(|_| AppError::BadRequest("Invalid hex in encrypted_blob".into()))?;
    let secret_bytes = state.tee_secret.serialize();
    let decrypted = decrypt(&secret_bytes, &encrypted_bytes)
        .map_err(|e| AppError::BadRequest(format!("ECIES decryption failed: {}", e)))?;
    if decrypted.len() > MAX_DECRYPTED_JSON_BYTES {
        return Err(AppError::BadRequest(format!(
            "decrypted payload too large: {} bytes (max {})",
            decrypted.len(),
            MAX_DECRYPTED_JSON_BYTES
        )));
    }
    let browser_inputs: BrowserInputs = serde_json::from_slice(&decrypted)
        .map_err(|_| AppError::BadRequest("Decrypted payload is not valid JSON".into()))?;
    validate_browser_inputs(&browser_inputs)?;
    Ok(browser_inputs)
}

pub fn preflight_user_payload_liquidity(
    state: &Arc<AppState>,
    payload: &EncryptedRequest,
) -> AppResult<()> {
    payload.validate()?;
    let encrypted_bytes = hex::decode(payload.encrypted_blob.trim())
        .map_err(|_| AppError::BadRequest("Invalid hex in encrypted_blob".into()))?;
    let secret_bytes = state.tee_secret.serialize();
    let decrypted = decrypt(&secret_bytes, &encrypted_bytes)
        .map_err(|e| AppError::BadRequest(format!("ECIES decryption failed: {}", e)))?;
    if decrypted.len() > MAX_DECRYPTED_JSON_BYTES {
        return Err(AppError::BadRequest(format!(
            "decrypted payload too large: {} bytes (max {})",
            decrypted.len(),
            MAX_DECRYPTED_JSON_BYTES
        )));
    }
    let browser_inputs: BrowserLiquidityInputs = serde_json::from_slice(&decrypted)
        .map_err(|_| AppError::BadRequest("Decrypted payload is not valid JSON".into()))?;
    validate_browser_liquidity_inputs(&browser_inputs)?;
    Ok(())
}

pub fn record_bad_payload() {
    metrics::inc_bad_payload_total();
}

/// Additional withdraw preflight that does a single cheap-ish RPC check:
/// ensure the recipient token account is an SPL Token account for the correct mint.
///
/// This prevents wasting proof generation on requests that would inevitably fail during tx simulation.
pub async fn preflight_withdraw_recipient_account(
    state: &Arc<AppState>,
    browser_inputs: &BrowserInputs,
) -> AppResult<()> {
    let mint_pubkey = Pubkey::from_str(browser_inputs.mint.trim())
        .map_err(|_| AppError::BadRequest("Invalid mint".into()))?;
    let recipient_pubkey = Pubkey::from_str(browser_inputs.recipient.trim()).map_err(|_| {
        AppError::BadRequest("Invalid recipient token account pubkey".into())
    })?;

    if browser_inputs.sol_destination.is_some() {
        return Err(AppError::BadRequest(
            "sol_destination is no longer supported: withdraw WSOL to a WSOL token account and unwrap client-side"
                .into(),
        ));
    }

    // Normal withdraw: recipient must exist and be a token account for the mint.
    let rpc = state.rpc.clone();
    let acc = tokio::task::spawn_blocking(move || rpc.get_account(&recipient_pubkey))
        .await
        .map_err(|_| AppError::BadGateway("recipient account fetch task failed".into()))?
        .map_err(|e| AppError::BadGateway(format!("recipient token account fetch failed: {e}")))?;

    let token_program_id = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        .expect("static token program id");
    if acc.owner != token_program_id {
        return Err(AppError::BadRequest(format!(
            "recipient token account must be owned by SPL Token program (expected {} got {})",
            token_program_id, acc.owner
        )));
    }
    let ta = spl_token::state::Account::unpack(&acc.data)
        .map_err(|_| AppError::BadRequest("failed to decode recipient token account".into()))?;
    if ta.mint != mint_pubkey {
        return Err(AppError::BadRequest(format!(
            "recipient token account mint mismatch (expected {} got {})",
            mint_pubkey, ta.mint
        )));
    }
    Ok(())
}
