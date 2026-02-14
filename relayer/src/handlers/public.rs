use crate::constants::{
    DEFAULT_RAPIDSNARK_PATH, DEFAULT_WITHDRAW_WASM_PATH, DEFAULT_WITHDRAW_WITNESS_BIN,
    DEFAULT_WITHDRAW_WITNESS_JS, DEFAULT_WITHDRAW_ZKEY_PATH,
};
use crate::error::AppResult;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::Json as AxumJson;
use solana_sdk::signature::Signer;
use std::env;
use std::sync::Arc;

pub async fn get_tee_key(
    State(state): State<Arc<AppState>>,
) -> AppResult<AxumJson<serde_json::Value>> {
    let pk_hex = hex::encode(state.tee_public.serialize());
    Ok(AxumJson(serde_json::json!({ "tee_public_key": pk_hex })))
}

#[derive(serde::Deserialize)]
pub struct FeeQuery {
    // Backward-compat: legacy query param name.
    // Historically used for withdraw "amount" (u64 base units) even when the mint was not SOL.
    #[serde(rename = "amountLamports")]
    pub amount_lamports: Option<u64>,

    /// New API: operation selector.
    /// - deposit / deposit_asset
    /// - withdraw / withdraw_asset
    pub op: Option<String>,
    /// New API: asset mint (base58).
    pub mint: Option<String>,
    /// New API: amount in base units (u64).
    pub amount: Option<u64>,
}

pub async fn get_fee(
    State(state): State<Arc<AppState>>,
    Query(q): Query<FeeQuery>,
) -> AppResult<AxumJson<serde_json::Value>> {
    // New: USD-model fee quote when op+mint+amount are provided.
    if let (Some(op_str), Some(mint_str), Some(amount)) =
        (q.op.as_deref(), q.mint.as_deref(), q.amount)
    {
        let op = crate::pricing::FeeOp::parse(op_str)
            .ok_or_else(|| crate::error::AppError::BadRequest("Invalid op".into()))?;
        let quote = crate::pricing::quote_fee(state, op, mint_str, amount).await?;
        return Ok(AxumJson(serde_json::json!({
            "op": match quote.op { crate::pricing::FeeOp::DepositAsset => "deposit_asset", crate::pricing::FeeOp::WithdrawAsset => "withdraw_asset" },
            "mint": quote.mint.to_string(),
            "amount": quote.amount,
            "fee_amount": quote.fee_amount,
            "fee_waived": quote.fee_waived,
            "min_amount": quote.min_amount,
            "allowed": quote.allowed,
            "fee_usd_micro": quote.fee_usd_micro,
            "price_usd_micro": quote.price_usd_micro,
            "decimals": quote.decimals,
        })));
    }

    // Legacy: bps-only fee, for older clients.
    let fee_bps = crate::utils::relayer_fee_bps_from_env()
        .unwrap_or(crate::constants::DEFAULT_RELAYER_FEE_BPS);

    // If amount is provided, return the computed feeLamports for that amount.
    if let Some(amount) = q.amount_lamports {
        let fee = crate::utils::compute_relayer_fee_lamports(amount);
        return Ok(AxumJson(serde_json::json!({
            "feeBps": fee_bps,
            "amountLamports": amount,
            "feeLamports": fee
        })));
    }

    Ok(AxumJson(serde_json::json!({ "feeBps": fee_bps })))
}

pub async fn fee_health(
    State(state): State<Arc<AppState>>,
) -> AppResult<AxumJson<serde_json::Value>> {
    let (hermes_url, feeds) = crate::pricing::configured_hermes_feeds()?;
    let max_stale_secs: u64 = std::env::var("FEE_ORACLE_MAX_STALENESS_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(600);

    let now = crate::utils::now_ms();
    let price_cache = state.price_cache.lock().unwrap();
    let dec_cache = state.mint_decimals_cache.lock().unwrap();

    let mut mints: Vec<serde_json::Value> = Vec::new();
    for (mint, feed_id) in feeds {
        let cached_price = price_cache.get(&mint);
        let cached_dec = dec_cache.get(&mint).copied();
        let cached_age_ms = cached_price.map(|p| now.saturating_sub(p.fetched_ts_ms) as u64);
        let cached_fresh = cached_age_ms
            .map(|ms| ms <= max_stale_secs.saturating_mul(1000))
            .unwrap_or(false);
        mints.push(serde_json::json!({
            "mint": mint.to_string(),
            "feed_id_hex": feed_id,
            "decimals_cached": cached_dec,
            "price_cached": cached_price.is_some(),
            "price_usd_micro": cached_price.map(|p| p.usd_micro),
            "price_cached_age_ms": cached_age_ms,
            "price_cached_fresh": cached_fresh,
        }));
    }

    Ok(AxumJson(serde_json::json!({
        "hermes_url": hermes_url,
        "fee_oracle_max_staleness_secs": max_stale_secs,
        "mints": mints,
    })))
}

pub async fn readiness(
    State(state): State<Arc<AppState>>,
) -> AppResult<AxumJson<serde_json::Value>> {
    let ready = state.has_wallet();
    let wasm_path =
        env::var("WITHDRAW_WASM_PATH").unwrap_or_else(|_| DEFAULT_WITHDRAW_WASM_PATH.to_string());
    let witness_js =
        env::var("WITHDRAW_WITNESS_JS").unwrap_or_else(|_| DEFAULT_WITHDRAW_WITNESS_JS.to_string());
    let witness_bin = env::var("WITHDRAW_WITNESS_BIN")
        .unwrap_or_else(|_| DEFAULT_WITHDRAW_WITNESS_BIN.to_string());
    let zkey_path =
        env::var("WITHDRAW_ZKEY_PATH").unwrap_or_else(|_| DEFAULT_WITHDRAW_ZKEY_PATH.to_string());
    let rapidsnark_path =
        env::var("RAPIDSNARK_PATH").unwrap_or_else(|_| DEFAULT_RAPIDSNARK_PATH.to_string());

    let wasm_meta = std::fs::metadata(&wasm_path).ok();
    let witness_meta = std::fs::metadata(&witness_js).ok();
    let witness_bin_meta = std::fs::metadata(&witness_bin).ok();
    let zkey_meta = std::fs::metadata(&zkey_path).ok();
    let rapidsnark_meta = std::fs::metadata(&rapidsnark_path).ok();

    // Also expose relayer pubkey if provisioned (helps ops).
    let relayer_pubkey = state
        .relayer_wallet
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|k| k.pubkey().to_string()));

    Ok(AxumJson(serde_json::json!({
        "ready": ready,
        "relayer_pubkey": relayer_pubkey,
        "artifacts": {
            "withdraw_wasm_path": wasm_path,
            "withdraw_witness_js": witness_js,
            "withdraw_witness_bin": witness_bin,
            "withdraw_zkey_path": zkey_path,
            "rapidsnark_path": rapidsnark_path,
            "withdraw_wasm_ok": wasm_meta.as_ref().map(|m| m.is_file() && m.len() > 0).unwrap_or(false),
            "withdraw_witness_js_ok": witness_meta.as_ref().map(|m| m.is_file() && m.len() > 0).unwrap_or(false),
            "withdraw_witness_bin_ok": witness_bin_meta.as_ref().map(|m| m.is_file() && m.len() > 0).unwrap_or(false),
            "withdraw_zkey_ok": zkey_meta.as_ref().map(|m| m.is_file() && m.len() > 0).unwrap_or(false),
            "rapidsnark_ok": rapidsnark_meta.as_ref().map(|m| m.is_file() && m.len() > 0).unwrap_or(false),
            "withdraw_wasm_bytes": wasm_meta.as_ref().map(|m| m.len()),
            "withdraw_witness_js_bytes": witness_meta.as_ref().map(|m| m.len()),
            "withdraw_witness_bin_bytes": witness_bin_meta.as_ref().map(|m| m.len()),
            "withdraw_zkey_bytes": zkey_meta.as_ref().map(|m| m.len()),
            "rapidsnark_bytes": rapidsnark_meta.as_ref().map(|m| m.len()),
        }
    })))
}
