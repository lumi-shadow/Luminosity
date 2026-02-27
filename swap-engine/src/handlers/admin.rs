use crate::state::{AppState, JupiterSwapDebugEntry};
use crate::types::{api_err, ApiResult, AppError, ErrorBody};
use axum::extract::State;
use axum::Json;
use solana_sdk::signature::{Keypair, Signer};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tracing::{info, warn};

pub async fn volatility_status(
    State(st): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let mut feeds = serde_json::Map::new();
    for (mint, feed_id) in &st.cfg.hermes_feed_ids {
        let (sigma, momentum) = crate::volatility::read_vol(feed_id);
        feeds.insert(feed_id.chars().take(12).collect::<String>(), serde_json::json!({
            "mint": mint.to_string(),
            "sigma_bps": sigma,
            "momentum_bps": momentum,
        }));
    }
    Ok(Json(serde_json::json!({ "feeds": feeds })))
}

#[derive(serde::Deserialize)]
pub struct UploadKeyRequest {
    /// Hex-encoded 64-byte Solana keypair (secret + public) produced by Keypair::to_bytes().
    pub private_key: String,
}

pub async fn upload_key(
    State(st): State<AppState>,
    Json(req): Json<UploadKeyRequest>,
) -> ApiResult<serde_json::Value> {
    // Input caps: prevent pathological strings from reaching hex decode.
    const MAX_KEYPAIR_HEX_LEN: usize = 2 + 128; // optional 0x + 64-byte keypair
    if req.private_key.len() > MAX_KEYPAIR_HEX_LEN {
        return api_err(AppError::BadRequest(format!(
            "private_key too long: {} chars (max {MAX_KEYPAIR_HEX_LEN})",
            req.private_key.len()
        )));
    }

    // Seal TEE keypair: can be set only once.
    let mut tee_guard = st.tee_keypair.lock().map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                message: "mutex poisoned".into(),
            }),
        )
    })?;
    if tee_guard.is_some() {
        return api_err(AppError::Forbidden(
            "swap-engine is already initialized (tee key already set)".into(),
        ));
    }

    let key_bytes = hex::decode(req.private_key.trim_start_matches("0x"))
        .map_err(|_| AppError::BadRequest("invalid hex in private_key".into()))
        .and_then(|b| Keypair::try_from(b.as_slice()).map_err(|_| AppError::BadRequest("invalid keypair bytes".into())));
    let tee_kp = match key_bytes {
        Ok(k) => Arc::new(k),
        Err(e) => return api_err(e),
    };
    *tee_guard = Some(tee_kp.clone());

    // Start/seed TEE balance cache immediately after runtime key provisioning.
    // Without this, RFQ quote path can keep reading zero inventory from the atomic cache.
    let maker = tee_kp.pubkey();
    match crate::solana::fetch_registry_pools(&st.rpc_confirmed, &st.cfg.program_id) {
        Ok(pools) => {
            if let Some(first_pool) = pools.first() {
                match crate::solana::fetch_pool(&st.rpc_confirmed, first_pool) {
                    Ok(pool) => {
                        crate::solana::spawn_tee_balance_refresher(
                            Arc::clone(&st.rpc_confirmed),
                            maker,
                            pool.mint_a,
                            pool.mint_b,
                            std::time::Duration::from_secs(2),
                        );
                        info!("started TEE balance refresher after key upload (maker={})", maker);
                    }
                    Err(e) => {
                        warn!("upload-key: failed to fetch first pool for balance refresher: {e}");
                    }
                }
            } else {
                warn!("upload-key: registry has no pools; TEE balance refresher not started");
            }
        }
        Err(e) => {
            warn!("upload-key: failed to fetch registry pools for balance refresher: {e}");
        }
    }

    Ok(Json(serde_json::json!({
        "status": "initialized",
        "tee_pubkey": tee_kp.pubkey().to_string(),
    })))
}

#[derive(serde::Serialize)]
pub struct JupiterLatencySnapshot {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

#[derive(serde::Serialize)]
pub struct JupiterStatusResponse {
    pub enabled: bool,
    pub quote_requests_total: u64,
    pub quote_success_total: u64,
    pub swap_requests_total: u64,
    pub swap_success_total: u64,
    pub swap_failed_total: u64,
    pub fills_total: u64,
    pub fill_rate: f64,
    pub volume_in_base_total: u64,
    pub volume_out_base_total: u64,
    pub bundle_submitted_total: u64,
    pub bundle_landed_total: u64,
    pub bundle_failed_total: u64,
    pub bundle_success_rate: f64,
    pub quote_latency: JupiterLatencySnapshot,
    pub swap_latency: JupiterLatencySnapshot,
    pub last_swap_errors: Vec<String>,
    pub last_swap_debug: Vec<JupiterSwapDebugEntry>,
}

fn percentile(vals: &[u64], p: f64) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    let mut s = vals.to_vec();
    s.sort_unstable();
    let idx = ((p.clamp(0.0, 1.0) * (s.len().saturating_sub(1) as f64)).round()) as usize;
    s[idx] as f64
}

pub async fn jupiter_status(State(st): State<AppState>) -> ApiResult<JupiterStatusResponse> {
    let js = &st.jupiter_stats;
    let quote_requests_total = js.quote_requests.load(Ordering::Relaxed);
    let quote_success_total = js.quote_success.load(Ordering::Relaxed);
    let swap_requests_total = js.swap_requests.load(Ordering::Relaxed);
    let swap_success_total = js.swap_success.load(Ordering::Relaxed);
    let swap_failed_total = js.swap_failed.load(Ordering::Relaxed);
    let fills_total = js.fills_total.load(Ordering::Relaxed);
    let volume_in_base_total = js.volume_in_base_total.load(Ordering::Relaxed);
    let volume_out_base_total = js.volume_out_base_total.load(Ordering::Relaxed);
    let bundle_submitted_total = js.bundle_submitted_total.load(Ordering::Relaxed);
    let bundle_landed_total = js.bundle_landed_total.load(Ordering::Relaxed);
    let bundle_failed_total = js.bundle_failed_total.load(Ordering::Relaxed);

    let fill_rate = if quote_success_total == 0 {
        0.0
    } else {
        (fills_total as f64) / (quote_success_total as f64)
    };
    let bundle_denom = bundle_submitted_total.saturating_add(bundle_failed_total);
    let bundle_success_rate = if bundle_denom == 0 {
        0.0
    } else {
        (bundle_submitted_total as f64) / (bundle_denom as f64)
    };

    let last_swap_errors = match js.last_swap_errors.lock() {
        Ok(g) => g.iter().cloned().collect::<Vec<String>>(),
        Err(_) => vec![],
    };
    let last_swap_debug = match js.last_swap_debug.lock() {
        Ok(g) => g.iter().cloned().collect::<Vec<JupiterSwapDebugEntry>>(),
        Err(_) => vec![],
    };

    let quote_latency_vals = match js.quote_latency_ms.lock() {
        Ok(g) => g.iter().copied().collect::<Vec<u64>>(),
        Err(_) => return api_err(AppError::BadGateway("jupiter quote latency lock poisoned".into())),
    };
    let swap_latency_vals = match js.swap_latency_ms.lock() {
        Ok(g) => g.iter().copied().collect::<Vec<u64>>(),
        Err(_) => return api_err(AppError::BadGateway("jupiter swap latency lock poisoned".into())),
    };

    Ok(Json(JupiterStatusResponse {
        enabled: st.cfg.jupiter_enabled,
        quote_requests_total,
        quote_success_total,
        swap_requests_total,
        swap_success_total,
        swap_failed_total,
        fills_total,
        fill_rate,
        volume_in_base_total,
        volume_out_base_total,
        bundle_submitted_total,
        bundle_landed_total,
        bundle_failed_total,
        bundle_success_rate,
        quote_latency: JupiterLatencySnapshot {
            p50_ms: percentile(&quote_latency_vals, 0.50),
            p95_ms: percentile(&quote_latency_vals, 0.95),
            p99_ms: percentile(&quote_latency_vals, 0.99),
        },
        swap_latency: JupiterLatencySnapshot {
            p50_ms: percentile(&swap_latency_vals, 0.50),
            p95_ms: percentile(&swap_latency_vals, 0.95),
            p99_ms: percentile(&swap_latency_vals, 0.99),
        },
        last_swap_errors,
        last_swap_debug,
    }))
}

