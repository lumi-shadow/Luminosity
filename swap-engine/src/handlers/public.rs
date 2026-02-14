use crate::engine;
use crate::metrics;
use crate::rate_limit;
use crate::solvency;
use crate::state::{AppState, ExecuteJob};
use crate::types::{api_err, ApiResult, AppError, ExecuteRequest, ExecuteResponse, QuoteRequest, QuoteResponse};
use crate::utils;
use axum::{
    extract::ConnectInfo,
    extract::State,
    Json,
};
use std::time::Instant;
use std::time::Duration;
use std::str::FromStr;

pub async fn health() -> &'static str {
    "ok"
}

/// Solvency overview endpoint (production-friendly, read-only).
///
/// IMPORTANT:
/// - Vaults are shared per mint across all pools and also back asset notes.
/// - Therefore we report:
///   - per-pool headroom: vault_balance - pool.reserve (must be >= 0 to back that pool)
///   - per-mint reserved sum across pools (must be <= vault balance to avoid double-counting)
///   - free_for_asset_notes = vault_balance - reserved_sum (upper bound of what can back asset notes)
pub async fn health_solvency(State(st): State<AppState>) -> ApiResult<crate::solvency::SolvencyResponse> {
    match solvency::compute_solvency(solvency::ComputeSolvencyParams {
        rpc: &st.rpc_confirmed,
        program_id: st.cfg.program_id,
        indexer_url: st.cfg.indexer_url.clone(),
    }) {
        Ok(v) => Ok(Json(v)),
        Err(e) => api_err(e),
    }
}

#[derive(serde::Serialize)]
pub struct ReadyResponse {
    pub ready: bool,
    pub has_tee_key: bool,
}

pub async fn ready(State(st): State<AppState>) -> ApiResult<ReadyResponse> {
    let has_tee_key = st.tee_keypair.lock().map(|g| g.is_some()).unwrap_or(false);
    // "ready" means we can accept execute requests.
    // Quote can still work without keys (read-only).
    Ok(Json(ReadyResponse {
        ready: has_tee_key,
        has_tee_key,
    }))
}

#[derive(serde::Serialize)]
pub struct PoolInfo {
    pub pool: String,
    pub mint_a: String,
    pub mint_b: String,
    pub reserve_a: u64,
    pub reserve_b: u64,
}

/// List pools discovered from the on-chain Registry PDA.
pub async fn pools(State(st): State<AppState>) -> ApiResult<Vec<PoolInfo>> {
    let pools = match crate::solana::fetch_registry_pools(&st.rpc_confirmed, &st.cfg.program_id) {
        Ok(v) => v,
        Err(e) => return api_err(e),
    };

    let mut out = Vec::new();
    for pk in pools {
        // Skip empty/default entries (unregistered pool_id slots).
        if pk == solana_sdk::pubkey::Pubkey::default() {
            continue;
        }
        let p = match crate::solana::fetch_pool(&st.rpc_confirmed, &pk) {
            Ok(v) => v,
            Err(e) => return api_err(e),
        };
        out.push(PoolInfo {
            pool: pk.to_string(),
            mint_a: p.mint_a.to_string(),
            mint_b: p.mint_b.to_string(),
            reserve_a: p.reserve_a,
            reserve_b: p.reserve_b,
        });
    }

    Ok(Json(out))
}

/// Quote endpoint.
///
/// This is intentionally deterministic and side-effect free:
/// - reads pool virtual reserves from chain
/// - computes constant-product quote
/// - reads oracle prices (Pyth) and checks the implied price is within a confidence-expanded band
pub async fn quote(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<QuoteRequest>,
) -> ApiResult<QuoteResponse> {
    let t0 = Instant::now();
    metrics::metrics().quote_requests_total.inc();
    if let Err(e) = req.validate() {
        metrics::metrics().bad_payload_total.inc();
        if let Err(rl) = rate_limit::rate_limit_bad(&st, peer.ip()).await {
            metrics::metrics().rate_limited_total.inc();
            return api_err(rl);
        }
        return api_err(e);
    }
    if let Err(rl) = rate_limit::rate_limit_ok(&st, peer.ip()).await {
        metrics::metrics().rate_limited_total.inc();
        return api_err(rl);
    }
    let res = engine::quote(&st.cfg, &st.http, st.rpc_processed.clone(), req).await;
    metrics::metrics()
        .quote_ms
        .observe(t0.elapsed().as_millis() as f64);
    match res {
        Ok(v) => Ok(Json(v)),
        Err(e) => {
            metrics::metrics().quote_errors_total.inc();
            if matches!(e, AppError::BadRequest(_)) {
                metrics::metrics().bad_requests_total.inc();
                if let Err(rl) = rate_limit::rate_limit_bad(&st, peer.ip()).await {
                    metrics::metrics().rate_limited_total.inc();
                    return api_err(rl);
                }
            }
            api_err(e)
        }
    }
}

/// Execute endpoint.
///
/// High-level steps:
/// - run the same oracle checks as `quote` (and fail closed)
/// - ask the local `tree-indexer` for `/proof/:commitment` of the leaf we want to replace
/// - submit `execute_rfq_swap` (Anchor instruction) with:
///   - `RfqSwapUpdate` args
///   - encrypted note ciphertext (published in the on-chain `SwapEvent`)
///   - Merkle proof nodes as `remaining_accounts`
pub async fn execute(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<ExecuteRequest>,
) -> ApiResult<ExecuteResponse> {
    let t0 = Instant::now();
    metrics::metrics().execute_requests_total.inc();
    if let Err(e) = req.validate() {
        metrics::metrics().bad_payload_total.inc();
        if let Err(rl) = rate_limit::rate_limit_bad(&st, peer.ip()).await {
            metrics::metrics().rate_limited_total.inc();
            return api_err(rl);
        }
        return api_err(e);
    }
    if let Err(rl) = rate_limit::rate_limit_ok(&st, peer.ip()).await {
        metrics::metrics().rate_limited_total.inc();
        return api_err(rl);
    }
    metrics::metrics().jobs_accepted_total.inc();
    // Cap concurrent executes (expensive: RPC + indexer + tx submit).
    // Configure with SWAP_ENGINE_MAX_CONCURRENT_EXECUTE (default 2).
    let permit = match st.execute_semaphore.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => {
            return api_err(AppError::Unavailable(
                "execute concurrency limiter closed".into(),
            ))
        }
    };
    // Keys must be provisioned before executing swaps.
    let tee = {
        let g = st.tee_keypair.lock().unwrap();
        g.clone()
    };
    let Some(tee) = tee else {
        drop(permit);
        return api_err(AppError::Unavailable(
            "swap-engine not initialized (missing TEE key; call /upload-key)".into(),
        ));
    };

    let res = engine::execute(&st.cfg, &st.http, st.rpc_confirmed.clone(), req, &tee).await;
    metrics::metrics()
        .execute_ms
        .observe(t0.elapsed().as_millis() as f64);
    drop(permit);
    match res {
        Ok(v) => Ok(Json(v)),
        Err(e) => {
            metrics::metrics().execute_errors_total.inc();
            if matches!(e, AppError::BadRequest(_)) {
                metrics::metrics().bad_requests_total.inc();
                if let Err(rl) = rate_limit::rate_limit_bad(&st, peer.ip()).await {
                    metrics::metrics().rate_limited_total.inc();
                    return api_err(rl);
                }
            }
            api_err(e)
        }
    }
}

/// Job-based execute endpoint: returns immediately with a `job_id`.
/// The swap-engine continues executing even if the HTTP client disconnects.
pub async fn execute_job(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<ExecuteRequest>,
) -> ApiResult<serde_json::Value> {
    if let Err(e) = req.validate() {
        metrics::metrics().bad_payload_total.inc();
        if let Err(rl) = rate_limit::rate_limit_bad(&st, peer.ip()).await {
            metrics::metrics().rate_limited_total.inc();
            return api_err(rl);
        }
        return api_err(e);
    }
    // Backlog guard (prevents unbounded job memory growth / DoS).
    let max_jobs = std::env::var("SWAP_ENGINE_MAX_JOBS_IN_MEMORY")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2_000) as usize;
    let jobs_len = st.jobs.read().await.len();
    if jobs_len >= max_jobs {
        return api_err(AppError::TooManyRequests(format!(
            "swap-engine job backlog too large (jobs_in_memory={} max={})",
            jobs_len, max_jobs
        )));
    }
    if let Err(rl) = rate_limit::rate_limit_ok(&st, peer.ip()).await {
        metrics::metrics().rate_limited_total.inc();
        return api_err(rl);
    }
    metrics::metrics().jobs_accepted_total.inc();
    let job_id = utils::new_job_id(&st);
    let peer_ip = peer.ip();
    {
        let mut jobs = st.jobs.write().await;
        jobs.insert(
            job_id.clone(),
            ExecuteJob {
                id: job_id.clone(),
                status: "queued".into(),
                created_ts_ms: utils::now_ms(),
                started_ts_ms: None,
                finished_ts_ms: None,
                signature: None,
                result: None,
                error: None,
            },
        );
        utils::prune_jobs(&mut jobs, 2000);
    }

    let st_bg = st.clone();
    let job_id_bg = job_id.clone();
    tokio::spawn(async move {
        // Cap concurrent executes (expensive: RPC + indexer + tx submit).
        let permit = match st_bg.execute_semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                let mut jobs = st_bg.jobs.write().await;
                if let Some(j) = jobs.get_mut(&job_id_bg) {
                    j.status = "failed".into();
                    j.finished_ts_ms = Some(utils::now_ms());
                    j.error = Some("execute concurrency limiter closed".into());
                }
                return;
            }
        };

        {
            let mut jobs = st_bg.jobs.write().await;
            if let Some(j) = jobs.get_mut(&job_id_bg) {
                j.status = "running".into();
                j.started_ts_ms = Some(utils::now_ms());
            }
        }

        // Keys must be provisioned before executing swaps.
        let tee = { st_bg.tee_keypair.lock().unwrap().clone() };
        let Some(tee) = tee else {
            let mut jobs = st_bg.jobs.write().await;
            if let Some(j) = jobs.get_mut(&job_id_bg) {
                j.status = "failed".into();
                j.finished_ts_ms = Some(utils::now_ms());
                j.error = Some("swap-engine not initialized (missing TEE key; call /upload-key)".into());
            }
            drop(permit);
            return;
        };

        // Precompute pool PDA for cache refresh after confirmation.
        // (We can't rely on optimistic cache updates now that we don't sync-confirm submits.)
        let pool_pk_for_cache: Option<solana_sdk::pubkey::Pubkey> = (|| {
            let p_opt = req.pool.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty());
            if let Some(p) = p_opt {
                return solana_sdk::pubkey::Pubkey::from_str(p).ok();
            }
            let mi = solana_sdk::pubkey::Pubkey::from_str(req.mint_in.trim()).ok()?;
            let mo = solana_sdk::pubkey::Pubkey::from_str(req.mint_out.trim()).ok()?;
            let (a, b) = crate::solana::canonical_mints(mi, mo);
            Some(crate::solana::pool_pda(&st_bg.cfg.program_id, &a, &b).0)
        })();

        let res = engine::execute(
            &st_bg.cfg,
            &st_bg.http,
            st_bg.rpc_confirmed.clone(),
            req,
            &tee,
        )
        .await;
        drop(permit);

        match res {
            Ok(v) => {
                // Persist signature + result immediately (submit is done; confirmation can be async).
                {
                    let mut jobs = st_bg.jobs.write().await;
                    if let Some(j) = jobs.get_mut(&job_id_bg) {
                        j.status = "submitted".into();
                        j.signature = Some(v.signature.clone());
                        j.result = Some(v.clone());
                    }
                }

                // Confirm off the hot path (blocking RPC polling in a blocking task).
                // NOTE: we intentionally do NOT gate returning `result` on confirmation anymore.
                // The frontend can show "submitted" immediately and optionally keep waiting for "confirmed".
                let st_c = st_bg.clone();
                let job_id_c = job_id_bg.clone();
                tokio::spawn(async move {
                    let rpc = st_c.rpc_confirmed.clone();
                    let sig_str = v.signature.clone();
                    let confirm_timeout = std::env::var("SWAP_ENGINE_CONFIRM_TIMEOUT_SECS")
                        .ok()
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(60);

                    let confirm_res: Result<(), AppError> = tokio::task::spawn_blocking(move || {
                        let sig = solana_sdk::signature::Signature::from_str(&sig_str).map_err(|e| {
                            AppError::BadGateway(format!("invalid signature returned by submit: {e}"))
                        })?;
                        crate::solana::wait_for_signature_confirmed(
                            &rpc,
                            &sig,
                            Duration::from_secs(confirm_timeout),
                        )
                    })
                    .await
                    .unwrap_or_else(|e| Err(AppError::BadGateway(format!("confirm task failed: {e}"))));

                    if confirm_res.is_ok() {
                        // Refresh pool cache now that the tx is confirmed.
                        // Do this OUTSIDE the jobs lock (RPC is blocking).
                        if let Some(pool_pk) = pool_pk_for_cache {
                            let rpc = st_c.rpc_confirmed.clone();
                            let _ = tokio::task::spawn_blocking(move || {
                                if let Ok(p) = crate::solana::fetch_pool(&rpc, &pool_pk) {
                                    crate::solana::upsert_pool_cache(&pool_pk, p);
                                }
                            })
                            .await;
                        }
                    }

                    let mut jobs = st_c.jobs.write().await;
                    if let Some(j) = jobs.get_mut(&job_id_c) {
                        j.finished_ts_ms = Some(utils::now_ms());
                        match confirm_res {
                            Ok(()) => {
                                j.status = "confirmed".into();
                            }
                            Err(e) => {
                                metrics::metrics().execute_errors_total.inc();
                                j.status = "failed".into();
                                j.error = Some(e.to_string());
                            }
                        }
                    }
                });
            }
            Err(e) => {
                let mut jobs = st_bg.jobs.write().await;
                if let Some(j) = jobs.get_mut(&job_id_bg) {
                    j.finished_ts_ms = Some(utils::now_ms());
                    metrics::metrics().execute_errors_total.inc();
                    if matches!(e, AppError::BadRequest(_)) {
                        metrics::metrics().bad_requests_total.inc();
                        if let Err(rl) = rate_limit::rate_limit_bad(&st_bg, peer_ip).await {
                            metrics::metrics().rate_limited_total.inc();
                            j.status = "failed".into();
                            j.error = Some(rl.to_string());
                            return;
                        }
                    }
                    j.status = "failed".into();
                    j.error = Some(e.to_string());
                }
            }
        }
    });

    Ok(Json(serde_json::json!({ "job_id": job_id })))
}

