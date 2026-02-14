//! Swap Engine (TEE-style RFQ swap executor)
//!
//! This service is intended to run separately from the public relayer/indexer.
//! It performs *policy checks* (oracle sanity) and then submits the on-chain `execute_rfq_swap`
//! instruction as the configured `tee_authority`.
//!
//! API shape:
//! - `GET  /health`  -> simple liveness check
//! - `POST /quote`   -> computes an indicative quote and returns whether it passes oracle band checks
//! - `POST /execute` -> validates policy + fetches Merkle proof from indexer + submits tx (sync)
//! - `POST /execute-job` -> same as execute, but returns immediately with `job_id` and runs async
//!
//! Notes on responsibilities:
//! - The swap engine enforces oracle/safety policy and submits the on-chain instruction as `tee_authority`.
//! - Output notes are engine-issued:
//!   - the client supplies `note_pubkey_base64` (preferred) or `note_key_base64`
//!   - the engine generates the new commitment and encrypts the note, then publishes ciphertext in the
//!     on-chain `SwapEvent`.

mod config;
mod engine;
mod http_client;
mod indexer;
mod oracle;
mod solana;
mod solvency;
mod types;
mod rate_limit;
mod utils;
mod auth;
mod allowlist;
mod handlers;
mod router;
mod state;

use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::signature::{read_keypair_file, Keypair};
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::info;

mod metrics;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,swap_engine=debug,solana_pubsub_client=warn".into()),
        )
        .init();

    let cfg = config::load_config()?;
    info!(
        "starting swap-engine (bind={}, program_id={}, indexer_url={})",
        cfg.api_bind, cfg.program_id, cfg.indexer_url
    );
    info!(
        "quote policy: base_spread_bps={} max_spread_bps={} skew_k_bps={} max_skew_bps={} skew_small_div_bps={}",
        cfg.base_spread_bps, cfg.max_spread_bps, cfg.skew_k_bps, cfg.max_skew_bps
        , cfg.skew_small_div_bps
    );

    let http = reqwest::Client::new();
    let rpc_processed = Arc::new(RpcClient::new_with_commitment(
        cfg.rpc_url.clone(),
        CommitmentConfig::processed(),
    ));
    let rpc_confirmed = Arc::new(RpcClient::new_with_commitment(
        cfg.rpc_url.clone(),
        CommitmentConfig::confirmed(),
    ));
    // IP allowlist (opt-in)
    let allowlist_path: Option<std::path::PathBuf> = std::env::var("SWAP_ENGINE_ALLOWLIST_PATH")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);
    let allowlist = if let Some(p) = allowlist_path.as_ref() {
        match allowlist::load_allowlist(p) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("failed to load SWAP_ENGINE_ALLOWLIST_PATH ({}): {}", p.display(), e);
                allowlist::parse_allowlist_from_env()?
            }
        }
    } else {
        allowlist::parse_allowlist_from_env()?
    };
    if allowlist.is_empty() {
        tracing::warn!(
            "swap-engine IP allowlist disabled (no SWAP_ENGINE_ALLOWLIST / SWAP_ENGINE_ALLOWLIST_PATH). \
             This is fine behind a firewall, but do not expose :9797 publicly."
        );
    } else {
        tracing::info!("swap-engine IP allowlist enabled ({} entries)", allowlist.len());
    }

    let max_exec: usize = std::env::var("SWAP_ENGINE_MAX_CONCURRENT_EXECUTE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2);
    let state = state::AppState {
        cfg: Arc::new(cfg),
        http,
        rpc_processed,
        rpc_confirmed,
        tee_keypair: Arc::new(std::sync::Mutex::new(None)),
        execute_semaphore: Arc::new(Semaphore::new(max_exec.max(1))),
        jobs: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        job_seq: Arc::new(AtomicU64::new(1)),
        rate_limiter: Arc::new(tokio::sync::Mutex::new(rate_limit::RateLimiter::from_env())),
        allowlist: Arc::new(std::sync::RwLock::new(allowlist)),
        allowlist_path,
    };

    // Optional: load keypairs from mounted files (not baked into the image).
    // If present, this pre-initializes the engine and seals `/upload-key` from overwriting.
    if let Some(path) = state.cfg.tee_keypair.as_deref() {
        let kp: Keypair =
            read_keypair_file(path).map_err(|e| anyhow::anyhow!("read tee keypair failed: {e}"))?;
        *state.tee_keypair.lock().unwrap() = Some(Arc::new(kp));
    }

    // Cache SPL mint decimals at startup (registry pools -> mints -> decimals).
    // This avoids doing an RPC mint fetch on every quote/execute.
    {
        let n = crate::solana::init_mint_decimals_cache(&state.rpc_confirmed, &state.cfg.program_id)
            .map_err(|e| anyhow::anyhow!("init mint decimals cache failed: {e}"))?;
        info!("cached SPL mint decimals for {n} mints (from on-chain registry pools)");
    }

    // Hermes oracle cache: refresh in the background so `/quote` doesn't do HTTP per request.
    {
        let enabled = std::env::var("ORACLE_CACHE_ENABLED")
            .ok()
            .map(|v| v.trim().to_lowercase() != "false")
            .unwrap_or(true);
        if enabled {
            let refresh_ms: u64 = std::env::var("ORACLE_CACHE_REFRESH_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                // Public Hermes API rate limit: 30 requests / 10s / IP.
                // We do 1 batched request per refresh, so keep default <= 25 req/10s.
                .unwrap_or(400);
            let mut feed_ids: Vec<String> = state.cfg.hermes_feed_ids.values().cloned().collect();
            feed_ids.sort();
            feed_ids.dedup();
            let hermes_url = state.cfg.hermes_url.clone();
            let http_c = state.http.clone();
            tokio::spawn(async move {
                crate::oracle::pyth::hermes_cache_loop(http_c, hermes_url, feed_ids, refresh_ms)
                    .await;
            });
            info!("started Hermes oracle cache (refresh_ms={})", refresh_ms);
        } else {
            info!("Hermes oracle cache disabled (ORACLE_CACHE_ENABLED=false)");
        }
    }
    let bind = state.cfg.api_bind.clone();

    let app = router::build(state.clone());

    // Bind directly from the host:port string.
    let listener = tokio::net::TcpListener::bind(bind.as_str()).await?;
    info!("api listening on http://{}", bind);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
