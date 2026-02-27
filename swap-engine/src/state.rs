use crate::config;
use crate::rate_limit;
use crate::types::ExecuteResponse;
use ipnet::IpNet;
use solana_sdk::pubkey::Pubkey;
use solana_client::rpc_client::RpcClient;
use solana_sdk::signature::Keypair;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use tokio::sync::Semaphore;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<config::Config>,
    pub http: reqwest::Client,
    /// Shared Solana RPC clients (RPC calls are blocking; we still call them in spawn_blocking).
    /// Quotes can use `processed` commitment (indicative), while execute/solvency should stay `confirmed`.
    pub rpc_processed: Arc<RpcClient>,
    pub rpc_confirmed: Arc<RpcClient>,
    // Provisioned at runtime (Oyster) or loaded from mounted keypair files.
    pub tee_keypair: Arc<std::sync::Mutex<Option<Arc<Keypair>>>>,
    pub execute_semaphore: Arc<Semaphore>,
    pub jobs: Arc<tokio::sync::RwLock<HashMap<String, ExecuteJob>>>,
    pub job_seq: Arc<AtomicU64>,
    pub rate_limiter: Arc<Mutex<rate_limit::RateLimiter>>,
    pub allowlist: Arc<RwLock<Vec<IpNet>>>,
    pub allowlist_path: Option<PathBuf>,
    pub jupiter_quotes: Arc<tokio::sync::RwLock<HashMap<String, JupiterQuoteCacheEntry>>>,
    pub jupiter_stats: Arc<JupiterRuntimeStats>,
}

#[derive(Clone, Debug)]
pub struct JupiterQuoteCacheEntry {
    pub quote_id: String,
    pub taker: Option<Pubkey>,
    pub token_in: Pubkey,
    pub token_out: Pubkey,
    pub amount_in: u64,
    pub amount_out: u64,
    pub created_at_ms: u128,
}

pub struct JupiterRuntimeStats {
    pub quote_requests: AtomicU64,
    pub quote_success: AtomicU64,
    pub swap_requests: AtomicU64,
    pub swap_success: AtomicU64,
    pub swap_failed: AtomicU64,
    pub fills_total: AtomicU64,
    pub volume_in_base_total: AtomicU64,
    pub volume_out_base_total: AtomicU64,
    pub bundle_submitted_total: AtomicU64,
    pub bundle_landed_total: AtomicU64,
    pub bundle_failed_total: AtomicU64,
    pub quote_latency_ms: std::sync::Mutex<VecDeque<u64>>,
    pub swap_latency_ms: std::sync::Mutex<VecDeque<u64>>,
    pub last_swap_errors: std::sync::Mutex<VecDeque<String>>,
    pub last_swap_debug: std::sync::Mutex<VecDeque<JupiterSwapDebugEntry>>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct JupiterSwapDebugEntry {
    pub ts_ms: u128,
    pub request_id: String,
    pub quote_id: String,
    pub cache_quote_id: String,
    pub cache_taker: Option<String>,
    pub cache_token_in: String,
    pub cache_token_out: String,
    pub cache_amount_in: u64,
    pub cache_amount_out: u64,
    pub tx_taker: Option<String>,
    pub tx_maker: Option<String>,
    pub tx_input_mint: Option<String>,
    pub tx_output_mint: Option<String>,
    pub fill_input_amount: Option<u64>,
    pub fill_output_amount: Option<u64>,
    pub fill_expire_at: Option<i64>,
    pub outcome: String,
    pub error: Option<String>,
    pub note: Option<String>,
}

impl JupiterRuntimeStats {
    pub fn new() -> Self {
        Self {
            quote_requests: AtomicU64::new(0),
            quote_success: AtomicU64::new(0),
            swap_requests: AtomicU64::new(0),
            swap_success: AtomicU64::new(0),
            swap_failed: AtomicU64::new(0),
            fills_total: AtomicU64::new(0),
            volume_in_base_total: AtomicU64::new(0),
            volume_out_base_total: AtomicU64::new(0),
            bundle_submitted_total: AtomicU64::new(0),
            bundle_landed_total: AtomicU64::new(0),
            bundle_failed_total: AtomicU64::new(0),
            quote_latency_ms: std::sync::Mutex::new(VecDeque::with_capacity(2048)),
            swap_latency_ms: std::sync::Mutex::new(VecDeque::with_capacity(2048)),
            last_swap_errors: std::sync::Mutex::new(VecDeque::with_capacity(32)),
            last_swap_debug: std::sync::Mutex::new(VecDeque::with_capacity(64)),
        }
    }

    pub fn record_quote_latency(&self, v_ms: u64) {
        if let Ok(mut g) = self.quote_latency_ms.lock() {
            if g.len() >= 2048 {
                g.pop_front();
            }
            g.push_back(v_ms);
        }
    }

    pub fn record_swap_latency(&self, v_ms: u64) {
        if let Ok(mut g) = self.swap_latency_ms.lock() {
            if g.len() >= 2048 {
                g.pop_front();
            }
            g.push_back(v_ms);
        }
    }

    pub fn record_swap_error(&self, err: &str) {
        if let Ok(mut g) = self.last_swap_errors.lock() {
            if g.len() >= 32 {
                g.pop_front();
            }
            g.push_back(err.to_string());
        }
    }

    pub fn record_swap_debug(&self, row: JupiterSwapDebugEntry) {
        if let Ok(mut g) = self.last_swap_debug.lock() {
            if g.len() >= 64 {
                g.pop_front();
            }
            g.push_back(row);
        }
    }

    pub fn inc_volume(&self, in_base: u64, out_base: u64) {
        self.volume_in_base_total.fetch_add(in_base, Ordering::Relaxed);
        self.volume_out_base_total.fetch_add(out_base, Ordering::Relaxed);
    }
}

#[derive(serde::Serialize)]
pub struct ExecuteJob {
    pub id: String,
    pub status: String, // queued | running | submitted | confirmed | failed
    pub created_ts_ms: u128,
    pub started_ts_ms: Option<u128>,
    pub finished_ts_ms: Option<u128>,
    /// Populated as soon as the swap tx is submitted (even before it is confirmed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub result: Option<ExecuteResponse>,
    pub error: Option<String>,
}

