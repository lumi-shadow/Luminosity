use crate::config;
use crate::rate_limit;
use crate::types::ExecuteResponse;
use ipnet::IpNet;
use solana_client::rpc_client::RpcClient;
use solana_sdk::signature::Keypair;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
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

