use crate::rate_limit::RateLimiter;
use crate::types::RelayProgressEvent;
use ecies::{PublicKey, SecretKey};
use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

pub struct AppState {
    pub tee_secret: SecretKey,
    pub tee_public: PublicKey,
    pub relayer_wallet: Mutex<Option<Arc<Keypair>>>,
    pub admin_token: String,
    pub program_id: Pubkey,
    pub rpc: Arc<RpcClient>,
    pub jobs: tokio::sync::RwLock<HashMap<String, RelayJob>>,
    pub job_seq: AtomicU64,
    pub job_semaphore: Semaphore,
    pub rate_limiter: Mutex<RateLimiter>,
    pub allowlist: RwLock<Vec<IpNet>>,
    pub allowlist_path: Option<PathBuf>,
    /// Cache: which mints have a relayer fee ATA already created (to avoid CU waste).
    pub fee_ata_mints: Mutex<HashSet<Pubkey>>,
    /// Cache: mint -> USD price/decimals (short TTL, used for fee quotes).
    pub price_cache: Mutex<HashMap<Pubkey, crate::pricing::PricePoint>>,
    /// Cache: mint -> SPL decimals (fetched via RPC, stable).
    pub mint_decimals_cache: Mutex<HashMap<Pubkey, u8>>,
}

impl AppState {
    pub fn has_wallet(&self) -> bool {
        self.relayer_wallet
            .lock()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayJobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayJobKind {
    Withdraw,
    WithdrawLiquidity,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayJob {
    pub id: String,
    pub kind: RelayJobKind,
    pub status: RelayJobStatus,
    pub created_ts_ms: u128,
    pub started_ts_ms: Option<u128>,
    pub finished_ts_ms: Option<u128>,
    // Bounded progress log snapshot (NDJSON clients can poll this after reconnect).
    pub events: Vec<RelayProgressEvent>,
    pub result: Option<Value>,
    pub error: Option<String>,
}

pub fn new_job_id(state: &AppState, kind: RelayJobKind) -> String {
    let now_ms = crate::utils::now_ms();
    let seq = state.job_seq.fetch_add(1, Ordering::Relaxed);
    let k = match kind {
        RelayJobKind::Withdraw => "w",
        RelayJobKind::WithdrawLiquidity => "wl",
    };
    format!("job-{}-{}-{}", now_ms, seq, k)
}
