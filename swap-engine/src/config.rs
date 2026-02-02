//! Environment-driven configuration for `swap-engine`.
//!
//! We keep this intentionally small and explicit:
//! - RPC + indexer endpoints
//! - program id
//! - keypairs for signing
//! - oracle settings + feed mapping (mint -> pyth price account)

use anyhow::Context;
use solana_sdk::pubkey::Pubkey;
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::str::FromStr;

const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
// Hermes feed ids (mainnet):
// - Crypto.SOL/USD
const HERMES_SOL_USD_ID: &str = "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
// - Crypto.USDC/USD
const HERMES_USDC_USD_ID: &str = "eaa020c61cc479712813461ce153894a96a6c00b21ed0cfc2798d1f9a9e9c94a";

#[derive(Clone)]
pub struct Config {
    /// Unified admin token (required). Used to gate **admin-only** HTTP endpoints.
    ///
    /// Send via `Authorization: Bearer <token>` (or `x-admin-token`).
    pub admin_token: String,
    /// Solana HTTP RPC endpoint (Helius, etc).
    pub rpc_url: String,
    /// Base URL for the local tree-indexer, e.g. `http://127.0.0.1:8787`.
    pub indexer_url: String,
    /// Anchor program id (privacy pool).
    pub program_id: Pubkey,
    /// Optional path to JSON keypair file used as `tee_authority` signer on-chain.
    ///
    /// For Marlin Oyster we prefer runtime provisioning via `/upload-key`, so this is optional.
    pub tee_keypair: Option<PathBuf>,
    /// Axum bind address, host:port.
    pub api_bind: String,

    /// Hermes base URL for Pyth price service (used for automatic oracle feeds).
    pub hermes_url: String,
    /// Mapping from SPL mint -> Hermes feed id (hex string).
    ///
    /// This is auto-populated for WSOL and USDC by default.
    pub hermes_feed_ids: HashMap<Pubkey, String>,
    /// Reject oracle prices older than this many seconds.
    pub oracle_max_staleness_secs: u64,
    /// Expand confidence interval by this multiplier in basis points. 10_000 = 1.0x.
    pub oracle_conf_mult_bps: u64,

    // --- Oracle shock circuit breaker (flash-crash protection) ---
    /// If oracle mid jumps more than this many bps within `oracle_shock_window_secs`,
    /// the engine temporarily pauses quotes/executes for that pair.
    pub oracle_shock_max_jump_bps: u64,
    /// Time window for jump detection.
    pub oracle_shock_window_secs: u64,
    /// Cooldown after a shock is detected (seconds).
    pub oracle_shock_cooldown_secs: u64,

    // --- Quoting policy (spread widening) ---
    /// Base spread always applied to quotes (bps).
    pub base_spread_bps: u64,
    /// Additional spread for trade size (bps) = size_bps * size_spread_mult_bps / 10_000.
    pub size_spread_mult_bps: u64,
    /// Additional spread from oracle confidence (bps) = conf_bps * conf_spread_mult_bps / 10_000.
    pub conf_spread_mult_bps: u64,
    /// Additional spread from staleness (bps) = age_secs * stale_spread_bps_per_sec.
    pub stale_spread_bps_per_sec: u64,
    /// Hard cap on spread (bps).
    pub max_spread_bps: u64,

    // --- Inventory skew (mid shift) ---
    /// Multiply inventory imbalance by this factor to compute `skew_bps`.
    ///
    /// `imbalance_bps` is computed from USD value:
    ///   imbalance_bps = (value_b - value_a) / (value_a + value_b) * 10_000
    ///
    /// `skew_bps = clamp(imbalance_bps * skew_k_bps / 10_000, ±max_skew_bps)`
    pub skew_k_bps: i64,
    /// Clamp for skew_bps (absolute value).
    pub max_skew_bps: i64,
}

fn env_required(key: &str) -> anyhow::Result<String> {
    env::var(key).with_context(|| format!("Missing env var: {key}"))
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub fn load_config() -> anyhow::Result<Config> {
    let admin_token = env::var("ADMIN_TOKEN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| env::var("SWAP_ENGINE_ADMIN_TOKEN").ok().filter(|s| !s.trim().is_empty()))
        .ok_or_else(|| anyhow::anyhow!("Missing env var: ADMIN_TOKEN (or SWAP_ENGINE_ADMIN_TOKEN)"))?;

    let rpc_url = env_required("RPC_URL")?;
    let indexer_url = env_required("INDEXER_URL")?;
    let program_id =
        Pubkey::from_str(&env_required("PROGRAM_ID")?).context("Invalid PROGRAM_ID")?;

    let tee_keypair: Option<PathBuf> = env::var("TEE_KEYPAIR").ok().map(PathBuf::from);
    let api_bind = env::var("API_BIND").unwrap_or_else(|_| "0.0.0.0:9797".to_string());

    let oracle_max_staleness_secs = env_u64("ORACLE_MAX_STALENESS_SECS", 60);
    let oracle_conf_mult_bps = env_u64("ORACLE_CONF_MULT_BPS", 20_000);

    // Oracle shock circuit breaker defaults:
    // - detect jumps > 20% within 30s
    // - pause for 120s
    let oracle_shock_max_jump_bps = env_u64("ORACLE_SHOCK_MAX_JUMP_BPS", 2_000);
    let oracle_shock_window_secs = env_u64("ORACLE_SHOCK_WINDOW_SECS", 30);
    let oracle_shock_cooldown_secs = env_u64("ORACLE_SHOCK_COOLDOWN_SECS", 120);

    // Quoting policy defaults:
    // - 5 bps base
    // - size penalty ~ 1.5x of (trade_size / reserves) in bps
    // - confidence penalty ~ 2.0x of oracle conf bps
    // - staleness penalty 0.2 bps per second (kicks in if you allow staler quotes)
    // - cap at 200 bps
    let mut base_spread_bps = env_u64("BASE_SPREAD_BPS", 5);
    let size_spread_mult_bps = env_u64("SIZE_SPREAD_MULT_BPS", 15_000);
    let conf_spread_mult_bps = env_u64("CONF_SPREAD_MULT_BPS", 20_000);
    let stale_spread_bps_per_sec = env_u64("STALE_SPREAD_BPS_PER_SEC", 0);
    let mut max_spread_bps = env_u64("MAX_SPREAD_BPS", 200);

    // Inventory skew defaults:
    // - up to ±50 bps mid shift
    // - proportional to USD imbalance with k=1.0x
    let skew_k_bps: i64 = env::var("SKEW_K_BPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let mut max_skew_bps: i64 = env::var("MAX_SKEW_BPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);

    // --- Safety clamps ---
    //
    // Quotes apply multipliers of the form (10_000 ± bps)/10_000.
    // Therefore, values >= 10_000 can drive the multiplier to 0 (or negative conceptually).
    //
    // In production we never want configuration to be able to return "0 out" for a valid trade
    // purely due to policy knobs.
    if max_spread_bps >= 10_000 {
        tracing::warn!(
            "MAX_SPREAD_BPS={} is invalid (must be < 10_000); clamping to 9_999",
            max_spread_bps
        );
        max_spread_bps = 9_999;
    }
    if base_spread_bps > max_spread_bps {
        tracing::warn!(
            "BASE_SPREAD_BPS={} exceeds MAX_SPREAD_BPS={}; clamping base to max",
            base_spread_bps,
            max_spread_bps
        );
        base_spread_bps = max_spread_bps;
    }

    if max_skew_bps.abs() >= 10_000 {
        tracing::warn!(
            "MAX_SKEW_BPS={} is invalid (abs must be < 10_000); clamping to 9_999",
            max_skew_bps
        );
        max_skew_bps = max_skew_bps.signum() * 9_999;
    }
    // Hard cap to keep UX sane (prevents extreme '0 out' style quotes even if user misconfigures).
    const MAX_SKEW_BPS_HARD_CAP: i64 = 500;
    if max_skew_bps.abs() > MAX_SKEW_BPS_HARD_CAP {
        tracing::warn!(
            "MAX_SKEW_BPS={} too large; clamping to ±{}",
            max_skew_bps,
            MAX_SKEW_BPS_HARD_CAP
        );
        max_skew_bps = max_skew_bps.signum() * MAX_SKEW_BPS_HARD_CAP;
    }

    let hermes_url =
        env::var("HERMES_URL").unwrap_or_else(|_| "https://hermes.pyth.network".to_string());
    let mut hermes_feed_ids: HashMap<Pubkey, String> = HashMap::new();
    // Built-in defaults for your current mainnet pool.
    hermes_feed_ids.insert(
        Pubkey::from_str(WSOL_MINT).unwrap(),
        HERMES_SOL_USD_ID.to_string(),
    );
    hermes_feed_ids.insert(
        Pubkey::from_str(USDC_MINT).unwrap(),
        HERMES_USDC_USD_ID.to_string(),
    );

    // Optional override/extension:
    // JSON map { "<mint_pubkey>": "<hermes_feed_id_hex>", ... }
    let hermes_feeds_json = env::var("HERMES_FEEDS_JSON").unwrap_or_else(|_| "{}".to_string());
    let raw: HashMap<String, String> = serde_json::from_str(&hermes_feeds_json)
        .context("Invalid HERMES_FEEDS_JSON (expected JSON map mint->hermes_feed_id_hex)")?;
    for (mint_s, id_hex) in raw {
        let mint = Pubkey::from_str(&mint_s)
            .with_context(|| format!("Invalid mint pubkey in HERMES_FEEDS_JSON: {mint_s}"))?;
        hermes_feed_ids.insert(mint, id_hex);
    }

    Ok(Config {
        admin_token,
        rpc_url,
        indexer_url,
        program_id,
        tee_keypair,
        api_bind,
        hermes_url,
        hermes_feed_ids,
        oracle_max_staleness_secs,
        oracle_conf_mult_bps,
        oracle_shock_max_jump_bps,
        oracle_shock_window_secs,
        oracle_shock_cooldown_secs,
        base_spread_bps,
        size_spread_mult_bps,
        conf_spread_mult_bps,
        stale_spread_bps_per_sec,
        max_spread_bps,
        skew_k_bps,
        max_skew_bps,
    })
}
