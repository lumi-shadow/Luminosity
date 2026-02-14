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
use url::Url;

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
    /// Reject oracle prices whose publish_time is too far in the future.
    ///
    /// This prevents a future-timestamped value from bypassing staleness checks.
    pub oracle_max_future_secs: u64,
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
    /// Small-imbalance skew sensitivity (gentle).
    ///
    /// We compute an additional "small imbalance" signal:
    ///   small_skew_signal_bps = |imbalance_bps| / skew_small_div_bps
    ///
    /// The engine then uses:
    ///   skew_signal_bps = max(pow4_signal_bps, small_skew_signal_bps) * sign(imbalance)
    ///
    /// This makes skew meaningfully non-zero around ~50–300 bps imbalance without making it extreme.
    pub skew_small_div_bps: i64,

    // --- CPMM cap (large-trade protection) ---
    /// Only apply the CPMM output cap when the trade is at least this fraction of the input reserve.
    ///
    /// Units: basis points of `reserve_in` (so 100 = 1.00% of the input reserve).
    /// This prevents the CPMM cap from dominating small trades when the pool spot drifts from oracle.
    pub cpmm_cap_min_size_bps: u64,

    // --- Rebalancing incentive (optional) ---
    /// Allow a small positive bps bonus (quote slightly better than oracle mid) ONLY when the trade
    /// is predicted to reduce oracle deviation (post_err_bps < pre_err_bps).
    pub rebalance_bonus_bps: u64,
    /// Only consider applying rebalancing bonus when the pool's pre-trade oracle deviation is at least this many bps.
    pub rebalance_min_deviation_bps: u64,
    /// Hard cap on the positive bonus (bps).
    pub rebalance_max_bonus_bps: u64,
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

fn env_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .ok()
        .map(|v| {
            let s = v.trim().to_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "y" | "on")
        })
        .unwrap_or(default)
}

fn validate_hermes_url(raw: &str) -> anyhow::Result<String> {
    let u = Url::parse(raw).with_context(|| format!("Invalid HERMES_URL: {raw}"))?;
    let scheme = u.scheme();
    let allow_insecure_http = env_bool("HERMES_ALLOW_INSECURE_HTTP", false);
    if scheme != "https" && !(allow_insecure_http && scheme == "http") {
        anyhow::bail!(
            "HERMES_URL must use https (or set HERMES_ALLOW_INSECURE_HTTP=true): {raw}"
        );
    }
    let host = u
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("HERMES_URL missing host: {raw}"))?;

    // SSRF guard: by default, disallow localhost and private IP targets.
    // Operators can override for local Hermes nodes by setting HERMES_ALLOW_PRIVATE=true.
    let allow_private = env_bool("HERMES_ALLOW_PRIVATE", false);
    if !allow_private {
        if host.eq_ignore_ascii_case("localhost")
            || host.ends_with(".localhost")
            || host.eq_ignore_ascii_case("127.0.0.1")
            || host.eq_ignore_ascii_case("::1")
        {
            anyhow::bail!("HERMES_URL must not target localhost (set HERMES_ALLOW_PRIVATE=true to override): {raw}");
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let is_private = match ip {
                std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
                std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
            };
            if is_private {
                anyhow::bail!("HERMES_URL must not target a private IP (set HERMES_ALLOW_PRIVATE=true to override): {raw}");
            }
        }
    }

    Ok(raw.trim().trim_end_matches('/').to_string())
}

pub fn load_config() -> anyhow::Result<Config> {
    let admin_token = env::var("ADMIN_TOKEN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| env::var("SWAP_ENGINE_ADMIN_TOKEN").ok().filter(|s| !s.trim().is_empty()))
        .ok_or_else(|| anyhow::anyhow!("Missing env var: ADMIN_TOKEN (or SWAP_ENGINE_ADMIN_TOKEN)"))?;
    if admin_token.trim().len() < 32 {
        anyhow::bail!("ADMIN_TOKEN must be at least 32 characters");
    }

    let rpc_url = env_required("RPC_URL")?;
    let indexer_url = env_required("INDEXER_URL")?;
    let program_id =
        Pubkey::from_str(&env_required("PROGRAM_ID")?).context("Invalid PROGRAM_ID")?;

    let tee_keypair: Option<PathBuf> = env::var("TEE_KEYPAIR")
        .ok()
        .map(PathBuf::from)
        .map(|p| {
            // Basic path traversal guard for env-provided paths.
            // (Still relies on file permissions for actual access control.)
            if !p.is_absolute() {
                return Err(anyhow::anyhow!("TEE_KEYPAIR must be an absolute path"));
            }
            if p.components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(anyhow::anyhow!("TEE_KEYPAIR must not contain '..'"));
            }
            Ok(p)
        })
        .transpose()?;

    // Secure-by-default bind: only listen on loopback unless explicitly configured.
    let api_bind = env::var("API_BIND").unwrap_or_else(|_| "127.0.0.1:9797".to_string());

    let oracle_max_staleness_secs = env_u64("ORACLE_MAX_STALENESS_SECS", 60);
    let oracle_max_future_secs = env_u64("ORACLE_MAX_FUTURE_SECS", 5);
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
    // Gentle small-imbalance skew: 1 bps of skew signal per N bps imbalance.
    // Example: 250 => at ~250 bps imbalance you start seeing ~1 bps (before `skew_k_bps` scaling).
    let mut skew_small_div_bps: i64 = env::var("SKEW_SMALL_DIV_BPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(250);

    // CPMM cap defaults:
    // - only kick in when trade is >= 2% of reserve_in
    let cpmm_cap_min_size_bps = env_u64("CPMM_CAP_MIN_SIZE_BPS", 200);

    // Rebalancing incentive defaults:
    // - disabled by default unless explicitly enabled
    // - when enabled, keep it small (20-50 bps) and only when pool is meaningfully off oracle
    let rebalance_bonus_bps = env_u64("REBALANCE_BONUS_BPS", 0);
    let rebalance_min_deviation_bps = env_u64("REBALANCE_MIN_DEVIATION_BPS", 200);
    let rebalance_max_bonus_bps = env_u64("REBALANCE_MAX_BONUS_BPS", 50);

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
    // Skew divisor must be positive and not absurdly small.
    if skew_small_div_bps <= 0 {
        tracing::warn!("SKEW_SMALL_DIV_BPS={} invalid; defaulting to 250", skew_small_div_bps);
        skew_small_div_bps = 250;
    }
    // Hard floor: if too small, skew responds too aggressively in the 50–300 bps region.
    const SKEW_SMALL_DIV_BPS_FLOOR: i64 = 25;
    if skew_small_div_bps < SKEW_SMALL_DIV_BPS_FLOOR {
        tracing::warn!(
            "SKEW_SMALL_DIV_BPS={} too small; clamping to {}",
            skew_small_div_bps,
            SKEW_SMALL_DIV_BPS_FLOOR
        );
        skew_small_div_bps = SKEW_SMALL_DIV_BPS_FLOOR;
    }

    let hermes_url_raw =
        env::var("HERMES_URL").unwrap_or_else(|_| "https://hermes.pyth.network".to_string());
    let hermes_url = validate_hermes_url(&hermes_url_raw)?;
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
    const HERMES_FEEDS_JSON_MAX_LEN: usize = 32 * 1024;
    if hermes_feeds_json.len() > HERMES_FEEDS_JSON_MAX_LEN {
        anyhow::bail!(
            "HERMES_FEEDS_JSON too large ({} bytes, max {})",
            hermes_feeds_json.len(),
            HERMES_FEEDS_JSON_MAX_LEN
        );
    }
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
        oracle_max_future_secs,
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
        skew_small_div_bps,
        cpmm_cap_min_size_bps,
        rebalance_bonus_bps,
        rebalance_min_deviation_bps,
        rebalance_max_bonus_bps,
    })
}
