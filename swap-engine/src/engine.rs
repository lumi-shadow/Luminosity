//! Core “business logic” for the swap engine.
//!
//! We keep this file focused on:
//! - quote math
//! - oracle band checks
//! - preparing inputs for the on-chain `execute_rfq_swap` instruction
//!
//! Anything that touches the network is delegated:
//! - RPC fetching / tx submission lives in `solana.rs`
//! - indexer API calls live in `indexer.rs`
//! - Pyth parsing/policy lives in `oracle/pyth.rs`

use crate::config::Config;
use crate::indexer::{hex32, IndexerClient};
use crate::metrics;
use crate::oracle::pyth::{
    conf_band, enforce_staleness, get_cached_hermes_price, load_hermes_price, load_hermes_prices,
    now_unix, OraclePrice,
};
use crate::solana::{
    canonical_mints, execute_rfq_swap_append_tx, fetch_amm_tree_and_tee, fetch_asset_id_for_mint,
    fetch_mint_decimals, fetch_pool, fetch_pool_cached, fetch_token_account_amounts, pool_pda,
};
use crate::types::{
    AppError, ExecuteRequest, ExecuteResponse, OracleDetails, QuoteRequest, QuoteResponse,
    RfqSwapUpdate,
};
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::Engine;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use solana_client::rpc_client::RpcClient;
use solana_sdk::keccak::hashv as keccak_hashv;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use tracing::debug;
use x25519_dalek::{EphemeralSecret as X25519EphemeralSecret, PublicKey as X25519PublicKey};

fn quote_amount_out_pmm_oracle_mid(
    amount_in_base: u64,
    dec_in: u32,
    dec_out: u32,
    oracle_num_out_per_in: u128,
    oracle_den_out_per_in: u128,
    // Combined multiplier in bps applied to out amount:
    // (10_000 - spread_bps + skew_signed_bps) / 10_000
    bps_delta: i64,
) -> u64 {
    if amount_in_base == 0 || oracle_num_out_per_in == 0 || oracle_den_out_per_in == 0 {
        return 0;
    }
    // out_base = in_base * (out_per_in token ratio) * 10^dec_out / 10^dec_in
    // then apply bps_delta multiplier.
    let bps = clamp_i64(bps_delta, -9_999, 9_999);
    let bps_num: i128 = 10_000i128 + (bps as i128);
    if bps_num <= 0 {
        return 0;
    }
    let scale_out = pow10_i128(dec_out) as i128;
    let scale_in = pow10_i128(dec_in) as i128;
    if scale_out <= 0 || scale_in <= 0 {
        return 0;
    }
    let num = (amount_in_base as u128)
        .saturating_mul(oracle_num_out_per_in)
        .saturating_mul(scale_out as u128)
        .saturating_mul(bps_num as u128);
    let den = oracle_den_out_per_in
        .saturating_mul(scale_in as u128)
        .saturating_mul(10_000u128);
    if den == 0 {
        return 0;
    }
    (num / den) as u64
}

fn quote_amount_out_cpmm(amount_in_base: u64, reserve_in: u64, reserve_out: u64) -> u64 {
    // Classic constant-product output (no fees):
    // out = reserve_out * amount_in / (reserve_in + amount_in)
    //
    // Key property: output is highly non-linear for large trades, preventing "drain the pool at oracle mid".
    if amount_in_base == 0 || reserve_in == 0 || reserve_out == 0 {
        return 0;
    }
    let den = (reserve_in as u128).saturating_add(amount_in_base as u128);
    if den == 0 {
        return 0;
    }
    ((reserve_out as u128).saturating_mul(amount_in_base as u128) / den) as u64
}

fn pow10_i128(exp: u32) -> i128 {
    // exp is small for SPL decimals / Pyth exponents.
    let mut v: i128 = 1;
    for _ in 0..exp {
        v = v.saturating_mul(10);
    }
    v
}

fn clamp_u64(x: u64, lo: u64, hi: u64) -> u64 {
    core::cmp::min(core::cmp::max(x, lo), hi)
}

fn clamp_i64(x: i64, lo: i64, hi: i64) -> i64 {
    core::cmp::min(core::cmp::max(x, lo), hi)
}

fn bps_delta_from_spread_and_centerline_shift(
    spread_bps: u64,
    center_shift_bps: i64,
    direction_sign: i64,
) -> i64 {
    // Pricing model:
    // - Oracle mid is the center.
    // - `spread_bps` is the *total* spread width around oracle (bid/ask), so each side applies
    //   a penalty of `half_spread = spread_bps/2`.
    // - Inventory skew shifts the *centerline* by at most ±half_spread.
    //
    // For a given trade direction we compute:
    //   multiplier_bps = -half_spread + (direction_sign * clamp(center_shift, ±half_spread))
    //
    // This guarantees:
    // - we never accidentally quote better than oracle mid due to skew alone
    // - worst-case one side reaches oracle mid (0 penalty) while the other pays full spread (-spread)
    let half_spread_bps: i64 = (spread_bps as i64).saturating_div(2);
    let center = clamp_i64(center_shift_bps, -half_spread_bps, half_spread_bps);
    // Defensive guard: regardless of future asymmetric spread/skew changes, the applied delta must
    // never be positive (we never want to quote *better* than oracle mid due to policy knobs).
    let delta = (-(half_spread_bps)).saturating_add(direction_sign.saturating_mul(center));
    core::cmp::min(0, delta)
}

fn saturating_div_bps(num: u128, den: u128) -> u64 {
    // Return floor(num/den * 10_000) in bps, saturating on overflow / div0.
    if den == 0 {
        return u64::MAX;
    }
    let v = num.saturating_mul(10_000u128) / den;
    v.min(u64::MAX as u128) as u64
}

fn usd_value_scaled(
    reserve_base: u64,
    decimals: u32,
    price: i64,
    expo: i32,
    common_expo: i32,
) -> i128 {
    // USD value ~ reserve_tokens * price_usd
    //
    // reserve_tokens = reserve_base * 10^-decimals
    // price_usd = price * 10^expo
    //
    // value = reserve_base * price * 10^(expo - decimals)
    // We scale both sides to a shared exponent `common_expo` so we can compare without floats.
    let eff = expo.saturating_sub(decimals as i32); // exponent of (reserve*price)
    let delta = eff.saturating_sub(common_expo); // >= 0 if common_expo is min(eff_a, eff_b)
    let scale = pow10_i128(delta as u32);
    (reserve_base as i128)
        .saturating_mul(price as i128)
        .saturating_mul(scale)
}

fn oracle_mid_ratio_out_per_in(d: &OracleDetails) -> Result<(u128, u128), AppError> {
    // oracle_mid(out per in) = (price_in/USD) / (price_out/USD)
    // = (price_in * 10^expo_in) / (price_out * 10^expo_out)
    let p_in = d.price_in as i128;
    let p_out = d.price_out as i128;
    if p_in <= 0 || p_out <= 0 {
        return Err(AppError::BadGateway("oracle prices must be > 0".into()));
    }
    let mut num: i128 = p_in;
    let mut den: i128 = p_out;
    let delta = d.expo_in.saturating_sub(d.expo_out);
    if delta > 0 {
        num = num.saturating_mul(pow10_i128(delta as u32));
    } else if delta < 0 {
        den = den.saturating_mul(pow10_i128((-delta) as u32));
    }
    if num <= 0 || den <= 0 {
        return Err(AppError::BadGateway("oracle ratio invalid".into()));
    }
    Ok((num as u128, den as u128))
}

fn pool_spot_ratio_out_per_in(
    reserve_in_base: u64,
    reserve_out_base: u64,
    dec_in: u32,
    dec_out: u32,
) -> (u128, u128) {
    // price(out per in) in token units:
    //   (reserve_out/10^dec_out) / (reserve_in/10^dec_in)
    // = reserve_out * 10^dec_in / (reserve_in * 10^dec_out)
    let num = (reserve_out_base as u128).saturating_mul(pow10_i128(dec_in) as u128);
    let den = (reserve_in_base as u128).saturating_mul(pow10_i128(dec_out) as u128);
    (num, den.max(1))
}

fn rel_error_bps(pool_num: u128, pool_den: u128, oracle_num: u128, oracle_den: u128) -> u64 {
    // error = |pool/oracle - 1| in bps
    // pool/oracle = (pool_num/pool_den) / (oracle_num/oracle_den)
    //            = pool_num*oracle_den / (pool_den*oracle_num)
    // err_bps = |pool_num*oracle_den - pool_den*oracle_num| / (pool_den*oracle_num) * 10_000
    if oracle_num == 0 || pool_den == 0 {
        return u64::MAX;
    }
    let a = pool_num.saturating_mul(oracle_den);
    let b = pool_den.saturating_mul(oracle_num);
    let diff = a.abs_diff(b);
    saturating_div_bps(diff, b)
}

#[derive(Clone, Copy, Debug)]
struct OracleMidState {
    num: u128,
    den: u128,
    last_ts: i64,
    blocked_until: i64,
}

static ORACLE_MID_CACHE: OnceLock<Mutex<HashMap<(Pubkey, Pubkey), OracleMidState>>> =
    OnceLock::new();

fn oracle_mid_cache() -> &'static Mutex<HashMap<(Pubkey, Pubkey), OracleMidState>> {
    ORACLE_MID_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn maybe_trip_oracle_shock(
    cfg: &Config,
    now: i64,
    mint_a: Pubkey,
    mint_b: Pubkey,
    oracle_mid_b_per_a: (u128, u128),
) -> Result<(), AppError> {
    // Key by canonical mint ordering for stability.
    let (a, b) = canonical_mints(mint_a, mint_b);
    let (mut num, mut den) = oracle_mid_b_per_a;
    if a != mint_a {
        // Caller provided mid for (b per a) in the opposite order; invert.
        core::mem::swap(&mut num, &mut den);
    }
    if num == 0 || den == 0 {
        return Err(AppError::BadGateway("oracle mid ratio invalid".into()));
    }

    let mut g = oracle_mid_cache()
        .lock()
        .map_err(|_| AppError::BadGateway("oracle mid cache mutex poisoned".into()))?;
    let st = g.get(&(a, b)).copied();

    // If currently blocked, keep blocking until cooldown ends.
    if let Some(prev) = st {
        if now < prev.blocked_until {
            return Err(AppError::Forbidden(format!(
                "oracle shock circuit breaker active (cooldown {}s remaining)",
                (prev.blocked_until - now).max(0)
            )));
        }
    }

    // Detect a sudden jump relative to last seen mid within window.
    if let Some(prev) = st {
        let dt = now.saturating_sub(prev.last_ts).max(0) as u64;
        if dt <= cfg.oracle_shock_window_secs {
            let jump_bps = rel_error_bps(num, den, prev.num, prev.den);
            if jump_bps >= cfg.oracle_shock_max_jump_bps {
                let blocked_until = now.saturating_add(cfg.oracle_shock_cooldown_secs as i64);
                g.insert(
                    (a, b),
                    OracleMidState {
                        num,
                        den,
                        last_ts: now,
                        blocked_until,
                    },
                );
                return Err(AppError::Forbidden(format!(
                    "oracle shock detected: jump_bps={} window={}s; paused for {}s",
                    jump_bps, cfg.oracle_shock_window_secs, cfg.oracle_shock_cooldown_secs
                )));
            }
        }
    }

    // Update last seen mid.
    g.insert(
        (a, b),
        OracleMidState {
            num,
            den,
            last_ts: now,
            blocked_until: 0,
        },
    );
    Ok(())
}

async fn fetch_oracle_pair(
    cfg: &Config,
    http: &reqwest::Client,
    mint_in: &Pubkey,
    mint_out: &Pubkey,
) -> Result<(OraclePrice, OraclePrice), AppError> {
    let (Some(feed_in), Some(feed_out)) = (
        cfg.hermes_feed_ids.get(mint_in),
        cfg.hermes_feed_ids.get(mint_out),
    ) else {
        return Err(AppError::BadGateway(
            "missing oracle feeds for mint_in/mint_out (configure HERMES_FEEDS_JSON)".into(),
        ));
    };

    // Fast path: read from in-memory Hermes cache (refreshed in background).
    // Fallback: do a single batched Hermes request if cache is cold.
    let mut p_in = get_cached_hermes_price(feed_in);
    let mut p_out = get_cached_hermes_price(feed_out);
    if p_in.is_none() || p_out.is_none() {
        let got =
            load_hermes_prices(http, &cfg.hermes_url, &[feed_in.clone(), feed_out.clone()]).await?;
        p_in = p_in.or_else(|| got.get(feed_in).cloned());
        p_out = p_out.or_else(|| got.get(feed_out).cloned());
        // Last-resort fallback (should be rare).
        if p_in.is_none() {
            p_in = Some(load_hermes_price(http, &cfg.hermes_url, feed_in).await?);
        }
        if p_out.is_none() {
            p_out = Some(load_hermes_price(http, &cfg.hermes_url, feed_out).await?);
        }
    }
    let p_in =
        p_in.ok_or_else(|| AppError::BadGateway("missing oracle price for mint_in".into()))?;
    let p_out =
        p_out.ok_or_else(|| AppError::BadGateway("missing oracle price for mint_out".into()))?;
    Ok((p_in, p_out))
}

fn compute_quote_from_state(
    cfg: &Config,
    mint_in: Pubkey,
    mint_out: Pubkey,
    pool: &crate::types::PoolAccount,
    reserve_in: u64,
    reserve_out: u64,
    dec_in: u32,
    dec_out: u32,
    p_in: &OraclePrice,
    p_out: &OraclePrice,
    amount_in: u64,
) -> Result<QuoteResponse, AppError> {
    enforce_staleness(p_in, cfg.oracle_max_staleness_secs)?;
    enforce_staleness(p_out, cfg.oracle_max_staleness_secs)?;

    // Oracle shock circuit breaker (flash-crash / bad tick protection).
    // This is intentionally conservative: if the oracle mid jumps too far too fast, we pause.
    let now = now_unix();
    {
        // Build canonical (mint_a, mint_b) USD prices.
        let (a, b) = canonical_mints(mint_in, mint_out);
        let (p_a, p_b) = if mint_in == a {
            (p_in, p_out)
        } else {
            (p_out, p_in)
        };
        let (mid_b_per_a_num, mid_b_per_a_den) = oracle_mid_ratio_out_per_in(&OracleDetails {
            price_in: p_a.price,
            conf_in: p_a.conf,
            expo_in: p_a.expo,
            price_out: p_b.price,
            conf_out: p_b.conf,
            expo_out: p_b.expo,
            age_in_secs: 0,
            age_out_secs: 0,
            imbalance_bps: 0,
        })?;
        maybe_trip_oracle_shock(cfg, now, a, b, (mid_b_per_a_num, mid_b_per_a_den))?;
    }

    // PMM base: oracle mid price (out per in) in token units.
    let (oracle_num, oracle_den) = oracle_mid_ratio_out_per_in(&OracleDetails {
        price_in: p_in.price,
        conf_in: p_in.conf,
        expo_in: p_in.expo,
        price_out: p_out.price,
        conf_out: p_out.conf,
        expo_out: p_out.expo,
        age_in_secs: 0,
        age_out_secs: 0,
        imbalance_bps: 0,
    })?;

    // --- Inventory skew (mid shift) ---
    let (price_a, expo_a, dec_a, price_b, expo_b, dec_b) = if mint_in == pool.mint_a {
        (
            p_in.price,
            p_in.expo,
            dec_in,
            p_out.price,
            p_out.expo,
            dec_out,
        )
    } else {
        (
            p_out.price,
            p_out.expo,
            dec_out,
            p_in.price,
            p_in.expo,
            dec_in,
        )
    };
    let eff_a = expo_a.saturating_sub(dec_a as i32);
    let eff_b = expo_b.saturating_sub(dec_b as i32);
    let common_expo = eff_a.min(eff_b);

    // Canonical reserves: map to mint_a/mint_b (not mint_in/mint_out).
    let (reserve_a, reserve_b) = (pool.reserve_a, pool.reserve_b);
    let value_a = usd_value_scaled(reserve_a, dec_a, price_a, expo_a, common_expo);
    let value_b = usd_value_scaled(reserve_b, dec_b, price_b, expo_b, common_expo);
    let total = value_a.saturating_add(value_b);
    let imbalance_bps: i64 = if total == 0 {
        0
    } else {
        let num = value_b.saturating_sub(value_a).saturating_mul(10_000i128);
        (num / total) as i64
    };

    // Nonlinear inventory skew: use x^4 curve so it barely affects small imbalances,
    // and ramps up hard only when the pool is far off balance.
    //
    // Let x = |imbalance| / 10_000 (normalized to [0,1]).
    // Original (linear): imbalance_bps = sign * (x * 10_000)
    // New: imbalance_pow4_bps = sign * (x^4 * 10_000) = sign * (|imbalance_bps|^4 / 10_000^3)
    let denom_1e12: i128 = 1_000_000_000_000; // 10_000^3
    let abs_bps: i128 = (imbalance_bps as i128).unsigned_abs() as i128;
    let pow4_bps: i128 = if abs_bps == 0 {
        0
    } else {
        let abs4 = abs_bps
            .saturating_mul(abs_bps)
            .saturating_mul(abs_bps)
            .saturating_mul(abs_bps);
        let scaled = abs4.saturating_div(denom_1e12);
        let sign = imbalance_bps.signum() as i128;
        sign.saturating_mul(scaled)
    };

    let mut skew_bps: i64 = (pow4_bps as i128)
        .saturating_mul(cfg.skew_k_bps as i128)
        .saturating_div(10_000i128) as i64;
    skew_bps = clamp_i64(skew_bps, -cfg.max_skew_bps, cfg.max_skew_bps);

    debug!(
        imbalance_bps,
        pow4_bps = (pow4_bps as i64),
        skew_bps,
        skew_k_bps = cfg.skew_k_bps,
        max_skew_bps = cfg.max_skew_bps,
        "inventory skew (x^4)"
    );

    // Centerline shift is defined in canonical pool orientation (mint_a -> mint_b).
    // For the reverse direction we apply the opposite sign.
    let direction_sign: i64 = if mint_in == pool.mint_a { 1 } else { -1 };

    // --- Dynamic spread (LP protection) ---
    let age_in = now.saturating_sub(p_in.publish_time);
    let age_out = now.saturating_sub(p_out.publish_time);
    let age_max = core::cmp::max(age_in, age_out).max(0);

    // Trade size in bps of reserve_in (base units).
    let size_bps = saturating_div_bps(amount_in as u128, reserve_in as u128);

    // Confidence width in bps (conf / |price|).
    let conf_in_bps = saturating_div_bps(
        p_in.conf as u128,
        (p_in.price.unsigned_abs() as u128).max(1),
    );
    let conf_out_bps = saturating_div_bps(
        p_out.conf as u128,
        (p_out.price.unsigned_abs() as u128).max(1),
    );
    let conf_bps = core::cmp::max(conf_in_bps, conf_out_bps);

    let mut spread_bps = cfg.base_spread_bps;
    spread_bps =
        spread_bps.saturating_add((size_bps.saturating_mul(cfg.size_spread_mult_bps)) / 10_000);
    spread_bps =
        spread_bps.saturating_add((conf_bps.saturating_mul(cfg.conf_spread_mult_bps)) / 10_000);
    spread_bps =
        spread_bps.saturating_add((age_max as u64).saturating_mul(cfg.stale_spread_bps_per_sec));
    spread_bps = clamp_u64(spread_bps, 0, cfg.max_spread_bps);

    let bps_delta: i64 =
        bps_delta_from_spread_and_centerline_shift(spread_bps, skew_bps, direction_sign);
    let mut amount_out = quote_amount_out_pmm_oracle_mid(
        amount_in, dec_in, dec_out, oracle_num, oracle_den, bps_delta,
    );

    // Hard price-impact guard: cap oracle-mid quote by CPMM output.
    // This prevents pathological "near linear" pricing when a user tries to take a huge fraction of the pool.
    let cpmm_out = quote_amount_out_cpmm(amount_in, reserve_in, reserve_out);
    amount_out = core::cmp::min(amount_out, cpmm_out);

    // Safety: never exceed pool reserves. Keep strictly less than reserve_out to avoid execute underflow.
    let reserve_cap = reserve_out.saturating_sub(1);
    amount_out = core::cmp::min(amount_out, reserve_cap);

    // Compare implied ratio against oracle ratio using confidence bands.
    let implied_num = (amount_out as i128).saturating_mul(pow10_i128(dec_in));
    let implied_den = (amount_in as i128).saturating_mul(pow10_i128(dec_out));

    let (_in_lo, in_hi) = conf_band(p_in, cfg.oracle_conf_mult_bps);
    let (out_lo, _out_hi) = conf_band(p_out, cfg.oracle_conf_mult_bps);

    let common_expo = p_in.expo.min(p_out.expo);
    let in_scale = pow10_i128((p_in.expo - common_expo) as u32);
    let out_scale = pow10_i128((p_out.expo - common_expo) as u32);
    let in_hi = in_hi.saturating_mul(in_scale);
    let out_lo = out_lo.saturating_mul(out_scale);

    let mut price_ok = true;
    if implied_den == 0 || out_lo <= 0 || in_hi <= 0 {
        price_ok = false;
    } else {
        let lhs = implied_num.saturating_mul(out_lo);
        let rhs = implied_den.saturating_mul(in_hi);
        if lhs > rhs {
            let scale_in = pow10_i128(dec_in);
            let scale_out = pow10_i128(dec_out);
            if scale_in > 0 && scale_out > 0 {
                let num = (amount_in as u128)
                    .saturating_mul(scale_out as u128)
                    .saturating_mul(in_hi as u128);
                let den = (scale_in as u128).saturating_mul(out_lo as u128);
                if den > 0 {
                    let max_out = (num / den) as u64;
                    let reserve_cap = reserve_out.saturating_sub(1);
                    let max_out = core::cmp::min(max_out, reserve_cap);
                    amount_out = core::cmp::min(amount_out, max_out);
                } else {
                    price_ok = false;
                }
            } else {
                price_ok = false;
            }
        }
    }

    Ok(QuoteResponse {
        amount_out,
        spread_bps,
        // Expose signed skew for the requested direction for UI/debugging.
        skew_bps: clamp_i64(direction_sign.saturating_mul(skew_bps), -9_999, 9_999),
        price_ok,
        oracle_details: Some(OracleDetails {
            price_in: p_in.price,
            conf_in: p_in.conf,
            expo_in: p_in.expo,
            price_out: p_out.price,
            conf_out: p_out.conf,
            expo_out: p_out.expo,
            age_in_secs: age_in,
            age_out_secs: age_out,
            imbalance_bps,
        }),
    })
}

pub async fn quote(
    cfg: &Config,
    http: &reqwest::Client,
    rpc: Arc<RpcClient>,
    req: QuoteRequest,
) -> Result<QuoteResponse, AppError> {
    // Quote is a pure read path:
    // - read pool reserves from chain
    // - compute constant-product amount_out
    // - read oracle prices and check implied rate is inside confidence-expanded bounds
    let mint_in = Pubkey::from_str(&req.mint_in)
        .map_err(|_| AppError::BadRequest("invalid mint_in pubkey".into()))?;
    let mint_out = Pubkey::from_str(&req.mint_out)
        .map_err(|_| AppError::BadRequest("invalid mint_out pubkey".into()))?;

    let pool_pk = match req.pool.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(pool_s) => Pubkey::from_str(pool_s)
            .map_err(|_| AppError::BadRequest("invalid pool pubkey".into()))?,
        None => {
            // Derive pool PDA from canonical mint ordering.
            let (a, b) = canonical_mints(mint_in, mint_out);
            pool_pda(&cfg.program_id, &a, &b).0
        }
    };

    // Concurrency:
    // - Solana RPC (blocking) pool fetch runs in `spawn_blocking` (avoids stalling tokio worker).
    // - Hermes prices are read from cache; if cache is cold, we do a single batched HTTP request.
    let rpc = rpc.clone();
    let pool_fetch = tokio::task::spawn_blocking(move || {
        let t0 = Instant::now();
        let p = fetch_pool_cached(&rpc, &pool_pk)?;
        Ok::<(crate::types::PoolAccount, u128), AppError>((p, t0.elapsed().as_millis()))
    });
    let oracle_fetch = async {
        let t0 = Instant::now();
        let r = fetch_oracle_pair(cfg, http, &mint_in, &mint_out).await;
        (r, t0.elapsed().as_millis())
    };
    let (pool_res, oracle_res) = tokio::join!(pool_fetch, oracle_fetch);

    let (pool, pool_ms) = pool_res
        .map_err(|e| AppError::BadGateway(format!("pool fetch join failed: {e}")))?
        .map_err(|e| AppError::BadGateway(format!("pool fetch failed: {e}")))?;
    metrics::metrics().quote_pool_rpc_ms.observe(pool_ms as f64);

    let (oracle_r, oracle_ms) = oracle_res;
    metrics::metrics().quote_oracle_ms.observe(oracle_ms as f64);
    let (p_in, p_out) = oracle_r?;

    let (reserve_in, reserve_out) = if mint_in == pool.mint_a && mint_out == pool.mint_b {
        (pool.reserve_a, pool.reserve_b)
    } else if mint_in == pool.mint_b && mint_out == pool.mint_a {
        (pool.reserve_b, pool.reserve_a)
    } else {
        return Err(AppError::BadRequest(
            "mint_in/mint_out must match pool mints".into(),
        ));
    };

    // Decimals are needed for both oracle checks and inventory skew computations.
    let dec_in = fetch_mint_decimals(&mint_in)? as u32;
    let dec_out = fetch_mint_decimals(&mint_out)? as u32;

    let t0 = Instant::now();
    let out = compute_quote_from_state(
        cfg,
        mint_in,
        mint_out,
        &pool,
        reserve_in,
        reserve_out,
        dec_in,
        dec_out,
        &p_in,
        &p_out,
        req.amount_in,
    )?;
    metrics::metrics()
        .quote_compute_ms
        .observe(t0.elapsed().as_millis() as f64);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spread_is_symmetric_and_centerline_shift_is_bounded() {
        // total spread = 200 bps => 100 bps per side
        // centerline shift should move the center up/down by at most half-spread.
        // a->b direction_sign=+1
        assert_eq!(bps_delta_from_spread_and_centerline_shift(200, 50, 1), -50);
        // b->a direction_sign=-1 (mirror)
        assert_eq!(
            bps_delta_from_spread_and_centerline_shift(200, 50, -1),
            -150
        );

        // skew larger than half-spread is clamped (can't make quotes better than oracle mid)
        assert_eq!(bps_delta_from_spread_and_centerline_shift(200, 500, 1), 0);
        assert_eq!(
            bps_delta_from_spread_and_centerline_shift(200, 500, -1),
            -200
        );
    }

    #[test]
    fn never_quotes_better_than_oracle_mid_due_to_policy() {
        // For a wide range of parameters, delta must never be positive.
        for spread in [0u64, 1, 2, 5, 50, 199, 200, 201, 1_000, 9_999] {
            for shift in [-20_000i64, -5_000, -500, -50, 0, 50, 500, 5_000, 20_000] {
                for dir in [-1i64, 1] {
                    let d = bps_delta_from_spread_and_centerline_shift(spread, shift, dir);
                    assert!(d <= 0, "spread={spread} shift={shift} dir={dir} delta={d}");
                }
            }
        }
    }

    #[test]
    fn cpmm_introduces_real_price_impact_for_large_trades() {
        // If you swap 90% of reserve_in in a CPMM, you should get ~47.37% of reserve_out.
        let reserve_in = 1_000_000u64;
        let reserve_out = 1_000_000u64;
        let amount_in = 900_000u64;
        let out = quote_amount_out_cpmm(amount_in, reserve_in, reserve_out);
        assert_eq!(out, 473_684);
    }

    #[test]
    fn cpmm_caps_oracle_linear_quote_for_huge_trades() {
        // With oracle mid=1 and no policy penalty, the PMM math is linear.
        // The CPMM cap must dominate for huge trades.
        let reserve_in = 1_000_000u64;
        let reserve_out = 1_000_000u64;
        let amount_in = 900_000u64;
        let oracle_linear = quote_amount_out_pmm_oracle_mid(amount_in, 6, 6, 1, 1, 0);
        assert_eq!(oracle_linear, 900_000);
        let cpmm = quote_amount_out_cpmm(amount_in, reserve_in, reserve_out);
        assert_eq!(cpmm, 473_684);
        assert!(cpmm < oracle_linear);
    }
}
pub async fn execute(
    cfg: &Config,
    http: &reqwest::Client,
    rpc: Arc<RpcClient>,
    req: ExecuteRequest,
    tee_authority: &Keypair,
) -> Result<ExecuteResponse, AppError> {
    // Execute is a write path:
    // - fail closed if oracle checks do not pass
    // - fetch merkle proof for the leaf we are replacing (previous commitment)
    // - submit on-chain instruction to replace leaf + update virtual reserves
    let mint_in = Pubkey::from_str(&req.mint_in)
        .map_err(|_| AppError::BadRequest("invalid mint_in pubkey".into()))?;
    let mint_out = Pubkey::from_str(&req.mint_out)
        .map_err(|_| AppError::BadRequest("invalid mint_out pubkey".into()))?;

    // ---------------------------------------------------------------------
    // SECURITY: Bind amount_in to the input note commitment (if provided).
    //
    // The on-chain program cannot validate note plaintext (it only sees the commitment).
    // Therefore, the swap-engine must not trust an arbitrary `amount_in` coming from clients.
    //
    // If the caller provides `input_note`, we:
    // - parse it (mint, amount, nullifier, secret)
    // - compute the expected commitment for mint_in (requires asset_id lookup)
    // - require it matches `previous_commitment_hex`
    // - then use the note-derived amount for quoting/reserve math
    // ---------------------------------------------------------------------
    fn parse_asset_note_plaintext(note: &str) -> Result<(String, u64, [u8; 32], [u8; 32]), AppError> {
        let s = note.trim();
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 || parts[0] != "luminocity" || parts[1] != "asset" {
            return Err(AppError::BadRequest("invalid asset note format".into()));
        }
        let mint = parts[2].trim().to_string();
        let amount: u64 = parts[3]
            .trim()
            .parse()
            .map_err(|_| AppError::BadRequest("invalid note amount".into()))?;
        let hexcat = parts[4].trim();
        if hexcat.len() != 128 {
            return Err(AppError::BadRequest("invalid note (nullifier+secret) hex length".into()));
        }
        let null_hex = &hexcat[0..64];
        let sec_hex = &hexcat[64..128];
        let null_bytes = hex::decode(null_hex)
            .map_err(|_| AppError::BadRequest("invalid note nullifier hex".into()))?;
        let sec_bytes = hex::decode(sec_hex)
            .map_err(|_| AppError::BadRequest("invalid note secret hex".into()))?;
        let null32: [u8; 32] = null_bytes
            .try_into()
            .map_err(|_| AppError::BadRequest("invalid note nullifier length".into()))?;
        let sec32: [u8; 32] = sec_bytes
            .try_into()
            .map_err(|_| AppError::BadRequest("invalid note secret length".into()))?;
        Ok((mint, amount, null32, sec32))
    }

    fn commitment_from_note(nullifier: [u8; 32], secret: [u8; 32], amount: u64, asset_id: u32) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(32 + 32 + 8 + 4);
        preimage.extend_from_slice(&nullifier);
        preimage.extend_from_slice(&secret);
        preimage.extend_from_slice(&amount.to_le_bytes());
        preimage.extend_from_slice(&asset_id.to_le_bytes());
        keccak_hashv(&[&preimage]).0
    }

    // Default to request amount/commitment; override when input_note is present.
    let mut effective_amount_in: u64 = req.amount_in;
    let mut effective_prev_commitment_hex: String = req.previous_commitment_hex.clone();
    if let Some(note) = req.input_note.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let (note_mint, note_amount, nullifier, secret) = parse_asset_note_plaintext(note)?;
        if note_mint != req.mint_in.trim() {
            return Err(AppError::BadRequest(
                "input_note mint does not match mint_in".into(),
            ));
        }
        // Fetch asset_id for mint_in so we can recompute the commitment.
        let asset_in_id =
            fetch_asset_id_for_mint(&rpc, &cfg.program_id, &mint_in)?;
        let c = commitment_from_note(nullifier, secret, note_amount, asset_in_id);
        let expected_hex = format!("0x{}", hex::encode(c));
        let provided_hex = if req.previous_commitment_hex.trim_start_matches("0x").len() == 64 {
            format!("0x{}", req.previous_commitment_hex.trim_start_matches("0x"))
        } else {
            req.previous_commitment_hex.clone()
        };
        if !provided_hex.eq_ignore_ascii_case(&expected_hex) {
            return Err(AppError::BadRequest(
                "input_note does not match previous_commitment_hex".into(),
            ));
        }
        if req.amount_in != note_amount {
            return Err(AppError::BadRequest(
                "amount_in does not match input_note amount".into(),
            ));
        }
        effective_amount_in = note_amount;
        effective_prev_commitment_hex = expected_hex;
    }

    let pool_pk = match req.pool.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(pool_s) => Pubkey::from_str(pool_s)
            .map_err(|_| AppError::BadRequest("invalid pool pubkey".into()))?,
        None => {
            let (a, b) = canonical_mints(mint_in, mint_out);
            pool_pda(&cfg.program_id, &a, &b).0
        }
    };

    // NOTE: Legacy nullifier PDA spend-check removed.
    // Spent protection is enforced on-chain via spent-by-leaf-index bitmap.

    // Concurrency plan for execute:
    // - Oracle prices (cache/batched HTTP) in parallel
    // - Indexer merkle proof (blocking HTTP) in spawn_blocking
    // - Solana RPC reads (blocking) in spawn_blocking:
    //   - pool account
    //   - AMM config (merkle tree + expected tee)
    //   - vault balances (batched)
    //   - asset_id for mint_out
    let program_id = cfg.program_id;
    let mint_out_for_rpc = mint_out;
    let pool_pk_for_rpc = pool_pk;
    let rpc_for_task = rpc.clone();
    let rpc_task = tokio::task::spawn_blocking(
        move || -> Result<(crate::types::PoolAccount, Pubkey, Pubkey, u64, u64, u32), AppError> {
            let pool = fetch_pool(&rpc_for_task, &pool_pk_for_rpc)?;
            let (merkle_tree, expected_tee) = fetch_amm_tree_and_tee(&rpc_for_task, &program_id)?;
            let asset_out_id =
                fetch_asset_id_for_mint(&rpc_for_task, &program_id, &mint_out_for_rpc)?;
            let amts = fetch_token_account_amounts(&rpc_for_task, &[pool.vault_a, pool.vault_b])?;
            let vault_a_amt = amts.get(0).and_then(|v| *v).unwrap_or(0);
            let vault_b_amt = amts.get(1).and_then(|v| *v).unwrap_or(0);
            Ok((
                pool,
                merkle_tree,
                expected_tee,
                vault_a_amt,
                vault_b_amt,
                asset_out_id,
            ))
        },
    );

    let indexer_url = cfg.indexer_url.clone();
    let admin_token = cfg.admin_token.clone();
    let prev_commitment = effective_prev_commitment_hex.clone();
    let proof_task = tokio::task::spawn_blocking(
        move || -> Result<crate::types::IndexerProofResponse, AppError> {
            let indexer = IndexerClient::new(&indexer_url, admin_token)?;
            indexer.get_proof_by_commitment_hex(&prev_commitment)
        },
    );

    let oracle_task = fetch_oracle_pair(cfg, http, &mint_in, &mint_out);

    let (rpc_res, proof_res, oracle_res) = tokio::join!(rpc_task, proof_task, oracle_task);
    let (pool, merkle_tree, expected_tee, vault_a_amt, vault_b_amt, asset_out_id) =
        rpc_res.map_err(|e| AppError::BadGateway(format!("rpc task join failed: {e}")))??;
    let proof =
        proof_res.map_err(|e| AppError::BadGateway(format!("indexer task join failed: {e}")))??;
    let (p_in, p_out) = oracle_res?;

    // Validate the provisioned TEE key matches on-chain config.
    if tee_authority.pubkey() != expected_tee {
        return Err(AppError::Forbidden(format!(
            "TEE key mismatch: configured={} onchain_expected={}",
            tee_authority.pubkey(),
            expected_tee
        )));
    }

    // Determine reserves in the requested direction.
    let (reserve_in, reserve_out) = if mint_in == pool.mint_a && mint_out == pool.mint_b {
        (pool.reserve_a, pool.reserve_b)
    } else if mint_in == pool.mint_b && mint_out == pool.mint_a {
        (pool.reserve_b, pool.reserve_a)
    } else {
        return Err(AppError::BadRequest(
            "mint_in/mint_out must match pool mints".into(),
        ));
    };

    // Decimals are needed for both oracle checks and inventory skew computations.
    let dec_in = fetch_mint_decimals(&mint_in)? as u32;
    let dec_out = fetch_mint_decimals(&mint_out)? as u32;

    // Quote (same math/policy as /quote) using the fetched pool+oracle state.
    let q = compute_quote_from_state(
        cfg,
        mint_in,
        mint_out,
        &pool,
        reserve_in,
        reserve_out,
        dec_in,
        dec_out,
        &p_in,
        &p_out,
        effective_amount_in,
    )?;
    // Slippage guard:
    // - We always execute using the engine's *current* quote output (`q.amount_out`).
    // - The request-provided `amount_out` is interpreted as a **minimum acceptable output** ("min_out").
    //   This enables slippage tolerance between the time the user quoted and the time we execute.
    //
    // This also preserves the "no donation" property: callers cannot force a smaller executed out.
    let amount_out = q.amount_out;
    if amount_out < req.amount_out {
        return Err(AppError::Forbidden(format!(
            "slippage exceeded: min_out={} current_out={}",
            req.amount_out, amount_out
        )));
    }
    // Allow "rebalancing" trades that move the pool closer to oracle, even if `price_ok=false`.
    // This is important for bootstrapping / re-syncing a pool that is far from oracle.
    if !q.price_ok {
        let details = q.oracle_details.as_ref().ok_or_else(|| {
            AppError::BadGateway("oracle_details missing; cannot evaluate rebalancing trade".into())
        })?;
        let (oracle_num, oracle_den) = oracle_mid_ratio_out_per_in(details)?;

        // Map reserves into (in,out) for the requested direction.
        // Post-trade reserves (approx): +amount_in on input, -amount_out on output.
        if amount_out >= reserve_out {
            return Err(AppError::Forbidden(
                "amount_out exceeds pool reserves".into(),
            ));
        }
        let post_in = reserve_in
            .checked_add(effective_amount_in)
            .ok_or_else(|| AppError::BadGateway("reserve overflow (post_in)".into()))?;
        let post_out = reserve_out
            .checked_sub(amount_out)
            .ok_or_else(|| AppError::Forbidden("amount_out exceeds pool reserves".into()))?;

        let (pre_num, pre_den) =
            pool_spot_ratio_out_per_in(reserve_in, reserve_out, dec_in, dec_out);
        let (post_num, post_den) = pool_spot_ratio_out_per_in(post_in, post_out, dec_in, dec_out);
        let pre_err = rel_error_bps(pre_num, pre_den, oracle_num, oracle_den);
        let post_err = rel_error_bps(post_num, post_den, oracle_num, oracle_den);

        if post_err >= pre_err {
            return Err(AppError::Forbidden(format!(
                "oracle check failed (price band) and trade does not improve oracle deviation: pre_err_bps={} post_err_bps={}",
                pre_err, post_err
            )));
        }
        // else: allow rebalancing trade to proceed.
    }
    // Note: we enforce slippage via `min_out` above; executed out is always `q.amount_out`.

    let prev = hex32(&effective_prev_commitment_hex)?;
    let root = hex32(&proof.root_hex)?;

    let mut siblings = Vec::with_capacity(proof.siblings_hex.len());
    for s in &proof.siblings_hex {
        siblings.push(hex32(s)?);
    }
    // The on-chain Merkle tree uses a canopy, so `replace_leaf` only needs the *non-canopy*
    // portion of the proof as remaining accounts.
    //
    // For our deployed tree:
    // - depth = 24
    // - canopy_depth = 14  (see `scripts/init_mainnet.ts`)
    // => proof nodes needed as accounts = 24 - 14 = 10
    //
    // The indexer always returns the full depth (24) for circuit compatibility. Here we only
    // pass the required subset to keep transactions small.
    let canopy_depth: usize = std::env::var("TREE_CANOPY_DEPTH")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(14);
    let depth = siblings.len();
    if depth == 0 || canopy_depth > depth {
        return Err(AppError::BadGateway(format!(
            "invalid proof shape from indexer: depth={} canopy_depth={}",
            depth, canopy_depth
        )));
    }
    let needed = depth.saturating_sub(canopy_depth);
    if needed == 0 {
        return Err(AppError::BadGateway(format!(
            "canopy_depth={} covers full depth={}, expected canopy < depth",
            canopy_depth, depth
        )));
    }
    let siblings_for_tx: Vec<[u8; 32]> = siblings
        .get(0..needed)
        .ok_or_else(|| {
            AppError::BadGateway(format!(
                "proof siblings too short: got={} need_at_least={}",
                siblings.len(),
                needed
            ))
        })?
        .to_vec();

    // Pool mints were validated above when we mapped reserves.

    // Determine output commitment + ciphertext (engine-issued notes only).
    // The engine generates the note and encrypts it with:
    // - `note_pubkey_base64` (X25519 recipient pubkey), or
    // - `note_key_base64` (symmetric AES key)
    //
    // NOTE: We intentionally do not support "client-issued notes" here anymore: the swap-engine is
    // the trusted party that controls reserves and must therefore also control the note commitment
    // that gets inserted into the Merkle tree.
    // Prefer X25519 recipient key if provided.
    let recipient_pubkey: Option<[u8; 32]> = match req.note_pubkey_base64.as_deref() {
        Some(b64) if !b64.trim().is_empty() => {
            let pk_bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.trim().as_bytes())
                .map_err(|e| AppError::BadRequest(format!("invalid note_pubkey_base64: {e}")))?;
            if pk_bytes.len() != 32 {
                return Err(AppError::BadRequest(
                    "note_pubkey_base64 must decode to 32 bytes".into(),
                ));
            }
            Some(pk_bytes.try_into().expect("len"))
        }
        _ => None,
    };

    let key_bytes_opt: Option<Vec<u8>> = match req.note_key_base64.as_deref() {
        Some(b64) if !b64.trim().is_empty() => {
            let k = base64::engine::general_purpose::STANDARD
                .decode(b64.trim().as_bytes())
                .map_err(|e| AppError::BadRequest(format!("invalid note_key_base64: {e}")))?;
            if k.len() != 32 {
                return Err(AppError::BadRequest(
                    "note_key_base64 must decode to 32 bytes".into(),
                ));
            }
            Some(k)
        }
        _ => None,
    };

    if recipient_pubkey.is_none() && key_bytes_opt.is_none() {
        return Err(AppError::BadRequest(
            "note_pubkey_base64 (preferred) or note_key_base64 is required".into(),
        ));
    }

        // Use asset_id computed in RPC task (avoid extra RPC round trip).
        let asset_out_id = asset_out_id;

        // Generate output note preimage.
        let mut out_nullifier = [0u8; 32];
        let mut out_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut out_nullifier);
        rand::thread_rng().fill_bytes(&mut out_secret);

        let amount_le8 = amount_out.to_le_bytes();
        let asset_le4 = asset_out_id.to_le_bytes();
        let preimage: Vec<u8> = [
            out_nullifier.to_vec(),
            out_secret.to_vec(),
            amount_le8.to_vec(),
            asset_le4.to_vec(),
        ]
        .concat();
        let commitment = keccak_hashv(&[&preimage]).0;

        let note_plain = format!(
            "luminocity-asset-{}-{}-{}{}",
            mint_out,
            amount_out,
            hex::encode(out_nullifier),
            hex::encode(out_secret)
        );

        // Encrypt note plaintext for on-chain logs.
        //
        // X25519 mode:
        //   payload = eph_pub(32) || nonce(12) || ct+tag
        //
        // Symmetric mode:
        //   payload = nonce(12) || ct+tag
        let mut payload: Vec<u8> = Vec::new();
        if let Some(pk) = recipient_pubkey {
            let recipient = X25519PublicKey::from(pk);
            let eph_secret = X25519EphemeralSecret::random_from_rng(rand::thread_rng());
            let eph_pub = X25519PublicKey::from(&eph_secret);
            let shared = eph_secret.diffie_hellman(&recipient);
            let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
            let mut okm = [0u8; 32];
            hk.expand(b"p1vacy-note-x25519-v1", &mut okm)
                .map_err(|_| AppError::BadGateway("hkdf expand failed".into()))?;

            let cipher = Aes256Gcm::new_from_slice(&okm)
                .map_err(|_| AppError::BadGateway("aes init failed".into()))?;
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            let ct = cipher
                .encrypt((&nonce).into(), note_plain.as_bytes())
                .map_err(|_| AppError::BadGateway("note encryption failed".into()))?;
            payload.extend_from_slice(eph_pub.as_bytes());
            payload.extend_from_slice(&nonce);
            payload.extend_from_slice(&ct);
        } else if let Some(key_bytes) = key_bytes_opt {
            let cipher = Aes256Gcm::new_from_slice(&key_bytes)
                .map_err(|_| AppError::BadRequest("invalid note_key (aes init)".into()))?;
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            let ct = cipher
                .encrypt((&nonce).into(), note_plain.as_bytes())
                .map_err(|_| AppError::BadGateway("note encryption failed".into()))?;
            payload.extend_from_slice(&nonce);
            payload.extend_from_slice(&ct);
        }
        if payload.len() > 512 {
            return Err(AppError::BadRequest(format!(
                "encrypted_note too long: {} bytes (max 512)",
                payload.len()
            )));
        }
    let b64 = base64::engine::general_purpose::STANDARD.encode(&payload);
    let (new_leaf, encrypted_note, issued_note_plaintext, issued_ciphertext_b64) =
        (commitment, payload, Some(note_plain), Some(b64));

    // -------------------------------------------------------------------------
    // Phase 0 solvency guard (engine-side):
    // Ensure pool's virtual reserves never exceed the real vault token balances.
    //
    // This prevents the swap-engine from pushing the system into an un-withdrawable state.
    // -------------------------------------------------------------------------
    if pool.reserve_a > vault_a_amt || pool.reserve_b > vault_b_amt {
        return Err(AppError::BadGateway(format!(
            "pool insolvent: reserves exceed vault balances (reserve_a={} vault_a={} reserve_b={} vault_b={})",
            pool.reserve_a, vault_a_amt, pool.reserve_b, vault_b_amt
        )));
    }

    // Compute post-trade virtual reserves (canonical order in the Pool account).
    // This is the TEE's responsibility; clients must not be trusted to provide reserves.
    let (mut new_reserve_a, mut new_reserve_b) = (pool.reserve_a, pool.reserve_b);
    if mint_in == pool.mint_a {
        // a -> b: reserve_a increases, reserve_b decreases
        new_reserve_a = new_reserve_a
            .checked_add(req.amount_in)
            .ok_or_else(|| AppError::BadGateway("reserve overflow (new_reserve_a)".into()))?;
        new_reserve_b = new_reserve_b
            .checked_sub(amount_out)
            .ok_or_else(|| AppError::Forbidden("amount_out exceeds pool reserves".into()))?;
    } else {
        // b -> a: reserve_b increases, reserve_a decreases
        new_reserve_b = new_reserve_b
            .checked_add(req.amount_in)
            .ok_or_else(|| AppError::BadGateway("reserve overflow (new_reserve_b)".into()))?;
        new_reserve_a = new_reserve_a
            .checked_sub(amount_out)
            .ok_or_else(|| AppError::Forbidden("amount_out exceeds pool reserves".into()))?;
    }

    // Final guard: the updated reserves must still be covered by real vault balances.
    if new_reserve_a > vault_a_amt || new_reserve_b > vault_b_amt {
        return Err(AppError::Forbidden(format!(
            "solvency guard: swap would exceed vault balances (new_reserve_a={} vault_a={} new_reserve_b={} vault_b={})",
            new_reserve_a, vault_a_amt, new_reserve_b, vault_b_amt
        )));
    }

    let swap = RfqSwapUpdate {
        root,
        previous_leaf: prev,
        new_leaf,
        index: proof.leaf_index,
        new_reserve_a,
        new_reserve_b,
    };

    // Finally submit the on-chain instruction (submit-only; confirmation happens out-of-band).
    let sig = execute_rfq_swap_append_tx(
        &rpc,
        cfg.program_id,
        tee_authority,
        pool_pk,
        merkle_tree,
        swap,
        &encrypted_note,
        &siblings_for_tx,
    )?;

    // NOTE: we intentionally do NOT update the in-process pool cache here anymore.
    // Since we no longer synchronously confirm the transaction on this code path, updating the cache
    // optimistically would make `/quote` inconsistent if the tx fails or expires.

    Ok(ExecuteResponse {
        signature: sig.to_string(),
        amount_out: Some(amount_out),
        note: issued_note_plaintext,
        encrypted_note_base64: issued_ciphertext_b64,
    })
}
