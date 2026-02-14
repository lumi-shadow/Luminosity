//! On-chain PMM (Proactive Market Maker) pricing logic.
//!
//! Ported from swap-engine/src/engine.rs for fully on-chain, permissionless execution.
//! All math is integer-only (no floats), using u128 intermediate precision.
//!
//! Pricing model:
//!   1. Compute oracle mid price (out per in) from Pyth price feeds
//!   2. Apply dynamic spread (base + size + confidence + staleness)
//!   3. Apply inventory skew (shift price center based on pool imbalance)
//!   4. Cap output against CPMM (x*y=k) for large trades
//!   5. Cap output against pool reserves (never drain the pool)
//!
//! All policy knobs live in `PmmConfig` (stored on Pool, admin-configurable).

use crate::state::PmmConfig;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pow10(exp: u32) -> u128 {
    let mut v: u128 = 1;
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

/// floor(num/den * 10_000) in bps, saturating on overflow / div0.
fn saturating_div_bps(num: u128, den: u128) -> u64 {
    if den == 0 {
        return u64::MAX;
    }
    let v = num.saturating_mul(10_000u128) / den;
    v.min(u64::MAX as u128) as u64
}

// ---------------------------------------------------------------------------
// Core pricing
// ---------------------------------------------------------------------------

/// PMM oracle-anchored linear quote.
///
/// out = in * (oracle_num/oracle_den) * 10^dec_out / 10^dec_in * (10_000 + bps_delta) / 10_000
fn quote_pmm_oracle_mid(
    amount_in: u64,
    dec_in: u8,
    dec_out: u8,
    oracle_num: u128,
    oracle_den: u128,
    bps_delta: i64,
) -> u64 {
    if amount_in == 0 || oracle_num == 0 || oracle_den == 0 {
        return 0;
    }
    let bps = clamp_i64(bps_delta, -9_999, 9_999);
    let bps_num = 10_000i128 + (bps as i128);
    if bps_num <= 0 {
        return 0;
    }
    let scale_out = pow10(dec_out as u32);
    let scale_in = pow10(dec_in as u32);
    if scale_out == 0 || scale_in == 0 {
        return 0;
    }
    let num = (amount_in as u128)
        .saturating_mul(oracle_num)
        .saturating_mul(scale_out)
        .saturating_mul(bps_num as u128);
    let den = oracle_den
        .saturating_mul(scale_in)
        .saturating_mul(10_000u128);
    if den == 0 {
        return 0;
    }
    (num / den) as u64
}

/// Constant-product output: out = reserve_out * amount_in / (reserve_in + amount_in)
fn quote_cpmm(amount_in: u64, reserve_in: u64, reserve_out: u64) -> u64 {
    if amount_in == 0 || reserve_in == 0 || reserve_out == 0 {
        return 0;
    }
    let den = (reserve_in as u128).saturating_add(amount_in as u128);
    if den == 0 {
        return 0;
    }
    ((reserve_out as u128).saturating_mul(amount_in as u128) / den) as u64
}

/// Oracle mid ratio (out per in) from Pyth price feeds.
/// Returns (numerator, denominator) such that ratio = num/den in token units.
fn oracle_mid_ratio(
    price_in: i64,
    expo_in: i32,
    price_out: i64,
    expo_out: i32,
) -> Option<(u128, u128)> {
    if price_in <= 0 || price_out <= 0 {
        return None;
    }
    let mut num = price_in as u128;
    let mut den = price_out as u128;
    let delta = expo_in.saturating_sub(expo_out);
    if delta > 0 {
        num = num.saturating_mul(pow10(delta as u32));
    } else if delta < 0 {
        den = den.saturating_mul(pow10((-delta) as u32));
    }
    if num == 0 || den == 0 {
        return None;
    }
    Some((num, den))
}

/// USD value of reserves scaled to a common exponent (for inventory skew computation).
fn usd_value_scaled(
    reserve: u64,
    decimals: u8,
    price: i64,
    expo: i32,
    common_expo: i32,
) -> i128 {
    let eff = expo.saturating_sub(decimals as i32);
    let delta = eff.saturating_sub(common_expo).max(0);
    let scale = pow10(delta as u32) as i128;
    (reserve as i128)
        .saturating_mul(price as i128)
        .saturating_mul(scale)
}

/// Combine spread + inventory skew into a single bps delta.
/// Result is always <= 0 (never quote better than oracle mid).
fn bps_delta_from_spread_and_skew(
    spread_bps: u64,
    center_shift_bps: i64,
    direction_sign: i64,
) -> i64 {
    let half_spread = (spread_bps as i64).saturating_div(2);
    let center = clamp_i64(center_shift_bps, -half_spread, half_spread);
    let delta = (-half_spread).saturating_add(direction_sign.saturating_mul(center));
    core::cmp::min(0, delta)
}

// ---------------------------------------------------------------------------
// Pyth price types
// ---------------------------------------------------------------------------

/// Parsed Pyth price data (used by PMM compute functions).
///
/// Populated from a deserialized `PriceUpdateV2` account via `from_pyth_update`.
pub struct PythPrice {
    pub price: i64,
    pub conf: u64,
    pub expo: i32,
    pub timestamp: i64,
}

/// Construct a `PythPrice` from a deserialized Pyth `PriceUpdateV2` account.
///
/// The account ownership + discriminator are already validated by Anchor's
/// `Account<'info, PriceUpdateV2>` type. The caller is responsible for
/// staleness checks (via `pool.pmm.max_oracle_age_secs`).
pub fn from_pyth_update(
    update: &pyth_solana_receiver_sdk::price_update::PriceUpdateV2,
) -> PythPrice {
    PythPrice {
        price: update.price_message.price,
        conf: update.price_message.conf,
        expo: update.price_message.exponent,
        timestamp: update.price_message.publish_time,
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Compute the swap output amount using the full PMM pricing model.
///
/// On-chain equivalent of `compute_quote_from_state` from the swap engine.
/// All policy knobs are read from `cfg` (admin-configurable per pool).
///
/// Returns `None` if oracle data is invalid.
pub fn compute_swap_amount_out(
    cfg: &PmmConfig,
    amount_in: u64,
    reserve_in: u64,
    reserve_out: u64,
    dec_in: u8,
    dec_out: u8,
    base_spread_bps: u64,
    oracle_in: &PythPrice,
    oracle_out: &PythPrice,
    // true if mint_in == pool.mint_a (canonical direction)
    is_a_to_b: bool,
    now: i64,
    // Canonical pool reserves + decimals + oracle prices (for skew)
    reserve_a: u64,
    reserve_b: u64,
    dec_a: u8,
    dec_b: u8,
    price_a: i64,
    expo_a: i32,
    price_b: i64,
    expo_b: i32,
) -> Option<u64> {
    // 1. Oracle mid ratio
    let (oracle_num, oracle_den) = oracle_mid_ratio(
        oracle_in.price,
        oracle_in.expo,
        oracle_out.price,
        oracle_out.expo,
    )?;

    // 2. Inventory skew
    let eff_a = expo_a.saturating_sub(dec_a as i32);
    let eff_b = expo_b.saturating_sub(dec_b as i32);
    let common_expo = eff_a.min(eff_b);

    let value_a = usd_value_scaled(reserve_a, dec_a, price_a, expo_a, common_expo);
    let value_b = usd_value_scaled(reserve_b, dec_b, price_b, expo_b, common_expo);
    let total = value_a.saturating_add(value_b);
    let imbalance_bps: i64 = if total == 0 {
        0
    } else {
        (value_b
            .saturating_sub(value_a)
            .saturating_mul(10_000i128)
            / total) as i64
    };

    // Nonlinear (x^4) skew + gentle small-imbalance term
    let denom_1e12: i128 = 1_000_000_000_000;
    let abs_bps = (imbalance_bps as i128).unsigned_abs() as i128;
    let pow4_mag = if abs_bps == 0 {
        0i128
    } else {
        abs_bps
            .saturating_mul(abs_bps)
            .saturating_mul(abs_bps)
            .saturating_mul(abs_bps)
            .saturating_div(denom_1e12)
    };
    let skew_small_div = (cfg.skew_small_div_bps as i128).max(1);
    let small_mag = if abs_bps == 0 {
        0i128
    } else {
        abs_bps.saturating_div(skew_small_div)
    };
    let skew_signal_mag = core::cmp::max(pow4_mag, small_mag);
    let sign = (imbalance_bps as i128).signum();
    let skew_signal = sign.saturating_mul(skew_signal_mag);

    let max_skew = cfg.max_skew_bps as i64;
    let mut skew_bps = skew_signal
        .saturating_mul(cfg.skew_k_bps as i128)
        .saturating_div(10_000i128) as i64;
    skew_bps = clamp_i64(skew_bps, -max_skew, max_skew);

    let direction_sign: i64 = if is_a_to_b { 1 } else { -1 };

    // 3. Dynamic spread
    let age_in = now.saturating_sub(oracle_in.timestamp).max(0) as u64;
    let age_out = now.saturating_sub(oracle_out.timestamp).max(0) as u64;
    let age_max = core::cmp::max(age_in, age_out);

    let size_bps = saturating_div_bps(amount_in as u128, reserve_in as u128);
    let conf_in_bps = saturating_div_bps(
        oracle_in.conf as u128,
        (oracle_in.price.unsigned_abs() as u128).max(1),
    );
    let conf_out_bps = saturating_div_bps(
        oracle_out.conf as u128,
        (oracle_out.price.unsigned_abs() as u128).max(1),
    );
    let conf_bps = core::cmp::max(conf_in_bps, conf_out_bps);

    let mut spread_bps = base_spread_bps;
    spread_bps = spread_bps
        .saturating_add(size_bps.saturating_mul(cfg.size_spread_mult_bps as u64) / 10_000);
    spread_bps = spread_bps
        .saturating_add(conf_bps.saturating_mul(cfg.conf_spread_mult_bps as u64) / 10_000);
    spread_bps =
        spread_bps.saturating_add(age_max.saturating_mul(cfg.stale_spread_bps_per_sec as u64));
    spread_bps = clamp_u64(spread_bps, 0, cfg.max_spread_bps as u64);

    // 4. Combine spread + skew
    let bps_delta = bps_delta_from_spread_and_skew(spread_bps, skew_bps, direction_sign);

    // 5. PMM quote
    let mut amount_out = quote_pmm_oracle_mid(
        amount_in, dec_in, dec_out, oracle_num, oracle_den, bps_delta,
    );

    // 6. CPMM cap (large trades only)
    let cpmm_cap_min = cfg.cpmm_cap_min_size_bps as u64;
    let cpmm_out = quote_cpmm(amount_in, reserve_in, reserve_out);
    if cpmm_cap_min > 0 && size_bps >= cpmm_cap_min {
        amount_out = core::cmp::min(amount_out, cpmm_out);
    }

    // 7. Reserve cap
    let reserve_cap = reserve_out.saturating_sub(1);
    amount_out = core::cmp::min(amount_out, reserve_cap);

    Some(amount_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cfg() -> PmmConfig {
        PmmConfig::default()
    }

    #[test]
    fn cpmm_basic() {
        assert_eq!(quote_cpmm(900_000, 1_000_000, 1_000_000), 473_684);
    }

    #[test]
    fn pmm_oracle_mid_1to1() {
        let out = quote_pmm_oracle_mid(1_000_000, 6, 6, 1, 1, 0);
        assert_eq!(out, 1_000_000);
    }

    #[test]
    fn pmm_oracle_mid_with_spread() {
        let out = quote_pmm_oracle_mid(1_000_000, 6, 6, 1, 1, -50);
        assert_eq!(out, 995_000);
    }

    #[test]
    fn delta_never_positive() {
        for spread in [0u64, 50, 200, 500, 9_999] {
            for shift in [-5_000i64, -500, 0, 500, 5_000] {
                for dir in [-1i64, 1] {
                    let d = bps_delta_from_spread_and_skew(spread, shift, dir);
                    assert!(d <= 0, "spread={spread} shift={shift} dir={dir} delta={d}");
                }
            }
        }
    }

    #[test]
    fn oracle_mid_ratio_sol_usdc() {
        let (num, den) = oracle_mid_ratio(15_000_000_000, -8, 100_000_000, -8).unwrap();
        assert_eq!(num, 15_000_000_000);
        assert_eq!(den, 100_000_000);
    }

    #[test]
    fn full_pmm_with_config() {
        let cfg = default_cfg();
        let oracle_in = PythPrice { price: 15_000_000_000, conf: 10_000_000, expo: -8, timestamp: 100 };
        let oracle_out = PythPrice { price: 100_000_000, conf: 50_000, expo: -8, timestamp: 100 };
        // Swap 1 SOL (9 dec) for USDC (6 dec), balanced pool
        let out = compute_swap_amount_out(
            &cfg,
            1_000_000_000, // 1 SOL
            100_000_000_000, // 100 SOL reserve_in
            15_000_000_000, // 15k USDC reserve_out (balanced at $150)
            9, 6, // dec_in=9 (SOL), dec_out=6 (USDC)
            30, // 30 bps base spread
            &oracle_in, &oracle_out,
            true, // a->b
            100, // now
            100_000_000_000, 15_000_000_000, // reserve_a, reserve_b
            9, 6, // dec_a, dec_b
            15_000_000_000, -8, // price_a, expo_a
            100_000_000, -8,    // price_b, expo_b
        ).unwrap();
        // Should be ~$150 worth of USDC minus spread
        assert!(out > 147_000_000 && out < 150_000_000,
            "expected ~148-149 USDC (6 dec), got {}", out);
    }

    #[test]
    fn custom_config_higher_spread() {
        let mut cfg = default_cfg();
        cfg.max_spread_bps = 1_000;        // raise cap to 10%
        cfg.size_spread_mult_bps = 0;      // isolate base spread only
        cfg.conf_spread_mult_bps = 0;
        cfg.stale_spread_bps_per_sec = 0;
        let oracle = PythPrice { price: 100_000_000, conf: 0, expo: -8, timestamp: 100 };
        // 1:1 stablecoin swap, 500 bps base spread
        let out = compute_swap_amount_out(
            &cfg,
            1_000_000, 100_000_000, 100_000_000,
            6, 6, 500,
            &oracle, &oracle,
            true, 100,
            100_000_000, 100_000_000, 6, 6,
            100_000_000, -8, 100_000_000, -8,
        ).unwrap();
        // half_spread = 250 bps → multiplier = 9750/10000 → 975_000
        assert_eq!(out, 975_000);
    }

    #[test]
    fn size_spread_kicks_in_for_large_trade() {
        let mut cfg = default_cfg();
        cfg.max_spread_bps = 5_000;         // generous cap
        cfg.size_spread_mult_bps = 1_000;   // 10% of size_bps added
        cfg.conf_spread_mult_bps = 0;
        cfg.stale_spread_bps_per_sec = 0;
        cfg.cpmm_cap_min_size_bps = 0;      // disable CPMM cap for this test
        let oracle = PythPrice { price: 100_000_000, conf: 0, expo: -8, timestamp: 100 };
        // 10% trade (1M of 10M reserve) = 1000 bps size → size_spread = 1000*1000/10000 = 100 bps
        let out = compute_swap_amount_out(
            &cfg,
            1_000_000, 10_000_000, 10_000_000,
            6, 6, 50, // 50 bps base
            &oracle, &oracle,
            true, 100,
            10_000_000, 10_000_000, 6, 6,
            100_000_000, -8, 100_000_000, -8,
        ).unwrap();
        // total_spread = 50 + 100 = 150, half = 75 → multiplier = 9925/10000
        assert_eq!(out, 992_500);
    }
}
