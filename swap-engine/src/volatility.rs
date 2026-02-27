//! Real-time volatility and momentum tracker for RFQ spread adjustment.
//!
//! Observes every oracle price update (every ~400ms from Hermes) and computes:
//!   - **EWMA sigma (volatility)**: exponentially-weighted std-dev of log-returns
//!   - **EWMA momentum**: exponentially-weighted signed mean of log-returns
//!
//! The quote path reads these atomically — zero locks, zero allocations.
//!
//! ## Usage in RFQ quoting
//!
//! ```text
//! effective_spread = base_spread + vol_mult * sigma_bps
//! mid_shift        = momentum_mult * momentum_bps * direction
//! ```
//!
//! During calm markets sigma is low → tight spread, competitive.
//! During a dump sigma spikes → wide spread, you either win at fat margin or
//! naturally lose the route to a CEX hedger. Either way you don't bleed.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::OnceLock;

/// Compact per-feed volatility state, updated atomically.
struct FeedState {
    last_price: AtomicI64,
    /// EWMA of squared log-returns (ppm^2).
    var_scaled: AtomicU64,
    /// EWMA of signed log-returns (ppm).
    mean_scaled: AtomicI64,
    obs_count: AtomicU64,
    /// EWMA of conf/price ratio (ppm) — used as baseline to detect spikes.
    conf_ewma_ppm: AtomicU64,
}

impl FeedState {
    const fn new() -> Self {
        Self {
            last_price: AtomicI64::new(0),
            var_scaled: AtomicU64::new(0),
            mean_scaled: AtomicI64::new(0),
            obs_count: AtomicU64::new(0),
            conf_ewma_ppm: AtomicU64::new(0),
        }
    }
}

/// Fixed-size tracker for up to 8 feeds. Keyed by feed-id hash for O(1) lookup.
const MAX_FEEDS: usize = 8;

struct VolatilityTracker {
    feeds: [FeedState; MAX_FEEDS],
    feed_ids: [OnceLock<u64>; MAX_FEEDS],
    /// EWMA decay factor in parts-per-million (e.g. 50_000 = α of 0.05).
    alpha_ppm: u64,
}

static TRACKER: VolatilityTracker = VolatilityTracker {
    feeds: [
        FeedState::new(), FeedState::new(), FeedState::new(), FeedState::new(),
        FeedState::new(), FeedState::new(), FeedState::new(), FeedState::new(),
    ],
    feed_ids: [
        OnceLock::new(), OnceLock::new(), OnceLock::new(), OnceLock::new(),
        OnceLock::new(), OnceLock::new(), OnceLock::new(), OnceLock::new(),
    ],
    alpha_ppm: 50_000, // α = 0.05 → ~20-observation half-life (~8 seconds at 400ms refresh)
};

fn feed_hash(feed_id: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in feed_id.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn slot_for(feed_id: &str) -> Option<usize> {
    let h = feed_hash(feed_id);
    for (i, lock) in TRACKER.feed_ids.iter().enumerate() {
        match lock.get() {
            Some(&stored) if stored == h => return Some(i),
            None => {
                let _ = lock.set(h);
                if lock.get() == Some(&h) {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Call this every time a Hermes price update arrives for a feed.
/// Safe to call from any thread — fully lock-free.
pub fn observe_price(feed_id: &str, price: i64) {
    let Some(idx) = slot_for(feed_id) else { return };
    let state = &TRACKER.feeds[idx];

    let prev = state.last_price.swap(price, Ordering::Relaxed);
    if prev == 0 || price <= 0 || prev <= 0 {
        state.obs_count.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let return_ppm: i64 = ((price as i128 - prev as i128) * 1_000_000 / prev as i128) as i64;

    let alpha = TRACKER.alpha_ppm;
    let one_minus_alpha = 1_000_000u64.saturating_sub(alpha);

    let sq = (return_ppm as i128 * return_ppm as i128) as u64;
    let old_var = state.var_scaled.load(Ordering::Relaxed);
    let new_var = ((alpha as u128 * sq as u128 + one_minus_alpha as u128 * old_var as u128)
        / 1_000_000u128) as u64;
    state.var_scaled.store(new_var, Ordering::Relaxed);

    let old_mean = state.mean_scaled.load(Ordering::Relaxed);
    let new_mean = ((alpha as i128 * return_ppm as i128
        + one_minus_alpha as i128 * old_mean as i128)
        / 1_000_000i128) as i64;
    state.mean_scaled.store(new_mean, Ordering::Relaxed);

    state.obs_count.fetch_add(1, Ordering::Relaxed);
}

/// Inject oracle confidence as a synthetic variance signal — only when spiking.
///
/// Tracks an EWMA of conf/price. When the current reading exceeds 1.5x its
/// own EWMA (i.e. confidence is abnormally wide), we inject the excess into
/// the variance tracker. Steady-state confidence adds zero.
pub fn observe_confidence(feed_id: &str, conf: u64, price: i64) {
    if price <= 0 || conf == 0 { return; }
    let Some(idx) = slot_for(feed_id) else { return };
    let state = &TRACKER.feeds[idx];

    let conf_ppm = (conf as u128 * 1_000_000 / price.unsigned_abs() as u128) as u64;

    // Update EWMA of conf_ppm (slow decay for a stable baseline).
    let alpha_slow = TRACKER.alpha_ppm / 4; // quarter speed
    let one_minus_slow = 1_000_000u64.saturating_sub(alpha_slow);
    let old_ewma = state.conf_ewma_ppm.load(Ordering::Relaxed);
    let new_ewma = if old_ewma == 0 {
        conf_ppm // seed with first observation
    } else {
        ((alpha_slow as u128 * conf_ppm as u128
            + one_minus_slow as u128 * old_ewma as u128)
            / 1_000_000u128) as u64
    };
    state.conf_ewma_ppm.store(new_ewma, Ordering::Relaxed);

    // Only inject into vol when conf is >1.5x its baseline (a real spike).
    let threshold = new_ewma.saturating_mul(3) / 2;
    if conf_ppm <= threshold {
        return;
    }

    let excess_ppm = conf_ppm.saturating_sub(new_ewma);
    let excess_sq = excess_ppm as u128 * excess_ppm as u128;

    let alpha_conf = TRACKER.alpha_ppm / 2;
    let one_minus = 1_000_000u64.saturating_sub(alpha_conf);

    let old_var = state.var_scaled.load(Ordering::Relaxed);
    let new_var = ((alpha_conf as u128 * excess_sq
        + one_minus as u128 * old_var as u128)
        / 1_000_000u128) as u64;
    state.var_scaled.store(new_var, Ordering::Relaxed);
}

/// Read current volatility for a feed.
/// Returns `sigma_bps`: annualised-style instantaneous vol in basis points.
///
/// More precisely: the EWMA standard deviation of per-tick returns, scaled to bps.
/// At 400ms ticks, one second ≈ 2.5 ticks.
pub fn sigma_bps(feed_id: &str) -> u64 {
    let Some(idx) = slot_for(feed_id) else { return 0 };
    let state = &TRACKER.feeds[idx];
    if state.obs_count.load(Ordering::Relaxed) < 5 {
        return 0; // warmup: not enough data
    }
    let var = state.var_scaled.load(Ordering::Relaxed);
    // var is in ppm^2. sigma_ppm = sqrt(var). sigma_bps = sigma_ppm / 100.
    let sigma_ppm = isqrt(var);
    (sigma_ppm / 100) as u64
}

/// Read current momentum for a feed.
/// Returns signed `momentum_bps`: positive = price rising, negative = price falling.
pub fn momentum_bps(feed_id: &str) -> i64 {
    let Some(idx) = slot_for(feed_id) else { return 0 };
    let state = &TRACKER.feeds[idx];
    if state.obs_count.load(Ordering::Relaxed) < 5 {
        return 0;
    }
    let mean = state.mean_scaled.load(Ordering::Relaxed);
    // mean is in ppm. Convert to bps: / 100.
    (mean / 100) as i64
}

/// Read both sigma and momentum for a feed in one call.
#[allow(dead_code)]
pub fn read_vol(feed_id: &str) -> (u64, i64) {
    (sigma_bps(feed_id), momentum_bps(feed_id))
}

/// Integer square root (floor).
fn isqrt(n: u64) -> u64 {
    if n == 0 { return 0; }
    let mut x = (n as f64).sqrt() as u64;
    // Newton's method correction (the f64 sqrt can be off by 1).
    loop {
        let x1 = (x + n / x) / 2;
        if x1 >= x { return x; }
        x = x1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stable_price_low_vol() {
        let feed = "test_stable";
        for i in 0..50 {
            // Price oscillates ±0.01% around 8700000000
            let p = 8700000000i64 + if i % 2 == 0 { 870000 } else { -870000 };
            observe_price(feed, p);
        }
        let s = sigma_bps(feed);
        let m = momentum_bps(feed);
        assert!(s < 20, "stable price should have low vol, got {s}");
        assert!(m.abs() < 5, "stable price should have ~0 momentum, got {m}");
    }

    #[test]
    fn test_dump_high_vol_negative_momentum() {
        let feed = "test_dump";
        let mut price = 8700000000i64;
        for _ in 0..50 {
            observe_price(feed, price);
            price -= 8700000; // -0.1% per tick
        }
        let s = sigma_bps(feed);
        let m = momentum_bps(feed);
        assert!(s > 5, "dump should have high vol, got {s}");
        assert!(m < -5, "dump should have negative momentum, got {m}");
    }

    #[test]
    fn test_isqrt_values() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(100), 10);
        assert_eq!(isqrt(10000), 100);
        assert_eq!(isqrt(99), 9);
    }
}
