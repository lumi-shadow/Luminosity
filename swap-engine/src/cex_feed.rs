//! CEX circuit breaker: lightweight Binance WebSocket feed for SOL/USDT.
//!
//! Subscribes to the bookTicker stream and stores the latest mid-price atomically.
//! The quote path checks for excessive Pyth/Binance deviation and rejects quotes
//! if the prices diverge beyond a configurable threshold.
//!
//! Fails open: if Binance is unreachable or data is stale, quotes proceed normally.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use tracing::{info, warn};

/// Binance SOL/USDT mid-price in micro-USD (1e-6). $87.56 → 87_560_000.
static CEX_MID_MICRO: AtomicI64 = AtomicI64::new(0);
/// Epoch millis of the last successful price update.
static CEX_LAST_MS: AtomicU64 = AtomicU64::new(0);
/// Running count of circuit-breaker trips (for admin status / metrics).
static CEX_TRIPS: AtomicU64 = AtomicU64::new(0);

const BINANCE_WS_URL: &str = "wss://stream.binance.com:9443/ws/solusdt@bookTicker";
const STALE_THRESHOLD_MS: u64 = 10_000;

#[allow(dead_code)]
pub fn mid_price_micro() -> i64 {
    CEX_MID_MICRO.load(Ordering::Relaxed)
}

#[allow(dead_code)]
pub fn last_update_ms() -> u64 {
    CEX_LAST_MS.load(Ordering::Relaxed)
}

#[allow(dead_code)]
pub fn trip_count() -> u64 {
    CEX_TRIPS.load(Ordering::Relaxed)
}

/// Check that the Pyth oracle price for SOL/USD doesn't deviate too far from Binance.
///
/// Returns `Ok(())` when the deviation is within bounds **or** when the check
/// should be skipped (no data / stale feed). Returns `Err` with a human-readable
/// message when the circuit breaker trips.
pub fn check_deviation(
    oracle_sol_price: i64,
    oracle_sol_expo: i32,
    threshold_bps: u64,
) -> Result<(), String> {
    let cex_micro = CEX_MID_MICRO.load(Ordering::Relaxed);
    if cex_micro <= 0 {
        return Ok(()); // no CEX data yet — fail open
    }

    let now_ms = crate::utils::now_ms() as u64;
    let last = CEX_LAST_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) > STALE_THRESHOLD_MS {
        return Ok(()); // stale CEX data — fail open
    }

    // Convert Pyth price to micro-USD: price × 10^(expo + 6)
    let shift = oracle_sol_expo + 6;
    let pyth_micro: i64 = if shift >= 0 {
        oracle_sol_price.saturating_mul(10i64.saturating_pow(shift as u32))
    } else {
        oracle_sol_price / 10i64.saturating_pow((-shift) as u32)
    };

    if pyth_micro <= 0 {
        return Ok(());
    }

    let diff = (pyth_micro - cex_micro).unsigned_abs();
    let dev_bps = diff * 10_000 / cex_micro.unsigned_abs().max(1);

    if dev_bps > threshold_bps as u64 {
        CEX_TRIPS.fetch_add(1, Ordering::Relaxed);
        return Err(format!(
            "CEX circuit breaker: Pyth/Binance SOL deviation {dev_bps}bps exceeds {threshold_bps}bps threshold"
        ));
    }

    Ok(())
}

/// Spawn the Binance WebSocket listener. Reconnects automatically on failure.
pub fn spawn_binance_listener() {
    tokio::spawn(async move {
        loop {
            match run_ws_loop().await {
                Ok(()) => info!("Binance WS closed cleanly, reconnecting…"),
                Err(e) => warn!("Binance WS error: {e}, reconnecting in 2s…"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
}

async fn run_ws_loop() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let (ws_stream, _) = tokio_tungstenite::connect_async(BINANCE_WS_URL).await?;
    info!("connected to Binance WS (solusdt@bookTicker)");

    let (_, mut read) = ws_stream.split();

    while let Some(msg) = read.next().await {
        let msg = msg?;
        match msg {
            Message::Text(text) => {
                if let Some((bid, ask)) = parse_book_ticker(&text) {
                    let mid = ((bid + ask) / 2.0 * 1_000_000.0) as i64;
                    CEX_MID_MICRO.store(mid, Ordering::Relaxed);
                    CEX_LAST_MS.store(crate::utils::now_ms() as u64, Ordering::Relaxed);
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    Ok(())
}

/// Parse a Binance bookTicker JSON message into (best_bid, best_ask).
fn parse_book_ticker(text: &str) -> Option<(f64, f64)> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let bid: f64 = v.get("b")?.as_str()?.parse().ok()?;
    let ask: f64 = v.get("a")?.as_str()?.parse().ok()?;
    if bid > 0.0 && ask > 0.0 {
        Some((bid, ask))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_book_ticker() {
        let msg = r#"{"u":400900217,"s":"SOLUSDT","b":"87.56","B":"100.05","a":"87.57","A":"43.73"}"#;
        let (bid, ask) = parse_book_ticker(msg).unwrap();
        assert!((bid - 87.56).abs() < 0.001);
        assert!((ask - 87.57).abs() < 0.001);
    }

    #[test]
    fn test_check_deviation_no_data() {
        // With no CEX data loaded (static is 0), should fail open
        assert!(check_deviation(8756000000, -8, 15).is_ok());
    }
}
