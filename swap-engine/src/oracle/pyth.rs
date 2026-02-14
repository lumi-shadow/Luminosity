//! Pyth oracle helpers (Hermes HTTP).
//!
//! For the swap engine we want "Pyth-style" prices (price/conf/expo/publish_time) but we do not
//! want to hardcode Solana price account pubkeys per mint.
//!
//! We therefore use the Pyth **Hermes** price service:
//! - discover feed ids by symbol (or use built-in mapping for well-known assets)
//! - fetch latest price via `/api/latest_price_feeds?ids[]=...&verbose=true`
//!
//! This keeps the swap engine configuration-free for common pools (SOL/USDC) while still
//! returning confidence intervals and publish timestamps.

use crate::types::AppError;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone)]
pub struct OraclePrice {
    /// Price as integer with `expo` base-10 exponent (Pyth style).
    pub price: i64,
    pub conf: u64,
    pub expo: i32,
    pub publish_time: i64,
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[derive(serde::Deserialize)]
struct HermesLatestPriceFeed {
    #[allow(dead_code)]
    id: String,
    price: HermesPrice,
}

#[derive(serde::Deserialize)]
struct HermesPrice {
    price: String,
    conf: String,
    expo: i32,
    publish_time: i64,
}

static HERMES_PRICE_CACHE: OnceLock<RwLock<HashMap<String, OraclePrice>>> = OnceLock::new();

fn hermes_cache() -> &'static RwLock<HashMap<String, OraclePrice>> {
    HERMES_PRICE_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn get_cached_hermes_price(feed_id_hex: &str) -> Option<OraclePrice> {
    hermes_cache()
        .read()
        .ok()
        .and_then(|m| m.get(feed_id_hex).cloned())
}

fn upsert_cached_prices(prices: HashMap<String, OraclePrice>) {
    if let Ok(mut g) = hermes_cache().write() {
        for (k, v) in prices {
            g.insert(k, v);
        }
    }
}

fn validate_oracle_price(p: &OraclePrice) -> Result<(), AppError> {
    // Basic sanity checks to fail closed on malformed oracle data.
    if p.price <= 0 {
        return Err(AppError::BadGateway("oracle price must be > 0".into()));
    }
    // Pyth expo is typically a small negative integer (e.g. -8). Keep a generous bound.
    if p.expo < -30 || p.expo > 30 {
        return Err(AppError::BadGateway(format!(
            "oracle expo out of range: {} (expected [-30, 30])",
            p.expo
        )));
    }
    // publish_time is unix seconds.
    if p.publish_time <= 0 {
        return Err(AppError::BadGateway("oracle publish_time invalid".into()));
    }
    Ok(())
}

pub async fn load_hermes_prices(
    http: &reqwest::Client,
    hermes_url: &str,
    feed_ids_hex: &[String],
) -> Result<HashMap<String, OraclePrice>, AppError> {
    if feed_ids_hex.is_empty() {
        return Ok(HashMap::new());
    }
    let mut qs = String::new();
    for (i, id) in feed_ids_hex.iter().enumerate() {
        if i > 0 {
            qs.push('&');
        }
        qs.push_str("ids[]=");
        qs.push_str(id);
    }
    let url = format!(
        "{}/api/latest_price_feeds?{}&verbose=true",
        hermes_url.trim_end_matches('/'),
        qs
    );
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| AppError::BadGateway(format!("hermes fetch failed: {e}")))?;
    if !resp.status().is_success() {
        if resp.status().as_u16() == 429 {
            return Err(AppError::Unavailable(
                "hermes rate limited (HTTP 429). Public API allows 30 requests / 10s / IP; back off or use a Hermes node provider."
                    .into(),
            ));
        }
        return Err(AppError::BadGateway(format!(
            "hermes HTTP {}",
            resp.status()
        )));
    }
    let feeds: Vec<HermesLatestPriceFeed> = resp
        .json()
        .await
        .map_err(|e| AppError::BadGateway(format!("hermes JSON parse failed: {e}")))?;
    if feeds.is_empty() {
        return Err(AppError::BadGateway(
            "hermes returned empty feed list".into(),
        ));
    }
    let mut out: HashMap<String, OraclePrice> = HashMap::new();
    for f in feeds {
        let price: i64 = f
            .price
            .price
            .parse()
            .map_err(|_| AppError::BadGateway("hermes price parse failed".into()))?;
        let conf: u64 = f
            .price
            .conf
            .parse()
            .map_err(|_| AppError::BadGateway("hermes conf parse failed".into()))?;
        let p = OraclePrice {
            price,
            conf,
            expo: f.price.expo,
            publish_time: f.price.publish_time,
        };
        validate_oracle_price(&p)?;
        out.insert(f.id, p);
    }
    Ok(out)
}

pub async fn load_hermes_price(
    http: &reqwest::Client,
    hermes_url: &str,
    feed_id_hex: &str,
) -> Result<OraclePrice, AppError> {
    let url = format!(
        "{}/api/latest_price_feeds?ids[]={}&verbose=true",
        hermes_url.trim_end_matches('/'),
        feed_id_hex
    );
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| AppError::BadGateway(format!("hermes fetch failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::BadGateway(format!(
            "hermes HTTP {}",
            resp.status()
        )));
    }
    let feeds: Vec<HermesLatestPriceFeed> = resp
        .json()
        .await
        .map_err(|e| AppError::BadGateway(format!("hermes JSON parse failed: {e}")))?;
    let f = feeds
        .into_iter()
        .next()
        .ok_or_else(|| AppError::BadGateway("hermes returned empty feed list".into()))?;

    let price: i64 = f
        .price
        .price
        .parse()
        .map_err(|_| AppError::BadGateway("hermes price parse failed".into()))?;
    let conf: u64 = f
        .price
        .conf
        .parse()
        .map_err(|_| AppError::BadGateway("hermes conf parse failed".into()))?;

    let p = OraclePrice {
        price,
        conf,
        expo: f.price.expo,
        publish_time: f.price.publish_time,
    };
    validate_oracle_price(&p)?;
    Ok(p)
}

/// Background cache refresher for Hermes prices.
///
/// Goal: keep `/quote` fast by avoiding per-request Hermes HTTP calls.
pub async fn hermes_cache_loop(
    http: reqwest::Client,
    hermes_url: String,
    feed_ids_hex: Vec<String>,
    refresh_ms: u64,
) {
    let refresh_ms = refresh_ms.max(50);
    loop {
        match load_hermes_prices(&http, &hermes_url, &feed_ids_hex).await {
            Ok(prices) => upsert_cached_prices(prices),
            Err(e) => {
                tracing::warn!("hermes cache refresh failed: {e}");
                // Public Hermes applies a 60s penalty after 429. Respect it to avoid extended downtime.
                if e.to_string().contains("HTTP 429") || e.to_string().contains("rate limited") {
                    sleep(Duration::from_secs(60)).await;
                    continue;
                }
            }
        }
        sleep(Duration::from_millis(refresh_ms)).await;
    }
}

pub fn enforce_staleness(
    price: &OraclePrice,
    max_age_secs: u64,
    max_future_secs: u64,
) -> Result<(), AppError> {
    validate_oracle_price(price)?;
    // Pyth publish time is in unix seconds.
    let now = now_unix();
    if price.publish_time > now.saturating_add(max_future_secs as i64) {
        return Err(AppError::Forbidden(format!(
            "oracle publish_time too far in the future: publish_time={} now={} max_future_secs={}",
            price.publish_time, now, max_future_secs
        )));
    }
    // If slightly in the future (clock skew), treat age as 0.
    let age = now.saturating_sub(price.publish_time).max(0);
    if age as u64 > max_age_secs {
        return Err(AppError::Forbidden(format!(
            "oracle price too old: age_secs={} max_age_secs={}",
            age, max_age_secs
        )));
    }
    Ok(())
}

/// Return an inclusive band \([lo, hi]\) for the price, using `conf_mult_bps` * confidence.
pub fn conf_band(price: &OraclePrice, conf_mult_bps: u64) -> (i128, i128) {
    // Larix-style: widen the confidence interval by a multiplier, then accept any trade
    // that implies an exchange rate inside those widened bounds.
    let p = price.price as i128;
    let c = price.conf as i128;
    let mult = conf_mult_bps as i128; // bps of 1x = 10_000
    // Use saturating math to avoid overflow with misconfiguration/extreme values.
    let extra = c
        .saturating_mul(mult)
        .saturating_div(10_000i128);
    (p.saturating_sub(extra), p.saturating_add(extra))
}
