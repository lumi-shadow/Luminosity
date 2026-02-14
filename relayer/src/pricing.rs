use crate::error::AppError;
use crate::state::AppState;
use crate::utils::now_ms;
use solana_sdk::program_pack::Pack;
use solana_sdk::pubkey::Pubkey;
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use std::sync::Arc;

const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
// Hermes feed ids (mainnet), kept in sync with swap-engine defaults:
const HERMES_SOL_USD_ID: &str = "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
const HERMES_USDC_USD_ID: &str = "eaa020c61cc479712813461ce153894a96a6c00b21ed0cfc2798d1f9a9e9c94a";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeOp {
    DepositAsset,
    WithdrawAsset,
}

impl FeeOp {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "deposit" | "deposit_asset" => Some(FeeOp::DepositAsset),
            "withdraw" | "withdraw_asset" => Some(FeeOp::WithdrawAsset),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PricePoint {
    pub usd_micro: u64, // USD * 1e6
    pub decimals: u8,
    pub fetched_ts_ms: u128,
}

#[derive(Debug, Clone)]
pub struct FeeQuote {
    pub op: FeeOp,
    pub mint: Pubkey,
    pub amount: u64,     // base units
    pub fee_amount: u64, // base units
    /// If true, fee was waived because the amount is too small.
    pub fee_waived: bool,
    /// For deposits: minimum amount required to proceed (fee + 5% buffer). For withdraws: 0.
    pub min_amount: u64,
    /// Whether this operation is allowed for the given amount.
    pub allowed: bool,
    pub fee_usd_micro: u64,
    pub price_usd_micro: u64,
    pub decimals: u8,
}

fn pow10_u128(decimals: u8) -> u128 {
    let mut x: u128 = 1;
    for _ in 0..decimals {
        x = x.saturating_mul(10);
    }
    x
}

fn ceil_div_u128(n: u128, d: u128) -> u128 {
    if d == 0 {
        return u128::MAX;
    }
    (n + d - 1) / d
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
    #[allow(dead_code)]
    conf: String,
    expo: i32,
    #[allow(dead_code)]
    publish_time: i64,
}

fn pow10_i128(exp: u32) -> i128 {
    let mut x: i128 = 1;
    for _ in 0..exp {
        x = x.saturating_mul(10);
    }
    x
}

fn hermes_cfg() -> Result<(String, HashMap<Pubkey, String>), AppError> {
    let hermes_url =
        env::var("HERMES_URL").unwrap_or_else(|_| "https://hermes.pyth.network".to_string());
    let mut hermes_feed_ids: HashMap<Pubkey, String> = HashMap::new();
    // Built-in defaults for WSOL + USDC.
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
    let raw: HashMap<String, String> = serde_json::from_str(&hermes_feeds_json).map_err(|_| {
        AppError::BadGateway(
            "Invalid HERMES_FEEDS_JSON (expected JSON map mint->feed_id_hex)".into(),
        )
    })?;
    for (mint_s, id_hex) in raw {
        let mint = Pubkey::from_str(&mint_s)
            .map_err(|_| AppError::BadGateway("Invalid mint pubkey in HERMES_FEEDS_JSON".into()))?;
        hermes_feed_ids.insert(mint, id_hex);
    }
    Ok((hermes_url, hermes_feed_ids))
}

pub fn configured_hermes_feeds() -> Result<(String, Vec<(Pubkey, String)>), AppError> {
    let (url, map) = hermes_cfg()?;
    let mut v: Vec<(Pubkey, String)> = map.into_iter().collect();
    v.sort_by(|a, b| a.0.to_string().cmp(&b.0.to_string()));
    Ok((url, v))
}

fn usd_micro_from_pyth_price(price: i64, expo: i32) -> Result<u64, AppError> {
    if price <= 0 {
        return Err(AppError::BadGateway("oracle price must be > 0".into()));
    }
    // price_usd = price * 10^expo
    // usd_micro = price_usd * 1e6 = price * 10^(expo+6)
    let e = expo + 6;
    let p = price as i128;
    let v_i128 = if e >= 0 {
        p.saturating_mul(pow10_i128(e as u32))
    } else {
        // Round to nearest micro: (p / 10^-e) with half-up rounding.
        let d = pow10_i128((-e) as u32);
        (p.saturating_mul(2).saturating_add(d)) / (2 * d)
    };
    if v_i128 <= 0 {
        return Err(AppError::BadGateway("oracle usd_micro underflow".into()));
    }
    if v_i128 > (u64::MAX as i128) {
        return Err(AppError::BadGateway("oracle usd_micro overflow".into()));
    }
    Ok(v_i128 as u64)
}

fn mint_decimals_cached(state: &Arc<AppState>, mint: Pubkey) -> Result<u8, AppError> {
    {
        let g = state.mint_decimals_cache.lock().unwrap();
        if let Some(d) = g.get(&mint) {
            return Ok(*d);
        }
    }
    let acc = state
        .rpc
        .get_account(&mint)
        .map_err(|e| AppError::BadGateway(format!("mint fetch failed: {e}")))?;
    let m = spl_token::state::Mint::unpack(&acc.data)
        .map_err(|_| AppError::BadGateway("failed to decode mint account".into()))?;
    let d = m.decimals;
    {
        let mut g = state.mint_decimals_cache.lock().unwrap();
        g.insert(mint, d);
    }
    Ok(d)
}

async fn fetch_hermes_usd_micro(mint: Pubkey) -> Result<u64, AppError> {
    let (hermes_url, map) = hermes_cfg()?;
    let feed = map.get(&mint).ok_or_else(|| {
        AppError::BadGateway("missing oracle feed for mint (configure HERMES_FEEDS_JSON)".into())
    })?;

    let url = format!(
        "{}/api/latest_price_feeds?ids[]={}&verbose=true",
        hermes_url.trim_end_matches('/'),
        feed
    );
    let http = reqwest::Client::new();
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
    usd_micro_from_pyth_price(price, f.price.expo)
}

pub fn compute_fee_quote(
    op: FeeOp,
    mint: Pubkey,
    amount: u64,
    price: &PricePoint,
) -> Result<FeeQuote, AppError> {
    if amount == 0 {
        return Err(AppError::BadRequest("amount must be > 0".into()));
    }
    if price.usd_micro == 0 {
        return Err(AppError::BadGateway(
            "pricing unavailable (usd_micro=0)".into(),
        ));
    }

    // Fee model (launch defaults):
    // - Deposit (light proof): 5 bps + $0.05, cap $2
    // - Withdraw (3.6M constraints): 10 bps + $0.25, min $0.25, cap $5
    let (bps, base_usd_micro, min_usd_micro, cap_usd_micro) = match op {
        FeeOp::DepositAsset => (5u64, 50_000u64, 50_000u64, 2_000_000u64),
        FeeOp::WithdrawAsset => (10u64, 250_000u64, 250_000u64, 5_000_000u64),
    };

    let scale = pow10_u128(price.decimals);
    let amount_usd_micro: u64 = {
        let n = (amount as u128).saturating_mul(price.usd_micro as u128);
        let v = (n / scale).min(u64::MAX as u128);
        v as u64
    };

    let bps_component: u64 = {
        // ceil(amount_usd * bps / 10_000)
        let n = (amount_usd_micro as u128)
            .saturating_mul(bps as u128)
            .saturating_add(9_999);
        ((n / 10_000).min(u64::MAX as u128)) as u64
    };

    let mut fee_usd_micro = base_usd_micro.saturating_add(bps_component);
    if fee_usd_micro < min_usd_micro {
        fee_usd_micro = min_usd_micro;
    }
    if fee_usd_micro > cap_usd_micro {
        fee_usd_micro = cap_usd_micro;
    }

    // Convert fee USD -> token base units: ceil(fee_usd * 10^decimals / price_usd)
    let fee_amount_u128 = ceil_div_u128(
        (fee_usd_micro as u128).saturating_mul(scale),
        price.usd_micro as u128,
    );
    if fee_amount_u128 > (u64::MAX as u128) {
        return Err(AppError::Internal("fee amount overflow".into()));
    }
    let mut fee_amount = fee_amount_u128 as u64;
    let mut fee_waived = false;
    let mut min_amount: u64 = 0;
    let mut allowed: bool = true;

    // Abuse guard / dust policy:
    // - Withdraw: never lock dust -> waive fee if it would consume the amount.
    // - Deposit: NEVER waive; require amount >= fee + 5% buffer (so users don't spam tiny deposits
    //   and so the fee can't be gamed).
    if fee_amount >= amount {
        match op {
            FeeOp::WithdrawAsset => {
                fee_amount = 0;
                fee_usd_micro = 0;
                fee_waived = true;
            }
            FeeOp::DepositAsset => {
                allowed = false;
            }
        }
    }

    if matches!(op, FeeOp::DepositAsset) {
        // min_amount = fee + ceil(fee * 5 / 100)
        let buf = ((fee_amount as u128).saturating_mul(5).saturating_add(99) / 100) as u64;
        min_amount = fee_amount.saturating_add(buf.max(1));
        if amount < min_amount {
            allowed = false;
        }
    }

    Ok(FeeQuote {
        op,
        mint,
        amount,
        fee_amount,
        fee_waived,
        min_amount,
        allowed,
        fee_usd_micro,
        price_usd_micro: price.usd_micro,
        decimals: price.decimals,
    })
}

async fn fetch_hermes_price_point(
    state: Arc<AppState>,
    mint: Pubkey,
) -> Result<PricePoint, AppError> {
    let usd_micro = fetch_hermes_usd_micro(mint).await?;
    let decimals = mint_decimals_cached(&state, mint)?;
    Ok(PricePoint {
        usd_micro,
        decimals,
        fetched_ts_ms: now_ms(),
    })
}

pub async fn get_price_point_cached(
    state: Arc<AppState>,
    mint: Pubkey,
) -> Result<PricePoint, AppError> {
    const TTL_MS: u128 = 30_000;
    let max_stale_secs: u128 = env::var("FEE_ORACLE_MAX_STALENESS_SECS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(600);
    let max_stale_ms: u128 = max_stale_secs.saturating_mul(1_000);
    {
        let cache = state.price_cache.lock().unwrap();
        if let Some(v) = cache.get(&mint) {
            if now_ms().saturating_sub(v.fetched_ts_ms) <= TTL_MS {
                return Ok(v.clone());
            }
        }
    }

    let fresh = match fetch_hermes_price_point(state.clone(), mint).await {
        Ok(v) => v,
        Err(e) => {
            // Availability: if Hermes is briefly down, fall back to cached price for a while.
            let cache = state.price_cache.lock().unwrap();
            if let Some(v) = cache.get(&mint) {
                if now_ms().saturating_sub(v.fetched_ts_ms) <= max_stale_ms {
                    return Ok(v.clone());
                }
            }
            return Err(e);
        }
    };
    {
        let mut cache = state.price_cache.lock().unwrap();
        cache.insert(mint, fresh.clone());
    }
    Ok(fresh)
}

pub async fn quote_fee(
    state: Arc<AppState>,
    op: FeeOp,
    mint_str: &str,
    amount: u64,
) -> Result<FeeQuote, AppError> {
    let mint = Pubkey::from_str(mint_str.trim())
        .map_err(|_| AppError::BadRequest("Invalid mint".into()))?;
    let price = get_price_point_cached(state, mint).await?;
    compute_fee_quote(op, mint, amount, &price)
}
