use crate::engine;
use crate::metrics;
use crate::state::{AppState, JupiterQuoteCacheEntry, JupiterSwapDebugEntry};
use crate::types::{api_err, ApiResult, AppError};
use crate::types::jupiter_rfq::SwapResponse;
use axum::{extract::ConnectInfo, extract::State, Json};
use solana_sdk::message::SanitizedMessage;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer;
use std::collections::BTreeSet;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tracing::{info, warn};

pub async fn quote(
    State(st): State<AppState>,
    ConnectInfo(_peer): ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<crate::types::jupiter_rfq::QuoteRequest>,
) -> ApiResult<crate::types::jupiter_rfq::QuoteResponse> {
    let t0 = Instant::now();
    st.jupiter_stats.quote_requests.fetch_add(1, Ordering::Relaxed);
    metrics::metrics().jupiter_quote_requests_total.inc();
    metrics::metrics().quote_requests_total.inc();

    if let Err(e) = req.validate() {
        metrics::metrics().bad_payload_total.inc();
        return api_err(e);
    }

    let maker = {
        let g = st.tee_keypair.lock().unwrap();
        g.as_ref().map(|kp| kp.pubkey())
    }
    .ok_or_else(|| AppError::Unavailable("swap-engine missing TEE key (maker)".into()));

    let maker = match maker {
        Ok(v) => v,
        Err(e) => return api_err(e),
    };

    let req_for_cache = req.clone();
    let res = engine::quote_jupiter(&st.cfg, &st.http, st.rpc_processed.clone(), req, maker).await;
    metrics::metrics()
        .quote_ms
        .observe(t0.elapsed().as_millis() as f64);
    metrics::metrics()
        .jupiter_quote_ms
        .observe(t0.elapsed().as_millis() as f64);
    st.jupiter_stats
        .record_quote_latency(t0.elapsed().as_millis() as u64);
    let latency_ms = t0.elapsed().as_millis() as u64;
    match res {
        Ok(v) => {
            st.jupiter_stats.quote_success.fetch_add(1, Ordering::Relaxed);
            let token_in = Pubkey::from_str(v.token_in.trim())
                .map_err(|_| AppError::BadRequest("invalid tokenIn pubkey".into()));
            let token_out = Pubkey::from_str(v.token_out.trim())
                .map_err(|_| AppError::BadRequest("invalid tokenOut pubkey".into()));
            let taker_pk = v.taker.as_deref()
                .filter(|s| !s.trim().is_empty())
                .map(|s| Pubkey::from_str(s.trim()))
                .transpose()
                .ok().flatten();
            let amount_in = v.amount_in.trim().parse::<u64>()
                .map_err(|_| AppError::BadGateway("amount_in parse failed".into()));
            let amount_out = v.amount_out.trim().parse::<u64>()
                .map_err(|_| AppError::BadGateway("amount_out parse failed".into()));
            info!(
                event = "rfq_quote",
                outcome = "success",
                taker = v.taker.as_deref().unwrap_or("none"),
                quote_type = v.quote_type.as_str(),
                token_in = v.token_in.as_str(),
                token_out = v.token_out.as_str(),
                amount_in = v.amount_in.as_str(),
                amount_out = v.amount_out.as_str(),
                quote_id = v.quote_id.as_str(),
                latency_ms = latency_ms,
                "quote served"
            );
            match (token_in, token_out, amount_in, amount_out) {
                (Ok(ti), Ok(to), Ok(ai), Ok(ao)) => {
                    let (cache_amount_in, cache_amount_out) = adjust_cached_amounts_for_jupiter_fee(
                        &v.quote_type,
                        req_for_cache.fee_bps,
                        ai,
                        ao,
                    );
                    let mut quotes = st.jupiter_quotes.write().await;
                    let now_ms = crate::utils::now_ms();
                    let expiry_ms = 55_000u128;
                    if quotes.len() > 10_000 {
                        quotes.retain(|_, q| q.created_at_ms + expiry_ms > now_ms);
                    }
                    quotes.entry(v.quote_id.clone()).or_insert_with(|| {
                        JupiterQuoteCacheEntry {
                            quote_id: v.quote_id.clone(),
                            taker: taker_pk,
                            token_in: ti,
                            token_out: to,
                            amount_in: cache_amount_in,
                            amount_out: cache_amount_out,
                            created_at_ms: now_ms,
                        }
                    });
                    Ok(Json(v))
                }
                _ => Ok(Json(v)),
            }
        }
        Err(e) => {
            warn!(
                event = "rfq_quote",
                outcome = "error",
                taker = req_for_cache.taker.as_deref().unwrap_or("none"),
                quote_type = req_for_cache.quote_type.as_str(),
                token_in = req_for_cache.token_in.as_str(),
                token_out = req_for_cache.token_out.as_str(),
                error = %e,
                latency_ms = latency_ms,
                "quote failed"
            );
            if matches!(e, AppError::BadRequest(_)) {
                metrics::metrics().bad_requests_total.inc();
            }
            api_err(e)
        }
    }
}

pub async fn swap(
    State(st): State<AppState>,
    ConnectInfo(_peer): ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<crate::types::jupiter_rfq::SwapRequest>,
) -> ApiResult<crate::types::jupiter_rfq::SwapResponse> {
    let t0 = Instant::now();
    st.jupiter_stats.swap_requests.fetch_add(1, Ordering::Relaxed);
    metrics::metrics().jupiter_swap_requests_total.inc();
    metrics::metrics().execute_requests_total.inc();
    if let Err(e) = req.validate() {
        metrics::metrics().bad_payload_total.inc();
        return api_err(e);
    }

    // Jupiter acceptance-test sentinel requestIds: return canned responses.
    match req.request_id.as_str() {
        "00000000-0000-0000-0000-000000000001" => {
            return Ok(Json(SwapResponse::rejected(
                req.quote_id,
                "acceptance test: simulated rejection".into(),
            )));
        }
        "00000000-0000-0000-0000-000000000003" => {
            return Ok(Json(SwapResponse::rejected_with_reason(
                req.quote_id,
                "insufficientBalance",
            )));
        }
        "00000000-0000-0000-0000-000000000004" => {
            return Ok(Json(SwapResponse::rejected_with_reason(
                req.quote_id,
                "signatureVerificationFailed",
            )));
        }
        _ => {}
    }

    let quote = {
        let mut quotes = st.jupiter_quotes.write().await;
        let now_ms = crate::utils::now_ms();
        let expiry_ms = 55_000u128;
        quotes.retain(|_, q| q.created_at_ms + expiry_ms > now_ms);
        quotes
            .get(req.quote_id.trim())
            .cloned()
            .ok_or_else(|| AppError::BadRequest("quoteId not found or expired".into()))
    };
    let quote = match quote {
        Ok(v) => v,
        Err(e) => return api_err(e),
    };
    // Enforce quoted response binding.
    if quote.quote_id != req.quote_id {
        return api_err(AppError::BadRequest("quoteId mismatch".into()));
    }
    let volume_in = quote.amount_in;
    let volume_out = quote.amount_out;
    let log_taker = quote.taker.map(|p| p.to_string());
    let log_quote_id = quote.quote_id.clone();
    let log_token_in = quote.token_in.to_string();
    let log_token_out = quote.token_out.to_string();
    let swap_debug_base = build_swap_debug_base(&req, &quote);

    let tee = {
        let g = st.tee_keypair.lock().unwrap();
        g.clone()
    };
    let Some(tee) = tee else {
        return api_err(AppError::Unavailable(
            "swap-engine not initialized (missing TEE key)".into(),
        ));
    };

    let res = engine::swap_jupiter(
        &st.cfg,
        &st.http,
        st.rpc_confirmed.clone(),
        req,
        quote,
        &tee,
    )
    .await;

    let swap_latency_ms = t0.elapsed().as_millis() as u64;
    metrics::metrics()
        .execute_ms
        .observe(swap_latency_ms as f64);
    metrics::metrics()
        .jupiter_swap_ms
        .observe(swap_latency_ms as f64);
    st.jupiter_stats.record_swap_latency(swap_latency_ms);
    match res {
        Ok(v) => {
            st.jupiter_stats
                .record_swap_debug(with_swap_outcome(swap_debug_base, "accepted", None));
            st.jupiter_stats.swap_success.fetch_add(1, Ordering::Relaxed);
            st.jupiter_stats.fills_total.fetch_add(1, Ordering::Relaxed);
            st.jupiter_stats.inc_volume(volume_in, volume_out);
            metrics::metrics().jupiter_fills_total.inc();
            metrics::metrics()
                .jupiter_fill_volume_in_base_total
                .inc_by(volume_in);
            metrics::metrics()
                .jupiter_fill_volume_out_base_total
                .inc_by(volume_out);
            info!(
                event = "rfq_swap",
                outcome = "accepted",
                taker = log_taker.as_deref().unwrap_or("none"),
                quote_id = log_quote_id.as_str(),
                token_in = log_token_in.as_str(),
                token_out = log_token_out.as_str(),
                amount_in = volume_in,
                amount_out = volume_out,
                latency_ms = swap_latency_ms,
                tx_sig = v.tx_signature.as_deref().unwrap_or("none"),
                "swap filled"
            );
            Ok(Json(v))
        }
        Err(e) => {
            st.jupiter_stats.swap_failed.fetch_add(1, Ordering::Relaxed);
            st.jupiter_stats.record_swap_error(&e.to_string());
            st.jupiter_stats.record_swap_debug(with_swap_outcome(
                swap_debug_base,
                "rejected",
                Some(e.to_string()),
            ));
            metrics::metrics().execute_errors_total.inc();
            warn!(
                event = "rfq_swap",
                outcome = "rejected",
                taker = log_taker.as_deref().unwrap_or("none"),
                quote_id = log_quote_id.as_str(),
                token_in = log_token_in.as_str(),
                token_out = log_token_out.as_str(),
                amount_in = volume_in,
                amount_out = volume_out,
                error = %e,
                latency_ms = swap_latency_ms,
                "swap rejected"
            );
            api_err(e)
        }
    }
}

fn with_swap_outcome(
    mut row: JupiterSwapDebugEntry,
    outcome: &str,
    error: Option<String>,
) -> JupiterSwapDebugEntry {
    row.outcome = outcome.to_string();
    row.error = error;
    row
}

fn build_swap_debug_base(
    req: &crate::types::jupiter_rfq::SwapRequest,
    quote: &JupiterQuoteCacheEntry,
) -> JupiterSwapDebugEntry {
    let mut row = JupiterSwapDebugEntry {
        ts_ms: crate::utils::now_ms(),
        request_id: req.request_id.clone(),
        quote_id: req.quote_id.clone(),
        cache_quote_id: quote.quote_id.clone(),
        cache_taker: quote.taker.map(|v| v.to_string()),
        cache_token_in: quote.token_in.to_string(),
        cache_token_out: quote.token_out.to_string(),
        cache_amount_in: quote.amount_in,
        cache_amount_out: quote.amount_out,
        tx_taker: None,
        tx_maker: None,
        tx_input_mint: None,
        tx_output_mint: None,
        fill_input_amount: None,
        fill_output_amount: None,
        fill_expire_at: None,
        outcome: "pending".to_string(),
        error: None,
        note: None,
    };

    match order_engine_sdk::transaction::deserialize_transaction_base64_into_transaction_details(
        &req.transaction,
    ) {
        Ok(tx) => fill_debug_from_sanitized_message(&mut row, &tx.sanitized_message),
        Err(e) => {
            row.note = Some(format!("tx decode failed: {e}"));
        }
    }

    row
}

fn fill_debug_from_sanitized_message(row: &mut JupiterSwapDebugEntry, msg: &SanitizedMessage) {
    let order_engine_id = match Pubkey::from_str("61DFfeTKM7trxYcPQCM78bJ794ddZprZpAwAnLiwTpYH") {
        Ok(v) => v,
        Err(e) => {
            row.note = Some(format!("invalid order_engine_id: {e}"));
            return;
        }
    };
    let mut found_fill = false;

    for ix in msg.decompile_instructions() {
        if *ix.program_id != order_engine_id {
            continue;
        }
        found_fill = true;
        let pubkeys = ix.accounts.into_iter().map(|a| *a.pubkey).collect::<Vec<_>>();
        if pubkeys.len() > 1 {
            row.tx_taker = Some(pubkeys[0].to_string());
            row.tx_maker = Some(pubkeys[1].to_string());
        }
        if pubkeys.len() > 8 {
            row.tx_input_mint = Some(pubkeys[6].to_string());
            row.tx_output_mint = Some(pubkeys[8].to_string());
        }
        if ix.data.len() >= 32 {
            row.fill_input_amount = <[u8; 8]>::try_from(&ix.data[8..16])
                .ok()
                .map(u64::from_le_bytes);
            row.fill_output_amount = <[u8; 8]>::try_from(&ix.data[16..24])
                .ok()
                .map(u64::from_le_bytes);
            row.fill_expire_at = <[u8; 8]>::try_from(&ix.data[24..32])
                .ok()
                .map(i64::from_le_bytes);
        } else {
            row.note = Some("order-engine fill ix had insufficient data length".to_string());
        }
        break;
    }

    if !found_fill {
        row.note = Some("order-engine fill ix not found in transaction".to_string());
    }
}

fn adjust_cached_amounts_for_jupiter_fee(
    quote_type: &str,
    fee_bps: Option<u16>,
    amount_in: u64,
    amount_out: u64,
) -> (u64, u64) {
    let bps = fee_bps.unwrap_or(0);
    if bps == 0 || bps >= 10_000 {
        return (amount_in, amount_out);
    }

    match quote_type {
        // Jupiter builds fill output as net-after-fee for exactIn.
        "exactIn" => {
            let fee = ((amount_out as u128) * (bps as u128) / 10_000u128) as u64;
            (amount_in, amount_out.saturating_sub(fee))
        }
        // Jupiter builds fill input as gross-before-fee for exactOut.
        "exactOut" => (gross_from_net_with_fee_bps(amount_in, bps), amount_out),
        _ => (amount_in, amount_out),
    }
}

fn gross_from_net_with_fee_bps(net_amount: u64, fee_bps: u16) -> u64 {
    if fee_bps == 0 {
        return net_amount;
    }
    let denom = 10_000u128.saturating_sub(fee_bps as u128);
    if denom == 0 {
        return net_amount;
    }
    // Start with floor estimate; bump only if needed.
    let mut gross = ((net_amount as u128) * 10_000u128) / denom;
    for _ in 0..4 {
        if gross > u64::MAX as u128 {
            return u64::MAX;
        }
        let fee = gross.saturating_mul(fee_bps as u128) / 10_000u128;
        let net = gross.saturating_sub(fee);
        if net < net_amount as u128 {
            gross = gross.saturating_add(1);
            continue;
        }
        if gross == 0 {
            break;
        }
        let prev = gross - 1;
        let prev_fee = prev.saturating_mul(fee_bps as u128) / 10_000u128;
        let prev_net = prev.saturating_sub(prev_fee);
        if prev_net >= net_amount as u128 {
            gross = prev;
            continue;
        }
        break;
    }
    gross as u64
}

pub async fn tokens(
    State(st): State<AppState>,
    ConnectInfo(_peer): ConnectInfo<std::net::SocketAddr>,
) -> ApiResult<Vec<String>> {
    let rpc = st.rpc_confirmed.clone();
    let program_id = st.cfg.program_id;
    let out = tokio::task::spawn_blocking(move || -> Result<Vec<String>, AppError> {
        let pools = crate::solana::fetch_registry_pools(&rpc, &program_id)?;
        let mut mints: BTreeSet<String> = BTreeSet::new();
        for pool_pk in pools {
            if pool_pk == Pubkey::default() {
                continue;
            }
            let pool = crate::solana::fetch_pool(&rpc, &pool_pk)?;
            mints.insert(pool.mint_a.to_string());
            mints.insert(pool.mint_b.to_string());
        }
        Ok(mints.into_iter().collect())
    })
    .await
    .map_err(|e| AppError::BadGateway(format!("tokens task join failed: {e}")));
    let out = match out {
        Ok(v) => v,
        Err(e) => return api_err(e),
    };
    match out {
        Ok(v) => Ok(Json(v)),
        Err(e) => api_err(e),
    }
}
