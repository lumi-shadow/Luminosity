use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::sync::Mutex;
use std::sync::OnceLock;

use crate::solvency::{compute_solvency, ComputeSolvencyParams};
use crate::state::AppState;

pub struct Metrics {
    registry: Registry,
    pub quote_requests_total: Counter,
    pub quote_errors_total: Counter,
    pub execute_requests_total: Counter,
    pub execute_errors_total: Counter,
    pub jobs_accepted_total: Counter,
    pub bad_payload_total: Counter,
    /// Bad requests that passed basic handler validation but failed deeper checks (engine parsing/etc).
    pub bad_requests_total: Counter,
    pub rate_limited_total: Counter,
    pub quote_ms: Histogram,
    pub execute_ms: Histogram,
    pub quote_pool_rpc_ms: Histogram,
    pub quote_oracle_ms: Histogram,
    pub quote_compute_ms: Histogram,

    // Solvency gauges (computed from on-chain pool + vaults).
    pub solvency_ok: Gauge<i64>,
    pub solvency_pool: Family<SolvencyPoolLabel, Gauge<i64>>,
    pub solvency_mint: Family<SolvencyMintLabel, Gauge<i64>>,
}

fn buckets_ms() -> Vec<f64> {
    vec![
        5.0, 10.0, 25.0, 50.0, 75.0, 100.0, 150.0, 200.0, 300.0, 500.0, 750.0, 1000.0, 1500.0,
        2000.0, 3000.0, 5000.0, 10_000.0, 20_000.0,
    ]
}

static METRICS: OnceLock<Metrics> = OnceLock::new();
static SOLVENCY_CACHE: OnceLock<Mutex<(u128, crate::solvency::SolvencyResponse)>> = OnceLock::new();

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct SolvencyPoolLabel {
    pub pool: String,
    pub mint: String,
    pub kind: &'static str, // liabilities(reserve) | vault_balance | headroom
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct SolvencyMintLabel {
    pub mint: String,
    pub kind: &'static str, // vault_balance | reserved_in_pools | free_for_asset_notes
}

pub fn metrics() -> &'static Metrics {
    METRICS.get_or_init(|| {
        let mut registry = Registry::default();
        let quote_requests_total = Counter::default();
        registry.register("swap_engine_quote_requests_total", "Quote requests total", quote_requests_total.clone());
        let quote_errors_total = Counter::default();
        registry.register("swap_engine_quote_errors_total", "Quote errors total", quote_errors_total.clone());
        let execute_requests_total = Counter::default();
        registry.register(
            "swap_engine_execute_requests_total",
            "Execute requests total",
            execute_requests_total.clone(),
        );
        let execute_errors_total = Counter::default();
        registry.register(
            "swap_engine_execute_errors_total",
            "Execute errors total",
            execute_errors_total.clone(),
        );
        let jobs_accepted_total = Counter::default();
        registry.register(
            "swap_engine_jobs_accepted_total",
            "Execute jobs accepted total",
            jobs_accepted_total.clone(),
        );
        let bad_payload_total = Counter::default();
        registry.register(
            "swap_engine_bad_payload_total",
            "Bad payloads / validation failures total",
            bad_payload_total.clone(),
        );
        let bad_requests_total = Counter::default();
        registry.register(
            "swap_engine_bad_requests_total",
            "Bad requests total (post-validation failures)",
            bad_requests_total.clone(),
        );
        let rate_limited_total = Counter::default();
        registry.register(
            "swap_engine_rate_limited_total",
            "Requests rate-limited total",
            rate_limited_total.clone(),
        );

        let quote_ms = Histogram::new(buckets_ms().into_iter());
        registry.register("swap_engine_quote_ms", "Quote handler latency (ms)", quote_ms.clone());
        let execute_ms = Histogram::new(buckets_ms().into_iter());
        registry.register("swap_engine_execute_ms", "Execute handler latency (ms)", execute_ms.clone());

        let quote_pool_rpc_ms = Histogram::new(buckets_ms().into_iter());
        registry.register(
            "swap_engine_quote_pool_rpc_ms",
            "Quote: pool fetch (Solana RPC) latency (ms)",
            quote_pool_rpc_ms.clone(),
        );
        let quote_oracle_ms = Histogram::new(buckets_ms().into_iter());
        registry.register(
            "swap_engine_quote_oracle_ms",
            "Quote: oracle fetch latency (ms) (Hermes cache fast path; may include HTTP on cold cache)",
            quote_oracle_ms.clone(),
        );
        let quote_compute_ms = Histogram::new(buckets_ms().into_iter());
        registry.register(
            "swap_engine_quote_compute_ms",
            "Quote: pure compute/policy latency (ms) (no network)",
            quote_compute_ms.clone(),
        );

        let solvency_ok = Gauge::<i64>::default();
        registry.register("swap_engine_solvency_ok", "1 if solvent, 0 otherwise", solvency_ok.clone());

        let solvency_pool: Family<SolvencyPoolLabel, Gauge<i64>> = Family::default();
        registry.register(
            "swap_engine_solvency_pool",
            "Pool solvency values (kind=reserve|vault_balance|headroom) labeled by pool+mint",
            solvency_pool.clone(),
        );

        let solvency_mint: Family<SolvencyMintLabel, Gauge<i64>> = Family::default();
        registry.register(
            "swap_engine_solvency_mint",
            "Mint solvency values (kind=vault_balance|reserved_in_pools|free_for_asset_notes) labeled by mint",
            solvency_mint.clone(),
        );

        Metrics {
            registry,
            quote_requests_total,
            quote_errors_total,
            execute_requests_total,
            execute_errors_total,
            jobs_accepted_total,
            bad_payload_total,
            bad_requests_total,
            rate_limited_total,
            quote_ms,
            execute_ms,
            quote_pool_rpc_ms,
            quote_oracle_ms,
            quote_compute_ms,
            solvency_ok,
            solvency_pool,
            solvency_mint,
        }
    })
}

fn refresh_solvency_metrics(st: &AppState) {
    // Prometheus scrapes every 10s by default; keep this cheap with a small cache.
    // If the RPC is flaky, we keep the last snapshot (and do not fail the scrape).
    const TTL_MS: u128 = 8_000;

    let cache = SOLVENCY_CACHE.get_or_init(|| {
        Mutex::new((
            0u128,
            crate::solvency::SolvencyResponse {
                ok: false,
                program_id: st.cfg.program_id.to_string(),
                indexer_url: st.cfg.indexer_url.clone(),
                ts_ms: 0,
                mints: vec![],
                pools: vec![],
                warnings: vec!["no solvency snapshot yet".into()],
            },
        ))
    });

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let mut guard = cache.lock().unwrap();
    let (last_ms, last) = &mut *guard;
    if now.saturating_sub(*last_ms) >= TTL_MS {
        let rpc = crate::solana::rpc_client(st.cfg.rpc_url.clone());
        if let Ok(snap) = compute_solvency(ComputeSolvencyParams {
            rpc: &rpc,
            program_id: st.cfg.program_id,
            indexer_url: st.cfg.indexer_url.clone(),
        }) {
            *last = snap;
            *last_ms = now;
        }
    }

    let m = metrics();
    m.solvency_ok.set(if last.ok { 1 } else { 0 });

    // Pool values (store A and B sides as separate series by mint).
    for p in &last.pools {
        for (mint, reserve, vault_bal, headroom) in [
            (&p.mint_a, p.reserve_a, p.vault_a_balance, p.headroom_a),
            (&p.mint_b, p.reserve_b, p.vault_b_balance, p.headroom_b),
        ] {
            let base = SolvencyPoolLabel {
                pool: p.pool.clone(),
                mint: mint.clone(),
                kind: "reserve",
            };
            m.solvency_pool.get_or_create(&base).set(reserve as i64);
            let base2 = SolvencyPoolLabel {
                pool: p.pool.clone(),
                mint: mint.clone(),
                kind: "vault_balance",
            };
            m.solvency_pool.get_or_create(&base2).set(vault_bal as i64);
            let base3 = SolvencyPoolLabel {
                pool: p.pool.clone(),
                mint: mint.clone(),
                kind: "headroom",
            };
            m.solvency_pool.get_or_create(&base3).set(headroom);

            // Backward-compat alias for existing dashboards.
            let base4 = SolvencyPoolLabel {
                pool: p.pool.clone(),
                mint: mint.clone(),
                kind: "drift",
            };
            m.solvency_pool.get_or_create(&base4).set(headroom);
        }
    }

    for r in &last.mints {
        m.solvency_mint
            .get_or_create(&SolvencyMintLabel {
                mint: r.mint.clone(),
                kind: "vault_balance",
            })
            .set(r.vault_balance as i64);
        m.solvency_mint
            .get_or_create(&SolvencyMintLabel {
                mint: r.mint.clone(),
                kind: "reserved_in_pools",
            })
            .set(r.reserved_in_pools as i64);
        m.solvency_mint
            .get_or_create(&SolvencyMintLabel {
                mint: r.mint.clone(),
                kind: "free_for_asset_notes",
            })
            .set(r.free_for_asset_notes);
    }
}

pub async fn metrics_handler(State(st): State<AppState>) -> impl IntoResponse {
    refresh_solvency_metrics(&st);
    let m = metrics();
    let mut out = String::new();
    if let Err(e) = encode(&mut out, &m.registry) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("encode metrics failed: {e}"),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        out,
    )
        .into_response()
}
