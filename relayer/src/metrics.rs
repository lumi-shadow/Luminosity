use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::sync::OnceLock;

use crate::state::{AppState, RelayJobStatus};

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct ProveKind {
    pub kind: &'static str, // "withdraw" | "withdraw_liquidity"
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct ProvePath {
    pub kind: &'static str,    // "withdraw" | "withdraw_liquidity"
    pub witness: &'static str, // "native" | "wasm"
}

pub struct Metrics {
    registry: Registry,
    pub ready: Gauge<i64>,
    pub jobs_queued: Gauge<i64>,
    pub jobs_running: Gauge<i64>,
    pub jobs_succeeded: Gauge<i64>,
    pub jobs_failed: Gauge<i64>,
    pub jobs_accepted_total: Counter,
    pub bad_payload_total: Counter,
    pub indexer_mismatch_total: Counter,
    pub witness_ms: Family<ProveKind, Histogram>,
    pub rapidsnark_ms: Family<ProveKind, Histogram>,
    pub total_ms: Family<ProveKind, Histogram>,
    pub prove_runs_total: Family<ProvePath, Counter>,
    pub prove_last_witness_ms: Family<ProvePath, Gauge<i64>>,
    pub prove_last_rapidsnark_ms: Family<ProvePath, Gauge<i64>>,
    pub prove_last_total_ms: Family<ProvePath, Gauge<i64>>,
}

fn buckets_ms() -> Vec<f64> {
    vec![
        50.0, 100.0, 200.0, 300.0, 500.0, 750.0, 1000.0, 1500.0, 2000.0, 3000.0, 5000.0, 10_000.0,
        20_000.0, 45_000.0, 60_000.0, 90_000.0, 120_000.0, 180_000.0, 300_000.0,
    ]
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

pub fn metrics() -> &'static Metrics {
    METRICS.get_or_init(|| {
        let mut registry = Registry::default();

        let ready = Gauge::<i64>::default();
        registry.register(
            "relayer_ready",
            "Relayer ready (1=wallet provisioned)",
            ready.clone(),
        );

        let jobs_queued = Gauge::<i64>::default();
        registry.register("relayer_jobs_queued", "Jobs queued", jobs_queued.clone());
        let jobs_running = Gauge::<i64>::default();
        registry.register("relayer_jobs_running", "Jobs running", jobs_running.clone());
        let jobs_succeeded = Gauge::<i64>::default();
        registry.register(
            "relayer_jobs_succeeded",
            "Jobs succeeded",
            jobs_succeeded.clone(),
        );
        let jobs_failed = Gauge::<i64>::default();
        registry.register("relayer_jobs_failed", "Jobs failed", jobs_failed.clone());

        let jobs_accepted_total = Counter::default();
        registry.register(
            "relayer_jobs_accepted_total",
            "Accepted relay jobs (after rate limiting + payload preflight)",
            jobs_accepted_total.clone(),
        );
        let bad_payload_total = Counter::default();
        registry.register(
            "relayer_bad_payload_total",
            "Bad user payloads rejected before proving",
            bad_payload_total.clone(),
        );
        let indexer_mismatch_total = Counter::default();
        registry.register(
            "relayer_indexer_mismatch_total",
            "Indexer returned empty/mismatching leaf for computed commitment",
            indexer_mismatch_total.clone(),
        );

        let witness_ms: Family<ProveKind, Histogram> =
            Family::new_with_constructor(|| Histogram::new(buckets_ms().into_iter()));
        registry.register(
            "relayer_prove_witness_ms",
            "Witness generation time (ms)",
            witness_ms.clone(),
        );

        let rapidsnark_ms: Family<ProveKind, Histogram> =
            Family::new_with_constructor(|| Histogram::new(buckets_ms().into_iter()));
        registry.register(
            "relayer_prove_rapidsnark_ms",
            "Rapidsnark proving time (ms)",
            rapidsnark_ms.clone(),
        );

        let total_ms: Family<ProveKind, Histogram> =
            Family::new_with_constructor(|| Histogram::new(buckets_ms().into_iter()));
        registry.register(
            "relayer_prove_total_ms",
            "Total proving time (ms) = witness + rapidsnark + overhead",
            total_ms.clone(),
        );

        let prove_runs_total: Family<ProvePath, Counter> = Family::default();
        registry.register(
            "relayer_prove_runs_total",
            "Number of proves executed (labeled by kind and witness path)",
            prove_runs_total.clone(),
        );

        let prove_last_witness_ms: Family<ProvePath, Gauge<i64>> = Family::default();
        registry.register(
            "relayer_prove_last_witness_ms",
            "Last witness generation time observed (ms) (by kind+witness)",
            prove_last_witness_ms.clone(),
        );
        let prove_last_rapidsnark_ms: Family<ProvePath, Gauge<i64>> = Family::default();
        registry.register(
            "relayer_prove_last_rapidsnark_ms",
            "Last rapidsnark proving time observed (ms) (by kind+witness)",
            prove_last_rapidsnark_ms.clone(),
        );
        let prove_last_total_ms: Family<ProvePath, Gauge<i64>> = Family::default();
        registry.register(
            "relayer_prove_last_total_ms",
            "Last total proving time observed (ms) (by kind+witness)",
            prove_last_total_ms.clone(),
        );

        Metrics {
            registry,
            ready,
            jobs_queued,
            jobs_running,
            jobs_succeeded,
            jobs_failed,
            jobs_accepted_total,
            bad_payload_total,
            indexer_mismatch_total,
            witness_ms,
            rapidsnark_ms,
            total_ms,
            prove_runs_total,
            prove_last_witness_ms,
            prove_last_rapidsnark_ms,
            prove_last_total_ms,
        }
    })
}

pub fn inc_jobs_accepted_total() {
    metrics().jobs_accepted_total.inc();
}

pub fn inc_bad_payload_total() {
    metrics().bad_payload_total.inc();
}

pub fn inc_indexer_mismatch_total() {
    metrics().indexer_mismatch_total.inc();
}

pub fn observe_prove_timings(
    kind: &'static str,
    witness_ms: u128,
    rapidsnark_ms: u128,
    total_ms: u128,
    used_native_witness: bool,
) {
    let m = metrics();
    let path = ProvePath {
        kind,
        witness: if used_native_witness {
            "native"
        } else {
            "wasm"
        },
    };
    m.witness_ms
        .get_or_create(&ProveKind { kind })
        .observe(witness_ms as f64);
    m.rapidsnark_ms
        .get_or_create(&ProveKind { kind })
        .observe(rapidsnark_ms as f64);
    m.total_ms
        .get_or_create(&ProveKind { kind })
        .observe(total_ms as f64);
    m.prove_runs_total.get_or_create(&path).inc();
    // Gauges: always show latest observed run (prevents NaN/empty dashboards when idle).
    m.prove_last_witness_ms
        .get_or_create(&path)
        .set(witness_ms as i64);
    m.prove_last_rapidsnark_ms
        .get_or_create(&path)
        .set(rapidsnark_ms as i64);
    m.prove_last_total_ms
        .get_or_create(&path)
        .set(total_ms as i64);
}

pub async fn metrics_handler(State(state): State<std::sync::Arc<AppState>>) -> impl IntoResponse {
    // Update gauges on scrape (cheap + always current).
    let mut q = 0i64;
    let mut r = 0i64;
    let mut s = 0i64;
    let mut f = 0i64;
    {
        let jobs = state.jobs.read().await;
        for j in jobs.values() {
            match j.status {
                RelayJobStatus::Queued => q += 1,
                RelayJobStatus::Running => r += 1,
                RelayJobStatus::Succeeded => s += 1,
                RelayJobStatus::Failed => f += 1,
            }
        }
    }
    let m = metrics();
    m.ready.set(if state.has_wallet() { 1 } else { 0 });
    m.jobs_queued.set(q);
    m.jobs_running.set(r);
    m.jobs_succeeded.set(s);
    m.jobs_failed.set(f);

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
