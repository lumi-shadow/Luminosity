use crate::auth;
use crate::handlers;
use crate::state::AppState;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub fn build(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let public_routes = Router::new()
        .route("/tee-key", get(handlers::public::get_tee_key))
        .route("/fee", get(handlers::public::get_fee))
        .route("/fee/health", get(handlers::public::fee_health))
        .route("/ready", get(handlers::public::readiness))
        // deposit prep endpoints still live in crate root for now
        .route("/prepare-deposit", post(crate::prepare_deposit))
        .route(
            "/prepare-deposit-liquidity",
            post(crate::prepare_deposit_liquidity),
        )
        .route("/relay-job", post(handlers::relay_jobs::relay_job_handler))
        .route(
            "/relay-liquidity-job",
            post(handlers::relay_jobs::relay_liquidity_job_handler),
        )
        .route("/job/:id", get(handlers::jobs::job_status_handler));
    // Public routes are backend-only (IP allowlist).
    // NOTE: IP allowlist middleware is temporarily disabled to avoid bricking the service
    // when running without connect-info or when allowlist is unset.
    // (Admin endpoints remain protected by the admin token middleware.)

    let admin_routes = Router::new()
        .route("/metrics", get(crate::metrics::metrics_handler))
        .route("/upload-key", post(handlers::admin::upload_key))
        .route(
            "/admin/allowlist",
            get(crate::allowlist::get_allowlist).put(crate::allowlist::put_allowlist),
        )
        .route(
            "/admin/allowlist/self",
            post(crate::allowlist::post_allowlist_self),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin_token,
        ));

    Router::new()
        .merge(public_routes)
        .merge(admin_routes)
        .with_state(state)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}
