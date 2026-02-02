use crate::auth;
use crate::allowlist;
use crate::handlers;
use crate::state::AppState;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::{middleware, Router};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub fn build(state: AppState) -> Router {
    let public_routes = Router::new()
        .route("/health", get(handlers::public::health))
        .route("/health/solvency", get(handlers::public::health_solvency))
        .route("/ready", get(handlers::public::ready))
        .route("/pools", get(handlers::public::pools))
        .route("/quote", post(handlers::public::quote))
        .route("/execute", post(handlers::public::execute))
        .route("/execute-job", post(handlers::public::execute_job))
        .route("/job/:id", get(handlers::jobs::job_status));
    // NOTE: IP allowlist middleware is temporarily disabled to avoid bricking the service
    // when running without connect-info or when allowlist is unset.
    // (Admin endpoints remain protected by the admin token middleware.)

    let admin_routes = Router::new()
        .route("/metrics", get(crate::metrics::metrics_handler))
        .route("/upload-key", post(handlers::admin::upload_key))
        .route(
            "/admin/allowlist",
            get(allowlist::get_allowlist).put(allowlist::put_allowlist),
        )
        .route("/admin/allowlist/self", post(allowlist::post_allowlist_self))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin_token,
        ));

    Router::new()
        .merge(public_routes)
        .merge(admin_routes)
        .with_state(state)
        // Hard cap request body size to mitigate spam / pathological JSON payloads.
        // (All endpoints are small JSON; large uploads belong elsewhere.)
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
}

