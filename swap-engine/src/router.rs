use crate::auth;
use crate::allowlist;
use crate::handlers;
use crate::state::AppState;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request};
use axum::routing::{get, post};
use axum::{
    http::StatusCode,
    middleware,
    middleware::Next,
    response::IntoResponse,
    Json,
    Router,
};
use std::net::{IpAddr, SocketAddr};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| {
            let s = v.trim().to_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "y" | "on")
        })
        .unwrap_or(default)
}

pub fn build(state: AppState) -> Router {
    // Public routes are intended to be reached via a trusted proxy (Next.js API routes).
    // We enforce an optional IP allowlist at the HTTP boundary:
    //
    // - When `SWAP_ENGINE_ALLOWLIST_ONLY=true`, requests are rejected unless:
    //   - connect-info is available, AND
    //   - the peer IP is in the allowlist.
    //   This supports a bootstrap flow where the trusted proxy can self-register via:
    //     POST /admin/allowlist/self  (admin token required; NOT behind this middleware)
    //
    // - When allowlist-only is disabled, an empty allowlist is treated as "allow all" (default dev UX).
    let allowlist_mw_state = state.clone();
    let public_routes = Router::new()
        .route("/health", get(handlers::public::health))
        .route("/health/solvency", get(handlers::public::health_solvency))
        .route("/ready", get(handlers::public::ready))
        .route("/pools", get(handlers::public::pools))
        .route("/quote", post(handlers::public::quote))
        .route("/execute", post(handlers::public::execute))
        .route("/execute-job", post(handlers::public::execute_job))
        .route("/job/:id", get(handlers::jobs::job_status))
        // Enforce allowlist on *public* endpoints only.
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let st = allowlist_mw_state.clone();
            async move {
                let allowlist_only = env_bool("SWAP_ENGINE_ALLOWLIST_ONLY", false);

                let ip: Option<IpAddr> = req
                    .extensions()
                    .get::<SocketAddr>()
                    .map(|peer| peer.ip())
                    .or_else(|| {
                        req.extensions()
                            .get::<ConnectInfo<SocketAddr>>()
                            .map(|ConnectInfo(peer)| peer.ip())
                    });
                let ip = match ip {
                    Some(ip) => ip,
                    None => {
                        if allowlist_only {
                            return (
                                StatusCode::FORBIDDEN,
                                Json(crate::types::ErrorBody {
                                    error: "connect info missing (allowlist-only)".into(),
                                }),
                            )
                                .into_response();
                        }
                        return next.run(req).await;
                    }
                };

                let allowed = match st.allowlist.read() {
                    Ok(nets) => {
                        if allowlist_only {
                            !nets.is_empty() && nets.iter().any(|n| n.contains(&ip))
                        } else {
                            nets.is_empty() || nets.iter().any(|n| n.contains(&ip))
                        }
                    }
                    Err(_) => {
                        if allowlist_only {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(crate::types::ErrorBody {
                                    error: "allowlist lock poisoned (allowlist-only)".into(),
                                }),
                            )
                                .into_response();
                        }
                        true
                    }
                };

                if !allowed {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(crate::types::ErrorBody {
                            error: "ip not allowlisted".into(),
                        }),
                    )
                        .into_response();
                }

                next.run(req).await
            }
        }));

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

