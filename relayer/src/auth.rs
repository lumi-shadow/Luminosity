use crate::error::AppError;
use crate::state::AppState;
use axum::extract::Request;
use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::middleware::Next;
use axum::response::IntoResponse;
use std::sync::Arc;

fn header_admin_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn header_bearer_token(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let prefix = "Bearer ";
    if v.starts_with(prefix) {
        Some(v[prefix.len()..].trim().to_string())
    } else {
        None
    }
}

pub async fn require_admin_token(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let expected = state.admin_token.as_str();
    let headers = req.headers();
    let got = header_admin_token(headers).or_else(|| header_bearer_token(headers));
    if got.as_deref() != Some(expected) {
        return AppError::Forbidden("admin token required".into()).into_response();
    }
    next.run(req).await
}
