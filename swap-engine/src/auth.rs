use crate::state::AppState;
use crate::types::ErrorBody;
use crate::utils;
use axum::{
    extract::Request,
    extract::State,
    http::StatusCode,
    middleware::Next,
    response::IntoResponse,
    Json,
};

pub async fn require_admin_token(
    State(st): State<AppState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let expected = st.cfg.admin_token.as_str();
    let headers = req.headers();
    let got = utils::header_admin_token(headers).or_else(|| utils::header_bearer_token(headers));
    if got.as_deref() != Some(expected) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: "admin token required".into(),
            }),
        )
            .into_response();
    }
    next.run(req).await
}

