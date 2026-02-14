use axum::response::IntoResponse;
use axum::Json as AxumJson;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Bad Request: {0}")]
    BadRequest(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Unavailable: {0}")]
    Unavailable(String),
    #[error("Too Many Requests: {0}")]
    TooManyRequests(String),
    #[error("Internal Error: {0}")]
    Internal(String),
    #[error("Bad Gateway: {0}")]
    BadGateway(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            AppError::BadRequest(m) => (axum::http::StatusCode::BAD_REQUEST, m),
            AppError::Forbidden(m) => (axum::http::StatusCode::FORBIDDEN, m),
            AppError::Unavailable(m) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, m),
            AppError::TooManyRequests(m) => (axum::http::StatusCode::TOO_MANY_REQUESTS, m),
            AppError::Internal(m) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, m),
            AppError::BadGateway(m) => (axum::http::StatusCode::BAD_GATEWAY, m),
        };
        let body = serde_json::json!({ "error": msg });
        (status, AxumJson(body)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
