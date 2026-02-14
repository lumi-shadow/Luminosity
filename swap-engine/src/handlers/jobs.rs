use crate::state::AppState;
use crate::types::{ApiResult, ErrorBody};
use axum::extract::{Path, State};
use axum::Json;

pub async fn job_status(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<serde_json::Value> {
    let jobs = st.jobs.read().await;
    let j = jobs.get(&id).ok_or_else(|| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "unknown job id".into(),
            }),
        )
    })?;
    Ok(Json(
        serde_json::to_value(j).unwrap_or_else(|_| serde_json::json!({ "error": "serialize" })),
    ))
}

