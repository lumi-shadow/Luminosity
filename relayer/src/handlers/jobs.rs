use crate::error::AppError;
use crate::error::AppResult;
use crate::state::AppState;
use axum::extract::State;
use axum::Json as AxumJson;
use std::sync::Arc;

pub async fn job_status_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> AppResult<AxumJson<serde_json::Value>> {
    let jobs = state.jobs.read().await;
    let j = jobs
        .get(&id)
        .ok_or_else(|| AppError::BadRequest("unknown job id".into()))?;
    Ok(AxumJson(serde_json::to_value(j).unwrap_or_else(
        |_| serde_json::json!({"error":"serialize"}),
    )))
}
