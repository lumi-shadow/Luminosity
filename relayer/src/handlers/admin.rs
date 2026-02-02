use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::State;
use axum::Json as AxumJson;
use solana_sdk::signature::Keypair;
use std::sync::Arc;
use tracing::{info, warn};

pub async fn upload_key(
    State(state): State<Arc<AppState>>,
    AxumJson(payload): AxumJson<serde_json::Value>,
) -> AppResult<AxumJson<serde_json::Value>> {
    // Acquire lock immediately
    let mut guard = state.relayer_wallet.lock().unwrap();

    // If key exists, deny request
    if guard.is_some() {
        warn!("attempt to overwrite existing relayer key blocked");
        return Err(AppError::Forbidden(
            "Relayer is already initialized. Cannot overwrite key.".into(),
        ));
    }

    let key_hex = payload["private_key"]
        .as_str()
        .ok_or(AppError::BadRequest("Missing private_key".into()))?;
    let key_bytes = hex::decode(key_hex).map_err(|_| AppError::BadRequest("Invalid hex".into()))?;
    let keypair = Keypair::try_from(key_bytes.as_slice())
        .map_err(|_| AppError::BadRequest("Invalid keypair bytes".into()))?;

    *guard = Some(Arc::new(keypair));
    info!("relayer key provisioned (sealed)");

    Ok(AxumJson(serde_json::json!({ "status": "initialized" })))
}
