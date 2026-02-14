use crate::state::AppState;
use crate::types::{api_err, ApiResult, AppError, ErrorBody};
use axum::extract::State;
use axum::Json;
use solana_sdk::signature::{Keypair, Signer};
use std::sync::Arc;

#[derive(serde::Deserialize)]
pub struct UploadKeyRequest {
    /// Hex-encoded 64-byte Solana keypair (secret + public) produced by Keypair::to_bytes().
    pub private_key: String,
}

pub async fn upload_key(
    State(st): State<AppState>,
    Json(req): Json<UploadKeyRequest>,
) -> ApiResult<serde_json::Value> {
    // Input caps: prevent pathological strings from reaching hex decode.
    const MAX_KEYPAIR_HEX_LEN: usize = 2 + 128; // optional 0x + 64-byte keypair
    if req.private_key.len() > MAX_KEYPAIR_HEX_LEN {
        return api_err(AppError::BadRequest(format!(
            "private_key too long: {} chars (max {MAX_KEYPAIR_HEX_LEN})",
            req.private_key.len()
        )));
    }

    // Seal TEE keypair: can be set only once.
    let mut tee_guard = st.tee_keypair.lock().map_err(|_| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "mutex poisoned".into(),
            }),
        )
    })?;
    if tee_guard.is_some() {
        return api_err(AppError::Forbidden(
            "swap-engine is already initialized (tee key already set)".into(),
        ));
    }

    let key_bytes = hex::decode(req.private_key.trim_start_matches("0x"))
        .map_err(|_| AppError::BadRequest("invalid hex in private_key".into()))
        .and_then(|b| Keypair::try_from(b.as_slice()).map_err(|_| AppError::BadRequest("invalid keypair bytes".into())));
    let tee_kp = match key_bytes {
        Ok(k) => Arc::new(k),
        Err(e) => return api_err(e),
    };
    *tee_guard = Some(tee_kp.clone());

    Ok(Json(serde_json::json!({
        "status": "initialized",
        "tee_pubkey": tee_kp.pubkey().to_string(),
    })))
}

