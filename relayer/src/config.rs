use crate::error::{AppError, AppResult};
use std::env;

pub fn required_admin_token() -> AppResult<String> {
    // Prefer a unified token name across services.
    let v = env::var("ADMIN_TOKEN")
        .or_else(|_| env::var("RELAYER_ADMIN_TOKEN"))
        .map_err(|_| {
            AppError::Internal("ADMIN_TOKEN (or RELAYER_ADMIN_TOKEN) is required".into())
        })?;
    let v = v.trim().to_string();
    if v.is_empty() {
        return Err(AppError::Internal(
            "ADMIN_TOKEN (or RELAYER_ADMIN_TOKEN) must be non-empty".into(),
        ));
    }
    Ok(v)
}
