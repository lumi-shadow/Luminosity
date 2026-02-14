use axum::http::{header, HeaderMap};
use std::collections::HashMap;

pub fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn new_job_id(st: &crate::state::AppState) -> String {
    use std::sync::atomic::Ordering;
    let seq = st.job_seq.fetch_add(1, Ordering::Relaxed);
    format!("job-{}-{}", now_ms(), seq)
}

pub fn prune_jobs(jobs: &mut HashMap<String, crate::state::ExecuteJob>, max: usize) {
    if jobs.len() <= max {
        return;
    }
    let mut all: Vec<(String, u128)> = jobs
        .iter()
        .map(|(id, j)| (id.clone(), j.created_ts_ms))
        .collect();
    all.sort_by_key(|(_, ts)| *ts);
    let to_remove = jobs.len().saturating_sub(max);
    for (id, _) in all.into_iter().take(to_remove) {
        jobs.remove(&id);
    }
}

pub fn header_admin_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.contains('\r') && !s.contains('\n'))
        .filter(|s| !s.is_empty())
}

pub fn header_bearer_token(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if v.contains('\r') || v.contains('\n') {
        return None;
    }
    let prefix = "Bearer ";
    if v.starts_with(prefix) {
        let t = v[prefix.len()..].trim().to_string();
        if t.contains('\r') || t.contains('\n') {
            None
        } else {
            Some(t)
        }
    } else {
        None
    }
}

