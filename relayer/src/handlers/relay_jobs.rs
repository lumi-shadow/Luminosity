use crate::error::AppResult;
use crate::preflight;
use crate::rate_limit::{rate_limit_bad, rate_limit_ok};
use crate::state::{new_job_id, AppState, RelayJob, RelayJobKind, RelayJobStatus};
use crate::types::RelayRequest;
use axum::extract::{ConnectInfo, State};
use axum::Json as AxumJson;
use std::sync::Arc;
use tokio::sync::mpsc;

pub async fn relay_job_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    AxumJson(req): AxumJson<RelayRequest>,
) -> AppResult<AxumJson<serde_json::Value>> {
    req.validate()?;
    preflight::spam_guard_before_job(&state).await?;
    let browser_inputs = match preflight::preflight_user_payload_withdraw(&state, &req) {
        Ok(v) => v,
        Err(e) => {
            preflight::record_bad_payload();
            if let Err(rl_e) = rate_limit_bad(&state, peer.ip()) {
                return Err(rl_e);
            }
            return Err(e);
        }
    };
    if let Err(e) = preflight::preflight_withdraw_recipient_account(&state, &browser_inputs).await
    {
        preflight::record_bad_payload();
        if let Err(rl_e) = rate_limit_bad(&state, peer.ip()) {
            return Err(rl_e);
        }
        return Err(e);
    }
    rate_limit_ok(&state, peer.ip())?;
    crate::metrics::inc_jobs_accepted_total();

    let job_id = {
        let id = new_job_id(&state, RelayJobKind::Withdraw);
        let job = RelayJob {
            id: id.clone(),
            kind: RelayJobKind::Withdraw,
            status: RelayJobStatus::Queued,
            created_ts_ms: crate::utils::now_ms(),
            started_ts_ms: None,
            finished_ts_ms: None,
            events: vec![],
            result: None,
            error: None,
        };
        state.jobs.write().await.insert(id.clone(), job);
        id
    };

    let job_id_bg = job_id.clone();
    let state_bg = state.clone();
    tokio::spawn(async move {
        let permit = state_bg.job_semaphore.acquire().await;
        if permit.is_err() {
            let mut jobs = state_bg.jobs.write().await;
            if let Some(j) = jobs.get_mut(&job_id_bg) {
                j.status = RelayJobStatus::Failed;
                j.finished_ts_ms = Some(crate::utils::now_ms());
                j.error = Some("Failed to acquire concurrency permit".into());
            }
            return;
        }
        let _permit = permit.unwrap();

        let (tx, mut rx) = mpsc::channel::<crate::types::RelayProgressEvent>(256);
        {
            let mut jobs = state_bg.jobs.write().await;
            if let Some(j) = jobs.get_mut(&job_id_bg) {
                j.status = RelayJobStatus::Running;
                j.started_ts_ms = Some(crate::utils::now_ms());
            }
        }
        let state_events = state_bg.clone();
        let job_id_events = job_id_bg.clone();
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                let mut jobs = state_events.jobs.write().await;
                if let Some(j) = jobs.get_mut(&job_id_events) {
                    j.events.push(ev);
                    if j.events.len() > 500 {
                        j.events.drain(0..100);
                    }
                }
            }
        });

        // core logic is still in crate root for now
        let res = crate::relay_circom_inner(state_bg.clone(), req, Some(tx)).await;
        let mut jobs = state_bg.jobs.write().await;
        if let Some(j) = jobs.get_mut(&job_id_bg) {
            j.finished_ts_ms = Some(crate::utils::now_ms());
            match res {
                Ok(v) => {
                    j.status = RelayJobStatus::Succeeded;
                    j.result = Some(v);
                }
                Err(e) => {
                    j.status = RelayJobStatus::Failed;
                    j.error = Some(e.to_string());
                }
            }
        }
    });

    Ok(AxumJson(serde_json::json!({ "job_id": job_id })))
}

pub async fn relay_liquidity_job_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    AxumJson(req): AxumJson<RelayRequest>,
) -> AppResult<AxumJson<serde_json::Value>> {
    req.validate()?;
    preflight::spam_guard_before_job(&state).await?;
    if let Err(e) = preflight::preflight_user_payload_liquidity(&state, &req) {
        preflight::record_bad_payload();
        if let Err(rl_e) = rate_limit_bad(&state, peer.ip()) {
            return Err(rl_e);
        }
        return Err(e);
    }
    rate_limit_ok(&state, peer.ip())?;
    crate::metrics::inc_jobs_accepted_total();

    let job_id = {
        let id = new_job_id(&state, RelayJobKind::WithdrawLiquidity);
        let job = RelayJob {
            id: id.clone(),
            kind: RelayJobKind::WithdrawLiquidity,
            status: RelayJobStatus::Queued,
            created_ts_ms: crate::utils::now_ms(),
            started_ts_ms: None,
            finished_ts_ms: None,
            events: vec![],
            result: None,
            error: None,
        };
        state.jobs.write().await.insert(id.clone(), job);
        id
    };

    let job_id_bg = job_id.clone();
    let state_bg = state.clone();
    tokio::spawn(async move {
        let permit = state_bg.job_semaphore.acquire().await;
        if permit.is_err() {
            let mut jobs = state_bg.jobs.write().await;
            if let Some(j) = jobs.get_mut(&job_id_bg) {
                j.status = RelayJobStatus::Failed;
                j.finished_ts_ms = Some(crate::utils::now_ms());
                j.error = Some("Failed to acquire concurrency permit".into());
            }
            return;
        }
        let _permit = permit.unwrap();

        let (tx, mut rx) = mpsc::channel::<crate::types::RelayProgressEvent>(256);
        {
            let mut jobs = state_bg.jobs.write().await;
            if let Some(j) = jobs.get_mut(&job_id_bg) {
                j.status = RelayJobStatus::Running;
                j.started_ts_ms = Some(crate::utils::now_ms());
            }
        }
        let state_events = state_bg.clone();
        let job_id_events = job_id_bg.clone();
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                let mut jobs = state_events.jobs.write().await;
                if let Some(j) = jobs.get_mut(&job_id_events) {
                    j.events.push(ev);
                    if j.events.len() > 500 {
                        j.events.drain(0..100);
                    }
                }
            }
        });

        let res = crate::relay_circom_liquidity_inner(state_bg.clone(), req, Some(tx)).await;
        let mut jobs = state_bg.jobs.write().await;
        if let Some(j) = jobs.get_mut(&job_id_bg) {
            j.finished_ts_ms = Some(crate::utils::now_ms());
            match res {
                Ok(v) => {
                    j.status = RelayJobStatus::Succeeded;
                    j.result = Some(v);
                }
                Err(e) => {
                    j.status = RelayJobStatus::Failed;
                    j.error = Some(e.to_string());
                }
            }
        }
    });

    Ok(AxumJson(serde_json::json!({ "job_id": job_id })))
}
