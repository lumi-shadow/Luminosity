use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::extract::State;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Json as AxumJson;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(serde::Deserialize)]
pub struct AllowlistUpdateRequest {
    pub allowlist: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct AllowlistResponse {
    pub allowlist: Vec<String>,
}

pub fn parse_allowlist_items(items: &[String]) -> Result<Vec<IpNet>, AppError> {
    let mut out: Vec<IpNet> = Vec::new();
    for raw in items {
        let s = raw.trim();
        if s.is_empty() {
            continue;
        }
        let net = s.parse::<IpNet>().or_else(|_| {
            let ip = s
                .parse::<IpAddr>()
                .map_err(|_| AppError::BadRequest(format!("invalid CIDR/IP: {s}")))?;
            let prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            IpNet::new(ip, prefix).map_err(|_| AppError::BadRequest(format!("invalid IP net: {s}")))
        })?;
        out.push(net);
    }
    Ok(out)
}

pub fn parse_allowlist_from_env() -> Result<Vec<IpNet>, AppError> {
    let raw = match std::env::var("RELAYER_ALLOWLIST") {
        Ok(v) => v,
        Err(_) => return Ok(Vec::new()),
    };
    let items: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    parse_allowlist_items(&items)
}

pub fn load_allowlist(path: &PathBuf) -> Result<Vec<IpNet>, AppError> {
    if !path.exists() {
        return Err(AppError::Internal(format!(
            "allowlist file not found: {}",
            path.display()
        )));
    }
    let bytes = std::fs::read(path)
        .map_err(|e| AppError::Internal(format!("read allowlist failed: {e}")))?;
    let items: Vec<String> = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::Internal("allowlist JSON must be an array of strings".into()))?;
    parse_allowlist_items(&items)
}

fn persist_allowlist(state: &Arc<AppState>, nets: &[IpNet]) -> Result<(), AppError> {
    if let Some(p) = state.allowlist_path.as_ref() {
        let payload =
            serde_json::to_vec(&nets.iter().map(|n| n.to_string()).collect::<Vec<String>>())
                .map_err(|e| AppError::Internal(format!("serialize allowlist failed: {e}")))?;
        std::fs::write(p, payload).map_err(|e| {
            AppError::Internal(format!(
                "write allowlist failed (path={}): {e}",
                p.display()
            ))
        })?;
    }
    Ok(())
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| {
            let s = v.trim().to_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "y" | "on")
        })
        .unwrap_or(default)
}

#[allow(dead_code)]
pub async fn require_allowlisted_ip(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    // Optional strict mode (fully private service). When enabled, fail closed:
    // - Missing connect-info => 403
    //
    // Env:
    // - RELAYER_ALLOWLIST_ONLY=true
    let allowlist_only = env_bool("RELAYER_ALLOWLIST_ONLY", false);

    let ip: Option<IpAddr> = req
        .extensions()
        .get::<SocketAddr>()
        .map(|peer| peer.ip())
        .or_else(|| {
            req.extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(peer)| peer.ip())
        });
    let ip = match ip {
        Some(ip) => ip,
        None => {
            // If connect info is not available, fail open to avoid bricking deployments
            // that don't use `into_make_service_with_connect_info`.
            if allowlist_only {
                return AppError::Forbidden("connect info missing (allowlist-only)".into())
                    .into_response();
            }
            return next.run(req).await;
        }
    };
    let allowed = state.allowlist.read().map(|nets| {
        // If no allowlist is configured, do not block requests.
        // (Allowlist enforcement is opt-in via RELAYER_ALLOWLIST / RELAYER_ALLOWLIST_PATH.)
        nets.is_empty() || nets.iter().any(|n| n.contains(&ip))
    });
    let allowed = match allowed {
        Ok(v) => v,
        Err(_) => true, // fail-open to avoid bricking the service on poisoned lock
    };
    if !allowed {
        return AppError::Forbidden(format!("ip not allowlisted: {ip}")).into_response();
    }
    next.run(req).await
}

pub async fn get_allowlist(
    State(state): State<Arc<AppState>>,
) -> AppResult<AxumJson<AllowlistResponse>> {
    let nets = state
        .allowlist
        .read()
        .map_err(|_| AppError::Internal("allowlist lock poisoned".into()))?;
    Ok(AxumJson(AllowlistResponse {
        allowlist: nets.iter().map(|n| n.to_string()).collect(),
    }))
}

pub async fn put_allowlist(
    State(state): State<Arc<AppState>>,
    AxumJson(req): AxumJson<AllowlistUpdateRequest>,
) -> AppResult<AxumJson<AllowlistResponse>> {
    let nets = parse_allowlist_items(&req.allowlist)?;
    {
        let mut guard = state
            .allowlist
            .write()
            .map_err(|_| AppError::Internal("allowlist lock poisoned".into()))?;
        *guard = nets.clone();
    }
    persist_allowlist(&state, &nets)?;
    Ok(AxumJson(AllowlistResponse {
        allowlist: nets.iter().map(|n| n.to_string()).collect(),
    }))
}

pub async fn post_allowlist_self(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> AppResult<AxumJson<AllowlistResponse>> {
    let ip: IpAddr = peer.ip();
    let prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let net = IpNet::new(ip, prefix).map_err(|_| AppError::BadRequest("invalid peer ip".into()))?;
    let nets = {
        let mut guard = state
            .allowlist
            .write()
            .map_err(|_| AppError::Internal("allowlist lock poisoned".into()))?;
        if !guard.iter().any(|n| *n == net) {
            guard.push(net);
        }
        guard.clone()
    };
    persist_allowlist(&state, &nets)?;
    Ok(AxumJson(AllowlistResponse {
        allowlist: nets.iter().map(|n| n.to_string()).collect(),
    }))
}
