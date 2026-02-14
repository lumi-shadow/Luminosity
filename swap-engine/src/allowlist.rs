use crate::state::AppState;
use crate::types::{ApiResult, AppError, ErrorBody};
use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::extract::State;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json as AxumJson;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

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
    let raw = match std::env::var("SWAP_ENGINE_ALLOWLIST") {
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
        return Err(AppError::Unavailable(format!(
            "allowlist file not found: {}",
            path.display()
        )));
    }
    let bytes =
        std::fs::read(path).map_err(|e| AppError::Unavailable(format!("read allowlist failed: {e}")))?;
    let items: Vec<String> = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::Unavailable("allowlist JSON must be an array of strings".into()))?;
    parse_allowlist_items(&items)
}

fn persist_allowlist(st: &AppState, nets: &[IpNet]) -> Result<(), AppError> {
    if let Some(p) = st.allowlist_path.as_ref() {
        let payload = serde_json::to_vec(
            &nets.iter().map(|n| n.to_string()).collect::<Vec<String>>(),
        )
        .map_err(|e| AppError::Unavailable(format!("serialize allowlist failed: {e}")))?;
        std::fs::write(p, payload).map_err(|e| {
            AppError::Unavailable(format!("write allowlist failed (path={}): {e}", p.display()))
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
    State(st): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    // Optional strict mode (fully private service). When enabled, fail closed:
    // - Missing connect-info => 403
    //
    // Env:
    // - SWAP_ENGINE_ALLOWLIST_ONLY=true
    let allowlist_only = env_bool("SWAP_ENGINE_ALLOWLIST_ONLY", false);

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
                return (
                    axum::http::StatusCode::FORBIDDEN,
                    AxumJson(ErrorBody {
                        error: "connect info missing (allowlist-only)".into(),
                    }),
                )
                    .into_response();
            }
            return next.run(req).await;
        }
    };
    let allowed = st.allowlist.read().map(|nets| {
        // Default mode: if allowlist is empty, do not block requests.
        //
        // Strict mode (SWAP_ENGINE_ALLOWLIST_ONLY=true): fail closed if allowlist is empty.
        // This enables a safe bootstrap flow where the trusted proxy can self-register via:
        //   POST /admin/allowlist/self   (admin token required; not behind this middleware)
        if allowlist_only {
            !nets.is_empty() && nets.iter().any(|n| n.contains(&ip))
        } else {
            nets.is_empty() || nets.iter().any(|n| n.contains(&ip))
        }
    });
    let allowed = match allowed {
        Ok(v) => v,
        Err(_) => {
            if allowlist_only {
                // In strict mode, fail closed and force operator intervention.
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    AxumJson(ErrorBody {
                        error: "allowlist lock poisoned (allowlist-only)".into(),
                    }),
                )
                    .into_response();
            }
            true // fail-open in non-strict mode to avoid bricking the service
        }
    };
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            AxumJson(ErrorBody {
                error: "ip not allowlisted".into(),
            }),
        )
            .into_response();
    }
    next.run(req).await
}

pub async fn get_allowlist(State(st): State<AppState>) -> ApiResult<AllowlistResponse> {
    let nets = st
        .allowlist
        .read()
        .map_err(|_| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, AxumJson(crate::types::ErrorBody{ error: "allowlist lock poisoned".into()})))?;
    Ok(AxumJson(AllowlistResponse {
        allowlist: nets.iter().map(|n| n.to_string()).collect(),
    }))
}

pub async fn put_allowlist(
    State(st): State<AppState>,
    AxumJson(req): AxumJson<AllowlistUpdateRequest>,
) -> ApiResult<AllowlistResponse> {
    let nets = parse_allowlist_items(&req.allowlist).map_err(|e| {
        (
            e.status_code(),
            AxumJson(ErrorBody {
                error: e.to_string(),
            }),
        )
    })?;
    {
        let mut guard = st.allowlist.write().map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(crate::types::ErrorBody {
                    error: "allowlist lock poisoned".into(),
                }),
            )
        })?;
        *guard = nets.clone();
    }
    persist_allowlist(&st, &nets).map_err(|e| {
        (
            e.status_code(),
            AxumJson(ErrorBody {
                error: e.to_string(),
            }),
        )
    })?;
    Ok(AxumJson(AllowlistResponse {
        allowlist: nets.iter().map(|n| n.to_string()).collect(),
    }))
}

pub async fn post_allowlist_self(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> ApiResult<AllowlistResponse> {
    let ip: IpAddr = peer.ip();
    let prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let net = IpNet::new(ip, prefix)
        .map_err(|_| AppError::BadRequest("invalid peer ip".into()))
        .map_err(|e| {
            (
                e.status_code(),
                AxumJson(ErrorBody {
                    error: e.to_string(),
                }),
            )
        })?;
    let nets = {
        let mut guard = st.allowlist.write().map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(crate::types::ErrorBody {
                    error: "allowlist lock poisoned".into(),
                }),
            )
        })?;
        if !guard.iter().any(|n| *n == net) {
            guard.push(net);
        }
        guard.clone()
    };
    persist_allowlist(&st, &nets).map_err(|e| {
        (
            e.status_code(),
            AxumJson(ErrorBody {
                error: e.to_string(),
            }),
        )
    })?;
    Ok(AxumJson(AllowlistResponse {
        allowlist: nets.iter().map(|n| n.to_string()).collect(),
    }))
}

