//! Minimal HTTP client for talking to the local `tree-indexer`.
//!
//! We intentionally avoid TLS + heavyweight deps here:
//! - indexer is expected to be on the same host/VPC
//! - we only need GET + JSON responses
//!
//! This mirrors the relayer’s "no TLS" approach for the indexer URL.

use crate::types::AppError;
use std::io::{Read, Write};
use std::net::TcpStream;

pub fn parse_http_base(base: &str) -> Result<(String, u16, String), AppError> {
    // - http://127.0.0.1:8787
    // - http://localhost:8787/prefix
    //
    // NOTE: intentionally no TLS here (no https).
    let rest = base
        .strip_prefix("http://")
        .ok_or_else(|| AppError::BadRequest("INDEXER_URL must start with http://".into()))?;

    let (host_port, prefix) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p.trim_end_matches('/'))),
        None => (rest, "".to_string()),
    };

    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| AppError::BadRequest("INDEXER_URL port is invalid".into()))?;
            (h.to_string(), port)
        }
        None => (host_port.to_string(), 80),
    };

    Ok((host, port, prefix))
}

fn http_dechunk(body: &[u8]) -> Result<Vec<u8>, AppError> {
    // `Transfer-Encoding: chunked` is fairly common even for small JSON responses.
    // The indexer only returns small payloads, so a tiny dechunker is sufficient here.
    // Very small chunked decoder for indexer responses.
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        // read hex size line
        let mut line_end = None;
        for j in i..body.len().saturating_sub(1) {
            if body[j] == b'\r' && body[j + 1] == b'\n' {
                line_end = Some(j);
                break;
            }
        }
        let Some(le) = line_end else { break };
        let line = &body[i..le];
        let size = usize::from_str_radix(
            std::str::from_utf8(line)
                .map_err(|_| AppError::BadGateway("invalid chunk header".into()))?,
            16,
        )
        .map_err(|_| AppError::BadGateway("invalid chunk size".into()))?;
        i = le + 2;
        if size == 0 {
            break;
        }
        if i + size > body.len() {
            return Err(AppError::BadGateway("chunked body truncated".into()));
        }
        out.extend_from_slice(&body[i..i + size]);
        i += size + 2; // skip data + \r\n
    }
    Ok(out)
}

pub fn http_get_json(
    host: &str,
    port: u16,
    path: &str,
    bearer_token: Option<&str>,
) -> Result<(u16, Vec<u8>), AppError> {
    // NOTE: This is a deliberately small implementation:
    // - no keep-alives
    // - no redirects
    // - no compression
    // - "Connection: close"
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| AppError::BadGateway(format!("connect failed: {e}")))?;
    let auth_line = bearer_token
        .filter(|t| !t.trim().is_empty())
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    stream
        .write_all(
            format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json\r\n{}\
\r\n",
                path, host, auth_line
            )
            .as_bytes(),
        )
        .map_err(|e| AppError::BadGateway(format!("write failed: {e}")))?;

    let mut resp = Vec::new();
    stream
        .read_to_end(&mut resp)
        .map_err(|e| AppError::BadGateway(format!("read failed: {e}")))?;

    // Split header / body
    let needle = b"\r\n\r\n";
    let mut header_end = None;
    for i in 0..resp.len().saturating_sub(needle.len()) {
        if &resp[i..i + needle.len()] == needle {
            header_end = Some(i + needle.len());
            break;
        }
    }
    let header_end =
        header_end.ok_or_else(|| AppError::BadGateway("invalid HTTP response".into()))?;
    let header = &resp[..header_end];
    let body_raw = &resp[header_end..];

    let status_line_end = header
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| AppError::BadGateway("invalid HTTP header".into()))?;
    let status_line = &header[..status_line_end];
    let status_line = std::str::from_utf8(status_line)
        .map_err(|_| AppError::BadGateway("invalid HTTP status line".into()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| AppError::BadGateway("invalid HTTP status".into()))?
        .parse::<u16>()
        .map_err(|_| AppError::BadGateway("invalid HTTP status".into()))?;

    let header_str = std::str::from_utf8(header)
        .map_err(|_| AppError::BadGateway("invalid HTTP header".into()))?;
    let body = if header_str
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        http_dechunk(body_raw)?
    } else {
        body_raw.to_vec()
    };

    Ok((status, body))
}

pub fn http_post_json(
    host: &str,
    port: u16,
    path: &str,
    bearer_token: Option<&str>,
    json_body: &[u8],
) -> Result<(u16, Vec<u8>), AppError> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| AppError::BadGateway(format!("connect failed: {e}")))?;
    let auth_line = bearer_token
        .filter(|t| !t.trim().is_empty())
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let body_len = json_body.len();
    stream
        .write_all(
            format!(
                "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}\
\r\n",
                path, host, body_len, auth_line
            )
            .as_bytes(),
        )
        .map_err(|e| AppError::BadGateway(format!("write failed: {e}")))?;
    stream
        .write_all(json_body)
        .map_err(|e| AppError::BadGateway(format!("write failed: {e}")))?;

    let mut resp = Vec::new();
    stream
        .read_to_end(&mut resp)
        .map_err(|e| AppError::BadGateway(format!("read failed: {e}")))?;

    // Split header / body
    let needle = b"\r\n\r\n";
    let mut header_end = None;
    for i in 0..resp.len().saturating_sub(needle.len()) {
        if &resp[i..i + needle.len()] == needle {
            header_end = Some(i + needle.len());
            break;
        }
    }
    let header_end =
        header_end.ok_or_else(|| AppError::BadGateway("invalid HTTP response".into()))?;
    let header = &resp[..header_end];
    let body_raw = &resp[header_end..];

    let status_line_end = header
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| AppError::BadGateway("invalid HTTP header".into()))?;
    let status_line = &header[..status_line_end];
    let status_line = std::str::from_utf8(status_line)
        .map_err(|_| AppError::BadGateway("invalid HTTP status line".into()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| AppError::BadGateway("invalid HTTP status".into()))?
        .parse::<u16>()
        .map_err(|_| AppError::BadGateway("invalid HTTP status".into()))?;

    let header_str = std::str::from_utf8(header)
        .map_err(|_| AppError::BadGateway("invalid HTTP header".into()))?;
    let body = if header_str
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        http_dechunk(body_raw)?
    } else {
        body_raw.to_vec()
    };

    Ok((status, body))
}
