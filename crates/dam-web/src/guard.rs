//! Local-admin guardrails:
//!
//! - Reject non-loopback `Host` headers (DNS rebinding).
//! - Require local `Origin`/`Referer` for mutation routes — except when
//!   the request carries the tray POST token.
//!
//! These are not authentication. They are guardrails that match the
//! existing `dam-web` posture so dam-tray's WebView and a local browser
//! can both POST safely while reducing cross-site exposure. See
//! `RPBLC.Architecture/dam/web/architecture.md § Local Security Boundary`.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::AppState;

const TRAY_POST_TOKEN_HEADER: &str = "x-dam-web-tray-token";

/// Reject non-loopback Host headers. Public at any layer.
pub async fn loopback_host_guard(req: Request, next: Next) -> Result<Response, StatusCode> {
    if !host_is_loopback(req.headers(), req.uri()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(next.run(req).await)
}

/// Origin/Referer + tray-token guard. Applied to mutation routes.
pub async fn origin_guard(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if matches!(
        req.method(),
        &Method::GET | &Method::HEAD | &Method::OPTIONS
    ) {
        return Ok(next.run(req).await);
    }

    let headers = req.headers();
    if origin_is_local(headers) || tray_token_matches(headers, state.tray_post_token.as_deref()) {
        return Ok(next.run(req).await);
    }

    Err(StatusCode::FORBIDDEN)
}

fn host_is_loopback(headers: &HeaderMap, uri: &Uri) -> bool {
    if let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        return is_loopback_authority(host);
    }
    if let Some(authority) = uri.authority() {
        return is_loopback_authority(authority.as_str());
    }
    // Unix sockets, internal calls, etc. — accept (would not appear from a
    // remote origin since we bound to loopback).
    true
}

fn is_loopback_authority(value: &str) -> bool {
    let host = value.rsplit_once(':').map(|(h, _)| h).unwrap_or(value);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn origin_is_local(headers: &HeaderMap) -> bool {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if let Some(origin) = origin {
        return value_is_local(origin);
    }
    let referer = headers.get(header::REFERER).and_then(|v| v.to_str().ok());
    if let Some(referer) = referer {
        return value_is_local(referer);
    }
    false
}

fn value_is_local(value: &str) -> bool {
    let after_scheme = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value);
    let authority = after_scheme.split('/').next().unwrap_or("");
    is_loopback_authority(authority)
}

fn tray_token_matches(headers: &HeaderMap, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let Some(provided) = headers
        .get(TRAY_POST_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    constant_time_eq(provided.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn header_map(values: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (k, v) in values {
            headers.insert(*k, HeaderValue::from_static(v));
        }
        headers
    }

    #[test]
    fn loopback_host_accepts_127() {
        let headers = header_map(&[("host", "127.0.0.1:2896")]);
        let uri: Uri = "/api/v1/wallet".parse().unwrap();
        assert!(host_is_loopback(&headers, &uri));
    }

    #[test]
    fn loopback_host_rejects_remote() {
        let headers = header_map(&[("host", "example.com")]);
        let uri: Uri = "/api/v1/wallet".parse().unwrap();
        assert!(!host_is_loopback(&headers, &uri));
    }

    #[test]
    fn local_origin_passes() {
        let headers = header_map(&[("origin", "http://127.0.0.1:2896")]);
        assert!(origin_is_local(&headers));
    }

    #[test]
    fn remote_origin_fails() {
        let headers = header_map(&[("origin", "https://example.com")]);
        assert!(!origin_is_local(&headers));
    }

    #[test]
    fn tray_token_matches_when_equal() {
        let headers = header_map(&[("x-dam-web-tray-token", "secret")]);
        assert!(tray_token_matches(&headers, Some("secret")));
    }

    #[test]
    fn tray_token_rejects_when_different() {
        let headers = header_map(&[("x-dam-web-tray-token", "wrong")]);
        assert!(!tray_token_matches(&headers, Some("secret")));
    }

    #[test]
    fn tray_token_rejects_when_missing() {
        let headers = HeaderMap::new();
        assert!(!tray_token_matches(&headers, Some("secret")));
    }
}
