use std::sync::Arc;

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::state::AppState;

/// Decide whether a `Host` header value is acceptable.
///
/// This is a DNS-rebinding guard. A malicious web page can point a hostname it
/// controls at `127.0.0.1` and then have the victim's browser issue requests to
/// this server; those requests carry the attacker's hostname in `Host`. By
/// accepting only loopback literals (plus any operator-configured hostnames) we
/// reject rebound requests before they reach a handler.
///
/// `host` is the raw header value, which may include a `:port` suffix and may be
/// a bracketed IPv6 literal.
pub fn host_is_allowed(host: &str, allowed: &[String]) -> bool {
    let hostname = strip_port(host);

    if hostname.eq_ignore_ascii_case("localhost")
        || hostname.eq_ignore_ascii_case("localhost.localdomain")
    {
        return true;
    }

    // Any IP literal that is a loopback address (127.0.0.0/8, ::1).
    if let Ok(addr) = hostname.parse::<std::net::IpAddr>() {
        if addr.is_loopback() {
            return true;
        }
    }

    allowed
        .iter()
        .any(|entry| strip_port(entry).eq_ignore_ascii_case(hostname))
}

/// Strip a trailing `:port` and IPv6 brackets from a host header value.
fn strip_port(host: &str) -> &str {
    let host = host.trim();

    // Bracketed IPv6: "[::1]" or "[::1]:9100"
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }

    // Bare IPv6 without brackets has multiple colons — leave it intact.
    if host.matches(':').count() > 1 {
        return host;
    }

    match host.split_once(':') {
        Some((name, _port)) => name,
        None => host,
    }
}

/// Reject requests whose `Host` header is not a loopback or explicitly allowed
/// hostname, defeating DNS rebinding against the local API.
pub async fn host_guard(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // A missing Host header cannot come from a browser (HTTP/1.1 requires it and
    // HTTP/2 synthesises it from :authority), so absence is treated as a
    // non-browser client and allowed through to the auth layer.
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());

    match host {
        Some(host) if !host_is_allowed(host, &state.allowed_hosts) => (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "forbidden_host",
                "detail": "Host header is not an allowed hostname. Use a loopback address, or pass --allow-host to permit this name.",
            })),
        )
            .into_response(),
        _ => next.run(request).await,
    }
}

pub async fn bearer_auth(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(expected) = &state.auth_token else {
        return next.run(request).await;
    };

    let authorized = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|token| token == expected)
        .unwrap_or(false);

    if authorized {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({ "error": "unauthorized" })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_literals_are_allowed() {
        let none: Vec<String> = Vec::new();
        assert!(host_is_allowed("127.0.0.1", &none));
        assert!(host_is_allowed("127.0.0.1:9100", &none));
        assert!(host_is_allowed("127.0.0.53", &none));
        assert!(host_is_allowed("localhost", &none));
        assert!(host_is_allowed("localhost:9100", &none));
        assert!(host_is_allowed("[::1]", &none));
        assert!(host_is_allowed("[::1]:9100", &none));
    }

    #[test]
    fn rebinding_hostnames_are_rejected() {
        let none: Vec<String> = Vec::new();
        assert!(!host_is_allowed("evil.example.com", &none));
        assert!(!host_is_allowed("evil.example.com:9100", &none));
        // Attacker-controlled name that merely *contains* a loopback literal.
        assert!(!host_is_allowed("127.0.0.1.evil.example.com", &none));
        // Non-loopback IP the server may legitimately bind to still needs opt-in.
        assert!(!host_is_allowed("192.168.1.10:9100", &none));
    }

    #[test]
    fn explicitly_allowed_hosts_pass() {
        let allowed = vec!["wx.internal".to_string(), "192.168.1.10".to_string()];
        assert!(host_is_allowed("wx.internal", &allowed));
        assert!(host_is_allowed("WX.INTERNAL:9100", &allowed));
        assert!(host_is_allowed("192.168.1.10:9100", &allowed));
        assert!(!host_is_allowed("other.internal", &allowed));
    }
}
