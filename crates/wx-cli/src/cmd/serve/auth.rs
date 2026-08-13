use std::sync::Arc;

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::state::AppState;

/// Constant-time comparison of a presented bearer token against a
/// precomputed digest of the expected value.
///
/// Only the *presented* side is hashed, per request; the expected side was
/// hashed once at startup and is stored in `AppState` as a fixed-size digest.
/// This means:
/// - the comparison takes the same time regardless of *where* the first
///   difference occurs (no early-exit on a mismatching byte), and
/// - the *length* of the expected token cannot leak via timing: it never
///   participates in per-request work, so neither its hash time nor a length
///   mismatch can be observed. (The presented token's length is attacker-known
///   anyway, so its own hash time leaks nothing.)
///
/// The digests are compared with `subtle::ConstantTimeEq`, which compiles to a
/// fixed sequence of XOR/OR operations with no data-dependent branches.
fn tokens_equal(presented: &str, expected_digest: [u8; 32]) -> bool {
    let presented_digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
    bool::from(presented_digest.ct_eq(&expected_digest))
}

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
    let Some(expected_digest) = state.auth_token_digest else {
        return next.run(request).await;
    };

    let authorized = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|token| tokens_equal(token, expected_digest))
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
    use sha2::{Digest, Sha256};

    fn digest(secret: &str) -> [u8; 32] {
        Sha256::digest(secret.as_bytes()).into()
    }

    #[test]
    fn equal_tokens_match() {
        assert!(tokens_equal("secret-token", digest("secret-token")));
        // Unicode content hashes deterministically too.
        assert!(tokens_equal("你好-世界", digest("你好-世界")));
    }

    #[test]
    fn different_tokens_do_not_match() {
        assert!(!tokens_equal("secret-token", digest("secret-tokem")));
        assert!(!tokens_equal("secret-token", digest("Secret-token")));
        assert!(!tokens_equal("", digest("secret-token")));
        assert!(!tokens_equal("secret-token", digest("")));
    }

    #[test]
    fn tokens_of_different_length_do_not_match() {
        // Length mismatch must still return false; equality is false even
        // though only fixed-size digests are compared.
        assert!(!tokens_equal("short", digest("a-much-longer-token")));
        assert!(!tokens_equal("a-much-longer-token", digest("short")));
    }

    #[test]
    fn empty_tokens_match_only_each_other() {
        assert!(tokens_equal("", digest("")));
        assert!(!tokens_equal("", digest("x")));
    }

    #[test]
    fn comparison_does_not_depend_on_expected_value_work() {
        // The expected side is pre-hashed once: tokens_equal must reject even
        // when only the digest is available, and the digest is not derivable
        // from the function's behavior beyond the compare itself.
        let secret = "super-secret-token";
        let d = digest(secret);
        assert!(tokens_equal(secret, d));
        assert!(!tokens_equal("wrong", d));
    }

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
