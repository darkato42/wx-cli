use std::sync::Arc;

use axum::http::{HeaderValue, Method};
use axum::middleware;
use axum::routing::get;
use axum::Router;
use tower_http::cors::CorsLayer;

use super::auth;
use super::handlers;
use super::state::AppState;

pub fn build_router(state: Arc<AppState>) -> Router {
    let router = Router::new()
        .route("/api/v1/health", get(handlers::handler_health))
        .route("/api/v1/sessions", get(handlers::handler_sessions))
        .route("/api/v1/contacts", get(handlers::handler_contacts))
        .route("/api/v1/messages", get(handlers::handler_messages))
        .route("/api/v1/timeline", get(handlers::handler_timeline))
        .route("/api/v1/media", get(handlers::handler_media))
        .route("/api/v1/search", get(handlers::handler_search))
        .route("/api/v1/events", get(handlers::handler_sse))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::bearer_auth,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::host_guard,
        ));

    // CORS is OPT-IN and origin-scoped.
    //
    // Previously this was `CorsLayer::permissive()`, which sends
    // `Access-Control-Allow-Origin: *` on every response. Because the API binds
    // to loopback by default and (historically) ran without a token, that meant
    // *any* web page the user visited could read their entire WeChat history —
    // and hold an open SSE stream of incoming messages — with a plain `fetch()`.
    //
    // Programmatic clients (curl, agents, the thin client) do not perform CORS
    // preflight and are unaffected by omitting these headers. Browser front-ends
    // must now be named explicitly via `--cors-origin`.
    let origins = build_cors_origins(&state.cors_origins);
    match origins {
        Some(origins) => router.layer(
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([Method::GET, Method::OPTIONS])
                .allow_headers([axum::http::header::AUTHORIZATION])
                .allow_credentials(true),
        ),
        None => router,
    }
    .with_state(state)
}

/// Parse configured origins into header values, or `None` when CORS is disabled.
fn build_cors_origins(configured: &[String]) -> Option<Vec<HeaderValue>> {
    if configured.is_empty() {
        return None;
    }

    let parsed: Vec<HeaderValue> = configured
        .iter()
        .filter_map(|origin| match HeaderValue::from_str(origin) {
            Ok(value) => Some(value),
            Err(_) => {
                eprintln!("warn: ignoring invalid --cors-origin value: {origin}");
                None
            }
        })
        .collect();

    if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_configured_origins_disables_cors() {
        assert!(build_cors_origins(&[]).is_none());
    }

    #[test]
    fn valid_origins_are_parsed() {
        let origins = build_cors_origins(&["http://localhost:5173".to_string()])
            .expect("origins should parse");
        assert_eq!(origins.len(), 1);
        assert_eq!(origins[0], "http://localhost:5173");
    }

    #[test]
    fn invalid_origins_are_dropped() {
        assert!(build_cors_origins(&["not a header\nvalue".to_string()]).is_none());
    }
}
