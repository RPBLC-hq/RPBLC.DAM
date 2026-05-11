//! axum app, route table, embedded bundle.

use std::net::SocketAddr;

use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

use crate::AppState;
use crate::api;
use crate::bootstrap::{Bootstrap, render_index};
use crate::guard::{loopback_host_guard, origin_guard};

const BUNDLE_HTML: &str = include_str!("../assets/index.html");
const BUNDLE_JS: &str = include_str!("../assets/bundle.js");
const BUNDLE_CSS: &str = include_str!("../assets/bundle.css");
const FAVICON_SVG: &str = include_str!("../assets/favicon.svg");

pub async fn serve(addr: SocketAddr, state: AppState) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind {addr}: {e}"))?;

    let app = build_router(state);

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("axum serve error: {e}"))
}

pub fn build_router(state: AppState) -> Router {
    let api_routes =
        api::router().route_layer(middleware::from_fn_with_state(state.clone(), origin_guard));

    Router::new()
        .nest("/api/v1", api_routes)
        .route("/assets/bundle.js", get(serve_bundle_js))
        .route("/assets/bundle.css", get(serve_bundle_css))
        .route("/favicon.svg", get(serve_favicon))
        // Plain-text liveness probe used by `dam-tray` to verify the
        // child process is up. Lives at `/_alive` so it doesn't collide
        // with the SPA's `/health` surface.
        .route("/_alive", get(serve_plain_health))
        .fallback(get(serve_index))
        .with_state(state)
        .layer(middleware::from_fn(loopback_host_guard))
}

async fn serve_index(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl IntoResponse {
    let bootstrap = Bootstrap::from_state(&state);
    let html = render_index(BUNDLE_HTML, &bootstrap);
    Html(html)
}

async fn serve_bundle_js() -> impl IntoResponse {
    static_response(BUNDLE_JS, "application/javascript; charset=utf-8")
}

async fn serve_bundle_css() -> impl IntoResponse {
    static_response(BUNDLE_CSS, "text/css; charset=utf-8")
}

async fn serve_favicon() -> impl IntoResponse {
    static_response(FAVICON_SVG, "image/svg+xml; charset=utf-8")
}

async fn serve_plain_health() -> &'static str {
    "ok"
}

fn static_response(body: &'static str, content_type: &'static str) -> Response {
    let mut response = (StatusCode::OK, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_assets_are_embedded() {
        // Sanity: the include_str! values exist (placeholder content is fine).
        assert!(!BUNDLE_HTML.is_empty());
        assert!(!FAVICON_SVG.is_empty());
    }
}
