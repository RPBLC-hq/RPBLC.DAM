use crate::proxy::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

pub(crate) async fn handle_healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub(crate) async fn handle_readyz(State(state): State<AppState>) -> impl IntoResponse {
    match state.vault.conn().lock() {
        Ok(_) => (StatusCode::OK, "ready"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "not ready"),
    }
}
