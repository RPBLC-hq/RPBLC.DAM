use crate::proxy::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

pub(crate) async fn handle_healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

pub(crate) async fn handle_readyz(State(state): State<AppState>) -> impl IntoResponse {
    let Ok(conn) = state.vault.conn().lock() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "not ready");
    };

    match conn.query_row("SELECT 1", [], |_row| Ok(())) {
        Ok(()) => (StatusCode::OK, "ready"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "not ready"),
    }
}
