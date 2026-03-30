use axum::Router;
use axum::routing::{get, post};

use crate::proxy::AppState;
use crate::server::{
    handle_chat_completions, handle_codex_responses, handle_messages, handle_responses,
};

/// Build the axum router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(crate::health::handle_healthz))
        .route("/readyz", get(crate::health::handle_readyz))
        .route("/v1/messages", post(handle_messages))
        .route("/v1/chat/completions", post(handle_chat_completions))
        .route("/v1/responses", post(handle_responses))
        .route("/codex/responses", post(handle_codex_responses))
        .with_state(state)
}
