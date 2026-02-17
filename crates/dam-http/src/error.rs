use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// HTTP proxy error type, automatically converted to JSON error responses.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// The upstream LLM provider returned an error.
    #[error("upstream error: {0}")]
    Upstream(String),

    /// The client sent a malformed request.
    #[error("request error: {0}")]
    BadRequest(String),

    /// Internal proxy error (serialization, configuration, etc.).
    #[error("proxy error: {0}")]
    Proxy(String),

    /// A vault operation failed.
    #[error("vault error: {0}")]
    Vault(#[from] dam_core::DamError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Upstream(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Proxy(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            AppError::Vault(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        };

        let body = json!({
            "type": "error",
            "error": {
                "type": "proxy_error",
                "message": message,
            }
        });

        (status, axum::Json(body)).into_response()
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> Self {
        AppError::Upstream(e.to_string())
    }
}
