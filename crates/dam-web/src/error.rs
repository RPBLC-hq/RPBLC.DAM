//! Stable error envelope for `/api/v1/*`.
//!
//! Per `RPBLC.Architecture/dam/web/specs/error-policy.md`:
//!
//! - Backend never returns a sentence. Always a stable `code`.
//! - The frontend maps `code` to a hand-written banker-voice sentence.
//! - Status codes are set; the UI never displays them.
//!
//! Adding a variant here requires adding the corresponding EN + FR
//! catalog entry in the UI.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Stable error code names. Kebab-case → JSON in `Serialize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum WebErrorCode {
    DaemonUnreachable,
    DaemonStarting,
    WalletUnreachable,
    WalletValueMissing,
    ConsentGrantFailed,
    ConsentRevokeFailed,
    ApplyModifiedTarget,
    ApplyTargetUnwritable,
    NePendingUserApproval,
    NeRebootRequired,
    CaInstallDenied,
    SetupStepFailed,
    NetworkOffline,
    NotImplemented,
    InvalidRequest,
    Unknown,
}

impl WebErrorCode {
    fn http_status(self) -> StatusCode {
        match self {
            Self::WalletValueMissing => StatusCode::NOT_FOUND,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn retriable(self) -> bool {
        !matches!(
            self,
            Self::WalletValueMissing
                | Self::InvalidRequest
                | Self::NotImplemented
                | Self::ApplyModifiedTarget
                | Self::NeRebootRequired
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WebError {
    pub ok: bool,
    pub code: WebErrorCode,
    pub retriable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<&'static str>,
}

impl WebError {
    pub fn new(code: WebErrorCode) -> Self {
        Self {
            ok: false,
            code,
            retriable: code.retriable(),
            hint: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_hint(mut self, hint: &'static str) -> Self {
        self.hint = Some(hint);
        self
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let status = self.code.http_status();
        (status, Json(self)).into_response()
    }
}

/// Successful JSON envelope: `{ "ok": true, "data": <T> }`.
#[derive(Debug, Clone, Serialize)]
pub struct Ok<T: Serialize> {
    pub ok: bool,
    pub data: T,
}

impl<T: Serialize> Ok<T> {
    pub fn new(data: T) -> Self {
        Self { ok: true, data }
    }
}

impl<T: Serialize> IntoResponse for Ok<T> {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

/// Convenience type alias for handlers.
pub type WebResult<T> = Result<Ok<T>, WebError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_serializes_snake_case() {
        let body = serde_json::to_string(&WebError::new(WebErrorCode::DaemonUnreachable)).unwrap();
        assert!(body.contains("\"code\":\"daemon_unreachable\""));
        assert!(body.contains("\"ok\":false"));
        assert!(body.contains("\"retriable\":true"));
    }

    #[test]
    fn invalid_request_is_not_retriable() {
        let body = serde_json::to_string(&WebError::new(WebErrorCode::InvalidRequest)).unwrap();
        assert!(body.contains("\"retriable\":false"));
    }

    #[test]
    fn ok_envelope_serializes_correctly() {
        let body = serde_json::to_string(&Ok::new(serde_json::json!({"x": 1}))).unwrap();
        assert!(body.contains("\"ok\":true"));
        assert!(body.contains("\"data\""));
    }
}
