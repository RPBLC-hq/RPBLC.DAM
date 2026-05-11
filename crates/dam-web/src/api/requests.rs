//! Pending consent requests. In-memory until `dam-notify` owns delivery.

use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;

use crate::AppState;
use crate::error::{Ok, WebError, WebErrorCode, WebResult};
use crate::events_bus::EventTopic;
use crate::request_store::{PendingRequest, TriggerRequest};

#[derive(Debug, Clone, Default, Serialize)]
pub struct PendingRequests {
    pub items: Vec<PendingRequest>,
}

pub async fn pending(State(state): State<AppState>) -> WebResult<PendingRequests> {
    Ok(Ok::new(PendingRequests {
        items: state.requests.pending(),
    }))
}

pub async fn trigger(
    State(state): State<AppState>,
    Json(body): Json<TriggerRequest>,
) -> WebResult<PendingRequest> {
    let request = state.requests.trigger(body);
    state.events.notify(EventTopic::RequestPending);
    state.events.notify(EventTopic::ConnectUpdate);
    Ok(Ok::new(request))
}

pub async fn resolve(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> WebResult<PendingRequests> {
    state
        .requests
        .resolve(&id)
        .ok_or_else(|| WebError::new(WebErrorCode::WalletValueMissing))?;
    state.events.notify(EventTopic::RequestResolved);
    state.events.notify(EventTopic::ConnectUpdate);
    pending(State(state)).await
}
