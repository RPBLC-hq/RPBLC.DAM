//! `GET /api/v1/events` — Server-Sent Events.
//!
//! Forwards in-process broadcasts from [`EventBus`] (see
//! `events_bus.rs`): `request.pending`, `request.resolved`,
//! `connect.update`, `wallet.invalidate`. Each frame's `event:` is the
//! topic name and `data:` is empty — the React shell re-fetches the
//! canonical state from the matching JSON endpoint. A 15-second
//! heartbeat keeps the connection through proxy idle timers.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::Sse;
use axum::response::sse::{Event, KeepAlive};
use futures_util::Stream;
use futures_util::stream::{self, StreamExt};
use tokio_stream::wrappers::{BroadcastStream, IntervalStream};

use crate::AppState;
use crate::events_bus::EventTopic;

pub async fn stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let topics = BroadcastStream::new(state.events.subscribe()).filter_map(|item| async move {
        // BroadcastStream surfaces `Lagged` errors when a subscriber
        // can't keep up. Drop them — the next real event still
        // triggers a re-fetch, which is the only correctness goal.
        let topic: EventTopic = item.ok()?;
        // SSE requires a non-empty `data:` line for the EventSource API
        // to dispatch the event. Carrying a tiny ack payload (the topic
        // name) keeps the wire human-debuggable through curl while the
        // client still treats the frame as payloadless.
        Some(Result::<Event, Infallible>::Ok(
            Event::default().event(topic.as_str()).data(topic.as_str()),
        ))
    });

    let heartbeats = IntervalStream::new(tokio::time::interval(Duration::from_secs(15)))
        .map(|_| Result::<Event, Infallible>::Ok(Event::default().event("heartbeat").data("ok")));

    let merged = stream::select(topics, heartbeats);
    Sse::new(merged).keep_alive(KeepAlive::default())
}
