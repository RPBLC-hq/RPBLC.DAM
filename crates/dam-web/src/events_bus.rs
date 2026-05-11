//! In-process broadcast for `/api/v1/events` SSE.
//!
//! Mutating handlers (consent decisions, connect actions, wallet writes)
//! call [`EventBus::notify`]; the SSE handler subscribes and forwards
//! frames to the React shell, which uses them to invalidate the relevant
//! TanStack Query cache. v1 carries only an event topic — no payload —
//! so subscribers re-fetch the canonical state. When `dam-notify` lands,
//! the frame shape can grow without changing the wire contract.

use tokio::sync::broadcast;

const CHANNEL_CAPACITY: usize = 64;

/// Topics broadcast through the event bus. Mirrored on the React side
/// in `useEventStream`. Keep names stable — they are wire identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTopic {
    /// A pending consent request was added or its set changed.
    RequestPending,
    /// A pending consent request was resolved (allowed or denied).
    RequestResolved,
    /// Connect state changed (paused/resumed, setup advanced, etc.).
    ConnectUpdate,
    /// Wallet contents changed (grant or revoke landed).
    WalletInvalidate,
}

impl EventTopic {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequestPending => "request.pending",
            Self::RequestResolved => "request.resolved",
            Self::ConnectUpdate => "connect.update",
            Self::WalletInvalidate => "wallet.invalidate",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<EventTopic>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { sender }
    }

    pub fn notify(&self, topic: EventTopic) {
        // A send error means there are no live subscribers — that is the
        // common case (no SSE clients connected) and is not actionable.
        let _ = self.sender.send(topic);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventTopic> {
        self.sender.subscribe()
    }
}
