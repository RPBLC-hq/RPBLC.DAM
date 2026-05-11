use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct PendingRequest {
    pub id: String,
    pub actor: String,
    pub value_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_preview: Option<String>,
    pub purpose: String,
    pub expires_in_sec: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TriggerRequest {
    pub actor: Option<String>,
    pub value_label: Option<String>,
    pub value_preview: Option<String>,
    pub purpose: Option<String>,
    pub expires_in_sec: Option<u32>,
}

#[derive(Debug, Default)]
pub struct RequestStore {
    protected: AtomicBool,
    next_id: AtomicU64,
    pending: Mutex<Vec<PendingRequest>>,
}

impl RequestStore {
    pub fn is_protected(&self) -> bool {
        self.protected.load(Ordering::SeqCst)
    }

    pub fn set_protected(&self, protected: bool) {
        self.protected.store(protected, Ordering::SeqCst);
    }

    pub fn pending(&self) -> Vec<PendingRequest> {
        self.pending
            .lock()
            .map(|pending| pending.clone())
            .unwrap_or_default()
    }

    pub fn trigger(&self, body: TriggerRequest) -> PendingRequest {
        self.set_protected(true);
        let id = format!("req-{}", self.next_id.fetch_add(1, Ordering::SeqCst) + 1);
        let request = PendingRequest {
            id,
            actor: body.actor.unwrap_or_else(|| "anthropic".to_string()),
            value_label: body
                .value_label
                .unwrap_or_else(|| "mobile phone".to_string()),
            value_preview: body
                .value_preview
                .or_else(|| Some("+1 415 555 0142".to_string())),
            purpose: body.purpose.unwrap_or_else(|| {
                "send the verification code from your bank to confirm the wire".to_string()
            }),
            expires_in_sec: body.expires_in_sec.unwrap_or(30),
        };
        if let Ok(mut pending) = self.pending.lock() {
            pending.push(request.clone());
        }
        request
    }

    pub fn resolve(&self, id: &str) -> Option<PendingRequest> {
        let mut pending = self.pending.lock().ok()?;
        let index = pending.iter().position(|request| request.id == id)?;
        Some(pending.remove(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_adds_pending_request_and_marks_protected() {
        let store = RequestStore::default();

        let request = store.trigger(TriggerRequest {
            actor: Some("anthropic".to_string()),
            value_label: Some("mobile phone".to_string()),
            value_preview: None,
            purpose: Some("confirm a wire".to_string()),
            expires_in_sec: Some(18_000),
        });

        assert!(store.is_protected());
        assert_eq!(request.expires_in_sec, 18_000);
        assert_eq!(store.pending().len(), 1);
    }

    #[test]
    fn resolve_removes_only_matching_request() {
        let store = RequestStore::default();
        let first = store.trigger(TriggerRequest::default());
        let second = store.trigger(TriggerRequest::default());

        assert_eq!(
            store.resolve(&first.id).map(|request| request.id),
            Some(first.id)
        );

        let pending = store.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, second.id);
    }
}
