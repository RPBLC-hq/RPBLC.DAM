//! Activity feed (formerly "Recently Scanned"). Surfaces values DAM has
//! seen pass through that aren't in the wallet yet, plus per-event
//! actor context.
//!
//! v1 returns a small hardcoded set so the surface renders during
//! development. Real wiring comes when `dam-detect` exposes a streaming
//! feed of scanned values.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use serde::Serialize;

use crate::AppState;
use crate::error::{Ok, WebResult};

#[derive(Debug, Clone, Default, Serialize)]
pub struct ActivityView {
    pub items: Vec<ActivityItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityItem {
    pub id: String,
    pub ts: i64,
    pub kind: String,
    pub value: String,
    pub actor: Option<String>,
}

pub async fn list(State(_state): State<AppState>) -> WebResult<ActivityView> {
    Ok(Ok::new(ActivityView {
        items: seed_items(),
    }))
}

fn seed_items() -> Vec<ActivityItem> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    vec![
        ActivityItem {
            id: "scan-1".into(),
            ts: now - 90,
            kind: "email".into(),
            value: "alex@gathe.io".into(),
            actor: Some("anthropic".into()),
        },
        ActivityItem {
            id: "scan-2".into(),
            ts: now - 5 * 60,
            kind: "phone".into(),
            value: "+1 415 555 0142".into(),
            actor: Some("openai".into()),
        },
        ActivityItem {
            id: "scan-3".into(),
            ts: now - 12 * 60,
            kind: "card".into(),
            value: "•••• 4291".into(),
            actor: Some("perplexity".into()),
        },
        ActivityItem {
            id: "scan-4".into(),
            ts: now - 47 * 60,
            kind: "address".into(),
            value: "221b Baker St, London".into(),
            actor: Some("cursor".into()),
        },
    ]
}
