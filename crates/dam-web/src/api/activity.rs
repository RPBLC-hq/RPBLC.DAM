//! CTZN-facing activity feed and per-event evidence.

use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::AppState;
use crate::activity_map::{Decision, actor_from_message, derive_event_with_actor};
use crate::error::{Ok, WebError, WebErrorCode, WebResult};

#[derive(Debug, Clone, Serialize)]
pub struct ActivityFeed {
    pub events: Vec<ActivityEvent>,
    pub summary: ActivitySummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEvent {
    pub id: i64,
    pub ts: i64,
    pub day: String,
    pub actor: String,
    pub kind: String,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub audit_id: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ActivitySummary {
    pub total: u64,
    pub granted: u64,
    pub sealed: u64,
    pub denied: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActivityQuery {
    pub since: Option<i64>,
    pub decision: Option<String>,
    pub q: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ActivityQuery>,
) -> WebResult<ActivityFeed> {
    let entries = state
        .logs
        .list()
        .map_err(|_| WebError::new(WebErrorCode::DaemonUnreachable))?;

    let q = query.q.as_deref().unwrap_or("").to_lowercase();
    let decision_filter = query.decision.as_deref();

    let actors = operation_actors(&entries);
    let mut summary = ActivitySummary::default();
    let mut events = Vec::new();
    for entry in &entries {
        let Some(ev) =
            derive_event_with_actor(entry, actors.get(&entry.operation_id).map(String::as_str))
        else {
            continue;
        };
        if let Some(since) = query.since
            && entry.timestamp < since
        {
            continue;
        }
        match ev.decision {
            Decision::Granted => summary.granted += 1,
            Decision::Sealed => summary.sealed += 1,
            Decision::Denied => summary.denied += 1,
        }
        summary.total += 1;
        if let Some(d) = decision_filter
            && !decision_matches(d, ev.decision)
        {
            continue;
        }
        if !q.is_empty()
            && !ev.actor.to_lowercase().contains(&q)
            && !ev.kind.to_lowercase().contains(&q)
            && !ev
                .purpose
                .as_deref()
                .map(|p| p.to_lowercase().contains(&q))
                .unwrap_or(false)
        {
            continue;
        }
        events.push(ActivityEvent {
            id: ev.id,
            ts: ev.ts,
            day: ev.day,
            actor: ev.actor,
            kind: ev.kind,
            decision: ev.decision,
            purpose: ev.purpose,
            audit_id: ev.audit_id,
        });
    }

    Ok(Ok::new(ActivityFeed { events, summary }))
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEvidence {
    pub items: Vec<EvidenceItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceItem {
    pub label: String,
    pub value: String,
}

pub async fn detail(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> WebResult<ActivityEvidence> {
    let entries = state
        .logs
        .list()
        .map_err(|_| WebError::new(WebErrorCode::DaemonUnreachable))?;
    let entry = entries
        .into_iter()
        .find(|e| e.id == id)
        .ok_or_else(|| WebError::new(WebErrorCode::WalletValueMissing))?;

    let mut items = vec![
        EvidenceItem {
            label: "event_type".into(),
            value: entry.event_type.clone(),
        },
        EvidenceItem {
            label: "level".into(),
            value: entry.level.clone(),
        },
    ];
    if let Some(kind) = &entry.kind {
        items.push(EvidenceItem {
            label: "kind".into(),
            value: kind.clone(),
        });
    }
    if let Some(reference) = &entry.reference {
        items.push(EvidenceItem {
            label: "reference".into(),
            value: reference.clone(),
        });
    }
    if let Some(action) = &entry.action {
        items.push(EvidenceItem {
            label: "action".into(),
            value: action.clone(),
        });
    }
    items.push(EvidenceItem {
        label: "operation".into(),
        value: entry.operation_id.clone(),
    });
    items.push(EvidenceItem {
        label: "audit_id".into(),
        value: format!("evt_{:016x}", entry.id),
    });

    Ok(Ok::new(ActivityEvidence { items }))
}

fn decision_matches(filter: &str, decision: Decision) -> bool {
    matches!(
        (filter, decision),
        ("granted", Decision::Granted)
            | ("allowed", Decision::Granted)
            | ("sealed", Decision::Sealed)
            | ("denied", Decision::Denied)
            | ("all", _)
    )
}

fn operation_actors(entries: &[dam_log::LogEntry]) -> HashMap<String, String> {
    entries
        .iter()
        .filter_map(|entry| {
            actor_from_message(&entry.message).map(|actor| (entry.operation_id.clone(), actor))
        })
        .collect()
}
