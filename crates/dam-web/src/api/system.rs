//! Operator-facing system log. Web only.

use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::error::{Ok, WebError, WebErrorCode, WebResult};

#[derive(Debug, Clone, Serialize)]
pub struct SystemFeed {
    pub events: Vec<SystemEvent>,
    pub counts: SystemCounts,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SystemCounts {
    pub info: u64,
    pub warn: u64,
    pub error: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemEvent {
    pub id: i64,
    pub ts: i64,
    pub module: String,
    pub severity: Severity,
    pub message: String,
    pub details: Vec<DetailEntry>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetailEntry {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SystemQuery {
    pub scope: Option<String>,
    pub q: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<SystemQuery>,
) -> WebResult<SystemFeed> {
    let entries = state
        .logs
        .list()
        .map_err(|_| WebError::new(WebErrorCode::DaemonUnreachable))?;

    let scope = query.scope.as_deref().unwrap_or("issues");
    let q = query.q.as_deref().unwrap_or("").to_lowercase();

    let mut counts = SystemCounts::default();
    let mut events = Vec::new();

    for entry in entries {
        let severity = severity_from_level(&entry.level);
        match severity {
            Severity::Info => counts.info += 1,
            Severity::Warn => counts.warn += 1,
            Severity::Error => counts.error += 1,
        }
        if !scope_matches(scope, severity, &entry.event_type) {
            continue;
        }
        if !q.is_empty()
            && !entry.message.to_lowercase().contains(&q)
            && !entry.event_type.to_lowercase().contains(&q)
        {
            continue;
        }
        events.push(SystemEvent {
            id: entry.id,
            ts: entry.timestamp,
            module: module_from_event_type(&entry.event_type).to_string(),
            severity,
            message: entry.message.clone(),
            details: build_details(&entry),
        });
    }

    Ok(Ok::new(SystemFeed { events, counts }))
}

fn severity_from_level(level: &str) -> Severity {
    match level.to_ascii_lowercase().as_str() {
        "error" => Severity::Error,
        "warn" | "warning" => Severity::Warn,
        _ => Severity::Info,
    }
}

fn module_from_event_type(event_type: &str) -> &str {
    event_type
        .split_once('_')
        .map(|(m, _)| m)
        .unwrap_or(event_type)
}

fn scope_matches(scope: &str, severity: Severity, event_type: &str) -> bool {
    let module = module_from_event_type(event_type);
    match scope {
        "issues" => !matches!(severity, Severity::Info),
        "all" => true,
        "network" => module == "proxy" || module == "network" || module == "trust",
        other => module == other,
    }
}

fn build_details(entry: &dam_log::LogEntry) -> Vec<DetailEntry> {
    let mut details = Vec::new();
    if let Some(kind) = &entry.kind {
        details.push(DetailEntry {
            label: "kind".into(),
            value: kind.clone(),
        });
    }
    if let Some(reference) = &entry.reference {
        details.push(DetailEntry {
            label: "reference".into(),
            value: reference.clone(),
        });
    }
    if let Some(action) = &entry.action {
        details.push(DetailEntry {
            label: "action".into(),
            value: action.clone(),
        });
    }
    details.push(DetailEntry {
        label: "operation".into(),
        value: entry.operation_id.clone(),
    });
    details
}
