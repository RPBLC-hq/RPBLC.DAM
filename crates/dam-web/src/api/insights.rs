//! Privacy-dividend dashboard. Web home.

use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::error::{Ok, WebError, WebErrorCode, WebResult};

#[derive(Debug, Clone, Serialize)]
pub struct InsightsView {
    pub range: String,
    pub summary: Summary,
    pub apps: Vec<AppRank>,
    pub kinds: Vec<KindRank>,
    pub events: Vec<SignificantEvent>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub total: u64,
    pub kind_count: u64,
    pub app_count: u64,
    pub sentence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppRank {
    pub actor: String,
    pub total: u64,
    pub redacted: u64,
    pub allowed: u64,
    pub denied: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct KindRank {
    pub kind: String,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignificantEvent {
    pub id: i64,
    pub ts: i64,
    pub summary: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RangeQuery {
    pub range: Option<String>,
}

pub async fn get(
    State(state): State<AppState>,
    Query(query): Query<RangeQuery>,
) -> WebResult<InsightsView> {
    let entries = state
        .logs
        .list()
        .map_err(|_| WebError::new(WebErrorCode::DaemonUnreachable))?;

    let total = entries.len() as u64;
    let range = query.range.unwrap_or_else(|| "7d".into());
    Ok(Ok::new(InsightsView {
        range,
        summary: Summary {
            total,
            kind_count: 0,
            app_count: 0,
            sentence: if total == 0 {
                "No activity yet. Once your AI tools start asking, DAM will keep track.".into()
            } else {
                format!("DAM kept your real data in the vault {total} times.")
            },
        },
        apps: Vec::new(),
        kinds: Vec::new(),
        events: Vec::new(),
    }))
}
