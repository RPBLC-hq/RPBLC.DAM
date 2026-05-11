//! Merged Doctor + Diagnostics surface. Web only.

use axum::extract::State;
use serde::Serialize;

use crate::AppState;
use crate::error::{Ok, WebResult};

#[derive(Debug, Clone, Serialize)]
pub struct HealthView {
    pub summary: HealthSummary,
    pub daemon: DaemonSection,
    pub network: NetworkSection,
    pub trust: TrustSection,
    pub integrations: IntegrationsSection,
    pub recent: RecentSection,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthSummary {
    pub state: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DaemonSection {
    pub connected: bool,
    pub pid: Option<u32>,
    pub version: Option<String>,
    pub listen: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NetworkSection {
    pub mode: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TrustSection {
    pub mode: String,
    pub local_ca_installed: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct IntegrationsSection {
    pub profiles: Vec<IntegrationStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntegrationStatus {
    pub id: String,
    pub install_state: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RecentSection {
    pub events: Vec<RecentEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecentEvent {
    pub ts: i64,
    pub message: String,
    pub severity: &'static str,
}

pub async fn get(State(state): State<AppState>) -> WebResult<HealthView> {
    let _ = state;
    Ok(Ok::new(HealthView {
        summary: HealthSummary {
            state: "not_connected",
            message: "DAM is not running on this device.",
        },
        daemon: DaemonSection::default(),
        network: NetworkSection::default(),
        trust: TrustSection::default(),
        integrations: IntegrationsSection::default(),
        recent: RecentSection::default(),
    }))
}
