//! `GET /api/v1/connect` and `POST /api/v1/connect/action`.
//!
//! v2 wiring: derives the connect view from the real daemon state
//! (`dam_daemon::daemon_status`) and the diagnostics setup plan
//! (`dam_diagnostics::setup_plan`). Pause/resume call
//! `dam_daemon::set_protection_enabled` directly; first-run setup steps
//! (NE install, CA install, profile apply, daemon start) and full
//! connect/disconnect-stop are deferred to the native tray IPC, since
//! they require process spawning and the macOS NE entitlement that
//! only the tray bundle has. The SPA dispatches those through
//! `data-tray-connect` (handled in `dam-tray::main::connect_dam`).

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::AppState;
use crate::activity_map::{Decision, actor_from_message, derive_event_with_actor};
use crate::error::{Ok, WebError, WebErrorCode, WebResult};
use crate::events_bus::EventTopic;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum ConnectState {
    Protected,
    Paused,
    Disconnected,
    Degraded,
    NeedsSetup,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectView {
    pub state: ConnectState,
    pub message: String,
    pub proxy_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_since_unix: Option<u64>,
    pub pending_count: u32,
    pub counts: ConnectCounts,
    pub setup_plan: Option<SetupPlan>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectCounts {
    pub grants: u64,
    pub blocked_today: u64,
    pub apps_mediated: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetupPlan {
    pub steps: Vec<SetupStep>,
    pub current_step_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetupStep {
    pub id: String,
    pub label: String,
    pub state: SetupStepState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum SetupStepState {
    Todo,
    Current,
    Done,
    Blocked,
    Failed,
}

pub async fn get(State(state): State<AppState>) -> WebResult<ConnectView> {
    let pending_count = state.requests.pending().len() as u32;

    // Daemon record on disk. `Stale` and `Disconnected` are normal
    // first-run states, not errors; we only escalate to
    // DaemonUnreachable when the underlying read itself fails.
    let daemon_status =
        dam_daemon::daemon_status().map_err(|_| WebError::new(WebErrorCode::DaemonUnreachable))?;

    let (proxy_url, network_mode, trust_mode) = match &daemon_status {
        dam_daemon::DaemonStatus::Connected(daemon_state) => (
            Some(daemon_state.proxy_url.clone()),
            daemon_state.network_mode,
            daemon_state.trust.mode,
        ),
        // Disconnected default depends on whether dam-tray is hosting
        // us from a code-signed `.app` bundle. The macOS Network
        // Extension can only be installed by a bundled host; running
        // `dam-tray` from `cargo run`/`target/debug/` returns
        // NeedsApproval (or NeedsReboot) forever because there's no
        // extension to activate. So:
        //   * Bundled (`DAM_TRAY_BUNDLED=1` set by the tray):
        //     Tun capture + LocalCa trust. The setup checklist
        //     surfaces the NE-install + CA-install steps so the
        //     real production flow runs end-to-end.
        //   * Dev / unbundled: ExplicitProxy + Disabled. The setup
        //     checklist hides both steps — they're irrelevant to a
        //     dev run that mediates via an explicit `HTTPS_PROXY`
        //     env on the AI client. Only `daemon_start` remains.
        _ if std::env::var_os("DAM_TRAY_BUNDLED").is_some() => (
            None,
            dam_net::CaptureMode::Tun,
            dam_trust::TrustMode::LocalCa,
        ),
        _ => (
            None,
            dam_net::CaptureMode::ExplicitProxy,
            dam_trust::TrustMode::Disabled,
        ),
    };

    // Setup plan. `setup_plan` is best-effort here: a None plan still
    // lets us render the canonical disconnected/paused/protected
    // states, just without the per-step checklist on first run.
    let plan = dam_diagnostics::setup_plan(
        state.config.as_ref(),
        &dam_diagnostics::SetupPlanOptions {
            state_dir: None,
            config_path: state.config_path.clone(),
            proxy_url: proxy_url.clone(),
            network_mode,
            trust_mode,
        },
    )
    .ok();

    let connect_state = derive_connect_state(&daemon_status, plan.as_ref());

    let setup_plan = plan.as_ref().and_then(|p| match connect_state {
        ConnectState::NeedsSetup | ConnectState::Degraded => Some(map_setup_plan(p)),
        _ => None,
    });

    let message = match connect_state {
        ConnectState::Protected => "protected",
        ConnectState::Paused => "paused",
        ConnectState::Disconnected => "disconnected",
        ConnectState::Degraded => "degraded",
        ConnectState::NeedsSetup => "needs_setup",
    }
    .to_string();

    let protected_since_unix = match (&daemon_status, connect_state) {
        (dam_daemon::DaemonStatus::Connected(daemon_state), ConnectState::Protected) => {
            daemon_state
                .protection_started_at_unix
                .or(Some(daemon_state.started_at_unix))
        }
        _ => None,
    };

    Ok(Ok::new(ConnectView {
        state: connect_state,
        message,
        proxy_url,
        protected_since_unix,
        pending_count,
        counts: connect_counts(&state),
        setup_plan,
    }))
}

fn connect_counts(state: &AppState) -> ConnectCounts {
    ConnectCounts {
        grants: active_grants_count(state.consent_store.as_deref()),
        blocked_today: blocked_today_count(
            &state.logs.list().unwrap_or_default(),
            now_unix_secs().unwrap_or_default(),
        ),
        apps_mediated: apps_mediated_count().unwrap_or_default(),
    }
}

fn active_grants_count(store: Option<&dam_consent::ConsentStore>) -> u64 {
    let Some(store) = store else {
        return 0;
    };
    let now = now_unix_secs().unwrap_or_default();
    store
        .list()
        .map(|entries| {
            entries
                .into_iter()
                .filter(|entry| entry.is_active_at(now))
                .count() as u64
        })
        .unwrap_or_default()
}

fn blocked_today_count(entries: &[dam_log::LogEntry], now: i64) -> u64 {
    let today = epoch_day(now);
    let actors = operation_actors(entries);
    entries
        .iter()
        .filter(|entry| epoch_day(entry.timestamp) == today)
        .filter_map(|entry| {
            derive_event_with_actor(entry, actors.get(&entry.operation_id).map(String::as_str))
        })
        .filter(|event| matches!(event.decision, Decision::Denied))
        .count() as u64
}

fn apps_mediated_count() -> Result<u64, String> {
    let state_dir = dam_daemon::state_paths()
        .map(|paths| paths.state_dir)
        .map_err(|error| error.to_string())?;
    apps_mediated_count_from(&state_dir.join("integrations"))
}

fn apps_mediated_count_from(integration_state_dir: &Path) -> Result<u64, String> {
    dam_integrations::read_effective_enabled_integrations(integration_state_dir)
        .map(|profiles| profiles.len() as u64)
}

fn operation_actors(entries: &[dam_log::LogEntry]) -> HashMap<String, String> {
    entries
        .iter()
        .filter_map(|entry| {
            actor_from_message(&entry.message).map(|actor| (entry.operation_id.clone(), actor))
        })
        .collect()
}

fn epoch_day(timestamp: i64) -> i64 {
    timestamp.max(0) / 86_400
}

fn now_unix_secs() -> Result<i64, WebError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|_| WebError::new(WebErrorCode::Unknown))
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionRequest {
    pub step_id: String,
}

pub async fn post_action(
    State(state): State<AppState>,
    Json(body): Json<ActionRequest>,
) -> WebResult<ConnectView> {
    match body.step_id.as_str() {
        // Pause / resume only flips the on-disk protection flag — the
        // daemon process itself stays up. Cheap, purely in-process.
        "pause" => dam_daemon::set_protection_enabled(false)
            .map_err(|_| WebError::new(WebErrorCode::DaemonUnreachable))?,
        "resume" => dam_daemon::set_protection_enabled(true)
            .map_err(|_| WebError::new(WebErrorCode::DaemonUnreachable))?,
        // Connect, disconnect-with-stop, and the per-step setup
        // actions all require either spawning the `dam` binary or the
        // macOS Network Extension entitlement. The SPA dispatches them
        // through `data-tray-connect` IPC (see `dam-tray::main`); when
        // the SPA is loaded outside the tray (a browser tab), these
        // remain not-implemented for now and the user uses the CLI.
        _ => return Err(WebError::new(WebErrorCode::NotImplemented)),
    }
    state.events.notify(EventTopic::ConnectUpdate);
    get(State(state)).await
}

fn derive_connect_state(
    daemon_status: &dam_daemon::DaemonStatus,
    plan: Option<&dam_diagnostics::SetupPlan>,
) -> ConnectState {
    match daemon_status {
        dam_daemon::DaemonStatus::Connected(daemon_state) => {
            if matches!(
                plan.map(|p| p.state),
                Some(dam_diagnostics::SetupPlanState::Blocked)
            ) {
                return ConnectState::Degraded;
            }
            if matches!(
                plan.map(|p| p.state),
                Some(dam_diagnostics::SetupPlanState::NeedsAction)
            ) {
                return ConnectState::NeedsSetup;
            }
            if daemon_state.protection_enabled {
                ConnectState::Protected
            } else {
                ConnectState::Paused
            }
        }
        // Stale = state file points to a pid that's no longer running.
        // It's a degraded surface, not a clean disconnected one — the
        // user thought DAM was up and it isn't.
        dam_daemon::DaemonStatus::Stale(_) => ConnectState::Degraded,
        dam_daemon::DaemonStatus::Disconnected => match plan.map(|p| p.state) {
            Some(dam_diagnostics::SetupPlanState::NeedsAction)
            | Some(dam_diagnostics::SetupPlanState::Blocked) => ConnectState::NeedsSetup,
            _ => ConnectState::Disconnected,
        },
    }
}

fn map_setup_plan(plan: &dam_diagnostics::SetupPlan) -> SetupPlan {
    // Filter Skipped steps — those are diagnostic-audit checks that
    // didn't apply to the current config (e.g. "system proxy not
    // required in explicit-proxy mode"). Surfacing them in the
    // welcome checklist as Done steps reads as "you already did
    // these," which is misleading because the user didn't do anything.
    // Keep them off the welcome surface; they belong on Health.
    let mut steps: Vec<SetupStep> = plan
        .steps
        .iter()
        .filter(|step| step.status != dam_diagnostics::SetupStepStatus::Skipped)
        .map(map_setup_step)
        .collect();

    // The diagnostics plan returns steps in execution order. The first
    // outstanding step (Todo, Blocked, or Failed) is the one the user
    // can advance — promote its state to `Current` so the SPA's
    // SetupChecklist highlights it and the "Continue setup" CTA below
    // the list knows which action_id to dispatch.
    if let Some(idx) = steps.iter().position(|step| {
        matches!(
            step.state,
            SetupStepState::Todo | SetupStepState::Blocked | SetupStepState::Failed
        )
    }) && matches!(steps[idx].state, SetupStepState::Todo)
    {
        steps[idx].state = SetupStepState::Current;
    }

    let current_step_id = steps
        .iter()
        .find(|step| {
            matches!(
                step.state,
                SetupStepState::Current | SetupStepState::Blocked | SetupStepState::Failed
            )
        })
        .map(|step| step.id.clone());

    SetupPlan {
        steps,
        current_step_id,
    }
}

fn map_setup_step(step: &dam_diagnostics::SetupStep) -> SetupStep {
    let id = match step.kind {
        dam_diagnostics::SetupStepKind::LaunchAtLogin => "launch_at_login",
        dam_diagnostics::SetupStepKind::NetworkExtension
            if step.message.starts_with("Enable DAM Network Protection") =>
        {
            "ne_enable"
        }
        dam_diagnostics::SetupStepKind::NetworkExtensionConfiguration => "ne_config",
        dam_diagnostics::SetupStepKind::NetworkExtensionEnable => "ne_enable",
        dam_diagnostics::SetupStepKind::NetworkExtensionStart => "ne_start",
        dam_diagnostics::SetupStepKind::LinuxTransparentProxy => "linux_capture",
        dam_diagnostics::SetupStepKind::WindowsFilteringPlatform => "windows_capture",
        dam_diagnostics::SetupStepKind::NetworkExtension => "ne_install",
        // The user has approved the macOS NE; the system needs to
        // reboot to finish activating. Surface this as its own
        // checklist step so the user sees clean progress, not a hard
        // failure on the install click.
        dam_diagnostics::SetupStepKind::NetworkExtensionReboot => "ne_reboot",
        dam_diagnostics::SetupStepKind::LocalCa => "ca_install",
        dam_diagnostics::SetupStepKind::ProfileApply => "apply_profiles",
        dam_diagnostics::SetupStepKind::Daemon => "daemon_start",
        // SystemProxy is a same-bucket setup task as ProfileApply for
        // the SPA's checklist contract — both are "make the proxy
        // visible to traffic". Folded under apply_profiles so the SPA
        // doesn't need a separate slot.
        dam_diagnostics::SetupStepKind::SystemProxy => "apply_profiles",
    }
    .to_string();

    let label = step.message.clone();
    let (state, reason_code) = match step.status {
        dam_diagnostics::SetupStepStatus::Done => (SetupStepState::Done, None),
        dam_diagnostics::SetupStepStatus::Skipped => (SetupStepState::Done, None),
        dam_diagnostics::SetupStepStatus::Needed => (SetupStepState::Todo, None),
        dam_diagnostics::SetupStepStatus::Blocked => (
            SetupStepState::Blocked,
            Some("setup_step_failed".to_string()),
        ),
    };

    SetupStep {
        id,
        label,
        state,
        reason_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_grants_count_uses_current_unrevoked_consents() {
        let store = dam_consent::ConsentStore::open_in_memory().unwrap();
        let active = store
            .grant(&dam_consent::GrantConsent {
                kind: dam_core::SensitiveType::Email,
                value: "ada@example.test".to_string(),
                vault_key: None,
                ttl_seconds: 60,
                created_by: "test".to_string(),
                reason: None,
            })
            .unwrap();
        let revoked = store
            .grant(&dam_consent::GrantConsent {
                kind: dam_core::SensitiveType::Phone,
                value: "+1 415 555 0142".to_string(),
                vault_key: None,
                ttl_seconds: 60,
                created_by: "test".to_string(),
                reason: None,
            })
            .unwrap();

        assert!(store.revoke(&revoked.id).unwrap());

        assert_eq!(active_grants_count(Some(&store)), 1);
        assert!(
            store
                .active_for_value(active.kind, "ada@example.test")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn blocked_today_count_uses_activity_denial_mapping_for_current_utc_day() {
        let today = 2 * 86_400 + 60;
        let yesterday = today - 86_400;
        let entries = vec![
            log_entry(
                1,
                today,
                "policy_decision",
                Some("block"),
                "email",
                "blocked",
            ),
            log_entry(
                2,
                today,
                "policy_decision",
                Some("allow"),
                "email",
                "allowed",
            ),
            log_entry(
                3,
                yesterday,
                "policy_decision",
                Some("block"),
                "email",
                "old",
            ),
        ];

        assert_eq!(blocked_today_count(&entries, today), 1);
    }

    #[test]
    fn apps_mediated_count_reads_enabled_integrations() {
        let dir = tempfile::tempdir().unwrap();
        let integration_state_dir = dir.path().join("integrations");

        dam_integrations::set_integration_enabled("claude-code", true, &integration_state_dir)
            .unwrap();
        dam_integrations::set_integration_enabled("codex-api", true, &integration_state_dir)
            .unwrap();

        assert_eq!(apps_mediated_count_from(&integration_state_dir).unwrap(), 2);
    }

    fn log_entry(
        id: i64,
        timestamp: i64,
        event_type: &str,
        action: Option<&str>,
        kind: &str,
        message: &str,
    ) -> dam_log::LogEntry {
        dam_log::LogEntry {
            id,
            timestamp,
            operation_id: format!("op-{id}"),
            level: "info".to_string(),
            event_type: event_type.to_string(),
            kind: Some(kind.to_string()),
            reference: None,
            action: action.map(ToOwned::to_owned),
            message: message.to_string(),
        }
    }
}
