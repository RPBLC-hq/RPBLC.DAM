//! Settings, app profile toggles, compatibility apply/rollback routes, danger-zone actions.
//!
//! The shape follows `RPBLC.Architecture/dam/web/specs/settings-tab.md`.

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, env, path::PathBuf, process::Stdio};

use crate::AppState;
use crate::error::{Ok, WebError, WebErrorCode, WebResult};
use crate::events_bus::EventTopic;

const DAM_STATE_DIR_ENV: &str = "DAM_STATE_DIR";

#[derive(Debug, Clone, PartialEq, Eq)]
struct CaptureScope {
    hosts: Vec<String>,
    traffic_app_ids: Option<Vec<String>>,
    proxy_targets: Vec<dam_config::ProxyTargetConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsView {
    pub theme: String,
    pub locale: String,
    pub apps: Vec<AppSetting>,
    pub network: NetworkSetting,
    pub defaults: DefaultsSetting,
    pub danger: DangerSetting,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppSetting {
    pub id: String,
    pub name: String,
    pub purpose: String,
    pub enabled: bool,
    pub profile: String,
    pub profiles: Vec<String>,
    pub install_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkSetting {
    pub network_mode: String,
    pub trust_mode: String,
    pub ready: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefaultsSetting {
    pub auto_deny: String,
    pub remember_grants: bool,
    pub mask_in_log: bool,
    pub system_notify: bool,
    pub auto_resolve_inbound: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DangerSetting {
    pub can_stop_daemon: bool,
}

pub async fn get(State(state): State<AppState>) -> WebResult<SettingsView> {
    Ok(Ok::new(settings_view(&state)?))
}

fn settings_view(state: &AppState) -> Result<SettingsView, WebError> {
    Ok(SettingsView {
        theme: "system".into(),
        locale: "auto".into(),
        apps: app_settings(state)?,
        network: network_settings(state),
        defaults: DefaultsSetting {
            auto_deny: "60".into(),
            remember_grants: false,
            mask_in_log: true,
            system_notify: false,
            auto_resolve_inbound: state.config.proxy.resolve_inbound,
        },
        danger: DangerSetting {
            can_stop_daemon: true,
        },
    })
}

fn app_settings(state: &AppState) -> Result<Vec<AppSetting>, WebError> {
    let state_dir = dam_state_dir()?;
    let integration_state_dir = state_dir.join("integrations");
    dam_integrations::ensure_bundled_profile_files(&integration_state_dir)
        .map_err(settings_error)?;
    let proxy_url = proxy_url(state);
    let enabled = dam_integrations::read_effective_enabled_integrations(&integration_state_dir)
        .map_err(settings_error)?
        .into_iter()
        .map(|profile| profile.profile_id)
        .collect::<std::collections::BTreeSet<_>>();

    dam_integrations::profiles_from_state(&proxy_url, &integration_state_dir)
        .map_err(settings_error)?
        .into_iter()
        .map(|profile| {
            let target_path =
                dam_integrations::profile_definition_path(&integration_state_dir, &profile.id);
            Ok(AppSetting {
                enabled: enabled.contains(&profile.id),
                id: profile.id,
                name: profile.name,
                purpose: profile.summary,
                profile: "default".into(),
                profiles: vec!["default".into()],
                install_state: "applied".into(),
                target_path: Some(display_path(&target_path)),
            })
        })
        .collect()
}

fn network_settings(state: &AppState) -> NetworkSetting {
    match dam_daemon::daemon_status() {
        Ok(dam_daemon::DaemonStatus::Connected(daemon)) => NetworkSetting {
            network_mode: daemon.network_mode.tag().into(),
            trust_mode: daemon.trust.mode.tag().into(),
            ready: daemon.protection_enabled
                && !daemon.transparent_ai_interception_readiness.is_empty()
                && daemon
                    .transparent_ai_interception_readiness
                    .iter()
                    .all(|route| route.readiness.tag() == "ready"),
        },
        Ok(dam_daemon::DaemonStatus::Stale(daemon)) => NetworkSetting {
            network_mode: daemon.network_mode.tag().into(),
            trust_mode: daemon.trust.mode.tag().into(),
            ready: false,
        },
        _ => NetworkSetting {
            network_mode: state.config.proxy.mode.tag().into(),
            trust_mode: "disabled".into(),
            ready: false,
        },
    }
}

fn proxy_url(state: &AppState) -> String {
    match dam_daemon::daemon_status() {
        Ok(dam_daemon::DaemonStatus::Connected(daemon))
        | Ok(dam_daemon::DaemonStatus::Stale(daemon)) => daemon.proxy_url,
        _ => format!("http://{}", state.config.proxy.listen),
    }
}

fn dam_state_dir() -> Result<PathBuf, WebError> {
    dam_daemon::state_paths()
        .map(|paths| paths.state_dir)
        .map_err(|_| WebError::new(WebErrorCode::DaemonUnreachable))
}

fn display_path(path: &std::path::Path) -> String {
    if let Some(home) = env::var_os("HOME").map(PathBuf::from)
        && let Ok(relative) = path.strip_prefix(&home)
    {
        return format!("~/{}", relative.display());
    }
    path.display().to_string()
}

fn settings_error(error: String) -> WebError {
    if error.contains("target changed")
        || error.contains("no longer matches")
        || error.contains("rollback record needs attention")
    {
        WebError::new(WebErrorCode::ApplyModifiedTarget)
    } else if error.contains("failed to read")
        || error.contains("failed to write")
        || error.contains("failed to create")
        || error.contains("failed to replace")
        || error.contains("failed to sync")
    {
        WebError::new(WebErrorCode::ApplyTargetUnwritable)
    } else {
        WebError::new(WebErrorCode::Unknown)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppPatch {
    pub enabled: Option<bool>,
    pub profile: Option<String>,
}

pub async fn post_app(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<AppPatch>,
) -> WebResult<SettingsView> {
    if let Some(enabled) = body.enabled {
        set_app_enabled(&state, &id, enabled)?;
    }
    let _ = body.profile;
    Ok(Ok::new(settings_view(&state)?))
}

pub async fn post_apply(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> WebResult<SettingsView> {
    set_app_enabled(&state, &id, true)?;
    Ok(Ok::new(settings_view(&state)?))
}

pub async fn post_rollback(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> WebResult<SettingsView> {
    set_app_enabled(&state, &id, false)?;
    Ok(Ok::new(settings_view(&state)?))
}

fn set_app_enabled(state: &AppState, profile_id: &str, enabled: bool) -> Result<(), WebError> {
    let state_dir = dam_state_dir()?;
    let integration_state_dir = state_dir.join("integrations");
    dam_integrations::ensure_bundled_profile_files(&integration_state_dir)
        .map_err(settings_error)?;
    dam_integrations::set_integration_enabled(profile_id, enabled, &integration_state_dir)
        .map_err(settings_error)?;
    reconcile_running_capture_scope(state, &state_dir)?;
    state.events.notify(EventTopic::ConnectUpdate);
    Ok(())
}

fn reconcile_running_capture_scope(
    state: &AppState,
    state_dir: &std::path::Path,
) -> Result<(), WebError> {
    let daemon = match dam_daemon::daemon_status() {
        Ok(dam_daemon::DaemonStatus::Connected(daemon)) => daemon,
        Ok(dam_daemon::DaemonStatus::Disconnected | dam_daemon::DaemonStatus::Stale(_)) => {
            return Ok(());
        }
        Err(_) => return Err(WebError::new(WebErrorCode::DaemonUnreachable)),
    };
    let scope = capture_scope_for_state(state.config.as_ref(), state_dir)?;
    match daemon.network_mode {
        dam_net::CaptureMode::Tun => {
            dam_net_macos::install_network_extension_for_hosts(state_dir, &scope.hosts)
                .map_err(|_| WebError::new(WebErrorCode::SetupStepFailed))?;
        }
        dam_net::CaptureMode::SystemProxy => {
            dam_net_macos::install_system_proxy_for_hosts(
                state_dir,
                &daemon.proxy_url,
                &scope.hosts,
            )
            .map_err(|_| WebError::new(WebErrorCode::SetupStepFailed))?;
        }
        dam_net::CaptureMode::ExplicitProxy => {}
    }
    reconnect_daemon_for_app_scope(state, state_dir, &daemon, &scope)
}

fn capture_scope_for_state(
    config: &dam_config::DamConfig,
    state_dir: &std::path::Path,
) -> Result<CaptureScope, WebError> {
    let mut config = config.clone();
    let integration_state_dir = state_dir.join("integrations");
    let mut traffic_app_ids = None;
    if let Some(profile_ids) = dam_integrations::runtime_enabled_profile_ids(&integration_state_dir)
        .map_err(settings_error)?
    {
        let app_ids = dam_integrations::traffic_app_ids_for_profile_ids_from_state(
            &profile_ids,
            &integration_state_dir,
        )
        .map_err(settings_error)?;
        config.traffic.enabled_app_ids = Some(app_ids.clone());
        traffic_app_ids = Some(app_ids);
    }
    let routes = dam_net::ai_routes_from_profile(&config.traffic.effective_profile());
    Ok(CaptureScope {
        hosts: routes.iter().map(|route| route.host.clone()).collect(),
        traffic_app_ids,
        proxy_targets: proxy_targets_from_ai_routes(&routes),
    })
}

fn proxy_targets_from_ai_routes(routes: &[dam_net::AiRoute]) -> Vec<dam_config::ProxyTargetConfig> {
    let mut seen = BTreeSet::new();
    let mut targets = Vec::new();
    for route in routes {
        let key = (
            route.target_name.clone(),
            route.provider.clone(),
            route.upstream.clone(),
        );
        if !seen.insert(key.clone()) {
            continue;
        }
        let (name, provider, upstream) = key;
        targets.push(dam_config::ProxyTargetConfig {
            name,
            provider,
            upstream,
            failure_mode: None,
            api_key_env: None,
            api_key: None,
        });
    }
    targets
}

fn proxy_target_arg(target: &dam_config::ProxyTargetConfig) -> String {
    format!("{}|{}|{}", target.name, target.provider, target.upstream)
}

fn reconnect_daemon_for_app_scope(
    state: &AppState,
    state_dir: &std::path::Path,
    daemon: &dam_daemon::DaemonState,
    scope: &CaptureScope,
) -> Result<(), WebError> {
    let dam_bin =
        locate_dam_binary().ok_or_else(|| WebError::new(WebErrorCode::DaemonUnreachable))?;
    let mut args = vec!["connect".to_string()];
    if let Some(config_path) = daemon.config_path.as_ref().or(state.config_path.as_ref()) {
        args.extend(["--config".to_string(), config_path.display().to_string()]);
    }
    args.extend([
        "--db".to_string(),
        daemon.vault_path.display().to_string(),
        "--network-mode".to_string(),
        daemon.network_mode.tag().to_string(),
        "--trust-mode".to_string(),
        daemon.trust.mode.tag().to_string(),
    ]);
    for target in &scope.proxy_targets {
        args.extend(["--target".to_string(), proxy_target_arg(target)]);
    }
    if let Some(app_ids) = &scope.traffic_app_ids {
        if app_ids.is_empty() {
            args.push("--no-traffic-apps".to_string());
        } else {
            for app_id in app_ids {
                args.extend(["--traffic-app".to_string(), app_id.clone()]);
            }
        }
    }
    match &daemon.log_path {
        Some(path) => args.extend(["--log".to_string(), path.display().to_string()]),
        None => args.push("--no-log".to_string()),
    }
    if let Some(path) = &daemon.consent_path {
        args.extend(["--consent-db".to_string(), path.display().to_string()]);
    }
    args.push(if daemon.resolve_inbound {
        "--resolve-inbound".to_string()
    } else {
        "--no-resolve-inbound".to_string()
    });

    let output = std::process::Command::new(dam_bin)
        .args(&args)
        .env(DAM_STATE_DIR_ENV, state_dir)
        .stdin(Stdio::null())
        .output()
        .map_err(|_| WebError::new(WebErrorCode::DaemonUnreachable))?;
    if !output.status.success() {
        return Err(WebError::new(WebErrorCode::SetupStepFailed));
    }
    if !daemon.protection_enabled {
        dam_daemon::set_protection_enabled(false)
            .map_err(|_| WebError::new(WebErrorCode::DaemonUnreachable))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
pub struct DefaultsPatch {
    pub auto_deny: Option<String>,
    pub remember_grants: Option<bool>,
    pub mask_in_log: Option<bool>,
    pub system_notify: Option<bool>,
    pub auto_resolve_inbound: Option<bool>,
}

pub async fn post_defaults(
    State(_state): State<AppState>,
    Json(body): Json<DefaultsPatch>,
) -> WebResult<SettingsView> {
    let _ = (
        body.auto_deny,
        body.remember_grants,
        body.mask_in_log,
        body.system_notify,
        body.auto_resolve_inbound,
    );
    Err(WebError::new(WebErrorCode::NotImplemented))
}

#[derive(Debug, Clone, Serialize)]
pub struct DangerResult {
    pub ok: bool,
}

pub async fn post_stop_daemon(State(_state): State<AppState>) -> WebResult<DangerResult> {
    // Stop the whole local DAM stack: protection daemon, control
    // surfaces (`dam-tray`, `dam-web`), and any `dam` CLI in flight.
    // The UI dies after the response flushes; the operator relaunches
    // when they're ready.
    //
    // Order matters:
    //   1. Stop the protection daemon gracefully via `dam disconnect
    //      --stop` (it reads the daemon's pid from state and waits for
    //      clean shutdown). This is the only way the daemon's on-disk
    //      state file is correctly cleared.
    //   2. SIGKILL any surface processes still up — `dam-tray`,
    //      `dam-web`, and any stray `dam` CLI. `pkill -KILL -x`
    //      matches the exact basename so unrelated processes are
    //      untouched, and `-KILL` skips the SIGTERM grace period
    //      (the surfaces don't have a graceful path to drain).
    //   3. Exit this process. We're inside dam-web; once the surfaces
    //      are killed, the only thing keeping us up is this handler.
    tokio::spawn(async {
        // Let axum flush the response so the UI's `stop.mutate()`
        // resolves and the dialog closes before processes start dying.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        if let Some(dam_bin) = locate_dam_binary() {
            let _ = std::process::Command::new(&dam_bin)
                .args(["disconnect", "--stop"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }

        // Enumerate every dam-tray / dam-web / dam process by parsing
        // `/bin/ps -A`. We don't use `pkill -x` here: when dam-web is
        // spawned as a launchd-hosted child of the native tray on
        // macOS, `pkill -x <name>` returns "no match" for processes
        // that `ps` lists and that `pgrep -x` finds when invoked from
        // the launching shell. The reproducible workaround is to walk
        // `ps -A` ourselves and signal each PID directly via
        // `kill(2)`, which is unaffected by whatever process-listing
        // gate `pkill` consults.
        let me = std::process::id();
        let mut targets: Vec<u32> = Vec::new();
        if let Ok(out) = std::process::Command::new("/bin/ps")
            .args(["-A", "-o", "pid=,ucomm="])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let mut parts = line.trim().splitn(2, char::is_whitespace);
                let Some(pid_str) = parts.next() else {
                    continue;
                };
                let Some(name) = parts.next().map(str::trim) else {
                    continue;
                };
                if !matches!(name, "dam-tray" | "dam-web" | "dam") {
                    continue;
                }
                if let Ok(pid) = pid_str.parse::<u32>() {
                    targets.push(pid);
                }
            }
        }

        // Belt and braces: when this dam-web was spawned by the
        // native tray, include our immediate parent (dam-tray) in
        // case the ps walk missed it. We gate on `DAM_BIN` because
        // only the tray's spawn path sets that env, so this never
        // accidentally kills the user's shell when dam-web is run
        // standalone from a terminal.
        if std::env::var_os("DAM_BIN").is_some() {
            let parent = unsafe { libc::getppid() } as u32;
            if parent > 1 && !targets.contains(&parent) {
                targets.push(parent);
            }
        }

        // SIGKILL every target. Skip ourselves until the very end so
        // the loop completes before we drop. SAFETY: pids came from
        // `/bin/ps`; kill(2) with SIGKILL is signal-safe.
        let mut self_present = false;
        for pid in &targets {
            if *pid == me {
                self_present = true;
                continue;
            }
            unsafe {
                libc::kill(*pid as libc::c_int, libc::SIGKILL);
            }
        }
        if self_present {
            unsafe {
                libc::kill(me as libc::c_int, libc::SIGKILL);
            }
        }
        std::process::exit(0);
    });
    Ok(Ok::new(DangerResult { ok: true }))
}

/// Locate the `dam` binary so we can run `dam disconnect --stop` to
/// gracefully reap the protection daemon. The native tray spawns
/// dam-web with `DAM_BIN` set; in dev we fall back to looking for a
/// `dam` sibling next to the current executable.
fn locate_dam_binary() -> Option<std::path::PathBuf> {
    if let Ok(value) = std::env::var("DAM_BIN") {
        let path = std::path::PathBuf::from(value);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join("dam");
        if sibling.exists() {
            return Some(sibling);
        }
    }
    None
}

pub async fn post_reset(State(_state): State<AppState>) -> WebResult<DangerResult> {
    Err(WebError::new(WebErrorCode::NotImplemented))
}

pub async fn post_uninstall(State(_state): State<AppState>) -> WebResult<DangerResult> {
    Err(WebError::new(WebErrorCode::NotImplemented))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_errors_map_to_stable_codes() {
        assert_eq!(
            settings_error("target changed outside DAM".into()).code,
            WebErrorCode::ApplyModifiedTarget
        );
        assert_eq!(
            settings_error("failed to write target".into()).code,
            WebErrorCode::ApplyTargetUnwritable
        );
        assert_eq!(
            settings_error("some unexpected integration error".into()).code,
            WebErrorCode::Unknown
        );
    }

    #[test]
    fn capture_scope_expands_enabled_profiles_to_hosts_apps_and_targets() {
        let dir = tempfile::tempdir().unwrap();
        let integration_dir = dir.path().join("integrations");
        dam_integrations::ensure_bundled_profile_files(&integration_dir).unwrap();
        dam_integrations::set_integration_enabled("codex", true, &integration_dir).unwrap();

        let scope = capture_scope_for_state(&dam_config::DamConfig::default(), dir.path()).unwrap();

        assert_eq!(
            scope.traffic_app_ids,
            Some(vec![
                "anthropic-api".to_string(),
                "openai-api".to_string(),
                "chatgpt-codex".to_string(),
            ])
        );
        assert!(scope.hosts.contains(&"api.anthropic.com".to_string()));
        assert!(scope.hosts.contains(&"api.openai.com".to_string()));
        assert!(scope.hosts.contains(&"chatgpt.com".to_string()));
        assert!(scope.hosts.contains(&"ab.chatgpt.com".to_string()));
        assert!(
            scope
                .proxy_targets
                .iter()
                .any(|target| target.name == "anthropic")
        );
        assert!(
            scope
                .proxy_targets
                .iter()
                .any(|target| target.name == "openai")
        );
        assert!(
            scope
                .proxy_targets
                .iter()
                .any(|target| target.name == "chatgpt-codex")
        );
    }

    #[test]
    fn capture_scope_preserves_explicit_empty_enabled_profile_state() {
        let dir = tempfile::tempdir().unwrap();
        let integration_dir = dir.path().join("integrations");
        dam_integrations::ensure_bundled_profile_files(&integration_dir).unwrap();
        dam_integrations::set_integration_enabled("claude-code", false, &integration_dir).unwrap();

        let scope = capture_scope_for_state(&dam_config::DamConfig::default(), dir.path()).unwrap();

        assert_eq!(scope.traffic_app_ids, Some(Vec::new()));
        assert!(scope.hosts.is_empty());
        assert!(scope.proxy_targets.is_empty());
    }
}
