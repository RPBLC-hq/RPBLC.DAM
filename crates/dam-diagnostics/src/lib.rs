use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoctorOptions {
    pub proxy_url: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupPlanOptions {
    pub state_dir: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub proxy_url: Option<String>,
    pub network_mode: dam_net::CaptureMode,
    pub trust_mode: dam_trust::TrustMode,
}

impl Default for SetupPlanOptions {
    fn default() -> Self {
        Self {
            state_dir: None,
            config_path: None,
            proxy_url: None,
            network_mode: dam_net::CaptureMode::ExplicitProxy,
            trust_mode: dam_trust::TrustMode::Disabled,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupPlanState {
    Ready,
    NeedsAction,
    Blocked,
}

impl SetupPlanState {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NeedsAction => "needs_action",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupStepKind {
    ProfileApply,
    SystemProxy,
    LocalCa,
    Daemon,
}

impl SetupStepKind {
    pub fn tag(self) -> &'static str {
        match self {
            Self::ProfileApply => "profile_apply",
            Self::SystemProxy => "system_proxy",
            Self::LocalCa => "local_ca",
            Self::Daemon => "daemon",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupStepStatus {
    Done,
    Needed,
    Blocked,
    Skipped,
}

impl SetupStepStatus {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Needed => "needed",
            Self::Blocked => "blocked",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupStep {
    pub kind: SetupStepKind,
    pub status: SetupStepStatus,
    pub message: String,
    pub command: Option<Vec<String>>,
    pub requires_confirmation: bool,
    pub changes_system: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupPlan {
    pub state: SetupPlanState,
    pub message: String,
    pub state_dir: PathBuf,
    pub integration_state_dir: PathBuf,
    pub proxy_url: String,
    pub network_mode: dam_net::CaptureMode,
    pub trust_mode: dam_trust::TrustMode,
    pub active_profile: Option<dam_integrations::ActiveProfileState>,
    pub steps: Vec<SetupStep>,
}

pub async fn doctor_report(
    config: &dam_config::DamConfig,
    options: &DoctorOptions,
) -> dam_api::HealthReport {
    let mut report = config_report(config);

    report
        .components
        .push(router_component(config, &mut report.diagnostics));
    report
        .components
        .push(vault_runtime_component(config, &mut report.diagnostics));
    report
        .components
        .push(consent_runtime_component(config, &mut report.diagnostics));
    report
        .components
        .push(log_runtime_component(config, &mut report.diagnostics));
    report
        .components
        .push(proxy_runtime_component(config, options, &mut report.diagnostics).await);
    add_setup_plan_component(config, options, &mut report);
    report.components.push(claude_launcher_component());
    report.components.push(codex_api_launcher_component());
    report.components.push(codex_chatgpt_component());
    report.state = aggregate_state(&report.components);

    report
}

pub fn config_report(config: &dam_config::DamConfig) -> dam_api::HealthReport {
    let mut components = Vec::new();
    let mut diagnostics = Vec::new();

    components.push(dam_api::ComponentHealth {
        component: "config".to_string(),
        state: dam_api::HealthState::Healthy,
        message: "config loaded".to_string(),
    });
    components.push(vault_component(config, &mut diagnostics));
    components.push(consent_component(config, &mut diagnostics));
    components.push(log_component(config, &mut diagnostics));
    components.push(proxy_config_component(config, &mut diagnostics));
    components.push(failure_modes_component(config, &mut diagnostics));

    dam_api::HealthReport {
        state: aggregate_state(&components),
        components,
        diagnostics,
    }
}

pub fn proxy_health_url(
    config: &dam_config::DamConfig,
    proxy_url: Option<&str>,
) -> Result<String, String> {
    if let Some(proxy_url) = proxy_url {
        return append_health(proxy_url);
    }
    append_health(&format!("http://{}", config.proxy.listen))
}

pub fn setup_plan(
    config: &dam_config::DamConfig,
    options: &SetupPlanOptions,
) -> Result<SetupPlan, String> {
    let state_dir = match &options.state_dir {
        Some(state_dir) => state_dir.clone(),
        None => {
            dam_daemon::state_paths()
                .map_err(|error| error.to_string())?
                .state_dir
        }
    };
    let integration_state_dir = state_dir.join("integrations");
    let proxy_url = options
        .proxy_url
        .clone()
        .unwrap_or_else(|| format!("http://{}", config.proxy.listen));
    let active_profile = dam_integrations::read_active_profile(&integration_state_dir)?;
    let enabled_profiles =
        dam_integrations::read_effective_enabled_integrations(&integration_state_dir)?;
    let steps = vec![
        profile_setup_step(&enabled_profiles, &integration_state_dir, &proxy_url),
        system_proxy_setup_step(
            options.network_mode,
            &state_dir,
            options.config_path.as_ref(),
        ),
        local_ca_setup_step(options.trust_mode, &state_dir),
        daemon_setup_step(options.network_mode, options.trust_mode, &state_dir),
    ];

    let state = if steps
        .iter()
        .any(|step| step.status == SetupStepStatus::Blocked)
    {
        SetupPlanState::Blocked
    } else if steps
        .iter()
        .any(|step| step.status == SetupStepStatus::Needed)
    {
        SetupPlanState::NeedsAction
    } else {
        SetupPlanState::Ready
    };
    let message = setup_plan_message(state, &steps);

    Ok(SetupPlan {
        state,
        message,
        state_dir,
        integration_state_dir,
        proxy_url,
        network_mode: options.network_mode,
        trust_mode: options.trust_mode,
        active_profile,
        steps,
    })
}

fn profile_setup_step(
    enabled_profiles: &[dam_integrations::EnabledIntegrationState],
    integration_state_dir: &std::path::Path,
    proxy_url: &str,
) -> SetupStep {
    if enabled_profiles.is_empty() {
        return SetupStep {
            kind: SetupStepKind::ProfileApply,
            status: SetupStepStatus::Skipped,
            message: "no enabled profiles; default endpoint can be used".to_string(),
            command: None,
            requires_confirmation: false,
            changes_system: false,
        };
    }

    let mut any_needs_apply = false;
    let profile_ids = enabled_profiles
        .iter()
        .map(|profile| profile.profile_id.as_str())
        .collect::<Vec<_>>();
    for enabled_profile in enabled_profiles {
        let target_path = match dam_integrations::default_apply_path(
            &enabled_profile.profile_id,
            integration_state_dir,
            std::env::var_os("CODEX_HOME").map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
        ) {
            Ok(path) => path,
            Err(error) => {
                return SetupStep {
                    kind: SetupStepKind::ProfileApply,
                    status: SetupStepStatus::Blocked,
                    message: format!(
                        "enabled profile {} cannot be inspected: {error}",
                        enabled_profile.profile_id
                    ),
                    command: Some(vec![
                        "damctl".to_string(),
                        "integrations".to_string(),
                        "check".to_string(),
                        enabled_profile.profile_id.clone(),
                    ]),
                    requires_confirmation: false,
                    changes_system: false,
                };
            }
        };
        let inspection = match dam_integrations::inspect_apply(
            &enabled_profile.profile_id,
            proxy_url,
            target_path,
            integration_state_dir,
        ) {
            Ok(inspection) => inspection,
            Err(error) => {
                return SetupStep {
                    kind: SetupStepKind::ProfileApply,
                    status: SetupStepStatus::Blocked,
                    message: format!(
                        "enabled profile {} cannot be inspected: {error}",
                        enabled_profile.profile_id
                    ),
                    command: Some(vec![
                        "damctl".to_string(),
                        "integrations".to_string(),
                        "check".to_string(),
                        enabled_profile.profile_id.clone(),
                    ]),
                    requires_confirmation: false,
                    changes_system: false,
                };
            }
        };
        if inspection.record_error.is_some()
            || inspection.status == dam_integrations::IntegrationApplyStatus::Modified
        {
            return SetupStep {
                kind: SetupStepKind::ProfileApply,
                status: SetupStepStatus::Blocked,
                message: format!(
                    "enabled profile {} needs review: {}",
                    enabled_profile.profile_id, inspection.message
                ),
                command: Some(vec![
                    "damctl".to_string(),
                    "integrations".to_string(),
                    "check".to_string(),
                    enabled_profile.profile_id.clone(),
                ]),
                requires_confirmation: false,
                changes_system: false,
            };
        }
        if inspection.status == dam_integrations::IntegrationApplyStatus::NeedsApply {
            any_needs_apply = true;
        }
    }

    if any_needs_apply {
        SetupStep {
            kind: SetupStepKind::ProfileApply,
            status: SetupStepStatus::Needed,
            message: format!("enabled profiles need setup: {}", profile_ids.join(", ")),
            command: Some(vec![
                "dam".to_string(),
                "connect".to_string(),
                "--apply".to_string(),
            ]),
            requires_confirmation: true,
            changes_system: false,
        }
    } else {
        SetupStep {
            kind: SetupStepKind::ProfileApply,
            status: SetupStepStatus::Done,
            message: format!("enabled profiles are applied: {}", profile_ids.join(", ")),
            command: None,
            requires_confirmation: false,
            changes_system: false,
        }
    }
}

fn system_proxy_setup_step(
    network_mode: dam_net::CaptureMode,
    state_dir: &std::path::Path,
    config_path: Option<&PathBuf>,
) -> SetupStep {
    match network_mode {
        dam_net::CaptureMode::ExplicitProxy => SetupStep {
            kind: SetupStepKind::SystemProxy,
            status: SetupStepStatus::Skipped,
            message: "system proxy routing is not required in explicit proxy mode".to_string(),
            command: None,
            requires_confirmation: false,
            changes_system: false,
        },
        dam_net::CaptureMode::Tun => SetupStep {
            kind: SetupStepKind::SystemProxy,
            status: SetupStepStatus::Blocked,
            message: "TUN routing is not implemented in this local build".to_string(),
            command: None,
            requires_confirmation: false,
            changes_system: true,
        },
        dam_net::CaptureMode::SystemProxy => {
            if dam_net_macos::system_proxy_installed(state_dir) {
                return SetupStep {
                    kind: SetupStepKind::SystemProxy,
                    status: SetupStepStatus::Done,
                    message: "macOS PAC system proxy routing is installed".to_string(),
                    command: None,
                    requires_confirmation: false,
                    changes_system: false,
                };
            }
            let mut command = vec![
                "dam".to_string(),
                "network".to_string(),
                "install-system-proxy".to_string(),
            ];
            if let Some(config_path) = config_path {
                command.push("--config".to_string());
                command.push(config_path.display().to_string());
            }
            command.push("--yes".to_string());
            SetupStep {
                kind: SetupStepKind::SystemProxy,
                status: SetupStepStatus::Needed,
                message: "macOS PAC system proxy routing needs to be installed".to_string(),
                command: Some(command),
                requires_confirmation: true,
                changes_system: true,
            }
        }
    }
}

fn local_ca_setup_step(trust_mode: dam_trust::TrustMode, state_dir: &std::path::Path) -> SetupStep {
    match trust_mode {
        dam_trust::TrustMode::Disabled => SetupStep {
            kind: SetupStepKind::LocalCa,
            status: SetupStepStatus::Skipped,
            message: "local CA trust is not required while trust mode is disabled".to_string(),
            command: None,
            requires_confirmation: false,
            changes_system: false,
        },
        dam_trust::TrustMode::LocalCa => {
            let plan = match dam_trust::local_ca_install_plan(state_dir) {
                Ok(plan) => plan,
                Err(error) => {
                    return SetupStep {
                        kind: SetupStepKind::LocalCa,
                        status: SetupStepStatus::Blocked,
                        message: format!("local CA trust cannot be inspected: {error}"),
                        command: Some(vec![
                            "damctl".to_string(),
                            "trust".to_string(),
                            "inspect".to_string(),
                        ]),
                        requires_confirmation: false,
                        changes_system: true,
                    };
                }
            };
            if plan
                .artifact
                .as_ref()
                .map(dam_trust::LocalCaRecord::installed)
                .unwrap_or(false)
            {
                return SetupStep {
                    kind: SetupStepKind::LocalCa,
                    status: SetupStepStatus::Done,
                    message: "DAM local CA is installed in system trust".to_string(),
                    command: None,
                    requires_confirmation: false,
                    changes_system: false,
                };
            }
            if plan.support == dam_trust::TrustSupport::Planned {
                return SetupStep {
                    kind: SetupStepKind::LocalCa,
                    status: SetupStepStatus::Blocked,
                    message: plan.message,
                    command: None,
                    requires_confirmation: false,
                    changes_system: true,
                };
            }
            SetupStep {
                kind: SetupStepKind::LocalCa,
                status: SetupStepStatus::Needed,
                message: plan.message,
                command: Some(vec![
                    "dam".to_string(),
                    "trust".to_string(),
                    "install-local-ca".to_string(),
                    "--yes".to_string(),
                ]),
                requires_confirmation: true,
                changes_system: true,
            }
        }
    }
}

fn daemon_setup_step(
    network_mode: dam_net::CaptureMode,
    trust_mode: dam_trust::TrustMode,
    state_dir: &std::path::Path,
) -> SetupStep {
    let state_file = state_dir.join("daemon.json");
    let status = match dam_daemon::read_state_from(&state_file) {
        Ok(Some(state)) if dam_daemon::process_is_running(state.pid) => {
            if state.network_mode == network_mode && state.trust.mode == trust_mode {
                return SetupStep {
                    kind: SetupStepKind::Daemon,
                    status: SetupStepStatus::Done,
                    message: format!("daemon is connected at {}", state.proxy_url),
                    command: None,
                    requires_confirmation: false,
                    changes_system: false,
                };
            }
            return SetupStep {
                kind: SetupStepKind::Daemon,
                status: SetupStepStatus::Blocked,
                message: format!(
                    "daemon is already running with network mode {} and trust mode {}; disconnect before changing setup",
                    state.network_mode, state.trust.mode
                ),
                command: Some(vec!["dam".to_string(), "disconnect".to_string()]),
                requires_confirmation: true,
                changes_system: false,
            };
        }
        Ok(Some(_)) => "stale",
        Ok(None) => "disconnected",
        Err(_) => {
            return SetupStep {
                kind: SetupStepKind::Daemon,
                status: SetupStepStatus::Blocked,
                message: "daemon state is unreadable".to_string(),
                command: Some(vec![
                    "damctl".to_string(),
                    "daemon".to_string(),
                    "inspect".to_string(),
                ]),
                requires_confirmation: false,
                changes_system: false,
            };
        }
    };

    let mut command = vec!["dam".to_string(), "connect".to_string()];
    if network_mode != dam_net::CaptureMode::ExplicitProxy {
        command.push("--network-mode".to_string());
        command.push(network_mode.tag().to_string());
    }
    if trust_mode != dam_trust::TrustMode::Disabled {
        command.push("--trust-mode".to_string());
        command.push(trust_mode.tag().to_string());
    }
    SetupStep {
        kind: SetupStepKind::Daemon,
        status: SetupStepStatus::Needed,
        message: format!("daemon is {status}; start DAM"),
        command: Some(command),
        requires_confirmation: false,
        changes_system: false,
    }
}

fn setup_plan_message(state: SetupPlanState, steps: &[SetupStep]) -> String {
    match state {
        SetupPlanState::Ready => "local AI protection is ready".to_string(),
        SetupPlanState::Blocked => steps
            .iter()
            .find(|step| step.status == SetupStepStatus::Blocked)
            .map(|step| format!("setup is blocked: {}", step.message))
            .unwrap_or_else(|| "setup is blocked".to_string()),
        SetupPlanState::NeedsAction => steps
            .iter()
            .find(|step| step.status == SetupStepStatus::Needed)
            .map(|step| format!("next setup action: {}", step.message))
            .unwrap_or_else(|| "setup needs action".to_string()),
    }
}

fn add_setup_plan_component(
    config: &dam_config::DamConfig,
    options: &DoctorOptions,
    report: &mut dam_api::HealthReport,
) {
    let plan = match setup_plan(
        config,
        &SetupPlanOptions {
            state_dir: options.state_dir.clone(),
            config_path: options.config_path.clone(),
            proxy_url: options.proxy_url.clone(),
            ..SetupPlanOptions::default()
        },
    ) {
        Ok(plan) => plan,
        Err(error) => {
            report.components.push(dam_api::ComponentHealth {
                component: "setup_plan".to_string(),
                state: dam_api::HealthState::Degraded,
                message: format!("setup plan unavailable: {error}"),
            });
            report.diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Warning,
                "setup_plan_unavailable",
                error,
            ));
            return;
        }
    };
    let state = match plan.state {
        SetupPlanState::Ready => dam_api::HealthState::Healthy,
        SetupPlanState::NeedsAction => dam_api::HealthState::Degraded,
        SetupPlanState::Blocked => dam_api::HealthState::Unhealthy,
    };
    report.components.push(dam_api::ComponentHealth {
        component: "setup_plan".to_string(),
        state,
        message: plan.message.clone(),
    });
    for step in plan.steps.iter().filter(|step| {
        matches!(
            step.status,
            SetupStepStatus::Needed | SetupStepStatus::Blocked
        )
    }) {
        report.diagnostics.push(dam_api::Diagnostic::new(
            if step.status == SetupStepStatus::Blocked {
                dam_api::DiagnosticSeverity::Error
            } else {
                dam_api::DiagnosticSeverity::Warning
            },
            format!("setup_{}", step.kind.tag()),
            step.message.clone(),
        ));
    }
}

fn append_health(value: &str) -> Result<String, String> {
    let mut url = reqwest::Url::parse(value)
        .map_err(|error| format!("invalid proxy url {value}: {error}"))?;
    let path = url.path().trim_end_matches('/');
    url.set_path(&format!("{path}/health"));
    Ok(url.to_string())
}

fn aggregate_state(components: &[dam_api::ComponentHealth]) -> dam_api::HealthState {
    if components
        .iter()
        .any(|component| component.state == dam_api::HealthState::Unhealthy)
    {
        dam_api::HealthState::Unhealthy
    } else if components
        .iter()
        .any(|component| component.state == dam_api::HealthState::Degraded)
    {
        dam_api::HealthState::Degraded
    } else {
        dam_api::HealthState::Healthy
    }
}

fn vault_component(
    config: &dam_config::DamConfig,
    diagnostics: &mut Vec<dam_api::Diagnostic>,
) -> dam_api::ComponentHealth {
    match config.vault.backend {
        dam_config::VaultBackend::Sqlite => dam_api::ComponentHealth {
            component: "vault".to_string(),
            state: dam_api::HealthState::Healthy,
            message: format!("sqlite vault path {}", config.vault.sqlite_path.display()),
        },
        dam_config::VaultBackend::Remote
            if config.failure.vault_write == dam_config::VaultWriteFailureMode::RedactOnly =>
        {
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Warning,
                "remote_vault_not_implemented",
                "remote vault backend is configured but this local build only has redact-only fallback",
            ));
            dam_api::ComponentHealth {
                component: "vault".to_string(),
                state: dam_api::HealthState::Degraded,
                message: "remote vault backend is not implemented; redact-only fallback configured"
                    .to_string(),
            }
        }
        dam_config::VaultBackend::Remote => {
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Error,
                "remote_vault_not_implemented",
                "remote vault backend is configured but this local build cannot use it with fail-closed behavior",
            ));
            dam_api::ComponentHealth {
                component: "vault".to_string(),
                state: dam_api::HealthState::Unhealthy,
                message: "remote vault backend is not implemented for fail-closed behavior"
                    .to_string(),
            }
        }
    }
}

fn consent_component(
    config: &dam_config::DamConfig,
    _diagnostics: &mut Vec<dam_api::Diagnostic>,
) -> dam_api::ComponentHealth {
    if !config.consent.enabled {
        return dam_api::ComponentHealth {
            component: "consent".to_string(),
            state: dam_api::HealthState::Degraded,
            message: "consent is disabled".to_string(),
        };
    }

    match config.consent.backend {
        dam_config::ConsentBackend::Sqlite => dam_api::ComponentHealth {
            component: "consent".to_string(),
            state: dam_api::HealthState::Healthy,
            message: format!(
                "sqlite consent path {}, default ttl {}s, mcp writes {}",
                config.consent.sqlite_path.display(),
                config.consent.default_ttl_seconds,
                if config.consent.mcp_write_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
        },
    }
}

fn log_component(
    config: &dam_config::DamConfig,
    diagnostics: &mut Vec<dam_api::Diagnostic>,
) -> dam_api::ComponentHealth {
    if !config.log.enabled || config.log.backend == dam_config::LogBackend::None {
        return dam_api::ComponentHealth {
            component: "log".to_string(),
            state: dam_api::HealthState::Degraded,
            message: "logging is disabled".to_string(),
        };
    }

    match config.log.backend {
        dam_config::LogBackend::Sqlite => dam_api::ComponentHealth {
            component: "log".to_string(),
            state: dam_api::HealthState::Healthy,
            message: format!("sqlite log path {}", config.log.sqlite_path.display()),
        },
        dam_config::LogBackend::Remote
            if config.failure.log_write == dam_config::LogWriteFailureMode::WarnContinue =>
        {
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Warning,
                "remote_log_not_implemented",
                "remote log backend is configured but this local build only supports warn-and-continue",
            ));
            dam_api::ComponentHealth {
                component: "log".to_string(),
                state: dam_api::HealthState::Degraded,
                message: "remote log backend is not implemented; warn-and-continue configured"
                    .to_string(),
            }
        }
        dam_config::LogBackend::Remote => {
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Error,
                "remote_log_not_implemented",
                "remote log backend is configured but this local build cannot use it with fail-closed behavior",
            ));
            dam_api::ComponentHealth {
                component: "log".to_string(),
                state: dam_api::HealthState::Unhealthy,
                message: "remote log backend is not implemented for fail-closed behavior"
                    .to_string(),
            }
        }
        dam_config::LogBackend::None => unreachable!("none handled before backend match"),
    }
}

fn vault_runtime_component(
    config: &dam_config::DamConfig,
    diagnostics: &mut Vec<dam_api::Diagnostic>,
) -> dam_api::ComponentHealth {
    match config.vault.backend {
        dam_config::VaultBackend::Sqlite => match dam_vault::Vault::open(&config.vault.sqlite_path)
        {
            Ok(_) => dam_api::ComponentHealth {
                component: "vault_runtime".to_string(),
                state: dam_api::HealthState::Healthy,
                message: format!(
                    "sqlite vault opens at {}",
                    config.vault.sqlite_path.display()
                ),
            },
            Err(error) => {
                diagnostics.push(dam_api::Diagnostic::new(
                    dam_api::DiagnosticSeverity::Error,
                    "vault_sqlite_unavailable",
                    format!("sqlite vault cannot be opened: {error}"),
                ));
                dam_api::ComponentHealth {
                    component: "vault_runtime".to_string(),
                    state: dam_api::HealthState::Unhealthy,
                    message: format!(
                        "sqlite vault unavailable at {}",
                        config.vault.sqlite_path.display()
                    ),
                }
            }
        },
        dam_config::VaultBackend::Remote => dam_api::ComponentHealth {
            component: "vault_runtime".to_string(),
            state: dam_api::HealthState::Degraded,
            message: "remote vault runtime check is not implemented".to_string(),
        },
    }
}

fn consent_runtime_component(
    config: &dam_config::DamConfig,
    diagnostics: &mut Vec<dam_api::Diagnostic>,
) -> dam_api::ComponentHealth {
    if !config.consent.enabled {
        return dam_api::ComponentHealth {
            component: "consent_runtime".to_string(),
            state: dam_api::HealthState::Degraded,
            message: "consent is disabled".to_string(),
        };
    }

    match config.consent.backend {
        dam_config::ConsentBackend::Sqlite => {
            match dam_consent::ConsentStore::open(&config.consent.sqlite_path) {
                Ok(_) => dam_api::ComponentHealth {
                    component: "consent_runtime".to_string(),
                    state: dam_api::HealthState::Healthy,
                    message: format!(
                        "sqlite consent opens at {}",
                        config.consent.sqlite_path.display()
                    ),
                },
                Err(error) => {
                    diagnostics.push(dam_api::Diagnostic::new(
                        dam_api::DiagnosticSeverity::Error,
                        "consent_sqlite_unavailable",
                        format!("sqlite consent store cannot be opened: {error}"),
                    ));
                    dam_api::ComponentHealth {
                        component: "consent_runtime".to_string(),
                        state: dam_api::HealthState::Unhealthy,
                        message: format!(
                            "sqlite consent unavailable at {}",
                            config.consent.sqlite_path.display()
                        ),
                    }
                }
            }
        }
    }
}

fn log_runtime_component(
    config: &dam_config::DamConfig,
    diagnostics: &mut Vec<dam_api::Diagnostic>,
) -> dam_api::ComponentHealth {
    if !config.log.enabled || config.log.backend == dam_config::LogBackend::None {
        return dam_api::ComponentHealth {
            component: "log_runtime".to_string(),
            state: dam_api::HealthState::Degraded,
            message: "logging is disabled".to_string(),
        };
    }

    match config.log.backend {
        dam_config::LogBackend::Sqlite => match dam_log::LogStore::open(&config.log.sqlite_path) {
            Ok(_) => dam_api::ComponentHealth {
                component: "log_runtime".to_string(),
                state: dam_api::HealthState::Healthy,
                message: format!("sqlite log opens at {}", config.log.sqlite_path.display()),
            },
            Err(error) => {
                diagnostics.push(dam_api::Diagnostic::new(
                    dam_api::DiagnosticSeverity::Error,
                    "log_sqlite_unavailable",
                    format!("sqlite log cannot be opened: {error}"),
                ));
                dam_api::ComponentHealth {
                    component: "log_runtime".to_string(),
                    state: dam_api::HealthState::Unhealthy,
                    message: format!(
                        "sqlite log unavailable at {}",
                        config.log.sqlite_path.display()
                    ),
                }
            }
        },
        dam_config::LogBackend::Remote => dam_api::ComponentHealth {
            component: "log_runtime".to_string(),
            state: dam_api::HealthState::Degraded,
            message: "remote log runtime check is not implemented".to_string(),
        },
        dam_config::LogBackend::None => unreachable!("none handled before backend match"),
    }
}

fn proxy_config_component(
    config: &dam_config::DamConfig,
    diagnostics: &mut Vec<dam_api::Diagnostic>,
) -> dam_api::ComponentHealth {
    if !config.proxy.enabled {
        return dam_api::ComponentHealth {
            component: "proxy_config".to_string(),
            state: dam_api::HealthState::Degraded,
            message: "proxy is disabled".to_string(),
        };
    }

    let mut errors = Vec::new();
    if config.proxy.listen.parse::<SocketAddr>().is_err() {
        errors.push(format!(
            "proxy listen address is invalid: {}",
            config.proxy.listen
        ));
    }
    for target in &config.proxy.targets {
        if dam_router::ProviderKind::parse(&target.provider).is_err() {
            errors.push(format!(
                "proxy target {} uses unsupported provider {}",
                target.name, target.provider
            ));
        }
        if reqwest::Url::parse(&target.upstream).is_err() {
            errors.push(format!(
                "proxy target {} has invalid upstream URL {}",
                target.name, target.upstream
            ));
        }
        if let Some(api_key_env) = &target.api_key_env
            && target.api_key.is_none()
        {
            errors.push(format!(
                "proxy target {} requires missing env var {}",
                target.name, api_key_env
            ));
        }
    }

    if errors.is_empty() {
        dam_api::ComponentHealth {
            component: "proxy_config".to_string(),
            state: dam_api::HealthState::Healthy,
            message: format!(
                "proxy enabled on {} with {} target(s)",
                config.proxy.listen,
                config.proxy.targets.len()
            ),
        }
    } else {
        for error in &errors {
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Error,
                "proxy_config_invalid",
                error,
            ));
        }
        dam_api::ComponentHealth {
            component: "proxy_config".to_string(),
            state: dam_api::HealthState::Unhealthy,
            message: errors.join("; "),
        }
    }
}

fn failure_modes_component(
    config: &dam_config::DamConfig,
    diagnostics: &mut Vec<dam_api::Diagnostic>,
) -> dam_api::ComponentHealth {
    let mut reduced_modes = Vec::new();

    match config.proxy.default_failure_mode {
        dam_config::ProxyFailureMode::BypassOnError => {
            reduced_modes.push("proxy default bypass_on_error".to_string());
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Warning,
                "proxy_bypass_on_error",
                "proxy default failure mode can forward unprotected traffic when protection fails",
            ));
        }
        dam_config::ProxyFailureMode::RedactOnly => {
            reduced_modes.push("proxy default redact_only".to_string());
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Warning,
                "proxy_redact_only",
                "proxy default failure mode can continue with irreversible placeholders when recoverability is unavailable",
            ));
        }
        dam_config::ProxyFailureMode::BlockOnError => {}
    }

    for target in &config.proxy.targets {
        match target.failure_mode {
            Some(dam_config::ProxyFailureMode::BypassOnError) => {
                reduced_modes.push(format!("proxy target {} bypass_on_error", target.name));
                diagnostics.push(dam_api::Diagnostic::new(
                    dam_api::DiagnosticSeverity::Warning,
                    "proxy_target_bypass_on_error",
                    format!(
                        "proxy target {} can forward unprotected traffic when protection fails",
                        target.name
                    ),
                ));
            }
            Some(dam_config::ProxyFailureMode::RedactOnly) => {
                reduced_modes.push(format!("proxy target {} redact_only", target.name));
                diagnostics.push(dam_api::Diagnostic::new(
                    dam_api::DiagnosticSeverity::Warning,
                    "proxy_target_redact_only",
                    format!(
                        "proxy target {} can continue with irreversible placeholders when recoverability is unavailable",
                        target.name
                    ),
                ));
            }
            Some(dam_config::ProxyFailureMode::BlockOnError) | None => {}
        }
    }

    if config.failure.vault_write == dam_config::VaultWriteFailureMode::RedactOnly {
        reduced_modes.push("vault redact_only".to_string());
        diagnostics.push(dam_api::Diagnostic::new(
            dam_api::DiagnosticSeverity::Warning,
            "vault_redact_only",
            "vault write failures fall back to irreversible redaction",
        ));
    }

    if config.failure.log_write == dam_config::LogWriteFailureMode::WarnContinue {
        reduced_modes.push("log warn_continue".to_string());
        diagnostics.push(dam_api::Diagnostic::new(
            dam_api::DiagnosticSeverity::Warning,
            "log_warn_continue",
            "log write failures do not fail the protected path",
        ));
    }

    if reduced_modes.is_empty() {
        dam_api::ComponentHealth {
            component: "failure_modes".to_string(),
            state: dam_api::HealthState::Healthy,
            message: "failure modes are strict".to_string(),
        }
    } else {
        dam_api::ComponentHealth {
            component: "failure_modes".to_string(),
            state: dam_api::HealthState::Degraded,
            message: format!(
                "{} reduced-protection mode(s): {}",
                reduced_modes.len(),
                reduced_modes.join(", ")
            ),
        }
    }
}

fn router_component(
    config: &dam_config::DamConfig,
    diagnostics: &mut Vec<dam_api::Diagnostic>,
) -> dam_api::ComponentHealth {
    if !config.proxy.enabled {
        return dam_api::ComponentHealth {
            component: "router".to_string(),
            state: dam_api::HealthState::Degraded,
            message: "proxy routing is disabled".to_string(),
        };
    }

    let route = match dam_router::RoutePlan::from_proxy_config(&config.proxy) {
        Ok(route) => route,
        Err(error) => {
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Error,
                "router_invalid",
                error.to_string(),
            ));
            return dam_api::ComponentHealth {
                component: "router".to_string(),
                state: dam_api::HealthState::Unhealthy,
                message: error.to_string(),
            };
        }
    };

    let decision = route.decide(&reqwest::header::HeaderMap::new());
    let failure_mode = decision.failure_mode().tag();
    let target = decision.target();
    let provider = decision.provider_kind().id();
    match decision.auth() {
        dam_router::RouteAuth::CallerPassthrough => dam_api::ComponentHealth {
            component: "router".to_string(),
            state: dam_api::HealthState::Healthy,
            message: format!(
                "target {} routes to {provider} with caller auth passthrough and {failure_mode}",
                target.name
            ),
        },
        dam_router::RouteAuth::TargetApiKey => dam_api::ComponentHealth {
            component: "router".to_string(),
            state: dam_api::HealthState::Healthy,
            message: format!(
                "target {} routes to {provider} with configured target auth and {failure_mode}",
                target.name
            ),
        },
        dam_router::RouteAuth::ConfigRequired => {
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Warning,
                "router_config_required",
                format!(
                    "target {} requires {} or provider-compatible caller auth at request time",
                    target.name,
                    target
                        .api_key_env
                        .as_deref()
                        .unwrap_or("an API key env var")
                ),
            ));
            dam_api::ComponentHealth {
                component: "router".to_string(),
                state: dam_api::HealthState::Degraded,
                message: format!(
                    "target {} routes to {provider}, but auth is required before protected requests can flow",
                    target.name
                ),
            }
        }
    }
}

async fn proxy_runtime_component(
    config: &dam_config::DamConfig,
    options: &DoctorOptions,
    diagnostics: &mut Vec<dam_api::Diagnostic>,
) -> dam_api::ComponentHealth {
    if !config.proxy.enabled {
        return dam_api::ComponentHealth {
            component: "proxy_runtime".to_string(),
            state: dam_api::HealthState::Degraded,
            message: "proxy is not configured to run".to_string(),
        };
    }

    let health_url = match proxy_health_url(config, options.proxy_url.as_deref()) {
        Ok(url) => url,
        Err(error) => {
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Error,
                "proxy_url_invalid",
                &error,
            ));
            return dam_api::ComponentHealth {
                component: "proxy_runtime".to_string(),
                state: dam_api::HealthState::Unhealthy,
                message: error,
            };
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(2_000))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Error,
                "http_client_unavailable",
                error.to_string(),
            ));
            return dam_api::ComponentHealth {
                component: "proxy_runtime".to_string(),
                state: dam_api::HealthState::Unhealthy,
                message: "failed to build HTTP client".to_string(),
            };
        }
    };

    let report = match client.get(&health_url).send().await {
        Ok(response) => match response.json::<dam_api::ProxyReport>().await {
            Ok(report) => report,
            Err(error) => {
                diagnostics.push(dam_api::Diagnostic::new(
                    dam_api::DiagnosticSeverity::Error,
                    "proxy_status_unreadable",
                    format!("DAM proxy returned unreadable health JSON: {error}"),
                ));
                return dam_api::ComponentHealth {
                    component: "proxy_runtime".to_string(),
                    state: dam_api::HealthState::Unhealthy,
                    message: "DAM proxy returned unreadable health JSON".to_string(),
                };
            }
        },
        Err(error) => {
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Error,
                "dam_down",
                format!("DAM proxy is not reachable at {health_url}: {error}"),
            ));
            return dam_api::ComponentHealth {
                component: "proxy_runtime".to_string(),
                state: dam_api::HealthState::Unhealthy,
                message: format!("DAM proxy is not reachable at {health_url}"),
            };
        }
    };

    let state = proxy_state_to_health(report.state);
    for diagnostic in &report.diagnostics {
        diagnostics.push(diagnostic.clone());
    }
    dam_api::ComponentHealth {
        component: "proxy_runtime".to_string(),
        state,
        message: format!(
            "proxy reports {}: {}",
            proxy_state_tag(report.state),
            report.message
        ),
    }
}

fn proxy_state_to_health(state: dam_api::ProxyState) -> dam_api::HealthState {
    match state {
        dam_api::ProxyState::Protected => dam_api::HealthState::Healthy,
        dam_api::ProxyState::Bypassing | dam_api::ProxyState::ConfigRequired => {
            dam_api::HealthState::Degraded
        }
        dam_api::ProxyState::Blocked
        | dam_api::ProxyState::ProviderDown
        | dam_api::ProxyState::DamDown => dam_api::HealthState::Unhealthy,
    }
}

fn proxy_state_tag(state: dam_api::ProxyState) -> &'static str {
    match state {
        dam_api::ProxyState::Protected => "protected",
        dam_api::ProxyState::Bypassing => "bypassing",
        dam_api::ProxyState::Blocked => "blocked",
        dam_api::ProxyState::ProviderDown => "provider_down",
        dam_api::ProxyState::ConfigRequired => "config_required",
        dam_api::ProxyState::DamDown => "dam_down",
    }
}

fn claude_launcher_component() -> dam_api::ComponentHealth {
    dam_api::ComponentHealth {
        component: "launcher_claude".to_string(),
        state: dam_api::HealthState::Healthy,
        message: "dam claude uses Anthropic base-URL routing with caller auth passthrough"
            .to_string(),
    }
}

fn codex_api_launcher_component() -> dam_api::ComponentHealth {
    if std::env::var_os("OPENAI_API_KEY").is_some() {
        dam_api::ComponentHealth {
            component: "launcher_codex_api".to_string(),
            state: dam_api::HealthState::Healthy,
            message: "dam codex --api can use OPENAI_API_KEY through caller auth passthrough"
                .to_string(),
        }
    } else {
        dam_api::ComponentHealth {
            component: "launcher_codex_api".to_string(),
            state: dam_api::HealthState::Degraded,
            message: "dam codex --api requires OPENAI_API_KEY in the Codex environment".to_string(),
        }
    }
}

fn codex_chatgpt_component() -> dam_api::ComponentHealth {
    dam_api::ComponentHealth {
        component: "launcher_codex_chatgpt".to_string(),
        state: dam_api::HealthState::Healthy,
        message: "dam codex ChatGPT-login mode fails closed until its model transport is protected"
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use tokio::net::TcpListener;

    fn proxy_config(upstream: &str, provider: &str) -> dam_config::DamConfig {
        let dir = tempfile::tempdir().unwrap().keep();
        let mut config = dam_config::DamConfig::default();
        config.vault.sqlite_path = dir.join("vault.db");
        config.log.sqlite_path = dir.join("log.db");
        config.consent.sqlite_path = dir.join("consent.db");
        config.log.enabled = true;
        config.proxy.enabled = true;
        config.proxy.targets.push(dam_config::ProxyTargetConfig {
            name: "test".to_string(),
            provider: provider.to_string(),
            upstream: upstream.to_string(),
            failure_mode: None,
            api_key_env: None,
            api_key: None,
        });
        config
    }

    async fn spawn_health(report: dam_api::ProxyReport) -> String {
        async fn health(
            axum::Extension(report): axum::Extension<dam_api::ProxyReport>,
        ) -> Json<dam_api::ProxyReport> {
            Json(report)
        }

        let app = Router::new().route("/health", get(health));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app.layer(axum::Extension(report)))
                .await
                .unwrap();
        });
        format!("http://{addr}")
    }

    #[test]
    fn config_report_accepts_anthropic_provider() {
        let report = config_report(&proxy_config("https://api.anthropic.com", "anthropic"));

        assert_ne!(report.state, dam_api::HealthState::Unhealthy);
        assert!(!report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "proxy_config_invalid"
                && diagnostic.message.contains("unsupported provider")
        }));
    }

    #[test]
    fn config_report_marks_missing_proxy_key_as_unhealthy() {
        let mut config = proxy_config("https://api.openai.com", "openai-compatible");
        config.proxy.targets[0].api_key_env = Some("MISSING_TEST_OPENAI_KEY".to_string());

        let report = config_report(&config);

        assert_eq!(report.state, dam_api::HealthState::Unhealthy);
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "proxy_config_invalid"
                && diagnostic
                    .message
                    .contains("requires missing env var MISSING_TEST_OPENAI_KEY")
        }));
    }

    #[test]
    fn config_report_marks_reduced_failure_modes_as_degraded() {
        let report = config_report(&proxy_config("https://api.openai.com", "openai-compatible"));

        assert!(report.components.iter().any(|component| {
            component.component == "failure_modes"
                && component.state == dam_api::HealthState::Degraded
                && component.message.contains("proxy default bypass_on_error")
                && component.message.contains("vault redact_only")
                && component.message.contains("log warn_continue")
        }));
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "proxy_bypass_on_error"
                && diagnostic.message.contains("unprotected traffic")
        }));
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "vault_redact_only")
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "log_warn_continue")
        );
    }

    #[test]
    fn config_report_marks_strict_failure_modes_as_healthy() {
        let mut config = proxy_config("https://api.openai.com", "openai-compatible");
        config.proxy.default_failure_mode = dam_config::ProxyFailureMode::BlockOnError;
        config.failure.vault_write = dam_config::VaultWriteFailureMode::FailClosed;
        config.failure.log_write = dam_config::LogWriteFailureMode::FailClosed;

        let report = config_report(&config);

        assert!(report.components.iter().any(|component| {
            component.component == "failure_modes"
                && component.state == dam_api::HealthState::Healthy
                && component.message == "failure modes are strict"
        }));
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "proxy_bypass_on_error"
                    || diagnostic.code == "vault_redact_only"
                    || diagnostic.code == "log_warn_continue")
        );
    }

    #[test]
    fn setup_plan_defaults_to_daemon_start_when_disconnected() {
        let dir = tempfile::tempdir().unwrap();
        let config = proxy_config("https://api.openai.com", "openai-compatible");

        let plan = setup_plan(
            &config,
            &SetupPlanOptions {
                state_dir: Some(dir.path().join("state")),
                ..SetupPlanOptions::default()
            },
        )
        .unwrap();

        assert_eq!(plan.state, SetupPlanState::NeedsAction);
        assert!(plan.message.contains("daemon is disconnected"));
        assert!(plan.steps.iter().any(|step| {
            step.kind == SetupStepKind::ProfileApply && step.status == SetupStepStatus::Skipped
        }));
        assert!(plan.steps.iter().any(|step| {
            step.kind == SetupStepKind::SystemProxy && step.status == SetupStepStatus::Skipped
        }));
        assert!(plan.steps.iter().any(|step| {
            step.kind == SetupStepKind::LocalCa && step.status == SetupStepStatus::Skipped
        }));
        assert!(plan.steps.iter().any(|step| {
            step.kind == SetupStepKind::Daemon
                && step.status == SetupStepStatus::Needed
                && step.command == Some(vec!["dam".to_string(), "connect".to_string()])
        }));
    }

    #[test]
    fn setup_plan_reports_active_profile_needs_apply() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let integration_state_dir = state_dir.join("integrations");
        dam_integrations::set_active_profile("openai-compatible", &integration_state_dir).unwrap();
        let config = proxy_config("https://api.openai.com", "openai-compatible");

        let plan = setup_plan(
            &config,
            &SetupPlanOptions {
                state_dir: Some(state_dir),
                ..SetupPlanOptions::default()
            },
        )
        .unwrap();

        let step = plan
            .steps
            .iter()
            .find(|step| step.kind == SetupStepKind::ProfileApply)
            .unwrap();
        assert_eq!(step.status, SetupStepStatus::Needed);
        assert_eq!(
            step.command,
            Some(vec![
                "dam".to_string(),
                "connect".to_string(),
                "--apply".to_string()
            ])
        );
        assert!(step.requires_confirmation);
    }

    #[test]
    fn setup_plan_reports_system_proxy_setup_when_requested() {
        let dir = tempfile::tempdir().unwrap();
        let config = proxy_config("https://api.openai.com", "openai-compatible");

        let plan = setup_plan(
            &config,
            &SetupPlanOptions {
                state_dir: Some(dir.path().join("state")),
                config_path: Some(PathBuf::from("dam.example.toml")),
                network_mode: dam_net::CaptureMode::SystemProxy,
                ..SetupPlanOptions::default()
            },
        )
        .unwrap();

        let step = plan
            .steps
            .iter()
            .find(|step| step.kind == SetupStepKind::SystemProxy)
            .unwrap();
        assert_eq!(step.status, SetupStepStatus::Needed);
        assert_eq!(
            step.command,
            Some(vec![
                "dam".to_string(),
                "network".to_string(),
                "install-system-proxy".to_string(),
                "--config".to_string(),
                "dam.example.toml".to_string(),
                "--yes".to_string()
            ])
        );
        assert!(step.requires_confirmation);
        assert!(step.changes_system);
    }

    #[tokio::test]
    async fn doctor_uses_router_and_proxy_runtime_status() {
        let proxy_url = spawn_health(dam_api::ProxyReport {
            operation_id: None,
            target: Some("test".to_string()),
            upstream: Some("https://api.example.test".to_string()),
            state: dam_api::ProxyState::Protected,
            message: "proxy is ready".to_string(),
            diagnostics: Vec::new(),
        })
        .await;
        let config = proxy_config("https://api.example.test", "openai-compatible");

        let report = doctor_report(
            &config,
            &DoctorOptions {
                proxy_url: Some(proxy_url),
                ..DoctorOptions::default()
            },
        )
        .await;

        assert!(report.components.iter().any(|component| {
            component.component == "router"
                && component.state == dam_api::HealthState::Healthy
                && component.message.contains("caller auth passthrough")
        }));
        assert!(report.components.iter().any(|component| {
            component.component == "proxy_runtime"
                && component.state == dam_api::HealthState::Healthy
        }));
    }

    #[tokio::test]
    async fn doctor_reports_config_required_route_as_degraded() {
        let mut config = proxy_config("https://api.openai.com", "openai-compatible");
        config.proxy.targets[0].api_key_env = Some("MISSING_TEST_OPENAI_KEY".to_string());

        let report = doctor_report(
            &config,
            &DoctorOptions {
                proxy_url: Some("http://127.0.0.1:1".to_string()),
                ..DoctorOptions::default()
            },
        )
        .await;

        assert!(report.components.iter().any(|component| {
            component.component == "router" && component.state == dam_api::HealthState::Degraded
        }));
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "router_config_required"
                && diagnostic.message.contains("MISSING_TEST_OPENAI_KEY")
        }));
    }
}
