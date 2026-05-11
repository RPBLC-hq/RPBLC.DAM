use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use serde::Serialize;

const DEFAULT_LISTEN: &str = "127.0.0.1:7828";
const DEFAULT_LOG_PATH: &str = "log.db";
const DAM_WEB_BIN_ENV: &str = "DAM_WEB_BIN";
const LOGIN_ITEM_MARKER_RELPATH: &str = "startup/login-item.txt";
const LOGIN_ITEM_SKIP_MARKER_RELPATH: &str = "startup/login-item-skipped.txt";
const LAUNCH_AGENT_PLIST_RELPATH: &str = "Library/LaunchAgents/com.rpblc.dam-tray.plist";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    command: CommandKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandKind {
    Connect(ConnectArgs),
    Disconnect(DisconnectArgs),
    Status(StatusArgs),
    Logs(LogsArgs),
    Profile(ProfileArgs),
    Trust(TrustArgs),
    Network(NetworkArgs),
    Startup(StartupArgs),
    Integrations(IntegrationArgs),
    Web(WebArgs),
    DaemonRun(dam_daemon::ProxyOptions),
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebArgs {
    args: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StatusArgs {
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LogsArgs {
    json: bool,
    limit: usize,
    after_id: Option<i64>,
    operation_id: Option<String>,
    events: bool,
}

impl Default for LogsArgs {
    fn default() -> Self {
        Self {
            json: false,
            limit: 20,
            after_id: None,
            operation_id: None,
            events: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectArgs {
    proxy: dam_daemon::ProxyOptions,
    apply_profile_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DisconnectArgs {
    stop_daemon: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProfileArgs {
    Status { json: bool },
    Set { profile_id: String, json: bool },
    Clear { json: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrustArgs {
    GenerateArtifact { json: bool },
    DeleteArtifact { json: bool },
    InstallTrust { json: bool, yes: bool },
    RemoveTrust { json: bool, yes: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NetworkArgs {
    InstallProxy {
        config_path: Option<PathBuf>,
        json: bool,
        yes: bool,
    },
    RemoveProxy {
        json: bool,
        yes: bool,
    },
    InstallNetworkExtension {
        config_path: Option<PathBuf>,
        json: bool,
        yes: bool,
    },
    RemoveNetworkExtension {
        json: bool,
        yes: bool,
    },
    Status {
        json: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StartupArgs {
    Status { json: bool },
    SkipOpenAtLogin { json: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IntegrationArgs {
    List {
        json: bool,
        proxy_url: Option<String>,
    },
    Show {
        profile_id: String,
        json: bool,
        proxy_url: Option<String>,
    },
    Apply {
        profile_id: String,
        dry_run: bool,
        json: bool,
        proxy_url: Option<String>,
        target_path: Option<PathBuf>,
    },
    Rollback {
        profile_id: String,
        json: bool,
    },
}

#[derive(Debug, Clone, Serialize)]
struct StatusView {
    state: &'static str,
    message: String,
    daemon: Option<dam_daemon::DaemonState>,
    proxy: Option<dam_api::ProxyReport>,
    active_profile: Option<dam_integrations::ActiveProfileState>,
    active_profile_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct LogEventView {
    id: i64,
    timestamp: i64,
    operation_id: String,
    level: String,
    event_type: String,
    kind: Option<String>,
    reference: Option<String>,
    action: Option<String>,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct LogOperationSummary {
    operation_id: String,
    first_id: i64,
    last_id: i64,
    timestamp: i64,
    events: usize,
    event_types: Vec<String>,
    actions: Vec<String>,
    summary: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProfileStatusView {
    active_profile: Option<dam_integrations::ActiveProfileState>,
    enabled_profiles: Vec<dam_integrations::EnabledIntegrationState>,
    proxy_url: String,
    applies: Vec<dam_integrations::IntegrationApplyInspection>,
    inspection_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct StartupStatusView {
    state: &'static str,
    message: String,
    platform: &'static str,
    state_dir: PathBuf,
    marker: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
struct LocalCaGenerateView {
    state: &'static str,
    artifact: dam_trust::LocalCaArtifact,
}

#[derive(Debug, Clone, Serialize)]
struct LocalCaDeleteView {
    state: &'static str,
    deleted: bool,
    state_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectProfileExpansion {
    args: Vec<String>,
    selected_profile_ids: Vec<String>,
    traffic_app_ids: Option<Vec<String>>,
    apply_profile_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ConnectProfileSelection {
    profile_ids: Vec<String>,
    explicit_selection: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectApplyOutcome {
    result: dam_integrations::IntegrationApplyResult,
    rollback_available: bool,
}

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    };

    std::process::exit(code);
}

async fn run() -> Result<i32, String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let enabled_connect_profiles = enabled_profiles_for_connect_parse(&args)?;
    match parse_cli_with_connect_profiles(args, enabled_connect_profiles)? {
        Cli {
            command: CommandKind::Help,
        } => {
            println!("{}", usage());
            Ok(0)
        }
        Cli {
            command: CommandKind::Connect(args),
        } => connect(args).await,
        Cli {
            command: CommandKind::Disconnect(args),
        } => disconnect(args).await,
        Cli {
            command: CommandKind::Status(args),
        } => status(args).await,
        Cli {
            command: CommandKind::Logs(args),
        } => logs_command(args),
        Cli {
            command: CommandKind::Profile(args),
        } => profile_command(args),
        Cli {
            command: CommandKind::Trust(args),
        } => trust_command(args),
        Cli {
            command: CommandKind::Network(args),
        } => network_command(args),
        Cli {
            command: CommandKind::Startup(args),
        } => startup_command(args),
        Cli {
            command: CommandKind::Integrations(args),
        } => integrations(args).await,
        Cli {
            command: CommandKind::Web(args),
        } => web_command(args),
        Cli {
            command: CommandKind::DaemonRun(args),
        } => daemon_run(args).await,
    }
}

async fn connect(mut args: ConnectArgs) -> Result<i32, String> {
    let mut config = dam_daemon::proxy_config(&args.proxy)?;

    match dam_daemon::daemon_status().map_err(|error| error.to_string())? {
        dam_daemon::DaemonStatus::Connected(state) => {
            if !daemon_proxy_targets_match(&state, &config.proxy.targets)
                || !daemon_transparent_routes_match(&state, &config)
            {
                ensure_connect_transparent_prerequisites(&args.proxy, &config, None)?;
                println!("DAM profile traffic scope changed; restarting daemon");
                stop_connected_daemon(&state).await?;
            } else if !daemon_executable_matches_current(&state)? {
                if connect_setup_change_requested(&state, &args.proxy) && state.protection_enabled {
                    return Err(format!(
                        "DAM is already connected with network mode {} and trust mode {}; run `dam disconnect --stop` before changing setup",
                        state.network_mode, state.trust.mode
                    ));
                }
                args.proxy = proxy_options_for_existing_daemon(&state, &args.proxy);
                config = dam_daemon::proxy_config(&args.proxy)?;
                ensure_connect_transparent_prerequisites(&args.proxy, &config, None)?;
                println!("DAM daemon executable changed; restarting daemon");
                stop_connected_daemon(&state).await?;
            } else {
                if connect_setup_change_requested(&state, &args.proxy) {
                    if !state.protection_enabled {
                        dam_daemon::set_protection_enabled(true)
                            .map_err(|error| error.to_string())?;
                        for profile_id in &args.apply_profile_ids {
                            let outcome = apply_connect_profile(profile_id, &state.proxy_url)?;
                            print!("{}", render_connect_apply_outcome(&outcome));
                        }
                        println!(
                            "DAM protection enabled at {} using existing network mode {} and trust mode {}",
                            state.proxy_url, state.network_mode, state.trust.mode
                        );
                        return Ok(0);
                    }
                    return Err(format!(
                        "DAM is already connected with network mode {} and trust mode {}; run `dam disconnect --stop` before changing setup",
                        state.network_mode, state.trust.mode
                    ));
                }
                dam_daemon::set_protection_enabled(true).map_err(|error| error.to_string())?;
                for profile_id in &args.apply_profile_ids {
                    let outcome = apply_connect_profile(profile_id, &state.proxy_url)?;
                    print!("{}", render_connect_apply_outcome(&outcome));
                }
                println!("DAM protection enabled at {}", state.proxy_url);
                return Ok(0);
            }
        }
        dam_daemon::DaemonStatus::Stale(state) => {
            dam_daemon::remove_state_if_pid(state.pid).map_err(|error| error.to_string())?;
        }
        dam_daemon::DaemonStatus::Disconnected => {}
    }

    ensure_connect_transparent_prerequisites(&args.proxy, &config, None)?;

    for profile_id in &args.apply_profile_ids {
        let proxy_url = proxy_url_for_connect_apply(&args.proxy)?;
        let outcome = apply_connect_profile(profile_id, &proxy_url)?;
        print!("{}", render_connect_apply_outcome(&outcome));
    }

    let exe = std::env::current_exe()
        .map_err(|error| format!("failed to locate current dam executable: {error}"))?;
    let mut child = StdCommand::new(exe);
    child
        .arg("daemon-run")
        .args(dam_daemon::proxy_options_to_args(&args.proxy))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    child.process_group(0);
    child
        .spawn()
        .map_err(|error| format!("failed to start DAM daemon: {error}"))?;

    let state = wait_for_daemon_ready(Duration::from_secs(8)).await?;
    println!("DAM connected at {}", state.proxy_url);
    if let Some(target) = state.target_name.as_deref() {
        println!("target: {target}");
    }
    if let Some(upstream) = state.upstream.as_deref() {
        println!("upstream: {upstream}");
    }

    Ok(0)
}

fn proxy_options_for_existing_daemon(
    state: &dam_daemon::DaemonState,
    requested: &dam_daemon::ProxyOptions,
) -> dam_daemon::ProxyOptions {
    let mut proxy = requested.clone();
    proxy.config_path = state
        .config_path
        .clone()
        .or_else(|| requested.config_path.clone());
    proxy.listen = state.listen.clone();
    proxy.network_mode = state.network_mode;
    proxy.network_mode_explicit = false;
    proxy.trust_mode = state.trust.mode;
    proxy.trust_mode_explicit = false;
    proxy.targets = proxy_targets_for_existing_daemon(state);
    if proxy.targets.is_none() {
        if let Some(target_name) = &state.target_name {
            proxy.target_name = target_name.clone();
        }
        if let Some(provider) = &state.target_provider {
            proxy.provider = provider.clone();
        }
        if let Some(upstream) = &state.upstream {
            proxy.upstream = upstream.clone();
        }
    }
    proxy.vault_path = state.vault_path.clone();
    proxy.log_path = state.log_path.clone();
    proxy.consent_path = state.consent_path.clone();
    proxy.resolve_inbound = Some(state.resolve_inbound);
    proxy
}

fn proxy_targets_for_existing_daemon(
    state: &dam_daemon::DaemonState,
) -> Option<Vec<dam_config::ProxyTargetConfig>> {
    if !state.proxy_targets.is_empty() {
        return Some(
            state
                .proxy_targets
                .iter()
                .map(|target| dam_config::ProxyTargetConfig {
                    name: target.name.clone(),
                    provider: target.provider.clone(),
                    upstream: target.upstream.clone(),
                    failure_mode: None,
                    api_key_env: None,
                    api_key: None,
                })
                .collect(),
        );
    }

    let (Some(name), Some(provider), Some(upstream)) = (
        state.target_name.as_ref(),
        state.target_provider.as_ref(),
        state.upstream.as_ref(),
    ) else {
        return None;
    };

    Some(vec![dam_config::ProxyTargetConfig {
        name: name.clone(),
        provider: provider.clone(),
        upstream: upstream.clone(),
        failure_mode: None,
        api_key_env: None,
        api_key: None,
    }])
}

fn daemon_executable_matches_current(state: &dam_daemon::DaemonState) -> Result<bool, String> {
    let Some(executable_path) = state.executable_path.as_deref() else {
        return Ok(false);
    };
    let Some(executable_sha256) = state.executable_sha256.as_deref() else {
        return Ok(false);
    };
    let current = std::env::current_exe()
        .map_err(|error| format!("failed to locate current dam executable: {error}"))?;
    let current_sha256 = dam_daemon::executable_sha256(&current)
        .map_err(|error| format!("failed to fingerprint current dam executable: {error}"))?;

    Ok(paths_match(executable_path, &current) && executable_sha256 == current_sha256)
}

fn paths_match(left: &Path, right: &Path) -> bool {
    let left = left.canonicalize().unwrap_or_else(|_| left.to_path_buf());
    let right = right.canonicalize().unwrap_or_else(|_| right.to_path_buf());
    left == right
}

fn daemon_proxy_targets_match(
    state: &dam_daemon::DaemonState,
    requested_targets: &[dam_config::ProxyTargetConfig],
) -> bool {
    let current_targets: BTreeSet<_> = if state.proxy_targets.is_empty() {
        legacy_daemon_proxy_target_set(state)
    } else {
        state
            .proxy_targets
            .iter()
            .map(|target| {
                (
                    target.name.clone(),
                    target.provider.clone(),
                    target.upstream.clone(),
                )
            })
            .collect()
    };
    let requested_targets = requested_targets
        .iter()
        .map(|target| {
            (
                target.name.clone(),
                target.provider.clone(),
                target.upstream.clone(),
            )
        })
        .collect::<BTreeSet<_>>();

    current_targets == requested_targets
}

fn daemon_transparent_routes_match(
    state: &dam_daemon::DaemonState,
    config: &dam_config::DamConfig,
) -> bool {
    let current_routes = state
        .transparent_ai_routes
        .iter()
        .map(route_identity)
        .collect::<BTreeSet<_>>();
    let requested_routes = dam_net::ai_routes_from_profile(&config.traffic.effective_profile())
        .iter()
        .map(route_identity)
        .collect::<BTreeSet<_>>();

    current_routes == requested_routes
}

fn route_identity(route: &dam_net::AiRoute) -> (String, String, String, String, &'static str) {
    (
        route.host.clone(),
        route.provider.clone(),
        route.target_name.clone(),
        route.upstream.clone(),
        ai_traffic_kind_tag(route.kind),
    )
}

fn ai_traffic_kind_tag(kind: dam_net::AiTrafficKind) -> &'static str {
    match kind {
        dam_net::AiTrafficKind::OpenAiApi => "openai_api",
        dam_net::AiTrafficKind::AnthropicApi => "anthropic_api",
        dam_net::AiTrafficKind::XaiApi => "xai_api",
        dam_net::AiTrafficKind::ChatGptCodexBackend => "chatgpt_codex_backend",
        dam_net::AiTrafficKind::Custom => "custom",
    }
}

fn legacy_daemon_proxy_target_set(
    state: &dam_daemon::DaemonState,
) -> BTreeSet<(String, String, String)> {
    match (
        state.target_name.as_ref(),
        state.target_provider.as_ref(),
        state.upstream.as_ref(),
    ) {
        (Some(name), Some(provider), Some(upstream)) => {
            BTreeSet::from([(name.clone(), provider.clone(), upstream.clone())])
        }
        _ => BTreeSet::new(),
    }
}

fn connect_setup_change_requested(
    state: &dam_daemon::DaemonState,
    proxy: &dam_daemon::ProxyOptions,
) -> bool {
    (proxy.network_mode_explicit && state.network_mode != proxy.network_mode)
        || (proxy.trust_mode_explicit && state.trust.mode != proxy.trust_mode)
}

async fn stop_connected_daemon(state: &dam_daemon::DaemonState) -> Result<(), String> {
    dam_daemon::terminate_process(state.pid).map_err(|error| error.to_string())?;
    wait_for_daemon_stop(state.pid, Duration::from_secs(5)).await;
    dam_daemon::remove_state_if_pid(state.pid).map_err(|error| error.to_string())?;
    Ok(())
}

async fn disconnect(args: DisconnectArgs) -> Result<i32, String> {
    match dam_daemon::daemon_status().map_err(|error| error.to_string())? {
        dam_daemon::DaemonStatus::Disconnected => {
            println!("DAM is not connected");
            Ok(0)
        }
        dam_daemon::DaemonStatus::Stale(state) => {
            dam_daemon::remove_state_if_pid(state.pid).map_err(|error| error.to_string())?;
            println!("Removed stale DAM daemon state");
            Ok(0)
        }
        dam_daemon::DaemonStatus::Connected(state) => {
            if !args.stop_daemon {
                dam_daemon::set_protection_enabled(false).map_err(|error| error.to_string())?;
                println!("DAM protection paused; daemon remains active");
                return Ok(0);
            }
            stop_connected_daemon(&state).await?;
            println!("DAM disconnected");
            Ok(0)
        }
    }
}

async fn status(args: StatusArgs) -> Result<i32, String> {
    let (active_profile, active_profile_error) = active_profile_for_status();
    let view = match dam_daemon::daemon_status().map_err(|error| error.to_string())? {
        dam_daemon::DaemonStatus::Disconnected => StatusView {
            state: "disconnected",
            message: "DAM is not connected".to_string(),
            daemon: None,
            proxy: None,
            active_profile,
            active_profile_error,
        },
        dam_daemon::DaemonStatus::Stale(state) => StatusView {
            state: "stale",
            message: format!("daemon state points at stopped pid {}", state.pid),
            daemon: Some(state),
            proxy: None,
            active_profile,
            active_profile_error,
        },
        dam_daemon::DaemonStatus::Connected(state) => {
            let proxy = fetch_proxy_report(&state.proxy_url).await;
            match proxy {
                Ok(report) => StatusView {
                    state: match report.state {
                        dam_api::ProxyState::Protected => "connected",
                        dam_api::ProxyState::Bypassing => "bypassing",
                        _ => "degraded",
                    },
                    message: report.message.clone(),
                    daemon: Some(state),
                    proxy: Some(report),
                    active_profile,
                    active_profile_error,
                },
                Err(error) => StatusView {
                    state: "degraded",
                    message: error,
                    daemon: Some(state),
                    proxy: None,
                    active_profile,
                    active_profile_error,
                },
            }
        }
    };
    let code = if matches!(view.state, "connected" | "bypassing") {
        0
    } else {
        1
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&view)
                .map_err(|error| format!("failed to serialize status: {error}"))?
        );
    } else {
        print!("{}", render_status_view(&view));
    }

    Ok(code)
}

fn logs_command(args: LogsArgs) -> Result<i32, String> {
    let log_path = current_log_path()?
        .ok_or_else(|| "DAM logging is disabled for the current daemon/config".to_string())?;
    let store = dam_log::LogStore::open(&log_path)
        .map_err(|error| format!("failed to open DAM log at {}: {error}", log_path.display()))?;
    let entries = filtered_log_entries(store.list().map_err(|error| error.to_string())?, &args);

    if args.json {
        if args.events || args.operation_id.is_some() {
            let events = entries.into_iter().map(log_event_view).collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::to_string_pretty(&events)
                    .map_err(|error| format!("failed to serialize logs: {error}"))?
            );
        } else {
            let summaries = log_operation_summaries(entries, args.limit);
            println!(
                "{}",
                serde_json::to_string_pretty(&summaries)
                    .map_err(|error| format!("failed to serialize log summaries: {error}"))?
            );
        }
        return Ok(0);
    }

    if args.events || args.operation_id.is_some() {
        print!("{}", render_log_events(&entries, args.limit));
    } else {
        let summaries = log_operation_summaries(entries, args.limit);
        print!("{}", render_log_summaries(&summaries));
    }

    Ok(0)
}

fn current_log_path() -> Result<Option<PathBuf>, String> {
    match dam_daemon::daemon_status().map_err(|error| error.to_string())? {
        dam_daemon::DaemonStatus::Connected(state) | dam_daemon::DaemonStatus::Stale(state) => {
            Ok(state.log_path)
        }
        dam_daemon::DaemonStatus::Disconnected => {
            let paths = dam_daemon::state_paths().map_err(|error| error.to_string())?;
            Ok(Some(paths.state_dir.join(DEFAULT_LOG_PATH)))
        }
    }
}

fn filtered_log_entries(
    entries: Vec<dam_log::LogEntry>,
    args: &LogsArgs,
) -> Vec<dam_log::LogEntry> {
    entries
        .into_iter()
        .filter(|entry| args.after_id.is_none_or(|after_id| entry.id > after_id))
        .filter(|entry| {
            args.operation_id
                .as_deref()
                .is_none_or(|operation_id| entry.operation_id == operation_id)
        })
        .collect()
}

fn log_event_view(entry: dam_log::LogEntry) -> LogEventView {
    LogEventView {
        id: entry.id,
        timestamp: entry.timestamp,
        operation_id: entry.operation_id,
        level: entry.level,
        event_type: entry.event_type,
        kind: entry.kind,
        reference: entry.reference,
        action: entry.action,
        message: entry.message,
    }
}

fn log_operation_summaries(
    entries: Vec<dam_log::LogEntry>,
    limit: usize,
) -> Vec<LogOperationSummary> {
    let mut summaries = Vec::<LogOperationSummary>::new();
    for entry in entries {
        if let Some(summary) = summaries
            .iter_mut()
            .find(|summary| summary.operation_id == entry.operation_id)
        {
            summary.first_id = summary.first_id.min(entry.id);
            summary.last_id = summary.last_id.max(entry.id);
            summary.timestamp = summary.timestamp.max(entry.timestamp);
            summary.events += 1;
            push_unique(&mut summary.event_types, &entry.event_type);
            if let Some(action) = entry.action.as_deref() {
                push_unique(&mut summary.actions, action);
            }
            summary.summary = summarize_operation_message(&summary.summary, &entry);
        } else {
            let mut event_types = Vec::new();
            push_unique(&mut event_types, &entry.event_type);
            let mut actions = Vec::new();
            if let Some(action) = entry.action.as_deref() {
                push_unique(&mut actions, action);
            }
            summaries.push(LogOperationSummary {
                operation_id: entry.operation_id.clone(),
                first_id: entry.id,
                last_id: entry.id,
                timestamp: entry.timestamp,
                events: 1,
                event_types,
                actions,
                summary: summarize_operation_message("", &entry),
            });
        }

        if summaries.len() >= limit
            && summaries
                .last()
                .is_some_and(|summary| summary.operation_id != entry.operation_id)
        {
            summaries.truncate(limit);
            break;
        }
    }
    summaries.truncate(limit);
    summaries
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn summarize_operation_message(existing: &str, entry: &dam_log::LogEntry) -> String {
    let Some(piece) = log_summary_piece(entry) else {
        return existing.to_string();
    };
    append_summary_piece(existing, &piece)
}

fn append_summary_piece(existing: &str, piece: &str) -> String {
    if existing.is_empty() {
        return piece.to_string();
    }
    if existing.split(" | ").any(|part| part == piece) {
        return existing.to_string();
    }
    format!("{existing} | {piece}")
}

fn log_summary_piece(entry: &dam_log::LogEntry) -> Option<String> {
    match entry.action.as_deref() {
        Some("route_decision") => Some(shorten_log_message(&entry.message, 90)),
        Some("request_protection") => Some(shorten_log_message(&entry.message, 90)),
        Some("provider_response") => Some(shorten_log_message(&entry.message, 100)),
        Some("resolve_attempt" | "resolve_non_utf8" | "resolve_disabled") => Some(format!(
            "{} {}",
            entry.action.as_deref().unwrap(),
            entry.message
        )),
        Some("intercepted_response_write") => Some(shorten_log_message(&entry.message, 90)),
        Some("bypassing") => Some("bypassing".to_string()),
        Some("blocked") => Some(format!("blocked {}", entry.message)),
        Some("provider_down") => Some("provider_down".to_string()),
        Some("protected") => Some("protected".to_string()),
        _ => None,
    }
    .map(|value| shorten_log_message(&value, 140))
}

fn render_log_summaries(summaries: &[LogOperationSummary]) -> String {
    if summaries.is_empty() {
        return "No DAM log operations matched.\n".to_string();
    }

    let mut output = String::from("LastID  Time      Operation               Events  Summary\n");
    for summary in summaries {
        output.push_str(&format!(
            "{:<6} {:<9} {:<23} {:<7} {}\n",
            summary.last_id,
            compact_time(summary.timestamp),
            summary.operation_id,
            summary.events,
            summary.summary
        ));
    }
    output
}

fn render_log_events(entries: &[dam_log::LogEntry], limit: usize) -> String {
    let mut selected = entries.iter().take(limit).cloned().collect::<Vec<_>>();
    selected.sort_by_key(|entry| entry.id);
    if selected.is_empty() {
        return "No DAM log events matched.\n".to_string();
    }

    let mut output = String::from(
        "ID      Time      Operation               Type            Action                  Message\n",
    );
    for entry in selected {
        output.push_str(&format!(
            "{:<7} {:<9} {:<23} {:<15} {:<23} {}\n",
            entry.id,
            compact_time(entry.timestamp),
            entry.operation_id,
            entry.event_type,
            entry.action.unwrap_or_default(),
            shorten_log_message(&entry.message, 120)
        ));
    }
    output
}

fn compact_time(timestamp: i64) -> String {
    let seconds = timestamp.rem_euclid(86_400);
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn shorten_log_message(message: &str, max: usize) -> String {
    if message.chars().count() <= max {
        return message.to_string();
    }
    let mut output = message
        .chars()
        .take(max.saturating_sub(3))
        .collect::<String>();
    output.push_str("...");
    output
}

fn profile_command(args: ProfileArgs) -> Result<i32, String> {
    let state_dir = integration_state_dir()?;
    match args {
        ProfileArgs::Status { json } => {
            let view = profile_status_view(&state_dir)?;
            print_profile_status_view(&view, json)?;
        }
        ProfileArgs::Set { profile_id, json } => {
            dam_integrations::set_active_profile(&profile_id, &state_dir)?;
            let view = profile_status_view(&state_dir)?;
            print_profile_status_view(&view, json)?;
        }
        ProfileArgs::Clear { json } => {
            dam_integrations::clear_active_profile(&state_dir)?;
            let view = profile_status_view(&state_dir)?;
            print_profile_status_view(&view, json)?;
        }
    }
    Ok(0)
}

fn trust_command(args: TrustArgs) -> Result<i32, String> {
    let state_dir = dam_daemon::state_paths()
        .map(|paths| paths.state_dir)
        .map_err(|error| error.to_string())?;
    match args {
        TrustArgs::GenerateArtifact { json } => {
            let output = generate_local_ca_output(&state_dir, json)?;
            print!("{output}");
        }
        TrustArgs::DeleteArtifact { json } => {
            let output = delete_local_ca_output(&state_dir, json)?;
            print!("{output}");
        }
        TrustArgs::InstallTrust { json, yes } => {
            let output = install_local_ca_output(&state_dir, json, yes)?;
            print!("{output}");
        }
        TrustArgs::RemoveTrust { json, yes } => {
            let output = remove_local_ca_output(&state_dir, json, yes)?;
            print!("{output}");
        }
    }
    Ok(0)
}

fn network_command(args: NetworkArgs) -> Result<i32, String> {
    let state_dir = dam_daemon::state_paths()
        .map(|paths| paths.state_dir)
        .map_err(|error| error.to_string())?;
    let proxy_url = format!("http://{DEFAULT_LISTEN}");
    match args {
        NetworkArgs::InstallProxy {
            config_path,
            json,
            yes,
        } => {
            let config = dam_config::load(&dam_config::ConfigOverrides {
                config_path,
                ..dam_config::ConfigOverrides::default()
            })
            .map_err(|error| error.to_string())?;
            let hosts = configured_ai_hosts_for_state(&config, &state_dir)?;
            let result = if yes {
                dam_net_macos::install_system_proxy_for_hosts(&state_dir, &proxy_url, &hosts)
            } else {
                dam_net_macos::preview_install_system_proxy_for_hosts(
                    &state_dir, &proxy_url, &hosts,
                )
            }
            .map_err(|error| error.to_string())?;
            print_network_result(&result, json, yes)?;
        }
        NetworkArgs::RemoveProxy { json, yes } => {
            let result = if yes {
                dam_net_macos::remove_system_proxy(&state_dir, &proxy_url)
            } else {
                dam_net_macos::preview_remove_system_proxy(&state_dir, &proxy_url)
            }
            .map_err(|error| error.to_string())?;
            print_network_result(&result, json, yes)?;
        }
        NetworkArgs::InstallNetworkExtension {
            config_path,
            json,
            yes,
        } => {
            let config = dam_config::load(&dam_config::ConfigOverrides {
                config_path,
                ..dam_config::ConfigOverrides::default()
            })
            .map_err(|error| error.to_string())?;
            let hosts = configured_ai_hosts_for_state(&config, &state_dir)?;
            let result = if yes {
                dam_net_macos::install_network_extension_for_hosts(&state_dir, &hosts)
            } else {
                dam_net_macos::preview_install_network_extension_for_hosts(&state_dir, &hosts)
            }
            .map_err(|error| error.to_string())?;
            print_network_extension_result(&result, json, yes)?;
            if yes && result.state == dam_net_macos::MacosNetworkExtensionResultState::NeedsApproval
            {
                return Ok(75);
            }
        }
        NetworkArgs::RemoveNetworkExtension { json, yes } => {
            let result = if yes {
                dam_net_macos::remove_network_extension(&state_dir)
            } else {
                dam_net_macos::preview_remove_network_extension(&state_dir)
            }
            .map_err(|error| error.to_string())?;
            print_network_extension_result(&result, json, yes)?;
        }
        NetworkArgs::Status { json } => {
            let result =
                dam_net_macos::network_extension_status(&state_dir).map_err(|e| e.to_string())?;
            print_network_extension_result(&result, json, false)?;
        }
    }
    Ok(0)
}

fn startup_command(args: StartupArgs) -> Result<i32, String> {
    let state_dir = dam_daemon::state_paths()
        .map(|paths| paths.state_dir)
        .map_err(|error| error.to_string())?;
    match args {
        StartupArgs::Status { json } => {
            let view = startup_status_view(&state_dir);
            print_startup_status_view(&view, json)?;
        }
        StartupArgs::SkipOpenAtLogin { json } => {
            write_startup_skip_marker(&state_dir)?;
            let view = startup_status_view(&state_dir);
            print_startup_status_view(&view, json)?;
        }
    }
    Ok(0)
}

fn startup_status_view(state_dir: &Path) -> StartupStatusView {
    let registered_marker = state_dir.join(LOGIN_ITEM_MARKER_RELPATH);
    let skip_marker = state_dir.join(LOGIN_ITEM_SKIP_MARKER_RELPATH);
    let legacy_marker = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|home| home.join(LAUNCH_AGENT_PLIST_RELPATH));

    if registered_marker.exists() {
        return StartupStatusView {
            state: "registered",
            message: "DAM is marked to open at login".to_string(),
            platform: std::env::consts::OS,
            state_dir: state_dir.to_path_buf(),
            marker: Some(registered_marker),
        };
    }

    if let Some(legacy_marker) = legacy_marker.filter(|path| path.exists()) {
        return StartupStatusView {
            state: "registered",
            message: "DAM has a legacy launch agent registration".to_string(),
            platform: std::env::consts::OS,
            state_dir: state_dir.to_path_buf(),
            marker: Some(legacy_marker),
        };
    }

    if skip_marker.exists() {
        return StartupStatusView {
            state: "skipped",
            message: "Open at Login was skipped for this install".to_string(),
            platform: std::env::consts::OS,
            state_dir: state_dir.to_path_buf(),
            marker: Some(skip_marker),
        };
    }

    StartupStatusView {
        state: "unconfigured",
        message: if cfg!(target_os = "macos") {
            "Choose whether DAM should open at login".to_string()
        } else {
            "This platform does not currently require a DAM startup setup step".to_string()
        },
        platform: std::env::consts::OS,
        state_dir: state_dir.to_path_buf(),
        marker: None,
    }
}

fn write_startup_skip_marker(state_dir: &Path) -> Result<PathBuf, String> {
    let marker_path = state_dir.join(LOGIN_ITEM_SKIP_MARKER_RELPATH);
    if let Some(parent) = marker_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create startup marker dir: {error}"))?;
    }
    std::fs::write(&marker_path, "skipped\n")
        .map_err(|error| format!("write {}: {error}", marker_path.display()))?;
    Ok(marker_path)
}

fn print_startup_status_view(view: &StartupStatusView, json: bool) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(view)
                .map_err(|error| format!("failed to serialize startup status: {error}"))?
        );
    } else {
        print!("{}", render_startup_status_view(view));
    }
    Ok(())
}

fn render_startup_status_view(view: &StartupStatusView) -> String {
    let marker = view
        .marker
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "none".to_string());
    format!(
        "state: {}\nmessage: {}\nplatform: {}\nstate_dir: {}\nmarker: {}\n",
        view.state,
        view.message,
        view.platform,
        view.state_dir.display(),
        marker
    )
}

fn configured_ai_hosts(config: &dam_config::DamConfig) -> Vec<String> {
    dam_net::ai_routes_from_profile(&config.traffic.effective_profile())
        .into_iter()
        .map(|route| route.host)
        .collect()
}

fn configured_ai_hosts_for_state(
    config: &dam_config::DamConfig,
    state_dir: &Path,
) -> Result<Vec<String>, String> {
    let mut config = config.clone();
    let integration_state_dir = state_dir.join("integrations");
    if let Some(profile_ids) =
        dam_integrations::runtime_enabled_profile_ids(&integration_state_dir)?
    {
        config.traffic.enabled_app_ids = Some(traffic_app_ids_for_profiles(&profile_ids)?);
    }
    Ok(configured_ai_hosts(&config))
}

async fn integrations(args: IntegrationArgs) -> Result<i32, String> {
    match args {
        IntegrationArgs::List { json, proxy_url } => {
            let proxy_url = integration_proxy_url(proxy_url);
            let profiles = dam_integrations::profiles(&proxy_url);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&profiles)
                        .map_err(|error| format!("failed to serialize integrations: {error}"))?
                );
            } else {
                print!("{}", render_integration_list(&profiles, &proxy_url));
            }
            Ok(0)
        }
        IntegrationArgs::Show {
            profile_id,
            json,
            proxy_url,
        } => {
            let proxy_url = integration_proxy_url(proxy_url);
            let profile = dam_integrations::profile(&profile_id, &proxy_url).ok_or_else(|| {
                format!(
                    "unknown integration profile: {profile_id}\nknown profiles: {}",
                    dam_integrations::profile_ids().join(", ")
                )
            })?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&profile)
                        .map_err(|error| format!("failed to serialize integration: {error}"))?
                );
            } else {
                print!("{}", render_integration_profile(&profile, &proxy_url));
            }
            Ok(0)
        }
        IntegrationArgs::Apply {
            profile_id,
            dry_run,
            json,
            proxy_url,
            target_path,
        } => {
            let proxy_url = integration_proxy_url(proxy_url);
            let state_dir = integration_state_dir()?;
            let target_path = match target_path {
                Some(path) => path,
                None => default_integration_target_path(&profile_id, &state_dir)?,
            };
            let prepared = dam_integrations::prepare_apply(&profile_id, &proxy_url, target_path)?;
            let result = dam_integrations::run_apply(prepared, dry_run, &state_dir)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result)
                        .map_err(|error| format!("failed to serialize apply result: {error}"))?
                );
            } else {
                print!("{}", render_integration_apply_result(&result));
            }
            Ok(0)
        }
        IntegrationArgs::Rollback { profile_id, json } => {
            let state_dir = integration_state_dir()?;
            let result = dam_integrations::rollback_profile(&profile_id, &state_dir)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).map_err(|error| {
                        format!("failed to serialize rollback result: {error}")
                    })?
                );
            } else {
                print!("{}", render_integration_rollback_result(&result));
            }
            Ok(0)
        }
    }
}

async fn daemon_run(args: dam_daemon::ProxyOptions) -> Result<i32, String> {
    let config = dam_daemon::proxy_config(&args)?;
    dam_daemon::serve_with_modes(config, args.config_path, args.network_mode, args.trust_mode)
        .await
        .map_err(|error| error.to_string())?;
    Ok(0)
}

fn web_command(args: WebArgs) -> Result<i32, String> {
    let binary = dam_web_binary();
    let status = StdCommand::new(&binary)
        .args(args.args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| format!("failed to start dam-web from {}: {error}", binary.display()))?;

    Ok(status.code().unwrap_or(1))
}

fn dam_web_binary() -> PathBuf {
    if let Some(path) = std::env::var_os(DAM_WEB_BIN_ENV)
        && !path.is_empty()
    {
        return PathBuf::from(path);
    }
    if let Ok(current) = std::env::current_exe()
        && let Some(parent) = current.parent()
    {
        let sibling = parent.join(native_binary_name("dam-web"));
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from(native_binary_name("dam-web"))
}

fn native_binary_name(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

#[cfg(test)]
fn parse_cli(args: impl IntoIterator<Item = String>) -> Result<Cli, String> {
    parse_cli_with_connect_profiles(args, ConnectProfileSelection::default())
}

#[cfg(test)]
fn parse_cli_with_active_profiles(
    args: impl IntoIterator<Item = String>,
    active_profile_ids: Vec<String>,
) -> Result<Cli, String> {
    parse_cli_with_connect_profiles(
        args,
        ConnectProfileSelection {
            explicit_selection: !active_profile_ids.is_empty(),
            profile_ids: active_profile_ids,
        },
    )
}

fn parse_cli_with_connect_profiles(
    args: impl IntoIterator<Item = String>,
    connect_profiles: ConnectProfileSelection,
) -> Result<Cli, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    let Some(command) = args.first() else {
        return Ok(Cli {
            command: CommandKind::Help,
        });
    };

    match command.as_str() {
        "-h" | "--help" | "help" => Ok(Cli {
            command: CommandKind::Help,
        }),
        "connect" => parse_connect_command(&args[1..], connect_profiles),
        "disconnect" => parse_disconnect_command(&args[1..]),
        "status" => parse_status_command(&args[1..]),
        "logs" => parse_logs_command(&args[1..]),
        "profile" => parse_profile_command(&args[1..]),
        "trust" => parse_trust_command(&args[1..]),
        "network" => parse_network_command(&args[1..]),
        "startup" => parse_startup_command(&args[1..]),
        "integrations" => parse_integrations_command(&args[1..]),
        "web" => Ok(Cli {
            command: CommandKind::Web(WebArgs {
                args: args[1..].to_vec(),
            }),
        }),
        "daemon-run" => parse_daemon_run_command(&args[1..]),
        other => Err(format!("unknown command: {other}\n{}", usage())),
    }
}

fn parse_connect_command(
    args: &[String],
    connect_profiles: ConnectProfileSelection,
) -> Result<Cli, String> {
    if matches!(args.first().map(String::as_str), Some("-h" | "--help")) {
        println!("{}", usage_connect());
        std::process::exit(0);
    }

    let expanded = expand_connect_profile_args(args, &connect_profiles)?;
    let mut proxy = dam_daemon::parse_proxy_options(expanded.args)?;
    if expanded.selected_profile_ids.len() > 1 && proxy.targets.is_none() {
        proxy.targets = Some(proxy_targets_for_profiles(&expanded.selected_profile_ids)?);
    }
    if expanded.traffic_app_ids.is_some() {
        proxy.traffic_app_ids = expanded.traffic_app_ids;
    }
    for profile_id in &expanded.selected_profile_ids {
        validate_connect_apply_profile_matches_proxy(profile_id, &proxy)?;
    }
    Ok(Cli {
        command: CommandKind::Connect(ConnectArgs {
            proxy,
            apply_profile_ids: expanded.apply_profile_ids,
        }),
    })
}

fn parse_daemon_run_command(args: &[String]) -> Result<Cli, String> {
    Ok(Cli {
        command: CommandKind::DaemonRun(dam_daemon::parse_proxy_options(args.iter().cloned())?),
    })
}

fn parse_disconnect_command(args: &[String]) -> Result<Cli, String> {
    if matches!(args.first().map(String::as_str), Some("-h" | "--help")) {
        println!("{}", usage_disconnect());
        std::process::exit(0);
    }
    let mut parsed = DisconnectArgs::default();
    for arg in args {
        match arg.as_str() {
            "--stop" => parsed.stop_daemon = true,
            _ => return Err(format!("unknown disconnect argument: {arg}")),
        }
    }

    Ok(Cli {
        command: CommandKind::Disconnect(parsed),
    })
}

fn parse_status_command(args: &[String]) -> Result<Cli, String> {
    let mut parsed = StatusArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => parsed.json = true,
            "-h" | "--help" => {
                println!("{}", usage_status());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown status argument: {arg}")),
        }
        i += 1;
    }

    Ok(Cli {
        command: CommandKind::Status(parsed),
    })
}

fn parse_startup_command(args: &[String]) -> Result<Cli, String> {
    if args.is_empty() || matches!(args.first().map(String::as_str), Some("-h" | "--help")) {
        println!("{}", usage_startup());
        std::process::exit(0);
    }

    match args[0].as_str() {
        "status" => parse_startup_status(&args[1..]),
        "skip-open-at-login" => parse_startup_skip_open_at_login(&args[1..]),
        command => Err(format!("unknown startup command: {command}")),
    }
}

fn parse_startup_status(args: &[String]) -> Result<Cli, String> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                println!("{}", usage_startup_status());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown startup status argument: {arg}")),
        }
    }
    Ok(Cli {
        command: CommandKind::Startup(StartupArgs::Status { json }),
    })
}

fn parse_startup_skip_open_at_login(args: &[String]) -> Result<Cli, String> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                println!("{}", usage_startup_skip_open_at_login());
                std::process::exit(0);
            }
            arg => {
                return Err(format!(
                    "unknown startup skip-open-at-login argument: {arg}"
                ));
            }
        }
    }
    Ok(Cli {
        command: CommandKind::Startup(StartupArgs::SkipOpenAtLogin { json }),
    })
}

fn parse_logs_command(args: &[String]) -> Result<Cli, String> {
    let mut parsed = LogsArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => parsed.json = true,
            "--events" => parsed.events = true,
            "--limit" => {
                i += 1;
                parsed.limit = args
                    .get(i)
                    .ok_or_else(|| "--limit requires a number".to_string())?
                    .parse::<usize>()
                    .map_err(|_| "--limit requires a positive number".to_string())?;
                if parsed.limit == 0 {
                    return Err("--limit must be greater than zero".to_string());
                }
            }
            "--after-id" => {
                i += 1;
                parsed.after_id = Some(
                    args.get(i)
                        .ok_or_else(|| "--after-id requires an id".to_string())?
                        .parse::<i64>()
                        .map_err(|_| "--after-id requires an integer id".to_string())?,
                );
            }
            "--operation" => {
                i += 1;
                parsed.operation_id = Some(
                    args.get(i)
                        .ok_or_else(|| "--operation requires an operation id".to_string())?
                        .to_string(),
                );
            }
            "-h" | "--help" => {
                println!("{}", usage_logs());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown logs argument: {arg}")),
        }
        i += 1;
    }

    Ok(Cli {
        command: CommandKind::Logs(parsed),
    })
}

fn parse_profile_command(args: &[String]) -> Result<Cli, String> {
    if args.is_empty() || matches!(args.first().map(String::as_str), Some("-h" | "--help")) {
        println!("{}", usage_profile());
        std::process::exit(0);
    }

    match args[0].as_str() {
        "status" => parse_profile_status(&args[1..]),
        "set" => parse_profile_set(&args[1..]),
        "clear" => parse_profile_clear(&args[1..]),
        command => Err(format!("unknown profile command: {command}")),
    }
}

fn parse_profile_status(args: &[String]) -> Result<Cli, String> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                println!("{}", usage_profile_status());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown profile status argument: {arg}")),
        }
    }

    Ok(Cli {
        command: CommandKind::Profile(ProfileArgs::Status { json }),
    })
}

fn parse_profile_set(args: &[String]) -> Result<Cli, String> {
    let mut profile_id = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                println!("{}", usage_profile_set());
                std::process::exit(0);
            }
            arg if profile_id.is_none() => profile_id = Some(arg.to_string()),
            arg => return Err(format!("unexpected profile set argument: {arg}")),
        }
        i += 1;
    }

    let profile_id = profile_id.ok_or_else(|| "profile set requires a profile id".to_string())?;
    Ok(Cli {
        command: CommandKind::Profile(ProfileArgs::Set { profile_id, json }),
    })
}

fn parse_profile_clear(args: &[String]) -> Result<Cli, String> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                println!("{}", usage_profile_clear());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown profile clear argument: {arg}")),
        }
    }

    Ok(Cli {
        command: CommandKind::Profile(ProfileArgs::Clear { json }),
    })
}

fn parse_trust_command(args: &[String]) -> Result<Cli, String> {
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help") {
        println!("{}", usage_trust());
        std::process::exit(0);
    }
    match args[0].as_str() {
        "generate-local-ca" => parse_trust_generate_local_ca(&args[1..]),
        "delete-local-ca" => parse_trust_delete_local_ca(&args[1..]),
        "install-local-ca" => parse_trust_install_local_ca(&args[1..]),
        "remove-local-ca" => parse_trust_remove_local_ca(&args[1..]),
        command => Err(format!("unknown trust command: {command}")),
    }
}

fn parse_trust_generate_local_ca(args: &[String]) -> Result<Cli, String> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                println!("{}", usage_trust_generate_local_ca());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown trust generate-local-ca argument: {arg}")),
        }
    }
    Ok(Cli {
        command: CommandKind::Trust(TrustArgs::GenerateArtifact { json }),
    })
}

fn parse_trust_delete_local_ca(args: &[String]) -> Result<Cli, String> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                println!("{}", usage_trust_delete_local_ca());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown trust delete-local-ca argument: {arg}")),
        }
    }
    Ok(Cli {
        command: CommandKind::Trust(TrustArgs::DeleteArtifact { json }),
    })
}

fn parse_trust_install_local_ca(args: &[String]) -> Result<Cli, String> {
    let mut json = false;
    let mut yes = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--yes" => yes = true,
            "--dry-run" => yes = false,
            "-h" | "--help" => {
                println!("{}", usage_trust_install_local_ca());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown trust install-local-ca argument: {arg}")),
        }
    }
    Ok(Cli {
        command: CommandKind::Trust(TrustArgs::InstallTrust { json, yes }),
    })
}

fn parse_trust_remove_local_ca(args: &[String]) -> Result<Cli, String> {
    let mut json = false;
    let mut yes = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--yes" => yes = true,
            "--dry-run" => yes = false,
            "-h" | "--help" => {
                println!("{}", usage_trust_remove_local_ca());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown trust remove-local-ca argument: {arg}")),
        }
    }
    Ok(Cli {
        command: CommandKind::Trust(TrustArgs::RemoveTrust { json, yes }),
    })
}

fn parse_network_command(args: &[String]) -> Result<Cli, String> {
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help") {
        println!("{}", usage_network());
        std::process::exit(0);
    }
    match args[0].as_str() {
        "install-system-proxy" => parse_network_install_system_proxy(&args[1..]),
        "remove-system-proxy" => parse_network_remove_system_proxy(&args[1..]),
        "install-network-extension" => parse_network_install_network_extension(&args[1..]),
        "remove-network-extension" => parse_network_remove_network_extension(&args[1..]),
        "status" => parse_network_status(&args[1..]),
        command => Err(format!("unknown network command: {command}")),
    }
}

fn parse_network_install_system_proxy(args: &[String]) -> Result<Cli, String> {
    let mut config_path = None;
    let mut json = false;
    let mut yes = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                config_path = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| "--config requires a path".to_string())?,
                ));
            }
            "--json" => json = true,
            "--yes" => yes = true,
            "--dry-run" => yes = false,
            "-h" | "--help" => {
                println!("{}", usage_network_install_system_proxy());
                std::process::exit(0);
            }
            arg => {
                return Err(format!(
                    "unknown network install-system-proxy argument: {arg}"
                ));
            }
        }
        i += 1;
    }
    Ok(Cli {
        command: CommandKind::Network(NetworkArgs::InstallProxy {
            config_path,
            json,
            yes,
        }),
    })
}

fn parse_network_remove_system_proxy(args: &[String]) -> Result<Cli, String> {
    let mut json = false;
    let mut yes = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--yes" => yes = true,
            "--dry-run" => yes = false,
            "-h" | "--help" => {
                println!("{}", usage_network_remove_system_proxy());
                std::process::exit(0);
            }
            arg => {
                return Err(format!(
                    "unknown network remove-system-proxy argument: {arg}"
                ));
            }
        }
    }
    Ok(Cli {
        command: CommandKind::Network(NetworkArgs::RemoveProxy { json, yes }),
    })
}

fn parse_network_install_network_extension(args: &[String]) -> Result<Cli, String> {
    let mut config_path = None;
    let mut json = false;
    let mut yes = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                config_path = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| "--config requires a path".to_string())?,
                ));
            }
            "--json" => json = true,
            "--yes" => yes = true,
            "--dry-run" => yes = false,
            "-h" | "--help" => {
                println!("{}", usage_network_install_network_extension());
                std::process::exit(0);
            }
            arg => {
                return Err(format!(
                    "unknown network install-network-extension argument: {arg}"
                ));
            }
        }
        i += 1;
    }
    Ok(Cli {
        command: CommandKind::Network(NetworkArgs::InstallNetworkExtension {
            config_path,
            json,
            yes,
        }),
    })
}

fn parse_network_remove_network_extension(args: &[String]) -> Result<Cli, String> {
    let mut json = false;
    let mut yes = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--yes" => yes = true,
            "--dry-run" => yes = false,
            "-h" | "--help" => {
                println!("{}", usage_network_remove_network_extension());
                std::process::exit(0);
            }
            arg => {
                return Err(format!(
                    "unknown network remove-network-extension argument: {arg}"
                ));
            }
        }
    }
    Ok(Cli {
        command: CommandKind::Network(NetworkArgs::RemoveNetworkExtension { json, yes }),
    })
}

fn parse_network_status(args: &[String]) -> Result<Cli, String> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                println!("{}", usage_network_status());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown network status argument: {arg}")),
        }
    }
    Ok(Cli {
        command: CommandKind::Network(NetworkArgs::Status { json }),
    })
}

fn parse_integrations_command(args: &[String]) -> Result<Cli, String> {
    if args.is_empty() || matches!(args.first().map(String::as_str), Some("-h" | "--help")) {
        println!("{}", usage_integrations());
        std::process::exit(0);
    }

    match args[0].as_str() {
        "list" => parse_integrations_list(&args[1..]),
        "show" => parse_integrations_show(&args[1..]),
        "apply" => parse_integrations_apply(&args[1..]),
        "rollback" => parse_integrations_rollback(&args[1..]),
        command => Err(format!("unknown integrations command: {command}")),
    }
}

fn parse_integrations_list(args: &[String]) -> Result<Cli, String> {
    let mut json = false;
    let mut proxy_url = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--proxy-url" => {
                i += 1;
                proxy_url = Some(required_value(args, i, "--proxy-url")?.to_string());
            }
            "-h" | "--help" => {
                println!("{}", usage_integrations_list());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown integrations list argument: {arg}")),
        }
        i += 1;
    }

    Ok(Cli {
        command: CommandKind::Integrations(IntegrationArgs::List { json, proxy_url }),
    })
}

fn parse_integrations_show(args: &[String]) -> Result<Cli, String> {
    let mut profile_id = None;
    let mut json = false;
    let mut proxy_url = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--proxy-url" => {
                i += 1;
                proxy_url = Some(required_value(args, i, "--proxy-url")?.to_string());
            }
            "-h" | "--help" => {
                println!("{}", usage_integrations_show());
                std::process::exit(0);
            }
            arg if profile_id.is_none() => profile_id = Some(arg.to_string()),
            arg => return Err(format!("unexpected integrations show argument: {arg}")),
        }
        i += 1;
    }

    let profile_id =
        profile_id.ok_or_else(|| "integrations show requires a profile id".to_string())?;
    Ok(Cli {
        command: CommandKind::Integrations(IntegrationArgs::Show {
            profile_id,
            json,
            proxy_url,
        }),
    })
}

fn parse_integrations_apply(args: &[String]) -> Result<Cli, String> {
    let mut profile_id = None;
    let mut dry_run = true;
    let mut dry_run_explicit = false;
    let mut write = false;
    let mut json = false;
    let mut proxy_url = None;
    let mut target_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run" => {
                dry_run = true;
                dry_run_explicit = true;
            }
            "--write" => {
                write = true;
                dry_run = false;
            }
            "--json" => json = true,
            "--proxy-url" => {
                i += 1;
                proxy_url = Some(required_value(args, i, "--proxy-url")?.to_string());
            }
            "--target-path" => {
                i += 1;
                target_path = Some(PathBuf::from(required_value(args, i, "--target-path")?));
            }
            "-h" | "--help" => {
                println!("{}", usage_integrations_apply());
                std::process::exit(0);
            }
            arg if profile_id.is_none() => profile_id = Some(arg.to_string()),
            arg => return Err(format!("unexpected integrations apply argument: {arg}")),
        }
        i += 1;
    }

    if dry_run_explicit && write {
        return Err("integrations apply cannot combine --dry-run and --write".to_string());
    }
    let profile_id =
        profile_id.ok_or_else(|| "integrations apply requires a profile id".to_string())?;
    Ok(Cli {
        command: CommandKind::Integrations(IntegrationArgs::Apply {
            profile_id,
            dry_run,
            json,
            proxy_url,
            target_path,
        }),
    })
}

fn parse_integrations_rollback(args: &[String]) -> Result<Cli, String> {
    let mut profile_id = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                println!("{}", usage_integrations_rollback());
                std::process::exit(0);
            }
            arg if profile_id.is_none() => profile_id = Some(arg.to_string()),
            arg => return Err(format!("unexpected integrations rollback argument: {arg}")),
        }
        i += 1;
    }

    let profile_id =
        profile_id.ok_or_else(|| "integrations rollback requires a profile id".to_string())?;
    Ok(Cli {
        command: CommandKind::Integrations(IntegrationArgs::Rollback { profile_id, json }),
    })
}

fn expand_connect_profile_args(
    args: &[String],
    connect_profiles: &ConnectProfileSelection,
) -> Result<ConnectProfileExpansion, String> {
    let mut expanded = Vec::new();
    let mut remaining = Vec::new();
    let mut selected_profile_ids = Vec::new();
    let mut traffic_selection_explicit = connect_profiles.explicit_selection;
    let mut apply = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => {
                i += 1;
                let id = required_value(args, i, "--profile")?;
                if !selected_profile_ids.is_empty() {
                    return Err("--profile can only be supplied once".to_string());
                }
                let profile = dam_integrations::profile(id, dam_integrations::DEFAULT_PROXY_URL)
                    .ok_or_else(|| {
                        format!(
                            "unknown integration profile: {id}\nknown profiles: {}",
                            dam_integrations::profile_ids().join(", ")
                        )
                    })?;
                expanded.extend(profile.connect_args);
                selected_profile_ids.push(id.to_string());
                traffic_selection_explicit = true;
            }
            "--apply" => apply = true,
            arg => remaining.push(arg.to_string()),
        }
        i += 1;
    }

    if selected_profile_ids.is_empty() && !connect_profiles.profile_ids.is_empty() {
        selected_profile_ids = connect_profiles.profile_ids.clone();
        if selected_profile_ids.len() == 1 {
            let id = &selected_profile_ids[0];
            let profile = dam_integrations::profile(id, dam_integrations::DEFAULT_PROXY_URL)
                .ok_or_else(|| {
                    format!(
                        "unknown enabled integration profile: {id}\nknown profiles: {}",
                        dam_integrations::profile_ids().join(", ")
                    )
                })?;
            expanded.extend(profile.connect_args);
        }
    }

    if apply && selected_profile_ids.is_empty() {
        return Err(
            "--apply requires --profile <id> or enabled profiles in `dam profile status`"
                .to_string(),
        );
    }
    if selected_profile_ids.len() > 1 {
        expanded.extend([
            "--network-mode".to_string(),
            "tun".to_string(),
            "--trust-mode".to_string(),
            "local_ca".to_string(),
        ]);
    } else if profiles_require_local_ca(&selected_profile_ids)? {
        expanded.extend(["--trust-mode".to_string(), "local_ca".to_string()]);
    }

    expanded.extend(remaining);
    let apply_profile_ids = if apply {
        selected_profile_ids.clone()
    } else {
        Vec::new()
    };
    let traffic_app_ids = if traffic_selection_explicit {
        Some(traffic_app_ids_for_profiles(&selected_profile_ids)?)
    } else {
        None
    };
    Ok(ConnectProfileExpansion {
        args: expanded,
        selected_profile_ids,
        traffic_app_ids,
        apply_profile_ids,
    })
}

fn profiles_require_local_ca(profile_ids: &[String]) -> Result<bool, String> {
    for profile_id in profile_ids {
        let profile = dam_integrations::profile(profile_id, dam_integrations::DEFAULT_PROXY_URL)
            .ok_or_else(|| {
                format!(
                    "unknown enabled integration profile: {profile_id}\nknown profiles: {}",
                    dam_integrations::profile_ids().join(", ")
                )
            })?;
        if profile
            .connect_args
            .windows(2)
            .any(|pair| pair[0] == "--trust-mode" && pair[1] == "local_ca")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn required_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

async fn wait_for_daemon_ready(timeout: Duration) -> Result<dam_daemon::DaemonState, String> {
    let started = std::time::Instant::now();
    let mut last_error = None;
    loop {
        match dam_daemon::daemon_status().map_err(|error| error.to_string())? {
            dam_daemon::DaemonStatus::Connected(state) => {
                match fetch_proxy_report(&state.proxy_url).await {
                    Ok(report) if report.state == dam_api::ProxyState::Protected => {
                        return Ok(state);
                    }
                    Ok(report) => {
                        last_error = Some(format!(
                            "proxy reported {}: {}",
                            proxy_state_tag(report.state),
                            report.message
                        ));
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            dam_daemon::DaemonStatus::Stale(state) => {
                last_error = Some(format!("daemon exited early with pid {}", state.pid));
            }
            dam_daemon::DaemonStatus::Disconnected => {}
        }

        if started.elapsed() >= timeout {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(match last_error {
        Some(error) => format!("DAM daemon did not become ready: {error}"),
        None => "DAM daemon did not become ready".to_string(),
    })
}

async fn wait_for_daemon_stop(pid: u32, timeout: Duration) {
    let started = std::time::Instant::now();
    while started.elapsed() < timeout {
        if !dam_daemon::process_is_running(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn fetch_proxy_report(proxy_url: &str) -> Result<dam_api::ProxyReport, String> {
    let url = format!("{}/health", proxy_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(2_000))
        .build()
        .map_err(|error| format!("failed to build status client: {error}"))?;
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|error| format!("DAM proxy is not reachable at {url}: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("DAM proxy status returned {}", response.status()));
    }

    response
        .json::<dam_api::ProxyReport>()
        .await
        .map_err(|error| format!("DAM proxy returned an unreadable status response: {error}"))
}

fn render_status_view(view: &StatusView) -> String {
    let mut output = String::new();
    output.push_str(&format!("state: {}\n", view.state));
    output.push_str(&format!("message: {}\n", view.message));
    match &view.active_profile {
        Some(profile) => output.push_str(&format!("active_profile: {}\n", profile.profile_id)),
        None => output.push_str("active_profile: none\n"),
    }
    if let Some(error) = &view.active_profile_error {
        output.push_str(&format!("warning active_profile: {error}\n"));
    }
    if let Some(state) = &view.daemon {
        output.push_str(&format!("pid: {}\n", state.pid));
        output.push_str(&format!("proxy: {}\n", state.proxy_url));
        output.push_str(&format!("network_mode: {}\n", state.network_mode));
        output.push_str(&format!(
            "protection_enabled: {}\n",
            state.protection_enabled
        ));
        output.push_str(&format!(
            "routing_routes: {}\n",
            state.transparent_ai_routing_readiness.len()
        ));
        for route in &state.transparent_ai_routing_readiness {
            output.push_str(&format!(
                "routing_route {}: {} - {}\n",
                route.route.target_name, route.readiness, route.message
            ));
        }
        output.push_str(&format!("trust_mode: {}\n", state.trust.mode));
        output.push_str(&format!(
            "trust_routes: {}\n",
            state.transparent_ai_trust_readiness.len()
        ));
        for route in &state.transparent_ai_trust_readiness {
            output.push_str(&format!(
                "trust_route {}: {} - {}\n",
                route.route.target_name, route.readiness, route.message
            ));
        }
        output.push_str(&format!(
            "interception_routes: {}\n",
            state.transparent_ai_interception_readiness.len()
        ));
        for route in &state.transparent_ai_interception_readiness {
            output.push_str(&format!(
                "interception_route {}: {} - {}\n",
                route.route.target_name, route.readiness, route.message
            ));
        }
        if let Some(target) = &state.target_name {
            output.push_str(&format!("target: {target}\n"));
        }
        if let Some(provider) = &state.target_provider {
            output.push_str(&format!("provider: {provider}\n"));
        }
        if let Some(upstream) = &state.upstream {
            output.push_str(&format!("upstream: {upstream}\n"));
        }
    }
    if let Some(proxy) = &view.proxy {
        output.push_str(&format!("protection: {}\n", proxy_state_tag(proxy.state)));
        for diagnostic in &proxy.diagnostics {
            output.push_str(&format!(
                "{} {}: {}\n",
                severity_tag(diagnostic.severity),
                diagnostic.code,
                diagnostic.message
            ));
        }
    }
    output
}

fn print_profile_status_view(view: &ProfileStatusView, json: bool) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(view)
                .map_err(|error| format!("failed to serialize profile status: {error}"))?
        );
    } else {
        print!("{}", render_profile_status_view(view));
    }
    Ok(())
}

fn print_network_result(
    result: &dam_net_macos::MacosSystemProxyResult,
    json: bool,
    approved: bool,
) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result)
                .map_err(|error| format!("failed to serialize network result: {error}"))?
        );
    } else {
        print!("{}", render_network_result(result, approved));
    }
    Ok(())
}

fn print_network_extension_result(
    result: &dam_net_macos::MacosNetworkExtensionResult,
    json: bool,
    approved: bool,
) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result).map_err(|error| format!(
                "failed to serialize network extension result: {error}"
            ))?
        );
    } else {
        print!("{}", render_network_extension_result(result, approved));
    }
    Ok(())
}

fn render_profile_status_view(view: &ProfileStatusView) -> String {
    let mut output = String::new();
    match &view.active_profile {
        Some(profile) => {
            output.push_str(&format!("active_profile: {}\n", profile.profile_id));
            output.push_str(&format!("selected_at_unix: {}\n", profile.selected_at_unix));
        }
        None => output.push_str("active_profile: none\n"),
    }
    if view.enabled_profiles.is_empty() {
        output.push_str("enabled_profiles: none\n");
    } else {
        output.push_str(&format!(
            "enabled_profiles: {}\n",
            view.enabled_profiles
                .iter()
                .map(|profile| profile.profile_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    output.push_str(&format!("proxy_url: {}\n", view.proxy_url));
    for apply in &view.applies {
        output.push_str(&format!(
            "profile {} apply_state: {}\n",
            apply.profile_id,
            integration_apply_status_tag(apply.status)
        ));
        output.push_str(&format!(
            "profile {} target: {}\n",
            apply.profile_id,
            apply.target_path.display()
        ));
        output.push_str(&format!(
            "profile {} rollback: {}\n",
            apply.profile_id,
            if apply.rollback_available {
                "available"
            } else {
                "not_available"
            }
        ));
        if apply.rollback_available {
            output.push_str(&format!("rollback_profile: {}\n", apply.profile_id));
        }
        output.push_str(&format!(
            "profile {} message: {}\n",
            apply.profile_id, apply.message
        ));
    }
    if let Some(apply) = view.applies.first() {
        output.push_str(&format!(
            "apply_state: {}\n",
            integration_apply_status_tag(apply.status)
        ));
        output.push_str(&format!("target: {}\n", apply.target_path.display()));
        output.push_str(&format!(
            "rollback: {}\n",
            if apply.rollback_available {
                "available"
            } else {
                "not_available"
            }
        ));
        output.push_str(&format!("message: {}\n", apply.message));
    }
    for error in &view.inspection_errors {
        output.push_str(&format!("warning inspection: {error}\n"));
    }
    output
}

fn render_local_ca_generate_view(view: &LocalCaGenerateView) -> String {
    let artifact = &view.artifact;
    let mut output = String::new();
    output.push_str(&format!("state: {}\n", view.state));
    output.push_str(&format!("id: {}\n", artifact.record.id));
    output.push_str(&format!("label: {}\n", artifact.record.label));
    output.push_str(&format!(
        "fingerprint_sha256: {}\n",
        artifact.record.fingerprint_sha256
    ));
    if let Some(fingerprint_sha1) = &artifact.record.fingerprint_sha1 {
        output.push_str(&format!("fingerprint_sha1: {fingerprint_sha1}\n"));
    }
    output.push_str(&format!(
        "created_at_unix: {}\n",
        artifact.record.created_at_unix
    ));
    output.push_str("installed_at_unix: none\n");
    output.push_str(&format!(
        "manifest: {}\n",
        artifact.paths.manifest_path.display()
    ));
    output.push_str(&format!(
        "certificate: {}\n",
        artifact.paths.certificate_path.display()
    ));
    output.push_str(&format!(
        "private_key: {}\n",
        artifact.paths.private_key_path.display()
    ));
    output.push_str("local_trust: unchanged\n");
    output
}

fn render_local_ca_delete_view(view: &LocalCaDeleteView) -> String {
    let mut output = String::new();
    output.push_str(&format!("state: {}\n", view.state));
    output.push_str(&format!("deleted: {}\n", view.deleted));
    output.push_str(&format!("state_dir: {}\n", view.state_dir.display()));
    output.push_str("local_trust: unchanged\n");
    output
}

fn render_local_ca_system_trust_result(
    result: &dam_trust::LocalCaSystemTrustResult,
    approved: bool,
) -> String {
    let plan = &result.plan;
    let mut output = String::new();
    output.push_str(&format!("state: {}\n", result.state));
    output.push_str(&format!("action: {}\n", trust_action_tag(plan.action)));
    output.push_str(&format!("message: {}\n", plan.message));
    output.push_str(&format!("support: {}\n", trust_support_tag(plan.support)));
    output.push_str(&format!("platform_store: {}\n", plan.platform_store));
    output.push_str(&format!("requires_admin: {}\n", plan.requires_admin));
    output.push_str(&format!(
        "changes_local_trust: {}\n",
        plan.changes_system_trust
    ));
    output.push_str(&format!(
        "requires_user_consent: {}\n",
        plan.requires_user_consent
    ));
    output.push_str(&format!(
        "will_generate_artifact: {}\n",
        plan.will_generate_artifact
    ));
    output.push_str(&format!("can_execute: {}\n", plan.can_execute));
    output.push_str(&format!("system_store: {}\n", plan.system_store));
    output.push_str(&format!(
        "certificate: {}\n",
        plan.certificate_path.display()
    ));
    if let Some(artifact) = &result.artifact {
        output.push_str(&format!("id: {}\n", artifact.record.id));
        output.push_str(&format!(
            "fingerprint_sha256: {}\n",
            artifact.record.fingerprint_sha256
        ));
        if let Some(fingerprint_sha1) = &artifact.record.fingerprint_sha1 {
            output.push_str(&format!("fingerprint_sha1: {fingerprint_sha1}\n"));
        }
        output.push_str(&format!(
            "installed_at_unix: {}\n",
            artifact
                .record
                .installed_at_unix
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
    }
    for command in &plan.commands {
        output.push_str(&format!(
            "command: {} {}\n",
            command.program,
            command.args.join(" ")
        ));
    }
    output.push_str(&format!(
        "local_trust: {}\n",
        if result.system_trust_changed {
            "changed"
        } else {
            "unchanged"
        }
    ));
    if !approved && plan.can_execute {
        output.push_str("approval: rerun with --yes to apply this local trust change\n");
    }
    output
}

fn render_network_result(result: &dam_net_macos::MacosSystemProxyResult, approved: bool) -> String {
    let plan = &result.plan;
    let mut output = String::new();
    output.push_str(&format!(
        "state: {}\n",
        network_result_state_tag(result.state)
    ));
    output.push_str(&format!("action: {}\n", network_action_tag(plan.action)));
    output.push_str(&format!("message: {}\n", plan.message));
    output.push_str(&format!("support: {}\n", network_support_tag(plan.support)));
    output.push_str(&format!("proxy_url: {}\n", plan.proxy_url));
    output.push_str(&format!("pac_url: {}\n", plan.pac_url));
    output.push_str(&format!("pac_path: {}\n", plan.paths.pac_path.display()));
    output.push_str(&format!("services: {}\n", plan.services.len()));
    for service in &plan.services {
        output.push_str(&format!(
            "service {}: auto_proxy={} url={}\n",
            service.service_name,
            service.auto_proxy_enabled,
            service.auto_proxy_url.as_deref().unwrap_or("none")
        ));
    }
    for command in &plan.commands {
        output.push_str(&format!(
            "command: {} {}\n",
            command.program,
            command.args.join(" ")
        ));
    }
    output.push_str(&format!("can_execute: {}\n", plan.can_execute));
    output.push_str(&format!(
        "system_routes: {}\n",
        if result.system_routes_changed {
            "changed"
        } else {
            "unchanged"
        }
    ));
    if !approved && plan.can_execute {
        output.push_str("approval: rerun with --yes to apply this network change\n");
    }
    output
}

fn render_network_extension_result(
    result: &dam_net_macos::MacosNetworkExtensionResult,
    approved: bool,
) -> String {
    let plan = &result.plan;
    let mut output = String::new();
    output.push_str(&format!(
        "state: {}\n",
        network_extension_result_state_tag(result.state)
    ));
    output.push_str(&format!(
        "action: {}\n",
        network_extension_action_tag(plan.action)
    ));
    output.push_str(&format!("message: {}\n", plan.message));
    output.push_str(&format!(
        "support: {}\n",
        network_extension_support_tag(plan.support)
    ));
    output.push_str(&format!("bundle_id: {}\n", plan.bundle_identifier));
    output.push_str(&format!(
        "team_id: {}\n",
        plan.team_identifier.as_deref().unwrap_or("none")
    ));
    output.push_str(&format!("backend: {}\n", plan.backend_status.kind.tag()));
    output.push_str(&format!(
        "backend_readiness: {}\n",
        plan.backend_status.readiness.tag()
    ));
    output.push_str(&format!("backend_active: {}\n", plan.backend_status.active));
    output.push_str(&format!("protected_hosts: {}\n", plan.ai_hosts.join(", ")));
    for command in &plan.commands {
        output.push_str(&format!(
            "command: {} {}\n",
            command.program,
            command.args.join(" ")
        ));
    }
    output.push_str(&format!("can_execute: {}\n", plan.can_execute));
    output.push_str(&format!(
        "system_routes: {}\n",
        if result.system_routes_changed {
            "changed"
        } else {
            "unchanged"
        }
    ));
    if let Some(record) = &result.record {
        output.push_str(&format!(
            "activation_method: {}\n",
            record.activation_method
        ));
        output.push_str(&format!(
            "installed_at_unix: {}\n",
            record.installed_at_unix
        ));
    }
    if result.state == dam_net_macos::MacosNetworkExtensionResultState::NeedsApproval {
        output.push_str(
            "approval: approve DAM Network Protection in System Settings, then click Connect/Resume again\n",
        );
    }
    if !approved && plan.can_execute {
        output.push_str("approval: rerun with --yes to apply this Network Extension change\n");
    }
    output
}

fn network_result_state_tag(state: dam_net_macos::MacosSystemProxyResultState) -> &'static str {
    match state {
        dam_net_macos::MacosSystemProxyResultState::Preview => "preview",
        dam_net_macos::MacosSystemProxyResultState::Installed => "installed",
        dam_net_macos::MacosSystemProxyResultState::AlreadyInstalled => "already_installed",
        dam_net_macos::MacosSystemProxyResultState::Removed => "removed",
        dam_net_macos::MacosSystemProxyResultState::NotInstalled => "not_installed",
    }
}

fn network_action_tag(action: dam_net_macos::MacosSystemProxyAction) -> &'static str {
    match action {
        dam_net_macos::MacosSystemProxyAction::Install => "install",
        dam_net_macos::MacosSystemProxyAction::Remove => "remove",
    }
}

fn network_support_tag(support: dam_net_macos::MacosSystemProxySupport) -> &'static str {
    match support {
        dam_net_macos::MacosSystemProxySupport::Implemented => "implemented",
        dam_net_macos::MacosSystemProxySupport::Planned => "planned",
    }
}

fn network_extension_result_state_tag(
    state: dam_net_macos::MacosNetworkExtensionResultState,
) -> &'static str {
    match state {
        dam_net_macos::MacosNetworkExtensionResultState::Preview => "preview",
        dam_net_macos::MacosNetworkExtensionResultState::Installed => "installed",
        dam_net_macos::MacosNetworkExtensionResultState::AlreadyInstalled => "already_installed",
        dam_net_macos::MacosNetworkExtensionResultState::NeedsApproval => "needs_approval",
        dam_net_macos::MacosNetworkExtensionResultState::Removed => "removed",
        dam_net_macos::MacosNetworkExtensionResultState::NotInstalled => "not_installed",
        dam_net_macos::MacosNetworkExtensionResultState::Status => "status",
    }
}

fn network_extension_action_tag(
    action: dam_net_macos::MacosNetworkExtensionAction,
) -> &'static str {
    match action {
        dam_net_macos::MacosNetworkExtensionAction::Install => "install",
        dam_net_macos::MacosNetworkExtensionAction::Remove => "remove",
        dam_net_macos::MacosNetworkExtensionAction::Status => "status",
    }
}

fn network_extension_support_tag(
    support: dam_net_macos::MacosNetworkExtensionSupport,
) -> &'static str {
    match support {
        dam_net_macos::MacosNetworkExtensionSupport::Implemented => "implemented",
        dam_net_macos::MacosNetworkExtensionSupport::Planned => "planned",
    }
}

fn trust_action_tag(action: dam_trust::TrustAction) -> &'static str {
    match action {
        dam_trust::TrustAction::Inspect => "inspect",
        dam_trust::TrustAction::InstallLocalCa => "install_local_ca",
        dam_trust::TrustAction::RemoveLocalCa => "remove_local_ca",
    }
}

fn trust_support_tag(support: dam_trust::TrustSupport) -> &'static str {
    match support {
        dam_trust::TrustSupport::Implemented => "implemented",
        dam_trust::TrustSupport::Planned => "planned",
    }
}

fn profile_status_view(state_dir: &std::path::Path) -> Result<ProfileStatusView, String> {
    let active_profile = dam_integrations::read_active_profile(state_dir)?;
    let enabled_profiles = dam_integrations::read_effective_enabled_integrations(state_dir)?;
    let proxy_url = integration_proxy_url(None);
    let mut applies = Vec::new();
    let mut inspection_errors = Vec::new();
    for profile in &enabled_profiles {
        match default_integration_target_path(&profile.profile_id, state_dir).and_then(
            |target_path| {
                dam_integrations::inspect_apply(
                    &profile.profile_id,
                    &proxy_url,
                    target_path,
                    state_dir,
                )
            },
        ) {
            Ok(inspection) => applies.push(inspection),
            Err(error) => inspection_errors.push(format!("{}: {error}", profile.profile_id)),
        }
    }

    Ok(ProfileStatusView {
        active_profile,
        enabled_profiles,
        proxy_url,
        applies,
        inspection_errors,
    })
}

fn generate_local_ca_output(state_dir: &std::path::Path, json: bool) -> Result<String, String> {
    let artifact =
        dam_trust::generate_local_ca_artifact(state_dir).map_err(|error| error.to_string())?;
    let view = LocalCaGenerateView {
        state: "generated",
        artifact,
    };
    if json {
        serde_json::to_string_pretty(&view)
            .map(|value| format!("{value}\n"))
            .map_err(|error| format!("failed to serialize local CA result: {error}"))
    } else {
        Ok(render_local_ca_generate_view(&view))
    }
}

fn delete_local_ca_output(state_dir: &std::path::Path, json: bool) -> Result<String, String> {
    let deleted =
        dam_trust::delete_local_ca_artifact(state_dir).map_err(|error| error.to_string())?;
    let view = LocalCaDeleteView {
        state: if deleted { "deleted" } else { "missing" },
        deleted,
        state_dir: state_dir.to_path_buf(),
    };
    if json {
        serde_json::to_string_pretty(&view)
            .map(|value| format!("{value}\n"))
            .map_err(|error| format!("failed to serialize local CA delete result: {error}"))
    } else {
        Ok(render_local_ca_delete_view(&view))
    }
}

fn install_local_ca_output(
    state_dir: &std::path::Path,
    json: bool,
    yes: bool,
) -> Result<String, String> {
    let result = if yes {
        dam_trust::install_local_ca_system_trust(state_dir)
    } else {
        dam_trust::preview_local_ca_install(state_dir)
    }
    .map_err(|error| error.to_string())?;
    if json {
        serde_json::to_string_pretty(&result)
            .map(|value| format!("{value}\n"))
            .map_err(|error| format!("failed to serialize local CA install result: {error}"))
    } else {
        Ok(render_local_ca_system_trust_result(&result, yes))
    }
}

fn remove_local_ca_output(
    state_dir: &std::path::Path,
    json: bool,
    yes: bool,
) -> Result<String, String> {
    let result = if yes {
        dam_trust::remove_local_ca_system_trust(state_dir)
    } else {
        dam_trust::preview_local_ca_remove(state_dir)
    }
    .map_err(|error| error.to_string())?;
    if json {
        serde_json::to_string_pretty(&result)
            .map(|value| format!("{value}\n"))
            .map_err(|error| format!("failed to serialize local CA remove result: {error}"))
    } else {
        Ok(render_local_ca_system_trust_result(&result, yes))
    }
}

fn active_profile_for_status() -> (Option<dam_integrations::ActiveProfileState>, Option<String>) {
    let state_dir = match integration_state_dir() {
        Ok(path) => path,
        Err(error) => return (None, Some(error)),
    };
    match dam_integrations::read_active_profile(&state_dir) {
        Ok(profile) => (profile, None),
        Err(error) => (None, Some(error)),
    }
}

fn enabled_profiles_for_connect_parse(args: &[String]) -> Result<ConnectProfileSelection, String> {
    if !matches!(args.first().map(String::as_str), Some("connect")) {
        return Ok(ConnectProfileSelection::default());
    }
    let connect_args = &args[1..];
    if matches!(
        connect_args.first().map(String::as_str),
        Some("-h" | "--help")
    ) {
        return Ok(ConnectProfileSelection::default());
    }
    if connect_args.iter().any(|arg| arg == "--profile") {
        return Ok(ConnectProfileSelection::default());
    }

    let state_dir = integration_state_dir()?;
    let runtime_profiles = dam_integrations::runtime_enabled_profile_ids(&state_dir)?;
    let profiles = runtime_profiles.clone().unwrap_or_default();
    if profiles.is_empty() && connect_args.iter().any(|arg| arg == "--apply") {
        Err(
            "--apply requires --profile <id> or enabled profiles in `dam profile status`"
                .to_string(),
        )
    } else {
        Ok(ConnectProfileSelection {
            profile_ids: profiles,
            explicit_selection: runtime_profiles.is_some(),
        })
    }
}

fn integration_proxy_url(proxy_url: Option<String>) -> String {
    if let Some(proxy_url) = proxy_url {
        return proxy_url;
    }

    match dam_daemon::daemon_status() {
        Ok(dam_daemon::DaemonStatus::Connected(state)) => state.proxy_url,
        Ok(dam_daemon::DaemonStatus::Disconnected | dam_daemon::DaemonStatus::Stale(_))
        | Err(_) => dam_integrations::DEFAULT_PROXY_URL.to_string(),
    }
}

fn render_integration_list(
    profiles: &[dam_integrations::IntegrationProfile],
    proxy_url: &str,
) -> String {
    let mut output = String::new();
    output.push_str(&format!("proxy_url: {proxy_url}\n"));
    output.push_str("profiles:\n");
    for profile in profiles {
        output.push_str(&format!(
            "  {:<18} {} - {}\n",
            profile.id, profile.provider, profile.summary
        ));
    }
    output.push_str("\nUse `dam integrations show <profile>` for setup details.\n");
    output
}

fn render_integration_profile(
    profile: &dam_integrations::IntegrationProfile,
    proxy_url: &str,
) -> String {
    let mut output = String::new();
    output.push_str(&format!("profile: {}\n", profile.id));
    output.push_str(&format!("name: {}\n", profile.name));
    output.push_str(&format!("provider: {}\n", profile.provider));
    output.push_str(&format!("proxy_url: {proxy_url}\n"));
    output.push_str(&format!("summary: {}\n", profile.summary));

    if !profile.connect_args.is_empty() {
        let mut command = vec!["dam".to_string(), "connect".to_string()];
        command.extend(profile.connect_args.iter().cloned());
        output.push_str("\nconnect:\n");
        output.push_str(&format!("  {}\n", shell_command(&command)));
    }

    if !profile.settings.is_empty() {
        output.push_str("\nsettings:\n");
        for setting in &profile.settings {
            output.push_str(&format!(
                "  {}={}  # {}\n",
                setting.key,
                shell_quote(&setting.value),
                setting.description
            ));
        }
    }

    if !profile.commands.is_empty() {
        output.push_str("\ncommands:\n");
        for command in &profile.commands {
            output.push_str(&format!("  {}:\n", command.label));
            output.push_str(&format!("    {}\n", shell_command(&command.command)));
        }
    }

    if !profile.notes.is_empty() {
        output.push_str("\nnotes:\n");
        for note in &profile.notes {
            output.push_str(&format!("  - {note}\n"));
        }
    }

    output
}

fn integration_state_dir() -> Result<PathBuf, String> {
    dam_daemon::state_paths()
        .map(|paths| paths.state_dir.join("integrations"))
        .map_err(|error| error.to_string())
}

fn default_integration_target_path(
    profile_id: &str,
    state_dir: &std::path::Path,
) -> Result<PathBuf, String> {
    dam_integrations::default_apply_path(
        profile_id,
        state_dir,
        std::env::var_os("CODEX_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

fn apply_connect_profile(profile_id: &str, proxy_url: &str) -> Result<ConnectApplyOutcome, String> {
    let state_dir = integration_state_dir()?;
    let target_path = default_integration_target_path(profile_id, &state_dir)?;
    let inspection =
        dam_integrations::inspect_apply(profile_id, proxy_url, target_path.clone(), &state_dir)?;

    if let Some(error) = &inspection.record_error {
        return Err(format!(
            "integration profile {profile_id} cannot be applied safely: {}\nrollback record issue: {error}\nRun `damctl integrations check {profile_id}` for details or `dam integrations rollback {profile_id}` to restore the last DAM change.",
            inspection.message
        ));
    }

    if inspection.status == dam_integrations::IntegrationApplyStatus::Modified {
        return Err(format!(
            "integration profile {profile_id} was previously applied, but the target no longer matches DAM's desired content: {}\nrefusing to overwrite during `dam connect --apply`; run `damctl integrations check {profile_id}` for details or `dam integrations rollback {profile_id}` to restore the last DAM change.",
            inspection.target_path.display()
        ));
    }

    let rollback_available_before_apply = inspection.rollback_available;
    let prepared = dam_integrations::prepare_apply(profile_id, proxy_url, target_path)?;
    let result = dam_integrations::run_apply(prepared, false, &state_dir)?;
    let rollback_available = rollback_available_before_apply || result.record_path.is_some();

    Ok(ConnectApplyOutcome {
        result,
        rollback_available,
    })
}

fn ensure_connect_transparent_prerequisites(
    proxy: &dam_daemon::ProxyOptions,
    config: &dam_config::DamConfig,
    state_dir: Option<PathBuf>,
) -> Result<(), String> {
    if proxy.network_mode == dam_net::CaptureMode::ExplicitProxy
        && proxy.trust_mode == dam_trust::TrustMode::Disabled
    {
        return Ok(());
    }
    if configured_ai_hosts(config).is_empty() {
        return Ok(());
    }

    let plan = dam_diagnostics::setup_plan(
        config,
        &dam_diagnostics::SetupPlanOptions {
            state_dir,
            config_path: proxy.config_path.clone(),
            proxy_url: Some(proxy_url_for_connect_apply(proxy)?),
            network_mode: proxy.network_mode,
            trust_mode: proxy.trust_mode,
        },
    )?;
    for step in &plan.steps {
        let enforced = matches!(
            step.kind,
            dam_diagnostics::SetupStepKind::SystemProxy
                | dam_diagnostics::SetupStepKind::NetworkExtension
                | dam_diagnostics::SetupStepKind::NetworkExtensionConfiguration
                | dam_diagnostics::SetupStepKind::NetworkExtensionEnable
                | dam_diagnostics::SetupStepKind::NetworkExtensionStart
                | dam_diagnostics::SetupStepKind::LinuxTransparentProxy
                | dam_diagnostics::SetupStepKind::WindowsFilteringPlatform
                | dam_diagnostics::SetupStepKind::LocalCa
        );
        if enforced
            && matches!(
                step.status,
                dam_diagnostics::SetupStepStatus::Needed
                    | dam_diagnostics::SetupStepStatus::Blocked
            )
        {
            return Err(render_connect_prerequisite_error(step));
        }
    }

    Ok(())
}

fn render_connect_prerequisite_error(step: &dam_diagnostics::SetupStep) -> String {
    let mut message = format!(
        "DAM cannot start this transparent setup yet: {}",
        step.message
    );
    if let Some(command) = &step.command {
        message.push_str(&format!("\nRun `{}` first.", command.join(" ")));
    }
    message
}

fn validate_connect_apply_profile_matches_proxy(
    profile_id: &str,
    proxy: &dam_daemon::ProxyOptions,
) -> Result<(), String> {
    let profile = dam_integrations::profile(profile_id, dam_integrations::DEFAULT_PROXY_URL)
        .ok_or_else(|| {
            format!(
                "unknown integration profile: {profile_id}\nknown profiles: {}",
                dam_integrations::profile_ids().join(", ")
            )
        })?;
    let matches_proxy = proxy
        .targets
        .as_ref()
        .map(|targets| {
            targets
                .iter()
                .any(|target| target.provider == profile.provider)
        })
        .unwrap_or_else(|| profile.provider == proxy.provider);
    if !matches_proxy {
        return Err(format!(
            "profile {profile_id} uses provider {}, but connect is not configured for that provider",
            profile.provider
        ));
    }
    Ok(())
}

fn proxy_targets_for_profiles(
    profile_ids: &[String],
) -> Result<Vec<dam_config::ProxyTargetConfig>, String> {
    let mut targets = Vec::new();
    for profile_id in profile_ids {
        let profile = dam_integrations::profile(profile_id, dam_integrations::DEFAULT_PROXY_URL)
            .ok_or_else(|| {
                format!(
                    "unknown enabled integration profile: {profile_id}\nknown profiles: {}",
                    dam_integrations::profile_ids().join(", ")
                )
            })?;
        let options = dam_daemon::parse_proxy_options(profile.connect_args)?;
        let target = dam_config::ProxyTargetConfig {
            name: options.target_name,
            provider: options.provider,
            upstream: options.upstream,
            failure_mode: None,
            api_key_env: None,
            api_key: None,
        };
        if !targets
            .iter()
            .any(|existing: &dam_config::ProxyTargetConfig| {
                existing.name == target.name
                    && existing.provider == target.provider
                    && existing.upstream == target.upstream
            })
        {
            targets.push(target);
        }
    }
    Ok(targets)
}

fn traffic_app_ids_for_profiles(profile_ids: &[String]) -> Result<Vec<String>, String> {
    let mut app_ids = Vec::new();
    for profile_id in profile_ids {
        let profile = dam_integrations::profile(profile_id, dam_integrations::DEFAULT_PROXY_URL)
            .ok_or_else(|| {
                format!(
                    "unknown enabled integration profile: {profile_id}\nknown profiles: {}",
                    dam_integrations::profile_ids().join(", ")
                )
            })?;
        for app_id in profile.traffic_app_ids {
            if !app_ids.contains(&app_id) {
                app_ids.push(app_id);
            }
        }
    }
    Ok(app_ids)
}

fn proxy_url_for_connect_apply(options: &dam_daemon::ProxyOptions) -> Result<String, String> {
    let addr = options
        .listen
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid --listen address {}: {error}", options.listen))?;
    if addr.port() == 0 {
        return Err(
            "dam connect --apply requires a fixed --listen port; port 0 cannot be written into a harness profile"
                .to_string(),
        );
    }
    Ok(dam_daemon::local_base_url(addr))
}

fn render_integration_apply_result(result: &dam_integrations::IntegrationApplyResult) -> String {
    let mut output = String::new();
    output.push_str(&format!("profile: {}\n", result.profile_id));
    output.push_str(&format!("state: {}\n", result.message));
    output.push_str(&format!("proxy_url: {}\n", result.proxy_url));
    if let Some(record_path) = &result.record_path {
        output.push_str(&format!("rollback_record: {}\n", record_path.display()));
    }
    for change in &result.changes {
        output.push_str(&format!(
            "{}: {} - {}\n",
            change.action.tag(),
            change.path.display(),
            change.description
        ));
    }
    output
}

fn render_connect_apply_outcome(outcome: &ConnectApplyOutcome) -> String {
    let mut output = render_integration_apply_result(&outcome.result);
    if outcome.rollback_available {
        output.push_str(&format!(
            "rollback: dam integrations rollback {}\n",
            outcome.result.profile_id
        ));
    }
    output
}

fn render_integration_rollback_result(
    result: &dam_integrations::IntegrationRollbackResult,
) -> String {
    let mut output = String::new();
    output.push_str(&format!("profile: {}\n", result.profile_id));
    output.push_str(&format!("state: {}\n", result.message));
    for change in &result.changes {
        output.push_str(&format!(
            "{}: {} - {}\n",
            change.action.tag(),
            change.path.display(),
            change.description
        ));
    }
    output
}

fn shell_command(command: &[String]) -> String {
    command
        .iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "/:._=-".contains(ch))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
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

fn integration_apply_status_tag(status: dam_integrations::IntegrationApplyStatus) -> &'static str {
    match status {
        dam_integrations::IntegrationApplyStatus::Applied => "applied",
        dam_integrations::IntegrationApplyStatus::NeedsApply => "needs_apply",
        dam_integrations::IntegrationApplyStatus::Modified => "modified",
    }
}

fn severity_tag(severity: dam_api::DiagnosticSeverity) -> &'static str {
    match severity {
        dam_api::DiagnosticSeverity::Info => "info",
        dam_api::DiagnosticSeverity::Warning => "warning",
        dam_api::DiagnosticSeverity::Error => "error",
    }
}

fn usage() -> &'static str {
    "Usage: dam <command>\n\nCommands:\n  connect       Start or resume the background DAM proxy daemon\n  web           Start the local DAM web UI\n  status        Show background DAM protection status\n  logs          Show concise local DAM operation logs\n  profile       Select and inspect the active harness profile\n  trust         Manage local trust artifacts and approved local trust changes\n  network       Manage local network routing plans and approved changes\n  startup       Inspect or record local startup setup choices\n  disconnect    Pause DAM protection, or stop the daemon with --stop\n  integrations  List and inspect known harness integration profiles\n\nRun `dam connect --help`, `dam web --help`, `dam logs --help`, `dam profile --help`, `dam trust --help`, `dam network --help`, `dam startup --help`, or `dam integrations --help` for command options."
}

fn usage_connect() -> &'static str {
    "Usage: dam connect [--profile PROFILE] [--apply] [--openai|--anthropic] [DAM_OPTIONS]\n\nStarts a background DAM proxy daemon for proxy/interception routing. Enabled app profiles select daemon targets automatically. --apply additionally writes selected profile setup before connecting, with rollback support.\n\nDAM options:\n  --profile <id>          Use integration profile daemon defaults\n  --apply                 Write selected or enabled profile setup before connecting\n  --openai                Use the OpenAI-compatible target preset (default)\n  --anthropic             Use the Anthropic target preset\n  --config <path>         Load DAM config file before daemon overrides\n  --listen <addr>         Local proxy listen address (default: 127.0.0.1:7828)\n  --network-mode <mode>   Control-plane network mode: explicit_proxy, system_proxy, or tun\n  --trust-mode <mode>     Control-plane trust mode: disabled or local_ca\n  --target-name <name>    Proxy target name (default: openai)\n  --provider <provider>   Provider adapter: openai-compatible or anthropic\n  --upstream <url>        Provider upstream URL\n  --db <path>             Vault SQLite path (default: vault.db)\n  --log <path>            Log SQLite path (default: log.db)\n  --consent-db <path>     Consent SQLite path (default: consent.db)\n  --no-log                Disable DAM log writes\n  --no-resolve-inbound    Leave DAM references unresolved in inbound responses\n  --resolve-inbound       Restore DAM references in inbound responses (default)\n\nKnown profiles: openai-compatible, anthropic, claude-code, codex-api, codex-chatgpt, xai-compatible"
}

fn usage_status() -> &'static str {
    "Usage: dam status [--json]"
}

fn usage_logs() -> &'static str {
    "Usage: dam logs [--limit N] [--after-id ID] [--operation OPERATION_ID] [--events] [--json]\n\nShows concise non-sensitive operation summaries by default. Use --operation to inspect one operation's event timeline, or --events to show raw log event rows without grouping."
}

fn usage_disconnect() -> &'static str {
    "Usage: dam disconnect [--stop]\n\nBy default, `dam disconnect` pauses protection while leaving the daemon in pass-through mode so existing clients keep working. Use --stop after restoring routing or app profile setup when the daemon should exit."
}

fn usage_profile() -> &'static str {
    "Usage: dam profile <command>\n\nCommands:\n  status  Show the active harness profile and apply state\n  set     Select the active harness profile\n  clear   Clear the active harness profile"
}

fn usage_profile_status() -> &'static str {
    "Usage: dam profile status [--json]"
}

fn usage_profile_set() -> &'static str {
    "Usage: dam profile set <profile> [--json]"
}

fn usage_profile_clear() -> &'static str {
    "Usage: dam profile clear [--json]"
}

fn usage_trust() -> &'static str {
    "Usage: dam trust <command>\n\nCommands:\n  generate-local-ca  Generate local CA certificate/key artifacts without installing trust\n  delete-local-ca    Delete uninstalled local CA artifacts\n  install-local-ca   Preview or install the DAM local CA in local trust\n  remove-local-ca    Preview or remove the DAM local CA from local trust"
}

fn usage_trust_generate_local_ca() -> &'static str {
    "Usage: dam trust generate-local-ca [--json]\n\nCreates local CA certificate/key artifacts under the DAM state directory. This does not install a CA or change local trust."
}

fn usage_trust_delete_local_ca() -> &'static str {
    "Usage: dam trust delete-local-ca [--json]\n\nDeletes DAM-managed local CA artifacts only when they are not marked installed. This does not change local trust."
}

fn usage_trust_install_local_ca() -> &'static str {
    "Usage: dam trust install-local-ca [--dry-run|--yes] [--json]\n\nPreviews the local trust change by default. Use --yes to install the DAM local CA into the macOS user login keychain."
}

fn usage_trust_remove_local_ca() -> &'static str {
    "Usage: dam trust remove-local-ca [--dry-run|--yes] [--json]\n\nPreviews the local trust removal by default. Use --yes to remove the recorded DAM local CA from the macOS user login keychain."
}

fn usage_network() -> &'static str {
    "Usage: dam network <command>\n\nCommands:\n  install-system-proxy       Preview or install macOS PAC routing for proxy-capable traffic\n  remove-system-proxy        Preview or remove DAM macOS PAC routing and restore prior settings\n  install-network-extension  Preview or install macOS Network Extension capture for tun mode\n  remove-network-extension   Preview or remove DAM macOS Network Extension capture\n  status                     Show macOS capture backend status"
}

fn usage_network_install_system_proxy() -> &'static str {
    "Usage: dam network install-system-proxy [--config PATH] [--dry-run|--yes] [--json]\n\nPreviews macOS PAC system proxy routing by default. Use --yes to route proxy-capable HTTP and HTTPS traffic to DAM. Unknown hosts pass through untouched; active traffic profile hosts are protected only when routing, trust, consent, and the TLS adapter are all ready."
}

fn usage_network_remove_system_proxy() -> &'static str {
    "Usage: dam network remove-system-proxy [--dry-run|--yes] [--json]\n\nPreviews macOS PAC system proxy rollback by default. Use --yes to restore the prior auto-proxy settings recorded before DAM changed them."
}

fn usage_network_install_network_extension() -> &'static str {
    "Usage: dam network install-network-extension [--config PATH] [--dry-run|--yes] [--json]\n\nPreviews macOS Network Extension capture by default. Use --yes to activate the packaged Network Extension backend for DAM tun mode. In source builds without a packaged helper, DAM records control-plane state only; release builds must supply the native helper through DAM_MACOS_NE_HELPER or the app bundle."
}

fn usage_network_remove_network_extension() -> &'static str {
    "Usage: dam network remove-network-extension [--dry-run|--yes] [--json]\n\nPreviews macOS Network Extension removal by default. Use --yes to deactivate the packaged capture backend and clear DAM rollback state."
}

fn usage_network_status() -> &'static str {
    "Usage: dam network status [--json]\n\nShows macOS Network Extension capture state for DAM tun mode."
}

fn usage_startup() -> &'static str {
    "Usage: dam startup <command>\n\nCommands:\n  status              Show the local startup setup choice\n  skip-open-at-login  Record that Open at Login was intentionally skipped"
}

fn usage_startup_status() -> &'static str {
    "Usage: dam startup status [--json]\n\nShows whether DAM startup setup is registered, skipped, or still unconfigured."
}

fn usage_startup_skip_open_at_login() -> &'static str {
    "Usage: dam startup skip-open-at-login [--json]\n\nRecords the same choice as the tray Skip button so scripted installs can continue setup without adding DAM to Open at Login."
}

fn usage_integrations() -> &'static str {
    "Usage: dam integrations <command>\n\nCommands:\n  list      List known integration profiles\n  show      Show setup details for one integration profile\n  apply     Apply a harness integration profile with backup support\n  rollback  Roll back the last DAM integration profile change"
}

fn usage_integrations_list() -> &'static str {
    "Usage: dam integrations list [--proxy-url http://127.0.0.1:7828] [--json]"
}

fn usage_integrations_show() -> &'static str {
    "Usage: dam integrations show <profile> [--proxy-url http://127.0.0.1:7828] [--json]"
}

fn usage_integrations_apply() -> &'static str {
    "Usage: dam integrations apply <profile> [--write|--dry-run] [--proxy-url http://127.0.0.1:7828] [--target-path PATH] [--json]\n\nPreviews a harness integration profile by default. Use --write to change files; DAM creates a rollback record before changing files."
}

fn usage_integrations_rollback() -> &'static str {
    "Usage: dam integrations rollback <profile> [--json]"
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPENAI_API_UPSTREAM: &str = "https://api.openai.com";
    const ANTHROPIC_UPSTREAM: &str = "https://api.anthropic.com";

    #[test]
    fn removed_tool_launchers_are_not_cli_commands() {
        for command in ["codex", "claude"] {
            let error = parse_cli([command.to_string()]).unwrap_err();

            assert!(error.contains(&format!("unknown command: {command}")));
            assert!(!error.contains("one-shot"));
            assert!(!error.contains("fail"));
            assert!(!error.contains("dam codex"));
            assert!(!error.contains("dam claude"));
        }
    }

    #[test]
    fn parses_web_forwarding_command() {
        let cli = parse_cli([
            "web".to_string(),
            "--config".to_string(),
            "dam.example.toml".to_string(),
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            CommandKind::Web(WebArgs {
                args: vec!["--config".to_string(), "dam.example.toml".to_string()],
            })
        );
    }

    #[test]
    fn parses_connect_with_anthropic_preset() {
        let cli = parse_cli([
            "connect".to_string(),
            "--anthropic".to_string(),
            "--listen".to_string(),
            "127.0.0.1:9000".to_string(),
        ])
        .unwrap();

        let CommandKind::Connect(args) = cli.command else {
            panic!("expected connect");
        };
        assert_eq!(args.apply_profile_ids, Vec::<String>::new());
        assert_eq!(args.proxy.listen, "127.0.0.1:9000");
        assert_eq!(args.proxy.target_name, "anthropic");
        assert_eq!(args.proxy.provider, "anthropic");
        assert_eq!(args.proxy.upstream, ANTHROPIC_UPSTREAM);
        assert_eq!(args.proxy.network_mode, dam_net::CaptureMode::ExplicitProxy);
        assert_eq!(args.proxy.trust_mode, dam_trust::TrustMode::Disabled);
    }

    #[test]
    fn parses_connect_with_integration_profile_defaults() {
        let cli = parse_cli([
            "connect".to_string(),
            "--profile".to_string(),
            "xai-compatible".to_string(),
            "--listen".to_string(),
            "127.0.0.1:9000".to_string(),
        ])
        .unwrap();

        let CommandKind::Connect(args) = cli.command else {
            panic!("expected connect");
        };
        assert_eq!(args.apply_profile_ids, Vec::<String>::new());
        assert_eq!(args.proxy.listen, "127.0.0.1:9000");
        assert_eq!(args.proxy.target_name, "xai");
        assert_eq!(args.proxy.provider, "openai-compatible");
        assert_eq!(args.proxy.upstream, "https://api.x.ai");
        assert_eq!(
            args.proxy.traffic_app_ids,
            Some(vec!["xai-api".to_string()])
        );
    }

    #[test]
    fn parses_connect_profile_apply() {
        let cli = parse_cli([
            "connect".to_string(),
            "--profile".to_string(),
            "claude-code".to_string(),
            "--apply".to_string(),
            "--listen".to_string(),
            "127.0.0.1:9000".to_string(),
        ])
        .unwrap();

        let CommandKind::Connect(args) = cli.command else {
            panic!("expected connect");
        };
        assert_eq!(args.apply_profile_ids, vec!["claude-code".to_string()]);
        assert_eq!(args.proxy.listen, "127.0.0.1:9000");
        assert_eq!(args.proxy.target_name, "anthropic");
        assert_eq!(args.proxy.provider, "anthropic");
        assert_eq!(args.proxy.upstream, ANTHROPIC_UPSTREAM);
        assert_eq!(
            args.proxy.traffic_app_ids,
            Some(vec!["anthropic-api".to_string()])
        );
        assert_eq!(args.proxy.network_mode, dam_net::CaptureMode::Tun);
        assert_eq!(args.proxy.trust_mode, dam_trust::TrustMode::LocalCa);
    }

    #[test]
    fn parses_connect_apply_with_enabled_profile() {
        let cli = parse_cli_with_active_profiles(
            [
                "connect".to_string(),
                "--apply".to_string(),
                "--listen".to_string(),
                "127.0.0.1:9000".to_string(),
            ],
            vec!["claude-code".to_string()],
        )
        .unwrap();

        let CommandKind::Connect(args) = cli.command else {
            panic!("expected connect");
        };
        assert_eq!(args.apply_profile_ids, vec!["claude-code".to_string()]);
        assert_eq!(args.proxy.listen, "127.0.0.1:9000");
        assert_eq!(args.proxy.provider, "anthropic");
        assert_eq!(args.proxy.upstream, ANTHROPIC_UPSTREAM);
        assert_eq!(
            args.proxy.traffic_app_ids,
            Some(vec!["anthropic-api".to_string()])
        );
        assert_eq!(args.proxy.network_mode, dam_net::CaptureMode::Tun);
        assert_eq!(args.proxy.trust_mode, dam_trust::TrustMode::LocalCa);
    }

    #[test]
    fn parses_connect_with_enabled_profile_selecting_targets_only() {
        let cli = parse_cli_with_active_profiles(
            [
                "connect".to_string(),
                "--listen".to_string(),
                "127.0.0.1:9000".to_string(),
            ],
            vec!["claude-code".to_string()],
        )
        .unwrap();

        let CommandKind::Connect(args) = cli.command else {
            panic!("expected connect");
        };
        assert_eq!(args.apply_profile_ids, Vec::<String>::new());
        assert_eq!(args.proxy.listen, "127.0.0.1:9000");
        assert_eq!(args.proxy.provider, "anthropic");
        assert_eq!(args.proxy.upstream, ANTHROPIC_UPSTREAM);
        assert_eq!(args.proxy.network_mode, dam_net::CaptureMode::Tun);
        assert_eq!(args.proxy.trust_mode, dam_trust::TrustMode::LocalCa);
    }

    #[test]
    fn parses_connect_with_explicit_empty_enabled_profiles_as_empty_traffic_scope() {
        let cli = parse_cli_with_connect_profiles(
            [
                "connect".to_string(),
                "--listen".to_string(),
                "127.0.0.1:9000".to_string(),
            ],
            ConnectProfileSelection {
                profile_ids: Vec::new(),
                explicit_selection: true,
            },
        )
        .unwrap();

        let CommandKind::Connect(args) = cli.command else {
            panic!("expected connect");
        };
        assert_eq!(args.apply_profile_ids, Vec::<String>::new());
        assert_eq!(args.proxy.listen, "127.0.0.1:9000");
        assert_eq!(args.proxy.traffic_app_ids, Some(Vec::new()));
    }

    #[test]
    fn connect_profile_defaults_can_be_overridden_for_explicit_proxy_tests() {
        let cli = parse_cli_with_active_profiles(
            [
                "connect".to_string(),
                "--apply".to_string(),
                "--listen".to_string(),
                "127.0.0.1:9000".to_string(),
                "--network-mode".to_string(),
                "explicit_proxy".to_string(),
                "--trust-mode".to_string(),
                "disabled".to_string(),
            ],
            vec!["claude-code".to_string()],
        )
        .unwrap();

        let CommandKind::Connect(args) = cli.command else {
            panic!("expected connect");
        };
        assert_eq!(args.apply_profile_ids, vec!["claude-code".to_string()]);
        assert_eq!(args.proxy.network_mode, dam_net::CaptureMode::ExplicitProxy);
        assert_eq!(args.proxy.trust_mode, dam_trust::TrustMode::Disabled);
    }

    #[test]
    fn parses_connect_apply_with_multiple_enabled_profiles() {
        let cli = parse_cli_with_active_profiles(
            [
                "connect".to_string(),
                "--apply".to_string(),
                "--listen".to_string(),
                "127.0.0.1:9000".to_string(),
            ],
            vec!["codex-api".to_string(), "claude-code".to_string()],
        )
        .unwrap();

        let CommandKind::Connect(args) = cli.command else {
            panic!("expected connect");
        };
        assert_eq!(
            args.apply_profile_ids,
            vec!["codex-api".to_string(), "claude-code".to_string()]
        );
        assert_eq!(
            args.proxy.traffic_app_ids,
            Some(vec!["openai-api".to_string(), "anthropic-api".to_string()])
        );
        let targets = args.proxy.targets.unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(args.proxy.trust_mode, dam_trust::TrustMode::LocalCa);
        assert!(
            targets
                .iter()
                .any(|target| target.provider == "openai-compatible")
        );
        assert!(targets.iter().any(|target| target.provider == "anthropic"));
    }

    #[test]
    fn connect_setup_change_ignores_implicit_default_modes_for_existing_daemon() {
        let state = test_daemon_state(
            dam_net::CaptureMode::Tun,
            dam_trust::TrustMode::LocalCa,
            true,
        );
        let proxy = dam_daemon::ProxyOptions::default();

        assert!(!connect_setup_change_requested(&state, &proxy));
    }

    #[test]
    fn connect_setup_change_honors_explicit_mode_flags() {
        let state = test_daemon_state(
            dam_net::CaptureMode::Tun,
            dam_trust::TrustMode::LocalCa,
            true,
        );
        let proxy = dam_daemon::ProxyOptions {
            network_mode: dam_net::CaptureMode::ExplicitProxy,
            network_mode_explicit: true,
            trust_mode: dam_trust::TrustMode::Disabled,
            trust_mode_explicit: true,
            ..dam_daemon::ProxyOptions::default()
        };

        assert!(connect_setup_change_requested(&state, &proxy));
    }

    #[test]
    fn existing_daemon_restart_options_preserve_running_setup() {
        let mut state = test_daemon_state(
            dam_net::CaptureMode::Tun,
            dam_trust::TrustMode::LocalCa,
            true,
        );
        state.listen = "127.0.0.1:9001".to_string();
        state.vault_path = PathBuf::from("/tmp/dam/vault.db");
        state.log_path = Some(PathBuf::from("/tmp/dam/log.db"));
        state.consent_path = Some(PathBuf::from("/tmp/dam/consent.db"));
        state.proxy_targets = vec![
            dam_daemon::DaemonProxyTargetState {
                name: "anthropic".to_string(),
                provider: "anthropic".to_string(),
                upstream: ANTHROPIC_UPSTREAM.to_string(),
            },
            dam_daemon::DaemonProxyTargetState {
                name: "openai".to_string(),
                provider: "openai-compatible".to_string(),
                upstream: OPENAI_API_UPSTREAM.to_string(),
            },
        ];

        let requested = dam_daemon::ProxyOptions::default();
        let proxy = proxy_options_for_existing_daemon(&state, &requested);

        assert_eq!(proxy.listen, "127.0.0.1:9001");
        assert_eq!(proxy.network_mode, dam_net::CaptureMode::Tun);
        assert!(!proxy.network_mode_explicit);
        assert_eq!(proxy.trust_mode, dam_trust::TrustMode::LocalCa);
        assert!(!proxy.trust_mode_explicit);
        assert_eq!(proxy.vault_path, PathBuf::from("/tmp/dam/vault.db"));
        assert_eq!(proxy.log_path, Some(PathBuf::from("/tmp/dam/log.db")));
        assert_eq!(
            proxy.consent_path,
            Some(PathBuf::from("/tmp/dam/consent.db"))
        );
        let targets = proxy.targets.unwrap();
        assert_eq!(targets.len(), 2);
        assert!(targets.iter().any(|target| target.name == "anthropic"));
        assert!(targets.iter().any(|target| target.name == "openai"));
    }

    #[test]
    fn daemon_without_recorded_executable_requires_restart() {
        let mut state = test_daemon_state(
            dam_net::CaptureMode::ExplicitProxy,
            dam_trust::TrustMode::Disabled,
            true,
        );
        state.executable_path = None;

        assert!(!daemon_executable_matches_current(&state).unwrap());
    }

    #[test]
    fn connect_apply_requires_profile_or_enabled_profiles() {
        let error = parse_cli(["connect".to_string(), "--apply".to_string()]).unwrap_err();

        assert!(error.contains("enabled profiles"));
    }

    #[test]
    fn connect_apply_rejects_profile_provider_mismatch() {
        let error = parse_cli([
            "connect".to_string(),
            "--profile".to_string(),
            "claude-code".to_string(),
            "--apply".to_string(),
            "--openai".to_string(),
        ])
        .unwrap_err();

        assert!(error.contains("connect is not configured for that provider"));
    }

    #[test]
    fn connect_apply_rejects_dynamic_port() {
        let options = dam_daemon::ProxyOptions {
            listen: "127.0.0.1:0".to_string(),
            ..dam_daemon::ProxyOptions::default()
        };

        let error = proxy_url_for_connect_apply(&options).unwrap_err();

        assert!(error.contains("fixed --listen port"));
    }

    #[test]
    fn connect_preflight_allows_default_explicit_proxy_setup() {
        let dir = tempfile::tempdir().unwrap();
        let options = dam_daemon::ProxyOptions::default();
        let config = dam_daemon::proxy_config(&options).unwrap();

        ensure_connect_transparent_prerequisites(&options, &config, Some(dir.path().join("state")))
            .unwrap();
    }

    #[test]
    fn connect_preflight_blocks_missing_system_proxy_setup() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("dam.toml");
        std::fs::write(&config_path, "").unwrap();
        let options = dam_daemon::ProxyOptions {
            network_mode: dam_net::CaptureMode::SystemProxy,
            config_path: Some(config_path),
            ..dam_daemon::ProxyOptions::default()
        };
        let config = dam_daemon::proxy_config(&options).unwrap();

        let error = ensure_connect_transparent_prerequisites(
            &options,
            &config,
            Some(dir.path().join("state")),
        )
        .unwrap_err();

        assert!(error.contains("system proxy routing needs to be installed"));
        assert!(error.contains("dam network install-system-proxy"));
        assert!(error.contains("--config"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn connect_preflight_blocks_missing_network_extension_setup() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("dam.toml");
        std::fs::write(&config_path, "").unwrap();
        let options = dam_daemon::ProxyOptions {
            network_mode: dam_net::CaptureMode::Tun,
            config_path: Some(config_path),
            ..dam_daemon::ProxyOptions::default()
        };
        let config = dam_daemon::proxy_config(&options).unwrap();

        let error = ensure_connect_transparent_prerequisites(
            &options,
            &config,
            Some(dir.path().join("state")),
        )
        .unwrap_err();

        assert!(error.contains("Network Extension capture needs to be installed"));
        assert!(error.contains("dam network install-network-extension"));
        assert!(error.contains("--config"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn connect_preflight_blocks_missing_network_extension_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        dam_net_macos::record_system_extension_ready(
            &state_dir,
            "com.rpblc.dam.network-extension",
            None,
            vec!["api.openai.com".to_string()],
        )
        .unwrap();
        let options = dam_daemon::ProxyOptions {
            network_mode: dam_net::CaptureMode::Tun,
            ..dam_daemon::ProxyOptions::default()
        };
        let config = dam_daemon::proxy_config(&options).unwrap();

        let error = ensure_connect_transparent_prerequisites(&options, &config, Some(state_dir))
            .unwrap_err();

        assert!(error.contains("configuration"));
        assert!(error.contains("dam network install-network-extension"));
    }

    #[test]
    fn connect_preflight_blocks_missing_local_ca_setup() {
        let dir = tempfile::tempdir().unwrap();
        let options = dam_daemon::ProxyOptions {
            trust_mode: dam_trust::TrustMode::LocalCa,
            ..dam_daemon::ProxyOptions::default()
        };
        let config = dam_daemon::proxy_config(&options).unwrap();

        let error = ensure_connect_transparent_prerequisites(
            &options,
            &config,
            Some(dir.path().join("state")),
        )
        .unwrap_err();

        assert!(error.contains("local CA"));
        if dam_trust::PlatformTrustStore::current() == dam_trust::PlatformTrustStore::MacosKeychain
        {
            assert!(error.contains("dam trust install-local-ca"));
        } else {
            assert!(error.contains("not implemented"));
        }
    }

    #[test]
    fn parses_integrations_list_json() {
        let cli = parse_cli([
            "integrations".to_string(),
            "list".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            CommandKind::Integrations(IntegrationArgs::List {
                json: true,
                proxy_url: None,
            })
        );
    }

    #[test]
    fn parses_integrations_show_with_proxy_url() {
        let cli = parse_cli([
            "integrations".to_string(),
            "show".to_string(),
            "codex-api".to_string(),
            "--proxy-url".to_string(),
            "http://127.0.0.1:9000".to_string(),
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            CommandKind::Integrations(IntegrationArgs::Show {
                profile_id: "codex-api".to_string(),
                json: false,
                proxy_url: Some("http://127.0.0.1:9000".to_string()),
            })
        );
    }

    #[test]
    fn parses_integrations_apply_with_dry_run_and_target_path() {
        let cli = parse_cli([
            "integrations".to_string(),
            "apply".to_string(),
            "codex-api".to_string(),
            "--dry-run".to_string(),
            "--target-path".to_string(),
            "/tmp/codex.toml".to_string(),
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            CommandKind::Integrations(IntegrationArgs::Apply {
                profile_id: "codex-api".to_string(),
                dry_run: true,
                json: false,
                proxy_url: None,
                target_path: Some(PathBuf::from("/tmp/codex.toml")),
            })
        );
    }

    #[test]
    fn integrations_apply_defaults_to_dry_run_and_requires_write_for_mutation() {
        let preview = parse_cli([
            "integrations".to_string(),
            "apply".to_string(),
            "codex-api".to_string(),
        ])
        .unwrap();

        assert_eq!(
            preview.command,
            CommandKind::Integrations(IntegrationArgs::Apply {
                profile_id: "codex-api".to_string(),
                dry_run: true,
                json: false,
                proxy_url: None,
                target_path: None,
            })
        );

        let write = parse_cli([
            "integrations".to_string(),
            "apply".to_string(),
            "codex-api".to_string(),
            "--write".to_string(),
        ])
        .unwrap();

        assert_eq!(
            write.command,
            CommandKind::Integrations(IntegrationArgs::Apply {
                profile_id: "codex-api".to_string(),
                dry_run: false,
                json: false,
                proxy_url: None,
                target_path: None,
            })
        );
    }

    #[test]
    fn integrations_apply_rejects_dry_run_with_write() {
        let error = parse_cli([
            "integrations".to_string(),
            "apply".to_string(),
            "codex-api".to_string(),
            "--dry-run".to_string(),
            "--write".to_string(),
        ])
        .unwrap_err();

        assert!(error.contains("cannot combine"));
    }

    #[test]
    fn parses_integrations_rollback_json() {
        let cli = parse_cli([
            "integrations".to_string(),
            "rollback".to_string(),
            "codex-api".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            CommandKind::Integrations(IntegrationArgs::Rollback {
                profile_id: "codex-api".to_string(),
                json: true,
            })
        );
    }

    #[test]
    fn integration_profile_render_quotes_spaced_command_args() {
        let profile = dam_integrations::profile("codex-api", "http://127.0.0.1:7828").unwrap();
        let rendered = render_integration_profile(&profile, "http://127.0.0.1:7828");

        assert!(rendered.contains("HTTPS_PROXY=http://127.0.0.1:7828"));
        assert!(rendered.contains("HTTP_PROXY=http://127.0.0.1:7828"));
        assert!(!rendered.contains("dam_openai"));
    }

    #[test]
    fn parses_status_json() {
        let cli = parse_cli(["status".to_string(), "--json".to_string()]).unwrap();

        assert_eq!(cli.command, CommandKind::Status(StatusArgs { json: true }));
    }

    #[test]
    fn parses_logs_filters() {
        let cli = parse_cli([
            "logs".to_string(),
            "--limit".to_string(),
            "5".to_string(),
            "--after-id".to_string(),
            "42".to_string(),
            "--operation".to_string(),
            "abc123".to_string(),
            "--events".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            CommandKind::Logs(LogsArgs {
                json: true,
                limit: 5,
                after_id: Some(42),
                operation_id: Some("abc123".to_string()),
                events: true,
            })
        );
    }

    #[test]
    fn log_summary_collapses_proxy_diagnostics() {
        let entries = vec![
            dam_log::LogEntry {
                id: 3,
                timestamp: 3,
                operation_id: "op".to_string(),
                level: "info".to_string(),
                event_type: "proxy_forward".to_string(),
                kind: None,
                reference: None,
                action: Some("provider_response".to_string()),
                message: "provider response status=200 content_type=text/event-stream content_encoding=none streaming=true".to_string(),
            },
            dam_log::LogEntry {
                id: 2,
                timestamp: 2,
                operation_id: "op".to_string(),
                level: "info".to_string(),
                event_type: "proxy_forward".to_string(),
                kind: None,
                reference: None,
                action: Some("request_protection".to_string()),
                message: "request protection detections=1 replacements=1 tokenized=1 blocked=0".to_string(),
            },
            dam_log::LogEntry {
                id: 1,
                timestamp: 1,
                operation_id: "op".to_string(),
                level: "info".to_string(),
                event_type: "proxy_forward".to_string(),
                kind: None,
                reference: None,
                action: Some("route_decision".to_string()),
                message: "route target=anthropic provider=anthropic protection_enabled=true resolve_inbound=true request_bytes=100".to_string(),
            },
        ];

        let summaries = log_operation_summaries(entries, 10);

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].events, 3);
        assert!(summaries[0].summary.contains("route target=anthropic"));
        assert!(
            summaries[0]
                .summary
                .contains("request protection detections=1")
        );
        assert!(
            summaries[0]
                .summary
                .contains("provider response status=200")
        );
    }

    #[test]
    fn parses_profile_status_json() {
        let cli = parse_cli([
            "profile".to_string(),
            "status".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            CommandKind::Profile(ProfileArgs::Status { json: true })
        );
    }

    #[test]
    fn parses_profile_set_json() {
        let cli = parse_cli([
            "profile".to_string(),
            "set".to_string(),
            "claude-code".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            CommandKind::Profile(ProfileArgs::Set {
                profile_id: "claude-code".to_string(),
                json: true,
            })
        );
    }

    #[test]
    fn parses_profile_clear_json() {
        let cli = parse_cli([
            "profile".to_string(),
            "clear".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            CommandKind::Profile(ProfileArgs::Clear { json: true })
        );
    }

    #[test]
    fn parses_trust_generate_local_ca_json() {
        let cli = parse_cli([
            "trust".to_string(),
            "generate-local-ca".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            CommandKind::Trust(TrustArgs::GenerateArtifact { json: true })
        );
    }

    #[test]
    fn parses_trust_delete_local_ca_json() {
        let cli = parse_cli([
            "trust".to_string(),
            "delete-local-ca".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            CommandKind::Trust(TrustArgs::DeleteArtifact { json: true })
        );
    }

    #[test]
    fn parses_trust_install_and_remove_local_ca_approval() {
        let install = parse_cli([
            "trust".to_string(),
            "install-local-ca".to_string(),
            "--yes".to_string(),
            "--json".to_string(),
        ])
        .unwrap();
        let remove = parse_cli([
            "trust".to_string(),
            "remove-local-ca".to_string(),
            "--yes".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            install.command,
            CommandKind::Trust(TrustArgs::InstallTrust {
                json: true,
                yes: true
            })
        );
        assert_eq!(
            remove.command,
            CommandKind::Trust(TrustArgs::RemoveTrust {
                json: true,
                yes: true
            })
        );
    }

    #[test]
    fn parses_network_install_and_remove_system_proxy_approval() {
        let install = parse_cli([
            "network".to_string(),
            "install-system-proxy".to_string(),
            "--yes".to_string(),
            "--json".to_string(),
        ])
        .unwrap();
        let remove = parse_cli([
            "network".to_string(),
            "remove-system-proxy".to_string(),
            "--yes".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            install.command,
            CommandKind::Network(NetworkArgs::InstallProxy {
                config_path: None,
                json: true,
                yes: true
            })
        );
        assert_eq!(
            remove.command,
            CommandKind::Network(NetworkArgs::RemoveProxy {
                json: true,
                yes: true
            })
        );
    }

    #[test]
    fn parses_network_install_config_path() {
        let cli = parse_cli([
            "network".to_string(),
            "install-system-proxy".to_string(),
            "--config".to_string(),
            "dam.enterprise.toml".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            cli.command,
            CommandKind::Network(NetworkArgs::InstallProxy {
                config_path: Some(PathBuf::from("dam.enterprise.toml")),
                json: true,
                yes: false
            })
        );
    }

    #[test]
    fn parses_network_extension_commands() {
        let install = parse_cli([
            "network".to_string(),
            "install-network-extension".to_string(),
            "--config".to_string(),
            "dam.enterprise.toml".to_string(),
            "--yes".to_string(),
            "--json".to_string(),
        ])
        .unwrap();
        let remove = parse_cli([
            "network".to_string(),
            "remove-network-extension".to_string(),
            "--yes".to_string(),
            "--json".to_string(),
        ])
        .unwrap();
        let status = parse_cli([
            "network".to_string(),
            "status".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            install.command,
            CommandKind::Network(NetworkArgs::InstallNetworkExtension {
                config_path: Some(PathBuf::from("dam.enterprise.toml")),
                json: true,
                yes: true
            })
        );
        assert_eq!(
            remove.command,
            CommandKind::Network(NetworkArgs::RemoveNetworkExtension {
                json: true,
                yes: true
            })
        );
        assert_eq!(
            status.command,
            CommandKind::Network(NetworkArgs::Status { json: true })
        );
    }

    #[test]
    fn parses_startup_commands() {
        let status = parse_cli([
            "startup".to_string(),
            "status".to_string(),
            "--json".to_string(),
        ])
        .unwrap();
        let skip = parse_cli([
            "startup".to_string(),
            "skip-open-at-login".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            status.command,
            CommandKind::Startup(StartupArgs::Status { json: true })
        );
        assert_eq!(
            skip.command,
            CommandKind::Startup(StartupArgs::SkipOpenAtLogin { json: true })
        );
    }

    #[test]
    fn startup_skip_open_at_login_records_marker() {
        let dir = tempfile::tempdir().unwrap();
        let marker = write_startup_skip_marker(dir.path()).unwrap();

        assert!(marker.exists());
        let view = startup_status_view(dir.path());
        assert_eq!(view.state, "skipped");
        assert_eq!(view.marker, Some(marker));
    }

    #[test]
    fn local_ca_generate_and_delete_outputs_do_not_install_local_trust() {
        let dir = tempfile::tempdir().unwrap();

        let generated = generate_local_ca_output(dir.path(), false).unwrap();
        assert!(generated.contains("state: generated"));
        assert!(generated.contains("local_trust: unchanged"));
        assert!(generated.contains("fingerprint_sha256: "));

        let deleted = delete_local_ca_output(dir.path(), false).unwrap();
        assert!(deleted.contains("state: deleted"));
        assert!(deleted.contains("local_trust: unchanged"));

        let missing = delete_local_ca_output(dir.path(), true).unwrap();
        let report: serde_json::Value = serde_json::from_str(&missing).unwrap();
        assert_eq!(report["state"], "missing");
        assert_eq!(report["deleted"], false);
    }

    #[test]
    fn local_ca_install_and_remove_preview_require_approval() {
        let dir = tempfile::tempdir().unwrap();

        let install = install_local_ca_output(dir.path(), false, false).unwrap();
        assert!(install.contains("state: preview"));
        assert!(install.contains("will_generate_artifact: true"));
        assert!(install.contains("local_trust: unchanged"));
        assert!(install.contains("approval: rerun with --yes"));

        let generated = generate_local_ca_output(dir.path(), false).unwrap();
        assert!(generated.contains("state: generated"));

        let remove = remove_local_ca_output(dir.path(), true, false).unwrap();
        let report: serde_json::Value = serde_json::from_str(&remove).unwrap();
        assert_eq!(report["state"], "preview");
        assert_eq!(report["system_trust_changed"], false);
        assert_eq!(report["plan"]["can_execute"], false);
    }

    #[test]
    fn parses_daemon_run_as_internal_proxy_options() {
        let cli = parse_cli([
            "daemon-run".to_string(),
            "--target-name".to_string(),
            "xai".to_string(),
            "--provider".to_string(),
            "openai-compatible".to_string(),
            "--upstream".to_string(),
            "https://api.x.ai".to_string(),
        ])
        .unwrap();

        let CommandKind::DaemonRun(args) = cli.command else {
            panic!("expected daemon run");
        };
        assert_eq!(args.target_name, "xai");
        assert_eq!(args.upstream, "https://api.x.ai");
    }

    fn test_daemon_state(
        network_mode: dam_net::CaptureMode,
        trust_mode: dam_trust::TrustMode,
        protection_enabled: bool,
    ) -> dam_daemon::DaemonState {
        dam_daemon::DaemonState {
            version: 4,
            pid: 1,
            executable_path: Some(PathBuf::from("/usr/local/bin/dam")),
            executable_sha256: Some("abc123".to_string()),
            listen: "127.0.0.1:7828".to_string(),
            proxy_url: "http://127.0.0.1:7828".to_string(),
            config_path: None,
            vault_path: PathBuf::from("vault.db"),
            log_path: Some(PathBuf::from("log.db")),
            consent_path: Some(PathBuf::from("consent.db")),
            resolve_inbound: true,
            target_name: Some("openai".to_string()),
            target_provider: Some("openai-compatible".to_string()),
            upstream: Some(OPENAI_API_UPSTREAM.to_string()),
            proxy_targets: Vec::new(),
            started_at_unix: 0,
            network_mode,
            transparent_ai_routes: Vec::new(),
            transparent_ai_routing_readiness: Vec::new(),
            trust: dam_trust::TrustState {
                mode: trust_mode,
                ..dam_trust::TrustState::default()
            },
            transparent_ai_trust_readiness: Vec::new(),
            transparent_ai_interception_readiness: Vec::new(),
            protection_enabled,
            protection_started_at_unix: if protection_enabled { Some(0) } else { None },
        }
    }
}
