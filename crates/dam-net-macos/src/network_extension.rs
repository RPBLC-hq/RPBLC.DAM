use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

const NETWORK_EXTENSION_DIR: &str = "network/macos-network-extension";
const STATE_FILE: &str = "latest.json";
const STATE_VERSION: u32 = 1;
const HELPER_ENV: &str = "DAM_MACOS_NE_HELPER";
const BUNDLE_ID_ENV: &str = "DAM_MACOS_NE_BUNDLE_ID";
const TEAM_ID_ENV: &str = "DAM_MACOS_NE_TEAM_ID";
const PROXY_HOST_ENV: &str = "DAM_MACOS_NE_PROXY_HOST";
const PROXY_PORT_ENV: &str = "DAM_MACOS_NE_PROXY_PORT";
const EXCLUDED_SIGNING_IDS_ENV: &str = "DAM_MACOS_NE_EXCLUDED_SIGNING_IDS";
const DEFAULT_BUNDLE_ID: &str = "com.rpblc.dam.network-extension";
const DEFAULT_PROXY_HOST: &str = "127.0.0.1";
const DEFAULT_PROXY_PORT: &str = "7828";
const DEFAULT_EXCLUDED_SIGNING_IDENTIFIERS: &[&str] = &[
    "com.rpblc.dam",
    "com.rpblc.dam.daemon",
    "com.rpblc.dam.proxy",
    "com.rpblc.dam.tray",
    "com.rpblc.dam.network-extension",
    "com.rpblc.dam.helper",
];

#[derive(Debug, thiserror::Error)]
pub enum MacosNetworkExtensionError {
    #[error("macOS Network Extension support is not implemented for this platform")]
    UnsupportedPlatform,

    #[error("failed to create Network Extension state directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to read Network Extension state {path}: {source}")]
    ReadState {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse Network Extension state {path}: {source}")]
    ParseState {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[error("failed to serialize Network Extension state: {0}")]
    SerializeState(serde_json::Error),

    #[error("failed to write Network Extension state file {path}: {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to delete Network Extension state file {path}: {source}")]
    DeleteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to run Network Extension helper {program}: {source}")]
    RunHelper {
        program: String,
        source: std::io::Error,
    },

    #[error(
        "macOS Network Extension helper is required to configure capture for {bundle_identifier}; set DAM_MACOS_NE_HELPER in source builds or use the signed app bundle"
    )]
    MissingHelper { bundle_identifier: String },

    #[error("Network Extension helper failed ({status}): {program} {args}; {stderr}")]
    HelperFailed {
        program: String,
        args: String,
        status: String,
        stderr: String,
    },

    #[error("system clock is before unix epoch")]
    Clock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosNetworkExtensionPaths {
    pub directory: PathBuf,
    pub state_path: PathBuf,
}

impl MacosNetworkExtensionPaths {
    pub fn for_state_dir(state_dir: impl AsRef<Path>) -> Self {
        let directory = state_dir.as_ref().join(NETWORK_EXTENSION_DIR);
        Self {
            state_path: directory.join(STATE_FILE),
            directory,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosNetworkExtensionStateRecord {
    pub version: u32,
    pub bundle_identifier: String,
    pub team_identifier: Option<String>,
    pub ai_hosts: Vec<String>,
    pub installed_at_unix: u64,
    pub active: bool,
    pub activation_method: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosNetworkExtensionAction {
    Install,
    Remove,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosNetworkExtensionSupport {
    Implemented,
    Planned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosNetworkExtensionResultState {
    Preview,
    Installed,
    AlreadyInstalled,
    NeedsApproval,
    Removed,
    NotInstalled,
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosNetworkExtensionCommand {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosNetworkExtensionPlan {
    pub action: MacosNetworkExtensionAction,
    pub support: MacosNetworkExtensionSupport,
    pub paths: MacosNetworkExtensionPaths,
    pub bundle_identifier: String,
    pub team_identifier: Option<String>,
    pub ai_hosts: Vec<String>,
    pub commands: Vec<MacosNetworkExtensionCommand>,
    pub requires_admin: bool,
    pub changes_system_routes: bool,
    pub can_execute: bool,
    pub helper_required_for_release: bool,
    pub message: String,
    pub backend_status: dam_net::CaptureBackendStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosNetworkExtensionResult {
    pub state: MacosNetworkExtensionResultState,
    pub plan: MacosNetworkExtensionPlan,
    pub record: Option<MacosNetworkExtensionStateRecord>,
    pub system_routes_changed: bool,
}

pub fn network_extension_installed(state_dir: impl AsRef<Path>) -> bool {
    read_record(&MacosNetworkExtensionPaths::for_state_dir(state_dir))
        .ok()
        .flatten()
        .is_some()
}

pub fn network_extension_active(state_dir: impl AsRef<Path>) -> bool {
    read_record(&MacosNetworkExtensionPaths::for_state_dir(state_dir))
        .ok()
        .flatten()
        .map(|record| record.active)
        .unwrap_or(false)
}

pub fn preview_install_network_extension(
    state_dir: impl AsRef<Path>,
) -> Result<MacosNetworkExtensionResult, MacosNetworkExtensionError> {
    let hosts = default_ai_hosts();
    preview_install_network_extension_for_hosts(state_dir, &hosts)
}

pub fn preview_install_network_extension_for_hosts(
    state_dir: impl AsRef<Path>,
    ai_hosts: &[String],
) -> Result<MacosNetworkExtensionResult, MacosNetworkExtensionError> {
    ensure_macos()?;
    let plan = install_plan_for_hosts(state_dir, ai_hosts)?;
    let record = read_record(&plan.paths)?;
    Ok(MacosNetworkExtensionResult {
        state: match record.as_ref().map(|record| record.active) {
            Some(true) => MacosNetworkExtensionResultState::AlreadyInstalled,
            Some(false) => MacosNetworkExtensionResultState::NeedsApproval,
            None => MacosNetworkExtensionResultState::Preview,
        },
        record,
        plan,
        system_routes_changed: false,
    })
}

pub fn install_network_extension(
    state_dir: impl AsRef<Path>,
) -> Result<MacosNetworkExtensionResult, MacosNetworkExtensionError> {
    let hosts = default_ai_hosts();
    install_network_extension_for_hosts(state_dir, &hosts)
}

pub fn install_network_extension_for_hosts(
    state_dir: impl AsRef<Path>,
    ai_hosts: &[String],
) -> Result<MacosNetworkExtensionResult, MacosNetworkExtensionError> {
    ensure_macos()?;
    let plan = install_plan_for_hosts(&state_dir, ai_hosts)?;
    if !plan.can_execute {
        if !plan.backend_status.active && plan.commands.is_empty() {
            return Err(MacosNetworkExtensionError::MissingHelper {
                bundle_identifier: plan.bundle_identifier,
            });
        }
        return Ok(MacosNetworkExtensionResult {
            state: MacosNetworkExtensionResultState::AlreadyInstalled,
            record: read_record(&plan.paths)?,
            plan,
            system_routes_changed: false,
        });
    }

    for command in &plan.commands {
        run_helper_command(command)?;
    }

    let record = MacosNetworkExtensionStateRecord {
        version: STATE_VERSION,
        bundle_identifier: plan.bundle_identifier.clone(),
        team_identifier: plan.team_identifier.clone(),
        ai_hosts: plan.ai_hosts.clone(),
        installed_at_unix: unix_timestamp()?,
        active: true,
        activation_method: "app_owned_system_extension_native_helper_config".to_string(),
    };
    write_state_record(&plan.paths, &record)?;

    Ok(MacosNetworkExtensionResult {
        state: MacosNetworkExtensionResultState::Installed,
        plan,
        record: Some(record),
        system_routes_changed: true,
    })
}

pub fn preview_remove_network_extension(
    state_dir: impl AsRef<Path>,
) -> Result<MacosNetworkExtensionResult, MacosNetworkExtensionError> {
    ensure_macos()?;
    let plan = remove_plan(state_dir)?;
    let record = read_record(&plan.paths)?;
    Ok(MacosNetworkExtensionResult {
        state: if record.is_some() {
            MacosNetworkExtensionResultState::Preview
        } else {
            MacosNetworkExtensionResultState::NotInstalled
        },
        record,
        plan,
        system_routes_changed: false,
    })
}

pub fn remove_network_extension(
    state_dir: impl AsRef<Path>,
) -> Result<MacosNetworkExtensionResult, MacosNetworkExtensionError> {
    ensure_macos()?;
    let plan = remove_plan(state_dir)?;
    let record = read_record(&plan.paths)?;
    if record.is_none() {
        return Ok(MacosNetworkExtensionResult {
            state: MacosNetworkExtensionResultState::NotInstalled,
            plan,
            record: None,
            system_routes_changed: false,
        });
    }
    if !plan.can_execute {
        return Err(MacosNetworkExtensionError::MissingHelper {
            bundle_identifier: plan.bundle_identifier,
        });
    }

    for command in &plan.commands {
        run_helper_command(command)?;
    }
    delete_if_exists(&plan.paths.state_path)?;

    Ok(MacosNetworkExtensionResult {
        state: MacosNetworkExtensionResultState::Removed,
        plan,
        record,
        system_routes_changed: true,
    })
}

pub fn network_extension_status(
    state_dir: impl AsRef<Path>,
) -> Result<MacosNetworkExtensionResult, MacosNetworkExtensionError> {
    let paths = MacosNetworkExtensionPaths::for_state_dir(state_dir);
    let mut record = read_record(&paths)?;
    let mut live_message = None;
    if let Some(existing) = record.as_mut() {
        let command = helper_command(
            "status",
            &existing.bundle_identifier,
            existing.team_identifier.as_deref(),
            &[],
        )
        .into_iter()
        .next();
        if let Some(command) = command {
            let status = run_helper_status_command(&command)?;
            live_message = Some(status.message.clone());
            existing.active = status.active;
            write_state_record(&paths, existing)?;
        } else {
            existing.active = false;
            live_message = Some(
                "macOS Network Extension helper is unavailable; live capture status cannot be verified"
                    .to_string(),
            );
            write_state_record(&paths, existing)?;
        }
    }
    let plan = status_plan(paths, record.as_ref(), live_message);
    Ok(MacosNetworkExtensionResult {
        state: MacosNetworkExtensionResultState::Status,
        plan,
        record,
        system_routes_changed: false,
    })
}

fn install_plan_for_hosts(
    state_dir: impl AsRef<Path>,
    ai_hosts: &[String],
) -> Result<MacosNetworkExtensionPlan, MacosNetworkExtensionError> {
    let paths = MacosNetworkExtensionPaths::for_state_dir(state_dir);
    let record = read_record(&paths)?;
    let ai_hosts = normalized_ai_hosts(ai_hosts);
    let bundle_identifier = bundle_identifier();
    let team_identifier = team_identifier();
    let installed = record.as_ref().is_some_and(|record| record.active);
    let pending_approval = record.as_ref().is_some_and(|record| !record.active);
    let commands = helper_command(
        "install",
        &bundle_identifier,
        team_identifier.as_deref(),
        &ai_hosts,
    );
    let support = support();
    let can_execute =
        support == MacosNetworkExtensionSupport::Implemented && !installed && !commands.is_empty();
    let message = if installed {
        "macOS Network Extension capture is already recorded active".to_string()
    } else if pending_approval {
        "macOS Network Extension activation is waiting for user approval".to_string()
    } else if commands.is_empty() {
        "packaged macOS Network Extension helper is required before capture can be configured"
            .to_string()
    } else {
        "will ask the packaged macOS helper to configure Network Extension capture".to_string()
    };
    let backend_status = backend_status_from_record(record.as_ref(), message.clone());

    Ok(MacosNetworkExtensionPlan {
        action: MacosNetworkExtensionAction::Install,
        support,
        paths,
        bundle_identifier,
        team_identifier,
        ai_hosts,
        commands,
        requires_admin: true,
        changes_system_routes: true,
        can_execute,
        helper_required_for_release: true,
        message,
        backend_status,
    })
}

fn remove_plan(
    state_dir: impl AsRef<Path>,
) -> Result<MacosNetworkExtensionPlan, MacosNetworkExtensionError> {
    let paths = MacosNetworkExtensionPaths::for_state_dir(state_dir);
    let record = read_record(&paths)?;
    let bundle_identifier = record
        .as_ref()
        .map(|record| record.bundle_identifier.clone())
        .unwrap_or_else(bundle_identifier);
    let team_identifier = record
        .as_ref()
        .and_then(|record| record.team_identifier.clone())
        .or_else(team_identifier);
    let commands = helper_command(
        "remove",
        &bundle_identifier,
        team_identifier.as_deref(),
        &[],
    );
    let support = support();
    let can_execute = support == MacosNetworkExtensionSupport::Implemented
        && record.is_some()
        && !commands.is_empty();
    let message = if record.is_some() {
        if commands.is_empty() {
            "packaged macOS Network Extension helper is required before capture can be removed"
                .to_string()
        } else {
            "will ask the packaged macOS helper to deactivate Network Extension capture".to_string()
        }
    } else {
        "no DAM macOS Network Extension capture state exists".to_string()
    };
    let backend_status = backend_status_from_record(record.as_ref(), message.clone());

    Ok(MacosNetworkExtensionPlan {
        action: MacosNetworkExtensionAction::Remove,
        support,
        paths,
        bundle_identifier,
        team_identifier,
        ai_hosts: record
            .as_ref()
            .map(|record| record.ai_hosts.clone())
            .unwrap_or_default(),
        commands,
        requires_admin: true,
        changes_system_routes: true,
        can_execute,
        helper_required_for_release: true,
        message,
        backend_status,
    })
}

fn status_plan(
    paths: MacosNetworkExtensionPaths,
    record: Option<&MacosNetworkExtensionStateRecord>,
    live_message: Option<String>,
) -> MacosNetworkExtensionPlan {
    let commands = record
        .map(|record| {
            helper_command(
                "status",
                &record.bundle_identifier,
                record.team_identifier.as_deref(),
                &[],
            )
        })
        .unwrap_or_default();
    let can_execute = !commands.is_empty();
    let message = live_message.unwrap_or_else(|| {
        record
            .map(|record| {
                if record.active {
                    "macOS Network Extension capture is recorded active"
                } else {
                    "macOS Network Extension capture is recorded inactive"
                }
            })
            .unwrap_or("macOS Network Extension capture is not installed")
            .to_string()
    });
    MacosNetworkExtensionPlan {
        action: MacosNetworkExtensionAction::Status,
        support: support(),
        paths,
        bundle_identifier: record
            .map(|record| record.bundle_identifier.clone())
            .unwrap_or_else(bundle_identifier),
        team_identifier: record
            .and_then(|record| record.team_identifier.clone())
            .or_else(team_identifier),
        ai_hosts: record
            .map(|record| record.ai_hosts.clone())
            .unwrap_or_default(),
        commands,
        requires_admin: false,
        changes_system_routes: false,
        can_execute,
        helper_required_for_release: true,
        backend_status: backend_status_from_record(record, message.clone()),
        message,
    }
}

fn backend_status_from_record(
    record: Option<&MacosNetworkExtensionStateRecord>,
    message: String,
) -> dam_net::CaptureBackendStatus {
    match record {
        Some(record) if record.active => dam_net::CaptureBackendStatus {
            kind: dam_net::CaptureBackendKind::MacosNetworkExtension,
            platform: dam_net::CapturePlatform::Macos,
            mode: dam_net::CaptureMode::Tun,
            support: dam_net::CaptureSupport::Implemented,
            installed: true,
            active: true,
            requires_admin: true,
            changes_system_routes: true,
            rollback_available: true,
            readiness: dam_net::CaptureBackendReadiness::Ready,
            message,
        },
        Some(_) => dam_net::CaptureBackendStatus {
            kind: dam_net::CaptureBackendKind::MacosNetworkExtension,
            platform: dam_net::CapturePlatform::Macos,
            mode: dam_net::CaptureMode::Tun,
            support: dam_net::CaptureSupport::Implemented,
            installed: true,
            active: false,
            requires_admin: true,
            changes_system_routes: true,
            rollback_available: true,
            readiness: dam_net::CaptureBackendReadiness::NeedsApproval,
            message,
        },
        None => dam_net::CaptureBackendStatus {
            kind: dam_net::CaptureBackendKind::MacosNetworkExtension,
            platform: dam_net::CapturePlatform::Macos,
            mode: dam_net::CaptureMode::Tun,
            support: if cfg!(target_os = "macos") {
                dam_net::CaptureSupport::Implemented
            } else {
                dam_net::CaptureSupport::Planned
            },
            installed: false,
            active: false,
            requires_admin: true,
            changes_system_routes: true,
            rollback_available: false,
            readiness: dam_net::CaptureBackendReadiness::NeedsInstall,
            message,
        },
    }
}

fn helper_command(
    action: &str,
    bundle_identifier: &str,
    team_identifier: Option<&str>,
    ai_hosts: &[String],
) -> Vec<MacosNetworkExtensionCommand> {
    let Some(helper) = helper_path() else {
        return Vec::new();
    };
    let mut args = vec![
        action.to_string(),
        "--bundle-id".to_string(),
        bundle_identifier.to_string(),
    ];
    if let Some(team_identifier) = team_identifier {
        args.extend(["--team-id".to_string(), team_identifier.to_string()]);
    }
    if action == "install" {
        args.extend(["--proxy-host".to_string(), proxy_host()]);
        args.extend(["--proxy-port".to_string(), proxy_port()]);
        for host in ai_hosts {
            args.extend(["--protect-host".to_string(), host.to_string()]);
        }
        for identifier in excluded_signing_identifiers() {
            args.extend(["--exclude-signing-id".to_string(), identifier]);
        }
    }
    vec![MacosNetworkExtensionCommand {
        program: helper.display().to_string(),
        args,
    }]
}

fn helper_path() -> Option<PathBuf> {
    if let Some(helper) = env::var_os(HELPER_ENV).filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(helper));
    }

    let exe = env::current_exe().ok()?;
    let exe_dir = exe.parent()?;
    helper_path_candidates(exe_dir)
        .into_iter()
        .find(|path| path.is_file())
}

fn helper_path_candidates(exe_dir: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![
        exe_dir.join("dam-macos-ne-helper"),
        exe_dir.join("Helpers").join("dam-macos-ne-helper"),
    ];
    if let Some(contents_dir) = exe_dir.parent() {
        candidates.push(
            contents_dir
                .join("Helpers")
                .join("DAMMacosNEHelper.app")
                .join("Contents")
                .join("MacOS")
                .join("dam-macos-ne-helper"),
        );
    }
    candidates
}

fn run_helper_command(
    command: &MacosNetworkExtensionCommand,
) -> Result<(), MacosNetworkExtensionError> {
    let output = Command::new(&command.program)
        .args(&command.args)
        .output()
        .map_err(|source| MacosNetworkExtensionError::RunHelper {
            program: command.program.clone(),
            source,
        })?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.starts_with("needs_user_approval ") {
            return Err(MacosNetworkExtensionError::HelperFailed {
                program: command.program.clone(),
                args: command.args.join(" "),
                status: "needs_user_approval".to_string(),
                stderr: stdout,
            });
        }
        return Ok(());
    }
    let mut stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() && was_sigkill(&output.status) {
        stderr = "macOS killed the Network Extension helper before it could run; the installed app provisioning profile likely does not authorize a restricted entitlement such as com.apple.developer.networking.networkextension or com.apple.security.application-groups".to_string();
    }
    Err(MacosNetworkExtensionError::HelperFailed {
        program: command.program.clone(),
        args: command.args.join(" "),
        status: output.status.to_string(),
        stderr,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HelperLiveStatus {
    active: bool,
    message: String,
}

fn run_helper_status_command(
    command: &MacosNetworkExtensionCommand,
) -> Result<HelperLiveStatus, MacosNetworkExtensionError> {
    let output = Command::new(&command.program)
        .args(&command.args)
        .output()
        .map_err(|source| MacosNetworkExtensionError::RunHelper {
            program: command.program.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(MacosNetworkExtensionError::HelperFailed {
            program: command.program.clone(),
            args: command.args.join(" "),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(parse_helper_status(&stdout))
}

fn parse_helper_status(output: &str) -> HelperLiveStatus {
    let lower = output.to_ascii_lowercase();
    let active = lower.split_whitespace().any(|part| part == "connected");
    let message = if output.trim().is_empty() {
        "macOS Network Extension helper returned an empty live status".to_string()
    } else {
        format!("macOS Network Extension live status: {}", output.trim())
    };
    HelperLiveStatus { active, message }
}

#[cfg(unix)]
fn was_sigkill(status: &std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt;

    status.signal() == Some(9)
}

#[cfg(not(unix))]
fn was_sigkill(_status: &std::process::ExitStatus) -> bool {
    false
}

fn write_state_record(
    paths: &MacosNetworkExtensionPaths,
    record: &MacosNetworkExtensionStateRecord,
) -> Result<(), MacosNetworkExtensionError> {
    fs::create_dir_all(&paths.directory).map_err(|source| {
        MacosNetworkExtensionError::CreateDir {
            path: paths.directory.clone(),
            source,
        }
    })?;
    let raw =
        serde_json::to_vec_pretty(record).map_err(MacosNetworkExtensionError::SerializeState)?;
    write_atomic(&paths.state_path, &raw, 0o600)
}

fn read_record(
    paths: &MacosNetworkExtensionPaths,
) -> Result<Option<MacosNetworkExtensionStateRecord>, MacosNetworkExtensionError> {
    if !paths.state_path.exists() {
        return Ok(None);
    }
    let raw =
        fs::read(&paths.state_path).map_err(|source| MacosNetworkExtensionError::ReadState {
            path: paths.state_path.clone(),
            source,
        })?;
    serde_json::from_slice(&raw).map(Some).map_err(|source| {
        MacosNetworkExtensionError::ParseState {
            path: paths.state_path.clone(),
            source,
        }
    })
}

fn write_atomic(
    path: &Path,
    bytes: &[u8],
    #[allow(unused_variables)] unix_mode: u32,
) -> Result<(), MacosNetworkExtensionError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| MacosNetworkExtensionError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let temp_path = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("dam-net-macos-ne"),
        uuid::Uuid::new_v4().simple()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(unix_mode);
    }
    let result = (|| -> std::io::Result<()> {
        let mut file = options.open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp_path, path)?;
        Ok(())
    })();
    if let Err(source) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(MacosNetworkExtensionError::WriteFile {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

fn delete_if_exists(path: &Path) -> Result<(), MacosNetworkExtensionError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(MacosNetworkExtensionError::DeleteFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn default_ai_hosts() -> Vec<String> {
    dam_net::known_ai_hosts()
}

fn normalized_ai_hosts(hosts: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for host in hosts {
        let host = dam_net::normalize_ai_host(host);
        if !host.is_empty() && !normalized.contains(&host) {
            normalized.push(host);
        }
    }
    normalized
}

fn bundle_identifier() -> String {
    env::var(BUNDLE_ID_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BUNDLE_ID.to_string())
}

fn team_identifier() -> Option<String> {
    env::var(TEAM_ID_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn proxy_host() -> String {
    env::var(PROXY_HOST_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_PROXY_HOST.to_string())
}

fn proxy_port() -> String {
    env::var(PROXY_PORT_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| value.parse::<u16>().is_ok())
        .unwrap_or_else(|| DEFAULT_PROXY_PORT.to_string())
}

fn excluded_signing_identifiers() -> Vec<String> {
    env::var(EXCLUDED_SIGNING_IDS_ENV)
        .ok()
        .map(|raw| {
            raw.split([',', ';'])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty())
        .unwrap_or_else(|| {
            DEFAULT_EXCLUDED_SIGNING_IDENTIFIERS
                .iter()
                .map(|value| value.to_string())
                .collect()
        })
}

fn support() -> MacosNetworkExtensionSupport {
    if cfg!(target_os = "macos") {
        MacosNetworkExtensionSupport::Implemented
    } else {
        MacosNetworkExtensionSupport::Planned
    }
}

fn ensure_macos() -> Result<(), MacosNetworkExtensionError> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        Err(MacosNetworkExtensionError::UnsupportedPlatform)
    }
}

fn unix_timestamp() -> Result<u64, MacosNetworkExtensionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| MacosNetworkExtensionError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::{Mutex, MutexGuard};

    static HELPER_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct HelperEnvGuard {
        _lock: MutexGuard<'static, ()>,
        _temp: Option<tempfile::TempDir>,
    }

    impl HelperEnvGuard {
        fn install() -> Self {
            use std::os::unix::fs::PermissionsExt;

            let temp = tempfile::tempdir().unwrap();
            let helper = temp.path().join("helper.sh");
            fs::write(
                &helper,
                "#!/bin/sh\nif [ \"$1\" = \"status\" ]; then echo \"enabled com.rpblc.dam.network-extension connected\"; fi\nexit 0\n",
            )
            .unwrap();
            fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
            let mut guard = Self::with_helper_path(&helper);
            guard._temp = Some(temp);
            guard
        }

        fn with_helper_path(path: &Path) -> Self {
            let lock = HELPER_ENV_LOCK.lock().unwrap();
            unsafe {
                env::set_var(HELPER_ENV, path);
            }
            Self {
                _lock: lock,
                _temp: None,
            }
        }
    }

    impl Drop for HelperEnvGuard {
        fn drop(&mut self) {
            unsafe {
                env::remove_var(HELPER_ENV);
            }
        }
    }

    #[test]
    fn status_reports_needs_install_without_state() {
        let dir = tempfile::tempdir().unwrap();
        let result = network_extension_status(dir.path()).unwrap();

        assert_eq!(result.state, MacosNetworkExtensionResultState::Status);
        assert_eq!(
            result.plan.backend_status.readiness,
            dam_net::CaptureBackendReadiness::NeedsInstall
        );
        assert!(!result.plan.backend_status.active);
    }

    #[test]
    fn install_records_active_network_extension_state() {
        let _helper = HelperEnvGuard::install();
        let dir = tempfile::tempdir().unwrap();
        let result =
            install_network_extension_for_hosts(dir.path(), &["api.openai.com".to_string()])
                .unwrap();

        assert_eq!(result.state, MacosNetworkExtensionResultState::Installed);
        assert!(network_extension_installed(dir.path()));
        assert!(network_extension_active(dir.path()));
        let status = network_extension_status(dir.path()).unwrap();
        assert_eq!(
            status.plan.backend_status.readiness,
            dam_net::CaptureBackendReadiness::Ready
        );
        assert_eq!(status.record.unwrap().ai_hosts, vec!["api.openai.com"]);
    }

    #[test]
    fn helper_needs_user_approval_fails_without_recording_pending_state() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("helper.sh");
        fs::write(
            &helper,
            "#!/bin/sh\necho 'needs_user_approval com.rpblc.dam.network-extension approve DAM Network Protection in System Settings'\n",
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();

        let _helper = HelperEnvGuard::with_helper_path(&helper);
        let error =
            install_network_extension_for_hosts(dir.path(), &["api.openai.com".to_string()])
                .unwrap_err();

        assert!(error.to_string().contains("needs_user_approval"));
        assert!(!network_extension_installed(dir.path()));
        assert!(!network_extension_active(dir.path()));
    }

    #[cfg(unix)]
    #[test]
    fn helper_sigkill_reports_likely_restricted_entitlement_failure() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("helper.sh");
        fs::write(&helper, "#!/bin/sh\nkill -9 $$\n").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();

        let _helper = HelperEnvGuard::with_helper_path(&helper);
        let error =
            install_network_extension_for_hosts(dir.path(), &["api.openai.com".to_string()])
                .unwrap_err();
        let message = error.to_string();

        assert!(message.contains("signal: 9"));
        assert!(message.contains("provisioning profile likely does not authorize"));
        assert!(message.contains("com.apple.developer.networking.networkextension"));
        assert!(!network_extension_installed(dir.path()));
    }

    #[test]
    fn install_plan_passes_runtime_configuration_to_helper() {
        let _helper = HelperEnvGuard::install();
        let dir = tempfile::tempdir().unwrap();
        let result = preview_install_network_extension_for_hosts(
            dir.path(),
            &["API.OpenAI.com.".to_string()],
        )
        .unwrap();
        let command = result.plan.commands.first().unwrap();

        assert!(command.args.contains(&"--proxy-host".to_string()));
        assert!(command.args.contains(&"127.0.0.1".to_string()));
        assert!(command.args.contains(&"--proxy-port".to_string()));
        assert!(command.args.contains(&"7828".to_string()));
        assert!(command.args.contains(&"--protect-host".to_string()));
        assert!(command.args.contains(&"api.openai.com".to_string()));
        assert!(command.args.contains(&"--exclude-signing-id".to_string()));
        assert!(command.args.contains(&"com.rpblc.dam.proxy".to_string()));
    }

    #[test]
    fn helper_path_candidates_include_packaged_helper_app_wrapper() {
        let candidates = helper_path_candidates(Path::new("/Applications/DAM.app/Contents/MacOS"));

        assert!(candidates.contains(&PathBuf::from(
            "/Applications/DAM.app/Contents/Helpers/DAMMacosNEHelper.app/Contents/MacOS/dam-macos-ne-helper"
        )));
    }

    #[test]
    fn remove_deletes_network_extension_state() {
        let _helper = HelperEnvGuard::install();
        let dir = tempfile::tempdir().unwrap();
        install_network_extension(dir.path()).unwrap();

        let removed = remove_network_extension(dir.path()).unwrap();

        assert_eq!(removed.state, MacosNetworkExtensionResultState::Removed);
        assert!(!network_extension_installed(dir.path()));
        assert!(!network_extension_active(dir.path()));
    }

    #[test]
    fn status_reconciles_record_when_helper_reports_disconnected() {
        use std::os::unix::fs::PermissionsExt;

        let active_helper = HelperEnvGuard::install();
        let dir = tempfile::tempdir().unwrap();
        install_network_extension(dir.path()).unwrap();
        drop(active_helper);

        let helper = dir.path().join("status-helper.sh");
        fs::write(
            &helper,
            "#!/bin/sh\nif [ \"$1\" = \"status\" ]; then echo \"enabled com.rpblc.dam.network-extension disconnected\"; fi\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let _helper = HelperEnvGuard::with_helper_path(&helper);

        let status = network_extension_status(dir.path()).unwrap();

        assert!(!status.record.unwrap().active);
        assert!(!network_extension_active(dir.path()));
        assert_eq!(
            status.plan.backend_status.readiness,
            dam_net::CaptureBackendReadiness::NeedsApproval
        );
    }

    #[test]
    fn remove_requires_helper_when_record_exists() {
        let _helper = HelperEnvGuard::install();
        let dir = tempfile::tempdir().unwrap();
        install_network_extension(dir.path()).unwrap();
        unsafe {
            env::remove_var(HELPER_ENV);
        }

        let error = remove_network_extension(dir.path()).unwrap_err();

        assert!(error.to_string().contains("helper is required"));
        assert!(network_extension_installed(dir.path()));
    }
}
