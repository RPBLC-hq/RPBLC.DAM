use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const NETWORK_DIR: &str = "network/macos-system-proxy";
const ROLLBACK_FILE: &str = "latest.json";
const PAC_FILE: &str = "dam-ai-proxy.pac";
const RECORD_VERSION: u32 = 1;
const NETWORKSETUP: &str = "/usr/sbin/networksetup";

#[derive(Debug, thiserror::Error)]
pub enum MacosNetworkError {
    #[error("macOS system proxy support is not implemented for this platform")]
    UnsupportedPlatform,

    #[error("failed to create network state directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("macOS system proxy rollback record already exists at {0}")]
    AlreadyApplied(PathBuf),

    #[error("failed to read network rollback record {path}: {source}")]
    ReadRollback {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse network rollback record {path}: {source}")]
    ParseRollback {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[error("failed to serialize network rollback record: {0}")]
    SerializeRollback(serde_json::Error),

    #[error("failed to write network state file {path}: {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to delete network state file {path}: {source}")]
    DeleteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to run network command {program}: {source}")]
    RunCommand {
        program: String,
        source: std::io::Error,
    },

    #[error("network command failed ({status}): {program} {args}; {stderr}")]
    CommandFailed {
        program: String,
        args: String,
        status: String,
        stderr: String,
    },

    #[error("no active macOS network services were found")]
    NoNetworkServices,

    #[error("system clock is before unix epoch")]
    Clock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosNetworkPaths {
    pub directory: PathBuf,
    pub rollback_path: PathBuf,
    pub pac_path: PathBuf,
}

impl MacosNetworkPaths {
    pub fn for_state_dir(state_dir: impl AsRef<Path>) -> Self {
        let directory = state_dir.as_ref().join(NETWORK_DIR);
        Self {
            rollback_path: directory.join(ROLLBACK_FILE),
            pac_path: directory.join(PAC_FILE),
            directory,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosSystemProxyServiceState {
    pub service_name: String,
    pub auto_proxy_enabled: bool,
    pub auto_proxy_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosSystemProxyRollbackRecord {
    pub version: u32,
    pub proxy_url: String,
    pub pac_url: String,
    pub pac_path: PathBuf,
    pub services: Vec<MacosSystemProxyServiceState>,
    pub applied_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosNetworkCommand {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosSystemProxyAction {
    Install,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosSystemProxySupport {
    Implemented,
    Planned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosSystemProxyPlan {
    pub action: MacosSystemProxyAction,
    pub support: MacosSystemProxySupport,
    pub paths: MacosNetworkPaths,
    pub proxy_url: String,
    pub pac_url: String,
    pub ai_hosts: Vec<String>,
    pub services: Vec<MacosSystemProxyServiceState>,
    pub commands: Vec<MacosNetworkCommand>,
    pub requires_admin: bool,
    pub changes_system_routes: bool,
    pub can_execute: bool,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosSystemProxyResultState {
    Preview,
    Installed,
    AlreadyInstalled,
    Removed,
    NotInstalled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosSystemProxyResult {
    pub state: MacosSystemProxyResultState,
    pub plan: MacosSystemProxyPlan,
    pub record: Option<MacosSystemProxyRollbackRecord>,
    pub system_routes_changed: bool,
}

pub fn system_proxy_installed(state_dir: impl AsRef<Path>) -> bool {
    MacosNetworkPaths::for_state_dir(state_dir)
        .rollback_path
        .exists()
}

pub fn preview_install_system_proxy(
    state_dir: impl AsRef<Path>,
    proxy_url: &str,
) -> Result<MacosSystemProxyResult, MacosNetworkError> {
    let hosts = default_ai_hosts();
    preview_install_system_proxy_for_hosts(state_dir, proxy_url, &hosts)
}

pub fn preview_install_system_proxy_for_hosts(
    state_dir: impl AsRef<Path>,
    proxy_url: &str,
    ai_hosts: &[String],
) -> Result<MacosSystemProxyResult, MacosNetworkError> {
    ensure_macos()?;
    let plan = install_plan_for_hosts(state_dir, proxy_url, ai_hosts, &NetworkSetupRunner)?;
    Ok(MacosSystemProxyResult {
        state: if plan.can_execute {
            MacosSystemProxyResultState::Preview
        } else {
            MacosSystemProxyResultState::AlreadyInstalled
        },
        record: read_rollback(&plan.paths)?,
        plan,
        system_routes_changed: false,
    })
}

pub fn preview_remove_system_proxy(
    state_dir: impl AsRef<Path>,
    proxy_url: &str,
) -> Result<MacosSystemProxyResult, MacosNetworkError> {
    ensure_macos()?;
    let plan = remove_plan(state_dir, proxy_url)?;
    Ok(MacosSystemProxyResult {
        state: if plan.can_execute {
            MacosSystemProxyResultState::Preview
        } else {
            MacosSystemProxyResultState::NotInstalled
        },
        record: read_rollback(&plan.paths)?,
        plan,
        system_routes_changed: false,
    })
}

pub fn install_system_proxy(
    state_dir: impl AsRef<Path>,
    proxy_url: &str,
) -> Result<MacosSystemProxyResult, MacosNetworkError> {
    let hosts = default_ai_hosts();
    install_system_proxy_for_hosts(state_dir, proxy_url, &hosts)
}

pub fn install_system_proxy_for_hosts(
    state_dir: impl AsRef<Path>,
    proxy_url: &str,
    ai_hosts: &[String],
) -> Result<MacosSystemProxyResult, MacosNetworkError> {
    ensure_macos()?;
    install_system_proxy_for_hosts_with_runner(state_dir, proxy_url, ai_hosts, &NetworkSetupRunner)
}

pub fn remove_system_proxy(
    state_dir: impl AsRef<Path>,
    proxy_url: &str,
) -> Result<MacosSystemProxyResult, MacosNetworkError> {
    ensure_macos()?;
    remove_system_proxy_with_runner(state_dir, proxy_url, &NetworkSetupRunner)
}

#[cfg(test)]
fn install_system_proxy_with_runner(
    state_dir: impl AsRef<Path>,
    proxy_url: &str,
    runner: &impl Runner,
) -> Result<MacosSystemProxyResult, MacosNetworkError> {
    let hosts = default_ai_hosts();
    install_system_proxy_for_hosts_with_runner(state_dir, proxy_url, &hosts, runner)
}

fn install_system_proxy_for_hosts_with_runner(
    state_dir: impl AsRef<Path>,
    proxy_url: &str,
    ai_hosts: &[String],
    runner: &impl Runner,
) -> Result<MacosSystemProxyResult, MacosNetworkError> {
    let plan = install_plan_for_hosts(&state_dir, proxy_url, ai_hosts, runner)?;
    if !plan.can_execute {
        return Ok(MacosSystemProxyResult {
            state: MacosSystemProxyResultState::AlreadyInstalled,
            record: read_rollback(&plan.paths)?,
            plan,
            system_routes_changed: false,
        });
    }

    fs::create_dir_all(&plan.paths.directory).map_err(|source| MacosNetworkError::CreateDir {
        path: plan.paths.directory.clone(),
        source,
    })?;
    let record = MacosSystemProxyRollbackRecord {
        version: RECORD_VERSION,
        proxy_url: plan.proxy_url.clone(),
        pac_url: plan.pac_url.clone(),
        pac_path: plan.paths.pac_path.clone(),
        services: plan.services.clone(),
        applied_at_unix: unix_timestamp()?,
    };
    let record_json =
        serde_json::to_vec_pretty(&record).map_err(MacosNetworkError::SerializeRollback)?;
    write_atomic(&plan.paths.rollback_path, &record_json, 0o600)?;
    write_atomic(
        &plan.paths.pac_path,
        pac_content_for_hosts(&plan.proxy_url, &plan.ai_hosts).as_bytes(),
        0o644,
    )?;

    for command in &plan.commands {
        run_network_command(runner, command)?;
    }

    Ok(MacosSystemProxyResult {
        state: MacosSystemProxyResultState::Installed,
        plan,
        record: Some(record),
        system_routes_changed: true,
    })
}

fn remove_system_proxy_with_runner(
    state_dir: impl AsRef<Path>,
    proxy_url: &str,
    runner: &impl Runner,
) -> Result<MacosSystemProxyResult, MacosNetworkError> {
    let plan = remove_plan(&state_dir, proxy_url)?;
    let Some(record) = read_rollback(&plan.paths)? else {
        return Ok(MacosSystemProxyResult {
            state: MacosSystemProxyResultState::NotInstalled,
            plan,
            record: None,
            system_routes_changed: false,
        });
    };

    for command in &plan.commands {
        run_network_command(runner, command)?;
    }
    delete_if_exists(&plan.paths.rollback_path)?;
    delete_if_exists(&plan.paths.pac_path)?;

    Ok(MacosSystemProxyResult {
        state: MacosSystemProxyResultState::Removed,
        plan,
        record: Some(record),
        system_routes_changed: true,
    })
}

#[cfg(test)]
fn install_plan(
    state_dir: impl AsRef<Path>,
    proxy_url: &str,
    runner: &impl Runner,
) -> Result<MacosSystemProxyPlan, MacosNetworkError> {
    let hosts = default_ai_hosts();
    install_plan_for_hosts(state_dir, proxy_url, &hosts, runner)
}

fn install_plan_for_hosts(
    state_dir: impl AsRef<Path>,
    proxy_url: &str,
    ai_hosts: &[String],
    runner: &impl Runner,
) -> Result<MacosSystemProxyPlan, MacosNetworkError> {
    let paths = MacosNetworkPaths::for_state_dir(state_dir);
    let pac_url = file_url(&paths.pac_path);
    let ai_hosts = normalized_ai_hosts(ai_hosts);
    if paths.rollback_path.exists() {
        let services = read_rollback(&paths)?
            .map(|record| record.services)
            .unwrap_or_default();
        return Ok(MacosSystemProxyPlan {
            action: MacosSystemProxyAction::Install,
            support: support(),
            paths,
            proxy_url: proxy_url.to_string(),
            pac_url,
            ai_hosts,
            services,
            commands: Vec::new(),
            requires_admin: false,
            changes_system_routes: true,
            can_execute: false,
            message: "macOS system proxy routing is already installed by DAM".to_string(),
        });
    }

    let services = inspect_services(runner)?;
    if services.is_empty() {
        return Err(MacosNetworkError::NoNetworkServices);
    }
    let commands = install_commands(&services, &pac_url);
    Ok(MacosSystemProxyPlan {
        action: MacosSystemProxyAction::Install,
        support: support(),
        paths,
        proxy_url: proxy_url.to_string(),
        pac_url,
        ai_hosts,
        services,
        commands,
        requires_admin: false,
        changes_system_routes: true,
        can_execute: support() == MacosSystemProxySupport::Implemented,
        message: "will route known AI hosts through DAM using a macOS PAC system proxy".to_string(),
    })
}

fn remove_plan(
    state_dir: impl AsRef<Path>,
    proxy_url: &str,
) -> Result<MacosSystemProxyPlan, MacosNetworkError> {
    let paths = MacosNetworkPaths::for_state_dir(state_dir);
    let record = read_rollback(&paths)?;
    let services = record
        .as_ref()
        .map(|record| record.services.clone())
        .unwrap_or_default();
    let commands = record.as_ref().map(remove_commands).unwrap_or_default();
    Ok(MacosSystemProxyPlan {
        action: MacosSystemProxyAction::Remove,
        support: support(),
        pac_url: record
            .as_ref()
            .map(|record| record.pac_url.clone())
            .unwrap_or_else(|| file_url(&paths.pac_path)),
        proxy_url: record
            .as_ref()
            .map(|record| record.proxy_url.clone())
            .unwrap_or_else(|| proxy_url.to_string()),
        ai_hosts: default_ai_hosts(),
        services,
        commands,
        requires_admin: false,
        changes_system_routes: true,
        can_execute: record.is_some() && support() == MacosSystemProxySupport::Implemented,
        message: if record.is_some() {
            "will restore macOS auto-proxy settings from DAM rollback state".to_string()
        } else {
            "no DAM macOS system proxy rollback state exists".to_string()
        },
        paths,
    })
}

fn inspect_services(
    runner: &impl Runner,
) -> Result<Vec<MacosSystemProxyServiceState>, MacosNetworkError> {
    let services = list_services(runner)?;
    let mut states = Vec::with_capacity(services.len());
    for service in services {
        let output = runner.run(NETWORKSETUP, &["-getautoproxyurl", &service])?;
        states.push(MacosSystemProxyServiceState {
            service_name: service,
            auto_proxy_enabled: parse_enabled(&output),
            auto_proxy_url: parse_url(&output),
        });
    }
    Ok(states)
}

fn list_services(runner: &impl Runner) -> Result<Vec<String>, MacosNetworkError> {
    let output = runner.run(NETWORKSETUP, &["-listallnetworkservices"])?;
    Ok(parse_network_services(&output))
}

fn install_commands(
    services: &[MacosSystemProxyServiceState],
    pac_url: &str,
) -> Vec<MacosNetworkCommand> {
    services
        .iter()
        .flat_map(|service| {
            [
                networksetup_command(vec!["-setautoproxyurl", &service.service_name, pac_url]),
                networksetup_command(vec!["-setautoproxystate", &service.service_name, "on"]),
            ]
        })
        .collect()
}

fn remove_commands(record: &MacosSystemProxyRollbackRecord) -> Vec<MacosNetworkCommand> {
    record
        .services
        .iter()
        .flat_map(|service| {
            let mut commands = Vec::new();
            if let Some(url) = &service.auto_proxy_url {
                commands.push(networksetup_command(vec![
                    "-setautoproxyurl",
                    &service.service_name,
                    url,
                ]));
            }
            commands.push(networksetup_command(vec![
                "-setautoproxystate",
                &service.service_name,
                if service.auto_proxy_enabled {
                    "on"
                } else {
                    "off"
                },
            ]));
            commands
        })
        .collect()
}

fn networksetup_command(args: Vec<&str>) -> MacosNetworkCommand {
    MacosNetworkCommand {
        program: NETWORKSETUP.to_string(),
        args: args.into_iter().map(str::to_string).collect(),
    }
}

fn run_network_command(
    runner: &impl Runner,
    command: &MacosNetworkCommand,
) -> Result<(), MacosNetworkError> {
    let args = command.args.iter().map(String::as_str).collect::<Vec<_>>();
    runner.run(&command.program, &args).map(|_| ())
}

fn parse_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("An asterisk"))
        .filter(|line| !line.starts_with('*'))
        .map(str::to_string)
        .collect()
}

fn parse_enabled(output: &str) -> bool {
    output.lines().any(|line| {
        line.trim()
            .strip_prefix("Enabled:")
            .map(|value| matches!(value.trim(), "Yes" | "yes" | "1"))
            .unwrap_or(false)
    })
}

fn parse_url(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("URL:")
            .map(str::trim)
            .filter(|value| !value.is_empty() && *value != "(null)")
            .map(str::to_string)
    })
}

#[cfg(test)]
fn pac_content(proxy_url: &str) -> String {
    let hosts = default_ai_hosts();
    pac_content_for_hosts(proxy_url, &hosts)
}

fn pac_content_for_hosts(proxy_url: &str, ai_hosts: &[String]) -> String {
    let proxy = proxy_url
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let host_checks = normalized_ai_hosts(ai_hosts)
        .into_iter()
        .map(|host| format!("host === \"{host}\""))
        .collect::<Vec<_>>()
        .join(" || ");
    let host_checks = if host_checks.is_empty() {
        "false".to_string()
    } else {
        host_checks
    };
    format!(
        "function FindProxyForURL(url, host) {{\n  host = host.toLowerCase();\n  if ({host_checks}) {{\n    return \"PROXY {proxy}\";\n  }}\n  return \"DIRECT\";\n}}\n"
    )
}

fn default_ai_hosts() -> Vec<String> {
    dam_net::known_ai_hosts()
        .into_iter()
        .map(str::to_string)
        .collect()
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

fn read_rollback(
    paths: &MacosNetworkPaths,
) -> Result<Option<MacosSystemProxyRollbackRecord>, MacosNetworkError> {
    if !paths.rollback_path.exists() {
        return Ok(None);
    }
    let bytes =
        fs::read(&paths.rollback_path).map_err(|source| MacosNetworkError::ReadRollback {
            path: paths.rollback_path.clone(),
            source,
        })?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|source| MacosNetworkError::ParseRollback {
            path: paths.rollback_path.clone(),
            source,
        })
}

fn write_atomic(path: &Path, bytes: &[u8], unix_mode: u32) -> Result<(), MacosNetworkError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| MacosNetworkError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let temp_path = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("dam-net-macos"),
        uuid::Uuid::new_v4().simple()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
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
        return Err(MacosNetworkError::WriteFile {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

fn delete_if_exists(path: &Path) -> Result<(), MacosNetworkError> {
    if path.exists() {
        fs::remove_file(path).map_err(|source| MacosNetworkError::DeleteFile {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn file_url(path: &Path) -> String {
    let path = path.to_string_lossy();
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'/' | b'-' | b'.' | b'_' | b'~' => encoded.push(byte as char),
            b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' => encoded.push(byte as char),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    format!("file://{encoded}")
}

fn unix_timestamp() -> Result<u64, MacosNetworkError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| MacosNetworkError::Clock)
}

fn support() -> MacosSystemProxySupport {
    if cfg!(target_os = "macos") {
        MacosSystemProxySupport::Implemented
    } else {
        MacosSystemProxySupport::Planned
    }
}

fn ensure_macos() -> Result<(), MacosNetworkError> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        Err(MacosNetworkError::UnsupportedPlatform)
    }
}

trait Runner {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, MacosNetworkError>;
}

struct NetworkSetupRunner;

impl Runner for NetworkSetupRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, MacosNetworkError> {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|source| MacosNetworkError::RunCommand {
                program: program.to_string(),
                source,
            })?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
        Err(MacosNetworkError::CommandFailed {
            program: program.to_string(),
            args: args.join(" "),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque};

    struct FakeRunner {
        outputs: RefCell<VecDeque<String>>,
        commands: RefCell<Vec<Vec<String>>>,
    }

    impl FakeRunner {
        fn new(outputs: Vec<&str>) -> Self {
            Self {
                outputs: RefCell::new(outputs.into_iter().map(str::to_string).collect()),
                commands: RefCell::new(Vec::new()),
            }
        }
    }

    impl Runner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<String, MacosNetworkError> {
            let mut command = vec![program.to_string()];
            command.extend(args.iter().map(|arg| (*arg).to_string()));
            self.commands.borrow_mut().push(command);
            Ok(self.outputs.borrow_mut().pop_front().unwrap_or_default())
        }
    }

    #[test]
    fn parses_network_services_without_disabled_entries() {
        let services = parse_network_services(
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nUSB 10/100/1000 LAN\n",
        );

        assert_eq!(services, vec!["Wi-Fi", "USB 10/100/1000 LAN"]);
    }

    #[test]
    fn parses_auto_proxy_state() {
        let output = "URL: file:///tmp/dam.pac\nEnabled: Yes\n";

        assert!(parse_enabled(output));
        assert_eq!(parse_url(output), Some("file:///tmp/dam.pac".to_string()));
    }

    #[test]
    fn pac_routes_only_known_ai_hosts() {
        let pac = pac_content("http://127.0.0.1:7828");

        assert!(pac.contains("host === \"api.openai.com\""));
        assert!(pac.contains("PROXY 127.0.0.1:7828"));
        assert!(pac.contains("DIRECT"));
        assert!(!pac.contains("example.com"));
    }

    #[test]
    fn pac_accepts_configured_ai_hosts() {
        let pac = pac_content_for_hosts(
            "http://127.0.0.1:7828",
            &[
                "https://api.enterprise-ai.example/v1".to_string(),
                "API.ENTERPRISE-AI.EXAMPLE:443".to_string(),
            ],
        );

        assert!(pac.contains("host === \"api.enterprise-ai.example\""));
        assert_eq!(pac.matches("api.enterprise-ai.example").count(), 1);
        assert!(!pac.contains("api.openai.com"));
    }

    #[test]
    fn file_url_percent_encodes_paths_for_pac_settings() {
        let path = PathBuf::from("/Users/Alexy Boyer/.dam/network/macos-system-proxy/dam ai.pac");

        assert_eq!(
            file_url(&path),
            "file:///Users/Alexy%20Boyer/.dam/network/macos-system-proxy/dam%20ai.pac"
        );
    }

    #[test]
    fn install_plan_records_prior_service_states_and_commands() {
        let runner = FakeRunner::new(vec![
            "Wi-Fi\nUSB LAN\n",
            "URL: file:///old.pac\nEnabled: Yes\n",
            "URL:\nEnabled: No\n",
        ]);
        let dir = tempfile::tempdir().unwrap();

        let plan = install_plan(dir.path(), "http://127.0.0.1:7828", &runner).unwrap();

        assert!(plan.can_execute || plan.support == MacosSystemProxySupport::Planned);
        assert!(plan.ai_hosts.contains(&"api.openai.com".to_string()));
        assert_eq!(plan.services.len(), 2);
        assert_eq!(plan.commands.len(), 4);
        assert_eq!(plan.commands[0].args[0], "-setautoproxyurl");
        assert_eq!(plan.commands[1].args[0], "-setautoproxystate");
        assert_eq!(plan.commands[1].args[2], "on");
    }

    #[test]
    fn apply_writes_rollback_before_route_commands_and_remove_restores() {
        let runner = FakeRunner::new(vec![
            "Wi-Fi\n",
            "URL: file:///old.pac\nEnabled: Yes\n",
            "",
            "",
            "",
            "",
        ]);
        let dir = tempfile::tempdir().unwrap();

        let installed =
            install_system_proxy_with_runner(dir.path(), "http://127.0.0.1:7828", &runner).unwrap();

        if support() == MacosSystemProxySupport::Implemented {
            assert_eq!(installed.state, MacosSystemProxyResultState::Installed);
            assert!(installed.plan.paths.rollback_path.exists());
            assert!(installed.plan.paths.pac_path.exists());

            let removed =
                remove_system_proxy_with_runner(dir.path(), "http://127.0.0.1:7828", &runner)
                    .unwrap();

            assert_eq!(removed.state, MacosSystemProxyResultState::Removed);
            assert!(!removed.plan.paths.rollback_path.exists());
            assert!(!removed.plan.paths.pac_path.exists());
            let commands = runner.commands.borrow();
            assert!(
                commands
                    .iter()
                    .any(|command| command.contains(&"-setautoproxyurl".to_string()))
            );
            assert!(
                commands
                    .iter()
                    .any(|command| command.contains(&"-setautoproxystate".to_string()))
            );
        } else {
            assert_eq!(
                installed.state,
                MacosSystemProxyResultState::AlreadyInstalled
            );
        }
    }
}
