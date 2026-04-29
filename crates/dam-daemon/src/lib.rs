use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:7828";
pub const DEFAULT_VAULT_PATH: &str = "vault.db";
pub const DEFAULT_LOG_PATH: &str = "log.db";
pub const OPENAI_API_UPSTREAM: &str = "https://api.openai.com";
pub const ANTHROPIC_UPSTREAM: &str = "https://api.anthropic.com";
pub const STATE_DIR_ENV: &str = "DAM_STATE_DIR";

const STATE_FILE: &str = "daemon.json";
const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyOptions {
    pub config_path: Option<PathBuf>,
    pub listen: String,
    pub target_name: String,
    pub provider: String,
    pub upstream: String,
    pub vault_path: PathBuf,
    pub log_path: Option<PathBuf>,
    pub consent_path: Option<PathBuf>,
    pub resolve_inbound: Option<bool>,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            config_path: None,
            listen: DEFAULT_LISTEN.to_string(),
            target_name: "openai".to_string(),
            provider: "openai-compatible".to_string(),
            upstream: OPENAI_API_UPSTREAM.to_string(),
            vault_path: PathBuf::from(DEFAULT_VAULT_PATH),
            log_path: Some(PathBuf::from(DEFAULT_LOG_PATH)),
            consent_path: None,
            resolve_inbound: None,
        }
    }
}

impl ProxyOptions {
    pub fn apply_openai_preset(&mut self) {
        self.target_name = "openai".to_string();
        self.provider = "openai-compatible".to_string();
        self.upstream = OPENAI_API_UPSTREAM.to_string();
    }

    pub fn apply_anthropic_preset(&mut self) {
        self.target_name = "anthropic".to_string();
        self.provider = "anthropic".to_string();
        self.upstream = ANTHROPIC_UPSTREAM.to_string();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonState {
    pub version: u32,
    pub pid: u32,
    pub listen: String,
    pub proxy_url: String,
    pub config_path: Option<PathBuf>,
    pub vault_path: PathBuf,
    pub log_path: Option<PathBuf>,
    pub consent_path: Option<PathBuf>,
    pub resolve_inbound: bool,
    pub target_name: Option<String>,
    pub target_provider: Option<String>,
    pub upstream: Option<String>,
    pub started_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonStatus {
    Disconnected,
    Stale(DaemonState),
    Connected(DaemonState),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePaths {
    pub state_dir: PathBuf,
    pub state_file: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("{0}")]
    Message(String),

    #[error("DAM daemon is already running with pid {0}")]
    AlreadyRunning(u32),

    #[error("failed to create state directory {path}: {source}")]
    CreateStateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to read daemon state {path}: {source}")]
    ReadState {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to write daemon state {path}: {source}")]
    WriteState {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse daemon state {path}: {source}")]
    ParseState {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[error("failed to serialize daemon state: {0}")]
    SerializeState(serde_json::Error),

    #[error("failed to remove daemon state {path}: {source}")]
    RemoveState {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("invalid proxy listen address {listen}: {source}")]
    InvalidListen {
        listen: String,
        source: std::net::AddrParseError,
    },

    #[error("failed to bind proxy listener {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("failed to build proxy: {0}")]
    BuildProxy(dam_proxy::ProxyError),

    #[error("proxy server failed: {0}")]
    Server(std::io::Error),

    #[error("failed to signal daemon pid {pid}: {source}")]
    Signal { pid: u32, source: std::io::Error },
}

pub fn parse_proxy_options(args: impl IntoIterator<Item = String>) -> Result<ProxyOptions, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    let mut options = ProxyOptions::default();
    let mut target_name_explicit = false;
    let mut upstream_explicit = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--openai" => {
                options.apply_openai_preset();
            }
            "--anthropic" => {
                options.apply_anthropic_preset();
            }
            "--config" => {
                i += 1;
                options.config_path = Some(PathBuf::from(required_value(&args, i, "--config")?));
            }
            "--listen" => {
                i += 1;
                options.listen = required_value(&args, i, "--listen")?.to_string();
            }
            "--target-name" => {
                i += 1;
                options.target_name = required_value(&args, i, "--target-name")?.to_string();
                target_name_explicit = true;
            }
            "--provider" => {
                i += 1;
                let provider = required_value(&args, i, "--provider")?;
                options.provider = provider.to_string();
                if provider == "anthropic" {
                    if !target_name_explicit {
                        options.target_name = "anthropic".to_string();
                    }
                    if !upstream_explicit {
                        options.upstream = ANTHROPIC_UPSTREAM.to_string();
                    }
                } else if provider == "openai-compatible" {
                    if !target_name_explicit {
                        options.target_name = "openai".to_string();
                    }
                    if !upstream_explicit {
                        options.upstream = OPENAI_API_UPSTREAM.to_string();
                    }
                }
            }
            "--upstream" => {
                i += 1;
                options.upstream = required_value(&args, i, "--upstream")?.to_string();
                upstream_explicit = true;
            }
            "--db" => {
                i += 1;
                options.vault_path = PathBuf::from(required_value(&args, i, "--db")?);
            }
            "--log" => {
                i += 1;
                options.log_path = Some(PathBuf::from(required_value(&args, i, "--log")?));
            }
            "--consent-db" => {
                i += 1;
                options.consent_path =
                    Some(PathBuf::from(required_value(&args, i, "--consent-db")?));
            }
            "--no-log" => {
                options.log_path = None;
            }
            "--resolve-inbound" => {
                options.resolve_inbound = Some(true);
            }
            "--no-resolve-inbound" => {
                options.resolve_inbound = Some(false);
            }
            arg => return Err(format!("unknown daemon option: {arg}")),
        }
        i += 1;
    }

    Ok(options)
}

pub fn proxy_options_to_args(options: &ProxyOptions) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(config_path) = &options.config_path {
        args.extend(["--config".to_string(), config_path.display().to_string()]);
    }
    args.extend(["--listen".to_string(), options.listen.clone()]);
    args.extend(["--target-name".to_string(), options.target_name.clone()]);
    args.extend(["--provider".to_string(), options.provider.clone()]);
    args.extend(["--upstream".to_string(), options.upstream.clone()]);
    args.extend(["--db".to_string(), options.vault_path.display().to_string()]);
    match &options.log_path {
        Some(path) => args.extend(["--log".to_string(), path.display().to_string()]),
        None => args.push("--no-log".to_string()),
    }
    if let Some(path) = &options.consent_path {
        args.extend(["--consent-db".to_string(), path.display().to_string()]);
    }
    match options.resolve_inbound {
        Some(true) => args.push("--resolve-inbound".to_string()),
        Some(false) => args.push("--no-resolve-inbound".to_string()),
        None => {}
    }
    args
}

pub fn proxy_config(options: &ProxyOptions) -> Result<dam_config::DamConfig, String> {
    let overrides = dam_config::ConfigOverrides {
        config_path: options.config_path.clone(),
        vault_sqlite_path: Some(options.vault_path.clone()),
        log_sqlite_path: options.log_path.clone(),
        log_enabled: Some(options.log_path.is_some()),
        consent_sqlite_path: options.consent_path.clone(),
        proxy_enabled: Some(true),
        proxy_listen: Some(options.listen.clone()),
        proxy_resolve_inbound: options.resolve_inbound,
        proxy_target_name: Some(options.target_name.clone()),
        proxy_target_provider: Some(options.provider.clone()),
        proxy_target_upstream: Some(options.upstream.clone()),
        proxy_target_api_key_env: Some(String::new()),
        ..dam_config::ConfigOverrides::default()
    };

    dam_config::load(&overrides).map_err(|error| format!("failed to load DAM config: {error}"))
}

pub async fn serve(
    config: dam_config::DamConfig,
    config_path: Option<PathBuf>,
) -> Result<(), DaemonError> {
    if let DaemonStatus::Connected(state) = daemon_status()?
        && state.pid != std::process::id()
    {
        return Err(DaemonError::AlreadyRunning(state.pid));
    }

    let addr = config
        .proxy
        .listen
        .parse::<SocketAddr>()
        .map_err(|source| DaemonError::InvalidListen {
            listen: config.proxy.listen.clone(),
            source,
        })?;
    let app = dam_proxy::build_app(config.clone()).map_err(DaemonError::BuildProxy)?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| DaemonError::Bind { addr, source })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| DaemonError::Bind { addr, source })?;
    let state = state_from_config(&config, config_path, local_addr);

    write_state(&state)?;

    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(DaemonError::Server);

    let _ = remove_state_if_pid(state.pid);
    result
}

pub fn daemon_status() -> Result<DaemonStatus, DaemonError> {
    let Some(state) = read_state()? else {
        return Ok(DaemonStatus::Disconnected);
    };

    if process_is_running(state.pid) {
        Ok(DaemonStatus::Connected(state))
    } else {
        Ok(DaemonStatus::Stale(state))
    }
}

pub fn state_paths() -> Result<StatePaths, DaemonError> {
    state_paths_from_env(
        std::env::var_os(STATE_DIR_ENV).map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

pub fn state_paths_from_env(
    state_dir: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Result<StatePaths, DaemonError> {
    let state_dir = match state_dir {
        Some(path) if !path.as_os_str().is_empty() => path,
        _ => home
            .filter(|path| !path.as_os_str().is_empty())
            .map(|path| path.join(".dam"))
            .ok_or_else(|| {
                DaemonError::Message(format!(
                    "{STATE_DIR_ENV} or HOME is required to locate daemon state"
                ))
            })?,
    };
    Ok(StatePaths {
        state_file: state_dir.join(STATE_FILE),
        state_dir,
    })
}

pub fn read_state() -> Result<Option<DaemonState>, DaemonError> {
    let paths = state_paths()?;
    read_state_from(&paths.state_file)
}

pub fn read_state_from(path: &Path) -> Result<Option<DaemonState>, DaemonError> {
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|source| DaemonError::ParseState {
                path: path.to_path_buf(),
                source,
            }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(DaemonError::ReadState {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub fn write_state(state: &DaemonState) -> Result<(), DaemonError> {
    let paths = state_paths()?;
    fs::create_dir_all(&paths.state_dir).map_err(|source| DaemonError::CreateStateDir {
        path: paths.state_dir.clone(),
        source,
    })?;
    write_state_to(&paths.state_file, state)
}

pub fn write_state_to(path: &Path, state: &DaemonState) -> Result<(), DaemonError> {
    let raw = serde_json::to_string_pretty(state).map_err(DaemonError::SerializeState)?;
    fs::write(path, format!("{raw}\n")).map_err(|source| DaemonError::WriteState {
        path: path.to_path_buf(),
        source,
    })
}

pub fn remove_state() -> Result<(), DaemonError> {
    let paths = state_paths()?;
    remove_state_file(&paths.state_file)
}

pub fn remove_state_if_pid(pid: u32) -> Result<(), DaemonError> {
    let paths = state_paths()?;
    let Some(state) = read_state_from(&paths.state_file)? else {
        return Ok(());
    };
    if state.pid == pid {
        remove_state_file(&paths.state_file)?;
    }
    Ok(())
}

pub fn remove_state_file(path: &Path) -> Result<(), DaemonError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(DaemonError::RemoveState {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub fn process_is_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    #[cfg(unix)]
    {
        Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}")])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains(&pid.to_string())
            })
            .unwrap_or(false)
    }
}

pub fn terminate_process(pid: u32) -> Result<(), DaemonError> {
    #[cfg(unix)]
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|source| DaemonError::Signal { pid, source })?;

    #[cfg(windows)]
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|source| DaemonError::Signal { pid, source })?;

    if status.success() {
        Ok(())
    } else {
        Err(DaemonError::Message(format!(
            "failed to signal daemon pid {pid}: command exited with {status}"
        )))
    }
}

pub fn local_base_url(addr: SocketAddr) -> String {
    let host = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST).to_string(),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST).to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
        ip => ip.to_string(),
    };

    format!("http://{host}:{}", addr.port())
}

fn required_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn state_from_config(
    config: &dam_config::DamConfig,
    config_path: Option<PathBuf>,
    local_addr: SocketAddr,
) -> DaemonState {
    let target = config.proxy.targets.first();
    DaemonState {
        version: STATE_VERSION,
        pid: std::process::id(),
        listen: local_addr.to_string(),
        proxy_url: local_base_url(local_addr),
        config_path,
        vault_path: config.vault.sqlite_path.clone(),
        log_path: if config.log.enabled && config.log.backend == dam_config::LogBackend::Sqlite {
            Some(config.log.sqlite_path.clone())
        } else {
            None
        },
        consent_path: if config.consent.enabled {
            Some(config.consent.sqlite_path.clone())
        } else {
            None
        },
        resolve_inbound: config.proxy.resolve_inbound,
        target_name: target.map(|target| target.name.clone()),
        target_provider: target.map(|target| target.provider.clone()),
        upstream: target.map(|target| target.upstream.clone()),
        started_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs(),
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let ctrl_c = tokio::signal::ctrl_c();
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(_) => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            _ = ctrl_c => {}
            _ = terminate => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_preset_sets_target_provider_and_upstream() {
        let options = parse_proxy_options(["--anthropic".to_string()]).unwrap();

        assert_eq!(options.target_name, "anthropic");
        assert_eq!(options.provider, "anthropic");
        assert_eq!(options.upstream, ANTHROPIC_UPSTREAM);
    }

    #[test]
    fn provider_anthropic_updates_defaults_when_not_explicit() {
        let options =
            parse_proxy_options(["--provider".to_string(), "anthropic".to_string()]).unwrap();

        assert_eq!(options.target_name, "anthropic");
        assert_eq!(options.provider, "anthropic");
        assert_eq!(options.upstream, ANTHROPIC_UPSTREAM);
    }

    #[test]
    fn proxy_options_round_trip_through_args() {
        let options = ProxyOptions {
            config_path: Some(PathBuf::from("dam.toml")),
            listen: "127.0.0.1:9000".to_string(),
            target_name: "xai".to_string(),
            provider: "openai-compatible".to_string(),
            upstream: "https://api.x.ai".to_string(),
            vault_path: PathBuf::from("vault.db"),
            log_path: None,
            consent_path: Some(PathBuf::from("consent.db")),
            resolve_inbound: Some(true),
        };

        assert_eq!(
            parse_proxy_options(proxy_options_to_args(&options)).unwrap(),
            options
        );
    }

    #[test]
    fn proxy_config_uses_caller_auth_passthrough() {
        let options = ProxyOptions::default();
        let config = proxy_config(&options).unwrap();

        assert_eq!(config.proxy.targets.len(), 1);
        assert_eq!(config.proxy.targets[0].name, "openai");
        assert_eq!(config.proxy.targets[0].provider, "openai-compatible");
        assert_eq!(config.proxy.targets[0].api_key_env, None);
        assert_eq!(config.proxy.targets[0].api_key, None);
        assert!(config.proxy.enabled);
        assert!(config.log.enabled);
    }

    #[test]
    fn state_paths_prefer_explicit_state_dir() {
        let paths = state_paths_from_env(
            Some(PathBuf::from("/tmp/dam-state")),
            Some(PathBuf::from("/home/example")),
        )
        .unwrap();

        assert_eq!(paths.state_dir, PathBuf::from("/tmp/dam-state"));
        assert_eq!(
            paths.state_file,
            PathBuf::from("/tmp/dam-state").join(STATE_FILE)
        );
    }

    #[test]
    fn state_paths_fall_back_to_home_dot_dam() {
        let paths = state_paths_from_env(None, Some(PathBuf::from("/home/example"))).unwrap();

        assert_eq!(paths.state_dir, PathBuf::from("/home/example/.dam"));
    }

    #[test]
    fn state_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE);
        let state = DaemonState {
            version: STATE_VERSION,
            pid: 123,
            listen: "127.0.0.1:7828".to_string(),
            proxy_url: "http://127.0.0.1:7828".to_string(),
            config_path: Some(PathBuf::from("dam.toml")),
            vault_path: PathBuf::from("vault.db"),
            log_path: Some(PathBuf::from("log.db")),
            consent_path: Some(PathBuf::from("consent.db")),
            resolve_inbound: false,
            target_name: Some("openai".to_string()),
            target_provider: Some("openai-compatible".to_string()),
            upstream: Some(OPENAI_API_UPSTREAM.to_string()),
            started_at_unix: 42,
        };

        write_state_to(&path, &state).unwrap();

        assert_eq!(read_state_from(&path).unwrap(), Some(state));
    }
}
