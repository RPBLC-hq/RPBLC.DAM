//! `dam-web` — local React SPA + JSON API for DAM.
//!
//! Wiring only. Real handlers live under `api/*`; the axum app is in
//! `server`. See `RPBLC.Architecture/dam/web/architecture.md`.

mod activity_map;
mod api;
mod bootstrap;
mod error;
mod events_bus;
mod guard;
mod request_store;
mod server;

use std::env;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

const DAM_WEB_SHELL_ENV: &str = "DAM_WEB_SHELL";
const DAM_WEB_SHELL_TRAY: &str = "tray";
const DAM_WEB_TRAY_POST_TOKEN_ENV: &str = "DAM_WEB_TRAY_POST_TOKEN";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Web,
    Tray,
}

impl Surface {
    fn from_env() -> Self {
        match env::var(DAM_WEB_SHELL_ENV) {
            Ok(value) if value == DAM_WEB_SHELL_TRAY => Self::Tray,
            _ => Self::Web,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Tray => "tray",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CliArgs {
    addr: Option<String>,
    config_path: Option<PathBuf>,
    db_path: Option<PathBuf>,
    log_path: Option<PathBuf>,
    consent_path: Option<PathBuf>,
}

#[derive(Clone)]
pub struct AppState {
    pub surface: Surface,
    pub tray_post_token: Option<String>,
    pub vault: Arc<dam_vault::Vault>,
    pub consent_store: Option<Arc<dam_consent::ConsentStore>>,
    pub logs: Arc<dam_log::LogStore>,
    pub config: Arc<dam_config::DamConfig>,
    pub config_path: Option<PathBuf>,
    pub db_path: Arc<PathBuf>,
    pub log_path: Arc<PathBuf>,
    pub client: reqwest::Client,
    pub requests: Arc<request_store::RequestStore>,
    pub events: Arc<events_bus::EventBus>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match parse_args(env::args_os().skip(1)) {
        Ok(cli) => cli,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("{}", usage());
            return ExitCode::from(2);
        }
    };

    let overrides = build_overrides(&cli);
    let config = match dam_config::load(&overrides) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("failed to load config: {error}");
            return ExitCode::from(2);
        }
    };

    let db_path = config.vault.sqlite_path.clone();
    let log_path = config.log.sqlite_path.clone();

    let addr: SocketAddr = match config.web.addr.parse() {
        Ok(addr) => addr,
        Err(error) => {
            eprintln!("invalid web.addr `{}`: {error}", config.web.addr);
            return ExitCode::from(2);
        }
    };

    let vault = match dam_vault::Vault::open(&db_path) {
        Ok(vault) => Arc::new(vault),
        Err(error) => {
            eprintln!("failed to open vault db {}: {error}", db_path.display());
            return ExitCode::from(1);
        }
    };
    let logs = match dam_log::LogStore::open(&log_path) {
        Ok(store) => Arc::new(store),
        Err(error) => {
            eprintln!("failed to open log db {}: {error}", log_path.display());
            return ExitCode::from(1);
        }
    };
    let consent_store = if config.consent.enabled {
        match dam_consent::ConsentStore::open(&config.consent.sqlite_path) {
            Ok(store) => Some(Arc::new(store)),
            Err(error) => {
                eprintln!(
                    "failed to open consent db {}: {error}",
                    config.consent.sqlite_path.display()
                );
                return ExitCode::from(1);
            }
        }
    } else {
        None
    };

    let state = AppState {
        surface: Surface::from_env(),
        tray_post_token: env::var(DAM_WEB_TRAY_POST_TOKEN_ENV)
            .ok()
            .filter(|t| !t.is_empty()),
        vault,
        consent_store,
        logs,
        config: Arc::new(config),
        config_path: cli.config_path.clone(),
        db_path: Arc::new(db_path),
        log_path: Arc::new(log_path),
        client: reqwest::Client::new(),
        requests: Arc::new(request_store::RequestStore::default()),
        events: Arc::new(events_bus::EventBus::new()),
    };

    eprintln!(
        "dam-web listening on http://{addr}  (surface={})",
        state.surface.as_str()
    );

    if let Err(error) = server::serve(addr, state).await {
        eprintln!("dam-web server error: {error}");
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}

fn parse_args(mut args: impl Iterator<Item = OsString>) -> Result<CliArgs, String> {
    let mut cli = CliArgs::default();
    while let Some(raw) = args.next() {
        let arg = raw.to_string_lossy().into_owned();
        match arg.as_str() {
            "--addr" => cli.addr = Some(required(&mut args, "--addr")?),
            "--config" => cli.config_path = Some(required(&mut args, "--config")?.into()),
            "--db" => cli.db_path = Some(required(&mut args, "--db")?.into()),
            "--log" => cli.log_path = Some(required(&mut args, "--log")?.into()),
            "--consent-db" => cli.consent_path = Some(required(&mut args, "--consent-db")?.into()),
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(cli)
}

fn required(args: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<String, String> {
    args.next()
        .map(|v| v.to_string_lossy().into_owned())
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn build_overrides(cli: &CliArgs) -> dam_config::ConfigOverrides {
    let mut overrides = dam_config::ConfigOverrides::default();
    if let Some(path) = &cli.config_path {
        overrides.config_path = Some(path.clone());
    }
    if let Some(addr) = &cli.addr {
        overrides.web_addr = Some(addr.clone());
    }
    if let Some(path) = &cli.db_path {
        overrides.vault_sqlite_path = Some(path.clone());
    }
    if let Some(path) = &cli.log_path {
        overrides.log_sqlite_path = Some(path.clone());
    }
    if let Some(path) = &cli.consent_path {
        overrides.consent_sqlite_path = Some(path.clone());
    }
    overrides
}

fn usage() -> &'static str {
    "Usage: dam-web [--addr 127.0.0.1:2896] [--config dam.toml] [--db vault.db] [--log log.db] [--consent-db consent.db]"
}
