use std::{
    ffi::OsString,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::{Command as StdCommand, Stdio},
    time::Duration,
};

use serde::Serialize;
use tokio::{net::TcpListener, process::Command as TokioCommand, sync::oneshot};

const DEFAULT_LISTEN: &str = "127.0.0.1:7828";
const DEFAULT_VAULT_PATH: &str = "vault.db";
const DEFAULT_LOG_PATH: &str = "log.db";
const CODEX_CHATGPT_UPSTREAM: &str = "https://chatgpt.com";
const OPENAI_API_UPSTREAM: &str = "https://api.openai.com";
const ANTHROPIC_UPSTREAM: &str = "https://api.anthropic.com";
const CODEX_UNSUPPORTED_MESSAGE: &str = "dam codex ChatGPT-login mode is disabled because Codex v0.125 sends model turns to wss://chatgpt.com/backend-api/codex/responses, which is not controlled by chatgpt_base_url. DAM would not protect the prompt. Use dam codex --api with OPENAI_API_KEY for the current Codex protected path, or use dam claude.";
const CODEX_API_KEY_ENV: &str = "OPENAI_API_KEY";
const CODEX_DAM_PROVIDER_ID: &str = "dam_openai";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tool {
    Codex,
    Claude,
}

impl Tool {
    fn default_upstream(self) -> &'static str {
        match self {
            Self::Codex => CODEX_CHATGPT_UPSTREAM,
            Self::Claude => ANTHROPIC_UPSTREAM,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    command: CommandKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandKind {
    Launch(LaunchArgs),
    Connect(dam_daemon::ProxyOptions),
    Disconnect,
    Status(StatusArgs),
    Integrations(IntegrationArgs),
    DaemonRun(dam_daemon::ProxyOptions),
    Help(Option<Tool>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StatusArgs {
    json: bool,
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
}

#[derive(Debug, Clone, Serialize)]
struct StatusView {
    state: &'static str,
    message: String,
    daemon: Option<dam_daemon::DaemonState>,
    proxy: Option<dam_api::ProxyReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LaunchArgs {
    tool: Tool,
    config_path: Option<PathBuf>,
    listen: String,
    upstream: String,
    vault_path: PathBuf,
    log_path: Option<PathBuf>,
    consent_path: Option<PathBuf>,
    resolve_inbound: Option<bool>,
    codex_api_key_mode: bool,
    tool_args: Vec<String>,
}

impl LaunchArgs {
    fn target_name(&self) -> &'static str {
        match (self.tool, self.codex_api_key_mode) {
            (Tool::Codex, true) => "openai",
            (Tool::Codex, false) => "chatgpt",
            (Tool::Claude, _) => "anthropic",
        }
    }

    fn target_provider(&self) -> &'static str {
        match (self.tool, self.codex_api_key_mode) {
            (Tool::Codex, true) => "openai-compatible",
            (Tool::Codex, false) => "chatgpt",
            (Tool::Claude, _) => "anthropic",
        }
    }

    fn codex_provider_base_url(&self, local_base_url: &str) -> String {
        format!("{}/v1", local_base_url.trim_end_matches('/'))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolCommand {
    program: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
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
    match parse_cli(std::env::args().skip(1))? {
        Cli {
            command: CommandKind::Help(tool),
        } => {
            match tool {
                Some(tool) => println!("{}", usage_launch(tool)),
                None => println!("{}", usage()),
            }
            Ok(0)
        }
        Cli {
            command: CommandKind::Launch(args),
        } => launch(args).await,
        Cli {
            command: CommandKind::Connect(args),
        } => connect(args).await,
        Cli {
            command: CommandKind::Disconnect,
        } => disconnect().await,
        Cli {
            command: CommandKind::Status(args),
        } => status(args).await,
        Cli {
            command: CommandKind::Integrations(args),
        } => integrations(args).await,
        Cli {
            command: CommandKind::DaemonRun(args),
        } => daemon_run(args).await,
    }
}

async fn connect(args: dam_daemon::ProxyOptions) -> Result<i32, String> {
    dam_daemon::proxy_config(&args)?;

    match dam_daemon::daemon_status().map_err(|error| error.to_string())? {
        dam_daemon::DaemonStatus::Connected(state) => {
            println!("DAM already connected at {}", state.proxy_url);
            return Ok(0);
        }
        dam_daemon::DaemonStatus::Stale(state) => {
            dam_daemon::remove_state_if_pid(state.pid).map_err(|error| error.to_string())?;
        }
        dam_daemon::DaemonStatus::Disconnected => {}
    }

    let exe = std::env::current_exe()
        .map_err(|error| format!("failed to locate current dam executable: {error}"))?;
    let mut child = StdCommand::new(exe);
    child
        .arg("daemon-run")
        .args(dam_daemon::proxy_options_to_args(&args))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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

async fn disconnect() -> Result<i32, String> {
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
            dam_daemon::terminate_process(state.pid).map_err(|error| error.to_string())?;
            wait_for_daemon_stop(state.pid, Duration::from_secs(5)).await;
            dam_daemon::remove_state_if_pid(state.pid).map_err(|error| error.to_string())?;
            println!("DAM disconnected");
            Ok(0)
        }
    }
}

async fn status(args: StatusArgs) -> Result<i32, String> {
    let view = match dam_daemon::daemon_status().map_err(|error| error.to_string())? {
        dam_daemon::DaemonStatus::Disconnected => StatusView {
            state: "disconnected",
            message: "DAM is not connected".to_string(),
            daemon: None,
            proxy: None,
        },
        dam_daemon::DaemonStatus::Stale(state) => StatusView {
            state: "stale",
            message: format!("daemon state points at stopped pid {}", state.pid),
            daemon: Some(state),
            proxy: None,
        },
        dam_daemon::DaemonStatus::Connected(state) => {
            let proxy = fetch_proxy_report(&state.proxy_url).await;
            match proxy {
                Ok(report) => StatusView {
                    state: if report.state == dam_api::ProxyState::Protected {
                        "connected"
                    } else {
                        "degraded"
                    },
                    message: report.message.clone(),
                    daemon: Some(state),
                    proxy: Some(report),
                },
                Err(error) => StatusView {
                    state: "degraded",
                    message: error,
                    daemon: Some(state),
                    proxy: None,
                },
            }
        }
    };
    let code = if view.state == "connected" { 0 } else { 1 };

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
    }
}

async fn daemon_run(args: dam_daemon::ProxyOptions) -> Result<i32, String> {
    let config = dam_daemon::proxy_config(&args)?;
    dam_daemon::serve(config, args.config_path)
        .await
        .map_err(|error| error.to_string())?;
    Ok(0)
}

async fn launch(args: LaunchArgs) -> Result<i32, String> {
    ensure_supported_launch(&args)?;

    let config = proxy_config(&args)?;
    let addr = parse_listen_addr(&config.proxy.listen)?;
    let app =
        dam_proxy::build_app(config).map_err(|error| format!("failed to build proxy: {error}"))?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|error| format!("failed to bind DAM proxy on {addr}: {error}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|error| format!("failed to read DAM proxy address: {error}"))?;
    let base_url = local_base_url(local_addr);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let mut server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    if let Err(error) = wait_for_health(&base_url).await {
        let _ = shutdown_tx.send(());
        let _ = server.await;
        return Err(error);
    }

    eprintln!(
        "DAM proxy protecting {} traffic at {}",
        args.target_name(),
        base_url
    );

    let tool_command = tool_command(&args, &base_url)?;
    let mut child = spawn_tool(&tool_command)?;

    let exit_code = tokio::select! {
        result = child.wait() => {
            let status = result.map_err(|error| format!("failed to wait for {}: {error}", tool_command.program))?;
            status.code().unwrap_or(1)
        }
        server_result = &mut server => {
            let _ = child.kill().await;
            let result = server_result.map_err(|error| format!("DAM proxy task failed: {error}"))?;
            match result {
                Ok(()) => return Err("DAM proxy stopped before the tool exited".to_string()),
                Err(error) => return Err(format!("DAM proxy failed before the tool exited: {error}")),
            }
        }
        signal = tokio::signal::ctrl_c() => {
            if let Err(error) = signal {
                return Err(format!("failed to listen for Ctrl-C: {error}"));
            }
            let _ = child.kill().await;
            130
        }
    };

    let _ = shutdown_tx.send(());
    let _ = server.await;

    Ok(exit_code)
}

fn ensure_supported_launch(args: &LaunchArgs) -> Result<(), String> {
    match args.tool {
        Tool::Codex if args.codex_api_key_mode => ensure_codex_api_key_available(),
        Tool::Codex => Err(CODEX_UNSUPPORTED_MESSAGE.to_string()),
        Tool::Claude => Ok(()),
    }
}

fn ensure_codex_api_key_available() -> Result<(), String> {
    match std::env::var(CODEX_API_KEY_ENV) {
        Ok(value) if !value.trim().is_empty() => Ok(()),
        _ => Err(format!(
            "dam codex --api requires {CODEX_API_KEY_ENV}. Codex API-key mode routes the OpenAI Responses API through DAM; ChatGPT-login Codex remains fail-closed."
        )),
    }
}

fn parse_cli(args: impl IntoIterator<Item = String>) -> Result<Cli, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    let Some(command) = args.first() else {
        return Ok(Cli {
            command: CommandKind::Help(None),
        });
    };

    match command.as_str() {
        "-h" | "--help" | "help" => Ok(Cli {
            command: CommandKind::Help(None),
        }),
        "connect" => parse_connect_command(&args[1..]),
        "disconnect" => parse_disconnect_command(&args[1..]),
        "status" => parse_status_command(&args[1..]),
        "integrations" => parse_integrations_command(&args[1..]),
        "daemon-run" => parse_daemon_run_command(&args[1..]),
        "codex" => parse_tool_command(Tool::Codex, &args[1..]),
        "claude" => parse_tool_command(Tool::Claude, &args[1..]),
        other => Err(format!("unknown command: {other}\n{}", usage())),
    }
}

fn parse_connect_command(args: &[String]) -> Result<Cli, String> {
    if matches!(args.first().map(String::as_str), Some("-h" | "--help")) {
        println!("{}", usage_connect());
        std::process::exit(0);
    }

    let args = expand_connect_profile_args(args)?;
    Ok(Cli {
        command: CommandKind::Connect(dam_daemon::parse_proxy_options(args)?),
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
    if let Some(arg) = args.first() {
        return Err(format!("unknown disconnect argument: {arg}"));
    }

    Ok(Cli {
        command: CommandKind::Disconnect,
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

fn parse_integrations_command(args: &[String]) -> Result<Cli, String> {
    if args.is_empty() || matches!(args.first().map(String::as_str), Some("-h" | "--help")) {
        println!("{}", usage_integrations());
        std::process::exit(0);
    }

    match args[0].as_str() {
        "list" => parse_integrations_list(&args[1..]),
        "show" => parse_integrations_show(&args[1..]),
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

fn expand_connect_profile_args(args: &[String]) -> Result<Vec<String>, String> {
    let mut expanded = Vec::new();
    let mut remaining = Vec::new();
    let mut profile_id = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => {
                i += 1;
                let id = required_value(args, i, "--profile")?;
                if profile_id.replace(id.to_string()).is_some() {
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
            }
            arg => remaining.push(arg.to_string()),
        }
        i += 1;
    }

    expanded.extend(remaining);
    Ok(expanded)
}

fn parse_tool_command(tool: Tool, args: &[String]) -> Result<Cli, String> {
    if matches!(args.first().map(String::as_str), Some("-h" | "--help")) {
        return Ok(Cli {
            command: CommandKind::Help(Some(tool)),
        });
    }

    Ok(Cli {
        command: CommandKind::Launch(parse_launch_args(tool, args)?),
    })
}

fn parse_launch_args(tool: Tool, args: &[String]) -> Result<LaunchArgs, String> {
    let mut launch = LaunchArgs {
        tool,
        config_path: None,
        listen: DEFAULT_LISTEN.to_string(),
        upstream: tool.default_upstream().to_string(),
        vault_path: PathBuf::from(DEFAULT_VAULT_PATH),
        log_path: Some(PathBuf::from(DEFAULT_LOG_PATH)),
        consent_path: None,
        resolve_inbound: None,
        codex_api_key_mode: false,
        tool_args: Vec::new(),
    };

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--" => {
                launch.tool_args.extend(args[i + 1..].iter().cloned());
                break;
            }
            "--config" => {
                i += 1;
                launch.config_path = Some(PathBuf::from(required_value(args, i, "--config")?));
            }
            "--listen" => {
                i += 1;
                launch.listen = required_value(args, i, "--listen")?.to_string();
            }
            "--upstream" => {
                i += 1;
                launch.upstream = required_value(args, i, "--upstream")?.to_string();
            }
            "--db" => {
                i += 1;
                launch.vault_path = PathBuf::from(required_value(args, i, "--db")?);
            }
            "--log" => {
                i += 1;
                launch.log_path = Some(PathBuf::from(required_value(args, i, "--log")?));
            }
            "--consent-db" => {
                i += 1;
                launch.consent_path = Some(PathBuf::from(required_value(args, i, "--consent-db")?));
            }
            "--no-log" => {
                launch.log_path = None;
            }
            "--resolve-inbound" => {
                launch.resolve_inbound = Some(true);
            }
            "--no-resolve-inbound" => {
                launch.resolve_inbound = Some(false);
            }
            "--api" if tool == Tool::Codex => {
                launch.codex_api_key_mode = true;
                if launch.upstream == CODEX_CHATGPT_UPSTREAM {
                    launch.upstream = OPENAI_API_UPSTREAM.to_string();
                }
            }
            _ => {
                launch.tool_args.extend(args[i..].iter().cloned());
                break;
            }
        }
        i += 1;
    }

    Ok(launch)
}

fn required_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn proxy_config(args: &LaunchArgs) -> Result<dam_config::DamConfig, String> {
    let overrides = dam_config::ConfigOverrides {
        config_path: args.config_path.clone(),
        vault_sqlite_path: Some(args.vault_path.clone()),
        log_sqlite_path: args.log_path.clone(),
        log_enabled: Some(args.log_path.is_some()),
        consent_sqlite_path: args.consent_path.clone(),
        proxy_enabled: Some(true),
        proxy_listen: Some(args.listen.clone()),
        proxy_resolve_inbound: args.resolve_inbound,
        proxy_target_name: Some(args.target_name().to_string()),
        proxy_target_provider: Some(args.target_provider().to_string()),
        proxy_target_upstream: Some(args.upstream.clone()),
        proxy_target_api_key_env: Some(String::new()),
        ..dam_config::ConfigOverrides::default()
    };

    dam_config::load(&overrides).map_err(|error| format!("failed to load DAM config: {error}"))
}

fn parse_listen_addr(listen: &str) -> Result<SocketAddr, String> {
    listen
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid --listen address {listen}: {error}"))
}

fn local_base_url(addr: SocketAddr) -> String {
    let host = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST).to_string(),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST).to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
        ip => ip.to_string(),
    };

    format!("http://{host}:{}", addr.port())
}

async fn wait_for_health(base_url: &str) -> Result<(), String> {
    let url = format!("{}/health", base_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .map_err(|error| format!("failed to build health client: {error}"))?;

    for _ in 0..40 {
        if let Ok(response) = client.get(&url).send().await
            && response.status().is_success()
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    Err(format!("DAM proxy did not become ready at {url}"))
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
    if let Some(state) = &view.daemon {
        output.push_str(&format!("pid: {}\n", state.pid));
        output.push_str(&format!("proxy: {}\n", state.proxy_url));
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

fn severity_tag(severity: dam_api::DiagnosticSeverity) -> &'static str {
    match severity {
        dam_api::DiagnosticSeverity::Info => "info",
        dam_api::DiagnosticSeverity::Warning => "warning",
        dam_api::DiagnosticSeverity::Error => "error",
    }
}

fn tool_command(args: &LaunchArgs, base_url: &str) -> Result<ToolCommand, String> {
    let base_url = base_url.trim_end_matches('/');
    match args.tool {
        Tool::Codex => codex_tool_command(args, base_url),
        Tool::Claude => {
            let tool_args = args.tool_args.to_vec();
            Ok(ToolCommand {
                program: "claude".to_string(),
                args: tool_args,
                env: vec![("ANTHROPIC_BASE_URL".to_string(), base_url.to_string())],
            })
        }
    }
}

fn codex_tool_command(args: &LaunchArgs, base_url: &str) -> Result<ToolCommand, String> {
    if !args.codex_api_key_mode {
        return Err(CODEX_UNSUPPORTED_MESSAGE.to_string());
    }
    validate_codex_api_tool_args(&args.tool_args)?;

    let codex_base_url = args.codex_provider_base_url(base_url);
    let mut tool_args = vec![
        "-c".to_string(),
        format!("model_provider={}", toml_string(CODEX_DAM_PROVIDER_ID)),
        "-c".to_string(),
        format!(
            "model_providers.{CODEX_DAM_PROVIDER_ID}.name={}",
            toml_string("OpenAI through DAM")
        ),
        "-c".to_string(),
        format!(
            "model_providers.{CODEX_DAM_PROVIDER_ID}.base_url={}",
            toml_string(&codex_base_url)
        ),
        "-c".to_string(),
        format!(
            "model_providers.{CODEX_DAM_PROVIDER_ID}.env_key={}",
            toml_string(CODEX_API_KEY_ENV)
        ),
        "-c".to_string(),
        format!(
            "model_providers.{CODEX_DAM_PROVIDER_ID}.wire_api={}",
            toml_string("responses")
        ),
        "-c".to_string(),
        format!("model_providers.{CODEX_DAM_PROVIDER_ID}.supports_websockets=false"),
    ];
    tool_args.extend(args.tool_args.iter().cloned());

    Ok(ToolCommand {
        program: "codex".to_string(),
        args: tool_args,
        env: Vec::new(),
    })
}

fn validate_codex_api_tool_args(args: &[String]) -> Result<(), String> {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--oss" || arg == "--local-provider" {
            return Err(format!(
                "{arg} cannot be used with dam codex --api because it would bypass the DAM OpenAI provider"
            ));
        }
        if arg == "-c" || arg == "--config" {
            let Some(value) = args.get(i + 1) else {
                return Ok(());
            };
            if codex_config_override_can_bypass_dam(value) {
                return Err(format!(
                    "Codex config override `{value}` cannot be used with dam codex --api because it can bypass DAM"
                ));
            }
            i += 2;
            continue;
        }
        i += 1;
    }

    Ok(())
}

fn codex_config_override_can_bypass_dam(value: &str) -> bool {
    let Some((key, _)) = value.split_once('=') else {
        return false;
    };
    let key = key.trim();
    key == "model_provider"
        || key == "openai_base_url"
        || key == "chatgpt_base_url"
        || key == "preferred_auth_method"
        || key.starts_with("model_providers.")
        || key.starts_with("profiles.")
}

fn toml_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn spawn_tool(command: &ToolCommand) -> Result<tokio::process::Child, String> {
    let mut child = TokioCommand::new(&command.program);
    child
        .args(command.args.iter().map(OsString::from))
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    for (key, value) in &command.env {
        child.env(key, value);
    }

    child
        .spawn()
        .map_err(|error| format!("failed to start {}: {error}", command.program))
}

fn usage() -> &'static str {
    "Usage: dam <command>\n\nCommands:\n  connect       Start the background DAM proxy daemon\n  status        Show background DAM protection status\n  disconnect    Stop the background DAM proxy daemon\n  integrations  List and inspect known harness integration profiles\n  codex         Start Codex through DAM in explicit API-key mode, or fail closed for ChatGPT-login mode\n  claude        Start a local DAM proxy and launch Claude Code through it\n\nRun `dam connect --help`, `dam integrations --help`, `dam codex --help`, or `dam claude --help` for command options."
}

fn usage_connect() -> &'static str {
    "Usage: dam connect [--profile PROFILE|--openai|--anthropic] [DAM_OPTIONS]\n\nStarts a background DAM proxy daemon. By default this exposes an OpenAI-compatible local endpoint at http://127.0.0.1:7828/v1 and forwards caller-owned provider auth headers.\n\nDAM options:\n  --profile <id>          Apply integration profile daemon defaults\n  --openai                Use the OpenAI-compatible preset (default)\n  --anthropic             Use the Anthropic preset\n  --config <path>         Load DAM config file before daemon overrides\n  --listen <addr>         Local proxy listen address (default: 127.0.0.1:7828)\n  --target-name <name>    Proxy target name (default: openai)\n  --provider <provider>   Provider adapter: openai-compatible or anthropic\n  --upstream <url>        Provider upstream URL\n  --db <path>             Vault SQLite path (default: vault.db)\n  --log <path>            Log SQLite path (default: log.db)\n  --consent-db <path>     Consent SQLite path (default: consent.db)\n  --no-log                Disable DAM log writes\n  --no-resolve-inbound    Leave DAM references unresolved in inbound responses (default)\n  --resolve-inbound       Restore DAM references in inbound responses\n\nKnown profiles: openai-compatible, anthropic, claude-code, codex-api, xai-compatible"
}

fn usage_status() -> &'static str {
    "Usage: dam status [--json]"
}

fn usage_disconnect() -> &'static str {
    "Usage: dam disconnect"
}

fn usage_integrations() -> &'static str {
    "Usage: dam integrations <command>\n\nCommands:\n  list  List known integration profiles\n  show  Show setup details for one integration profile"
}

fn usage_integrations_list() -> &'static str {
    "Usage: dam integrations list [--proxy-url http://127.0.0.1:7828] [--json]"
}

fn usage_integrations_show() -> &'static str {
    "Usage: dam integrations show <profile> [--proxy-url http://127.0.0.1:7828] [--json]"
}

fn usage_launch(tool: Tool) -> &'static str {
    match tool {
        Tool::Codex => {
            "Usage: dam codex --api [DAM_OPTIONS] [-- CODEX_ARGS...]\n\nCodex ChatGPT-login mode is disabled: current Codex ChatGPT model turns use wss://chatgpt.com/backend-api/codex/responses and are not controlled by chatgpt_base_url. Use --api with OPENAI_API_KEY to route Codex Responses API traffic through DAM.\n\nDAM options:\n  --api                   Use Codex API-key mode through DAM (requires OPENAI_API_KEY)\n  --config <path>         Load DAM config file before launcher overrides\n  --listen <addr>         Local proxy listen address (default: 127.0.0.1:7828)\n  --upstream <url>        Provider upstream (default with --api: https://api.openai.com)\n  --db <path>             Vault SQLite path (default: vault.db)\n  --log <path>            Log SQLite path (default: log.db)\n  --consent-db <path>     Consent SQLite path (default: consent.db)\n  --no-log                Disable DAM log writes\n  --no-resolve-inbound    Leave DAM references unresolved in inbound responses (default)\n  --resolve-inbound       Restore DAM references in inbound responses"
        }
        Tool::Claude => {
            "Usage: dam claude [DAM_OPTIONS] [-- CLAUDE_ARGS...]\n\nDAM options:\n  --config <path>          Load DAM config file before launcher overrides\n  --listen <addr>          Local proxy listen address (default: 127.0.0.1:7828)\n  --upstream <url>         Provider upstream (default: https://api.anthropic.com)\n  --db <path>              Vault SQLite path (default: vault.db)\n  --log <path>             Log SQLite path (default: log.db)\n  --consent-db <path>      Consent SQLite path (default: consent.db)\n  --no-log                 Disable DAM log writes\n  --no-resolve-inbound     Leave DAM references unresolved in inbound responses (default)\n  --resolve-inbound        Restore DAM references in inbound responses"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_launch_fails_closed_until_model_transport_is_protected() {
        let args = LaunchArgs {
            tool: Tool::Codex,
            config_path: None,
            listen: "127.0.0.1:7828".to_string(),
            upstream: CODEX_CHATGPT_UPSTREAM.to_string(),
            vault_path: PathBuf::from("vault.db"),
            log_path: Some(PathBuf::from("log.db")),
            consent_path: None,
            resolve_inbound: None,
            codex_api_key_mode: false,
            tool_args: Vec::new(),
        };

        let error = ensure_supported_launch(&args).unwrap_err();
        assert!(error.contains("backend-api/codex/responses"));
        assert!(error.contains("would not protect the prompt"));
        assert!(error.contains("dam codex --api"));
    }

    #[test]
    fn claude_command_sets_anthropic_base_url_env() {
        let args = LaunchArgs {
            tool: Tool::Claude,
            config_path: None,
            listen: "127.0.0.1:7828".to_string(),
            upstream: ANTHROPIC_UPSTREAM.to_string(),
            vault_path: PathBuf::from("vault.db"),
            log_path: Some(PathBuf::from("log.db")),
            consent_path: None,
            resolve_inbound: None,
            codex_api_key_mode: false,
            tool_args: vec!["--model".into(), "sonnet".into()],
        };
        let command = tool_command(&args, "http://127.0.0.1:7828/").unwrap();

        assert_eq!(command.program, "claude");
        assert_eq!(command.args, ["--model", "sonnet"]);
        assert_eq!(
            command.env,
            [(
                "ANTHROPIC_BASE_URL".to_string(),
                "http://127.0.0.1:7828".to_string()
            )]
        );
    }

    #[test]
    fn parses_dam_options_and_passes_remaining_args_to_tool() {
        let cli = parse_cli([
            "codex".to_string(),
            "--listen".to_string(),
            "127.0.0.1:9000".to_string(),
            "--db".to_string(),
            "test-vault.db".to_string(),
            "--consent-db".to_string(),
            "test-consent.db".to_string(),
            "--no-resolve-inbound".to_string(),
            "--".to_string(),
            "-m".to_string(),
            "gpt-5.5".to_string(),
        ])
        .unwrap();

        let CommandKind::Launch(args) = cli.command else {
            panic!("expected launch");
        };
        assert_eq!(args.tool, Tool::Codex);
        assert_eq!(args.listen, "127.0.0.1:9000");
        assert_eq!(args.vault_path, PathBuf::from("test-vault.db"));
        assert_eq!(args.consent_path, Some(PathBuf::from("test-consent.db")));
        assert_eq!(args.resolve_inbound, Some(false));
        assert!(!args.codex_api_key_mode);
        assert_eq!(args.tool_args, ["-m", "gpt-5.5"]);
    }

    #[test]
    fn parses_codex_api_mode_and_openai_api_default_upstream() {
        let cli = parse_cli([
            "codex".to_string(),
            "--api".to_string(),
            "--".to_string(),
            "-m".to_string(),
            "gpt-5.5".to_string(),
        ])
        .unwrap();

        let CommandKind::Launch(args) = cli.command else {
            panic!("expected launch");
        };
        assert_eq!(args.tool, Tool::Codex);
        assert!(args.codex_api_key_mode);
        assert_eq!(args.upstream, OPENAI_API_UPSTREAM);
        assert_eq!(args.tool_args, ["-m", "gpt-5.5"]);
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
        assert_eq!(args.listen, "127.0.0.1:9000");
        assert_eq!(args.target_name, "anthropic");
        assert_eq!(args.provider, "anthropic");
        assert_eq!(args.upstream, ANTHROPIC_UPSTREAM);
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
        assert_eq!(args.listen, "127.0.0.1:9000");
        assert_eq!(args.target_name, "xai");
        assert_eq!(args.provider, "openai-compatible");
        assert_eq!(args.upstream, "https://api.x.ai");
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
    fn integration_profile_render_quotes_spaced_command_args() {
        let profile = dam_integrations::profile("codex-api", "http://127.0.0.1:7828").unwrap();
        let rendered = render_integration_profile(&profile, "http://127.0.0.1:7828");

        assert!(rendered.contains("'model_providers.dam_openai.name=\"OpenAI through DAM\"'"));
        assert!(rendered.contains("model_providers.dam_openai.supports_websockets=false"));
    }

    #[test]
    fn parses_status_json() {
        let cli = parse_cli(["status".to_string(), "--json".to_string()]).unwrap();

        assert_eq!(cli.command, CommandKind::Status(StatusArgs { json: true }));
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

    #[test]
    fn codex_api_command_sets_dam_provider_overrides() {
        let args = LaunchArgs {
            tool: Tool::Codex,
            config_path: None,
            listen: "127.0.0.1:7828".to_string(),
            upstream: OPENAI_API_UPSTREAM.to_string(),
            vault_path: PathBuf::from("vault.db"),
            log_path: Some(PathBuf::from("log.db")),
            consent_path: None,
            resolve_inbound: None,
            codex_api_key_mode: true,
            tool_args: vec!["-m".into(), "gpt-5.5".into()],
        };

        let command = tool_command(&args, "http://127.0.0.1:7828").unwrap();

        assert_eq!(command.program, "codex");
        assert_eq!(command.env, Vec::<(String, String)>::new());
        assert!(
            command
                .args
                .contains(&"model_provider=\"dam_openai\"".to_string())
        );
        assert!(command.args.contains(
            &"model_providers.dam_openai.base_url=\"http://127.0.0.1:7828/v1\"".to_string()
        ));
        assert!(
            command
                .args
                .contains(&"model_providers.dam_openai.env_key=\"OPENAI_API_KEY\"".to_string())
        );
        assert!(
            command
                .args
                .contains(&"model_providers.dam_openai.supports_websockets=false".to_string())
        );
        assert!(
            command
                .args
                .ends_with(&["-m".to_string(), "gpt-5.5".to_string()])
        );
    }

    #[test]
    fn codex_api_rejects_provider_overrides_that_can_bypass_dam() {
        let error = validate_codex_api_tool_args(&[
            "-c".to_string(),
            "model_provider=\"openai\"".to_string(),
        ])
        .unwrap_err();

        assert!(error.contains("bypass DAM"));
    }

    #[test]
    fn codex_api_rejects_chatgpt_and_profile_overrides_that_can_bypass_dam() {
        for override_value in [
            "chatgpt_base_url=\"https://chatgpt.com\"",
            "preferred_auth_method=\"chatgpt\"",
            "profiles.default.model_provider=\"openai\"",
        ] {
            let error =
                validate_codex_api_tool_args(&["-c".to_string(), override_value.to_string()])
                    .unwrap_err();

            assert!(error.contains("bypass DAM"), "{override_value}");
        }
    }

    #[test]
    fn first_unknown_argument_starts_tool_args() {
        let cli = parse_cli([
            "claude".to_string(),
            "--model".to_string(),
            "sonnet".to_string(),
        ])
        .unwrap();

        let CommandKind::Launch(args) = cli.command else {
            panic!("expected launch");
        };
        assert_eq!(args.tool, Tool::Claude);
        assert_eq!(args.tool_args, ["--model", "sonnet"]);
    }

    #[test]
    fn launcher_config_uses_pass_through_auth() {
        let args = LaunchArgs {
            tool: Tool::Codex,
            config_path: None,
            listen: "127.0.0.1:7828".to_string(),
            upstream: OPENAI_API_UPSTREAM.to_string(),
            vault_path: PathBuf::from("vault.db"),
            log_path: Some(PathBuf::from("log.db")),
            consent_path: Some(PathBuf::from("consent-test.db")),
            resolve_inbound: None,
            codex_api_key_mode: true,
            tool_args: Vec::new(),
        };

        let config = proxy_config(&args).unwrap();

        assert!(config.proxy.enabled);
        assert_eq!(config.proxy.targets.len(), 1);
        assert_eq!(config.proxy.targets[0].name, "openai");
        assert_eq!(config.proxy.targets[0].provider, "openai-compatible");
        assert_eq!(config.proxy.targets[0].upstream, OPENAI_API_UPSTREAM);
        assert_eq!(config.proxy.targets[0].api_key_env, None);
        assert_eq!(config.proxy.targets[0].api_key, None);
        assert!(!config.proxy.resolve_inbound);
        assert!(config.log.enabled);
        assert_eq!(config.log.sqlite_path, PathBuf::from("log.db"));
        assert_eq!(config.consent.sqlite_path, PathBuf::from("consent-test.db"));
    }

    #[test]
    fn launcher_config_can_enable_inbound_resolution() {
        let args = LaunchArgs {
            tool: Tool::Claude,
            config_path: None,
            listen: "127.0.0.1:7828".to_string(),
            upstream: ANTHROPIC_UPSTREAM.to_string(),
            vault_path: PathBuf::from("vault.db"),
            log_path: Some(PathBuf::from("log.db")),
            consent_path: None,
            resolve_inbound: Some(true),
            codex_api_key_mode: false,
            tool_args: Vec::new(),
        };

        let config = proxy_config(&args).unwrap();

        assert_eq!(config.proxy.targets[0].name, "anthropic");
        assert_eq!(config.proxy.targets[0].provider, "anthropic");
        assert!(config.proxy.resolve_inbound);
    }
}
