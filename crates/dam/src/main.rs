use std::{
    ffi::OsString,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use tokio::{net::TcpListener, process::Command, sync::oneshot};

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
    Help(Option<Tool>),
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
    }
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
        "codex" => parse_tool_command(Tool::Codex, &args[1..]),
        "claude" => parse_tool_command(Tool::Claude, &args[1..]),
        other => Err(format!("unknown command: {other}\n{}", usage())),
    }
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
        proxy_target_provider: Some("openai-compatible".to_string()),
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
    key == "model_provider" || key == "openai_base_url" || key.starts_with("model_providers.")
}

fn toml_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn spawn_tool(command: &ToolCommand) -> Result<tokio::process::Child, String> {
    let mut child = Command::new(&command.program);
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
    "Usage: dam <command>\n\nCommands:\n  codex   Start Codex through DAM in explicit API-key mode, or fail closed for ChatGPT-login mode\n  claude  Start a local DAM proxy and launch Claude Code through it\n\nRun `dam codex --help` or `dam claude --help` for command options."
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

        assert!(config.proxy.resolve_inbound);
    }
}
