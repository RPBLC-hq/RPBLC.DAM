use std::env;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Status(StatusArgs),
    Doctor(DoctorArgs),
    ConfigCheck(ConfigCheckArgs),
    McpConfig(McpConfigArgs),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CommonArgs {
    config: dam_config::ConfigOverrides,
    json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StatusArgs {
    common: CommonArgs,
    proxy_url: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DoctorArgs {
    common: CommonArgs,
    proxy_url: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ConfigCheckArgs {
    common: CommonArgs,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct McpConfigArgs {
    config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandOutput {
    code: i32,
    stdout: String,
    stderr: String,
}

impl CommandOutput {
    fn fail(code: i32, stderr: impl Into<String>) -> Self {
        Self {
            code,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

#[tokio::main]
async fn main() {
    let output = match parse_args(env::args().skip(1)) {
        Ok(command) => run(command).await,
        Err(message) => CommandOutput::fail(2, format!("{message}\n{}", usage())),
    };

    print!("{}", output.stdout);
    eprint!("{}", output.stderr);
    std::process::exit(output.code);
}

async fn run(command: Command) -> CommandOutput {
    match command {
        Command::Status(args) => status(args).await,
        Command::Doctor(args) => doctor(args).await,
        Command::ConfigCheck(args) => config_check(args),
        Command::McpConfig(args) => mcp_config(args),
    }
}

async fn status(args: StatusArgs) -> CommandOutput {
    let (config, config_warning) = match dam_config::load(&args.common.config) {
        Ok(config) => (Some(config), None),
        Err(error) if args.proxy_url.is_some() => {
            (None, Some(format!("config load failed: {error}")))
        }
        Err(error) => return CommandOutput::fail(2, format!("config load failed: {error}\n")),
    };

    let health_url = match status_url(&args, config.as_ref()) {
        Ok(url) => url,
        Err(message) => return CommandOutput::fail(2, format!("{message}\n")),
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(2_000))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return CommandOutput::fail(1, format!("failed to build http client: {error}\n"));
        }
    };

    let report = match client.get(&health_url).send().await {
        Ok(response) => match response.json::<dam_api::ProxyReport>().await {
            Ok(report) => report,
            Err(error) => dam_down_report(
                config.as_ref(),
                format!("DAM proxy returned an unreadable status response: {error}"),
            ),
        },
        Err(error) => dam_down_report(
            config.as_ref(),
            format!("DAM proxy is not reachable at {health_url}: {error}"),
        ),
    };

    let code = if report.state == dam_api::ProxyState::Protected {
        0
    } else {
        1
    };

    let stdout = if args.common.json {
        json(&report)
    } else {
        render_proxy_report(&report, config_warning.as_deref())
    };

    CommandOutput {
        code,
        stdout,
        stderr: String::new(),
    }
}

async fn doctor(args: DoctorArgs) -> CommandOutput {
    let config = match dam_config::load(&args.common.config) {
        Ok(config) => config,
        Err(error) => {
            let report = config_load_failed_report(error);
            return CommandOutput {
                code: 2,
                stdout: if args.common.json {
                    json(&report)
                } else {
                    render_health_report(&report)
                },
                stderr: String::new(),
            };
        }
    };

    let report = dam_diagnostics::doctor_report(
        &config,
        &dam_diagnostics::DoctorOptions {
            proxy_url: args.proxy_url,
        },
    )
    .await;
    let code = if report.state == dam_api::HealthState::Unhealthy {
        1
    } else {
        0
    };
    let stdout = if args.common.json {
        json(&report)
    } else {
        render_health_report(&report)
    };

    CommandOutput {
        code,
        stdout,
        stderr: String::new(),
    }
}

fn config_check(args: ConfigCheckArgs) -> CommandOutput {
    let config = match dam_config::load(&args.common.config) {
        Ok(config) => config,
        Err(error) => {
            let report = config_load_failed_report(error);
            return CommandOutput {
                code: 1,
                stdout: if args.common.json {
                    json(&report)
                } else {
                    render_health_report(&report)
                },
                stderr: String::new(),
            };
        }
    };

    let report = dam_diagnostics::config_report(&config);
    let code = if report.state == dam_api::HealthState::Unhealthy {
        1
    } else {
        0
    };
    let stdout = if args.common.json {
        json(&report)
    } else {
        render_health_report(&report)
    };

    CommandOutput {
        code,
        stdout,
        stderr: String::new(),
    }
}

fn mcp_config(args: McpConfigArgs) -> CommandOutput {
    let mut mcp_args = Vec::new();
    if let Some(config_path) = args.config_path {
        mcp_args.push("--config".to_string());
        mcp_args.push(config_path.display().to_string());
    }

    let value = serde_json::json!({
        "mcpServers": {
            "dam": {
                "command": "dam-mcp",
                "args": mcp_args
            }
        }
    });

    CommandOutput {
        code: 0,
        stdout: format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
        stderr: String::new(),
    }
}

fn config_load_failed_report(error: dam_config::ConfigError) -> dam_api::HealthReport {
    dam_api::HealthReport {
        state: dam_api::HealthState::Unhealthy,
        components: vec![dam_api::ComponentHealth {
            component: "config".to_string(),
            state: dam_api::HealthState::Unhealthy,
            message: format!("config load failed: {error}"),
        }],
        diagnostics: vec![dam_api::Diagnostic::new(
            dam_api::DiagnosticSeverity::Error,
            "config_load_failed",
            error.to_string(),
        )],
    }
}

fn status_url(args: &StatusArgs, config: Option<&dam_config::DamConfig>) -> Result<String, String> {
    if let Some(proxy_url) = &args.proxy_url {
        return dam_diagnostics::proxy_health_url(
            &dam_config::DamConfig::default(),
            Some(proxy_url),
        );
    }

    let config =
        config.ok_or_else(|| "config is required when --proxy-url is omitted".to_string())?;
    dam_diagnostics::proxy_health_url(config, None)
}

fn dam_down_report(
    config: Option<&dam_config::DamConfig>,
    message: String,
) -> dam_api::ProxyReport {
    let target = config.and_then(|config| config.proxy.targets.first());
    dam_api::ProxyReport {
        operation_id: None,
        target: target.map(|target| target.name.clone()),
        upstream: target.map(|target| target.upstream.clone()),
        state: dam_api::ProxyState::DamDown,
        message: message.clone(),
        diagnostics: vec![dam_api::Diagnostic::new(
            dam_api::DiagnosticSeverity::Error,
            "dam_down",
            message,
        )],
    }
}

fn render_proxy_report(report: &dam_api::ProxyReport, config_warning: Option<&str>) -> String {
    let mut output = String::new();
    output.push_str(&format!("state: {}\n", proxy_state_tag(report.state)));
    output.push_str(&format!("message: {}\n", report.message));
    if let Some(target) = &report.target {
        output.push_str(&format!("target: {target}\n"));
    }
    if let Some(upstream) = &report.upstream {
        output.push_str(&format!("upstream: {upstream}\n"));
    }
    if let Some(operation_id) = &report.operation_id {
        output.push_str(&format!("operation_id: {operation_id}\n"));
    }
    if let Some(config_warning) = config_warning {
        output.push_str(&format!("warning: {config_warning}\n"));
    }
    for diagnostic in &report.diagnostics {
        output.push_str(&format!(
            "{} {}: {}\n",
            severity_tag(diagnostic.severity),
            diagnostic.code,
            diagnostic.message
        ));
    }
    output
}

fn render_health_report(report: &dam_api::HealthReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("state: {}\n", health_state_tag(report.state)));
    for component in &report.components {
        output.push_str(&format!(
            "{}: {} - {}\n",
            component.component,
            health_state_tag(component.state),
            component.message
        ));
    }
    for diagnostic in &report.diagnostics {
        output.push_str(&format!(
            "{} {}: {}\n",
            severity_tag(diagnostic.severity),
            diagnostic.code,
            diagnostic.message
        ));
    }
    output
}

fn json<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_string_pretty(value) {
        Ok(json) => format!("{json}\n"),
        Err(error) => format!(
            "{{\"state\":\"unhealthy\",\"diagnostics\":[{{\"severity\":\"error\",\"code\":\"json_serialize_failed\",\"message\":\"{error}\"}}]}}\n"
        ),
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

fn health_state_tag(state: dam_api::HealthState) -> &'static str {
    match state {
        dam_api::HealthState::Healthy => "healthy",
        dam_api::HealthState::Degraded => "degraded",
        dam_api::HealthState::Unhealthy => "unhealthy",
        dam_api::HealthState::Unknown => "unknown",
    }
}

fn severity_tag(severity: dam_api::DiagnosticSeverity) -> &'static str {
    match severity {
        dam_api::DiagnosticSeverity::Info => "info",
        dam_api::DiagnosticSeverity::Warning => "warning",
        dam_api::DiagnosticSeverity::Error => "error",
    }
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    if args.is_empty() {
        return Err("missing command".to_string());
    }

    match args[0].as_str() {
        "status" => parse_status_args(&args[1..]),
        "doctor" => parse_doctor_args(&args[1..]),
        "config" => parse_config_args(&args[1..]),
        "mcp" => parse_mcp_args(&args[1..]),
        "-h" | "--help" => {
            println!("{}", usage());
            std::process::exit(0);
        }
        command => Err(format!("unknown command: {command}")),
    }
}

fn parse_mcp_args(args: &[String]) -> Result<Command, String> {
    if args.first().map(String::as_str) != Some("config") {
        return Err("expected mcp config".to_string());
    }

    let mut parsed = McpConfigArgs::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                parsed.config_path = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| "--config requires a path".to_string())?,
                ));
            }
            "-h" | "--help" => {
                println!("{}", usage_mcp_config());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown mcp config argument: {arg}")),
        }
        i += 1;
    }

    Ok(Command::McpConfig(parsed))
}

fn parse_status_args(args: &[String]) -> Result<Command, String> {
    let mut parsed = StatusArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                parsed.common.config.config_path = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| "--config requires a path".to_string())?,
                ));
            }
            "--proxy-url" => {
                i += 1;
                parsed.proxy_url = Some(
                    args.get(i)
                        .ok_or_else(|| "--proxy-url requires a URL".to_string())?
                        .clone(),
                );
            }
            "--json" => parsed.common.json = true,
            "-h" | "--help" => {
                println!("{}", usage_status());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown status argument: {arg}")),
        }
        i += 1;
    }

    Ok(Command::Status(parsed))
}

fn parse_doctor_args(args: &[String]) -> Result<Command, String> {
    let mut parsed = DoctorArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                parsed.common.config.config_path = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| "--config requires a path".to_string())?,
                ));
            }
            "--proxy-url" => {
                i += 1;
                parsed.proxy_url = Some(
                    args.get(i)
                        .ok_or_else(|| "--proxy-url requires a URL".to_string())?
                        .clone(),
                );
            }
            "--json" => parsed.common.json = true,
            "-h" | "--help" => {
                println!("{}", usage_doctor());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown doctor argument: {arg}")),
        }
        i += 1;
    }

    Ok(Command::Doctor(parsed))
}

fn parse_config_args(args: &[String]) -> Result<Command, String> {
    if args.first().map(String::as_str) != Some("check") {
        return Err("expected config check".to_string());
    }

    let mut parsed = ConfigCheckArgs::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                parsed.common.config.config_path = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| "--config requires a path".to_string())?,
                ));
            }
            "--json" => parsed.common.json = true,
            "-h" | "--help" => {
                println!("{}", usage_config_check());
                std::process::exit(0);
            }
            arg => return Err(format!("unknown config check argument: {arg}")),
        }
        i += 1;
    }

    Ok(Command::ConfigCheck(parsed))
}

fn usage() -> &'static str {
    "Usage: damctl <command>\n\nCommands:\n  status        Check the local DAM proxy health endpoint\n  doctor        Run local readiness checks for the protected UX\n  config check  Validate local DAM config for the current implementation\n  mcp config    Print MCP server config for DAM"
}

fn usage_status() -> &'static str {
    "Usage: damctl status [--config dam.toml] [--proxy-url http://127.0.0.1:7828] [--json]"
}

fn usage_doctor() -> &'static str {
    "Usage: damctl doctor [--config dam.toml] [--proxy-url http://127.0.0.1:7828] [--json]"
}

fn usage_config_check() -> &'static str {
    "Usage: damctl config check [--config dam.toml] [--json]"
}

fn usage_mcp_config() -> &'static str {
    "Usage: damctl mcp config [--config dam.toml]"
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use tokio::net::TcpListener;

    async fn spawn_health(report: dam_api::ProxyReport) -> String {
        async fn health_from_extension(
            axum::Extension(report): axum::Extension<dam_api::ProxyReport>,
        ) -> Json<dam_api::ProxyReport> {
            Json(report)
        }

        let app = Router::new().route("/health", get(health_from_extension));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app.layer(axum::Extension(report)))
                .await
                .unwrap();
        });
        format!("http://{addr}")
    }

    fn write_config(dir: &std::path::Path, body: &str) -> PathBuf {
        let path = dir.join("dam.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn parse_status_accepts_proxy_url_and_json() {
        let command = parse_args([
            "status".to_string(),
            "--proxy-url".to_string(),
            "http://127.0.0.1:7828".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            command,
            Command::Status(StatusArgs {
                common: CommonArgs {
                    json: true,
                    ..CommonArgs::default()
                },
                proxy_url: Some("http://127.0.0.1:7828".to_string()),
            })
        );
    }

    #[test]
    fn parse_doctor_accepts_config_proxy_url_and_json() {
        let command = parse_args([
            "doctor".to_string(),
            "--config".to_string(),
            "/tmp/dam.toml".to_string(),
            "--proxy-url".to_string(),
            "http://127.0.0.1:7828".to_string(),
            "--json".to_string(),
        ])
        .unwrap();

        assert_eq!(
            command,
            Command::Doctor(DoctorArgs {
                common: CommonArgs {
                    config: dam_config::ConfigOverrides {
                        config_path: Some(PathBuf::from("/tmp/dam.toml")),
                        ..dam_config::ConfigOverrides::default()
                    },
                    json: true,
                },
                proxy_url: Some("http://127.0.0.1:7828".to_string()),
            })
        );
    }

    #[test]
    fn parse_config_check_accepts_config() {
        let command = parse_args([
            "config".to_string(),
            "check".to_string(),
            "--config".to_string(),
            "/tmp/dam.toml".to_string(),
        ])
        .unwrap();

        assert_eq!(
            command,
            Command::ConfigCheck(ConfigCheckArgs {
                common: CommonArgs {
                    config: dam_config::ConfigOverrides {
                        config_path: Some(PathBuf::from("/tmp/dam.toml")),
                        ..dam_config::ConfigOverrides::default()
                    },
                    json: false,
                }
            })
        );
    }

    #[test]
    fn parse_mcp_config_accepts_config() {
        let command = parse_args([
            "mcp".to_string(),
            "config".to_string(),
            "--config".to_string(),
            "/tmp/dam.toml".to_string(),
        ])
        .unwrap();

        assert_eq!(
            command,
            Command::McpConfig(McpConfigArgs {
                config_path: Some(PathBuf::from("/tmp/dam.toml")),
            })
        );
    }

    #[test]
    fn mcp_config_outputs_dam_mcp_server() {
        let output = mcp_config(McpConfigArgs {
            config_path: Some(PathBuf::from("dam.toml")),
        });

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("\"command\": \"dam-mcp\""));
        assert!(output.stdout.contains("\"--config\""));
    }

    #[tokio::test]
    async fn status_reports_protected_from_proxy() {
        let proxy_url = spawn_health(dam_api::ProxyReport {
            operation_id: None,
            target: Some("openai".to_string()),
            upstream: Some("http://127.0.0.1:9999".to_string()),
            state: dam_api::ProxyState::Protected,
            message: "proxy is ready".to_string(),
            diagnostics: Vec::new(),
        })
        .await;

        let output = status(StatusArgs {
            common: CommonArgs::default(),
            proxy_url: Some(proxy_url),
        })
        .await;

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("state: protected"));
        assert!(output.stdout.contains("target: openai"));
    }

    #[tokio::test]
    async fn status_json_reports_dam_down_when_proxy_is_unreachable() {
        let output = status(StatusArgs {
            common: CommonArgs {
                json: true,
                ..CommonArgs::default()
            },
            proxy_url: Some("http://127.0.0.1:1".to_string()),
        })
        .await;

        assert_eq!(output.code, 1);
        let report: dam_api::ProxyReport = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(report.state, dam_api::ProxyState::DamDown);
        assert_eq!(report.diagnostics[0].code, "dam_down");
    }

    #[tokio::test]
    async fn doctor_json_reports_router_and_proxy_runtime() {
        let proxy_url = spawn_health(dam_api::ProxyReport {
            operation_id: None,
            target: Some("openai".to_string()),
            upstream: Some("http://127.0.0.1:9999".to_string()),
            state: dam_api::ProxyState::Protected,
            message: "proxy is ready".to_string(),
            diagnostics: Vec::new(),
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            dir.path(),
            &format!(
                r#"
                [vault]
                path = "{vault}"

                [log]
                enabled = true
                path = "{log}"

                [consent]
                path = "{consent}"

                [proxy]
                enabled = true
                listen = "127.0.0.1:7828"

                [[proxy.targets]]
                name = "openai"
                provider = "openai-compatible"
                upstream = "https://api.openai.com"
                "#,
                vault = dir.path().join("vault.db").display(),
                log = dir.path().join("log.db").display(),
                consent = dir.path().join("consent.db").display(),
            ),
        );

        let output = doctor(DoctorArgs {
            common: CommonArgs {
                config: dam_config::ConfigOverrides {
                    config_path: Some(path),
                    ..dam_config::ConfigOverrides::default()
                },
                json: true,
            },
            proxy_url: Some(proxy_url),
        })
        .await;

        assert_eq!(output.code, 0);
        let report: dam_api::HealthReport = serde_json::from_str(&output.stdout).unwrap();
        assert!(report.components.iter().any(|component| {
            component.component == "router" && component.state == dam_api::HealthState::Healthy
        }));
        assert!(report.components.iter().any(|component| {
            component.component == "proxy_runtime"
                && component.state == dam_api::HealthState::Healthy
        }));
    }

    #[test]
    fn config_check_reports_missing_proxy_api_key_as_unhealthy() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            dir.path(),
            r#"
            [proxy]
            enabled = true
            listen = "127.0.0.1:7828"

            [[proxy.targets]]
            name = "openai"
            provider = "openai-compatible"
            upstream = "https://api.openai.com"
            api_key_env = "MISSING_TEST_OPENAI_KEY"
            "#,
        );

        let output = config_check(ConfigCheckArgs {
            common: CommonArgs {
                config: dam_config::ConfigOverrides {
                    config_path: Some(path),
                    ..dam_config::ConfigOverrides::default()
                },
                json: true,
            },
        });

        assert_eq!(output.code, 1);
        let report: dam_api::HealthReport = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(report.state, dam_api::HealthState::Unhealthy);
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "proxy_config_invalid"
                && diagnostic
                    .message
                    .contains("requires missing env var MISSING_TEST_OPENAI_KEY")
        }));
    }

    #[test]
    fn config_check_accepts_anthropic_provider() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            dir.path(),
            r#"
            [proxy]
            enabled = true
            listen = "127.0.0.1:7828"

            [[proxy.targets]]
            name = "anthropic"
            provider = "anthropic"
            upstream = "https://api.anthropic.com"
            "#,
        );

        let output = config_check(ConfigCheckArgs {
            common: CommonArgs {
                config: dam_config::ConfigOverrides {
                    config_path: Some(path),
                    ..dam_config::ConfigOverrides::default()
                },
                json: true,
            },
        });

        assert_eq!(output.code, 0);
        let report: dam_api::HealthReport = serde_json::from_str(&output.stdout).unwrap();
        assert_ne!(report.state, dam_api::HealthState::Unhealthy);
        assert!(!report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "proxy_config_invalid"
                && diagnostic.message.contains("unsupported provider")
        }));
    }

    #[test]
    fn default_config_report_is_degraded_but_not_failed() {
        let report = dam_diagnostics::config_report(&dam_config::DamConfig::default());
        let output = CommandOutput {
            code: if report.state == dam_api::HealthState::Unhealthy {
                1
            } else {
                0
            },
            stdout: render_health_report(&report),
            stderr: String::new(),
        };

        assert_eq!(output.code, 0);
        assert!(output.stdout.contains("state: degraded"));
        assert!(
            output
                .stdout
                .contains("proxy_config: degraded - proxy is disabled")
        );
    }
}
