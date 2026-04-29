use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoctorOptions {
    pub proxy_url: Option<String>,
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
