use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use dam_core::{
    EventSink, LogEvent, LogEventType, LogLevel, VaultReadError, VaultReader, VaultRecord,
    VaultWriter,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

const MAX_REQUEST_BYTES: usize = 10 * 1024 * 1024;
const ANTHROPIC_API_KEY_HEADER: &str = "x-api-key";

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("proxy is disabled")]
    Disabled,

    #[error("proxy target is missing")]
    MissingTarget,

    #[error("unsupported proxy provider: {0}")]
    UnsupportedProvider(String),

    #[error("invalid proxy listen address {addr}: {source}")]
    InvalidListen {
        addr: String,
        source: std::net::AddrParseError,
    },

    #[error("failed to bind proxy listener {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },

    #[error("proxy server failed: {0}")]
    Server(std::io::Error),

    #[error("failed to initialize provider: {0}")]
    ProviderInit(String),

    #[error("vault backend is unavailable and fail-closed is configured: {0}")]
    VaultUnavailable(String),

    #[error("log backend is unavailable and fail-closed is configured: {0}")]
    LogUnavailable(String),

    #[error("consent backend is unavailable: {0}")]
    ConsentUnavailable(String),
}

#[derive(Clone)]
enum ProviderAdapter {
    OpenAi(dam_provider_openai::OpenAiProvider),
    Anthropic(dam_provider_anthropic::AnthropicProvider),
}

impl ProviderAdapter {
    fn for_name(name: &str) -> Result<Self, ProxyError> {
        match name {
            "openai-compatible" => dam_provider_openai::OpenAiProvider::new()
                .map(Self::OpenAi)
                .map_err(|error| ProxyError::ProviderInit(error.to_string())),
            "anthropic" => dam_provider_anthropic::AnthropicProvider::new()
                .map(Self::Anthropic)
                .map_err(|error| ProxyError::ProviderInit(error.to_string())),
            other => Err(ProxyError::UnsupportedProvider(other.to_string())),
        }
    }

    fn caller_auth_header_present(&self, headers: &HeaderMap) -> bool {
        match self {
            Self::OpenAi(_) => headers.contains_key(header::AUTHORIZATION),
            Self::Anthropic(_) => {
                headers.contains_key(ANTHROPIC_API_KEY_HEADER)
                    || headers.contains_key(header::AUTHORIZATION)
            }
        }
    }
}

#[derive(Clone)]
pub struct ProxyState {
    target: dam_config::ProxyTargetConfig,
    default_failure_mode: dam_config::ProxyFailureMode,
    resolve_inbound: bool,
    vault: Arc<dyn ProxyVault>,
    consent_store: Option<Arc<dam_consent::ConsentStore>>,
    log_sink: Option<Arc<dyn EventSink>>,
    policy: dam_policy::StaticPolicy,
    replacement_options: dam_core::ReplacementPlanOptions,
    provider: ProviderAdapter,
}

trait ProxyVault: VaultWriter + VaultReader {}

impl<T> ProxyVault for T where T: VaultWriter + VaultReader {}

struct FailingVault {
    message: String,
}

impl VaultWriter for FailingVault {
    fn write(&self, _record: &VaultRecord) -> Result<(), dam_core::VaultWriteError> {
        Err(dam_core::VaultWriteError::new(self.message.clone()))
    }
}

impl VaultReader for FailingVault {
    fn read(&self, _reference: &dam_core::Reference) -> Result<Option<String>, VaultReadError> {
        Err(VaultReadError::new(self.message.clone()))
    }
}

pub async fn run(config: dam_config::DamConfig) -> Result<(), ProxyError> {
    let addr = config
        .proxy
        .listen
        .parse()
        .map_err(|source| ProxyError::InvalidListen {
            addr: config.proxy.listen.clone(),
            source,
        })?;
    let app = build_app(config)?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| ProxyError::Bind { addr, source })?;

    axum::serve(listener, app).await.map_err(ProxyError::Server)
}

pub fn build_app(config: dam_config::DamConfig) -> Result<Router, ProxyError> {
    if !config.proxy.enabled {
        return Err(ProxyError::Disabled);
    }

    let target = config
        .proxy
        .targets
        .first()
        .cloned()
        .ok_or(ProxyError::MissingTarget)?;

    let provider = ProviderAdapter::for_name(&target.provider)?;

    let replacement_options = dam_core::ReplacementPlanOptions {
        deduplicate_replacements: config.policy.deduplicate_replacements,
    };

    let state = ProxyState {
        target,
        default_failure_mode: config.proxy.default_failure_mode,
        resolve_inbound: config.proxy.resolve_inbound,
        vault: open_vault(&config)?,
        consent_store: open_consent_store(&config)?,
        log_sink: open_log_sink(&config)?,
        policy: dam_policy::StaticPolicy::from(config.policy),
        replacement_options,
        provider,
    };

    Ok(Router::new()
        .route("/health", get(health))
        .fallback(proxy)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(Arc::new(state)))
}

fn open_vault(config: &dam_config::DamConfig) -> Result<Arc<dyn ProxyVault>, ProxyError> {
    match config.vault.backend {
        dam_config::VaultBackend::Sqlite => match dam_vault::Vault::open(&config.vault.sqlite_path)
        {
            Ok(vault) => Ok(Arc::new(vault)),
            Err(error)
                if config.failure.vault_write == dam_config::VaultWriteFailureMode::RedactOnly =>
            {
                Ok(Arc::new(FailingVault {
                    message: error.to_string(),
                }))
            }
            Err(error) => Err(ProxyError::VaultUnavailable(error.to_string())),
        },
        dam_config::VaultBackend::Remote
            if config.failure.vault_write == dam_config::VaultWriteFailureMode::RedactOnly =>
        {
            Ok(Arc::new(FailingVault {
                message: "remote vault backend is not implemented".to_string(),
            }))
        }
        dam_config::VaultBackend::Remote => Err(ProxyError::VaultUnavailable(
            "remote vault backend is not implemented".to_string(),
        )),
    }
}

fn open_consent_store(
    config: &dam_config::DamConfig,
) -> Result<Option<Arc<dam_consent::ConsentStore>>, ProxyError> {
    if !config.consent.enabled {
        return Ok(None);
    }

    match config.consent.backend {
        dam_config::ConsentBackend::Sqlite => {
            dam_consent::ConsentStore::open(&config.consent.sqlite_path)
                .map(Arc::new)
                .map(Some)
                .map_err(|error| ProxyError::ConsentUnavailable(error.to_string()))
        }
    }
}

fn open_log_sink(config: &dam_config::DamConfig) -> Result<Option<Arc<dyn EventSink>>, ProxyError> {
    if !config.log.enabled || config.log.backend == dam_config::LogBackend::None {
        return Ok(None);
    }

    match config.log.backend {
        dam_config::LogBackend::Sqlite => match dam_log::LogStore::open(&config.log.sqlite_path) {
            Ok(store) => Ok(Some(Arc::new(store))),
            Err(_) if config.failure.log_write == dam_config::LogWriteFailureMode::WarnContinue => {
                Ok(None)
            }
            Err(error) => Err(ProxyError::LogUnavailable(error.to_string())),
        },
        dam_config::LogBackend::Remote
            if config.failure.log_write == dam_config::LogWriteFailureMode::WarnContinue =>
        {
            Ok(None)
        }
        dam_config::LogBackend::Remote => Err(ProxyError::LogUnavailable(
            "remote log backend is not implemented".to_string(),
        )),
        dam_config::LogBackend::None => Ok(None),
    }
}

async fn health(State(state): State<Arc<ProxyState>>) -> Response {
    let (proxy_state, message) = if state.target_requires_missing_api_key(&HeaderMap::new()) {
        (
            dam_api::ProxyState::ConfigRequired,
            "target API key is missing".to_string(),
        )
    } else {
        (dam_api::ProxyState::Protected, "proxy is ready".to_string())
    };

    status_response(StatusCode::OK, proxy_state, message, None, &state.target)
}

async fn proxy(
    State(state): State<Arc<ProxyState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation_id = dam_core::generate_operation_id();

    if state.target_requires_missing_api_key(&headers) {
        record_proxy_event(
            &state,
            &operation_id,
            LogLevel::Error,
            LogEventType::ProxyFailure,
            "config_required",
            "proxy target API key is missing",
        );
        return status_response(
            StatusCode::SERVICE_UNAVAILABLE,
            dam_api::ProxyState::ConfigRequired,
            "proxy target API key is missing".to_string(),
            Some(operation_id),
            &state.target,
        );
    }

    if request_has_unsupported_content_encoding(&headers) {
        record_proxy_event(
            &state,
            &operation_id,
            LogLevel::Error,
            LogEventType::ProxyFailure,
            "blocked",
            "encoded request bodies are not supported",
        );
        return status_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            dam_api::ProxyState::Blocked,
            "encoded request bodies are not supported".to_string(),
            Some(operation_id),
            &state.target,
        );
    }

    let body_text = match std::str::from_utf8(&body) {
        Ok(text) => text,
        Err(_) => {
            return handle_protection_failure(
                state,
                method,
                uri,
                headers,
                body,
                operation_id,
                "request body is not utf-8",
            )
            .await;
        }
    };

    let protected = match dam_pipeline::protect_text(
        body_text,
        &operation_id,
        &state.policy,
        state.vault.as_ref(),
        state.consent_store.as_deref(),
        state.log_sink.as_deref(),
        state.replacement_options,
    ) {
        Ok(result) => result,
        Err(_) => {
            return handle_protection_failure(
                state,
                method,
                uri,
                headers,
                body,
                operation_id,
                "consent check failed",
            )
            .await;
        }
    };

    if protected.is_blocked() {
        record_proxy_event(
            &state,
            &operation_id,
            LogLevel::Warn,
            LogEventType::ProxyFailure,
            "blocked",
            "proxy request blocked by policy",
        );
        return status_response(
            StatusCode::FORBIDDEN,
            dam_api::ProxyState::Blocked,
            "proxy request blocked by policy".to_string(),
            Some(operation_id),
            &state.target,
        );
    }

    let protected_body = protected
        .output
        .expect("non-blocked pipeline result should include output");
    forward_or_provider_down(
        state,
        method,
        uri,
        headers,
        Bytes::from(protected_body),
        operation_id,
        "protected",
    )
    .await
}

async fn handle_protection_failure(
    state: Arc<ProxyState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    operation_id: String,
    message: &'static str,
) -> Response {
    match state.failure_mode() {
        dam_config::ProxyFailureMode::BypassOnError => {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Warn,
                LogEventType::ProxyBypass,
                "bypass_on_error",
                message,
            );
            forward_or_provider_down(state, method, uri, headers, body, operation_id, "bypassing")
                .await
        }
        dam_config::ProxyFailureMode::RedactOnly | dam_config::ProxyFailureMode::BlockOnError => {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Error,
                LogEventType::ProxyFailure,
                "blocked",
                message,
            );
            status_response(
                StatusCode::BAD_GATEWAY,
                dam_api::ProxyState::Blocked,
                message.to_string(),
                Some(operation_id),
                &state.target,
            )
        }
    }
}

async fn forward_or_provider_down(
    state: Arc<ProxyState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    operation_id: String,
    action: &'static str,
) -> Response {
    match forward_request(&state, method, uri, headers, body, &operation_id).await {
        Ok(response) => {
            let event_type = if action == "bypassing" {
                LogEventType::ProxyBypass
            } else {
                LogEventType::ProxyForward
            };
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Info,
                event_type,
                action,
                "proxy request forwarded",
            );
            response
        }
        Err(error) => {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Error,
                LogEventType::ProxyFailure,
                "provider_down",
                "upstream provider is unavailable",
            );
            status_response(
                StatusCode::BAD_GATEWAY,
                dam_api::ProxyState::ProviderDown,
                error,
                Some(operation_id),
                &state.target,
            )
        }
    }
}

async fn forward_request(
    state: &ProxyState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    operation_id: &str,
) -> Result<Response, String> {
    let target_api_key = state
        .target
        .api_key
        .as_ref()
        .map(|api_key| api_key.expose());
    match &state.provider {
        ProviderAdapter::OpenAi(provider) => {
            let request = dam_provider_openai::ForwardRequest {
                upstream: &state.target.upstream,
                method,
                uri,
                headers,
                body,
                target_api_key,
            };
            provider
                .forward(request, |response_body| {
                    resolve_response_body(state, operation_id, response_body)
                })
                .await
                .map_err(|error| error.to_string())
        }
        ProviderAdapter::Anthropic(provider) => {
            let request = dam_provider_anthropic::ForwardRequest {
                upstream: &state.target.upstream,
                method,
                uri,
                headers,
                body,
                target_api_key,
            };
            provider
                .forward(request, |response_body| {
                    resolve_response_body(state, operation_id, response_body)
                })
                .await
                .map_err(|error| error.to_string())
        }
    }
}

fn resolve_response_body(state: &ProxyState, operation_id: &str, body: Bytes) -> Bytes {
    if !state.resolve_inbound {
        return body;
    }

    let body_text = match std::str::from_utf8(body.as_ref()) {
        Ok(text) => text,
        Err(_) => return body,
    };
    let result = dam_pipeline::resolve_text(
        body_text,
        operation_id,
        state.vault.as_ref(),
        state.log_sink.as_deref(),
    );
    result.output.map(Bytes::from).unwrap_or(body)
}

fn request_has_unsupported_content_encoding(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .any(|part| !part.eq_ignore_ascii_case("identity"))
        })
}

fn record_proxy_event(
    state: &ProxyState,
    operation_id: &str,
    level: LogLevel,
    event_type: LogEventType,
    action: &'static str,
    message: &'static str,
) {
    let Some(sink) = &state.log_sink else {
        return;
    };

    let event = LogEvent::new(operation_id, level, event_type, message).with_action(action);
    let _ = sink.record(&event);
}

fn status_response(
    status: StatusCode,
    state: dam_api::ProxyState,
    message: String,
    operation_id: Option<String>,
    target: &dam_config::ProxyTargetConfig,
) -> Response {
    let diagnostics = proxy_diagnostics(state, &message);

    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(dam_api::ProxyReport {
            operation_id,
            target: Some(target.name.clone()),
            upstream: Some(target.upstream.clone()),
            state,
            message,
            diagnostics,
        }),
    )
        .into_response()
}

fn proxy_diagnostics(state: dam_api::ProxyState, message: &str) -> Vec<dam_api::Diagnostic> {
    match state {
        dam_api::ProxyState::Protected => Vec::new(),
        dam_api::ProxyState::Bypassing => vec![dam_api::Diagnostic::new(
            dam_api::DiagnosticSeverity::Warning,
            "bypassing",
            message,
        )],
        dam_api::ProxyState::Blocked => vec![dam_api::Diagnostic::new(
            dam_api::DiagnosticSeverity::Error,
            "blocked",
            message,
        )],
        dam_api::ProxyState::ProviderDown => vec![dam_api::Diagnostic::new(
            dam_api::DiagnosticSeverity::Error,
            "provider_down",
            message,
        )],
        dam_api::ProxyState::ConfigRequired => vec![dam_api::Diagnostic::new(
            dam_api::DiagnosticSeverity::Error,
            "config_required",
            message,
        )],
        dam_api::ProxyState::DamDown => vec![dam_api::Diagnostic::new(
            dam_api::DiagnosticSeverity::Error,
            "dam_down",
            message,
        )],
    }
}

impl ProxyState {
    fn failure_mode(&self) -> dam_config::ProxyFailureMode {
        self.target
            .effective_failure_mode(self.default_failure_mode)
    }

    fn target_requires_missing_api_key(&self, headers: &HeaderMap) -> bool {
        self.target.api_key_env.is_some()
            && self.target.api_key.is_none()
            && !self.provider.caller_auth_header_present(headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use std::sync::Mutex;

    fn proxy_config(upstream: String) -> dam_config::DamConfig {
        proxy_config_with_provider(upstream, "openai-compatible")
    }

    fn proxy_config_with_provider(upstream: String, provider: &str) -> dam_config::DamConfig {
        let dir = tempfile::tempdir().unwrap().keep();
        let mut config = dam_config::DamConfig::default();
        config.vault.sqlite_path = dir.join("vault.db");
        config.consent.sqlite_path = dir.join("consent.db");
        config.log.enabled = true;
        config.log.sqlite_path = dir.join("log.db");
        config.proxy.enabled = true;
        config.proxy.targets.push(dam_config::ProxyTargetConfig {
            name: "test-openai".to_string(),
            provider: provider.to_string(),
            upstream,
            failure_mode: None,
            api_key_env: None,
            api_key: None,
        });
        config
    }

    fn anthropic_proxy_config(upstream: String) -> dam_config::DamConfig {
        let mut config = proxy_config_with_provider(upstream, "anthropic");
        config.proxy.targets[0].name = "test-anthropic".to_string();
        config
    }

    async fn spawn_app(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn spawn_echo_upstream() -> String {
        async fn echo(body: Bytes) -> Response {
            (StatusCode::OK, body).into_response()
        }

        spawn_app(Router::new().route("/v1/chat/completions", post(echo))).await
    }

    async fn spawn_capture_echo_upstream(seen_body: Arc<Mutex<Option<String>>>) -> String {
        async fn echo(
            State(seen_body): State<Arc<Mutex<Option<String>>>>,
            body: Bytes,
        ) -> Response {
            let body_text =
                String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
            *seen_body.lock().unwrap() = Some(body_text.clone());
            (StatusCode::OK, body_text).into_response()
        }

        spawn_app(
            Router::new()
                .route("/v1/chat/completions", post(echo))
                .with_state(seen_body),
        )
        .await
    }

    async fn spawn_capture_headers_upstream(
        seen_headers: Arc<Mutex<Vec<(String, String)>>>,
    ) -> String {
        async fn echo(
            State(seen_headers): State<Arc<Mutex<Vec<(String, String)>>>>,
            headers: HeaderMap,
        ) -> Response {
            *seen_headers.lock().unwrap() = headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value.to_string()))
                })
                .collect();
            (StatusCode::OK, "{}").into_response()
        }

        spawn_app(
            Router::new()
                .route("/v1/chat/completions", post(echo))
                .with_state(seen_headers),
        )
        .await
    }

    async fn spawn_capture_anthropic_headers_upstream(
        seen_headers: Arc<Mutex<Vec<(String, String)>>>,
        seen_body: Arc<Mutex<Option<String>>>,
    ) -> String {
        async fn echo(
            State((seen_headers, seen_body)): State<(
                Arc<Mutex<Vec<(String, String)>>>,
                Arc<Mutex<Option<String>>>,
            )>,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            *seen_headers.lock().unwrap() = headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value.to_string()))
                })
                .collect();
            let body_text =
                String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
            *seen_body.lock().unwrap() = Some(body_text.clone());
            (StatusCode::OK, body_text).into_response()
        }

        spawn_app(
            Router::new()
                .route("/v1/messages", post(echo))
                .with_state((seen_headers, seen_body)),
        )
        .await
    }

    async fn spawn_capture_sse_upstream(seen_body: Arc<Mutex<Option<String>>>) -> String {
        async fn sse(State(seen_body): State<Arc<Mutex<Option<String>>>>, body: Bytes) -> Response {
            let body_text =
                String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
            *seen_body.lock().unwrap() = Some(body_text.clone());
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/event-stream")],
                format!("event: response.output_text.delta\ndata: {body_text}\n\n"),
            )
                .into_response()
        }

        spawn_app(
            Router::new()
                .route("/v1/responses", post(sse))
                .with_state(seen_body),
        )
        .await
    }

    async fn proxy_report(response: reqwest::Response) -> dam_api::ProxyReport {
        response.json().await.expect("proxy report json")
    }

    #[tokio::test]
    async fn redacts_outbound_request_and_resolves_inbound_response() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(upstream_seen.clone()).await;
        let mut config = proxy_config(upstream);
        config.proxy.resolve_inbound = true;
        let vault_path = config.vault.sqlite_path.clone();
        let log_path = config.log.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(r#"{"messages":[{"content":"email alice@example.com"}]}"#)
            .send()
            .await
            .unwrap();

        let body = response.text().await.unwrap();
        assert!(body.contains("alice@example.com"));
        assert!(!body.contains("[email:"));

        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("alice@example.com"));
        assert!(upstream_body.contains("[email:"));
        assert_eq!(
            dam_vault::Vault::open(vault_path).unwrap().count().unwrap(),
            1
        );
        assert!(dam_log::LogStore::open(log_path).unwrap().count().unwrap() > 0);
    }

    #[tokio::test]
    async fn reuses_references_for_duplicate_outbound_values_by_default() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(upstream_seen.clone()).await;
        let config = proxy_config(upstream);
        let vault_path = config.vault.sqlite_path.clone();
        let log_path = config.log.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(r#"{"input":"email alice@example.com again alice@example.com"}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        let references = dam_core::find_references(&upstream_body);
        assert_eq!(references.len(), 2);
        assert_eq!(references[0].reference, references[1].reference);
        assert_eq!(
            dam_vault::Vault::open(&vault_path)
                .unwrap()
                .count()
                .unwrap(),
            1
        );

        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert_eq!(
            logs.iter()
                .filter(|entry| entry.event_type == "vault_write")
                .count(),
            1
        );
        assert_eq!(
            logs.iter()
                .filter(|entry| entry.event_type == "redaction")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn redacts_spaced_email_variants_from_outbound_history() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(upstream_seen.clone()).await;
        let config = proxy_config(upstream);
        let vault_path = config.vault.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(
                r#"{"messages":[{"role":"assistant","content":"wololo@ w.com"},{"role":"user","content":"wololo @w.com"}]}"#,
            )
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("wololo@ w.com"));
        assert!(!upstream_body.contains("wololo @w.com"));
        assert!(upstream_body.contains("[email:"));
        assert_eq!(
            dam_vault::Vault::open(&vault_path)
                .unwrap()
                .count()
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn active_consent_allows_outbound_value() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(upstream_seen.clone()).await;
        let config = proxy_config(upstream);
        let consent_path = config.consent.sqlite_path.clone();
        let vault_path = config.vault.sqlite_path.clone();
        let log_path = config.log.sqlite_path.clone();
        dam_consent::ConsentStore::open(&consent_path)
            .unwrap()
            .grant(&dam_consent::GrantConsent {
                kind: dam_core::SensitiveType::Email,
                value: "alice@example.com".to_string(),
                vault_key: None,
                ttl_seconds: 60,
                created_by: "test".to_string(),
                reason: None,
            })
            .unwrap();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(r#"{"input":"email alice@example.com"}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(upstream_body.contains("alice@example.com"));
        assert_eq!(
            dam_vault::Vault::open(vault_path).unwrap().count().unwrap(),
            0
        );
        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| {
            entry.event_type == "consent"
                && entry
                    .action
                    .as_deref()
                    .is_some_and(|a| a.starts_with("allow:"))
        }));
    }

    #[tokio::test]
    async fn target_api_key_replaces_inbound_authorization() {
        let seen_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let upstream = spawn_capture_headers_upstream(seen_headers.clone()).await;
        let mut config = proxy_config(upstream);
        config.proxy.targets[0].api_key_env = Some("TEST_UPSTREAM_KEY".to_string());
        config.proxy.targets[0].api_key = Some(dam_config::SecretValue::new(
            "TEST_UPSTREAM_KEY",
            "upstream-secret",
        ));
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .header(header::AUTHORIZATION, "Bearer local-agent-secret")
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let authorization_values = seen_headers
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();
        assert_eq!(authorization_values, ["Bearer upstream-secret"]);
    }

    #[tokio::test]
    async fn anthropic_provider_forwards_caller_x_api_key_and_protects_body() {
        let seen_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let seen_body = Arc::new(Mutex::new(None::<String>));
        let upstream =
            spawn_capture_anthropic_headers_upstream(seen_headers.clone(), seen_body.clone()).await;
        let proxy = spawn_app(build_app(anthropic_proxy_config(upstream)).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/messages"))
            .header("x-api-key", "caller-secret")
            .body(r#"{"messages":[{"content":"email alice@example.com"}]}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let x_api_key_values = seen_headers
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("x-api-key"))
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();
        assert_eq!(x_api_key_values, ["caller-secret"]);

        let upstream_body = seen_body.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("alice@example.com"));
        assert!(upstream_body.contains("[email:"));
    }

    #[tokio::test]
    async fn anthropic_target_api_key_replaces_inbound_x_api_key_and_authorization() {
        let seen_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let seen_body = Arc::new(Mutex::new(None::<String>));
        let upstream =
            spawn_capture_anthropic_headers_upstream(seen_headers.clone(), seen_body).await;
        let mut config = anthropic_proxy_config(upstream);
        config.proxy.targets[0].api_key_env = Some("TEST_ANTHROPIC_KEY".to_string());
        config.proxy.targets[0].api_key = Some(dam_config::SecretValue::new(
            "TEST_ANTHROPIC_KEY",
            "upstream-secret",
        ));
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/messages"))
            .header("x-api-key", "local-agent-secret")
            .header(header::AUTHORIZATION, "Bearer local-authorization")
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = seen_headers.lock().unwrap();
        let x_api_key_values = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("x-api-key"))
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();
        assert_eq!(x_api_key_values, ["upstream-secret"]);
        assert!(
            !headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        );
    }

    #[tokio::test]
    async fn anthropic_missing_target_api_key_accepts_caller_x_api_key() {
        let seen_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let seen_body = Arc::new(Mutex::new(None::<String>));
        let upstream =
            spawn_capture_anthropic_headers_upstream(seen_headers.clone(), seen_body).await;
        let mut config = anthropic_proxy_config(upstream);
        config.proxy.targets[0].api_key_env = Some("MISSING_ANTHROPIC_KEY".to_string());
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/messages"))
            .header("x-api-key", "caller-secret")
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn hop_by_hop_and_connection_listed_headers_are_not_forwarded() {
        let seen_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let upstream = spawn_capture_headers_upstream(seen_headers.clone()).await;
        let proxy = spawn_app(build_app(proxy_config(upstream)).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .header(header::CONNECTION, "x-drop-me, keep-alive")
            .header("x-drop-me", "secret")
            .header("te", "trailers")
            .header("trailer", "x-trailer")
            .header("upgrade", "websocket")
            .header("proxy-authorization", "Basic local")
            .header("x-keep-me", "ok")
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = seen_headers.lock().unwrap();
        assert!(
            headers
                .iter()
                .any(|(name, value)| { name.eq_ignore_ascii_case("x-keep-me") && value == "ok" })
        );
        for blocked in [
            "connection",
            "x-drop-me",
            "te",
            "trailer",
            "upgrade",
            "proxy-authorization",
        ] {
            assert!(
                !headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case(blocked)),
                "{blocked} should not be forwarded"
            );
        }
    }

    #[tokio::test]
    async fn leaves_inbound_response_references_unresolved_by_default() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(upstream_seen.clone()).await;
        let config = proxy_config(upstream);
        let vault_path = config.vault.sqlite_path.clone();
        let log_path = config.log.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(r#"{"messages":[{"content":"email alice@example.com"}]}"#)
            .send()
            .await
            .unwrap();

        let body = response.text().await.unwrap();
        assert!(!body.contains("alice@example.com"));
        assert!(body.contains("[email:"));

        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert_eq!(body, upstream_body);
        assert_eq!(
            dam_vault::Vault::open(vault_path).unwrap().count().unwrap(),
            1
        );

        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(!logs.iter().any(|entry| entry.event_type == "vault_read"));
        assert!(!logs.iter().any(|entry| entry.event_type == "resolve"));
    }

    #[tokio::test]
    async fn streams_event_stream_responses_without_inbound_resolution() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_sse_upstream(upstream_seen.clone()).await;
        let config = proxy_config(upstream);
        let vault_path = config.vault.sqlite_path.clone();
        let log_path = config.log.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/responses"))
            .body(r#"{"input":[{"content":"email erin@example.com"}],"stream":true}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );
        let body = response.text().await.unwrap();
        assert!(!body.contains("erin@example.com"));
        assert!(body.contains("[email:"));

        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("erin@example.com"));
        assert!(upstream_body.contains("[email:"));
        assert_eq!(
            dam_vault::Vault::open(vault_path).unwrap().count().unwrap(),
            1
        );

        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(!logs.iter().any(|entry| entry.event_type == "vault_read"));
        assert!(!logs.iter().any(|entry| entry.event_type == "resolve"));
    }

    #[tokio::test]
    async fn health_reports_protected_with_dam_api_shape() {
        let upstream = spawn_echo_upstream().await;
        let config = proxy_config(upstream.clone());
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .get(format!("{proxy}/health"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let report = proxy_report(response).await;
        assert_eq!(report.state, dam_api::ProxyState::Protected);
        assert_eq!(report.target, Some("test-openai".to_string()));
        assert_eq!(report.upstream, Some(upstream));
        assert!(report.operation_id.is_none());
        assert!(report.diagnostics.is_empty());
    }

    #[tokio::test]
    async fn health_reports_config_required_with_dam_api_shape() {
        let upstream = spawn_echo_upstream().await;
        let mut config = proxy_config(upstream);
        config.proxy.targets[0].api_key_env = Some("MISSING_TEST_KEY".to_string());
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .get(format!("{proxy}/health"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let report = proxy_report(response).await;
        assert_eq!(report.state, dam_api::ProxyState::ConfigRequired);
        assert_eq!(report.diagnostics[0].code, "config_required");
    }

    #[tokio::test]
    async fn bypasses_invalid_utf8_when_configured() {
        let upstream = spawn_echo_upstream().await;
        let mut config = proxy_config(upstream);
        config.proxy.default_failure_mode = dam_config::ProxyFailureMode::BypassOnError;
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(vec![0xff, b'a'])
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.bytes().await.unwrap().as_ref(), &[0xff, b'a']);
    }

    #[tokio::test]
    async fn blocks_invalid_utf8_when_configured() {
        let upstream = spawn_echo_upstream().await;
        let mut config = proxy_config(upstream);
        config.proxy.default_failure_mode = dam_config::ProxyFailureMode::BlockOnError;
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(vec![0xff, b'a'])
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let report = proxy_report(response).await;
        assert_eq!(report.state, dam_api::ProxyState::Blocked);
        assert_eq!(report.diagnostics[0].code, "blocked");
        assert!(report.message.contains("not utf-8"));
    }

    #[tokio::test]
    async fn blocks_encoded_request_bodies_before_bypass_policy() {
        let upstream = spawn_echo_upstream().await;
        let mut config = proxy_config(upstream);
        config.proxy.default_failure_mode = dam_config::ProxyFailureMode::BypassOnError;
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .header(header::CONTENT_ENCODING, "gzip")
            .body("not actually gzip")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let report = proxy_report(response).await;
        assert_eq!(report.state, dam_api::ProxyState::Blocked);
        assert!(report.message.contains("encoded request bodies"));
    }

    #[tokio::test]
    async fn policy_block_does_not_forward() {
        let upstream = spawn_echo_upstream().await;
        let mut config = proxy_config(upstream);
        config.policy.default_action = dam_core::PolicyAction::Block;
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body("email alice@example.com")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let report = proxy_report(response).await;
        assert_eq!(report.state, dam_api::ProxyState::Blocked);
        assert_eq!(report.diagnostics[0].code, "blocked");
    }

    #[tokio::test]
    async fn missing_proxy_api_key_reports_config_required() {
        let upstream = spawn_echo_upstream().await;
        let mut config = proxy_config(upstream);
        config.proxy.targets[0].api_key_env = Some("MISSING_TEST_KEY".to_string());
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let report = proxy_report(response).await;
        assert_eq!(report.state, dam_api::ProxyState::ConfigRequired);
        assert_eq!(report.diagnostics[0].code, "config_required");
    }

    #[tokio::test]
    async fn provider_down_is_reported_separately() {
        let config = proxy_config("http://127.0.0.1:1".to_string());
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let report = proxy_report(response).await;
        assert_eq!(report.state, dam_api::ProxyState::ProviderDown);
        assert_eq!(report.diagnostics[0].code, "provider_down");
    }

    #[test]
    fn unsupported_provider_fails_at_startup() {
        let mut config = proxy_config("http://127.0.0.1:9999".to_string());
        config.proxy.targets[0].provider = "unknown".to_string();

        assert!(matches!(
            build_app(config).unwrap_err(),
            ProxyError::UnsupportedProvider(_)
        ));
    }

    #[test]
    fn disabled_proxy_fails_at_startup() {
        let mut config = proxy_config("http://127.0.0.1:9999".to_string());
        config.proxy.enabled = false;

        assert!(matches!(
            build_app(config).unwrap_err(),
            ProxyError::Disabled
        ));
    }

    #[test]
    fn fixture_paths_are_temp_files() {
        let config = proxy_config("http://127.0.0.1:9999".to_string());

        assert!(config.vault.sqlite_path.ends_with("vault.db"));
        assert!(config.log.sqlite_path.ends_with("log.db"));
    }
}
