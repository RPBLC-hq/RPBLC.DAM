use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use dam_core::{
    EventSink, LogEvent, LogEventType, LogLevel, VaultReadError, VaultReader, VaultRecord,
    VaultWriter,
};
use http_body_util::BodyExt;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use std::{
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Once},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

const MAX_REQUEST_BYTES: usize = 10 * 1024 * 1024;
const MAX_INTERCEPTED_HEADER_BYTES: usize = 64 * 1024;

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

    #[error("proxy listen address must be loopback: {0}")]
    NonLoopbackListen(SocketAddr),

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

struct ProviderAdapters {
    openai: dam_provider_openai::OpenAiProvider,
    anthropic: dam_provider_anthropic::AnthropicProvider,
}

enum ProviderAdapter<'a> {
    OpenAi(&'a dam_provider_openai::OpenAiProvider),
    Anthropic(&'a dam_provider_anthropic::AnthropicProvider),
}

impl ProviderAdapters {
    fn new() -> Result<Self, ProxyError> {
        Ok(Self {
            openai: dam_provider_openai::OpenAiProvider::new()
                .map_err(|error| ProxyError::ProviderInit(error.to_string()))?,
            anthropic: dam_provider_anthropic::AnthropicProvider::new()
                .map_err(|error| ProxyError::ProviderInit(error.to_string()))?,
        })
    }

    fn get(&self, kind: dam_router::ProviderKind) -> ProviderAdapter<'_> {
        match kind {
            dam_router::ProviderKind::OpenAiCompatible => ProviderAdapter::OpenAi(&self.openai),
            dam_router::ProviderKind::Anthropic => ProviderAdapter::Anthropic(&self.anthropic),
        }
    }
}

pub struct ProxyState {
    routes: dam_router::RouteTable,
    resolve_inbound: bool,
    vault: Arc<dyn ProxyVault>,
    consent_store: Option<Arc<dam_consent::ConsentStore>>,
    log_sink: Option<Arc<dyn EventSink>>,
    policy: dam_policy::StaticPolicy,
    replacement_options: dam_core::ReplacementPlanOptions,
    providers: ProviderAdapters,
    transparent_interception: Option<TransparentInterceptionConfig>,
}

#[derive(Clone)]
pub struct TransparentInterceptionConfig {
    pub state_dir: PathBuf,
    pub network_mode: dam_net::CaptureMode,
    pub system_proxy_active: bool,
    pub tun_active: bool,
    pub ai_routes: Vec<dam_net::AiRoute>,
    pub trust: dam_trust::TrustState,
    pub user_consented: bool,
}

impl From<dam_router::RouteError> for ProxyError {
    fn from(error: dam_router::RouteError) -> Self {
        match error {
            dam_router::RouteError::MissingTarget => Self::MissingTarget,
            dam_router::RouteError::UnsupportedProvider(provider) => {
                Self::UnsupportedProvider(provider)
            }
        }
    }
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
    let addr: SocketAddr =
        config
            .proxy
            .listen
            .parse()
            .map_err(|source| ProxyError::InvalidListen {
                addr: config.proxy.listen.clone(),
                source,
            })?;
    if !addr.ip().is_loopback() {
        return Err(ProxyError::NonLoopbackListen(addr));
    }
    let app = build_app(config)?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| ProxyError::Bind { addr, source })?;

    axum::serve(listener, app).await.map_err(ProxyError::Server)
}

pub fn build_app(config: dam_config::DamConfig) -> Result<Router, ProxyError> {
    build_app_with_interception(config, None)
}

pub fn build_app_with_interception(
    config: dam_config::DamConfig,
    transparent_interception: Option<TransparentInterceptionConfig>,
) -> Result<Router, ProxyError> {
    let state = build_state(config, transparent_interception)?;

    Ok(Router::new()
        .route("/health", get(health))
        .fallback(proxy)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state))
}

fn build_state(
    config: dam_config::DamConfig,
    transparent_interception: Option<TransparentInterceptionConfig>,
) -> Result<Arc<ProxyState>, ProxyError> {
    if !config.proxy.enabled {
        return Err(ProxyError::Disabled);
    }

    let routes = dam_router::RouteTable::from_proxy_config(&config.proxy)?;
    let providers = ProviderAdapters::new()?;

    let replacement_options = dam_core::ReplacementPlanOptions {
        deduplicate_replacements: config.policy.deduplicate_replacements,
    };

    Ok(Arc::new(ProxyState {
        routes,
        resolve_inbound: config.proxy.resolve_inbound,
        vault: open_vault(&config)?,
        consent_store: open_consent_store(&config)?,
        log_sink: open_log_sink(&config)?,
        policy: dam_policy::StaticPolicy::from(config.policy),
        replacement_options,
        providers,
        transparent_interception,
    }))
}

pub async fn serve_transparent_with_shutdown<F>(
    listener: TcpListener,
    config: dam_config::DamConfig,
    transparent_interception: TransparentInterceptionConfig,
    shutdown: F,
) -> Result<(), ProxyError>
where
    F: Future<Output = ()> + Send,
{
    let state = build_state(config, Some(transparent_interception))?;
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(ProxyError::Server)?;
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = handle_raw_proxy_connection(state, stream).await;
                });
            }
        }
    }
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
    health_response(&state)
}

fn health_response(state: &ProxyState) -> Response {
    let route = state.routes.decide(&HeaderMap::new(), None);
    let (proxy_state, message) = if route.config_required() {
        (
            dam_api::ProxyState::ConfigRequired,
            "target API key is missing".to_string(),
        )
    } else {
        (dam_api::ProxyState::Protected, "proxy is ready".to_string())
    };

    status_response(StatusCode::OK, proxy_state, message, None, route.target())
}

async fn handle_raw_proxy_connection(
    state: Arc<ProxyState>,
    mut stream: TcpStream,
) -> Result<(), String> {
    let operation_id = dam_core::generate_operation_id();
    let request = match read_intercepted_http_request(&mut stream).await {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(error) => {
            write_intercepted_error(&mut stream, StatusCode::BAD_REQUEST, &error).await?;
            return Err(error);
        }
    };

    if request.method == Method::CONNECT {
        return handle_raw_connect_request(state, operation_id, request, stream).await;
    }

    let response = if request.method == Method::GET && request.uri.path() == "/health" {
        health_response(&state)
    } else {
        proxy_http_request(
            state,
            request.method,
            request.uri,
            request.headers,
            request.body,
            operation_id,
        )
        .await
    };
    write_intercepted_http_response(&mut stream, response).await
}

async fn handle_raw_connect_request(
    state: Arc<ProxyState>,
    operation_id: String,
    request: InterceptedHttpRequest,
    mut stream: TcpStream,
) -> Result<(), String> {
    let route = state.routes.decide(&request.headers, Some(&request.uri));
    let Some(interception) = state.transparent_interception.clone() else {
        let response = connect_blocked_response(
            &state,
            route,
            &operation_id,
            StatusCode::NOT_IMPLEMENTED,
            "transparent CONNECT traffic requires the TLS interception runtime",
        );
        write_intercepted_http_response(&mut stream, response).await?;
        return Ok(());
    };

    let Some(host) = connect_host(&request.uri, &request.headers) else {
        let response = connect_blocked_response(
            &state,
            route,
            &operation_id,
            StatusCode::BAD_REQUEST,
            "CONNECT target host is missing",
        );
        write_intercepted_http_response(&mut stream, response).await?;
        return Ok(());
    };
    let Some(ai_route) = dam_net::classify_ai_host_with_routes(&host, &interception.ai_routes)
    else {
        let response = connect_blocked_response(
            &state,
            route,
            &operation_id,
            StatusCode::FORBIDDEN,
            "CONNECT target is not in the known AI route scope",
        );
        write_intercepted_http_response(&mut stream, response).await?;
        return Ok(());
    };
    let route = state
        .routes
        .decide_for_ai_route(&request.headers, &ai_route);
    if !route_matches_ai_target(route, &ai_route) {
        let response = connect_blocked_response(
            &state,
            route,
            &operation_id,
            StatusCode::FORBIDDEN,
            "CONNECT target does not match the configured proxy target",
        );
        write_intercepted_http_response(&mut stream, response).await?;
        return Ok(());
    }

    let readiness = transparent_interception_readiness(&interception, ai_route);
    if readiness.readiness != dam_intercept::TlsInterceptionReadiness::Ready {
        record_proxy_event(
            &state,
            &operation_id,
            LogLevel::Error,
            LogEventType::ProxyFailure,
            "blocked",
            "transparent TLS interception is not ready",
        );
        let response = status_response(
            StatusCode::SERVICE_UNAVAILABLE,
            dam_api::ProxyState::Blocked,
            readiness.message,
            Some(operation_id),
            route.target(),
        );
        write_intercepted_http_response(&mut stream, response).await?;
        return Ok(());
    }

    let acceptor = match tls_acceptor_for_host(&interception, &host) {
        Ok(acceptor) => acceptor,
        Err(message) => {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Error,
                LogEventType::ProxyFailure,
                "blocked",
                "failed to prepare transparent TLS interception",
            );
            let response = status_response(
                StatusCode::BAD_GATEWAY,
                dam_api::ProxyState::Blocked,
                message,
                Some(operation_id),
                route.target(),
            );
            write_intercepted_http_response(&mut stream, response).await?;
            return Ok(());
        }
    };

    handle_intercepted_tls_io(state, &operation_id, stream, acceptor, true).await
}

async fn proxy(State(state): State<Arc<ProxyState>>, mut request: Request) -> Response {
    let operation_id = dam_core::generate_operation_id();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let route = state.routes.decide(&headers, Some(&uri));

    if method == Method::CONNECT {
        return handle_connect_request(
            state.clone(),
            route,
            operation_id,
            &uri,
            &headers,
            &mut request,
        );
    }

    let body = match to_bytes(request.into_body(), MAX_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return handle_protection_failure(
                state.clone(),
                route,
                operation_id,
                "request body exceeds the supported size",
            );
        }
    };

    proxy_http_request(state, method, uri, headers, body, operation_id).await
}

fn handle_connect_request(
    state: Arc<ProxyState>,
    route: dam_router::RouteDecision<'_>,
    operation_id: String,
    uri: &Uri,
    headers: &HeaderMap,
    request: &mut Request,
) -> Response {
    let Some(interception) = state.transparent_interception.clone() else {
        return connect_blocked_response(
            &state,
            route,
            &operation_id,
            StatusCode::NOT_IMPLEMENTED,
            "transparent CONNECT traffic requires the TLS interception runtime",
        );
    };

    let Some(host) = connect_host(uri, headers) else {
        return connect_blocked_response(
            &state,
            route,
            &operation_id,
            StatusCode::BAD_REQUEST,
            "CONNECT target host is missing",
        );
    };

    let Some(ai_route) = dam_net::classify_ai_host_with_routes(&host, &interception.ai_routes)
    else {
        return connect_blocked_response(
            &state,
            route,
            &operation_id,
            StatusCode::FORBIDDEN,
            "CONNECT target is not in the known AI route scope",
        );
    };

    let route = state.routes.decide_for_ai_route(headers, &ai_route);
    if !route_matches_ai_target(route, &ai_route) {
        return connect_blocked_response(
            &state,
            route,
            &operation_id,
            StatusCode::FORBIDDEN,
            "CONNECT target does not match the configured proxy target",
        );
    }

    let readiness = transparent_interception_readiness(&interception, ai_route);
    if readiness.readiness != dam_intercept::TlsInterceptionReadiness::Ready {
        record_proxy_event(
            &state,
            &operation_id,
            LogLevel::Error,
            LogEventType::ProxyFailure,
            "blocked",
            "transparent TLS interception is not ready",
        );
        return status_response(
            StatusCode::SERVICE_UNAVAILABLE,
            dam_api::ProxyState::Blocked,
            readiness.message,
            Some(operation_id),
            route.target(),
        );
    }

    let acceptor = match tls_acceptor_for_host(&interception, &host) {
        Ok(acceptor) => acceptor,
        Err(message) => {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Error,
                LogEventType::ProxyFailure,
                "blocked",
                "failed to prepare transparent TLS interception",
            );
            return status_response(
                StatusCode::BAD_GATEWAY,
                dam_api::ProxyState::Blocked,
                message,
                Some(operation_id),
                route.target(),
            );
        }
    };

    if request
        .extensions()
        .get::<hyper::upgrade::OnUpgrade>()
        .is_none()
    {
        record_proxy_event(
            &state,
            &operation_id,
            LogLevel::Error,
            LogEventType::ProxyFailure,
            "blocked",
            "CONNECT request cannot be upgraded",
        );
        return status_response(
            StatusCode::BAD_GATEWAY,
            dam_api::ProxyState::Blocked,
            "CONNECT request cannot be upgraded".to_string(),
            Some(operation_id),
            route.target(),
        );
    }

    let upgrade = hyper::upgrade::on(request);
    tokio::spawn(handle_upgraded_connect(
        state,
        operation_id,
        upgrade,
        acceptor,
    ));

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::OK.into_response())
}

fn connect_blocked_response(
    state: &ProxyState,
    route: dam_router::RouteDecision<'_>,
    operation_id: &str,
    status: StatusCode,
    message: &'static str,
) -> Response {
    record_proxy_event(
        state,
        operation_id,
        LogLevel::Error,
        LogEventType::ProxyFailure,
        "blocked",
        message,
    );
    status_response(
        status,
        dam_api::ProxyState::Blocked,
        message.to_string(),
        Some(operation_id.to_string()),
        route.target(),
    )
}

async fn proxy_http_request(
    state: Arc<ProxyState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    operation_id: String,
) -> Response {
    let route = state.routes.decide(&headers, Some(&uri));

    if route.config_required() {
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
            route.target(),
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
            route.target(),
        );
    }

    let body_text = match std::str::from_utf8(&body) {
        Ok(text) => text,
        Err(_) => {
            return handle_protection_failure(
                state.clone(),
                route,
                operation_id,
                "request body is not utf-8",
            );
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
                state.clone(),
                route,
                operation_id,
                "request protection failed",
            );
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
            route.target(),
        );
    }

    let Some(protected_body) = protected.output else {
        return handle_protection_failure(
            state.clone(),
            route,
            operation_id,
            "request protection did not produce output",
        );
    };
    forward_or_provider_down(
        state.clone(),
        route,
        ForwardAttempt {
            method,
            uri,
            headers,
            body: Bytes::from(protected_body),
            operation_id,
            action: "protected",
        },
    )
    .await
}

async fn handle_upgraded_connect(
    state: Arc<ProxyState>,
    operation_id: String,
    upgrade: hyper::upgrade::OnUpgrade,
    acceptor: TlsAcceptor,
) {
    let upgraded = match upgrade.await {
        Ok(upgraded) => upgraded,
        Err(_) => {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Error,
                LogEventType::ProxyFailure,
                "blocked",
                "CONNECT upgrade failed",
            );
            return;
        }
    };

    if let Err(error) =
        handle_intercepted_tls_connection(state.clone(), &operation_id, upgraded, acceptor).await
    {
        record_proxy_event(
            &state,
            &operation_id,
            LogLevel::Error,
            LogEventType::ProxyFailure,
            "blocked",
            "intercepted TLS request failed",
        );
        let _ = error;
    }
}

async fn handle_intercepted_tls_connection(
    state: Arc<ProxyState>,
    operation_id: &str,
    upgraded: Upgraded,
    acceptor: TlsAcceptor,
) -> Result<(), String> {
    handle_intercepted_tls_io(state, operation_id, TokioIo::new(upgraded), acceptor, true).await
}

async fn handle_intercepted_tls_io<T>(
    state: Arc<ProxyState>,
    operation_id: &str,
    mut io: T,
    acceptor: TlsAcceptor,
    acknowledge_connect: bool,
) -> Result<(), String>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    if acknowledge_connect {
        io.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|error| format!("failed to acknowledge CONNECT tunnel: {error}"))?;
        io.flush()
            .await
            .map_err(|error| format!("failed to flush CONNECT tunnel: {error}"))?;
    }
    let mut tls = acceptor
        .accept(io)
        .await
        .map_err(|error| format!("TLS handshake failed: {error}"))?;

    let request = match read_intercepted_http_request(&mut tls).await {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(error) => {
            write_intercepted_error(&mut tls, StatusCode::BAD_REQUEST, &error).await?;
            return Err(error);
        }
    };

    let response = proxy_http_request(
        state,
        request.method,
        request.uri,
        request.headers,
        request.body,
        operation_id.to_string(),
    )
    .await;

    if let Err(error) = write_intercepted_http_response(&mut tls, response).await {
        let _ = write_intercepted_error(&mut tls, StatusCode::BAD_GATEWAY, &error).await;
        return Err(error);
    }
    let _ = tls.shutdown().await;
    Ok(())
}

struct InterceptedHttpRequest {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
}

fn tls_server_config(issued: dam_trust::LocalCaIssuedCertificate) -> Result<ServerConfig, String> {
    ensure_rustls_crypto_provider();
    let cert_chain = vec![CertificateDer::from(issued.certificate_der)];
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(issued.private_key_der));
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|error| format!("failed to configure TLS certificate: {error}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn ensure_rustls_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

fn tls_acceptor_for_host(
    interception: &TransparentInterceptionConfig,
    host: &str,
) -> Result<TlsAcceptor, String> {
    let issued = dam_trust::issue_local_ca_leaf_certificate(&interception.state_dir, host)
        .map_err(|error| format!("failed to issue local TLS certificate: {error}"))?;
    tls_server_config(issued).map(|config| TlsAcceptor::from(Arc::new(config)))
}

fn transparent_interception_readiness(
    interception: &TransparentInterceptionConfig,
    ai_route: dam_net::AiRoute,
) -> dam_intercept::RouteTlsInterceptionReadiness {
    let routing = dam_net::transparent_route_capture_readiness(
        ai_route.clone(),
        dam_net::TrafficProtocol::Https,
        interception.network_mode,
        interception.system_proxy_active,
        interception.tun_active,
    );
    let trust_report = dam_trust::readiness_for_route(
        &dam_net::decide_transparent_route_with_routes(
            &dam_net::TrafficObservation::new(
                ai_route.host.clone(),
                dam_net::TrafficProtocol::Https,
            ),
            &interception.ai_routes,
        ),
        &interception.trust,
        interception.user_consented,
    );
    let route_trust = dam_trust::RouteTrustReadiness {
        route: ai_route.clone(),
        protocol: dam_net::TrafficProtocol::Https,
        readiness: trust_report.readiness,
        message: trust_report.message,
    };

    dam_intercept::readiness_for_route(
        &routing,
        &route_trust,
        interception.user_consented,
        dam_intercept::TlsInterceptionAdapter::new(true),
    )
}

fn connect_host(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    uri.authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .map(normalize_host)
        .filter(|host| !host.is_empty())
}

fn route_matches_ai_target(
    route: dam_router::RouteDecision<'_>,
    ai_route: &dam_net::AiRoute,
) -> bool {
    let target = route.target();
    route.provider_kind().id() == ai_route.provider
        && (target.name == ai_route.target_name
            || normalize_host(&target.upstream) == normalize_host(&ai_route.upstream))
}

async fn read_intercepted_http_request<T>(
    stream: &mut T,
) -> Result<Option<InterceptedHttpRequest>, String>
where
    T: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut scratch = [0_u8; 1024];
    let header_end = loop {
        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
        if buffer.len() >= MAX_INTERCEPTED_HEADER_BYTES {
            return Err("intercepted request headers are too large".to_string());
        }
        let read = stream
            .read(&mut scratch)
            .await
            .map_err(|error| format!("failed to read intercepted request: {error}"))?;
        if read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err("intercepted request ended before headers completed".to_string());
        }
        buffer.extend_from_slice(&scratch[..read]);
    };

    let head = std::str::from_utf8(&buffer[..header_end])
        .map_err(|_| "intercepted request headers are not utf-8".to_string())?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "intercepted request line is missing".to_string())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| "intercepted request method is missing".to_string())?
        .parse::<Method>()
        .map_err(|_| "intercepted request method is invalid".to_string())?;
    let target = request_parts
        .next()
        .ok_or_else(|| "intercepted request target is missing".to_string())?;
    let version = request_parts
        .next()
        .ok_or_else(|| "intercepted HTTP version is missing".to_string())?;
    if request_parts.next().is_some() || version != "HTTP/1.1" {
        return Err("only HTTP/1.1 intercepted requests are supported".to_string());
    }
    let uri = parse_intercepted_request_target(target)?;

    let mut headers = HeaderMap::new();
    let mut content_length_count = 0;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err("folded intercepted request headers are not supported".to_string());
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("intercepted request header is invalid".to_string());
        };
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| "intercepted request header name is invalid".to_string())?;
        if name == header::CONTENT_LENGTH {
            content_length_count += 1;
        }
        let value = HeaderValue::from_str(value.trim())
            .map_err(|_| "intercepted request header value is invalid".to_string())?;
        headers.append(name, value);
    }

    if headers.contains_key(header::TRANSFER_ENCODING) {
        return Err("chunked intercepted requests are not supported".to_string());
    }
    if content_length_count > 1 {
        return Err("multiple content-length headers are not supported".to_string());
    }
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| "content-length is invalid".to_string())
                .and_then(|value| {
                    value
                        .parse::<usize>()
                        .map_err(|_| "content-length is invalid".to_string())
                })
        })
        .transpose()?
        .unwrap_or(0);
    if content_length > MAX_REQUEST_BYTES {
        return Err("intercepted request body exceeds the supported size".to_string());
    }

    let body_start = header_end + 4;
    let mut body = buffer[body_start..].to_vec();
    if body.len() > content_length {
        body.truncate(content_length);
    }
    while body.len() < content_length {
        let mut chunk = vec![0_u8; content_length - body.len()];
        stream
            .read_exact(&mut chunk)
            .await
            .map_err(|error| format!("failed to read intercepted request body: {error}"))?;
        body.extend_from_slice(&chunk);
    }

    Ok(Some(InterceptedHttpRequest {
        method,
        uri,
        headers,
        body: Bytes::from(body),
    }))
}

async fn write_intercepted_http_response<T>(
    stream: &mut T,
    response: Response,
) -> Result<(), String>
where
    T: AsyncWrite + Unpin,
{
    let streaming = response_is_streaming(&response);
    let (parts, body) = response.into_parts();
    let reason = parts.status.canonical_reason().unwrap_or("");
    stream
        .write_all(format!("HTTP/1.1 {} {reason}\r\n", parts.status.as_u16()).as_bytes())
        .await
        .map_err(|error| format!("failed to write intercepted response: {error}"))?;
    for (name, value) in parts.headers.iter() {
        if intercepted_response_should_skip_header(name) {
            continue;
        }
        stream
            .write_all(name.as_str().as_bytes())
            .await
            .map_err(|error| format!("failed to write intercepted response: {error}"))?;
        stream
            .write_all(b": ")
            .await
            .map_err(|error| format!("failed to write intercepted response: {error}"))?;
        stream
            .write_all(value.as_bytes())
            .await
            .map_err(|error| format!("failed to write intercepted response: {error}"))?;
        stream
            .write_all(b"\r\n")
            .await
            .map_err(|error| format!("failed to write intercepted response: {error}"))?;
    }
    if streaming {
        stream
            .write_all(b"transfer-encoding: chunked\r\nconnection: close\r\n\r\n")
            .await
            .map_err(|error| format!("failed to write intercepted response: {error}"))?;
        write_intercepted_chunked_body(stream, body).await?;
        return Ok(());
    }

    let body = to_bytes(body, MAX_REQUEST_BYTES)
        .await
        .map_err(|_| "intercepted response body exceeds the supported size".to_string())?;
    stream
        .write_all(
            format!(
                "content-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .map_err(|error| format!("failed to write intercepted response: {error}"))?;
    stream
        .write_all(&body)
        .await
        .map_err(|error| format!("failed to write intercepted response: {error}"))?;
    Ok(())
}

async fn write_intercepted_chunked_body<T>(stream: &mut T, mut body: Body) -> Result<(), String>
where
    T: AsyncWrite + Unpin,
{
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|error| format!("failed to read intercepted streaming response: {error}"))?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        stream
            .write_all(format!("{:x}\r\n", data.len()).as_bytes())
            .await
            .map_err(|error| format!("failed to write intercepted streaming response: {error}"))?;
        stream
            .write_all(&data)
            .await
            .map_err(|error| format!("failed to write intercepted streaming response: {error}"))?;
        stream
            .write_all(b"\r\n")
            .await
            .map_err(|error| format!("failed to write intercepted streaming response: {error}"))?;
    }
    stream
        .write_all(b"0\r\n\r\n")
        .await
        .map_err(|error| format!("failed to finish intercepted streaming response: {error}"))
}

async fn write_intercepted_error<T>(
    stream: &mut T,
    status: StatusCode,
    message: &str,
) -> Result<(), String>
where
    T: AsyncWrite + Unpin,
{
    let safe_message = if message.is_empty() {
        "intercepted request failed"
    } else {
        message
    };
    let reason = status.canonical_reason().unwrap_or("Error");
    let body = format!("{safe_message}\n");
    let response = format!(
        "HTTP/1.1 {} {reason}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        status.as_u16(),
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| format!("failed to write intercepted error response: {error}"))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_intercepted_request_target(target: &str) -> Result<Uri, String> {
    target
        .parse::<Uri>()
        .or_else(|_| format!("http://{target}").parse::<Uri>())
        .map_err(|_| "intercepted request target is invalid".to_string())
}

fn response_is_streaming(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .any(|part| part.trim().eq_ignore_ascii_case("text/event-stream"))
        })
}

fn intercepted_response_should_skip_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "content-length" | "connection" | "transfer-encoding" | "keep-alive" | "upgrade"
    )
}

fn normalize_host(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('.');
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .or_else(|| trimmed.strip_prefix("wss://"))
        .or_else(|| trimmed.strip_prefix("ws://"))
        .unwrap_or(trimmed);
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    host_port
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| {
            host_port
                .split_once(':')
                .map(|(host, _)| host)
                .unwrap_or(host_port)
        })
        .to_ascii_lowercase()
}

fn handle_protection_failure(
    state: Arc<ProxyState>,
    route: dam_router::RouteDecision<'_>,
    operation_id: String,
    message: &'static str,
) -> Response {
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
        route.target(),
    )
}

struct ForwardAttempt {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    operation_id: String,
    action: &'static str,
}

async fn forward_or_provider_down(
    state: Arc<ProxyState>,
    route: dam_router::RouteDecision<'_>,
    attempt: ForwardAttempt,
) -> Response {
    match forward_request(
        &state,
        route,
        attempt.method,
        attempt.uri,
        attempt.headers,
        attempt.body,
        &attempt.operation_id,
    )
    .await
    {
        Ok(response) => {
            let event_type = if attempt.action == "bypassing" {
                LogEventType::ProxyBypass
            } else {
                LogEventType::ProxyForward
            };
            record_proxy_event(
                &state,
                &attempt.operation_id,
                LogLevel::Info,
                event_type,
                attempt.action,
                "proxy request forwarded",
            );
            response
        }
        Err(error) => {
            record_proxy_event(
                &state,
                &attempt.operation_id,
                LogLevel::Error,
                LogEventType::ProxyFailure,
                "provider_down",
                "upstream provider is unavailable",
            );
            status_response(
                StatusCode::BAD_GATEWAY,
                dam_api::ProxyState::ProviderDown,
                error,
                Some(attempt.operation_id),
                route.target(),
            )
        }
    }
}

async fn forward_request(
    state: &ProxyState,
    route: dam_router::RouteDecision<'_>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    operation_id: &str,
) -> Result<Response, String> {
    let target_api_key = route.target_api_key();
    match state.providers.get(route.provider_kind()) {
        ProviderAdapter::OpenAi(provider) => {
            let request = dam_provider_openai::ForwardRequest {
                upstream: &route.target().upstream,
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
                upstream: &route.target().upstream,
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
    async fn transparent_connect_requests_fail_closed_without_tls_runtime() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(upstream_seen.clone()).await;
        let config = proxy_config(upstream);
        let log_path = config.log.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;
        let addr = proxy.strip_prefix("http://").unwrap();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        let mut response = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut response)
            .await
            .unwrap();

        assert!(response.starts_with("HTTP/1.1 501"));
        assert!(
            response.contains("transparent CONNECT traffic requires the TLS interception runtime")
        );
        assert!(upstream_seen.lock().unwrap().is_none());
        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| {
            entry.event_type == "proxy_failure"
                && entry.action.as_deref() == Some("blocked")
                && entry
                    .message
                    .contains("transparent CONNECT traffic requires")
        }));
    }

    #[tokio::test]
    async fn transparent_connect_requests_fail_closed_when_interception_is_not_ready() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(upstream_seen.clone()).await;
        let mut config = proxy_config(upstream);
        config.proxy.targets[0].name = "openai".to_string();
        let interception = TransparentInterceptionConfig {
            state_dir: tempfile::tempdir().unwrap().keep(),
            network_mode: dam_net::CaptureMode::SystemProxy,
            system_proxy_active: true,
            tun_active: false,
            ai_routes: dam_net::known_ai_routes(),
            trust: dam_trust::TrustState::default(),
            user_consented: true,
        };
        let proxy =
            spawn_app(build_app_with_interception(config, Some(interception)).unwrap()).await;
        let addr = proxy.strip_prefix("http://").unwrap();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        let mut response = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut response)
            .await
            .unwrap();

        assert!(response.starts_with("HTTP/1.1 503"));
        assert!(response.contains("TLS interception is disabled"));
        assert!(upstream_seen.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn transparent_connect_uses_configured_ai_route_registry() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(upstream_seen.clone()).await;
        let mut config = proxy_config(upstream);
        config.proxy.targets[0].name = "enterprise-ai".to_string();
        let ai_routes = dam_net::ai_routes_with_overlays([dam_net::AiRoute::custom(
            "api.enterprise-ai.example",
            dam_net::OPENAI_COMPATIBLE_PROVIDER,
            "enterprise-ai",
            "https://api.enterprise-ai.example",
        )]);
        let interception = TransparentInterceptionConfig {
            state_dir: tempfile::tempdir().unwrap().keep(),
            network_mode: dam_net::CaptureMode::SystemProxy,
            system_proxy_active: true,
            tun_active: false,
            ai_routes,
            trust: dam_trust::TrustState::default(),
            user_consented: true,
        };
        let proxy =
            spawn_app(build_app_with_interception(config, Some(interception)).unwrap()).await;
        let addr = proxy.strip_prefix("http://").unwrap();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"CONNECT api.enterprise-ai.example:443 HTTP/1.1\r\nHost: api.enterprise-ai.example:443\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

        let mut response = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut response)
            .await
            .unwrap();

        assert!(response.starts_with("HTTP/1.1 503"));
        assert!(response.contains("TLS interception is disabled"));
        assert!(!response.contains("not in the known AI route scope"));
        assert!(upstream_seen.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn transparent_connect_tls_http1_requests_are_protected() {
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::{
            ClientConfig, RootCertStore,
            pki_types::{CertificateDer, ServerName},
        };

        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(upstream_seen.clone()).await;
        let mut config = proxy_config(upstream);
        config.proxy.targets[0].name = "openai".to_string();

        let dir = tempfile::tempdir().unwrap();
        let artifact = dam_trust::generate_local_ca_artifact_at(dir.path(), 1).unwrap();
        let mut record = artifact.record.clone();
        record.installed_at_unix = Some(2);
        let trust = dam_trust::TrustState {
            mode: dam_trust::TrustMode::LocalCa,
            local_ca: Some(record),
            ..dam_trust::TrustState::default()
        };
        let interception = TransparentInterceptionConfig {
            state_dir: dir.path().to_path_buf(),
            network_mode: dam_net::CaptureMode::SystemProxy,
            system_proxy_active: true,
            tun_active: false,
            ai_routes: dam_net::known_ai_routes(),
            trust,
            user_consented: true,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            serve_transparent_with_shutdown(listener, config, interception, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n",
        )
        .await
        .unwrap();
        let connect_response = read_until_headers(&mut stream).await;
        assert!(String::from_utf8_lossy(&connect_response).starts_with("HTTP/1.1 200"));

        let mut roots = RootCertStore::empty();
        let ca_der = dam_trust::issue_local_ca_leaf_certificate(dir.path(), "api.openai.com")
            .unwrap()
            .ca_certificate_der;
        roots.add(CertificateDer::from(ca_der)).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from("api.openai.com".to_string()).unwrap();
        let mut tls = connector.connect(server_name, stream).await.unwrap();

        let body = r#"{"input":"email alice@example.com"}"#;
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        tokio::io::AsyncWriteExt::write_all(&mut tls, request.as_bytes())
            .await
            .unwrap();
        let response = read_intercepted_test_response(&mut tls).await;

        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(!response.contains("alice@example.com"));
        assert!(response.contains("[email:"));
        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("alice@example.com"));
        assert!(upstream_body.contains("[email:"));
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn transparent_plain_http_streams_event_stream_responses() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_sse_upstream(upstream_seen.clone()).await;
        let config = proxy_config(upstream);
        let interception = TransparentInterceptionConfig {
            state_dir: tempfile::tempdir().unwrap().keep(),
            network_mode: dam_net::CaptureMode::SystemProxy,
            system_proxy_active: true,
            tun_active: false,
            ai_routes: dam_net::known_ai_routes(),
            trust: dam_trust::TrustState::default(),
            user_consented: true,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            serve_transparent_with_shutdown(listener, config, interception, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = r#"{"input":[{"content":"email erin@example.com"}],"stream":true}"#;
        let request = format!(
            "POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes())
            .await
            .unwrap();
        let response = read_intercepted_test_response(&mut stream).await;

        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("content-type: text/event-stream"));
        assert!(response.contains("transfer-encoding: chunked"));
        assert!(!response.contains("erin@example.com"));
        assert!(response.contains("[email:"));
        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("erin@example.com"));
        assert!(upstream_body.contains("[email:"));
        let _ = shutdown_tx.send(());
    }

    async fn read_until_headers<T>(stream: &mut T) -> Vec<u8>
    where
        T: tokio::io::AsyncRead + Unpin,
    {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = tokio::io::AsyncReadExt::read(stream, &mut chunk)
                .await
                .unwrap();
            assert!(
                read != 0,
                "connection closed before headers completed: {}",
                String::from_utf8_lossy(&buffer)
            );
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.ends_with(b"\r\n\r\n") {
                return buffer;
            }
        }
    }

    async fn read_intercepted_test_response<T>(stream: &mut T) -> String
    where
        T: tokio::io::AsyncRead + Unpin,
    {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            match tokio::io::AsyncReadExt::read(stream, &mut chunk).await {
                Ok(0) => break,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(error) => panic!("failed to read intercepted response: {error}"),
            }
        }
        String::from_utf8(buffer).expect("intercepted response should be utf-8")
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
    async fn blocks_invalid_utf8_even_when_bypass_is_configured() {
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

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let report = proxy_report(response).await;
        assert_eq!(report.state, dam_api::ProxyState::Blocked);
        assert_eq!(report.diagnostics[0].code, "blocked");
        assert!(report.message.contains("not utf-8"));
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
    async fn blocks_consent_errors_even_when_bypass_is_configured() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(upstream_seen.clone()).await;
        let mut config = proxy_config(upstream);
        config.proxy.default_failure_mode = dam_config::ProxyFailureMode::BypassOnError;
        let consent_path = config.consent.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;
        {
            let conn = rusqlite::Connection::open(consent_path).unwrap();
            conn.execute_batch("DROP TABLE consents;").unwrap();
        }

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(r#"{"input":"email alice@example.com"}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let report = proxy_report(response).await;
        assert_eq!(report.state, dam_api::ProxyState::Blocked);
        assert_eq!(report.diagnostics[0].code, "blocked");
        assert!(report.message.contains("request protection failed"));
        assert!(upstream_seen.lock().unwrap().is_none());
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
        assert!(!report.message.contains("127.0.0.1:1"));
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
