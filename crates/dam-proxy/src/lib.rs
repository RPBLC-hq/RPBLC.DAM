use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use dam_core::{
    EventSink, LogEventType, LogLevel, VaultReadError, VaultReader, VaultRecord, VaultWriter,
};
use http_body_util::BodyExt;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, Once, RwLock},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    },
};

mod events;
mod providers;
mod websocket;

use events::{log_intercepted_response_write, log_provider_response, record_proxy_event};
use providers::{ProviderAdapter, ProviderAdapters};

const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
const MAX_INTERCEPTED_HEADER_BYTES: usize = 64 * 1024;
const PASSTHROUGH_RESUME_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectBypassReason {
    NonAiRoute,
    ProtectionPaused,
}

impl ConnectBypassReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::NonAiRoute => "non_ai_route",
            Self::ProtectionPaused => "protection_paused",
        }
    }
}

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

pub struct ProxyState {
    routes: dam_router::RouteTable,
    resolve_inbound: bool,
    route_resolve_inbound: HashMap<String, bool>,
    route_protect_inbound: HashMap<String, bool>,
    vault: Arc<dyn ProxyVault>,
    consent_store: Option<Arc<dam_consent::ConsentStore>>,
    log_sink: Option<Arc<dyn EventSink>>,
    policy: dam_policy::StaticPolicy,
    replacement_options: dam_core::ReplacementPlanOptions,
    providers: ProviderAdapters,
    transparent_interception: Option<TransparentInterceptionConfig>,
    tls_acceptor_cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
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
    pub protection_control_path: Option<PathBuf>,
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

impl ProxyState {
    fn protection_enabled(&self) -> bool {
        self.transparent_interception
            .as_ref()
            .and_then(|config| config.protection_control_path.as_ref())
            .map(protection_control_enabled)
            .unwrap_or(true)
    }
}

struct FailingVault {
    message: String,
}

impl VaultWriter for FailingVault {
    fn write_with_options(
        &self,
        _record: &VaultRecord,
        _options: dam_core::VaultWriteOptions,
    ) -> Result<dam_core::Reference, dam_core::VaultWriteError> {
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
        route_resolve_inbound: route_resolve_inbound(&config.traffic.effective_profile()),
        route_protect_inbound: route_protect_inbound(&config.traffic.effective_profile()),
        vault: open_vault(&config)?,
        consent_store: open_consent_store(&config)?,
        log_sink: open_log_sink(&config)?,
        policy: dam_policy::StaticPolicy::from(config.policy),
        replacement_options,
        providers,
        transparent_interception,
        tls_acceptor_cache: Mutex::new(HashMap::new()),
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
    let addr = listener.local_addr().map_err(ProxyError::Server)?;
    if !addr.ip().is_loopback() {
        return Err(ProxyError::NonLoopbackListen(addr));
    }
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
    let (proxy_state, message) = if !state.protection_enabled() {
        (
            dam_api::ProxyState::Bypassing,
            "protection is paused; traffic is passed through".to_string(),
        )
    } else if route.config_required() {
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

    if request.method == Method::GET && request.uri.path() == "/health" {
        let response = health_response(&state);
        return write_intercepted_http_response(&mut stream, response).await;
    }

    if is_forward_proxy_http_request(&request.uri)
        && !should_protect_forward_proxy_http_request(&state, &request)
    {
        return handle_raw_http_pass_through(state, operation_id, request, stream).await;
    }

    let response = proxy_http_request(
        state.clone(),
        request.method,
        request.uri,
        request.headers,
        request.body,
        operation_id.clone(),
    )
    .await;
    log_intercepted_response_write(&state, &operation_id, &response);
    write_intercepted_http_response(&mut stream, response).await
}

async fn handle_raw_connect_request(
    state: Arc<ProxyState>,
    operation_id: String,
    request: InterceptedHttpRequest,
    mut stream: TcpStream,
) -> Result<(), String> {
    let route = state.routes.decide(&request.headers, Some(&request.uri));
    let Some(authority) = connect_authority(&request.uri, &request.headers) else {
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
    let ai_route = dam_net::classify_ai_host_with_routes(&authority.host, &interception.ai_routes);
    let protection_paused = !state.protection_enabled();
    if ai_route.is_none() || protection_paused {
        let bypass_reason = if ai_route.is_some() && protection_paused {
            ConnectBypassReason::ProtectionPaused
        } else {
            ConnectBypassReason::NonAiRoute
        };
        return handle_raw_connect_tunnel(
            state,
            operation_id,
            authority,
            bypass_reason,
            stream,
            ai_route.is_some() && protection_paused,
        )
        .await;
    }
    let ai_route = ai_route.unwrap();
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

    let acceptor = match tls_acceptor_for_host(&state, &interception, &authority.host) {
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
    let route = route_for_request(&state, &headers, &uri);

    if method == Method::CONNECT {
        return handle_connect_request(
            state.clone(),
            route,
            operation_id,
            &uri,
            &headers,
            &mut request,
        )
        .await;
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

async fn handle_connect_request(
    state: Arc<ProxyState>,
    route: dam_router::RouteDecision<'_>,
    operation_id: String,
    uri: &Uri,
    headers: &HeaderMap,
    request: &mut Request,
) -> Response {
    let Some(authority) = connect_authority(uri, headers) else {
        return connect_blocked_response(
            &state,
            route,
            &operation_id,
            StatusCode::BAD_REQUEST,
            "CONNECT target host is missing",
        );
    };

    let Some(interception) = state.transparent_interception.clone() else {
        return connect_blocked_response(
            &state,
            route,
            &operation_id,
            StatusCode::NOT_IMPLEMENTED,
            "transparent CONNECT traffic requires the TLS interception runtime",
        );
    };
    let ai_route = dam_net::classify_ai_host_with_routes(&authority.host, &interception.ai_routes);
    let protection_paused = !state.protection_enabled();
    if ai_route.is_none() || protection_paused {
        let bypass_reason = if ai_route.is_some() && protection_paused {
            ConnectBypassReason::ProtectionPaused
        } else {
            ConnectBypassReason::NonAiRoute
        };
        return handle_connect_tunnel_request(
            state,
            route,
            operation_id,
            authority,
            bypass_reason,
            request,
            ai_route.is_some() && protection_paused,
        )
        .await;
    }
    let ai_route = ai_route.unwrap();

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

    let acceptor = match tls_acceptor_for_host(&state, &interception, &authority.host) {
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

async fn handle_connect_tunnel_request(
    state: Arc<ProxyState>,
    route: dam_router::RouteDecision<'_>,
    operation_id: String,
    authority: TargetAuthority,
    bypass_reason: ConnectBypassReason,
    request: &mut Request,
    close_on_protection_resume: bool,
) -> Response {
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

    let upstream = match connect_target(&authority).await {
        Ok(upstream) => upstream,
        Err(error) => {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Error,
                LogEventType::ProxyFailure,
                "provider_down",
                "CONNECT passthrough target is unavailable",
            );
            return status_response(
                StatusCode::BAD_GATEWAY,
                dam_api::ProxyState::ProviderDown,
                error,
                Some(operation_id),
                route.target(),
            );
        }
    };

    let upgrade = hyper::upgrade::on(request);
    tokio::spawn(handle_upgraded_tunnel(
        state,
        operation_id,
        authority,
        bypass_reason,
        upgrade,
        upstream,
        close_on_protection_resume,
    ));

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::OK.into_response())
}

async fn handle_raw_connect_tunnel(
    state: Arc<ProxyState>,
    operation_id: String,
    authority: TargetAuthority,
    bypass_reason: ConnectBypassReason,
    mut stream: TcpStream,
    close_on_protection_resume: bool,
) -> Result<(), String> {
    let mut upstream = match connect_target(&authority).await {
        Ok(upstream) => upstream,
        Err(error) => {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Error,
                LogEventType::ProxyFailure,
                "provider_down",
                "CONNECT passthrough target is unavailable",
            );
            write_intercepted_error(&mut stream, StatusCode::BAD_GATEWAY, &error).await?;
            return Ok(());
        }
    };

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|error| format!("failed to acknowledge CONNECT tunnel: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("failed to flush CONNECT tunnel: {error}"))?;
    record_proxy_event(
        &state,
        &operation_id,
        LogLevel::Info,
        LogEventType::ProxyBypass,
        "bypassing",
        format!(
            "CONNECT tunnel passed through without inspection target={}:{} reason={}",
            authority.host,
            authority.port,
            bypass_reason.as_str()
        ),
    );
    match copy_passthrough_tunnel(
        &state,
        &operation_id,
        &mut stream,
        &mut upstream,
        close_on_protection_resume,
    )
    .await
    {
        Ok(PassthroughTunnelOutcome::Completed) => Ok(()),
        Ok(PassthroughTunnelOutcome::ClosedOnProtectionResume) => Ok(()),
        Err(error) => Err(format!("CONNECT passthrough failed: {error}")),
    }
}

async fn handle_raw_http_pass_through(
    state: Arc<ProxyState>,
    operation_id: String,
    request: InterceptedHttpRequest,
    mut stream: TcpStream,
) -> Result<(), String> {
    let Some(authority) = http_authority(&request.uri, &request.headers) else {
        write_intercepted_error(
            &mut stream,
            StatusCode::BAD_REQUEST,
            "HTTP proxy target host is missing",
        )
        .await?;
        return Ok(());
    };
    let mut upstream = match connect_target(&authority).await {
        Ok(upstream) => upstream,
        Err(error) => {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Error,
                LogEventType::ProxyFailure,
                "provider_down",
                "HTTP passthrough target is unavailable",
            );
            write_intercepted_error(&mut stream, StatusCode::BAD_GATEWAY, &error).await?;
            return Ok(());
        }
    };

    write_forward_proxy_request(&mut upstream, &request, &authority).await?;
    record_proxy_event(
        &state,
        &operation_id,
        LogLevel::Info,
        LogEventType::ProxyBypass,
        "bypassing",
        "HTTP request passed through without inspection",
    );
    tokio::io::copy(&mut upstream, &mut stream)
        .await
        .map(|_| ())
        .map_err(|error| format!("HTTP passthrough failed: {error}"))
}

async fn proxy_http_request(
    state: Arc<ProxyState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    operation_id: String,
) -> Response {
    let route = route_for_request(&state, &headers, &uri);
    let protection_enabled = state.protection_enabled();
    let inbound_plan = InboundTransformPlan {
        resolve_references: protection_enabled && state.resolve_inbound_for_route(route),
        protect_sensitive_data: protection_enabled && state.protect_inbound_for_route(route),
    };
    record_proxy_event(
        &state,
        &operation_id,
        LogLevel::Info,
        LogEventType::ProxyForward,
        "route_decision",
        format!(
            "route target={} provider={} method={} path={} protection_enabled={} resolve_inbound={} protect_inbound={} request_bytes={}",
            route.target().name,
            route.target().provider,
            method,
            uri.path(),
            protection_enabled,
            inbound_plan.resolve_references,
            inbound_plan.protect_sensitive_data,
            body.len()
        ),
    );

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

    if !protection_enabled {
        return forward_or_provider_down(
            state.clone(),
            route,
            ForwardAttempt {
                method,
                uri,
                headers,
                body,
                operation_id,
                action: "bypassing",
                related_domains: Arc::new(Vec::new()),
                inbound_plan,
            },
        )
        .await;
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
        dam_pipeline::ProtectTextContext {
            reference_vault: Some(state.vault.as_ref()),
            consent_store: state.consent_store.as_deref(),
            event_sink: state.log_sink.as_deref(),
            ..dam_pipeline::ProtectTextContext::default()
        },
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
    record_proxy_event(
        &state,
        &operation_id,
        LogLevel::Info,
        LogEventType::ProxyForward,
        "request_protection",
        format!(
            "request protection detections={} replacements={} tokenized={} blocked={}",
            protected.detections.len(),
            protected.plan.replacements.len(),
            protected.plan.tokenized_count(),
            protected.plan.blocked_count()
        ),
    );

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
    let related_domains = Arc::new(related_domains_from_detections(&protected.detections));
    let body_changed = protected_body.as_str() != body_text;
    let mut protected_headers = headers;
    if body_changed {
        let removed = strip_body_integrity_headers(&mut protected_headers);
        if removed > 0 {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Info,
                LogEventType::ProxyForward,
                "request_integrity_headers_removed",
                format!("removed body integrity headers count={removed}"),
            );
        }
    }
    forward_or_provider_down(
        state.clone(),
        route,
        ForwardAttempt {
            method,
            uri,
            headers: protected_headers,
            body: Bytes::from(protected_body),
            operation_id,
            action: "protected",
            related_domains,
            inbound_plan,
        },
    )
    .await
}

fn related_domains_from_detections(detections: &[dam_core::Detection]) -> Vec<String> {
    let mut domains = BTreeSet::new();
    for detection in detections
        .iter()
        .filter(|detection| detection.kind == dam_core::SensitiveType::Email)
    {
        let email =
            dam_core::canonical_sensitive_value(dam_core::SensitiveType::Email, &detection.value);
        let Some((_, domain)) = email.rsplit_once('@') else {
            continue;
        };
        let domain = dam_core::canonical_sensitive_value(dam_core::SensitiveType::Domain, domain);
        if domain.contains('.') {
            domains.insert(domain);
        }
    }
    domains.into_iter().collect()
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

async fn handle_upgraded_tunnel(
    state: Arc<ProxyState>,
    operation_id: String,
    authority: TargetAuthority,
    bypass_reason: ConnectBypassReason,
    upgrade: hyper::upgrade::OnUpgrade,
    mut upstream: TcpStream,
    close_on_protection_resume: bool,
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
    let mut client = TokioIo::new(upgraded);
    record_proxy_event(
        &state,
        &operation_id,
        LogLevel::Info,
        LogEventType::ProxyBypass,
        "bypassing",
        format!(
            "CONNECT tunnel passed through without inspection target={}:{} reason={}",
            authority.host,
            authority.port,
            bypass_reason.as_str()
        ),
    );
    match copy_passthrough_tunnel(
        &state,
        &operation_id,
        &mut client,
        &mut upstream,
        close_on_protection_resume,
    )
    .await
    {
        Ok(PassthroughTunnelOutcome::Completed)
        | Ok(PassthroughTunnelOutcome::ClosedOnProtectionResume) => {}
        Err(_) => {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Warn,
                LogEventType::ProxyFailure,
                "bypassing",
                "CONNECT passthrough ended with an I/O error",
            );
        }
    }
}

enum PassthroughTunnelOutcome {
    Completed,
    ClosedOnProtectionResume,
}

async fn copy_passthrough_tunnel<C, U>(
    state: &ProxyState,
    operation_id: &str,
    client: &mut C,
    upstream: &mut U,
    close_on_protection_resume: bool,
) -> Result<PassthroughTunnelOutcome, std::io::Error>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    if !close_on_protection_resume {
        tokio::io::copy_bidirectional(client, upstream).await?;
        return Ok(PassthroughTunnelOutcome::Completed);
    }

    let copy = tokio::io::copy_bidirectional(client, upstream);
    tokio::pin!(copy);
    let mut interval = tokio::time::interval(PASSTHROUGH_RESUME_POLL_INTERVAL);
    loop {
        tokio::select! {
            result = &mut copy => {
                result?;
                return Ok(PassthroughTunnelOutcome::Completed);
            }
            _ = interval.tick() => {
                if state.protection_enabled() {
                    record_proxy_event(
                        state,
                        operation_id,
                        LogLevel::Info,
                        LogEventType::ProxyBypass,
                        "bypassing",
                        "paused AI CONNECT tunnel closed because protection resumed",
                    );
                    return Ok(PassthroughTunnelOutcome::ClosedOnProtectionResume);
                }
            }
        }
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

    if websocket::is_upgrade_request(&request.method, &request.headers) {
        return handle_intercepted_websocket(state, operation_id, request, tls).await;
    }

    let response = proxy_http_request(
        state.clone(),
        request.method,
        request.uri,
        request.headers,
        request.body,
        operation_id.to_string(),
    )
    .await;

    log_intercepted_response_write(&state, operation_id, &response);
    if let Err(error) = write_intercepted_http_response(&mut tls, response).await {
        let _ = write_intercepted_error(&mut tls, StatusCode::BAD_GATEWAY, &error).await;
        return Err(error);
    }
    let _ = tls.shutdown().await;
    Ok(())
}

async fn handle_intercepted_websocket<T>(
    state: Arc<ProxyState>,
    operation_id: &str,
    request: InterceptedHttpRequest,
    mut client_tls: tokio_rustls::server::TlsStream<T>,
) -> Result<(), String>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let route = route_for_request(&state, &request.headers, &request.uri);
    let protection_enabled = state.protection_enabled();
    if route.config_required() {
        record_proxy_event(
            &state,
            operation_id,
            LogLevel::Error,
            LogEventType::ProxyFailure,
            "config_required",
            "WebSocket target API key is missing",
        );
        write_intercepted_error(
            &mut client_tls,
            StatusCode::SERVICE_UNAVAILABLE,
            "WebSocket target API key is missing",
        )
        .await?;
        return Ok(());
    }

    let Some(authority) = https_authority(&request.uri, &request.headers) else {
        write_intercepted_error(
            &mut client_tls,
            StatusCode::BAD_REQUEST,
            "WebSocket target host is missing",
        )
        .await?;
        return Ok(());
    };
    let upstream_tcp = connect_target(&authority).await?;
    let connector = upstream_tls_connector();
    let server_name = ServerName::try_from(authority.host.clone())
        .map_err(|_| "WebSocket target host is not a valid TLS server name".to_string())?;
    let mut upstream_tls = connector
        .connect(server_name, upstream_tcp)
        .await
        .map_err(|error| format!("WebSocket upstream TLS handshake failed: {error}"))?;

    write_websocket_upgrade_request(&mut upstream_tls, &request, &authority).await?;
    let upstream_head = read_intercepted_response_head(&mut upstream_tls).await?;
    if !websocket::response_is_switching_protocols(&upstream_head)? {
        write_intercepted_error(
            &mut client_tls,
            StatusCode::BAD_GATEWAY,
            "WebSocket upstream did not switch protocols",
        )
        .await?;
        return Ok(());
    }
    let response_head = websocket::filter_response_header_bytes(&upstream_head)?;
    client_tls
        .write_all(&response_head)
        .await
        .map_err(|error| format!("failed to write WebSocket upgrade response: {error}"))?;
    client_tls
        .flush()
        .await
        .map_err(|error| format!("failed to flush WebSocket upgrade response: {error}"))?;

    record_proxy_event(
        &state,
        operation_id,
        LogLevel::Info,
        LogEventType::ProxyForward,
        if protection_enabled {
            "protected"
        } else {
            "bypassing"
        },
        if protection_enabled {
            "WebSocket tunnel established with connection protection snapshot enabled"
        } else {
            "WebSocket tunnel established with connection protection snapshot disabled"
        },
    );

    proxy_websocket_frames(
        state,
        operation_id,
        client_tls,
        upstream_tls,
        protection_enabled,
    )
    .await
}

async fn proxy_websocket_frames<C, U>(
    state: Arc<ProxyState>,
    operation_id: &str,
    client_tls: C,
    upstream_tls: U,
    protection_enabled: bool,
) -> Result<(), String>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_reader, mut client_writer) = tokio::io::split(client_tls);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream_tls);
    let related_domains = Arc::new(RwLock::new(Vec::new()));
    let outcome = {
        let client_to_upstream = proxy_websocket_client_frames(
            state.clone(),
            operation_id.to_string(),
            &mut client_reader,
            &mut upstream_writer,
            related_domains.clone(),
            protection_enabled,
        );
        let upstream_to_client = proxy_websocket_upstream_frames(
            state.clone(),
            operation_id.to_string(),
            &mut upstream_reader,
            &mut client_writer,
            related_domains,
            protection_enabled,
        );

        tokio::select! {
            result = client_to_upstream => result,
            result = upstream_to_client => result,
        }
    }?;

    if matches!(outcome, WebSocketClientFrameOutcome::PolicyBlocked) {
        let close = websocket::WebSocketFrame::close(1008, "blocked by DAM policy");
        websocket::write_unmasked_frame(&mut client_writer, &close).await?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebSocketClientFrameOutcome {
    Completed,
    PolicyBlocked,
}

async fn proxy_websocket_client_frames<R, W>(
    state: Arc<ProxyState>,
    operation_id: String,
    reader: &mut R,
    writer: &mut W,
    related_domains: Arc<RwLock<Vec<String>>>,
    protection_enabled: bool,
) -> Result<WebSocketClientFrameOutcome, String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let Some(mut frame) = (match websocket::read_frame(reader).await {
            Ok(frame) => frame,
            Err(error) if protection_enabled && websocket_frame_error_is_unsupported(&error) => {
                record_proxy_event(
                    &state,
                    &operation_id,
                    LogLevel::Warn,
                    LogEventType::ProxyFailure,
                    "unsupported_websocket_frame",
                    "WebSocket request frame closed because unsupported protected frame shape was received",
                );
                return Ok(WebSocketClientFrameOutcome::PolicyBlocked);
            }
            Err(error) => return Err(error),
        }) else {
            return Ok(WebSocketClientFrameOutcome::Completed);
        };
        if frame.is_unfragmented_text() && protection_enabled {
            let text = std::str::from_utf8(&frame.payload)
                .map_err(|_| "WebSocket text frame is not utf-8".to_string())?;
            let protected = dam_pipeline::protect_text(
                text,
                &operation_id,
                &state.policy,
                state.vault.as_ref(),
                dam_pipeline::ProtectTextContext {
                    reference_vault: Some(state.vault.as_ref()),
                    consent_store: state.consent_store.as_deref(),
                    event_sink: state.log_sink.as_deref(),
                    ..dam_pipeline::ProtectTextContext::default()
                },
                state.replacement_options,
            )
            .map_err(|_| "WebSocket request frame protection failed".to_string())?;
            if protected.is_blocked() {
                record_proxy_event(
                    &state,
                    &operation_id,
                    LogLevel::Warn,
                    LogEventType::ProxyFailure,
                    "blocked",
                    "WebSocket request frame blocked by policy",
                );
                return Ok(WebSocketClientFrameOutcome::PolicyBlocked);
            }
            remember_related_domains(&related_domains, &protected.detections)?;
            let Some(output) = protected.output else {
                return Err("WebSocket request frame protection did not produce output".to_string());
            };
            frame.payload = output.into_bytes();
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Info,
                LogEventType::ProxyForward,
                "protected",
                "WebSocket request text frame protected",
            );
        } else if protection_enabled && websocket_frame_requires_body_protection(&frame) {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Warn,
                LogEventType::ProxyFailure,
                "unsupported_websocket_frame",
                "WebSocket request frame closed because fragmented/binary protection is parked",
            );
            return Ok(WebSocketClientFrameOutcome::PolicyBlocked);
        }
        let is_close = frame.opcode == websocket::OPCODE_CLOSE;
        websocket::write_masked_frame(writer, &frame).await?;
        if is_close {
            return Ok(WebSocketClientFrameOutcome::Completed);
        }
    }
}

async fn proxy_websocket_upstream_frames<R, W>(
    state: Arc<ProxyState>,
    operation_id: String,
    reader: &mut R,
    writer: &mut W,
    related_domains: Arc<RwLock<Vec<String>>>,
    protection_enabled: bool,
) -> Result<WebSocketClientFrameOutcome, String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let Some(mut frame) = (match websocket::read_frame(reader).await {
            Ok(frame) => frame,
            Err(error) if protection_enabled && websocket_frame_error_is_unsupported(&error) => {
                record_proxy_event(
                    &state,
                    &operation_id,
                    LogLevel::Warn,
                    LogEventType::ProxyFailure,
                    "unsupported_websocket_frame",
                    "WebSocket response frame closed because unsupported protected frame shape was received",
                );
                return Ok(WebSocketClientFrameOutcome::PolicyBlocked);
            }
            Err(error) => return Err(error),
        }) else {
            return Ok(WebSocketClientFrameOutcome::Completed);
        };
        if frame.is_unfragmented_text() && protection_enabled {
            let text = std::str::from_utf8(&frame.payload)
                .map_err(|_| "WebSocket response text frame is not utf-8".to_string())?;
            let domains = related_domains.read().map_err(|_| {
                "WebSocket related-domain state is unavailable after a prior failure".to_string()
            })?;
            let protected = dam_pipeline::protect_text(
                text,
                &operation_id,
                &state.policy,
                state.vault.as_ref(),
                dam_pipeline::ProtectTextContext {
                    reference_vault: Some(state.vault.as_ref()),
                    consent_store: state.consent_store.as_deref(),
                    event_sink: state.log_sink.as_deref(),
                    related_domains: domains.as_slice(),
                    ..dam_pipeline::ProtectTextContext::default()
                },
                state.replacement_options,
            )
            .map_err(|_| "WebSocket response frame protection failed".to_string())?;
            if protected.is_blocked() {
                record_proxy_event(
                    &state,
                    &operation_id,
                    LogLevel::Warn,
                    LogEventType::ProxyFailure,
                    "inbound_blocked",
                    "WebSocket response frame blocked by policy",
                );
                return Ok(WebSocketClientFrameOutcome::PolicyBlocked);
            } else {
                let Some(output) = protected.output else {
                    return Err(
                        "WebSocket response frame protection did not produce output".to_string()
                    );
                };
                frame.payload = output.into_bytes();
            }
            if !protected.detections.is_empty() {
                record_proxy_event(
                    &state,
                    &operation_id,
                    LogLevel::Info,
                    LogEventType::ProxyForward,
                    "inbound_protection",
                    format!(
                        "WebSocket response text frame protected detections={} replacements={} tokenized={} blocked={}",
                        protected.detections.len(),
                        protected.plan.replacements.len(),
                        protected.plan.tokenized_count(),
                        protected.plan.blocked_count()
                    ),
                );
            }
        } else if protection_enabled && websocket_frame_requires_body_protection(&frame) {
            record_proxy_event(
                &state,
                &operation_id,
                LogLevel::Warn,
                LogEventType::ProxyFailure,
                "unsupported_websocket_frame",
                "WebSocket response frame closed because fragmented/binary protection is parked",
            );
            return Ok(WebSocketClientFrameOutcome::PolicyBlocked);
        }
        let is_close = frame.opcode == websocket::OPCODE_CLOSE;
        websocket::write_unmasked_frame(writer, &frame).await?;
        if is_close {
            return Ok(WebSocketClientFrameOutcome::Completed);
        }
    }
}

fn remember_related_domains(
    related_domains: &Arc<RwLock<Vec<String>>>,
    detections: &[dam_core::Detection],
) -> Result<(), String> {
    let mut related_domains = related_domains.write().map_err(|_| {
        "WebSocket related-domain state is unavailable after a prior failure".to_string()
    })?;
    for domain in related_domains_from_detections(detections) {
        if !related_domains.contains(&domain) {
            related_domains.push(domain);
        }
    }
    Ok(())
}

fn websocket_frame_requires_body_protection(frame: &websocket::WebSocketFrame) -> bool {
    frame.is_fragmented_text_or_continuation() || frame.is_binary()
}

fn websocket_frame_error_is_unsupported(error: &str) -> bool {
    error.contains("compressed or extension WebSocket frames are not supported")
}

async fn write_websocket_upgrade_request<T>(
    upstream: &mut T,
    request: &InterceptedHttpRequest,
    authority: &TargetAuthority,
) -> Result<(), String>
where
    T: AsyncWrite + Unpin,
{
    let target = origin_form_target(&request.uri);
    upstream
        .write_all(format!("{} {target} HTTP/1.1\r\n", request.method).as_bytes())
        .await
        .map_err(|error| format!("failed to write WebSocket upgrade request: {error}"))?;
    upstream
        .write_all(format!("host: {}\r\n", authority_header_value(authority)).as_bytes())
        .await
        .map_err(|error| format!("failed to write WebSocket upgrade request: {error}"))?;
    upstream
        .write_all(b"connection: Upgrade\r\nupgrade: websocket\r\n")
        .await
        .map_err(|error| format!("failed to write WebSocket upgrade request: {error}"))?;
    for (name, value) in request.headers.iter() {
        if websocket::request_header_should_skip(name) {
            continue;
        }
        upstream
            .write_all(name.as_str().as_bytes())
            .await
            .map_err(|error| format!("failed to write WebSocket upgrade request: {error}"))?;
        upstream
            .write_all(b": ")
            .await
            .map_err(|error| format!("failed to write WebSocket upgrade request: {error}"))?;
        upstream
            .write_all(value.as_bytes())
            .await
            .map_err(|error| format!("failed to write WebSocket upgrade request: {error}"))?;
        upstream
            .write_all(b"\r\n")
            .await
            .map_err(|error| format!("failed to write WebSocket upgrade request: {error}"))?;
    }
    upstream
        .write_all(b"\r\n")
        .await
        .map_err(|error| format!("failed to finish WebSocket upgrade request: {error}"))?;
    upstream
        .flush()
        .await
        .map_err(|error| format!("failed to flush WebSocket upgrade request: {error}"))
}

async fn read_intercepted_response_head<T>(stream: &mut T) -> Result<Vec<u8>, String>
where
    T: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if find_header_end(&buffer).is_some() {
            return Ok(buffer);
        }
        if buffer.len() >= MAX_INTERCEPTED_HEADER_BYTES {
            return Err("WebSocket upstream response headers are too large".to_string());
        }
        let read = stream
            .read(&mut byte)
            .await
            .map_err(|error| format!("failed to read WebSocket upstream response: {error}"))?;
        if read == 0 {
            return Err("WebSocket upstream response ended before headers completed".to_string());
        }
        buffer.extend_from_slice(&byte[..read]);
    }
}

fn upstream_tls_connector() -> TlsConnector {
    ensure_rustls_crypto_provider();
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
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
    state: &ProxyState,
    interception: &TransparentInterceptionConfig,
    host: &str,
) -> Result<TlsAcceptor, String> {
    let host = dam_net::normalize_ai_host(host);
    if host.is_empty() {
        return Err("failed to issue local TLS certificate: host is empty".to_string());
    }
    if let Some(config) = state
        .tls_acceptor_cache
        .lock()
        .map_err(|_| "TLS certificate cache is unavailable".to_string())?
        .get(&host)
        .cloned()
    {
        return Ok(TlsAcceptor::from(config));
    }

    let issued = dam_trust::issue_local_ca_leaf_certificate(&interception.state_dir, &host)
        .map_err(|error| format!("failed to issue local TLS certificate: {error}"))?;
    let config = Arc::new(tls_server_config(issued)?);
    state
        .tls_acceptor_cache
        .lock()
        .map_err(|_| "TLS certificate cache is unavailable".to_string())?
        .insert(host, config.clone());
    Ok(TlsAcceptor::from(config))
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetAuthority {
    host: String,
    port: u16,
}

fn connect_authority(uri: &Uri, headers: &HeaderMap) -> Option<TargetAuthority> {
    uri.authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .and_then(|value| parse_target_authority(value, 443))
}

fn http_authority(uri: &Uri, headers: &HeaderMap) -> Option<TargetAuthority> {
    if matches!(uri.scheme_str(), Some(scheme) if !scheme.eq_ignore_ascii_case("http")) {
        return None;
    }
    uri.authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .and_then(|value| parse_target_authority(value, 80))
}

fn https_authority(uri: &Uri, headers: &HeaderMap) -> Option<TargetAuthority> {
    if matches!(uri.scheme_str(), Some(scheme) if !scheme.eq_ignore_ascii_case("https")) {
        return None;
    }
    uri.authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .and_then(|value| parse_target_authority(value, 443))
}

fn parse_target_authority(value: &str, default_port: u16) -> Option<TargetAuthority> {
    let value = value
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or_default()
        .trim();
    if value.is_empty() {
        return None;
    }

    if let Some(rest) = value.strip_prefix('[') {
        let (host, remainder) = rest.split_once(']')?;
        let port = remainder
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Some(TargetAuthority {
            host: host.to_ascii_lowercase(),
            port,
        });
    }

    let (host, port) = value
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
        .unwrap_or((value, default_port));
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(TargetAuthority { host, port })
}

async fn connect_target(authority: &TargetAuthority) -> Result<TcpStream, String> {
    TcpStream::connect((authority.host.as_str(), authority.port))
        .await
        .map_err(|error| {
            format!(
                "failed to connect to {}:{}: {error}",
                authority.host, authority.port
            )
        })
}

fn is_forward_proxy_http_request(uri: &Uri) -> bool {
    uri.scheme().is_some() && uri.authority().is_some()
}

fn should_protect_forward_proxy_http_request(
    state: &ProxyState,
    request: &InterceptedHttpRequest,
) -> bool {
    if !state.protection_enabled() {
        return false;
    }
    let Some(interception) = state.transparent_interception.as_ref() else {
        return false;
    };
    http_authority(&request.uri, &request.headers)
        .and_then(|authority| {
            dam_net::classify_ai_host_with_routes(&authority.host, &interception.ai_routes)
        })
        .is_some()
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

impl ProxyState {
    fn resolve_inbound_for_route(&self, route: dam_router::RouteDecision<'_>) -> bool {
        self.resolve_inbound
            && self
                .route_resolve_inbound
                .get(&route.target().name)
                .copied()
                .unwrap_or(true)
    }

    fn protect_inbound_for_route(&self, route: dam_router::RouteDecision<'_>) -> bool {
        self.route_protect_inbound
            .get(&route.target().name)
            .copied()
            .unwrap_or(false)
    }
}

fn route_resolve_inbound(profile: &dam_net::TrafficProfile) -> HashMap<String, bool> {
    let mut policies = HashMap::new();
    for app in &profile.apps {
        if !app.enabled || app.action != dam_net::TrafficAction::Inspect {
            continue;
        }
        let target_name = app
            .target_name
            .as_ref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&app.id);
        policies.insert(target_name.clone(), app.inbound.resolve_references);
    }
    policies
}

fn route_protect_inbound(profile: &dam_net::TrafficProfile) -> HashMap<String, bool> {
    let mut policies = HashMap::new();
    for app in &profile.apps {
        if !app.enabled || app.action != dam_net::TrafficAction::Inspect {
            continue;
        }
        let target_name = app
            .target_name
            .as_ref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&app.id);
        policies.insert(target_name.clone(), app.inbound.protect_sensitive_data);
    }
    policies
}

fn route_for_request<'a>(
    state: &'a ProxyState,
    headers: &HeaderMap,
    uri: &Uri,
) -> dam_router::RouteDecision<'a> {
    if let Some(ai_route) = ai_route_for_request(state, headers, uri) {
        return state.routes.decide_for_ai_route(headers, &ai_route);
    }

    state.routes.decide(headers, Some(uri))
}

fn ai_route_for_request(
    state: &ProxyState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Option<dam_net::AiRoute> {
    let interception = state.transparent_interception.as_ref()?;
    let authority = https_authority(uri, headers).or_else(|| http_authority(uri, headers))?;
    dam_net::classify_ai_host_with_routes(&authority.host, &interception.ai_routes)
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

async fn write_forward_proxy_request<T>(
    upstream: &mut T,
    request: &InterceptedHttpRequest,
    authority: &TargetAuthority,
) -> Result<(), String>
where
    T: AsyncWrite + Unpin,
{
    let target = origin_form_target(&request.uri);
    upstream
        .write_all(format!("{} {target} HTTP/1.1\r\n", request.method).as_bytes())
        .await
        .map_err(|error| format!("failed to write passthrough request: {error}"))?;
    upstream
        .write_all(format!("host: {}\r\n", authority_header_value(authority)).as_bytes())
        .await
        .map_err(|error| format!("failed to write passthrough request: {error}"))?;
    for (name, value) in request.headers.iter() {
        if passthrough_request_should_skip_header(name) {
            continue;
        }
        upstream
            .write_all(name.as_str().as_bytes())
            .await
            .map_err(|error| format!("failed to write passthrough request: {error}"))?;
        upstream
            .write_all(b": ")
            .await
            .map_err(|error| format!("failed to write passthrough request: {error}"))?;
        upstream
            .write_all(value.as_bytes())
            .await
            .map_err(|error| format!("failed to write passthrough request: {error}"))?;
        upstream
            .write_all(b"\r\n")
            .await
            .map_err(|error| format!("failed to write passthrough request: {error}"))?;
    }
    upstream
        .write_all(b"connection: close\r\n\r\n")
        .await
        .map_err(|error| format!("failed to write passthrough request: {error}"))?;
    upstream
        .write_all(&request.body)
        .await
        .map_err(|error| format!("failed to write passthrough request body: {error}"))?;
    upstream
        .flush()
        .await
        .map_err(|error| format!("failed to flush passthrough request: {error}"))
}

fn origin_form_target(uri: &Uri) -> String {
    uri.path_and_query()
        .map(|value| value.as_str().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "/".to_string())
}

fn authority_header_value(authority: &TargetAuthority) -> String {
    if authority.port == 80 {
        authority.host.clone()
    } else if authority.host.contains(':') {
        format!("[{}]:{}", authority.host, authority.port)
    } else {
        format!("{}:{}", authority.host, authority.port)
    }
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

fn passthrough_request_should_skip_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "proxy-connection"
            | "proxy-authorization"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn protection_control_enabled(path: &PathBuf) -> bool {
    let Ok(value) = fs::read_to_string(path) else {
        return true;
    };
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&value)
        && let Some(enabled) = json.get("enabled").and_then(serde_json::Value::as_bool)
    {
        return enabled;
    }
    !value.trim().eq_ignore_ascii_case("disabled")
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
    related_domains: Arc<Vec<String>>,
    inbound_plan: InboundTransformPlan,
}

#[derive(Debug, Clone, Copy)]
struct InboundTransformPlan {
    resolve_references: bool,
    protect_sensitive_data: bool,
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
        Arc::clone(&attempt.related_domains),
        attempt.inbound_plan,
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
    state: &Arc<ProxyState>,
    route: dam_router::RouteDecision<'_>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    operation_id: &str,
    related_domains: Arc<Vec<String>>,
    inbound_plan: InboundTransformPlan,
) -> Result<Response, String> {
    let target_api_key = route.target_api_key();
    let transform_inbound = inbound_plan.resolve_references || inbound_plan.protect_sensitive_data;
    match state.providers.get(route.provider_kind()) {
        ProviderAdapter::OpenAi(provider) => {
            let target_name = route.target().name.clone();
            let target_provider = route.target().provider.clone();
            let response_state = Arc::clone(state);
            let response_operation_id = operation_id.to_owned();
            let response_related_domains = Arc::clone(&related_domains);
            let request = dam_provider_openai::ForwardRequest {
                upstream: &route.target().upstream,
                method,
                uri,
                headers,
                body,
                target_api_key,
                transform_streaming_response: transform_inbound,
            };
            record_proxy_event(
                state,
                operation_id,
                LogLevel::Info,
                LogEventType::ProxyForward,
                "provider_forward_start",
                format!(
                    "provider forward start target={target_name} provider={target_provider} resolve_inbound={} transform_streaming={}",
                    inbound_plan.resolve_references, transform_inbound
                ),
            );
            let response = provider
                .forward(request, move |response_body| {
                    resolve_response_body(
                        &response_state,
                        &response_operation_id,
                        response_body,
                        inbound_plan,
                        response_related_domains.as_slice(),
                    )
                })
                .await
                .map_err(|error| error.to_string())?;
            log_provider_response(state, operation_id, &response);
            Ok(response)
        }
        ProviderAdapter::Anthropic(provider) => {
            let target_name = route.target().name.clone();
            let target_provider = route.target().provider.clone();
            let response_state = Arc::clone(state);
            let response_operation_id = operation_id.to_owned();
            let response_related_domains = Arc::clone(&related_domains);
            let request = dam_provider_anthropic::ForwardRequest {
                upstream: &route.target().upstream,
                method,
                uri,
                headers,
                body,
                target_api_key,
                transform_streaming_response: transform_inbound,
            };
            record_proxy_event(
                state,
                operation_id,
                LogLevel::Info,
                LogEventType::ProxyForward,
                "provider_forward_start",
                format!(
                    "provider forward start target={target_name} provider={target_provider} resolve_inbound={} transform_streaming={}",
                    inbound_plan.resolve_references, transform_inbound
                ),
            );
            let response = provider
                .forward(request, move |response_body| {
                    resolve_response_body(
                        &response_state,
                        &response_operation_id,
                        response_body,
                        inbound_plan,
                        response_related_domains.as_slice(),
                    )
                })
                .await
                .map_err(|error| error.to_string())?;
            log_provider_response(state, operation_id, &response);
            Ok(response)
        }
    }
}

fn resolve_response_body(
    state: &ProxyState,
    operation_id: &str,
    body: Bytes,
    inbound_plan: InboundTransformPlan,
    related_domains: &[String],
) -> Bytes {
    if !inbound_plan.resolve_references {
        record_proxy_event(
            state,
            operation_id,
            LogLevel::Info,
            LogEventType::ProxyForward,
            "resolve_disabled",
            format!("inbound resolution disabled response_bytes={}", body.len()),
        );
        if !inbound_plan.protect_sensitive_data {
            return body;
        }
        let body_text = match std::str::from_utf8(body.as_ref()) {
            Ok(text) => text,
            Err(_) => return body,
        };
        return protect_inbound_response_body(state, operation_id, body_text, related_domains)
            .map(Bytes::from)
            .unwrap_or(body);
    }

    let body_text = match std::str::from_utf8(body.as_ref()) {
        Ok(text) => text,
        Err(_) => {
            record_proxy_event(
                state,
                operation_id,
                LogLevel::Warn,
                LogEventType::Resolve,
                "resolve_non_utf8",
                format!(
                    "inbound resolution skipped non_utf8 response_bytes={}",
                    body.len()
                ),
            );
            return body;
        }
    };
    let result = dam_pipeline::resolve_text(
        body_text,
        operation_id,
        state.vault.as_ref(),
        state.log_sink.as_deref(),
    );
    record_proxy_event(
        state,
        operation_id,
        LogLevel::Info,
        LogEventType::Resolve,
        "resolve_attempt",
        format!(
            "inbound resolution references={} resolved={} missing={} read_failures={} response_bytes={}",
            result.plan.references.len(),
            result.plan.resolved_count(),
            result.plan.missing_count(),
            result.plan.read_failure_count(),
            body.len()
        ),
    );
    if let Some(output) = result.output {
        return Bytes::from(output);
    }

    if inbound_plan.protect_sensitive_data {
        protect_inbound_response_body(state, operation_id, body_text, related_domains)
            .map(Bytes::from)
            .unwrap_or(body)
    } else {
        body
    }
}

fn protect_inbound_response_body(
    state: &ProxyState,
    operation_id: &str,
    body_text: &str,
    related_domains: &[String],
) -> Option<String> {
    if !state.protection_enabled() {
        return None;
    }

    let protected = match dam_pipeline::protect_text(
        body_text,
        operation_id,
        &state.policy,
        state.vault.as_ref(),
        dam_pipeline::ProtectTextContext {
            reference_vault: Some(state.vault.as_ref()),
            consent_store: state.consent_store.as_deref(),
            event_sink: state.log_sink.as_deref(),
            related_domains,
            ..dam_pipeline::ProtectTextContext::default()
        },
        state.replacement_options,
    ) {
        Ok(result) => result,
        Err(_) => {
            record_proxy_event(
                state,
                operation_id,
                LogLevel::Warn,
                LogEventType::ProxyFailure,
                "inbound_protection_failed",
                "inbound response protection failed",
            );
            return None;
        }
    };

    if protected.detections.is_empty() {
        return None;
    }

    record_proxy_event(
        state,
        operation_id,
        LogLevel::Info,
        LogEventType::ProxyForward,
        "inbound_protection",
        format!(
            "inbound protection detections={} replacements={} tokenized={} blocked={}",
            protected.detections.len(),
            protected.plan.replacements.len(),
            protected.plan.tokenized_count(),
            protected.plan.blocked_count()
        ),
    );

    if protected.is_blocked() {
        record_proxy_event(
            state,
            operation_id,
            LogLevel::Warn,
            LogEventType::ProxyFailure,
            "inbound_blocked",
            "inbound response blocked by policy",
        );
        return Some("[blocked by DAM policy]".to_string());
    }

    protected.output
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

fn strip_body_integrity_headers(headers: &mut HeaderMap) -> usize {
    let mut removed = 0;
    for name in [
        "content-digest",
        "content-md5",
        "digest",
        "repr-digest",
        "signature",
        "signature-input",
        "x-content-digest",
        "x-content-md5",
        "x-body-digest",
        "x-body-sha256",
        "x-payload-digest",
        "x-payload-sha256",
        "x-signature",
    ] {
        if headers.remove(name).is_some() {
            removed += 1;
        }
    }
    removed
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
    use futures_util::stream;
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

    fn set_test_target_inbound_policy(
        config: &mut dam_config::DamConfig,
        resolve_references: bool,
        protect_sensitive_data: bool,
    ) {
        let target = config.proxy.targets[0].clone();
        config
            .traffic
            .profile
            .apps
            .push(dam_net::TrafficAppProfile {
                id: format!("{}-test-route", target.name),
                name: None,
                enabled: true,
                priority: 100,
                match_rules: dam_net::TrafficMatch {
                    domains: vec![target.upstream.clone()],
                    ..dam_net::TrafficMatch::default()
                },
                action: dam_net::TrafficAction::Inspect,
                adapter: dam_net::ProtocolAdapterKind::Http,
                provider: Some(target.provider),
                target_name: Some(target.name),
                upstream: Some(target.upstream),
                traffic_kind: dam_net::AiTrafficKind::Custom,
                steps: Vec::new(),
                outbound: dam_net::TrafficDirectionPolicy::default(),
                inbound: dam_net::TrafficInboundPolicy {
                    resolve_references,
                    protect_sensitive_data,
                    ..dam_net::TrafficInboundPolicy::default()
                },
            });
    }

    async fn spawn_app(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn websocket_response_text_frames_are_tokenized_before_client() {
        let config = proxy_config("https://chatgpt.com".to_string());
        let log_path = config.log.sqlite_path.clone();
        let state = build_state(config, None).unwrap();
        let mut upstream = Vec::new();
        websocket::write_unmasked_frame(
            &mut upstream,
            &websocket::WebSocketFrame {
                fin: true,
                opcode: websocket::OPCODE_TEXT,
                payload: br#"{"content":"banana@example.com"}"#.to_vec(),
            },
        )
        .await
        .unwrap();
        websocket::write_unmasked_frame(&mut upstream, &websocket::WebSocketFrame::close(1000, ""))
            .await
            .unwrap();
        let mut client = Vec::new();

        proxy_websocket_upstream_frames(
            state,
            "websocket-inbound-test".to_string(),
            &mut upstream.as_slice(),
            &mut client,
            Arc::new(RwLock::new(Vec::new())),
            true,
        )
        .await
        .unwrap();

        let frame = websocket::read_frame(&mut client.as_slice())
            .await
            .unwrap()
            .unwrap();
        let body = String::from_utf8(frame.payload).unwrap();
        assert!(!body.contains("banana@example.com"));
        assert!(body.contains("[email:"));
        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| {
            entry.action.as_deref() == Some("inbound_protection")
                && entry
                    .message
                    .contains("WebSocket response text frame protected")
        }));
    }

    #[tokio::test]
    async fn websocket_response_uses_related_domains_from_request_context() {
        let state = build_state(proxy_config("https://chatgpt.com".to_string()), None).unwrap();
        let mut upstream = Vec::new();
        websocket::write_unmasked_frame(
            &mut upstream,
            &websocket::WebSocketFrame {
                fin: true,
                opcode: websocket::OPCODE_TEXT,
                payload: br#"{"content":"wolol3o22.com"}"#.to_vec(),
            },
        )
        .await
        .unwrap();
        websocket::write_unmasked_frame(&mut upstream, &websocket::WebSocketFrame::close(1000, ""))
            .await
            .unwrap();
        let mut client = Vec::new();

        proxy_websocket_upstream_frames(
            state,
            "websocket-related-domain-test".to_string(),
            &mut upstream.as_slice(),
            &mut client,
            Arc::new(RwLock::new(vec!["wolol3o22.com".to_string()])),
            true,
        )
        .await
        .unwrap();

        let frame = websocket::read_frame(&mut client.as_slice())
            .await
            .unwrap()
            .unwrap();
        let body = String::from_utf8(frame.payload).unwrap();
        assert!(!body.contains("wolol3o22.com"));
        assert!(body.contains("[domain:"));
    }

    #[tokio::test]
    async fn websocket_response_respects_connection_protection_snapshot() {
        let state = build_state(proxy_config("https://chatgpt.com".to_string()), None).unwrap();
        let mut upstream = Vec::new();
        websocket::write_unmasked_frame(
            &mut upstream,
            &websocket::WebSocketFrame {
                fin: true,
                opcode: websocket::OPCODE_TEXT,
                payload: br#"{"content":"banana@example.com"}"#.to_vec(),
            },
        )
        .await
        .unwrap();
        websocket::write_unmasked_frame(&mut upstream, &websocket::WebSocketFrame::close(1000, ""))
            .await
            .unwrap();
        let mut client = Vec::new();

        proxy_websocket_upstream_frames(
            state,
            "websocket-snapshot-test".to_string(),
            &mut upstream.as_slice(),
            &mut client,
            Arc::new(RwLock::new(Vec::new())),
            false,
        )
        .await
        .unwrap();

        let frame = websocket::read_frame(&mut client.as_slice())
            .await
            .unwrap()
            .unwrap();
        let body = String::from_utf8(frame.payload).unwrap();
        assert!(body.contains("banana@example.com"));
        assert!(!body.contains("[email:"));
    }

    #[tokio::test]
    async fn websocket_response_fragmented_text_fails_closed_when_protected() {
        let state = build_state(proxy_config("https://chatgpt.com".to_string()), None).unwrap();
        let mut upstream = Vec::new();
        websocket::write_unmasked_frame(
            &mut upstream,
            &websocket::WebSocketFrame {
                fin: false,
                opcode: websocket::OPCODE_TEXT,
                payload: br#"{"content":"banana@example.com"}"#.to_vec(),
            },
        )
        .await
        .unwrap();
        let mut client = Vec::new();

        let outcome = proxy_websocket_upstream_frames(
            state,
            "websocket-fragmented-inbound-test".to_string(),
            &mut upstream.as_slice(),
            &mut client,
            Arc::new(RwLock::new(Vec::new())),
            true,
        )
        .await
        .unwrap();

        assert_eq!(outcome, WebSocketClientFrameOutcome::PolicyBlocked);
        assert!(client.is_empty());
    }

    #[tokio::test]
    async fn websocket_response_compressed_frame_fails_closed_when_protected() {
        let state = build_state(proxy_config("https://chatgpt.com".to_string()), None).unwrap();
        let mut upstream = vec![0x80 | 0x40 | websocket::OPCODE_TEXT, 5];
        upstream.extend_from_slice(b"hello");
        let mut client = Vec::new();

        let outcome = proxy_websocket_upstream_frames(
            state,
            "websocket-compressed-inbound-test".to_string(),
            &mut upstream.as_slice(),
            &mut client,
            Arc::new(RwLock::new(Vec::new())),
            true,
        )
        .await
        .unwrap();

        assert_eq!(outcome, WebSocketClientFrameOutcome::PolicyBlocked);
        assert!(client.is_empty());
    }

    #[tokio::test]
    async fn websocket_response_policy_block_fails_closed() {
        let mut config = proxy_config("https://chatgpt.com".to_string());
        config.policy.default_action = dam_core::PolicyAction::Block;
        let state = build_state(config, None).unwrap();
        let mut upstream = Vec::new();
        websocket::write_unmasked_frame(
            &mut upstream,
            &websocket::WebSocketFrame {
                fin: true,
                opcode: websocket::OPCODE_TEXT,
                payload: br#"{"content":"banana@example.com"}"#.to_vec(),
            },
        )
        .await
        .unwrap();
        let mut client = Vec::new();

        let outcome = proxy_websocket_upstream_frames(
            state,
            "websocket-inbound-block-test".to_string(),
            &mut upstream.as_slice(),
            &mut client,
            Arc::new(RwLock::new(Vec::new())),
            true,
        )
        .await
        .unwrap();

        assert_eq!(outcome, WebSocketClientFrameOutcome::PolicyBlocked);
        assert!(client.is_empty());
    }

    #[tokio::test]
    async fn websocket_upgrade_request_strips_extension_negotiation() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "chatgpt.com".parse().unwrap());
        headers.insert("sec-websocket-key", "abc".parse().unwrap());
        headers.insert(
            "sec-websocket-extensions",
            "permessage-deflate".parse().unwrap(),
        );
        let request = InterceptedHttpRequest {
            method: Method::GET,
            uri: Uri::from_static("https://chatgpt.com/backend-api/ws?x=1"),
            headers,
            body: Bytes::new(),
        };
        let mut output = Vec::new();

        write_websocket_upgrade_request(
            &mut output,
            &request,
            &TargetAuthority {
                host: "chatgpt.com".to_string(),
                port: 443,
            },
        )
        .await
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.starts_with("GET /backend-api/ws?x=1 HTTP/1.1\r\n"));
        assert!(text.contains("sec-websocket-key: abc\r\n"));
        assert!(
            !text
                .to_ascii_lowercase()
                .contains("sec-websocket-extensions")
        );
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

    async fn spawn_raw_sensitive_response_upstream(
        seen_body: Arc<Mutex<Option<String>>>,
    ) -> String {
        async fn raw_response(
            State(seen_body): State<Arc<Mutex<Option<String>>>>,
            body: Bytes,
        ) -> Response {
            let body_text =
                String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
            *seen_body.lock().unwrap() = Some(body_text);

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"message":{"content":"provider returned leak@example.com"}}"#,
                ))
                .unwrap()
        }

        spawn_app(
            Router::new()
                .route("/v1/chat/completions", post(raw_response))
                .with_state(seen_body),
        )
        .await
    }

    async fn spawn_raw_domain_response_upstream(seen_body: Arc<Mutex<Option<String>>>) -> String {
        async fn raw_response(
            State(seen_body): State<Arc<Mutex<Option<String>>>>,
            body: Bytes,
        ) -> Response {
            let body_text =
                String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
            *seen_body.lock().unwrap() = Some(body_text);

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"message":{"content":"provider returned leak.example"}}"#,
                ))
                .unwrap()
        }

        spawn_app(
            Router::new()
                .route("/v1/chat/completions", post(raw_response))
                .with_state(seen_body),
        )
        .await
    }

    async fn spawn_capture_codex_compact_upstream(seen_body: Arc<Mutex<Option<String>>>) -> String {
        async fn compact(
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
                .route("/backend-api/codex/responses/compact", post(compact))
                .with_state(seen_body),
        )
        .await
    }

    async fn spawn_json_escaped_reference_upstream(
        seen_body: Arc<Mutex<Option<String>>>,
    ) -> String {
        async fn json_response(
            State(seen_body): State<Arc<Mutex<Option<String>>>>,
            body: Bytes,
        ) -> Response {
            let body_text =
                String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
            *seen_body.lock().unwrap() = Some(body_text.clone());
            let reference = dam_core::find_references(&body_text)
                .into_iter()
                .next()
                .expect("protected upstream body should contain a reference")
                .reference
                .display();
            let escaped_reference = reference.replace('[', r"\\[").replace(']', r"\\]");
            let response = format!(r#"{{"message":{{"content":"{escaped_reference}"}}}}"#);

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(response))
                .unwrap()
        }

        spawn_app(
            Router::new()
                .route("/v1/chat/completions", post(json_response))
                .with_state(seen_body),
        )
        .await
    }

    async fn spawn_ndjson_escaped_reference_upstream(
        seen_body: Arc<Mutex<Option<String>>>,
    ) -> String {
        async fn ndjson_response(
            State(seen_body): State<Arc<Mutex<Option<String>>>>,
            body: Bytes,
        ) -> Response {
            let body_text =
                String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
            *seen_body.lock().unwrap() = Some(body_text.clone());
            let reference = dam_core::find_references(&body_text)
                .into_iter()
                .next()
                .expect("protected upstream body should contain a reference")
                .reference
                .display();
            let escaped_reference = reference.replace('[', r"\\[").replace(']', r"\\]");
            let response = format!(r#"{{"type":"delta","text":"{escaped_reference}"}}"#);

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/x-ndjson")
                .body(Body::from(format!("{response}\n")))
                .unwrap()
        }

        spawn_app(
            Router::new()
                .route("/v1/chat/completions", post(ndjson_response))
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

    async fn spawn_capture_headers_and_body_upstream(
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
                .route("/v1/chat/completions", post(echo))
                .with_state((seen_headers, seen_body)),
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

    async fn spawn_capture_anthropic_sse_text_delta_upstream(
        seen_body: Arc<Mutex<Option<String>>>,
    ) -> String {
        async fn sse(State(seen_body): State<Arc<Mutex<Option<String>>>>, body: Bytes) -> Response {
            let body_text =
                String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
            *seen_body.lock().unwrap() = Some(body_text.clone());
            let start = body_text
                .find("[email:")
                .expect("protected upstream body should contain email reference");
            let end = start
                + body_text[start..]
                    .find(']')
                    .expect("email reference should be closed")
                + 1;
            let reference = &body_text[start..end];
            let split_at = reference.len() / 2;
            let first = &reference[..split_at];
            let second = &reference[split_at..];
            let first_event = format!(
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"text_delta\",\"text\":\"{first}\"}}}}\n\n"
            );
            let second_event = format!(
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"text_delta\",\"text\":\"{second}\"}}}}\n\n"
            );
            let chunks = stream::iter([
                Ok::<_, std::io::Error>(Bytes::from(first_event)),
                Ok(Bytes::from(second_event)),
                Ok(Bytes::from_static(
                    b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
                )),
            ]);

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(chunks))
                .unwrap()
        }

        spawn_app(
            Router::new()
                .route("/v1/messages", post(sse))
                .with_state(seen_body),
        )
        .await
    }

    async fn spawn_anthropic_sse_raw_domain_upstream(
        seen_body: Arc<Mutex<Option<String>>>,
    ) -> String {
        async fn sse(State(seen_body): State<Arc<Mutex<Option<String>>>>, body: Bytes) -> Response {
            let body_text =
                String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
            *seen_body.lock().unwrap() = Some(body_text);
            let chunks = stream::iter([
                Ok::<_, std::io::Error>(Bytes::from_static(
                    br#"event: content_block_delta
data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"splonk.io"}}

"#,
                )),
                Ok(Bytes::from_static(
                    b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
                )),
            ]);

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(chunks))
                .unwrap()
        }

        spawn_app(
            Router::new()
                .route("/v1/messages", post(sse))
                .with_state(seen_body),
        )
        .await
    }

    async fn spawn_capture_sse_upstream(seen_body: Arc<Mutex<Option<String>>>) -> String {
        async fn sse(State(seen_body): State<Arc<Mutex<Option<String>>>>, body: Bytes) -> Response {
            let body_text =
                String::from_utf8(body.to_vec()).expect("upstream body should be utf-8");
            *seen_body.lock().unwrap() = Some(body_text.clone());
            let event = format!("event: response.output_text.delta\ndata: {body_text}\n\n");
            let split_at = event
                .find("[email:")
                .map(|index| index + "[email:".len() + 8)
                .unwrap_or(event.len());
            let chunks = stream::iter([
                Ok::<_, std::io::Error>(Bytes::from(event[..split_at].to_string())),
                Ok(Bytes::from(event[split_at..].to_string())),
            ]);

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(chunks))
                .unwrap()
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

    fn transparent_config(state_dir: PathBuf) -> TransparentInterceptionConfig {
        TransparentInterceptionConfig {
            state_dir,
            network_mode: dam_net::CaptureMode::SystemProxy,
            system_proxy_active: true,
            tun_active: false,
            ai_routes: dam_net::known_ai_routes(),
            trust: dam_trust::TrustState::default(),
            user_consented: true,
            protection_control_path: None,
        }
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
    async fn transparent_connect_passes_unknown_hosts_through_without_inspection() {
        let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let seen_for_origin = seen.clone();
        tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut buffer = [0_u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buffer)
                .await
                .unwrap();
            *seen_for_origin.lock().unwrap() = buffer.to_vec();
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong")
                .await
                .unwrap();
        });

        let upstream = spawn_capture_echo_upstream(Arc::new(Mutex::new(None::<String>))).await;
        let config = proxy_config(upstream);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            serve_transparent_with_shutdown(
                listener,
                config,
                transparent_config(tempfile::tempdir().unwrap().keep()),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                origin_addr, origin_addr
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let connect_response = read_until_headers(&mut stream).await;
        assert!(String::from_utf8_lossy(&connect_response).starts_with("HTTP/1.1 200"));

        tokio::io::AsyncWriteExt::write_all(&mut stream, b"ping")
            .await
            .unwrap();
        let mut response = [0_u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut response)
            .await
            .unwrap();

        assert_eq!(&response, b"pong");
        assert_eq!(&*seen.lock().unwrap(), b"ping");
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn paused_ai_connect_tunnel_closes_when_protection_resumes() {
        let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let seen_for_origin = seen.clone();
        tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut buffer = [0_u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buffer)
                .await
                .unwrap();
            *seen_for_origin.lock().unwrap() = buffer.to_vec();
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong")
                .await
                .unwrap();
            let mut keepalive = [0_u8; 1];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut keepalive).await;
        });

        let upstream = spawn_capture_echo_upstream(Arc::new(Mutex::new(None::<String>))).await;
        let mut config = proxy_config(upstream);
        config.proxy.targets[0].name = "test-openai".to_string();
        let log_path = config.log.sqlite_path.clone();
        let dir = tempfile::tempdir().unwrap();
        let control_path = dir.path().join("protection-control");
        fs::write(&control_path, "disabled\n").unwrap();
        let mut interception = transparent_config(dir.path().to_path_buf());
        interception.protection_control_path = Some(control_path.clone());
        interception.ai_routes = vec![dam_net::AiRoute::custom(
            "127.0.0.1",
            dam_net::OPENAI_COMPATIBLE_PROVIDER,
            "test-openai",
            "https://127.0.0.1",
        )];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            serve_transparent_with_shutdown(listener, config, interception, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                origin_addr, origin_addr
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let connect_response = read_until_headers(&mut stream).await;
        assert!(String::from_utf8_lossy(&connect_response).starts_with("HTTP/1.1 200"));

        tokio::io::AsyncWriteExt::write_all(&mut stream, b"ping")
            .await
            .unwrap();
        let mut response = [0_u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut response)
            .await
            .unwrap();
        assert_eq!(&response, b"pong");

        fs::write(&control_path, "enabled\n").unwrap();
        let mut one_byte = [0_u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut one_byte)).await;
        match closed {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(count)) => panic!("expected paused AI tunnel to close, read {count} bytes"),
            Err(_) => panic!("paused AI tunnel stayed open after protection resumed"),
        }

        assert_eq!(&*seen.lock().unwrap(), b"ping");
        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| {
            entry.event_type == "proxy_bypass"
                && entry.message.contains(&format!("target={origin_addr}"))
                && entry.message.contains("reason=protection_paused")
        }));
        assert!(logs.iter().any(|entry| {
            entry.event_type == "proxy_bypass"
                && entry.message.contains("closed because protection resumed")
        }));
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn transparent_plain_http_passes_unknown_hosts_through_without_redaction() {
        let seen = Arc::new(Mutex::new(None::<String>));
        let origin = spawn_capture_echo_upstream(seen.clone()).await;
        let origin_addr = origin.strip_prefix("http://").unwrap().to_string();
        let config = proxy_config(origin.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            serve_transparent_with_shutdown(
                listener,
                config,
                transparent_config(tempfile::tempdir().unwrap().keep()),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
            .unwrap();
        });

        let body = r#"{"input":"alice@example.com"}"#;
        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            format!(
                "POST http://{origin_addr}/v1/chat/completions HTTP/1.1\r\nHost: {origin_addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .as_bytes(),
        )
        .await
        .unwrap();

        let mut response = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut response)
            .await
            .unwrap();

        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("alice@example.com"));
        assert_eq!(seen.lock().unwrap().as_deref(), Some(body));
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn paused_protection_bypasses_explicit_provider_requests() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(upstream_seen.clone()).await;
        let config = proxy_config(upstream);
        let dir = tempfile::tempdir().unwrap();
        let control_path = dir.path().join("protection.state");
        std::fs::write(&control_path, "disabled\n").unwrap();
        let mut interception = transparent_config(dir.path().to_path_buf());
        interception.protection_control_path = Some(control_path);
        let proxy =
            spawn_app(build_app_with_interception(config, Some(interception)).unwrap()).await;

        let report = proxy_report(reqwest::get(format!("{proxy}/health")).await.unwrap()).await;
        assert_eq!(report.state, dam_api::ProxyState::Bypassing);

        let body = r#"{"input":"alice@example.com"}"#;
        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .header(header::AUTHORIZATION, "Bearer local")
            .body(body)
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success());
        assert_eq!(upstream_seen.lock().unwrap().as_deref(), Some(body));
    }

    #[test]
    fn protection_control_reads_json_and_legacy_disabled_state() {
        let dir = tempfile::tempdir().unwrap();
        let control_path = dir.path().join("protection.state");

        std::fs::write(&control_path, "{\"enabled\": false}\n").unwrap();
        assert!(!protection_control_enabled(&control_path));

        std::fs::write(&control_path, "{\"enabled\": true}\n").unwrap();
        assert!(protection_control_enabled(&control_path));

        std::fs::write(&control_path, "disabled\n").unwrap();
        assert!(!protection_control_enabled(&control_path));
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
            protection_control_path: None,
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
        let ai_routes = vec![dam_net::AiRoute::custom(
            "api.enterprise-ai.example",
            dam_net::OPENAI_COMPATIBLE_PROVIDER,
            "enterprise-ai",
            "https://api.enterprise-ai.example",
        )];
        let interception = TransparentInterceptionConfig {
            state_dir: tempfile::tempdir().unwrap().keep(),
            network_mode: dam_net::CaptureMode::SystemProxy,
            system_proxy_active: true,
            tun_active: false,
            ai_routes,
            trust: dam_trust::TrustState::default(),
            user_consented: true,
            protection_control_path: None,
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
            protection_control_path: None,
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
    async fn transparent_chatgpt_backend_http_requests_use_ai_route_target() {
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::{
            ClientConfig, RootCertStore,
            pki_types::{CertificateDer, ServerName},
        };

        let fallback_seen = Arc::new(Mutex::new(None::<String>));
        let fallback_upstream = spawn_capture_echo_upstream(fallback_seen.clone()).await;
        let chatgpt_seen = Arc::new(Mutex::new(None::<String>));
        let chatgpt_upstream = spawn_capture_codex_compact_upstream(chatgpt_seen.clone()).await;

        let mut config = proxy_config_with_provider(fallback_upstream, dam_net::ANTHROPIC_PROVIDER);
        config.proxy.targets[0].name = "anthropic".to_string();
        config.proxy.targets.push(dam_config::ProxyTargetConfig {
            name: "chatgpt-codex".to_string(),
            provider: dam_net::OPENAI_COMPATIBLE_PROVIDER.to_string(),
            upstream: chatgpt_upstream,
            failure_mode: None,
            api_key_env: None,
            api_key: None,
        });
        let log_path = config.log.sqlite_path.clone();

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
            protection_control_path: None,
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
            b"CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n",
        )
        .await
        .unwrap();
        let connect_response = read_until_headers(&mut stream).await;
        assert!(String::from_utf8_lossy(&connect_response).starts_with("HTTP/1.1 200"));

        let mut roots = RootCertStore::empty();
        let ca_der = dam_trust::issue_local_ca_leaf_certificate(dir.path(), "chatgpt.com")
            .unwrap()
            .ca_certificate_der;
        roots.add(CertificateDer::from(ca_der)).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from("chatgpt.com".to_string()).unwrap();
        let mut tls = connector.connect(server_name, stream).await.unwrap();

        let body = r#"{"input":"email codex@example.com"}"#;
        let request = format!(
            "POST /backend-api/codex/responses/compact HTTP/1.1\r\nHost: chatgpt.com\r\nCookie: test=session\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        tokio::io::AsyncWriteExt::write_all(&mut tls, request.as_bytes())
            .await
            .unwrap();
        let response = read_intercepted_test_response(&mut tls).await;

        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(!response.contains("codex@example.com"));
        assert!(response.contains("[email:"));
        assert!(fallback_seen.lock().unwrap().is_none());
        let upstream_body = chatgpt_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("codex@example.com"));
        assert!(upstream_body.contains("[email:"));
        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| {
            entry.action.as_deref() == Some("route_decision")
                && entry.message.contains("target=chatgpt-codex")
        }));
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn transparent_plain_http_resolves_event_stream_responses() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_sse_upstream(upstream_seen.clone()).await;
        let config = proxy_config(upstream);
        let log_path = config.log.sqlite_path.clone();
        let interception = TransparentInterceptionConfig {
            state_dir: tempfile::tempdir().unwrap().keep(),
            network_mode: dam_net::CaptureMode::SystemProxy,
            system_proxy_active: true,
            tun_active: false,
            ai_routes: dam_net::known_ai_routes(),
            trust: dam_trust::TrustState::default(),
            user_consented: true,
            protection_control_path: None,
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
        assert!(response.contains("erin@example.com"));
        assert!(!response.contains("[email:"));
        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("erin@example.com"));
        assert!(upstream_body.contains("[email:"));
        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        for action in [
            "route_decision",
            "request_protection",
            "provider_forward_start",
            "provider_response",
            "intercepted_response_write",
            "resolve_attempt",
        ] {
            assert!(
                logs.iter()
                    .any(|entry| entry.action.as_deref() == Some(action)),
                "missing proxy diagnostic action {action}"
            );
        }
        assert!(
            logs.iter().all(|entry| {
                !entry.message.contains("erin@example.com")
                    && !entry
                        .reference
                        .as_deref()
                        .unwrap_or_default()
                        .contains("erin@example.com")
            }),
            "logs must not contain raw sensitive values"
        );
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
    async fn active_consent_expands_allowed_references_from_outbound_history() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_echo_upstream(upstream_seen.clone()).await;
        let config = proxy_config(upstream);
        let vault_path = config.vault.sqlite_path.clone();
        let consent_path = config.consent.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(r#"{"input":"email history@example.com"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let first_upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        let reference = dam_core::find_references(&first_upstream_body)
            .into_iter()
            .next()
            .expect("first request should be tokenized")
            .reference;

        let vault = dam_vault::Vault::open(&vault_path).unwrap();
        dam_consent::ConsentStore::open(&consent_path)
            .unwrap()
            .grant_for_reference(&reference.key(), &vault, 60, "test", None)
            .unwrap();
        let history = format!(r#"{{"input":"repeat {}"}}"#, reference.display());

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(history)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let second_upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(second_upstream_body.contains("history@example.com"));
        assert!(!second_upstream_body.contains(&reference.display()));
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
    async fn anthropic_provider_resolves_references_split_across_text_delta_events() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_capture_anthropic_sse_text_delta_upstream(upstream_seen.clone()).await;
        let config = anthropic_proxy_config(upstream);
        let vault_path = config.vault.sqlite_path.clone();
        let log_path = config.log.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/messages"))
            .header("x-api-key", "caller-secret")
            .body(r#"{"messages":[{"content":"email banana@example.test"}],"stream":true}"#)
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
        assert!(body.contains("banana@example.test"));
        assert!(!body.contains("[email:"));

        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("banana@example.test"));
        assert!(upstream_body.contains("[email:"));
        assert_eq!(
            dam_vault::Vault::open(vault_path).unwrap().count().unwrap(),
            1
        );

        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| entry.event_type == "vault_read"));
        assert!(logs.iter().any(|entry| entry.event_type == "resolve"));
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
    async fn protected_body_strips_body_integrity_headers() {
        let seen_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let seen_body = Arc::new(Mutex::new(None::<String>));
        let upstream =
            spawn_capture_headers_and_body_upstream(seen_headers.clone(), seen_body.clone()).await;
        let proxy = spawn_app(build_app(proxy_config(upstream)).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .header("content-digest", "sha-256=:original:")
            .header("digest", "sha-256=original")
            .header("content-md5", "original")
            .header("signature", "sig1=:original:")
            .header("signature-input", "sig1=(\"content-digest\")")
            .header("x-keep-me", "ok")
            .body(r#"{"messages":[{"content":"email alice@example.com"}]}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let upstream_body = seen_body.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("alice@example.com"));
        assert!(upstream_body.contains("[email:"));

        let headers = seen_headers.lock().unwrap();
        assert!(
            headers
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("x-keep-me") && value == "ok")
        );
        for stripped in [
            "content-digest",
            "digest",
            "content-md5",
            "signature",
            "signature-input",
        ] {
            assert!(
                !headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case(stripped)),
                "{stripped} should be stripped after body mutation"
            );
        }
    }

    #[tokio::test]
    async fn unchanged_body_keeps_body_integrity_headers() {
        let seen_headers = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let seen_body = Arc::new(Mutex::new(None::<String>));
        let upstream =
            spawn_capture_headers_and_body_upstream(seen_headers.clone(), seen_body.clone()).await;
        let proxy = spawn_app(build_app(proxy_config(upstream)).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .header("content-digest", "sha-256=:original:")
            .header("x-keep-me", "ok")
            .body(r#"{"messages":[{"content":"hello"}]}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            seen_body.lock().unwrap().as_deref(),
            Some(r#"{"messages":[{"content":"hello"}]}"#)
        );

        let headers = seen_headers.lock().unwrap();
        assert!(
            headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("content-digest") && value == "sha-256=:original:"
            }),
            "content-digest should stay when the body is not changed"
        );
        assert!(
            headers
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("x-keep-me") && value == "ok")
        );
    }

    #[tokio::test]
    async fn resolves_inbound_response_references_by_default() {
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
        assert!(body.contains("alice@example.com"));
        assert!(!body.contains("[email:"));

        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("alice@example.com"));
        assert!(upstream_body.contains("[email:"));
        assert_eq!(
            dam_vault::Vault::open(vault_path).unwrap().count().unwrap(),
            1
        );

        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| entry.event_type == "vault_read"));
        assert!(logs.iter().any(|entry| entry.event_type == "resolve"));
    }

    #[tokio::test]
    async fn resolves_json_escaped_inbound_response_references_by_default() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_json_escaped_reference_upstream(upstream_seen.clone()).await;
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

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let body = response.text().await.unwrap();
        assert!(body.contains("alice@example.com"));
        assert!(!body.contains("[email:"));
        assert!(!body.contains(r"\\[email:"));

        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("alice@example.com"));
        assert!(upstream_body.contains("[email:"));
        assert_eq!(
            dam_vault::Vault::open(vault_path).unwrap().count().unwrap(),
            1
        );

        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| entry.event_type == "vault_read"));
        assert!(logs.iter().any(|entry| entry.event_type == "resolve"));
    }

    #[tokio::test]
    async fn resolves_ndjson_escaped_inbound_response_references_by_default() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_ndjson_escaped_reference_upstream(upstream_seen.clone()).await;
        let config = proxy_config(upstream);
        let log_path = config.log.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(r#"{"messages":[{"content":"email alice@example.com"}]}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/x-ndjson")
        );
        let body = response.text().await.unwrap();
        assert!(body.contains("alice@example.com"));
        assert!(!body.contains("[email:"));
        assert!(!body.contains(r"\\[email:"));

        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| entry.event_type == "vault_read"));
        assert!(logs.iter().any(|entry| entry.event_type == "resolve"));
    }

    #[tokio::test]
    async fn passes_raw_sensitive_inbound_response_without_explicit_inbound_protection() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_raw_sensitive_response_upstream(upstream_seen.clone()).await;
        let config = proxy_config(upstream);
        let log_path = config.log.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(r#"{"messages":[{"content":"hello"}]}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.unwrap();
        assert!(body.contains("leak@example.com"));
        assert!(!body.contains("[email:"));

        assert_eq!(
            upstream_seen.lock().unwrap().as_deref(),
            Some(r#"{"messages":[{"content":"hello"}]}"#)
        );

        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(!logs.iter().any(|entry| {
            entry.event_type == "proxy_forward"
                && entry.action.as_deref() == Some("inbound_protection")
        }));
    }

    #[tokio::test]
    async fn tokenizes_raw_sensitive_inbound_response_when_route_opts_in() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_raw_sensitive_response_upstream(upstream_seen.clone()).await;
        let mut config = proxy_config(upstream);
        set_test_target_inbound_policy(&mut config, true, true);
        let log_path = config.log.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(r#"{"messages":[{"content":"hello"}]}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.unwrap();
        assert!(!body.contains("leak@example.com"));
        assert!(body.contains("[email:"));

        assert_eq!(
            upstream_seen.lock().unwrap().as_deref(),
            Some(r#"{"messages":[{"content":"hello"}]}"#)
        );

        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| {
            entry.event_type == "proxy_forward"
                && entry.action.as_deref() == Some("inbound_protection")
        }));
        assert!(logs.iter().any(|entry| {
            entry.event_type == "redaction" && entry.action.as_deref() == Some("tokenized")
        }));
    }

    #[tokio::test]
    async fn tokenizes_raw_email_domain_in_inbound_response_from_request_context() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_raw_domain_response_upstream(upstream_seen.clone()).await;
        let mut config = proxy_config(upstream);
        set_test_target_inbound_policy(&mut config, true, true);
        let log_path = config.log.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/chat/completions"))
            .body(r#"{"messages":[{"content":"email person@leak.example"}]}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.unwrap();
        assert!(!body.contains("leak.example"));
        assert!(body.contains("[domain:"));

        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("person@leak.example"));
        assert!(upstream_body.contains("[email:"));

        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| {
            entry.event_type == "proxy_forward"
                && entry.action.as_deref() == Some("inbound_protection")
        }));
        assert!(logs.iter().any(|entry| {
            entry.kind.as_deref() == Some("domain")
                && entry.event_type == "redaction"
                && entry.action.as_deref() == Some("tokenized")
        }));
    }

    #[tokio::test]
    async fn tokenizes_raw_email_domain_in_anthropic_stream_from_request_context() {
        let upstream_seen = Arc::new(Mutex::new(None::<String>));
        let upstream = spawn_anthropic_sse_raw_domain_upstream(upstream_seen.clone()).await;
        let mut config = anthropic_proxy_config(upstream);
        config.proxy.targets[0].name = "anthropic".to_string();
        let log_path = config.log.sqlite_path.clone();
        let proxy = spawn_app(build_app(config).unwrap()).await;

        let response = reqwest::Client::new()
            .post(format!("{proxy}/v1/messages"))
            .body(r#"{"messages":[{"content":"email banana@splonk.io"}],"stream":true}"#)
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
        assert!(!body.contains("splonk.io"));
        assert!(body.contains("[domain:"));

        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("banana@splonk.io"));
        assert!(upstream_body.contains("[email:"));

        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| {
            entry.event_type == "proxy_forward"
                && entry.action.as_deref() == Some("resolve_disabled")
        }));
        assert!(logs.iter().any(|entry| {
            entry.event_type == "proxy_forward"
                && entry.action.as_deref() == Some("inbound_protection")
        }));
        assert!(logs.iter().any(|entry| {
            entry.kind.as_deref() == Some("domain")
                && entry.event_type == "redaction"
                && entry.action.as_deref() == Some("tokenized")
        }));
    }

    #[tokio::test]
    async fn resolves_event_stream_response_references_by_default() {
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
        assert!(body.contains("erin@example.com"));
        assert!(!body.contains("[email:"));

        let upstream_body = upstream_seen.lock().unwrap().clone().unwrap();
        assert!(!upstream_body.contains("erin@example.com"));
        assert!(upstream_body.contains("[email:"));
        assert_eq!(
            dam_vault::Vault::open(vault_path).unwrap().count().unwrap(),
            1
        );

        let logs = dam_log::LogStore::open(log_path).unwrap().list().unwrap();
        assert!(logs.iter().any(|entry| entry.event_type == "vault_read"));
        assert!(logs.iter().any(|entry| entry.event_type == "resolve"));
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
