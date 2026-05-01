use axum::Router;
use axum::body::Bytes;
use axum::extract::Request;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use dam_log::{LogEntry, LogStore};
use dam_vault::{Vault, VaultEntry};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command as TokioCommand;

const RPBLC_HOME_URL: &str = "https://rpblc.com";
const RPBLC_FAVICON_SVG: &str = include_str!("../assets/favicon.svg");
const DAM_BIN_ENV: &str = "DAM_BIN";
const DAM_WEB_SHELL_ENV: &str = "DAM_WEB_SHELL";
const DAM_WEB_SHELL_TRAY: &str = "tray";
const DAM_WEB_TRAY_POST_TOKEN_ENV: &str = "DAM_WEB_TRAY_POST_TOKEN";
const DAM_TRAY_OPEN_RPBLC_MESSAGE: &str = "dam-tray:open-rpblc";
const DAM_TRAY_CONNECT_MESSAGE: &str = "dam-tray:connect";
const DAM_TRAY_QUIT_MESSAGE: &str = "dam-tray:quit";
const CONNECT_SYSTEM_CONFIRM_FIELD: &str = "confirm_system_changes";

#[derive(Clone)]
struct AppState {
    vault: Arc<Vault>,
    consent_store: Option<Arc<dam_consent::ConsentStore>>,
    logs: Arc<LogStore>,
    config: Arc<dam_config::DamConfig>,
    config_path: Option<PathBuf>,
    client: reqwest::Client,
    db_path: Arc<PathBuf>,
    log_path: Arc<PathBuf>,
}

#[derive(Debug, Clone)]
struct CliArgs {
    config: dam_config::ConfigOverrides,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortDirection {
    Asc,
    Desc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VaultSortField {
    Key,
    Value,
    Created,
    Updated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VaultOrder {
    field: VaultSortField,
    direction: SortDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogSortField {
    Id,
    Time,
    Level,
    Type,
    Operation,
    Kind,
    Reference,
    Action,
    Message,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogOrder {
    field: LogSortField,
    direction: SortDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DashboardState {
    Protected,
    Disconnected,
    Degraded,
    NeedsSetup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellMode {
    Browser,
    Tray,
}

impl ShellMode {
    fn from_env() -> Self {
        match env::var(DAM_WEB_SHELL_ENV) {
            Ok(value) if value == DAM_WEB_SHELL_TRAY => Self::Tray,
            _ => Self::Browser,
        }
    }

    fn is_tray(self) -> bool {
        self == Self::Tray
    }
}

#[derive(Debug, Clone)]
struct ConnectDashboard {
    state: DashboardState,
    message: String,
    proxy_url: String,
    daemon: Option<dam_daemon::DaemonState>,
    proxy: Option<dam_api::ProxyReport>,
    setup_plan: Option<dam_diagnostics::SetupPlan>,
    setup_plan_error: Option<String>,
    active_profile_error: Option<String>,
    enabled_profiles: Vec<dam_integrations::EnabledIntegrationState>,
    enabled_profiles_error: Option<String>,
    active_profile_apply: Option<dam_integrations::IntegrationApplyInspection>,
    profiles: Vec<ProfileCard>,
    notice: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct ProfileCard {
    profile: dam_integrations::IntegrationProfile,
    apply: Option<dam_integrations::IntegrationApplyInspection>,
    inspection_error: Option<String>,
    active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectSetupAction<'a> {
    Ready,
    ApplyProfile,
    RunSetupCommand(&'a dam_diagnostics::SetupStep),
    RunDaemon,
    Blocked(&'a dam_diagnostics::SetupStep),
}

#[tokio::main]
async fn main() {
    let cli = match parse_args(env::args().skip(1)) {
        Ok(cli) => cli,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("{}", usage());
            std::process::exit(2);
        }
    };

    let config = match dam_config::load(&cli.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("failed to load config: {error}");
            std::process::exit(2);
        }
    };

    let db_path = match vault_db_path(&config) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    let log_path = match log_db_path(&config) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    let addr = match parse_addr(&config.web.addr) {
        Ok(addr) => addr,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    let vault = match Vault::open(db_path) {
        Ok(vault) => Arc::new(vault),
        Err(error) => {
            eprintln!("failed to open vault db {}: {error}", db_path.display());
            std::process::exit(1);
        }
    };

    let logs = match LogStore::open(log_path) {
        Ok(logs) => Arc::new(logs),
        Err(error) => {
            eprintln!("failed to open log db {}: {error}", log_path.display());
            std::process::exit(1);
        }
    };

    let consent_store = match open_consent_store(&config) {
        Ok(store) => store.map(Arc::new),
        Err(error) => {
            eprintln!("failed to open consent db: {error}");
            std::process::exit(1);
        }
    };

    let state = AppState {
        vault,
        consent_store,
        logs,
        config: Arc::new(config.clone()),
        config_path: cli.config.config_path.clone(),
        client: http_client(),
        db_path: Arc::new(db_path.to_path_buf()),
        log_path: Arc::new(log_path.to_path_buf()),
    };

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("failed to bind {addr}: {error}");
            std::process::exit(1);
        }
    };

    println!("DAM web listening on http://{addr}");
    println!("vault database: {}", db_path.display());
    println!("log database: {}", log_path.display());

    if let Err(error) = axum::serve(listener, router(state)).await {
        eprintln!("server error: {error}");
        std::process::exit(1);
    }
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/connect", get(connect_dashboard))
        .route("/connect/action", post(connect_action))
        .route("/settings", get(settings_dashboard))
        .route("/settings/integrations", post(settings_action))
        .route("/", get(home))
        .route("/vault", get(vault))
        .route("/vault/detail/:key", get(vault_detail))
        .route("/logs", get(logs))
        .route("/allowed", get(consents))
        .route("/consents", get(consents))
        .route("/allowed/grant", post(grant_consent))
        .route("/allowed/revoke", post(revoke_consent))
        .route("/consents/grant", post(grant_consent))
        .route("/consents/revoke", post(revoke_consent))
        .route("/doctor", get(doctor))
        .route("/diagnostics", get(diagnostics))
        .route("/favicon.svg", get(favicon))
        .route("/health", get(|| async { "ok" }))
        .route_layer(middleware::from_fn(require_local_browser_context))
        .with_state(state)
}

async fn require_local_browser_context(request: Request, next: Next) -> Response {
    if !host_header_is_local(request.headers()) {
        return (StatusCode::FORBIDDEN, "invalid Host header").into_response();
    }

    if request.method() == Method::POST && !post_context_is_local(request.headers(), request.uri())
    {
        return (StatusCode::FORBIDDEN, "invalid request origin").into_response();
    }

    next.run(request).await
}

fn host_header_is_local(headers: &HeaderMap) -> bool {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_local_host_value)
}

fn post_origin_is_local(headers: &HeaderMap) -> bool {
    headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|value| value.to_str().ok())
        .and_then(origin_host)
        .is_some_and(is_loopback_host)
}

fn post_context_is_local(headers: &HeaderMap, uri: &axum::http::Uri) -> bool {
    post_origin_is_local(headers)
        || tray_post_token_is_valid(
            uri.query(),
            env::var(DAM_WEB_TRAY_POST_TOKEN_ENV).ok().as_deref(),
        )
}

fn tray_post_token_is_valid(query: Option<&str>, expected: Option<&str>) -> bool {
    let Some(expected) = expected.filter(|value| !value.is_empty()) else {
        return false;
    };
    query
        .into_iter()
        .flat_map(|query| query.split('&'))
        .filter_map(|pair| pair.split_once('='))
        .any(|(name, value)| name == "tray_token" && value == expected)
}

fn origin_host(value: &str) -> Option<&str> {
    let after_scheme = value.split_once("://")?.1;
    Some(
        after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(after_scheme),
    )
}

fn is_local_host_value(value: &str) -> bool {
    is_loopback_host(value)
}

fn is_loopback_host(value: &str) -> bool {
    let host = strip_host_port(value.trim()).to_ascii_lowercase();
    matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn strip_host_port(value: &str) -> &str {
    if value.starts_with('[') {
        return value
            .find(']')
            .map(|index| &value[..=index])
            .unwrap_or(value);
    }
    value.split_once(':').map(|(host, _)| host).unwrap_or(value)
}

async fn home() -> Response {
    match dam_daemon::daemon_status() {
        Ok(dam_daemon::DaemonStatus::Connected(_)) => Redirect::to("/vault").into_response(),
        _ => Redirect::to("/connect").into_response(),
    }
}

async fn vault(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let order = VaultOrder::from_params(&params);
    match state.vault.list() {
        Ok(mut entries) => {
            sort_vault_entries(&mut entries, order);
            let consents = list_consents(&state);
            Html(render_vault_with_order(
                &state.db_path,
                &entries,
                order,
                &consents,
            ))
            .into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(render_error("Vault error", &error.to_string())),
        )
            .into_response(),
    }
}

async fn vault_detail(State(state): State<AppState>, AxumPath(key): AxumPath<String>) -> Response {
    match state.vault.list() {
        Ok(entries) => {
            let consents = list_consents(&state);
            match entries.iter().find(|entry| entry.key == key) {
                Some(entry) => {
                    let logs = state.logs.list().unwrap_or_default();
                    Html(render_vault_detail(
                        entry,
                        active_consent_for_vault_entry(&consents, entry),
                        &logs,
                    ))
                    .into_response()
                }
                None => (
                    StatusCode::NOT_FOUND,
                    Html(render_error("Vault value not found", &key)),
                )
                    .into_response(),
            }
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(render_error("Vault error", &error.to_string())),
        )
            .into_response(),
    }
}

async fn connect_dashboard(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let notice = params.get("notice").cloned();
    let error = params.get("error").cloned();
    Html(render_connect_dashboard(
        &build_connect_dashboard(&state, notice, error).await,
    ))
    .into_response()
}

async fn connect_action(State(state): State<AppState>, body: Bytes) -> Response {
    let form = parse_form(&body);
    let action = form.get("action").map(String::as_str).unwrap_or("");
    let result = match action {
        "select_profile" => {
            let Some(profile_id) = form.get("profile_id") else {
                return (StatusCode::BAD_REQUEST, "profile_id is required").into_response();
            };
            set_active_profile(profile_id).map(|_| "profile selected".to_string())
        }
        "enable_profile" => {
            let Some(profile_id) = form.get("profile_id") else {
                return (StatusCode::BAD_REQUEST, "profile_id is required").into_response();
            };
            set_profile_enabled(profile_id, true).map(|_| "profile enabled".to_string())
        }
        "disable_profile" => {
            let Some(profile_id) = form.get("profile_id") else {
                return (StatusCode::BAD_REQUEST, "profile_id is required").into_response();
            };
            set_profile_enabled(profile_id, false).map(|_| "profile disabled".to_string())
        }
        "clear_profile" => clear_active_profile().map(|_| "profile cleared".to_string()),
        "apply_profile" => apply_enabled_profiles(&state).map(|_| "setup applied".to_string()),
        "rollback_profile" => rollback_enabled_profiles().map(|_| "setup rolled back".to_string()),
        "connect" => advance_connect_setup(
            &state,
            form.get(CONNECT_SYSTEM_CONFIRM_FIELD).map(String::as_str) == Some("yes"),
        )
        .await
        .map(|_| "DAM connected".to_string()),
        "disconnect" => disconnect_protection(&state)
            .await
            .map(|_| "DAM disconnected".to_string()),
        _ => Err(format!("unknown connect action: {action}")),
    };

    match result {
        Ok(message) => Redirect::to(&format!(
            "/connect?notice={}",
            form_url_encode_component(&message)
        ))
        .into_response(),
        Err(error) => {
            let dashboard = build_connect_dashboard(&state, None, Some(error)).await;
            (
                StatusCode::BAD_REQUEST,
                Html(render_connect_dashboard(&dashboard)),
            )
                .into_response()
        }
    }
}

async fn settings_dashboard(Query(params): Query<HashMap<String, String>>) -> Response {
    let notice = params.get("notice").cloned();
    let error = params.get("error").cloned();
    Html(render_settings_dashboard(notice, error)).into_response()
}

async fn settings_action(body: Bytes) -> Response {
    let form = parse_form(&body);
    let action = form.get("action").map(String::as_str).unwrap_or("");
    let result = match action {
        "enable_profile" => {
            let Some(profile_id) = form.get("profile_id") else {
                return (StatusCode::BAD_REQUEST, "profile_id is required").into_response();
            };
            set_profile_enabled(profile_id, true).map(|_| "profile enabled".to_string())
        }
        "disable_profile" => {
            let Some(profile_id) = form.get("profile_id") else {
                return (StatusCode::BAD_REQUEST, "profile_id is required").into_response();
            };
            set_profile_enabled(profile_id, false).map(|_| "profile disabled".to_string())
        }
        _ => Err(format!("unknown settings action: {action}")),
    };

    match result {
        Ok(message) => Redirect::to(&format!(
            "/settings?notice={}",
            form_url_encode_component(&message)
        ))
        .into_response(),
        Err(error) => Redirect::to(&format!(
            "/settings?error={}",
            form_url_encode_component(&error)
        ))
        .into_response(),
    }
}

async fn consents(State(state): State<AppState>) -> Response {
    match &state.consent_store {
        Some(store) => match store.list() {
            Ok(entries) => Html(render_consents(&entries)).into_response(),
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(render_error("Consent error", &error.to_string())),
            )
                .into_response(),
        },
        None => Html(render_consents_disabled()).into_response(),
    }
}

async fn grant_consent(State(state): State<AppState>, body: Bytes) -> Response {
    let Some(store) = &state.consent_store else {
        return (StatusCode::BAD_REQUEST, "consent is disabled").into_response();
    };
    let form = parse_form(&body);
    let Some(vault_key) = form.get("vault_key") else {
        return (StatusCode::BAD_REQUEST, "vault_key is required").into_response();
    };
    let ttl_seconds = form
        .get("ttl_seconds")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(state.config.consent.default_ttl_seconds);
    let reason = form
        .get("reason")
        .filter(|value| !value.is_empty())
        .cloned();

    match store.grant_for_reference(
        vault_key,
        state.vault.as_ref(),
        ttl_seconds,
        "dam-web",
        reason,
    ) {
        Ok(_) => Redirect::to("/vault").into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Html(render_error("Consent grant failed", &error.to_string())),
        )
            .into_response(),
    }
}

async fn revoke_consent(State(state): State<AppState>, body: Bytes) -> Response {
    let Some(store) = &state.consent_store else {
        return (StatusCode::BAD_REQUEST, "consent is disabled").into_response();
    };
    let form = parse_form(&body);
    let Some(id) = form.get("id") else {
        return (StatusCode::BAD_REQUEST, "id is required").into_response();
    };

    match store.revoke(id) {
        Ok(_) => Redirect::to(revoke_return_to(&form)).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Html(render_error("Consent revoke failed", &error.to_string())),
        )
            .into_response(),
    }
}

async fn logs(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let order = LogOrder::from_params(&params);
    match state.logs.list() {
        Ok(mut entries) => {
            sort_log_entries(&mut entries, order);
            Html(render_logs_with_order(&state.log_path, &entries, order)).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(render_error("Log error", &error.to_string())),
        )
            .into_response(),
    }
}

async fn diagnostics(State(state): State<AppState>) -> Response {
    let config_report = build_config_report(&state.config);
    let proxy_report = proxy_report(&state.config, &state.client).await;
    Html(render_diagnostics(&config_report, &proxy_report)).into_response()
}

async fn doctor(State(state): State<AppState>) -> Response {
    let mut report =
        dam_diagnostics::doctor_report(&state.config, &dam_diagnostics::DoctorOptions::default())
            .await;
    redact_local_paths(&mut report, &state.config);
    Html(render_doctor(&report)).into_response()
}

async fn favicon() -> Response {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        RPBLC_FAVICON_SVG,
    )
        .into_response()
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<CliArgs, String> {
    let mut cli = CliArgs {
        config: dam_config::ConfigOverrides::default(),
    };

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--config requires a path".to_string())?;
                cli.config.config_path = Some(PathBuf::from(value));
            }
            "--db" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--db requires a path".to_string())?;
                cli.config.vault_sqlite_path = Some(PathBuf::from(value));
            }
            "--log" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--log requires a path".to_string())?;
                cli.config.log_sqlite_path = Some(PathBuf::from(value));
            }
            "--addr" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--addr requires an address".to_string())?;
                cli.config.web_addr = Some(value);
            }
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(cli)
}

fn vault_db_path(config: &dam_config::DamConfig) -> Result<&Path, String> {
    match config.vault.backend {
        dam_config::VaultBackend::Sqlite => Ok(&config.vault.sqlite_path),
        dam_config::VaultBackend::Remote => {
            Err("remote vault backend is configured but not implemented in dam-web yet".to_string())
        }
    }
}

fn log_db_path(config: &dam_config::DamConfig) -> Result<&Path, String> {
    match config.log.backend {
        dam_config::LogBackend::Sqlite => Ok(&config.log.sqlite_path),
        dam_config::LogBackend::None => Err(
            "log backend is disabled; dam-web requires a sqlite log database for /logs".to_string(),
        ),
        dam_config::LogBackend::Remote => {
            Err("remote log backend is configured but not implemented in dam-web yet".to_string())
        }
    }
}

fn open_consent_store(
    config: &dam_config::DamConfig,
) -> Result<Option<dam_consent::ConsentStore>, dam_consent::ConsentError> {
    if !config.consent.enabled {
        return Ok(None);
    }

    match config.consent.backend {
        dam_config::ConsentBackend::Sqlite => {
            dam_consent::ConsentStore::open(&config.consent.sqlite_path).map(Some)
        }
    }
}

fn parse_addr(value: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = value
        .parse()
        .map_err(|_| format!("invalid web address: {value}"))?;
    if !addr.ip().is_loopback() {
        return Err(format!("web address must be loopback: {value}"));
    }
    Ok(addr)
}

fn usage() -> &'static str {
    "Usage: dam-web [--config dam.toml] [--db vault.db] [--log log.db] [--addr 127.0.0.1:2896]"
}

impl Default for VaultOrder {
    fn default() -> Self {
        Self {
            field: VaultSortField::Updated,
            direction: SortDirection::Desc,
        }
    }
}

impl Default for LogOrder {
    fn default() -> Self {
        Self {
            field: LogSortField::Id,
            direction: SortDirection::Desc,
        }
    }
}

impl SortDirection {
    fn from_param(value: &str) -> Option<Self> {
        match value {
            "asc" => Some(Self::Asc),
            "desc" => Some(Self::Desc),
            _ => None,
        }
    }

    fn param(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Asc => "ascending",
            Self::Desc => "descending",
        }
    }

    fn apply(self, ordering: Ordering) -> Ordering {
        match self {
            Self::Asc => ordering,
            Self::Desc => ordering.reverse(),
        }
    }
}

impl VaultSortField {
    fn from_param(value: &str) -> Option<Self> {
        match value {
            "key" => Some(Self::Key),
            "value" => Some(Self::Value),
            "created" => Some(Self::Created),
            "updated" => Some(Self::Updated),
            _ => None,
        }
    }

    fn param(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Value => "value",
            Self::Created => "created",
            Self::Updated => "updated",
        }
    }
}

impl LogSortField {
    fn from_param(value: &str) -> Option<Self> {
        match value {
            "id" => Some(Self::Id),
            "time" => Some(Self::Time),
            "level" => Some(Self::Level),
            "type" => Some(Self::Type),
            "operation" => Some(Self::Operation),
            "kind" => Some(Self::Kind),
            "reference" => Some(Self::Reference),
            "action" => Some(Self::Action),
            "message" => Some(Self::Message),
            _ => None,
        }
    }

    fn param(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::Time => "time",
            Self::Level => "level",
            Self::Type => "type",
            Self::Operation => "operation",
            Self::Kind => "kind",
            Self::Reference => "reference",
            Self::Action => "action",
            Self::Message => "message",
        }
    }
}

impl VaultOrder {
    fn from_params(params: &HashMap<String, String>) -> Self {
        let Some(field) = params
            .get("sort")
            .and_then(|value| VaultSortField::from_param(value))
        else {
            return Self::default();
        };
        let direction = params
            .get("dir")
            .and_then(|value| SortDirection::from_param(value))
            .unwrap_or(SortDirection::Asc);
        Self { field, direction }
    }
}

impl LogOrder {
    fn from_params(params: &HashMap<String, String>) -> Self {
        let Some(field) = params
            .get("sort")
            .and_then(|value| LogSortField::from_param(value))
        else {
            return Self::default();
        };
        let direction = params
            .get("dir")
            .and_then(|value| SortDirection::from_param(value))
            .unwrap_or(SortDirection::Asc);
        Self { field, direction }
    }
}

fn sort_vault_entries(entries: &mut [VaultEntry], order: VaultOrder) {
    entries.sort_by(|left, right| {
        let ordering = match order.field {
            VaultSortField::Key => left.key.cmp(&right.key),
            VaultSortField::Value => left.value.cmp(&right.value),
            VaultSortField::Created => left.created_at.cmp(&right.created_at),
            VaultSortField::Updated => left.updated_at.cmp(&right.updated_at),
        };
        order
            .direction
            .apply(ordering.then_with(|| left.key.cmp(&right.key)))
    });
}

fn sort_log_entries(entries: &mut [LogEntry], order: LogOrder) {
    entries.sort_by(|left, right| {
        let ordering = match order.field {
            LogSortField::Id => left.id.cmp(&right.id),
            LogSortField::Time => left.timestamp.cmp(&right.timestamp),
            LogSortField::Level => left.level.cmp(&right.level),
            LogSortField::Type => left.event_type.cmp(&right.event_type),
            LogSortField::Operation => left.operation_id.cmp(&right.operation_id),
            LogSortField::Kind => optional_str(&left.kind).cmp(optional_str(&right.kind)),
            LogSortField::Reference => {
                optional_str(&left.reference).cmp(optional_str(&right.reference))
            }
            LogSortField::Action => optional_str(&left.action).cmp(optional_str(&right.action)),
            LogSortField::Message => left.message.cmp(&right.message),
        };
        order
            .direction
            .apply(ordering.then_with(|| left.id.cmp(&right.id)))
    });
}

fn optional_str(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("")
}

fn render_vault_sort_header(label: &str, field: VaultSortField, order: VaultOrder) -> String {
    render_sort_header(
        label,
        "/vault",
        field.param(),
        field == order.field,
        order.direction,
    )
}

fn render_log_sort_header(label: &str, field: LogSortField, order: LogOrder) -> String {
    render_sort_header(
        label,
        "/logs",
        field.param(),
        field == order.field,
        order.direction,
    )
}

fn render_sort_header(
    label: &str,
    path: &str,
    field: &str,
    active: bool,
    active_direction: SortDirection,
) -> String {
    format!(
        r#"<th><span class="sortable-heading"><span class="order-label">{label}</span><span class="order-buttons">{asc}{desc}</span></span></th>"#,
        label = escape_html(label),
        asc = render_order_button(
            path,
            field,
            label,
            SortDirection::Asc,
            active,
            active_direction
        ),
        desc = render_order_button(
            path,
            field,
            label,
            SortDirection::Desc,
            active,
            active_direction
        ),
    )
}

fn render_order_button(
    path: &str,
    field: &str,
    label: &str,
    direction: SortDirection,
    active: bool,
    active_direction: SortDirection,
) -> String {
    let is_active = active && direction == active_direction;
    let class = if is_active {
        "order-button active"
    } else {
        "order-button"
    };
    let symbol = match direction {
        SortDirection::Asc => "A-Z",
        SortDirection::Desc => "Z-A",
    };
    let aria_label = format!("Sort {label} {}", direction.label());
    format!(
        r#"<a class="{class}" href="{path}?sort={field}&amp;dir={dir}" aria-label="{aria_label}" title="{aria_label}">{symbol}</a>"#,
        class = class,
        path = escape_html(path),
        field = escape_html(field),
        dir = direction.param(),
        aria_label = escape_html(&aria_label),
        symbol = symbol,
    )
}

#[cfg(test)]
fn render_vault(db_path: &Path, entries: &[VaultEntry]) -> String {
    render_vault_with_order(db_path, entries, VaultOrder::default(), &[])
}

fn render_vault_with_order(
    db_path: &Path,
    entries: &[VaultEntry],
    order: VaultOrder,
    consents: &[dam_consent::ConsentEntry],
) -> String {
    let rows = if entries.is_empty() {
        "<tr><td class=\"empty\" colspan=\"4\">No protected values yet.</td></tr>".to_string()
    } else {
        entries
            .iter()
            .map(|entry| render_vault_row(entry, active_consent_for_vault_entry(consents, entry)))
            .collect::<Vec<_>>()
            .join("\n")
    };

    render_shell(
        "DAM Vault",
        "Vault",
        &format!("Vault: {}", escape_html(&db_path.display().to_string())),
        entries.len(),
        "values",
        &format!(
            r#"<table class="data-table vault-table">
      <thead>
        <tr>
          {value_header}
          <th>Kind</th>
          {updated_header}
          <th>Allowed</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>"#,
            value_header = render_vault_sort_header("Value", VaultSortField::Value, order),
            updated_header = render_vault_sort_header("Seen", VaultSortField::Updated, order),
        ),
    )
}

fn list_consents(state: &AppState) -> Vec<dam_consent::ConsentEntry> {
    state
        .consent_store
        .as_ref()
        .and_then(|store| store.list().ok())
        .unwrap_or_default()
}

fn active_consent_for_vault_entry<'a>(
    consents: &'a [dam_consent::ConsentEntry],
    vault_entry: &VaultEntry,
) -> Option<&'a dam_consent::ConsentEntry> {
    let now = unix_now_lossy();
    dam_core::Reference::parse_key(&vault_entry.key).and_then(|reference| {
        let value_fingerprint = dam_consent::fingerprint(reference.kind, &vault_entry.value);
        consents
            .iter()
            .filter(|entry| {
                entry.kind == reference.kind
                    && entry.value_fingerprint == value_fingerprint
                    && entry.is_active_at(now)
            })
            .max_by_key(|entry| entry.expires_at)
    })
}

fn revoke_return_to(form: &HashMap<String, String>) -> &'static str {
    match form.get("return_to").map(String::as_str) {
        Some("/vault") | Some("/") => "/vault",
        _ => "/allowed",
    }
}

async fn build_connect_dashboard(
    state: &AppState,
    notice: Option<String>,
    error: Option<String>,
) -> ConnectDashboard {
    let (_, active_profile_error) = read_active_profile_for_web();
    let (enabled_profiles, enabled_profiles_error) = read_enabled_profiles_for_web();
    let daemon_status = dam_daemon::daemon_status();
    let (daemon, mut proxy, daemon_error) = match daemon_status {
        Ok(dam_daemon::DaemonStatus::Connected(daemon)) => {
            let report = fetch_daemon_proxy_report(&state.client, &daemon.proxy_url).await;
            match report {
                Ok(report) => (Some(daemon), Some(report), None),
                Err(error) => (Some(daemon), None, Some(error)),
            }
        }
        Ok(dam_daemon::DaemonStatus::Stale(daemon)) => (
            Some(daemon),
            None,
            Some("daemon process is no longer running".to_string()),
        ),
        Ok(dam_daemon::DaemonStatus::Disconnected) => (None, None, None),
        Err(error) => (None, None, Some(error.to_string())),
    };

    if proxy.is_none() && daemon.is_none() && state.config.proxy.enabled {
        let report = proxy_report(&state.config, &state.client).await;
        if report.state != dam_api::ProxyState::DamDown {
            proxy = Some(report);
        }
    }

    let proxy_url = daemon
        .as_ref()
        .map(|daemon| daemon.proxy_url.clone())
        .unwrap_or_else(|| configured_proxy_url(&state.config));
    let profiles = profile_cards(&proxy_url, &enabled_profiles);
    let primary_enabled_profile = enabled_profiles.first();
    let active_profile_apply = primary_enabled_profile.and_then(|enabled| {
        profiles
            .iter()
            .find(|card| card.profile.id == enabled.profile_id)
            .and_then(|card| card.apply.clone())
    });
    let active_profile_inspection_error = primary_enabled_profile.and_then(|enabled| {
        profiles
            .iter()
            .find(|card| card.profile.id == enabled.profile_id)
            .and_then(|card| card.inspection_error.clone())
    });
    let (setup_plan, setup_plan_error) = connect_setup_plan(state)
        .map_or_else(|error| (None, Some(error)), |plan| (Some(plan), None));
    let state_tag = if active_profile_inspection_error.is_some()
        || enabled_profiles_error.is_some()
        || setup_plan_error.is_some()
    {
        DashboardState::Degraded
    } else {
        dashboard_state(daemon.as_ref(), proxy.as_ref(), setup_plan.as_ref())
    };
    let mut message = dashboard_message(state_tag).to_string();
    if let Some(error) = daemon_error
        .or(active_profile_error.clone())
        .or(enabled_profiles_error.clone())
        .or(active_profile_inspection_error)
        .or(setup_plan_error.clone())
    {
        message = error;
    }
    if matches!(state_tag, DashboardState::NeedsSetup)
        && let Some(step) = first_non_daemon_setup_step(
            setup_plan.as_ref(),
            dam_diagnostics::SetupStepStatus::Blocked,
        )
        .or_else(|| {
            first_non_daemon_setup_step(
                setup_plan.as_ref(),
                dam_diagnostics::SetupStepStatus::Needed,
            )
        })
    {
        message = step.message.clone();
    }

    ConnectDashboard {
        state: state_tag,
        message,
        proxy_url,
        daemon,
        proxy,
        setup_plan,
        setup_plan_error,
        active_profile_error,
        enabled_profiles,
        enabled_profiles_error,
        active_profile_apply,
        profiles,
        notice,
        error,
    }
}

fn profile_cards(
    proxy_url: &str,
    enabled_profiles: &[dam_integrations::EnabledIntegrationState],
) -> Vec<ProfileCard> {
    let state_dir = integration_state_dir();
    dam_integrations::profiles(proxy_url)
        .into_iter()
        .map(|profile| {
            let active = enabled_profiles
                .iter()
                .any(|enabled| enabled.profile_id == profile.id);
            let (apply, inspection_error) = match &state_dir {
                Ok(state_dir) => match default_integration_target_path(&profile.id, state_dir)
                    .and_then(|target_path| {
                        dam_integrations::inspect_apply(
                            &profile.id,
                            proxy_url,
                            target_path,
                            state_dir,
                        )
                    }) {
                    Ok(inspection) => (Some(inspection), None),
                    Err(error) => (None, Some(error)),
                },
                Err(error) => (None, Some(error.clone())),
            };
            ProfileCard {
                profile,
                apply,
                inspection_error,
                active,
            }
        })
        .collect()
}

fn dashboard_state(
    daemon: Option<&dam_daemon::DaemonState>,
    proxy: Option<&dam_api::ProxyReport>,
    setup_plan: Option<&dam_diagnostics::SetupPlan>,
) -> DashboardState {
    match (daemon, proxy) {
        (Some(_), Some(report)) if report.state == dam_api::ProxyState::Protected => {
            return DashboardState::Protected;
        }
        (Some(_), _) => return DashboardState::Degraded,
        (None, _) => {}
    }
    if first_non_daemon_setup_step(setup_plan, dam_diagnostics::SetupStepStatus::Blocked).is_some()
    {
        DashboardState::Degraded
    } else if first_non_daemon_setup_step(setup_plan, dam_diagnostics::SetupStepStatus::Needed)
        .is_some()
    {
        DashboardState::NeedsSetup
    } else {
        DashboardState::Disconnected
    }
}

fn dashboard_message(state: DashboardState) -> &'static str {
    match state {
        DashboardState::Protected => "AI traffic is routed through DAM",
        DashboardState::Disconnected => "Ready to connect",
        DashboardState::Degraded => "Attention needed before one-click protection",
        DashboardState::NeedsSetup => "Setup is needed before traffic can be protected",
    }
}

fn connect_network_mode() -> dam_net::CaptureMode {
    dam_net::CaptureMode::SystemProxy
}

fn connect_trust_mode() -> dam_trust::TrustMode {
    dam_trust::TrustMode::LocalCa
}

fn connect_setup_plan(state: &AppState) -> Result<dam_diagnostics::SetupPlan, String> {
    let state_dir = dam_daemon::state_paths()
        .map(|paths| paths.state_dir)
        .map_err(|error| error.to_string())?;
    dam_diagnostics::setup_plan(
        &state.config,
        &dam_diagnostics::SetupPlanOptions {
            state_dir: Some(state_dir),
            config_path: state.config_path.clone(),
            proxy_url: Some(configured_proxy_url(&state.config)),
            network_mode: connect_network_mode(),
            trust_mode: connect_trust_mode(),
        },
    )
}

fn first_non_daemon_setup_step(
    setup_plan: Option<&dam_diagnostics::SetupPlan>,
    status: dam_diagnostics::SetupStepStatus,
) -> Option<&dam_diagnostics::SetupStep> {
    setup_plan
        .into_iter()
        .flat_map(|plan| plan.steps.iter())
        .find(|step| step.kind != dam_diagnostics::SetupStepKind::Daemon && step.status == status)
}

fn connect_requires_system_confirmation(view: &ConnectDashboard) -> bool {
    view.setup_plan
        .as_ref()
        .map(|plan| {
            plan.steps.iter().any(|step| {
                step.status == dam_diagnostics::SetupStepStatus::Needed
                    && step.changes_system
                    && step.requires_confirmation
            })
        })
        .unwrap_or(false)
}

fn read_active_profile_for_web() -> (Option<dam_integrations::ActiveProfileState>, Option<String>) {
    match integration_state_dir()
        .and_then(|state_dir| dam_integrations::read_active_profile(&state_dir))
    {
        Ok(profile) => (profile, None),
        Err(error) => (None, Some(error)),
    }
}

fn read_enabled_profiles_for_web() -> (
    Vec<dam_integrations::EnabledIntegrationState>,
    Option<String>,
) {
    match integration_state_dir()
        .and_then(|state_dir| dam_integrations::read_effective_enabled_integrations(&state_dir))
    {
        Ok(profiles) => (profiles, None),
        Err(error) => (Vec::new(), Some(error)),
    }
}

fn integration_state_dir() -> Result<PathBuf, String> {
    dam_daemon::state_paths()
        .map(|paths| paths.state_dir.join("integrations"))
        .map_err(|error| error.to_string())
}

fn default_integration_target_path(profile_id: &str, state_dir: &Path) -> Result<PathBuf, String> {
    dam_integrations::default_apply_path(
        profile_id,
        state_dir,
        env::var_os("CODEX_HOME").map(PathBuf::from),
        env::var_os("HOME").map(PathBuf::from),
    )
}

fn set_active_profile(profile_id: &str) -> Result<(), String> {
    let state_dir = integration_state_dir()?;
    dam_integrations::set_active_profile(profile_id, &state_dir)?;
    Ok(())
}

fn set_profile_enabled(profile_id: &str, enabled: bool) -> Result<(), String> {
    let state_dir = integration_state_dir()?;
    dam_integrations::set_integration_enabled(profile_id, enabled, &state_dir)?;
    Ok(())
}

fn clear_active_profile() -> Result<(), String> {
    let state_dir = integration_state_dir()?;
    dam_integrations::clear_active_profile(&state_dir)?;
    Ok(())
}

fn apply_enabled_profiles(state: &AppState) -> Result<(), String> {
    let state_dir = integration_state_dir()?;
    let profiles = dam_integrations::read_effective_enabled_integrations(&state_dir)?;
    if profiles.is_empty() {
        return Err("enable an app before applying setup".to_string());
    }
    let proxy_url = connected_proxy_url().unwrap_or_else(|| configured_proxy_url(&state.config));
    for profile in profiles {
        apply_profile_by_id(&profile.profile_id, &proxy_url, &state_dir)?;
    }
    Ok(())
}

fn apply_profile_by_id(profile_id: &str, proxy_url: &str, state_dir: &Path) -> Result<(), String> {
    let target_path = default_integration_target_path(profile_id, state_dir)?;
    let inspection =
        dam_integrations::inspect_apply(profile_id, proxy_url, target_path.clone(), state_dir)?;
    if let Some(error) = &inspection.record_error {
        return Err(format!(
            "setup cannot be applied safely because rollback state needs attention: {error}"
        ));
    }
    if inspection.status == dam_integrations::IntegrationApplyStatus::Modified {
        return Err(
            "setup target was modified after DAM applied it; review or rollback before applying"
                .to_string(),
        );
    }
    let prepared = dam_integrations::prepare_apply(profile_id, proxy_url, target_path)?;
    dam_integrations::run_apply(prepared, false, state_dir)?;
    Ok(())
}

fn rollback_enabled_profiles() -> Result<(), String> {
    let state_dir = integration_state_dir()?;
    let profiles = dam_integrations::read_effective_enabled_integrations(&state_dir)?;
    if profiles.is_empty() {
        return Err("enable an app before rolling back setup".to_string());
    }
    for profile in profiles {
        dam_integrations::rollback_profile(&profile.profile_id, &state_dir)?;
    }
    Ok(())
}

async fn advance_connect_setup(
    state: &AppState,
    system_changes_confirmed: bool,
) -> Result<(), String> {
    for _ in 0..8 {
        let plan = connect_setup_plan(state)?;
        match next_connect_setup_action(&plan) {
            ConnectSetupAction::Ready => return Ok(()),
            ConnectSetupAction::ApplyProfile => {
                apply_enabled_profiles(state)?;
            }
            ConnectSetupAction::RunSetupCommand(step) => {
                if step.changes_system && !system_changes_confirmed {
                    return Err(system_confirmation_message(step.kind).to_string());
                }
                run_dam_setup_command(step, Duration::from_secs(180)).await?;
            }
            ConnectSetupAction::RunDaemon => return run_dam_connect(state).await,
            ConnectSetupAction::Blocked(step) => return Err(step.message.clone()),
        }
    }

    Err("setup did not settle after several actions".to_string())
}

fn next_connect_setup_action(plan: &dam_diagnostics::SetupPlan) -> ConnectSetupAction<'_> {
    let step = plan
        .steps
        .iter()
        .find(|step| step.status == dam_diagnostics::SetupStepStatus::Blocked)
        .or_else(|| {
            plan.steps
                .iter()
                .find(|step| step.status == dam_diagnostics::SetupStepStatus::Needed)
        });
    let Some(step) = step else {
        return ConnectSetupAction::Ready;
    };

    match (step.kind, step.status) {
        (_, dam_diagnostics::SetupStepStatus::Blocked) => ConnectSetupAction::Blocked(step),
        (
            dam_diagnostics::SetupStepKind::ProfileApply,
            dam_diagnostics::SetupStepStatus::Needed,
        ) => ConnectSetupAction::ApplyProfile,
        (
            dam_diagnostics::SetupStepKind::SystemProxy | dam_diagnostics::SetupStepKind::LocalCa,
            dam_diagnostics::SetupStepStatus::Needed,
        ) => ConnectSetupAction::RunSetupCommand(step),
        (dam_diagnostics::SetupStepKind::Daemon, dam_diagnostics::SetupStepStatus::Needed) => {
            ConnectSetupAction::RunDaemon
        }
        _ => ConnectSetupAction::Ready,
    }
}

fn system_confirmation_message(kind: dam_diagnostics::SetupStepKind) -> &'static str {
    match kind {
        dam_diagnostics::SetupStepKind::SystemProxy => "confirm system routing before connecting",
        dam_diagnostics::SetupStepKind::LocalCa => "confirm local trust setup before connecting",
        _ => "confirm system changes before connecting",
    }
}

async fn run_dam_setup_command(
    step: &dam_diagnostics::SetupStep,
    timeout: Duration,
) -> Result<(), String> {
    let command = step
        .command
        .as_ref()
        .ok_or_else(|| format!("setup step {} has no command", step.kind.tag()))?;
    if command.first().map(String::as_str) != Some("dam") {
        return Err(format!(
            "setup step {} uses an unsupported command",
            step.kind.tag()
        ));
    }
    run_dam_command_with_timeout(command[1..].to_vec(), timeout).await
}

async fn run_dam_connect(state: &AppState) -> Result<(), String> {
    let has_enabled_profiles = !read_enabled_profiles_for_web().0.is_empty();
    let mut args = vec!["connect".to_string()];
    if has_enabled_profiles {
        args.push("--apply".to_string());
    }
    if let Some(config_path) = &state.config_path {
        args.extend(["--config".to_string(), config_path.display().to_string()]);
    }
    args.extend(["--listen".to_string(), state.config.proxy.listen.clone()]);
    args.extend([
        "--db".to_string(),
        state.config.vault.sqlite_path.display().to_string(),
    ]);
    if state.config.log.enabled && state.config.log.backend == dam_config::LogBackend::Sqlite {
        args.extend([
            "--log".to_string(),
            state.config.log.sqlite_path.display().to_string(),
        ]);
    } else {
        args.push("--no-log".to_string());
    }
    if state.config.consent.enabled {
        args.extend([
            "--consent-db".to_string(),
            state.config.consent.sqlite_path.display().to_string(),
        ]);
    }
    args.extend([
        "--network-mode".to_string(),
        connect_network_mode().tag().to_string(),
        "--trust-mode".to_string(),
        connect_trust_mode().tag().to_string(),
    ]);
    run_dam_command(args).await
}

async fn run_dam_command(args: Vec<String>) -> Result<(), String> {
    run_dam_command_with_timeout(args, Duration::from_secs(30)).await
}

fn system_proxy_remove_args() -> Vec<String> {
    vec![
        "network".to_string(),
        "remove-system-proxy".to_string(),
        "--yes".to_string(),
    ]
}

async fn run_dam_command_with_timeout(args: Vec<String>, timeout: Duration) -> Result<(), String> {
    let output = tokio::time::timeout(timeout, async {
        TokioCommand::new(dam_binary()).args(&args).output().await
    })
    .await
    .map_err(|_| "dam command timed out".to_string())?
    .map_err(|error| format!("failed to run dam: {error}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let message = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    Err(if message.is_empty() {
        format!("dam command failed with {}", output.status)
    } else {
        message.chars().take(600).collect()
    })
}

fn dam_binary() -> OsString {
    env::var_os(DAM_BIN_ENV).unwrap_or_else(|| OsString::from("dam"))
}

async fn disconnect_protection(state: &AppState) -> Result<(), String> {
    run_dam_command_with_timeout(system_proxy_remove_args(), Duration::from_secs(180))
        .await
        .map_err(|error| format!("failed to restore system proxy routing: {error}"))?;
    rollback_enabled_profiles_if_available(state)
        .map_err(|error| format!("failed to restore enabled profile setup: {error}"))?;
    disconnect_daemon()
}

fn rollback_enabled_profiles_if_available(state: &AppState) -> Result<(), String> {
    let state_dir = integration_state_dir()?;
    let profiles = dam_integrations::read_effective_enabled_integrations(&state_dir)?;
    if profiles.is_empty() {
        return Ok(());
    }
    let proxy_url = connected_proxy_url().unwrap_or_else(|| configured_proxy_url(&state.config));
    for profile in profiles {
        let target_path = default_integration_target_path(&profile.profile_id, &state_dir)?;
        let inspection = dam_integrations::inspect_apply(
            &profile.profile_id,
            &proxy_url,
            target_path,
            &state_dir,
        )?;
        if let Some(error) = inspection.record_error {
            return Err(format!("rollback state needs attention: {error}"));
        }
        if inspection.rollback_available {
            dam_integrations::rollback_profile(&profile.profile_id, &state_dir)?;
        }
    }
    Ok(())
}

fn disconnect_daemon() -> Result<(), String> {
    match dam_daemon::daemon_status().map_err(|error| error.to_string())? {
        dam_daemon::DaemonStatus::Disconnected => Ok(()),
        dam_daemon::DaemonStatus::Stale(state) => {
            dam_daemon::remove_state_if_pid(state.pid).map_err(|error| error.to_string())
        }
        dam_daemon::DaemonStatus::Connected(state) => {
            dam_daemon::terminate_process(state.pid).map_err(|error| error.to_string())?;
            dam_daemon::remove_state_if_pid(state.pid).map_err(|error| error.to_string())
        }
    }
}

fn connected_proxy_url() -> Option<String> {
    match dam_daemon::daemon_status() {
        Ok(dam_daemon::DaemonStatus::Connected(state)) => Some(state.proxy_url),
        _ => None,
    }
}

fn configured_proxy_url(config: &dam_config::DamConfig) -> String {
    config
        .proxy
        .listen
        .parse::<SocketAddr>()
        .map(dam_daemon::local_base_url)
        .unwrap_or_else(|_| dam_integrations::DEFAULT_PROXY_URL.to_string())
}

async fn fetch_daemon_proxy_report(
    client: &reqwest::Client,
    proxy_url: &str,
) -> Result<dam_api::ProxyReport, String> {
    let health_url = format!("{}/health", proxy_url.trim_end_matches('/'));
    let response = client
        .get(&health_url)
        .send()
        .await
        .map_err(|error| format!("DAM proxy is not reachable at {health_url}: {error}"))?;
    response
        .json::<dam_api::ProxyReport>()
        .await
        .map_err(|error| format!("DAM proxy returned unreadable health JSON: {error}"))
}

#[cfg(test)]
fn render_logs(log_path: &Path, entries: &[LogEntry]) -> String {
    render_logs_with_order(log_path, entries, LogOrder::default())
}

fn render_logs_with_order(log_path: &Path, entries: &[LogEntry], order: LogOrder) -> String {
    let rows = if entries.is_empty() {
        "<tr><td class=\"empty\" colspan=\"9\">No log events found.</td></tr>".to_string()
    } else {
        entries
            .iter()
            .map(render_log_row)
            .collect::<Vec<_>>()
            .join("\n")
    };

    render_shell(
        "DAM Logs",
        "Logs",
        &format!("Database: {}", escape_html(&log_path.display().to_string())),
        entries.len(),
        "events",
        &format!(
            r#"<table class="data-table logs-table">
      <thead>
        <tr>
          {id_header}
          {time_header}
          {level_header}
          {type_header}
          {operation_header}
          {kind_header}
          {reference_header}
          {action_header}
          {message_header}
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>"#,
            id_header = render_log_sort_header("ID", LogSortField::Id, order),
            time_header = render_log_sort_header("Time", LogSortField::Time, order),
            level_header = render_log_sort_header("Level", LogSortField::Level, order),
            type_header = render_log_sort_header("Type", LogSortField::Type, order),
            operation_header = render_log_sort_header("Operation", LogSortField::Operation, order),
            kind_header = render_log_sort_header("Kind", LogSortField::Kind, order),
            reference_header = render_log_sort_header("Reference", LogSortField::Reference, order),
            action_header = render_log_sort_header("Action", LogSortField::Action, order),
            message_header = render_log_sort_header("Message", LogSortField::Message, order),
        ),
    )
}

fn render_connect_dashboard(view: &ConnectDashboard) -> String {
    let active_profile_id = enabled_profiles_display(view);
    let apply_state = view
        .active_profile_apply
        .as_ref()
        .map(|apply| integration_apply_status_tag(apply.status))
        .unwrap_or("automatic");
    let target_provider = view
        .daemon
        .as_ref()
        .and_then(|daemon| daemon.target_provider.as_deref())
        .or_else(|| {
            view.enabled_profiles.first().and_then(|enabled| {
                view.profiles
                    .iter()
                    .find(|card| card.profile.id == enabled.profile_id)
                    .map(|card| card.profile.provider.as_str())
            })
        })
        .unwrap_or("automatic");
    let upstream = view
        .daemon
        .as_ref()
        .and_then(|daemon| daemon.upstream.as_deref())
        .unwrap_or("automatic");
    let primary_action = render_primary_connect_action(view);
    let profile_options = view
        .profiles
        .iter()
        .map(render_profile_option)
        .collect::<Vec<_>>()
        .join("\n");
    let setup_actions = render_setup_actions(view);
    let notice = view
        .notice
        .as_ref()
        .map(|message| render_banner("notice", message))
        .unwrap_or_default();
    let error = view
        .error
        .as_ref()
        .map(|message| render_banner("error", message))
        .unwrap_or_default();
    let active_profile_warning = view
        .active_profile_error
        .as_ref()
        .or(view.enabled_profiles_error.as_ref())
        .map(|message| render_banner("error", message))
        .unwrap_or_default();
    let diagnostics = render_dashboard_diagnostics(view);

    render_shell(
        "DAM Connect",
        "Connect",
        "One-click protection.",
        1,
        "apps",
        &format!(
            r#"<section class="connect-hero status-{state_class}">
      {notice}
      {error}
      {active_profile_warning}
      <div class="connect-status">
        <div>
          <div class="status-label">Protection</div>
          <div class="connect-state">{state_label}</div>
          <p>{message}</p>
        </div>
        {primary_action}
      </div>
      <dl class="connect-facts">
        <dt>Mode</dt><dd>Protect Everything</dd>
        <dt>Apps</dt><dd>{active_profile}</dd>
      </dl>
      {setup_actions}
    </section>
    <section class="connect-grid">
      <details class="connect-section profile-panel">
        <summary>
          <span class="toggle-title">Apps</span>
          <span class="toggle-value">{active_profile}</span>
          <span class="toggle-chevron" aria-hidden="true"></span>
        </summary>
        <div class="profile-list">{profile_options}</div>
      </details>
      <details class="connect-section">
        <summary>
          <span class="toggle-title">Details</span>
          <span class="toggle-chevron" aria-hidden="true"></span>
        </summary>
        <div class="settings-list">
          <div><span>Endpoint</span><strong>{proxy_url}</strong></div>
          <div><span>Provider</span><strong>{provider}</strong></div>
          <div><span>Upstream</span><strong>{upstream}</strong></div>
          <div><span>Setup</span><strong>{apply_state}</strong></div>
          <div><span>Vault</span><strong>{vault_path}</strong></div>
          <div><span>Log</span><strong>{log_path}</strong></div>
          <div><span>Inbound References</span><strong>{resolve_inbound}</strong></div>
          <div><span>DAM Binary</span><strong>{dam_bin}</strong></div>
        </div>
        {diagnostics}
      </details>
    </section>"#,
            state_class = escape_html(dashboard_state_class(view.state)),
            notice = notice,
            error = error,
            active_profile_warning = active_profile_warning,
            state_label = escape_html(dashboard_state_label(view.state)),
            message = escape_html(&view.message),
            primary_action = primary_action,
            active_profile = escape_html(&active_profile_id),
            proxy_url = escape_html(&view.proxy_url),
            provider = escape_html(target_provider),
            upstream = escape_html(upstream),
            apply_state = escape_html(apply_state),
            setup_actions = setup_actions,
            profile_options = profile_options,
            vault_path = escape_html(&view_profile_vault_path(view)),
            log_path = escape_html(&view_profile_log_path(view)),
            resolve_inbound = escape_html(&view_profile_resolve_inbound(view)),
            dam_bin = escape_html(&dam_binary().to_string_lossy()),
            diagnostics = diagnostics,
        ),
    )
}

fn render_settings_dashboard(notice: Option<String>, error: Option<String>) -> String {
    let (enabled_profiles, enabled_error) = read_enabled_profiles_for_web();
    let proxy_url = dam_integrations::DEFAULT_PROXY_URL.to_string();
    let profiles = profile_cards(&proxy_url, &enabled_profiles);
    let rows = profiles
        .iter()
        .map(render_settings_profile)
        .collect::<Vec<_>>()
        .join("\n");
    let notice = notice
        .as_ref()
        .map(|message| render_banner("notice", message))
        .unwrap_or_default();
    let error = error
        .as_ref()
        .or(enabled_error.as_ref())
        .map(|message| render_banner("error", message))
        .unwrap_or_default();

    render_shell(
        "DAM Settings",
        "Settings",
        "App routing and harness configs.",
        enabled_profiles.len(),
        "enabled",
        &format!(
            r#"<section class="connect-section settings-panel">
      {notice}
      {error}
      <div class="section-title">Apps</div>
      <div class="profile-list">{rows}</div>
    </section>"#,
            notice = notice,
            error = error,
            rows = rows,
        ),
    )
}

fn render_settings_profile(card: &ProfileCard) -> String {
    let apply_status = card
        .apply
        .as_ref()
        .map(|apply| integration_apply_status_tag(apply.status))
        .unwrap_or("unknown");
    let action = if card.active {
        ("disable_profile", "Disable", "enabled")
    } else {
        ("enable_profile", "Enable", "disabled")
    };
    let settings = card
        .profile
        .settings
        .iter()
        .map(|setting| {
            format!(
                "<div><span>{}</span><strong>{}</strong></div>",
                escape_html(&setting.key),
                escape_html(&setting.value)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let settings = if settings.is_empty() {
        "<p class=\"quiet\">No app config is written by this profile.</p>".to_string()
    } else {
        format!("<div class=\"settings-list\">{settings}</div>")
    };

    format!(
        r#"<article class="profile-option settings-profile{selected}">
      <div class="profile-select-row">
        <span class="profile-name">{name}</span>
        <span class="profile-summary">{summary}</span>
        <span class="profile-state">{state}</span>
      </div>
      <form class="settings-profile-action" method="post" action="/settings/integrations">
        <input type="hidden" name="action" value="{action}">
        <input type="hidden" name="profile_id" value="{profile_id}">
        <button class="action-button" type="submit">{label}</button>
      </form>
      <div class="profile-more-panel settings-profile-detail">
        <dl>
          <dt>ID</dt><dd>{id}</dd>
          <dt>Provider</dt><dd>{provider}</dd>
          <dt>Setup</dt><dd>{apply_status}</dd>
        </dl>
        {settings}
      </div>
    </article>"#,
        selected = if card.active { " selected" } else { "" },
        name = escape_html(profile_display_name(&card.profile)),
        summary = escape_html(profile_display_summary(&card.profile)),
        state = action.2,
        action = action.0,
        label = action.1,
        profile_id = escape_html(&card.profile.id),
        id = escape_html(&card.profile.id),
        provider = escape_html(&card.profile.provider),
        apply_status = escape_html(apply_status),
        settings = settings,
    )
}

fn render_primary_connect_action(view: &ConnectDashboard) -> String {
    if view.daemon.is_some() {
        return concat!(
            r#"<form method="post" action="/connect/action">"#,
            r#"<input type="hidden" name="action" value="disconnect">"#,
            r#"<button class="connect-button disconnect" type="submit">Disconnect</button></form>"#
        )
        .to_string();
    }
    if view.setup_plan_error.is_some()
        || first_non_daemon_setup_step(
            view.setup_plan.as_ref(),
            dam_diagnostics::SetupStepStatus::Blocked,
        )
        .is_some()
    {
        return r#"<button class="connect-button" type="button" disabled>Review Setup</button>"#
            .to_string();
    }
    if !view.enabled_profiles.is_empty() && view.active_profile_apply.is_none() {
        return r#"<button class="connect-button" type="button" disabled>Review Setup</button>"#
            .to_string();
    }
    let system_confirm = if connect_requires_system_confirmation(view) {
        format!(
            r#"<button class="connect-button" type="submit" name="{field}" value="yes" data-confirm="Allow DAM to update local network and trust settings?">Connect</button>"#,
            field = CONNECT_SYSTEM_CONFIRM_FIELD
        )
    } else {
        r#"<button class="connect-button" type="submit">Connect</button>"#.to_string()
    };
    concat!(
        r#"<form method="post" action="/connect/action">"#,
        r#"<input type="hidden" name="action" value="connect">"#
    )
    .to_string()
        + &system_confirm
        + "</form>"
}

fn render_setup_actions(view: &ConnectDashboard) -> String {
    let rollback_button = if view
        .active_profile_apply
        .as_ref()
        .map(|apply| apply.rollback_available)
        .unwrap_or(false)
    {
        concat!(
            r#"<form method="post" action="/connect/action">"#,
            r#"<input type="hidden" name="action" value="rollback_profile">"#,
            r#"<button class="action-button danger" type="submit">Rollback</button></form>"#
        )
        .to_string()
    } else {
        String::new()
    };
    let setup_step = first_non_daemon_setup_step(
        view.setup_plan.as_ref(),
        dam_diagnostics::SetupStepStatus::Blocked,
    )
    .or_else(|| {
        first_non_daemon_setup_step(
            view.setup_plan.as_ref(),
            dam_diagnostics::SetupStepStatus::Needed,
        )
    });
    let step_label = setup_step
        .map(|step| format!("Next: {}", setup_step_label(step.kind)))
        .unwrap_or_else(|| "Ready".to_string());
    let target = view
        .active_profile_apply
        .as_ref()
        .map(|apply| apply.target_path.display().to_string())
        .unwrap_or_else(|| "local setup".to_string());
    if rollback_button.is_empty() && setup_step.is_none() {
        return String::new();
    }
    format!(
        r#"<div class="setup-actions">{rollback_button}<span>{step_label}</span><span>{target}</span></div>"#,
        rollback_button = rollback_button,
        step_label = escape_html(&step_label),
        target = escape_html(&target),
    )
}

fn setup_step_label(kind: dam_diagnostics::SetupStepKind) -> &'static str {
    match kind {
        dam_diagnostics::SetupStepKind::ProfileApply => "Profile",
        dam_diagnostics::SetupStepKind::SystemProxy => "Routing",
        dam_diagnostics::SetupStepKind::LocalCa => "Trust",
        dam_diagnostics::SetupStepKind::Daemon => "Connect",
    }
}

fn render_profile_option(card: &ProfileCard) -> String {
    let apply_status = card
        .apply
        .as_ref()
        .map(|apply| integration_apply_status_tag(apply.status))
        .unwrap_or("unknown");
    let apply_message = card
        .apply
        .as_ref()
        .map(|apply| apply.message.as_str())
        .or(card.inspection_error.as_deref())
        .unwrap_or("profile target has not been inspected");
    let row_state = if card.active { " selected" } else { "" };
    let select_control = if card.active {
        format!(
            concat!(
                r#"<form class="profile-select-form" method="post" action="/connect/action">"#,
                r#"<input type="hidden" name="action" value="disable_profile">"#,
                r#"<input type="hidden" name="profile_id" value="{profile_id}">"#,
                r#"<button class="profile-select-row" type="submit">"#,
                r#"<span class="profile-name">{name}</span>"#,
                r#"<span class="profile-summary">{summary}</span>"#,
                r#"<span class="profile-state">enabled</span></button></form>"#
            ),
            profile_id = escape_html(&card.profile.id),
            name = escape_html(profile_display_name(&card.profile)),
            summary = escape_html(profile_display_summary(&card.profile)),
        )
    } else {
        format!(
            concat!(
                r#"<form class="profile-select-form" method="post" action="/connect/action">"#,
                r#"<input type="hidden" name="action" value="enable_profile">"#,
                r#"<input type="hidden" name="profile_id" value="{profile_id}">"#,
                r#"<button class="profile-select-row" type="submit">"#,
                r#"<span class="profile-name">{name}</span>"#,
                r#"<span class="profile-summary">{summary}</span>"#,
                r#"<span class="profile-state">{apply_status}</span></button></form>"#
            ),
            profile_id = escape_html(&card.profile.id),
            name = escape_html(profile_display_name(&card.profile)),
            summary = escape_html(profile_display_summary(&card.profile)),
            apply_status = escape_html(apply_status),
        )
    };

    format!(
        r#"<div class="profile-option{row_state}">
      {select_control}
      <details class="profile-more">
        <summary aria-label="Profile details" title="Profile details">...</summary>
      </details>
      <div class="profile-more-panel">
        <dl>
          <dt>ID</dt><dd>{id}</dd>
          <dt>Provider</dt><dd>{provider}</dd>
          <dt>Setup</dt><dd>{apply_status}</dd>
        </dl>
        <p class="profile-note">{apply_message}</p>
      </div>
    </div>"#,
        row_state = row_state,
        select_control = select_control,
        id = escape_html(&card.profile.id),
        provider = escape_html(&card.profile.provider),
        apply_status = escape_html(apply_status),
        apply_message = escape_html(apply_message),
    )
}

fn profile_display_name(profile: &dam_integrations::IntegrationProfile) -> &str {
    if profile.id == "openai-compatible" {
        "Protect Everything"
    } else {
        &profile.name
    }
}

fn profile_display_summary(profile: &dam_integrations::IntegrationProfile) -> &str {
    if profile.id == "openai-compatible" {
        "Default protection"
    } else {
        &profile.summary
    }
}

fn enabled_profiles_display(view: &ConnectDashboard) -> String {
    if view.enabled_profiles.is_empty() {
        return "Protect Everything".to_string();
    }
    view.enabled_profiles
        .iter()
        .filter_map(|enabled| {
            view.profiles
                .iter()
                .find(|card| card.profile.id == enabled.profile_id)
                .map(|card| profile_display_name(&card.profile).to_string())
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_dashboard_diagnostics(view: &ConnectDashboard) -> String {
    let mut items = Vec::new();
    if let Some(proxy) = &view.proxy {
        items.push(format!(
            "<li><strong>proxy</strong><br>{}</li>",
            escape_html(&proxy.message)
        ));
        for diagnostic in &proxy.diagnostics {
            items.push(format!(
                "<li><strong>{} {}</strong><br>{}</li>",
                escape_html(severity_tag(diagnostic.severity)),
                escape_html(&diagnostic.code),
                escape_html(&diagnostic.message)
            ));
        }
    }
    if let Some(apply) = &view.active_profile_apply
        && let Some(error) = &apply.record_error
    {
        items.push(format!(
            "<li><strong>rollback</strong><br>{}</li>",
            escape_html(error)
        ));
    }
    if items.is_empty() {
        return "<p class=\"quiet\">No blocking diagnostics.</p>".to_string();
    }
    format!(
        "<ul class=\"diagnostics-list dashboard-diagnostics\">{}</ul>",
        items.join("\n")
    )
}

fn render_banner(kind: &str, message: &str) -> String {
    format!(
        r#"<div class="banner {kind}">{message}</div>"#,
        kind = escape_html(kind),
        message = escape_html(message),
    )
}

fn dashboard_state_label(state: DashboardState) -> &'static str {
    match state {
        DashboardState::Protected => "Protected",
        DashboardState::Disconnected => "Disconnected",
        DashboardState::Degraded => "Needs Review",
        DashboardState::NeedsSetup => "Needs Setup",
    }
}

fn dashboard_state_class(state: DashboardState) -> &'static str {
    match state {
        DashboardState::Protected => "protected",
        DashboardState::Disconnected => "unknown",
        DashboardState::Degraded => "degraded",
        DashboardState::NeedsSetup => "config_required",
    }
}

fn integration_apply_status_tag(status: dam_integrations::IntegrationApplyStatus) -> &'static str {
    match status {
        dam_integrations::IntegrationApplyStatus::Applied => "applied",
        dam_integrations::IntegrationApplyStatus::NeedsApply => "needs_setup",
        dam_integrations::IntegrationApplyStatus::Modified => "modified",
    }
}

fn view_profile_vault_path(view: &ConnectDashboard) -> String {
    view.daemon
        .as_ref()
        .map(|daemon| daemon.vault_path.display().to_string())
        .unwrap_or_else(|| "configured in dam-web".to_string())
}

fn view_profile_log_path(view: &ConnectDashboard) -> String {
    view.daemon
        .as_ref()
        .and_then(|daemon| daemon.log_path.as_ref())
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "configured in dam-web".to_string())
}

fn view_profile_resolve_inbound(view: &ConnectDashboard) -> String {
    view.daemon
        .as_ref()
        .map(|daemon| daemon.resolve_inbound.to_string())
        .unwrap_or_else(|| "false".to_string())
}

fn render_diagnostics(
    config_report: &dam_api::HealthReport,
    proxy_report: &dam_api::ProxyReport,
) -> String {
    let config_cards = config_report
        .components
        .iter()
        .map(render_component_card)
        .collect::<Vec<_>>()
        .join("\n");
    let config_diagnostics = render_diagnostic_list(&config_report.diagnostics);
    let proxy_diagnostics = render_diagnostic_list(&proxy_report.diagnostics);

    render_shell(
        "DAM Diagnostics",
        "Diagnostics",
        "Local damctl-style checks for config health and proxy protection state.",
        config_report.components.len() + 1,
        "checks",
        &format!(
            r#"<section class="diagnostics-grid">
      <article class="status-card status-{proxy_class}">
        <div class="status-label">Proxy Status</div>
        <div class="state-pill state-{proxy_class}">{proxy_state}</div>
        <p>{proxy_message}</p>
        <dl>
          <dt>Target</dt><dd>{proxy_target}</dd>
          <dt>Upstream</dt><dd>{proxy_upstream}</dd>
          <dt>Operation</dt><dd>{proxy_operation}</dd>
        </dl>
        {proxy_diagnostics}
      </article>
      <article class="status-card status-{config_class}">
        <div class="status-label">Config Check</div>
        <div class="state-pill state-{config_class}">{config_state}</div>
        <p>{config_message}</p>
        {config_diagnostics}
      </article>
    </section>
    <section class="component-grid">
      {config_cards}
    </section>"#,
            proxy_class = escape_html(proxy_state_tag(proxy_report.state)),
            proxy_state = escape_html(proxy_state_tag(proxy_report.state)),
            proxy_message = escape_html(&proxy_report.message),
            proxy_target = escape_html(proxy_report.target.as_deref().unwrap_or("not configured")),
            proxy_upstream =
                escape_html(proxy_report.upstream.as_deref().unwrap_or("not configured")),
            proxy_operation = escape_html(proxy_report.operation_id.as_deref().unwrap_or("none")),
            proxy_diagnostics = proxy_diagnostics,
            config_class = escape_html(health_state_tag(config_report.state)),
            config_state = escape_html(health_state_tag(config_report.state)),
            config_message = escape_html(config_summary(config_report.state)),
            config_diagnostics = config_diagnostics,
            config_cards = config_cards,
        ),
    )
}

fn render_doctor(report: &dam_api::HealthReport) -> String {
    let cards = report
        .components
        .iter()
        .map(render_component_card)
        .collect::<Vec<_>>()
        .join("\n");
    let diagnostics = render_diagnostic_list(&report.diagnostics);

    render_shell(
        "DAM Doctor",
        "Doctor",
        "Local readiness checks for protected AI traffic.",
        report.components.len(),
        "checks",
        &format!(
            r#"<section class="diagnostics-grid">
      <article class="status-card status-{state_class}">
        <div class="status-label">Overall Readiness</div>
        <div class="state-pill state-{state_class}">{state}</div>
        <p>{message}</p>
        {diagnostics}
      </article>
    </section>
    <section class="component-grid">
      {cards}
    </section>"#,
            state_class = escape_html(health_state_tag(report.state)),
            state = escape_html(health_state_tag(report.state)),
            message = escape_html(config_summary(report.state)),
            diagnostics = diagnostics,
            cards = cards,
        ),
    )
}

fn render_shell(
    title: &str,
    active: &str,
    meta: &str,
    count: usize,
    count_label: &str,
    content: &str,
) -> String {
    render_shell_with_mode(
        ShellMode::from_env(),
        title,
        active,
        meta,
        count,
        count_label,
        content,
    )
}

fn render_shell_with_mode(
    shell_mode: ShellMode,
    title: &str,
    active: &str,
    meta: &str,
    count: usize,
    count_label: &str,
    content: &str,
) -> String {
    let body_class = if shell_mode.is_tray() {
        " class=\"tray-shell\""
    } else {
        ""
    };
    let tray_quit = if shell_mode.is_tray() {
        r#"<button class="tray-quit" type="button" data-tray-quit aria-label="Quit DAM" title="Quit DAM">⏻</button>"#
    } else {
        ""
    };
    let brand_tray_attrs = if shell_mode.is_tray() {
        r#" data-tray-external="rpblc""#
    } else {
        ""
    };
    let tray_post_token = env::var(DAM_WEB_TRAY_POST_TOKEN_ENV)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_default();
    let tray_script = if shell_mode.is_tray() {
        r#"<script>
    (() => {
      const post = (message) => {
        if (window.ipc && typeof window.ipc.postMessage === "function") {
          window.ipc.postMessage(message);
        }
      };
      const trayPostToken = "{tray_post_token}";
      if (trayPostToken) {
        const attachTrayPostToken = (form) => {
          if (!form || String(form.method).toLowerCase() !== "post") {
            return;
          }
          const url = new URL(form.getAttribute("action") || window.location.href, window.location.href);
          if (url.origin !== window.location.origin) {
            return;
          }
          url.searchParams.set("tray_token", trayPostToken);
          form.setAttribute("action", `${url.pathname}${url.search}${url.hash}`);
        };
        document.querySelectorAll("form").forEach(attachTrayPostToken);
        document.addEventListener("submit", (event) => {
          attachTrayPostToken(event.target);
        }, true);
      }
      document.addEventListener("submit", (event) => {
        const form = event.target;
        if (!form || String(form.method).toLowerCase() !== "post") {
          return;
        }
        const action = form.querySelector("input[name='action']");
        if (!action || action.value !== "connect") {
          return;
        }
        event.preventDefault();
        const submitter = event.submitter || form.querySelector("button[type='submit']");
        if (submitter) {
          submitter.disabled = true;
        }
        post("{connect_message}");
      }, true);
      document.querySelectorAll("[data-tray-external='rpblc']").forEach((link) => {
        link.addEventListener("click", (event) => {
          event.preventDefault();
          post("{open_rpblc_message}");
        });
      });
      const button = document.querySelector("[data-tray-quit]");
      if (button) {
        button.addEventListener("click", () => {
          button.disabled = true;
          post("{quit_message}");
        });
      }
    })();
  </script>"#
            .replace("{tray_post_token}", &escape_js_string(&tray_post_token))
            .replace("{connect_message}", DAM_TRAY_CONNECT_MESSAGE)
            .replace("{open_rpblc_message}", DAM_TRAY_OPEN_RPBLC_MESSAGE)
            .replace("{quit_message}", DAM_TRAY_QUIT_MESSAGE)
    } else {
        String::new()
    };
    let confirm_script = if shell_mode.is_tray() {
        String::new()
    } else {
        r#"<script>
    (() => {
      document.querySelectorAll("[data-confirm]").forEach((button) => {
        button.addEventListener("click", (event) => {
          const message = button.getAttribute("data-confirm");
          if (message && !window.confirm(message)) {
            event.preventDefault();
          }
        });
      });
    })();
  </script>"#
            .to_string()
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <title>{title}</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0a0a08;
      --panel: #12120f;
      --panel-strong: #181714;
      --line: #1e1d1a;
      --line-strong: #2c2a22;
      --soft: #3d3a32;
      --muted: #78736a;
      --text: #dedad2;
      --bright: #faf8f2;
      --accent: #B8965A;
      --flash: #F5F0E8;
      --ok: #67c58a;
      --ok-bg: rgba(103, 197, 138, .12);
      --ok-line: rgba(103, 197, 138, .58);
      --warn: #d9b95f;
      --warn-bg: rgba(217, 185, 95, .13);
      --warn-line: rgba(217, 185, 95, .62);
      --bad: #df7865;
      --bad-bg: rgba(223, 120, 101, .13);
      --bad-line: rgba(223, 120, 101, .62);
      --unknown: #9d9588;
      --unknown-bg: rgba(157, 149, 136, .12);
      --unknown-line: rgba(157, 149, 136, .52);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 16px/1.45 Manrope, ui-sans-serif, system-ui, sans-serif;
    }}
    main {{
      width: min(1240px, calc(100vw - 32px));
      margin: 0 auto 42px;
      padding: 0;
    }}
    .brand-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 18px;
      position: sticky;
      top: 0;
      z-index: 100;
      border-bottom: 1px solid var(--line);
      background: rgba(10, 10, 8, .92);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      padding: 6px 24px;
      margin: 0 calc((100vw - min(1240px, calc(100vw - 32px))) / -2) 28px;
    }}
    .brand-home {{
      display: inline-flex;
      align-items: center;
      gap: 12px;
      color: inherit;
      text-decoration: none;
      min-height: 36px;
    }}
    .brand-mark {{
      display: inline-flex;
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 26px;
      line-height: 1;
      font-weight: 800;
      letter-spacing: 0;
    }}
    .brand-mark .glyph {{ transition: color 120ms ease; }}
    .brand-mark .letter {{ color: var(--bright); }}
    .brand-mark .colon {{ color: var(--accent); }}
    .brand-mark .bracket {{ color: var(--soft); }}
    .brand-copy {{
      color: var(--muted);
      font-size: 13px;
      line-height: 1;
    }}
    .brand-out {{
      color: var(--muted);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      text-decoration: none;
      letter-spacing: 0;
      text-transform: uppercase;
    }}
    .brand-home:hover .brand-mark .glyph {{ color: var(--bg); }}
    .brand-home:hover .brand-mark .colon {{ color: var(--bg); }}
    .brand-mark .glyph:hover {{ color: var(--bright) !important; }}
    .brand-mark .colon:hover {{ color: var(--accent) !important; }}
    .brand-out:hover {{ color: var(--bright); }}
    .brand-actions {{
      display: inline-flex;
      align-items: center;
      gap: 12px;
      flex-shrink: 0;
      min-height: 36px;
    }}
    .nav-more {{
      position: relative;
      flex: 0 0 auto;
    }}
    .nav-more summary {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      list-style: none;
      cursor: pointer;
      color: var(--muted);
      min-width: 40px;
      min-height: 36px;
      padding: 0 10px;
    }}
    .chevron-mark {{
      width: 9px;
      height: 9px;
      border-right: 2px solid currentColor;
      border-bottom: 2px solid currentColor;
      transform: rotate(45deg);
      position: relative;
      top: -2px;
    }}
    .nav-more summary::-webkit-details-marker {{
      display: none;
    }}
    .nav-more summary:hover,
    .nav-more[open] summary {{
      color: var(--bright);
    }}
    .nav-more-menu {{
      position: absolute;
      right: 0;
      top: calc(100% + 10px);
      min-width: 156px;
      z-index: 120;
      border: 1px solid var(--line);
      background: var(--panel);
      box-shadow: 8px 8px 0 var(--line);
      padding: 8px;
    }}
    .nav-more-menu a {{
      display: block;
      padding: 9px 10px;
      white-space: nowrap;
    }}
    .tray-quit {{
      display: none;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: 999px;
      border: 1px solid var(--line-strong);
      background: transparent;
      color: var(--muted);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 15px;
      font-weight: 700;
      letter-spacing: 0;
      cursor: pointer;
    }}
    .tray-quit:hover {{
      color: var(--bad);
      border-color: var(--bad-line);
    }}
    .tray-quit:disabled {{
      cursor: wait;
      opacity: .62;
    }}
    nav {{
      display: flex;
      align-items: center;
      gap: 2px;
      margin: 0;
      min-width: 0;
      overflow: visible;
    }}
    nav a {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: 0;
      color: var(--muted);
      background: transparent;
      min-height: 36px;
      padding: 0 10px;
      text-decoration: none;
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      line-height: 1;
      letter-spacing: 0;
      text-transform: uppercase;
    }}
    nav a.active {{
      background: transparent;
      color: var(--accent);
    }}
    nav a:hover {{ color: var(--bright); }}
    header {{
      display: flex;
      justify-content: space-between;
      gap: 24px;
      align-items: end;
      margin-bottom: 22px;
    }}
    h1 {{
      margin: 0 0 6px;
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: clamp(32px, 7vw, 70px);
      line-height: .9;
      letter-spacing: 0;
      color: var(--bright);
    }}
    .meta {{
      color: var(--muted);
      overflow-wrap: anywhere;
    }}
    .count {{
      border: 1px solid var(--line);
      background: var(--panel);
      padding: 14px 18px;
      min-width: 140px;
      text-align: center;
      box-shadow: 8px 8px 0 var(--line);
    }}
    .count strong {{
      display: block;
      color: var(--accent);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 34px;
      line-height: 1;
    }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--line);
      background: var(--panel);
    }}
    .connect-surface {{
      overflow: visible;
      border: 0;
      background: transparent;
    }}
    .content-surface {{
      overflow: visible;
      border: 0;
      background: transparent;
    }}
    .connect-hero {{
      border: 1px solid var(--line);
      background: var(--panel);
      padding: 22px;
      margin-bottom: 18px;
      box-shadow: 8px 8px 0 var(--line);
    }}
    .connect-status {{
      display: flex;
      justify-content: space-between;
      gap: 24px;
      align-items: center;
      margin-bottom: 18px;
    }}
    .connect-state {{
      margin: 8px 0 6px;
      color: var(--bright);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: clamp(30px, 8vw, 74px);
      line-height: .95;
      letter-spacing: 0;
    }}
    .connect-status p {{
      margin: 0;
      color: var(--muted);
    }}
    .connect-button {{
      width: 168px;
      height: 168px;
      border: 2px solid var(--accent);
      border-radius: 50%;
      background: var(--accent);
      color: var(--bg);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 18px;
      font-weight: 900;
      letter-spacing: 0;
      text-transform: uppercase;
      cursor: pointer;
      box-shadow: 0 0 0 10px rgba(184, 150, 90, .12), 8px 8px 0 var(--line);
    }}
    .connect-button:hover {{
      background: var(--flash);
      border-color: var(--flash);
    }}
    .connect-button:disabled {{
      cursor: not-allowed;
      background: var(--panel-strong);
      color: var(--muted);
      border-color: var(--line-strong);
      box-shadow: 8px 8px 0 var(--line);
    }}
    .connect-button.disconnect {{
      color: var(--bad);
      background: transparent;
      border-color: var(--bad);
      box-shadow: 0 0 0 10px rgba(223, 120, 101, .10), 8px 8px 0 var(--line);
    }}
    .connect-facts {{
      grid-template-columns: 140px 1fr;
      padding-top: 16px;
      border-top: 1px solid var(--line);
    }}
    .setup-actions {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 18px;
      padding-top: 16px;
      border-top: 1px solid var(--line);
      color: var(--muted);
      overflow-wrap: anywhere;
    }}
    .setup-actions span {{
      min-width: 0;
      overflow-wrap: anywhere;
    }}
    .connect-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1.4fr) minmax(300px, .8fr);
      gap: 18px;
    }}
    .connect-section {{
      border: 1px solid var(--line);
      background: var(--panel);
      padding: 18px;
      box-shadow: 8px 8px 0 var(--line);
    }}
    .section-title {{
      margin-bottom: 14px;
      color: var(--accent);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      letter-spacing: 0;
      text-transform: uppercase;
    }}
    details.connect-section {{
      padding: 0;
      overflow: visible;
      border: 0;
      background: transparent;
      box-shadow: none;
    }}
    details.connect-section summary {{
      display: grid;
      grid-template-columns: auto minmax(0, 1fr) 18px;
      align-items: center;
      gap: 12px;
      list-style: none;
      cursor: pointer;
      min-height: 40px;
      padding: 0 12px;
      border: 1px solid var(--line-strong);
      background: var(--panel-strong);
      box-shadow: 3px 3px 0 var(--line);
      color: var(--accent);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0;
      text-transform: uppercase;
    }}
    details.connect-section summary:hover {{
      border-color: var(--accent);
      background: rgba(184, 150, 90, .08);
    }}
    details.connect-section summary::-webkit-details-marker {{
      display: none;
    }}
    details.connect-section[open] summary {{
      border-color: var(--line-strong);
    }}
    .toggle-title {{
      color: var(--accent);
      white-space: nowrap;
    }}
    .toggle-value {{
      min-width: 0;
      color: var(--bright);
      font-family: Manrope, ui-sans-serif, system-ui, sans-serif;
      font-size: 13px;
      font-weight: 700;
      text-transform: none;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .toggle-chevron {{
      grid-column: 3;
      justify-self: end;
      width: 8px;
      height: 8px;
      border-right: 2px solid currentColor;
      border-bottom: 2px solid currentColor;
      transform: rotate(45deg);
      position: relative;
      top: -2px;
    }}
    details.connect-section[open] .toggle-chevron {{
      transform: rotate(225deg);
      top: 2px;
    }}
    details.connect-section > .profile-list,
    details.connect-section > .settings-list,
    details.connect-section > .diagnostics-list,
    details.connect-section > .quiet {{
      margin: 14px 0 0;
    }}
    .profile-list {{
      display: grid;
      gap: 8px;
    }}
    .profile-option {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 36px;
      align-items: stretch;
      border: 1px solid var(--line);
      background: var(--panel-strong);
    }}
    .profile-option.selected {{
      border-color: var(--accent);
    }}
    .settings-panel {{
      padding: 18px;
    }}
    .settings-profile {{
      grid-template-columns: minmax(0, 1fr) auto;
    }}
    .settings-profile-action {{
      display: flex;
      align-items: center;
      padding: 10px 12px;
      border-left: 1px solid var(--line);
    }}
    .settings-profile-detail {{
      display: block;
    }}
    .profile-select-form {{
      display: contents;
    }}
    .profile-select-row {{
      appearance: none;
      -webkit-appearance: none;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      grid-template-areas:
        "name state"
        "summary summary";
      align-items: center;
      gap: 5px 12px;
      width: 100%;
      min-width: 0;
      border: 0;
      background: transparent;
      color: inherit;
      padding: 10px 12px;
      text-align: left;
      cursor: pointer;
    }}
    .profile-select-row:disabled {{
      cursor: default;
      opacity: 1;
    }}
    .profile-select-row:hover {{
      background: rgba(184, 150, 90, .08);
    }}
    .profile-select-row:disabled:hover {{
      background: transparent;
    }}
    .profile-name {{
      grid-area: name;
      min-width: 0;
      color: var(--bright);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      font-weight: 800;
      line-height: 1;
      letter-spacing: 0;
      text-transform: uppercase;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .profile-summary {{
      grid-area: summary;
      min-width: 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.2;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .profile-state {{
      grid-area: state;
      justify-self: end;
      color: var(--accent);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 11px;
      line-height: 1;
      text-transform: uppercase;
      white-space: nowrap;
    }}
    .profile-more {{
      border-left: 1px solid var(--line);
      position: relative;
    }}
    .profile-more summary {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 36px;
      min-height: 100%;
      list-style: none;
      cursor: pointer;
      color: var(--muted);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 15px;
      font-weight: 800;
      line-height: 1;
      letter-spacing: 0;
    }}
    .profile-more summary::-webkit-details-marker {{
      display: none;
    }}
    .profile-more summary:hover,
    .profile-more[open] summary {{
      color: var(--bright);
      background: rgba(184, 150, 90, .08);
    }}
    .profile-more-panel {{
      grid-column: 1 / -1;
      border-top: 1px solid var(--line);
      padding: 12px;
      background: rgba(18, 18, 15, .58);
    }}
    .profile-more:not([open]) + .profile-more-panel {{
      display: none;
    }}
    .profile-more-panel dl {{
      grid-template-columns: 86px 1fr;
      margin: 0 0 10px;
    }}
    .profile-note {{
      margin: 0 !important;
      min-height: 0;
      color: var(--muted);
      font-size: 13px;
    }}
    .settings-list {{
      display: grid;
      gap: 10px;
    }}
    .settings-list div {{
      display: grid;
      gap: 3px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--line);
    }}
    .settings-list span {{
      color: var(--muted);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      text-transform: uppercase;
    }}
    .settings-list strong {{
      color: var(--text);
      font-weight: 500;
      overflow-wrap: anywhere;
    }}
    .banner {{
      border: 1px solid var(--line-strong);
      padding: 10px 12px;
      margin-bottom: 12px;
      background: var(--panel-strong);
    }}
    .banner.notice {{
      color: var(--ok);
      border-color: var(--ok-line);
      background: var(--ok-bg);
    }}
    .banner.error {{
      color: var(--bad);
      border-color: var(--bad-line);
      background: var(--bad-bg);
    }}
    .quiet {{
      color: var(--muted);
      margin: 14px 0 0;
    }}
    table {{
      width: 100%;
      min-width: 860px;
      border-collapse: collapse;
    }}
    .logs-table {{
      min-width: 1180px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 12px 14px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background: var(--panel-strong);
      color: var(--accent);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    .sortable-heading {{
      display: inline-flex;
      flex-direction: column;
      align-items: flex-start;
      gap: 8px;
      min-width: 0;
    }}
    .order-label {{
      white-space: nowrap;
    }}
    .order-buttons {{
      display: inline-flex;
      gap: 6px;
    }}
    .order-button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 30px;
      height: 20px;
      border: 1px solid var(--line-strong);
      color: var(--accent);
      background: transparent;
      text-decoration: none;
      font-size: 10px;
      line-height: 1;
      letter-spacing: 0;
      font-weight: 800;
    }}
    .order-button:hover,
    .order-button.active {{
      color: var(--bg);
      background: var(--accent);
      border-color: var(--accent);
    }}
    td.key, td.reference {{
      color: var(--accent);
      overflow-wrap: anywhere;
    }}
    td.value, td.message {{
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }}
    .primary-value a {{
      color: var(--bright);
      text-decoration: none;
      font-weight: 700;
    }}
    .primary-value a:hover {{
      color: var(--accent);
    }}
    time {{
      color: var(--muted);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      white-space: nowrap;
    }}
    .value-detail {{
      border: 1px solid var(--line);
      background: var(--panel);
      padding: 18px;
      margin-bottom: 18px;
      box-shadow: 8px 8px 0 var(--line);
    }}
    .value-detail-head {{
      display: flex;
      align-items: start;
      justify-content: space-between;
      gap: 18px;
      margin-bottom: 16px;
    }}
    .value-detail h2 {{
      margin: 6px 0 0;
      color: var(--bright);
      font-size: 28px;
      line-height: 1.12;
      overflow-wrap: anywhere;
    }}
    .empty {{
      color: var(--muted);
      text-align: center;
      padding: 48px 14px;
    }}
    .diagnostics-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
      margin-bottom: 16px;
    }}
    .component-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 16px;
    }}
    .status-card {{
      border: 1px solid var(--line);
      background: var(--panel);
      padding: 18px;
      box-shadow: 8px 8px 0 var(--line);
      min-height: 190px;
    }}
    .state-pill {{
      display: inline-flex;
      align-items: center;
      width: fit-content;
      margin: 10px 0 12px;
      border: 1px solid currentColor;
      padding: 7px 10px;
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      font-weight: 800;
      letter-spacing: 0;
      text-transform: uppercase;
    }}
    .state-pill::before {{
      content: "";
      display: inline-block;
      width: 8px;
      height: 8px;
      margin-right: 8px;
      background: currentColor;
      box-shadow: 0 0 16px currentColor;
    }}
    .status-card p {{
      color: var(--text);
      margin: 0 0 14px;
      overflow-wrap: anywhere;
    }}
    .status-label {{
      color: var(--accent);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      letter-spacing: 0;
      text-transform: uppercase;
    }}
    .status-healthy,
    .status-protected {{
      border-color: var(--ok-line);
      background:
        linear-gradient(135deg, var(--ok-bg), transparent 46%),
        var(--panel);
      box-shadow: 8px 8px 0 rgba(103, 197, 138, .16);
    }}
    .status-degraded,
    .status-bypassing,
    .status-config_required {{
      border-color: var(--warn-line);
      background:
        linear-gradient(135deg, var(--warn-bg), transparent 46%),
        var(--panel);
      box-shadow: 8px 8px 0 rgba(217, 185, 95, .16);
    }}
    .status-unhealthy,
    .status-blocked,
    .status-provider_down,
    .status-dam_down {{
      border-color: var(--bad-line);
      background:
        linear-gradient(135deg, var(--bad-bg), transparent 46%),
        var(--panel);
      box-shadow: 8px 8px 0 rgba(223, 120, 101, .16);
    }}
    .status-unknown {{
      border-color: var(--unknown-line);
      background:
        linear-gradient(135deg, var(--unknown-bg), transparent 46%),
        var(--panel);
      box-shadow: 8px 8px 0 rgba(157, 149, 136, .14);
    }}
    .state-healthy,
    .state-protected {{
      color: var(--ok);
      background: var(--ok-bg);
    }}
    .state-degraded,
    .state-bypassing,
    .state-config_required {{
      color: var(--warn);
      background: var(--warn-bg);
    }}
    .state-unhealthy,
    .state-blocked,
    .state-provider_down,
    .state-dam_down {{
      color: var(--bad);
      background: var(--bad-bg);
    }}
    .state-unknown {{
      color: var(--unknown);
      background: var(--unknown-bg);
    }}
    dl {{
      display: grid;
      grid-template-columns: 92px 1fr;
      gap: 6px 12px;
      margin: 14px 0 0;
    }}
    dt {{
      color: var(--muted);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    dd {{
      margin: 0;
      overflow-wrap: anywhere;
    }}
    .diagnostics-list {{
      margin: 14px 0 0;
      padding: 0;
      list-style: none;
    }}
    .diagnostics-list li {{
      border-top: 1px solid var(--line);
      padding-top: 10px;
      margin-top: 10px;
      color: var(--muted);
      overflow-wrap: anywhere;
    }}
    .diagnostics-list strong {{
      color: var(--accent);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    .inline-form {{
      display: inline;
      margin: 0;
    }}
    .action-cell {{
      white-space: nowrap;
    }}
    .action-button {{
      appearance: none;
      -webkit-appearance: none;
      border: 1px solid var(--line-strong);
      background: var(--panel-strong);
      color: var(--accent);
      padding: 6px 10px;
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0;
      text-transform: uppercase;
      cursor: pointer;
      box-shadow: 3px 3px 0 var(--line);
    }}
    .action-button:hover {{
      border-color: var(--accent);
      background: var(--accent);
      color: var(--bg);
    }}
    .action-button.danger {{
      color: var(--bad);
    }}
    .action-button.danger:hover {{
      border-color: var(--bad);
      background: var(--bad);
      color: var(--bg);
    }}
    .action-button:disabled {{
      cursor: not-allowed;
      color: var(--muted);
      background: transparent;
    }}
    .badge {{
      display: inline-block;
      border: 1px solid var(--line);
      padding: 3px 7px;
      margin-right: 8px;
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
    }}
    .badge.active-profile {{
      color: var(--accent);
      border-color: var(--accent);
    }}
    .badge.allowed {{
      color: var(--ok);
      border-color: var(--ok-line);
    }}
    body.tray-shell {{
      overflow-x: hidden;
    }}
    body.tray-shell main {{
      width: 100%;
      margin: 0;
      padding: 0 14px 14px;
    }}
    body.tray-shell .tray-quit {{
      display: inline-flex;
    }}
    body.tray-shell .brand-bar {{
      padding: 8px 14px;
      margin: 0 -14px 10px;
      gap: 10px;
    }}
    body.tray-shell .brand-copy,
    body.tray-shell .brand-out {{
      display: none;
    }}
    body.tray-shell nav {{
      gap: 2px;
      margin-bottom: 0;
      overflow: visible;
      padding-bottom: 0;
    }}
    body.tray-shell nav a {{
      flex: 0 0 auto;
      padding: 0 9px;
      font-size: 11px;
    }}
    body.tray-shell .nav-more summary {{
      min-width: 36px;
      padding: 0 8px;
    }}
    body.tray-shell header {{
      display: none;
    }}
    body.tray-shell .connect-hero,
    body.tray-shell .connect-section {{
      box-shadow: none;
    }}
    body.tray-shell .connect-hero {{
      padding: 16px;
      margin-bottom: 12px;
    }}
    body.tray-shell .connect-status {{
      display: grid;
      gap: 14px;
      margin-bottom: 14px;
    }}
    body.tray-shell .connect-state {{
      font-size: 34px;
    }}
    body.tray-shell .connect-button {{
      width: 112px;
      height: 112px;
      font-size: 13px;
      justify-self: start;
      box-shadow: 0 0 0 8px rgba(184, 150, 90, .12);
    }}
    body.tray-shell .connect-button.disconnect {{
      box-shadow: 0 0 0 8px rgba(223, 120, 101, .10);
    }}
    body.tray-shell .connect-facts {{
      grid-template-columns: 94px 1fr;
      font-size: 12px;
    }}
    body.tray-shell .setup-actions {{
      align-items: stretch;
    }}
    body.tray-shell .connect-grid {{
      grid-template-columns: 1fr;
      gap: 12px;
    }}
    body.tray-shell .connect-section {{
      padding: 0;
    }}
    body.tray-shell .profile-select-row {{
      padding: 10px 12px;
    }}
    body.tray-shell .profile-state {{
      display: none;
    }}
    body.tray-shell .settings-list strong {{
      font-size: 12px;
    }}
    @media (max-width: 720px) {{
      header {{ display: block; }}
      body.tray-shell header {{ display: none; }}
      .count {{ margin-top: 18px; }}
      th, td {{ padding: 10px 8px; font-size: 13px; }}
      .diagnostics-grid,
      .component-grid,
      .connect-grid {{ grid-template-columns: 1fr; }}
      .profile-state {{ display: none; }}
      .connect-status {{ display: grid; }}
      .connect-button {{ width: 132px; height: 132px; }}
    }}
  </style>
</head>
<body{body_class}>
  <main>
    <div class="brand-bar">
      <a class="brand-home" href="{brand_url}" target="_blank" rel="noopener noreferrer" aria-label="RPBLC home"{brand_tray_attrs}>
        <span class="brand-mark" aria-hidden="true"><span class="glyph bracket">[</span><span class="glyph letter">R</span><span class="glyph colon">:</span><span class="glyph bracket">]</span></span>
        <span class="brand-copy">privacy infrastructure</span>
      </a>
      <nav>
        <a class="{connect_class}" href="/connect">Connect</a>
        <a class="{settings_class}" href="/settings">Settings</a>
        <a class="{vault_class}" href="/vault">Vault</a>
        <a class="{allowed_class}" href="/allowed">Allowed</a>
        <details class="nav-more">
          <summary aria-label="More" title="More"><span class="chevron-mark" aria-hidden="true"></span></summary>
          <div class="nav-more-menu">
            <a class="{insights_class}" href="/logs">Insights</a>
            <a class="{doctor_class}" href="/doctor">Doctor</a>
            <a class="{diagnostics_class}" href="/diagnostics">Diagnostics</a>
          </div>
        </details>
      </nav>
      <div class="brand-actions">
        {tray_quit}
        <a class="brand-out" href="{brand_url}" target="_blank" rel="noopener noreferrer"{brand_tray_attrs}>RPBLC.com</a>
      </div>
    </div>
    <header>
      <div>
        <h1>{title}</h1>
        <div class="meta">{meta}</div>
      </div>
      <div class="count"><strong>{count}</strong> {count_label}</div>
    </header>
    <div class="{content_class}">
      {content}
    </div>
  </main>
  {confirm_script}
  {tray_script}
</body>
</html>"#,
        brand_url = RPBLC_HOME_URL,
        body_class = body_class,
        tray_quit = tray_quit,
        brand_tray_attrs = brand_tray_attrs,
        confirm_script = confirm_script,
        tray_script = tray_script,
        title = title,
        meta = meta,
        count = count,
        count_label = count_label,
        content = content,
        content_class = if active == "Connect" {
            "connect-surface"
        } else if active == "Settings" || title == "Vault Value" {
            "content-surface"
        } else {
            "table-wrap"
        },
        connect_class = if active == "Connect" { "active" } else { "" },
        settings_class = if active == "Settings" { "active" } else { "" },
        vault_class = if active == "Vault" { "active" } else { "" },
        insights_class = if active == "Logs" { "active" } else { "" },
        allowed_class = if active == "Allowed" { "active" } else { "" },
        doctor_class = if active == "Doctor" { "active" } else { "" },
        diagnostics_class = if active == "Diagnostics" {
            "active"
        } else {
            ""
        },
    )
}

fn render_vault_row(
    entry: &VaultEntry,
    active_consent: Option<&dam_consent::ConsentEntry>,
) -> String {
    let allowed_cell = match active_consent {
        Some(consent) => format!(
            concat!(
                "<span class=\"badge allowed\">allowed</span>",
                "<form class=\"inline-form\" method=\"post\" action=\"/consents/revoke\">",
                "<input type=\"hidden\" name=\"id\" value=\"{}\">",
                "<input type=\"hidden\" name=\"return_to\" value=\"/vault\">",
                "<button class=\"action-button danger\" type=\"submit\">Protect</button></form>"
            ),
            escape_html(&consent.id)
        ),
        None => format!(
            concat!(
                "<form class=\"inline-form\" method=\"post\" action=\"/consents/grant\">",
                "<input type=\"hidden\" name=\"vault_key\" value=\"{}\">",
                "<button class=\"action-button\" type=\"submit\">Allow</button></form>"
            ),
            escape_html(&entry.key)
        ),
    };
    let (kind, _) = vault_entry_kind_token(entry);
    let detail_url = format!("/vault/detail/{}", form_url_encode_component(&entry.key));

    format!(
        concat!(
            "<tr>",
            "<td class=\"value primary-value\"><a href=\"{}\" title=\"{}\">{}</a></td>",
            "<td>{}</td>",
            "<td>{}</td>",
            "<td class=\"action-cell\">{}</td>",
            "</tr>"
        ),
        escape_html(&detail_url),
        escape_html(&entry.key),
        escape_html(&entry.value),
        escape_html(&kind),
        render_time(entry.updated_at),
        allowed_cell
    )
}

fn vault_entry_kind_token(entry: &VaultEntry) -> (String, String) {
    dam_core::Reference::parse_key(&entry.key)
        .map(|reference| (reference.kind.tag().to_string(), reference.id))
        .unwrap_or_else(|| ("value".to_string(), entry.key.clone()))
}

fn render_vault_detail(
    entry: &VaultEntry,
    active_consent: Option<&dam_consent::ConsentEntry>,
    logs: &[LogEntry],
) -> String {
    let (kind, token) = vault_entry_kind_token(entry);
    let allowed_action = match active_consent {
        Some(consent) => format!(
            concat!(
                "<form method=\"post\" action=\"/consents/revoke\">",
                "<input type=\"hidden\" name=\"id\" value=\"{}\">",
                "<input type=\"hidden\" name=\"return_to\" value=\"/vault\">",
                "<button class=\"action-button danger\" type=\"submit\">Protect</button></form>"
            ),
            escape_html(&consent.id)
        ),
        None => format!(
            concat!(
                "<form method=\"post\" action=\"/consents/grant\">",
                "<input type=\"hidden\" name=\"vault_key\" value=\"{}\">",
                "<button class=\"action-button\" type=\"submit\">Allow</button></form>"
            ),
            escape_html(&entry.key)
        ),
    };
    let audit_rows = logs
        .iter()
        .filter(|log| log.reference.as_deref() == Some(entry.key.as_str()))
        .map(render_value_audit_row)
        .collect::<Vec<_>>();
    let audit = if audit_rows.is_empty() {
        "<tr><td class=\"empty\" colspan=\"4\">No audit events found for this token.</td></tr>"
            .to_string()
    } else {
        audit_rows.join("\n")
    };

    render_shell(
        "Vault Value",
        "Vault",
        "Value details",
        1,
        "value",
        &format!(
            r#"<section class="value-detail">
      <div class="value-detail-head">
        <div>
          <div class="status-label">{kind}</div>
          <h2>{value}</h2>
        </div>
        {allowed_action}
      </div>
      <dl>
        <dt>Token</dt><dd class="reference">{token}</dd>
        <dt>First Seen</dt><dd>{created}</dd>
        <dt>Last Seen</dt><dd>{updated}</dd>
        <dt>State</dt><dd>{allowed_state}</dd>
      </dl>
    </section>
    <section class="value-detail">
      <div class="section-title">Audit</div>
      <table class="data-table logs-table">
        <thead><tr><th>When</th><th>Event</th><th>Action</th><th>Message</th></tr></thead>
        <tbody>{audit}</tbody>
      </table>
    </section>"#,
            kind = escape_html(&kind),
            value = escape_html(&entry.value),
            allowed_action = allowed_action,
            token = escape_html(&token),
            created = render_time(entry.created_at),
            updated = render_time(entry.updated_at),
            allowed_state = if active_consent.is_some() {
                "Allowed through DAM"
            } else {
                "Protected"
            },
            audit = audit,
        ),
    )
}

fn render_value_audit_row(entry: &LogEntry) -> String {
    format!(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"message\">{}</td></tr>",
        render_time(entry.timestamp),
        escape_html(&entry.event_type),
        escape_optional(&entry.action),
        escape_html(&entry.message),
    )
}

fn render_consents(entries: &[dam_consent::ConsentEntry]) -> String {
    let now = unix_now_lossy();
    let rows = if entries.is_empty() {
        "<tr><td class=\"empty\" colspan=\"8\">Nothing allowed through.</td></tr>".to_string()
    } else {
        entries
            .iter()
            .map(|entry| render_consent_row(entry, now))
            .collect::<Vec<_>>()
            .join("\n")
    };

    render_shell(
        "Allowed Values",
        "Allowed",
        "Values currently allowed through DAM",
        entries.len(),
        "allowed",
        &format!(
            r#"<table class="data-table consents-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Status</th>
          <th>Kind</th>
          <th>Vault Key</th>
          <th>Created</th>
          <th>Expires</th>
          <th>Source</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>"#
        ),
    )
}

fn render_consents_disabled() -> String {
    render_shell(
        "Allowed Values",
        "Allowed",
        "Allowed values are disabled",
        0,
        "allowed",
        "<p class=\"empty\">Allowed values are disabled in the current config.</p>",
    )
}

fn render_consent_row(entry: &dam_consent::ConsentEntry, now: i64) -> String {
    let status = entry.status_at(now);
    let action = if status == "active" {
        format!(
            concat!(
                "<form class=\"inline-form\" method=\"post\" action=\"/consents/revoke\">",
                "<input type=\"hidden\" name=\"id\" value=\"{}\">",
                "<input type=\"hidden\" name=\"return_to\" value=\"/allowed\">",
                "<button class=\"action-button danger\" type=\"submit\">Protect</button></form>"
            ),
            escape_html(&entry.id)
        )
    } else {
        String::new()
    };

    format!(
        concat!(
            "<tr><td class=\"key\">{}</td><td><span class=\"badge\">{}</span></td>",
            "<td>{}</td><td class=\"key\">{}</td><td>{}</td><td>{}</td>",
            "<td>{}</td><td class=\"action-cell\">{}</td></tr>"
        ),
        escape_html(&entry.id),
        escape_html(status),
        escape_html(entry.kind.tag()),
        escape_optional(&entry.vault_key),
        render_time(entry.created_at),
        render_time(entry.expires_at),
        escape_html(&entry.created_by),
        action
    )
}

fn render_log_row(entry: &LogEntry) -> String {
    format!(
        concat!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>",
            "<td>{}</td><td>{}</td><td class=\"reference\">{}</td>",
            "<td>{}</td><td class=\"message\">{}</td></tr>"
        ),
        entry.id,
        escape_html(&format_unix_secs(entry.timestamp)),
        escape_html(&entry.level),
        escape_html(&entry.event_type),
        escape_html(&entry.operation_id),
        escape_optional(&entry.kind),
        escape_optional(&entry.reference),
        escape_optional(&entry.action),
        escape_html(&entry.message)
    )
}

fn render_error(title: &str, message: &str) -> String {
    format!(
        "<!doctype html><title>{}</title><h1>{}</h1><pre>{}</pre>",
        escape_html(title),
        escape_html(title),
        escape_html(message)
    )
}

async fn proxy_report(
    config: &dam_config::DamConfig,
    client: &reqwest::Client,
) -> dam_api::ProxyReport {
    if !config.proxy.enabled {
        return dam_api::ProxyReport {
            operation_id: None,
            target: config
                .proxy
                .targets
                .first()
                .map(|target| target.name.clone()),
            upstream: config
                .proxy
                .targets
                .first()
                .map(|target| target.upstream.clone()),
            state: dam_api::ProxyState::ConfigRequired,
            message: "proxy is disabled".to_string(),
            diagnostics: vec![dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Warning,
                "proxy_disabled",
                "proxy is disabled in config",
            )],
        };
    }

    let health_url = format!("http://{}/health", config.proxy.listen);
    match client.get(&health_url).send().await {
        Ok(response) => match response.json::<dam_api::ProxyReport>().await {
            Ok(report) => report,
            Err(error) => dam_down_report(
                config,
                format!("DAM proxy returned unreadable health JSON: {error}"),
            ),
        },
        Err(error) => dam_down_report(
            config,
            format!("DAM proxy is not reachable at {health_url}: {error}"),
        ),
    }
}

fn build_config_report(config: &dam_config::DamConfig) -> dam_api::HealthReport {
    let mut components = Vec::new();
    let mut diagnostics = Vec::new();

    components.push(dam_api::ComponentHealth {
        component: "config".to_string(),
        state: dam_api::HealthState::Healthy,
        message: "config loaded".to_string(),
    });
    components.push(vault_component(config, &mut diagnostics));
    components.push(log_component(config, &mut diagnostics));
    components.push(proxy_component(config, &mut diagnostics));

    let state = if components
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
    };

    dam_api::HealthReport {
        state,
        components,
        diagnostics,
    }
}

fn redact_local_paths(report: &mut dam_api::HealthReport, config: &dam_config::DamConfig) {
    let paths = [
        config.vault.sqlite_path.display().to_string(),
        config.log.sqlite_path.display().to_string(),
        config.consent.sqlite_path.display().to_string(),
    ];
    for component in &mut report.components {
        component.message = redact_strings(&component.message, &paths);
    }
    for diagnostic in &mut report.diagnostics {
        diagnostic.message = redact_strings(&diagnostic.message, &paths);
    }
}

fn redact_strings(value: &str, needles: &[String]) -> String {
    needles
        .iter()
        .filter(|needle| !needle.is_empty())
        .fold(value.to_string(), |redacted, needle| {
            redacted.replace(needle, "[local sqlite path]")
        })
}

fn vault_component(
    config: &dam_config::DamConfig,
    diagnostics: &mut Vec<dam_api::Diagnostic>,
) -> dam_api::ComponentHealth {
    match config.vault.backend {
        dam_config::VaultBackend::Sqlite => dam_api::ComponentHealth {
            component: "vault".to_string(),
            state: dam_api::HealthState::Healthy,
            message: "sqlite vault configured".to_string(),
        },
        dam_config::VaultBackend::Remote => {
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Error,
                "remote_vault_not_implemented",
                "remote vault backend is not implemented in dam-web diagnostics yet",
            ));
            dam_api::ComponentHealth {
                component: "vault".to_string(),
                state: dam_api::HealthState::Unhealthy,
                message: "remote vault backend is not implemented".to_string(),
            }
        }
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
            message: "sqlite log configured".to_string(),
        },
        dam_config::LogBackend::Remote => {
            diagnostics.push(dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Error,
                "remote_log_not_implemented",
                "remote log backend is not implemented in dam-web diagnostics yet",
            ));
            dam_api::ComponentHealth {
                component: "log".to_string(),
                state: dam_api::HealthState::Unhealthy,
                message: "remote log backend is not implemented".to_string(),
            }
        }
        dam_config::LogBackend::None => unreachable!("none handled before backend match"),
    }
}

fn proxy_component(
    config: &dam_config::DamConfig,
    diagnostics: &mut Vec<dam_api::Diagnostic>,
) -> dam_api::ComponentHealth {
    if !config.proxy.enabled {
        return dam_api::ComponentHealth {
            component: "proxy".to_string(),
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
        if !matches!(target.provider.as_str(), "openai-compatible" | "anthropic") {
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
            component: "proxy".to_string(),
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
            component: "proxy".to_string(),
            state: dam_api::HealthState::Unhealthy,
            message: errors.join("; "),
        }
    }
}

fn dam_down_report(config: &dam_config::DamConfig, message: String) -> dam_api::ProxyReport {
    let target = config.proxy.targets.first();
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

fn render_component_card(component: &dam_api::ComponentHealth) -> String {
    format!(
        r#"<article class="status-card status-{state_class}">
      <div class="status-label">{component_name}</div>
      <div class="state-pill state-{state_class}">{state}</div>
      <p>{message}</p>
    </article>"#,
        state_class = escape_html(health_state_tag(component.state)),
        component_name = escape_html(&component.component),
        state = escape_html(health_state_tag(component.state)),
        message = escape_html(&component.message),
    )
}

fn render_diagnostic_list(diagnostics: &[dam_api::Diagnostic]) -> String {
    if diagnostics.is_empty() {
        return String::new();
    }

    let items = diagnostics
        .iter()
        .map(|diagnostic| {
            format!(
                "<li><strong>{} {}</strong><br>{}</li>",
                escape_html(severity_tag(diagnostic.severity)),
                escape_html(&diagnostic.code),
                escape_html(&diagnostic.message)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("<ul class=\"diagnostics-list\">{items}</ul>")
}

fn config_summary(state: dam_api::HealthState) -> &'static str {
    match state {
        dam_api::HealthState::Healthy => "config is healthy",
        dam_api::HealthState::Degraded => "config is usable with warnings",
        dam_api::HealthState::Unhealthy => "config has blocking issues",
        dam_api::HealthState::Unknown => "config health is unknown",
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

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(2_000))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn unix_now_lossy() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn parse_form(body: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Some((percent_decode(key)?, percent_decode(value)?))
        })
        .collect()
}

fn percent_decode(input: &str) -> Option<String> {
    let input = input.replace('+', " ");
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
            output.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            output.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(output).ok()
}

fn form_url_encode_component(input: &str) -> String {
    let mut output = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char);
            }
            b' ' => output.push('+'),
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

fn format_unix_secs(timestamp: i64) -> String {
    let days = timestamp.div_euclid(86_400);
    let seconds_of_day = timestamp.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

fn render_time(timestamp: i64) -> String {
    let absolute = format_unix_secs(timestamp);
    let relative = format_relative_unix_secs(timestamp, unix_now_lossy());
    format!(
        r#"<time datetime="{absolute}" title="{absolute}">{relative}</time>"#,
        absolute = escape_html(&absolute),
        relative = escape_html(&relative),
    )
}

fn format_relative_unix_secs(timestamp: i64, now: i64) -> String {
    if timestamp > now {
        let future = compact_duration(timestamp.saturating_sub(now));
        return if future == "now" {
            "now".to_string()
        } else {
            format!("in {future}")
        };
    }
    let delta = now.saturating_sub(timestamp).max(0);
    let past = compact_duration(delta);
    if past == "now" {
        past
    } else {
        format!("{past} ago")
    }
}

fn compact_duration(delta: i64) -> String {
    if delta < 5 {
        return "now".to_string();
    }
    if delta < 60 {
        return format!("{delta}s");
    }
    let minutes = delta / 60;
    if minutes < 60 {
        return format!("{minutes}m");
    }
    let hours = minutes / 60;
    if hours < 24 {
        return format!("{hours}h");
    }
    let days = hours / 24;
    if days < 30 {
        return format!("{days}d");
    }
    let months = days / 30;
    if months < 12 {
        return format!("{months}mo");
    }
    format!("{}y", days / 365)
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };

    (year, month, day)
}

fn escape_optional(input: &Option<String>) -> String {
    input.as_deref().map(escape_html).unwrap_or_default()
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn escape_js_string(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '<' => escaped.push_str("\\u003c"),
            '>' => escaped.push_str("\\u003e"),
            '&' => escaped.push_str("\\u0026"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_host_checks_reject_dns_rebinding_hosts() {
        assert!(is_local_host_value("127.0.0.1:2896"));
        assert!(is_local_host_value("localhost:2896"));
        assert!(is_local_host_value("[::1]:2896"));
        assert!(!is_local_host_value("attacker.example:2896"));
    }

    #[test]
    fn post_origin_checks_reject_cross_site_origins() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "http://127.0.0.1:2896".parse().unwrap());
        assert!(post_origin_is_local(&headers));

        headers.insert(header::ORIGIN, "https://attacker.example".parse().unwrap());
        assert!(!post_origin_is_local(&headers));
    }

    #[test]
    fn tray_post_token_allows_originless_tray_forms_only_with_match() {
        assert!(tray_post_token_is_valid(
            Some("tray_token=abc123"),
            Some("abc123")
        ));
        assert!(tray_post_token_is_valid(
            Some("notice=ok&tray_token=abc123"),
            Some("abc123")
        ));
        assert!(!tray_post_token_is_valid(
            Some("tray_token=wrong"),
            Some("abc123")
        ));
        assert!(!tray_post_token_is_valid(
            Some("tray_token=abc123"),
            Some("")
        ));
        assert!(!tray_post_token_is_valid(Some("tray_token=abc123"), None));
    }

    #[test]
    fn escape_js_string_prevents_script_breakout() {
        assert_eq!(
            escape_js_string("\"<tag>&\n"),
            "\\\"\\u003ctag\\u003e\\u0026\\n"
        );
    }

    #[test]
    fn parse_args_uses_defaults() {
        let cli = parse_args(Vec::new()).unwrap();

        assert_eq!(cli.config, dam_config::ConfigOverrides::default());
    }

    #[test]
    fn parse_args_accepts_config_db_log_and_addr() {
        let cli = parse_args([
            "--config".to_string(),
            "/tmp/dam.toml".to_string(),
            "--db".to_string(),
            "/tmp/vault.db".to_string(),
            "--log".to_string(),
            "/tmp/log.db".to_string(),
            "--addr".to_string(),
            "127.0.0.1:9000".to_string(),
        ])
        .unwrap();

        assert_eq!(cli.config.config_path, Some(PathBuf::from("/tmp/dam.toml")));
        assert_eq!(
            cli.config.vault_sqlite_path,
            Some(PathBuf::from("/tmp/vault.db"))
        );
        assert_eq!(
            cli.config.log_sqlite_path,
            Some(PathBuf::from("/tmp/log.db"))
        );
        assert_eq!(cli.config.web_addr, Some("127.0.0.1:9000".to_string()));
    }

    #[test]
    fn html_escaping_prevents_markup_injection() {
        assert_eq!(
            escape_html("<script>alert('x') & \"y\"</script>"),
            "&lt;script&gt;alert(&#39;x&#39;) &amp; &quot;y&quot;&lt;/script&gt;"
        );
    }

    #[test]
    fn unix_timestamps_render_as_utc_time() {
        assert_eq!(format_unix_secs(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_unix_secs(1), "1970-01-01 00:00:01 UTC");
        assert_eq!(format_unix_secs(1_741_146_096), "2025-03-05 03:41:36 UTC");
    }

    #[test]
    fn relative_times_render_compact_labels() {
        assert_eq!(format_relative_unix_secs(100, 102), "now");
        assert_eq!(format_relative_unix_secs(40, 100), "1m ago");
        assert_eq!(format_relative_unix_secs(100, 100 + 23 * 3_600), "23h ago");
        assert_eq!(format_relative_unix_secs(200, 100), "in 1m");
    }

    #[test]
    fn render_vault_escapes_entry_content() {
        let html = render_vault(
            &PathBuf::from("vault.db"),
            &[VaultEntry {
                key: "email:<alice>".to_string(),
                value: "<alice@example.com>".to_string(),
                created_at: 1,
                updated_at: 2,
            }],
        );

        assert!(html.contains("&lt;alice@example.com&gt;"));
        assert!(html.contains("title=\"1970-01-01 00:00:02 UTC\""));
        assert!(html.contains("href=\"/vault/detail/email%3A%3Calice%3E\""));
        assert!(!html.contains("<alice@example.com>"));
    }

    #[test]
    fn render_vault_includes_column_order_buttons() {
        let html = render_vault(&PathBuf::from("vault.db"), &[]);

        assert!(html.contains("aria-label=\"Sort Value ascending\""));
        assert!(html.contains("sortable-heading"));
        assert!(html.contains("order-label"));
        assert!(html.contains("href=\"/vault?sort=value&amp;dir=asc\""));
        assert!(html.contains("href=\"/vault?sort=updated&amp;dir=desc\""));
        assert!(html.contains("class=\"order-button active\""));
        assert!(html.contains("Allowed"));
    }

    #[test]
    fn render_vault_row_includes_grant_button() {
        let html = render_vault(
            &PathBuf::from("vault.db"),
            &[VaultEntry {
                key: "email:1111111111111111111111".to_string(),
                value: "alice@example.test".to_string(),
                created_at: 1,
                updated_at: 2,
            }],
        );

        assert!(html.contains("action=\"/consents/grant\""));
        assert!(html.contains("name=\"vault_key\""));
        assert!(html.contains("class=\"action-button\""));
    }

    #[test]
    fn render_vault_marks_duplicate_exact_value_as_active() {
        let first_reference = dam_core::Reference::generate(dam_core::SensitiveType::Email);
        let second_reference = dam_core::Reference::generate(dam_core::SensitiveType::Email);
        let entries = vec![
            VaultEntry {
                key: first_reference.key(),
                value: "alice@example.test".to_string(),
                created_at: 1,
                updated_at: 2,
            },
            VaultEntry {
                key: second_reference.key(),
                value: "alice@example.test".to_string(),
                created_at: 3,
                updated_at: 4,
            },
        ];
        let consents = vec![dam_consent::ConsentEntry {
            id: "consent_123".to_string(),
            kind: dam_core::SensitiveType::Email,
            value_fingerprint: dam_consent::fingerprint(
                dam_core::SensitiveType::Email,
                "alice@example.test",
            ),
            vault_key: Some(first_reference.key()),
            scope: "global".to_string(),
            created_at: 1,
            expires_at: unix_now_lossy() + 60,
            revoked_at: None,
            created_by: "test".to_string(),
            reason: None,
        }];

        let html = render_vault_with_order(
            &PathBuf::from("vault.db"),
            &entries,
            VaultOrder::default(),
            &consents,
        );

        assert_eq!(html.matches("action=\"/consents/revoke\"").count(), 2);
        assert!(html.contains("name=\"return_to\" value=\"/vault\""));
        assert!(!html.contains("action=\"/consents/grant\""));
    }

    #[test]
    fn render_consents_includes_revoke_button_for_active_entries() {
        let html = render_consents(&[dam_consent::ConsentEntry {
            id: "consent_123".to_string(),
            kind: dam_core::SensitiveType::Email,
            value_fingerprint: "fp".to_string(),
            vault_key: Some("email:1111111111111111111111".to_string()),
            scope: "global".to_string(),
            created_at: 1,
            expires_at: unix_now_lossy() + 60,
            revoked_at: None,
            created_by: "test".to_string(),
            reason: None,
        }]);

        assert!(html.contains("consent_123"));
        assert!(html.contains("action=\"/consents/revoke\""));
        assert!(html.contains("class=\"action-button danger\""));
        assert!(html.contains("name=\"return_to\" value=\"/allowed\""));
        assert!(html.contains("Protect"));
    }

    #[test]
    fn vault_entries_sort_by_selected_order() {
        let mut entries = vec![
            VaultEntry {
                key: "email:b".to_string(),
                value: "second@example.com".to_string(),
                created_at: 2,
                updated_at: 10,
            },
            VaultEntry {
                key: "email:a".to_string(),
                value: "first@example.com".to_string(),
                created_at: 1,
                updated_at: 20,
            },
        ];

        sort_vault_entries(
            &mut entries,
            VaultOrder {
                field: VaultSortField::Updated,
                direction: SortDirection::Desc,
            },
        );

        assert_eq!(entries[0].key, "email:a");
        assert_eq!(entries[1].key, "email:b");
    }

    #[test]
    fn render_shell_includes_rpblc_branding() {
        let html = render_vault(&PathBuf::from("vault.db"), &[]);

        assert!(html.contains("rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\""));
        assert!(html.contains("https://rpblc.com"));
        assert!(html.contains("RPBLC.com"));
        assert!(html.contains("privacy infrastructure"));
        assert!(html.contains("margin: 0 auto 42px;"));
        assert!(html.contains("padding: 0;\n    }\n    .brand-bar"));
        assert!(html.contains("padding: 6px 24px;"));
    }

    #[test]
    fn render_logs_escapes_entry_content() {
        let html = render_logs(
            &PathBuf::from("log.db"),
            &[LogEntry {
                id: 1,
                timestamp: 2,
                operation_id: "op-<1>".to_string(),
                level: "warn".to_string(),
                event_type: "redaction".to_string(),
                kind: Some("email".to_string()),
                reference: Some("email:<ref>".to_string()),
                action: Some("fallback_redacted".to_string()),
                message: "<no raw value>".to_string(),
            }],
        );

        assert!(html.contains("op-&lt;1&gt;"));
        assert!(html.contains("1970-01-01 00:00:02 UTC"));
        assert!(html.contains("email:&lt;ref&gt;"));
        assert!(html.contains("&lt;no raw value&gt;"));
        assert!(!html.contains("<no raw value>"));
    }

    #[test]
    fn render_logs_includes_column_order_buttons() {
        let html = render_logs(&PathBuf::from("log.db"), &[]);

        assert!(html.contains("aria-label=\"Sort ID descending\""));
        assert!(html.contains("sortable-heading"));
        assert!(html.contains("order-label"));
        assert!(html.contains("href=\"/logs?sort=id&amp;dir=desc\""));
        assert!(html.contains("href=\"/logs?sort=message&amp;dir=asc\""));
        assert!(html.contains("class=\"order-button active\""));
    }

    #[test]
    fn log_entries_sort_by_selected_order() {
        let mut entries = vec![
            LogEntry {
                id: 2,
                timestamp: 20,
                operation_id: "op-2".to_string(),
                level: "warn".to_string(),
                event_type: "proxy_forward".to_string(),
                kind: None,
                reference: None,
                action: None,
                message: "b message".to_string(),
            },
            LogEntry {
                id: 1,
                timestamp: 10,
                operation_id: "op-1".to_string(),
                level: "info".to_string(),
                event_type: "resolve".to_string(),
                kind: Some("email".to_string()),
                reference: Some("email:ref".to_string()),
                action: Some("resolved".to_string()),
                message: "a message".to_string(),
            },
        ];

        sort_log_entries(
            &mut entries,
            LogOrder {
                field: LogSortField::Message,
                direction: SortDirection::Asc,
            },
        );

        assert_eq!(entries[0].message, "a message");
        assert_eq!(entries[1].message, "b message");
    }

    #[test]
    fn render_diagnostics_shows_config_and_proxy_status() {
        let html = render_diagnostics(
            &dam_api::HealthReport {
                state: dam_api::HealthState::Degraded,
                components: vec![dam_api::ComponentHealth {
                    component: "proxy".to_string(),
                    state: dam_api::HealthState::Degraded,
                    message: "proxy is disabled".to_string(),
                }],
                diagnostics: vec![dam_api::Diagnostic::new(
                    dam_api::DiagnosticSeverity::Warning,
                    "proxy_disabled",
                    "proxy is disabled in config",
                )],
            },
            &dam_api::ProxyReport {
                operation_id: None,
                target: Some("openai".to_string()),
                upstream: Some("https://api.openai.com".to_string()),
                state: dam_api::ProxyState::ConfigRequired,
                message: "proxy is disabled".to_string(),
                diagnostics: Vec::new(),
            },
        );

        assert!(html.contains("DAM Diagnostics"));
        assert!(html.contains("Proxy Status"));
        assert!(html.contains("Config Check"));
        assert!(html.contains("config_required"));
        assert!(html.contains("proxy_disabled"));
        assert!(html.contains("status-config_required"));
        assert!(html.contains("state-config_required"));
        assert!(html.contains("status-degraded"));
        assert!(html.contains("state-degraded"));
        assert!(html.contains("DAM Diagnostics"));
    }

    #[test]
    fn render_doctor_shows_readiness_components() {
        let html = render_doctor(&dam_api::HealthReport {
            state: dam_api::HealthState::Degraded,
            components: vec![
                dam_api::ComponentHealth {
                    component: "router".to_string(),
                    state: dam_api::HealthState::Healthy,
                    message: "target openai routes to openai-compatible".to_string(),
                },
                dam_api::ComponentHealth {
                    component: "proxy_runtime".to_string(),
                    state: dam_api::HealthState::Degraded,
                    message: "proxy is not configured to run".to_string(),
                },
            ],
            diagnostics: vec![dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Warning,
                "router_config_required",
                "target requires auth",
            )],
        });

        assert!(html.contains("DAM Doctor"));
        assert!(html.contains("Overall Readiness"));
        assert!(html.contains("router"));
        assert!(html.contains("proxy_runtime"));
        assert!(html.contains("router_config_required"));
        assert!(html.contains("href=\"/doctor\""));
        assert!(html.contains("class=\"active\" href=\"/doctor\""));
    }

    #[test]
    fn redacts_local_sqlite_paths_from_web_health_reports() {
        let mut config = dam_config::DamConfig::default();
        config.vault.sqlite_path = PathBuf::from("/Users/example/.dam/vault.db");
        config.log.sqlite_path = PathBuf::from("/Users/example/.dam/log.db");
        config.consent.sqlite_path = PathBuf::from("/Users/example/.dam/consent.db");
        let mut report = dam_api::HealthReport {
            state: dam_api::HealthState::Healthy,
            components: vec![dam_api::ComponentHealth {
                component: "vault_runtime".to_string(),
                state: dam_api::HealthState::Healthy,
                message: "sqlite vault opens at /Users/example/.dam/vault.db".to_string(),
            }],
            diagnostics: vec![dam_api::Diagnostic::new(
                dam_api::DiagnosticSeverity::Error,
                "log_sqlite_unavailable",
                "sqlite log unavailable at /Users/example/.dam/log.db",
            )],
        };

        redact_local_paths(&mut report, &config);

        let rendered = format!("{report:?}");
        assert!(!rendered.contains("/Users/example/.dam"));
        assert!(rendered.contains("[local sqlite path]"));
    }

    #[test]
    fn render_connect_dashboard_shows_local_protection_controls() {
        let view = test_connect_dashboard(
            DashboardState::NeedsSetup,
            Some("claude-code"),
            Some(dam_integrations::IntegrationApplyStatus::NeedsApply),
        );

        let html = render_connect_dashboard(&view);

        assert!(html.contains("DAM Connect"));
        assert!(html.contains("Choose Profile") || html.contains("Needs Setup"));
        assert!(html.contains("class=\"connect-button\" type=\"submit\">Connect</button>"));
        assert!(html.contains("action=\"/connect/action\""));
        assert!(html.contains("Claude Code"));
        assert!(html.contains("<span class=\"toggle-title\">Apps</span>"));
        assert!(html.contains("<span class=\"toggle-value\">Claude Code</span>"));
        assert!(html.contains("<span class=\"toggle-chevron\" aria-hidden=\"true\"></span>"));
        assert!(html.contains("Next: Profile"));
        assert!(html.contains("href=\"/connect\""));
        assert!(html.contains("class=\"active\" href=\"/connect\""));
    }

    #[test]
    fn render_connect_dashboard_confirms_system_setup_from_primary_cta() {
        let mut view = test_connect_dashboard(DashboardState::NeedsSetup, None, None);
        if let Some(plan) = &mut view.setup_plan {
            plan.steps[1].status = dam_diagnostics::SetupStepStatus::Needed;
            plan.steps[1].message = "routing setup".to_string();
            plan.steps[1].command = Some(vec![
                "dam".to_string(),
                "network".to_string(),
                "install-system-proxy".to_string(),
                "--yes".to_string(),
            ]);
            plan.steps[1].requires_confirmation = true;
            plan.steps[1].changes_system = true;
        }

        let html = render_connect_dashboard(&view);

        assert!(html.contains("name=\"confirm_system_changes\" value=\"yes\""));
        assert!(
            html.contains("data-confirm=\"Allow DAM to update local network and trust settings?\"")
        );
        assert!(html.contains("Next: Routing"));
        assert!(html.contains("Connect</button>"));
    }

    #[test]
    fn connect_setup_action_applies_profile_before_daemon() {
        let plan = test_setup_plan(
            Some(dam_integrations::ActiveProfileState {
                profile_id: "claude-code".to_string(),
                selected_at_unix: 1,
            }),
            Some(dam_integrations::IntegrationApplyStatus::NeedsApply),
        );

        assert!(matches!(
            next_connect_setup_action(&plan),
            ConnectSetupAction::ApplyProfile
        ));
    }

    #[test]
    fn connect_setup_action_runs_routing_before_trust_and_daemon() {
        let mut plan = test_setup_plan(None, None);
        plan.steps[1].status = dam_diagnostics::SetupStepStatus::Needed;
        plan.steps[1].kind = dam_diagnostics::SetupStepKind::SystemProxy;
        plan.steps[1].command = Some(vec![
            "dam".to_string(),
            "network".to_string(),
            "install-system-proxy".to_string(),
            "--yes".to_string(),
        ]);
        plan.steps[2].status = dam_diagnostics::SetupStepStatus::Needed;
        plan.steps[2].kind = dam_diagnostics::SetupStepKind::LocalCa;
        plan.steps[2].command = Some(vec![
            "dam".to_string(),
            "trust".to_string(),
            "install-local-ca".to_string(),
            "--yes".to_string(),
        ]);

        match next_connect_setup_action(&plan) {
            ConnectSetupAction::RunSetupCommand(step) => {
                assert_eq!(step.kind, dam_diagnostics::SetupStepKind::SystemProxy);
            }
            action => panic!("unexpected setup action: {action:?}"),
        }
    }

    #[test]
    fn connect_setup_action_blocks_before_running_needed_steps() {
        let mut plan = test_setup_plan(None, None);
        plan.steps[1].status = dam_diagnostics::SetupStepStatus::Needed;
        plan.steps[2].status = dam_diagnostics::SetupStepStatus::Blocked;
        plan.steps[2].kind = dam_diagnostics::SetupStepKind::LocalCa;
        plan.steps[2].message = "trust needs review".to_string();

        match next_connect_setup_action(&plan) {
            ConnectSetupAction::Blocked(step) => {
                assert_eq!(step.kind, dam_diagnostics::SetupStepKind::LocalCa);
                assert_eq!(step.message, "trust needs review");
            }
            action => panic!("unexpected setup action: {action:?}"),
        }
    }

    #[test]
    fn connect_setup_action_runs_daemon_after_setup() {
        let plan = test_setup_plan(None, None);

        assert!(matches!(
            next_connect_setup_action(&plan),
            ConnectSetupAction::RunDaemon
        ));
    }

    #[test]
    fn render_connect_dashboard_blocks_modified_setup_one_click() {
        let mut view = test_connect_dashboard(
            DashboardState::Degraded,
            Some("claude-code"),
            Some(dam_integrations::IntegrationApplyStatus::Modified),
        );
        if let Some(apply) = &mut view.active_profile_apply {
            apply.rollback_available = true;
        }
        if let Some(card) = view.profiles.first_mut()
            && let Some(apply) = &mut card.apply
        {
            apply.rollback_available = true;
        }

        let html = render_connect_dashboard(&view);

        assert!(html.contains("Review Setup"));
        assert!(html.contains("Rollback"));
        assert!(!html.contains("name=\"action\" value=\"connect\""));
    }

    #[test]
    fn render_connect_dashboard_escapes_profile_messages() {
        let mut view = test_connect_dashboard(DashboardState::Disconnected, None, None);
        view.profiles[0].inspection_error = Some("<bad setup>".to_string());
        view.error = Some("<script>x</script>".to_string());

        let html = render_connect_dashboard(&view);

        assert!(html.contains("&lt;bad setup&gt;"));
        assert!(html.contains("&lt;script&gt;x&lt;/script&gt;"));
        assert!(!html.contains("<script>x</script>"));
    }

    #[test]
    fn render_shell_tray_mode_adds_quit_bridge() {
        let html = render_shell_with_mode(
            ShellMode::Tray,
            "DAM Connect",
            "Connect",
            "meta",
            0,
            "items",
            "<p>content</p>",
        );

        assert!(html.contains("<body class=\"tray-shell\">"));
        assert!(html.contains("data-tray-external=\"rpblc\""));
        assert!(html.contains("window.ipc.postMessage(message)"));
        assert!(html.contains("dam-tray:open-rpblc"));
        assert!(html.contains("dam-tray:connect"));
        assert!(html.contains("class=\"tray-quit\""));
        assert!(html.contains("aria-label=\"Quit DAM\""));
        assert!(html.contains(">⏻</button>"));
        assert!(html.contains(
            "<summary aria-label=\"More\" title=\"More\"><span class=\"chevron-mark\" aria-hidden=\"true\"></span></summary>"
        ));
        assert!(!html.contains(">More</summary>"));
        assert!(html.contains(
            "body.tray-shell nav {\n      gap: 2px;\n      margin-bottom: 0;\n      overflow: visible;"
        ));
        assert!(html.contains("dam-tray:quit"));
    }

    #[test]
    fn render_shell_browser_mode_omits_quit_bridge() {
        let html = render_shell_with_mode(
            ShellMode::Browser,
            "DAM Connect",
            "Connect",
            "meta",
            0,
            "items",
            "<p>content</p>",
        );

        assert!(!html.contains("class=\"tray-quit\""));
        assert!(!html.contains("data-tray-external=\"rpblc\""));
        assert!(!html.contains("dam-tray:open-rpblc"));
        assert!(!html.contains("dam-tray:connect"));
        assert!(!html.contains("dam-tray:quit"));
    }

    #[test]
    fn disconnect_restores_system_proxy_before_stopping_daemon() {
        assert_eq!(
            system_proxy_remove_args(),
            vec![
                "network".to_string(),
                "remove-system-proxy".to_string(),
                "--yes".to_string(),
            ]
        );
    }

    #[test]
    fn form_url_encode_component_encodes_notices() {
        assert_eq!(form_url_encode_component("DAM connected"), "DAM+connected");
        assert_eq!(form_url_encode_component("a/b?c"), "a%2Fb%3Fc");
    }

    #[test]
    fn favicon_uses_vendored_rpblc_public_asset_shape() {
        assert!(RPBLC_FAVICON_SVG.contains("viewBox=\"0 0 64 64\""));
        assert!(RPBLC_FAVICON_SVG.contains("font-family=\"'JetBrains Mono', monospace\""));
        assert!(RPBLC_FAVICON_SVG.contains("<tspan fill=\"#faf8f2\">R</tspan>"));
    }

    #[test]
    fn config_report_marks_default_proxy_as_degraded() {
        let report = build_config_report(&dam_config::DamConfig::default());

        assert_eq!(report.state, dam_api::HealthState::Degraded);
        assert!(report.components.iter().any(|component| {
            component.component == "proxy" && component.state == dam_api::HealthState::Degraded
        }));
    }

    #[test]
    fn config_report_accepts_anthropic_provider() {
        let mut config = dam_config::DamConfig::default();
        config.proxy.enabled = true;
        config.proxy.targets.push(dam_config::ProxyTargetConfig {
            name: "anthropic".to_string(),
            provider: "anthropic".to_string(),
            upstream: "https://api.anthropic.com".to_string(),
            failure_mode: None,
            api_key_env: None,
            api_key: None,
        });

        let report = build_config_report(&config);

        assert!(!report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "proxy_config_invalid"
                && diagnostic.message.contains("unsupported provider")
        }));
    }

    fn test_connect_dashboard(
        state: DashboardState,
        active_profile_id: Option<&str>,
        apply_status: Option<dam_integrations::IntegrationApplyStatus>,
    ) -> ConnectDashboard {
        let profile =
            dam_integrations::profile("claude-code", dam_integrations::DEFAULT_PROXY_URL).unwrap();
        let active_profile =
            active_profile_id.map(|profile_id| dam_integrations::ActiveProfileState {
                profile_id: profile_id.to_string(),
                selected_at_unix: 1,
            });
        let apply = apply_status.map(|status| dam_integrations::IntegrationApplyInspection {
            profile_id: "claude-code".to_string(),
            proxy_url: dam_integrations::DEFAULT_PROXY_URL.to_string(),
            target_path: PathBuf::from("/tmp/settings.json"),
            rollback_record_path: PathBuf::from("/tmp/latest.json"),
            status,
            planned_action: dam_integrations::FileAction::Create,
            rollback_available: false,
            record_error: None,
            message: "integration profile is not applied".to_string(),
        });
        ConnectDashboard {
            state,
            message: dashboard_message(state).to_string(),
            proxy_url: dam_integrations::DEFAULT_PROXY_URL.to_string(),
            daemon: None,
            proxy: None,
            setup_plan: Some(test_setup_plan(active_profile.clone(), apply_status)),
            setup_plan_error: None,
            active_profile_error: None,
            enabled_profiles: active_profile
                .as_ref()
                .map(|profile| {
                    vec![dam_integrations::EnabledIntegrationState {
                        profile_id: profile.profile_id.clone(),
                        enabled_at_unix: profile.selected_at_unix,
                    }]
                })
                .unwrap_or_default(),
            enabled_profiles_error: None,
            active_profile_apply: apply.clone(),
            profiles: vec![ProfileCard {
                profile,
                apply,
                inspection_error: None,
                active: active_profile_id == Some("claude-code"),
            }],
            notice: None,
            error: None,
        }
    }

    fn test_setup_plan(
        active_profile: Option<dam_integrations::ActiveProfileState>,
        apply_status: Option<dam_integrations::IntegrationApplyStatus>,
    ) -> dam_diagnostics::SetupPlan {
        let profile_step_status = match (active_profile.as_ref(), apply_status) {
            (None, _) => dam_diagnostics::SetupStepStatus::Skipped,
            (_, Some(dam_integrations::IntegrationApplyStatus::Modified)) => {
                dam_diagnostics::SetupStepStatus::Blocked
            }
            (_, Some(dam_integrations::IntegrationApplyStatus::NeedsApply)) => {
                dam_diagnostics::SetupStepStatus::Needed
            }
            (_, Some(dam_integrations::IntegrationApplyStatus::Applied)) => {
                dam_diagnostics::SetupStepStatus::Done
            }
            (_, None) => dam_diagnostics::SetupStepStatus::Blocked,
        };
        let state = if profile_step_status == dam_diagnostics::SetupStepStatus::Blocked {
            dam_diagnostics::SetupPlanState::Blocked
        } else if profile_step_status == dam_diagnostics::SetupStepStatus::Needed {
            dam_diagnostics::SetupPlanState::NeedsAction
        } else {
            dam_diagnostics::SetupPlanState::NeedsAction
        };
        dam_diagnostics::SetupPlan {
            state,
            message: "test setup plan".to_string(),
            state_dir: PathBuf::from("/tmp/dam-state"),
            integration_state_dir: PathBuf::from("/tmp/dam-state/integrations"),
            proxy_url: dam_integrations::DEFAULT_PROXY_URL.to_string(),
            network_mode: dam_net::CaptureMode::ExplicitProxy,
            trust_mode: dam_trust::TrustMode::Disabled,
            active_profile,
            steps: vec![
                dam_diagnostics::SetupStep {
                    kind: dam_diagnostics::SetupStepKind::ProfileApply,
                    status: profile_step_status,
                    message: "profile setup".to_string(),
                    command: if profile_step_status == dam_diagnostics::SetupStepStatus::Needed {
                        Some(vec![
                            "dam".to_string(),
                            "connect".to_string(),
                            "--apply".to_string(),
                        ])
                    } else {
                        None
                    },
                    requires_confirmation: false,
                    changes_system: false,
                },
                dam_diagnostics::SetupStep {
                    kind: dam_diagnostics::SetupStepKind::SystemProxy,
                    status: dam_diagnostics::SetupStepStatus::Skipped,
                    message: "routing skipped".to_string(),
                    command: None,
                    requires_confirmation: false,
                    changes_system: false,
                },
                dam_diagnostics::SetupStep {
                    kind: dam_diagnostics::SetupStepKind::LocalCa,
                    status: dam_diagnostics::SetupStepStatus::Skipped,
                    message: "trust skipped".to_string(),
                    command: None,
                    requires_confirmation: false,
                    changes_system: false,
                },
                dam_diagnostics::SetupStep {
                    kind: dam_diagnostics::SetupStepKind::Daemon,
                    status: dam_diagnostics::SetupStepStatus::Needed,
                    message: "daemon disconnected".to_string(),
                    command: Some(vec!["dam".to_string(), "connect".to_string()]),
                    requires_confirmation: false,
                    changes_system: false,
                },
            ],
        }
    }
}
