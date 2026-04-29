use axum::Router;
use axum::body::Bytes;
use axum::extract::Request;
use axum::extract::{Query, State};
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
    NeedsProfile,
}

#[derive(Debug, Clone)]
struct ConnectDashboard {
    state: DashboardState,
    message: String,
    proxy_url: String,
    daemon: Option<dam_daemon::DaemonState>,
    proxy: Option<dam_api::ProxyReport>,
    active_profile: Option<dam_integrations::ActiveProfileState>,
    active_profile_error: Option<String>,
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
        .route("/", get(index))
        .route("/logs", get(logs))
        .route("/consents", get(consents))
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

    if request.method() == Method::POST && !post_origin_is_local(request.headers()) {
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

async fn index(
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

async fn connect_dashboard(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let notice = params.get("notice").cloned();
    Html(render_connect_dashboard(
        &build_connect_dashboard(&state, notice, None).await,
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
        "clear_profile" => clear_active_profile().map(|_| "profile cleared".to_string()),
        "apply_profile" => apply_active_profile(&state).map(|_| "setup applied".to_string()),
        "rollback_profile" => rollback_active_profile().map(|_| "setup rolled back".to_string()),
        "connect" => run_dam_connect(&state)
            .await
            .map(|_| "DAM connected".to_string()),
        "disconnect" => disconnect_daemon().map(|_| "DAM disconnected".to_string()),
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
        Ok(_) => Redirect::to("/").into_response(),
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
    let report =
        dam_diagnostics::doctor_report(&state.config, &dam_diagnostics::DoctorOptions::default())
            .await;
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
    value
        .parse()
        .map_err(|_| format!("invalid web address: {value}"))
}

fn usage() -> &'static str {
    "Usage: dam-web [--config dam.toml] [--db vault.db] [--log log.db] [--addr 127.0.0.1:2896]"
}

impl Default for VaultOrder {
    fn default() -> Self {
        Self {
            field: VaultSortField::Key,
            direction: SortDirection::Asc,
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
        "/",
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
        "<tr><td class=\"empty\" colspan=\"5\">No vault entries found.</td></tr>".to_string()
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
        &format!("Database: {}", escape_html(&db_path.display().to_string())),
        entries.len(),
        "entries",
        &format!(
            r#"<table class="data-table vault-table">
      <thead>
        <tr>
          {key_header}
          {value_header}
          {created_header}
          {updated_header}
          <th>Consent</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>"#,
            key_header = render_vault_sort_header("Key", VaultSortField::Key, order),
            value_header = render_vault_sort_header("Value", VaultSortField::Value, order),
            created_header = render_vault_sort_header("Created", VaultSortField::Created, order),
            updated_header = render_vault_sort_header("Updated", VaultSortField::Updated, order),
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
        Some("/") => "/",
        _ => "/consents",
    }
}

async fn build_connect_dashboard(
    state: &AppState,
    notice: Option<String>,
    error: Option<String>,
) -> ConnectDashboard {
    let (active_profile, active_profile_error) = read_active_profile_for_web();
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
    let profiles = profile_cards(&proxy_url, active_profile.as_ref());
    let active_profile_apply = active_profile.as_ref().and_then(|active| {
        profiles
            .iter()
            .find(|card| card.profile.id == active.profile_id)
            .and_then(|card| card.apply.clone())
    });
    let active_profile_inspection_error = active_profile.as_ref().and_then(|active| {
        profiles
            .iter()
            .find(|card| card.profile.id == active.profile_id)
            .and_then(|card| card.inspection_error.clone())
    });
    let state_tag = if active_profile_inspection_error.is_some() {
        DashboardState::Degraded
    } else {
        dashboard_state(
            daemon.as_ref(),
            proxy.as_ref(),
            active_profile.as_ref(),
            active_profile_apply.as_ref(),
        )
    };
    let mut message = dashboard_message(state_tag).to_string();
    if let Some(error) = daemon_error
        .or(active_profile_error.clone())
        .or(active_profile_inspection_error)
    {
        message = error;
    }

    ConnectDashboard {
        state: state_tag,
        message,
        proxy_url,
        daemon,
        proxy,
        active_profile,
        active_profile_error,
        active_profile_apply,
        profiles,
        notice,
        error,
    }
}

fn profile_cards(
    proxy_url: &str,
    active_profile: Option<&dam_integrations::ActiveProfileState>,
) -> Vec<ProfileCard> {
    let state_dir = integration_state_dir();
    dam_integrations::profiles(proxy_url)
        .into_iter()
        .map(|profile| {
            let active = active_profile
                .map(|active| active.profile_id == profile.id)
                .unwrap_or(false);
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
    active_profile: Option<&dam_integrations::ActiveProfileState>,
    active_profile_apply: Option<&dam_integrations::IntegrationApplyInspection>,
) -> DashboardState {
    if active_profile.is_none() {
        return DashboardState::NeedsProfile;
    }
    if matches!(
        active_profile_apply.map(|apply| apply.status),
        Some(dam_integrations::IntegrationApplyStatus::NeedsApply)
    ) {
        return DashboardState::NeedsSetup;
    }
    if matches!(
        active_profile_apply.map(|apply| apply.status),
        Some(dam_integrations::IntegrationApplyStatus::Modified)
    ) {
        return DashboardState::Degraded;
    }
    match (daemon, proxy) {
        (Some(_), Some(report)) if report.state == dam_api::ProxyState::Protected => {
            DashboardState::Protected
        }
        (Some(_), _) => DashboardState::Degraded,
        (None, _) => DashboardState::Disconnected,
    }
}

fn dashboard_message(state: DashboardState) -> &'static str {
    match state {
        DashboardState::Protected => "AI traffic is routed through DAM",
        DashboardState::Disconnected => "Ready to connect",
        DashboardState::Degraded => "Attention needed before one-click protection",
        DashboardState::NeedsSetup => "Setup is needed before traffic can be protected",
        DashboardState::NeedsProfile => "Choose what DAM should protect",
    }
}

fn read_active_profile_for_web() -> (Option<dam_integrations::ActiveProfileState>, Option<String>) {
    match integration_state_dir()
        .and_then(|state_dir| dam_integrations::read_active_profile(&state_dir))
    {
        Ok(profile) => (profile, None),
        Err(error) => (None, Some(error)),
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

fn clear_active_profile() -> Result<(), String> {
    let state_dir = integration_state_dir()?;
    dam_integrations::clear_active_profile(&state_dir)?;
    Ok(())
}

fn apply_active_profile(state: &AppState) -> Result<(), String> {
    let state_dir = integration_state_dir()?;
    let active = dam_integrations::read_active_profile(&state_dir)?
        .ok_or_else(|| "select a profile before applying setup".to_string())?;
    let proxy_url = connected_proxy_url().unwrap_or_else(|| configured_proxy_url(&state.config));
    let target_path = default_integration_target_path(&active.profile_id, &state_dir)?;
    let inspection = dam_integrations::inspect_apply(
        &active.profile_id,
        &proxy_url,
        target_path.clone(),
        &state_dir,
    )?;
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
    let prepared = dam_integrations::prepare_apply(&active.profile_id, &proxy_url, target_path)?;
    dam_integrations::run_apply(prepared, false, &state_dir)?;
    Ok(())
}

fn rollback_active_profile() -> Result<(), String> {
    let state_dir = integration_state_dir()?;
    let active = dam_integrations::read_active_profile(&state_dir)?
        .ok_or_else(|| "select a profile before rolling back setup".to_string())?;
    dam_integrations::rollback_profile(&active.profile_id, &state_dir)?;
    Ok(())
}

async fn run_dam_connect(state: &AppState) -> Result<(), String> {
    if read_active_profile_for_web().0.is_none() {
        return Err("select a profile before connecting".to_string());
    }
    let mut args = vec!["connect".to_string(), "--apply".to_string()];
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
    run_dam_command(args).await
}

async fn run_dam_command(args: Vec<String>) -> Result<(), String> {
    let output = tokio::time::timeout(Duration::from_secs(15), async {
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
    let active_profile_id = view
        .active_profile
        .as_ref()
        .map(|profile| profile.profile_id.as_str())
        .unwrap_or("none");
    let apply_state = view
        .active_profile_apply
        .as_ref()
        .map(|apply| integration_apply_status_tag(apply.status))
        .unwrap_or("not_applied");
    let target_provider = view
        .daemon
        .as_ref()
        .and_then(|daemon| daemon.target_provider.as_deref())
        .or_else(|| {
            view.active_profile.as_ref().and_then(|active| {
                view.profiles
                    .iter()
                    .find(|card| card.profile.id == active.profile_id)
                    .map(|card| card.profile.provider.as_str())
            })
        })
        .unwrap_or("not selected");
    let upstream = view
        .daemon
        .as_ref()
        .and_then(|daemon| daemon.upstream.as_deref())
        .unwrap_or("selected by profile");
    let primary_action = render_primary_connect_action(view);
    let profile_cards = view
        .profiles
        .iter()
        .map(render_profile_card)
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
        .map(|message| render_banner("error", message))
        .unwrap_or_default();
    let diagnostics = render_dashboard_diagnostics(view);

    render_shell(
        "DAM Connect",
        "Connect",
        "One-click local protection for supported AI harnesses.",
        if view.active_profile.is_some() { 1 } else { 0 },
        "profile",
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
        <dt>Profile</dt><dd>{active_profile}</dd>
        <dt>Endpoint</dt><dd>{proxy_url}</dd>
        <dt>Provider</dt><dd>{provider}</dd>
        <dt>Upstream</dt><dd>{upstream}</dd>
        <dt>Setup</dt><dd>{apply_state}</dd>
      </dl>
      {setup_actions}
    </section>
    <section class="connect-grid">
      <div class="connect-section">
        <div class="section-title">Profiles</div>
        <div class="profile-grid">{profile_cards}</div>
      </div>
      <div class="connect-section">
        <div class="section-title">Settings</div>
        <div class="settings-list">
          <div><span>Vault</span><strong>{vault_path}</strong></div>
          <div><span>Log</span><strong>{log_path}</strong></div>
          <div><span>Inbound References</span><strong>{resolve_inbound}</strong></div>
          <div><span>DAM Binary</span><strong>{dam_bin}</strong></div>
        </div>
        {diagnostics}
      </div>
    </section>"#,
            state_class = escape_html(dashboard_state_class(view.state)),
            notice = notice,
            error = error,
            active_profile_warning = active_profile_warning,
            state_label = escape_html(dashboard_state_label(view.state)),
            message = escape_html(&view.message),
            primary_action = primary_action,
            active_profile = escape_html(active_profile_id),
            proxy_url = escape_html(&view.proxy_url),
            provider = escape_html(target_provider),
            upstream = escape_html(upstream),
            apply_state = escape_html(apply_state),
            setup_actions = setup_actions,
            profile_cards = profile_cards,
            vault_path = escape_html(&view_profile_vault_path(view)),
            log_path = escape_html(&view_profile_log_path(view)),
            resolve_inbound = escape_html(&view_profile_resolve_inbound(view)),
            dam_bin = escape_html(&dam_binary().to_string_lossy()),
            diagnostics = diagnostics,
        ),
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
    if view.active_profile.is_none() {
        return r#"<button class="connect-button" type="button" disabled>Choose Profile</button>"#
            .to_string();
    }
    if view.active_profile_apply.is_none() {
        return r#"<button class="connect-button" type="button" disabled>Review Setup</button>"#
            .to_string();
    }
    if matches!(
        view.active_profile_apply.as_ref().map(|apply| apply.status),
        Some(dam_integrations::IntegrationApplyStatus::Modified)
    ) {
        return r#"<button class="connect-button" type="button" disabled>Review Setup</button>"#
            .to_string();
    }
    concat!(
        r#"<form method="post" action="/connect/action">"#,
        r#"<input type="hidden" name="action" value="connect">"#,
        r#"<button class="connect-button" type="submit">Connect</button></form>"#
    )
    .to_string()
}

fn render_setup_actions(view: &ConnectDashboard) -> String {
    let Some(apply) = &view.active_profile_apply else {
        return String::new();
    };
    let apply_button = if apply.status == dam_integrations::IntegrationApplyStatus::Modified
        || apply.record_error.is_some()
    {
        r#"<button class="action-button" type="button" disabled>Apply Setup</button>"#.to_string()
    } else {
        concat!(
            r#"<form method="post" action="/connect/action">"#,
            r#"<input type="hidden" name="action" value="apply_profile">"#,
            r#"<button class="action-button" type="submit">Apply Setup</button></form>"#
        )
        .to_string()
    };
    let rollback_button = if apply.rollback_available {
        concat!(
            r#"<form method="post" action="/connect/action">"#,
            r#"<input type="hidden" name="action" value="rollback_profile">"#,
            r#"<button class="action-button danger" type="submit">Rollback</button></form>"#
        )
        .to_string()
    } else {
        String::new()
    };
    format!(
        r#"<div class="setup-actions">{apply_button}{rollback_button}<span>{target}</span></div>"#,
        apply_button = apply_button,
        rollback_button = rollback_button,
        target = escape_html(&apply.target_path.display().to_string()),
    )
}

fn render_profile_card(card: &ProfileCard) -> String {
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
    let active_badge = if card.active {
        r#"<span class="badge active-profile">active</span>"#
    } else {
        ""
    };
    let select_button = if card.active {
        r#"<button class="action-button" type="button" disabled>Selected</button>"#.to_string()
    } else {
        format!(
            concat!(
                r#"<form method="post" action="/connect/action">"#,
                r#"<input type="hidden" name="action" value="select_profile">"#,
                r#"<input type="hidden" name="profile_id" value="{profile_id}">"#,
                r#"<button class="action-button" type="submit">Select</button></form>"#
            ),
            profile_id = escape_html(&card.profile.id),
        )
    };

    format!(
        r#"<article class="profile-card {active_class}">
      <div class="profile-top">
        <div>
          <h2>{name}</h2>
          <p>{summary}</p>
        </div>
        {active_badge}
      </div>
      <dl>
        <dt>ID</dt><dd>{id}</dd>
        <dt>Provider</dt><dd>{provider}</dd>
        <dt>Setup</dt><dd>{apply_status}</dd>
      </dl>
      <p class="profile-note">{apply_message}</p>
      {select_button}
    </article>"#,
        active_class = if card.active { "selected" } else { "" },
        name = escape_html(&card.profile.name),
        summary = escape_html(&card.profile.summary),
        active_badge = active_badge,
        id = escape_html(&card.profile.id),
        provider = escape_html(&card.profile.provider),
        apply_status = escape_html(apply_status),
        apply_message = escape_html(apply_message),
        select_button = select_button,
    )
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
        DashboardState::NeedsProfile => "Choose Profile",
    }
}

fn dashboard_state_class(state: DashboardState) -> &'static str {
    match state {
        DashboardState::Protected => "protected",
        DashboardState::Disconnected => "unknown",
        DashboardState::Degraded => "degraded",
        DashboardState::NeedsSetup => "config_required",
        DashboardState::NeedsProfile => "unknown",
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
      margin: 42px auto;
    }}
    .brand-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 18px;
      border: 1px solid var(--line);
      background: rgba(18, 18, 15, .82);
      padding: 14px 18px;
      margin-bottom: 12px;
    }}
    .brand-home {{
      display: inline-flex;
      align-items: baseline;
      gap: 12px;
      color: inherit;
      text-decoration: none;
    }}
    .brand-mark {{
      display: inline-flex;
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 26px;
      font-weight: 800;
      letter-spacing: 0;
    }}
    .brand-mark .letter {{ color: var(--bright); }}
    .brand-mark .colon {{ color: var(--accent); }}
    .brand-mark .bracket {{ color: var(--soft); }}
    .brand-copy {{
      color: var(--muted);
      font-size: 13px;
    }}
    .brand-out {{
      color: var(--muted);
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      text-decoration: none;
      letter-spacing: 0;
      text-transform: uppercase;
    }}
    .brand-home:hover .brand-mark .letter,
    .brand-out:hover {{
      color: var(--accent);
    }}
    nav {{
      display: flex;
      gap: 10px;
      margin-bottom: 28px;
    }}
    nav a {{
      border: 1px solid var(--line);
      color: var(--muted);
      background: rgba(18, 18, 15, .72);
      padding: 9px 12px;
      text-decoration: none;
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      letter-spacing: 0;
      text-transform: uppercase;
    }}
    nav a.active {{
      background: var(--bg);
      color: var(--accent);
      border-color: var(--line-strong);
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
    .profile-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    .profile-card {{
      border: 1px solid var(--line);
      background: var(--panel-strong);
      padding: 14px;
    }}
    .profile-card.selected {{
      border-color: var(--accent);
    }}
    .profile-top {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
    }}
    .profile-card h2 {{
      margin: 0 0 6px;
      color: var(--bright);
      font-size: 18px;
      line-height: 1.15;
      letter-spacing: 0;
    }}
    .profile-card p {{
      margin: 0;
      color: var(--muted);
      font-size: 14px;
    }}
    .profile-card dl {{
      grid-template-columns: 86px 1fr;
      margin-bottom: 12px;
    }}
    .profile-note {{
      min-height: 42px;
      margin-bottom: 12px !important;
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
    @media (max-width: 720px) {{
      header {{ display: block; }}
      .count {{ margin-top: 18px; }}
      th, td {{ padding: 10px 8px; font-size: 13px; }}
      .diagnostics-grid,
      .component-grid,
      .connect-grid,
      .profile-grid {{ grid-template-columns: 1fr; }}
      .connect-status {{ display: grid; }}
      .connect-button {{ width: 132px; height: 132px; }}
    }}
  </style>
</head>
<body>
  <main>
    <div class="brand-bar">
      <a class="brand-home" href="{brand_url}" target="_blank" rel="noopener noreferrer" aria-label="RPBLC home">
        <span class="brand-mark" aria-hidden="true"><span class="bracket">[</span><span class="letter">R</span><span class="colon">:</span><span class="bracket">]</span></span>
        <span class="brand-copy">privacy infrastructure</span>
      </a>
      <a class="brand-out" href="{brand_url}" target="_blank" rel="noopener noreferrer">RPBLC.com</a>
    </div>
    <nav>
      <a class="{connect_class}" href="/connect">Connect</a>
      <a class="{vault_class}" href="/">Vault</a>
      <a class="{logs_class}" href="/logs">Logs</a>
      <a class="{consents_class}" href="/consents">Consents</a>
      <a class="{doctor_class}" href="/doctor">Doctor</a>
      <a class="{diagnostics_class}" href="/diagnostics">Diagnostics</a>
    </nav>
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
</body>
</html>"#,
        brand_url = RPBLC_HOME_URL,
        title = title,
        meta = meta,
        count = count,
        count_label = count_label,
        content = content,
        content_class = if active == "Connect" {
            "connect-surface"
        } else {
            "table-wrap"
        },
        connect_class = if active == "Connect" { "active" } else { "" },
        vault_class = if active == "Vault" { "active" } else { "" },
        logs_class = if active == "Logs" { "active" } else { "" },
        consents_class = if active == "Consents" { "active" } else { "" },
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
    let consent_cell = match active_consent {
        Some(consent) => format!(
            concat!(
                "<span class=\"badge\">active</span>",
                "<form class=\"inline-form\" method=\"post\" action=\"/consents/revoke\">",
                "<input type=\"hidden\" name=\"id\" value=\"{}\">",
                "<input type=\"hidden\" name=\"return_to\" value=\"/\">",
                "<button class=\"action-button danger\" type=\"submit\">Revoke</button></form>"
            ),
            escape_html(&consent.id)
        ),
        None => format!(
            concat!(
                "<form class=\"inline-form\" method=\"post\" action=\"/consents/grant\">",
                "<input type=\"hidden\" name=\"vault_key\" value=\"{}\">",
                "<button class=\"action-button\" type=\"submit\">Grant</button></form>"
            ),
            escape_html(&entry.key)
        ),
    };

    format!(
        "<tr><td class=\"key\">{}</td><td class=\"value\">{}</td><td>{}</td><td>{}</td><td class=\"action-cell\">{}</td></tr>",
        escape_html(&entry.key),
        escape_html(&entry.value),
        escape_html(&format_unix_secs(entry.created_at)),
        escape_html(&format_unix_secs(entry.updated_at)),
        consent_cell
    )
}

fn render_consents(entries: &[dam_consent::ConsentEntry]) -> String {
    let now = unix_now_lossy();
    let rows = if entries.is_empty() {
        "<tr><td class=\"empty\" colspan=\"8\">No consents found.</td></tr>".to_string()
    } else {
        entries
            .iter()
            .map(|entry| render_consent_row(entry, now))
            .collect::<Vec<_>>()
            .join("\n")
    };

    render_shell(
        "DAM Consents",
        "Consents",
        "Exact-value passthrough grants",
        entries.len(),
        "consents",
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
        "DAM Consents",
        "Consents",
        "Consent is disabled",
        0,
        "consents",
        "<p class=\"empty\">Consent storage is disabled in the current config.</p>",
    )
}

fn render_consent_row(entry: &dam_consent::ConsentEntry, now: i64) -> String {
    let status = entry.status_at(now);
    let action = if status == "active" {
        format!(
            concat!(
                "<form class=\"inline-form\" method=\"post\" action=\"/consents/revoke\">",
                "<input type=\"hidden\" name=\"id\" value=\"{}\">",
                "<input type=\"hidden\" name=\"return_to\" value=\"/consents\">",
                "<button class=\"action-button danger\" type=\"submit\">Revoke</button></form>"
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
        escape_html(&format_unix_secs(entry.created_at)),
        escape_html(&format_unix_secs(entry.expires_at)),
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
            message: format!("sqlite log path {}", config.log.sqlite_path.display()),
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

        assert!(html.contains("email:&lt;alice&gt;"));
        assert!(html.contains("&lt;alice@example.com&gt;"));
        assert!(html.contains("1970-01-01 00:00:01 UTC"));
        assert!(html.contains("1970-01-01 00:00:02 UTC"));
        assert!(!html.contains("<alice@example.com>"));
    }

    #[test]
    fn render_vault_includes_column_order_buttons() {
        let html = render_vault(&PathBuf::from("vault.db"), &[]);

        assert!(html.contains("aria-label=\"Sort Key ascending\""));
        assert!(html.contains("sortable-heading"));
        assert!(html.contains("order-label"));
        assert!(html.contains("href=\"/?sort=key&amp;dir=asc\""));
        assert!(html.contains("href=\"/?sort=updated&amp;dir=desc\""));
        assert!(html.contains("class=\"order-button active\""));
        assert!(html.contains("Consent"));
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
        assert!(html.contains("name=\"return_to\" value=\"/\""));
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
        assert!(html.contains("name=\"return_to\" value=\"/consents\""));
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
        assert!(html.contains("href=\"/diagnostics\""));
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
    fn render_connect_dashboard_shows_vpn_style_controls() {
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
        assert!(html.contains("Apply Setup"));
        assert!(html.contains("href=\"/connect\""));
        assert!(html.contains("class=\"active\" href=\"/connect\""));
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
        let mut view = test_connect_dashboard(DashboardState::NeedsProfile, None, None);
        view.profiles[0].inspection_error = Some("<bad setup>".to_string());
        view.error = Some("<script>x</script>".to_string());

        let html = render_connect_dashboard(&view);

        assert!(html.contains("&lt;bad setup&gt;"));
        assert!(html.contains("&lt;script&gt;x&lt;/script&gt;"));
        assert!(!html.contains("<script>x</script>"));
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
            active_profile,
            active_profile_error: None,
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
}
