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
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const RPBLC_HOME_URL: &str = "https://rpblc.com";
const RPBLC_FAVICON_DATA_URI: &str = concat!(
    "data:image/svg+xml,",
    "%3Csvg viewBox='0 0 64 64' fill='none' xmlns='http://www.w3.org/2000/svg'%3E",
    "%3Crect x='1' y='1' width='62' height='62' rx='0' stroke='%23faf8f2' stroke-width='2'/%3E",
    "%3Ctext x='32' y='46' text-anchor='middle' font-family='JetBrains Mono, monospace' font-size='36' font-weight='700'%3E",
    "%3Ctspan fill='%233d3a32'%3E%5B%3C/tspan%3E",
    "%3Ctspan fill='%23faf8f2'%3ER%3C/tspan%3E",
    "%3Ctspan fill='%23B8965A'%3E%3A%3C/tspan%3E",
    "%3Ctspan fill='%233d3a32'%3E%5D%3C/tspan%3E",
    "%3C/text%3E%3C/svg%3E"
);

#[derive(Clone)]
struct AppState {
    vault: Arc<Vault>,
    consent_store: Option<Arc<dam_consent::ConsentStore>>,
    logs: Arc<LogStore>,
    config: Arc<dam_config::DamConfig>,
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
        .route("/", get(index))
        .route("/logs", get(logs))
        .route("/consents", get(consents))
        .route("/consents/grant", post(grant_consent))
        .route("/consents/revoke", post(revoke_consent))
        .route("/diagnostics", get(diagnostics))
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
  <link rel="icon" type="image/svg+xml" href="{favicon}">
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
      background:
        radial-gradient(circle at 16% 0%, rgba(184, 150, 90, .13), transparent 28rem),
        radial-gradient(circle at 90% 10%, rgba(61, 58, 50, .32), transparent 24rem),
        var(--bg);
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
      letter-spacing: .02em;
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
      letter-spacing: .04em;
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
      letter-spacing: .04em;
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
      letter-spacing: -0.07em;
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
      letter-spacing: .08em;
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
      letter-spacing: .08em;
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
      letter-spacing: .08em;
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
      letter-spacing: .06em;
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
      letter-spacing: .06em;
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
      letter-spacing: .06em;
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
    .badge {{
      display: inline-block;
      border: 1px solid var(--line);
      padding: 3px 7px;
      margin-right: 8px;
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
    }}
    @media (max-width: 720px) {{
      header {{ display: block; }}
      .count {{ margin-top: 18px; }}
      th, td {{ padding: 10px 8px; font-size: 13px; }}
      .diagnostics-grid,
      .component-grid {{ grid-template-columns: 1fr; }}
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
      <a class="{vault_class}" href="/">Vault</a>
      <a class="{logs_class}" href="/logs">Logs</a>
      <a class="{consents_class}" href="/consents">Consents</a>
      <a class="{diagnostics_class}" href="/diagnostics">Diagnostics</a>
    </nav>
    <header>
      <div>
        <h1>{title}</h1>
        <div class="meta">{meta}</div>
      </div>
      <div class="count"><strong>{count}</strong> {count_label}</div>
    </header>
    <div class="table-wrap">
      {content}
    </div>
  </main>
</body>
</html>"#,
        favicon = RPBLC_FAVICON_DATA_URI,
        brand_url = RPBLC_HOME_URL,
        title = title,
        meta = meta,
        count = count,
        count_label = count_label,
        content = content,
        vault_class = if active == "Vault" { "active" } else { "" },
        logs_class = if active == "Logs" { "active" } else { "" },
        consents_class = if active == "Consents" { "active" } else { "" },
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

        assert!(html.contains("rel=\"icon\" type=\"image/svg+xml\""));
        assert!(html.contains("data:image/svg+xml"));
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
}
