use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:7828";
pub const CODEX_API_KEY_ENV: &str = "OPENAI_API_KEY";
pub const HTTPS_PROXY_ENV: &str = "HTTPS_PROXY";
pub const HTTP_PROXY_ENV: &str = "HTTP_PROXY";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationProfile {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub provider: String,
    #[serde(default)]
    pub traffic_app_ids: Vec<String>,
    pub connect_args: Vec<String>,
    pub settings: Vec<IntegrationSetting>,
    pub commands: Vec<IntegrationCommand>,
    pub notes: Vec<String>,
    pub automation: AutomationLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveProfileState {
    pub profile_id: String,
    pub selected_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnabledIntegrationState {
    pub profile_id: String,
    pub enabled_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnabledIntegrationsState {
    #[serde(default)]
    pub profiles: Vec<EnabledIntegrationState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationSetting {
    pub key: String,
    pub value: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationCommand {
    pub label: String,
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationLevel {
    Manual,
    ConnectPreset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct IntegrationApplyPlan {
    profile_id: String,
    profile_name: String,
    dry_run: bool,
    proxy_url: String,
    changes: Vec<IntegrationFileChange>,
    notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrationFileChange {
    pub path: PathBuf,
    pub action: FileAction,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAction {
    Create,
    Update,
    Unchanged,
    Delete,
    Restore,
}

impl FileAction {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Unchanged => "unchanged",
            Self::Delete => "delete",
            Self::Restore => "restore",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedIntegrationApply {
    pub profile_id: String,
    pub profile_name: String,
    pub proxy_url: String,
    pub target_path: PathBuf,
    desired_content: String,
    existed: bool,
    current_content: Option<String>,
    pub action: FileAction,
    pub description: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrationApplyResult {
    pub profile_id: String,
    pub dry_run: bool,
    pub proxy_url: String,
    pub changes: Vec<IntegrationFileChange>,
    pub record_path: Option<PathBuf>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrationRollbackResult {
    pub profile_id: String,
    pub changes: Vec<IntegrationFileChange>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrationApplyInspection {
    pub profile_id: String,
    pub proxy_url: String,
    pub target_path: PathBuf,
    pub rollback_record_path: PathBuf,
    pub status: IntegrationApplyStatus,
    pub planned_action: FileAction,
    pub rollback_available: bool,
    pub record_error: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationApplyStatus {
    Applied,
    NeedsApply,
    Modified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IntegrationApplyRecord {
    profile_id: String,
    applied_at_unix: u64,
    files: Vec<IntegrationBackupFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IntegrationBackupFile {
    path: PathBuf,
    existed: bool,
    backup_path: Option<PathBuf>,
}

pub fn profiles(proxy_url: &str) -> Vec<IntegrationProfile> {
    PROFILE_JSONS
        .iter()
        .map(|raw| {
            parse_profile_json(raw, proxy_url)
                .expect("bundled DAM integration profile JSON must be valid")
        })
        .collect()
}

pub fn profiles_from_state(
    proxy_url: &str,
    integration_state_dir: &Path,
) -> Result<Vec<IntegrationProfile>, String> {
    let mut profiles = profiles(proxy_url);
    for integration in read_stored_profile_files(integration_state_dir)? {
        upsert_profile(
            &mut profiles,
            render_profile_templates(integration, proxy_url),
        );
    }
    Ok(profiles)
}

pub fn profile(id: &str, proxy_url: &str) -> Option<IntegrationProfile> {
    profiles(proxy_url)
        .into_iter()
        .find(|profile| profile.id == id)
}

pub fn profile_from_state(
    id: &str,
    proxy_url: &str,
    integration_state_dir: &Path,
) -> Result<Option<IntegrationProfile>, String> {
    Ok(profiles_from_state(proxy_url, integration_state_dir)?
        .into_iter()
        .find(|profile| profile.id == id))
}

pub fn profile_ids() -> Vec<&'static str> {
    PROFILE_IDS.to_vec()
}

pub fn default_enabled_profile_ids() -> Vec<&'static str> {
    DEFAULT_ENABLED_PROFILE_IDS.to_vec()
}

fn upsert_profile(profiles: &mut Vec<IntegrationProfile>, profile: IntegrationProfile) {
    if let Some(existing) = profiles
        .iter_mut()
        .find(|existing| existing.id == profile.id)
    {
        *existing = profile;
    } else {
        profiles.push(profile);
    }
}

const PROFILE_IDS: &[&str] = &["claude-code", "codex"];

const DEFAULT_ENABLED_PROFILE_IDS: &[&str] = &["claude-code"];

const PROFILE_JSONS: &[&str] = &[
    include_str!("../profiles/claude-code.json"),
    include_str!("../profiles/codex.json"),
];

const PROFILE_DEFINITIONS_DIR: &str = "profiles";
const APPLY_RECORDS_DIR: &str = "apply-records";

pub fn profile_definitions_dir(integration_state_dir: &Path) -> PathBuf {
    integration_state_dir.join(PROFILE_DEFINITIONS_DIR)
}

pub fn profile_definition_path(integration_state_dir: &Path, id: &str) -> PathBuf {
    profile_definitions_dir(integration_state_dir).join(format!("{id}.json"))
}

pub fn ensure_bundled_profile_files(integration_state_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let dir = profile_definitions_dir(integration_state_dir);
    fs::create_dir_all(&dir).map_err(|error| {
        format!(
            "failed to create profile directory {}: {error}",
            dir.display()
        )
    })?;
    let mut written = Vec::new();
    for raw in PROFILE_JSONS {
        let profile = parse_profile_json(raw, DEFAULT_PROXY_URL)?;
        let path = dir.join(format!("{}.json", profile.id));
        if path.exists() {
            continue;
        }
        atomic_write(&path, format!("{}\n", raw.trim_end()).as_bytes())?;
        written.push(path);
    }
    Ok(written)
}

fn read_stored_profile_files(
    integration_state_dir: &Path,
) -> Result<Vec<IntegrationProfile>, String> {
    let mut files = Vec::new();
    let mut ids = BTreeSet::new();
    let dir = profile_definitions_dir(integration_state_dir);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(files),
        Err(error) => {
            return Err(format!(
                "failed to read profile directory {}: {error}",
                dir.display()
            ));
        }
    };
    let mut paths = entries
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| format!("failed to read profile entry: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    for path in paths {
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let raw = fs::read_to_string(&path)
            .map_err(|error| format!("failed to read profile {}: {error}", path.display()))?;
        let profile = serde_json::from_str::<IntegrationProfile>(&raw)
            .map_err(|error| format!("failed to parse profile {}: {error}", path.display()))?;
        validate_integration_profile(&profile)?;
        if !ids.insert(profile.id.clone()) {
            return Err(format!(
                "duplicate integration profile id {} in {}",
                profile.id,
                integration_state_dir.display()
            ));
        }
        files.push(profile);
    }
    Ok(files)
}

pub fn traffic_app_ids_for_profile_ids_from_state(
    profile_ids: &[String],
    integration_state_dir: &Path,
) -> Result<Vec<String>, String> {
    let mut app_ids = Vec::new();
    for profile_id in profile_ids {
        let profile = profile_from_state(profile_id, DEFAULT_PROXY_URL, integration_state_dir)?
            .ok_or_else(|| unknown_profile_error_with_state(profile_id, integration_state_dir))?;
        for app_id in profile.traffic_app_ids {
            if !app_ids.contains(&app_id) {
                app_ids.push(app_id);
            }
        }
    }
    Ok(app_ids)
}

fn validate_integration_profile(profile: &IntegrationProfile) -> Result<(), String> {
    if profile.id.trim().is_empty() {
        return Err("integration profile id is required".to_string());
    }
    if profile.name.trim().is_empty() {
        return Err(format!(
            "integration profile {} name is required",
            profile.id
        ));
    }
    if profile.provider.trim().is_empty() {
        return Err(format!(
            "integration profile {} provider is required",
            profile.id
        ));
    }
    Ok(())
}

fn default_enabled_integrations() -> Vec<EnabledIntegrationState> {
    DEFAULT_ENABLED_PROFILE_IDS
        .iter()
        .map(|profile_id| EnabledIntegrationState {
            profile_id: (*profile_id).to_string(),
            enabled_at_unix: 0,
        })
        .collect()
}

fn canonical_runtime_profile_id(profile_id: &str) -> Result<Option<String>, String> {
    if PROFILE_IDS.contains(&profile_id) {
        return Ok(Some(profile_id.to_string()));
    }
    match profile_id {
        "openai-compatible" | "codex-api" | "codex-chatgpt" => Ok(Some("codex".to_string())),
        "anthropic" => Ok(Some("claude-code".to_string())),
        "xai-compatible" => Ok(None),
        _ => Err(unknown_profile_error(profile_id)),
    }
}

fn push_dedup_enabled(
    profiles: &mut Vec<EnabledIntegrationState>,
    profile_id: String,
    enabled_at_unix: u64,
) {
    if !profiles
        .iter()
        .any(|profile| profile.profile_id == profile_id)
    {
        profiles.push(EnabledIntegrationState {
            profile_id,
            enabled_at_unix,
        });
    }
}

fn parse_profile_json(raw: &str, proxy_url: &str) -> Result<IntegrationProfile, String> {
    let profile = serde_json::from_str::<IntegrationProfile>(raw)
        .map_err(|error| format!("failed to parse integration profile JSON: {error}"))?;
    Ok(render_profile_templates(profile, proxy_url))
}

fn render_profile_templates(
    mut profile: IntegrationProfile,
    proxy_url: &str,
) -> IntegrationProfile {
    for setting in &mut profile.settings {
        setting.value = render_template(&setting.value, proxy_url);
    }
    for command in &mut profile.commands {
        for arg in &mut command.command {
            *arg = render_template(arg, proxy_url);
        }
    }
    for note in &mut profile.notes {
        *note = render_template(note, proxy_url);
    }
    profile
}

fn render_template(value: &str, proxy_url: &str) -> String {
    value
        .replace("{{proxy_url}}", proxy_url.trim_end_matches('/'))
        .replace("{{https_proxy_env}}", HTTPS_PROXY_ENV)
        .replace("{{http_proxy_env}}", HTTP_PROXY_ENV)
        .replace("{{codex_api_key_env}}", CODEX_API_KEY_ENV)
}

pub fn active_profile_path(integration_state_dir: &Path) -> PathBuf {
    integration_state_dir.join("active-profile.json")
}

pub fn enabled_integrations_path(integration_state_dir: &Path) -> PathBuf {
    integration_state_dir.join("enabled-integrations.json")
}

pub fn read_active_profile(
    integration_state_dir: &Path,
) -> Result<Option<ActiveProfileState>, String> {
    let path = active_profile_path(integration_state_dir);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "failed to read active profile {}: {error}",
                path.display()
            ));
        }
    };
    let state = serde_json::from_str::<ActiveProfileState>(&raw)
        .map_err(|error| format!("failed to parse active profile {}: {error}", path.display()))?;
    let Some(profile_id) = canonical_runtime_profile_id(&state.profile_id)? else {
        return Ok(None);
    };
    Ok(Some(ActiveProfileState {
        profile_id,
        selected_at_unix: state.selected_at_unix,
    }))
}

pub fn read_enabled_integrations(
    integration_state_dir: &Path,
) -> Result<Vec<EnabledIntegrationState>, String> {
    read_enabled_integrations_file(integration_state_dir)
        .map(|profiles| profiles.unwrap_or_default())
}

pub fn read_effective_enabled_integrations(
    integration_state_dir: &Path,
) -> Result<Vec<EnabledIntegrationState>, String> {
    read_runtime_enabled_integrations(integration_state_dir)
        .map(|profiles| profiles.unwrap_or_else(default_enabled_integrations))
}

pub fn read_runtime_enabled_integrations(
    integration_state_dir: &Path,
) -> Result<Option<Vec<EnabledIntegrationState>>, String> {
    if let Some(profiles) = read_enabled_integrations_file(integration_state_dir)? {
        return Ok(Some(profiles));
    }

    if let Some(active) = read_active_profile(integration_state_dir)? {
        return Ok(Some(vec![EnabledIntegrationState {
            profile_id: active.profile_id,
            enabled_at_unix: active.selected_at_unix,
        }]));
    }

    Ok(Some(default_enabled_integrations()))
}

pub fn enabled_profile_ids(integration_state_dir: &Path) -> Result<Vec<String>, String> {
    read_effective_enabled_integrations(integration_state_dir).map(|profiles| {
        profiles
            .into_iter()
            .map(|profile| profile.profile_id)
            .collect()
    })
}

pub fn runtime_enabled_profile_ids(
    integration_state_dir: &Path,
) -> Result<Option<Vec<String>>, String> {
    read_runtime_enabled_integrations(integration_state_dir).map(|profiles| {
        profiles.map(|profiles| {
            profiles
                .into_iter()
                .map(|profile| profile.profile_id)
                .collect()
        })
    })
}

pub fn traffic_app_ids_for_profile_ids(profile_ids: &[String]) -> Result<Vec<String>, String> {
    let mut app_ids = Vec::new();
    for profile_id in profile_ids {
        let profile = profile(profile_id, DEFAULT_PROXY_URL)
            .ok_or_else(|| unknown_profile_error(profile_id))?;
        for app_id in profile.traffic_app_ids {
            if !app_ids.contains(&app_id) {
                app_ids.push(app_id);
            }
        }
    }
    Ok(app_ids)
}

pub fn set_integration_enabled(
    profile_id: &str,
    enabled: bool,
    integration_state_dir: &Path,
) -> Result<Vec<EnabledIntegrationState>, String> {
    let Some(profile_id) = canonical_runtime_profile_id(profile_id)? else {
        return read_effective_enabled_integrations(integration_state_dir);
    };
    if profile_from_state(&profile_id, DEFAULT_PROXY_URL, integration_state_dir)?.is_none() {
        return Err(unknown_profile_error_with_state(
            &profile_id,
            integration_state_dir,
        ));
    }
    ensure_bundled_profile_files(integration_state_dir)?;

    fs::create_dir_all(integration_state_dir).map_err(|error| {
        format!(
            "failed to create integration state directory {}: {error}",
            integration_state_dir.display()
        )
    })?;

    let mut profiles = read_effective_enabled_integrations(integration_state_dir)?;
    profiles.retain(|profile| profile.profile_id != profile_id);
    if enabled {
        profiles.push(EnabledIntegrationState {
            profile_id,
            enabled_at_unix: unix_timestamp()?,
        });
    }
    write_enabled_integrations(integration_state_dir, profiles)
}

pub fn clear_enabled_integrations(integration_state_dir: &Path) -> Result<bool, String> {
    let path = enabled_integrations_path(integration_state_dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "failed to remove enabled integrations {}: {error}",
            path.display()
        )),
    }
}

pub fn set_active_profile(
    profile_id: &str,
    integration_state_dir: &Path,
) -> Result<ActiveProfileState, String> {
    let Some(profile_id) = canonical_runtime_profile_id(profile_id)? else {
        return Err(unknown_profile_error_with_state(
            profile_id,
            integration_state_dir,
        ));
    };
    if profile_from_state(&profile_id, DEFAULT_PROXY_URL, integration_state_dir)?.is_none() {
        return Err(unknown_profile_error_with_state(
            &profile_id,
            integration_state_dir,
        ));
    }
    ensure_bundled_profile_files(integration_state_dir)?;
    fs::create_dir_all(integration_state_dir).map_err(|error| {
        format!(
            "failed to create integration state directory {}: {error}",
            integration_state_dir.display()
        )
    })?;
    let state = ActiveProfileState {
        profile_id,
        selected_at_unix: unix_timestamp()?,
    };
    write_json_file(&active_profile_path(integration_state_dir), &state)?;
    Ok(state)
}

pub fn clear_active_profile(integration_state_dir: &Path) -> Result<bool, String> {
    let path = active_profile_path(integration_state_dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "failed to remove active profile {}: {error}",
            path.display()
        )),
    }
}

fn read_enabled_integrations_file(
    integration_state_dir: &Path,
) -> Result<Option<Vec<EnabledIntegrationState>>, String> {
    let path = enabled_integrations_path(integration_state_dir);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "failed to read enabled integrations {}: {error}",
                path.display()
            ));
        }
    };
    let state = serde_json::from_str::<EnabledIntegrationsState>(&raw).map_err(|error| {
        format!(
            "failed to parse enabled integrations {}: {error}",
            path.display()
        )
    })?;
    let mut profiles = Vec::new();
    for enabled in state.profiles {
        if let Some(profile_id) = canonical_runtime_profile_id(&enabled.profile_id)? {
            push_dedup_enabled(&mut profiles, profile_id, enabled.enabled_at_unix);
        }
    }
    Ok(Some(profiles))
}

fn write_enabled_integrations(
    integration_state_dir: &Path,
    profiles: Vec<EnabledIntegrationState>,
) -> Result<Vec<EnabledIntegrationState>, String> {
    let state = EnabledIntegrationsState { profiles };
    write_json_file(&enabled_integrations_path(integration_state_dir), &state)?;
    Ok(state.profiles)
}

pub fn default_apply_path(
    profile_id: &str,
    integration_state_dir: &Path,
    _codex_home: Option<PathBuf>,
    _home: Option<PathBuf>,
) -> Result<PathBuf, String> {
    if profile_from_state(profile_id, DEFAULT_PROXY_URL, integration_state_dir)?.is_some() {
        return Ok(profile_definition_path(integration_state_dir, profile_id));
    }
    Err(unknown_profile_error_with_state(
        profile_id,
        integration_state_dir,
    ))
}

pub fn prepare_apply(
    profile_id: &str,
    proxy_url: &str,
    target_path: PathBuf,
) -> Result<PreparedIntegrationApply, String> {
    let profile =
        profile(profile_id, proxy_url).ok_or_else(|| unknown_profile_error(profile_id))?;
    prepare_apply_for_profile(profile_id, profile, proxy_url, target_path)
}

pub fn prepare_apply_in_state(
    profile_id: &str,
    proxy_url: &str,
    target_path: PathBuf,
    integration_state_dir: &Path,
) -> Result<PreparedIntegrationApply, String> {
    if target_path == profile_definition_path(integration_state_dir, profile_id)
        && let Some((profile_id, profile_name, desired_content, notes)) =
            profile_catalog_apply_content(profile_id, integration_state_dir)?
    {
        return prepare_apply_for_content(
            profile_id.clone(),
            profile_name,
            proxy_url,
            target_path,
            desired_content,
            profile_apply_description(&profile_id),
            notes,
        );
    }
    let profile = profile_from_state(profile_id, proxy_url, integration_state_dir)?
        .ok_or_else(|| unknown_profile_error_with_state(profile_id, integration_state_dir))?;
    prepare_apply_for_profile(profile_id, profile, proxy_url, target_path)
}

fn profile_catalog_apply_content(
    profile_id: &str,
    integration_state_dir: &Path,
) -> Result<Option<(String, String, String, Vec<String>)>, String> {
    let path = profile_definition_path(integration_state_dir, profile_id);
    match fs::read_to_string(&path) {
        Ok(raw) => {
            let profile = serde_json::from_str::<IntegrationProfile>(&raw)
                .map_err(|error| format!("failed to parse profile {}: {error}", path.display()))?;
            validate_integration_profile(&profile)?;
            return Ok(Some((
                profile.id,
                profile.name,
                profile_file_content(&raw),
                profile.notes,
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("failed to read {}: {error}", path.display())),
    }

    for raw in PROFILE_JSONS {
        let profile = parse_profile_json(raw, DEFAULT_PROXY_URL)?;
        if profile.id == profile_id {
            return Ok(Some((
                profile.id,
                profile.name,
                profile_file_content(raw),
                profile.notes,
            )));
        }
    }

    Ok(None)
}

fn prepare_apply_for_profile(
    profile_id: &str,
    profile: IntegrationProfile,
    proxy_url: &str,
    target_path: PathBuf,
) -> Result<PreparedIntegrationApply, String> {
    let desired_content = integration_profile_content(&profile)?;
    prepare_apply_for_content(
        profile_id.to_string(),
        profile.name,
        proxy_url,
        target_path,
        desired_content,
        profile_apply_description(profile_id),
        profile.notes,
    )
}

fn prepare_apply_for_content(
    profile_id: String,
    profile_name: String,
    proxy_url: &str,
    target_path: PathBuf,
    desired_content: String,
    description: String,
    notes: Vec<String>,
) -> Result<PreparedIntegrationApply, String> {
    let (existed, current_content) = read_optional_file(&target_path)?;
    let action = match (
        existed,
        current_content.as_deref() == Some(desired_content.as_str()),
    ) {
        (_, true) => FileAction::Unchanged,
        (true, false) => FileAction::Update,
        (false, false) => FileAction::Create,
    };

    Ok(PreparedIntegrationApply {
        profile_id,
        profile_name,
        proxy_url: proxy_url.to_string(),
        target_path,
        desired_content,
        existed,
        current_content,
        action,
        description,
        notes,
    })
}

fn profile_apply_description(profile_id: &str) -> String {
    format!("write DAM-managed JSON profile {profile_id}")
}

pub fn run_apply(
    prepared: PreparedIntegrationApply,
    dry_run: bool,
    state_dir: &Path,
) -> Result<IntegrationApplyResult, String> {
    let changes = vec![IntegrationFileChange {
        path: prepared.target_path.clone(),
        action: prepared.action,
        description: prepared.description.clone(),
    }];
    if dry_run {
        let plan = IntegrationApplyPlan {
            profile_id: prepared.profile_id.clone(),
            profile_name: prepared.profile_name,
            dry_run,
            proxy_url: prepared.proxy_url.clone(),
            changes: changes.clone(),
            notes: prepared.notes,
        };
        return Ok(IntegrationApplyResult {
            profile_id: prepared.profile_id,
            dry_run,
            proxy_url: prepared.proxy_url,
            changes,
            record_path: None,
            message: render_apply_plan_message(&plan),
        });
    }

    let profile_dir = profile_state_dir(state_dir, &prepared.profile_id);
    let record_path = profile_dir.join("latest.json");
    let (rollback_available, record_error) =
        rollback_record_state(&prepared.profile_id, &record_path);
    if let Some(error) = record_error {
        return Err(format!(
            "refusing to apply {} because its rollback record needs attention: {error}",
            prepared.profile_id
        ));
    }
    if rollback_available {
        if prepared.action == FileAction::Unchanged {
            return Ok(IntegrationApplyResult {
                profile_id: prepared.profile_id,
                dry_run: false,
                proxy_url: prepared.proxy_url,
                changes,
                record_path: Some(record_path),
                message: "integration profile already applied".to_string(),
            });
        }
        return Err(format!(
            "refusing to apply {} because DAM already has a rollback record and the target changed; run `dam integrations rollback {}` before applying again",
            prepared.profile_id, prepared.profile_id
        ));
    }
    if prepared.action == FileAction::Unchanged {
        return Ok(IntegrationApplyResult {
            profile_id: prepared.profile_id,
            dry_run: false,
            proxy_url: prepared.proxy_url,
            changes,
            record_path: None,
            message:
                "integration profile content is already present; no rollback record was written"
                    .to_string(),
        });
    }

    fs::create_dir_all(&profile_dir).map_err(|error| {
        format!(
            "failed to create integration state directory {}: {error}",
            profile_dir.display()
        )
    })?;
    let applied_at_unix = unix_timestamp()?;
    let backup_dir = create_backup_dir(&profile_dir, applied_at_unix)?;

    let backup_path = if prepared.existed {
        let backup_path = backup_dir.join("target.backup");
        atomic_write(
            &backup_path,
            prepared.current_content.unwrap_or_default().as_bytes(),
        )?;
        Some(backup_path)
    } else {
        None
    };

    if let Some(parent) = prepared.target_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create target directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let record = IntegrationApplyRecord {
        profile_id: prepared.profile_id.clone(),
        applied_at_unix,
        files: vec![IntegrationBackupFile {
            path: prepared.target_path.clone(),
            existed: prepared.existed,
            backup_path,
        }],
    };
    write_json_file(&record_path, &record)?;
    atomic_write(&prepared.target_path, prepared.desired_content.as_bytes())?;

    Ok(IntegrationApplyResult {
        profile_id: prepared.profile_id,
        dry_run: false,
        proxy_url: prepared.proxy_url,
        changes,
        record_path: Some(record_path),
        message: "integration profile applied".to_string(),
    })
}

pub fn inspect_apply(
    profile_id: &str,
    proxy_url: &str,
    target_path: PathBuf,
    state_dir: &Path,
) -> Result<IntegrationApplyInspection, String> {
    let prepared = prepare_apply(profile_id, proxy_url, target_path)?;
    inspect_prepared_apply(prepared, profile_id, state_dir)
}

pub fn inspect_apply_in_state(
    profile_id: &str,
    proxy_url: &str,
    target_path: PathBuf,
    state_dir: &Path,
    integration_state_dir: &Path,
) -> Result<IntegrationApplyInspection, String> {
    let prepared =
        prepare_apply_in_state(profile_id, proxy_url, target_path, integration_state_dir)?;
    inspect_prepared_apply(prepared, profile_id, state_dir)
}

fn inspect_prepared_apply(
    prepared: PreparedIntegrationApply,
    profile_id: &str,
    state_dir: &Path,
) -> Result<IntegrationApplyInspection, String> {
    let record_path = profile_state_dir(state_dir, profile_id).join("latest.json");
    let (rollback_available, record_error) = rollback_record_state(profile_id, &record_path);
    let status = match (prepared.action, rollback_available, false) {
        (FileAction::Unchanged, _, _) => IntegrationApplyStatus::Applied,
        (_, true, false) => IntegrationApplyStatus::Modified,
        _ => IntegrationApplyStatus::NeedsApply,
    };
    let message = match (status, rollback_available, record_error.as_ref()) {
        (IntegrationApplyStatus::Applied, true, None) => {
            "integration profile is applied; rollback is available"
        }
        (IntegrationApplyStatus::Applied, false, None) => {
            "integration profile content is present; no DAM rollback record is available"
        }
        (IntegrationApplyStatus::Applied, false, Some(_)) => {
            "integration profile content is present; rollback record is unreadable"
        }
        (IntegrationApplyStatus::Applied, true, Some(_)) => {
            "integration profile content is present; rollback record needs attention"
        }
        (IntegrationApplyStatus::Modified, true, None) => {
            "integration profile was applied but target content no longer matches DAM's desired content"
        }
        (IntegrationApplyStatus::Modified, _, Some(_)) => {
            "integration profile target content changed and rollback record is unreadable"
        }
        (IntegrationApplyStatus::Modified, false, None) => {
            "integration profile target content does not match DAM's desired content"
        }
        (IntegrationApplyStatus::NeedsApply, true, None) => {
            "integration profile is not applied but rollback is available"
        }
        (IntegrationApplyStatus::NeedsApply, _, Some(_)) => {
            "integration profile is not applied and rollback record is unreadable"
        }
        (IntegrationApplyStatus::NeedsApply, _, None) => "integration profile is not applied",
    }
    .to_string();

    Ok(IntegrationApplyInspection {
        profile_id: prepared.profile_id,
        proxy_url: prepared.proxy_url,
        target_path: prepared.target_path,
        rollback_record_path: record_path,
        status,
        planned_action: prepared.action,
        rollback_available,
        record_error,
        message,
    })
}

pub fn rollback_profile(
    profile_id: &str,
    state_dir: &Path,
) -> Result<IntegrationRollbackResult, String> {
    let record_path = profile_state_dir(state_dir, profile_id).join("latest.json");
    let raw = fs::read_to_string(&record_path).map_err(|error| {
        format!(
            "failed to read rollback record for {profile_id} at {}: {error}",
            record_path.display()
        )
    })?;
    let record = serde_json::from_str::<IntegrationApplyRecord>(&raw).map_err(|error| {
        format!(
            "failed to parse rollback record {}: {error}",
            record_path.display()
        )
    })?;
    let mut changes = Vec::new();
    for file in &record.files {
        if file.existed {
            let backup_path = file.backup_path.as_ref().ok_or_else(|| {
                format!(
                    "rollback record for {} is missing backup path",
                    file.path.display()
                )
            })?;
            if let Some(parent) = file.path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent).map_err(|error| {
                    format!(
                        "failed to create restore directory {}: {error}",
                        parent.display()
                    )
                })?;
            }
            atomic_copy(backup_path, &file.path)?;
            changes.push(IntegrationFileChange {
                path: file.path.clone(),
                action: FileAction::Restore,
                description: "restore backup".to_string(),
            });
        } else {
            match fs::remove_file(&file.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "failed to remove created file {}: {error}",
                        file.path.display()
                    ));
                }
            }
            changes.push(IntegrationFileChange {
                path: file.path.clone(),
                action: FileAction::Delete,
                description: "remove file created by DAM".to_string(),
            });
        }
    }
    fs::remove_file(&record_path).map_err(|error| {
        format!(
            "failed to remove rollback record {}: {error}",
            record_path.display()
        )
    })?;

    Ok(IntegrationRollbackResult {
        profile_id: record.profile_id,
        changes,
        message: "integration profile rolled back".to_string(),
    })
}

pub fn profile_state_dir(state_dir: &Path, profile_id: &str) -> PathBuf {
    state_dir.join(APPLY_RECORDS_DIR).join(profile_id)
}

fn integration_profile_content(profile: &IntegrationProfile) -> Result<String, String> {
    serde_json::to_string_pretty(profile)
        .map(|json| format!("{json}\n"))
        .map_err(|error| {
            format!(
                "failed to serialize integration profile {}: {error}",
                profile.id
            )
        })
}

fn profile_file_content(raw: &str) -> String {
    format!("{}\n", raw.trim_end())
}

fn read_optional_file(path: &Path) -> Result<(bool, Option<String>), String> {
    match fs::read_to_string(path) {
        Ok(content) => Ok((true, Some(content))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((false, None)),
        Err(error) => Err(format!("failed to read {}: {error}", path.display())),
    }
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(value)
        .map_err(|error| format!("failed to serialize {}: {error}", path.display()))?;
    atomic_write(path, format!("{raw}\n").as_bytes())
}

fn create_backup_dir(profile_dir: &Path, applied_at_unix: u64) -> Result<PathBuf, String> {
    let backups_dir = profile_dir.join("backups");
    fs::create_dir_all(&backups_dir).map_err(|error| {
        format!(
            "failed to create backup directory {}: {error}",
            backups_dir.display()
        )
    })?;
    tempfile::Builder::new()
        .prefix(&format!("{applied_at_unix}-"))
        .tempdir_in(&backups_dir)
        .map(|dir| dir.keep())
        .map_err(|error| {
            format!(
                "failed to create backup directory in {}: {error}",
                backups_dir.display()
            )
        })
}

fn atomic_copy(source: &Path, target: &Path) -> Result<(), String> {
    let content = fs::read(source)
        .map_err(|error| format!("failed to read backup {}: {error}", source.display()))?;
    atomic_write(target, &content)
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let temp_dir = parent.unwrap_or_else(|| Path::new("."));
    if let Some(parent) = parent {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create directory {}: {error}", parent.display()))?;
    }
    let mut temp = tempfile::NamedTempFile::new_in(temp_dir).map_err(|error| {
        format!(
            "failed to create temporary file for {}: {error}",
            path.display()
        )
    })?;
    temp.write_all(content).map_err(|error| {
        format!(
            "failed to write temporary file for {}: {error}",
            path.display()
        )
    })?;
    temp.as_file_mut().sync_all().map_err(|error| {
        format!(
            "failed to sync temporary file for {}: {error}",
            path.display()
        )
    })?;
    temp.persist(path).map(|_| ()).map_err(|error| {
        format!(
            "failed to replace {} atomically: {}",
            path.display(),
            error.error
        )
    })
}

fn rollback_record_state(profile_id: &str, record_path: &Path) -> (bool, Option<String>) {
    match fs::read_to_string(record_path) {
        Ok(raw) => match serde_json::from_str::<IntegrationApplyRecord>(&raw) {
            Ok(record) if record.profile_id == profile_id => (true, None),
            Ok(record) => (
                false,
                Some(format!(
                    "rollback record profile id {} does not match {profile_id}",
                    record.profile_id
                )),
            ),
            Err(error) => (
                false,
                Some(format!(
                    "failed to parse rollback record {}: {error}",
                    record_path.display()
                )),
            ),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (false, None),
        Err(error) => (
            false,
            Some(format!(
                "failed to read rollback record {}: {error}",
                record_path.display()
            )),
        ),
    }
}

fn render_apply_plan_message(plan: &IntegrationApplyPlan) -> String {
    if plan
        .changes
        .iter()
        .all(|change| change.action == FileAction::Unchanged)
    {
        "integration profile already applied".to_string()
    } else if plan.dry_run {
        "dry run complete; no files changed".to_string()
    } else {
        "integration profile prepared".to_string()
    }
}

fn unix_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before unix epoch".to_string())
}

fn unknown_profile_error(profile_id: &str) -> String {
    format!(
        "unknown integration profile: {profile_id}\nknown profiles: {}",
        profile_ids().join(", ")
    )
}

fn unknown_profile_error_with_state(profile_id: &str, integration_state_dir: &Path) -> String {
    let mut ids = profile_ids()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if let Ok(profiles) = profiles_from_state(DEFAULT_PROXY_URL, integration_state_dir) {
        ids.extend(profiles.into_iter().map(|profile| profile.id));
    }
    ids.sort();
    ids.dedup();
    format!(
        "unknown integration profile: {profile_id}\nknown profiles: {}",
        ids.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_stable_profile_ids() {
        assert_eq!(profile_ids(), ["claude-code", "codex"]);
        assert_eq!(default_enabled_profile_ids(), ["claude-code"]);
    }

    #[test]
    fn claude_code_profile_uses_proxy_env_not_anthropic_base_url() {
        let profile = profile("claude-code", "http://127.0.0.1:7828/").unwrap();

        assert!(profile.connect_args.contains(&"--network-mode".to_string()));
        assert!(profile.connect_args.contains(&"tun".to_string()));
        assert!(profile.connect_args.contains(&"--trust-mode".to_string()));
        assert!(profile.connect_args.contains(&"local_ca".to_string()));
        assert_eq!(profile.traffic_app_ids, vec!["anthropic-api"]);
        assert_eq!(profile.settings[0].key, HTTPS_PROXY_ENV);
        assert_eq!(profile.settings[0].value, "http://127.0.0.1:7828");
        assert_eq!(profile.settings[1].key, HTTP_PROXY_ENV);
        assert!(
            !profile
                .settings
                .iter()
                .any(|setting| setting.key == "ANTHROPIC_BASE_URL")
        );
    }

    #[test]
    fn codex_profile_merges_api_and_subscription_traffic() {
        let profile = profile("codex", DEFAULT_PROXY_URL).unwrap();
        let command = &profile.commands[1].command;

        assert_eq!(profile.provider, "openai-compatible");
        assert!(profile.connect_args.contains(&"--network-mode".to_string()));
        assert!(profile.connect_args.contains(&"tun".to_string()));
        assert!(profile.connect_args.contains(&"--trust-mode".to_string()));
        assert!(profile.connect_args.contains(&"local_ca".to_string()));
        assert_eq!(profile.settings[0].key, HTTPS_PROXY_ENV);
        assert_eq!(profile.settings[1].key, HTTP_PROXY_ENV);
        assert_eq!(profile.traffic_app_ids, vec!["openai-api", "chatgpt-codex"]);
        assert!(command.contains(&format!("{HTTPS_PROXY_ENV}={DEFAULT_PROXY_URL}")));
        assert!(command.contains(&format!("{HTTP_PROXY_ENV}={DEFAULT_PROXY_URL}")));
        assert!(!command.iter().any(|arg| arg.contains("dam_openai")));
    }

    #[test]
    fn removed_profiles_are_not_visible_catalog_entries() {
        for profile_id in [
            "openai-compatible",
            "anthropic",
            "codex-api",
            "codex-chatgpt",
            "xai-compatible",
        ] {
            assert!(profile(profile_id, DEFAULT_PROXY_URL).is_none());
        }
    }

    #[test]
    fn codex_default_path_lives_under_integration_state() {
        let dir = tempfile::tempdir().unwrap();
        let integration_dir = dir.path().join("integrations");
        let path = default_apply_path("codex", &integration_dir, None, None).unwrap();

        assert_eq!(path, integration_dir.join("profiles").join("codex.json"));
    }

    #[test]
    fn claude_default_path_lives_under_profile_folder() {
        let dir = tempfile::tempdir().unwrap();
        let integration_dir = dir.path().join("integrations");
        let path = default_apply_path("claude-code", &integration_dir, None, None).unwrap();

        assert_eq!(
            path,
            integration_dir.join("profiles").join("claude-code.json")
        );
    }

    #[test]
    fn bundled_profile_files_are_seeded_as_json() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("integrations");

        let written = ensure_bundled_profile_files(&state_dir).unwrap();

        assert_eq!(written.len(), 2);
        for profile_id in ["claude-code", "codex"] {
            let path = profile_definition_path(&state_dir, profile_id);
            let raw = fs::read_to_string(path).unwrap();
            let profile: IntegrationProfile = serde_json::from_str(&raw).unwrap();
            assert_eq!(profile.id, profile_id);
        }
    }

    #[test]
    fn profiles_from_state_does_not_seed_profile_files() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("integrations");

        let profiles = profiles_from_state(DEFAULT_PROXY_URL, &state_dir).unwrap();

        assert_eq!(
            profiles
                .iter()
                .map(|profile| profile.id.as_str())
                .collect::<Vec<_>>(),
            vec!["claude-code", "codex"]
        );
        assert!(!state_dir.exists());
    }

    #[test]
    fn catalog_profile_file_is_already_applied_when_seeded() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("integrations");
        ensure_bundled_profile_files(&state_dir).unwrap();
        let target_path = profile_definition_path(&state_dir, "claude-code");

        let inspection = inspect_apply_in_state(
            "claude-code",
            DEFAULT_PROXY_URL,
            target_path,
            &state_dir,
            &state_dir,
        )
        .unwrap();

        assert_eq!(inspection.status, IntegrationApplyStatus::Applied);
        assert_eq!(inspection.planned_action, FileAction::Unchanged);
    }

    #[test]
    fn active_profile_state_roundtrips_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("integrations");

        assert_eq!(read_active_profile(&state_dir).unwrap(), None);

        let selected = set_active_profile("claude-code", &state_dir).unwrap();
        assert_eq!(selected.profile_id, "claude-code");
        assert_eq!(read_active_profile(&state_dir).unwrap(), Some(selected));

        assert!(clear_active_profile(&state_dir).unwrap());
        assert_eq!(read_active_profile(&state_dir).unwrap(), None);
        assert!(!clear_active_profile(&state_dir).unwrap());
    }

    #[test]
    fn active_profile_rejects_unknown_profile() {
        let dir = tempfile::tempdir().unwrap();
        let error = set_active_profile("missing", dir.path()).unwrap_err();

        assert!(error.contains("unknown integration profile: missing"));
    }

    #[test]
    fn enabled_integrations_roundtrip_and_fallback_to_active_profile() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("integrations");

        let active = set_active_profile("claude-code", &state_dir).unwrap();
        assert_eq!(
            read_effective_enabled_integrations(&state_dir).unwrap(),
            vec![EnabledIntegrationState {
                profile_id: "claude-code".to_string(),
                enabled_at_unix: active.selected_at_unix,
            }]
        );

        let enabled = set_integration_enabled("codex", true, &state_dir).unwrap();
        assert_eq!(
            enabled
                .iter()
                .map(|profile| profile.profile_id.as_str())
                .collect::<Vec<_>>(),
            vec!["claude-code", "codex"]
        );
        assert_eq!(
            enabled_profile_ids(&state_dir).unwrap(),
            vec!["claude-code".to_string(), "codex".to_string()]
        );

        let enabled = set_integration_enabled("claude-code", true, &state_dir).unwrap();
        assert_eq!(
            enabled
                .iter()
                .map(|profile| profile.profile_id.as_str())
                .collect::<Vec<_>>(),
            vec!["codex", "claude-code"]
        );

        let enabled = set_integration_enabled("codex", false, &state_dir).unwrap();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].profile_id, "claude-code");

        assert!(clear_enabled_integrations(&state_dir).unwrap());
        assert!(!clear_enabled_integrations(&state_dir).unwrap());
    }

    #[test]
    fn runtime_enabled_integrations_default_to_claude_code_only() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("integrations");

        assert_eq!(
            runtime_enabled_profile_ids(&state_dir).unwrap(),
            Some(vec!["claude-code".to_string()])
        );

        set_active_profile("claude-code", &state_dir).unwrap();
        assert_eq!(
            runtime_enabled_profile_ids(&state_dir).unwrap(),
            Some(vec!["claude-code".to_string()])
        );

        set_integration_enabled("claude-code", false, &state_dir).unwrap();
        assert_eq!(
            runtime_enabled_profile_ids(&state_dir).unwrap(),
            Some(Vec::new())
        );
        assert_eq!(
            traffic_app_ids_for_profile_ids(&["claude-code".to_string(), "codex".to_string()])
                .unwrap(),
            vec![
                "anthropic-api".to_string(),
                "openai-api".to_string(),
                "chatgpt-codex".to_string()
            ]
        );
    }

    #[test]
    fn retired_enabled_profile_ids_are_migrated_for_runtime_state() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("integrations");
        fs::create_dir_all(&state_dir).unwrap();
        write_json_file(
            &enabled_integrations_path(&state_dir),
            &EnabledIntegrationsState {
                profiles: vec![
                    EnabledIntegrationState {
                        profile_id: "openai-compatible".to_string(),
                        enabled_at_unix: 1,
                    },
                    EnabledIntegrationState {
                        profile_id: "codex-chatgpt".to_string(),
                        enabled_at_unix: 2,
                    },
                    EnabledIntegrationState {
                        profile_id: "anthropic".to_string(),
                        enabled_at_unix: 3,
                    },
                    EnabledIntegrationState {
                        profile_id: "xai-compatible".to_string(),
                        enabled_at_unix: 4,
                    },
                ],
            },
        )
        .unwrap();

        assert_eq!(
            runtime_enabled_profile_ids(&state_dir).unwrap(),
            Some(vec!["codex".to_string(), "claude-code".to_string()])
        );
    }

    #[test]
    fn enabled_integrations_reject_unknown_profile() {
        let dir = tempfile::tempdir().unwrap();
        let error = set_integration_enabled("missing", true, dir.path()).unwrap_err();

        assert!(error.contains("unknown integration profile: missing"));
    }

    #[test]
    fn codex_apply_writes_profile_json_and_rollback_restores_backup() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let profile_path = dir.path().join("codex.json");
        let original = "{\"id\":\"old-profile\"}\n";
        fs::write(&profile_path, original).unwrap();

        let prepared =
            prepare_apply("codex", "http://127.0.0.1:9000", profile_path.clone()).unwrap();
        let result = run_apply(prepared, false, &state_dir).unwrap();

        assert!(!result.dry_run);
        assert_eq!(result.changes[0].action, FileAction::Update);
        let applied = fs::read_to_string(&profile_path).unwrap();
        let profile: IntegrationProfile = serde_json::from_str(&applied).unwrap();
        assert_eq!(profile.id, "codex");
        assert_eq!(profile.traffic_app_ids, vec!["openai-api", "chatgpt-codex"]);
        assert_eq!(profile.settings[0].value, "http://127.0.0.1:9000");
        assert!(!applied.contains("dam_openai"));

        let rollback = rollback_profile("codex", &state_dir).unwrap();

        assert_eq!(rollback.changes[0].action, FileAction::Restore);
        assert_eq!(fs::read_to_string(&profile_path).unwrap(), original);
    }

    #[test]
    fn claude_code_apply_writes_profile_json_and_rollback_restores_backup() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let profile_path = dir.path().join("claude-code.json");
        let original = "{\"id\":\"old-profile\"}\n";
        fs::write(&profile_path, original).unwrap();

        let prepared = prepare_apply(
            "claude-code",
            "http://127.0.0.1:9000/",
            profile_path.clone(),
        )
        .unwrap();
        let result = run_apply(prepared, false, &state_dir).unwrap();

        assert_eq!(result.changes[0].action, FileAction::Update);
        let applied = fs::read_to_string(&profile_path).unwrap();
        let profile: IntegrationProfile = serde_json::from_str(&applied).unwrap();
        assert_eq!(profile.id, "claude-code");
        assert_eq!(profile.traffic_app_ids, vec!["anthropic-api"]);
        assert_eq!(profile.settings[0].value, "http://127.0.0.1:9000");
        assert_eq!(profile.settings[1].value, "http://127.0.0.1:9000");

        let rollback = rollback_profile("claude-code", &state_dir).unwrap();

        assert_eq!(rollback.changes[0].action, FileAction::Restore);
        assert_eq!(fs::read_to_string(&profile_path).unwrap(), original);
    }

    #[test]
    fn profile_apply_creates_json_file_and_rollback_deletes_it() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let profile_path = dir.path().join("codex.json");

        let prepared =
            prepare_apply("codex", "http://127.0.0.1:9000", profile_path.clone()).unwrap();
        let result = run_apply(prepared, false, &state_dir).unwrap();

        assert_eq!(result.changes[0].action, FileAction::Create);
        let applied = fs::read_to_string(&profile_path).unwrap();
        let profile: IntegrationProfile = serde_json::from_str(&applied).unwrap();
        assert_eq!(profile.id, "codex");
        assert_eq!(profile.settings[0].value, "http://127.0.0.1:9000");

        let rollback = rollback_profile("codex", &state_dir).unwrap();

        assert_eq!(rollback.changes[0].action, FileAction::Delete);
        assert!(!profile_path.exists());
    }

    #[test]
    fn inspect_apply_reports_missing_applied_and_modified_states() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let profile_path = dir.path().join("codex.json");

        let missing = inspect_apply(
            "codex",
            "http://127.0.0.1:9000",
            profile_path.clone(),
            &state_dir,
        )
        .unwrap();
        assert_eq!(missing.status, IntegrationApplyStatus::NeedsApply);
        assert_eq!(missing.planned_action, FileAction::Create);
        assert!(!missing.rollback_available);

        let prepared =
            prepare_apply("codex", "http://127.0.0.1:9000", profile_path.clone()).unwrap();
        run_apply(prepared, false, &state_dir).unwrap();

        let applied = inspect_apply(
            "codex",
            "http://127.0.0.1:9000",
            profile_path.clone(),
            &state_dir,
        )
        .unwrap();
        assert_eq!(applied.status, IntegrationApplyStatus::Applied);
        assert_eq!(applied.planned_action, FileAction::Unchanged);
        assert!(applied.rollback_available);

        fs::write(&profile_path, "{\"id\":\"changed\"}\n").unwrap();

        let modified =
            inspect_apply("codex", "http://127.0.0.1:9000", profile_path, &state_dir).unwrap();
        assert_eq!(modified.status, IntegrationApplyStatus::Modified);
        assert_eq!(modified.planned_action, FileAction::Update);
        assert!(modified.rollback_available);
    }

    #[test]
    fn run_apply_refuses_modified_target_with_existing_rollback_record() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let profile_path = dir.path().join("codex.json");

        let prepared =
            prepare_apply("codex", "http://127.0.0.1:9000", profile_path.clone()).unwrap();
        run_apply(prepared, false, &state_dir).unwrap();
        fs::write(&profile_path, "{\"id\":\"changed\"}\n").unwrap();

        let prepared = prepare_apply("codex", "http://127.0.0.1:9000", profile_path).unwrap();
        let error = run_apply(prepared, false, &state_dir).unwrap_err();

        assert!(error.contains("already has a rollback record"));
    }

    #[test]
    fn run_apply_does_not_rebackup_already_applied_target() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let profile_path = dir.path().join("codex.json");

        let prepared =
            prepare_apply("codex", "http://127.0.0.1:9000", profile_path.clone()).unwrap();
        run_apply(prepared, false, &state_dir).unwrap();
        let backups_dir = profile_state_dir(&state_dir, "codex").join("backups");
        let backup_count = fs::read_dir(&backups_dir).unwrap().count();

        let prepared = prepare_apply("codex", "http://127.0.0.1:9000", profile_path).unwrap();
        let result = run_apply(prepared, false, &state_dir).unwrap();

        assert_eq!(result.changes[0].action, FileAction::Unchanged);
        assert_eq!(fs::read_dir(backups_dir).unwrap().count(), backup_count);
    }

    #[test]
    fn inspect_apply_reports_unreadable_rollback_record() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let profile_path = dir.path().join("codex.json");
        let record_path = profile_state_dir(&state_dir, "codex").join("latest.json");
        fs::create_dir_all(record_path.parent().unwrap()).unwrap();
        fs::write(&record_path, "not json").unwrap();

        let report =
            inspect_apply("codex", "http://127.0.0.1:9000", profile_path, &state_dir).unwrap();

        assert_eq!(report.status, IntegrationApplyStatus::NeedsApply);
        assert!(!report.rollback_available);
        assert!(report.record_error.unwrap().contains("failed to parse"));
    }
}
