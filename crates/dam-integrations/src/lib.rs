use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:7828";
pub const CODEX_API_KEY_ENV: &str = "OPENAI_API_KEY";
pub const CLAUDE_BASE_URL_ENV: &str = "ANTHROPIC_BASE_URL";
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

pub fn profile(id: &str, proxy_url: &str) -> Option<IntegrationProfile> {
    profiles(proxy_url)
        .into_iter()
        .find(|profile| profile.id == id)
}

pub fn profile_ids() -> Vec<&'static str> {
    PROFILE_IDS.to_vec()
}

const PROFILE_IDS: &[&str] = &[
    "openai-compatible",
    "anthropic",
    "claude-code",
    "codex-api",
    "codex-chatgpt",
    "xai-compatible",
];

const PROFILE_JSONS: &[&str] = &[
    include_str!("../profiles/openai-compatible.json"),
    include_str!("../profiles/anthropic.json"),
    include_str!("../profiles/claude-code.json"),
    include_str!("../profiles/codex-api.json"),
    include_str!("../profiles/codex-chatgpt.json"),
    include_str!("../profiles/xai-compatible.json"),
];

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
    if profile(&state.profile_id, DEFAULT_PROXY_URL).is_none() {
        return Err(format!(
            "active profile {} is not a known integration profile\nknown profiles: {}",
            state.profile_id,
            profile_ids().join(", ")
        ));
    }
    Ok(Some(state))
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
        .map(|profiles| profiles.unwrap_or_default())
}

pub fn read_runtime_enabled_integrations(
    integration_state_dir: &Path,
) -> Result<Option<Vec<EnabledIntegrationState>>, String> {
    if let Some(profiles) = read_enabled_integrations_file(integration_state_dir)? {
        return Ok(Some(profiles));
    }

    Ok(read_active_profile(integration_state_dir)?.map(|active| {
        vec![EnabledIntegrationState {
            profile_id: active.profile_id,
            enabled_at_unix: active.selected_at_unix,
        }]
    }))
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
    if profile(profile_id, DEFAULT_PROXY_URL).is_none() {
        return Err(unknown_profile_error(profile_id));
    }

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
            profile_id: profile_id.to_string(),
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
    if profile(profile_id, DEFAULT_PROXY_URL).is_none() {
        return Err(unknown_profile_error(profile_id));
    }
    fs::create_dir_all(integration_state_dir).map_err(|error| {
        format!(
            "failed to create integration state directory {}: {error}",
            integration_state_dir.display()
        )
    })?;
    let state = ActiveProfileState {
        profile_id: profile_id.to_string(),
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
        if profile(&enabled.profile_id, DEFAULT_PROXY_URL).is_none() {
            return Err(format!(
                "enabled profile {} is not a known integration profile\nknown profiles: {}",
                enabled.profile_id,
                profile_ids().join(", ")
            ));
        }
        if !profiles
            .iter()
            .any(|profile: &EnabledIntegrationState| profile.profile_id == enabled.profile_id)
        {
            profiles.push(enabled);
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
    home: Option<PathBuf>,
) -> Result<PathBuf, String> {
    match profile_id {
        "claude-code" => claude_settings_path(home),
        _ if profile(profile_id, DEFAULT_PROXY_URL).is_some() => Ok(integration_state_dir
            .join("profiles")
            .join(format!("{profile_id}.env"))),
        _ => Err(unknown_profile_error(profile_id)),
    }
}

pub fn prepare_apply(
    profile_id: &str,
    proxy_url: &str,
    target_path: PathBuf,
) -> Result<PreparedIntegrationApply, String> {
    let profile =
        profile(profile_id, proxy_url).ok_or_else(|| unknown_profile_error(profile_id))?;
    let (existed, current_content) = read_optional_file(&target_path)?;
    let desired_content =
        desired_integration_content(profile_id, &profile, proxy_url, current_content.as_deref())?;
    let action = match (
        existed,
        current_content.as_deref() == Some(desired_content.as_str()),
    ) {
        (_, true) => FileAction::Unchanged,
        (true, false) => FileAction::Update,
        (false, false) => FileAction::Create,
    };
    let description = match profile_id {
        "claude-code" => "update Claude Code settings env with DAM proxy routing".to_string(),
        _ => "write DAM-managed proxy environment file for this profile".to_string(),
    };

    Ok(PreparedIntegrationApply {
        profile_id: profile.id,
        profile_name: profile.name,
        proxy_url: proxy_url.to_string(),
        target_path,
        desired_content,
        existed,
        current_content,
        action,
        description,
        notes: profile.notes,
    })
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
        if !allows_reapply_with_existing_record(&prepared) {
            return Err(format!(
                "refusing to apply {} because DAM already has a rollback record and the target changed; run `dam integrations rollback {}` before applying again",
                prepared.profile_id, prepared.profile_id
            ));
        }
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
    let record_path = profile_state_dir(state_dir, profile_id).join("latest.json");
    let (rollback_available, record_error) = rollback_record_state(profile_id, &record_path);
    let status = match (
        prepared.action,
        rollback_available,
        allows_reapply_with_existing_record(&prepared),
    ) {
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

fn allows_reapply_with_existing_record(prepared: &PreparedIntegrationApply) -> bool {
    prepared.profile_id == "claude-code"
        && prepared.current_content.as_deref().is_some_and(|content| {
            claude_settings_use_legacy_dam_base_url(content, &prepared.proxy_url)
        })
}

fn claude_settings_use_legacy_dam_base_url(current: &str, proxy_url: &str) -> bool {
    let Ok(settings) = serde_json::from_str::<Value>(current) else {
        return false;
    };
    let Some(env) = settings.get("env").and_then(Value::as_object) else {
        return false;
    };
    let Some(base_url) = env.get(CLAUDE_BASE_URL_ENV).and_then(Value::as_str) else {
        return false;
    };
    let base_url = base_url.trim_end_matches('/');
    base_url == proxy_url.trim_end_matches('/') || is_local_http_proxy_url(base_url)
}

fn is_local_http_proxy_url(value: &str) -> bool {
    value.starts_with("http://127.0.0.1:")
        || value.starts_with("http://localhost:")
        || value.starts_with("http://[::1]:")
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
    state_dir.join("profiles").join(profile_id)
}

fn proxy_env_settings(proxy_url: &str) -> Vec<IntegrationSetting> {
    let proxy_url = proxy_url.trim_end_matches('/').to_string();
    vec![
        IntegrationSetting {
            key: HTTPS_PROXY_ENV.to_string(),
            value: proxy_url.clone(),
            description: "HTTPS proxy for explicit-proxy fallback".to_string(),
        },
        IntegrationSetting {
            key: HTTP_PROXY_ENV.to_string(),
            value: proxy_url,
            description: "HTTP proxy for explicit-proxy fallback".to_string(),
        },
    ]
}

fn claude_settings_path(home: Option<PathBuf>) -> Result<PathBuf, String> {
    let home = home
        .filter(|home| !home.as_os_str().is_empty())
        .ok_or_else(|| "HOME is required to locate Claude Code settings".to_string())?;
    Ok(home.join(".claude").join("settings.json"))
}

fn desired_integration_content(
    profile_id: &str,
    profile: &IntegrationProfile,
    proxy_url: &str,
    current_content: Option<&str>,
) -> Result<String, String> {
    match profile_id {
        "claude-code" => claude_settings_content(current_content.unwrap_or_default(), proxy_url),
        _ => Ok(env_profile_content(profile)),
    }
}

fn claude_settings_content(current: &str, proxy_url: &str) -> Result<String, String> {
    let mut settings = if current.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str::<Value>(current)
            .map_err(|error| format!("failed to parse Claude Code settings JSON: {error}"))?
    };
    let settings_object = settings
        .as_object_mut()
        .ok_or_else(|| "Claude Code settings JSON root must be an object".to_string())?;
    let env = settings_object
        .entry("env")
        .or_insert_with(|| Value::Object(Map::new()));
    let env_object = env
        .as_object_mut()
        .ok_or_else(|| "Claude Code settings env value must be an object".to_string())?;
    env_object.remove(CLAUDE_BASE_URL_ENV);
    for setting in proxy_env_settings(proxy_url) {
        env_object.insert(setting.key, Value::String(setting.value));
    }
    serde_json::to_string_pretty(&settings)
        .map(|json| format!("{json}\n"))
        .map_err(|error| format!("failed to serialize Claude Code settings JSON: {error}"))
}

fn env_profile_content(profile: &IntegrationProfile) -> String {
    let mut output = String::new();
    output.push_str(&format!("# DAM integration profile: {}\n", profile.id));
    output.push_str("# Generated by `dam integrations apply`.\n");
    output
        .push_str("# Provider credentials stay with the harness; this file contains no secrets.\n");
    for setting in &profile.settings {
        output.push_str(&format!(
            "export {}={}\n",
            setting.key,
            shell_quote(&setting.value)
        ));
    }
    output
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

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':'))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn unknown_profile_error(profile_id: &str) -> String {
    format!(
        "unknown integration profile: {profile_id}\nknown profiles: {}",
        profile_ids().join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_stable_profile_ids() {
        assert_eq!(
            profile_ids(),
            [
                "openai-compatible",
                "anthropic",
                "claude-code",
                "codex-api",
                "codex-chatgpt",
                "xai-compatible"
            ]
        );
    }

    #[test]
    fn openai_profiles_use_proxy_env_not_base_url() {
        let profile = profile("openai-compatible", DEFAULT_PROXY_URL).unwrap();

        assert!(profile.connect_args.contains(&"--network-mode".to_string()));
        assert!(profile.connect_args.contains(&"tun".to_string()));
        assert!(profile.connect_args.contains(&"--trust-mode".to_string()));
        assert!(profile.connect_args.contains(&"local_ca".to_string()));
        assert_eq!(profile.traffic_app_ids, vec!["openai-api"]);
        assert_eq!(profile.settings[0].key, HTTPS_PROXY_ENV);
        assert_eq!(profile.settings[0].value, DEFAULT_PROXY_URL);
        assert_eq!(profile.settings[1].key, HTTP_PROXY_ENV);
        assert!(!profile.settings.iter().any(|setting| {
            matches!(
                setting.key.as_str(),
                "OPENAI_BASE_URL" | "ANTHROPIC_BASE_URL"
            )
        }));
    }

    #[test]
    fn anthropic_profiles_use_proxy_env_not_base_url() {
        let profile = profile("anthropic", "http://127.0.0.1:7828/").unwrap();

        assert!(profile.connect_args.contains(&"--network-mode".to_string()));
        assert!(profile.connect_args.contains(&"tun".to_string()));
        assert!(profile.connect_args.contains(&"--trust-mode".to_string()));
        assert!(profile.connect_args.contains(&"local_ca".to_string()));
        assert_eq!(profile.traffic_app_ids, vec!["anthropic-api"]);
        assert_eq!(profile.settings[0].key, HTTPS_PROXY_ENV);
        assert_eq!(profile.settings[0].value, DEFAULT_PROXY_URL);
        assert_eq!(profile.settings[1].key, HTTP_PROXY_ENV);
        assert!(!profile.settings.iter().any(|setting| {
            matches!(
                setting.key.as_str(),
                "OPENAI_BASE_URL" | "ANTHROPIC_BASE_URL"
            )
        }));
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
                .any(|setting| setting.key == CLAUDE_BASE_URL_ENV)
        );
    }

    #[test]
    fn xai_profile_supplies_connect_target_args() {
        let profile = profile("xai-compatible", DEFAULT_PROXY_URL).unwrap();

        assert_eq!(
            profile.connect_args,
            [
                "--target-name",
                "xai",
                "--provider",
                "openai-compatible",
                "--upstream",
                "https://api.x.ai",
                "--network-mode",
                "tun",
                "--trust-mode",
                "local_ca"
            ]
        );
        assert_eq!(profile.settings[0].key, HTTPS_PROXY_ENV);
        assert_eq!(profile.traffic_app_ids, vec!["xai-api"]);
    }

    #[test]
    fn codex_profile_uses_proxy_env_not_custom_provider() {
        let profile = profile("codex-api", DEFAULT_PROXY_URL).unwrap();
        let command = &profile.commands[1].command;

        assert_eq!(profile.settings[0].key, HTTPS_PROXY_ENV);
        assert_eq!(profile.settings[1].key, HTTP_PROXY_ENV);
        assert_eq!(profile.traffic_app_ids, vec!["openai-api"]);
        assert!(command.contains(&format!("{HTTPS_PROXY_ENV}={DEFAULT_PROXY_URL}")));
        assert!(command.contains(&format!("{HTTP_PROXY_ENV}={DEFAULT_PROXY_URL}")));
        assert!(!command.iter().any(|arg| arg.contains("dam_openai")));
    }

    #[test]
    fn codex_chatgpt_profile_targets_chatgpt_websocket_backend() {
        let profile = profile("codex-chatgpt", DEFAULT_PROXY_URL).unwrap();

        assert_eq!(profile.provider, "openai-compatible");
        assert_eq!(
            profile.connect_args,
            [
                "--target-name",
                "chatgpt-codex",
                "--provider",
                "openai-compatible",
                "--upstream",
                "https://chatgpt.com",
                "--network-mode",
                "tun",
                "--trust-mode",
                "local_ca"
            ]
        );
        assert!(profile.summary.contains("WebSocket"));
        assert_eq!(profile.settings[0].key, HTTPS_PROXY_ENV);
        assert_eq!(profile.traffic_app_ids, vec!["chatgpt-codex"]);
    }

    #[test]
    fn codex_default_path_lives_under_integration_state() {
        let path = default_apply_path(
            "codex-api",
            Path::new("/tmp/dam/integrations"),
            Some(PathBuf::from("/tmp/codex")),
            Some(PathBuf::from("/tmp/home")),
        )
        .unwrap();

        assert_eq!(
            path,
            PathBuf::from("/tmp/dam/integrations/profiles/codex-api.env")
        );
    }

    #[test]
    fn claude_default_path_uses_home_settings() {
        let path = default_apply_path(
            "claude-code",
            Path::new("/tmp/dam/integrations"),
            None,
            Some(PathBuf::from("/tmp/home")),
        )
        .unwrap();

        assert_eq!(path, PathBuf::from("/tmp/home/.claude/settings.json"));
    }

    #[test]
    fn generic_env_default_path_lives_under_integration_state() {
        let path = default_apply_path(
            "anthropic",
            Path::new("/tmp/dam/integrations"),
            None,
            Some(PathBuf::from("/tmp/home")),
        )
        .unwrap();

        assert_eq!(
            path,
            PathBuf::from("/tmp/dam/integrations/profiles/anthropic.env")
        );
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

        let enabled = set_integration_enabled("codex-api", true, &state_dir).unwrap();
        assert_eq!(
            enabled
                .iter()
                .map(|profile| profile.profile_id.as_str())
                .collect::<Vec<_>>(),
            vec!["claude-code", "codex-api"]
        );
        assert_eq!(
            enabled_profile_ids(&state_dir).unwrap(),
            vec!["claude-code".to_string(), "codex-api".to_string()]
        );

        let enabled = set_integration_enabled("claude-code", true, &state_dir).unwrap();
        assert_eq!(
            enabled
                .iter()
                .map(|profile| profile.profile_id.as_str())
                .collect::<Vec<_>>(),
            vec!["codex-api", "claude-code"]
        );

        let enabled = set_integration_enabled("codex-api", false, &state_dir).unwrap();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].profile_id, "claude-code");

        assert!(clear_enabled_integrations(&state_dir).unwrap());
        assert!(!clear_enabled_integrations(&state_dir).unwrap());
    }

    #[test]
    fn runtime_enabled_integrations_distinguish_empty_enabled_state_from_absent_state() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("integrations");

        assert_eq!(runtime_enabled_profile_ids(&state_dir).unwrap(), None);

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
            traffic_app_ids_for_profile_ids(&["claude-code".to_string()]).unwrap(),
            vec!["anthropic-api".to_string()]
        );
    }

    #[test]
    fn enabled_integrations_reject_unknown_profile() {
        let dir = tempfile::tempdir().unwrap();
        let error = set_integration_enabled("missing", true, dir.path()).unwrap_err();

        assert!(error.contains("unknown integration profile: missing"));
    }

    #[test]
    fn codex_apply_writes_proxy_env_and_rollback_restores_backup() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let env_path = dir.path().join("codex.env");
        let original = "export EXISTING=1\n";
        fs::write(&env_path, original).unwrap();

        let prepared =
            prepare_apply("codex-api", "http://127.0.0.1:9000", env_path.clone()).unwrap();
        let result = run_apply(prepared, false, &state_dir).unwrap();

        assert!(!result.dry_run);
        assert_eq!(result.changes[0].action, FileAction::Update);
        let applied = fs::read_to_string(&env_path).unwrap();
        assert!(applied.contains("# DAM integration profile: codex-api"));
        assert!(applied.contains("export HTTPS_PROXY=http://127.0.0.1:9000"));
        assert!(applied.contains("export HTTP_PROXY=http://127.0.0.1:9000"));
        assert!(!applied.contains("dam_openai"));

        let rollback = rollback_profile("codex-api", &state_dir).unwrap();

        assert_eq!(rollback.changes[0].action, FileAction::Restore);
        assert_eq!(fs::read_to_string(&env_path).unwrap(), original);
    }

    #[test]
    fn claude_code_apply_writes_settings_and_rollback_restores_backup() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let settings_path = dir.path().join("settings.json");
        let original = r#"{"model":"claude-sonnet-4-5","env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:7828","FOO":"bar"}}"#;
        fs::write(&settings_path, original).unwrap();

        let prepared = prepare_apply(
            "claude-code",
            "http://127.0.0.1:9000/",
            settings_path.clone(),
        )
        .unwrap();
        let result = run_apply(prepared, false, &state_dir).unwrap();

        assert_eq!(result.changes[0].action, FileAction::Update);
        let applied = fs::read_to_string(&settings_path).unwrap();
        let settings: Value = serde_json::from_str(&applied).unwrap();
        assert_eq!(settings["model"], "claude-sonnet-4-5");
        assert_eq!(settings["env"]["FOO"], "bar");
        assert!(settings["env"][CLAUDE_BASE_URL_ENV].is_null());
        assert_eq!(settings["env"][HTTPS_PROXY_ENV], "http://127.0.0.1:9000");
        assert_eq!(settings["env"][HTTP_PROXY_ENV], "http://127.0.0.1:9000");

        let rollback = rollback_profile("claude-code", &state_dir).unwrap();

        assert_eq!(rollback.changes[0].action, FileAction::Restore);
        assert_eq!(fs::read_to_string(&settings_path).unwrap(), original);
    }

    #[test]
    fn claude_code_apply_migrates_legacy_dam_base_url_with_rollback_record() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let settings_path = dir.path().join("settings.json");
        let legacy = r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:7828","FOO":"bar"}}"#;
        fs::write(&settings_path, legacy).unwrap();
        let profile_dir = profile_state_dir(&state_dir, "claude-code");
        fs::create_dir_all(&profile_dir).unwrap();
        let backup_path = profile_dir.join("legacy.backup");
        fs::write(&backup_path, r#"{"env":{"FOO":"bar"}}"#).unwrap();
        write_json_file(
            &profile_dir.join("latest.json"),
            &IntegrationApplyRecord {
                profile_id: "claude-code".to_string(),
                applied_at_unix: 1,
                files: vec![IntegrationBackupFile {
                    path: settings_path.clone(),
                    existed: true,
                    backup_path: Some(backup_path),
                }],
            },
        )
        .unwrap();

        let inspection = inspect_apply(
            "claude-code",
            DEFAULT_PROXY_URL,
            settings_path.clone(),
            &state_dir,
        )
        .unwrap();
        assert_eq!(inspection.status, IntegrationApplyStatus::NeedsApply);

        let prepared =
            prepare_apply("claude-code", DEFAULT_PROXY_URL, settings_path.clone()).unwrap();
        let result = run_apply(prepared, false, &state_dir).unwrap();

        assert_eq!(result.message, "integration profile applied");
        let settings: Value =
            serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
        assert!(settings["env"][CLAUDE_BASE_URL_ENV].is_null());
        assert_eq!(settings["env"][HTTPS_PROXY_ENV], DEFAULT_PROXY_URL);
        assert_eq!(settings["env"][HTTP_PROXY_ENV], DEFAULT_PROXY_URL);
    }

    #[test]
    fn claude_code_apply_rejects_non_object_env_settings() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        fs::write(&settings_path, r#"{"env":"invalid"}"#).unwrap();

        let error =
            prepare_apply("claude-code", "http://127.0.0.1:9000", settings_path).unwrap_err();

        assert!(error.contains("env value must be an object"));
    }

    #[test]
    fn env_profile_apply_creates_file_and_rollback_deletes_it() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let env_path = dir.path().join("anthropic.env");

        let prepared =
            prepare_apply("anthropic", "http://127.0.0.1:9000", env_path.clone()).unwrap();
        let result = run_apply(prepared, false, &state_dir).unwrap();

        assert_eq!(result.changes[0].action, FileAction::Create);
        let applied = fs::read_to_string(&env_path).unwrap();
        assert!(applied.contains("# DAM integration profile: anthropic"));
        assert!(applied.contains("export HTTPS_PROXY=http://127.0.0.1:9000"));
        assert!(applied.contains("export HTTP_PROXY=http://127.0.0.1:9000"));

        let rollback = rollback_profile("anthropic", &state_dir).unwrap();

        assert_eq!(rollback.changes[0].action, FileAction::Delete);
        assert!(!env_path.exists());
    }

    #[test]
    fn inspect_apply_reports_missing_applied_and_modified_states() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let env_path = dir.path().join("anthropic.env");

        let missing = inspect_apply(
            "anthropic",
            "http://127.0.0.1:9000",
            env_path.clone(),
            &state_dir,
        )
        .unwrap();
        assert_eq!(missing.status, IntegrationApplyStatus::NeedsApply);
        assert_eq!(missing.planned_action, FileAction::Create);
        assert!(!missing.rollback_available);

        let prepared =
            prepare_apply("anthropic", "http://127.0.0.1:9000", env_path.clone()).unwrap();
        run_apply(prepared, false, &state_dir).unwrap();

        let applied = inspect_apply(
            "anthropic",
            "http://127.0.0.1:9000",
            env_path.clone(),
            &state_dir,
        )
        .unwrap();
        assert_eq!(applied.status, IntegrationApplyStatus::Applied);
        assert_eq!(applied.planned_action, FileAction::Unchanged);
        assert!(applied.rollback_available);

        fs::write(&env_path, "export HTTPS_PROXY=http://example.invalid\n").unwrap();

        let modified =
            inspect_apply("anthropic", "http://127.0.0.1:9000", env_path, &state_dir).unwrap();
        assert_eq!(modified.status, IntegrationApplyStatus::Modified);
        assert_eq!(modified.planned_action, FileAction::Update);
        assert!(modified.rollback_available);
    }

    #[test]
    fn run_apply_refuses_modified_target_with_existing_rollback_record() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let env_path = dir.path().join("anthropic.env");

        let prepared =
            prepare_apply("anthropic", "http://127.0.0.1:9000", env_path.clone()).unwrap();
        run_apply(prepared, false, &state_dir).unwrap();
        fs::write(&env_path, "export HTTPS_PROXY=http://example.invalid\n").unwrap();

        let prepared = prepare_apply("anthropic", "http://127.0.0.1:9000", env_path).unwrap();
        let error = run_apply(prepared, false, &state_dir).unwrap_err();

        assert!(error.contains("already has a rollback record"));
    }

    #[test]
    fn run_apply_does_not_rebackup_already_applied_target() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let env_path = dir.path().join("anthropic.env");

        let prepared =
            prepare_apply("anthropic", "http://127.0.0.1:9000", env_path.clone()).unwrap();
        run_apply(prepared, false, &state_dir).unwrap();
        let backups_dir = profile_state_dir(&state_dir, "anthropic").join("backups");
        let backup_count = fs::read_dir(&backups_dir).unwrap().count();

        let prepared = prepare_apply("anthropic", "http://127.0.0.1:9000", env_path).unwrap();
        let result = run_apply(prepared, false, &state_dir).unwrap();

        assert_eq!(result.changes[0].action, FileAction::Unchanged);
        assert_eq!(fs::read_dir(backups_dir).unwrap().count(), backup_count);
    }

    #[test]
    fn inspect_apply_reports_unreadable_rollback_record() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let env_path = dir.path().join("anthropic.env");
        let record_path = profile_state_dir(&state_dir, "anthropic").join("latest.json");
        fs::create_dir_all(record_path.parent().unwrap()).unwrap();
        fs::write(&record_path, "not json").unwrap();

        let report =
            inspect_apply("anthropic", "http://127.0.0.1:9000", env_path, &state_dir).unwrap();

        assert_eq!(report.status, IntegrationApplyStatus::NeedsApply);
        assert!(!report.rollback_available);
        assert!(report.record_error.unwrap().contains("failed to parse"));
    }
}
