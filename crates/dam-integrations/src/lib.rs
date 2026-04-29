use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use toml_edit::{DocumentMut, Item, Table, value};

pub const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:7828";
pub const CODEX_API_KEY_ENV: &str = "OPENAI_API_KEY";
pub const CODEX_DAM_PROVIDER_ID: &str = "dam_openai";
pub const CLAUDE_BASE_URL_ENV: &str = "ANTHROPIC_BASE_URL";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationProfile {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub provider: String,
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
    vec![
        openai_compatible(proxy_url),
        anthropic(proxy_url),
        claude_code(proxy_url),
        codex_api(proxy_url),
        xai_compatible(proxy_url),
    ]
}

pub fn profile(id: &str, proxy_url: &str) -> Option<IntegrationProfile> {
    profiles(proxy_url)
        .into_iter()
        .find(|profile| profile.id == id)
}

pub fn profile_ids() -> Vec<&'static str> {
    vec![
        "openai-compatible",
        "anthropic",
        "claude-code",
        "codex-api",
        "xai-compatible",
    ]
}

pub fn openai_base_url(proxy_url: &str) -> String {
    format!("{}/v1", proxy_url.trim_end_matches('/'))
}

pub fn active_profile_path(integration_state_dir: &Path) -> PathBuf {
    integration_state_dir.join("active-profile.json")
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

pub fn default_apply_path(
    profile_id: &str,
    integration_state_dir: &Path,
    codex_home: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Result<PathBuf, String> {
    match profile_id {
        "codex-api" => codex_config_path(codex_home, home),
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
        "codex-api" => "update Codex config with DAM OpenAI provider".to_string(),
        "claude-code" => "update Claude Code settings env with DAM Anthropic base URL".to_string(),
        _ => "write DAM-managed environment file for this profile".to_string(),
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
    let record_path = profile_state_dir(state_dir, profile_id).join("latest.json");
    let (rollback_available, record_error) = rollback_record_state(profile_id, &record_path);
    let status = match (prepared.action, rollback_available) {
        (FileAction::Unchanged, _) => IntegrationApplyStatus::Applied,
        (_, true) => IntegrationApplyStatus::Modified,
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
    state_dir.join("profiles").join(profile_id)
}

fn openai_compatible(proxy_url: &str) -> IntegrationProfile {
    IntegrationProfile {
        id: "openai-compatible".to_string(),
        name: "Generic OpenAI-compatible harness".to_string(),
        summary: "Point an OpenAI-compatible SDK or harness at the local DAM /v1 endpoint."
            .to_string(),
        provider: "openai-compatible".to_string(),
        connect_args: vec!["--openai".to_string()],
        settings: vec![IntegrationSetting {
            key: "OPENAI_BASE_URL".to_string(),
            value: openai_base_url(proxy_url),
            description: "OpenAI-compatible base URL for clients that honor OPENAI_BASE_URL"
                .to_string(),
        }],
        commands: vec![IntegrationCommand {
            label: "Start DAM for OpenAI-compatible traffic".to_string(),
            command: vec![
                "dam".to_string(),
                "connect".to_string(),
                "--openai".to_string(),
            ],
        }],
        notes: vec![
            "Keep provider credentials owned by the harness. DAM forwards caller auth headers."
                .to_string(),
            "Use this for SDKs and tools that let you set an OpenAI-compatible base URL."
                .to_string(),
        ],
        automation: AutomationLevel::ConnectPreset,
    }
}

fn anthropic(proxy_url: &str) -> IntegrationProfile {
    IntegrationProfile {
        id: "anthropic".to_string(),
        name: "Generic Anthropic-compatible harness".to_string(),
        summary: "Point an Anthropic-compatible harness at the local DAM endpoint.".to_string(),
        provider: "anthropic".to_string(),
        connect_args: vec!["--anthropic".to_string()],
        settings: vec![IntegrationSetting {
            key: CLAUDE_BASE_URL_ENV.to_string(),
            value: proxy_url.trim_end_matches('/').to_string(),
            description: "Anthropic-compatible base URL for clients that honor ANTHROPIC_BASE_URL"
                .to_string(),
        }],
        commands: vec![IntegrationCommand {
            label: "Start DAM for Anthropic traffic".to_string(),
            command: vec![
                "dam".to_string(),
                "connect".to_string(),
                "--anthropic".to_string(),
            ],
        }],
        notes: vec![
            "Keep provider credentials owned by the harness. DAM forwards caller auth headers."
                .to_string(),
            "Use this for tools that speak Anthropic's HTTP API and expose a base URL setting."
                .to_string(),
        ],
        automation: AutomationLevel::ConnectPreset,
    }
}

fn claude_code(proxy_url: &str) -> IntegrationProfile {
    IntegrationProfile {
        id: "claude-code".to_string(),
        name: "Claude Code".to_string(),
        summary: "Run Claude Code through a background Anthropic-compatible DAM endpoint."
            .to_string(),
        provider: "anthropic".to_string(),
        connect_args: vec!["--anthropic".to_string()],
        settings: vec![IntegrationSetting {
            key: CLAUDE_BASE_URL_ENV.to_string(),
            value: proxy_url.trim_end_matches('/').to_string(),
            description: "Claude Code session environment setting".to_string(),
        }],
        commands: vec![
            IntegrationCommand {
                label: "Start DAM for Claude Code".to_string(),
                command: vec![
                    "dam".to_string(),
                    "connect".to_string(),
                    "--anthropic".to_string(),
                ],
            },
            IntegrationCommand {
                label: "Launch Claude Code against the connected daemon".to_string(),
                command: vec![
                    "env".to_string(),
                    format!("ANTHROPIC_BASE_URL={}", proxy_url.trim_end_matches('/')),
                    "claude".to_string(),
                ],
            },
        ],
        notes: vec![
            "`dam claude` remains the one-shot path when a background daemon is not needed."
                .to_string(),
            "`dam integrations apply claude-code` writes the env setting to Claude Code settings JSON with a rollback record.".to_string(),
            "Use `--target-path .claude/settings.local.json` for a project-local Claude Code setting instead of the default user setting.".to_string(),
            "Claude Code keeps provider authentication; DAM only receives and forwards the request headers.".to_string(),
        ],
        automation: AutomationLevel::ConnectPreset,
    }
}

fn codex_api(proxy_url: &str) -> IntegrationProfile {
    let base_url = openai_base_url(proxy_url);
    IntegrationProfile {
        id: "codex-api".to_string(),
        name: "Codex API-key mode".to_string(),
        summary: "Point Codex API-key mode at a background OpenAI-compatible DAM endpoint."
            .to_string(),
        provider: "openai-compatible".to_string(),
        connect_args: vec!["--openai".to_string()],
        settings: vec![
            IntegrationSetting {
                key: "model_provider".to_string(),
                value: "dam_openai".to_string(),
                description: "Temporary Codex provider id for DAM-routed API-key mode".to_string(),
            },
            IntegrationSetting {
                key: "model_providers.dam_openai.base_url".to_string(),
                value: base_url.clone(),
                description: "OpenAI Responses API base URL through DAM".to_string(),
            },
            IntegrationSetting {
                key: "model_providers.dam_openai.env_key".to_string(),
                value: "OPENAI_API_KEY".to_string(),
                description: "Codex still owns the provider API key".to_string(),
            },
            IntegrationSetting {
                key: "model_providers.dam_openai.supports_websockets".to_string(),
                value: "false".to_string(),
                description: "Disable Codex WebSockets until DAM has a WebSocket adapter"
                    .to_string(),
            },
        ],
        commands: vec![
            IntegrationCommand {
                label: "Start DAM for Codex API-key mode".to_string(),
                command: vec!["dam".to_string(), "connect".to_string(), "--openai".to_string()],
            },
            IntegrationCommand {
                label: "Launch Codex against the connected daemon".to_string(),
                command: codex_command(&base_url),
            },
        ],
        notes: vec![
            "`dam codex --api` remains the one-shot protected path.".to_string(),
            "Codex ChatGPT-login mode is still not protected by this profile because its model transport uses the ChatGPT backend path/WebSocket flow.".to_string(),
        ],
        automation: AutomationLevel::ConnectPreset,
    }
}

fn xai_compatible(proxy_url: &str) -> IntegrationProfile {
    IntegrationProfile {
        id: "xai-compatible".to_string(),
        name: "xAI OpenAI-compatible harness".to_string(),
        summary: "Start DAM with xAI as an OpenAI-compatible upstream target.".to_string(),
        provider: "openai-compatible".to_string(),
        connect_args: vec![
            "--target-name".to_string(),
            "xai".to_string(),
            "--provider".to_string(),
            "openai-compatible".to_string(),
            "--upstream".to_string(),
            "https://api.x.ai".to_string(),
        ],
        settings: vec![IntegrationSetting {
            key: "OPENAI_BASE_URL".to_string(),
            value: openai_base_url(proxy_url),
            description: "OpenAI-compatible base URL exposed by DAM for the harness".to_string(),
        }],
        commands: vec![IntegrationCommand {
            label: "Start DAM with xAI upstream".to_string(),
            command: vec![
                "dam".to_string(),
                "connect".to_string(),
                "--profile".to_string(),
                "xai-compatible".to_string(),
            ],
        }],
        notes: vec![
            "The harness still owns provider credentials. Configure its xAI API key through the harness's normal secret mechanism.".to_string(),
            "This profile only selects the upstream target and exposes a local OpenAI-compatible DAM endpoint.".to_string(),
        ],
        automation: AutomationLevel::ConnectPreset,
    }
}

fn codex_command(base_url: &str) -> Vec<String> {
    vec![
        "codex".to_string(),
        "-c".to_string(),
        "model_provider=\"dam_openai\"".to_string(),
        "-c".to_string(),
        "model_providers.dam_openai.name=\"OpenAI through DAM\"".to_string(),
        "-c".to_string(),
        format!("model_providers.dam_openai.base_url=\"{base_url}\""),
        "-c".to_string(),
        "model_providers.dam_openai.env_key=\"OPENAI_API_KEY\"".to_string(),
        "-c".to_string(),
        "model_providers.dam_openai.wire_api=\"responses\"".to_string(),
        "-c".to_string(),
        "model_providers.dam_openai.supports_websockets=false".to_string(),
    ]
}

fn codex_config_path(
    codex_home: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Result<PathBuf, String> {
    if let Some(home) = codex_home
        && !home.as_os_str().is_empty()
    {
        return Ok(home.join("config.toml"));
    }
    let home = home
        .filter(|home| !home.as_os_str().is_empty())
        .ok_or_else(|| "HOME or CODEX_HOME is required to locate Codex config".to_string())?;
    Ok(home.join(".codex").join("config.toml"))
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
        "codex-api" => codex_config_content(current_content.unwrap_or_default(), proxy_url),
        "claude-code" => claude_settings_content(current_content.unwrap_or_default(), proxy_url),
        _ => Ok(env_profile_content(profile)),
    }
}

fn codex_config_content(current: &str, proxy_url: &str) -> Result<String, String> {
    let mut document = current
        .parse::<DocumentMut>()
        .map_err(|error| format!("failed to parse Codex config TOML: {error}"))?;
    let base_url = openai_base_url(proxy_url);

    document["model_provider"] = value(CODEX_DAM_PROVIDER_ID);
    if !matches!(document.get("model_providers"), Some(Item::Table(_))) {
        document["model_providers"] = Item::Table(Table::new());
    }
    let providers = document["model_providers"]
        .as_table_mut()
        .ok_or_else(|| "failed to prepare Codex model_providers table in config".to_string())?;
    if !matches!(providers.get(CODEX_DAM_PROVIDER_ID), Some(Item::Table(_))) {
        providers.insert(CODEX_DAM_PROVIDER_ID, Item::Table(Table::new()));
    }
    let provider = providers[CODEX_DAM_PROVIDER_ID]
        .as_table_mut()
        .ok_or_else(|| "failed to prepare Codex dam_openai provider table in config".to_string())?;
    provider.insert("name", value("OpenAI through DAM"));
    provider.insert("base_url", value(base_url));
    provider.insert("env_key", value(CODEX_API_KEY_ENV));
    provider.insert("wire_api", value("responses"));
    provider.insert("supports_websockets", value(false));

    Ok(document.to_string())
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
    env_object.insert(
        CLAUDE_BASE_URL_ENV.to_string(),
        Value::String(proxy_url.trim_end_matches('/').to_string()),
    );
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
                "xai-compatible"
            ]
        );
    }

    #[test]
    fn openai_profiles_use_v1_local_endpoint() {
        let profile = profile("openai-compatible", DEFAULT_PROXY_URL).unwrap();

        assert_eq!(profile.settings[0].key, "OPENAI_BASE_URL");
        assert_eq!(profile.settings[0].value, "http://127.0.0.1:7828/v1");
    }

    #[test]
    fn anthropic_profiles_use_root_local_endpoint() {
        let profile = profile("anthropic", "http://127.0.0.1:7828/").unwrap();

        assert_eq!(profile.settings[0].key, "ANTHROPIC_BASE_URL");
        assert_eq!(profile.settings[0].value, "http://127.0.0.1:7828");
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
                "https://api.x.ai"
            ]
        );
    }

    #[test]
    fn codex_profile_disables_websockets() {
        let profile = profile("codex-api", DEFAULT_PROXY_URL).unwrap();
        let command = &profile.commands[1].command;

        assert!(
            command.contains(&"model_providers.dam_openai.supports_websockets=false".to_string())
        );
    }

    #[test]
    fn codex_default_path_prefers_codex_home() {
        let path = default_apply_path(
            "codex-api",
            Path::new("/tmp/dam/integrations"),
            Some(PathBuf::from("/tmp/codex")),
            Some(PathBuf::from("/tmp/home")),
        )
        .unwrap();

        assert_eq!(path, PathBuf::from("/tmp/codex/config.toml"));
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
    fn codex_apply_writes_config_and_rollback_restores_backup() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let config_path = dir.path().join("config.toml");
        let original = "approval_policy = \"never\"\n";
        fs::write(&config_path, original).unwrap();

        let prepared =
            prepare_apply("codex-api", "http://127.0.0.1:9000", config_path.clone()).unwrap();
        let result = run_apply(prepared, false, &state_dir).unwrap();

        assert!(!result.dry_run);
        assert_eq!(result.changes[0].action, FileAction::Update);
        let applied = fs::read_to_string(&config_path).unwrap();
        assert!(applied.contains("approval_policy = \"never\""));
        assert!(applied.contains("model_provider = \"dam_openai\""));
        assert!(applied.contains("base_url = \"http://127.0.0.1:9000/v1\""));
        assert!(applied.contains("supports_websockets = false"));

        let rollback = rollback_profile("codex-api", &state_dir).unwrap();

        assert_eq!(rollback.changes[0].action, FileAction::Restore);
        assert_eq!(fs::read_to_string(&config_path).unwrap(), original);
    }

    #[test]
    fn claude_code_apply_writes_settings_and_rollback_restores_backup() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let settings_path = dir.path().join("settings.json");
        let original = r#"{"model":"claude-sonnet-4-5","env":{"FOO":"bar"}}"#;
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
        assert_eq!(
            settings["env"][CLAUDE_BASE_URL_ENV],
            "http://127.0.0.1:9000"
        );

        let rollback = rollback_profile("claude-code", &state_dir).unwrap();

        assert_eq!(rollback.changes[0].action, FileAction::Restore);
        assert_eq!(fs::read_to_string(&settings_path).unwrap(), original);
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
        assert!(applied.contains("export ANTHROPIC_BASE_URL=http://127.0.0.1:9000"));

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

        fs::write(
            &env_path,
            "export ANTHROPIC_BASE_URL=http://example.invalid\n",
        )
        .unwrap();

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
        fs::write(
            &env_path,
            "export ANTHROPIC_BASE_URL=http://example.invalid\n",
        )
        .unwrap();

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
