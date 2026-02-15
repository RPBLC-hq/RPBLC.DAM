use crate::locale::Locale;
use crate::pii_type::PiiType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Top-level DAM configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DamConfig {
    pub vault: VaultConfig,
    pub detection: DetectionConfig,
    pub server: ServerConfig,
}

impl DamConfig {
    /// Load config from a TOML file, falling back to defaults.
    pub fn load(path: &Path) -> crate::error::DamResult<Self> {
        if path.exists() {
            let contents = std::fs::read_to_string(path)?;
            let config: Self = toml::from_str(&contents)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    /// Save config to a TOML file.
    pub fn save(&self, path: &Path) -> crate::error::DamResult<()> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| crate::error::DamError::Config(e.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// The default DAM home directory: `~/.dam/`
    pub fn default_home() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".dam")
    }

    /// The default config file path: `~/.dam/config.toml`
    pub fn default_config_path() -> PathBuf {
        Self::default_home().join("config.toml")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Path to the SQLite vault database.
    pub path: PathBuf,
    /// How the KEK is sourced.
    pub key_source: KeySource,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            path: DamConfig::default_home().join("vault.db"),
            key_source: KeySource::OsKeychain,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    /// Use the OS keychain (DPAPI / macOS Keychain / libsecret).
    OsKeychain,
    /// Derive KEK from a passphrase via Argon2id.
    Passphrase,
    /// Read KEK from an environment variable.
    EnvVar { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Detection sensitivity level.
    pub sensitivity: Sensitivity,
    /// PII types to exclude from detection.
    pub excluded_types: Vec<PiiType>,
    /// Terms to whitelist (never flag as PII).
    pub whitelist: Vec<String>,
    /// User-defined regex rules: name → pattern.
    pub custom_rules: HashMap<String, CustomRule>,
    /// Active locales for PII detection patterns.
    #[serde(default = "default_locales")]
    pub locales: Vec<Locale>,
}

fn default_locales() -> Vec<Locale> {
    Locale::defaults()
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            sensitivity: Sensitivity::Standard,
            excluded_types: Vec::new(),
            whitelist: Vec::new(),
            custom_rules: HashMap::new(),
            locales: Locale::defaults(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Structured PII only: email, phone, SSN, CC, addresses.
    Standard,
    /// + names, dates, organizations, locations.
    Elevated,
    /// + any noun phrase matching vault history.
    Maximum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub pattern: String,
    pub pii_type: PiiType,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// HTTP API port (for `dam serve`).
    pub http_port: u16,
    /// API bearer token for HTTP API.
    pub api_token: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_port: 7828,
            api_token: None,
        }
    }
}
