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
    ///
    /// Honors the `DAM_HOME` environment variable if set, allowing tests
    /// and CI to run in isolated temp directories without touching `~/.dam/`.
    pub fn default_home() -> PathBuf {
        if let Some(home) = std::env::var_os("DAM_HOME") {
            if !home.is_empty() {
                return PathBuf::from(home);
            }
        }
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
    #[serde(default = "default_locales", deserialize_with = "deserialize_locales")]
    pub locales: Vec<Locale>,
}

fn default_locales() -> Vec<Locale> {
    Locale::defaults()
}

/// Tolerant deserializer that silently drops unknown locale strings.
/// This prevents config loading from failing when locale variants are removed
/// (e.g. "jp", "kr", "in", "cn" from older configs).
fn deserialize_locales<'de, D>(deserializer: D) -> Result<Vec<Locale>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let strings: Vec<String> = Vec::deserialize(deserializer)?;
    Ok(strings
        .iter()
        .filter_map(|s| s.parse::<Locale>().ok())
        .collect())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_locales_drops_unknown() {
        let toml = r#"
[vault]
path = "/tmp/vault.db"
key_source = "os_keychain"

[detection]
sensitivity = "standard"
excluded_types = []
whitelist = []
locales = ["global", "us", "jp", "kr", "in", "cn"]

[detection.custom_rules]

[server]
http_port = 7828
"#;
        let config: DamConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.detection.locales, vec![Locale::Global, Locale::Us]);
    }

    #[test]
    fn deserialize_locales_keeps_valid() {
        let toml = r#"
[vault]
path = "/tmp/vault.db"
key_source = "os_keychain"

[detection]
sensitivity = "standard"
excluded_types = []
whitelist = []
locales = ["global", "us", "eu", "fr"]

[detection.custom_rules]

[server]
http_port = 7828
"#;
        let config: DamConfig = toml::from_str(toml).unwrap();
        assert_eq!(
            config.detection.locales,
            vec![Locale::Global, Locale::Us, Locale::Eu, Locale::Fr]
        );
    }

    #[test]
    fn missing_locales_uses_default() {
        let toml = r#"
[vault]
path = "/tmp/vault.db"
key_source = "os_keychain"

[detection]
sensitivity = "standard"
excluded_types = []
whitelist = []

[detection.custom_rules]

[server]
http_port = 7828
"#;
        let config: DamConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.detection.locales, Locale::defaults());
    }
}
