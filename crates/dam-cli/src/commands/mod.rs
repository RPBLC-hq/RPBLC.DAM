pub mod audit;
pub mod config;
pub mod consent;
pub mod init;
pub mod mcp;
pub mod scan;
pub mod serve;
pub mod vault;

use anyhow::Result;
use dam_core::config::{DamConfig, KeySource};
use dam_vault::{KeychainManager, VaultStore};
use std::sync::Arc;

/// Accept both `email:a3f71bc9` and `[email:a3f71bc9]` from the user.
pub fn strip_brackets(s: &str) -> &str {
    s.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(s)
}

/// Load config from the default path or return defaults.
pub fn load_config() -> Result<DamConfig> {
    let config_path = DamConfig::default_config_path();
    let config = DamConfig::load(&config_path)?;
    Ok(config)
}

/// Open the vault using the configured key source.
pub fn open_vault(config: &DamConfig) -> Result<Arc<VaultStore>> {
    let kek = match &config.vault.key_source {
        KeySource::OsKeychain => KeychainManager::get_kek()?,
        KeySource::Passphrase => {
            // Read passphrase from stdin
            eprintln!("Enter vault passphrase: ");
            let mut passphrase = String::new();
            std::io::stdin().read_line(&mut passphrase)?;
            let passphrase = passphrase.trim();
            // Use a fixed salt derived from the vault path for deterministic key derivation
            let salt = format!("rpblc-dam:{}", config.vault.path.display());
            let salt_bytes = salt.as_bytes();
            // Argon2 requires salt between 8 and (2^32 - 1) bytes
            let salt = if salt_bytes.len() >= 8 {
                &salt_bytes[..std::cmp::min(salt_bytes.len(), 64)]
            } else {
                b"rpblc-dam-default-salt!!"
            };
            KeychainManager::kek_from_passphrase(passphrase, salt)?
        }
        KeySource::EnvVar { name } => KeychainManager::kek_from_env(name)?,
    };

    let vault = VaultStore::open(&config.vault.path, kek)?;
    Ok(Arc::new(vault))
}
