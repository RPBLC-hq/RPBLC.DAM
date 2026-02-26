pub mod audit;
pub mod config;
pub mod consent;
pub mod daemon;
pub mod health;
pub mod init;
pub mod mcp;
pub mod scan;
pub mod serve;
pub mod status;
pub mod vault;

use anyhow::Result;
use dam_core::config::{DamConfig, KeySource};
use dam_vault::{KeychainManager, VaultStore};
use std::sync::Arc;

/// Load config from the default path or return defaults.
pub fn load_config() -> Result<DamConfig> {
    let config_path = DamConfig::default_config_path();
    let config = DamConfig::load(&config_path)?;
    Ok(config)
}

/// Load config, auto-creating a default config file if none exists.
///
/// Returns `(config, auto_inited)` where `auto_inited` is true if the config
/// file was created by this call. Use this for commands like `serve` and `mcp`
/// that should just work without requiring `dam init` first.
pub fn load_config_auto_init() -> Result<(DamConfig, bool)> {
    let config_path = DamConfig::default_config_path();
    if config_path.exists() {
        let config = DamConfig::load(&config_path)?;
        return Ok((config, false));
    }

    // Auto-create default config
    let config = DamConfig::default();
    config.save(&config_path)?;
    eprintln!(
        "  [auto-init] Created default config at {}",
        config_path.display()
    );
    eprintln!("  [auto-init] Run `dam init` to customize settings.");
    Ok((config, true))
}

/// Open the vault using the configured key source.
pub fn open_vault(config: &DamConfig) -> Result<Arc<VaultStore>> {
    let kek = match &config.vault.key_source {
        KeySource::OsKeychain => match KeychainManager::get_kek() {
            Ok(kek) => kek,
            Err(_) => {
                eprintln!("  [auto-init] KEK not found in OS keychain, creating...");
                KeychainManager::get_or_create_kek()?
            }
        },
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
