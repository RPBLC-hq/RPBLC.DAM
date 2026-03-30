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
use std::path::PathBuf;
use std::sync::Arc;

/// Path to the PID file: `~/.dam/dam.pid`
pub fn pid_file_path() -> PathBuf {
    DamConfig::default_home().join("dam.pid")
}

/// Write current process PID to the PID file.
pub fn write_pid_file() -> Result<()> {
    let path = pid_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, std::process::id().to_string())?;
    Ok(())
}

/// Remove the PID file if it exists.
pub fn remove_pid_file() {
    let _ = std::fs::remove_file(pid_file_path());
}

/// Read PID from the PID file, if it exists and is valid.
pub fn read_pid() -> Option<u32> {
    std::fs::read_to_string(pid_file_path())
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

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
            Err(err) => {
                let msg = err.to_string();
                // Only auto-create if the KEK genuinely doesn't exist.
                // Transient errors (locked keychain, permissions) must surface
                // to avoid creating a new KEK that orphans existing vault data.
                if msg.contains("No matching entry found") {
                    eprintln!("  [auto-init] KEK not found in OS keychain, creating...");
                    KeychainManager::get_or_create_kek()?
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to access KEK in OS keychain: {msg}\n\
                         Ensure your OS keychain is unlocked and accessible, then retry."
                    ));
                }
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
