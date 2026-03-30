use anyhow::Result;
use clap::Subcommand;
use dam_core::config::DamConfig;

use super::init::parse_locale_list;

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show the current configuration
    Show,

    /// Validate configuration and required files
    Validate,

    /// Get a configuration value
    Get {
        /// Configuration key (e.g., "detection.locales")
        key: String,
    },

    /// Set a configuration value
    Set {
        /// Configuration key (e.g., "detection.sensitivity")
        key: String,
        /// New value
        value: String,
    },
}

fn apply_set(config: &mut DamConfig, key: &str, value: &str) -> Result<()> {
    match key {
        "detection.sensitivity" => {
            config.detection.sensitivity = match value {
                "standard" => dam_core::config::Sensitivity::Standard,
                "elevated" => dam_core::config::Sensitivity::Elevated,
                "maximum" => dam_core::config::Sensitivity::Maximum,
                _ => {
                    anyhow::bail!("Invalid sensitivity: {value}. Use: standard, elevated, maximum")
                }
            };
        }
        "detection.locales" => {
            config.detection.locales = parse_locale_list(value)?;
        }
        "server.http_port" => {
            config.server.http_port = value.parse()?;
        }
        "server.consent_passthrough" => {
            config.server.consent_passthrough = value.parse()?;
        }
        "server.anthropic_upstream_url" => {
            config.server.anthropic_upstream_url = if value.trim().is_empty() {
                None
            } else {
                Some(value.to_string())
            };
        }
        "server.openai_upstream_url" => {
            config.server.openai_upstream_url = if value.trim().is_empty() {
                None
            } else {
                Some(value.to_string())
            };
        }
        "server.codex_upstream_url" => {
            config.server.codex_upstream_url = if value.trim().is_empty() {
                None
            } else {
                Some(value.to_string())
            };
        }
        _ => anyhow::bail!("Unknown config key: {key}"),
    }
    Ok(())
}

pub async fn run(action: ConfigAction, json: bool) -> Result<()> {
    let config_path = DamConfig::default_config_path();

    match action {
        ConfigAction::Validate => {
            let config = DamConfig::load(&config_path)?;
            let vault_parent_exists = config
                .vault
                .path
                .parent()
                .map(|p| p.exists())
                .unwrap_or(false);

            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "config_path": config_path,
                        "vault_path": config.vault.path,
                        "vault_parent_exists": vault_parent_exists,
                        "http_port": config.server.http_port,
                    })
                );
            } else {
                println!("Config OK: {}", config_path.display());
                println!("Vault path: {}", config.vault.path.display());
                println!("HTTP port: {}", config.server.http_port);
            }
        }
        ConfigAction::Show => {
            if config_path.exists() {
                let contents = std::fs::read_to_string(&config_path)?;
                println!("# {}\n", config_path.display());
                println!("{contents}");
            } else {
                println!("No config file found at {}", config_path.display());
                println!("Run 'dam init' to create one.");
            }
        }

        ConfigAction::Get { key } => {
            let config = DamConfig::load(&config_path)?;

            match key.as_str() {
                "detection.locales" => {
                    let display: Vec<String> = config
                        .detection
                        .locales
                        .iter()
                        .map(|l| l.to_string())
                        .collect();
                    println!("{}", display.join(", "));
                }
                "detection.sensitivity" => {
                    let s = match config.detection.sensitivity {
                        dam_core::config::Sensitivity::Standard => "standard",
                        dam_core::config::Sensitivity::Elevated => "elevated",
                        dam_core::config::Sensitivity::Maximum => "maximum",
                    };
                    println!("{s}");
                }
                "server.http_port" => {
                    println!("{}", config.server.http_port);
                }
                "server.consent_passthrough" => {
                    println!("{}", config.server.consent_passthrough);
                }
                "server.anthropic_upstream_url" => {
                    println!(
                        "{}",
                        config.server.anthropic_upstream_url.unwrap_or_default()
                    );
                }
                "server.openai_upstream_url" => {
                    println!("{}", config.server.openai_upstream_url.unwrap_or_default());
                }
                "server.codex_upstream_url" => {
                    println!("{}", config.server.codex_upstream_url.unwrap_or_default());
                }
                _ => {
                    anyhow::bail!("Unknown config key: {key}");
                }
            }
        }

        ConfigAction::Set { key, value } => {
            let mut config = DamConfig::load(&config_path)?;

            apply_set(&mut config, &key, &value)?;

            config.save(&config_path)?;

            // Print normalized value for locales (shows what was actually written)
            if key == "detection.locales" {
                let display: Vec<String> = config
                    .detection
                    .locales
                    .iter()
                    .map(|l| l.to_string())
                    .collect();
                println!("Updated {key} = {}", display.join(", "));
            } else {
                println!("Updated {key} = {value}");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::apply_set;
    use dam_core::config::DamConfig;

    #[test]
    fn set_server_consent_passthrough() {
        let mut cfg = DamConfig::default();
        apply_set(&mut cfg, "server.consent_passthrough", "true").unwrap();
        assert!(cfg.server.consent_passthrough);
    }

    #[test]
    fn set_and_clear_upstream_url() {
        let mut cfg = DamConfig::default();
        apply_set(
            &mut cfg,
            "server.openai_upstream_url",
            "https://api.example.com",
        )
        .unwrap();
        assert_eq!(
            cfg.server.openai_upstream_url.as_deref(),
            Some("https://api.example.com")
        );

        apply_set(&mut cfg, "server.openai_upstream_url", "").unwrap();
        assert!(cfg.server.openai_upstream_url.is_none());
    }

    #[test]
    fn invalid_key_and_value_fail() {
        let mut cfg = DamConfig::default();
        assert!(apply_set(&mut cfg, "unknown.key", "x").is_err());
        assert!(apply_set(&mut cfg, "detection.sensitivity", "ultra").is_err());
        assert!(apply_set(&mut cfg, "server.http_port", "not-a-number").is_err());
    }
}
