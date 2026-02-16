use anyhow::Result;
use clap::Subcommand;
use dam_core::config::DamConfig;

use super::init::parse_locale_list;

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show the current configuration
    Show,

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

pub async fn run(action: ConfigAction) -> Result<()> {
    let config_path = DamConfig::default_config_path();

    match action {
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
                _ => {
                    anyhow::bail!("Unknown config key: {key}");
                }
            }
        }

        ConfigAction::Set { key, value } => {
            let mut config = DamConfig::load(&config_path)?;

            match key.as_str() {
                "detection.sensitivity" => {
                    config.detection.sensitivity = match value.as_str() {
                        "standard" => dam_core::config::Sensitivity::Standard,
                        "elevated" => dam_core::config::Sensitivity::Elevated,
                        "maximum" => dam_core::config::Sensitivity::Maximum,
                        _ => anyhow::bail!(
                            "Invalid sensitivity: {value}. Use: standard, elevated, maximum"
                        ),
                    };
                }
                "detection.locales" => {
                    config.detection.locales = parse_locale_list(&value)?;
                }
                "server.http_port" => {
                    config.server.http_port = value.parse()?;
                }
                _ => {
                    anyhow::bail!("Unknown config key: {key}");
                }
            }

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
