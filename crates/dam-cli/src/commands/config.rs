use anyhow::Result;
use clap::Subcommand;
use dam_core::config::DamConfig;

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show the current configuration
    Show,

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
                "server.http_port" => {
                    config.server.http_port = value.parse()?;
                }
                _ => {
                    anyhow::bail!("Unknown config key: {key}");
                }
            }

            config.save(&config_path)?;
            println!("Updated {key} = {value}");
        }
    }

    Ok(())
}
