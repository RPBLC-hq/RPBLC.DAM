use anyhow::Result;

use super::{load_config, open_vault};

pub async fn run(json: bool) -> Result<()> {
    let config = load_config()?;
    let vault = open_vault(&config)?;
    let entry_count = vault.list_entries(None, 1_000_000)?.len();

    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "config_path": dam_core::config::DamConfig::default_config_path(),
                "vault_path": config.vault.path,
                "http_port": config.server.http_port,
                "consent_passthrough": config.server.consent_passthrough,
                "entry_count": entry_count,
                "upstreams": {
                    "anthropic": config.server.anthropic_upstream_url,
                    "openai": config.server.openai_upstream_url,
                    "codex": config.server.codex_upstream_url,
                }
            })
        );
    } else {
        println!("DAM status");
        println!("- Vault: {}", config.vault.path.display());
        println!("- Entries: {entry_count}");
        println!("- HTTP port: {}", config.server.http_port);
        println!(
            "- Consent passthrough: {}",
            config.server.consent_passthrough
        );
    }

    Ok(())
}
