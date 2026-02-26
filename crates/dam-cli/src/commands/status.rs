use anyhow::Result;
use dam_core::config::DamConfig;
use serde_json::{Value, json};

use super::{load_config, open_vault};

fn build_status_json(config: &DamConfig, entry_count: usize) -> Value {
    json!({
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
}

pub async fn run(json: bool) -> Result<()> {
    let config = load_config()?;
    let vault = open_vault(&config)?;
    let entry_count = vault.list_entries(None, 1_000_000)?.len();

    if json {
        println!("{}", build_status_json(&config, entry_count));
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

#[cfg(test)]
mod tests {
    use super::build_status_json;
    use dam_core::config::DamConfig;

    #[test]
    fn status_json_contains_expected_fields() {
        let cfg = DamConfig::default();
        let payload = build_status_json(&cfg, 7);
        assert_eq!(payload["ok"], true);
        assert_eq!(payload["entry_count"], 7);
        assert!(payload["http_port"].is_number());
        assert!(payload["upstreams"].is_object());
    }
}
