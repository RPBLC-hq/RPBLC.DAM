use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;
use comfy_table::{Cell, Table};
use dam_core::PiiRef;
use dam_vault::ConsentManager;

/// Parse a TTL string like "30m", "2h", "7d" into seconds.
fn parse_ttl(ttl: &str) -> Result<i64> {
    let ttl = ttl.trim();
    if ttl.is_empty() {
        anyhow::bail!("TTL cannot be empty");
    }

    let (num_str, unit) = ttl.split_at(ttl.len() - 1);
    let num: i64 = num_str.parse().map_err(|_| {
        anyhow::anyhow!("Invalid TTL format: {ttl:?}. Use e.g. \"30m\", \"1h\", \"7d\"")
    })?;

    if num <= 0 {
        anyhow::bail!("TTL must be positive, got {ttl:?}");
    }

    let secs = match unit {
        "m" => num * 60,
        "h" => num * 3600,
        "d" => num * 86400,
        _ => anyhow::bail!(
            "Unknown TTL unit {unit:?} in {ttl:?}. Use 'm' (minutes), 'h' (hours), or 'd' (days)"
        ),
    };

    Ok(secs)
}

#[derive(Subcommand)]
pub enum ConsentAction {
    /// List consent rules
    List {
        /// Filter by reference key
        #[arg(long)]
        r#ref: Option<String>,
    },

    /// Grant consent for an accessor to resolve a reference
    Grant {
        /// Reference key, e.g. "email:a3f71bc9"
        ref_id: String,
        /// Accessor (tool name), e.g. "claude", "send_email", or "*" for all
        accessor: String,
        /// Purpose, e.g. "send_email", "display", or "*" for all
        purpose: String,
        /// Duration for consent (e.g. "30m", "1h", "24h", "7d")
        #[arg(long)]
        ttl: String,
        /// Skip validation that reference exists (for pre-granting)
        #[arg(long)]
        force: bool,
    },

    /// Revoke consent
    Revoke {
        /// Reference key, e.g. "email:a3f71bc9"
        ref_id: String,
        /// Accessor (tool name)
        accessor: String,
        /// Purpose
        purpose: String,
    },
}

pub async fn run(action: ConsentAction) -> Result<()> {
    let config = super::load_config()?;
    let vault = super::open_vault(&config)?;

    match action {
        ConsentAction::List { r#ref } => {
            // Normalize: parse as PiiRef to strip brackets, then use key form
            let r#ref = r#ref
                .map(|s| s.parse::<PiiRef>().map(|r| r.key()))
                .transpose()?;
            let rules = ConsentManager::list_consent(vault.conn(), r#ref.as_deref())?;

            if rules.is_empty() {
                println!("No consent rules found.");
                return Ok(());
            }

            let mut table = Table::new();
            table.set_header(vec![
                "Reference",
                "Accessor",
                "Purpose",
                "Allowed",
                "Created",
                "Expires",
            ]);

            for rule in &rules {
                let created = chrono::DateTime::from_timestamp(rule.created_at, 0)
                    .map(|dt: chrono::DateTime<chrono::Utc>| {
                        dt.format("%Y-%m-%d %H:%M").to_string()
                    })
                    .unwrap_or_else(|| rule.created_at.to_string());

                let expires = rule
                    .expires_at
                    .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                    .map(|dt: chrono::DateTime<chrono::Utc>| {
                        dt.format("%Y-%m-%d %H:%M").to_string()
                    })
                    .unwrap_or_else(|| "never".to_string());

                table.add_row(vec![
                    Cell::new(&rule.ref_id),
                    Cell::new(&rule.accessor),
                    Cell::new(&rule.purpose),
                    Cell::new(if rule.allowed { "yes" } else { "no" }),
                    Cell::new(created),
                    Cell::new(expires),
                ]);
            }

            println!("{table}");
            println!("\n{} rules", rules.len());
        }

        ConsentAction::Grant {
            ref_id,
            accessor,
            purpose,
            ttl,
            force,
        } => {
            // Validate inputs
            if ref_id.trim().is_empty() {
                anyhow::bail!("Reference ID cannot be empty");
            }
            if accessor.trim().is_empty() {
                anyhow::bail!("Accessor cannot be empty");
            }
            if purpose.trim().is_empty() {
                anyhow::bail!("Purpose cannot be empty");
            }

            // Parse ref (accepts both bracketed and bare forms)
            let pii_ref: PiiRef = ref_id.parse()?;
            let key = pii_ref.key();

            // Check if reference exists in vault (unless --force is used)
            if !force && vault.retrieve_pii(&pii_ref).is_err() {
                anyhow::bail!(
                    "Reference [{key}] not found in vault. Use --force to grant consent anyway."
                );
            }

            let duration_secs = parse_ttl(&ttl)?;
            let expires_at = chrono::Utc::now().timestamp() + duration_secs;

            ConsentManager::grant_consent(
                vault.conn(),
                &key,
                &accessor,
                &purpose,
                Some(expires_at),
            )?;

            let expires_str = chrono::DateTime::from_timestamp(expires_at, 0)
                .map(|dt: chrono::DateTime<chrono::Utc>| {
                    dt.format("%Y-%m-%d %H:%M UTC").to_string()
                })
                .unwrap_or_else(|| expires_at.to_string());

            println!(
                "{} Granted: {} can access [{}] for '{}' (expires {})",
                "✓".green(),
                accessor,
                key,
                purpose,
                expires_str
            );
        }

        ConsentAction::Revoke {
            ref_id,
            accessor,
            purpose,
        } => {
            // Validate inputs
            if ref_id.trim().is_empty() {
                anyhow::bail!("Reference ID cannot be empty");
            }
            if accessor.trim().is_empty() {
                anyhow::bail!("Accessor cannot be empty");
            }
            if purpose.trim().is_empty() {
                anyhow::bail!("Purpose cannot be empty");
            }

            let pii_ref: PiiRef = ref_id.parse()?;
            let key = pii_ref.key();
            ConsentManager::revoke_consent(vault.conn(), &key, &accessor, &purpose)?;
            println!(
                "{} Revoked: {} can no longer access [{}] for '{}'",
                "✓".green(),
                accessor,
                key,
                purpose
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_parse_minutes() {
        assert_eq!(parse_ttl("30m").unwrap(), 1800);
        assert_eq!(parse_ttl("1m").unwrap(), 60);
    }

    #[test]
    fn ttl_parse_hours() {
        assert_eq!(parse_ttl("1h").unwrap(), 3600);
        assert_eq!(parse_ttl("2h").unwrap(), 7200);
        assert_eq!(parse_ttl("24h").unwrap(), 86400);
    }

    #[test]
    fn ttl_parse_days() {
        assert_eq!(parse_ttl("7d").unwrap(), 604800);
        assert_eq!(parse_ttl("1d").unwrap(), 86400);
    }

    #[test]
    fn ttl_invalid_rejected() {
        assert!(parse_ttl("abc").is_err());
        assert!(parse_ttl("0m").is_err());
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("-1h").is_err());
        assert!(parse_ttl("10x").is_err());
    }
}
