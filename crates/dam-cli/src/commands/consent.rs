use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;
use comfy_table::{Cell, Table};
use dam_core::PiiRef;
use dam_vault::ConsentManager;

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

            ConsentManager::grant_consent(vault.conn(), &key, &accessor, &purpose, None)?;
            println!(
                "{} Granted: {} can access [{}] for '{}'",
                "✓".green(),
                accessor,
                key,
                purpose
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
