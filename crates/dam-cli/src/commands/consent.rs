use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;
use comfy_table::{Cell, Table};
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
        /// Reference key, e.g. "email:a3f7"
        ref_id: String,
        /// Accessor (tool name), e.g. "claude", "send_email", or "*" for all
        accessor: String,
        /// Purpose, e.g. "send_email", "display", or "*" for all
        purpose: String,
    },

    /// Revoke consent
    Revoke {
        /// Reference key, e.g. "email:a3f7"
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
        } => {
            ConsentManager::grant_consent(vault.conn(), &ref_id, &accessor, &purpose, None)?;
            println!(
                "{} Granted: {} can access [{}] for '{}'",
                "✓".green(),
                accessor,
                ref_id,
                purpose
            );
        }

        ConsentAction::Revoke {
            ref_id,
            accessor,
            purpose,
        } => {
            ConsentManager::revoke_consent(vault.conn(), &ref_id, &accessor, &purpose)?;
            println!(
                "{} Revoked: {} can no longer access [{}] for '{}'",
                "✓".green(),
                accessor,
                ref_id,
                purpose
            );
        }
    }

    Ok(())
}
