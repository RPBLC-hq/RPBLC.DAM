use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;
use comfy_table::{Cell, Table};
use dam_core::{PiiRef, PiiType};

#[derive(Subcommand)]
pub enum VaultAction {
    /// List vault entries (metadata only, no decryption)
    List {
        /// Filter by PII type (e.g., "email", "phone")
        #[arg(long, short = 't')]
        r#type: Option<String>,
    },

    /// Show (decrypt) a specific entry
    Show {
        /// Reference key, e.g. "email:a3f71bc9"
        ref_id: String,
    },

    /// Delete a vault entry
    Delete {
        /// Reference key, e.g. "email:a3f71bc9"
        ref_id: String,
    },
}

pub async fn run(action: VaultAction) -> Result<()> {
    let config = super::load_config()?;
    let vault = super::open_vault(&config)?;

    match action {
        VaultAction::List { r#type } => {
            let type_filter = r#type
                .as_deref()
                .map(|t| t.parse::<PiiType>())
                .transpose()?;

            let entries = vault.list_entries(type_filter)?;

            if entries.is_empty() {
                println!("No entries found.");
                return Ok(());
            }

            let mut table = Table::new();
            table.set_header(vec!["Reference", "Type", "Created", "Source", "Label"]);

            for entry in &entries {
                let created = chrono::DateTime::from_timestamp(entry.created_at, 0)
                    .map(|dt: chrono::DateTime<chrono::Utc>| {
                        dt.format("%Y-%m-%d %H:%M").to_string()
                    })
                    .unwrap_or_else(|| entry.created_at.to_string());

                table.add_row(vec![
                    Cell::new(&entry.ref_id),
                    Cell::new(entry.pii_type.to_string()),
                    Cell::new(created),
                    Cell::new(entry.source.as_deref().unwrap_or("-")),
                    Cell::new(entry.label.as_deref().unwrap_or("-")),
                ]);
            }

            println!("{table}");
            println!("\n{} entries", entries.len());
        }

        VaultAction::Show { ref_id } => {
            let pii_ref = PiiRef::from_key(&ref_id)?;
            let value = vault.retrieve_pii(&pii_ref)?;
            println!("{}: {}", ref_id.yellow(), value);
        }

        VaultAction::Delete { ref_id } => {
            let pii_ref = PiiRef::from_key(&ref_id)?;
            vault.delete_entry(&pii_ref)?;
            println!("{} Deleted [{}]", "✓".green(), ref_id);
        }
    }

    Ok(())
}
