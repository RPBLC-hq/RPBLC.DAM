use anyhow::Result;
use comfy_table::{Cell, Table};
use dam_vault::AuditLog;

pub async fn run(ref_filter: Option<String>, limit: usize) -> Result<()> {
    let config = super::load_config()?;
    let vault = super::open_vault(&config)?;

    let ref_filter = ref_filter.map(|s| super::strip_brackets(&s).to_owned());
    let entries = AuditLog::query(vault.conn(), ref_filter.as_deref(), limit)?;

    if entries.is_empty() {
        println!("No audit entries found.");
        return Ok(());
    }

    let mut table = Table::new();
    table.set_header(vec![
        "ID",
        "Time",
        "Reference",
        "Accessor",
        "Purpose",
        "Action",
        "Granted",
        "Detail",
    ]);

    for entry in &entries {
        let ts = chrono::DateTime::from_timestamp(entry.ts, 0)
            .map(|dt: chrono::DateTime<chrono::Utc>| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| entry.ts.to_string());

        table.add_row(vec![
            Cell::new(entry.id),
            Cell::new(ts),
            Cell::new(&entry.ref_id),
            Cell::new(&entry.accessor),
            Cell::new(&entry.purpose),
            Cell::new(&entry.action),
            Cell::new(if entry.granted { "yes" } else { "no" }),
            Cell::new(entry.detail.as_deref().unwrap_or("-")),
        ]);
    }

    println!("{table}");
    println!("\n{} entries (limit: {limit})", entries.len());

    if entries.iter().any(|e| e.prev_hash.is_some()) {
        println!("\nHash chain: present (use 'dam audit --verify' to validate)");
    }

    Ok(())
}
