use anyhow::Result;
use colored::Colorize;
use dam_core::config::DamConfig;
use dam_vault::KeychainManager;

pub async fn run() -> Result<()> {
    let home = DamConfig::default_home();
    let config_path = DamConfig::default_config_path();

    println!("{}", "RPBLC DAM — Initializing".bold());
    println!();

    // 1. Create home directory
    std::fs::create_dir_all(&home)?;
    println!("  {} Created {}", "✓".green(), home.display());

    // 2. Generate and store KEK
    match KeychainManager::get_kek() {
        Ok(_) => {
            println!("  {} KEK already exists in OS keychain", "✓".green());
        }
        Err(_) => {
            KeychainManager::get_or_create_kek()?;
            println!("  {} Generated KEK and stored in OS keychain", "✓".green());
        }
    }

    // 3. Create default config
    let config = DamConfig::default();
    if !config_path.exists() {
        config.save(&config_path)?;
        println!("  {} Created {}", "✓".green(), config_path.display());
    } else {
        println!(
            "  {} Config already exists at {}",
            "✓".green(),
            config_path.display()
        );
    }

    // 4. Create vault database
    let kek = KeychainManager::get_kek()?;
    let _vault = dam_vault::VaultStore::open(&config.vault.path, kek)?;
    println!(
        "  {} Created vault at {}",
        "✓".green(),
        config.vault.path.display()
    );

    println!();
    println!("{}", "MCP Configuration".bold().underline());
    println!();

    let dam_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "dam".to_string());

    // Claude Code
    println!("{}", "Claude Code (.mcp.json):".bold());
    println!(
        r#"{{
  "mcpServers": {{
    "dam": {{
      "command": "{}",
      "args": ["mcp"]
    }}
  }}
}}"#,
        dam_path.replace('\\', "\\\\")
    );
    println!();

    // Codex
    println!("{}", "Codex (~/.codex/config.toml):".bold());
    println!(
        r#"[mcp_servers.dam]
command = "{}"
args = ["mcp"]"#,
        dam_path.replace('\\', "\\\\")
    );
    println!();

    // OpenClaw
    println!("{}", "OpenClaw (mcp_config.json):".bold());
    println!(
        r#"{{
  "mcpServers": {{
    "dam": {{
      "command": "{}",
      "args": ["mcp"]
    }}
  }}
}}"#,
        dam_path.replace('\\', "\\\\")
    );

    println!();
    println!(
        "{}",
        "Copy the appropriate config snippet above into your agent's configuration file.".dimmed()
    );
    println!(
        "{}",
        "Then restart the agent to enable DAM protection.".dimmed()
    );

    Ok(())
}
