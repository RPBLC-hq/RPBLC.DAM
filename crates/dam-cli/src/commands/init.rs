use anyhow::Result;
use colored::Colorize;
use dam_core::Locale;
use dam_core::config::DamConfig;
use dam_vault::KeychainManager;

pub async fn run() -> Result<()> {
    let home = DamConfig::default_home();
    let config_path = DamConfig::default_config_path();

    println!("{}", "DAM — Initializing".bold());
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

    // 3. Select locales + create config
    let mut config = DamConfig::default();
    if !config_path.exists() {
        let selected_locales = select_locales()?;
        let locale_display: Vec<String> = selected_locales.iter().map(|l| l.to_string()).collect();
        println!(
            "  {} Detection locales: {}",
            "✓".green(),
            locale_display.join(", ")
        );

        config.detection.locales = selected_locales;
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

/// Detect likely locales from the OS locale string.
fn suggest_locales_from_os() -> Vec<Locale> {
    suggest_locales_from_str(sys_locale::get_locale().as_deref())
}

/// Parse a locale string (e.g. "en-US", "fr-FR") into suggested Locale selections.
fn suggest_locales_from_str(locale_str: Option<&str>) -> Vec<Locale> {
    let Some(locale) = locale_str else {
        return vec![Locale::Us];
    };

    // Normalize: "en_US" → "en-us", "fr-FR" → "fr-fr"
    let normalized = locale.replace('_', "-").to_lowercase();

    // Try to extract country code (after the dash)
    let country = normalized.split('-').nth(1).unwrap_or("");
    let lang = normalized.split('-').next().unwrap_or("");

    match (lang, country) {
        (_, "us") => vec![Locale::Us],
        (_, "ca") if lang == "fr" => vec![Locale::Ca, Locale::Fr],
        (_, "ca") => vec![Locale::Us, Locale::Ca],
        (_, "gb") => vec![Locale::Uk, Locale::Eu],
        ("fr", _) => vec![Locale::Fr, Locale::Eu],
        ("de", _) => vec![Locale::De, Locale::Eu],
        _ => vec![Locale::Us],
    }
}

/// Run the interactive locale selection, or fall back to OS detection for non-TTY.
fn select_locales() -> Result<Vec<Locale>> {
    use std::io::IsTerminal;

    let os_suggestions = suggest_locales_from_os();

    if !std::io::stdin().is_terminal() {
        // Non-interactive fallback
        let mut locales = vec![Locale::Global];
        locales.extend(&os_suggestions);
        let display: Vec<String> = locales.iter().map(|l| l.to_string()).collect();
        println!(
            "  Non-interactive mode: using detected locale(s): {}",
            display.join(", ")
        );
        return Ok(locales);
    }

    let selectable = Locale::selectable();
    let items: Vec<&str> = selectable.iter().map(|l| l.label()).collect();

    // Pre-select items matching OS suggestions
    let defaults: Vec<bool> = selectable
        .iter()
        .map(|l| os_suggestions.contains(l))
        .collect();

    println!("Select regions you handle personal data from:");
    println!("  {} is always active.", Locale::Global.label());
    println!();

    let chosen_indices = dialoguer::MultiSelect::new()
        .items(&items)
        .defaults(&defaults)
        .with_prompt("  ↑↓ move · Space toggle · Enter confirm")
        .report(false)
        .interact()?;

    let mut locales = vec![Locale::Global];
    for idx in chosen_indices {
        locales.push(selectable[idx]);
    }

    println!("  Tip: Change later with `dam config set detection.locales`");

    Ok(locales)
}

/// Parse a comma-separated locale string into a Vec<Locale>, always including Global.
pub fn parse_locale_list(value: &str) -> Result<Vec<Locale>, dam_core::DamError> {
    if value.trim().eq_ignore_ascii_case("all") {
        return Ok(Locale::all().to_vec());
    }

    let mut locales = vec![Locale::Global];
    for part in value.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let locale: Locale = trimmed.parse()?;
        if !locales.contains(&locale) {
            locales.push(locale);
        }
    }

    Ok(locales)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggest_us_for_en_us() {
        let result = suggest_locales_from_str(Some("en-US"));
        assert_eq!(result, vec![Locale::Us]);
    }

    #[test]
    fn suggest_us_ca_for_en_ca() {
        let result = suggest_locales_from_str(Some("en-CA"));
        assert_eq!(result, vec![Locale::Us, Locale::Ca]);
    }

    #[test]
    fn suggest_uk_eu_for_en_gb() {
        let result = suggest_locales_from_str(Some("en-GB"));
        assert_eq!(result, vec![Locale::Uk, Locale::Eu]);
    }

    #[test]
    fn suggest_fr_eu_for_fr_fr() {
        let result = suggest_locales_from_str(Some("fr-FR"));
        assert_eq!(result, vec![Locale::Fr, Locale::Eu]);
    }

    #[test]
    fn suggest_ca_fr_for_fr_ca() {
        let result = suggest_locales_from_str(Some("fr-CA"));
        assert_eq!(result, vec![Locale::Ca, Locale::Fr]);
    }

    #[test]
    fn suggest_de_eu_for_de_de() {
        let result = suggest_locales_from_str(Some("de-DE"));
        assert_eq!(result, vec![Locale::De, Locale::Eu]);
    }

    #[test]
    fn suggest_de_eu_for_de_at() {
        let result = suggest_locales_from_str(Some("de-AT"));
        assert_eq!(result, vec![Locale::De, Locale::Eu]);
    }

    #[test]
    fn suggest_us_for_unknown() {
        let result = suggest_locales_from_str(Some("zh-TW"));
        assert_eq!(result, vec![Locale::Us]);
    }

    #[test]
    fn suggest_us_for_none() {
        let result = suggest_locales_from_str(None);
        assert_eq!(result, vec![Locale::Us]);
    }

    #[test]
    fn suggest_handles_underscore() {
        let result = suggest_locales_from_str(Some("en_US"));
        assert_eq!(result, vec![Locale::Us]);
    }

    #[test]
    fn parse_locale_list_basic() {
        let result = parse_locale_list("us,ca").unwrap();
        assert_eq!(result, vec![Locale::Global, Locale::Us, Locale::Ca]);
    }

    #[test]
    fn parse_locale_list_all() {
        let result = parse_locale_list("all").unwrap();
        assert_eq!(result, Locale::all().to_vec());
    }

    #[test]
    fn parse_locale_list_includes_global() {
        let result = parse_locale_list("fr").unwrap();
        assert!(result.contains(&Locale::Global));
        assert!(result.contains(&Locale::Fr));
    }

    #[test]
    fn parse_locale_list_dedup() {
        let result = parse_locale_list("us,us,global").unwrap();
        assert_eq!(result, vec![Locale::Global, Locale::Us]);
    }

    #[test]
    fn parse_locale_list_with_spaces() {
        let result = parse_locale_list(" us , ca , de ").unwrap();
        assert_eq!(
            result,
            vec![Locale::Global, Locale::Us, Locale::Ca, Locale::De]
        );
    }

    #[test]
    fn parse_locale_list_invalid() {
        let err = parse_locale_list("us,xx").unwrap_err();
        assert!(err.to_string().contains("unknown locale"));
    }
}
