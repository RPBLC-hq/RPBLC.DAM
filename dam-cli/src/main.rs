mod mcp;

use anyhow::Result;
use clap::{Parser, Subcommand};
use dam_core::config::DamConfig;
use dam_core::flow::FlowExecutor;
use dam_core::proxy::{ProxyState, start_proxy};
use dam_core::Module;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "dam", about = "Data Access Mediator — protect sensitive data in transit")]
struct Cli {
    /// Port to listen on
    #[arg(short, long, default_value = "7828")]
    port: u16,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    // -- Consent commands --

    /// Manage consent rules
    Consent {
        #[command(subcommand)]
        action: ConsentCommands,
    },

    // -- Vault commands --

    /// Resolve a token to its original value
    Resolve {
        /// Token key or [token] (e.g., email:7B2Hkq... or [email:7B2Hkq...])
        token: String,
    },
    /// List all tokens in the vault
    Tokens,

    // -- Log commands --

    /// Show detection statistics
    Stats,
    /// Show recent detection events
    Log {
        /// Maximum number of events to show
        #[arg(short = 'n', long, default_value = "20")]
        limit: u32,
    },

    // -- Other --

    /// Start MCP server on stdio
    Mcp,
}

#[derive(Subcommand)]
enum ConsentCommands {
    /// Grant consent — allow data to pass through
    Grant {
        /// Data type (e.g., email, ssn, cc) or * for all
        #[arg(long, default_value = "*")]
        r#type: String,

        /// Specific token key or [token] (e.g., email:7B2Hkq... or [email:7B2Hkq...])
        #[arg(long)]
        token: Option<String>,

        /// Raw value to resolve to a token (e.g., john@acme.com)
        #[arg(long)]
        value: Option<String>,

        /// Destination host (e.g., api.anthropic.com) or * for all
        #[arg(long, default_value = "*")]
        dest: String,

        /// Time-to-live (e.g., 30m, 1h, 24h, 7d) or "permanent"
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Deny — explicitly block data from passing through
    Deny {
        /// Data type or *
        #[arg(long, default_value = "*")]
        r#type: String,

        /// Specific token key or [token]
        #[arg(long)]
        token: Option<String>,

        /// Destination host or *
        #[arg(long, default_value = "*")]
        dest: String,
    },
    /// List all active consent rules
    List,
    /// Revoke a consent rule by ID
    Revoke {
        /// Rule ID to revoke
        id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose { "debug" } else { "info,dam=info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .compact()
        .init();

    let config = DamConfig {
        port: cli.port,
        verbose: cli.verbose,
        ..DamConfig::default()
    };
    config.ensure_home()?;

    match cli.command {
        Some(Commands::Consent { action }) => cmd_consent(&config, action)?,
        Some(Commands::Stats) => cmd_stats(&config)?,
        Some(Commands::Resolve { token }) => cmd_resolve(&config, &token)?,
        Some(Commands::Tokens) => cmd_tokens(&config)?,
        Some(Commands::Log { limit }) => cmd_log(&config, limit)?,
        Some(Commands::Mcp) => cmd_mcp(&config).await?,
        None => cmd_serve(&config).await?,
    }

    Ok(())
}

async fn cmd_serve(config: &DamConfig) -> Result<()> {
    let kek = dam_vault::encrypt::load_or_generate_kek(&config.key_path())?;
    let vault_store = Arc::new(dam_vault::VaultStore::open(&config.vault_db_path(), kek)?);
    let consent_store = Arc::new(dam_consent::ConsentStore::open(&config.consent_db_path())?);
    let log_store = Arc::new(dam_log::LogStore::open(&config.log_db_path())?);

    // Pipeline: detect-pii → detect-secrets → consent → vault → redact → log
    let modules: Vec<Arc<dyn Module>> = vec![
        Arc::new(dam_detect_pii::PiiDetectionModule::new()),
        Arc::new(dam_detect_secrets::SecretsDetectionModule::new()),
        Arc::new(dam_consent::ConsentModule::new(consent_store.clone())),
        Arc::new(dam_vault::VaultModule::new(vault_store.clone())),
        Arc::new(dam_redact::RedactModule::new(vault_store.clone())),
        Arc::new(dam_log::LogModule::new(log_store.clone())),
    ];

    let flow = Arc::new(FlowExecutor::new(modules));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?;

    // Auto-resolve: resolve DAM tokens in LLM responses back to original values
    let resolver_vault = vault_store.clone();
    let resolver: dam_core::proxy::TokenResolver = Arc::new(move |token| {
        resolver_vault.retrieve(token).ok()
    });

    let state = ProxyState { flow, client, resolver: Some(resolver) };
    start_proxy(state, config.port).await?;

    Ok(())
}

// -- Consent commands --

fn cmd_consent(config: &DamConfig, action: ConsentCommands) -> Result<()> {
    let consent_store = dam_consent::ConsentStore::open(&config.consent_db_path())?;

    match action {
        ConsentCommands::Grant { r#type, token, value, dest, ttl } => {
            let token_key = resolve_token_arg(config, token, value)?;
            let ttl_secs = parse_ttl(ttl.as_deref(), consent_store.default_ttl_secs)?;

            let rule = consent_store.grant(
                &r#type,
                token_key.as_deref(),
                &dest,
                dam_consent::ConsentAction::Pass,
                ttl_secs,
            )?;

            let expiry = match rule.expires_at {
                Some(ts) => format!("expires at {ts}"),
                None => "permanent".to_string(),
            };
            println!("Granted: {} ({expiry})", rule.id);
            println!("  type={} dest={}", rule.data_type, rule.destination);
            if let Some(tk) = &rule.token_key {
                println!("  token={tk}");
            }
        }
        ConsentCommands::Deny { r#type, token, dest } => {
            let token_key = resolve_token_arg(config, token, None)?;

            let rule = consent_store.grant(
                &r#type,
                token_key.as_deref(),
                &dest,
                dam_consent::ConsentAction::Redact,
                None, // deny rules are permanent by default
            )?;

            println!("Denied: {} (permanent)", rule.id);
            println!("  type={} dest={}", rule.data_type, rule.destination);
            if let Some(tk) = &rule.token_key {
                println!("  token={tk}");
            }
        }
        ConsentCommands::List => {
            let rules = consent_store.list()?;
            if rules.is_empty() {
                println!("No active consent rules.");
                return Ok(());
            }

            println!("{:<38} {:<8} {:<12} {:<25} {:<10}", "ID", "ACTION", "TYPE", "DESTINATION", "EXPIRES");
            println!("{}", "-".repeat(95));
            for rule in &rules {
                let action = rule.action.as_str();
                let token_suffix = rule.token_key.as_ref()
                    .map(|t| format!(" [{}]", t))
                    .unwrap_or_default();
                let expiry = rule.expires_at
                    .map(|ts| ts.to_string())
                    .unwrap_or_else(|| "permanent".into());
                println!(
                    "{:<38} {:<8} {:<12} {:<25} {:<10}",
                    rule.id,
                    action,
                    format!("{}{}", rule.data_type, token_suffix),
                    rule.destination,
                    expiry,
                );
            }
        }
        ConsentCommands::Revoke { id } => {
            if consent_store.revoke(&id)? {
                println!("Revoked: {id}");
            } else {
                println!("Rule not found: {id}");
            }
        }
    }

    Ok(())
}

/// Resolve --token or --value arguments to a token key string.
fn resolve_token_arg(
    config: &DamConfig,
    token: Option<String>,
    value: Option<String>,
) -> Result<Option<String>> {
    if let Some(t) = token {
        // Strip brackets if present: [email:xxx] → email:xxx
        let inner = t.strip_prefix('[').unwrap_or(&t);
        let inner = inner.strip_suffix(']').unwrap_or(inner);
        return Ok(Some(inner.to_string()));
    }

    if let Some(val) = value {
        // Look up the value in the vault to find its token
        let kek = dam_vault::encrypt::load_or_generate_kek(&config.key_path())?;
        let store = dam_vault::VaultStore::open(&config.vault_db_path(), kek)?;
        let entries = store.list(None)?;
        for entry in &entries {
            let token: dam_core::Token = match entry.ref_id.parse() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if let Ok(stored_val) = store.retrieve(&token) {
                if stored_val == val {
                    return Ok(Some(entry.ref_id.clone()));
                }
            }
        }
        anyhow::bail!("Value '{}' not found in vault. It must be detected first.", val);
    }

    Ok(None)
}

/// Parse TTL string to seconds. "permanent" → None, "30m" → Some(1800), etc.
fn parse_ttl(ttl: Option<&str>, default_secs: u64) -> Result<Option<u64>> {
    match ttl {
        None => {
            if default_secs == 0 {
                Ok(None)
            } else {
                Ok(Some(default_secs))
            }
        }
        Some("permanent") | Some("perm") | Some("forever") => Ok(None),
        Some(s) => {
            let (num_str, multiplier) = if let Some(n) = s.strip_suffix('m') {
                (n, 60u64)
            } else if let Some(n) = s.strip_suffix('h') {
                (n, 3600u64)
            } else if let Some(n) = s.strip_suffix('d') {
                (n, 86400u64)
            } else if let Some(n) = s.strip_suffix('s') {
                (n, 1u64)
            } else {
                // Assume seconds
                (s, 1u64)
            };
            let num: u64 = num_str.parse()
                .map_err(|_| anyhow::anyhow!("Invalid TTL: '{s}'. Use 30m, 1h, 24h, 7d, or permanent."))?;
            Ok(Some(num * multiplier))
        }
    }
}

// -- Vault commands --

fn cmd_resolve(config: &DamConfig, token_str: &str) -> Result<()> {
    let kek = dam_vault::encrypt::load_or_generate_kek(&config.key_path())?;
    let store = dam_vault::VaultStore::open(&config.vault_db_path(), kek)?;
    let token: dam_core::Token = token_str.parse()?;
    match store.retrieve(&token) {
        Ok(value) => println!("{value}"),
        Err(e) => eprintln!("Error: {e}"),
    }
    Ok(())
}

fn cmd_tokens(config: &DamConfig) -> Result<()> {
    let kek = dam_vault::encrypt::load_or_generate_kek(&config.key_path())?;
    let store = dam_vault::VaultStore::open(&config.vault_db_path(), kek)?;
    let entries = store.list(None)?;

    if entries.is_empty() {
        println!("Vault is empty.");
        return Ok(());
    }

    println!("{:<40} {:<12} {}", "TOKEN", "TYPE", "CREATED");
    println!("{}", "-".repeat(65));
    for entry in &entries {
        println!("{:<40} {:<12} {}", entry.ref_id, entry.data_type, entry.created_at);
    }
    Ok(())
}

// -- Log commands --

fn cmd_stats(config: &DamConfig) -> Result<()> {
    let log_store = dam_log::LogStore::open(&config.log_db_path())?;
    let stats = log_store.stats()?;

    if stats.is_empty() {
        println!("No detections recorded yet.");
        return Ok(());
    }

    println!("{:<12} {:>6} {:>8} {:>6}  {}", "TYPE", "TOTAL", "REDACTED", "PASSED", "TOP DESTINATIONS");
    println!("{}", "-".repeat(75));
    for stat in &stats {
        let dests = stat.top_destinations.join(", ");
        println!("{:<12} {:>6} {:>8} {:>6}  {}", stat.data_type, stat.count, stat.redacted, stat.passed, dests);
    }
    Ok(())
}

fn cmd_log(config: &DamConfig, limit: u32) -> Result<()> {
    let log_store = dam_log::LogStore::open(&config.log_db_path())?;
    let events = log_store.query_all(Some(limit))?;

    if events.is_empty() {
        println!("No events recorded yet.");
        return Ok(());
    }

    println!("{:<12} {:<20} {:<10} {}", "TYPE", "DESTINATION", "ACTION", "PREVIEW");
    println!("{}", "-".repeat(65));
    for event in &events {
        println!("{:<12} {:<20} {:<10} {}", event.data_type, event.destination, event.action, event.value_preview);
    }
    Ok(())
}

// -- MCP --

async fn cmd_mcp(config: &DamConfig) -> Result<()> {
    use rmcp::ServiceExt;

    let kek = dam_vault::encrypt::load_or_generate_kek(&config.key_path())?;
    let vault_store = Arc::new(dam_vault::VaultStore::open(&config.vault_db_path(), kek)?);
    let consent_store = Arc::new(dam_consent::ConsentStore::open(&config.consent_db_path())?);
    let log_store = Arc::new(dam_log::LogStore::open(&config.log_db_path())?);

    let server = mcp::DamMcpServer::new(vault_store, consent_store, log_store);
    let transport = rmcp::transport::io::stdio();

    let service = server.serve(transport).await?;
    service.waiting().await?;

    Ok(())
}
