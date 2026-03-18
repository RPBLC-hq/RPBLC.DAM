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
    /// Show detection statistics
    Stats,
    /// Resolve a token to its original value
    Resolve {
        /// Token to resolve (e.g., email:a3f71bc9)
        token: String,
    },
    /// List all tokens in the vault
    Tokens,
    /// Show recent detection events
    Log {
        /// Maximum number of events to show
        #[arg(short = 'n', long, default_value = "20")]
        limit: u32,
    },
    /// Start MCP server on stdio
    Mcp,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup tracing
    let filter = if cli.verbose { "debug" } else { "info,dam=info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .compact()
        .init();

    // Setup config
    let config = DamConfig {
        port: cli.port,
        verbose: cli.verbose,
        ..DamConfig::default()
    };
    config.ensure_home()?;

    match cli.command {
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
    // Initialize vault
    let kek = dam_vault::encrypt::load_or_generate_kek(&config.key_path())?;
    let vault_store = Arc::new(dam_vault::VaultStore::open(&config.vault_db_path(), kek)?);

    // Initialize log store
    let log_store = Arc::new(dam_log::LogStore::open(&config.log_db_path())?);

    // Build module chain: detect-pii → detect-secrets → vault → log
    let modules: Vec<Arc<dyn Module>> = vec![
        Arc::new(dam_detect_pii::PiiDetectionModule::new()),
        Arc::new(dam_detect_secrets::SecretsDetectionModule::new()),
        Arc::new(dam_vault::VaultModule::new(vault_store.clone())),
        Arc::new(dam_log::LogModule::new(log_store.clone())),
    ];

    let flow = Arc::new(FlowExecutor::new(modules));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?;

    let state = ProxyState { flow, client };
    start_proxy(state, config.port).await?;

    Ok(())
}

fn cmd_stats(config: &DamConfig) -> Result<()> {
    let log_store = dam_log::LogStore::open(&config.log_db_path())?;
    let stats = log_store.stats()?;

    if stats.is_empty() {
        println!("No detections recorded yet.");
        return Ok(());
    }

    println!("{:<15} {:>8}  {}", "TYPE", "COUNT", "TOP DESTINATIONS");
    println!("{}", "-".repeat(60));
    for stat in &stats {
        let dests = stat.top_destinations.join(", ");
        println!("{:<15} {:>8}  {}", stat.data_type, stat.count, dests);
    }
    Ok(())
}

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

    println!("{:<25} {:<12} {}", "TOKEN", "TYPE", "CREATED");
    println!("{}", "-".repeat(55));
    for entry in &entries {
        println!("{:<25} {:<12} {}", entry.ref_id, entry.data_type, entry.created_at);
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

async fn cmd_mcp(_config: &DamConfig) -> Result<()> {
    println!("MCP server not yet implemented (phase 2)");
    Ok(())
}
