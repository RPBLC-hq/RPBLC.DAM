//! CLI binary for DAM — wires all crates together into a single `dam` command.
//!
//! Subcommands: `init`, `mcp`, `scan`, `vault`, `consent`, `audit`, `config`, `serve`.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "dam", version, about = "DAM — PII firewall for AI agents")]
struct Cli {
    /// Enable verbose logging (debug-level tracing output)
    #[arg(long, short, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize DAM: create vault, store KEK, generate config
    Init,

    /// Start the MCP server (stdio transport)
    Mcp,

    /// Scan text for PII and show redacted output
    Scan {
        /// Text to scan (reads from stdin if omitted)
        text: Option<String>,
    },

    /// Manage vault entries
    Vault {
        #[command(subcommand)]
        action: commands::vault::VaultAction,
    },

    /// Manage consent rules
    Consent {
        #[command(subcommand)]
        action: commands::consent::ConsentAction,
    },

    /// View audit trail
    Audit {
        /// Filter by reference key (e.g., "email:a3f71bc9")
        #[arg(long)]
        r#ref: Option<String>,

        /// Maximum number of entries to show
        #[arg(long, default_value = "50")]
        limit: usize,
    },

    /// View or update configuration
    Config {
        #[command(subcommand)]
        action: commands::config::ConfigAction,
    },

    /// Start the HTTP proxy (Anthropic + OpenAI API passthrough with PII redaction)
    Serve {
        /// Port to listen on
        #[arg(long, default_value = "7828")]
        port: u16,

        /// Override upstream Anthropic API base URL
        #[arg(long)]
        anthropic_upstream: Option<String>,

        /// Override upstream OpenAI API base URL
        #[arg(long)]
        openai_upstream: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing (only for non-MCP commands, MCP uses stdio)
    let cli = Cli::parse();

    match &cli.command {
        Commands::Mcp => {} // Don't init tracing for MCP (it uses stdio)
        _ => {
            let default_level = if cli.verbose {
                tracing::Level::DEBUG
            } else {
                tracing::Level::WARN
            };
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env()
                        .add_directive(default_level.into()),
                )
                .init();
        }
    }

    match cli.command {
        Commands::Init => commands::init::run().await,
        Commands::Mcp => commands::mcp::run().await,
        Commands::Scan { text } => commands::scan::run(text).await,
        Commands::Vault { action } => commands::vault::run(action).await,
        Commands::Consent { action } => commands::consent::run(action).await,
        Commands::Audit { r#ref, limit } => commands::audit::run(r#ref, limit).await,
        Commands::Config { action } => commands::config::run(action).await,
        Commands::Serve {
            port,
            anthropic_upstream,
            openai_upstream,
        } => commands::serve::run(port, anthropic_upstream, openai_upstream).await,
    }
}
