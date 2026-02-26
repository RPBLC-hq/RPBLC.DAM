use anyhow::Result;
use dam_core::config::DamConfig;
use dam_http::proxy::AppState;
use dam_http::router::router;

use super::{load_config_auto_init, open_vault};

/// Path to the PID file: `~/.dam/dam.pid`
fn pid_file_path() -> std::path::PathBuf {
    DamConfig::default_home().join("dam.pid")
}

/// Write current process PID to the PID file.
fn write_pid_file() -> Result<()> {
    let path = pid_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, std::process::id().to_string())?;
    Ok(())
}

/// Remove the PID file if it exists.
fn remove_pid_file() {
    let path = pid_file_path();
    let _ = std::fs::remove_file(path);
}

/// Wait for a shutdown signal (ctrl-c on all platforms, SIGTERM on Unix).
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }

    eprintln!("\nShutting down...");
    remove_pid_file();
}

pub async fn run(
    port: u16,
    anthropic_upstream: Option<String>,
    openai_upstream: Option<String>,
    codex_upstream: Option<String>,
) -> Result<()> {
    let (mut config, _auto_inited) = load_config_auto_init()?;
    tracing::debug!("config loaded");
    let vault = open_vault(&config)?;
    tracing::debug!("vault opened");

    // Apply CLI overrides
    if let Some(url) = anthropic_upstream {
        config.server.anthropic_upstream_url = Some(url);
    }
    if let Some(url) = openai_upstream {
        config.server.openai_upstream_url = Some(url);
    }
    if let Some(url) = codex_upstream {
        config.server.codex_upstream_url = Some(url);
    }

    let state = AppState::new(&config, vault);
    let app = router(state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Write PID file after successfully binding
    write_pid_file()?;

    eprintln!("DAM proxy listening on http://{addr}");
    eprintln!();
    eprintln!("  Anthropic: set ANTHROPIC_BASE_URL=http://{addr}");
    eprintln!("  OpenAI:    set OPENAI_BASE_URL=http://{addr}/v1");
    eprintln!("  Codex:     set baseUrl=http://{addr}");
    eprintln!();
    eprintln!("Routes:");
    eprintln!("  GET  /healthz               (liveness)");
    eprintln!("  GET  /readyz                (readiness)");
    eprintln!("  POST /v1/messages           (Anthropic Messages API)");
    eprintln!("  POST /v1/chat/completions   (OpenAI Chat Completions API)");
    eprintln!("  POST /v1/responses          (OpenAI Responses API)");
    eprintln!("  POST /codex/responses       (OpenAI Codex API)");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}
