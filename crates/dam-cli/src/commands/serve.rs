use anyhow::Result;
use dam_http::proxy::AppState;
use dam_http::server::router;

use super::{load_config, open_vault};

pub async fn run(
    port: u16,
    anthropic_upstream: Option<String>,
    openai_upstream: Option<String>,
    codex_upstream: Option<String>,
) -> Result<()> {
    let mut config = load_config()?;
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

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
