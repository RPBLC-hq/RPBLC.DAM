use anyhow::Result;
use dam_http::proxy::AppState;
use dam_http::server::router;

use super::{load_config, open_vault};

pub async fn run(port: u16) -> Result<()> {
    let config = load_config()?;
    let vault = open_vault(&config)?;

    let state = AppState::new(&config, vault);
    let app = router(state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    eprintln!("DAM proxy listening on http://{addr}");
    eprintln!("Set ANTHROPIC_BASE_URL=http://{addr} to use with any Anthropic client");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
