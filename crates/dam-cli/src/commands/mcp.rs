use anyhow::Result;
use dam_detect::DetectionPipeline;
use dam_mcp::DamMcpServer;
use dam_resolve::Resolver;
use rmcp::ServiceExt;
use std::sync::Arc;

pub async fn run() -> Result<()> {
    let (config, _auto_inited) = super::load_config_auto_init()?;
    let vault = super::open_vault(&config)?;

    let pipeline = Arc::new(DetectionPipeline::new(&config, vault.clone()));
    let resolver = Arc::new(Resolver::new(vault.clone()));

    let server = DamMcpServer::new(vault, pipeline, resolver);

    let transport = rmcp::transport::io::stdio();
    let service = server.serve(transport).await?;
    service.waiting().await?;

    Ok(())
}
