//! binscout-mcp: MCP server over stdio (M6).

use rmcp::ServiceExt;
use rmcp::transport::io::stdio;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = binscout::mcp::BinscoutMcp::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
