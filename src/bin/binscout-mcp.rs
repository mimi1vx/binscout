//! binscout-mcp: MCP server over stdio (M6).

use rmcp::ServiceExt;
use rmcp::transport::async_rw::AsyncRwTransport;
use rmcp::transport::io::stdio;

/// Inbound stdio line cap: rmcp drops longer lines without a response, so
/// this must sit above the largest line the handler still answers with a
/// proper error — a maxed-out `annotations_import` document plus its
/// JSON-RPC envelope.
const MAX_LINE_BYTES: usize = binscout::annotations::MAX_TRANSFER_BYTES + 1024 * 1024;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (stdin, stdout) = stdio();
    let transport =
        AsyncRwTransport::new_server(stdin, stdout).with_max_line_length(MAX_LINE_BYTES);
    let service = binscout::mcp::BinscoutMcp::new().serve(transport).await?;
    service.waiting().await?;
    Ok(())
}
