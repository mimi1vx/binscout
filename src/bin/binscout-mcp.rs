//! binscout-mcp: MCP server entry (M0 stub, full tools land in M6).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!(
        "{}",
        serde_json::json!({"name": "binscout-mcp", "version": binscout::version(), "status": "stub-m0"})
    );
    Ok(())
}
