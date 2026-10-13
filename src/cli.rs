use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;

/// Agent-first CLI: every command prints valid JSON to stdout.
#[derive(Debug, Parser)]
#[command(
    name = "rsdbg",
    version,
    about = "headless agent-first binary analysis"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Show project/binary info (M0: path + version only).
    ProjectInfo { binary: PathBuf },
    /// List functions (M0: unimplemented, reserved for M4).
    Functions { binary: PathBuf },
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.cmd {
            Cmd::ProjectInfo { binary } => {
                let p = rsdbg::Project::open(&binary)
                    .with_context(|| format!("open {}", binary.display()))?;
                println!(
                    "{}",
                    json!({"binary": p.path().display().to_string(), "version": rsdbg::version()})
                );
            }
            Cmd::Functions { .. } => {
                anyhow::bail!("functions: not implemented until M4 (analysis)");
            }
        }
        Ok(())
    }
}
