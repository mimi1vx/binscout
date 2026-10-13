//! binscout core: headless agent-first binary analysis (M0 scaffold).

pub mod disasm;
pub mod error;
pub mod ir;
pub mod loader;

use std::path::Path;

use crate::error::{Error, Result};

/// Crate version, also served via CLI `--version` and MCP `project_info`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Opened analysis project (M0: stub, no DB yet).
///
/// M1+ will memory-map `path`, parse headers via `object`,
/// and open the `redb` store. M0 only validates the path exists
/// so CLI/MCP plumbing can be tested end to end.
#[derive(Debug)]
pub struct Project {
    path: std::path::PathBuf,
}

impl Project {
    /// Open a binary for analysis.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] if the path does not exist,
    /// [`Error::Unsupported`] if it is not a file (M1 refines this).
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::NotFound(path.display().to_string()));
        }
        if !path.is_file() {
            return Err(Error::Unsupported(format!(
                "not a file: {}",
                path.display()
            )));
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// Path of the analyzed binary.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}
