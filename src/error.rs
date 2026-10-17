//! Core errors: the [`Error`](enum@crate::error::Error) variants and the [`Result`] alias.

use thiserror::Error;

/// Core error type for the library (application binaries wrap with `anyhow` + context).
#[derive(Debug, Error)]
pub enum Error {
    /// Requested binary or project path does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// Valid file but unsupported format/arch for this version.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Bytes that do not decode to a valid instruction.
    #[error("invalid opcode: {0}")]
    Invalid(String),
    /// Analysis limits hit (cap on insns, JSON bytes, pagination).
    #[error("limit exceeded: {0}")]
    Limit(String),
    /// Persistent store failure.
    #[error("storage: {0}")]
    Storage(String),
    /// Operating-system I/O failure (read/stat/open outside the sidecar).
    #[error("io: {0}")]
    Io(String),
}

impl Error {
    /// Machine-readable kind for the `kind` field of the CLI error
    /// envelope and the MCP error `data` object. The human message
    /// (`Display`) is unchanged; match on this instead of parsing it.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "not_found",
            Self::Unsupported(_) => "unsupported",
            Self::Invalid(_) => "invalid",
            Self::Limit(_) => "limit",
            Self::Storage(_) => "storage",
            Self::Io(_) => "io",
        }
    }
}

/// Library result alias.
pub type Result<T> = std::result::Result<T, Error>;
