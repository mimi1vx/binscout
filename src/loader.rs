//! M1 loader: binary format readers mapped to shared [`Segment`]s.
//!
//! ELF/PE/Mach-O go through the `object` crate (parent epic
//! `rsdbg-m1-loader-0tp`); the LE branch is a custom pure-Rust reader in
//! [`le`] because `object` has no Linear Executable support.

pub mod le;

use crate::disasm::Arch;

/// One loaded object: a contiguous virtual range with its file bytes.
///
/// `data` holds the file-backed prefix of the range (zero-padded per page by
/// the LE reader); `mem_size` is the full in-memory size, which may exceed
/// `data.len()` when the tail is zero-fill or `bss`-like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Flat virtual address of the first byte.
    pub vaddr: u64,
    /// In-memory size of the object.
    pub mem_size: u64,
    /// File-backed bytes starting at `vaddr`.
    pub data: Vec<u8>,
    /// Object is readable.
    pub readable: bool,
    /// Object is writable.
    pub writable: bool,
    /// Object is executable.
    pub executable: bool,
}

impl Segment {
    /// Architecture the segment's code targets (LE is x86-only for now).
    #[must_use]
    pub fn arch(&self) -> Arch {
        Arch::X86_32
    }

    /// Length of the file-backed prefix.
    #[must_use]
    pub fn file_size(&self) -> usize {
        self.data.len()
    }
}
