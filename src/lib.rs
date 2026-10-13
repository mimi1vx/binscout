#![warn(missing_docs)]
//! binscout core: headless agent-first binary analysis.

pub mod analysis;
pub mod db;
pub mod disasm;
pub mod error;
pub mod ir;
pub mod loader;
pub mod mcp;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::analysis::{Analysis, Xref, XrefKind, analyze};
use crate::db::{Annotation, BinaryMeta, ProjectInfo};
use crate::disasm::{Disassembler, Insn};
use crate::error::{Error, Result};
use crate::loader::{LoadedBinary, RawOptions, load, load_raw};

/// Crate version, also served via CLI `--version` and MCP `project_info`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Opened analysis project: binary plus its cached analysis and annotations.
///
/// The binary file is only ever read; all persistence (analysis snapshot,
/// renames, comments) goes to the `redb` sidecar at [`Project::db_path`],
/// written solely by [`Project::save`] and the annotation setters.
#[derive(Debug)]
pub struct Project {
    path: PathBuf,
    db_path: PathBuf,
    content_hash: u64,
    size: u64,
    binary: LoadedBinary,
    analysis: Analysis,
    annotations: BTreeMap<u64, Annotation>,
}

impl Project {
    /// [`Project::open`] with an optional explicit DB path (`None` = sidecar).
    ///
    /// # Errors
    /// Same as [`Project::open`].
    pub fn open_any(binary: &Path, db: Option<&Path>) -> Result<Self> {
        match db {
            Some(d) => Self::open_with_db(binary, d),
            None => Self::open(binary),
        }
    }

    /// Open a container binary (ELF/PE/Mach-O/LE) with the default sidecar DB.
    ///
    /// Unrecognized bytes fall back to raw x86-64 at base 0 so fixture blobs
    /// and shellcode open without options; explicit bases/arches go through
    /// [`Project::open_raw`]. Reads the sidecar when present: a matching
    /// content hash loads the cached snapshot, a mismatch re-analyzes while
    /// keeping stored annotations. Never writes; call [`Project::save`].
    ///
    /// # Errors
    /// [`Error::NotFound`] if the path does not exist, [`Error::Unsupported`]
    /// if it is not a file or the arch has no disassembler, [`Error::Invalid`]
    /// on undecodable input, [`Error::Storage`] on DB or I/O failure.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_db(path, &db::default_db_path(path))
    }

    /// [`Project::open`] with an explicit DB path (keeps fixture dirs clean).
    ///
    /// # Errors
    /// Same as [`Project::open`].
    pub fn open_with_db(binary: &Path, db_path: &Path) -> Result<Self> {
        Self::open_inner(binary, db_path, None)
    }

    /// Open a raw blob with explicit mapping options plus explicit DB path.
    ///
    /// # Errors
    /// Same as [`Project::open`].
    pub fn open_raw(binary: &Path, db_path: &Path, opts: RawOptions) -> Result<Self> {
        Self::open_inner(binary, db_path, Some(opts))
    }

    fn open_inner(binary: &Path, db_path: &Path, raw: Option<RawOptions>) -> Result<Self> {
        if !binary.exists() {
            return Err(Error::NotFound(binary.display().to_string()));
        }
        if !binary.is_file() {
            return Err(Error::Unsupported(format!(
                "not a file: {}",
                binary.display()
            )));
        }
        let bytes = std::fs::read(binary)
            .map_err(|e| Error::Storage(format!("read {}: {e}", binary.display())))?;
        let hash = db::content_hash(&bytes);
        let size = bytes.len() as u64;

        let stored = if db_path.exists() {
            let db = db::open_db(db_path)?;
            db::load(&db)?
        } else {
            None
        };

        match stored {
            Some(hit) if hit.meta.content_hash == hash => Ok(Self {
                path: binary.to_path_buf(),
                db_path: db_path.to_path_buf(),
                content_hash: hash,
                size,
                binary: reload_binary(&bytes, raw)?,
                analysis: hit.analysis,
                annotations: hit.annotations,
            }),
            stored => {
                let annotations = stored.map(|s| s.annotations).unwrap_or_default();
                let loaded = match raw {
                    Some(opts) => load_raw(&bytes, opts)?,
                    None => load_or_raw(&bytes)?,
                };
                let analysis = analyze(&loaded)?;
                Ok(Self {
                    path: binary.to_path_buf(),
                    db_path: db_path.to_path_buf(),
                    content_hash: hash,
                    size,
                    binary: loaded,
                    analysis,
                    annotations,
                })
            }
        }
    }

    /// Persist the analysis snapshot and annotations to the sidecar DB.
    ///
    /// Only ever writes [`Project::db_path`]; the binary is untouched.
    ///
    /// # Errors
    /// [`Error::Storage`] on any `redb` or encoding failure.
    pub fn save(&self) -> Result<()> {
        let db = db::open_db(&self.db_path)?;
        db::save(&db, &self.meta(), &self.analysis, &self.annotations)?;
        Ok(())
    }

    fn meta(&self) -> BinaryMeta {
        BinaryMeta {
            version: db::SCHEMA_VERSION,
            binary_path: self.path.display().to_string(),
            content_hash: self.content_hash,
            size: self.size,
            arch: db::arch_name(self.binary.arch).to_string(),
            format: db::format_name(self.binary.format).to_string(),
            entry: self.binary.entry,
        }
    }

    /// Agent-facing summary; always JSON-serializable.
    #[must_use]
    pub fn project_info(&self) -> ProjectInfo {
        let s = self.analysis.summary();
        ProjectInfo {
            binary: self.path.display().to_string(),
            db_path: self.db_path.display().to_string(),
            version: version().to_string(),
            arch: db::arch_name(self.binary.arch).to_string(),
            format: db::format_name(self.binary.format).to_string(),
            entry: self.binary.entry,
            content_hash: self.content_hash,
            size: self.size,
            functions: s.functions,
            blocks: s.blocks,
            insns: s.insns,
            xrefs: s.xrefs,
            strings: s.strings,
            annotations: self.annotations.values().filter(|a| !a.is_empty()).count(),
        }
    }

    /// Path of the analyzed binary.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Path of the `redb` sidecar (only file this project writes).
    #[must_use]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Content hash the in-memory analysis was taken over.
    #[must_use]
    pub fn content_hash(&self) -> u64 {
        self.content_hash
    }

    /// Parsed binary headers, segments, and symbols.
    #[must_use]
    pub fn binary(&self) -> &LoadedBinary {
        &self.binary
    }

    /// Cached analysis (functions, CFGs, xrefs, strings).
    #[must_use]
    pub fn analysis(&self) -> &Analysis {
        &self.analysis
    }

    /// All annotations keyed by address.
    #[must_use]
    pub fn annotations(&self) -> &BTreeMap<u64, Annotation> {
        &self.annotations
    }

    /// Annotation at `addr`, if any.
    #[must_use]
    pub fn annotation(&self, addr: u64) -> Option<&Annotation> {
        self.annotations.get(&addr).filter(|a| !a.is_empty())
    }

    /// Display name of a function: annotation rename wins over export name.
    #[must_use]
    pub fn function_name(&self, entry: u64) -> Option<String> {
        if let Some(n) = self
            .annotations
            .get(&entry)
            .and_then(|a| a.name.clone())
            .filter(|n| !n.is_empty())
        {
            return Some(n);
        }
        self.analysis.functions.get(&entry)?.name.clone()
    }

    /// Rename a function in the DB only; the binary is never modified.
    ///
    /// An empty `name` clears the rename. Persists immediately.
    ///
    /// # Errors
    /// [`Error::NotFound`] for unknown function entries, [`Error::Storage`]
    /// when the annotation cannot be persisted.
    pub fn rename_function(&mut self, entry: u64, name: &str) -> Result<()> {
        if !self.analysis.functions.contains_key(&entry) {
            return Err(Error::NotFound(format!("function {entry:#x}")));
        }
        let ann = self.annotations.entry(entry).or_default();
        ann.name = (!name.is_empty()).then(|| name.to_string());
        if ann.is_empty() {
            self.annotations.remove(&entry);
        }
        self.save()
    }

    /// Comment an address in the DB only; the binary is never modified.
    ///
    /// Any address is commentable (instructions, functions, strings, data).
    /// An empty `comment` clears the comment. Persists immediately.
    ///
    /// # Errors
    /// [`Error::Storage`] when the annotation cannot be persisted.
    pub fn set_comment(&mut self, addr: u64, comment: &str) -> Result<()> {
        let ann = self.annotations.entry(addr).or_default();
        ann.comment = (!comment.is_empty()).then(|| comment.to_string());
        if ann.is_empty() {
            self.annotations.remove(&addr);
        }
        self.save()
    }

    /// File-backed bytes mapped at `va` (zero-padded past file data).
    ///
    /// # Errors
    /// [`Error::Limit`] for empty/oversize ranges, [`Error::NotFound`] when
    /// the range is not fully mapped.
    pub fn bytes_at(&self, va: u64, len: usize) -> Result<Vec<u8>> {
        if len == 0 || len > MAX_RANGE_BYTES {
            return Err(Error::Limit(format!("range length {len} out of bounds")));
        }
        let end = va.wrapping_add(len as u64);
        let seg = self
            .binary
            .segments
            .iter()
            .find(|s| va >= s.vaddr && end <= s.vaddr.wrapping_add(s.mem_size))
            .ok_or_else(|| Error::NotFound(format!("no bytes mapped at {va:#x}")))?;
        let mut out = vec![0u8; len];
        let off = (va - seg.vaddr) as usize;
        let have = seg.data.len().saturating_sub(off).min(len);
        out[..have].copy_from_slice(&seg.data[off..off + have]);
        Ok(out)
    }

    /// Disassemble `len` bytes at `va` with the binary's architecture.
    ///
    /// # Errors
    /// Same as [`Project::bytes_at`], plus [`Error::Invalid`] on undecodable
    /// bytes.
    pub fn disasm_at(&self, addr: u64, len: usize) -> Result<Vec<Insn>> {
        let bytes = self.bytes_at(addr, len)?;
        self.binary.arch.disassembler().disasm_range(&bytes, addr)
    }

    /// Function rows with annotation renames resolved, ordered by entry.
    #[must_use]
    pub fn functions_resolved(&self, offset: usize, limit: usize) -> Vec<serde_json::Value> {
        self.analysis
            .functions_page(offset, limit.min(MAX_ROWS))
            .into_iter()
            .map(|f| {
                serde_json::json!({
                    "id": f.id, "entry": f.entry,
                    "name": self.function_name(f.entry),
                    "blocks": f.blocks, "insns": f.insns, "calls": f.calls,
                })
            })
            .collect()
    }

    /// Full function detail: blocks with instructions in address order.
    ///
    /// # Errors
    /// [`Error::NotFound`] for unknown function entries.
    pub fn func_detail(&self, entry: u64) -> Result<serde_json::Value> {
        let f = self
            .analysis
            .functions
            .get(&entry)
            .ok_or_else(|| Error::NotFound(format!("function {entry:#x}")))?;
        let blocks: Vec<serde_json::Value> = f
            .blocks
            .values()
            .map(|b| {
                serde_json::json!({
                    "id": b.id(entry), "start": b.start, "end": b.end(),
                    "insns": b.insns, "succs": f.successors(b.start),
                })
            })
            .collect();
        Ok(serde_json::json!({
            "id": f.id(), "entry": f.entry,
            "name": self.function_name(entry),
            "blocks": blocks, "edges": f.edges(),
            "calls": self.analysis.calls_of(entry),
        }))
    }

    /// CFG of one function: block nodes plus `(from, to)` block edges.
    ///
    /// # Errors
    /// [`Error::NotFound`] for unknown function entries.
    pub fn cfg_of(&self, entry: u64) -> Result<serde_json::Value> {
        let f = self
            .analysis
            .functions
            .get(&entry)
            .ok_or_else(|| Error::NotFound(format!("function {entry:#x}")))?;
        let nodes: Vec<serde_json::Value> = f
            .blocks
            .values()
            .map(|b| {
                serde_json::json!({
                    "start": b.start, "end": b.end(),
                    "insns": b.insns.len(), "succs": f.successors(b.start),
                })
            })
            .collect();
        Ok(serde_json::json!({ "entry": entry, "nodes": nodes, "edges": f.edges() }))
    }

    /// Lift `len` bytes at `va` to IR.
    ///
    /// # Errors
    /// Same as [`Project::disasm_at`].
    pub fn ir_at(&self, addr: u64, len: usize) -> Result<serde_json::Value> {
        let insns = self.disasm_at(addr, len)?;
        let lifted = crate::ir::lift_range(self.binary.arch, &insns);
        Ok(serde_json::json!({ "addr": addr, "insns": insns.len(), "ir": lifted }))
    }

    /// Xrefs filtered by endpoint/kind, paged.
    #[must_use]
    pub fn query_xrefs(
        &self,
        to: Option<u64>,
        from: Option<u64>,
        kind: Option<XrefKind>,
        offset: usize,
        limit: usize,
    ) -> Vec<Xref> {
        self.analysis
            .xrefs
            .iter()
            .copied()
            .filter(|x| to.is_none_or(|t| x.to == t))
            .filter(|x| from.is_none_or(|f| x.from == f))
            .filter(|x| kind.is_none_or(|k| x.kind == k))
            .skip(offset)
            .take(limit.min(MAX_ROWS))
            .collect()
    }

    /// Imports plus exports for symbol views.
    #[must_use]
    pub fn symbols_json(&self) -> serde_json::Value {
        serde_json::json!({ "imports": self.binary.imports, "exports": self.binary.exports })
    }

    /// Current annotation at `addr`.
    #[must_use]
    pub fn annotation_json(&self, addr: u64) -> serde_json::Value {
        match self.annotation(addr) {
            Some(a) => serde_json::json!({ "addr": addr, "name": a.name, "comment": a.comment }),
            None => serde_json::json!({ "addr": addr, "name": null, "comment": null }),
        }
    }
}

/// Cap on raw bytes per [`Project::bytes_at`] call.
pub const MAX_RANGE_BYTES: usize = 1 << 20;
/// Cap on rows per paged query.
const MAX_ROWS: usize = 1024;

/// Parse a CLI/MCP address: `0x`-prefixed hex or plain decimal.
///
/// # Errors
/// [`Error::Invalid`] when the string is neither.
pub fn parse_addr(s: &str) -> Result<u64> {
    let s = s.trim();
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse::<u64>()
    };
    v.map_err(|_| Error::Invalid(format!("bad address: {s:?}")))
}

/// Parse an xref kind filter: `code`, `data`, or `string`.
///
/// # Errors
/// [`Error::Invalid`] for anything else.
pub fn parse_xref_kind(s: &str) -> Result<XrefKind> {
    match s.to_lowercase().as_str() {
        "code" => Ok(XrefKind::Code),
        "data" => Ok(XrefKind::Data),
        "string" => Ok(XrefKind::String),
        _ => Err(Error::Invalid(format!("bad xref kind: {s:?}"))),
    }
}

/// Re-read the binary bytes for a hash-matching cached snapshot.
///
/// Raw blobs need their mapping options again; containers re-parse.
fn reload_binary(bytes: &[u8], raw: Option<RawOptions>) -> Result<LoadedBinary> {
    match raw {
        Some(opts) => load_raw(bytes, opts),
        None => load_or_raw(bytes),
    }
}

/// Container parse with raw x86-64 fallback for unrecognized bytes.
///
/// Only [`Error::Invalid`] (not a container) falls back; recognized
/// containers with unsupported arches still report [`Error::Unsupported`].
fn load_or_raw(bytes: &[u8]) -> Result<LoadedBinary> {
    match load(bytes) {
        Ok(b) => Ok(b),
        Err(Error::Invalid(_)) => load_raw(
            bytes,
            RawOptions {
                base: 0,
                arch: crate::disasm::Arch::X86_64,
                entry: None,
            },
        ),
        Err(e) => Err(e),
    }
}
