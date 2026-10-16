#![warn(missing_docs)]
//! binscout core: headless agent-first binary analysis.

pub mod analysis;
pub mod annotations;
pub mod db;
pub mod diff;
pub mod disasm;
pub mod error;
pub mod flirt;
pub mod ir;
pub mod loader;
pub mod mcp;
pub mod pseudo;
pub mod search;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::analysis::{
    Analysis, BlockSummary, DiagnosticKind, DiagnosticRow, StringsFilter, Xref, XrefKind, analyze,
    diagnostic_detail,
};
use crate::db::{Annotation, BinaryMeta, ProjectInfo};
use crate::disasm::{Disassembler, Insn, PartialDisasm};
use crate::error::{Error, Result};
use crate::flirt::FlirtHint;
use crate::loader::strings::StringHit;
use crate::loader::{LoadedBinary, RawOptions, load, load_raw};
use crate::search::{ByteMatch, BytePattern};

/// Crate version, also served via CLI `--version` and MCP `project_info`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Parse an explicit raw architecture name.
///
/// Accepts the five disassembler modes (`x86_64`, `x86_32`, `aarch64`,
/// `arm32`, `thumb`), case-insensitively.
///
/// # Errors
/// [`Error::Invalid`] for anything else.
pub fn parse_raw_arch(s: &str) -> Result<crate::disasm::Arch> {
    match s.to_lowercase().as_str() {
        "x86_64" => Ok(crate::disasm::Arch::X86_64),
        "x86_32" => Ok(crate::disasm::Arch::X86_32),
        "aarch64" => Ok(crate::disasm::Arch::Aarch64),
        "arm32" => Ok(crate::disasm::Arch::Arm32),
        "thumb" => Ok(crate::disasm::Arch::Thumb),
        _ => Err(Error::Invalid(format!(
            "unknown arch: {s:?} (expected one of x86_64, x86_32, aarch64, arm32, thumb)"
        ))),
    }
}

/// Parse the shared explicit-raw options used by the CLI (`--raw --arch
/// --base [--entry]`) and MCP (`raw: {arch, base, entry?}`).
///
/// `raw` is the explicit-mode flag; `arch`/`base`/`entry` are the raw-only
/// strings. Returns `None` for auto mode (unchanged container detection
/// with raw x86-64-at-0 fallback) and `Some` for explicit raw. Entry
/// range/alignment and base-plus-length overflow are validated later in
/// [`crate::loader::load_raw`], so explicit failures error without falling
/// back to another mode.
///
/// # Errors
/// [`Error::Invalid`] when raw-only options appear without raw mode, when
/// `arch`/`base` are missing in raw mode, or on bad arch/address strings.
pub fn parse_raw_options(
    raw: bool,
    arch: Option<&str>,
    base: Option<&str>,
    entry: Option<&str>,
) -> Result<Option<RawOptions>> {
    if !raw {
        if arch.is_some() || base.is_some() || entry.is_some() {
            return Err(Error::Invalid(
                "raw options (--arch/--base/--entry) require --raw (or MCP raw object)".to_string(),
            ));
        }
        return Ok(None);
    }
    let Some(arch) = arch else {
        return Err(Error::Invalid(
            "explicit raw mode requires --arch (or MCP raw.arch)".to_string(),
        ));
    };
    let Some(base) = base else {
        return Err(Error::Invalid(
            "explicit raw mode requires --base (or MCP raw.base)".to_string(),
        ));
    };
    Ok(Some(RawOptions {
        base: parse_addr(base)?,
        arch: parse_raw_arch(arch)?,
        entry: entry.map(parse_addr).transpose()?,
    }))
}

/// Open a binary with an optional explicit raw mapping and optional explicit
/// DB path.
///
/// Shared by the CLI and MCP so every binary-taking operation interprets
/// raw options identically: `None` preserves auto detection (container
/// parse with raw x86-64-at-0 fallback), `Some` opens the explicit mapping
/// with no fallback. Reads never save or create the sidecar.
///
/// # Errors
/// Same as [`Project::open`] plus raw-mapping validation from
/// [`crate::loader::load_raw`].
pub fn open_mapped(binary: &Path, db: Option<&Path>, raw: Option<RawOptions>) -> Result<Project> {
    let owned;
    let db_path = match db {
        Some(p) => p,
        None => {
            owned = db::default_db_path(binary);
            // Borrow lives until the open call below returns.
            &owned
        }
    };
    match raw {
        Some(opts) => Project::open_raw(binary, db_path, opts),
        None => Project::open_with_db(binary, db_path),
    }
}

/// Filters for [`Project::functions_filtered`]: every present field must match.
///
/// `query` is a case-insensitive substring over the rename-resolved display
/// name (functions with no name never match a query). `caller` keeps the
/// functions that call the function containing that address; `callee` keeps
/// the functions called by the function containing that address. `range`
/// keeps functions whose entry lies in the inclusive bounds (normalized so
/// `lo <= hi`). An anchor address lying in no function matches nothing.
#[derive(Debug, Clone, Default)]
pub struct FunctionFilter {
    /// Case-insensitive name substring; `None` disables the filter.
    pub query: Option<String>,
    /// Keep callers of the function containing this address.
    pub caller: Option<u64>,
    /// Keep callees of the function containing this address.
    pub callee: Option<u64>,
    /// Keep functions with `entry` in `lo..=hi`.
    pub range: Option<(u64, u64)>,
}

/// Wire protocol revision served in every [`Page`] envelope.
///
/// Frozen by `docs/book/src/json-protocol.md`: additive fields do not bump
/// it, any shape change or removal does. It is distinct from the crate
/// version and the sidecar schema version.
pub const WIRE_PROTOCOL: u32 = 1;

/// Compact function metadata: entry, rename-resolved name, and counts.
///
/// `blocks`/`insns` are row counts and `calls` is the direct-callee count:
/// unlike [`Project::func_detail`], this carries no instruction arrays, no
/// block rows, and no unbounded call-target array, so it stays small for
/// arbitrarily large functions. `reasons` is the sorted, deduplicated
/// discovery vocabulary (see [`crate::analysis::DiscoveryReason`]).
///
/// JSON pairs `entry` with `entry_hex`; `entry_hex` is recomputed on
/// serialize and ignored on deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FuncMeta {
    /// Stable ID (`func@0x...`).
    pub id: String,
    /// Function entry address (canonical; interior queries snap here).
    pub entry: u64,
    /// Rename-resolved display name, if any.
    pub name: Option<String>,
    /// Basic block count.
    pub blocks: usize,
    /// Instruction count across all blocks.
    pub insns: usize,
    /// Direct-callee count (not the target array).
    pub calls: usize,
    /// Sorted, deduplicated discovery reasons.
    ///
    /// Defaults to empty so metadata written before provenance tracking
    /// still decodes.
    #[serde(default)]
    pub reasons: Vec<crate::analysis::DiscoveryReason>,
    /// Inferred-edge count (resolved single-slot indirect jumps, not the
    /// edge array: see [`Project::cfg_of`] for the pairs).
    ///
    /// Defaults to zero so metadata written before inference still decodes.
    #[serde(default)]
    pub inferred_edges: usize,
}

impl Serialize for FuncMeta {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("FuncMeta", 9)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("entry", &self.entry)?;
        st.serialize_field("entry_hex", &crate::addr_hex(self.entry))?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("blocks", &self.blocks)?;
        st.serialize_field("insns", &self.insns)?;
        st.serialize_field("calls", &self.calls)?;
        st.serialize_field("reasons", &self.reasons)?;
        st.serialize_field("inferred_edges", &self.inferred_edges)?;
        st.end()
    }
}

/// One transitive callgraph row: a reachable function plus its distance.
///
/// `entry` is the reachable function entry, `depth` the shortest
/// callgraph distance from the query root (direct neighbors are depth
/// 1), and `name` the rename-resolved display name, if any.
///
/// JSON pairs `entry` with `entry_hex` and carries the stable
/// `func@0x...` id; both twins are recomputed on serialize and ignored
/// on deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CallNode {
    /// Reachable function entry address.
    pub entry: u64,
    /// Shortest callgraph distance from the query root (1-based).
    pub depth: usize,
    /// Rename-resolved display name, if any.
    pub name: Option<String>,
}

impl Serialize for CallNode {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("CallNode", 5)?;
        st.serialize_field("id", &format!("func@{:#x}", self.entry))?;
        st.serialize_field("entry", &self.entry)?;
        st.serialize_field("entry_hex", &crate::addr_hex(self.entry))?;
        st.serialize_field("depth", &self.depth)?;
        st.serialize_field("name", &self.name)?;
        st.end()
    }
}

/// One backward-slice row: an instruction that can reach the query target.
/// `addr` is the reaching instruction address, `depth` the shortest
/// reverse-walk distance from the query root (direct predecessors are
/// depth 1), `func` the entry of the function containing `addr` (null
/// when in no function), and `name` that function's rename-resolved
/// display name, if any.
///
/// JSON pairs `addr` with `addr_hex` and `func` with `func_hex`, and
/// carries the stable `addr@0x...` id; the twins and the id are
/// recomputed on serialize and ignored on deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SliceNode {
    /// Reaching instruction address.
    pub addr: u64,
    /// Shortest reverse-walk distance from the query root (1-based).
    pub depth: usize,
    /// Entry of the function containing `addr`, if any.
    pub func: Option<u64>,
    /// Rename-resolved display name of that function, if any.
    pub name: Option<String>,
}

impl Serialize for SliceNode {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("SliceNode", 6)?;
        st.serialize_field("id", &format!("addr@{:#x}", self.addr))?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("depth", &self.depth)?;
        st.serialize_field("func", &self.func)?;
        st.serialize_field("func_hex", &self.func.map(crate::addr_hex))?;
        st.serialize_field("name", &self.name)?;
        st.end()
    }
}

/// One page of rows under the protocol-1 envelope
/// (`docs/book/src/json-protocol.md`).
///
/// `total` is the exact row count before paging; `offset` echoes the
/// request; `limit` is the effective limit clipped to the 1024-row cap;
/// `next_offset` is the next page's offset, or null when the page is
/// exhausted (`offset + limit >= total`) or the effective limit is zero;
/// `items` holds this page's rows in deterministic address order. An
/// offset past the end is a normal empty page, not an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    /// Wire revision (see [`WIRE_PROTOCOL`]).
    pub protocol: u32,
    /// Exact row count before paging.
    pub total: usize,
    /// Requested offset, echoed back.
    pub offset: usize,
    /// Effective limit after the 1024-row clip.
    pub limit: usize,
    /// Offset for the next page, or null when exhausted.
    pub next_offset: Option<usize>,
    /// This page's rows.
    pub items: Vec<T>,
}

/// Wrap `items` in the protocol-1 [`Page`] envelope.
///
/// `limit` is clipped to [`MAX_ROWS`]; `next_offset` uses the effective
/// limit with saturating arithmetic, so extreme offsets cannot wrap.
fn page_envelope<T>(total: usize, offset: usize, limit: usize, items: Vec<T>) -> Page<T> {
    let effective = limit.min(MAX_ROWS);
    let end = offset.saturating_add(effective);
    let next_offset = if effective == 0 || end >= total {
        None
    } else {
        Some(end)
    };
    Page {
        protocol: WIRE_PROTOCOL,
        total,
        offset,
        limit: effective,
        next_offset,
        items,
    }
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
    content_sha256: String,
    size: u64,
    binary: LoadedBinary,
    analysis: Analysis,
    annotations: BTreeMap<u64, Annotation>,
    mapping: db::StoredMapping,
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

    /// Open a supported container binary (ELF/PE/Mach-O/COFF/LE) with the default
    /// sidecar DB.
    ///
    /// LE images analyze as x86_32; force raw mapping of any bytes
    /// through [`Project::open_raw`]. Unrecognized bytes fall back to raw
    /// x86-64 at base 0 so fixture blobs and shellcode open without options;
    /// explicit bases/arches go through [`Project::open_raw`]. Reads the
    /// sidecar when present: a matching content hash, loader mapping, and
    /// analysis revision loads the cached snapshot, a mismatch re-analyzes
    /// while keeping same-mapping stored annotations. A populated sidecar
    /// under an incompatible mapping errors with a separate-DB message
    /// instead of reusing layouts. A stale sidecar's derived rows are never
    /// decoded (only its metadata and annotations are read), so a large
    /// obsolete snapshot costs no decoding proportional to its discarded
    /// rows. Never writes; call [`Project::save`].
    ///
    /// Input policy: at most 512 MiB are read (single open, chunked with
    /// checked growth); containers with large unmapped overlays still open
    /// while mapped/name/demangled/snapshot budgets may reject with
    /// [`Error::Limit`]. Budget rejections are intentional behavior changes,
    /// never raw fallback: only [`Error::Invalid`] falls back.
    ///
    /// # Errors
    /// [`Error::NotFound`] if the path does not exist, [`Error::Unsupported`]
    /// if it is not a file or the arch has no disassembler,
    /// [`Error::Invalid`] on undecodable input,
    /// [`Error::Limit`] on input/name/metadata/snapshot budget overrun,
    /// [`Error::Storage`] on DB or I/O failure.
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
    /// The mapping is part of the cache identity: same bytes opened with
    /// different arch/base/entry (or auto vs explicit) never share cached
    /// layouts, and populated annotation sidecars under another mapping
    /// require a separate DB path.
    ///
    /// # Errors
    /// Same as [`Project::open`].
    pub fn open_raw(binary: &Path, db_path: &Path, opts: RawOptions) -> Result<Self> {
        Self::open_inner(binary, db_path, Some(opts))
    }

    fn open_inner(binary: &Path, db_path: &Path, raw: Option<RawOptions>) -> Result<Self> {
        // Single-open bounded read: one handle, chunked with checked
        // accumulation, so a growing file cannot slip past a stat cap.
        let bytes = read_input_bytes(binary)?;
        let hash = db::content_hash(&bytes);
        let size = bytes.len() as u64;
        let mapping = db::StoredMapping::for_request(raw);

        // Metadata-first snapshot read over a read-only handle: cache
        // identity covers content, loader mapping, and analysis revision
        // before any layout replay (see `db::load_cached`), and the
        // read-only open itself costs nothing proportional to the file.
        // Reads never save and never create the sidecar.
        let cached = if db_path.exists() {
            match db::open_db_read_only(db_path) {
                Ok(db) => Some(db::load_cached(&db, hash, &mapping)?),
                // Raced with a concurrent sidecar deletion: read as absent.
                Err(_) if !db_path.exists() => None,
                Err(e) => return Err(e),
            }
        } else {
            None
        };

        match cached {
            Some(db::Snapshot::Hit(hit)) => {
                let loaded = reload_binary(&bytes, raw)?;
                let db::Loaded {
                    arch,
                    functions,
                    call_edges,
                    xrefs,
                    strings,
                    diagnostics,
                    annotations,
                    meta,
                } = *hit;
                let analysis = crate::analysis::rebuild(
                    arch,
                    &loaded,
                    &functions,
                    &call_edges,
                    xrefs,
                    strings,
                    crate::analysis::Diagnostics {
                        records: diagnostics,
                        truncated: meta.diagnostics_truncated,
                        omitted: meta.diagnostics_omitted,
                        inferred_truncated: meta.inferred_truncated,
                        inferred_omitted: meta.inferred_omitted,
                    },
                )?;
                Ok(Self {
                    path: binary.to_path_buf(),
                    db_path: db_path.to_path_buf(),
                    content_hash: hash,
                    content_sha256: crate::annotations::sha256_hex(&bytes),
                    size,
                    binary: loaded,
                    analysis,
                    annotations,
                    mapping,
                })
            }
            Some(db::Snapshot::Stale { annotations, .. }) => {
                Self::reanalyze(binary, db_path, bytes, raw, hash, size, annotations)
            }
            Some(db::Snapshot::Miss) | None => {
                Self::reanalyze(binary, db_path, bytes, raw, hash, size, BTreeMap::new())
            }
        }
    }

    /// Re-analyze `bytes` from scratch, carrying `annotations` forward.
    ///
    /// Stale sidecars keep user renames and comments by address under the
    /// same mapping; the derived analysis always comes from the current
    /// bytes, never from storage. A mapping mismatch over populated
    /// annotations never reaches this path: [`db::load_cached`] errors first.
    fn reanalyze(
        binary: &Path,
        db_path: &Path,
        bytes: Vec<u8>,
        raw: Option<RawOptions>,
        hash: u64,
        size: u64,
        annotations: BTreeMap<u64, Annotation>,
    ) -> Result<Self> {
        let mapping = db::StoredMapping::for_request(raw);
        let loaded = match raw {
            Some(opts) => load_raw(&bytes, opts)?,
            None => load_or_raw(&bytes)?,
        };
        let analysis = analyze(&loaded)?;
        Ok(Self {
            path: binary.to_path_buf(),
            db_path: db_path.to_path_buf(),
            content_hash: hash,
            content_sha256: crate::annotations::sha256_hex(&bytes),
            size,
            binary: loaded,
            analysis,
            annotations,
            mapping,
        })
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
            supported: true,
            reason: None,
            mapping: Some(self.mapping.clone()),
            analysis_rev: Some(db::ANALYSIS_REVISION),
            diagnostics_truncated: self.analysis.diagnostics.truncated,
            diagnostics_omitted: self.analysis.diagnostics.omitted,
            inferred_truncated: self.analysis.diagnostics.inferred_truncated,
            inferred_omitted: self.analysis.diagnostics.inferred_omitted,
        }
    }

    /// Loader mapping this project was opened with (auto vs explicit raw).
    ///
    /// Part of the cache identity: snapshots replay layouts only when the
    /// stored mapping agrees with this value.
    #[must_use]
    pub fn mapping(&self) -> &db::StoredMapping {
        &self.mapping
    }

    /// Persist one changed annotation row, falling back to a full snapshot.
    ///
    /// Tries [`db::save_annotation`](crate::db::save_annotation) first: when
    /// the sidecar holds a snapshot for this binary and mapping, only the
    /// `annotations` row changes. Otherwise (fresh DB or same-mapping
    /// content mismatch) rewrites the full snapshot via [`Project::save`].
    /// A populated sidecar under an incompatible mapping errors instead of
    /// overwriting.
    fn persist_annotation(&self, addr: u64) -> Result<()> {
        let db = db::open_db(&self.db_path)?;
        let ann = self.annotations.get(&addr).filter(|a| !a.is_empty());
        match db::save_annotation(&db, &self.meta(), addr, ann)? {
            db::AnnotationSave::Fast => Ok(()),
            db::AnnotationSave::NeedsFull => {
                db::save(&db, &self.meta(), &self.analysis, &self.annotations)?;
                Ok(())
            }
        }
    }

    /// Agent-facing summary; always JSON-serializable.
    #[must_use]
    pub fn project_info(&self) -> ProjectInfo {
        let s = self.analysis.summary();
        let (mode, base) = match &self.mapping {
            db::StoredMapping::Auto => ("auto".to_string(), None),
            db::StoredMapping::Explicit { base, .. } => ("raw".to_string(), Some(*base)),
        };
        ProjectInfo {
            binary: self.path.display().to_string(),
            db_path: self.db_path.display().to_string(),
            version: version().to_string(),
            protocol: WIRE_PROTOCOL,
            mode,
            base,
            arch: db::arch_name(self.binary.arch).to_string(),
            format: db::format_name(self.binary.format).to_string(),
            entry: self.binary.entry,
            content_hash: self.content_hash,
            size: self.size,
            supported: true,
            reason: None,
            functions: s.functions,
            blocks: s.blocks,
            insns: s.insns,
            xrefs: s.xrefs,
            strings: s.strings,
            annotations: self.annotations.values().filter(|a| !a.is_empty()).count(),
            diagnostics: self.analysis.diagnostics.records.len(),
            diagnostics_truncated: self.analysis.diagnostics.truncated,
            diagnostics_omitted: self.analysis.diagnostics.omitted,
            inferred_truncated: self.analysis.diagnostics.inferred_truncated,
            inferred_omitted: self.analysis.diagnostics.inferred_omitted,
            analysis_revision: crate::analysis::ANALYSIS_REVISION,
        }
    }

    /// Storage stats for the project: binary size plus sidecar DB size
    /// and the same analysis counts as [`Project::project_info`].
    ///
    /// Opens without saving like the other read paths; `db_size` is `0`
    /// when no sidecar exists yet. The `stats` CLI/MCP surface reports
    /// this verbatim so operators see the cost of a cached snapshot.
    ///
    /// # Errors
    /// [`Error::Storage`] when the sidecar exists but cannot be statted.
    pub fn stats_json(&self) -> Result<serde_json::Value> {
        let s = self.analysis.summary();
        let db_size = db::db_file_size(&self.db_path)?;
        let (mode, (base, base_hex)) = match &self.mapping {
            db::StoredMapping::Auto => ("auto".to_string(), crate::opt_addr_pair(None)),
            db::StoredMapping::Explicit { base, .. } => {
                ("raw".to_string(), crate::opt_addr_pair(Some(*base)))
            }
        };
        let (entry, entry_hex) = crate::opt_addr_pair(self.binary.entry);
        Ok(serde_json::json!({
            "binary": self.path.display().to_string(),
            "db_path": self.db_path.display().to_string(),
            "version": version(),
            "protocol": WIRE_PROTOCOL,
            "mode": mode,
            "base": base,
            "base_hex": base_hex,
            "arch": db::arch_name(self.binary.arch),
            "format": db::format_name(self.binary.format),
            "entry": entry,
            "entry_hex": entry_hex,
            "content_hash": self.content_hash,
            "size": self.size,
            "db_size": db_size,
            "functions": s.functions,
            "blocks": s.blocks,
            "insns": s.insns,
            "xrefs": s.xrefs,
            "strings": s.strings,
            "annotations": self.annotations.values().filter(|a| !a.is_empty()).count(),
            "diagnostics": self.analysis.diagnostics.records.len(),
            "diagnostics_truncated": self.analysis.diagnostics.truncated,
            "diagnostics_omitted": self.analysis.diagnostics.omitted,
            "inferred_truncated": self.analysis.diagnostics.inferred_truncated,
            "inferred_omitted": self.analysis.diagnostics.inferred_omitted,
            "analysis_revision": crate::analysis::ANALYSIS_REVISION,
        }))
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

    /// Hex SHA-256 of the binary bytes the analysis was taken over.
    ///
    /// Cryptographic identity for portable annotation interchange (see
    /// [`Project::export_annotations`]); the 64-bit
    /// [`Project::content_hash`] only detects "binary changed, re-analyze".
    #[must_use]
    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    /// Binary size in bytes the analysis was taken over.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
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
    /// An empty `name` clears the rename. Persists immediately via a
    /// single-row transaction when the cached snapshot matches, else a full
    /// snapshot rewrite.
    ///
    /// # Errors
    /// [`Error::NotFound`] for unknown function entries, [`Error::Limit`]
    /// when the name exceeds 8 KiB, [`Error::Storage`] when the annotation
    /// cannot be persisted.
    pub fn rename_function(&mut self, entry: u64, name: &str) -> Result<()> {
        if !self.analysis.functions.contains_key(&entry) {
            return Err(Error::NotFound(format!("function {entry:#x}")));
        }
        if name.len() > crate::db::MAX_ANNOTATION_BYTES {
            return Err(Error::Limit(format!(
                "rename of {} bytes exceeds {}",
                name.len(),
                crate::db::MAX_ANNOTATION_BYTES
            )));
        }
        let ann = self.annotations.entry(entry).or_default();
        ann.name = (!name.is_empty()).then(|| name.to_string());
        if ann.is_empty() {
            self.annotations.remove(&entry);
        }
        self.persist_annotation(entry)
    }

    /// Comment an address in the DB only; the binary is never modified.
    ///
    /// Any address is commentable (instructions, functions, strings, data).
    /// An empty `comment` clears the comment. Persists immediately via a
    /// single-row transaction when the cached snapshot matches, else a full
    /// snapshot rewrite. Structured struct-layout/sizeof hints also travel
    /// through this channel: format them with
    /// [`crate::annotations::format_type_hint`] (or store them directly
    /// with [`Project::set_type_hint`]) and read them back with
    /// [`Project::type_hint_at`]; they are never validated against the
    /// binary.
    ///
    /// # Errors
    /// [`Error::Limit`] when the comment exceeds 8 KiB, [`Error::Storage`]
    /// when the annotation cannot be persisted.
    pub fn set_comment(&mut self, addr: u64, comment: &str) -> Result<()> {
        if comment.len() > crate::db::MAX_ANNOTATION_BYTES {
            return Err(Error::Limit(format!(
                "comment of {} bytes exceeds {}",
                comment.len(),
                crate::db::MAX_ANNOTATION_BYTES
            )));
        }
        let ann = self.annotations.entry(addr).or_default();
        ann.comment = (!comment.is_empty()).then(|| comment.to_string());
        if ann.is_empty() {
            self.annotations.remove(&addr);
        }
        self.persist_annotation(addr)
    }

    /// Store a structured struct-layout/sizeof hint at `addr`.
    ///
    /// Formats `hint` with [`crate::annotations::format_type_hint`] and
    /// stores it as an ordinary comment, so the any-address contract, the
    /// 8 KiB cap, the immediate persistence, and the export/import
    /// round-trip all behave exactly like [`Project::set_comment`]. There
    /// is no type system: the layout is a hint for agents, never checked
    /// against the binary.
    ///
    /// # Errors
    /// [`Error::Invalid`] on hint shape violations,
    /// [`Error::Limit`] when the formatted hint exceeds 8 KiB,
    /// [`Error::Storage`] when the annotation cannot be persisted.
    pub fn set_type_hint(&mut self, addr: u64, hint: &crate::annotations::TypeHint) -> Result<()> {
        let comment = crate::annotations::format_type_hint(hint)?;
        self.set_comment(addr, &comment)
    }

    /// Read back the structured hint at `addr`, if the comment carries one.
    ///
    /// `Ok(None)` when there is no annotation, no comment, or a plain
    /// free-text comment; a corrupt hint (prefix present but unparsable)
    /// is [`Error::Invalid`], never silent.
    ///
    /// # Errors
    /// [`Error::Invalid`] on a corrupt type-hint comment.
    pub fn type_hint_at(&self, addr: u64) -> Result<Option<crate::annotations::TypeHint>> {
        match self.annotation(addr).and_then(|a| a.comment.as_deref()) {
            None => Ok(None),
            Some(text) => crate::annotations::parse_type_hint(text),
        }
    }

    /// Export renames and comments as a portable JSON interchange document.
    ///
    /// The document carries the format revision, the binary's SHA-256 plus
    /// size, the effective loader mapping, and the sorted non-empty rows;
    /// host paths and analysis snapshots are excluded. Strictly read-only:
    /// no sidecar is created or modified. Fails explicitly past the
    /// interchange size cap instead of emitting an unimportable document.
    ///
    /// # Errors
    /// [`Error::Limit`] past annotation or document budgets,
    /// [`Error::Storage`] on encoding failure.
    pub fn export_annotations(&self) -> Result<String> {
        crate::annotations::build_document(
            &self.content_sha256,
            self.size,
            &self.mapping,
            &self.annotations,
        )
    }

    /// Import a document from [`Project::export_annotations`] atomically.
    ///
    /// The whole document is validated before a single transaction:
    /// identity, mapping, duplicates, budgets, rename targets, and merge
    /// conflicts. On success the changes persist in one transaction (an
    /// annotation-only batch write, or a full snapshot rewrite when no
    /// matching snapshot exists) and memory updates only after the commit;
    /// on any failure the DB and the in-memory annotations are unchanged.
    /// Default (`overwrite == false`) fails on differing existing field
    /// values while equal values and fills of absent fields succeed;
    /// `overwrite == true` replaces supplied fields only (absent fields
    /// untouched, empty strings clear). Rows outside the document remain.
    /// Rename targets must be known function entries; comments keep the
    /// any-address contract.
    ///
    /// # Errors
    /// [`Error::Invalid`] on malformed documents, duplicates, and
    /// default-mode conflicts; [`Error::Storage`] on identity/mapping
    /// mismatches; [`Error::NotFound`] on unknown rename targets;
    /// [`Error::Limit`] past input/field/row budgets.
    pub fn import_annotations(
        &mut self,
        document: &str,
        overwrite: bool,
    ) -> Result<crate::annotations::ImportSummary> {
        let doc = crate::annotations::parse_document(document)?;
        let is_function = |addr: u64| self.analysis.functions.contains_key(&addr);
        let changes = crate::annotations::validate_document(
            &doc,
            &self.content_sha256,
            self.size,
            &self.mapping,
            &is_function,
            &self.annotations,
            overwrite,
        )?;
        let summary = crate::annotations::ImportSummary {
            rows: doc.annotations.len(),
            changed: changes.len(),
        };
        if !changes.is_empty() {
            let db = db::open_db(&self.db_path)?;
            match db::save_annotation_batch(&db, &self.meta(), &changes)? {
                db::AnnotationSave::Fast => {}
                db::AnnotationSave::NeedsFull => {
                    let mut merged = self.annotations.clone();
                    crate::annotations::apply_changes(&mut merged, &changes);
                    db::save(&db, &self.meta(), &self.analysis, &merged)?;
                }
            }
            crate::annotations::apply_changes(&mut self.annotations, &changes);
        }
        Ok(summary)
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
        let len_u64 = len as u64;
        let seg = self
            .binary
            .segments
            .iter()
            .find(|s| {
                if va < s.vaddr {
                    return false;
                }
                let Some(off) = va.checked_sub(s.vaddr) else {
                    return false;
                };
                let Some(need) = off.checked_add(len_u64) else {
                    return false;
                };
                need <= s.mem_size
            })
            .ok_or_else(|| Error::NotFound(format!("no bytes mapped at {va:#x}")))?;
        let mut out = vec![0u8; len];
        let off = (va - seg.vaddr) as usize;
        let have = seg.data.len().saturating_sub(off).min(len);
        if have > 0 {
            out[..have].copy_from_slice(&seg.data[off..off + have]);
        }
        Ok(out)
    }

    /// Disassemble `len` bytes at `va` with the binary's architecture.
    ///
    /// Returns the valid prefix plus `error_at` for the first bad opcode
    /// (`None` when the whole range decodes); cap overruns are still
    /// errors. Serializes as `{"insns": [...], "error_at": null|{...}}`.
    ///
    /// # Errors
    /// Same as [`Project::bytes_at`], plus [`Error::Limit`] on cap overrun.
    pub fn disasm_at(&self, addr: u64, len: usize) -> Result<PartialDisasm> {
        let bytes = self.bytes_at(addr, len)?;
        self.binary
            .arch
            .disassembler()
            .disasm_range_partial(&bytes, addr)
    }

    /// Function rows with annotation renames resolved, ordered by entry.
    #[must_use]
    pub fn functions_resolved(&self, offset: usize, limit: usize) -> Vec<serde_json::Value> {
        self.functions_filtered(&FunctionFilter::default(), offset, limit)
    }

    /// Function rows with annotation renames resolved, filtered then paged.
    ///
    /// Every present [`FunctionFilter`] field must match; filtering happens
    /// before paging so `offset`/`limit` apply to the matching rows.
    #[must_use]
    pub fn functions_filtered(
        &self,
        filter: &FunctionFilter,
        offset: usize,
        limit: usize,
    ) -> Vec<serde_json::Value> {
        // Resolve anchor addresses once: None = filter disabled,
        // Some(None) = anchor lies in no function (matches nothing).
        let caller: Option<Option<u64>> =
            filter.caller.map(|a| self.analysis.containing_function(a));
        let callee_calls: Option<Option<Vec<u64>>> = filter.callee.map(|a| {
            self.analysis
                .containing_function(a)
                .map(|c| self.analysis.calls_of(c))
        });
        let range = filter
            .range
            .map(|(a, b)| if a <= b { (a, b) } else { (b, a) });
        let query = filter.query.as_deref().map(|s| s.to_lowercase());
        self.analysis
            .functions
            .values()
            .filter(|f| range.is_none_or(|(lo, hi)| f.entry >= lo && f.entry <= hi))
            .filter(|f| match caller {
                None => true,
                Some(None) => false,
                Some(Some(c)) => self.analysis.calls_of(f.entry).contains(&c),
            })
            .filter(|f| match &callee_calls {
                None => true,
                Some(None) => false,
                Some(Some(cs)) => cs.contains(&f.entry),
            })
            .filter(|f| match &query {
                Some(q) => self
                    .function_name(f.entry)
                    .is_some_and(|n| n.to_lowercase().contains(q.as_str())),
                None => true,
            })
            .skip(offset)
            .take(limit.min(MAX_ROWS))
            .map(|f| {
                let (entry, entry_hex) = addr_pair(f.entry);
                serde_json::json!({
                    "id": f.id(), "entry": entry, "entry_hex": entry_hex,
                    "name": self.function_name(f.entry),
                    "blocks": f.blocks.len(), "insns": f.insn_count(), "calls": self.analysis.calls_of(f.entry),
                })
            })
            .collect()
    }

    /// Full function detail: blocks with instructions in address order.
    ///
    /// `addr` may be any address inside the function; it snaps to the
    /// containing entry. The result carries both `entry` (the canonical
    /// function entry) and `containing_entry` (the entry containing `addr`).
    ///
    /// # Errors
    /// [`Error::NotFound`] when `addr` lies in no function.
    pub fn func_detail(&self, addr: u64) -> Result<serde_json::Value> {
        let entry = self
            .analysis
            .containing_function(addr)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        let f = self
            .analysis
            .functions
            .get(&entry)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        let blocks: Vec<serde_json::Value> = f
            .blocks
            .values()
            .map(|b| {
                let (start, start_hex) = addr_pair(b.start);
                let (end, end_hex) = addr_pair(b.end());
                serde_json::json!({
                    "id": b.id(entry), "start": start, "start_hex": start_hex,
                    "end": end, "end_hex": end_hex,
                    "insns": b.insns, "succs": f.successors(b.start),
                })
            })
            .collect();
        let (entry_json, entry_hex) = addr_pair(f.entry);
        let (_, containing_hex) = addr_pair(entry);
        Ok(serde_json::json!({
            "id": f.id(), "entry": entry_json, "entry_hex": entry_hex,
            "containing_entry": entry, "containing_entry_hex": containing_hex,
            "name": self.function_name(entry),
            "blocks": blocks, "edges": f.edges(),
            "inferred_edges": f.inferred_edges(),
            "calls": self.analysis.calls_of(entry),
        }))
    }

    /// Compact function metadata: entry, rename-resolved name, and counts.
    ///
    /// `addr` may be any address inside the function; it snaps to the
    /// containing entry exactly like [`Project::func_detail`]. `calls` is
    /// the direct-callee count, never the target array, so metadata stays
    /// bounded for arbitrarily large functions.
    ///
    /// # Errors
    /// [`Error::NotFound`] when `addr` lies in no function.
    pub fn func_meta(&self, addr: u64) -> Result<FuncMeta> {
        let entry = self
            .analysis
            .containing_function(addr)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        let f = self
            .analysis
            .functions
            .get(&entry)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        Ok(FuncMeta {
            id: f.id(),
            entry,
            name: self.function_name(entry),
            blocks: f.blocks.len(),
            insns: f.insn_count(),
            calls: self.analysis.calls_count(entry),
            reasons: f.reason_list(),
            inferred_edges: f.inferred_edges().len(),
        })
    }

    /// Block summaries of one function ordered by block start, paged.
    ///
    /// `addr` may be any address inside the function; it snaps to the
    /// containing entry exactly like [`Project::func_detail`]. Rows come
    /// from [`Analysis::blocks_page`](crate::analysis::Analysis::blocks_page),
    /// so only the selected page is materialized; `total` is the block
    /// count read without building rows.
    ///
    /// # Errors
    /// [`Error::NotFound`] when `addr` lies in no function.
    pub fn func_blocks_page(
        &self,
        addr: u64,
        offset: usize,
        limit: usize,
    ) -> Result<Page<BlockSummary>> {
        let entry = self
            .analysis
            .containing_function(addr)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        let total = self
            .analysis
            .functions
            .get(&entry)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?
            .blocks
            .len();
        let items = self
            .analysis
            .blocks_page(entry, offset, limit)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        Ok(page_envelope(total, offset, limit, items))
    }

    /// Instructions of one function-owned block in address order, paged.
    ///
    /// `addr` may be any address inside the function; it snaps to the
    /// containing entry exactly like [`Project::func_detail`]. `block`
    /// must be a block start belonging to that function: a foreign block
    /// (or any non-start address) is [`Error::NotFound`], never a silent
    /// cross-function read. Rows come from
    /// [`Analysis::block_insns`](crate::analysis::Analysis::block_insns),
    /// so only the selected page is cloned; `total` is the instruction
    /// count read without cloning rows.
    ///
    /// # Errors
    /// [`Error::NotFound`] when `addr` lies in no function, or when
    /// `block` is not a block of that function.
    pub fn func_block_insns_page(
        &self,
        addr: u64,
        block: u64,
        offset: usize,
        limit: usize,
    ) -> Result<Page<Insn>> {
        let entry = self
            .analysis
            .containing_function(addr)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        let total = self
            .analysis
            .functions
            .get(&entry)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?
            .blocks
            .get(&block)
            .ok_or_else(|| Error::NotFound(format!("block {block:#x} in function {entry:#x}")))?
            .insns
            .len();
        let items = self
            .analysis
            .block_insns(entry, block, offset, limit)
            .ok_or_else(|| Error::NotFound(format!("block {block:#x} in function {entry:#x}")))?;
        Ok(page_envelope(total, offset, limit, items))
    }

    /// CFG of one function: block nodes plus `(from, to)` block edges.
    ///
    /// `addr` may be any address inside the function; it snaps to the
    /// containing entry. The result carries both `entry` (the canonical
    /// function entry) and `containing_entry` (the entry containing `addr`).
    ///
    /// # Errors
    /// [`Error::NotFound`] when `addr` lies in no function.
    pub fn cfg_of(&self, addr: u64) -> Result<serde_json::Value> {
        let entry = self
            .analysis
            .containing_function(addr)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        let f = self
            .analysis
            .functions
            .get(&entry)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        let nodes: Vec<serde_json::Value> = f
            .blocks
            .values()
            .map(|b| {
                let (start, start_hex) = addr_pair(b.start);
                let (end, end_hex) = addr_pair(b.end());
                serde_json::json!({
                    "start": start, "start_hex": start_hex,
                    "end": end, "end_hex": end_hex,
                    "insns": b.insns.len(), "succs": f.successors(b.start),
                })
            })
            .collect();
        let (_, entry_hex) = addr_pair(entry);
        Ok(
            serde_json::json!({ "entry": entry, "entry_hex": entry_hex, "containing_entry": entry, "containing_entry_hex": entry_hex, "nodes": nodes, "edges": f.edges(), "inferred_edges": f.inferred_edges() }),
        )
    }

    /// Approximate control-flow structure of one function: syntactic loops
    /// and ifs over the direct CFG plus the M3 lift, with the approximation
    /// warning.
    ///
    /// `addr` may be any address inside the function; it snaps to the
    /// containing entry exactly like [`Project::cfg_of`]. The result
    /// carries `entry` (the canonical function entry) plus `structure`
    /// (`loops`/`ifs` rows with `0x`-hex twins and the top-level
    /// `warning`). Read-only: never writes the binary or the sidecar.
    ///
    /// # Errors
    /// [`Error::NotFound`] when `addr` lies in no function.
    pub fn structure_of(&self, addr: u64) -> Result<serde_json::Value> {
        let entry = self
            .analysis
            .containing_function(addr)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        let structure = self
            .analysis
            .structure_of(entry)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        let structure = serde_json::to_value(structure).expect("structure serializes");
        let (entry_json, entry_hex) = addr_pair(entry);
        Ok(serde_json::json!({
            "entry": entry_json, "entry_hex": entry_hex,
            "containing_entry": entry, "containing_entry_hex": entry_hex,
            "structure": structure,
        }))
    }

    /// Approximate pseudo-C of one function: one lossy C-like line per IR
    /// row plus the assembled text, with the approximation warning.
    ///
    /// `addr` may be any address inside the function; it snaps to the
    /// containing entry exactly like [`Project::cfg_of`]. Each line
    /// propagates its source IR warning (`None` for mapped rows); the
    /// top-level `warning` is always
    /// [`PSEUDO_WARNING`](crate::pseudo::PSEUDO_WARNING). Read-only: never
    /// writes the binary or the sidecar.
    ///
    /// # Errors
    /// [`Error::NotFound`] when `addr` lies in no function.
    pub fn pseudo_of(&self, addr: u64) -> Result<serde_json::Value> {
        let entry = self
            .analysis
            .containing_function(addr)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        let func = self
            .analysis
            .functions
            .get(&entry)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        let pseudo = crate::pseudo::render_function(self.binary.arch, func);
        let pseudo = serde_json::to_value(pseudo).expect("pseudo serializes");
        let (entry_json, entry_hex) = addr_pair(entry);
        Ok(serde_json::json!({
            "entry": entry_json, "entry_hex": entry_hex,
            "containing_entry": entry, "containing_entry_hex": entry_hex,
            "pseudo": pseudo,
        }))
    }

    /// Lift `len` bytes at `va` to IR.
    ///
    /// Lifts the valid prefix (see [`Project::disasm_at`]) and reports the
    /// first bad opcode in `error_at` (`None` on a clean range).
    ///
    /// # Errors
    /// Same as [`Project::disasm_at`].
    pub fn ir_at(&self, addr: u64, len: usize) -> Result<serde_json::Value> {
        let partial = self.disasm_at(addr, len)?;
        let lifted = crate::ir::lift_range(self.binary.arch, &partial.insns);
        let (addr_json, addr_hex) = addr_pair(addr);
        Ok(
            serde_json::json!({ "addr": addr_json, "addr_hex": addr_hex, "insns": partial.insns.len(), "ir": lifted, "error_at": partial.error_at }),
        )
    }

    /// Transitive callees of the function containing `addr`, paged.
    ///
    /// `addr` may be any address inside the function; it snaps to the
    /// containing entry exactly like [`Project::func_detail`]. `depth`
    /// bounds the walk to that many call edges (direct callees are depth
    /// 1, zero yields an empty page); values past
    /// [`crate::analysis::MAX_CALL_DEPTH`] are [`Error::Invalid`]. Rows
    /// order by entry with the shortest distance in `depth`, and only
    /// the selected page resolves names, so per-page work scales with
    /// the page. Read-only: never writes the binary or the sidecar.
    ///
    /// # Errors
    /// [`Error::NotFound`] when `addr` lies in no function,
    /// [`Error::Invalid`] when `depth` exceeds the hop cap.
    pub fn callees_page(
        &self,
        addr: u64,
        depth: usize,
        offset: usize,
        limit: usize,
    ) -> Result<Page<CallNode>> {
        let entry = self
            .analysis
            .containing_function(addr)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        if depth > crate::analysis::MAX_CALL_DEPTH {
            return Err(Error::Invalid(format!(
                "depth {depth} exceeds {}",
                crate::analysis::MAX_CALL_DEPTH
            )));
        }
        let reached = self.analysis.callees_transitive(entry, depth);
        let total = reached.len();
        let items: Vec<CallNode> = reached
            .into_iter()
            .skip(offset)
            .take(limit.min(MAX_ROWS))
            .map(|(target, d)| CallNode {
                entry: target,
                depth: d,
                name: self.function_name(target),
            })
            .collect();
        Ok(page_envelope(total, offset, limit, items))
    }

    /// Transitive callers of the function containing `addr`, paged.
    ///
    /// Mirror of [`Project::callees_page`] over incoming callgraph
    /// edges: `addr` snaps to its containing entry, `depth` bounds the
    /// reverse walk (direct callers are depth 1), rows order by entry
    /// with the shortest distance, and only the selected page resolves
    /// names. Read-only: never writes the binary or the sidecar.
    ///
    /// # Errors
    /// [`Error::NotFound`] when `addr` lies in no function,
    /// [`Error::Invalid`] when `depth` exceeds the hop cap.
    pub fn callers_page(
        &self,
        addr: u64,
        depth: usize,
        offset: usize,
        limit: usize,
    ) -> Result<Page<CallNode>> {
        let entry = self
            .analysis
            .containing_function(addr)
            .ok_or_else(|| Error::NotFound(format!("function {addr:#x}")))?;
        if depth > crate::analysis::MAX_CALL_DEPTH {
            return Err(Error::Invalid(format!(
                "depth {depth} exceeds {}",
                crate::analysis::MAX_CALL_DEPTH
            )));
        }
        let reached = self.analysis.callers_transitive(entry, depth);
        let total = reached.len();
        let items: Vec<CallNode> = reached
            .into_iter()
            .skip(offset)
            .take(limit.min(MAX_ROWS))
            .map(|(target, d)| CallNode {
                entry: target,
                depth: d,
                name: self.function_name(target),
            })
            .collect();
        Ok(page_envelope(total, offset, limit, items))
    }

    /// Backward slice of `to`: every instruction that can reach it, paged.
    ///
    /// Bounded reverse walk over xref edges of every kind plus
    /// intra-function CFG predecessors (see
    /// [`Analysis::slice_to`](crate::analysis::Analysis::slice_to)):
    /// `depth` bounds the walk to that many reverse hops (direct
    /// predecessors are depth 1, zero yields an empty page); values
    /// past [`crate::analysis::MAX_SLICE_DEPTH`] are [`Error::Invalid`].
    /// Any address is a valid root (data/string targets lie in no
    /// function); rows order by address with the shortest distance in
    /// `depth`, and only the selected page resolves containing
    /// functions and names, so per-page work scales with the page.
    /// Read-only: never writes the binary or the sidecar.
    ///
    /// # Errors
    /// [`Error::Invalid`] when `depth` exceeds the hop cap.
    pub fn slice_page(
        &self,
        to: u64,
        depth: usize,
        offset: usize,
        limit: usize,
    ) -> Result<Page<SliceNode>> {
        if depth > crate::analysis::MAX_SLICE_DEPTH {
            return Err(Error::Invalid(format!(
                "depth {depth} exceeds {}",
                crate::analysis::MAX_SLICE_DEPTH
            )));
        }
        let reached = self.analysis.slice_to(to, depth);
        let total = reached.len();
        let items: Vec<SliceNode> = reached
            .into_iter()
            .skip(offset)
            .take(limit.min(MAX_ROWS))
            .map(|(addr, d)| {
                let func = self.analysis.containing_function(addr);
                SliceNode {
                    addr,
                    depth: d,
                    name: func.and_then(|e| self.function_name(e)),
                    func,
                }
            })
            .collect();
        Ok(page_envelope(total, offset, limit, items))
    }

    /// Machine-readable lift coverage for `arch` plus per-range accounting.
    ///
    /// The arch-level tables come from [`crate::ir::coverage`]; `range`
    /// counts come from actual per-instruction lifts of the valid prefix
    /// (see [`Project::disasm_at`]), so `decoded == lifted + unlifted`
    /// exactly and `unlifted_mnemonics` names the distinct fallback
    /// mnemonics (sorted, capped at [`MAX_COVERAGE_MNEMONICS`]) with their
    /// real warning strings. `error_at` mirrors the disassembler's first
    /// bad opcode (`None` on a clean range). Opens nothing new and never
    /// writes; range caps follow [`Project::bytes_at`].
    ///
    /// # Errors
    /// [`Error::Invalid`] when `arch` differs from the binary's
    /// architecture; same as [`Project::disasm_at`] otherwise.
    pub fn ir_coverage_at(
        &self,
        arch: crate::disasm::Arch,
        addr: u64,
        len: usize,
    ) -> Result<serde_json::Value> {
        if arch != self.binary.arch {
            return Err(Error::Invalid(format!(
                "ir-coverage arch {} does not match binary arch {}",
                crate::db::arch_name(arch),
                crate::db::arch_name(self.binary.arch),
            )));
        }
        let partial = self.disasm_at(addr, len)?;
        let mut lifted = 0usize;
        let mut unlifted = 0usize;
        let mut counts: BTreeMap<&str, (usize, String)> = BTreeMap::new();
        for insn in &partial.insns {
            let rows = crate::ir::lift(arch, insn);
            let warning = rows.iter().find_map(|r| r.warning.clone());
            match warning {
                Some(w) => {
                    unlifted += 1;
                    counts
                        .entry(insn.mnem.as_str())
                        .and_modify(|(n, _)| *n += 1)
                        .or_insert((1, w));
                }
                None => lifted += 1,
            }
        }
        let (truncated, unlifted_mnemonics): (bool, Vec<serde_json::Value>) = {
            let mut rows: Vec<(&str, (usize, String))> = counts.into_iter().collect();
            let truncated = rows.len() > MAX_COVERAGE_MNEMONICS;
            rows.truncate(MAX_COVERAGE_MNEMONICS);
            let values = rows
                .into_iter()
                .map(|(mnemonic, (count, warning))| {
                    serde_json::json!({"mnemonic": mnemonic, "count": count, "warning": warning})
                })
                .collect();
            (truncated, values)
        };
        let mut value =
            serde_json::to_value(crate::ir::coverage(arch)).expect("coverage serializes");
        let (range_addr, range_hex) = addr_pair(addr);
        value["range"] = serde_json::json!({
            "addr": range_addr, "addr_hex": range_hex,
            "decoded": partial.insns.len(), "lifted": lifted, "unlifted": unlifted,
            "unlifted_mnemonics": unlifted_mnemonics, "truncated": truncated,
            "error_at": partial.error_at,
        });
        Ok(value)
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
        self.xrefs_matching(to, from, kind)
            .skip(offset)
            .take(limit.min(MAX_ROWS))
            .collect()
    }

    /// Count of xrefs matching the [`Project::query_xrefs`] filters, before
    /// paging. The CLI/MCP `xrefs` envelope reports this as `total` so
    /// large result sets page without scanning blind.
    #[must_use]
    pub fn count_xrefs(&self, to: Option<u64>, from: Option<u64>, kind: Option<XrefKind>) -> usize {
        self.xrefs_matching(to, from, kind).count()
    }

    /// Xrefs matching the endpoint/kind filters, in storage order.
    fn xrefs_matching(
        &self,
        to: Option<u64>,
        from: Option<u64>,
        kind: Option<XrefKind>,
    ) -> impl Iterator<Item = Xref> + '_ {
        self.analysis
            .xrefs
            .iter()
            .copied()
            .filter(move |x| to.is_none_or(|t| x.to == t))
            .filter(move |x| from.is_none_or(|f| x.from == f))
            .filter(move |x| kind.is_none_or(|k| x.kind == k))
    }

    /// Imports plus exports for symbol views.
    ///
    /// Ordinal-only imports carry `ordinal` plus `unresolved: true`;
    /// C++ imports/exports carry `demangled` when [`crate::loader::demangle_cpp`]
    /// recognizes the mangling.
    #[must_use]
    pub fn symbols_json(&self) -> serde_json::Value {
        serde_json::json!({ "imports": self.binary.imports, "exports": self.binary.exports })
    }

    /// Section table in file order: name, virtual address, in-memory size,
    /// file offset/size of the raw bytes, and permissions.
    ///
    /// `vaddr` is the flat virtual address the loader mapped the section at
    /// (PE: `IMAGE_BASE + RVA`, so `.text` at RVA `0x1000` in a
    /// `0x400000`-based image lives at `0x401000`); `file_off` locates the
    /// section's raw bytes in the file. Raw blobs have no table and report
    /// an empty array.
    #[must_use]
    pub fn sections_json(&self) -> serde_json::Value {
        let rows: Vec<serde_json::Value> = self
            .binary
            .sections
            .iter()
            .map(|s| {
                let (vaddr, vaddr_hex) = addr_pair(s.vaddr);
                serde_json::json!({
                    "name": s.name, "vaddr": vaddr, "vaddr_hex": vaddr_hex, "size": s.size,
                    "file_off": s.file_off, "file_size": s.data.len(),
                    "readable": s.readable, "writable": s.writable,
                    "executable": s.executable,
                })
            })
            .collect();
        serde_json::Value::Array(rows)
    }

    /// Extracted strings, filtered then paged (the `strings` command query).
    ///
    /// See [`Analysis::strings_page_filtered`] for the filter semantics:
    /// executable-memory hits are hidden unless the filter opts back in.
    ///
    /// # Errors
    /// [`Error::Invalid`] when the filter pattern is overlong or a `regex:`
    /// expression fails to compile.
    pub fn query_strings(&self, filter: &StringsFilter) -> Result<Vec<StringHit>> {
        self.analysis.strings_page_filtered(filter)
    }

    /// Decoded-view strings: `strings --decode` over an in-memory transform.
    ///
    /// Re-extracts over a per-segment decoded copy (see
    /// [`Analysis::strings_decoded_view`]) with the same filter semantics
    /// as [`Project::query_strings`]: single-byte XOR/add/rot-obfuscated
    /// text shows up with its original offsets and addresses. Strictly
    /// read-only: the binary and the sidecar are never written.
    ///
    /// # Errors
    /// [`Error::Invalid`] when the filter pattern is overlong or a `regex:`
    /// expression fails to compile.
    pub fn query_strings_decoded(
        &self,
        filter: &StringsFilter,
        decode: crate::loader::strings::DecodeSpec,
    ) -> Result<Vec<StringHit>> {
        self.analysis
            .strings_decoded_view(&self.binary, filter, decode)
    }

    /// Search mapped file bytes for a literal/wildcard pattern, paged.
    ///
    /// `pattern` is whitespace-separated full-byte tokens, each two hex
    /// digits or a `??` wildcard (see [`BytePattern::parse`]). `section`
    /// keeps matches fully inside a file-backed section of that exact name;
    /// `range` is half-open `[lo, hi)` over match VAs. Rows order by virtual
    /// address with overlapping matches included, under the protocol-1
    /// [`Page`] envelope; `total` is exact and may require a full bounded
    /// scan. Read-only: never writes the binary or the sidecar.
    ///
    /// # Errors
    /// [`Error::Invalid`] on malformed/overlong patterns and empty ranges,
    /// [`Error::NotFound`] when `section` names no section,
    /// [`Error::Limit`] past the per-request scan budget.
    pub fn search_bytes(
        &self,
        pattern: &str,
        section: Option<&str>,
        range: Option<(u64, u64)>,
        offset: usize,
        limit: usize,
    ) -> Result<Page<ByteMatch>> {
        let parsed = BytePattern::parse(pattern)?;
        let (total, items) = crate::search::run(
            &self.binary,
            &parsed,
            section,
            range,
            offset,
            limit.min(MAX_ROWS),
        )?;
        Ok(page_envelope(total, offset, limit, items))
    }

    /// Diagnostics filtered by kind and containing function, under the
    /// protocol-1 [`Page`] envelope.
    ///
    /// Filtering precedes paging (see
    /// [`Analysis::diagnostics_matching`](crate::analysis::Analysis::diagnostics_matching)):
    /// `total` is the filtered count and only the selected page is
    /// materialized into rows. `func` may be any address inside a
    /// function; it snaps to the containing entry exactly like
    /// [`Project::func_detail`]. Read-only: never writes the binary or
    /// the sidecar.
    ///
    /// # Errors
    /// [`Error::NotFound`] when `func` lies in no function.
    pub fn query_diagnostics(
        &self,
        kind: Option<DiagnosticKind>,
        func: Option<u64>,
        offset: usize,
        limit: usize,
    ) -> Result<Page<DiagnosticRow>> {
        let entry = func
            .map(|a| {
                self.analysis
                    .containing_function(a)
                    .ok_or_else(|| Error::NotFound(format!("function {a:#x}")))
            })
            .transpose()?;
        let matched = self.analysis.diagnostics_matching(kind, entry);
        let total = matched.len();
        let items = matched
            .into_iter()
            .skip(offset)
            .take(limit.min(MAX_ROWS))
            .map(|d| DiagnosticRow {
                kind: d.kind,
                addr: d.addr,
                func: self.analysis.containing_function(d.addr),
                detail: diagnostic_detail(d.kind).to_string(),
            })
            .collect();
        Ok(page_envelope(total, offset, limit, items))
    }

    /// Current annotation at `addr`.
    #[must_use]
    pub fn annotation_json(&self, addr: u64) -> serde_json::Value {
        let (addr_json, addr_hex) = addr_pair(addr);
        match self.annotation(addr) {
            Some(a) => {
                serde_json::json!({ "addr": addr_json, "addr_hex": addr_hex, "name": a.name, "comment": a.comment })
            }
            None => {
                serde_json::json!({ "addr": addr_json, "addr_hex": addr_hex, "name": null, "comment": null })
            }
        }
    }

    /// FLIRT-like library hints: corpus signature matches over each
    /// function's leading bytes, under the protocol-1 [`Page`] envelope.
    ///
    /// Filtering precedes paging: `addr` snaps to its containing entry
    /// exactly like [`Project::func_detail`] and keeps only that function's
    /// hints (`total` is the filtered count); `None` lists every hint
    /// ordered by entry. Suggested names stay hints: this never renames,
    /// comments, or otherwise writes the binary or the sidecar.
    ///
    /// # Errors
    /// [`Error::NotFound`] when `addr` lies in no function.
    pub fn query_flirt_hints(
        &self,
        addr: Option<u64>,
        offset: usize,
        limit: usize,
    ) -> Result<Page<FlirtHint>> {
        let entry = addr
            .map(|a| {
                self.analysis
                    .containing_function(a)
                    .ok_or_else(|| Error::NotFound(format!("function {a:#x}")))
            })
            .transpose()?;
        let matched: Vec<FlirtHint> = crate::flirt::hints_for_analysis(&self.analysis)
            .into_iter()
            .filter(|h| entry.is_none_or(|e| h.entry == e))
            .collect();
        let total = matched.len();
        let items = matched
            .into_iter()
            .skip(offset)
            .take(limit.min(MAX_ROWS))
            .collect();
        Ok(page_envelope(total, offset, limit, items))
    }
}

/// Cap on raw bytes per [`Project::bytes_at`] call.
pub const MAX_RANGE_BYTES: usize = 1 << 20;
/// Cap on rows per paged query.
const MAX_ROWS: usize = 1024;
/// Cap on distinct unlifted mnemonics in an
/// [`Project::ir_coverage_at`] range summary; beyond it `truncated` is set.
pub const MAX_COVERAGE_MNEMONICS: usize = 32;

/// Machine-readable lift coverage for `arch`, without opening a binary.
///
/// Families publish the same mnemonic slices the [`crate::ir`] dispatch
/// predicates consult, with explicit implemented/partial/unmapped status
/// plus the engine-wide limitations; unknown mnemonics stay fallback NOP
/// with a warning. With a range, use [`Project::ir_coverage_at`], which
/// adds per-range `decoded`/`lifted`/`unlifted` counts from actual lifts.
#[must_use]
pub fn ir_coverage(arch: crate::disasm::Arch) -> serde_json::Value {
    serde_json::to_value(crate::ir::coverage(arch)).expect("coverage serializes")
}

/// Format a virtual address as canonical `0x`-hex (`0x401000`).
///
/// Every JSON address field pairs its integer value with this string form
/// (`addr` + `addr_hex`, `entry` + `entry_hex`, `from` + `from_hex`, ...),
/// so agents can join outputs without guessing the base. Lowercase, no
/// leading zeros (except `0x0` itself).
#[must_use]
pub fn addr_hex(addr: u64) -> String {
    format!("{addr:#x}")
}

/// Dual address encoding: integer value plus canonical `0x`-hex string.
///
/// Returns `(addr, addr_hex(addr))` for spreading into JSON envelopes; the
/// integer keeps numeric range queries working, the string keeps joins
/// unambiguous.
#[must_use]
pub fn addr_pair(addr: u64) -> (u64, String) {
    (addr, addr_hex(addr))
}

/// Dual encoding for optional addresses: `(None, None)` stays null on both
/// sides instead of inventing an address.
#[must_use]
pub fn opt_addr_pair(addr: Option<u64>) -> (Option<u64>, Option<String>) {
    (addr, addr.map(addr_hex))
}

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

/// Parse an xref kind filter: `code`, `data`, `string`, or
/// `inferred-code` (provenance-marked single-slot resolutions).
///
/// # Errors
/// [`Error::Invalid`] for anything else.
pub fn parse_xref_kind(s: &str) -> Result<XrefKind> {
    match s.to_lowercase().as_str() {
        "code" => Ok(XrefKind::Code),
        "data" => Ok(XrefKind::Data),
        "string" => Ok(XrefKind::String),
        "inferred-code" => Ok(XrefKind::InferredCode),
        _ => Err(Error::Invalid(format!("bad xref kind: {s:?}"))),
    }
}

/// Parse a diagnostics kind filter: `unresolved-indirect-jump`,
/// `unresolved-indirect-call`, or `decode-failure` (case-insensitive).
///
/// # Errors
/// [`Error::Invalid`] for anything else.
pub fn parse_diagnostic_kind(s: &str) -> Result<DiagnosticKind> {
    match s.to_lowercase().as_str() {
        "unresolved-indirect-jump" => Ok(DiagnosticKind::UnresolvedIndirectJump),
        "unresolved-indirect-call" => Ok(DiagnosticKind::UnresolvedIndirectCall),
        "decode-failure" => Ok(DiagnosticKind::DecodeFailure),
        _ => Err(Error::Invalid(format!("bad diagnostic kind: {s:?}"))),
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

/// Read one input file with a hard pre-parse budget.
///
/// Opens the path once and accumulates 64 KiB chunks with checked
/// arithmetic, so `stat`-then-read races and mid-read growth cannot dodge
/// [`crate::loader::MAX_INPUT_BYTES`]. Containers larger than
/// [`crate::loader::MAX_MAPPED_BYTES`] still open when their mapped bytes
/// fit: unmapped overlays/debug data are accepted up to the input cap.
/// Oversize returns [`Error::Limit`] (never `Invalid`), so
/// [`load_or_raw`] does not fall back to raw.
///
/// # Errors
/// [`Error::NotFound`] if the path does not exist, [`Error::Unsupported`]
/// if it is not a file, [`Error::Limit`] past the input cap,
/// [`Error::Storage`] on I/O failure.
fn read_input_bytes(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::NotFound(path.display().to_string()),
        _ => Error::Storage(format!("stat {}: {e}", path.display())),
    })?;
    if !meta.is_file() {
        return Err(Error::Unsupported(format!(
            "not a file: {}",
            path.display()
        )));
    }
    let file = std::fs::File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::NotFound(path.display().to_string()),
        _ => Error::Storage(format!("read {}: {e}", path.display())),
    })?;
    let cap = crate::loader::MAX_INPUT_BYTES;
    let mut reader = file;
    read_stream_capped(&mut reader, cap, &path.display().to_string())
}

/// Accumulate a stream with checked growth against `cap`.
///
/// Split from [`read_input_bytes`] so the exact/over boundary and
/// mid-read growth are unit-testable without a 512 MiB file: every chunk
/// extends the total with [`checked_add`](u64::checked_add) and rejects
/// past `cap` with [`Error::Limit`].
fn read_stream_capped(reader: &mut impl std::io::Read, cap: u64, label: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(reader, &mut chunk)
            .map_err(|e| Error::Storage(format!("read {label}: {e}")))?;
        if n == 0 {
            break;
        }
        let next = (out.len() as u64)
            .checked_add(n as u64)
            .filter(|m| *m <= cap)
            .ok_or_else(|| Error::Limit("input exceeds 512 MiB".to_string()))?;
        out.reserve_exact(n);
        out.extend_from_slice(&chunk[..n]);
        debug_assert_eq!(out.len() as u64, next);
    }
    Ok(out)
}

/// Container parse with raw x86-64 fallback for unrecognized bytes.
///
/// Only [`Error::Invalid`] on unrecognized input falls back; recognized
/// containers that fail to parse (LE included) report the parse error,
/// and [`Error::Limit`]/[`Error::Unsupported`] propagate unchanged. LE
/// images that parse flow to analysis as x86_32.
fn load_or_raw(bytes: &[u8]) -> Result<LoadedBinary> {
    match load(bytes) {
        Ok(bin) => Ok(bin),
        Err(Error::Invalid(_)) if !crate::loader::is_recognized(bytes) => load_raw(
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

#[cfg(test)]
mod tests {
    use super::{parse_addr, parse_diagnostic_kind, parse_xref_kind, read_stream_capped};
    use crate::analysis::XrefKind;
    use crate::error::Error;

    #[test]
    fn parse_addr_hex_equals_decimal() {
        assert_eq!(parse_addr("0x402100").expect("hex"), 0x402100);
        assert_eq!(parse_addr("0X402100").expect("upper hex"), 0x402100);
        assert_eq!(
            parse_addr("4202752").expect("decimal"),
            parse_addr("0x402100").expect("hex")
        );
        assert!(parse_addr("zz").is_err());
    }

    #[test]
    fn parse_xref_kind_is_case_insensitive() {
        for (s, want) in [
            ("code", XrefKind::Code),
            ("Data", XrefKind::Data),
            ("STRING", XrefKind::String),
            ("inferred-code", XrefKind::InferredCode),
            ("Inferred-Code", XrefKind::InferredCode),
        ] {
            assert_eq!(parse_xref_kind(s).expect("known kind"), want);
        }
        assert!(parse_xref_kind("nope").is_err());
    }

    #[test]
    fn parse_diagnostic_kind_takes_kebab_case_only() {
        use crate::analysis::DiagnosticKind;
        for (s, want) in [
            (
                "unresolved-indirect-jump",
                DiagnosticKind::UnresolvedIndirectJump,
            ),
            (
                "Unresolved-Indirect-Call",
                DiagnosticKind::UnresolvedIndirectCall,
            ),
            ("DECODE-FAILURE", DiagnosticKind::DecodeFailure),
        ] {
            assert_eq!(parse_diagnostic_kind(s).expect("known kind"), want);
        }
        for s in ["code", "", "UnresolvedIndirectCall", "decode_failure"] {
            assert!(parse_diagnostic_kind(s).is_err(), "{s:?} must error");
        }
    }

    #[test]
    fn stream_cap_exact_passes_over_fails() {
        let exact = vec![0x41u8; 16];
        let mut cur = std::io::Cursor::new(exact.clone());
        let got = read_stream_capped(&mut cur, 16, "t").expect("exact cap passes");
        assert_eq!(got, exact);
        let mut cur = std::io::Cursor::new(vec![0x41u8; 17]);
        let err = read_stream_capped(&mut cur, 16, "t").unwrap_err();
        assert!(matches!(err, Error::Limit(_)), "got {err:?}");
    }

    /// A reader that grows past its initial length must still hit the cap:
    /// the accumulator never trusts a stat size.
    #[test]
    fn stream_cap_catches_mid_read_growth() {
        struct Growing {
            left: usize,
        }
        impl std::io::Read for Growing {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.left == 0 {
                    return Ok(0);
                }
                let n = buf.len().min(self.left).min(7);
                buf[..n].fill(0x42);
                self.left -= n;
                Ok(n)
            }
        }
        let mut g = Growing { left: 25 };
        let err = read_stream_capped(&mut g, 16, "g").unwrap_err();
        assert!(matches!(err, Error::Limit(_)), "got {err:?}");
        let mut g = Growing { left: 16 };
        let got = read_stream_capped(&mut g, 16, "g").expect("exact growth passes");
        assert_eq!(got.len(), 16);
    }
}
