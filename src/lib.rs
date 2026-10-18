#![warn(missing_docs)]
//! binscout core: headless agent-first binary analysis.

pub mod analysis;
pub mod annotations;
pub mod crypto;
pub mod db;
pub mod diff;
pub mod disasm;
pub mod error;
pub mod flirt;
pub mod gopclntab;
pub mod headers;
pub mod ir;
pub mod loader;
pub mod mcp;
pub mod pseudo;
pub mod search;
pub mod stackstrings;

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use crate::analysis::{
    Analysis, AnalysisSummary, BlockSummary, DiagnosticKind, DiagnosticRow, StringsFilter, Xref,
    XrefKind, analyze_with_seeds, diagnostic_detail, import_index, import_slots,
};
use crate::db::{Annotation, BinaryMeta, ProjectInfo};
use crate::disasm::{Disassembler, Insn, PartialDisasm, resolve_adrp_pair};
use crate::error::{Error, Result};
use crate::flirt::FlirtHint;
use crate::loader::strings::{Encoding, StringHit};
use crate::loader::{LoadedBinary, RawOptions, load_raw, load_raw_vec, load_with_slice};
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

/// Open a binary with an optional explicit raw mapping, an optional fat
/// Mach-O slice selection, and an optional explicit DB path.
///
/// Shared by the CLI and MCP so every binary-taking operation interprets
/// options identically: `raw` `Some` opens the explicit mapping with no
/// fallback, `fat_arch` `Some` analyzes that fat slice (passed through
/// unchanged to [`crate::loader::load_with_slice`]; missing/unknown
/// selections on fat input error listing the available archs, and any
/// selection on thin input errors), and both `None` preserves auto
/// detection (container parse with raw x86-64-at-0 fallback). Raw and fat
/// selections are exclusive. Reads never save or create the sidecar.
///
/// # Errors
/// Same as [`Project::open`] plus raw-mapping validation from
/// [`crate::loader::load_raw`], plus [`Error::Invalid`] when raw and fat
/// selections are combined, plus [`Error::Invalid`] when the DB path
/// resolves to the analyzed binary.
pub fn open_mapped(
    binary: &Path,
    db: Option<&Path>,
    raw: Option<RawOptions>,
    fat_arch: Option<&str>,
) -> Result<Project> {
    let owned;
    let db_path = match db {
        Some(p) => p,
        None => {
            owned = db::default_db_path(binary);
            // Borrow lives until the open call below returns.
            &owned
        }
    };
    match (raw, fat_arch) {
        (Some(_), Some(_)) => Err(Error::Invalid(
            "--raw and --fat-arch are exclusive (or MCP raw with fat_arch)".to_string(),
        )),
        (Some(opts), None) => Project::open_raw(binary, db_path, opts),
        (None, Some(arch)) => Project::open_fat(binary, db_path, arch),
        (None, None) => Project::open_with_db(binary, db_path),
    }
}

/// [`open_mapped`] for loader-only commands: explicit DB path (or the
/// default sidecar), explicit raw mapping, and fat Mach-O slice selection
/// interpreted identically, returning [`LoaderOpened`] so cache hits skip
/// instruction re-decode (see [`Project::open_loader_only`]).
///
/// # Errors
/// Same as [`open_mapped`].
pub fn open_mapped_loader_only(
    binary: &Path,
    db: Option<&Path>,
    raw: Option<RawOptions>,
    fat_arch: Option<&str>,
) -> Result<LoaderOpened> {
    let owned;
    let db_path = match db {
        Some(p) => p,
        None => {
            owned = db::default_db_path(binary);
            // Borrow lives until the open call below returns.
            &owned
        }
    };
    match (raw, fat_arch) {
        (Some(_), Some(_)) => Err(Error::Invalid(
            "--raw and --fat-arch are exclusive (or MCP raw with fat_arch)".to_string(),
        )),
        _ => Project::open_loader_only(binary, db_path, raw, fat_arch),
    }
}

/// Cache identity for an open request: explicit raw wins, else the fat
/// slice selection, else auto detection. Raw and fat are exclusive.
fn mapping_for(raw: Option<RawOptions>, fat_arch: Option<&str>) -> Result<db::StoredMapping> {
    match (raw, fat_arch) {
        (Some(_), Some(_)) => Err(Error::Invalid(
            "--raw and --fat-arch are exclusive (or MCP raw with fat_arch)".to_string(),
        )),
        (Some(opts), None) => Ok(db::StoredMapping::for_request(Some(opts))),
        (None, Some(arch)) => Ok(db::StoredMapping::for_fat_slice(arch)),
        (None, None) => Ok(db::StoredMapping::for_request(None)),
    }
}

/// Reject a `--db` path that resolves to the analyzed binary.
///
/// The sidecar is rewritten by [`Project::save`], so opening with the
/// binary as its own DB would overwrite the input. Symlinks resolve via
/// `canonicalize`; hard links share `(dev, ino)` on unix. Best-effort:
/// unresolvable paths simply do not match.
fn reject_db_is_binary(binary: &Path, db_path: &Path) -> Result<()> {
    if !db_path.exists() {
        return Ok(());
    }
    if let (Ok(can_bin), Ok(can_db)) = (
        std::fs::canonicalize(binary),
        std::fs::canonicalize(db_path),
    ) && can_bin == can_db
    {
        return Err(Error::Invalid(
            "--db must not be the analyzed binary".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(bin_meta), Ok(db_meta)) = (std::fs::metadata(binary), std::fs::metadata(db_path))
            && bin_meta.dev() == db_meta.dev()
            && bin_meta.ino() == db_meta.ino()
        {
            return Err(Error::Invalid(
                "--db must not be the analyzed binary".to_string(),
            ));
        }
    }
    Ok(())
}

/// Shared open prologue for [`Project::open_inner`] and the loader-only
/// open: input bytes plus content identity (hash, SHA-256, size), the
/// effective loader mapping, and the read-only snapshot lookup.
///
/// The snapshot read is metadata-first over a read-only handle: cache
/// identity covers content hash plus SHA-256 and size, loader mapping, and
/// analysis revision before any layout replay (see `db::load_cached`), and
/// the read-only open itself costs nothing proportional to the file. Reads
/// never save and never create the sidecar.
///
/// SHA-256 is computed only for a tentative match: the cheap identity
/// (schema version, content hash, size, mapping, analysis revision) is
/// checked against the stored row first, and only an agreement pays for the
/// wide hash that confirms the hit. `sha256` is empty when no sidecar
/// agrees, and the project computes it on first use (see
/// [`Project::ensure_sha256`]).
struct OpenInputs {
    bytes: Vec<u8>,
    hash: u64,
    sha256: String,
    size: u64,
    mapping: db::StoredMapping,
    cached: Option<db::Snapshot>,
}

/// Cheap snapshot identity without the wide hash: mirrors the
/// [`db::load_cached`] gates before its SHA-256 comparison, so a `true`
/// here means the stored row is worth confirming with SHA-256.
fn snapshot_fast_matches(
    meta: &db::BinaryMeta,
    hash: u64,
    size: u64,
    mapping: &db::StoredMapping,
) -> bool {
    meta.version == db::SCHEMA_VERSION
        && meta.content_hash == hash
        && meta.size == size
        && meta.mapping.as_ref() == Some(mapping)
        && meta.analysis_rev == Some(db::ANALYSIS_REVISION)
}

/// Cache a computed SHA-256 digest, or defer it: an empty digest means the
/// open skipped the wide hash (no tentative snapshot match) and the project
/// computes it on first use (see [`Project::ensure_sha256`]).
fn cache_sha256(sha256: String) -> OnceLock<String> {
    if sha256.is_empty() {
        OnceLock::new()
    } else {
        OnceLock::from(sha256)
    }
}

fn read_open_inputs(
    binary: &Path,
    db_path: &Path,
    raw: Option<RawOptions>,
    fat_arch: Option<&str>,
) -> Result<OpenInputs> {
    reject_db_is_binary(binary, db_path)?;
    // Single-open bounded read: one handle, chunked with checked
    // accumulation, so a growing file cannot slip past a stat cap.
    let bytes = read_input_bytes(binary)?;
    let hash = db::content_hash(&bytes);
    let size = bytes.len() as u64;
    let mapping = mapping_for(raw, fat_arch)?;
    let (cached, sha256) = if db_path.exists() {
        match db::open_db_read_only(db_path) {
            Ok(db) => {
                // Metadata first: only a cheap-identity agreement pays for
                // SHA-256. An empty digest never confirms a hit (stored rows
                // always carry a real one), so the mismatch path below
                // reproduces the stale/error outcomes exactly.
                let tentative = match db::read_meta(&db)? {
                    Some(meta) => snapshot_fast_matches(&meta, hash, size, &mapping),
                    None => false,
                };
                let sha256 = if tentative {
                    crate::annotations::sha256_hex(&bytes)
                } else {
                    String::new()
                };
                let snap = db::load_cached(&db, hash, &sha256, size, &mapping)?;
                (Some(snap), sha256)
            }
            // Raced with a concurrent sidecar deletion: read as absent.
            Err(_) if !db_path.exists() => (None, String::new()),
            Err(e) => return Err(e),
        }
    } else {
        (None, String::new())
    };
    Ok(OpenInputs {
        bytes,
        hash,
        sha256,
        size,
        mapping,
        cached,
    })
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
    /// Whether this function never returns (see
    /// [`crate::analysis::Function::noreturn`]).
    ///
    /// Defaults to `false` so metadata written before noreturn tracking
    /// still decodes.
    #[serde(default)]
    pub noreturn: bool,
}

impl Serialize for FuncMeta {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("FuncMeta", 10)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("entry", &self.entry)?;
        st.serialize_field("entry_hex", &crate::addr_hex(self.entry))?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("blocks", &self.blocks)?;
        st.serialize_field("insns", &self.insns)?;
        st.serialize_field("calls", &self.calls)?;
        st.serialize_field("reasons", &self.reasons)?;
        st.serialize_field("inferred_edges", &self.inferred_edges)?;
        st.serialize_field("noreturn", &self.noreturn)?;
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

/// Typed view over raw bytes for [`Project::bytes_view`].
///
/// `U8`/`U16`/`U32`/`U64` decode fixed-width little- or big-endian
/// integers (`values` holds the floor of `len / width` rows); `Ptr`
/// decodes pointer-width integers (8 bytes on 64-bit targets, 4
/// otherwise); `CStr` decodes the range up to the first NUL byte as one
/// lossy UTF-8 string; `Utf16` decodes UTF-16 code units in the selected
/// byte order up to the first NUL unit as one lossy string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytesAs {
    /// One row per byte.
    U8,
    /// 2-byte units.
    U16,
    /// 4-byte units.
    U32,
    /// 8-byte units.
    U64,
    /// Pointer-width units (arch-dependent).
    Ptr,
    /// NUL-terminated lossy UTF-8 string.
    CStr,
    /// NUL-terminated lossy UTF-16 string.
    Utf16,
}

/// Byte order for multi-byte [`BytesAs`] views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytesEndian {
    /// Least significant byte first.
    Le,
    /// Most significant byte first.
    Be,
}

/// Raw byte range with VA/file provenance and a typed view.
///
/// `bytes_hex` is the range as continuous lowercase hex; `values` is the
/// [`BytesAs`] decoding (integers as numbers, `cstr`/`utf16` as a single
/// string row). `file_off`/`section` describe the range start only: the
/// file offset is null when the start byte is zero-fill/BSS or otherwise
/// unbacked, and the section is the covering file-backed section name
/// (null for zero-fill and section-less ranges, following
/// [`Project::search_bytes`] provenance).
///
/// JSON pairs `addr` with `addr_hex`; `file_off` stays a plain
/// integer-or-null like the search and section views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytesView {
    /// Range start virtual address.
    pub addr: u64,
    /// File offset of the range start, if file-backed.
    pub file_off: Option<u64>,
    /// Covering file-backed section name, if any.
    pub section: Option<String>,
    /// Raw bytes of the range.
    pub bytes: Vec<u8>,
    /// Typed decoding of [`BytesView::bytes`].
    pub values: Vec<serde_json::Value>,
}

impl BytesView {
    /// Range bytes as continuous lowercase hex.
    #[must_use]
    pub fn bytes_hex(&self) -> String {
        let mut out = String::with_capacity(self.bytes.len() * 2);
        for b in &self.bytes {
            out.push(char::from_digit(u32::from(*b >> 4), 16).expect("hex digit"));
            out.push(char::from_digit(u32::from(*b & 0x0f), 16).expect("hex digit"));
        }
        out
    }
}

impl serde::Serialize for BytesView {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("BytesView", 7)?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("file_off", &self.file_off)?;
        st.serialize_field("section", &self.section)?;
        st.serialize_field("len", &self.bytes.len())?;
        st.serialize_field("bytes_hex", &self.bytes_hex())?;
        st.serialize_field("values", &self.values)?;
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
pub(crate) fn page_envelope<T>(
    total: usize,
    offset: usize,
    limit: usize,
    items: Vec<T>,
) -> Page<T> {
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

/// Render-time listing context: name and string indexes built once per
/// read so per-row enrichment stays cheap.
///
/// A pure derived view over the project: building it writes nothing, and
/// the rows it annotates are never persisted.
struct EnrichCtx<'a> {
    /// First symbol-table name per code address.
    symbols: BTreeMap<u64, &'a str>,
    /// First import name per resolved call-pointer address.
    imports: BTreeMap<u64, &'a str>,
    /// Import slot map (see [`import_slots`](crate::analysis::import_slots)).
    slots: BTreeMap<u64, usize>,
    /// Recovered string spans as `(start, end, value)`, in address order.
    spans: Vec<(u64, u64, &'a str)>,
}

/// Outcome of [`Project::open_loader_only`]: either a decode-free
/// cache-hit view or a fully analyzed project.
///
/// Loader-only commands (`sections`, `symbols`, `search-bytes`, `bytes`,
/// `headers`, `strings`, `annotations-export`, `stats`, and the
/// `load`/`project_info` summaries) serve from either variant with
/// byte-identical JSON: a hit skips instruction re-decode entirely, while a
/// stale or missing snapshot falls back to the full open. Both sides are
/// boxed: each holds the mapped binary bytes, so an inline enum would carry
/// hundreds of bytes per value.
#[derive(Debug)]
pub enum LoaderOpened {
    /// Cache hit: serving needs no instruction decode (see [`LoaderProject`]).
    Cached(Box<LoaderProject>),
    /// Stale or missing snapshot: fully analyzed, same as [`Project::open`].
    Fresh(Box<Project>),
}

/// Cache-hit view for loader-only commands: binary plus stored snapshot
/// rows, without re-decoding a single instruction.
///
/// Built by [`Project::open_loader_only`] only when the sidecar holds a
/// matching snapshot (content hash plus SHA-256 and size, loader mapping,
/// and analysis revision already verified equal). Outcome counts come from
/// the stored layouts instead of a rebuilt
/// [`Analysis`]: one persisted instruction
/// boundary replays to exactly one instruction (any mismatch is snapshot
/// corruption), and xrefs, strings, and diagnostics replay verbatim, so the
/// counts equal a full open's. Only the sidecar is ever read; like
/// [`Project`], this never writes the analyzed binary.
#[derive(Debug)]
pub struct LoaderProject {
    path: PathBuf,
    db_path: PathBuf,
    content_hash: u64,
    content_sha256: String,
    size: u64,
    binary: LoadedBinary,
    summary: AnalysisSummary,
    diagnostics: usize,
    diagnostics_truncated: bool,
    diagnostics_omitted: usize,
    inferred_truncated: bool,
    inferred_omitted: usize,
    strings: Vec<StringHit>,
    annotations: BTreeMap<u64, Annotation>,
    func_seeds: BTreeMap<u64, crate::db::FuncSeed>,
    mapping: db::StoredMapping,
}

/// Outcome counts from stored snapshot rows, without decoding.
///
/// `functions` is the layout count, `blocks`/`insns` sum the stored block
/// and boundary rows, and `xrefs`/`strings` are the stored row counts: the
/// rebuild replays each boundary to exactly one instruction and carries the
/// row vectors over unchanged, so this equals a full open's
/// [`Analysis::summary`](crate::analysis::Analysis::summary).
fn summary_of_hit(
    functions: &[crate::analysis::FunctionLayout],
    xrefs: &[Xref],
    strings: &[StringHit],
) -> AnalysisSummary {
    AnalysisSummary {
        functions: functions.len(),
        blocks: functions.iter().map(|f| f.blocks.len()).sum(),
        insns: functions
            .iter()
            .map(|f| f.blocks.iter().map(|b| b.insns.len()).sum::<usize>())
            .sum(),
        xrefs: xrefs.len(),
        strings: strings.len(),
    }
}

impl LoaderProject {
    /// Whether the sidecar already holds this exact snapshot.
    ///
    /// Always true: a [`LoaderProject`] only exists for a cache hit, so
    /// `load` skips its `save` exactly like a fresh full open.
    #[must_use]
    pub fn snapshot_fresh(&self) -> bool {
        true
    }

    /// Agent-facing summary; always JSON-serializable.
    ///
    /// Same document as [`Project::project_info`]: counts come from the
    /// stored snapshot rows instead of a rebuilt analysis.
    #[must_use]
    pub fn project_info(&self) -> ProjectInfo {
        let s = &self.summary;
        let (mode, base) = match &self.mapping {
            db::StoredMapping::Auto => ("auto".to_string(), None),
            db::StoredMapping::Explicit { base, .. } => ("raw".to_string(), Some(*base)),
            db::StoredMapping::Fat { .. } => ("fat".to_string(), None),
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
            diagnostics: self.diagnostics,
            diagnostics_truncated: self.diagnostics_truncated,
            diagnostics_omitted: self.diagnostics_omitted,
            inferred_truncated: self.inferred_truncated,
            inferred_omitted: self.inferred_omitted,
            analysis_revision: crate::analysis::ANALYSIS_REVISION,
        }
    }

    /// Storage stats for the project: binary size plus sidecar DB size
    /// and the same analysis counts as [`LoaderProject::project_info`].
    ///
    /// Same document as [`Project::stats_json`]: `db_size` is `0` when no
    /// sidecar exists yet. A loader-only open only exists for a cache hit,
    /// so no stale annotations were dropped.
    ///
    /// # Errors
    /// [`Error::Storage`] when the sidecar exists but cannot be statted.
    pub fn stats_json(&self) -> Result<serde_json::Value> {
        let s = &self.summary;
        let db_size = db::db_file_size(&self.db_path)?;
        let (mode, (base, base_hex)) = match &self.mapping {
            db::StoredMapping::Auto => ("auto".to_string(), crate::opt_addr_pair(None)),
            db::StoredMapping::Explicit { base, .. } => {
                ("raw".to_string(), crate::opt_addr_pair(Some(*base)))
            }
            db::StoredMapping::Fat { .. } => ("fat".to_string(), crate::opt_addr_pair(None)),
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
            "content_sha256": self.content_sha256,
            "size": self.size,
            "db_size": db_size,
            "functions": s.functions,
            "blocks": s.blocks,
            "insns": s.insns,
            "xrefs": s.xrefs,
            "strings": s.strings,
            "annotations": self.annotations.values().filter(|a| !a.is_empty()).count(),
            "annotations_dropped": 0,
            "stale_warning": serde_json::Value::Null,
            "diagnostics": self.diagnostics,
            "diagnostics_truncated": self.diagnostics_truncated,
            "diagnostics_omitted": self.diagnostics_omitted,
            "inferred_truncated": self.inferred_truncated,
            "inferred_omitted": self.inferred_omitted,
            "analysis_revision": crate::analysis::ANALYSIS_REVISION,
        }))
    }

    /// On-demand header metadata: triage staples plus file hashes.
    ///
    /// Same document as [`Project::headers_json`]: re-reads the binary file
    /// and parses its container headers, computed on demand and never
    /// persisted.
    ///
    /// # Errors
    /// [`Error::Storage`] when the binary cannot be re-read, [`Error::Limit`]
    /// past the input budget (see [`crate::loader::MAX_INPUT_BYTES`]).
    pub fn headers_json(&self) -> Result<serde_json::Value> {
        let bytes = read_input_bytes(&self.path)?;
        Ok(crate::headers::headers_of(
            &bytes,
            &self.binary,
            &self.content_sha256,
        ))
    }

    /// Imports plus exports plus symbol-table code addresses for symbol views.
    ///
    /// Same document as [`Project::symbols_json`]: straight from the loader,
    /// no analysis involved.
    #[must_use]
    pub fn symbols_json(&self) -> serde_json::Value {
        serde_json::json!({ "imports": self.binary.imports, "exports": self.binary.exports, "symbols": self.binary.symbols })
    }

    /// Section table in file order: name, virtual address, in-memory size,
    /// file offset/size of the raw bytes, and permissions.
    ///
    /// Same rows as [`Project::sections_json`]: straight from the loader,
    /// no analysis involved. Raw blobs have no table and report an empty
    /// array.
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
                    "file_off": s.file_off, "file_size": s.file_size,
                    "readable": s.readable, "writable": s.writable,
                    "executable": s.executable,
                })
            })
            .collect();
        serde_json::Value::Array(rows)
    }

    /// Raw byte range at `va` with VA/file provenance and a typed view.
    ///
    /// Same result as [`Project::bytes_view`]: validated through the shared
    /// range helper (same 1 MiB cap, zero-padded BSS tails, unmapped ranges
    /// are [`Error::NotFound`]). Read-only: never writes the binary or the
    /// sidecar.
    ///
    /// # Errors
    /// Same as [`Project::bytes_view`].
    pub fn bytes_view(
        &self,
        va: u64,
        len: usize,
        as_: BytesAs,
        endian: BytesEndian,
    ) -> Result<BytesView> {
        bytes_view_of(&self.binary, va, len, as_, endian)
    }

    /// Raw byte range with the struct layout stored at `hint_addr` rendered
    /// over it.
    ///
    /// Same result as [`Project::bytes_view_as_type`]: the range reads
    /// through the shared helper (same 1 MiB cap, zero-padded BSS tails,
    /// unmapped ranges are [`Error::NotFound`]). Read-only: never writes
    /// the binary or the sidecar.
    ///
    /// # Errors
    /// Same as [`Project::bytes_view_as_type`].
    pub fn bytes_view_as_type(
        &self,
        va: u64,
        len: usize,
        as_: BytesAs,
        endian: BytesEndian,
        hint_addr: u64,
    ) -> Result<serde_json::Value> {
        bytes_view_as_type_of(
            &self.binary,
            &self.annotations,
            va,
            len,
            as_,
            endian,
            hint_addr,
        )
    }

    /// Search mapped file bytes for a literal/wildcard pattern, paged.
    ///
    /// Same page as [`Project::search_bytes`]: `pattern` is
    /// whitespace-separated full-byte tokens, each two hex digits or a `??`
    /// wildcard. Read-only: never writes the binary or the sidecar.
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

    /// Extracted strings, filtered then paged (the `strings` command query).
    ///
    /// Same rows as [`Project::query_strings`]: the stored snapshot rows
    /// through the shared filter, no decoded analysis involved.
    ///
    /// # Errors
    /// [`Error::Invalid`] when the filter pattern is overlong or a `regex:`
    /// expression fails to compile.
    pub fn query_strings(&self, filter: &StringsFilter) -> Result<Vec<StringHit>> {
        crate::analysis::filter_string_hits(&self.strings, filter)
    }

    /// Extracted strings, filtered then paged under the protocol-1 envelope.
    ///
    /// Same page as [`Project::query_strings_envelope`]: `total` is the
    /// exact filtered count and `items` holds the requested page.
    ///
    /// # Errors
    /// Same as [`LoaderProject::query_strings`].
    pub fn query_strings_envelope(&self, filter: &StringsFilter) -> Result<Page<StringHit>> {
        let total = crate::analysis::count_string_hits(&self.strings, filter)?;
        let items = crate::analysis::filter_string_hits(&self.strings, filter)?;
        Ok(page_envelope(total, filter.start, filter.limit, items))
    }

    /// Decoded-view strings: `strings --decode` over an in-memory transform.
    ///
    /// Same rows as [`Project::query_strings_decoded`]: re-extracted over a
    /// per-segment decoded copy, strictly read-only.
    ///
    /// # Errors
    /// [`Error::Invalid`] when the filter pattern is overlong or a `regex:`
    /// expression fails to compile.
    pub fn query_strings_decoded(
        &self,
        filter: &StringsFilter,
        decode: crate::loader::strings::DecodeSpec,
    ) -> Result<Vec<StringHit>> {
        let hits = crate::analysis::decoded_string_hits(&self.binary, decode);
        crate::analysis::filter_string_hits(&hits, filter)
    }

    /// Decoded-view strings under the protocol-1 envelope.
    ///
    /// Same page as [`Project::query_strings_decoded_envelope`].
    ///
    /// # Errors
    /// Same as [`LoaderProject::query_strings_decoded`].
    pub fn query_strings_decoded_envelope(
        &self,
        filter: &StringsFilter,
        decode: crate::loader::strings::DecodeSpec,
    ) -> Result<Page<StringHit>> {
        let hits = crate::analysis::decoded_string_hits(&self.binary, decode);
        let total = crate::analysis::count_string_hits(&hits, filter)?;
        let items = crate::analysis::filter_string_hits(&hits, filter)?;
        Ok(page_envelope(total, filter.start, filter.limit, items))
    }

    /// Export renames, comments, and function seeds as a portable JSON
    /// interchange document.
    ///
    /// Same document as [`Project::export_annotations`]: strictly read-only,
    /// no sidecar is created or modified.
    ///
    /// # Errors
    /// [`Error::Limit`] past annotation, seed, or document budgets,
    /// [`Error::Storage`] on encoding failure.
    pub fn export_annotations(&self) -> Result<String> {
        crate::annotations::build_document(
            &self.content_sha256,
            self.size,
            &self.mapping,
            &self.annotations,
            &self.func_seeds,
        )
    }
}

/// Raw bytes at `va` from one loaded binary (the [`Project::bytes_at`]
/// core, shared with the loader-only open).
///
/// Same 1 MiB cap, zero-padded BSS tails, unmapped ranges are
/// [`Error::NotFound`].
fn bytes_at_in(bin: &LoadedBinary, va: u64, len: usize) -> Result<Vec<u8>> {
    if len == 0 || len > MAX_RANGE_BYTES {
        return Err(Error::Limit(format!("range length {len} out of bounds")));
    }
    let len_u64 = len as u64;
    let seg = bin
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

/// File offset of the byte at `va` in one loaded binary (the
/// [`Project::file_off_of`] core, shared with the loader-only open).
fn file_off_of_in(bin: &LoadedBinary, va: u64) -> Option<u64> {
    for sec in &bin.sections {
        if sec.file_size == 0 || va < sec.vaddr {
            continue;
        }
        let d = va - sec.vaddr;
        if d < sec.file_size {
            return sec.file_off.checked_add(d);
        }
    }
    if bin.format == crate::loader::BinaryFormat::Raw {
        for seg in &bin.segments {
            if va < seg.vaddr {
                continue;
            }
            let d = va - seg.vaddr;
            if d < seg.data.len() as u64 {
                return Some(d);
            }
        }
    }
    None
}

/// Name of the file-backed section covering `va` in one loaded binary (the
/// [`Project::section_of`] core, shared with the loader-only open).
fn section_of_in(bin: &LoadedBinary, va: u64) -> Option<&str> {
    for sec in &bin.sections {
        if sec.file_size == 0 || va < sec.vaddr {
            continue;
        }
        let d = va - sec.vaddr;
        if d < sec.file_size {
            return Some(sec.name.as_str());
        }
    }
    None
}

/// Decode up to 8 bytes as one integer in `endian` order.
fn decode_int(bytes: &[u8], le: bool) -> u64 {
    let mut v = 0u64;
    if le {
        for (i, &b) in bytes.iter().enumerate() {
            v |= u64::from(b) << (8 * i);
        }
    } else {
        for &b in bytes {
            v = (v << 8) | u64::from(b);
        }
    }
    v
}

/// Raw byte range with VA/file provenance and a typed view from one loaded
/// binary (the [`Project::bytes_view`] core, shared with the loader-only
/// open).
fn bytes_view_of(
    bin: &LoadedBinary,
    va: u64,
    len: usize,
    as_: BytesAs,
    endian: BytesEndian,
) -> Result<BytesView> {
    let bytes = bytes_at_in(bin, va, len)?;
    let width = match as_ {
        BytesAs::U8 | BytesAs::CStr => 1,
        BytesAs::U16 | BytesAs::Utf16 => 2,
        BytesAs::U32 => 4,
        BytesAs::U64 => 8,
        BytesAs::Ptr => match bin.arch {
            crate::disasm::Arch::X86_64 | crate::disasm::Arch::Aarch64 => 8,
            _ => 4,
        },
    };
    let le = endian == BytesEndian::Le;
    let values: Vec<serde_json::Value> = match as_ {
        BytesAs::U8 => bytes.iter().map(|&b| serde_json::Value::from(b)).collect(),
        BytesAs::U16 | BytesAs::U32 | BytesAs::U64 | BytesAs::Ptr => bytes
            .chunks_exact(width)
            .map(|w| serde_json::Value::from(decode_int(w, le)))
            .collect(),
        BytesAs::CStr => {
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            vec![serde_json::Value::from(
                String::from_utf8_lossy(&bytes[..end]).into_owned(),
            )]
        }
        BytesAs::Utf16 => {
            let (units, _) = bytes.as_chunks::<2>();
            let units: Vec<u16> = units.iter().map(|w| decode_int(w, le) as u16).collect();
            let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
            vec![serde_json::Value::from(String::from_utf16_lossy(
                &units[..end],
            ))]
        }
    };
    Ok(BytesView {
        addr: va,
        file_off: file_off_of_in(bin, va),
        section: section_of_in(bin, va).map(str::to_string),
        bytes,
        values,
    })
}

/// Raw byte range with a stored struct layout rendered over it.
///
/// Reads `[va, va+len)` exactly like [`Project::bytes_view`] (same 1 MiB
/// cap, zero-padded BSS tails, unmapped ranges are [`Error::NotFound`])
/// with the same `values` typed decoding in `endian` order, then renders
/// the [`TypeHint`](crate::annotations::TypeHint) stored at `hint_addr`
/// as `fields`: one row per struct field with its own `addr`/`addr_hex`
/// twins, `bytes_hex`, and integer `value` in `endian` order (null for
/// fields wider than 8 bytes). The result also echoes the wire hint in
/// `hint` and where it was read from in `hint_addr`/`hint_addr_hex`. The
/// hint address keeps the any-address comment contract: a missing hint is
/// [`Error::Invalid`], never silent.
fn bytes_view_as_type_of(
    bin: &LoadedBinary,
    annotations: &BTreeMap<u64, Annotation>,
    va: u64,
    len: usize,
    as_: BytesAs,
    endian: BytesEndian,
    hint_addr: u64,
) -> Result<serde_json::Value> {
    let hint = match annotations
        .get(&hint_addr)
        .and_then(|a| a.comment.as_deref())
    {
        None => {
            return Err(Error::Invalid(format!("no type hint at {hint_addr:#x}")));
        }
        Some(text) => crate::annotations::parse_type_hint(text)?
            .ok_or_else(|| Error::Invalid(format!("no type hint at {hint_addr:#x}")))?,
    };
    let size = usize::try_from(hint.size).unwrap_or(usize::MAX);
    if len < size {
        return Err(Error::Invalid(format!(
            "range length {len} smaller than struct {} size {}",
            hint.name, hint.size
        )));
    }
    let view = bytes_view_of(bin, va, len, as_, endian)?;
    let le = endian == BytesEndian::Le;
    let fields: Vec<serde_json::Value> = hint
        .fields
        .iter()
        .map(|f| {
            let off = f.offset as usize;
            let end = off + f.size as usize;
            let bytes = &view.bytes[off..end];
            let mut bytes_hex = String::with_capacity(bytes.len() * 2);
            for b in bytes {
                bytes_hex.push(char::from_digit(u32::from(*b >> 4), 16).expect("hex digit"));
                bytes_hex.push(char::from_digit(u32::from(*b & 0x0f), 16).expect("hex digit"));
            }
            let (addr, addr_hex) = addr_pair(va + f.offset);
            let value = if bytes.len() <= 8 {
                serde_json::Value::from(decode_int(bytes, le))
            } else {
                serde_json::Value::Null
            };
            serde_json::json!({
                "name": f.name,
                "offset": f.offset,
                "size": f.size,
                "addr": addr,
                "addr_hex": addr_hex,
                "bytes_hex": bytes_hex,
                "value": value,
            })
        })
        .collect();
    let mut value = serde_json::to_value(&view).expect("bytes view serializes");
    let (hint_addr_json, hint_addr_hex) = addr_pair(hint_addr);
    value["hint"] = crate::annotations::type_hint_json(&hint);
    value["hint_addr"] = serde_json::Value::from(hint_addr_json);
    value["hint_addr_hex"] = serde_json::Value::from(hint_addr_hex);
    value["fields"] = serde_json::Value::Array(fields);
    Ok(value)
}

/// Opened analysis project: binary plus its cached analysis and annotations.
///
/// The binary file is only ever read; all persistence (analysis snapshot,
/// renames, comments, function seeds) goes to the `redb` sidecar at
/// [`Project::db_path`], written solely by [`Project::save`] and the
/// annotation/seed setters.
#[derive(Debug)]
pub struct Project {
    path: PathBuf,
    db_path: PathBuf,
    content_hash: u64,
    content_sha256: OnceLock<String>,
    size: u64,
    binary: LoadedBinary,
    analysis: Analysis,
    /// Seed identity the in-memory analysis was taken over (see
    /// [`db::seeds_hash`]): the fallback writers re-analyze when merged
    /// seeds diverge from this instead of saving stale layouts.
    analysis_seeds_hash: u64,
    annotations: BTreeMap<u64, Annotation>,
    func_seeds: BTreeMap<u64, crate::db::FuncSeed>,
    mapping: db::StoredMapping,
    stale_annotations_dropped: usize,
    stale_warning: Option<String>,
    /// Whether the sidecar already holds this exact snapshot: set when the
    /// open replayed a cache hit, or after a full rewrite (see
    /// [`Project::snapshot_fresh`]). Atomic so [`Project::save`] can mark
    /// the snapshot fresh through `&self` while `Project` stays `Send + Sync`.
    snapshot_fresh: AtomicBool,
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
    /// sidecar when present: a matching content hash plus SHA-256 and size,
    /// loader mapping, and
    /// analysis revision loads the cached snapshot, a mismatch re-analyzes
    /// while keeping stored annotations only when
    /// [`db::stale_carry_plausible`] holds
    /// (same path or same arch/format/entry). An unrelated sidecar's rows
    /// are dropped and reported via [`Project::stale_warning`]. A populated
    /// sidecar
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
    /// [`Error::Storage`] on DB failure, [`Error::Io`] on I/O failure.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_db(path, &db::default_db_path(path))
    }

    /// [`Project::open`] with an explicit DB path (keeps fixture dirs clean).
    ///
    /// # Errors
    /// Same as [`Project::open`].
    pub fn open_with_db(binary: &Path, db_path: &Path) -> Result<Self> {
        Self::open_inner(binary, db_path, None, None)
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
        Self::open_inner(binary, db_path, Some(opts), None)
    }

    /// Open the selected slice of a fat (universal) Mach-O binary plus
    /// explicit DB path.
    ///
    /// `fat_arch` is the caller-supplied slice selector, passed through
    /// unchanged to [`crate::loader::load_with_slice`] (canonical names
    /// `x86_64`/`x86_32`/`aarch64`/`arm32` case-insensitively, plus the
    /// `lipo` aliases); supplying it for thin input errors. The selection is
    /// part of the cache identity: each slice keeps its own snapshot, and
    /// populated annotation sidecars under another mapping require a
    /// separate DB path.
    ///
    /// # Errors
    /// Same as [`Project::open`], plus [`Error::Invalid`] when fat input
    /// has no usable selection (missing, unknown, or ambiguous).
    pub fn open_fat(binary: &Path, db_path: &Path, fat_arch: &str) -> Result<Self> {
        Self::open_inner(binary, db_path, None, Some(fat_arch))
    }

    /// Open for loader-only commands, skipping instruction re-decode on a
    /// cache hit.
    ///
    /// Shares the [`Project::open_with_db`] cache identity (content hash
    /// plus SHA-256 and size, loader mapping, analysis revision) over an
    /// explicit DB path. A matching snapshot returns
    /// [`LoaderOpened::Cached`]: the binary plus stored counts, strings,
    /// annotations, and seeds, with outcome counts derived from the stored
    /// layouts instead of a rebuilt analysis. A stale or missing snapshot
    /// returns [`LoaderOpened::Fresh`]: a fully analyzed project identical
    /// to [`Project::open_with_db`]. Reads never save or create the sidecar;
    /// only [`Project::save`] and the annotation/seed setters write, and
    /// only the sidecar.
    ///
    /// # Errors
    /// Same as [`Project::open_with_db`].
    pub fn open_loader_only(
        binary: &Path,
        db_path: &Path,
        raw: Option<RawOptions>,
        fat_arch: Option<&str>,
    ) -> Result<LoaderOpened> {
        let inputs = read_open_inputs(binary, db_path, raw, fat_arch)?;
        let OpenInputs {
            bytes,
            hash,
            sha256,
            size,
            mapping,
            cached,
        } = inputs;
        match cached {
            Some(db::Snapshot::Hit(hit)) => {
                // A hit always confirms SHA-256 up front; recompute
                // defensively if it ever arrives empty rather than caching a
                // wrong identity.
                let sha256 = if sha256.is_empty() {
                    crate::annotations::sha256_hex(&bytes)
                } else {
                    sha256
                };
                let loaded = reload_binary(bytes, raw, fat_arch)?;
                let db::Loaded {
                    functions,
                    xrefs,
                    strings,
                    diagnostics,
                    annotations,
                    seeds,
                    meta,
                    ..
                } = *hit;
                let summary = summary_of_hit(&functions, &xrefs, &strings);
                Ok(LoaderOpened::Cached(Box::new(LoaderProject {
                    path: binary.to_path_buf(),
                    db_path: db_path.to_path_buf(),
                    content_hash: hash,
                    content_sha256: sha256,
                    size,
                    binary: loaded,
                    summary,
                    diagnostics: diagnostics.len(),
                    diagnostics_truncated: meta.diagnostics_truncated,
                    diagnostics_omitted: meta.diagnostics_omitted,
                    inferred_truncated: meta.inferred_truncated,
                    inferred_omitted: meta.inferred_omitted,
                    strings,
                    annotations,
                    func_seeds: seeds,
                    mapping,
                })))
            }
            Some(db::Snapshot::Stale {
                meta: stale_meta,
                annotations,
                seeds,
            }) => Ok(LoaderOpened::Fresh(Box::new(Self::reanalyze(
                binary,
                db_path,
                bytes,
                raw,
                fat_arch,
                hash,
                sha256,
                size,
                Some(stale_meta),
                annotations,
                seeds,
            )?))),
            Some(db::Snapshot::Miss) | None => Ok(LoaderOpened::Fresh(Box::new(Self::reanalyze(
                binary,
                db_path,
                bytes,
                raw,
                fat_arch,
                hash,
                sha256,
                size,
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            )?))),
        }
    }

    fn open_inner(
        binary: &Path,
        db_path: &Path,
        raw: Option<RawOptions>,
        fat_arch: Option<&str>,
    ) -> Result<Self> {
        let inputs = read_open_inputs(binary, db_path, raw, fat_arch)?;
        let bytes = inputs.bytes;
        let hash = inputs.hash;
        let sha256 = inputs.sha256;
        let size = inputs.size;
        let mapping = inputs.mapping;
        let cached = inputs.cached;

        match cached {
            Some(db::Snapshot::Hit(hit)) => {
                let loaded = reload_binary(bytes, raw, fat_arch)?;
                let db::Loaded {
                    arch,
                    functions,
                    call_edges,
                    xrefs,
                    strings,
                    diagnostics,
                    annotations,
                    seeds,
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
                    content_sha256: cache_sha256(sha256),
                    size,
                    binary: loaded,
                    analysis,
                    analysis_seeds_hash: meta.seeds_hash,
                    annotations,
                    func_seeds: seeds,
                    mapping,
                    stale_annotations_dropped: 0,
                    stale_warning: None,
                    snapshot_fresh: AtomicBool::new(true),
                })
            }
            Some(db::Snapshot::Stale {
                meta: stale_meta,
                annotations,
                seeds,
            }) => Self::reanalyze(
                binary,
                db_path,
                bytes,
                raw,
                fat_arch,
                hash,
                sha256,
                size,
                Some(stale_meta),
                annotations,
                seeds,
            ),
            Some(db::Snapshot::Miss) | None => Self::reanalyze(
                binary,
                db_path,
                bytes,
                raw,
                fat_arch,
                hash,
                sha256,
                size,
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            ),
        }
    }

    /// Re-analyze `bytes` from scratch, carrying user rows forward when plausible.
    ///
    /// Stale sidecars keep user renames, comments, and seeds by address only
    /// when [`db::stale_carry_plausible`] holds (same path or same
    /// arch/format/entry); otherwise the rows belong to an unrelated binary
    /// and are dropped with a stale warning. The derived analysis always
    /// comes from the current bytes, never from storage. A mapping mismatch
    /// over populated user rows never reaches this path:
    /// [`db::load_cached`] errors first.
    #[allow(
        clippy::too_many_arguments,
        reason = "open plumbing: paths plus raw/fat mapping, content, and user rows"
    )]
    fn reanalyze(
        binary: &Path,
        db_path: &Path,
        bytes: Vec<u8>,
        raw: Option<RawOptions>,
        fat_arch: Option<&str>,
        hash: u64,
        sha256: String,
        size: u64,
        stale_meta: Option<db::BinaryMeta>,
        annotations: BTreeMap<u64, Annotation>,
        seeds: BTreeMap<u64, crate::db::FuncSeed>,
    ) -> Result<Self> {
        let mapping = mapping_for(raw, fat_arch)?;
        let loaded = if let Some(opts) = raw {
            // Move the read buffer into the raw segment: no second copy.
            load_raw_vec(bytes, opts)?
        } else {
            let loaded = load_or_raw(&bytes, fat_arch)?;
            // The loader owns its bytes from here on (segments hold the
            // file-backed ranges, sections are metadata over them); drop
            // the read buffer so containers hold the input once.
            drop(bytes);
            loaded
        };
        let user = active_user_seeds(&seeds);
        let analysis = analyze_with_seeds(&loaded, &user)?;
        let current_path = binary.display().to_string();
        let current_arch = db::arch_name(loaded.arch).to_string();
        let current_format = db::format_name(loaded.format).to_string();
        let current_entry = loaded.entry;
        let (annotations, seeds, stale_annotations_dropped, stale_warning) = match stale_meta {
            Some(stored)
                if !db::stale_carry_plausible(
                    &stored,
                    &current_path,
                    &current_arch,
                    &current_format,
                    current_entry,
                ) =>
            {
                let n = annotations.len() + seeds.len();
                let warning = if n > 0 {
                    Some(format!(
                        "dropped {n} stale annotation(s): sidecar was written for unrelated binary (path/arch/format/entry mismatch); not carried"
                    ))
                } else {
                    None
                };
                (BTreeMap::new(), BTreeMap::new(), n, warning)
            }
            _ => (annotations, seeds, 0, None),
        };
        Ok(Self {
            path: binary.to_path_buf(),
            db_path: db_path.to_path_buf(),
            content_hash: hash,
            content_sha256: cache_sha256(sha256),
            size,
            binary: loaded,
            analysis,
            analysis_seeds_hash: db::seeds_hash(&seeds),
            annotations,
            func_seeds: seeds,
            mapping,
            stale_annotations_dropped,
            stale_warning,
            snapshot_fresh: AtomicBool::new(false),
        })
    }

    /// Persist the analysis snapshot, annotations, and function seeds to the
    /// sidecar DB, then reclaim the free pages the full rewrite leaves behind.
    ///
    /// Only ever writes [`Project::db_path`]; the binary is untouched.
    /// Rewriting every table and re-inserting identical rows still strands
    /// free pages, so the compaction runs on every full rewrite; repeat
    /// `load`s skip [`Project::save`] entirely while
    /// [`Project::snapshot_fresh`] holds.
    ///
    /// # Errors
    /// [`Error::Storage`] on any `redb`, encoding, or compaction failure.
    pub fn save(&self) -> Result<()> {
        let mut db = db::open_db(&self.db_path)?;
        self.persist_full(&mut db, &self.annotations, &self.func_seeds)
    }

    /// Rewrite the full snapshot through an open handle, compact, and mark
    /// the snapshot fresh.
    ///
    /// Shared by [`Project::save`] and the seed/annotation-write fallbacks
    /// that must rewrite every table when the sidecar holds no matching
    /// snapshot. `db` stays open across the call so the single-handle rule
    /// holds, and the flag records that the sidecar now matches memory.
    fn persist_full(
        &self,
        db: &mut redb::Database,
        annotations: &BTreeMap<u64, Annotation>,
        seeds: &BTreeMap<u64, crate::db::FuncSeed>,
    ) -> Result<()> {
        db::save(db, &self.meta()?, &self.analysis, annotations, seeds)?;
        db.compact()
            .map_err(|e| Error::Storage(format!("compact {}: {e}", self.db_path.display())))?;
        self.snapshot_fresh.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Snapshot identity for `seeds` under the current analysis counts.
    ///
    /// # Errors
    /// Same as [`Project::ensure_sha256`].
    fn meta_for(
        &self,
        analysis: &Analysis,
        seeds: &BTreeMap<u64, crate::db::FuncSeed>,
    ) -> Result<BinaryMeta> {
        Ok(BinaryMeta {
            version: db::SCHEMA_VERSION,
            binary_path: self.path.display().to_string(),
            content_hash: self.content_hash,
            content_sha256: self.ensure_sha256()?.to_owned(),
            size: self.size,
            arch: db::arch_name(self.binary.arch).to_string(),
            format: db::format_name(self.binary.format).to_string(),
            entry: self.binary.entry,
            supported: true,
            reason: None,
            mapping: Some(self.mapping.clone()),
            analysis_rev: Some(db::ANALYSIS_REVISION),
            seeds_hash: db::seeds_hash(seeds),
            diagnostics_truncated: analysis.diagnostics.truncated,
            diagnostics_omitted: analysis.diagnostics.omitted,
            inferred_truncated: analysis.diagnostics.inferred_truncated,
            inferred_omitted: analysis.diagnostics.inferred_omitted,
        })
    }

    /// Snapshot identity for the in-memory analysis and seeds.
    ///
    /// # Errors
    /// Same as [`Project::ensure_sha256`].
    fn meta(&self) -> Result<BinaryMeta> {
        self.meta_for(&self.analysis, &self.func_seeds)
    }

    /// Loader mapping this project was opened with (auto vs explicit raw).
    ///
    /// Part of the cache identity: snapshots replay layouts only when the
    /// stored mapping agrees with this value.
    #[must_use]
    pub fn mapping(&self) -> &db::StoredMapping {
        &self.mapping
    }

    /// Whether the sidecar already holds this exact snapshot.
    ///
    /// True when the open replayed a cache hit — [`db::load_cached`]
    /// matched content hash plus SHA-256 and size, loader mapping, and
    /// analysis revision before any layout replay, so the persisted rows
    /// equal the in-memory state — or after [`Project::save`] rewrote and
    /// compacted it. `load` skips its `save` while this holds, so repeat
    /// loads on an unchanged binary neither rewrite tables nor grow free
    /// pages. Single-row annotation writes keep the sidecar in sync without
    /// clearing this; full-rewrite fallbacks re-mark it on commit.
    #[must_use]
    pub fn snapshot_fresh(&self) -> bool {
        self.snapshot_fresh.load(Ordering::Relaxed)
    }

    /// Persist one changed annotation row, falling back to a full snapshot.
    ///
    /// Tries [`db::save_annotation`](crate::db::save_annotation) first: when
    /// the sidecar holds a snapshot for this binary and mapping, only the
    /// `annotations` row changes. Otherwise (fresh DB or same-mapping
    /// content mismatch) rewrites the full snapshot, re-analyzing first
    /// when the seeds diverged. The fallback merges
    /// the single changed row onto the sidecar's current user rows when
    /// the stored lineage is plausible (see [`db::stale_carry_plausible`),
    /// so rows another process wrote in between are kept; an unrelated
    /// sidecar is replaced with the in-memory state instead. A populated
    /// sidecar under an incompatible mapping errors instead of
    /// overwriting.
    fn persist_annotation(&mut self, addr: u64) -> Result<()> {
        let ann = self.annotations.get(&addr).filter(|a| !a.is_empty());
        let fast = {
            let db = db::open_db(&self.db_path)?;
            db::save_annotation(&db, &self.meta()?, addr, ann)?
        };
        match fast {
            db::AnnotationSave::Fast => Ok(()),
            db::AnnotationSave::NeedsFull => {
                let changes = BTreeMap::from([(addr, ann.cloned())]);
                self.persist_merged(changes, BTreeMap::new())
            }
        }
    }

    /// Merge pending changes over the sidecar state, re-analyze when the
    /// seeds diverged, save, and adopt the merged seeds.
    ///
    /// Reads the sidecar's current user rows and, when the stored lineage
    /// is plausible for this project, applies `ann_changes` and
    /// `seed_changes` on top so concurrent rows survive. Otherwise (fresh
    /// DB or unrelated sidecar) falls back to the in-memory rows with the
    /// changes applied. When the merged seeds differ from the seeds the
    /// in-memory analysis was taken over
    /// ([`Project`](Self::analysis_seeds_hash)), the analysis is rebuilt
    /// from the current bytes before saving, so derived rows always match
    /// the stored seeds. Memory adopts the merged seeds (and the rebuilt
    /// analysis, if any); annotations keep the existing apply-changes
    /// semantics. A populated sidecar under an incompatible mapping errors
    /// from the save instead of overwriting.
    fn persist_merged(
        &mut self,
        ann_changes: BTreeMap<u64, Option<Annotation>>,
        seed_changes: BTreeMap<u64, Option<crate::db::FuncSeed>>,
    ) -> Result<()> {
        let mut db = db::open_db(&self.db_path)?;
        let (merged_ann, merged_seeds) =
            self.merged_fallback_state(&db, &ann_changes, &seed_changes)?;
        let merged_hash = db::seeds_hash(&merged_seeds);
        let analysis = if merged_hash != self.analysis_seeds_hash {
            let user = active_user_seeds(&merged_seeds);
            analyze_with_seeds(&self.binary, &user)?
        } else {
            self.analysis.clone()
        };
        db::save(
            &db,
            &self.meta_for(&analysis, &merged_seeds)?,
            &analysis,
            &merged_ann,
            &merged_seeds,
        )?;
        db.compact()
            .map_err(|e| Error::Storage(format!("compact {}: {e}", self.db_path.display())))?;
        crate::annotations::apply_changes(&mut self.annotations, &ann_changes);
        // Seeds adopt the merged map wholesale: the saved analysis was
        // taken over exactly these rows.
        self.func_seeds = merged_seeds;
        if merged_hash != self.analysis_seeds_hash {
            self.analysis = analysis;
            self.analysis_seeds_hash = merged_hash;
        }
        self.snapshot_fresh.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Merge fallback user rows for a full-snapshot rewrite.
    ///
    /// Reads the sidecar's current annotations and seeds and, when the
    /// stored lineage is plausible for this project, applies `ann_changes`
    /// (`None` deletes) and `seed_changes` on top so concurrent rows
    /// survive. Otherwise (fresh DB or unrelated sidecar) falls back to the
    /// in-memory rows with the changes applied. Annotation and seed write
    /// paths share this helper.
    fn merged_fallback_state(
        &self,
        db: &redb::Database,
        ann_changes: &BTreeMap<u64, Option<Annotation>>,
        seed_changes: &BTreeMap<u64, Option<crate::db::FuncSeed>>,
    ) -> Result<(
        BTreeMap<u64, Annotation>,
        BTreeMap<u64, crate::db::FuncSeed>,
    )> {
        let ours = self.meta()?;
        let base = match db::load_meta_and_annotations(db)? {
            Some((persisted_meta, annotations, seeds)) => {
                if persisted_meta.mapping != ours.mapping {
                    None
                } else {
                    let plausible = persisted_meta.fast_write_eq(&ours)
                        || db::stale_carry_plausible(
                            &persisted_meta,
                            &ours.binary_path,
                            &ours.arch,
                            &ours.format,
                            ours.entry,
                        );
                    plausible.then_some((annotations, seeds))
                }
            }
            None => None,
        };
        match base {
            Some((mut annotations, mut seeds)) => {
                crate::annotations::apply_changes(&mut annotations, ann_changes);
                crate::annotations::apply_seed_changes(&mut seeds, seed_changes);
                Ok((annotations, seeds))
            }
            None => {
                let mut annotations = self.annotations.clone();
                crate::annotations::apply_changes(&mut annotations, ann_changes);
                let mut seeds = self.func_seeds.clone();
                crate::annotations::apply_seed_changes(&mut seeds, seed_changes);
                Ok((annotations, seeds))
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
            db::StoredMapping::Fat { .. } => ("fat".to_string(), None),
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
    /// Includes the SHA-256 content identity plus the stale-annotation
    /// drop count and warning (see [`Project::stale_warning`]).
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
            db::StoredMapping::Fat { .. } => ("fat".to_string(), crate::opt_addr_pair(None)),
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
            "content_sha256": self.ensure_sha256()?,
            "size": self.size,
            "db_size": db_size,
            "functions": s.functions,
            "blocks": s.blocks,
            "insns": s.insns,
            "xrefs": s.xrefs,
            "strings": s.strings,
            "annotations": self.annotations.values().filter(|a| !a.is_empty()).count(),
            "annotations_dropped": self.stale_annotations_dropped,
            "stale_warning": self.stale_warning,
            "diagnostics": self.analysis.diagnostics.records.len(),
            "diagnostics_truncated": self.analysis.diagnostics.truncated,
            "diagnostics_omitted": self.analysis.diagnostics.omitted,
            "inferred_truncated": self.analysis.diagnostics.inferred_truncated,
            "inferred_omitted": self.analysis.diagnostics.inferred_omitted,
            "analysis_revision": crate::analysis::ANALYSIS_REVISION,
        }))
    }

    /// On-demand header metadata: triage staples plus file hashes.
    ///
    /// Re-reads the binary file and parses its container headers via
    /// [`crate::headers::headers_of`] (PE mitigations/Rich/imphash/PDB,
    /// ELF interpreter/needed/RELRO/NX/PIE, Mach-O load commands/codesign,
    /// plus `sha256` and `md5`). Computed on demand, never persisted:
    /// reads never save or create the sidecar, and unparseable inputs
    /// degrade to `null` fields rather than errors. See
    /// `docs/book/src/json-protocol.md` for the shape.
    ///
    /// # Errors
    /// [`Error::Storage`] when the binary cannot be re-read, [`Error::Limit`]
    /// past the input budget (see [`crate::loader::MAX_INPUT_BYTES`]).
    pub fn headers_json(&self) -> Result<serde_json::Value> {
        let bytes = read_input_bytes(&self.path)?;
        let sha256 = self.sha256_for(&bytes)?;
        Ok(crate::headers::headers_of(&bytes, &self.binary, sha256))
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
    /// Together with [`Project::size`] it gates the snapshot cache in
    /// [`db::load_cached`], so a hash collision cannot replay another
    /// binary's layouts.
    ///
    /// Empty when the open skipped the wide hash (no tentative snapshot
    /// match) and nothing has needed it yet; use
    /// [`Project::ensure_sha256`] for the computed digest.
    #[must_use]
    pub fn content_sha256(&self) -> &str {
        self.content_sha256.get().map_or("", String::as_str)
    }

    /// Hex SHA-256 of the binary bytes, computing it on first use.
    ///
    /// Opens with no tentative snapshot match skip the wide hash; the first
    /// save, export, import check, or stats call re-reads the input and
    /// hashes it, caching the digest. The re-read is guarded by the content
    /// hash plus size taken at open, so a file replaced since open errors
    /// instead of snapshotting one binary's analysis under another
    /// binary's identity.
    ///
    /// # Errors
    /// [`Error::Storage`] when the binary cannot be re-read or no longer
    /// matches the opened identity.
    pub fn ensure_sha256(&self) -> Result<&str> {
        let bytes = read_input_bytes(&self.path)?;
        self.sha256_for(&bytes)
    }

    /// [`Project::ensure_sha256`] over already-read `bytes`: guards them
    /// against the opened identity, then caches and returns the digest.
    ///
    /// Lets [`Project::headers_json`] hash the single re-read it already
    /// does instead of reading the file twice.
    ///
    /// # Errors
    /// Same as [`Project::ensure_sha256`], minus the re-read.
    fn sha256_for(&self, bytes: &[u8]) -> Result<&str> {
        if db::content_hash(bytes) != self.content_hash || bytes.len() as u64 != self.size {
            return Err(Error::Storage(format!(
                "binary changed since open: {}",
                self.path.display()
            )));
        }
        let digest = self
            .content_sha256
            .get_or_init(|| crate::annotations::sha256_hex(bytes));
        Ok(digest.as_str())
    }

    /// Stale annotations dropped for an unrelated sidecar on open.
    ///
    /// Counts rows discarded because [`db::stale_carry_plausible`] failed
    /// (different path and different arch/format/entry): reusing one `--db`
    /// path for an unrelated binary no longer imports its renames. Zero on
    /// cache hits and on plausible stale opens.
    #[must_use]
    pub fn stale_annotations_dropped(&self) -> usize {
        self.stale_annotations_dropped
    }

    /// Why stale annotations were dropped, if any.
    ///
    /// `Some` exactly when [`Project::stale_annotations_dropped`] is
    /// non-zero: names the unrelated sidecar lineage that was ignored.
    /// Agents surfacing `stats` should include this alongside the drop
    /// count instead of silently carrying foreign renames.
    #[must_use]
    pub fn stale_warning(&self) -> Option<&str> {
        self.stale_warning.as_deref()
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

    /// Display name of a function: annotation rename wins over the
    /// analysis name (export > symbol-table > stub import, with ELF PLT
    /// stubs as `sym@plt` and PE import thunks under the bare name).
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

    /// Build the render-time listing context for one read.
    ///
    /// Pure derived view; building it never writes the binary or the
    /// sidecar.
    fn enrich_ctx(&self) -> EnrichCtx<'_> {
        let mut symbols: BTreeMap<u64, &str> = BTreeMap::new();
        for s in &self.binary.symbols {
            symbols.entry(s.address).or_insert(s.name.as_str());
        }
        let mut imports: BTreeMap<u64, &str> = BTreeMap::new();
        for imp in &self.binary.imports {
            if let Some(slot) = imp.address {
                imports.entry(slot).or_insert(imp.name.as_str());
            }
        }
        let mut spans: Vec<(u64, u64, &str)> = Vec::new();
        for h in &self.analysis.strings {
            let Some(start) = h.vaddr else {
                continue;
            };
            // Same classic-only rule as xref recovery (see `analyze`):
            // multibyte hits are listing coverage, never span participants.
            let len = match h.encoding {
                Encoding::Ascii => h.value.len() as u64,
                Encoding::Utf16Le | Encoding::Utf16Be => h.value.len() as u64 * 2,
                Encoding::Utf8 | Encoding::Utf16LeBmp | Encoding::Base64 => continue,
            };
            spans.push((start, start.wrapping_add(len), h.value.as_str()));
        }
        spans.sort();
        EnrichCtx {
            symbols,
            imports,
            slots: import_slots(&self.binary),
            spans,
        }
    }

    /// Display name of a branch or data target: rename-resolved function
    /// name wins, then the symbol table, then the import name. Code
    /// targets (and known function entries) degrade to `func@0x...`;
    /// unresolvable data targets report `None` rather than inventing a
    /// name. Pure read-only lookup for listings.
    fn target_name_in(&self, ctx: &EnrichCtx, target: u64, is_code: bool) -> Option<String> {
        if let Some(name) = self.function_name(target) {
            return Some(name);
        }
        if let Some(name) = ctx.symbols.get(&target) {
            return Some((*name).to_string());
        }
        if let Some(name) = ctx.imports.get(&target) {
            return Some((*name).to_string());
        }
        if is_code || self.analysis.functions.contains_key(&target) {
            return Some(format!("func@{target:#x}"));
        }
        None
    }

    /// Preview of the recovered string containing `addr`, if any.
    ///
    /// Matches the analysis string-xref rule: the address may point
    /// anywhere inside the span, not just at its start. Pure read-only
    /// lookup for listings.
    fn string_preview_in(&self, ctx: &EnrichCtx, addr: u64) -> Option<String> {
        let idx = ctx.spans.partition_point(|(start, _, _)| *start <= addr);
        ctx.spans[..idx]
            .iter()
            .rev()
            .find(|(start, end, _)| addr >= *start && addr < *end)
            .map(|(_, _, value)| crate::disasm::string_preview(value))
    }

    /// Fill a listing row's additive annotation fields in place.
    ///
    /// `prev` is the address-ordered predecessor for `adrp` pair
    /// resolution (`None` at a page start degrades to the row's own
    /// `mem_target`). Only absent fields are filled, so stored rows keep
    /// their decoded values and repeated reads agree. Never persists.
    fn enrich_insn(&self, ctx: &EnrichCtx, insn: &mut Insn, prev: Option<&Insn>) {
        if insn.import.is_none()
            && let Some(i) = import_index(
                &ctx.slots,
                &self.analysis.import_stubs,
                insn.branch_target,
                insn.mem_target,
            )
            && let Some(imp) = self.binary.imports.get(i)
        {
            insn.import = Some(imp.name.clone());
        }
        let resolved_mem = prev
            .and_then(|p| resolve_adrp_pair(p, insn))
            .or(insn.mem_target);
        if insn.target_name.is_none() {
            if let Some(t) = insn.branch_target {
                insn.target_name = self.target_name_in(ctx, t, true);
            } else if let Some(m) = resolved_mem {
                insn.target_name = self.target_name_in(ctx, m, false);
            }
        }
        if insn.comment.is_none() {
            insn.comment = self.annotation(insn.addr).and_then(|a| a.comment.clone());
        }
        if insn.string.is_none()
            && let Some(m) = resolved_mem
        {
            insn.string = self.string_preview_in(ctx, m);
        }
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

    /// Atomically rename and/or comment the annotation at `addr`.
    ///
    /// Validates both inputs before touching memory or disk, then persists
    /// the merged row in one transaction (single-row fast path or full
    /// snapshot rewrite, like [`Project::import_annotations`]). A failing
    /// comment never leaves a rename behind and vice versa. `None` leaves
    /// the field untouched; an empty string clears it. Both `None` is a
    /// no-op that never touches the sidecar, so `annotate` without flags
    /// stays read-only.
    ///
    /// Rename targets must be known function entries; comments accept any
    /// address. The binary is never modified.
    ///
    /// # Errors
    /// [`Error::NotFound`] for unknown rename targets, [`Error::Limit`]
    /// when either field exceeds 8 KiB, [`Error::Storage`] when the
    /// annotation cannot be persisted.
    pub fn annotate(
        &mut self,
        addr: u64,
        rename: Option<&str>,
        comment: Option<&str>,
    ) -> Result<()> {
        if rename.is_some() && !self.analysis.functions.contains_key(&addr) {
            return Err(Error::NotFound(format!("function {addr:#x}")));
        }
        if let Some(name) = rename
            && name.len() > crate::db::MAX_ANNOTATION_BYTES
        {
            return Err(Error::Limit(format!(
                "rename of {} bytes exceeds {}",
                name.len(),
                crate::db::MAX_ANNOTATION_BYTES
            )));
        }
        if let Some(text) = comment
            && text.len() > crate::db::MAX_ANNOTATION_BYTES
        {
            return Err(Error::Limit(format!(
                "comment of {} bytes exceeds {}",
                text.len(),
                crate::db::MAX_ANNOTATION_BYTES
            )));
        }
        if rename.is_none() && comment.is_none() {
            return Ok(());
        }
        let current = self.annotations.get(&addr).cloned();
        let mut merged = current.clone().unwrap_or_default();
        if let Some(name) = rename {
            merged.name = (!name.is_empty()).then(|| name.to_string());
        }
        if let Some(text) = comment {
            merged.comment = (!text.is_empty()).then(|| text.to_string());
        }
        let next = (!merged.is_empty()).then_some(merged);
        if next == current {
            return Ok(());
        }
        let mut changes = BTreeMap::new();
        changes.insert(addr, next);
        let fast = {
            let db = db::open_db(&self.db_path)?;
            db::save_annotation_batch(&db, &self.meta()?, &changes)?
        };
        match fast {
            db::AnnotationSave::Fast => {
                crate::annotations::apply_changes(&mut self.annotations, &changes);
            }
            db::AnnotationSave::NeedsFull => {
                self.persist_merged(changes, BTreeMap::new())?;
            }
        }
        Ok(())
    }

    /// Define a user function seed at `addr`.
    ///
    /// Records the agent assertion "there is code at `addr`" (shellcode,
    /// firmware vectors, obfuscated code, missed callbacks) and
    /// re-analyzes immediately so the function materializes when the bytes
    /// decode. Any address is accepted, like [`Project::set_comment`];
    /// undecodable seeds are inert (no function, no error). Defining an
    /// excluded address re-activates it. Persists immediately via a full
    /// snapshot rewrite carrying the new seeds hash.
    ///
    /// `mode` selects the 32-bit ARM decode (`Arm`/`Thumb`) and is
    /// rejected on other architectures; `None` decodes with the project
    /// arch. The binary is never modified.
    ///
    /// # Errors
    /// [`Error::Invalid`] when `mode` is set on a non-32-bit-ARM project,
    /// [`Error::Limit`] past the seed row budget or analysis budgets,
    /// [`Error::Storage`] when the snapshot cannot be persisted.
    pub fn define_func(
        &mut self,
        addr: u64,
        mode: Option<crate::analysis::SeedMode>,
    ) -> Result<()> {
        self.check_seed_mode(mode)?;
        let mut seeds = self.func_seeds.clone();
        if !seeds.contains_key(&addr) && seeds.len() >= crate::db::MAX_SNAPSHOT_SEEDS {
            return Err(Error::Limit("func seeds exceed cap".to_string()));
        }
        seeds.insert(
            addr,
            crate::db::FuncSeed {
                mode,
                excluded: false,
            },
        );
        let mut changes = BTreeMap::new();
        changes.insert(addr, seeds.get(&addr).copied());
        self.persist_merged(BTreeMap::new(), changes)
    }

    /// Undefine the function seed at `addr`.
    ///
    /// Records the agent assertion "this isn't a function": the address is
    /// excluded from seeding and re-analysis drops the function unless
    /// another seed path still reaches it. The row is kept as data (not
    /// deleted), so the verdict survives reloads and transfers. Any
    /// address is accepted, even one never defined. Persists immediately
    /// via a full snapshot rewrite. The binary is never modified.
    ///
    /// # Errors
    /// [`Error::Limit`] past analysis budgets, [`Error::Storage`] when the
    /// snapshot cannot be persisted.
    pub fn undefine_func(&mut self, addr: u64) -> Result<()> {
        let mode = self.func_seeds.get(&addr).and_then(|s| s.mode);
        let mut changes = BTreeMap::new();
        changes.insert(
            addr,
            Some(crate::db::FuncSeed {
                mode,
                excluded: true,
            }),
        );
        self.persist_merged(BTreeMap::new(), changes)
    }

    /// Reject a seed decode mode outside 32-bit ARM projects.
    fn check_seed_mode(&self, mode: Option<crate::analysis::SeedMode>) -> Result<()> {
        if mode.is_some()
            && !matches!(
                self.binary.arch,
                crate::disasm::Arch::Arm32 | crate::disasm::Arch::Thumb
            )
        {
            return Err(Error::Invalid(format!(
                "func seed mode needs a 32-bit ARM project (arch {})",
                crate::db::arch_name(self.binary.arch),
            )));
        }
        Ok(())
    }

    /// All user-defined function seeds keyed by address.
    #[must_use]
    pub fn func_seeds(&self) -> &BTreeMap<u64, crate::db::FuncSeed> {
        &self.func_seeds
    }

    /// Seed row at `addr` as JSON (`mode`/`excluded`, with `addr` twins).
    ///
    /// Absent rows report `mode: null, excluded: false`, mirroring
    /// [`Project::annotation_json`].
    #[must_use]
    pub fn seed_json(&self, addr: u64) -> serde_json::Value {
        let (addr_json, addr_hex) = addr_pair(addr);
        match self.func_seeds.get(&addr) {
            Some(s) => serde_json::json!({
                "addr": addr_json,
                "addr_hex": addr_hex,
                "mode": s.mode.map(|m| m.as_str()),
                "excluded": s.excluded,
            }),
            None => serde_json::json!({
                "addr": addr_json,
                "addr_hex": addr_hex,
                "mode": null,
                "excluded": false,
            }),
        }
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

    /// Store a structured struct-layout/sizeof hint from its wire JSON.
    ///
    /// Parses `json` as the `{"kind":"struct",..}` object
    /// [`crate::annotations::format_type_hint`] emits (see
    /// [`crate::annotations::parse_type_hint_json`]) and stores it exactly
    /// like [`Project::set_type_hint`]: any address, the 8 KiB cap,
    /// immediate persistence, and the export/import round-trip. An empty
    /// (or whitespace-only) `json` clears the hint, mirroring the empty
    /// comment clear: when the comment at `addr` carries a hint (or a
    /// corrupt hint prefix) it is cleared, otherwise a plain free-text
    /// comment is left alone and clearing is a no-op.
    ///
    /// # Errors
    /// [`Error::Invalid`] on malformed JSON or hint shape violations,
    /// [`Error::Limit`] when the formatted hint exceeds 8 KiB,
    /// [`Error::Storage`] when the annotation cannot be persisted.
    pub fn set_type_hint_json(&mut self, addr: u64, json: &str) -> Result<()> {
        if json.trim().is_empty() {
            let carries = self
                .annotation(addr)
                .and_then(|a| a.comment.as_deref())
                .is_some_and(|c| c.starts_with(crate::annotations::TYPE_HINT_PREFIX));
            if carries {
                self.set_comment(addr, "")?;
            }
            return Ok(());
        }
        let hint = crate::annotations::parse_type_hint_json(json)?;
        self.set_type_hint(addr, &hint)
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

    /// Export renames, comments, and function seeds as a portable JSON
    /// interchange document.
    ///
    /// The document carries the format revision, the binary's SHA-256 plus
    /// size, the effective loader mapping, the sorted non-empty annotation
    /// rows, and the sorted seed rows (excluded rows included);
    /// host paths and analysis snapshots are excluded. Strictly read-only:
    /// no sidecar is created or modified. Fails explicitly past the
    /// interchange size cap instead of emitting an unimportable document.
    ///
    /// # Errors
    /// [`Error::Limit`] past annotation, seed, or document budgets,
    /// [`Error::Storage`] on encoding failure.
    pub fn export_annotations(&self) -> Result<String> {
        crate::annotations::build_document(
            self.ensure_sha256()?,
            self.size,
            &self.mapping,
            &self.annotations,
            &self.func_seeds,
        )
    }

    /// Import a document from [`Project::export_annotations`] atomically.
    ///
    /// The whole document is validated before a single transaction:
    /// identity, mapping, duplicates, budgets, rename targets, seed modes,
    /// and merge conflicts. On success the changes persist in one
    /// transaction (an annotation-only batch write, or a full snapshot
    /// rewrite when no matching snapshot exists or the seeds changed, with
    /// a re-analysis first so derived rows match the stored seeds) and
    /// memory updates only after the commit; on any failure the DB and the
    /// in-memory rows are unchanged.
    /// Default (`overwrite == false`) fails on differing existing field
    /// values while equal values and fills of absent fields succeed;
    /// `overwrite == true` replaces supplied fields only (absent fields
    /// untouched, empty strings clear). Rows outside the document remain.
    /// Rename targets must be known function entries; comments keep the
    /// any-address contract, as do seed rows (with seed modes restricted
    /// to 32-bit ARM projects).
    ///
    /// # Errors
    /// [`Error::Invalid`] on malformed documents, duplicates, bad seed
    /// modes, and default-mode conflicts; [`Error::Storage`] on
    /// identity/mapping mismatches; [`Error::NotFound`] on unknown rename
    /// targets; [`Error::Limit`] past input/field/row budgets.
    pub fn import_annotations(
        &mut self,
        document: &str,
        overwrite: bool,
    ) -> Result<crate::annotations::ImportSummary> {
        let doc = crate::annotations::parse_document(document)?;
        let is_function = |addr: u64| self.analysis.functions.contains_key(&addr);
        let changes = crate::annotations::validate_document(
            &doc,
            self.ensure_sha256()?,
            self.size,
            &self.mapping,
            &is_function,
            &self.annotations,
            overwrite,
        )?;
        let seed_changes = crate::annotations::validate_seed_rows(
            &doc.func_seeds,
            self.binary.arch,
            &self.func_seeds,
            overwrite,
        )?;
        let summary = crate::annotations::ImportSummary {
            rows: doc.annotations.len() + doc.func_seeds.len(),
            changed: changes.len() + seed_changes.len(),
        };
        if changes.is_empty() && seed_changes.is_empty() {
            return Ok(summary);
        }
        if seed_changes.is_empty() {
            let fast = {
                let db = db::open_db(&self.db_path)?;
                db::save_annotation_batch(&db, &self.meta()?, &changes)?
            };
            match fast {
                db::AnnotationSave::Fast => {
                    crate::annotations::apply_changes(&mut self.annotations, &changes);
                }
                db::AnnotationSave::NeedsFull => {
                    self.persist_merged(changes, BTreeMap::new())?;
                }
            }
        } else {
            self.persist_merged(changes, seed_changes)?;
        }
        Ok(summary)
    }

    /// Build a portable annotation document over this project's identity.
    ///
    /// The crate-internal seam behind [`crate::diff::transfer_renames`]:
    /// the caller supplies rename rows addressed in this project and this
    /// wraps them in an [`crate::annotations::AnnotationDocument`] carrying
    /// this binary's SHA-256 plus size and loader mapping, so the result
    /// imports through [`Project::import_annotations`] unchanged. Read-only:
    /// no sidecar is created or modified.
    ///
    /// # Errors
    /// [`Error::Invalid`] on duplicate or field-less rows,
    /// [`Error::NotFound`] when a rename targets an unknown function entry,
    /// [`Error::Limit`] past field, row, or document budgets,
    /// [`Error::Storage`] when the binary cannot be re-read for its digest.
    pub(crate) fn transfer_document(
        &self,
        rows: Vec<crate::annotations::AnnotationRow>,
    ) -> Result<crate::annotations::AnnotationDocument> {
        use crate::annotations::{ANNOTATION_FORMAT_REVISION, MAX_TRANSFER_BYTES};
        let mut sorted = rows;
        sorted.sort_by_key(|r| r.addr);
        let mut seen = std::collections::BTreeSet::new();
        for row in &sorted {
            if !seen.insert(row.addr) {
                return Err(Error::Invalid(format!(
                    "duplicate transfer address {:#x}",
                    row.addr
                )));
            }
            if row.rename.as_deref().is_none_or(|s| s.is_empty()) && row.comment.is_none() {
                return Err(Error::Invalid(format!(
                    "transfer row at {:#x} has neither rename nor comment",
                    row.addr
                )));
            }
            for (label, s) in [("rename", &row.rename), ("comment", &row.comment)] {
                if let Some(t) = s
                    && t.len() > crate::db::MAX_ANNOTATION_BYTES
                {
                    return Err(Error::Limit(format!(
                        "transfer {label} of {} bytes exceeds {}",
                        t.len(),
                        crate::db::MAX_ANNOTATION_BYTES
                    )));
                }
            }
            if let Some(name) = &row.rename
                && !name.is_empty()
                && !self.analysis.functions.contains_key(&row.addr)
            {
                return Err(Error::NotFound(format!(
                    "rename target {:#x} is not a known function",
                    row.addr
                )));
            }
        }
        if sorted.len() > crate::db::MAX_SNAPSHOT_ANNOTATIONS {
            return Err(Error::Limit("transfer exceeds cap".to_string()));
        }
        let doc = crate::annotations::AnnotationDocument {
            revision: ANNOTATION_FORMAT_REVISION,
            sha256: self.ensure_sha256()?.to_string(),
            size: self.size,
            mapping: self.mapping.clone(),
            annotations: sorted,
            func_seeds: Vec::new(),
        };
        let text = serde_json::to_string(&doc)
            .map_err(|e| Error::Storage(format!("encode transfer document: {e}")))?;
        if text.len() > MAX_TRANSFER_BYTES {
            return Err(Error::Limit(format!(
                "transfer of {} bytes exceeds the {MAX_TRANSFER_BYTES}-byte cap",
                text.len()
            )));
        }
        Ok(doc)
    }

    /// File-backed bytes mapped at `va` (zero-padded past file data).
    ///
    /// # Errors
    /// [`Error::Limit`] for empty/oversize ranges, [`Error::NotFound`] when
    /// the range is not fully mapped.
    pub fn bytes_at(&self, va: u64, len: usize) -> Result<Vec<u8>> {
        bytes_at_in(&self.binary, va, len)
    }

    /// File offset of the byte at `va`, if file-backed.
    ///
    /// Sections win over the raw fallback: an address inside a section's
    /// file-backed prefix reports `section.file_off + (va - vaddr)`;
    /// otherwise raw mappings report the blob offset `va - base`. Zero
    /// fill/BSS tails and unmapped addresses report `None`, matching the
    /// `file_off` provenance of [`Project::search_bytes`].
    #[must_use]
    pub fn file_off_of(&self, va: u64) -> Option<u64> {
        file_off_of_in(&self.binary, va)
    }

    /// Virtual address backed by file offset `off`, if any.
    ///
    /// Reverse of [`Project::file_off_of`]: the first file-backed section
    /// (or raw blob prefix) covering `off` reports its VA. Gaps, BSS, and
    /// past-end offsets report `None`.
    #[must_use]
    pub fn va_of_file_off(&self, off: u64) -> Option<u64> {
        for sec in &self.binary.sections {
            if sec.file_size == 0 || off < sec.file_off {
                continue;
            }
            let d = off - sec.file_off;
            if d < sec.file_size {
                return sec.vaddr.checked_add(d);
            }
        }
        if self.binary.format == crate::loader::BinaryFormat::Raw {
            for seg in &self.binary.segments {
                if off < seg.data.len() as u64 {
                    return seg.vaddr.checked_add(off);
                }
            }
        }
        None
    }

    /// Name of the file-backed section covering `va`, if any.
    ///
    /// Zero-fill/BSS tails and section-less ranges report `None`, matching
    /// the `section` provenance of [`Project::search_bytes`].
    #[must_use]
    pub fn section_of(&self, va: u64) -> Option<&str> {
        section_of_in(&self.binary, va)
    }

    /// Raw byte range at `va` with VA/file provenance and a typed view.
    ///
    /// Validates the range through [`Project::bytes_at`] (same 1 MiB cap,
    /// zero-padded BSS tails, unmapped ranges are [`Error::NotFound`]);
    /// `file_off`/`section` describe the range start via
    /// [`Project::file_off_of`]/[`Project::section_of`]. `values` decodes
    /// the bytes per `as_` in `endian` order (see [`BytesAs`]). Read-only:
    /// never writes the binary or the sidecar.
    ///
    /// # Errors
    /// Same as [`Project::bytes_at`].
    pub fn bytes_view(
        &self,
        va: u64,
        len: usize,
        as_: BytesAs,
        endian: BytesEndian,
    ) -> Result<BytesView> {
        bytes_view_of(&self.binary, va, len, as_, endian)
    }

    /// Raw byte range with the struct layout stored at `hint_addr` rendered
    /// over it.
    ///
    /// Reads `[va, va+len)` exactly like [`Project::bytes_view`] (same 1
    /// MiB cap, zero-padded BSS tails, unmapped ranges are
    /// [`Error::NotFound`]) with the same `values` typed decoding in
    /// `endian` order, then renders the
    /// [`TypeHint`](crate::annotations::TypeHint) stored at `hint_addr` as
    /// `fields`: one row per struct field with its own `addr`/`addr_hex`
    /// twins, `bytes_hex`, and integer `value` in `endian` order (null for
    /// fields wider than 8 bytes). The result also echoes the wire hint in
    /// `hint` and where it was read from in `hint_addr`/`hint_addr_hex`.
    /// `len` must cover the struct size; extra bytes read normally. The
    /// hint address keeps the any-address comment contract. Read-only:
    /// never writes the binary or the sidecar.
    ///
    /// # Errors
    /// [`Error::Invalid`] when no hint is stored at `hint_addr`, on a
    /// corrupt hint, or when `len` is smaller than the struct size; same as
    /// [`Project::bytes_at`] otherwise.
    pub fn bytes_view_as_type(
        &self,
        va: u64,
        len: usize,
        as_: BytesAs,
        endian: BytesEndian,
        hint_addr: u64,
    ) -> Result<serde_json::Value> {
        bytes_view_as_type_of(
            &self.binary,
            &self.annotations,
            va,
            len,
            as_,
            endian,
            hint_addr,
        )
    }

    /// Disassemble `len` bytes at `va` with the binary's architecture.
    ///
    /// Returns the valid prefix plus `error_at` for the first bad opcode
    /// (`None` when the whole range decodes); cap overruns are still
    /// errors. Rows carry the resolved import name when the instruction
    /// calls through an import slot or stub (see
    /// [`crate::analysis::XrefKind::Import`]), plus the render-time
    /// `target_name`/`comment`/`string` listing annotations (see
    /// [`Insn`]). Serializes as
    /// `{"insns": [...], "error_at": null|{...}}`.
    ///
    /// # Errors
    /// Same as [`Project::bytes_at`], plus [`Error::Limit`] on cap overrun.
    pub fn disasm_at(&self, addr: u64, len: usize) -> Result<PartialDisasm> {
        let bytes = self.bytes_at(addr, len)?;
        let mut partial = self
            .binary
            .arch
            .disassembler()
            .disasm_range_partial(&bytes, addr)?;
        let ctx = self.enrich_ctx();
        let mut prev: Option<Insn> = None;
        for insn in &mut partial.insns {
            self.enrich_insn(&ctx, insn, prev.as_ref());
            prev = Some(insn.clone());
        }
        Ok(partial)
    }

    /// Function rows with annotation renames resolved, ordered by entry.
    #[must_use]
    pub fn functions_resolved(&self, offset: usize, limit: usize) -> Vec<serde_json::Value> {
        self.functions_filtered(&FunctionFilter::default(), offset, limit)
    }

    /// Function rows with annotation renames resolved, filtered then paged.
    ///
    /// Every present [`FunctionFilter`] field must match; filtering happens
    /// before paging so `offset`/`limit` apply to the matching rows. Rows
    /// carry the full `calls` target array (unbounded for large callers);
    /// [`Project::functions_envelope`] is the opt-in preview that wraps
    /// the same matches in the protocol-1 [`Page`] envelope with compact
    /// `calls_count` rows instead.
    #[must_use]
    pub fn functions_filtered(
        &self,
        filter: &FunctionFilter,
        offset: usize,
        limit: usize,
    ) -> Vec<serde_json::Value> {
        self.matching_function_entries(filter)
            .into_iter()
            .skip(offset)
            .take(limit.min(MAX_ROWS))
            .map(|entry| {
                let (entry_json, entry_hex) = addr_pair(entry);
                let f = &self.analysis.functions[&entry];
                serde_json::json!({
                    "id": f.id(), "entry": entry_json, "entry_hex": entry_hex,
                    "name": self.function_name(entry),
                    "blocks": f.blocks.len(), "insns": f.insn_count(), "calls": self.analysis.calls_of(entry),
                    "noreturn": f.noreturn,
                })
            })
            .collect()
    }

    /// Entries matching [`Project::functions_filtered`], in entry order.
    ///
    /// Shared by the legacy bare-array list, the exact count, and the
    /// opt-in envelope so all three agree on the match set.
    fn matching_function_entries(&self, filter: &FunctionFilter) -> Vec<u64> {
        // Resolve anchor addresses once: None = filter disabled,
        // Some(None) = anchor lies in no function (matches nothing).
        // Caller/callee target sets are materialized once as sorted arrays
        // so per-function checks binary-search instead of allocating and
        // sorting a `calls_of` Vec per row.
        let callers: Option<Option<Vec<u64>>> = filter.caller.map(|a| {
            self.analysis
                .containing_function(a)
                .map(|c| self.analysis.callers_of(c))
        });
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
            .filter(|f| match &callers {
                None => true,
                Some(None) => false,
                Some(Some(cs)) => cs.binary_search(&f.entry).is_ok(),
            })
            .filter(|f| match &callee_calls {
                None => true,
                Some(None) => false,
                Some(Some(cs)) => cs.binary_search(&f.entry).is_ok(),
            })
            .filter(|f| match &query {
                Some(q) => self
                    .function_name(f.entry)
                    .is_some_and(|n| n.to_lowercase().contains(q.as_str())),
                None => true,
            })
            .map(|f| f.entry)
            .collect()
    }

    /// Exact count of [`Project::functions_filtered`] matches, before paging.
    ///
    /// Lets agents learn the function count without paging to the end;
    /// the opt-in [`Project::functions_envelope`] reports this as `total`.
    #[must_use]
    pub fn count_functions_filtered(&self, filter: &FunctionFilter) -> usize {
        self.matching_function_entries(filter).len()
    }

    /// Filtered function matches under the protocol-1 [`Page`] envelope.
    ///
    /// Opt-in preview of the planned functions-shape migration (see
    /// `docs/book/src/migration.md`): `total` is the exact match count
    /// and rows are compact — `calls_count` replaces the unbounded
    /// `calls` target array, so the page stays bounded for arbitrarily
    /// large callers. Direct callees remain one `callees` query away
    /// (`depth` 1). The legacy [`Project::functions_filtered`] bare array
    /// keeps the `calls` array unchanged.
    #[must_use]
    pub fn functions_envelope(
        &self,
        filter: &FunctionFilter,
        offset: usize,
        limit: usize,
    ) -> Page<serde_json::Value> {
        let matched = self.matching_function_entries(filter);
        let total = matched.len();
        let items = matched
            .into_iter()
            .skip(offset)
            .take(limit.min(MAX_ROWS))
            .map(|entry| {
                let (entry_json, entry_hex) = addr_pair(entry);
                let f = &self.analysis.functions[&entry];
                serde_json::json!({
                    "id": f.id(), "entry": entry_json, "entry_hex": entry_hex,
                    "name": self.function_name(entry),
                    "blocks": f.blocks.len(), "insns": f.insn_count(),
                    "calls_count": self.analysis.calls_count(entry),
                    "noreturn": f.noreturn,
                })
            })
            .collect();
        page_envelope(total, offset, limit, items)
    }

    /// Full function detail: blocks with instructions in address order.
    ///
    /// `addr` may be any address inside the function; it snaps to the
    /// containing entry. The result carries both `entry` (the canonical
    /// function entry) and `containing_entry` (the entry containing `addr`),
    /// plus `query_addr` echoing the address the caller passed.
    /// Instruction rows carry the render-time `target_name`/`comment`/
    /// `string` listing annotations (see [`Insn`]).
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
        let ctx = self.enrich_ctx();
        let blocks: Vec<serde_json::Value> = f
            .blocks
            .values()
            .map(|b| {
                let (start, start_hex) = addr_pair(b.start);
                let (end, end_hex) = addr_pair(b.end());
                let mut prev: Option<Insn> = None;
                let mut insns = b.insns.clone();
                for insn in &mut insns {
                    self.enrich_insn(&ctx, insn, prev.as_ref());
                    prev = Some(insn.clone());
                }
                serde_json::json!({
                    "id": b.id(entry), "start": start, "start_hex": start_hex,
                    "end": end, "end_hex": end_hex,
                    "insns": insns, "succs": f.successors(b.start),
                })
            })
            .collect();
        let (entry_json, entry_hex) = addr_pair(f.entry);
        let (_, containing_hex) = addr_pair(entry);
        let (query_json, query_hex) = addr_pair(addr);
        Ok(serde_json::json!({
            "id": f.id(), "entry": entry_json, "entry_hex": entry_hex,
            "containing_entry": entry, "containing_entry_hex": containing_hex,
            "query_addr": query_json, "query_addr_hex": query_hex,
            "name": self.function_name(entry),
            "blocks": blocks, "edges": f.edges(),
            "inferred_edges": f.inferred_edges(),
            "calls": self.analysis.calls_of(entry),
            "noreturn": f.noreturn,
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
            inferred_edges: f.inferred_len(),
            noreturn: f.noreturn,
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
    /// count read without cloning rows. Each row carries the render-time
    /// `target_name`/`comment`/`string` listing annotations (see
    /// [`Insn`]); `adrp` pairs split by a page boundary resolve from the
    /// page's own rows only.
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
        let mut items = self
            .analysis
            .block_insns(entry, block, offset, limit)
            .ok_or_else(|| Error::NotFound(format!("block {block:#x} in function {entry:#x}")))?;
        let ctx = self.enrich_ctx();
        let mut prev: Option<Insn> = None;
        for insn in &mut items {
            self.enrich_insn(&ctx, insn, prev.as_ref());
            prev = Some(insn.clone());
        }
        Ok(page_envelope(total, offset, limit, items))
    }

    /// CFG of one function: block nodes plus `(from, to)` block edges.
    ///
    /// `addr` may be any address inside the function; it snaps to the
    /// containing entry. The result carries both `entry` (the canonical
    /// function entry) and `containing_entry` (the entry containing `addr`),
    /// plus `query_addr` echoing the address the caller passed.
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
        let (query_json, query_hex) = addr_pair(addr);
        Ok(
            serde_json::json!({ "entry": entry, "entry_hex": entry_hex, "containing_entry": entry, "containing_entry_hex": entry_hex, "query_addr": query_json, "query_addr_hex": query_hex, "nodes": nodes, "edges": f.edges(), "inferred_edges": f.inferred_edges() }),
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
    /// `warning`), and `query_addr` echoing the address the caller
    /// passed. Read-only: never writes the binary or the sidecar.
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
        let (query_json, query_hex) = addr_pair(addr);
        Ok(serde_json::json!({
            "entry": entry_json, "entry_hex": entry_hex,
            "containing_entry": entry, "containing_entry_hex": entry_hex,
            "query_addr": query_json, "query_addr_hex": query_hex,
            "structure": structure,
        }))
    }

    /// Approximate pseudo-C of one function: one lossy C-like line per IR
    /// row plus the assembled text, with the approximation warning.
    ///
    /// `addr` may be any address inside the function; it snaps to the
    /// containing entry exactly like [`Project::cfg_of`]. The top-level
    /// object carries `query_addr` echoing the address the caller passed.
    /// Each line propagates its source IR warning (`None` for mapped rows) and the
    /// resolved import name when the source instruction calls through an
    /// import slot or stub; direct call/branch targets render under their
    /// display name (rename wins over symbol-table and import names, with
    /// a `func@0x...` fallback), data references append their string
    /// preview as `// "..."`, and annotations append as `// ...`. Lines
    /// also carry the additive `target_name`/`comment`/`string` fields.
    /// The top-level `warning` is always
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
        let mut pseudo = crate::pseudo::render_function(self.binary.arch, func);
        let by_addr: BTreeMap<u64, &String> = func
            .blocks
            .values()
            .flat_map(|b| &b.insns)
            .filter_map(|i| i.import.as_ref().map(|name| (i.addr, name)))
            .collect();
        for line in &mut pseudo.lines {
            if let Some(name) = by_addr.get(&line.addr) {
                line.import = Some((*name).clone());
            }
        }
        let ctx = self.enrich_ctx();
        let mut rows: BTreeMap<u64, (&Insn, Option<&Insn>)> = BTreeMap::new();
        for block in func.blocks.values() {
            let mut prev: Option<&Insn> = None;
            for insn in &block.insns {
                rows.insert(insn.addr, (insn, prev));
                prev = Some(insn);
            }
        }
        for line in &mut pseudo.lines {
            let Some((insn, prev)) = rows.get(&line.addr) else {
                continue;
            };
            let resolved_mem = prev
                .and_then(|p| resolve_adrp_pair(p, insn))
                .or(insn.mem_target);
            let ctrl = crate::ir::lift(self.binary.arch, insn)
                .into_iter()
                .find(|r| r.op.is_control())
                .map(|r| (r.op, r.target));
            match ctrl {
                Some((crate::ir::IrOp::Call, Some(t))) => {
                    if let Some(name) = self.target_name_in(&ctx, t, true) {
                        line.text = format!("call {name}();");
                        line.target_name = Some(name);
                    }
                }
                Some((crate::ir::IrOp::Call, None)) => {
                    if let Some(name) = line.import.clone() {
                        line.text = format!("call {name}();");
                    }
                }
                Some((crate::ir::IrOp::Branch, Some(t))) => {
                    if let Some(name) = self.target_name_in(&ctx, t, true) {
                        line.text = format!("goto {name};");
                        line.target_name = Some(name);
                    }
                }
                Some((crate::ir::IrOp::CBranch, Some(t))) => {
                    if let Some(name) = self.target_name_in(&ctx, t, true) {
                        if let Some(pos) = line.text.find("goto 0x")
                            && let Some(rel) = line.text[pos + 5..].find(';')
                        {
                            line.text.replace_range(pos + 5..pos + 5 + rel, &name);
                        }
                        line.target_name = Some(name);
                    }
                }
                _ => {}
            }
            if line.string.is_none()
                && let Some(m) = resolved_mem
            {
                line.string = self.string_preview_in(&ctx, m);
            }
            if line.comment.is_none() {
                line.comment = self.annotation(line.addr).and_then(|a| a.comment.clone());
            }
            if let Some(preview) = line.string.clone() {
                line.text.push_str(&format!(" // \"{preview}\""));
            }
            if let Some(comment) = line.comment.clone() {
                let flat: String = comment
                    .chars()
                    .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
                    .collect();
                line.text.push_str(&format!(" // {flat}"));
            }
        }
        let pseudo = serde_json::to_value(pseudo).expect("pseudo serializes");
        let (entry_json, entry_hex) = addr_pair(entry);
        let (query_json, query_hex) = addr_pair(addr);
        Ok(serde_json::json!({
            "entry": entry_json, "entry_hex": entry_hex,
            "containing_entry": entry, "containing_entry_hex": entry_hex,
            "query_addr": query_json, "query_addr_hex": query_hex,
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

    /// Backward slice of `addr`: every instruction that can reach it, paged.
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
        addr: u64,
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
        let reached = self.analysis.slice_to(addr, depth);
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

    /// Xrefs filtered by endpoint/kind with the pre-page count, in one pass.
    ///
    /// The single call behind the CLI/MCP `xrefs` envelope: `total` is the
    /// exact match count and `items` the requested page, computed in one
    /// index-narrowed pass instead of separate count and page scans. `limit`
    /// clips to `MAX_ROWS`, as in [`Project::query_xrefs`].
    #[must_use]
    pub fn query_xrefs_page(
        &self,
        to: Option<u64>,
        from: Option<u64>,
        kind: Option<XrefKind>,
        offset: usize,
        limit: usize,
    ) -> (usize, Vec<Xref>) {
        self.analysis
            .xrefs_matching_page(to, from, kind, offset, limit.min(MAX_ROWS))
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
        self.query_xrefs_page(to, from, kind, offset, limit).1
    }

    /// Count of xrefs matching the [`Project::query_xrefs`] filters, before
    /// paging. The CLI/MCP `xrefs` envelope reports this as `total` so
    /// large result sets page without scanning blind.
    #[must_use]
    pub fn count_xrefs(&self, to: Option<u64>, from: Option<u64>, kind: Option<XrefKind>) -> usize {
        self.query_xrefs_page(to, from, kind, 0, 0).0
    }

    /// Imports plus exports plus symbol-table code addresses for symbol views.
    ///
    /// Ordinal-only imports carry `ordinal` plus `unresolved: true`;
    /// C++ imports/exports/symbols carry `demangled` when [`crate::loader::demangle_cpp`]
    /// recognizes the mangling. Resolved imports carry the call pointer in
    /// `address`/`address_hex`: the `__stubs`/`__auth_stubs` entry on
    /// Mach-O, the IAT slot on PE, the GOT slot on ELF; every other import
    /// row carries null on both sides. `symbols` holds
    /// one `{name, address, address_hex}` row per defined text symbol
    /// (locals included), deduplicated by address; empty for raw blobs
    /// and LE images, which have no symbol tables.
    #[must_use]
    pub fn symbols_json(&self) -> serde_json::Value {
        serde_json::json!({ "imports": self.binary.imports, "exports": self.binary.exports, "symbols": self.binary.symbols })
    }

    /// Section table in file order: name, virtual address, in-memory size,
    /// file offset/size of the raw bytes, Shannon entropy, and permissions.
    ///
    /// `vaddr` is the flat virtual address the loader mapped the section at
    /// (PE: `IMAGE_BASE + RVA`, so `.text` at RVA `0x1000` in a
    /// `0x400000`-based image lives at `0x401000`); `file_off` locates the
    /// section's raw bytes in the file. `entropy` is the Shannon entropy of
    /// the file-backed bytes in bits per byte (0–8; `0.0` for virtual-only
    /// sections): values over ~7.2 with a tiny import table mark a
    /// possibly-packed section. Raw blobs have no table and report
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
                    "file_off": s.file_off, "file_size": s.file_size,
                    "entropy": s.entropy(),
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

    /// Extracted strings, filtered then paged under the protocol-1 envelope.
    ///
    /// Opt-in preview of the planned strings-shape migration (see
    /// `docs/book/src/migration.md`): `total` is the exact filtered count
    /// and `items` holds the requested page. The legacy
    /// [`Project::query_strings`] bare array is unchanged.
    ///
    /// # Errors
    /// Same as [`Project::query_strings`].
    pub fn query_strings_envelope(&self, filter: &StringsFilter) -> Result<Page<StringHit>> {
        let total = self.analysis.strings_count_filtered(filter)?;
        let items = self.analysis.strings_page_filtered(filter)?;
        Ok(page_envelope(total, filter.start, filter.limit, items))
    }

    /// Decoded-view strings: `strings --decode` over an in-memory transform.
    ///
    /// Re-extracts over a per-segment decoded copy (see
    /// [`Analysis::strings_decoded_view`]) with the same filter semantics
    /// as [`Project::query_strings`]: single-byte XOR/add/rot- and rolling
    /// multi-byte XOR-obfuscated text shows up with its original offsets
    /// and addresses, and `base64` reports base64 blobs' plaintext.
    /// Strictly read-only: the binary and the sidecar are never written.
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

    /// Decoded-view strings under the protocol-1 envelope.
    ///
    /// Same opt-in preview as [`Project::query_strings_envelope`] over the
    /// in-memory decoded view (see [`Project::query_strings_decoded`]).
    ///
    /// # Errors
    /// Same as [`Project::query_strings_decoded`].
    pub fn query_strings_decoded_envelope(
        &self,
        filter: &StringsFilter,
        decode: crate::loader::strings::DecodeSpec,
    ) -> Result<Page<StringHit>> {
        let total = self
            .analysis
            .strings_decoded_count(&self.binary, filter, decode.clone())?;
        let items = self
            .analysis
            .strings_decoded_view(&self.binary, filter, decode)?;
        Ok(page_envelope(total, filter.start, filter.limit, items))
    }

    /// Recovered stack-constructed strings: runs of
    /// `mov [rsp/rbp+off], imm` within one block, reassembled with
    /// function and address (see [`crate::stackstrings::recover`]).
    /// A separate surface from [`Project::query_strings`]: read-only,
    /// never writes the binary or the sidecar.
    #[must_use]
    pub fn stack_strings(&self) -> Vec<crate::stackstrings::StackString> {
        crate::stackstrings::recover(&self.analysis)
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

    /// Scan mapped bytes for known crypto constants, paged.
    ///
    /// Runs the static [`crate::crypto::CRYPTO_CONSTS`] table (AES
    /// S-box/T-table, SHA-1/256 round constants, MD5/CRC-32 tables,
    /// `expand 32-byte k`, Blowfish P-array, TEA delta, in LE/BE word
    /// orders) through the same bounded scan as [`Project::search_bytes`].
    /// `name` keeps one constant (e.g. `aes-sbox`); `section` keeps matches
    /// fully inside a file-backed section of that exact name. Rows order by
    /// `(addr, name)` under the protocol-1 [`Page`] envelope; `total` is
    /// exact. Each row's `xrefs_count` counts analysis xrefs (any kind) to
    /// its address, so unreferenced short hits (notably `tea-delta`) read
    /// as indicative only. Read-only: never writes the binary or the
    /// sidecar.
    ///
    /// # Errors
    /// [`Error::NotFound`] when `name` matches no table entry or `section`
    /// names no section, [`Error::Limit`] past the per-pattern scan budget.
    pub fn crypto_scan(
        &self,
        name: Option<&str>,
        section: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Page<crate::crypto::CryptoHit>> {
        let matched = crate::crypto::scan(&self.binary, name, section)?;
        let total = matched.len();
        let items = matched
            .into_iter()
            .skip(offset)
            .take(limit.min(MAX_ROWS))
            .map(|(name, m)| crate::crypto::CryptoHit {
                addr: m.addr,
                name,
                file_off: m.file_off,
                section: m.section,
                len: m.len,
                xrefs_count: self.count_xrefs(Some(m.addr), None, None),
            })
            .collect();
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
        self.query_flirt_hints_with(addr, offset, limit, &[])
    }

    /// [`Project::query_flirt_hints`] plus `extra` user signatures (see
    /// [`crate::flirt::load_signature_file`): builtin hints come first
    /// per function (longest first), then user matches (longest first).
    ///
    /// Read-only like the base query: user files never reach the binary
    /// or the sidecar.
    ///
    /// # Errors
    /// Same as [`Project::query_flirt_hints`].
    pub fn query_flirt_hints_with(
        &self,
        addr: Option<u64>,
        offset: usize,
        limit: usize,
        extra: &[crate::flirt::RuntimeSignature],
    ) -> Result<Page<FlirtHint>> {
        let entry = addr
            .map(|a| {
                self.analysis
                    .containing_function(a)
                    .ok_or_else(|| Error::NotFound(format!("function {a:#x}")))
            })
            .transpose()?;
        let matched: Vec<FlirtHint> = match entry {
            Some(e) => {
                let func = self
                    .analysis
                    .functions
                    .get(&e)
                    .ok_or_else(|| Error::NotFound(format!("function {e:#x}")))?;
                crate::flirt::hints_for_function_with(self.analysis.arch, func, extra)
            }
            None => crate::flirt::hints_for_analysis_with(&self.analysis, extra),
        };
        let total = matched.len();
        let items = matched
            .into_iter()
            .skip(offset)
            .take(limit.min(MAX_ROWS))
            .collect();
        Ok(page_envelope(total, offset, limit, items))
    }

    /// Emit a JSON signature document for the project's named functions
    /// (see [`crate::flirt::SignatureFile`]): the `sig-gen` output that
    /// `--sigs` reads back.
    ///
    /// Each rename-resolved named function contributes its masked
    /// leading bytes ([`crate::flirt::generate_for_function`]); unnamed,
    /// too-short, or too-masked functions are skipped, and identical
    /// `(arch, bytes)` shapes keep only the lowest entry's name.
    /// Read-only: never writes the binary or the sidecar.
    #[must_use]
    pub fn generate_signatures(&self) -> crate::flirt::SignatureFile {
        let is_mapped = |va: u64| {
            self.binary
                .segments
                .iter()
                .any(|g| va >= g.vaddr && va.saturating_sub(g.vaddr) < g.mem_size)
        };
        let mut seen = HashSet::new();
        let mut signatures = Vec::new();
        for (entry, func) in &self.analysis.functions {
            let Some(name) = self.function_name(*entry) else {
                continue;
            };
            let arch = func.decode_arch.unwrap_or(self.analysis.arch);
            let Some(row) = crate::flirt::generate_for_function(arch, func, &name, is_mapped)
            else {
                continue;
            };
            if seen.insert((row.arch.clone(), row.bytes.clone())) {
                signatures.push(row);
            }
        }
        crate::flirt::SignatureFile {
            version: crate::flirt::SIGNATURE_FILE_VERSION,
            signatures,
        }
    }

    /// Recover Go functions from the `pclntab` table (see
    /// [`crate::gopclntab::recover`]): linker names plus exact
    /// `[entry, end)` ranges, in functab order.
    ///
    /// Empty when no table is located (not a Go binary); only a
    /// located-but-corrupt table errors. Read-only: never writes the
    /// binary or the sidecar.
    ///
    /// # Errors
    /// [`Error::Invalid`] on a corrupt located table,
    /// [`Error::Unsupported`] on a big-endian table.
    pub fn go_funcs(&self) -> Result<Vec<crate::gopclntab::GoFunc>> {
        crate::gopclntab::recover(&self.binary)
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

/// Active user seeds for analysis: non-excluded rows as [`UserSeed`]s.
///
/// Excluded rows are kept as data but never seed analysis; `None` modes
/// decode with the project arch.
fn active_user_seeds(seeds: &BTreeMap<u64, crate::db::FuncSeed>) -> Vec<crate::analysis::UserSeed> {
    seeds
        .iter()
        .filter(|(_, s)| !s.excluded)
        .map(|(&addr, s)| crate::analysis::UserSeed { addr, mode: s.mode })
        .collect()
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

/// Parse an xref kind filter: `code`, `data`, `string`, `import`
/// (call sites through an import slot or stub), or `inferred-code`
/// (provenance-marked single-slot resolutions).
///
/// # Errors
/// [`Error::Invalid`] for anything else.
pub fn parse_xref_kind(s: &str) -> Result<XrefKind> {
    match s.to_lowercase().as_str() {
        "code" => Ok(XrefKind::Code),
        "data" => Ok(XrefKind::Data),
        "string" => Ok(XrefKind::String),
        "import" => Ok(XrefKind::Import),
        "inferred-code" => Ok(XrefKind::InferredCode),
        _ => Err(Error::Invalid(format!("bad xref kind: {s:?}"))),
    }
}

/// Parse a diagnostics kind filter: `unresolved-indirect-jump`,
/// `unresolved-indirect-call`, `noreturn-cut`, or `decode-failure`
/// (case-insensitive).
///
/// # Errors
/// [`Error::Invalid`] for anything else.
pub fn parse_diagnostic_kind(s: &str) -> Result<DiagnosticKind> {
    match s.to_lowercase().as_str() {
        "unresolved-indirect-jump" => Ok(DiagnosticKind::UnresolvedIndirectJump),
        "unresolved-indirect-call" => Ok(DiagnosticKind::UnresolvedIndirectCall),
        "noreturn-cut" => Ok(DiagnosticKind::NoreturnCut),
        "decode-failure" => Ok(DiagnosticKind::DecodeFailure),
        _ => Err(Error::Invalid(format!("bad diagnostic kind: {s:?}"))),
    }
}

/// Parse a typed byte view: `u8`, `u16`, `u32`, `u64`, `ptr`, `cstr`,
/// or `utf16` (case-insensitive, see [`BytesAs`]).
///
/// # Errors
/// [`Error::Invalid`] for anything else.
pub fn parse_bytes_as(s: &str) -> Result<BytesAs> {
    match s.to_lowercase().as_str() {
        "u8" => Ok(BytesAs::U8),
        "u16" => Ok(BytesAs::U16),
        "u32" => Ok(BytesAs::U32),
        "u64" => Ok(BytesAs::U64),
        "ptr" => Ok(BytesAs::Ptr),
        "cstr" => Ok(BytesAs::CStr),
        "utf16" => Ok(BytesAs::Utf16),
        _ => Err(Error::Invalid(format!("bad bytes view: {s:?}"))),
    }
}

/// Parse a byte order: `le` or `be` (case-insensitive, see [`BytesEndian`]).
///
/// # Errors
/// [`Error::Invalid`] for anything else.
pub fn parse_bytes_endian(s: &str) -> Result<BytesEndian> {
    match s.to_lowercase().as_str() {
        "le" => Ok(BytesEndian::Le),
        "be" => Ok(BytesEndian::Be),
        _ => Err(Error::Invalid(format!("bad byte order: {s:?}"))),
    }
}

/// Re-read the binary bytes for a hash-matching cached snapshot.
///
/// Raw blobs need their mapping options again; containers re-parse with the
/// same fat slice selection.
fn reload_binary(
    bytes: Vec<u8>,
    raw: Option<RawOptions>,
    fat_arch: Option<&str>,
) -> Result<LoadedBinary> {
    match raw {
        Some(opts) => load_raw_vec(bytes, opts),
        None => load_or_raw(&bytes, fat_arch),
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
/// [`Error::Io`] on I/O failure.
fn read_input_bytes(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::NotFound(path.display().to_string()),
        _ => Error::Io(format!("stat {}: {e}", path.display())),
    })?;
    if !meta.is_file() {
        return Err(Error::Unsupported(format!(
            "not a file: {}",
            path.display()
        )));
    }
    let file = std::fs::File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::NotFound(path.display().to_string()),
        _ => Error::Io(format!("read {}: {e}", path.display())),
    })?;
    let cap = crate::loader::MAX_INPUT_BYTES;
    // One allocation for the common case: the stat size is only a capacity
    // hint (a growing file still hits the checked cap chunk by chunk), and
    // sparse files merely reserve address space until bytes are written.
    let hint = meta.len().min(cap);
    let mut reader = file;
    read_stream_capped(&mut reader, cap, &path.display().to_string(), hint)
}

/// Accumulate a stream with checked growth against `cap`.
///
/// Split from [`read_input_bytes`] so the exact/over boundary and
/// mid-read growth are unit-testable without a 512 MiB file: every chunk
/// extends the total with [`checked_add`](u64::checked_add) and rejects
/// past `cap` with [`Error::Limit`]. `hint` preallocates once (the stat
/// size from [`read_input_bytes`]); later chunks grow amortized instead of
/// reallocating per 64 KiB chunk.
fn read_stream_capped(
    reader: &mut impl std::io::Read,
    cap: u64,
    label: &str,
    hint: u64,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(hint.min(cap) as usize);
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(reader, &mut chunk)
            .map_err(|e| Error::Io(format!("read {label}: {e}")))?;
        if n == 0 {
            break;
        }
        let next = (out.len() as u64)
            .checked_add(n as u64)
            .filter(|m| *m <= cap)
            .ok_or_else(|| Error::Limit("input exceeds 512 MiB".to_string()))?;
        out.reserve(n);
        out.extend_from_slice(&chunk[..n]);
        debug_assert_eq!(out.len() as u64, next);
    }
    Ok(out)
}

/// Container parse with raw x86-64 fallback for unrecognized bytes.
///
/// `fat_arch` passes through to [`load_with_slice`](crate::loader::load_with_slice):
/// it selects the slice for fat input (missing/unknown selections error
/// listing the available archs) and errors for thin containers. An
/// explicit selection also disables the raw fallback, so unrecognized
/// bytes with a selection report the parse error instead of silently
/// opening as raw. Only [`Error::Invalid`] on unrecognized input without
/// a selection falls back; recognized containers that fail to parse (LE
/// included) report the parse error, and [`Error::Limit`]/
/// [`Error::Unsupported`] propagate unchanged. LE images that parse flow
/// to analysis as x86_32.
fn load_or_raw(bytes: &[u8], fat_arch: Option<&str>) -> Result<LoadedBinary> {
    match load_with_slice(bytes, fat_arch) {
        Ok(bin) => Ok(bin),
        Err(Error::Invalid(_)) if fat_arch.is_none() && !crate::loader::is_recognized(bytes) => {
            load_raw(
                bytes,
                RawOptions {
                    base: 0,
                    arch: crate::disasm::Arch::X86_64,
                    entry: None,
                },
            )
        }
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
            ("import", XrefKind::Import),
            ("Import", XrefKind::Import),
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
            ("noreturn-cut", DiagnosticKind::NoreturnCut),
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
        let got = read_stream_capped(&mut cur, 16, "t", 0).expect("exact cap passes");
        assert_eq!(got, exact);
        let mut cur = std::io::Cursor::new(vec![0x41u8; 17]);
        let err = read_stream_capped(&mut cur, 16, "t", 0).unwrap_err();
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
        let err = read_stream_capped(&mut g, 16, "g", 0).unwrap_err();
        assert!(matches!(err, Error::Limit(_)), "got {err:?}");
        let mut g = Growing { left: 16 };
        let got = read_stream_capped(&mut g, 16, "g", 0).expect("exact growth passes");
        assert_eq!(got.len(), 16);
    }

    /// A correct capacity hint avoids reallocations entirely.
    #[test]
    fn stream_capped_preallocates_once() {
        let input = vec![0x43u8; 1024];
        let mut cur = std::io::Cursor::new(input.clone());
        let got = read_stream_capped(&mut cur, 2048, "h", 1024).expect("hinted read");
        assert_eq!(got, input);
        assert_eq!(got.capacity(), 1024);
    }
}
