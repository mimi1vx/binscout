//! M5 persist: `redb` project store plus annotations.
//!
//! One project DB holds a single binary's snapshot: the [`BinaryMeta`] row,
//! one [`FunctionRecord`] per function, one [`BlockRecord`] per basic block,
//! the [`Xref`] set, extracted [`StringHit`]s, and user [`Annotation`]s.
//! Values are JSON so rows stay debuggable with any `redb` inspector.
//!
//! Block rows store address ranges plus successors only; instructions are
//! re-decoded from the binary on open (see
//! [`Analysis::rebuild`](crate::analysis::rebuild)). Caching rendered
//! instructions made small binaries produce huge sidecars, so derived text
//! is never persisted.
//!
//! [`save`] rewrites every table in one transaction; [`load`] rebuilds the
//! skeleton [`Loaded`] snapshot and the caller re-decodes instructions via
//! [`Analysis::rebuild`](crate::analysis::rebuild), returning stored
//! annotations untouched. [`load_cached`] filters by content hash plus
//! SHA-256 and size, loader
//! mapping, and analysis revision in one read transaction: matching
//! snapshots load the skeleton fully, stale ones (different content, mapping,
//! revision, or an older schema version) return metadata plus annotations
//! without decoding the discarded derived rows (see its stale-cache
//! policy). A mapping mismatch over a populated annotation sidecar errors
//! with a separate-DB message instead of reusing layouts or remapping
//! annotations. Callers detect a changed binary by comparing
//! [`content_hash`] against [`BinaryMeta::content_hash`]: re-analysis runs,
//! same-mapping annotations carry over by address when
//! [`stale_carry_plausible`] holds, and only an explicit
//! [`save`] writes — the analyzed binary itself is only ever read.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::analysis::{Analysis, FunctionLayout, Xref};
use crate::disasm::Arch;
use crate::error::{Error, Result};
use crate::loader::BinaryFormat;
use crate::loader::strings::StringHit;

/// Schema version stored under `meta["version"]`.
///
/// Version 6 strengthens cache identity with SHA-256 plus size alongside
/// the FNV-1a hash, so same bytes opened under different
/// raw options never share cached layouts and old snapshots re-analyze
/// rather than synthesizing clean diagnostics.
pub const SCHEMA_VERSION: u32 = 6;
/// Revision of the analysis engine covered by cached snapshots.
///
/// Re-exported from [`crate::analysis`] so cache identity has one source:
/// a stored revision mismatch re-analyzes instead of replaying layouts.
pub use crate::analysis::ANALYSIS_REVISION;
/// Cap on cached function rows (mirrors analysis [`MAX_FUNCTIONS`](crate::analysis::MAX_FUNCTIONS)).
pub const MAX_SNAPSHOT_FUNCTIONS: usize = 100_000;
/// Cap on cached block rows (blocks never exceed decoded instructions).
pub const MAX_SNAPSHOT_BLOCKS: usize = 1_000_000;
/// Cap on cached xref rows (1M per kind times three kinds).
pub const MAX_SNAPSHOT_XREFS: usize = 3_000_000;
/// Cap on cached string rows (10k per segment times 256 segments, rounded up).
pub const MAX_SNAPSHOT_STRINGS: usize = 3_000_000;
/// Cap on stored annotation rows (user-created; 10k is 100x typical use).
pub const MAX_SNAPSHOT_ANNOTATIONS: usize = 10_000;
/// Cap on cached diagnostic rows (mirrors analysis [`MAX_DIAGNOSTICS`](crate::analysis::MAX_DIAGNOSTICS)).
pub const MAX_SNAPSHOT_DIAGNOSTICS: usize = 100_000;
/// Cap on cached inferred-edge rows (mirrors analysis [`MAX_INFERRED_EDGES`](crate::analysis::MAX_INFERRED_EDGES)).
pub const MAX_SNAPSHOT_INFERRED_EDGES: usize = 100_000;
/// Cap on one annotation name/comment in bytes.
///
/// 8 KiB holds pasted stack traces while keeping a single row trivial.
pub const MAX_ANNOTATION_BYTES: usize = 8192;

const META: TableDefinition<&str, String> = TableDefinition::new("meta");
const BINARIES: TableDefinition<u64, String> = TableDefinition::new("binaries");
const FUNCTIONS: TableDefinition<u64, String> = TableDefinition::new("functions");
const BLOCKS: TableDefinition<String, String> = TableDefinition::new("blocks");
const XREFS: TableDefinition<String, String> = TableDefinition::new("xrefs");
const STRINGS: TableDefinition<u64, String> = TableDefinition::new("strings");
const ANNOTATIONS: TableDefinition<u64, String> = TableDefinition::new("annotations");
const DIAGNOSTICS: TableDefinition<String, String> = TableDefinition::new("diagnostics");

/// Deterministic 64-bit FNV-1a hash of the binary bytes.
///
/// Non-cryptographic: it only detects "binary changed, re-analyze", it is not
/// a tamper check. Deterministic across processes, unlike `DefaultHasher`.
#[must_use]
pub fn content_hash(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut h = OFFSET;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// Sidecar DB path for a binary: `foo.exe` -> `foo.exe.rsdbg.redb`.
///
/// Appends `.rsdbg.redb` to the full file name so `foo.exe` and `foo.dll`
/// never share a sidecar. There is no fallback to the old colliding path.
#[must_use]
pub fn default_db_path(binary: &Path) -> PathBuf {
    let mut s = binary.as_os_str().to_owned();
    s.push(".rsdbg.redb");
    PathBuf::from(s)
}

/// Size of the project DB file in bytes.
///
/// Returns `0` when no sidecar exists yet (a project opened but never
/// saved has no file to measure). Used by the `stats` command so
/// operators see the storage cost of a cached snapshot.
///
/// # Errors
/// [`Error::Storage`] when the path exists but its metadata is unreadable.
pub fn db_file_size(path: &Path) -> Result<u64> {
    match std::fs::metadata(path) {
        Ok(m) => Ok(m.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(Error::Storage(format!("stat {}: {e}", path.display()))),
    }
}

/// Reclaim free pages in the project DB file (`redb` compaction).
///
/// `save` rewrites every table, so repeated re-analysis can leave free
/// pages behind; compaction shrinks the file back down. Returns `true`
/// when compaction reclaimed space. There is no separate vacuum step:
/// `redb` has no `VACUUM` command, `compact` is the equivalent.
///
/// # Errors
/// [`Error::Storage`] when the file cannot be opened or compacted
/// (e.g. another process holds a live transaction on it).
pub fn compact_db(path: &Path) -> Result<bool> {
    let mut db = open_db(path)?;
    db.compact()
        .map_err(|e| Error::Storage(format!("compact {}: {e}", path.display())))
}

/// Canonical arch string used in [`BinaryMeta`] and [`ProjectInfo`].
#[must_use]
pub fn arch_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "x86_64",
        Arch::X86_32 => "x86_32",
        Arch::Aarch64 => "aarch64",
        Arch::Arm32 => "arm32",
        Arch::Thumb => "thumb",
    }
}

/// Inverse of [`arch_name`].
///
/// # Errors
/// [`Error::Storage`] on an unknown persisted value (corrupt/forged DB).
pub fn parse_arch(s: &str) -> Result<Arch> {
    match s {
        "x86_64" => Ok(Arch::X86_64),
        "x86_32" => Ok(Arch::X86_32),
        "aarch64" => Ok(Arch::Aarch64),
        "arm32" => Ok(Arch::Arm32),
        "thumb" => Ok(Arch::Thumb),
        other => Err(Error::Storage(format!(
            "unknown arch in project db: {other}"
        ))),
    }
}

/// Canonical format string used in [`BinaryMeta`] and [`ProjectInfo`].
#[must_use]
pub fn format_name(format: BinaryFormat) -> &'static str {
    match format {
        BinaryFormat::Elf => "elf",
        BinaryFormat::Pe => "pe",
        BinaryFormat::MachO => "macho",
        BinaryFormat::Coff => "coff",
        BinaryFormat::Le => "le",
        BinaryFormat::Raw => "raw",
    }
}

/// Inverse of [`format_name`].
///
/// # Errors
/// [`Error::Storage`] on an unknown persisted value (corrupt/forged DB).
pub fn parse_format(s: &str) -> Result<BinaryFormat> {
    match s {
        "elf" => Ok(BinaryFormat::Elf),
        "pe" => Ok(BinaryFormat::Pe),
        "macho" => Ok(BinaryFormat::MachO),
        "coff" => Ok(BinaryFormat::Coff),
        "le" => Ok(BinaryFormat::Le),
        "raw" => Ok(BinaryFormat::Raw),
        other => Err(Error::Storage(format!(
            "unknown format in project db: {other}"
        ))),
    }
}

/// Effective loader configuration recorded in a snapshot.
///
/// `Auto` means the binary was opened without explicit raw options
/// (container parse with raw x86-64-at-0 fallback for unrecognized bytes).
/// `Explicit` records the caller-supplied raw mapping. `Fat` records a fat
/// Mach-O slice open by canonical slice arch name: different slices never
/// share snapshots, even over identical container bytes. Auto, explicit,
/// and fat never alias each other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum StoredMapping {
    /// Opened without explicit raw options.
    Auto,
    /// Opened with explicit raw `arch`/`base`/`entry`.
    Explicit {
        /// Canonical arch string (see [`arch_name`]).
        arch: String,
        /// Virtual address of the first byte.
        base: u64,
        /// Entry-point address, if supplied.
        entry: Option<u64>,
    },
    /// Opened with a fat Mach-O slice selection.
    Fat {
        /// Canonical slice arch name (see
        /// [`crate::loader::load_with_slice`]).
        arch: String,
    },
}

impl StoredMapping {
    /// Mapping identity for an open request (`None` = auto detection).
    #[must_use]
    pub fn for_request(raw: Option<crate::loader::RawOptions>) -> Self {
        match raw {
            None => Self::Auto,
            Some(opts) => Self::Explicit {
                arch: arch_name(opts.arch).to_string(),
                base: opts.base,
                entry: opts.entry,
            },
        }
    }

    /// Mapping identity for a fat Mach-O slice open.
    ///
    /// `arch` is the caller-supplied slice selector (the CLI `--fat-arch` /
    /// MCP `fat_arch` value the follow-up plumbing passes through
    /// unchanged); it canonicalizes through
    /// [`crate::loader::normalize_fat_selector`] so aliases share one
    /// snapshot (`arm64` ≡ `aarch64`, `x86-64` ≡ `x86_64`,
    /// case-insensitively). Unknown spellings lowercase as before; the
    /// loader rejects them at open, so they never persist a snapshot.
    #[must_use]
    pub fn for_fat_slice(arch: &str) -> Self {
        Self::Fat {
            arch: crate::loader::normalize_fat_selector(arch)
                .map(str::to_string)
                .unwrap_or_else(|| arch.to_lowercase()),
        }
    }

    /// One-line description for mapping-conflict errors.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Auto => "auto".to_string(),
            Self::Explicit { arch, base, entry } => match entry {
                Some(e) => format!("explicit raw {arch} base {base:#x} entry {e:#x}"),
                None => format!("explicit raw {arch} base {base:#x}"),
            },
            Self::Fat { arch } => format!("fat slice {arch}"),
        }
    }
}

/// Mapping-conflict error: the sidecar holds `stored_count` live
/// annotation(s) under `stored`, but the current open requests `expected`.
///
/// Annotations are never remapped across address spaces; the caller must
/// open with a separate `--db PATH` for this mapping.
fn mapping_conflict(
    stored: &StoredMapping,
    stored_count: usize,
    expected: &StoredMapping,
) -> Error {
    Error::Storage(format!(
        "mapping mismatch: project db holds {stored_count} annotation(s) under {}, but current open requests {}; use a separate --db PATH for this mapping (annotations are never remapped)",
        stored.describe(),
        expected.describe(),
    ))
}

/// Legacy-ambiguous error: a pre-mapping snapshot holds annotations whose
/// address space cannot be established, so no mapping can safely reuse it.
fn legacy_ambiguous(stored_count: usize, version: u32) -> Error {
    Error::Storage(format!(
        "mapping mismatch: project db holds {stored_count} annotation(s) under an unknown legacy mapping (schema v{version}); use a separate --db PATH for this mapping (annotations are never remapped)"
    ))
}

/// What binary a snapshot was taken over; row 0 of the `binaries` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryMeta {
    /// Snapshot schema version.
    pub version: u32,
    /// Analyzed binary path.
    pub binary_path: String,
    /// Hash of the file contents.
    pub content_hash: u64,
    /// Hex SHA-256 of the file contents.
    ///
    /// Strengthens [`BinaryMeta::content_hash`] (FNV-1a-64) against
    /// collisions: cache identity compares both plus [`BinaryMeta::size`].
    /// Defaults to empty so pre-v6 snapshots without the field still
    /// decode; such snapshots never hit the cache (empty never equals a
    /// real digest) and re-analyze instead.
    #[serde(default)]
    pub content_sha256: String,
    /// File size in bytes.
    pub size: u64,
    /// Architecture string.
    pub arch: String,
    /// Format string.
    pub format: String,
    /// Entry-point address, if known.
    pub entry: Option<u64>,
    /// Whether the format is supported for analysis.
    ///
    /// Always true for persisted snapshots: only successfully opened
    /// (hence supported) formats are saved. Defaults to true so pre-L1
    /// snapshots without the field still decode.
    #[serde(default = "default_supported")]
    pub supported: bool,
    /// Why `supported` is false, if so.
    #[serde(default)]
    pub reason: Option<String>,
    /// Effective loader mapping the snapshot was taken over.
    ///
    /// `None` marks a pre-v3 snapshot whose mapping cannot be established;
    /// such snapshots are rebuilt, never trusted, and require a separate DB
    /// when they hold annotations.
    #[serde(default)]
    pub mapping: Option<StoredMapping>,
    /// Analysis revision the snapshot was taken over.
    ///
    /// `None` marks a pre-v3 snapshot; a mismatch re-analyzes while
    /// carrying same-mapping annotations forward.
    #[serde(default)]
    pub analysis_rev: Option<u32>,
    /// Whether discovery produced more diagnostics than the record cap.
    ///
    /// Defaults to false so pre-v4 snapshots without the field still
    /// decode; such snapshots never hit the cache (their schema version
    /// mismatches) and re-analyze instead.
    #[serde(default)]
    pub diagnostics_truncated: bool,
    /// Diagnostics omitted by the record cap (zero unless truncated).
    ///
    /// Defaults to zero for pre-v4 snapshots; see
    /// [`BinaryMeta::diagnostics_truncated`].
    #[serde(default)]
    pub diagnostics_omitted: usize,
    /// Whether indirect-jump resolution produced more inferred edges than
    /// the project cap.
    ///
    /// Defaults to false so pre-v5 snapshots without the field still
    /// decode; such snapshots never hit the cache (their schema version
    /// mismatches) and re-analyze instead.
    #[serde(default)]
    pub inferred_truncated: bool,
    /// Inferred edges omitted by the project cap (zero unless truncated).
    ///
    /// Defaults to zero for pre-v5 snapshots; see
    /// [`BinaryMeta::inferred_truncated`].
    #[serde(default)]
    pub inferred_omitted: usize,
}

fn default_supported() -> bool {
    true
}

impl BinaryMeta {
    /// Equality for fast annotation writes: all content identity except host path.
    ///
    /// [`BinaryMeta::binary_path`] is display-only: opening the same file as
    /// `./a` versus `/abs/a` must take the single-row fast path, not force a
    /// full-snapshot fallback. Every other field (hash, SHA-256, size, arch,
    /// format, entry, mapping, revisions, truncation flags) still gates the
    /// fast path.
    #[must_use]
    pub fn fast_write_eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.content_hash == other.content_hash
            && self.content_sha256 == other.content_sha256
            && self.size == other.size
            && self.arch == other.arch
            && self.format == other.format
            && self.entry == other.entry
            && self.supported == other.supported
            && self.reason == other.reason
            && self.mapping == other.mapping
            && self.analysis_rev == other.analysis_rev
            && self.diagnostics_truncated == other.diagnostics_truncated
            && self.diagnostics_omitted == other.diagnostics_omitted
            && self.inferred_truncated == other.inferred_truncated
            && self.inferred_omitted == other.inferred_omitted
    }
}

/// Whether stale annotations plausibly belong to the current binary.
///
/// True when the stored snapshot names the same host path, or when the
/// stored arch, format, and entry all match the freshly loaded binary.
/// Otherwise the sidecar was reused for an unrelated binary and its
/// renames/comments must be dropped rather than carried by address.
#[must_use]
pub fn stale_carry_plausible(
    stored: &BinaryMeta,
    current_path: &str,
    current_arch: &str,
    current_format: &str,
    current_entry: Option<u64>,
) -> bool {
    if stored.binary_path == current_path {
        return true;
    }
    stored.arch == current_arch && stored.format == current_format && stored.entry == current_entry
}

/// One function row: export name plus sorted direct callees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionRecord {
    /// Function entry address.
    pub entry: u64,
    /// Export name or rename, if any.
    pub name: Option<String>,
    /// Sorted direct callees.
    pub calls: Vec<u64>,
    /// Sorted, deduplicated discovery reasons.
    ///
    /// Defaults to empty so layouts written before provenance tracking
    /// still decode; such snapshots never hit the cache (their analysis
    /// revision mismatches) and re-analyze instead.
    #[serde(default)]
    pub reasons: Vec<crate::analysis::DiscoveryReason>,
}

/// One basic-block row: address range, per-instruction boundaries, and
/// sorted successors.
///
/// Instructions are not stored; the open path re-decodes each recorded
/// `(address, size)` boundary from the binary (see
/// [`crate::analysis::rebuild`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRecord {
    /// Owning function entry.
    pub func_entry: u64,
    /// Address of the first instruction.
    pub start: u64,
    /// End address (one past the last byte).
    pub end: u64,
    /// `(address, size)` of every instruction in address order.
    pub insns: Vec<crate::analysis::InsnLayout>,
    /// Successor block starts.
    pub succs: Vec<u64>,
    /// Inferred successor block starts from resolved single-slot indirect
    /// jumps; direct successors stay in [`BlockRecord::succs`].
    ///
    /// Defaults to empty so rows written before inference still decode;
    /// such snapshots never hit the cache (their analysis revision
    /// mismatches) and re-analyze instead.
    #[serde(default)]
    pub inferred_succs: Vec<u64>,
}

/// User annotation at one address: rename and/or free-text comment.
///
/// Stored only in the project DB; the analyzed binary is never modified.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Annotation {
    /// Function rename.
    pub name: Option<String>,
    /// Free-text comment.
    pub comment: Option<String>,
}

impl Annotation {
    /// Whether both fields are empty (row can be dropped).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.name.as_deref().is_none_or(str::is_empty)
            && self.comment.as_deref().is_none_or(str::is_empty)
    }
}

/// Agent-facing project summary; always JSON-serializable (M6 CLI/MCP).
///
/// JSON pairs `entry` with `entry_hex` (`null` on both sides when the
/// container names no entry) and `base` with `base_hex` (`null` on both
/// sides in auto mode).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProjectInfo {
    /// Analyzed binary path.
    pub binary: String,
    /// Sidecar DB path.
    pub db_path: String,
    /// Crate version.
    pub version: String,
    /// Wire protocol revision (see `docs/book/src/json-protocol.md`).
    #[serde(default = "default_protocol")]
    pub protocol: u32,
    /// Effective loader mode: `"auto"`, `"raw"`, or `"fat"`.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Effective raw base address (`None` in auto mode).
    #[serde(default)]
    pub base: Option<u64>,
    /// Architecture string.
    pub arch: String,
    /// Format string.
    pub format: String,
    /// Entry-point address, if known.
    pub entry: Option<u64>,
    /// Hash of the file contents.
    pub content_hash: u64,
    /// File size in bytes.
    pub size: u64,
    /// Whether the format is supported for analysis.
    ///
    /// Always true for successfully opened projects: unsupported formats
    /// fail at open instead of returning a `supported:false` project.
    ///
    /// [`Error::Unsupported`]: crate::error::Error::Unsupported
    #[serde(default = "default_supported")]
    pub supported: bool,
    /// Why `supported` is false, if so.
    #[serde(default)]
    pub reason: Option<String>,
    /// Discovered functions.
    pub functions: usize,
    /// Basic blocks across all functions.
    pub blocks: usize,
    /// Decoded instructions.
    pub insns: usize,
    /// Recorded cross-references.
    pub xrefs: usize,
    /// Extracted strings.
    pub strings: usize,
    /// Stored annotations.
    pub annotations: usize,
    /// Retained diagnostic records (see [`crate::analysis::Diagnostics`]).
    ///
    /// Evidence about where analysis is incomplete, not a completeness
    /// proof: zero retained diagnostics never means complete recovery.
    #[serde(default)]
    pub diagnostics: usize,
    /// Whether discovery produced more diagnostics than the record cap.
    #[serde(default)]
    pub diagnostics_truncated: bool,
    /// Diagnostics omitted by the record cap (zero unless truncated).
    #[serde(default)]
    pub diagnostics_omitted: usize,
    /// Whether indirect-jump resolution produced more inferred edges than
    /// the project cap (see [`crate::analysis::Diagnostics`]).
    #[serde(default)]
    pub inferred_truncated: bool,
    /// Inferred edges omitted by the project cap (zero unless truncated).
    #[serde(default)]
    pub inferred_omitted: usize,
    /// Analysis revision the in-memory result was taken over (see
    /// [`crate::analysis::ANALYSIS_REVISION`]).
    #[serde(default)]
    pub analysis_revision: u32,
}

fn default_protocol() -> u32 {
    crate::WIRE_PROTOCOL
}

fn default_mode() -> String {
    "auto".to_string()
}

impl Serialize for ProjectInfo {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("ProjectInfo", 27)?;
        st.serialize_field("binary", &self.binary)?;
        st.serialize_field("db_path", &self.db_path)?;
        st.serialize_field("version", &self.version)?;
        st.serialize_field("protocol", &self.protocol)?;
        st.serialize_field("mode", &self.mode)?;
        st.serialize_field("base", &self.base)?;
        st.serialize_field("base_hex", &self.base.map(crate::addr_hex))?;
        st.serialize_field("arch", &self.arch)?;
        st.serialize_field("format", &self.format)?;
        st.serialize_field("entry", &self.entry)?;
        st.serialize_field("entry_hex", &self.entry.map(crate::addr_hex))?;
        st.serialize_field("content_hash", &self.content_hash)?;
        st.serialize_field("size", &self.size)?;
        st.serialize_field("supported", &self.supported)?;
        st.serialize_field("reason", &self.reason)?;
        st.serialize_field("functions", &self.functions)?;
        st.serialize_field("blocks", &self.blocks)?;
        st.serialize_field("insns", &self.insns)?;
        st.serialize_field("xrefs", &self.xrefs)?;
        st.serialize_field("strings", &self.strings)?;
        st.serialize_field("annotations", &self.annotations)?;
        st.serialize_field("diagnostics", &self.diagnostics)?;
        st.serialize_field("diagnostics_truncated", &self.diagnostics_truncated)?;
        st.serialize_field("diagnostics_omitted", &self.diagnostics_omitted)?;
        st.serialize_field("inferred_truncated", &self.inferred_truncated)?;
        st.serialize_field("inferred_omitted", &self.inferred_omitted)?;
        st.serialize_field("analysis_revision", &self.analysis_revision)?;
        st.end()
    }
}

/// Snapshot read back by [`load`]: metadata, cached layouts, annotations.
///
/// Instructions are not included; the caller rebuilds the [`Analysis`]
/// from the layouts plus the binary via
/// [`rebuild`](crate::analysis::rebuild).
#[derive(Debug)]
pub struct Loaded {
    /// Snapshot metadata (row 0).
    pub meta: BinaryMeta,
    /// Disassembler target the snapshot was taken as.
    pub arch: Arch,
    /// Cached function layouts (entry, name, callees, block ranges, reasons).
    pub functions: Vec<FunctionLayout>,
    /// Cached callgraph edges as `(caller, callee)` pairs.
    pub call_edges: Vec<(u64, u64)>,
    /// Cached cross-references.
    pub xrefs: Vec<Xref>,
    /// Cached extracted strings.
    pub strings: Vec<StringHit>,
    /// Cached diagnostics sorted by `(addr, kind)`.
    pub diagnostics: Vec<crate::analysis::Diagnostic>,
    /// Annotations keyed by address.
    pub annotations: BTreeMap<u64, Annotation>,
}

impl Loaded {
    /// Re-decode snapshot instructions from `bin` into a full [`Analysis`].
    ///
    /// The snapshot holds block layouts only; this steps each range with the
    /// same decoder the analysis walker uses, so the result equals a fresh
    /// analysis of the same bytes — including identical diagnostics and
    /// discovery reasons. Stored annotations are not part of the
    /// returned value; read [`Loaded::annotations`] directly.
    ///
    /// # Errors
    /// [`Error::Storage`] on corrupt layouts (see
    /// [`rebuild`](crate::analysis::rebuild)), [`Error::Limit`] past
    /// analysis budgets.
    pub fn rebuild(self, bin: &crate::loader::LoadedBinary) -> Result<Analysis> {
        crate::analysis::rebuild(
            self.arch,
            bin,
            &self.functions,
            &self.call_edges,
            self.xrefs,
            self.strings,
            crate::analysis::Diagnostics {
                records: self.diagnostics,
                truncated: self.meta.diagnostics_truncated,
                omitted: self.meta.diagnostics_omitted,
                inferred_truncated: self.meta.inferred_truncated,
                inferred_omitted: self.meta.inferred_omitted,
            },
        )
    }
}

/// Open (creating if needed) the project DB at `path`.
///
/// Scope this to writers ([`save`], [`save_annotation`], [`compact_db`]):
/// read paths take [`open_db_read_only`] so a large sidecar costs no
/// write-side open work and reads never create the file.
///
/// # Errors
/// [`Error::Storage`] when the file cannot be created or opened.
pub fn open_db(path: &Path) -> Result<Database> {
    Database::create(path).map_err(|e| Error::Storage(format!("open db: {e}")))
}

/// Open the project DB at `path` for reads only.
///
/// Unlike [`open_db`] this never creates the file, never takes the write
/// lock, and skips write-side open work that scales with the file (debug
/// builds of `redb` walk every page on writable open, which made opening a
/// small binary against a large stale sidecar cost seconds and hundreds of
/// megabytes). All [`Project`](crate::Project) read opens use this; writers
/// open separately via [`open_db`].
///
/// # Errors
/// [`Error::Storage`] when the file does not exist or cannot be opened.
pub fn open_db_read_only(path: &Path) -> Result<redb::ReadOnlyDatabase> {
    redb::Database::builder()
        .open_read_only(path)
        .map_err(|e| Error::Storage(format!("open db: {e}")))
}

fn block_key(func_entry: u64, start: u64) -> String {
    format!("{func_entry:016x}:{start:016x}")
}

fn xref_kind_name(kind: crate::analysis::XrefKind) -> &'static str {
    match kind {
        crate::analysis::XrefKind::Code => "code",
        crate::analysis::XrefKind::Data => "data",
        crate::analysis::XrefKind::String => "string",
        crate::analysis::XrefKind::Import => "import",
        crate::analysis::XrefKind::InferredCode => "inferred-code",
    }
}

fn xref_key(x: &Xref) -> String {
    format!("{:016x}:{}:{:016x}", x.from, xref_kind_name(x.kind), x.to)
}

fn diagnostic_kind_name(kind: crate::analysis::DiagnosticKind) -> &'static str {
    match kind {
        crate::analysis::DiagnosticKind::UnresolvedIndirectJump => "indirect_jump",
        crate::analysis::DiagnosticKind::UnresolvedIndirectCall => "indirect_call",
        crate::analysis::DiagnosticKind::DecodeFailure => "decode_failure",
    }
}

fn diagnostic_key(d: &crate::analysis::Diagnostic) -> String {
    format!("{:016x}:{}", d.addr, diagnostic_kind_name(d.kind))
}

fn json<T: Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|e| Error::Storage(format!("encode row: {e}")))
}

fn decode<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T> {
    serde_json::from_str(s).map_err(|e| Error::Storage(format!("decode row: {e}")))
}

/// Reject one annotation whose name/comment exceeds the per-field budget.
///
/// 8 KiB bounds a single row before it ever reaches the sidecar.
fn check_annotation_text(ann: &Annotation) -> Result<()> {
    for (label, s) in [("name", &ann.name), ("comment", &ann.comment)] {
        if let Some(t) = s
            && t.len() > MAX_ANNOTATION_BYTES
        {
            return Err(Error::Limit(format!(
                "annotation {label} of {} bytes exceeds {MAX_ANNOTATION_BYTES}",
                t.len()
            )));
        }
    }
    Ok(())
}

/// Pre-write row-count budget check so [`save`] never writes a snapshot
/// that [`load`] would reject. Counts mirror the analysis caps plus the
/// annotation cap.
fn check_analysis_budgets(
    analysis: &Analysis,
    annotations: &BTreeMap<u64, Annotation>,
) -> Result<()> {
    if analysis.functions.len() > MAX_SNAPSHOT_FUNCTIONS {
        return Err(Error::Limit("snapshot functions exceed cap".to_string()));
    }
    let blocks: usize = analysis.functions.values().map(|f| f.blocks.len()).sum();
    if blocks > MAX_SNAPSHOT_BLOCKS {
        return Err(Error::Limit("snapshot blocks exceed cap".to_string()));
    }
    if analysis.xrefs.len() > MAX_SNAPSHOT_XREFS {
        return Err(Error::Limit("snapshot xrefs exceed cap".to_string()));
    }
    if analysis.strings.len() > MAX_SNAPSHOT_STRINGS {
        return Err(Error::Limit("snapshot strings exceed cap".to_string()));
    }
    if analysis.diagnostics.records.len() > MAX_SNAPSHOT_DIAGNOSTICS {
        return Err(Error::Limit("snapshot diagnostics exceed cap".to_string()));
    }
    let inferred: usize = analysis.functions.values().map(|f| f.inferred_len()).sum();
    if inferred > MAX_SNAPSHOT_INFERRED_EDGES {
        return Err(Error::Limit(
            "snapshot inferred edges exceed cap".to_string(),
        ));
    }
    let live = annotations.values().filter(|a| !a.is_empty()).count();
    if live > MAX_SNAPSHOT_ANNOTATIONS {
        return Err(Error::Limit("snapshot annotations exceed cap".to_string()));
    }
    for ann in annotations.values() {
        if !ann.is_empty() {
            check_annotation_text(ann)?;
        }
    }
    Ok(())
}

fn delete_if_exists(wtxn: &redb::WriteTransaction, table: &str) -> Result<()> {
    let deleted = match table {
        "meta" => wtxn.delete_table(META),
        "binaries" => wtxn.delete_table(BINARIES),
        "functions" => wtxn.delete_table(FUNCTIONS),
        "blocks" => wtxn.delete_table(BLOCKS),
        "xrefs" => wtxn.delete_table(XREFS),
        "strings" => wtxn.delete_table(STRINGS),
        "annotations" => wtxn.delete_table(ANNOTATIONS),
        "diagnostics" => wtxn.delete_table(DIAGNOSTICS),
        _ => return Err(Error::Storage(format!("unknown table {table}"))),
    };
    match deleted {
        Ok(_) => Ok(()),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(()),
        Err(e) => Err(Error::Storage(format!("clear {table}: {e}"))),
    }
}

/// Count live (non-empty) annotation rows inside a write transaction.
///
/// Used by writers to decide whether overwriting a mapping-incompatible
/// snapshot would drop user data. Corrupt rows error rather than reading
/// as empty.
fn live_annotations_in_wtxn(wtxn: &redb::WriteTransaction) -> Result<usize> {
    let t = wtxn
        .open_table(ANNOTATIONS)
        .map_err(|e| Error::Storage(format!("open annotations: {e}")))?;
    let mut live = 0usize;
    for row in t
        .iter()
        .map_err(|e| Error::Storage(format!("read annotations: {e}")))?
    {
        let (_, v) = row.map_err(|e| Error::Storage(format!("read annotations: {e}")))?;
        let ann: Annotation = decode(&v.value())?;
        check_annotation_text(&ann)?;
        if !ann.is_empty() {
            live += 1;
        }
    }
    Ok(live)
}

/// Outcome of [`save_annotation`]: whether the single-row fast path applied.
///
/// [`AnnotationSave::Fast`] means only the `annotations` table changed;
/// [`AnnotationSave::NeedsFull`] means there is no matching snapshot and the
/// caller must fall back to [`save`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationSave {
    /// Single annotation row inserted/deleted; analysis tables untouched.
    Fast,
    /// No matching snapshot (fresh DB or metadata mismatch); needs full save.
    NeedsFull,
}

/// Persist one annotation row when the durable snapshot matches `meta`.
///
/// Reads the persisted `meta`/`binaries` rows inside the same write
/// transaction that would modify `annotations`, so an annotation never lands
/// on a snapshot written for different bytes by another process. On match,
/// inserts (`Some` non-empty) or deletes (`None`/empty) only that row and
/// commits; the `functions`/`blocks`/`xrefs`/`strings` tables are never
/// opened for writing. Identity ignores [`BinaryMeta::binary_path`]
/// (see [`BinaryMeta::fast_write_eq`]): opening the same file via
/// different relative/absolute spellings still takes the fast path.
/// On a fresh DB or any content/revision mismatch under
/// the same mapping, aborts without writing and returns
/// [`AnnotationSave::NeedsFull`]. A populated sidecar under an incompatible
/// mapping (or an ambiguous legacy mapping) errors instead of returning
/// `NeedsFull`, so a single-row write never migrates annotations across
/// address spaces. Never touches the analyzed binary.
///
/// # Errors
/// [`Error::Limit`] when the annotation text exceeds
/// [`MAX_ANNOTATION_BYTES`], [`Error::Storage`] on any `redb` or encoding
/// failure (including write contention with another process) and on
/// mapping conflicts holding live annotations.
pub fn save_annotation(
    db: &Database,
    meta: &BinaryMeta,
    addr: u64,
    ann: Option<&Annotation>,
) -> Result<AnnotationSave> {
    if let Some(a) = ann
        && !a.is_empty()
    {
        check_annotation_text(a)?;
    }
    let encoded: Option<String> = match ann {
        Some(a) if !a.is_empty() => Some(json(a)?),
        _ => None,
    };
    let wtxn = db
        .begin_write()
        .map_err(|e| Error::Storage(format!("begin write: {e}")))?;
    {
        let meta_table = wtxn
            .open_table(META)
            .map_err(|e| Error::Storage(format!("open meta: {e}")))?;
        let version = meta_table
            .get("version")
            .map_err(|e| Error::Storage(format!("read meta: {e}")))?;
        if version.is_none() {
            return Ok(AnnotationSave::NeedsFull);
        }
    }
    {
        let binaries = wtxn
            .open_table(BINARIES)
            .map_err(|e| Error::Storage(format!("open binaries: {e}")))?;
        let row = binaries
            .get(0u64)
            .map_err(|e| Error::Storage(format!("read binaries: {e}")))?;
        let Some(row) = row else {
            return Ok(AnnotationSave::NeedsFull);
        };
        let persisted: BinaryMeta = decode(&row.value())?;
        if persisted.mapping != meta.mapping {
            let live = live_annotations_in_wtxn(&wtxn)?;
            if live > 0 {
                let expected = meta.mapping.clone().unwrap_or(StoredMapping::Auto);
                match persisted.mapping {
                    Some(stored) => return Err(mapping_conflict(&stored, live, &expected)),
                    None => return Err(legacy_ambiguous(live, persisted.version)),
                }
            }
            return Ok(AnnotationSave::NeedsFull);
        }
        if !persisted.fast_write_eq(meta) {
            return Ok(AnnotationSave::NeedsFull);
        }
    }
    {
        let mut t = wtxn
            .open_table(ANNOTATIONS)
            .map_err(|e| Error::Storage(format!("open annotations: {e}")))?;
        match encoded {
            Some(s) => {
                t.insert(addr, s)
                    .map_err(|e| Error::Storage(format!("write annotations: {e}")))?;
            }
            None => {
                t.remove(addr)
                    .map_err(|e| Error::Storage(format!("remove annotations: {e}")))?;
            }
        }
    }
    wtxn.commit()
        .map_err(|e| Error::Storage(format!("commit: {e}")))?;
    Ok(AnnotationSave::Fast)
}

/// Persist validated annotation rows in one transaction, for imports.
///
/// Same guards as [`save_annotation`], applied once for the whole batch:
/// reads the persisted `meta`/`binaries` rows inside the write transaction
/// that applies every change, so rows never land on a snapshot written for
/// different bytes by another process. Identity ignores
/// [`BinaryMeta::binary_path`] (see [`BinaryMeta::fast_write_eq`]).
/// On match, upserts (`Some` non-empty)
/// or deletes (`None`) every entry of `changes` and commits once; the
/// `functions`/`blocks`/`xrefs`/`strings` tables are never opened for
/// writing. An empty `changes` map commits nothing and returns
/// [`AnnotationSave::Fast`]. On a fresh DB or any content/revision mismatch
/// under the same mapping, aborts without writing and returns
/// [`AnnotationSave::NeedsFull`]. A populated sidecar under an incompatible
/// mapping (or an ambiguous legacy mapping) errors instead of returning
/// `NeedsFull`, so a batch write never migrates annotations across address
/// spaces. Validate the document fully before calling: this commits
/// everything or nothing at the storage layer, but semantic validation is
/// the caller's job. Never touches the analyzed binary.
///
/// # Errors
/// [`Error::Limit`] when an annotation text exceeds
/// [`MAX_ANNOTATION_BYTES`], [`Error::Storage`] on any `redb` or encoding
/// failure (including write contention with another process) and on
/// mapping conflicts holding live annotations.
pub fn save_annotation_batch(
    db: &Database,
    meta: &BinaryMeta,
    changes: &BTreeMap<u64, Option<Annotation>>,
) -> Result<AnnotationSave> {
    for ann in changes.values().flatten() {
        check_annotation_text(ann)?;
    }
    if changes.is_empty() {
        return Ok(AnnotationSave::Fast);
    }
    let wtxn = db
        .begin_write()
        .map_err(|e| Error::Storage(format!("begin write: {e}")))?;
    {
        let meta_table = wtxn
            .open_table(META)
            .map_err(|e| Error::Storage(format!("open meta: {e}")))?;
        let version = meta_table
            .get("version")
            .map_err(|e| Error::Storage(format!("read meta: {e}")))?;
        if version.is_none() {
            return Ok(AnnotationSave::NeedsFull);
        }
    }
    {
        let binaries = wtxn
            .open_table(BINARIES)
            .map_err(|e| Error::Storage(format!("open binaries: {e}")))?;
        let row = binaries
            .get(0u64)
            .map_err(|e| Error::Storage(format!("read binaries: {e}")))?;
        let Some(row) = row else {
            return Ok(AnnotationSave::NeedsFull);
        };
        let persisted: BinaryMeta = decode(&row.value())?;
        if persisted.mapping != meta.mapping {
            let live = live_annotations_in_wtxn(&wtxn)?;
            if live > 0 {
                let expected = meta.mapping.clone().unwrap_or(StoredMapping::Auto);
                match persisted.mapping {
                    Some(stored) => return Err(mapping_conflict(&stored, live, &expected)),
                    None => return Err(legacy_ambiguous(live, persisted.version)),
                }
            }
            return Ok(AnnotationSave::NeedsFull);
        }
        if !persisted.fast_write_eq(meta) {
            return Ok(AnnotationSave::NeedsFull);
        }
    }
    {
        let mut t = wtxn
            .open_table(ANNOTATIONS)
            .map_err(|e| Error::Storage(format!("open annotations: {e}")))?;
        for (&addr, next) in changes {
            match next {
                Some(ann) => {
                    t.insert(addr, json(ann)?)
                        .map_err(|e| Error::Storage(format!("write annotations: {e}")))?;
                }
                None => {
                    t.remove(addr)
                        .map_err(|e| Error::Storage(format!("remove annotations: {e}")))?;
                }
            }
        }
    }
    wtxn.commit()
        .map_err(|e| Error::Storage(format!("commit: {e}")))?;
    Ok(AnnotationSave::Fast)
}

/// Refuse to overwrite a populated snapshot under an incompatible mapping.
///
/// Reads the existing `binaries` row plus live annotations inside the same
/// write transaction the caller will commit, so a concurrent mapping change
/// cannot slip past the check. A fresh DB (no version marker or binary row)
/// never conflicts; an incompatible or ambiguous legacy mapping with live
/// annotations errors, while an empty sidecar overwrites freely.
fn reject_mapping_overwrite(wtxn: &redb::WriteTransaction, meta: &BinaryMeta) -> Result<()> {
    let version: Option<String> = {
        let t = wtxn
            .open_table(META)
            .map_err(|e| Error::Storage(format!("open meta: {e}")))?;
        t.get("version")
            .map_err(|e| Error::Storage(format!("read meta: {e}")))?
            .map(|v| v.value())
    };
    let Some(_) = version else {
        return Ok(());
    };
    let persisted: Option<BinaryMeta> = {
        let t = wtxn
            .open_table(BINARIES)
            .map_err(|e| Error::Storage(format!("open binaries: {e}")))?;
        match t
            .get(0u64)
            .map_err(|e| Error::Storage(format!("read binaries: {e}")))?
        {
            Some(row) => Some(decode(&row.value())?),
            None => None,
        }
    };
    let Some(persisted) = persisted else {
        return Ok(());
    };
    if persisted.mapping == meta.mapping {
        return Ok(());
    }
    let live = live_annotations_in_wtxn(wtxn)?;
    if live == 0 {
        return Ok(());
    }
    let expected = meta.mapping.clone().unwrap_or(StoredMapping::Auto);
    match persisted.mapping {
        Some(stored) => Err(mapping_conflict(&stored, live, &expected)),
        None => Err(legacy_ambiguous(live, persisted.version)),
    }
}

/// Persist `meta`, `analysis`, and `annotations` to `db` in one transaction.
///
/// Clears all eight tables first so a smaller re-analysis leaves no stale
/// rows. Row counts are checked against the snapshot budgets before
/// committing, so a snapshot that [`load`] could not read back is never
/// written. Only block layouts persist; instructions re-decode on open.
/// Never touches the analyzed binary. Overwriting a populated sidecar under
/// an incompatible (or ambiguous legacy) mapping errors instead of dropping
/// annotations; use a separate DB path for the new mapping.
///
/// # Errors
/// [`Error::Limit`] when row budgets are exceeded,
/// [`Error::Storage`] on any `redb` or encoding failure, and on mapping
/// conflicts holding live annotations.
pub fn save(
    db: &Database,
    meta: &BinaryMeta,
    analysis: &Analysis,
    annotations: &BTreeMap<u64, Annotation>,
) -> Result<()> {
    check_analysis_budgets(analysis, annotations)?;
    let wtxn = db
        .begin_write()
        .map_err(|e| Error::Storage(format!("begin write: {e}")))?;
    reject_mapping_overwrite(&wtxn, meta)?;
    for t in [
        "meta",
        "binaries",
        "functions",
        "blocks",
        "xrefs",
        "strings",
        "annotations",
        "diagnostics",
    ] {
        delete_if_exists(&wtxn, t)?;
    }
    {
        let mut t = wtxn
            .open_table(META)
            .map_err(|e| Error::Storage(format!("open meta: {e}")))?;
        t.insert("version", SCHEMA_VERSION.to_string())
            .map_err(|e| Error::Storage(format!("write meta: {e}")))?;
        t.insert("binary_path", meta.binary_path.clone())
            .map_err(|e| Error::Storage(format!("write meta: {e}")))?;
        t.insert("content_hash", meta.content_hash.to_string())
            .map_err(|e| Error::Storage(format!("write meta: {e}")))?;
        t.insert("content_sha256", meta.content_sha256.clone())
            .map_err(|e| Error::Storage(format!("write meta: {e}")))?;
        t.insert("size", meta.size.to_string())
            .map_err(|e| Error::Storage(format!("write meta: {e}")))?;
        t.insert("arch", meta.arch.clone())
            .map_err(|e| Error::Storage(format!("write meta: {e}")))?;
        t.insert("format", meta.format.clone())
            .map_err(|e| Error::Storage(format!("write meta: {e}")))?;
        t.insert(
            "entry",
            meta.entry.map(|e| e.to_string()).unwrap_or_default(),
        )
        .map_err(|e| Error::Storage(format!("write meta: {e}")))?;
    }
    {
        let mut t = wtxn
            .open_table(BINARIES)
            .map_err(|e| Error::Storage(format!("open binaries: {e}")))?;
        t.insert(0u64, json(meta)?)
            .map_err(|e| Error::Storage(format!("write binaries: {e}")))?;
    }
    let layouts = crate::analysis::layout(analysis);
    {
        let mut t = wtxn
            .open_table(FUNCTIONS)
            .map_err(|e| Error::Storage(format!("open functions: {e}")))?;
        for f in &layouts {
            let rec = FunctionRecord {
                entry: f.entry,
                name: f.name.clone(),
                calls: f.calls.clone(),
                reasons: f.reasons.clone(),
            };
            t.insert(f.entry, json(&rec)?)
                .map_err(|e| Error::Storage(format!("write functions: {e}")))?;
        }
    }
    {
        let mut t = wtxn
            .open_table(BLOCKS)
            .map_err(|e| Error::Storage(format!("open blocks: {e}")))?;
        for f in &layouts {
            for b in &f.blocks {
                let rec = BlockRecord {
                    func_entry: f.entry,
                    start: b.start,
                    end: b.end,
                    insns: b.insns.clone(),
                    succs: b.succs.clone(),
                    inferred_succs: b.inferred_succs.clone(),
                };
                t.insert(block_key(f.entry, b.start), json(&rec)?)
                    .map_err(|e| Error::Storage(format!("write blocks: {e}")))?;
            }
        }
    }
    {
        let mut t = wtxn
            .open_table(XREFS)
            .map_err(|e| Error::Storage(format!("open xrefs: {e}")))?;
        for x in &analysis.xrefs {
            t.insert(xref_key(x), json(x)?)
                .map_err(|e| Error::Storage(format!("write xrefs: {e}")))?;
        }
    }
    {
        let mut t = wtxn
            .open_table(STRINGS)
            .map_err(|e| Error::Storage(format!("open strings: {e}")))?;
        for (i, h) in analysis.strings.iter().enumerate() {
            t.insert(i as u64, json(h)?)
                .map_err(|e| Error::Storage(format!("write strings: {e}")))?;
        }
    }
    {
        let mut t = wtxn
            .open_table(ANNOTATIONS)
            .map_err(|e| Error::Storage(format!("open annotations: {e}")))?;
        for (&addr, ann) in annotations {
            if ann.is_empty() {
                continue;
            }
            t.insert(addr, json(ann)?)
                .map_err(|e| Error::Storage(format!("write annotations: {e}")))?;
        }
    }
    {
        let mut t = wtxn
            .open_table(DIAGNOSTICS)
            .map_err(|e| Error::Storage(format!("open diagnostics: {e}")))?;
        for d in &analysis.diagnostics.records {
            t.insert(diagnostic_key(d), json(d)?)
                .map_err(|e| Error::Storage(format!("write diagnostics: {e}")))?;
        }
    }
    wtxn.commit()
        .map_err(|e| Error::Storage(format!("commit: {e}")))?;
    Ok(())
}

/// Read the `meta` version marker plus the `binaries` row 0.
///
/// Returns `Ok(None)` when the DB holds no snapshot yet (fresh file,
/// missing `meta` table, or no version row). A present `meta` table without
/// a `binaries` row, or an undecodable `binaries` row, is corruption and
/// errors: without metadata no hash comparison is possible.
fn read_meta_row(rtxn: &redb::ReadTransaction) -> Result<Option<BinaryMeta>> {
    let meta_table = match rtxn.open_table(META) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(Error::Storage(format!("open meta: {e}"))),
    };
    let has_version = meta_table
        .get("version")
        .map_err(|e| Error::Storage(format!("read meta: {e}")))?;
    if has_version.is_none() {
        return Ok(None);
    }
    drop(meta_table);

    let t = rtxn
        .open_table(BINARIES)
        .map_err(|e| Error::Storage(format!("open binaries: {e}")))?;
    let row = t
        .get(0u64)
        .map_err(|e| Error::Storage(format!("read binaries: {e}")))?
        .ok_or_else(|| Error::Storage("project db has meta but no binary row".to_string()))?;
    Ok(Some(decode(&row.value())?))
}

/// Current snapshot identity plus annotations, without decoding layouts.
///
/// Used by annotation-write fallbacks to merge one batch on top of rows
/// another process wrote in between: returns `None` on a fresh DB.
/// A missing annotations table reads as empty; corrupt rows still error so
/// user data is never silently dropped.
///
/// # Errors
/// [`Error::Storage`] on unreadable metadata or corrupt annotation rows.
/// [`Error::Limit`] when annotation budgets are exceeded.
pub fn load_meta_and_annotations(
    db: &Database,
) -> Result<Option<(BinaryMeta, BTreeMap<u64, Annotation>)>> {
    let rtxn = db
        .begin_read()
        .map_err(|e| Error::Storage(format!("begin read: {e}")))?;
    let Some(meta) = read_meta_row(&rtxn)? else {
        return Ok(None);
    };
    let annotations = read_annotations_or_empty(&rtxn)?;
    Ok(Some((meta, annotations)))
}

/// Persisted derived rows (`functions`/block layouts, call edges, xrefs,
/// strings, diagnostics) shared by [`load`] and the hit path of [`load_cached`].
///
/// Instructions are not part of the snapshot; the caller re-decodes them
/// from the binary via
/// [`rebuild`](crate::analysis::rebuild).
struct SnapshotParts {
    functions: Vec<FunctionLayout>,
    call_edges: Vec<(u64, u64)>,
    xrefs: Vec<Xref>,
    strings: Vec<StringHit>,
    diagnostics: Vec<crate::analysis::Diagnostic>,
}

/// Decode the derived `functions`/`blocks`/`xrefs`/`strings` tables into
/// persistable layouts.
///
/// A missing table or an undecodable row is corruption and errors; callers
/// holding a known-stale snapshot must not call this at all (see the
/// stale-cache policy on [`load_cached`]). Row counts are capped so a
/// forged sidecar fails fast with [`Error::Limit`].
fn read_snapshot_parts(rtxn: &redb::ReadTransaction) -> Result<SnapshotParts> {
    let mut records: Vec<FunctionRecord> = Vec::new();
    {
        let t = rtxn
            .open_table(FUNCTIONS)
            .map_err(|e| Error::Storage(format!("open functions: {e}")))?;
        for row in t
            .iter()
            .map_err(|e| Error::Storage(format!("read functions: {e}")))?
        {
            let (_, v) = row.map_err(|e| Error::Storage(format!("read functions: {e}")))?;
            let raw = v.value();
            if records.len() >= MAX_SNAPSHOT_FUNCTIONS {
                return Err(Error::Limit("snapshot functions exceed cap".to_string()));
            }
            records.push(decode(&raw)?);
        }
    }
    let mut blocks_by_func: BTreeMap<u64, Vec<crate::analysis::BlockLayout>> = BTreeMap::new();
    let mut block_count: usize = 0;
    let mut inferred_count: usize = 0;
    {
        let t = rtxn
            .open_table(BLOCKS)
            .map_err(|e| Error::Storage(format!("open blocks: {e}")))?;
        for row in t
            .iter()
            .map_err(|e| Error::Storage(format!("read blocks: {e}")))?
        {
            let (_, v) = row.map_err(|e| Error::Storage(format!("read blocks: {e}")))?;
            let raw = v.value();
            block_count += 1;
            if block_count > MAX_SNAPSHOT_BLOCKS {
                return Err(Error::Limit("snapshot blocks exceed cap".to_string()));
            }
            let rec: BlockRecord = decode(&raw)?;
            inferred_count += rec.inferred_succs.len();
            if inferred_count > MAX_SNAPSHOT_INFERRED_EDGES {
                return Err(Error::Limit(
                    "snapshot inferred edges exceed cap".to_string(),
                ));
            }
            blocks_by_func
                .entry(rec.func_entry)
                .or_default()
                .push(crate::analysis::BlockLayout {
                    start: rec.start,
                    end: rec.end,
                    insns: rec.insns,
                    succs: rec.succs,
                    inferred_succs: rec.inferred_succs,
                });
        }
    }
    let mut functions: Vec<FunctionLayout> = Vec::new();
    let mut call_edges: Vec<(u64, u64)> = Vec::new();
    for rec in records {
        let entry = rec.entry;
        let mut blocks = blocks_by_func.remove(&entry).unwrap_or_default();
        blocks.sort_by_key(|b| b.start);
        let mut reasons = rec.reasons.clone();
        reasons.sort_unstable();
        reasons.dedup();
        functions.push(FunctionLayout {
            entry,
            name: rec.name.clone(),
            calls: rec.calls.clone(),
            blocks,
            reasons,
        });
        call_edges.extend(rec.calls.into_iter().map(|c| (entry, c)));
    }
    let mut xrefs: Vec<Xref> = Vec::new();
    {
        let t = rtxn
            .open_table(XREFS)
            .map_err(|e| Error::Storage(format!("open xrefs: {e}")))?;
        for row in t
            .iter()
            .map_err(|e| Error::Storage(format!("read xrefs: {e}")))?
        {
            let (_, v) = row.map_err(|e| Error::Storage(format!("read xrefs: {e}")))?;
            let raw = v.value();
            if xrefs.len() >= MAX_SNAPSHOT_XREFS {
                return Err(Error::Limit("snapshot xrefs exceed cap".to_string()));
            }
            xrefs.push(decode(&raw)?);
        }
    }
    xrefs.sort_by_key(|a| (a.from, a.kind, a.to));
    let mut strings: Vec<StringHit> = Vec::new();
    {
        let t = rtxn
            .open_table(STRINGS)
            .map_err(|e| Error::Storage(format!("open strings: {e}")))?;
        for row in t
            .iter()
            .map_err(|e| Error::Storage(format!("read strings: {e}")))?
        {
            let (_, v) = row.map_err(|e| Error::Storage(format!("read strings: {e}")))?;
            let raw = v.value();
            if strings.len() >= MAX_SNAPSHOT_STRINGS {
                return Err(Error::Limit("snapshot strings exceed cap".to_string()));
            }
            strings.push(decode(&raw)?);
        }
    }
    let diagnostics = read_diagnostics(rtxn)?;
    Ok(SnapshotParts {
        functions,
        call_edges,
        xrefs,
        strings,
        diagnostics,
    })
}

/// Decode stored diagnostics, sorted by `(addr, kind)`.
///
/// A missing table or an undecodable row is corruption and errors. Row
/// counts are capped so a forged sidecar fails fast with [`Error::Limit`].
fn read_diagnostics(rtxn: &redb::ReadTransaction) -> Result<Vec<crate::analysis::Diagnostic>> {
    let t = rtxn
        .open_table(DIAGNOSTICS)
        .map_err(|e| Error::Storage(format!("open diagnostics: {e}")))?;
    let mut diagnostics: Vec<crate::analysis::Diagnostic> = Vec::new();
    for row in t
        .iter()
        .map_err(|e| Error::Storage(format!("read diagnostics: {e}")))?
    {
        let (_, v) = row.map_err(|e| Error::Storage(format!("read diagnostics: {e}")))?;
        let raw = v.value();
        if diagnostics.len() >= MAX_SNAPSHOT_DIAGNOSTICS {
            return Err(Error::Limit("snapshot diagnostics exceed cap".to_string()));
        }
        diagnostics.push(decode(&raw)?);
    }
    diagnostics.sort_unstable();
    diagnostics.dedup();
    Ok(diagnostics)
}

/// Decode every stored annotation, skipping empty rows.
///
/// A missing table or an undecodable row is corruption and errors. Row
/// counts and per-field text are capped so a forged
/// sidecar fails fast with [`Error::Limit`].
fn read_annotations(rtxn: &redb::ReadTransaction) -> Result<BTreeMap<u64, Annotation>> {
    let t = rtxn
        .open_table(ANNOTATIONS)
        .map_err(|e| Error::Storage(format!("open annotations: {e}")))?;
    let mut annotations: BTreeMap<u64, Annotation> = BTreeMap::new();
    for row in t
        .iter()
        .map_err(|e| Error::Storage(format!("read annotations: {e}")))?
    {
        let (k, v) = row.map_err(|e| Error::Storage(format!("read annotations: {e}")))?;
        let raw = v.value();
        if annotations.len() >= MAX_SNAPSHOT_ANNOTATIONS {
            return Err(Error::Limit("snapshot annotations exceed cap".to_string()));
        }
        let ann: Annotation = decode(&raw)?;
        check_annotation_text(&ann)?;
        if !ann.is_empty() {
            annotations.insert(k.value(), ann);
        }
    }
    Ok(annotations)
}

/// Decode stored annotations, reading a missing table as empty.
///
/// Stale snapshots carry annotations forward even when the sidecar has no
/// annotations table (hand-built or partially written DBs); a corrupt
/// annotation row still errors, since silently dropping user renames and
/// comments would lose data the re-analysis keeps. Same row/text
/// budgets as [`read_annotations`](fn@read_annotations) apply.
fn read_annotations_or_empty(rtxn: &redb::ReadTransaction) -> Result<BTreeMap<u64, Annotation>> {
    let t = match rtxn.open_table(ANNOTATIONS) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(BTreeMap::new()),
        Err(e) => return Err(Error::Storage(format!("open annotations: {e}"))),
    };
    let mut annotations: BTreeMap<u64, Annotation> = BTreeMap::new();
    for row in t
        .iter()
        .map_err(|e| Error::Storage(format!("read annotations: {e}")))?
    {
        let (k, v) = row.map_err(|e| Error::Storage(format!("read annotations: {e}")))?;
        let raw = v.value();
        if annotations.len() >= MAX_SNAPSHOT_ANNOTATIONS {
            return Err(Error::Limit("snapshot annotations exceed cap".to_string()));
        }
        let ann: Annotation = decode(&raw)?;
        check_annotation_text(&ann)?;
        if !ann.is_empty() {
            annotations.insert(k.value(), ann);
        }
    }
    Ok(annotations)
}

/// Hash- and mapping-filtered snapshot read back by [`load_cached`].
///
/// The stale variant carries only what a content-hash, mapping, revision, or
/// schema mismatch preserves: metadata plus annotations. Derived rows are
/// never decoded on that path (see the stale-cache policy on
/// [`load_cached`]).
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Snapshot {
    /// Stored hash, mapping, and revisions match on the current schema:
    /// cached layouts plus annotations. The caller re-decodes instructions
    /// from the binary via [`rebuild`](crate::analysis::rebuild).
    Hit(Box<Loaded>),
    /// Stored hash, mapping, analysis revision, or schema version differs:
    /// metadata plus annotations only; the derived
    /// `functions`/`blocks`/`xrefs`/`strings` tables were never opened.
    Stale {
        /// Snapshot metadata (row 0 of `binaries`).
        meta: BinaryMeta,
        /// Annotations keyed by address.
        annotations: BTreeMap<u64, Annotation>,
    },
    /// No snapshot yet (fresh file, missing `meta` table, or no version row).
    Miss,
}

/// Load the snapshot for one binary identity and loader mapping in a single
/// read transaction.
///
/// Accepts any readable handle ([`Database`] or [`redb::ReadOnlyDatabase`]);
/// read opens pass a read-only handle from [`open_db_read_only`].
///
/// Cache identity covers the binary content (`expected_hash` plus
/// `expected_sha256` and `expected_size`), the
/// loader mapping — auto, explicit raw arch/base/entry, or fat slice arch
/// (`expected_mapping`) — and the analysis revision: layouts replay only when
/// all agree with the stored snapshot on the current
/// [`SCHEMA_VERSION`]. The 64-bit FNV-1a hash is a fast pre-check; the
/// SHA-256 plus size is the collision-resistant gate, so a constructed
/// FNV collision cannot replay another binary's layouts. A mapping mismatch
/// never reuses layouts, even when the bytes are identical; auto and
/// explicit opens never alias.
///
/// Reads and validates the `meta`/`binaries` rows first. On any identity
/// mismatch the derived tables are never opened, so opening a small binary
/// against a sidecar written for a large one costs no decoding proportional
/// to the discarded rows. A version, content, or revision mismatch under the
/// same mapping returns [`Snapshot::Stale`] with the stored annotations and
/// the binary re-analyzes. A legacy snapshot whose mapping cannot be
/// established is rebuilt, never trusted. A mapping mismatch (or an
/// ambiguous legacy mapping) over a populated annotation sidecar errors
/// with a separate-DB message instead of carrying annotations across address
/// spaces or silently dropping them. Metadata and rows come from one read
/// transaction, so a concurrent writer cannot interleave a metadata row
/// from one snapshot with rows from another.
///
/// Stale-cache policy (a deliberate behavior change; strict all-input
/// equivalence with [`load`] is not claimed): a stale snapshot's derived
/// rows are discarded unchecked, so corrupt derived rows (bad JSON, unknown
/// shapes) and missing derived tables no longer error — [`load`] would have
/// errored on them before the caller ever compared hashes. Schema `version`,
/// `arch`, and `format` are likewise unchecked on the stale path since they
/// only gate analysis decoding. What is still validated on the stale path:
/// the `meta` version marker, the `binaries` row (missing/undecodable rows
/// error, as without metadata no hash comparison is possible), and every
/// annotation row (a corrupt annotation errors because annotations carry
/// over into the re-analysis when [`stale_carry_plausible`] holds; a missing
/// annotations table reads as empty).
/// A full identity match keeps the exact [`load`] validation:
/// unknown arch/format, and any corrupt or missing table error.
///
/// Callers filter stale annotations with [`stale_carry_plausible`]:
/// [`load_cached`] itself returns the stored rows so one read transaction
/// stays coherent (see its coherence test); [`Project::open`](crate::Project::open)
/// drops implausible rows and reports them via its stale warning.
///
/// # Errors
/// [`Error::Storage`] on unreadable metadata, on corrupt annotations, on
/// mapping conflicts holding live annotations, and — for full identity
/// matches only — on corrupt derived rows, missing tables, or unknown
/// arch/format values. [`Error::Limit`] when snapshot row
/// budgets are exceeded (forged sidecar).
pub fn load_cached(
    db: &impl ReadableDatabase,
    expected_hash: u64,
    expected_sha256: &str,
    expected_size: u64,
    expected_mapping: &StoredMapping,
) -> Result<Snapshot> {
    let rtxn = db
        .begin_read()
        .map_err(|e| Error::Storage(format!("begin read: {e}")))?;
    let meta = match read_meta_row(&rtxn)? {
        None => return Ok(Snapshot::Miss),
        Some(meta) => meta,
    };
    if meta.version != SCHEMA_VERSION {
        let annotations = read_annotations_or_empty(&rtxn)?;
        if !annotations.is_empty() {
            match meta.mapping.clone() {
                None => return Err(legacy_ambiguous(annotations.len(), meta.version)),
                Some(stored) if &stored != expected_mapping => {
                    return Err(mapping_conflict(
                        &stored,
                        annotations.len(),
                        expected_mapping,
                    ));
                }
                Some(_) => {}
            }
        }
        return Ok(Snapshot::Stale { meta, annotations });
    }
    if meta.mapping.as_ref() != Some(expected_mapping) {
        let annotations = read_annotations_or_empty(&rtxn)?;
        if !annotations.is_empty() {
            match meta.mapping.clone() {
                Some(stored) => {
                    return Err(mapping_conflict(
                        &stored,
                        annotations.len(),
                        expected_mapping,
                    ));
                }
                None => return Err(legacy_ambiguous(annotations.len(), meta.version)),
            }
        }
        return Ok(Snapshot::Stale { meta, annotations });
    }
    if meta.content_hash != expected_hash
        || meta.content_sha256 != expected_sha256
        || meta.size != expected_size
        || meta.analysis_rev != Some(ANALYSIS_REVISION)
    {
        let annotations = read_annotations_or_empty(&rtxn)?;
        return Ok(Snapshot::Stale { meta, annotations });
    }
    let arch = parse_arch(&meta.arch)?;
    parse_format(&meta.format)?;
    let parts = read_snapshot_parts(&rtxn)?;
    let annotations = read_annotations(&rtxn)?;
    Ok(Snapshot::Hit(Box::new(Loaded {
        meta,
        arch,
        functions: parts.functions,
        call_edges: parts.call_edges,
        xrefs: parts.xrefs,
        strings: parts.strings,
        diagnostics: parts.diagnostics,
        annotations,
    })))
}

/// Load a snapshot written by [`save`].
///
/// Returns `Ok(None)` when the DB has no snapshot yet (fresh file or no
/// `meta` table). Rebuilds function layouts, CFGs, and the callgraph from
/// stored edges; the caller re-decodes instructions via
/// [`rebuild`](crate::analysis::rebuild). Prefer [`load_cached`] on open
/// paths: it skips decoding derived rows the caller would discard after a
/// content-hash mismatch.
///
/// # Errors
/// [`Error::Storage`] on corrupt rows or unknown arch/format values,
/// [`Error::Limit`] when snapshot row budgets are exceeded.
pub fn load(db: &Database) -> Result<Option<Loaded>> {
    let rtxn = db
        .begin_read()
        .map_err(|e| Error::Storage(format!("begin read: {e}")))?;
    let meta = match read_meta_row(&rtxn)? {
        None => return Ok(None),
        Some(meta) => meta,
    };
    if meta.version != SCHEMA_VERSION {
        return Err(Error::Storage(format!(
            "project db version {} != {}",
            meta.version, SCHEMA_VERSION
        )));
    }
    let arch = parse_arch(&meta.arch)?;
    parse_format(&meta.format)?;
    let parts = read_snapshot_parts(&rtxn)?;
    let annotations = read_annotations(&rtxn)?;
    Ok(Some(Loaded {
        meta,
        arch,
        functions: parts.functions,
        call_edges: parts.call_edges,
        xrefs: parts.xrefs,
        strings: parts.strings,
        diagnostics: parts.diagnostics,
        annotations,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_sensitive() {
        assert_eq!(content_hash(b"abc"), content_hash(b"abc"));
        assert_ne!(content_hash(b"abc"), content_hash(b"abd"));
        assert_ne!(content_hash(b"abc"), content_hash(b""));
    }

    #[test]
    fn arch_and_format_round_trip() {
        for a in [
            Arch::X86_64,
            Arch::X86_32,
            Arch::Aarch64,
            Arch::Arm32,
            Arch::Thumb,
        ] {
            assert_eq!(parse_arch(arch_name(a)).unwrap(), a);
        }
        for f in [
            BinaryFormat::Elf,
            BinaryFormat::Pe,
            BinaryFormat::MachO,
            BinaryFormat::Coff,
            BinaryFormat::Le,
            BinaryFormat::Raw,
        ] {
            assert_eq!(parse_format(format_name(f)).unwrap(), f);
        }
        assert!(parse_arch("mips").is_err());
        assert!(parse_format("wasm").is_err());
    }

    #[test]
    fn empty_annotation_prunes() {
        assert!(Annotation::default().is_empty());
        assert!(
            !Annotation {
                name: Some("f".to_string()),
                comment: None,
            }
            .is_empty()
        );
        assert!(
            !Annotation {
                name: Some(String::new()),
                comment: Some("c".to_string()),
            }
            .is_empty()
        );
    }

    #[test]
    fn default_db_path_appends_suffix() {
        assert_eq!(
            default_db_path(Path::new("foo.exe")),
            PathBuf::from("foo.exe.rsdbg.redb")
        );
        assert_eq!(
            default_db_path(Path::new("foo.dll")),
            PathBuf::from("foo.dll.rsdbg.redb")
        );
        assert_ne!(
            default_db_path(Path::new("foo.exe")),
            default_db_path(Path::new("foo.dll"))
        );
        assert_eq!(
            default_db_path(Path::new("ls.arm64e")),
            PathBuf::from("ls.arm64e.rsdbg.redb")
        );
        assert_eq!(
            default_db_path(Path::new("prog")),
            PathBuf::from("prog.rsdbg.redb")
        );
    }
}
