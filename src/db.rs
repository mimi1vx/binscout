//! M5 persist: `redb` project store plus annotations.
//!
//! One project DB holds a single binary's snapshot: the [`BinaryMeta`] row,
//! one function row per function (carrying that function's block layouts),
//! [`Xref`] entries in chunks, extracted [`StringHit`] bodies in chunks,
//! and user [`Annotation`]s.
//! Metadata, annotations, and user seeds stay JSON so they remain readable
//! with any `redb` inspector; derived rows (functions, xrefs, strings,
//! diagnostics) are compact little-endian binary. Per-instruction JSON
//! objects, `0x`-hex twins, and `format!`-built keys once made small
//! binaries produce ~20x sidecars, so derived tables use binary values
//! (functions and diagnostics keep tuple keys) or small chunked blobs
//! (xrefs and strings) with integer keys and no duplicated hex.
//!
//! Chunking keeps single values small enough to pack like small rows while
//! row visits stay in the dozens: cache-hit opens decode tens of rows
//! instead of tens of thousands.
//!
//! Block layouts store address ranges plus per-instruction sizes only;
//! instructions are
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
///
/// Version 7 adds the `func_seeds` table plus the `seeds_hash` snapshot
/// identity (see [`FuncSeed`]): user-defined function seeds persist
/// across opens and join analysis on every open.
///
/// Version 8 stores derived rows as compact binary: functions keep one
/// row per function (carrying its block layouts, no per-block keys) while
/// xrefs and strings pack many entries per small chunked blob row; key
/// twins, per-instruction JSON objects, and `format!`-built keys are gone.
/// Old sidecars stay readable as stale (the stale path never opens derived
/// tables), so they re-analyze instead of erroring.
pub const SCHEMA_VERSION: u32 = 8;
/// Revision of the analysis engine covered by cached snapshots.
///
/// Re-exported from [`crate::analysis`] so cache identity has one source:
/// a stored revision mismatch re-analyzes instead of replaying layouts.
pub use crate::analysis::ANALYSIS_REVISION;
/// Cap on cached function rows (mirrors analysis [`MAX_FUNCTIONS`](crate::analysis::MAX_FUNCTIONS)).
pub const MAX_SNAPSHOT_FUNCTIONS: usize = 100_000;
/// Cap on cached block rows (blocks never exceed decoded instructions).
pub const MAX_SNAPSHOT_BLOCKS: usize = 1_000_000;
/// Max xrefs per `xrefs` blob row (fixed 17-byte entries): small enough
/// to pack like small rows while row visits stay in the dozens.
const XREFS_PER_ROW: usize = 512;
/// Max strings per `strings` blob row: small enough to pack like small
/// rows while row visits stay in the dozens.
const STRINGS_PER_ROW: usize = 128;
/// Cap on cached xref rows (1M per kind times three kinds).
pub const MAX_SNAPSHOT_XREFS: usize = 3_000_000;
/// Cap on cached string rows (10k per segment times 256 segments, rounded up).
pub const MAX_SNAPSHOT_STRINGS: usize = 3_000_000;
/// Cap on stored annotation rows (user-created; 10k is 100x typical use).
pub const MAX_SNAPSHOT_ANNOTATIONS: usize = 10_000;
/// Cap on stored user-seed rows (user-created; mirrors annotations).
pub const MAX_SNAPSHOT_SEEDS: usize = 10_000;
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
const FUNCTIONS: TableDefinition<u64, Vec<u8>> = TableDefinition::new("functions");
const XREFS: TableDefinition<u64, Vec<u8>> = TableDefinition::new("xrefs");
const STRINGS: TableDefinition<u64, Vec<u8>> = TableDefinition::new("strings");
const ANNOTATIONS: TableDefinition<u64, String> = TableDefinition::new("annotations");
const FUNC_SEEDS: TableDefinition<u64, String> = TableDefinition::new("func_seeds");
const DIAGNOSTICS: TableDefinition<(u64, u8), ()> = TableDefinition::new("diagnostics");

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
    /// Hash of the active user-seed set the snapshot was taken over.
    ///
    /// Computed by [`seeds_hash`] over the non-excluded rows: a change
    /// (define/undefine) re-analyzes and rewrites the snapshot, so
    /// derived rows always match the stored seeds. Defaults to zero so
    /// pre-v7 snapshots without the field still decode; such snapshots
    /// never hit the cache (their schema version mismatches) and
    /// re-analyze instead.
    #[serde(default)]
    pub seeds_hash: u64,
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
    /// format, entry, mapping, revisions, seed identity, truncation flags)
    /// still gates the fast path.
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
            && self.seeds_hash == other.seeds_hash
    }
}

/// Whether stale user rows plausibly belong to the current binary.
///
/// True when the stored snapshot names the same host path, or when the
/// stored arch, format, and entry all match the freshly loaded binary.
/// Otherwise the sidecar was reused for an unrelated binary and its
/// renames/comments/seeds must be dropped rather than carried by address.
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

/// One user-defined function seed at one address.
///
/// `define-func` inserts (or re-activates) a row; `undefine-func` marks it
/// excluded. Excluded rows never seed analysis but are kept as data, so an
/// agent's "this isn't a function" verdict survives reloads and transfers.
/// Stored only in the project DB; the analyzed binary is never modified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuncSeed {
    /// Decode-mode override (`None` = project arch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<crate::analysis::SeedMode>,
    /// Whether the address is excluded from seeding (kept as data).
    #[serde(default)]
    pub excluded: bool,
}

/// Snapshot identity of the active user-seed set.
///
/// Deterministic FNV-1a over the sorted non-excluded rows (`addr` plus
/// mode); excluded rows are kept as data but never seed analysis, so they
/// stay out of the identity. Stored in [`BinaryMeta::seeds_hash`]:
/// derived snapshot rows always match the stored seeds because every
/// seed change re-analyzes before saving.
#[must_use]
pub fn seeds_hash(seeds: &BTreeMap<u64, FuncSeed>) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut h = OFFSET;
    for (&addr, seed) in seeds {
        if seed.excluded {
            continue;
        }
        for b in addr.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(PRIME);
        }
        let m = match seed.mode {
            None => 0,
            Some(crate::analysis::SeedMode::Arm) => 1,
            Some(crate::analysis::SeedMode::Thumb) => 2,
        };
        h ^= m;
        h = h.wrapping_mul(PRIME);
    }
    h
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
    /// Cached function layouts (entry, name, callees, block ranges,
    /// reasons, decode-arch overrides).
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
    /// User-defined function seeds keyed by address (excluded rows kept).
    pub seeds: BTreeMap<u64, FuncSeed>,
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

fn json<T: Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|e| Error::Storage(format!("encode row: {e}")))
}

fn decode<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T> {
    serde_json::from_str(s).map_err(|e| Error::Storage(format!("decode row: {e}")))
}

/// Little-endian binary writer for derived snapshot rows.
///
/// `functions` and `strings` chunked blobs plus `xrefs` chunked entries
/// store compact binary instead of JSON: per-instruction JSON objects,
/// `0x`-hex twins, and `format!`-built keys once made small binaries
/// produce ~20x sidecars. Counts are `u32` (row sizes stay far below 4 GiB:
/// mapped bytes cap at 256 MiB), addresses `u64`, sizes single bytes.
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Length-prefixed bytes (`u32` length, then the bytes).
    fn bytes(&mut self, v: &[u8]) {
        // Infallible: every stored blob derives from mapped bytes or their
        // names, all bounded by the 256 MiB loader cap.
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
    }

    fn str(&mut self, v: &str) {
        self.bytes(v.as_bytes());
    }

    /// Raw bytes, appended without a length prefix.
    ///
    /// Only for concatenating self-delimiting rows in chunked blobs: the
    /// reader consumes exactly one row per call and checks the chunk end
    /// afterwards.
    fn raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// Unsigned LEB128: block-start deltas ascend, so small gaps take one
    /// or two bytes instead of eight.
    fn uleb128(&mut self, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.u8(b);
                break;
            }
            self.u8(b | 0x80);
        }
    }

    /// Flag byte (`0` = none, `1` = some) plus the length-prefixed string.
    fn opt_str(&mut self, v: Option<&str>) {
        match v {
            Some(s) => {
                self.u8(1);
                self.str(s);
            }
            None => self.u8(0),
        }
    }

    /// Count plus the `u64` items.
    fn u64_vec(&mut self, vs: &[u64]) {
        // Infallible: row item counts stay far below `u32::MAX` (snapshot
        // row caps bound every vector encoded here).
        self.u32(vs.len() as u32);
        for &v in vs {
            self.u64(v);
        }
    }

    /// Successor and inferred-successor lists of one block.
    ///
    /// Direct successors never exceed two per block (branch target plus
    /// fallthrough at most) and inferred never exceed fifteen, so both
    /// counts usually pack into one byte: the low two bits hold the direct
    /// count, the high six the inferred count. Longer lists (only reachable
    /// if analysis ever grows new edge shapes) take the `0xFF` escape hatch
    /// plus two `u32` counts.
    fn succ_lists(&mut self, succs: &[u64], inferred: &[u64]) {
        if succs.len() <= 3 && inferred.len() <= 15 {
            self.u8(succs.len() as u8 | ((inferred.len() as u8) << 2));
        } else {
            self.u8(0xFF);
            // Infallible: lengths stay far below `u32::MAX` (see above).
            self.u32(succs.len() as u32);
            self.u32(inferred.len() as u32);
        }
        for &v in succs.iter().chain(inferred) {
            self.u64(v);
        }
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Little-endian binary reader for derived snapshot rows.
///
/// Every failure reports `decode row`, the same marker the stale-cache
/// policy keys corrupt-row errors on.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn u8(&mut self) -> Result<u8> {
        let (&b, rest) = self
            .buf
            .split_first()
            .ok_or_else(|| Error::Storage("decode row: truncated".to_string()))?;
        self.buf = rest;
        Ok(b)
    }

    fn u32(&mut self) -> Result<u32> {
        let (b, rest) = self
            .buf
            .split_at_checked(4)
            .ok_or_else(|| Error::Storage("decode row: truncated".to_string()))?;
        self.buf = rest;
        Ok(u32::from_le_bytes(b.try_into().expect("split 4 bytes")))
    }

    fn u64(&mut self) -> Result<u64> {
        let (b, rest) = self
            .buf
            .split_at_checked(8)
            .ok_or_else(|| Error::Storage("decode row: truncated".to_string()))?;
        self.buf = rest;
        Ok(u64::from_le_bytes(b.try_into().expect("split 8 bytes")))
    }

    /// A `u32` count of `width`-byte items, bounded by the bytes left so a
    /// forged count cannot pre-size a huge allocation.
    fn count(&mut self, width: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n > self.buf.len() / width.max(1) {
            return Err(Error::Storage("decode row: count exceeds row".to_string()));
        }
        Ok(n)
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.count(1)?;
        let (b, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(b)
    }

    fn str(&mut self) -> Result<&'a str> {
        let b = self.bytes()?;
        std::str::from_utf8(b).map_err(|_| Error::Storage("decode row: bad utf-8".to_string()))
    }

    fn opt_string(&mut self) -> Result<Option<String>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.str()?.to_string())),
            _ => Err(Error::Storage("decode row: bad option flag".to_string())),
        }
    }

    /// Count plus the `u64` items.
    fn u64_vec(&mut self) -> Result<Vec<u64>> {
        let n = self.count(8)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.u64()?);
        }
        Ok(out)
    }

    /// Successor and inferred-successor lists of one block (see
    /// [`Writer::succ_lists`]).
    fn succ_lists(&mut self) -> Result<(Vec<u64>, Vec<u64>)> {
        let (n, m) = match self.u8()? {
            // Guarded below like [`Reader::count`]: a forged escape must
            // not pre-size a huge allocation.
            0xFF => (self.u32()? as usize, self.u32()? as usize),
            b => {
                let m = (b >> 2) as usize;
                if m > 15 {
                    return Err(Error::Storage(
                        "decode row: bad successor counts".to_string(),
                    ));
                }
                ((b & 0x03) as usize, m)
            }
        };
        let total = n
            .checked_add(m)
            .ok_or_else(|| Error::Storage("decode row: bad successor counts".to_string()))?;
        if total > self.buf.len() / 8 {
            return Err(Error::Storage("decode row: count exceeds row".to_string()));
        }
        let mut out = Vec::with_capacity(total);
        for _ in 0..total {
            out.push(self.u64()?);
        }
        let inferred = out.split_off(n.min(out.len()));
        Ok((out, inferred))
    }

    /// Flag byte (`0` = absent, `1` = present) plus the `u64` item.
    fn opt_u64(&mut self) -> Result<Option<u64>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(Error::Storage("decode row: bad option flag".to_string())),
        }
    }

    /// Unsigned LEB128 (see [`Writer::uleb128`]).
    fn uleb128(&mut self) -> Result<u64> {
        let mut out = 0u64;
        for i in 0..10 {
            let b = self.u8()?;
            if i == 9 && b & 0x7e != 0 {
                return Err(Error::Storage("decode row: varint overflow".to_string()));
            }
            out |= ((b & 0x7f) as u64) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(out);
            }
        }
        Err(Error::Storage("decode row: bad varint".to_string()))
    }

    fn end(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Storage("decode row: trailing bytes".to_string()))
        }
    }
}

/// Discriminant of an [`XrefKind`](crate::analysis::XrefKind) for xref keys.
///
/// Order matches the kind's `Ord` (code, data, string, import,
/// inferred-code) so key order equals the `(from, kind, to)` sort.
fn xref_kind_code(kind: crate::analysis::XrefKind) -> u8 {
    match kind {
        crate::analysis::XrefKind::Code => 0,
        crate::analysis::XrefKind::Data => 1,
        crate::analysis::XrefKind::String => 2,
        crate::analysis::XrefKind::Import => 3,
        crate::analysis::XrefKind::InferredCode => 4,
    }
}

/// Inverse of [`xref_kind_code`].
fn decode_xref_kind(v: u8) -> Result<crate::analysis::XrefKind> {
    match v {
        0 => Ok(crate::analysis::XrefKind::Code),
        1 => Ok(crate::analysis::XrefKind::Data),
        2 => Ok(crate::analysis::XrefKind::String),
        3 => Ok(crate::analysis::XrefKind::Import),
        4 => Ok(crate::analysis::XrefKind::InferredCode),
        _ => Err(Error::Storage(format!("decode row: bad xref kind {v}"))),
    }
}

/// Discriminant of a [`DiscoveryReason`](crate::analysis::DiscoveryReason).
fn reason_code(reason: crate::analysis::DiscoveryReason) -> u8 {
    match reason {
        crate::analysis::DiscoveryReason::Entry => 0,
        crate::analysis::DiscoveryReason::Export => 1,
        crate::analysis::DiscoveryReason::Symbol => 2,
        crate::analysis::DiscoveryReason::DirectCall => 3,
        crate::analysis::DiscoveryReason::Prologue => 4,
        crate::analysis::DiscoveryReason::User => 5,
    }
}

/// Inverse of [`reason_code`].
fn decode_reason(v: u8) -> Result<crate::analysis::DiscoveryReason> {
    match v {
        0 => Ok(crate::analysis::DiscoveryReason::Entry),
        1 => Ok(crate::analysis::DiscoveryReason::Export),
        2 => Ok(crate::analysis::DiscoveryReason::Symbol),
        3 => Ok(crate::analysis::DiscoveryReason::DirectCall),
        4 => Ok(crate::analysis::DiscoveryReason::Prologue),
        5 => Ok(crate::analysis::DiscoveryReason::User),
        _ => Err(Error::Storage(format!("decode row: bad reason {v}"))),
    }
}

/// Discriminant of a [`DiagnosticKind`](crate::analysis::DiagnosticKind)
/// for diagnostics keys; order matches its `Ord` so key order equals the
/// `(addr, kind)` sort.
fn diagnostic_kind_code(kind: crate::analysis::DiagnosticKind) -> u8 {
    match kind {
        crate::analysis::DiagnosticKind::UnresolvedIndirectJump => 0,
        crate::analysis::DiagnosticKind::UnresolvedIndirectCall => 1,
        crate::analysis::DiagnosticKind::DecodeFailure => 2,
    }
}

/// Inverse of [`diagnostic_kind_code`].
fn decode_diagnostic_kind(v: u8) -> Result<crate::analysis::DiagnosticKind> {
    match v {
        0 => Ok(crate::analysis::DiagnosticKind::UnresolvedIndirectJump),
        1 => Ok(crate::analysis::DiagnosticKind::UnresolvedIndirectCall),
        2 => Ok(crate::analysis::DiagnosticKind::DecodeFailure),
        _ => Err(Error::Storage(format!(
            "decode row: bad diagnostic kind {v}"
        ))),
    }
}

/// Discriminant of a [`Encoding`](crate::loader::strings::Encoding).
fn encoding_code(enc: crate::loader::strings::Encoding) -> u8 {
    match enc {
        crate::loader::strings::Encoding::Ascii => 0,
        crate::loader::strings::Encoding::Utf16Le => 1,
        crate::loader::strings::Encoding::Utf16Be => 2,
        crate::loader::strings::Encoding::Utf8 => 3,
        crate::loader::strings::Encoding::Utf16LeBmp => 4,
        crate::loader::strings::Encoding::Base64 => 5,
    }
}

/// Inverse of [`encoding_code`].
fn decode_encoding(v: u8) -> Result<crate::loader::strings::Encoding> {
    match v {
        0 => Ok(crate::loader::strings::Encoding::Ascii),
        1 => Ok(crate::loader::strings::Encoding::Utf16Le),
        2 => Ok(crate::loader::strings::Encoding::Utf16Be),
        3 => Ok(crate::loader::strings::Encoding::Utf8),
        4 => Ok(crate::loader::strings::Encoding::Utf16LeBmp),
        5 => Ok(crate::loader::strings::Encoding::Base64),
        _ => Err(Error::Storage(format!("decode row: bad encoding {v}"))),
    }
}

/// Encode one function row: name, sorted callees, reasons, decode-arch
/// override, and its block layouts in start order. The entry rides in the
/// table key; blocks ride in the value so one row holds the whole function
/// and no per-block key repeats the entry. The first block start is
/// absolute, the rest are unsigned LEB128 deltas from the previous start
/// (starts ascend, so deltas never go negative and small gaps take one or
/// two bytes). Lengths are `u32`: blocks never exceed the 256 MiB loader
/// cap.
fn encode_function(f: &crate::analysis::FunctionLayout) -> Vec<u8> {
    let mut w = Writer::new();
    w.opt_str(f.name.as_deref());
    w.u64_vec(&f.calls);
    // Infallible: reasons stay in the single digits.
    w.u32(f.reasons.len() as u32);
    for &r in &f.reasons {
        w.u8(reason_code(r));
    }
    w.opt_str(f.arch.as_deref());
    let mut blocks: Vec<&crate::analysis::BlockLayout> = f.blocks.iter().collect();
    blocks.sort_by_key(|b| b.start);
    // Infallible: block counts stay far below `u32::MAX` (snapshot row caps
    // bound every vector encoded here).
    w.u32(blocks.len() as u32);
    let mut prev = 0u64;
    let mut first = true;
    for b in blocks {
        if first {
            w.u64(b.start);
            first = false;
        } else {
            w.uleb128(b.start.wrapping_sub(prev));
        }
        prev = b.start;
        // Infallible: block lengths stay far below `u32::MAX` (blocks lie
        // within mapped bytes, capped at 256 MiB).
        w.u32(b.end.wrapping_sub(b.start) as u32);
        // Infallible: blocks hold far fewer than `u32::MAX` instructions.
        w.u32(b.insns.len() as u32);
        for i in &b.insns {
            w.u8(i.size);
        }
        let mut addr = b.start;
        let mut contiguous = true;
        for i in &b.insns {
            if i.addr != addr {
                contiguous = false;
            }
            addr = addr.wrapping_add(u64::from(i.size));
        }
        if contiguous {
            w.u8(0);
        } else {
            w.u8(1);
            for i in &b.insns {
                w.u64(i.addr);
            }
        }
        w.succ_lists(&b.succs, &b.inferred_succs);
    }
    w.finish()
}

/// Decode one function row; `entry` rides in the table key.
fn decode_function(entry: u64, raw: &[u8]) -> Result<(crate::analysis::FunctionLayout, usize)> {
    let mut r = Reader::new(raw);
    let name = r.opt_string()?;
    let calls = r.u64_vec()?;
    let n_reasons = r.count(1)?;
    let mut reasons = Vec::with_capacity(n_reasons);
    for _ in 0..n_reasons {
        reasons.push(decode_reason(r.u8()?)?);
    }
    let arch = r.opt_string()?;
    let n_blocks = r.count(8)?;
    let mut blocks = Vec::with_capacity(n_blocks.min(1024));
    let mut prev = 0u64;
    let mut first = true;
    for _ in 0..n_blocks {
        let start = if first {
            first = false;
            r.u64()?
        } else {
            prev.wrapping_add(r.uleb128()?)
        };
        prev = start;
        let len = r.u32()?;
        let end = start.wrapping_add(u64::from(len));
        let n = r.count(1)?;
        let mut sizes = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            sizes.push(r.u8()?);
        }
        let mut addrs: Vec<u64> = Vec::with_capacity(n.min(1024));
        match r.u8()? {
            0 => {
                let mut addr = start;
                for &size in &sizes {
                    addrs.push(addr);
                    addr = addr.wrapping_add(u64::from(size));
                }
            }
            1 => {
                for _ in 0..n {
                    addrs.push(r.u64()?);
                }
            }
            f => {
                return Err(Error::Storage(format!(
                    "decode row: bad block address flag {f}"
                )));
            }
        }
        let (succs, inferred_succs) = r.succ_lists()?;
        let insns = sizes
            .into_iter()
            .zip(addrs)
            .map(|(size, addr)| crate::analysis::InsnLayout { addr, size })
            .collect();
        blocks.push(crate::analysis::BlockLayout {
            start,
            end,
            insns,
            succs,
            inferred_succs,
        });
    }
    let layout = crate::analysis::FunctionLayout {
        entry,
        name,
        calls,
        blocks,
        reasons,
        arch,
    };
    let n = layout.blocks.len();
    r.end()?;
    Ok((layout, n))
}

/// Encode one string row without the wire `vaddr_hex` twin.
fn encode_string(h: &StringHit) -> Vec<u8> {
    let mut w = Writer::new();
    // Infallible: offsets index mapped bytes, bounded by the 256 MiB loader
    // cap, so they always fit `u32`.
    w.u32(h.offset as u32);
    match h.vaddr {
        Some(v) => {
            w.u8(1);
            w.u64(v);
        }
        None => w.u8(0),
    }
    w.u8(encoding_code(h.encoding));
    w.str(&h.value);
    w.opt_str(h.section.as_deref());
    w.u8(u8::from(h.executable));
    w.finish()
}

/// Decode one string body from the shared chunk reader. Consumes exactly
/// one body: the caller checks the chunk end afterwards.
fn decode_string(r: &mut Reader<'_>) -> Result<StringHit> {
    let offset = r.u32()? as usize;
    let vaddr = r.opt_u64()?;
    let encoding = decode_encoding(r.u8()?)?;
    let value = r.str()?.to_string();
    let section = r.opt_string()?;
    let executable = match r.u8()? {
        0 => false,
        1 => true,
        f => {
            return Err(Error::Storage(format!(
                "decode row: bad executable flag {f}"
            )));
        }
    };
    Ok(StringHit {
        offset,
        vaddr,
        encoding,
        value,
        section,
        executable,
    })
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
/// annotation and seed caps.
fn check_analysis_budgets(
    analysis: &Analysis,
    annotations: &BTreeMap<u64, Annotation>,
    seeds: &BTreeMap<u64, FuncSeed>,
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
    let inferred: usize = analysis
        .functions
        .values()
        .map(|f| f.inferred_edges().len())
        .sum();
    if inferred > MAX_SNAPSHOT_INFERRED_EDGES {
        return Err(Error::Limit(
            "snapshot inferred edges exceed cap".to_string(),
        ));
    }
    let live = annotations.values().filter(|a| !a.is_empty()).count();
    if live > MAX_SNAPSHOT_ANNOTATIONS {
        return Err(Error::Limit("snapshot annotations exceed cap".to_string()));
    }
    if seeds.len() > MAX_SNAPSHOT_SEEDS {
        return Err(Error::Limit("snapshot func seeds exceed cap".to_string()));
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
        "xrefs" => wtxn.delete_table(XREFS),
        "strings" => wtxn.delete_table(STRINGS),
        "annotations" => wtxn.delete_table(ANNOTATIONS),
        "func_seeds" => wtxn.delete_table(FUNC_SEEDS),
        "diagnostics" => wtxn.delete_table(DIAGNOSTICS),
        _ => return Err(Error::Storage(format!("unknown table {table}"))),
    };
    match deleted {
        Ok(_) => Ok(()),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(()),
        Err(e) => Err(Error::Storage(format!("clear {table}: {e}"))),
    }
}

/// Count live user rows (non-empty annotations plus all seed rows) inside
/// a write transaction.
///
/// Used by writers to decide whether overwriting a mapping-incompatible
/// snapshot would drop user data. Corrupt rows error rather than reading
/// as empty.
fn live_user_rows_in_wtxn(wtxn: &redb::WriteTransaction) -> Result<usize> {
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
    let t = wtxn
        .open_table(FUNC_SEEDS)
        .map_err(|e| Error::Storage(format!("open func_seeds: {e}")))?;
    for row in t
        .iter()
        .map_err(|e| Error::Storage(format!("read func_seeds: {e}")))?
    {
        let (_, v) = row.map_err(|e| Error::Storage(format!("read func_seeds: {e}")))?;
        let _: FuncSeed = decode(&v.value())?;
        live += 1;
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
/// commits; the `functions`/`xrefs`/`strings` tables are never
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
            let live = live_user_rows_in_wtxn(&wtxn)?;
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
/// `functions`/`xrefs`/`strings` tables are never opened for
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
            let live = live_user_rows_in_wtxn(&wtxn)?;
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
/// Reads the existing `binaries` row plus live user rows inside the same
/// write transaction the caller will commit, so a concurrent mapping change
/// cannot slip past the check. A fresh DB (no version marker or binary row)
/// never conflicts; an incompatible or ambiguous legacy mapping with live
/// annotations or seeds errors, while an empty sidecar overwrites freely.
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
    let live = live_user_rows_in_wtxn(wtxn)?;
    if live == 0 {
        return Ok(());
    }
    let expected = meta.mapping.clone().unwrap_or(StoredMapping::Auto);
    match persisted.mapping {
        Some(stored) => Err(mapping_conflict(&stored, live, &expected)),
        None => Err(legacy_ambiguous(live, persisted.version)),
    }
}

/// Persist `meta`, `analysis`, `annotations`, and `seeds` to `db` in one transaction.
///
/// Clears all eight tables first so a smaller re-analysis leaves no stale
/// rows. Row counts are checked against the snapshot budgets before
/// committing, so a snapshot that [`load`] could not read back is never
/// written. Only block layouts persist (inside their function chunk);
/// instructions re-decode on open.
/// Never touches the analyzed binary. Overwriting a populated sidecar under
/// an incompatible (or ambiguous legacy) mapping errors instead of dropping
/// user rows; use a separate DB path for the new mapping.
///
/// # Errors
/// [`Error::Limit`] when row budgets are exceeded,
/// [`Error::Storage`] on any `redb` or encoding failure, and on mapping
/// conflicts holding live user rows.
pub fn save(
    db: &Database,
    meta: &BinaryMeta,
    analysis: &Analysis,
    annotations: &BTreeMap<u64, Annotation>,
    seeds: &BTreeMap<u64, FuncSeed>,
) -> Result<()> {
    check_analysis_budgets(analysis, annotations, seeds)?;
    let wtxn = db
        .begin_write()
        .map_err(|e| Error::Storage(format!("begin write: {e}")))?;
    reject_mapping_overwrite(&wtxn, meta)?;
    for t in [
        "meta",
        "binaries",
        "functions",
        "xrefs",
        "strings",
        "annotations",
        "func_seeds",
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
            t.insert(f.entry, encode_function(f))
                .map_err(|e| Error::Storage(format!("write functions: {e}")))?;
        }
    }
    {
        let mut t = wtxn
            .open_table(XREFS)
            .map_err(|e| Error::Storage(format!("open xrefs: {e}")))?;
        // Chunked blob rows: one row per xref costs microseconds in
        // debug builds, so fixed 17-byte entries pack `XREFS_PER_ROW`
        // per row behind a count prefix. Chunks stay small enough to
        // pack like small rows.
        for (chunk, group) in analysis.xrefs.chunks(XREFS_PER_ROW).enumerate() {
            let mut w = Writer::new();
            // Infallible: chunks hold at most `XREFS_PER_ROW` entries.
            w.u32(group.len() as u32);
            for x in group {
                w.u64(x.from);
                w.u8(xref_kind_code(x.kind));
                w.u64(x.to);
            }
            t.insert(chunk as u64, w.finish())
                .map_err(|e| Error::Storage(format!("write xrefs: {e}")))?;
        }
    }
    {
        let mut t = wtxn
            .open_table(STRINGS)
            .map_err(|e| Error::Storage(format!("open strings: {e}")))?;
        // Chunked blob rows like `xrefs`: self-delimiting bodies need no
        // per-row framing beyond the chunk count.
        for (chunk, group) in analysis.strings.chunks(STRINGS_PER_ROW).enumerate() {
            let mut w = Writer::new();
            // Infallible: chunks hold at most `STRINGS_PER_ROW` bodies.
            w.u32(group.len() as u32);
            for h in group {
                w.raw(&encode_string(h));
            }
            t.insert(chunk as u64, w.finish())
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
            .open_table(FUNC_SEEDS)
            .map_err(|e| Error::Storage(format!("open func_seeds: {e}")))?;
        for (&addr, seed) in seeds {
            t.insert(addr, json(seed)?)
                .map_err(|e| Error::Storage(format!("write func_seeds: {e}")))?;
        }
    }
    {
        let mut t = wtxn
            .open_table(DIAGNOSTICS)
            .map_err(|e| Error::Storage(format!("open diagnostics: {e}")))?;
        for d in &analysis.diagnostics.records {
            t.insert((d.addr, diagnostic_kind_code(d.kind)), ())
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

/// Current snapshot identity plus user rows from one read transaction:
/// metadata, annotations, and function seeds.
pub type MetaState = (
    BinaryMeta,
    BTreeMap<u64, Annotation>,
    BTreeMap<u64, FuncSeed>,
);

/// Current snapshot identity plus user rows, without decoding layouts.
///
/// Used by write fallbacks to merge one batch on top of rows another
/// process wrote in between: returns `None` on a fresh DB.
/// Missing `annotations`/`func_seeds` tables read as empty; corrupt rows
/// still error so user data is never silently dropped.
///
/// # Errors
/// [`Error::Storage`] on unreadable metadata or corrupt user rows.
/// [`Error::Limit`] when row budgets are exceeded.
pub fn load_meta_and_annotations(db: &Database) -> Result<Option<MetaState>> {
    let rtxn = db
        .begin_read()
        .map_err(|e| Error::Storage(format!("begin read: {e}")))?;
    let Some(meta) = read_meta_row(&rtxn)? else {
        return Ok(None);
    };
    let annotations = read_annotations_or_empty(&rtxn)?;
    let seeds = read_func_seeds_or_empty(&rtxn)?;
    Ok(Some((meta, annotations, seeds)))
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

/// Decode the derived `functions`/`xrefs`/`strings` tables into
/// persistable layouts.
///
/// Function rows carry their block layouts, so no separate block table is
/// read. A missing table or an undecodable row is corruption and errors; callers holding a known-stale snapshot must not
/// call this at all (see the stale-cache policy on [`load_cached`]). Row
/// counts are capped so a forged sidecar fails fast with [`Error::Limit`].
fn read_snapshot_parts(rtxn: &redb::ReadTransaction) -> Result<SnapshotParts> {
    let mut records: Vec<crate::analysis::FunctionLayout> = Vec::new();
    let mut block_count: usize = 0;
    let mut inferred_count: usize = 0;
    {
        let t = rtxn
            .open_table(FUNCTIONS)
            .map_err(|e| Error::Storage(format!("open functions: {e}")))?;
        for row in t
            .iter()
            .map_err(|e| Error::Storage(format!("read functions: {e}")))?
        {
            let (k, v) = row.map_err(|e| Error::Storage(format!("read functions: {e}")))?;
            let raw = v.value();
            if records.len() >= MAX_SNAPSHOT_FUNCTIONS {
                return Err(Error::Limit("snapshot functions exceed cap".to_string()));
            }
            let (mut layout, n) = decode_function(k.value(), &raw)?;
            block_count += n;
            if block_count > MAX_SNAPSHOT_BLOCKS {
                return Err(Error::Limit("snapshot blocks exceed cap".to_string()));
            }
            inferred_count += layout
                .blocks
                .iter()
                .map(|b| b.inferred_succs.len())
                .sum::<usize>();
            if inferred_count > MAX_SNAPSHOT_INFERRED_EDGES {
                return Err(Error::Limit(
                    "snapshot inferred edges exceed cap".to_string(),
                ));
            }
            layout.blocks.sort_by_key(|b| b.start);
            let mut reasons = layout.reasons.clone();
            reasons.sort_unstable();
            reasons.dedup();
            layout.reasons = reasons;
            records.push(layout);
        }
    }
    // Numeric entry order, independent of key encoding: `call_edges` below
    // follows this order.
    records.sort_by_key(|f| f.entry);
    let mut functions: Vec<FunctionLayout> = Vec::new();
    let mut call_edges: Vec<(u64, u64)> = Vec::new();
    for rec in records {
        let entry = rec.entry;
        call_edges.extend(rec.calls.iter().map(|c| (entry, *c)));
        functions.push(rec);
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
            let mut r = Reader::new(&raw);
            // Width 17 (one fixed entry): valid chunks never trip this.
            let n = r.count(17)?;
            for _ in 0..n {
                if xrefs.len() >= MAX_SNAPSHOT_XREFS {
                    return Err(Error::Limit("snapshot xrefs exceed cap".to_string()));
                }
                let from = r.u64()?;
                let kind = decode_xref_kind(r.u8()?)?;
                let to = r.u64()?;
                xrefs.push(Xref { from, to, kind });
            }
            r.end()?;
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
            let mut r = Reader::new(&raw);
            // Width 8 (below the 11-byte minimum body): valid chunks
            // never trip this.
            let n = r.count(8)?;
            for _ in 0..n {
                if strings.len() >= MAX_SNAPSHOT_STRINGS {
                    return Err(Error::Limit("snapshot strings exceed cap".to_string()));
                }
                strings.push(decode_string(&mut r)?);
            }
            r.end()?;
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
        let (k, _) = row.map_err(|e| Error::Storage(format!("read diagnostics: {e}")))?;
        let (addr, kind) = k.value();
        if diagnostics.len() >= MAX_SNAPSHOT_DIAGNOSTICS {
            return Err(Error::Limit("snapshot diagnostics exceed cap".to_string()));
        }
        diagnostics.push(crate::analysis::Diagnostic {
            addr,
            kind: decode_diagnostic_kind(kind)?,
        });
    }
    diagnostics.sort_unstable();
    diagnostics.dedup();
    Ok(diagnostics)
}

/// Decode stored seed rows, reading a missing table as empty.
///
/// Snapshots carry seeds forward even when the sidecar has no seeds table
/// (fresh or partially written DBs); a corrupt row still errors, since
/// silently dropping user seeds would lose the `define-func` intent a
/// re-analysis keeps. Row counts are capped so a forged sidecar fails fast
/// with [`Error::Limit`].
fn read_func_seeds_or_empty(rtxn: &redb::ReadTransaction) -> Result<BTreeMap<u64, FuncSeed>> {
    let t = match rtxn.open_table(FUNC_SEEDS) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(BTreeMap::new()),
        Err(e) => return Err(Error::Storage(format!("open func_seeds: {e}"))),
    };
    let mut seeds: BTreeMap<u64, FuncSeed> = BTreeMap::new();
    for row in t
        .iter()
        .map_err(|e| Error::Storage(format!("read func_seeds: {e}")))?
    {
        let (k, v) = row.map_err(|e| Error::Storage(format!("read func_seeds: {e}")))?;
        let raw = v.value();
        if seeds.len() >= MAX_SNAPSHOT_SEEDS {
            return Err(Error::Limit("snapshot func seeds exceed cap".to_string()));
        }
        seeds.insert(k.value(), decode(&raw)?);
    }
    Ok(seeds)
}

/// Decode every stored seed row.
///
/// A missing table or an undecodable row is corruption and errors. Row
/// counts are capped so a forged sidecar fails fast with [`Error::Limit`].
fn read_func_seeds(rtxn: &redb::ReadTransaction) -> Result<BTreeMap<u64, FuncSeed>> {
    let t = rtxn
        .open_table(FUNC_SEEDS)
        .map_err(|e| Error::Storage(format!("open func_seeds: {e}")))?;
    let mut seeds: BTreeMap<u64, FuncSeed> = BTreeMap::new();
    for row in t
        .iter()
        .map_err(|e| Error::Storage(format!("read func_seeds: {e}")))?
    {
        let (k, v) = row.map_err(|e| Error::Storage(format!("read func_seeds: {e}")))?;
        let raw = v.value();
        if seeds.len() >= MAX_SNAPSHOT_SEEDS {
            return Err(Error::Limit("snapshot func seeds exceed cap".to_string()));
        }
        seeds.insert(k.value(), decode(&raw)?);
    }
    Ok(seeds)
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
    /// cached layouts plus annotations and seeds. The caller re-decodes
    /// instructions from the binary via [`rebuild`](crate::analysis::rebuild).
    Hit(Box<Loaded>),
    /// Stored hash, mapping, analysis revision, or schema version differs:
    /// metadata plus annotations and seeds only; the derived
    /// `functions`/`xrefs`/`strings` tables were never opened.
    Stale {
        /// Snapshot metadata (row 0 of `binaries`).
        meta: BinaryMeta,
        /// Annotations keyed by address.
        annotations: BTreeMap<u64, Annotation>,
        /// User-defined function seeds keyed by address.
        seeds: BTreeMap<u64, FuncSeed>,
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
/// seeds and the binary re-analyzes. A legacy snapshot whose mapping cannot be
/// established is rebuilt, never trusted. A mapping mismatch (or an
/// ambiguous legacy mapping) over a populated annotation sidecar errors
/// with a separate-DB message instead of carrying user rows across address
/// spaces or silently dropping them. Metadata and rows come from one read
/// transaction, so a concurrent writer cannot interleave a metadata row
/// from one snapshot with rows from another.
///
/// Stale-cache policy (a deliberate behavior change; strict all-input
/// equivalence with [`load`] is not claimed): a stale snapshot's derived
/// rows are discarded unchecked, so corrupt derived rows (bad encodings,
/// shapes) and missing derived tables no longer error — [`load`] would have
/// errored on them before the caller ever compared hashes. Schema `version`,
/// `arch`, and `format` are likewise unchecked on the stale path since they
/// only gate analysis decoding. What is still validated on the stale path:
/// the `meta` version marker, the `binaries` row (missing/undecodable rows
/// error, as without metadata no hash comparison is possible), and every
/// annotation and seed row (corrupt user rows error because they carry
/// over into the re-analysis when [`stale_carry_plausible`] holds; missing
/// tables read as empty).
/// A full identity match keeps the exact [`load`] validation:
/// unknown arch/format, and any corrupt or missing table error.
///
/// Callers filter stale user rows with [`stale_carry_plausible`]:
/// [`load_cached`] itself returns the stored rows so one read transaction
/// stays coherent (see its coherence test); [`Project::open`](crate::Project::open)
/// drops implausible rows and reports them via its stale warning.
///
/// # Errors
/// [`Error::Storage`] on unreadable metadata, on corrupt user rows, on
/// mapping conflicts holding live user rows, and — for full identity
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
        let seeds = read_func_seeds_or_empty(&rtxn)?;
        let live = annotations.len() + seeds.len();
        if live > 0 {
            match meta.mapping.clone() {
                None => return Err(legacy_ambiguous(live, meta.version)),
                Some(stored) if &stored != expected_mapping => {
                    return Err(mapping_conflict(&stored, live, expected_mapping));
                }
                Some(_) => {}
            }
        }
        return Ok(Snapshot::Stale {
            meta,
            annotations,
            seeds,
        });
    }
    if meta.mapping.as_ref() != Some(expected_mapping) {
        let annotations = read_annotations_or_empty(&rtxn)?;
        let seeds = read_func_seeds_or_empty(&rtxn)?;
        let live = annotations.len() + seeds.len();
        if live > 0 {
            match meta.mapping.clone() {
                Some(stored) => {
                    return Err(mapping_conflict(&stored, live, expected_mapping));
                }
                None => return Err(legacy_ambiguous(live, meta.version)),
            }
        }
        return Ok(Snapshot::Stale {
            meta,
            annotations,
            seeds,
        });
    }
    if meta.content_hash != expected_hash
        || meta.content_sha256 != expected_sha256
        || meta.size != expected_size
        || meta.analysis_rev != Some(ANALYSIS_REVISION)
    {
        let annotations = read_annotations_or_empty(&rtxn)?;
        let seeds = read_func_seeds_or_empty(&rtxn)?;
        return Ok(Snapshot::Stale {
            meta,
            annotations,
            seeds,
        });
    }
    let arch = parse_arch(&meta.arch)?;
    parse_format(&meta.format)?;
    let parts = read_snapshot_parts(&rtxn)?;
    let annotations = read_annotations(&rtxn)?;
    let seeds = read_func_seeds(&rtxn)?;
    Ok(Snapshot::Hit(Box::new(Loaded {
        meta,
        arch,
        functions: parts.functions,
        call_edges: parts.call_edges,
        xrefs: parts.xrefs,
        strings: parts.strings,
        diagnostics: parts.diagnostics,
        annotations,
        seeds,
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
    let seeds = read_func_seeds(&rtxn)?;
    Ok(Some(Loaded {
        meta,
        arch,
        functions: parts.functions,
        call_edges: parts.call_edges,
        xrefs: parts.xrefs,
        strings: parts.strings,
        diagnostics: parts.diagnostics,
        annotations,
        seeds,
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

    fn sample_layout() -> crate::analysis::FunctionLayout {
        use crate::analysis::{BlockLayout, DiscoveryReason, FunctionLayout, InsnLayout};
        FunctionLayout {
            entry: 0x1000,
            name: Some("f".to_string()),
            calls: vec![0x1020, 0x1040],
            blocks: vec![
                BlockLayout {
                    start: 0x1000,
                    end: 0x1008,
                    insns: vec![
                        InsnLayout {
                            addr: 0x1000,
                            size: 5,
                        },
                        InsnLayout {
                            addr: 0x1005,
                            size: 3,
                        },
                    ],
                    succs: vec![0x1008, 0x1010],
                    inferred_succs: vec![0x1020],
                },
                BlockLayout {
                    start: 0x1008,
                    end: 0x1009,
                    insns: vec![InsnLayout {
                        addr: 0x1008,
                        size: 1,
                    }],
                    succs: vec![],
                    inferred_succs: vec![],
                },
            ],
            reasons: vec![DiscoveryReason::Entry, DiscoveryReason::DirectCall],
            arch: Some("thumb".to_string()),
        }
    }

    fn decode_body(entry: u64, raw: &[u8]) -> Result<crate::analysis::FunctionLayout> {
        let (layout, _) = decode_function(entry, raw)?;
        Ok(layout)
    }

    #[test]
    fn binary_function_row_round_trip() {
        let layout = sample_layout();
        let back = decode_body(layout.entry, &encode_function(&layout)).expect("round trip");
        assert_eq!(back, layout);
        let minimal = crate::analysis::FunctionLayout {
            entry: 0x2000,
            name: None,
            calls: vec![],
            blocks: vec![],
            reasons: vec![],
            arch: None,
        };
        let back = decode_body(minimal.entry, &encode_function(&minimal)).expect("round trip");
        assert_eq!(back, minimal);
    }

    #[test]
    fn binary_explicit_addresses_survive() {
        // Overlapping decodes never share one block from real analysis, but
        // the explicit-address flag must not lose them if they ever do.
        let mut layout = sample_layout();
        layout.blocks[0].insns[1].addr = 0x1001;
        let raw = encode_function(&layout);
        let back = decode_body(layout.entry, &raw).expect("round trip");
        assert_eq!(back, layout);
        assert_eq!(back.blocks[0].insns[1].addr, 0x1001);
    }

    fn decode_str(raw: &[u8]) -> Result<StringHit> {
        let mut r = Reader::new(raw);
        let hit = decode_string(&mut r)?;
        r.end()?;
        Ok(hit)
    }

    #[test]
    fn binary_rows_reject_garbage() {
        for bad in [
            vec![2u8],               // bad option flag
            vec![1, 9, 0, 0, 0, 65], // bad UTF-8
            vec![255u8],             // bad varint
            vec![1, 0, 0, 0],        // truncated string
        ] {
            let err = decode_str(&bad).unwrap_err();
            assert!(
                err.to_string().contains("decode row"),
                "unexpected: {err:?}"
            );
        }
        for v in [255u8, 9] {
            assert!(decode_xref_kind(v).is_err());
            assert!(decode_diagnostic_kind(v).is_err());
            assert!(decode_reason(v).is_err());
            assert!(decode_encoding(v).is_err());
        }
        // Truncations and trailing bytes fail.
        let good = encode_function(&sample_layout());
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad.truncate(i);
            let err = decode_body(sample_layout().entry, &bad).unwrap_err();
            assert!(
                err.to_string().contains("decode row"),
                "prefix {i} decoded: {bad:?}"
            );
        }
        let mut bad = good.clone();
        bad.push(0);
        assert!(decode_body(sample_layout().entry, &bad).is_err());
    }

    #[test]
    fn codec_uleb128_round_trip() {
        for v in [0u64, 1, 127, 128, 300, 0xFFFF_FFFF, u64::MAX] {
            let mut w = Writer::new();
            w.uleb128(v);
            let raw = w.finish();
            let mut r = Reader::new(&raw);
            assert_eq!(r.uleb128().unwrap(), v);
            assert!(r.end().is_ok());
        }
        assert!(Reader::new(&[0x80]).uleb128().is_err());
        let mut bad = vec![0xFF; 9];
        bad.push(0x7F);
        assert!(Reader::new(&bad).uleb128().is_err());
    }

    #[test]
    fn codec_string_row_round_trip() {
        let hit = StringHit {
            offset: 12,
            vaddr: Some(0x1012),
            encoding: crate::loader::strings::Encoding::Ascii,
            value: "hi".to_string(),
            section: Some(".text".to_string()),
            executable: true,
        };
        assert_eq!(decode_str(&encode_string(&hit)).unwrap(), hit);
        let bare = StringHit {
            offset: 0,
            vaddr: None,
            encoding: crate::loader::strings::Encoding::Utf16Le,
            value: "AB".to_string(),
            section: None,
            executable: false,
        };
        assert_eq!(decode_str(&encode_string(&bare)).unwrap(), bare);
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
