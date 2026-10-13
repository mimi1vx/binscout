//! M5 persist: `redb` project store plus annotations.
//!
//! One project DB holds a single binary's snapshot: the [`BinaryMeta`] row,
//! one [`FunctionRecord`] per function, one [`BlockRecord`] per basic block,
//! the [`Xref`] set, extracted [`StringHit`]s, and user [`Annotation`]s.
//! Values are JSON so rows stay debuggable with any `redb` inspector.
//!
//! [`save`] rewrites every table in one transaction; [`load`] rebuilds the
//! [`Analysis`] via [`Analysis::from_parts`](crate::analysis::Analysis::from_parts)
//! and returns stored annotations untouched. [`load_cached`] filters by
//! content hash in one read transaction: matching snapshots load fully,
//! stale ones return metadata plus annotations without decoding the
//! discarded derived rows (see its stale-cache policy). Callers detect a
//! changed binary by comparing [`content_hash`] against
//! [`BinaryMeta::content_hash`]: re-analysis runs, annotations carry over by
//! address, and only an explicit [`save`] writes — the analyzed binary
//! itself is only ever read.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::analysis::{Analysis, BasicBlock, Xref};
use crate::disasm::Arch;
use crate::error::{Error, Result};
use crate::loader::BinaryFormat;
use crate::loader::strings::StringHit;

/// Schema version stored under `meta["version"]`.
pub const SCHEMA_VERSION: u32 = 1;
/// Cap on aggregate encoded snapshot row bytes decoded or written.
///
/// 64 MiB dwarfs fixture snapshots (tens of KiB) while keeping a forged
/// sidecar from decoding gigabytes before rejection.
pub const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
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

/// Sidecar DB path for a binary: `foo.bin` -> `foo.rsdbg.redb`.
#[must_use]
pub fn default_db_path(binary: &Path) -> PathBuf {
    let mut p = binary.to_path_buf();
    p.set_extension("rsdbg.redb");
    p
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
        "le" => Ok(BinaryFormat::Le),
        "raw" => Ok(BinaryFormat::Raw),
        other => Err(Error::Storage(format!(
            "unknown format in project db: {other}"
        ))),
    }
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
    /// Always true for persisted snapshots: recognized-but-unsupported
    /// formats (LE) are rejected at open and never saved. Defaults to true
    /// so pre-L1 snapshots without the field still decode.
    #[serde(default = "default_supported")]
    pub supported: bool,
    /// Why `supported` is false, if so.
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_supported() -> bool {
    true
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
}

/// One basic-block row with its instructions and sorted successors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRecord {
    /// Owning function entry.
    pub func_entry: u64,
    /// Address of the first instruction.
    pub start: u64,
    /// End address (one past the last byte).
    pub end: u64,
    /// Decoded instructions in address order.
    pub insns: Vec<crate::disasm::Insn>,
    /// Successor block starts.
    pub succs: Vec<u64>,
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
/// container names no entry).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProjectInfo {
    /// Analyzed binary path.
    pub binary: String,
    /// Sidecar DB path.
    pub db_path: String,
    /// Crate version.
    pub version: String,
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
    /// Always true for successfully opened projects: recognized-but-
    /// unsupported formats (LE) fail at open with [`Error::Unsupported`]
    /// instead of returning a `supported:false` project.
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
}

impl Serialize for ProjectInfo {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("ProjectInfo", 17)?;
        st.serialize_field("binary", &self.binary)?;
        st.serialize_field("db_path", &self.db_path)?;
        st.serialize_field("version", &self.version)?;
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
        st.end()
    }
}

/// Snapshot read back by [`load`]: metadata, rebuilt analysis, annotations.
#[derive(Debug)]
pub struct Loaded {
    /// Snapshot metadata (row 0).
    pub meta: BinaryMeta,
    /// Rebuilt analysis snapshot.
    pub analysis: Analysis,
    /// Annotations keyed by address.
    pub annotations: BTreeMap<u64, Annotation>,
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
    }
}

fn xref_key(x: &Xref) -> String {
    format!("{:016x}:{}:{:016x}", x.from, xref_kind_name(x.kind), x.to)
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

/// Add encoded row bytes to the snapshot aggregate budget.
fn account_snapshot(total: &mut u64, len: usize) -> Result<()> {
    *total = total
        .checked_add(len as u64)
        .filter(|m| *m <= MAX_SNAPSHOT_BYTES)
        .ok_or_else(|| Error::Limit("snapshot exceeds 64 MiB".to_string()))?;
    Ok(())
}

/// Pre-write row-count budget check so [`save`] never writes a snapshot
/// that [`load`] would reject. Counts mirror the analysis caps plus the
/// annotation cap; byte totals are enforced at read time row by row.
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
        _ => return Err(Error::Storage(format!("unknown table {table}"))),
    };
    match deleted {
        Ok(_) => Ok(()),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(()),
        Err(e) => Err(Error::Storage(format!("clear {table}: {e}"))),
    }
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
/// opened for writing. On a fresh DB or any metadata mismatch, aborts
/// without writing and returns [`AnnotationSave::NeedsFull`]. Never touches
/// the analyzed binary.
///
/// # Errors
/// [`Error::Limit`] when the annotation text exceeds
/// [`MAX_ANNOTATION_BYTES`], [`Error::Storage`] on any `redb` or encoding
/// failure (including write contention with another process).
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
        if persisted != *meta {
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

/// Persist `meta`, `analysis`, and `annotations` to `db` in one transaction.
///
/// Clears all seven tables first so a smaller re-analysis leaves no stale
/// rows. Row counts and aggregate encoded bytes are checked against the
/// snapshot budgets before committing, so a snapshot that [`load`] could not
/// read back is never written. Never touches the analyzed binary.
///
/// # Errors
/// [`Error::Limit`] when row or byte budgets are exceeded,
/// [`Error::Storage`] on any `redb` or encoding failure.
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
    for t in [
        "meta",
        "binaries",
        "functions",
        "blocks",
        "xrefs",
        "strings",
        "annotations",
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
    {
        let mut t = wtxn
            .open_table(FUNCTIONS)
            .map_err(|e| Error::Storage(format!("open functions: {e}")))?;
        for f in analysis.functions.values() {
            let mut calls = analysis.calls_of(f.entry);
            calls.sort_unstable();
            let rec = FunctionRecord {
                entry: f.entry,
                name: f.name.clone(),
                calls,
            };
            t.insert(f.entry, json(&rec)?)
                .map_err(|e| Error::Storage(format!("write functions: {e}")))?;
        }
    }
    {
        let mut t = wtxn
            .open_table(BLOCKS)
            .map_err(|e| Error::Storage(format!("open blocks: {e}")))?;
        for f in analysis.functions.values() {
            for b in f.blocks.values() {
                let mut succs = f.successors(b.start);
                succs.sort_unstable();
                let rec = BlockRecord {
                    func_entry: f.entry,
                    start: b.start,
                    end: b.end(),
                    insns: b.insns.clone(),
                    succs,
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

/// Decoded derived rows (`functions`/CFG edges, xrefs, strings) shared by
/// [`load`] and the hit path of [`load_cached`].
struct AnalysisParts {
    functions: BTreeMap<u64, crate::analysis::Function>,
    call_edges: Vec<(u64, u64)>,
    xrefs: Vec<Xref>,
    strings: Vec<StringHit>,
}

/// Decode the derived `functions`/`blocks`/`xrefs`/`strings` tables.
///
/// A missing table or an undecodable row is corruption and errors; callers
/// holding a known-stale snapshot must not call this at all (see the
/// stale-cache policy on [`load_cached`]). Row counts and aggregate encoded
/// bytes are capped so a forged sidecar fails fast with [`Error::Limit`]
/// instead of decoding gigabytes.
fn read_analysis_parts(rtxn: &redb::ReadTransaction) -> Result<AnalysisParts> {
    let mut snapshot_bytes: u64 = 0;
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
            account_snapshot(&mut snapshot_bytes, raw.len())?;
            if records.len() >= MAX_SNAPSHOT_FUNCTIONS {
                return Err(Error::Limit("snapshot functions exceed cap".to_string()));
            }
            records.push(decode(&raw)?);
        }
    }
    let mut blocks_by_func: BTreeMap<u64, BTreeMap<u64, BasicBlock>> = BTreeMap::new();
    let mut edges_by_func: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
    let mut block_count: usize = 0;
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
            account_snapshot(&mut snapshot_bytes, raw.len())?;
            block_count += 1;
            if block_count > MAX_SNAPSHOT_BLOCKS {
                return Err(Error::Limit("snapshot blocks exceed cap".to_string()));
            }
            let rec: BlockRecord = decode(&raw)?;
            blocks_by_func.entry(rec.func_entry).or_default().insert(
                rec.start,
                BasicBlock {
                    start: rec.start,
                    insns: rec.insns,
                },
            );
            edges_by_func
                .entry(rec.func_entry)
                .or_default()
                .extend(rec.succs.into_iter().map(|s| (rec.start, s)));
        }
    }
    let mut functions: BTreeMap<u64, crate::analysis::Function> = BTreeMap::new();
    let mut call_edges: Vec<(u64, u64)> = Vec::new();
    for rec in records {
        let entry = rec.entry;
        let blocks = blocks_by_func.remove(&entry).unwrap_or_default();
        let edges = edges_by_func.remove(&entry).unwrap_or_default();
        functions.insert(
            entry,
            crate::analysis::Function::from_parts(entry, rec.name, blocks, &edges),
        );
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
            account_snapshot(&mut snapshot_bytes, raw.len())?;
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
            account_snapshot(&mut snapshot_bytes, raw.len())?;
            if strings.len() >= MAX_SNAPSHOT_STRINGS {
                return Err(Error::Limit("snapshot strings exceed cap".to_string()));
            }
            strings.push(decode(&raw)?);
        }
    }
    Ok(AnalysisParts {
        functions,
        call_edges,
        xrefs,
        strings,
    })
}

/// Decode every stored annotation, skipping empty rows.
///
/// A missing table or an undecodable row is corruption and errors. Row
/// counts, per-field text, and aggregate bytes are capped so a forged
/// sidecar fails fast with [`Error::Limit`].
fn read_annotations(rtxn: &redb::ReadTransaction) -> Result<BTreeMap<u64, Annotation>> {
    let t = rtxn
        .open_table(ANNOTATIONS)
        .map_err(|e| Error::Storage(format!("open annotations: {e}")))?;
    let mut annotations: BTreeMap<u64, Annotation> = BTreeMap::new();
    let mut snapshot_bytes: u64 = 0;
    for row in t
        .iter()
        .map_err(|e| Error::Storage(format!("read annotations: {e}")))?
    {
        let (k, v) = row.map_err(|e| Error::Storage(format!("read annotations: {e}")))?;
        let raw = v.value();
        account_snapshot(&mut snapshot_bytes, raw.len())?;
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
/// comments would lose data the re-analysis keeps. Same row/text/byte
/// budgets as [`read_annotations`](fn@read_annotations) apply.
fn read_annotations_or_empty(rtxn: &redb::ReadTransaction) -> Result<BTreeMap<u64, Annotation>> {
    let t = match rtxn.open_table(ANNOTATIONS) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(BTreeMap::new()),
        Err(e) => return Err(Error::Storage(format!("open annotations: {e}"))),
    };
    let mut annotations: BTreeMap<u64, Annotation> = BTreeMap::new();
    let mut snapshot_bytes: u64 = 0;
    for row in t
        .iter()
        .map_err(|e| Error::Storage(format!("read annotations: {e}")))?
    {
        let (k, v) = row.map_err(|e| Error::Storage(format!("read annotations: {e}")))?;
        let raw = v.value();
        account_snapshot(&mut snapshot_bytes, raw.len())?;
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

/// Hash-filtered snapshot read back by [`load_cached`].
///
/// The stale variant carries only what a content-hash mismatch preserves:
/// metadata plus annotations. Derived rows are never decoded on that path
/// (see the stale-cache policy on [`load_cached`]).
#[derive(Debug)]
pub enum Snapshot {
    /// Stored hash matches: full cached analysis plus annotations.
    Hit(Box<Loaded>),
    /// Stored hash differs: metadata plus annotations only; the derived
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

/// Load the snapshot for one binary hash in a single read transaction.
///
/// Accepts any readable handle ([`Database`] or [`redb::ReadOnlyDatabase`]);
/// read opens pass a read-only handle from [`open_db_read_only`].
///
/// Reads and validates the `meta`/`binaries` rows first. When the stored
/// `content_hash` differs from `expected_hash`, returns [`Snapshot::Stale`]
/// with the stored annotations after decoding only the `annotations` table;
/// the derived tables are never opened, so opening a small binary against a
/// sidecar written for a large one costs no decoding proportional to the
/// discarded rows. On a hash match the full snapshot loads exactly as
/// [`load`] does. Metadata and rows come from one read transaction, so a
/// concurrent writer cannot interleave a metadata row from one snapshot with
/// rows from another.
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
/// over into the re-analysis; a missing annotations table reads as empty).
/// A matching hash keeps the exact [`load`] validation: version mismatch,
/// unknown arch/format, and any corrupt or missing table error.
///
/// # Errors
/// [`Error::Storage`] on unreadable metadata, on corrupt annotations, and —
/// for matching hashes only — on corrupt derived rows, missing tables, or
/// unknown version/arch/format values. [`Error::Limit`] when snapshot row
/// or byte budgets are exceeded (forged or oversized sidecar).
pub fn load_cached(db: &impl ReadableDatabase, expected_hash: u64) -> Result<Snapshot> {
    let rtxn = db
        .begin_read()
        .map_err(|e| Error::Storage(format!("begin read: {e}")))?;
    let meta = match read_meta_row(&rtxn)? {
        None => return Ok(Snapshot::Miss),
        Some(meta) => meta,
    };
    if meta.content_hash != expected_hash {
        let annotations = read_annotations_or_empty(&rtxn)?;
        return Ok(Snapshot::Stale { meta, annotations });
    }
    if meta.version != SCHEMA_VERSION {
        return Err(Error::Storage(format!(
            "project db version {} != {}",
            meta.version, SCHEMA_VERSION
        )));
    }
    let arch = parse_arch(&meta.arch)?;
    parse_format(&meta.format)?;
    let parts = read_analysis_parts(&rtxn)?;
    let annotations = read_annotations(&rtxn)?;
    let analysis = Analysis::from_parts(
        arch,
        parts.functions,
        &parts.call_edges,
        parts.xrefs,
        parts.strings,
    );
    Ok(Snapshot::Hit(Box::new(Loaded {
        meta,
        analysis,
        annotations,
    })))
}

/// Load a snapshot written by [`save`].
///
/// Returns `Ok(None)` when the DB has no snapshot yet (fresh file or no
/// `meta` table). Rebuilds CFGs and the callgraph from stored edges.
/// Prefer [`load_cached`] on open paths: it skips decoding derived rows the
/// caller would discard after a content-hash mismatch.
///
/// # Errors
/// [`Error::Storage`] on corrupt rows or unknown arch/format values,
/// [`Error::Limit`] when snapshot row or byte budgets are exceeded.
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
    let parts = read_analysis_parts(&rtxn)?;
    let annotations = read_annotations(&rtxn)?;
    let analysis = Analysis::from_parts(
        arch,
        parts.functions,
        &parts.call_edges,
        parts.xrefs,
        parts.strings,
    );
    Ok(Some(Loaded {
        meta,
        analysis,
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
}
