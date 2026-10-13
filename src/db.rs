//! M5 persist: `redb` project store plus annotations.
//!
//! One project DB holds a single binary's snapshot: the [`BinaryMeta`] row,
//! one [`FunctionRecord`] per function, one [`BlockRecord`] per basic block,
//! the [`Xref`] set, extracted [`StringHit`]s, and user [`Annotation`]s.
//! Values are JSON so rows stay debuggable with any `redb` inspector.
//!
//! [`save`] rewrites every table in one transaction; [`load`] rebuilds the
//! [`Analysis`] via [`Analysis::from_parts`](crate::analysis::Analysis::from_parts)
//! and returns stored annotations untouched. Callers detect a changed binary
//! by comparing [`content_hash`] against [`BinaryMeta::content_hash`]:
//! re-analysis runs, annotations carry over by address, and only an explicit
//! [`save`] writes — the analyzed binary itself is only ever read.

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
/// # Errors
/// [`Error::Storage`] when the file cannot be created or opened.
pub fn open_db(path: &Path) -> Result<Database> {
    Database::create(path).map_err(|e| Error::Storage(format!("open db: {e}")))
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

/// Persist `meta`, `analysis`, and `annotations` to `db` in one transaction.
///
/// Clears all seven tables first so a smaller re-analysis leaves no stale
/// rows. Never touches the analyzed binary.
///
/// # Errors
/// [`Error::Storage`] on any `redb` or encoding failure.
pub fn save(
    db: &Database,
    meta: &BinaryMeta,
    analysis: &Analysis,
    annotations: &BTreeMap<u64, Annotation>,
) -> Result<()> {
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

/// Load a snapshot written by [`save`].
///
/// Returns `Ok(None)` when the DB has no snapshot yet (fresh file or no
/// `meta` table). Rebuilds CFGs and the callgraph from stored edges.
///
/// # Errors
/// [`Error::Storage`] on corrupt rows or unknown arch/format values.
pub fn load(db: &Database) -> Result<Option<Loaded>> {
    let rtxn = db
        .begin_read()
        .map_err(|e| Error::Storage(format!("begin read: {e}")))?;
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

    let meta: BinaryMeta = {
        let t = rtxn
            .open_table(BINARIES)
            .map_err(|e| Error::Storage(format!("open binaries: {e}")))?;
        let row = t
            .get(0u64)
            .map_err(|e| Error::Storage(format!("read binaries: {e}")))?
            .ok_or_else(|| Error::Storage("project db has meta but no binary row".to_string()))?;
        decode(&row.value())?
    };
    if meta.version != SCHEMA_VERSION {
        return Err(Error::Storage(format!(
            "project db version {} != {}",
            meta.version, SCHEMA_VERSION
        )));
    }
    let arch = parse_arch(&meta.arch)?;
    parse_format(&meta.format)?;

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
            records.push(decode(&v.value())?);
        }
    }
    let mut blocks_by_func: BTreeMap<u64, BTreeMap<u64, BasicBlock>> = BTreeMap::new();
    let mut edges_by_func: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
    {
        let t = rtxn
            .open_table(BLOCKS)
            .map_err(|e| Error::Storage(format!("open blocks: {e}")))?;
        for row in t
            .iter()
            .map_err(|e| Error::Storage(format!("read blocks: {e}")))?
        {
            let (_, v) = row.map_err(|e| Error::Storage(format!("read blocks: {e}")))?;
            let rec: BlockRecord = decode(&v.value())?;
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
            xrefs.push(decode(&v.value())?);
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
            strings.push(decode(&v.value())?);
        }
    }
    let mut annotations: BTreeMap<u64, Annotation> = BTreeMap::new();
    {
        let t = rtxn
            .open_table(ANNOTATIONS)
            .map_err(|e| Error::Storage(format!("open annotations: {e}")))?;
        for row in t
            .iter()
            .map_err(|e| Error::Storage(format!("read annotations: {e}")))?
        {
            let (k, v) = row.map_err(|e| Error::Storage(format!("read annotations: {e}")))?;
            let ann: Annotation = decode(&v.value())?;
            if !ann.is_empty() {
                annotations.insert(k.value(), ann);
            }
        }
    }
    let analysis = Analysis::from_parts(arch, functions, &call_edges, xrefs, strings);
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
