//! binscout MCP server: 32 tools over a cached [`Project`].
//!
//! Every tool takes a `binary` path (plus optional `db` sidecar path), opens
//! the project, and returns one JSON document as text. Failures surface as
//! tool errors, never as silent empty results.
//!
//! Opens go through a small in-process LRU (`CACHE_CAPACITY` entries):
//! the first call for a binary pays the full open (file read, content hash,
//! analysis or sidecar replay) while repeat calls only stat the binary and
//! reuse the entry while its length and mtime agree. A changed file reopens
//! outside any lock and replaces the entry. Reads never save; the sidecar
//! is written solely by `load` and the annotation/seed setters, exactly like
//! the CLI.
//!
//! Tool bodies are `async` and run the open inside
//! [`tokio::task::spawn_blocking`], so analysis never stalls the MCP event
//! loop. Only a brief map lookup plus one per-project [`Mutex`] guard the
//! cached entries, so different binaries open concurrently.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::SystemTime;

use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ServerHandler, tool, tool_handler, tool_router};

use crate::{FunctionFilter, Project, parse_addr, parse_xref_kind};

/// Explicit raw mapping for MCP binary-taking tools.
///
/// Mirrors the CLI `--raw --arch ARCH --base ADDR [--entry ADDR]` flags:
/// `arch`/`base` are required when `raw` is present, `entry` is optional,
/// and addresses parse as `0x`-hex or decimal via [`parse_addr`].
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct RawParams {
    /// Raw arch: `x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`.
    pub arch: Option<String>,
    /// Raw base address (`0x`-hex or decimal string).
    pub base: Option<String>,
    /// Raw entry address (`0x`-hex or decimal string).
    pub entry: Option<String>,
}

/// Max live projects in the in-process MCP cache: enough for an agent
/// comparing a couple of builds, small enough that idle entries cannot pile
/// up resident analysis. In-flight calls keep their `Arc` alive past
/// eviction, so eviction never invalidates a running query.
const CACHE_CAPACITY: usize = 4;

/// Identity of one cached project: canonical binary path, resolved sidecar
/// path, and loader mapping description. File identity (length plus mtime)
/// rides alongside in the entry and revalidates on every call, so an edited
/// binary reopens instead of serving stale analysis.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct CacheKey {
    /// Canonicalized binary path.
    binary: String,
    /// Explicit `db` path (canonicalized when it exists, absolutized
    /// otherwise) or the default sidecar of the canonical binary.
    db: String,
    /// Loader mapping ([`crate::db::StoredMapping::describe`]).
    mapping: String,
}

/// One cached open: validation file facts plus the project behind its own
/// lock. Sharing the handler shares the cache; each entry serializes its
/// own queries and read-modify-write annotations independently of the
/// other entries.
#[derive(Debug)]
struct ProjectEntry {
    /// Cache identity; never inserted for fallback opens that skipped the
    /// stat (missing binary: the open reports the error instead).
    key: CacheKey,
    /// Binary length at open time; a mismatch reopens.
    file_len: u64,
    /// Binary mtime at open time; a mismatch reopens.
    file_mtime: SystemTime,
    /// The open project. Mutations (rename/comment/import) hold this
    /// across their persist; queries hold it across row reads.
    project: Mutex<Project>,
}

impl ProjectEntry {
    /// Lock the project, tolerating a poisoned mutex: a panicked tool call
    /// must not wedge later calls on the same binary.
    fn lock_project(&self) -> MutexGuard<'_, Project> {
        self.project.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// In-memory-only entry for opens that skipped validation (the binary
    /// could not be statted, so no later call could match it anyway).
    fn ephemeral(project: Project) -> Self {
        Self {
            key: CacheKey {
                binary: String::new(),
                db: String::new(),
                mapping: String::new(),
            },
            file_len: 0,
            file_mtime: SystemTime::UNIX_EPOCH,
            project: Mutex::new(project),
        }
    }
}

/// In-process LRU over open projects, shared by every tool call served by
/// one `binscout-mcp` process. The map lock is held only for pointer
/// manipulations, never across file I/O or analysis.
#[derive(Debug, Default)]
struct ProjectCache {
    /// Entries plus MRU-first key order.
    state: Mutex<CacheState>,
}

/// Map plus recency order behind [`ProjectCache::state`].
#[derive(Debug, Default)]
struct CacheState {
    /// Live entries by identity.
    entries: HashMap<CacheKey, Arc<ProjectEntry>>,
    /// Key recency, most-recently-used first.
    order: VecDeque<CacheKey>,
}

impl ProjectCache {
    /// Return the entry when the key is cached and the file facts still
    /// match, refreshing its recency. A length/mtime mismatch returns
    /// `None` so the caller reopens and replaces the entry; the stale
    /// entry stays valid for calls already holding it.
    fn lookup(&self, key: &CacheKey, len: u64, mtime: SystemTime) -> Option<Arc<ProjectEntry>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let entry = state.entries.get(key)?.clone();
        if entry.file_len != len || entry.file_mtime != mtime {
            return None;
        }
        if let Some(pos) = state.order.iter().position(|k| k == key) {
            state.order.remove(pos);
        }
        state.order.push_front(key.clone());
        Some(entry)
    }

    /// Insert an entry, replacing the same key or evicting
    /// least-recently-used entries past [`CACHE_CAPACITY`].
    fn insert(&self, entry: Arc<ProjectEntry>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = state.order.iter().position(|k| k == &entry.key) {
            state.order.remove(pos);
        }
        state.order.push_front(entry.key.clone());
        state.entries.insert(entry.key.clone(), entry);
        while state.entries.len() > CACHE_CAPACITY {
            match state.order.pop_back() {
                Some(old) => {
                    state.entries.remove(&old);
                }
                None => break,
            }
        }
    }
}

/// Join failure of a blocking open: the analysis thread itself never
/// returns this, only a cancelled runtime does.
fn join_error(e: tokio::task::JoinError) -> ErrorData {
    ErrorData::internal_error(format!("background open failed: {e}"), None)
}

/// Resolve an explicit `db` string for cache identity: canonicalized when
/// the file exists, else its canonicalized parent plus the file name.
/// Best-effort: distinct spellings of one path only cost a duplicate
/// entry, never a wrong one.
///
/// Parent canonicalization (not just absolutization) keeps the key
/// stable across sidecar creation: the pre-creation key must equal the
/// post-creation canonical path, or one file would fork into two cache
/// keys — and two handle mutexes, breaking the single-handle guarantee.
/// (`/tmp` on macOS is a symlink, so a plain absolute path is not
/// stable.) When even the parent is unresolvable the open itself will
/// fail, so any stable string does.
fn resolve_db_str(db: &str) -> String {
    if let Ok(canonical) = std::fs::canonicalize(db) {
        return canonical.display().to_string();
    }
    let path = Path::new(db);
    if let (Some(parent), Some(file)) = (path.parent(), path.file_name())
        && let Ok(canon_parent) = std::fs::canonicalize(parent)
    {
        return canon_parent.join(file).display().to_string();
    }
    if path.is_absolute() {
        return db.to_string();
    }
    match std::env::current_dir() {
        Ok(cwd) => {
            let base = std::fs::canonicalize(&cwd).unwrap_or(cwd);
            base.join(path).display().to_string()
        }
        Err(_) => db.to_string(),
    }
}

/// Shared validated opener: explicit `db` path (or the default sidecar),
/// the optional explicit raw mapping, and the optional fat Mach-O slice
/// selection, parsed through [`crate::parse_raw_options`] so CLI and MCP
/// interpret options identically. Never saves; see [`Project::save`].
fn open_uncached(
    binary: &str,
    db: Option<&str>,
    raw_opts: Option<crate::loader::RawOptions>,
    fat_arch: Option<&str>,
) -> Result<Project, ErrorData> {
    let db_path;
    let db_ref = match db {
        Some(d) => {
            db_path = Path::new(d).to_path_buf();
            Some(db_path.as_path())
        }
        None => None,
    };
    crate::open_mapped(Path::new(binary), db_ref, raw_opts, fat_arch).map_err(|e| match e {
        crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
        other => ErrorData::internal_error(other.to_string(), None),
    })
}

/// Parse an MCP `raw` object through the shared CLI/MCP validator.
fn raw_options(raw: Option<&RawParams>) -> Result<Option<crate::loader::RawOptions>, ErrorData> {
    let (present, arch, base, entry) = match raw {
        None => (false, None, None, None),
        Some(r) => (
            true,
            r.arch.as_deref(),
            r.base.as_deref(),
            r.entry.as_deref(),
        ),
    };
    crate::parse_raw_options(present, arch, base, entry).map_err(|e| match e {
        crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
        other => ErrorData::internal_error(other.to_string(), None),
    })
}

fn ok(value: serde_json::Value) -> Result<String, ErrorData> {
    serde_json::to_string(&value)
        .map_err(|e| ErrorData::internal_error(format!("serialize result: {e}"), None))
}

fn opt_addr(s: Option<String>) -> Result<Option<u64>, ErrorData> {
    s.map(|v| parse_addr(&v))
        .transpose()
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))
}

fn all_params<T>(p: Parameters<T>) -> T {
    p.0
}

/// Parameters for single-binary tools (`project_info`, `symbols`, `sections`, `stats`).
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BinaryParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping (`arch`/`base` required, `entry` optional).
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
}

/// Parameters for the `strings` tool: filtered, paged string search.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct StringsParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Rows to skip after filtering.
    pub start: Option<usize>,
    /// Deprecated alias of `start` (warns on stderr).
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
    /// Wrap matches in the protocol-1 page envelope with an exact `total`
    /// (opt-in preview of the planned strings-shape migration; default
    /// stays a bare array).
    pub envelope: Option<bool>,
    /// Case-sensitive substring, or `regex:`-prefixed expression.
    pub pattern: Option<String>,
    /// Keep strings with at least this many characters.
    pub min_len: Option<usize>,
    /// Keep strings in exactly this section (e.g. `.rdata`).
    pub section: Option<String>,
    /// Show strings in executable memory (hidden by default).
    pub include_code: Option<bool>,
    /// Decode-and-display view over an in-memory transform: `xor:<byte>`,
    /// `add:<byte>`, or `rot:<0-7>` (byte is `0x`-hex or decimal). Reveals
    /// single-byte-obfuscated text with original offsets; never writes the
    /// binary.
    pub decode: Option<String>,
}

/// Parameters for the `functions` tool: paged list with optional filters.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FunctionsParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Case-insensitive substring over the rename-resolved name.
    pub query: Option<String>,
    /// Keep functions that call the function containing this address.
    pub caller: Option<String>,
    /// Keep functions called by the function containing this address.
    pub callee: Option<String>,
    /// Keep functions with entry at or above this address (needs range_hi).
    /// Inclusive bounds (`entry >= lo && entry <= hi`).
    pub range_lo: Option<String>,
    /// Keep functions with entry at or below this address (needs range_lo).
    /// Inclusive bounds (`entry >= lo && entry <= hi`).
    pub range_hi: Option<String>,
    /// Deprecated alias of `range_lo` (inclusive semantics, warns on
    /// stderr). `range_lo` wins when both are given.
    pub range_start: Option<String>,
    /// Deprecated alias of `range_hi` (inclusive semantics, warns on
    /// stderr). `range_hi` wins when both are given.
    pub range_end: Option<String>,
    /// First row to return.
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
    /// Wrap matches in the protocol-1 page envelope with an exact `total`
    /// and compact `calls_count` rows (opt-in preview of the planned
    /// functions-shape migration; default stays a bare array with the
    /// full `calls` target array).
    pub envelope: Option<bool>,
}

/// Parameters for single-address tools (`func`, `cfg`, `structure`, `pseudo`).
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddrParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Virtual address (`0x`-hex or decimal string).
    pub addr: String,
}

/// Parameters for the `blocks` tool: one function's block summaries, paged.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BlocksParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Function address: any address inside the function snaps to its
    /// containing entry.
    pub addr: String,
    /// First row to return.
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
}

/// Parameters for the `block_insns` tool: one block's instructions, paged.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BlockInsnsParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Function address: any address inside the function snaps to its
    /// containing entry.
    pub addr: String,
    /// Block start address; must belong to the containing function.
    pub block: String,
    /// First row to return.
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
}

/// Parameters for the `diagnostics` tool: paged provenance records.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DiagnosticsParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Only `unresolved-indirect-jump`, `unresolved-indirect-call`, or
    /// `decode-failure` sites.
    pub kind: Option<String>,
    /// Only sites in the function containing this address (`0x`-hex or
    /// decimal string).
    pub func: Option<String>,
    /// First row to return.
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
}

/// Parameters for byte-range tools (`disasm`, `ir`).
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RangeParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Virtual address (`0x`-hex or decimal string).
    pub addr: String,
    /// Bytes to decode.
    pub len: usize,
}

/// Parameters for the `bytes` tool: raw byte range with typed views.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BytesParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Virtual address (`0x`-hex or decimal string).
    pub addr: String,
    /// Bytes to read (capped at 1 MiB).
    pub len: usize,
    /// Typed view: `u8`, `u16`, `u32`, `u64`, `ptr`, `cstr`, `utf16` (default `u8`).
    pub r#as: Option<String>,
    /// Byte order for multi-byte views: `le` or `be` (default `le`).
    pub endian: Option<String>,
}

/// Parameters for the `xrefs` tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct XrefsParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Only xrefs pointing at this address (`0x`-hex or decimal).
    pub to: Option<String>,
    /// Only xrefs originating at this address.
    pub from: Option<String>,
    /// Only `code`, `data`, `string`, `import`, or `inferred-code` xrefs.
    pub kind: Option<String>,
    /// First row to return.
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
}

/// Parameters for the `ir_coverage` tool: arch-only coverage, or coverage
/// plus per-range accounting when `binary`/`addr`/`len` are all given.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct IrCoverageParams {
    /// Coverage arch: `x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`.
    pub arch: String,
    /// Path to the analyzed binary (needs `addr` and `len` for a range).
    pub binary: Option<String>,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Range address (`0x`-hex or decimal string; needs `binary` and `len`).
    pub addr: Option<String>,
    /// Range length in bytes (needs `binary` and `addr`).
    pub len: Option<usize>,
}

/// Parameters for the `rename` tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RenameParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Function entry address (`0x`-hex or decimal string).
    pub addr: String,
    /// New name (empty string clears).
    pub name: String,
}

/// Parameters for the `comment` tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CommentParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Address to comment (`0x`-hex or decimal string).
    pub addr: String,
    /// Comment text (empty string clears).
    pub comment: String,
}

/// Parameters for the `define_func` tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DefineFuncParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Seed address (`0x`-hex or decimal string, any address accepted).
    pub addr: String,
    /// 32-bit ARM decode mode: `arm` or `thumb` (other arches reject it).
    pub mode: Option<String>,
}

/// Parameters for the `undefine_func` tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UndefineFuncParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Seed address (`0x`-hex or decimal string, any address accepted).
    pub addr: String,
}

/// Parameters for the `search_bytes` tool: bounded byte-pattern search.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SearchBytesParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Whitespace-separated full-byte tokens: two hex digits or `??`.
    pub pattern: String,
    /// Keep matches fully inside this section (e.g. `.text`).
    pub section: Option<String>,
    /// Range start (`0x`-hex or decimal, needs range_end). Half-open
    /// `[lo, hi)` over match virtual addresses.
    pub range_start: Option<String>,
    /// Range end (`0x`-hex or decimal, needs range_start). Half-open
    /// `[lo, hi)` over match virtual addresses.
    pub range_end: Option<String>,
    /// Deprecated alias of `range_start` (half-open semantics, warns on
    /// stderr). `range_start` wins when both are given.
    pub range_lo: Option<String>,
    /// Deprecated alias of `range_end` (half-open semantics, warns on
    /// stderr). `range_end` wins when both are given.
    pub range_hi: Option<String>,
    /// First row to return.
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
}

/// Parameters for the `callees`/`callers` tools: depth-bounded transitive
/// callgraph reachability, paged under the protocol-1 envelope.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CallgraphParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Query address: any address inside the root function snaps to its
    /// containing entry.
    pub addr: String,
    /// Max call edges from the root (direct neighbors are depth 1;
    /// defaults to the 64-hop cap).
    pub depth: Option<usize>,
    /// First row to return.
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
}

/// Parameters for the `slice` tool: depth-bounded backward reachability
/// to one address, paged under the protocol-1 envelope.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SliceParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Slice root: every returned instruction can reach this address
    /// (`0x`-hex or decimal string; any address is valid, including
    /// data/string targets in no function).
    pub addr: String,
    /// Max reverse hops from the root (direct predecessors are depth 1;
    /// defaults to the 64-hop cap).
    pub depth: Option<usize>,
    /// First row to return.
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
}

/// Parameters for the `annotations_import` tool: merge a portable document.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AnnotationsImportParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Interchange document, as returned by `annotations_export`.
    pub document: String,
    /// Replace supplied fields on conflict instead of failing.
    pub overwrite: Option<bool>,
}

/// Parameters for the `flirt_hints` tool: read-only library-idiom hints.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FlirtHintsParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection (canonical `x86_64`/`x86_32`/`aarch64`/`arm32`
    /// or a `lipo` alias like `arm64`); required for fat containers.
    pub fat_arch: Option<String>,
    /// Only hints for the function containing this address (`0x`-hex or
    /// decimal string).
    pub addr: Option<String>,
    /// First row to return.
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
}

/// Parameters for the `diff` tool: function-level diff between two binaries.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DiffParams {
    /// Path of the first (baseline) binary.
    pub binary_a: String,
    /// Path of the second (new) binary.
    pub binary_b: String,
    /// Explicit project DB path for side A.
    pub db_a: Option<String>,
    /// Explicit project DB path for side B.
    pub db_b: Option<String>,
    /// Optional explicit raw mapping, applied to both binaries (the
    /// two-builds case shares one mapping).
    pub raw: Option<RawParams>,
    /// Fat Mach-O slice selection, applied to both binaries (the two-builds
    /// case shares one selection); required for fat containers.
    pub fat_arch: Option<String>,
}

/// MCP server handler; tools share one project cache.
///
/// The cache lock is held only for map manipulations: opens run outside
/// any lock (in `spawn_blocking`), and each cached project carries its own
/// [`Mutex`], so calls on different binaries proceed concurrently while
/// calls on one binary serialize. `redb` handles are never held across
/// calls — every sidecar open/save reopens its file under that file's
/// handle mutex (see the `db_locks` field), so the single-handle rule
/// holds without a global call lock.
#[derive(Debug, Clone, Default)]
pub struct BinscoutMcp {
    /// In-process LRU over open projects (see [`ProjectCache`]).
    cache: Arc<ProjectCache>,
    /// One mutex per sidecar path, shared by every entry that names it.
    ///
    /// `redb` enforces a single open handle per file per process with an
    /// OS file lock: a second open while a writable handle lives fails
    /// with `DatabaseAlreadyOpen`. Every window holding a sidecar handle —
    /// miss opens (read-only) and annotation persists/saves (writable) —
    /// runs under the file's mutex, so same-sidecar calls serialize while
    /// different sidecars proceed concurrently. Weak refs so idle files
    /// release their mutex; any spelling that resolves to one path shares
    /// one mutex through [`resolve_db_str`].
    db_locks: Arc<Mutex<HashMap<String, Weak<Mutex<()>>>>>,
}

impl BinscoutMcp {
    /// New handler with a fresh project cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mutex serializing sidecar-handle windows for one resolved `db` path
    /// (see the [`BinscoutMcp::db_locks`] field docs). Shared by opens and
    /// persists; always taken before the entry lock, never after.
    fn db_lock(&self, db: &str) -> Arc<Mutex<()>> {
        let mut locks = self.db_locks.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(live) = locks.get(db).and_then(Weak::upgrade) {
            return live;
        }
        let live = Arc::new(Mutex::new(()));
        locks.insert(db.to_string(), Arc::downgrade(&live));
        locks.retain(|_, w| w.strong_count() > 0);
        live
    }

    /// Cache identity plus validation facts for one open request, or `None`
    /// when the binary cannot be statted: the open path then runs uncached
    /// so it reports the canonical error.
    fn cache_key(
        binary: &str,
        db: Option<&str>,
        raw_opts: Option<crate::loader::RawOptions>,
        fat_arch: Option<&str>,
    ) -> Result<Option<(CacheKey, u64, SystemTime)>, ErrorData> {
        let bin_path = Path::new(binary);
        let (meta, canonical) = match (std::fs::metadata(bin_path), std::fs::canonicalize(bin_path))
        {
            (Ok(meta), Ok(canonical)) => (meta, canonical),
            _ => return Ok(None),
        };
        let mtime = match meta.modified() {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };
        let mapping = match (raw_opts, fat_arch) {
            (Some(_), Some(_)) => {
                return Err(ErrorData::invalid_params(
                    "--raw and --fat-arch are exclusive (or MCP raw with fat_arch)",
                    None,
                ));
            }
            (Some(opts), None) => crate::db::StoredMapping::for_request(Some(opts)),
            (None, Some(arch)) => crate::db::StoredMapping::for_fat_slice(arch),
            (None, None) => crate::db::StoredMapping::for_request(None),
        };
        let db_str = match db {
            Some(d) => resolve_db_str(d),
            None => format!("{}.rsdbg.redb", canonical.display()),
        };
        Ok(Some((
            CacheKey {
                binary: canonical.display().to_string(),
                db: db_str,
                mapping: mapping.describe(),
            },
            meta.len(),
            mtime,
        )))
    }

    /// Open through the cache: a length/mtime-validated hit returns the
    /// live entry, otherwise the binary opens outside any lock and the
    /// result replaces the entry. Synchronous file I/O and analysis: call
    /// from `spawn_blocking` via [`BinscoutMcp::open_owned`].
    fn cached_entry(
        &self,
        binary: &str,
        db: Option<&str>,
        raw: Option<&RawParams>,
        fat_arch: Option<&str>,
    ) -> Result<Arc<ProjectEntry>, ErrorData> {
        let raw_opts = raw_options(raw)?;
        let keyed = Self::cache_key(binary, db, raw_opts, fat_arch)?;
        let Some((key, len, mtime)) = keyed else {
            return Ok(Arc::new(ProjectEntry::ephemeral(open_uncached(
                binary, db, raw_opts, fat_arch,
            )?)));
        };
        if let Some(hit) = self.cache.lookup(&key, len, mtime) {
            return Ok(hit);
        }
        // The sidecar read inside the open holds a handle, so it runs under
        // the file mutex; analysis itself needs no lock and concurrent
        // misses on other files proceed.
        let db_mutex = self.db_lock(&key.db);
        let _db_guard = db_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let project = open_uncached(binary, db, raw_opts, fat_arch)?;
        // Re-stat so the stored facts describe the opened bytes; when the
        // file changed mid-open (or vanished) the entry stays ephemeral and
        // the next call revalidates from scratch.
        let entry = match Self::cache_key(binary, db, raw_opts, fat_arch)? {
            Some((_, fresh_len, fresh_mtime)) => {
                let entry = Arc::new(ProjectEntry {
                    key,
                    file_len: fresh_len,
                    file_mtime: fresh_mtime,
                    project: Mutex::new(project),
                });
                self.cache.insert(entry.clone());
                entry
            }
            None => Arc::new(ProjectEntry::ephemeral(project)),
        };
        Ok(entry)
    }

    /// Async entry point for every binary-taking tool: the open (file
    /// read, hash, analysis or sidecar replay) runs on the blocking pool
    /// while the caller only awaits the `Arc`. Queries then run inline
    /// under the entry lock: row reads plus serialization, no I/O.
    async fn open_owned(
        &self,
        binary: String,
        db: Option<String>,
        raw: Option<RawParams>,
        fat_arch: Option<String>,
    ) -> Result<Arc<ProjectEntry>, ErrorData> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            this.cached_entry(&binary, db.as_deref(), raw.as_ref(), fat_arch.as_deref())
        })
        .await
        .map_err(join_error)?
    }
}

#[tool_handler(
    name = "binscout-mcp",
    instructions = "Headless agent-first binary analysis. Every tool takes a binary path and returns one JSON document as text."
)]
impl ServerHandler for BinscoutMcp {}

#[tool_router]
impl BinscoutMcp {
    #[tool(
        name = "project_info",
        description = "Open a binary and report arch, format, entry, and analysis counts"
    )]
    async fn project_info(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        ok(serde_json::to_value(proj.project_info()).expect("project_info serializes"))
    }

    #[tool(
        name = "load",
        description = "Open a binary and persist the analysis snapshot to the project DB (binary untouched); CLI `load` parity, warms the sidecar so later opens replay it instead of re-analyzing"
    )]
    async fn load(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let db_mutex = self.db_lock(&entry.key.db);
        let _db_guard = db_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let proj = entry.lock_project();
        // Same skip as CLI `load`: a fresh snapshot needs no rewrite.
        if !proj.snapshot_fresh() {
            proj.save()
                .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        }
        ok(serde_json::to_value(proj.project_info()).expect("project_info serializes"))
    }

    #[tool(
        name = "functions",
        description = "List functions with rename-resolved names, filtered by query/caller/callee/range, paged by offset/limit. Range is inclusive (entry >= lo and <= hi); range_start/range_end are deprecated aliases of range_lo/range_hi. envelope:true wraps matches in the protocol-1 page envelope with an exact total and compact calls_count rows"
    )]
    async fn functions(&self, p: Parameters<FunctionsParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        if p.range_start.is_some() {
            eprintln!("warning: functions range_start is deprecated, use range_lo");
        }
        if p.range_end.is_some() {
            eprintln!("warning: functions range_end is deprecated, use range_hi");
        }
        // Cloned before the move into the open so filter errors keep their
        // post-open precedence (a missing binary still reports first).
        let (
            query,
            caller,
            callee,
            range_lo,
            range_hi,
            alias_lo,
            alias_hi,
            offset,
            limit,
            envelope,
        ) = (
            p.query.clone(),
            p.caller.clone(),
            p.callee.clone(),
            p.range_lo.clone(),
            p.range_hi.clone(),
            p.range_start.clone(),
            p.range_end.clone(),
            p.offset,
            p.limit,
            p.envelope.unwrap_or(false),
        );
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let lo = range_lo.or(alias_lo);
        let hi = range_hi.or(alias_hi);
        let filter = FunctionFilter {
            query,
            caller: opt_addr(caller)?,
            callee: opt_addr(callee)?,
            range: match (lo, hi) {
                (None, None) => None,
                (Some(lo), Some(hi)) => Some((
                    parse_addr(&lo).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?,
                    parse_addr(&hi).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?,
                )),
                _ => {
                    return Err(ErrorData::invalid_params(
                        "range_lo and range_hi must be given together",
                        None,
                    ));
                }
            },
        };
        if envelope {
            ok(serde_json::to_value(proj.functions_envelope(
                &filter,
                offset.unwrap_or(0),
                limit.unwrap_or(50),
            ))
            .expect("functions envelope serializes"))
        } else {
            let rows = proj.functions_filtered(&filter, offset.unwrap_or(0), limit.unwrap_or(50));
            ok(serde_json::Value::Array(rows))
        }
    }

    #[tool(
        name = "func",
        description = "Compact metadata of one function: entry, name, and block/insn/call counts. Any address inside the function snaps to its containing entry"
    )]
    async fn func(&self, p: Parameters<AddrParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let addr_s = p.addr.clone();
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.func_meta(addr)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(|m| ok(serde_json::to_value(m).expect("func_meta serializes")))
    }

    #[tool(
        name = "blocks",
        description = "Block summaries of one function ordered by block start, paged with total block count. Any address inside the function snaps to its containing entry"
    )]
    async fn blocks(&self, p: Parameters<BlocksParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (addr_s, offset, limit) = (p.addr.clone(), p.offset, p.limit);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.func_blocks_page(addr, offset.unwrap_or(0), limit.unwrap_or(50))
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(|page| ok(serde_json::to_value(page).expect("blocks page serializes")))
    }

    #[tool(
        name = "block_insns",
        description = "Instructions of one function-owned block in address order, paged. Addr snaps to its containing function; block must be a block start belonging to that function"
    )]
    async fn block_insns(&self, p: Parameters<BlockInsnsParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (addr_s, block_s, offset, limit) = (p.addr.clone(), p.block.clone(), p.offset, p.limit);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        let block =
            parse_addr(&block_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.func_block_insns_page(addr, block, offset.unwrap_or(0), limit.unwrap_or(50))
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(|page| ok(serde_json::to_value(page).expect("block_insns page serializes")))
    }

    #[tool(
        name = "diagnostics",
        description = "Analysis provenance: unresolved indirect sites and decode failures, filtered by kind and containing function, paged under the protocol-1 envelope"
    )]
    async fn diagnostics(&self, p: Parameters<DiagnosticsParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (kind_s, func_s, offset, limit) = (p.kind.clone(), p.func.clone(), p.offset, p.limit);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let kind = kind_s
            .as_deref()
            .map(crate::parse_diagnostic_kind)
            .transpose()
            .map_err(|e| match e {
                crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
                other => ErrorData::internal_error(other.to_string(), None),
            })?;
        let func = opt_addr(func_s)?;
        proj.query_diagnostics(kind, func, offset.unwrap_or(0), limit.unwrap_or(50))
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(|page| ok(serde_json::to_value(page).expect("diagnostics page serializes")))
    }

    #[tool(
        name = "disasm",
        description = "Disassemble len bytes at addr with the binary architecture; returns the valid prefix plus error_at for the first bad opcode (null on a clean range)"
    )]
    async fn disasm(&self, p: Parameters<RangeParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (addr_s, len) = (p.addr.clone(), p.len);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.disasm_at(addr, len)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(|v| ok(serde_json::to_value(v).expect("partial disasm serializes")))
    }

    #[tool(
        name = "bytes",
        description = "Read len bytes at addr with typed views and VA/file provenance; returns addr twins, file_off (null for zero-fill), section, bytes_hex, and decoded values (ranges cap at 1 MiB)"
    )]
    async fn bytes(&self, p: Parameters<BytesParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (addr_s, len, as_s, endian_s) =
            (p.addr.clone(), p.len, p.r#as.clone(), p.endian.clone());
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        let as_ = as_s
            .as_deref()
            .map(crate::parse_bytes_as)
            .transpose()
            .map_err(|e| match e {
                crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
                other => ErrorData::internal_error(other.to_string(), None),
            })?
            .unwrap_or(crate::BytesAs::U8);
        let endian = endian_s
            .as_deref()
            .map(crate::parse_bytes_endian)
            .transpose()
            .map_err(|e| match e {
                crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
                other => ErrorData::internal_error(other.to_string(), None),
            })?
            .unwrap_or(crate::BytesEndian::Le);
        proj.bytes_view(addr, len, as_, endian)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(|v| ok(serde_json::to_value(v).expect("bytes view serializes")))
    }

    #[tool(
        name = "cfg",
        description = "Control-flow graph of one function: block nodes plus block edges. Any address inside the function snaps to its containing entry"
    )]
    async fn cfg(&self, p: Parameters<AddrParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let addr_s = p.addr.clone();
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.cfg_of(addr)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(ok)
    }

    #[tool(
        name = "structure",
        description = "Approximate control-flow structure of one function: syntactic loops (back-edge headers with latches) and ifs (two-successor branch sites with then/else targets) plus an approximation warning. Any address inside the function snaps to its containing entry"
    )]
    async fn structure(&self, p: Parameters<AddrParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let addr_s = p.addr.clone();
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.structure_of(addr)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(ok)
    }

    #[tool(
        name = "pseudo",
        description = "Approximate pseudo-C of one function: one lossy C-like line per IR row plus assembled text, with an approximation warning. Any address inside the function snaps to its containing entry"
    )]
    async fn pseudo(&self, p: Parameters<AddrParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let addr_s = p.addr.clone();
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.pseudo_of(addr)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(ok)
    }

    #[tool(
        name = "callees",
        description = "Transitive callees of one function out to depth hops (direct callees are depth 1), ordered by entry with shortest distance, paged under the protocol-1 envelope. Addr snaps to its containing function"
    )]
    async fn callees(&self, p: Parameters<CallgraphParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (addr_s, depth, offset, limit) = (p.addr.clone(), p.depth, p.offset, p.limit);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.callees_page(
            addr,
            depth.unwrap_or(crate::analysis::MAX_CALL_DEPTH),
            offset.unwrap_or(0),
            limit.unwrap_or(50),
        )
        .map_err(|e| match e {
            crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
            other => ErrorData::internal_error(other.to_string(), None),
        })
        .and_then(|page| ok(serde_json::to_value(page).expect("callees page serializes")))
    }

    #[tool(
        name = "callers",
        description = "Transitive callers of one function out to depth hops (direct callers are depth 1), ordered by entry with shortest distance, paged under the protocol-1 envelope. Addr snaps to its containing function"
    )]
    async fn callers(&self, p: Parameters<CallgraphParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (addr_s, depth, offset, limit) = (p.addr.clone(), p.depth, p.offset, p.limit);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.callers_page(
            addr,
            depth.unwrap_or(crate::analysis::MAX_CALL_DEPTH),
            offset.unwrap_or(0),
            limit.unwrap_or(50),
        )
        .map_err(|e| match e {
            crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
            other => ErrorData::internal_error(other.to_string(), None),
        })
        .and_then(|page| ok(serde_json::to_value(page).expect("callers page serializes")))
    }

    #[tool(
        name = "slice",
        description = "Backward slice of one address: every instruction that can reach it via xref edges (any kind) and intra-function CFG predecessors, out to depth hops (direct predecessors are depth 1), ordered by address with shortest distance, paged under the protocol-1 envelope. Any address is a valid root"
    )]
    async fn slice(&self, p: Parameters<SliceParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (addr_s, depth, offset, limit) = (p.addr.clone(), p.depth, p.offset, p.limit);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.slice_page(
            addr,
            depth.unwrap_or(crate::analysis::MAX_SLICE_DEPTH),
            offset.unwrap_or(0),
            limit.unwrap_or(50),
        )
        .map_err(|e| match e {
            crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
            other => ErrorData::internal_error(other.to_string(), None),
        })
        .and_then(|page| ok(serde_json::to_value(page).expect("slice page serializes")))
    }

    #[tool(
        name = "xrefs",
        description = "Cross-references filtered by to/from address and kind, paged with total match count"
    )]
    async fn xrefs(&self, p: Parameters<XrefsParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (kind_s, to_s, from_s, offset, limit) = (
            p.kind.clone(),
            p.to.clone(),
            p.from.clone(),
            p.offset,
            p.limit,
        );
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let kind = kind_s
            .as_deref()
            .map(parse_xref_kind)
            .transpose()
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        let (to, from) = (opt_addr(to_s)?, opt_addr(from_s)?);
        let (total, rows) =
            proj.query_xrefs_page(to, from, kind, offset.unwrap_or(0), limit.unwrap_or(50));
        ok(serde_json::json!({ "total": total, "xrefs": rows }))
    }

    #[tool(
        name = "strings",
        description = "Extracted strings ordered by address, filtered by pattern/min-len/section, paged by start/limit. Hits in executable memory are hidden unless pattern, section, or include_code is given. Decode renders a read-only single-byte-obfuscated view: xor:<byte>, add:<byte>, or rot:<0-7>. offset is a deprecated alias of start. envelope:true wraps matches in the protocol-1 page envelope with an exact total"
    )]
    async fn strings(&self, p: Parameters<StringsParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        if p.offset.is_some() {
            eprintln!("warning: strings offset is deprecated, use start");
        }
        let decode = p
            .decode
            .as_deref()
            .map(crate::loader::strings::parse_decode_spec)
            .transpose()
            .map_err(|e| match e {
                crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
                other => ErrorData::internal_error(other.to_string(), None),
            })?;
        // Cloned before the move into the open; the decode error above keeps
        // its pre-open precedence.
        let (pattern, min_len, section, include_code, start, offset, limit, envelope) = (
            p.pattern.clone(),
            p.min_len,
            p.section.clone(),
            p.include_code,
            p.start,
            p.offset,
            p.limit,
            p.envelope.unwrap_or(false),
        );
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let filter = crate::analysis::StringsFilter {
            pattern,
            min_len,
            section,
            include_code: include_code.unwrap_or(false),
            start: start.or(offset).unwrap_or(0),
            limit: limit.unwrap_or(50),
        };
        if envelope {
            let page = match decode {
                Some(spec) => proj.query_strings_decoded_envelope(&filter, spec),
                None => proj.query_strings_envelope(&filter),
            }
            .map_err(|e| match e {
                crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
                other => ErrorData::internal_error(other.to_string(), None),
            })?;
            return ok(serde_json::to_value(page).expect("strings envelope serializes"));
        }
        let rows = match decode {
            Some(spec) => proj.query_strings_decoded(&filter, spec),
            None => proj.query_strings(&filter),
        }
        .map_err(|e| match e {
            crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
            other => ErrorData::internal_error(other.to_string(), None),
        })?;
        ok(serde_json::to_value(rows).expect("strings serialize"))
    }

    #[tool(
        name = "symbols",
        description = "Imports, exports, and symbol-table code addresses of the binary"
    )]
    async fn symbols(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        ok(entry.lock_project().symbols_json())
    }

    #[tool(
        name = "stats",
        description = "Storage stats: binary size, sidecar DB size, and analysis counts"
    )]
    async fn stats(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        entry
            .lock_project()
            .stats_json()
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(ok)
    }

    #[tool(
        name = "headers",
        description = "Header metadata: triage staples (PE mitigations/imphash/PDB, ELF interpreter/needed/RELRO/NX/PIE, Mach-O load commands/codesign) plus sha256/md5. Computed on demand from the container bytes, never persisted"
    )]
    async fn headers(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        entry
            .lock_project()
            .headers_json()
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(ok)
    }

    #[tool(
        name = "sections",
        description = "Section table: name, virtual address (PE: IMAGE_BASE + RVA), in-memory and file sizes, permissions"
    )]
    async fn sections(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        ok(entry.lock_project().sections_json())
    }

    #[tool(
        name = "ir",
        description = "Lift len bytes at addr to P-code-inspired IR"
    )]
    async fn ir(&self, p: Parameters<RangeParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (addr_s, len) = (p.addr.clone(), p.len);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.ir_at(addr, len)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(ok)
    }

    #[tool(
        name = "ir_coverage",
        description = "Machine-readable IR lift coverage for one arch (implemented families, partial mappings, limitations); with binary/addr/len adds per-range decoded/lifted/unlifted counts from actual lifts plus a bounded mnemonic summary"
    )]
    async fn ir_coverage(&self, p: Parameters<IrCoverageParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let arch = crate::parse_raw_arch(&p.arch)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        match (p.binary, p.addr, p.len) {
            (None, None, None) => ok(crate::ir_coverage(arch)),
            (Some(binary), Some(addr_s), Some(len)) => {
                let entry = self.open_owned(binary, p.db, p.raw, p.fat_arch).await?;
                let proj = entry.lock_project();
                let addr = parse_addr(&addr_s)
                    .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                proj.ir_coverage_at(arch, addr, len)
                    .map_err(|e| match e {
                        crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
                        other => ErrorData::internal_error(other.to_string(), None),
                    })
                    .and_then(ok)
            }
            _ => Err(ErrorData::invalid_params(
                "ir_coverage range needs binary, addr, and len together",
                None,
            )),
        }
    }

    #[tool(
        name = "rename",
        description = "Rename a function in the project DB (binary untouched); empty name clears"
    )]
    async fn rename(&self, p: Parameters<RenameParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (addr_s, name) = (p.addr.clone(), p.name.clone());
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let db_mutex = self.db_lock(&entry.key.db);
        let _db_guard = db_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let mut proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.rename_function(addr, &name)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        ok(proj.annotation_json(addr))
    }

    #[tool(
        name = "comment",
        description = "Comment any address in the project DB (binary untouched); empty comment clears"
    )]
    async fn comment(&self, p: Parameters<CommentParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (addr_s, comment) = (p.addr.clone(), p.comment.clone());
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let db_mutex = self.db_lock(&entry.key.db);
        let _db_guard = db_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let mut proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.set_comment(addr, &comment)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        ok(proj.annotation_json(addr))
    }

    #[tool(
        name = "annotation",
        description = "Read the annotation at one address (rename/comment with addr twins; nulls when unset). Read-only: never creates or modifies the sidecar; CLI `annotate` without flags parity"
    )]
    async fn annotation(&self, p: Parameters<AddrParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let addr_s = p.addr.clone();
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        ok(proj.annotation_json(addr))
    }

    #[tool(
        name = "define_func",
        description = "Define a user function seed at any address (binary untouched) and re-analyze so the function materializes when the bytes decode; optional 32-bit ARM decode mode arm/thumb"
    )]
    async fn define_func(&self, p: Parameters<DefineFuncParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (addr_s, mode_s) = (p.addr.clone(), p.mode.clone());
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let db_mutex = self.db_lock(&entry.key.db);
        let _db_guard = db_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let mut proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        let mode = mode_s
            .as_deref()
            .map(crate::analysis::SeedMode::parse)
            .transpose()
            .map_err(|e| match e {
                crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
                other => ErrorData::internal_error(other.to_string(), None),
            })?;
        proj.define_func(addr, mode)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        ok(proj.seed_json(addr))
    }

    #[tool(
        name = "undefine_func",
        description = "Exclude a function seed at any address (binary untouched) and re-analyze; the row is kept as data"
    )]
    async fn undefine_func(&self, p: Parameters<UndefineFuncParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let addr_s = p.addr.clone();
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let db_mutex = self.db_lock(&entry.key.db);
        let _db_guard = db_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let mut proj = entry.lock_project();
        let addr =
            parse_addr(&addr_s).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.undefine_func(addr)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        ok(proj.seed_json(addr))
    }

    #[tool(
        name = "search_bytes",
        description = "Search mapped file bytes for a whitespace-separated hex pattern (two hex digits or ?? per token), filtered by section/range, paged with total match count. Range is half-open [lo, hi) over match virtual addresses; range_lo/range_hi are deprecated aliases of range_start/range_end"
    )]
    async fn search_bytes(&self, p: Parameters<SearchBytesParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        if p.range_lo.is_some() {
            eprintln!("warning: search_bytes range_lo is deprecated, use range_start");
        }
        if p.range_hi.is_some() {
            eprintln!("warning: search_bytes range_hi is deprecated, use range_end");
        }
        let (pattern, section, range_start, range_end, alias_lo, alias_hi, offset, limit) = (
            p.pattern.clone(),
            p.section.clone(),
            p.range_start.clone(),
            p.range_end.clone(),
            p.range_lo.clone(),
            p.range_hi.clone(),
            p.offset,
            p.limit,
        );
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let lo = range_start.or(alias_lo);
        let hi = range_end.or(alias_hi);
        let range = match (lo, hi) {
            (None, None) => None,
            (Some(lo), Some(hi)) => Some((
                parse_addr(&lo).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?,
                parse_addr(&hi).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?,
            )),
            _ => {
                return Err(ErrorData::invalid_params(
                    "range_start and range_end must be given together",
                    None,
                ));
            }
        };
        proj.search_bytes(
            &pattern,
            section.as_deref(),
            range,
            offset.unwrap_or(0),
            limit.unwrap_or(50),
        )
        .map_err(|e| match e {
            crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
            other => ErrorData::internal_error(other.to_string(), None),
        })
        .and_then(|page| ok(serde_json::to_value(page).expect("search_bytes page serializes")))
    }

    #[tool(
        name = "annotations_export",
        description = "Emit the portable annotation interchange document (revision, sha256, size, mapping, sorted rows); read-only, never creates or modifies the sidecar"
    )]
    async fn annotations_export(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let doc = proj
            .export_annotations()
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        serde_json::from_str::<serde_json::Value>(&doc)
            .map_err(|e| {
                ErrorData::internal_error(format!("encode annotation document: {e}"), None)
            })
            .and_then(ok)
    }

    #[tool(
        name = "annotations_import",
        description = "Atomically merge a portable annotation document into the project DB; returns row/change counts. Default fails on conflicting fields, overwrite replaces supplied fields only"
    )]
    async fn annotations_import(
        &self,
        p: Parameters<AnnotationsImportParams>,
    ) -> Result<String, ErrorData> {
        let p = all_params(p);
        // Cloned before the move into the open so the transport note below
        // still holds: validation happens after the open, inside the entry
        // lock, before any write.
        let (document, overwrite) = (p.document.clone(), p.overwrite);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let db_mutex = self.db_lock(&entry.key.db);
        let _db_guard = db_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let mut proj = entry.lock_project();
        // Transport note: rmcp delivers `document` as a fully-materialized
        // `String` before this runs, so no pre-parse cap exists at this
        // layer; the core re-checks the 16 MiB serialized cap plus row/text
        // budgets during validation, before any write, and every failure
        // leaves the DB and memory unchanged.
        proj.import_annotations(&document, overwrite.unwrap_or(false))
            .map_err(|e| match e {
                crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
                other => ErrorData::internal_error(other.to_string(), None),
            })
            .and_then(|s| ok(serde_json::json!({"rows": s.rows, "changed": s.changed})))
    }

    #[tool(
        name = "flirt_hints",
        description = "FLIRT-like library hints: corpus signature matches over each function's leading bytes, paged under the protocol-1 envelope. Suggested names stay hints; read-only, never renames or writes the sidecar"
    )]
    async fn flirt_hints(&self, p: Parameters<FlirtHintsParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        let (addr_s, offset, limit) = (p.addr.clone(), p.offset, p.limit);
        let entry = self.open_owned(p.binary, p.db, p.raw, p.fat_arch).await?;
        let proj = entry.lock_project();
        let addr = opt_addr(addr_s)?;
        proj.query_flirt_hints(addr, offset.unwrap_or(0), limit.unwrap_or(50))
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(|page| ok(serde_json::to_value(page).expect("flirt hints page serializes")))
    }

    #[tool(
        name = "diff",
        description = "Function-level diff between two binaries: byte-identical pairs are matched, content-matched pairs are changed (with the match reason), the rest is added (only in B) / removed (only in A). Both projects open read-only, never creating or modifying a sidecar"
    )]
    async fn diff(&self, p: Parameters<DiffParams>) -> Result<String, ErrorData> {
        let p = all_params(p);
        raw_options(p.raw.as_ref())?;
        // Both sides open concurrently on the blocking pool; each lands on
        // its own cache entry (same binary twice shares one). Guards take
        // in pointer order below, so opposite-side concurrent diffs cannot
        // deadlock.
        let (entry_a, entry_b) = tokio::join!(
            self.open_owned(
                p.binary_a.clone(),
                p.db_a.clone(),
                p.raw.clone(),
                p.fat_arch.clone(),
            ),
            self.open_owned(
                p.binary_b.clone(),
                p.db_b.clone(),
                p.raw.clone(),
                p.fat_arch.clone(),
            )
        );
        let (entry_a, entry_b) = (entry_a?, entry_b?);
        if Arc::ptr_eq(&entry_a, &entry_b) {
            let proj = entry_a.lock_project();
            let report = crate::diff::diff_projects(&proj, &proj);
            ok(serde_json::to_value(report).expect("diff report serializes"))
        } else if Arc::as_ptr(&entry_a) < Arc::as_ptr(&entry_b) {
            let a = entry_a.lock_project();
            let b = entry_b.lock_project();
            let report = crate::diff::diff_projects(&a, &b);
            ok(serde_json::to_value(report).expect("diff report serializes"))
        } else {
            let b = entry_b.lock_project();
            let a = entry_a.lock_project();
            let report = crate::diff::diff_projects(&a, &b);
            ok(serde_json::to_value(report).expect("diff report serializes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// Unique scratch dir for one test; removed afterwards.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "binscout-mcp-cache-{}-{}-{}",
            tag,
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// Raw x86-64 blob (`nop; nop; ret`) at its own path: unrecognized
    /// bytes open through the raw fallback at base 0.
    fn write_blob(dir: &std::path::Path, name: &str, byte: u8) -> std::path::PathBuf {
        let mut bytes = vec![0x90, 0x90, 0xC3];
        bytes.push(byte);
        let path = dir.join(name);
        std::fs::write(&path, &bytes).expect("write blob");
        path
    }

    fn open_params(bin: &std::path::Path, db: &std::path::Path) -> (String, Option<String>) {
        (bin.display().to_string(), Some(db.display().to_string()))
    }

    #[test]
    fn repeat_open_returns_same_entry() {
        let dir = scratch("hit");
        let bin = write_blob(&dir, "a.bin", 0x90);
        let db = dir.join("a.redb");
        let (binary, db_s) = open_params(&bin, &db);
        let mcp = BinscoutMcp::new();
        let first = mcp
            .cached_entry(&binary, db_s.as_deref(), None, None)
            .expect("first open");
        let second = mcp
            .cached_entry(&binary, db_s.as_deref(), None, None)
            .expect("second open");
        assert!(Arc::ptr_eq(&first, &second), "hit must reuse the entry");
        assert!(!db.exists(), "reads never create the sidecar");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn edited_binary_reopens() {
        let dir = scratch("stale");
        let bin = write_blob(&dir, "a.bin", 0x90);
        let db = dir.join("a.redb");
        let (binary, db_s) = open_params(&bin, &db);
        let mcp = BinscoutMcp::new();
        let first = mcp
            .cached_entry(&binary, db_s.as_deref(), None, None)
            .expect("first open");
        assert_eq!(first.lock_project().analysis().summary().insns, 3);
        // Same path, different length: the entry must revalidate.
        std::fs::write(&bin, [0x90, 0xC3]).expect("rewrite blob");
        let second = mcp
            .cached_entry(&binary, db_s.as_deref(), None, None)
            .expect("second open");
        assert!(!Arc::ptr_eq(&first, &second), "edit must replace the entry");
        assert_eq!(second.lock_project().analysis().summary().insns, 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mapping_and_db_split_entries() {
        let dir = scratch("keys");
        let bin = write_blob(&dir, "a.bin", 0x90);
        let db_a = dir.join("a.redb");
        let db_b = dir.join("b.redb");
        let mcp = BinscoutMcp::new();
        let raw = |base: &str| RawParams {
            arch: Some("x86_64".to_string()),
            base: Some(base.to_string()),
            entry: None,
        };
        let auto = mcp
            .cached_entry(
                &bin.display().to_string(),
                Some(&db_a.display().to_string()),
                None,
                None,
            )
            .expect("auto open");
        let raw_open = mcp
            .cached_entry(
                &bin.display().to_string(),
                Some(&db_a.display().to_string()),
                Some(&raw("0x1000")),
                None,
            )
            .expect("raw open");
        let other_db = mcp
            .cached_entry(
                &bin.display().to_string(),
                Some(&db_b.display().to_string()),
                None,
                None,
            )
            .expect("other db open");
        assert!(!Arc::ptr_eq(&auto, &raw_open), "mapping splits entries");
        assert!(!Arc::ptr_eq(&auto, &other_db), "db path splits entries");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lru_evicts_past_capacity() {
        let dir = scratch("lru");
        let mcp = BinscoutMcp::new();
        let mut first_key = String::new();
        for i in 0..CACHE_CAPACITY + 1 {
            let bin = write_blob(&dir, &format!("f{i}.bin"), i as u8);
            let db = dir.join(format!("f{i}.redb"));
            let (binary, db_s) = open_params(&bin, &db);
            if i == 0 {
                first_key = binary.clone();
            }
            mcp.cached_entry(&binary, db_s.as_deref(), None, None)
                .expect("open");
        }
        let state = mcp.cache.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.entries.len(), CACHE_CAPACITY);
        assert!(
            state.entries.keys().all(|k| k.binary != first_key),
            "least-recently-used entry must evict"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
