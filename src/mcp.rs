//! binscout MCP server: 22 stateless tools over [`Project`].
//!
//! Every tool takes a `binary` path (plus optional `db` sidecar path), opens
//! the project, and returns one JSON document as text. Failures surface as
//! tool errors, never as silent empty results.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ServerHandler, tool, tool_handler, tool_router};

use crate::{FunctionFilter, Project, parse_addr, parse_xref_kind};

/// Explicit raw mapping for MCP binary-taking tools.
///
/// Mirrors the CLI `--raw --arch ARCH --base ADDR [--entry ADDR]` flags:
/// `arch`/`base` are required when `raw` is present, `entry` is optional,
/// and addresses parse as `0x`-hex or decimal via [`parse_addr`].
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RawParams {
    /// Raw arch: `x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`.
    pub arch: Option<String>,
    /// Raw base address (`0x`-hex or decimal string).
    pub base: Option<String>,
    /// Raw entry address (`0x`-hex or decimal string).
    pub entry: Option<String>,
}

/// Shared validated opener: explicit `db` path (or the default sidecar) plus
/// the optional explicit raw mapping, parsed through
/// [`crate::parse_raw_options`] so CLI and MCP interpret options identically.
fn open(binary: &str, db: Option<&str>, raw: Option<&RawParams>) -> Result<Project, ErrorData> {
    let raw_opts = raw_options(raw)?;
    let db_path;
    let db_ref = match db {
        Some(d) => {
            db_path = Path::new(d).to_path_buf();
            Some(db_path.as_path())
        }
        None => None,
    };
    crate::open_mapped(Path::new(binary), db_ref, raw_opts).map_err(|e| match e {
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
    /// Rows to skip after filtering.
    pub start: Option<usize>,
    /// Deprecated alias of `start`.
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
    /// Case-sensitive substring, or `regex:`-prefixed expression.
    pub pattern: Option<String>,
    /// Keep strings with at least this many characters.
    pub min_len: Option<usize>,
    /// Keep strings in exactly this section (e.g. `.rdata`).
    pub section: Option<String>,
    /// Show strings in executable memory (hidden by default).
    pub include_code: Option<bool>,
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
    /// Case-insensitive substring over the rename-resolved name.
    pub query: Option<String>,
    /// Keep functions that call the function containing this address.
    pub caller: Option<String>,
    /// Keep functions called by the function containing this address.
    pub callee: Option<String>,
    /// Keep functions with entry at or above this address (needs range_hi).
    pub range_lo: Option<String>,
    /// Keep functions with entry at or below this address (needs range_lo).
    pub range_hi: Option<String>,
    /// First row to return.
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
}

/// Parameters for single-address tools (`func`, `cfg`, `blocks`, `comment`).
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddrParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
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
    /// Virtual address (`0x`-hex or decimal string).
    pub addr: String,
    /// Bytes to decode.
    pub len: usize,
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
    /// Only xrefs pointing at this address (`0x`-hex or decimal).
    pub to: Option<String>,
    /// Only xrefs originating at this address.
    pub from: Option<String>,
    /// Only `code`, `data`, `string`, or `inferred-code` xrefs.
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
    /// Address to comment (`0x`-hex or decimal string).
    pub addr: String,
    /// Comment text (empty string clears).
    pub comment: String,
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
    /// Whitespace-separated full-byte tokens: two hex digits or `??`.
    pub pattern: String,
    /// Keep matches fully inside this section (e.g. `.text`).
    pub section: Option<String>,
    /// Range start (`0x`-hex or decimal, needs range_end).
    pub range_start: Option<String>,
    /// Range end (`0x`-hex or decimal, needs range_start).
    pub range_end: Option<String>,
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

/// Parameters for the `annotations_import` tool: merge a portable document.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AnnotationsImportParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Optional explicit raw mapping.
    pub raw: Option<RawParams>,
    /// Interchange document, as returned by `annotations_export`.
    pub document: String,
    /// Replace supplied fields on conflict instead of failing.
    pub overwrite: Option<bool>,
}

/// MCP server handler; serializes tool calls behind one lock.
#[derive(Debug, Clone, Default)]
pub struct BinscoutMcp {
    /// Serializes tool calls: `redb` allows one open handle per file per
    /// process, and rename/comment are read-modify-write cycles.
    lock: Arc<Mutex<()>>,
}

impl BinscoutMcp {
    /// New handler with a fresh call-serializing lock.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn guard(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|e| e.into_inner())
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
    fn project_info(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        ok(serde_json::to_value(proj.project_info()).expect("project_info serializes"))
    }

    #[tool(
        name = "functions",
        description = "List functions with rename-resolved names, filtered by query/caller/callee/range, paged by offset/limit"
    )]
    fn functions(&self, p: Parameters<FunctionsParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let filter = FunctionFilter {
            query: p.query,
            caller: opt_addr(p.caller)?,
            callee: opt_addr(p.callee)?,
            range: match (p.range_lo, p.range_hi) {
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
        let rows = proj.functions_filtered(&filter, p.offset.unwrap_or(0), p.limit.unwrap_or(50));
        ok(serde_json::Value::Array(rows))
    }

    #[tool(
        name = "func",
        description = "Compact metadata of one function: entry, name, and block/insn/call counts. Any address inside the function snaps to its containing entry"
    )]
    fn func(&self, p: Parameters<AddrParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.func_meta(addr)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(|m| ok(serde_json::to_value(m).expect("func_meta serializes")))
    }

    #[tool(
        name = "blocks",
        description = "Block summaries of one function ordered by block start, paged with total block count. Any address inside the function snaps to its containing entry"
    )]
    fn blocks(&self, p: Parameters<BlocksParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.func_blocks_page(addr, p.offset.unwrap_or(0), p.limit.unwrap_or(50))
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(|page| ok(serde_json::to_value(page).expect("blocks page serializes")))
    }

    #[tool(
        name = "block_insns",
        description = "Instructions of one function-owned block in address order, paged. Addr snaps to its containing function; block must be a block start belonging to that function"
    )]
    fn block_insns(&self, p: Parameters<BlockInsnsParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        let block =
            parse_addr(&p.block).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.func_block_insns_page(addr, block, p.offset.unwrap_or(0), p.limit.unwrap_or(50))
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(|page| ok(serde_json::to_value(page).expect("block_insns page serializes")))
    }

    #[tool(
        name = "diagnostics",
        description = "Analysis provenance: unresolved indirect sites and decode failures, filtered by kind and containing function, paged under the protocol-1 envelope"
    )]
    fn diagnostics(&self, p: Parameters<DiagnosticsParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let kind = p
            .kind
            .as_deref()
            .map(crate::parse_diagnostic_kind)
            .transpose()
            .map_err(|e| match e {
                crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
                other => ErrorData::internal_error(other.to_string(), None),
            })?;
        let func = opt_addr(p.func)?;
        proj.query_diagnostics(kind, func, p.offset.unwrap_or(0), p.limit.unwrap_or(50))
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(|page| ok(serde_json::to_value(page).expect("diagnostics page serializes")))
    }

    #[tool(
        name = "disasm",
        description = "Disassemble len bytes at addr with the binary architecture; returns the valid prefix plus error_at for the first bad opcode (null on a clean range)"
    )]
    fn disasm(&self, p: Parameters<RangeParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.disasm_at(addr, p.len)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(|v| ok(serde_json::to_value(v).expect("partial disasm serializes")))
    }

    #[tool(
        name = "cfg",
        description = "Control-flow graph of one function: block nodes plus block edges. Any address inside the function snaps to its containing entry"
    )]
    fn cfg(&self, p: Parameters<AddrParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.cfg_of(addr)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(ok)
    }

    #[tool(
        name = "callees",
        description = "Transitive callees of one function out to depth hops (direct callees are depth 1), ordered by entry with shortest distance, paged under the protocol-1 envelope. Addr snaps to its containing function"
    )]
    fn callees(&self, p: Parameters<CallgraphParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.callees_page(
            addr,
            p.depth.unwrap_or(crate::analysis::MAX_CALL_DEPTH),
            p.offset.unwrap_or(0),
            p.limit.unwrap_or(50),
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
    fn callers(&self, p: Parameters<CallgraphParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.callers_page(
            addr,
            p.depth.unwrap_or(crate::analysis::MAX_CALL_DEPTH),
            p.offset.unwrap_or(0),
            p.limit.unwrap_or(50),
        )
        .map_err(|e| match e {
            crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
            other => ErrorData::internal_error(other.to_string(), None),
        })
        .and_then(|page| ok(serde_json::to_value(page).expect("callers page serializes")))
    }

    #[tool(
        name = "xrefs",
        description = "Cross-references filtered by to/from address and kind, paged with total match count"
    )]
    fn xrefs(&self, p: Parameters<XrefsParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let kind = p
            .kind
            .as_deref()
            .map(parse_xref_kind)
            .transpose()
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        let (to, from) = (opt_addr(p.to)?, opt_addr(p.from)?);
        let total = proj.count_xrefs(to, from, kind);
        let rows = proj.query_xrefs(to, from, kind, p.offset.unwrap_or(0), p.limit.unwrap_or(50));
        ok(serde_json::json!({ "total": total, "xrefs": rows }))
    }

    #[tool(
        name = "strings",
        description = "Extracted strings ordered by address, filtered by pattern/min-len/section, paged by start/limit. Hits in executable memory are hidden unless pattern, section, or include_code is given"
    )]
    fn strings(&self, p: Parameters<StringsParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        if p.offset.is_some() {
            eprintln!("warning: strings offset is deprecated, use start");
        }
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let rows = proj
            .query_strings(&crate::analysis::StringsFilter {
                pattern: p.pattern,
                min_len: p.min_len,
                section: p.section,
                include_code: p.include_code.unwrap_or(false),
                start: p.start.or(p.offset).unwrap_or(0),
                limit: p.limit.unwrap_or(50),
            })
            .map_err(|e| match e {
                crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
                other => ErrorData::internal_error(other.to_string(), None),
            })?;
        ok(serde_json::to_value(rows).expect("strings serialize"))
    }

    #[tool(name = "symbols", description = "Imports and exports of the binary")]
    fn symbols(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        ok(open(&p.binary, p.db.as_deref(), p.raw.as_ref())?.symbols_json())
    }

    #[tool(
        name = "stats",
        description = "Storage stats: binary size, sidecar DB size, and analysis counts"
    )]
    fn stats(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        open(&p.binary, p.db.as_deref(), p.raw.as_ref())?
            .stats_json()
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(ok)
    }

    #[tool(
        name = "sections",
        description = "Section table: name, virtual address (PE: IMAGE_BASE + RVA), in-memory and file sizes, permissions"
    )]
    fn sections(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        ok(open(&p.binary, p.db.as_deref(), p.raw.as_ref())?.sections_json())
    }

    #[tool(
        name = "ir",
        description = "Lift len bytes at addr to P-code-inspired IR"
    )]
    fn ir(&self, p: Parameters<RangeParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.ir_at(addr, p.len)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(ok)
    }

    #[tool(
        name = "ir_coverage",
        description = "Machine-readable IR lift coverage for one arch (implemented families, partial mappings, limitations); with binary/addr/len adds per-range decoded/lifted/unlifted counts from actual lifts plus a bounded mnemonic summary"
    )]
    fn ir_coverage(&self, p: Parameters<IrCoverageParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let arch = crate::parse_raw_arch(&p.arch)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        match (p.binary, p.addr, p.len) {
            (None, None, None) => ok(crate::ir_coverage(arch)),
            (Some(binary), Some(addr), Some(len)) => {
                let proj = open(&binary, p.db.as_deref(), p.raw.as_ref())?;
                let addr = parse_addr(&addr)
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
    fn rename(&self, p: Parameters<RenameParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let mut proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.rename_function(addr, &p.name)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        ok(proj.annotation_json(addr))
    }

    #[tool(
        name = "comment",
        description = "Comment any address in the project DB (binary untouched); empty comment clears"
    )]
    fn comment(&self, p: Parameters<CommentParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let mut proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.set_comment(addr, &p.comment)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        ok(proj.annotation_json(addr))
    }

    #[tool(
        name = "search_bytes",
        description = "Search mapped file bytes for a whitespace-separated hex pattern (two hex digits or ?? per token), filtered by section/range, paged with total match count"
    )]
    fn search_bytes(&self, p: Parameters<SearchBytesParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        let range = match (p.range_start, p.range_end) {
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
            &p.pattern,
            p.section.as_deref(),
            range,
            p.offset.unwrap_or(0),
            p.limit.unwrap_or(50),
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
    fn annotations_export(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
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
    fn annotations_import(
        &self,
        p: Parameters<AnnotationsImportParams>,
    ) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        // Transport note: rmcp delivers `document` as a fully-materialized
        // `String` before this runs, so no pre-parse cap exists at this
        // layer; the core re-checks the 16 MiB serialized cap plus row/text
        // budgets during validation, before any write, and every failure
        // leaves the DB and memory unchanged.
        let mut proj = open(&p.binary, p.db.as_deref(), p.raw.as_ref())?;
        proj.import_annotations(&p.document, p.overwrite.unwrap_or(false))
            .map_err(|e| match e {
                crate::error::Error::Invalid(msg) => ErrorData::invalid_params(msg, None),
                other => ErrorData::internal_error(other.to_string(), None),
            })
            .and_then(|s| ok(serde_json::json!({"rows": s.rows, "changed": s.changed})))
    }
}
