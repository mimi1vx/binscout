//! binscout MCP server: 12 stateless tools over [`Project`].
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

/// Shared opener: explicit `db` path or the default sidecar.
fn open(binary: &str, db: Option<&str>) -> Result<Project, ErrorData> {
    let db_path;
    let db_ref = match db {
        Some(d) => {
            db_path = Path::new(d).to_path_buf();
            Some(db_path.as_path())
        }
        None => None,
    };
    Project::open_any(Path::new(binary), db_ref)
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))
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

/// Parameters for single-binary tools (`project_info`, `symbols`, `sections`).
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct BinaryParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path (default: `<binary>.rsdbg.redb` sidecar).
    pub db: Option<String>,
}

/// Parameters for the `strings` tool: filtered, paged string search.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct StringsParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
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

/// Parameters for single-address tools (`func`, `cfg`, `comment`).
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddrParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
    /// Virtual address (`0x`-hex or decimal string).
    pub addr: String,
}

/// Parameters for byte-range tools (`disasm`, `ir`).
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RangeParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
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
    /// Only xrefs pointing at this address (`0x`-hex or decimal).
    pub to: Option<String>,
    /// Only xrefs originating at this address.
    pub from: Option<String>,
    /// Only `code`, `data`, or `string` xrefs.
    pub kind: Option<String>,
    /// First row to return.
    pub offset: Option<usize>,
    /// Max rows (capped at 1024).
    pub limit: Option<usize>,
}

/// Parameters for the `rename` tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RenameParams {
    /// Path to the analyzed binary.
    pub binary: String,
    /// Explicit project DB path.
    pub db: Option<String>,
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
    /// Address to comment (`0x`-hex or decimal string).
    pub addr: String,
    /// Comment text (empty string clears).
    pub comment: String,
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
        let proj = open(&p.binary, p.db.as_deref())?;
        ok(serde_json::to_value(proj.project_info()).expect("project_info serializes"))
    }

    #[tool(
        name = "functions",
        description = "List functions with rename-resolved names, filtered by query/caller/callee/range, paged by offset/limit"
    )]
    fn functions(&self, p: Parameters<FunctionsParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref())?;
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
        description = "Full detail of one function: blocks with instructions, edges, calls. Any address inside the function snaps to its containing entry"
    )]
    fn func(&self, p: Parameters<AddrParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.func_detail(addr)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(ok)
    }

    #[tool(
        name = "disasm",
        description = "Disassemble len bytes at addr with the binary architecture; returns the valid prefix plus error_at for the first bad opcode (null on a clean range)"
    )]
    fn disasm(&self, p: Parameters<RangeParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref())?;
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
        let proj = open(&p.binary, p.db.as_deref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.cfg_of(addr)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(ok)
    }

    #[tool(
        name = "xrefs",
        description = "Cross-references filtered by to/from address and kind, paged with total match count"
    )]
    fn xrefs(&self, p: Parameters<XrefsParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref())?;
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
        let proj = open(&p.binary, p.db.as_deref())?;
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
        ok(open(&p.binary, p.db.as_deref())?.symbols_json())
    }

    #[tool(
        name = "sections",
        description = "Section table: name, virtual address (PE: IMAGE_BASE + RVA), in-memory and file sizes, permissions"
    )]
    fn sections(&self, p: Parameters<BinaryParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        ok(open(&p.binary, p.db.as_deref())?.sections_json())
    }

    #[tool(
        name = "ir",
        description = "Lift len bytes at addr to P-code-inspired IR"
    )]
    fn ir(&self, p: Parameters<RangeParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let proj = open(&p.binary, p.db.as_deref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.ir_at(addr, p.len)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
            .and_then(ok)
    }

    #[tool(
        name = "rename",
        description = "Rename a function in the project DB (binary untouched); empty name clears"
    )]
    fn rename(&self, p: Parameters<RenameParams>) -> Result<String, ErrorData> {
        let _guard = self.guard();
        let p = all_params(p);
        let mut proj = open(&p.binary, p.db.as_deref())?;
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
        let mut proj = open(&p.binary, p.db.as_deref())?;
        let addr =
            parse_addr(&p.addr).map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        proj.set_comment(addr, &p.comment)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        ok(proj.annotation_json(addr))
    }
}
