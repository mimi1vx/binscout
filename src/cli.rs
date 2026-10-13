//! binscout CLI: every command prints exactly one JSON value to stdout.
//!
//! Success prints the result with exit 0; failure prints
//! `{"error": "..."}` with exit 1, so stdout is always valid JSON.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Agent-first CLI: JSON on stdout, always.
#[derive(Debug, Parser)]
#[command(
    name = "binscout",
    version,
    about = "headless agent-first binary analysis"
)]
pub struct Cli {
    /// Explicit project DB path (default: `<binary>.rsdbg.redb` sidecar).
    #[arg(long, global = true)]
    pub db: Option<PathBuf>,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Open a binary, cache the analysis snapshot, print project info.
    Load { binary: PathBuf },
    /// List functions (rename-resolved), paged and optionally filtered.
    Functions {
        binary: PathBuf,
        /// Case-insensitive substring over the rename-resolved name.
        #[arg(long)]
        query: Option<String>,
        /// Keep functions that call the function containing this address.
        #[arg(long)]
        caller: Option<String>,
        /// Keep functions called by the function containing this address.
        #[arg(long)]
        callee: Option<String>,
        /// Keep functions with entry in LO..=HI (`0x`-hex or decimal).
        #[arg(long, num_args = 2, value_names = ["LO", "HI"])]
        range: Option<Vec<String>>,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Full detail of one function: blocks with instructions. Any address
    /// inside the function snaps to its containing entry.
    Func { binary: PathBuf, addr: String },
    /// Disassemble `len` bytes at `addr`.
    Disasm {
        binary: PathBuf,
        addr: String,
        len: usize,
    },
    /// Control-flow graph of one function. Any address inside the function
    /// snaps to its containing entry.
    Cfg { binary: PathBuf, addr: String },
    /// Cross-references, optionally filtered by endpoint/kind.
    Xrefs {
        binary: PathBuf,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Extracted strings, filtered and paged. Hits in executable memory
    /// (code bytes decoded as text) are hidden unless `--pattern`,
    /// `--section`, or `--include-code` is given.
    Strings {
        binary: PathBuf,
        /// Rows to skip after filtering.
        #[arg(long)]
        start: Option<usize>,
        /// Deprecated alias of `--start` (warns on stderr).
        #[arg(long, hide = true)]
        offset: Option<usize>,
        /// Max rows (capped at 1024).
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Case-sensitive substring, or `regex:`-prefixed expression.
        #[arg(long)]
        pattern: Option<String>,
        /// Keep strings with at least this many characters.
        #[arg(long)]
        min_len: Option<usize>,
        /// Keep strings in exactly this section (e.g. `.rdata`).
        #[arg(long)]
        section: Option<String>,
        /// Show strings in executable memory (hidden by default).
        #[arg(long)]
        include_code: bool,
    },
    /// Imports and exports.
    Symbols { binary: PathBuf },
    /// Lift `len` bytes at `addr` to IR.
    Ir {
        binary: PathBuf,
        addr: String,
        len: usize,
    },
    /// Read or write the annotation at `addr`.
    Annotate {
        binary: PathBuf,
        addr: String,
        /// Rename a function (empty string clears).
        #[arg(long)]
        rename: Option<String>,
        /// Comment any address (empty string clears).
        #[arg(long)]
        comment: Option<String>,
    },
}

impl Cli {
    pub fn run(self) -> ! {
        let db = self.db.as_deref();
        let result = match self.cmd {
            Cmd::Load { binary } => load(&binary, db),
            Cmd::Functions {
                binary,
                query,
                caller,
                callee,
                range,
                offset,
                limit,
            } => functions_filter(query, caller, callee, range)
                .and_then(|filter| functions(&binary, db, &filter, offset, limit)),
            Cmd::Func { binary, addr } => func(&binary, db, &addr),
            Cmd::Disasm { binary, addr, len } => disasm(&binary, db, &addr, len),
            Cmd::Cfg { binary, addr } => cfg(&binary, db, &addr),
            Cmd::Xrefs {
                binary,
                to,
                from,
                kind,
                offset,
                limit,
            } => xrefs(
                &binary,
                db,
                to.as_deref(),
                from.as_deref(),
                kind.as_deref(),
                offset,
                limit,
            ),
            Cmd::Strings {
                binary,
                start,
                offset,
                limit,
                pattern,
                min_len,
                section,
                include_code,
            } => {
                if offset.is_some() {
                    eprintln!("warning: --offset is deprecated, use --start");
                }
                strings(
                    &binary,
                    db,
                    &binscout::analysis::StringsFilter {
                        pattern,
                        min_len,
                        section,
                        include_code,
                        start: start.or(offset).unwrap_or(0),
                        limit,
                    },
                )
            }
            Cmd::Symbols { binary } => symbols(&binary, db),
            Cmd::Ir { binary, addr, len } => ir(&binary, db, &addr, len),
            Cmd::Annotate {
                binary,
                addr,
                rename,
                comment,
            } => annotate(&binary, db, &addr, rename.as_deref(), comment.as_deref()),
        };
        match result {
            Ok(value) => {
                println!("{value}");
                std::process::exit(0);
            }
            Err(e) => {
                println!("{}", serde_json::json!({ "error": e.to_string() }));
                std::process::exit(1);
            }
        }
    }
}

fn open(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
) -> binscout::error::Result<binscout::Project> {
    binscout::Project::open_any(binary, db)
}

fn opt_addr(s: Option<&str>) -> binscout::error::Result<Option<u64>> {
    s.map(binscout::parse_addr).transpose()
}

fn load(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db)?;
    p.save()?;
    Ok(serde_json::to_value(p.project_info()).expect("project_info serializes"))
}

fn functions_filter(
    query: Option<String>,
    caller: Option<String>,
    callee: Option<String>,
    range: Option<Vec<String>>,
) -> binscout::error::Result<binscout::FunctionFilter> {
    Ok(binscout::FunctionFilter {
        query,
        caller: caller.map(|s| binscout::parse_addr(&s)).transpose()?,
        callee: callee.map(|s| binscout::parse_addr(&s)).transpose()?,
        range: range
            .map(|pair| match &pair[..] {
                [lo, hi] => Ok((binscout::parse_addr(lo)?, binscout::parse_addr(hi)?)),
                _ => Err(binscout::error::Error::Invalid(
                    "--range takes LO HI".to_string(),
                )),
            })
            .transpose()?,
    })
}

fn functions(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    filter: &binscout::FunctionFilter,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db)?;
    Ok(serde_json::Value::Array(
        p.functions_filtered(filter, offset, limit),
    ))
}

fn func(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    addr: &str,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db)?;
    p.func_detail(binscout::parse_addr(addr)?)
}

fn disasm(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    addr: &str,
    len: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db)?;
    let addr = binscout::parse_addr(addr)?;
    Ok(serde_json::to_value(p.disasm_at(addr, len)?).expect("insns serialize"))
}

fn cfg(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    addr: &str,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db)?;
    p.cfg_of(binscout::parse_addr(addr)?)
}

fn xrefs(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    to: Option<&str>,
    from: Option<&str>,
    kind: Option<&str>,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db)?;
    let kind = kind.map(binscout::parse_xref_kind).transpose()?;
    let (to, from) = (opt_addr(to)?, opt_addr(from)?);
    let total = p.count_xrefs(to, from, kind);
    let rows = p.query_xrefs(to, from, kind, offset, limit);
    Ok(serde_json::json!({ "total": total, "xrefs": rows }))
}

fn strings(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    filter: &binscout::analysis::StringsFilter,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db)?;
    let rows = p.query_strings(filter)?;
    Ok(serde_json::to_value(rows).expect("strings serialize"))
}

fn symbols(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
) -> binscout::error::Result<serde_json::Value> {
    Ok(open(binary, db)?.symbols_json())
}

fn ir(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    addr: &str,
    len: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db)?;
    p.ir_at(binscout::parse_addr(addr)?, len)
}

fn annotate(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    addr: &str,
    rename: Option<&str>,
    comment: Option<&str>,
) -> binscout::error::Result<serde_json::Value> {
    let mut p = open(binary, db)?;
    let addr = binscout::parse_addr(addr)?;
    if let Some(name) = rename {
        p.rename_function(addr, name)?;
    }
    if let Some(text) = comment {
        p.set_comment(addr, text)?;
    }
    Ok(p.annotation_json(addr))
}
