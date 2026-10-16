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

    /// Explicit raw mapping mode (requires `--arch` and `--base`).
    #[arg(long, global = true)]
    pub raw: bool,

    /// Raw arch: `x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb` (requires `--raw`).
    #[arg(long, global = true)]
    pub arch: Option<String>,

    /// Raw base address (`0x`-hex or decimal, requires `--raw`).
    #[arg(long, global = true)]
    pub base: Option<String>,

    /// Raw entry address (`0x`-hex or decimal, requires `--raw`).
    #[arg(long, global = true)]
    pub entry: Option<String>,

    /// Fat Mach-O slice: `x86_64`, `x86_32`, `aarch64`, `arm32` (plus `lipo`
    /// aliases like `arm64`); required for fat containers.
    #[arg(long, global = true)]
    pub fat_arch: Option<String>,

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
    /// Compact metadata of one function: entry, name, and block/insn/call
    /// counts. Any address inside the function snaps to its containing
    /// entry. Paged block/insn rows come from `blocks`/`block-insns`;
    /// `cfg` remains the explicit full-graph export.
    Func { binary: PathBuf, addr: String },
    /// Block summaries of one function ordered by block start, paged.
    /// Any address inside the function snaps to its containing entry.
    Blocks {
        binary: PathBuf,
        addr: String,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Instructions of one function-owned block in address order, paged.
    /// `addr` snaps to its containing function; `block` must be a block
    /// start belonging to that function.
    BlockInsns {
        binary: PathBuf,
        addr: String,
        block: String,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Provenance records: unresolved indirect sites and decode failures,
    /// filtered by kind and containing function, paged under the
    /// protocol-1 envelope. Querying never writes a sidecar.
    Diagnostics {
        binary: PathBuf,
        /// Only `unresolved-indirect-jump`, `unresolved-indirect-call`,
        /// or `decode-failure` sites.
        #[arg(long)]
        kind: Option<String>,
        /// Only sites in the function containing this address.
        #[arg(long)]
        func: Option<String>,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Disassemble `len` bytes at `addr`.
    Disasm {
        binary: PathBuf,
        addr: String,
        len: usize,
    },
    /// Control-flow graph of one function. Any address inside the function
    /// snaps to its containing entry.
    Cfg { binary: PathBuf, addr: String },
    /// Approximate control-flow structure of one function: syntactic loops
    /// and ifs over the CFG plus the IR lift, with an approximation
    /// warning. Any address inside the function snaps to its containing
    /// entry.
    Structure { binary: PathBuf, addr: String },
    /// Approximate pseudo-C of one function: one lossy C-like line per IR
    /// row plus assembled text, with an approximation warning. Any address
    /// inside the function snaps to its containing entry.
    Pseudo { binary: PathBuf, addr: String },
    /// Transitive callees of one function: every function reachable by
    /// following call edges out to `--depth` hops. Any address inside the
    /// function snaps to its containing entry.
    Callees {
        binary: PathBuf,
        addr: String,
        /// Max call edges from the root (direct callees are depth 1).
        #[arg(long, default_value_t = binscout::analysis::MAX_CALL_DEPTH)]
        depth: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Transitive callers of one function: every function that can reach
    /// it by following call edges backward out to `--depth` hops. Any
    /// address inside the function snaps to its containing entry.
    Callers {
        binary: PathBuf,
        addr: String,
        /// Max call edges to the root (direct callers are depth 1).
        #[arg(long, default_value_t = binscout::analysis::MAX_CALL_DEPTH)]
        depth: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Backward slice of one address: every instruction that can reach
    /// it by following xref edges (any kind) and intra-function CFG
    /// predecessors backward out to `--depth` hops. Any address is a
    /// valid root (data/string targets lie in no function).
    Slice {
        binary: PathBuf,
        addr: String,
        /// Max reverse hops from the root (direct predecessors are depth 1).
        #[arg(long, default_value_t = binscout::analysis::MAX_SLICE_DEPTH)]
        depth: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
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
        /// Decode-and-display view over an in-memory transform:
        /// `xor:<byte>`, `add:<byte>`, or `rot:<0-7>` (byte is `0x`-hex or
        /// decimal). Reveals single-byte-obfuscated text with original
        /// offsets; never writes the binary.
        #[arg(long)]
        decode: Option<String>,
    },
    /// Imports and exports.
    Symbols { binary: PathBuf },
    /// Section table: name, virtual address, in-memory and file sizes,
    /// permissions. `vaddr` is the flat virtual address (PE:
    /// `IMAGE_BASE + RVA`); `file_off` locates the raw bytes in the file.
    Sections { binary: PathBuf },
    /// Lift `len` bytes at `addr` to IR.
    Ir {
        binary: PathBuf,
        addr: String,
        len: usize,
    },
    /// Machine-readable IR lift coverage for one architecture. Without a
    /// binary range, no binary is opened; with `binary addr len`, adds
    /// per-range decoded/lifted/unlifted counts from actual lifts.
    /// (`arch` is positional because `--arch` is the global raw-mapping flag.)
    IrCoverage {
        /// Coverage arch: `x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`.
        #[arg(value_name = "ARCH")]
        coverage_arch: String,
        binary: Option<PathBuf>,
        addr: Option<String>,
        len: Option<usize>,
    },
    /// FLIRT-like library hints (read-only): corpus signature matches over
    /// each function's leading bytes, paged under the protocol-1 envelope.
    /// Suggested names stay hints; querying never writes a sidecar.
    FlirtHints {
        binary: PathBuf,
        /// Only hints for the function containing this address.
        #[arg(long)]
        addr: Option<String>,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Storage stats: binary size, sidecar DB size, and analysis counts.
    Stats { binary: PathBuf },
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
    /// Search mapped file bytes for a byte pattern, paged.
    SearchBytes {
        binary: PathBuf,
        /// Whitespace-separated full-byte tokens: two hex digits or `??`.
        pattern: String,
        /// Keep matches fully inside this section (e.g. `.text`).
        #[arg(long)]
        section: Option<String>,
        /// Keep matches fully inside LO..HI (`0x`-hex or decimal, half-open).
        #[arg(long, num_args = 2, value_names = ["LO", "HI"])]
        range: Option<Vec<String>>,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Emit the portable annotation interchange document to stdout.
    /// Read-only: never creates or modifies the sidecar.
    AnnotationsExport { binary: PathBuf },
    /// Merge a portable annotation document into the project DB.
    /// Reads capped JSON from `--input`; the binary stays immutable.
    AnnotationsImport {
        binary: PathBuf,
        /// Path to the JSON document (as emitted by `annotations-export`).
        #[arg(long)]
        input: PathBuf,
        /// Replace supplied fields on conflict instead of failing.
        #[arg(long)]
        overwrite: bool,
    },
    /// Function-level diff between two binaries: byte-identical pairs are
    /// `matched`, content-matched pairs are `changed` (with the match
    /// reason), the rest is `added` (only in B) / `removed` (only in A).
    /// Both projects open read-only: never creates or modifies a sidecar.
    /// The global `--raw` mapping or `--fat-arch` selection (if any) applies
    /// to both binaries; use `--db-a`/`--db-b` instead of the global `--db`.
    Diff {
        /// First (baseline) binary.
        binary_a: PathBuf,
        /// Second (new) binary.
        binary_b: PathBuf,
        /// Explicit project DB path for side A (default: side-A sidecar).
        #[arg(long)]
        db_a: Option<PathBuf>,
        /// Explicit project DB path for side B (default: side-B sidecar).
        #[arg(long)]
        db_b: Option<PathBuf>,
    },
}

impl Cli {
    pub fn run(self) -> ! {
        let raw_opts = match binscout::parse_raw_options(
            self.raw,
            self.arch.as_deref(),
            self.base.as_deref(),
            self.entry.as_deref(),
        ) {
            Ok(o) => o,
            Err(e) => {
                println!("{}", serde_json::json!({ "error": e.to_string() }));
                std::process::exit(1);
            }
        };
        let db = self.db.as_deref();
        let fat_arch = self.fat_arch.as_deref();
        let result = match self.cmd {
            Cmd::Load { binary } => load(&binary, db, raw_opts, fat_arch),
            Cmd::Functions {
                binary,
                query,
                caller,
                callee,
                range,
                offset,
                limit,
            } => functions_filter(query, caller, callee, range).and_then(|filter| {
                functions(&binary, db, raw_opts, fat_arch, &filter, offset, limit)
            }),
            Cmd::Func { binary, addr } => func(&binary, db, raw_opts, fat_arch, &addr),
            Cmd::Blocks {
                binary,
                addr,
                offset,
                limit,
            } => blocks(&binary, db, raw_opts, fat_arch, &addr, offset, limit),
            Cmd::BlockInsns {
                binary,
                addr,
                block,
                offset,
                limit,
            } => block_insns(
                &binary, db, raw_opts, fat_arch, &addr, &block, offset, limit,
            ),
            Cmd::Diagnostics {
                binary,
                kind,
                func,
                offset,
                limit,
            } => diagnostics(
                &binary,
                db,
                raw_opts,
                fat_arch,
                kind.as_deref(),
                func.as_deref(),
                offset,
                limit,
            ),
            Cmd::Disasm { binary, addr, len } => {
                disasm(&binary, db, raw_opts, fat_arch, &addr, len)
            }
            Cmd::Cfg { binary, addr } => cfg(&binary, db, raw_opts, fat_arch, &addr),
            Cmd::Structure { binary, addr } => structure(&binary, db, raw_opts, fat_arch, &addr),
            Cmd::Pseudo { binary, addr } => pseudo(&binary, db, raw_opts, fat_arch, &addr),
            Cmd::Callees {
                binary,
                addr,
                depth,
                offset,
                limit,
            } => callees(&binary, db, raw_opts, fat_arch, &addr, depth, offset, limit),
            Cmd::Callers {
                binary,
                addr,
                depth,
                offset,
                limit,
            } => callers(&binary, db, raw_opts, fat_arch, &addr, depth, offset, limit),
            Cmd::Slice {
                binary,
                addr,
                depth,
                offset,
                limit,
            } => slice(&binary, db, raw_opts, fat_arch, &addr, depth, offset, limit),
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
                raw_opts,
                fat_arch,
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
                decode,
            } => {
                if offset.is_some() {
                    eprintln!("warning: --offset is deprecated, use --start");
                }
                let decode = match decode
                    .map(|s| binscout::loader::strings::parse_decode_spec(&s))
                    .transpose()
                {
                    Ok(d) => d,
                    Err(e) => {
                        println!("{}", serde_json::json!({ "error": e.to_string() }));
                        std::process::exit(1);
                    }
                };
                strings(
                    &binary,
                    db,
                    raw_opts,
                    fat_arch,
                    &binscout::analysis::StringsFilter {
                        pattern,
                        min_len,
                        section,
                        include_code,
                        start: start.or(offset).unwrap_or(0),
                        limit,
                    },
                    decode,
                )
            }
            Cmd::Symbols { binary } => symbols(&binary, db, raw_opts, fat_arch),
            Cmd::Sections { binary } => sections(&binary, db, raw_opts, fat_arch),
            Cmd::Ir { binary, addr, len } => ir(&binary, db, raw_opts, fat_arch, &addr, len),
            Cmd::IrCoverage {
                coverage_arch,
                binary,
                addr,
                len,
            } => ir_coverage(
                &coverage_arch,
                binary.as_deref(),
                db,
                raw_opts,
                fat_arch,
                addr.as_deref(),
                len,
            ),
            Cmd::Stats { binary } => stats(&binary, db, raw_opts, fat_arch),
            Cmd::FlirtHints {
                binary,
                addr,
                offset,
                limit,
            } => flirt_hints(
                &binary,
                db,
                raw_opts,
                fat_arch,
                addr.as_deref(),
                offset,
                limit,
            ),
            Cmd::Annotate {
                binary,
                addr,
                rename,
                comment,
            } => annotate(
                &binary,
                db,
                raw_opts,
                fat_arch,
                &addr,
                rename.as_deref(),
                comment.as_deref(),
            ),
            Cmd::SearchBytes {
                binary,
                pattern,
                section,
                range,
                offset,
                limit,
            } => search_bytes(
                &binary,
                db,
                raw_opts,
                fat_arch,
                &pattern,
                section.as_deref(),
                range,
                offset,
                limit,
            ),
            Cmd::AnnotationsExport { binary } => {
                annotations_export(&binary, db, raw_opts, fat_arch)
            }
            Cmd::AnnotationsImport {
                binary,
                input,
                overwrite,
            } => annotations_import(&binary, db, raw_opts, fat_arch, &input, overwrite),
            Cmd::Diff {
                binary_a,
                binary_b,
                db_a,
                db_b,
            } => bindiff(
                &binary_a,
                &binary_b,
                db,
                db_a.as_deref(),
                db_b.as_deref(),
                raw_opts,
                fat_arch,
            ),
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
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
) -> binscout::error::Result<binscout::Project> {
    binscout::open_mapped(binary, db, raw, fat_arch)
}

fn opt_addr(s: Option<&str>) -> binscout::error::Result<Option<u64>> {
    s.map(binscout::parse_addr).transpose()
}

fn load(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
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
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    filter: &binscout::FunctionFilter,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    Ok(serde_json::Value::Array(
        p.functions_filtered(filter, offset, limit),
    ))
}

fn func(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: &str,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    let meta = p.func_meta(binscout::parse_addr(addr)?)?;
    Ok(serde_json::to_value(meta).expect("func_meta serializes"))
}

fn blocks(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: &str,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    let page = p.func_blocks_page(binscout::parse_addr(addr)?, offset, limit)?;
    Ok(serde_json::to_value(page).expect("blocks page serializes"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn block_insns(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: &str,
    block: &str,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    let page = p.func_block_insns_page(
        binscout::parse_addr(addr)?,
        binscout::parse_addr(block)?,
        offset,
        limit,
    )?;
    Ok(serde_json::to_value(page).expect("block_insns page serializes"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn diagnostics(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    kind: Option<&str>,
    func: Option<&str>,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    let kind = kind.map(binscout::parse_diagnostic_kind).transpose()?;
    let func = opt_addr(func)?;
    let page = p.query_diagnostics(kind, func, offset, limit)?;
    Ok(serde_json::to_value(page).expect("diagnostics page serializes"))
}

fn disasm(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: &str,
    len: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    let addr = binscout::parse_addr(addr)?;
    Ok(serde_json::to_value(p.disasm_at(addr, len)?).expect("partial disasm serializes"))
}

fn cfg(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: &str,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    p.cfg_of(binscout::parse_addr(addr)?)
}

fn structure(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: &str,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    p.structure_of(binscout::parse_addr(addr)?)
}

fn pseudo(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: &str,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    p.pseudo_of(binscout::parse_addr(addr)?)
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn callees(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: &str,
    depth: usize,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    let page = p.callees_page(binscout::parse_addr(addr)?, depth, offset, limit)?;
    Ok(serde_json::to_value(page).expect("callees page serializes"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn callers(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: &str,
    depth: usize,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    let page = p.callers_page(binscout::parse_addr(addr)?, depth, offset, limit)?;
    Ok(serde_json::to_value(page).expect("callers page serializes"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn slice(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: &str,
    depth: usize,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    let page = p.slice_page(binscout::parse_addr(addr)?, depth, offset, limit)?;
    Ok(serde_json::to_value(page).expect("slice page serializes"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn xrefs(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    to: Option<&str>,
    from: Option<&str>,
    kind: Option<&str>,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    let kind = kind.map(binscout::parse_xref_kind).transpose()?;
    let (to, from) = (opt_addr(to)?, opt_addr(from)?);
    let total = p.count_xrefs(to, from, kind);
    let rows = p.query_xrefs(to, from, kind, offset, limit);
    Ok(serde_json::json!({ "total": total, "xrefs": rows }))
}

fn strings(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    filter: &binscout::analysis::StringsFilter,
    decode: Option<binscout::loader::strings::DecodeSpec>,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    let rows = match decode {
        Some(spec) => p.query_strings_decoded(filter, spec)?,
        None => p.query_strings(filter)?,
    };
    Ok(serde_json::to_value(rows).expect("strings serialize"))
}

fn symbols(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
) -> binscout::error::Result<serde_json::Value> {
    Ok(open(binary, db, raw, fat_arch)?.symbols_json())
}

fn sections(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
) -> binscout::error::Result<serde_json::Value> {
    Ok(open(binary, db, raw, fat_arch)?.sections_json())
}

fn ir(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: &str,
    len: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    p.ir_at(binscout::parse_addr(addr)?, len)
}

fn ir_coverage(
    arch: &str,
    binary: Option<&std::path::Path>,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: Option<&str>,
    len: Option<usize>,
) -> binscout::error::Result<serde_json::Value> {
    let arch = binscout::parse_raw_arch(arch)?;
    match (binary, addr, len) {
        (None, None, None) => Ok(binscout::ir_coverage(arch)),
        (Some(binary), Some(addr), Some(len)) => {
            open(binary, db, raw, fat_arch)?.ir_coverage_at(arch, binscout::parse_addr(addr)?, len)
        }
        _ => Err(binscout::error::Error::Invalid(
            "ir-coverage range needs BINARY ADDR LEN together".to_string(),
        )),
    }
}

fn stats(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
) -> binscout::error::Result<serde_json::Value> {
    open(binary, db, raw, fat_arch)?.stats_json()
}

fn flirt_hints(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: Option<&str>,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    let page = p.query_flirt_hints(opt_addr(addr)?, offset, limit)?;
    Ok(serde_json::to_value(page).expect("flirt hints page serializes"))
}

fn annotate(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    addr: &str,
    rename: Option<&str>,
    comment: Option<&str>,
) -> binscout::error::Result<serde_json::Value> {
    let mut p = open(binary, db, raw, fat_arch)?;
    let addr = binscout::parse_addr(addr)?;
    if let Some(name) = rename {
        p.rename_function(addr, name)?;
    }
    if let Some(text) = comment {
        p.set_comment(addr, text)?;
    }
    Ok(p.annotation_json(addr))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn search_bytes(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    pattern: &str,
    section: Option<&str>,
    range: Option<Vec<String>>,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch)?;
    let range = range
        .map(|pair| match &pair[..] {
            [lo, hi] => Ok((binscout::parse_addr(lo)?, binscout::parse_addr(hi)?)),
            _ => Err(binscout::error::Error::Invalid(
                "--range takes LO HI".to_string(),
            )),
        })
        .transpose()?;
    let page = p.search_bytes(pattern, section, range, offset, limit)?;
    Ok(serde_json::to_value(page).expect("search_bytes page serializes"))
}

fn annotations_export(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
) -> binscout::error::Result<serde_json::Value> {
    let doc = open(binary, db, raw, fat_arch)?.export_annotations()?;
    serde_json::from_str(&doc)
        .map_err(|e| binscout::error::Error::Storage(format!("encode annotation document: {e}")))
}

fn annotations_import(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    input: &std::path::Path,
    overwrite: bool,
) -> binscout::error::Result<serde_json::Value> {
    let text = read_transfer_document(input)?;
    let mut p = open(binary, db, raw, fat_arch)?;
    let summary = p.import_annotations(&text, overwrite)?;
    Ok(serde_json::json!({"rows": summary.rows, "changed": summary.changed}))
}

/// Function-level diff between two binaries, read-only on both sides.
///
/// The global `--db` cannot serve two projects, so `diff` takes per-side
/// `--db-a`/`--db-b` (each defaulting to its binary's sidecar) and rejects
/// the global flag explicitly instead of sharing one sidecar path. The
/// global `--raw` mapping or `--fat-arch` selection (if any) applies to both
/// binaries: the two-builds case shares one mapping. Neither project is
/// saved, so no sidecar is ever created or modified.
fn bindiff(
    binary_a: &std::path::Path,
    binary_b: &std::path::Path,
    global_db: Option<&std::path::Path>,
    db_a: Option<&std::path::Path>,
    db_b: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
) -> binscout::error::Result<serde_json::Value> {
    if global_db.is_some() {
        return Err(binscout::error::Error::Invalid(
            "diff takes --db-a/--db-b, not the global --db".to_string(),
        ));
    }
    let a = binscout::open_mapped(binary_a, db_a, raw, fat_arch)?;
    let b = binscout::open_mapped(binary_b, db_b, raw, fat_arch)?;
    let report = binscout::diff::diff_projects(&a, &b);
    Ok(serde_json::to_value(report).expect("diff report serializes"))
}

/// Read an interchange document with a hard pre-parse budget.
///
/// Metadata rejects missing/non-file/oversize inputs before any read; the
/// post-read length re-check closes stat-then-read growth races. The core
/// import enforces the same cap again, so this is an allocation guard only.
fn read_transfer_document(path: &std::path::Path) -> binscout::error::Result<String> {
    use binscout::annotations::MAX_TRANSFER_BYTES;
    use binscout::error::Error;
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
    if meta.len() > MAX_TRANSFER_BYTES as u64 {
        return Err(Error::Limit(format!(
            "annotation document of {} bytes exceeds the {MAX_TRANSFER_BYTES}-byte cap",
            meta.len()
        )));
    }
    let bytes =
        std::fs::read(path).map_err(|e| Error::Storage(format!("read {}: {e}", path.display())))?;
    if bytes.len() > MAX_TRANSFER_BYTES {
        return Err(Error::Limit(format!(
            "annotation document of {} bytes exceeds the {MAX_TRANSFER_BYTES}-byte cap",
            bytes.len()
        )));
    }
    String::from_utf8(bytes)
        .map_err(|e| Error::Invalid(format!("malformed annotation document: {e}")))
}
