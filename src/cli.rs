//! binscout CLI: every command prints exactly one JSON value to stdout.
//!
//! Success prints the result with exit 0; failure prints
//! `{"error": "...", "kind": "..."}` with exit 1, so stdout is always
//! valid JSON. `kind` is the machine-readable [`binscout::error::Error`]
//! discriminant (`not_found`, `invalid`, `limit`, `unsupported`,
//! `storage`, `io`); `error` keeps the human message unchanged.

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

    /// Raw arch: `x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`, `riscv32`, `riscv64`,
    /// `mips32`, `ppc32`, `ppc64` (requires `--raw`).
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

    /// PDB path for debug info: local file only, never fetched from the
    /// network. Public and procedure symbols seed function starts and
    /// names for PE binaries; other containers reject it.
    #[arg(long, global = true, value_name = "PATH")]
    pub pdb: Option<PathBuf>,

    /// External DWARF object path (a dSYM DWARF file or an unstripped
    /// copy): local file only, never fetched. `DW_TAG_subprogram` rows
    /// seed starts, ends, and names. Applies to container and `--raw`
    /// opens alike.
    #[arg(long, global = true, value_name = "PATH")]
    pub debug_file: Option<PathBuf>,

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
        /// Deprecated, ignored: output is always the page envelope.
        #[arg(long, hide = true)]
        envelope: bool,
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
    /// Read `len` bytes at `addr` with typed views and VA/file provenance.
    Bytes {
        binary: PathBuf,
        addr: String,
        /// Bytes to read (capped at 1 MiB).
        #[arg(long)]
        len: usize,
        /// Typed view: `u8`, `u16`, `u32`, `u64`, `ptr`, `cstr`, `utf16`.
        #[arg(long = "as", default_value = "u8")]
        as_view: String,
        /// Byte order for multi-byte views: `le` or `be`.
        #[arg(long, default_value = "le")]
        endian: String,
        /// Render struct fields over the range from the type hint stored at
        /// this address (`--len` must cover the struct size).
        #[arg(long)]
        as_type: Option<String>,
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
    /// predecessors backward out to `--depth` hops. Any mapped address
    /// is a valid root (data/string targets lie in no function).
    Slice {
        binary: PathBuf,
        addr: String,
        /// Max reverse hops from the root (direct predecessors are depth 1;
        /// defaults to 8).
        #[arg(long, default_value_t = binscout::analysis::DEFAULT_SLICE_DEPTH)]
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
        /// Include the bounded referencing-instruction list per string
        /// (capped at 64 refs per row), so one call replaces the
        /// `strings` then `xrefs --to --kind string` round-trip.
        #[arg(long)]
        with_xrefs: bool,
        /// Decode-and-display view over an in-memory transform:
        /// `xor:<byte>`, `xor:0x<HEXKEY>` (4+ hex digits, rolling
        /// multi-byte key), `add:<byte>`, `rot:<0-7>` (byte is `0x`-hex
        /// or decimal), or bare `base64` (reports base64 blobs'
        /// plaintext). Reveals obfuscated text with original offsets;
        /// never writes the binary.
        #[arg(long)]
        decode: Option<String>,
        /// Deprecated, ignored: output is always the page envelope.
        #[arg(long, hide = true)]
        envelope: bool,
    },
    /// Recovered stack-constructed strings: runs of
    /// `mov [rsp/rbp+off], imm` within one block, reassembled with
    /// function and address, paged under the protocol-1 envelope.
    /// Read-only: never writes the binary or the sidecar.
    StackStrings {
        binary: PathBuf,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Imports and exports.
    Symbols { binary: PathBuf },
    /// Section table: name, virtual address, in-memory and file sizes,
    /// Shannon entropy (bits per byte), permissions. `vaddr` is the flat
    /// virtual address (PE: `IMAGE_BASE + RVA`); `file_off` locates the
    /// raw bytes in the file.
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
        /// Extra user signatures: our JSON document (as emitted by
        /// `sig-gen`) or an IDA `.pat` file (by extension).
        #[arg(long)]
        sigs: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Emit a JSON signature document for the binary's named functions
    /// (masked leading bytes with `len`/`crc`): the `--sigs` input that
    /// `flirt-hints` reads back. Read-only: never writes the binary or
    /// a sidecar.
    SigGen { binary: PathBuf },
    /// Recover Go functions from the `pclntab` table (linker names plus
    /// exact boundaries), paged under the protocol-1 envelope.
    /// Read-only: never writes the binary or a sidecar.
    GoFuncs {
        binary: PathBuf,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Storage stats: binary size, sidecar DB size, and analysis counts.
    Stats { binary: PathBuf },
    /// Header metadata: triage staples (PE mitigations/imphash/PDB, ELF
    /// interpreter/needed/RELRO/NX/PIE, Mach-O load commands/codesign) plus
    /// `sha256`/`md5`. Computed on demand from the container bytes, never
    /// persisted; querying never writes a sidecar.
    Headers { binary: PathBuf },
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
    /// Define a user function seed at `addr` ("there is code here") and
    /// re-analyze immediately. Any address is accepted; undecodable seeds
    /// are inert. Persists to the sidecar; the binary is untouched.
    DefineFunc {
        binary: PathBuf,
        addr: String,
        /// 32-bit ARM decode mode: `arm` or `thumb` (other arches reject it).
        #[arg(long)]
        mode: Option<String>,
    },
    /// Read or write the structured type hint at `addr`.
    TypeHint {
        binary: PathBuf,
        addr: String,
        /// Wire hint JSON (`{"kind":"struct","name":..,"size":..,"fields":[..]}`);
        /// empty string clears the hint (plain comments are left alone).
        #[arg(long)]
        json: Option<String>,
        /// Read the hint (the default when `--json` is absent).
        #[arg(long)]
        get: bool,
    },
    /// Exclude the function seed at `addr` ("this isn't a function") and
    /// re-analyze immediately. The row is kept as data. Persists to the
    /// sidecar; the binary is untouched.
    UndefineFunc { binary: PathBuf, addr: String },
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
    /// Scan mapped bytes for known crypto constants (AES/SHA/MD5 tables,
    /// ChaCha sigma, Blowfish P-array, TEA delta), paged with xref counts.
    CryptoScan {
        binary: PathBuf,
        /// Keep only this constant (e.g. `aes-sbox`).
        #[arg(long)]
        name: Option<String>,
        /// Keep matches fully inside this section (e.g. `.rdata`).
        #[arg(long)]
        section: Option<String>,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Scan mapped bytes with user-supplied YARA rules, paged with VA,
    /// section, and containing function per hit. Rules come from a local
    /// path and are never fetched from the network. Requires the `yara`
    /// cargo feature (rebuild with `--features yara`).
    ScanYara {
        binary: PathBuf,
        /// Path to the YARA rules file (local path only).
        rules: PathBuf,
        /// Keep only this rule (e.g. `ransom_note`).
        #[arg(long)]
        rule: Option<String>,
        /// Keep matches whose start lies in this section (e.g. `.text`).
        #[arg(long)]
        section: Option<String>,
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
        /// First row of each of `added`/`removed`/`changed` to return.
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// Max rows per list (clipped to the 1024-row budget).
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Embed the side-B rename transfer document (side-A renames mapped
        /// through the pairing, ready for `annotations-import`).
        #[arg(long)]
        transfer_renames: bool,
    },
    /// Block- and instruction-level delta between two functions, one from
    /// each binary: blocks match by hash then by position, and every
    /// matched block carries a bounded instruction edit script. Both
    /// projects open read-only: never creates or modifies a sidecar. The
    /// global `--raw` mapping or `--fat-arch` selection (if any) applies
    /// to both binaries; use `--db-a`/`--db-b` instead of the global `--db`.
    DiffFunc {
        /// First (baseline) binary.
        binary_a: PathBuf,
        /// Second (new) binary.
        binary_b: PathBuf,
        /// Function address on side A (snaps to the containing entry).
        addr_a: String,
        /// Function address on side B (snaps to the containing entry).
        addr_b: String,
        /// Explicit project DB path for side A (default: side-A sidecar).
        #[arg(long)]
        db_a: Option<PathBuf>,
        /// Explicit project DB path for side B (default: side-B sidecar).
        #[arg(long)]
        db_b: Option<PathBuf>,
    },
    /// Assemble replacement bytes at one address and export the patch
    /// (`va`, `file_off`, `old_hex`, `new_hex`, `size_ok`) without
    /// writing the binary. The first instruction at `addr` sets the
    /// boundary; shorter replacements are NOP-padded, longer ones report
    /// `size_ok: false`. `--out` writes a `json`/`ips` patch file that
    /// must differ from the binary.
    Patch {
        binary: PathBuf,
        addr: String,
        /// Intel-syntax assembly encoded at `addr` (x86 only; one of
        /// `nop`, `ret`, `int3`, `jmp ADDR`, `call ADDR`).
        #[arg(long, conflicts_with = "bytes", required_unless_present = "bytes")]
        asm: Option<String>,
        /// Literal bytes as whitespace-separated hex pairs (`"90 90"`).
        #[arg(long, conflicts_with = "asm", required_unless_present = "asm")]
        bytes: Option<String>,
        /// Write the patch file here (never the analyzed binary).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Patch file format for `--out`: `json` or `ips`.
        #[arg(long)]
        format: Option<String>,
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
                emit_error(&e);
            }
        };
        let db = self.db.as_deref();
        let fat_arch = self.fat_arch.as_deref();
        let debug = binscout::DebugOptions {
            pdb: self.pdb,
            debug_file: self.debug_file,
        };
        let result = match self.cmd {
            Cmd::Load { binary } => load(&binary, db, raw_opts, fat_arch, &debug),
            Cmd::Functions {
                binary,
                query,
                caller,
                callee,
                range,
                offset,
                limit,
                envelope,
            } => functions_filter(query, caller, callee, range).and_then(|filter| {
                functions(
                    &binary, db, raw_opts, fat_arch, &debug, &filter, offset, limit, envelope,
                )
            }),
            Cmd::Func { binary, addr } => func(&binary, db, raw_opts, fat_arch, &debug, &addr),
            Cmd::Blocks {
                binary,
                addr,
                offset,
                limit,
            } => blocks(
                &binary, db, raw_opts, fat_arch, &debug, &addr, offset, limit,
            ),
            Cmd::BlockInsns {
                binary,
                addr,
                block,
                offset,
                limit,
            } => block_insns(
                &binary, db, raw_opts, fat_arch, &debug, &addr, &block, offset, limit,
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
                &debug,
                kind.as_deref(),
                func.as_deref(),
                offset,
                limit,
            ),
            Cmd::Disasm { binary, addr, len } => {
                disasm(&binary, db, raw_opts, fat_arch, &debug, &addr, len)
            }
            Cmd::Bytes {
                binary,
                addr,
                len,
                as_view,
                endian,
                as_type,
            } => bytes(
                &binary,
                db,
                raw_opts,
                fat_arch,
                &debug,
                &addr,
                len,
                &as_view,
                &endian,
                as_type.as_deref(),
            ),
            Cmd::Cfg { binary, addr } => cfg(&binary, db, raw_opts, fat_arch, &debug, &addr),
            Cmd::Structure { binary, addr } => {
                structure(&binary, db, raw_opts, fat_arch, &debug, &addr)
            }
            Cmd::Pseudo { binary, addr } => pseudo(&binary, db, raw_opts, fat_arch, &debug, &addr),
            Cmd::Callees {
                binary,
                addr,
                depth,
                offset,
                limit,
            } => callees(
                &binary, db, raw_opts, fat_arch, &debug, &addr, depth, offset, limit,
            ),
            Cmd::Callers {
                binary,
                addr,
                depth,
                offset,
                limit,
            } => callers(
                &binary, db, raw_opts, fat_arch, &debug, &addr, depth, offset, limit,
            ),
            Cmd::Slice {
                binary,
                addr,
                depth,
                offset,
                limit,
            } => slice(
                &binary, db, raw_opts, fat_arch, &debug, &addr, depth, offset, limit,
            ),
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
                &debug,
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
                with_xrefs,
                decode,
                envelope,
            } => {
                if offset.is_some() {
                    warn("warning: --offset is deprecated, use --start");
                }
                let decode = match decode
                    .map(|s| binscout::loader::strings::parse_decode_spec(&s))
                    .transpose()
                {
                    Ok(d) => d,
                    Err(e) => {
                        emit_error(&e);
                    }
                };
                strings(
                    &binary,
                    db,
                    raw_opts,
                    fat_arch,
                    &debug,
                    &binscout::analysis::StringsFilter {
                        pattern,
                        min_len,
                        section,
                        include_code,
                        start: start.or(offset).unwrap_or(0),
                        limit,
                    },
                    with_xrefs,
                    decode,
                    envelope,
                )
            }
            Cmd::Symbols { binary } => symbols(&binary, db, raw_opts, fat_arch, &debug),
            Cmd::StackStrings {
                binary,
                offset,
                limit,
            } => stack_strings(&binary, db, raw_opts, fat_arch, &debug, offset, limit),
            Cmd::Sections { binary } => sections(&binary, db, raw_opts, fat_arch, &debug),
            Cmd::Ir { binary, addr, len } => {
                ir(&binary, db, raw_opts, fat_arch, &debug, &addr, len)
            }
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
                &debug,
                addr.as_deref(),
                len,
            ),
            Cmd::Stats { binary } => stats(&binary, db, raw_opts, fat_arch, &debug),
            Cmd::Headers { binary } => headers(&binary, db, raw_opts, fat_arch, &debug),
            Cmd::FlirtHints {
                binary,
                addr,
                sigs,
                offset,
                limit,
            } => flirt_hints(
                &binary,
                db,
                raw_opts,
                fat_arch,
                &debug,
                addr.as_deref(),
                sigs.as_deref(),
                offset,
                limit,
            ),
            Cmd::SigGen { binary } => sig_gen(&binary, db, raw_opts, fat_arch, &debug),
            Cmd::GoFuncs {
                binary,
                offset,
                limit,
            } => go_funcs(&binary, db, raw_opts, fat_arch, &debug, offset, limit),
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
                &debug,
                &addr,
                rename.as_deref(),
                comment.as_deref(),
            ),
            Cmd::DefineFunc { binary, addr, mode } => define_func(
                &binary,
                db,
                raw_opts,
                fat_arch,
                &debug,
                &addr,
                mode.as_deref(),
            ),
            Cmd::TypeHint {
                binary,
                addr,
                json,
                get,
            } => type_hint(
                &binary,
                db,
                raw_opts,
                fat_arch,
                &debug,
                &addr,
                json.as_deref(),
                get,
            ),
            Cmd::UndefineFunc { binary, addr } => {
                undefine_func(&binary, db, raw_opts, fat_arch, &debug, &addr)
            }
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
                &debug,
                &pattern,
                section.as_deref(),
                range,
                offset,
                limit,
            ),
            Cmd::CryptoScan {
                binary,
                name,
                section,
                offset,
                limit,
            } => crypto_scan(
                &binary,
                db,
                raw_opts,
                fat_arch,
                &debug,
                name.as_deref(),
                section.as_deref(),
                offset,
                limit,
            ),
            Cmd::ScanYara {
                binary,
                rules,
                rule,
                section,
                offset,
                limit,
            } => scan_yara(
                &binary,
                db,
                raw_opts,
                fat_arch,
                &debug,
                &rules,
                rule.as_deref(),
                section.as_deref(),
                offset,
                limit,
            ),
            Cmd::AnnotationsExport { binary } => {
                annotations_export(&binary, db, raw_opts, fat_arch, &debug)
            }
            Cmd::AnnotationsImport {
                binary,
                input,
                overwrite,
            } => annotations_import(&binary, db, raw_opts, fat_arch, &debug, &input, overwrite),
            Cmd::Diff {
                binary_a,
                binary_b,
                db_a,
                db_b,
                offset,
                limit,
                transfer_renames,
            } => bindiff(
                &binary_a,
                &binary_b,
                db,
                db_a.as_deref(),
                db_b.as_deref(),
                raw_opts,
                fat_arch,
                &debug,
                offset,
                limit,
                transfer_renames,
            ),
            Cmd::DiffFunc {
                binary_a,
                binary_b,
                addr_a,
                addr_b,
                db_a,
                db_b,
            } => diff_func(
                &binary_a,
                &binary_b,
                &addr_a,
                &addr_b,
                db,
                db_a.as_deref(),
                db_b.as_deref(),
                raw_opts,
                fat_arch,
                &debug,
            ),
            Cmd::Patch {
                binary,
                addr,
                asm,
                bytes,
                out,
                format,
            } => patch(
                &binary,
                db,
                raw_opts,
                fat_arch,
                &debug,
                &addr,
                asm.as_deref(),
                bytes.as_deref(),
                out.as_deref(),
                format.as_deref(),
            ),
        };
        match result {
            Ok(value) => {
                emit(&value, 0);
            }
            Err(e) => {
                emit_error(&e);
            }
        }
    }
}

/// Write one JSON line to stdout without panicking on a closed pipe.
///
/// `println!` panics with exit 101 when stdout is a closed pipe (EPIPE),
/// which violates the CLI contract (success exits 0, runtime failure
/// prints `{"error": ..., "kind": ...}` and exits 1). A closed pipe means
/// the consumer went away, so exit quietly with the intended code instead:
/// success stays 0 (conventional SIGPIPE-quiet), failure stays 1.
fn emit(value: &serde_json::Value, code: i32) -> ! {
    use std::io::Write as _;
    let text = value.to_string();
    let mut out = std::io::stdout().lock();
    match writeln!(out, "{text}") {
        Ok(()) => std::process::exit(code),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(code),
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "failed to write stdout: {e}");
            std::process::exit(1);
        }
    }
}

/// Runtime failure envelope: the human message plus the machine-readable
/// [`binscout::error::Error::kind`], so agents branch on `kind` instead
/// of parsing `error`.
fn emit_error(e: &binscout::error::Error) -> ! {
    emit(
        &serde_json::json!({ "error": e.to_string(), "kind": e.kind() }),
        1,
    )
}

/// Best-effort stderr note that never panics, even on a closed stderr.
fn warn(msg: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "{msg}");
}

fn open(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
) -> binscout::error::Result<binscout::Project> {
    binscout::open_mapped(binary, db, raw, fat_arch, debug)
}

/// Open for loader-only commands: cache hits skip instruction re-decode
/// (see [`binscout::Project::open_loader_only`]).
fn open_loader(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
) -> binscout::error::Result<binscout::LoaderOpened> {
    binscout::open_mapped_loader_only(binary, db, raw, fat_arch, debug)
}

fn opt_addr(s: Option<&str>) -> binscout::error::Result<Option<u64>> {
    s.map(binscout::parse_addr).transpose()
}

fn load(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
) -> binscout::error::Result<serde_json::Value> {
    match open_loader(binary, db, raw, fat_arch, debug)? {
        binscout::LoaderOpened::Cached(p) => {
            // Cache hit: the open replayed the stored snapshot, so there is
            // nothing to save.
            Ok(serde_json::to_value(p.project_info()).expect("project_info serializes"))
        }
        binscout::LoaderOpened::Fresh(p) => {
            // Stale or missing snapshot: same skip as before, so repeat
            // loads on an unchanged binary neither rewrite tables nor grow
            // free pages. Misses and stale opens still save below.
            if !p.snapshot_fresh() {
                p.save()?;
            }
            Ok(serde_json::to_value(p.project_info()).expect("project_info serializes"))
        }
    }
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

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch/debug"
)]
fn functions(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    filter: &binscout::FunctionFilter,
    offset: usize,
    limit: usize,
    _envelope: bool,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
    Ok(
        serde_json::to_value(p.functions_envelope(filter, offset, limit))
            .expect("functions envelope serializes"),
    )
}

fn func(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: &str,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
    let meta = p.func_meta(binscout::parse_addr(addr)?)?;
    Ok(serde_json::to_value(meta).expect("func_meta serializes"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch/debug"
)]
fn blocks(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: &str,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
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
    debug: &binscout::DebugOptions,
    addr: &str,
    block: &str,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
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
    debug: &binscout::DebugOptions,
    kind: Option<&str>,
    func: Option<&str>,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
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
    debug: &binscout::DebugOptions,
    addr: &str,
    len: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
    let addr = binscout::parse_addr(addr)?;
    Ok(serde_json::to_value(p.disasm_at(addr, len)?).expect("partial disasm serializes"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch/debug"
)]
fn bytes(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: &str,
    len: usize,
    as_view: &str,
    endian: &str,
    as_type: Option<&str>,
) -> binscout::error::Result<serde_json::Value> {
    let addr = binscout::parse_addr(addr)?;
    let as_type = as_type.map(binscout::parse_addr).transpose()?;
    let as_ = binscout::parse_bytes_as(as_view)?;
    let endian = binscout::parse_bytes_endian(endian)?;
    match open_loader(binary, db, raw, fat_arch, debug)? {
        binscout::LoaderOpened::Cached(p) => match as_type {
            Some(hint) => p.bytes_view_as_type(addr, len, as_, endian, hint),
            None => Ok(serde_json::to_value(p.bytes_view(addr, len, as_, endian)?)
                .expect("bytes view serializes")),
        },
        binscout::LoaderOpened::Fresh(p) => match as_type {
            Some(hint) => p.bytes_view_as_type(addr, len, as_, endian, hint),
            None => Ok(serde_json::to_value(p.bytes_view(addr, len, as_, endian)?)
                .expect("bytes view serializes")),
        },
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch/debug"
)]
fn type_hint(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: &str,
    json: Option<&str>,
    get: bool,
) -> binscout::error::Result<serde_json::Value> {
    if json.is_some() && get {
        return Err(binscout::error::Error::Invalid(
            "type-hint takes either --json or --get, not both".to_string(),
        ));
    }
    let mut p = open(binary, db, raw, fat_arch, debug)?;
    let addr = binscout::parse_addr(addr)?;
    if let Some(json) = json {
        p.set_type_hint_json(addr, json)?;
    }
    let hint = p.type_hint_at(addr)?;
    let (addr_json, addr_hex) = binscout::addr_pair(addr);
    Ok(serde_json::json!({
        "addr": addr_json,
        "addr_hex": addr_hex,
        "hint": hint.map(|h| binscout::annotations::type_hint_json(&h)),
    }))
}

fn cfg(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: &str,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
    p.cfg_of(binscout::parse_addr(addr)?)
}

fn structure(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: &str,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
    p.structure_of(binscout::parse_addr(addr)?)
}

fn pseudo(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: &str,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
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
    debug: &binscout::DebugOptions,
    addr: &str,
    depth: usize,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
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
    debug: &binscout::DebugOptions,
    addr: &str,
    depth: usize,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
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
    debug: &binscout::DebugOptions,
    addr: &str,
    depth: usize,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
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
    debug: &binscout::DebugOptions,
    to: Option<&str>,
    from: Option<&str>,
    kind: Option<&str>,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
    let kind = kind.map(binscout::parse_xref_kind).transpose()?;
    let (to, from) = (opt_addr(to)?, opt_addr(from)?);
    Ok(
        serde_json::to_value(p.xref_rows_envelope(to, from, kind, offset, limit))
            .expect("xrefs page serializes"),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn strings(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    filter: &binscout::analysis::StringsFilter,
    with_xrefs: bool,
    decode: Option<binscout::loader::strings::DecodeSpec>,
    _envelope: bool,
) -> binscout::error::Result<serde_json::Value> {
    if with_xrefs {
        let p = open(binary, db, raw, fat_arch, debug)?;
        return strings_from_project(&p, filter, decode, true);
    }
    match open_loader(binary, db, raw, fat_arch, debug)? {
        binscout::LoaderOpened::Cached(p) => strings_from_loader(&p, filter, decode),
        binscout::LoaderOpened::Fresh(p) => strings_from_project(&p, filter, decode, false),
    }
}

fn strings_from_loader(
    p: &binscout::LoaderProject,
    filter: &binscout::analysis::StringsFilter,
    decode: Option<binscout::loader::strings::DecodeSpec>,
) -> binscout::error::Result<serde_json::Value> {
    let page = match decode {
        Some(spec) => p.query_strings_decoded_envelope(filter, spec)?,
        None => p.query_strings_envelope(filter)?,
    };
    Ok(serde_json::to_value(page).expect("strings envelope serializes"))
}

fn strings_from_project(
    p: &binscout::Project,
    filter: &binscout::analysis::StringsFilter,
    decode: Option<binscout::loader::strings::DecodeSpec>,
    with_xrefs: bool,
) -> binscout::error::Result<serde_json::Value> {
    let page = match decode {
        Some(spec) => p.query_strings_decoded_rows_envelope(filter, spec, with_xrefs)?,
        None => p.query_strings_rows_envelope(filter, with_xrefs)?,
    };
    Ok(serde_json::to_value(page).expect("strings envelope serializes"))
}

fn symbols(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
) -> binscout::error::Result<serde_json::Value> {
    Ok(match open_loader(binary, db, raw, fat_arch, debug)? {
        binscout::LoaderOpened::Cached(p) => p.symbols_json(),
        binscout::LoaderOpened::Fresh(p) => p.symbols_json(),
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch/debug"
)]
fn stack_strings(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    Ok(serde_json::to_value(
        open(binary, db, raw, fat_arch, debug)?.stack_strings_page(offset, limit),
    )
    .expect("stack strings serialize"))
}

fn sections(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
) -> binscout::error::Result<serde_json::Value> {
    Ok(match open_loader(binary, db, raw, fat_arch, debug)? {
        binscout::LoaderOpened::Cached(p) => p.sections_json(),
        binscout::LoaderOpened::Fresh(p) => p.sections_json(),
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch/debug"
)]
fn ir(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: &str,
    len: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
    p.ir_at(binscout::parse_addr(addr)?, len)
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch/debug"
)]
fn ir_coverage(
    arch: &str,
    binary: Option<&std::path::Path>,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: Option<&str>,
    len: Option<usize>,
) -> binscout::error::Result<serde_json::Value> {
    let arch = binscout::parse_raw_arch(arch)?;
    match (binary, addr, len) {
        (None, None, None) => Ok(binscout::ir_coverage(arch)),
        (Some(binary), Some(addr), Some(len)) => open(binary, db, raw, fat_arch, debug)?
            .ir_coverage_at(arch, binscout::parse_addr(addr)?, len),
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
    debug: &binscout::DebugOptions,
) -> binscout::error::Result<serde_json::Value> {
    match open_loader(binary, db, raw, fat_arch, debug)? {
        binscout::LoaderOpened::Cached(p) => p.stats_json(),
        binscout::LoaderOpened::Fresh(p) => p.stats_json(),
    }
}

fn headers(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
) -> binscout::error::Result<serde_json::Value> {
    match open_loader(binary, db, raw, fat_arch, debug)? {
        binscout::LoaderOpened::Cached(p) => p.headers_json(),
        binscout::LoaderOpened::Fresh(p) => p.headers_json(),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn flirt_hints(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: Option<&str>,
    sigs: Option<&std::path::Path>,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let extra = sigs
        .map(binscout::flirt::load_signature_file)
        .transpose()?
        .unwrap_or_default();
    let p = open(binary, db, raw, fat_arch, debug)?;
    let page = p.query_flirt_hints_with(opt_addr(addr)?, offset, limit, &extra)?;
    Ok(serde_json::to_value(page).expect("flirt hints page serializes"))
}

fn sig_gen(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
    Ok(serde_json::to_value(p.generate_signatures()).expect("signature document serializes"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch/debug"
)]
fn go_funcs(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
    Ok(serde_json::to_value(p.go_funcs_page(offset, limit)?).expect("go funcs serialize"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch/debug"
)]
fn annotate(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: &str,
    rename: Option<&str>,
    comment: Option<&str>,
) -> binscout::error::Result<serde_json::Value> {
    let mut p = open(binary, db, raw, fat_arch, debug)?;
    let addr = binscout::parse_addr(addr)?;
    p.annotate(addr, rename, comment)?;
    Ok(p.annotation_json(addr))
}

fn define_func(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: &str,
    mode: Option<&str>,
) -> binscout::error::Result<serde_json::Value> {
    let mut p = open(binary, db, raw, fat_arch, debug)?;
    let addr = binscout::parse_addr(addr)?;
    let mode = mode.map(binscout::analysis::SeedMode::parse).transpose()?;
    p.define_func(addr, mode)?;
    Ok(p.seed_json(addr))
}

fn undefine_func(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: &str,
) -> binscout::error::Result<serde_json::Value> {
    let mut p = open(binary, db, raw, fat_arch, debug)?;
    let addr = binscout::parse_addr(addr)?;
    p.undefine_func(addr)?;
    Ok(p.seed_json(addr))
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
    debug: &binscout::DebugOptions,
    pattern: &str,
    section: Option<&str>,
    range: Option<Vec<String>>,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let opened = open_loader(binary, db, raw, fat_arch, debug)?;
    let range = range
        .map(|pair| match &pair[..] {
            [lo, hi] => Ok((binscout::parse_addr(lo)?, binscout::parse_addr(hi)?)),
            _ => Err(binscout::error::Error::Invalid(
                "--range takes LO HI".to_string(),
            )),
        })
        .transpose()?;
    let page = match opened {
        binscout::LoaderOpened::Cached(p) => {
            p.search_bytes(pattern, section, range, offset, limit)?
        }
        binscout::LoaderOpened::Fresh(p) => {
            p.search_bytes(pattern, section, range, offset, limit)?
        }
    };
    Ok(serde_json::to_value(page).expect("search_bytes page serializes"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn crypto_scan(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    name: Option<&str>,
    section: Option<&str>,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
    let page = p.crypto_scan(name, section, offset, limit)?;
    Ok(serde_json::to_value(page).expect("crypto_scan page serializes"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn scan_yara(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    rules: &std::path::Path,
    rule: Option<&str>,
    section: Option<&str>,
    offset: usize,
    limit: usize,
) -> binscout::error::Result<serde_json::Value> {
    let p = open(binary, db, raw, fat_arch, debug)?;
    let page = p.scan_yara(rules, rule, section, offset, limit)?;
    Ok(serde_json::to_value(page).expect("scan_yara page serializes"))
}

fn annotations_export(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
) -> binscout::error::Result<serde_json::Value> {
    let doc = match open_loader(binary, db, raw, fat_arch, debug)? {
        binscout::LoaderOpened::Cached(p) => p.export_annotations()?,
        binscout::LoaderOpened::Fresh(p) => p.export_annotations()?,
    };
    serde_json::from_str(&doc)
        .map_err(|e| binscout::error::Error::Storage(format!("encode annotation document: {e}")))
}

fn annotations_import(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    input: &std::path::Path,
    overwrite: bool,
) -> binscout::error::Result<serde_json::Value> {
    let text = read_transfer_document(input)?;
    let mut p = open(binary, db, raw, fat_arch, debug)?;
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
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn bindiff(
    binary_a: &std::path::Path,
    binary_b: &std::path::Path,
    global_db: Option<&std::path::Path>,
    db_a: Option<&std::path::Path>,
    db_b: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    offset: usize,
    limit: usize,
    transfer_renames: bool,
) -> binscout::error::Result<serde_json::Value> {
    if global_db.is_some() {
        return Err(binscout::error::Error::Invalid(
            "diff takes --db-a/--db-b, not the global --db".to_string(),
        ));
    }
    let a = binscout::open_mapped(binary_a, db_a, raw, fat_arch, debug)?;
    let b = binscout::open_mapped(binary_b, db_b, raw, fat_arch, debug)?;
    let mut report = binscout::diff::diff_projects_page(&a, &b, offset, limit);
    if transfer_renames {
        report.transfer = Some(binscout::diff::transfer_renames(&a, &b)?);
    }
    Ok(serde_json::to_value(report).expect("diff report serializes"))
}

/// Block-level delta between two functions, read-only on both sides.
///
/// Takes `--db-a`/`--db-b` like [`bindiff`] and rejects the global `--db`
/// for the same reason; neither project is saved, so no sidecar is ever
/// created or modified.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn diff_func(
    binary_a: &std::path::Path,
    binary_b: &std::path::Path,
    addr_a: &str,
    addr_b: &str,
    global_db: Option<&std::path::Path>,
    db_a: Option<&std::path::Path>,
    db_b: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
) -> binscout::error::Result<serde_json::Value> {
    if global_db.is_some() {
        return Err(binscout::error::Error::Invalid(
            "diff-func takes --db-a/--db-b, not the global --db".to_string(),
        ));
    }
    let a = binscout::open_mapped(binary_a, db_a, raw, fat_arch, debug)?;
    let b = binscout::open_mapped(binary_b, db_b, raw, fat_arch, debug)?;
    let report = binscout::diff::diff_func(
        &a,
        binscout::parse_addr(addr_a)?,
        &b,
        binscout::parse_addr(addr_b)?,
    )?;
    Ok(serde_json::to_value(report).expect("func diff report serializes"))
}

/// Assemble replacement bytes at one address and export the patch.
///
/// Exactly one of `asm`/`bytes` is required (clap enforces the same);
/// `format` without `out` is an error. Stdout is always the preview
/// (`va`, `file_off`, `old_hex`, `new_hex`, `size_ok`), extended with
/// `out`/`format`/`bytes_written` when a patch file is written. The binary
/// and the sidecar are never written.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors subcommand args plus shared db/raw/fat-arch"
)]
fn patch(
    binary: &std::path::Path,
    db: Option<&std::path::Path>,
    raw: Option<binscout::loader::RawOptions>,
    fat_arch: Option<&str>,
    debug: &binscout::DebugOptions,
    addr: &str,
    asm: Option<&str>,
    bytes: Option<&str>,
    out: Option<&std::path::Path>,
    format: Option<&str>,
) -> binscout::error::Result<serde_json::Value> {
    if format.is_some() && out.is_none() {
        return Err(binscout::error::Error::Invalid(
            "--format needs --out".to_string(),
        ));
    }
    let p = open(binary, db, raw, fat_arch, debug)?;
    let input = match (asm, bytes) {
        (Some(text), None) => binscout::patch::PatchInput::Asm(text.to_string()),
        (None, Some(text)) => {
            binscout::patch::PatchInput::Bytes(binscout::patch::parse_patch_bytes(text)?)
        }
        (Some(_), Some(_)) => {
            return Err(binscout::error::Error::Invalid(
                "--asm and --bytes are exclusive".to_string(),
            ));
        }
        (None, None) => {
            return Err(binscout::error::Error::Invalid(
                "patch needs --asm or --bytes".to_string(),
            ));
        }
    };
    let preview = p.patch_preview(binscout::parse_addr(addr)?, &input)?;
    let mut value = serde_json::to_value(&preview).expect("patch preview serializes");
    if let Some(out) = out {
        let fmt = match format {
            Some(name) => binscout::patch::parse_patch_format(name)?,
            None => binscout::patch::PatchFileFormat::Json,
        };
        let summary = p.write_patch_file(&preview, out, fmt)?;
        for (key, val) in summary.as_object().expect("summary is an object") {
            value[key] = val.clone();
        }
    }
    Ok(value)
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
        _ => Error::Io(format!("stat {}: {e}", path.display())),
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
        std::fs::read(path).map_err(|e| Error::Io(format!("read {}: {e}", path.display())))?;
    if bytes.len() > MAX_TRANSFER_BYTES {
        return Err(Error::Limit(format!(
            "annotation document of {} bytes exceeds the {MAX_TRANSFER_BYTES}-byte cap",
            bytes.len()
        )));
    }
    String::from_utf8(bytes)
        .map_err(|e| Error::Invalid(format!("malformed annotation document: {e}")))
}
