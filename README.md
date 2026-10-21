# binscout

[![CI](https://github.com/mimi1vx/binscout/actions/workflows/ci.yml/badge.svg)](https://github.com/mimi1vx/binscout/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/mimi1vx/binscout#license)

Headless, agent-first binary analysis. Open a binary (ELF/PE/Mach-O/COFF/LE/raw),
get functions, CFGs, xrefs, strings, symbols, and IR — over a JSON CLI or an
MCP server over stdio. Annotations (renames, comments) live in a `redb`
sidecar; the binary is never written.

Full docs live in the [book](https://mimi1vx.github.io/binscout/).

## Install

From crates.io:

```sh
cargo install binscout
```

Or from git (latest `master`):

```sh
cargo install --git https://github.com/mimi1vx/binscout
```

Or from source:

```sh
git clone https://github.com/mimi1vx/binscout
cd binscout
cargo install --path .
```

This installs both `binscout` (JSON CLI) and `binscout-mcp` (MCP server).

## Quickstart

```sh
binscout load fw.elf                    # open the binary, cache the analysis snapshot
binscout functions fw.elf --limit 10    # first 10 functions
binscout disasm fw.elf 0x400000 32      # decode 32 bytes at the entry point
binscout annotate fw.elf 0x400000 --rename main   # rename a known function
```

## CLI

Every command prints exactly one JSON value to stdout. Runtime failures print
`{"error": "..."}` with exit 1, so stdout is always valid JSON. (Clap usage
errors for unknown flags/subcommands still go to stderr with exit 2.)

```sh
binscout [--db PATH] [--raw --arch ARCH --base ADDR [--entry ADDR]] [--fat-arch ARCH] [--pdb PATH] [--debug-file PATH] <command> <binary> [args]
```

`--db` overrides the sidecar DB (default `<binary>.rsdbg.redb`,
appended to the full file name so `foo.exe` and `foo.dll` never share
one). `--raw`
selects explicit raw mapping for firmware/blob workflows (`arch` is one
of `x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`, `riscv32`, `riscv64`, `mips32`,
`ppc32`, `ppc64`); without it,
container auto-detection applies. `--fat-arch` selects a slice of a
fat Mach-O container (`x86_64`, `x86_32`, `aarch64`, `arm32`, plus
`lipo` aliases like `arm64`, case-insensitive); it is required for fat
inputs and exclusive with `--raw`.

| Command | Example | Output |
|---|---|---|
| `load` | `binscout load fw.elf` | project info (`protocol`, `mode`, `arch`, `base`, diagnostic totals, `analysis_revision`); caches the analysis snapshot |
| `functions` | `binscout functions fw.elf --query main --limit 50` | function rows, renames resolved; filter with `--query` (case-insensitive name substring), `--caller`/`--callee` (addresses resolving to call-graph neighbors), `--range LO HI` (inclusive); page with `--offset`/`--limit` under the page envelope; rows carry `calls_count` instead of the `calls` target array |
| `func` | `binscout func fw.elf 0x400000` | compact metadata: entry, name, block/insn/call counts, discovery `reasons` |
| `blocks` | `binscout blocks fw.elf 0x400000 --limit 50` | block summaries of the containing function, paged under the page envelope |
| `block-insns` | `binscout block-insns fw.elf 0x400000 0x400000` | one block's instructions in address order, paged |
| `diagnostics` | `binscout diagnostics fw.elf --kind decode-failure` | provenance records (unresolved indirect sites, decode failures) filtered by `--kind`/`--func`, paged; never writes a sidecar |
| `disasm` | `binscout disasm fw.elf 0x400000 32` | decoded instructions (`addr` = hex or decimal, then byte count); trailing bad bytes report in `error_at`, ranges cap at 1 MiB |
| `cfg` | `binscout cfg fw.elf 0x400000` | block nodes plus `(from, to)` edges; `inferred_edges` holds provenance-marked indirect-jump resolutions (single-slot absolutes and guarded scaled-index tables; raw-only, same-function) |
| `structure` | `binscout structure fw.elf 0x400000` | approximate control-flow structure: syntactic loops and ifs over the CFG plus the IR lift, with an approximation warning |
| `pseudo` | `binscout pseudo fw.elf 0x400000` | approximate pseudo-C of one function: one lossy C-like line per IR row plus assembled text, with an approximation warning |
| `callees` | `binscout callees fw.elf 0x400000 --depth 5` | transitive callees out to `--depth` hops (direct are depth 1), ordered by entry with shortest distance, paged under the page envelope |
| `callers` | `binscout callers fw.elf 0x400000 --depth 5` | transitive callers out to `--depth` hops, ordered by entry with shortest distance, paged under the page envelope |
| `slice` | `binscout slice fw.elf 0x400000 --depth 5` | backward slice of an address: every instruction that can reach it via xref edges (any kind) and intra-function CFG predecessors out to `--depth` hops (direct are depth 1, default 8), ordered by address with shortest distance, paged under the page envelope; unmapped roots are a `NotFound` error |
| `xrefs` | `binscout xrefs fw.elf --to 0x400000 --kind code` | cross-references filtered by `--to`/`--from`/`--kind` (`code`, `data`, `string`, `import`, `inferred-code`), paged with `--offset`/`--limit` under the protocol-1 page envelope (`items`) with an exact `total` |
| `strings` | `binscout strings fw.elf --pattern SAVE --min-len 6 --limit 20` | extracted strings by address; `--pattern` (substring or `regex:` expression), `--min-len`, `--section`, `--include-code` (executable-memory hits hidden by default), `--decode` (`xor:<byte>`, `add:<byte>`, or `rot:<0-7>`, read-only in-memory transform with original offsets); paged by `--start`/`--limit` under the page envelope |
| `stack-strings` | `binscout stack-strings fw.elf --limit 20` | recovered stack-constructed strings with function and address, paged under the page envelope |
| `go-funcs` | `binscout go-funcs fw.elf --limit 20` | Go functions from the `pclntab` table, paged under the page envelope; empty table reads as an empty page |
| `bytes` | `binscout bytes fw.elf 0x400000 --len 32 --as u16` | raw bytes with VA/file provenance plus `bytes_hex` and typed `values` (`u8`/`u16`/`u32`/`u64`/`ptr`/`cstr`/`utf16`); integer views carry the exact `0x`-hex twin `values_hex` |
| `symbols` | `binscout symbols fw.elf` | imports and exports; Mach-O imports carry the `address` of their `__stubs` entry (null when unmapped), and each mapped stub seeds its own import-named function |
| `sections` | `binscout sections fw.elf` | section table: name, `vaddr` (flat VA = `IMAGE_BASE + RVA` on PE), in-memory/file sizes, permissions |
| `ir` | `binscout ir fw.elf 0x400000 32` | P-code-inspired lift of the range (`error_at` on trailing bad bytes, ranges cap at 1 MiB) |
| `ir-coverage` | `binscout ir-coverage x86_64` | machine-readable lift coverage for one arch; with `BINARY ADDR LEN` adds decoded/lifted/unlifted counts from actual lifts |
| `flirt-hints` | `binscout flirt-hints fw.elf --addr 0x400000` | FLIRT-like library hints (read-only): corpus signature matches over each function's leading bytes, paged under the page envelope; suggested names stay hints, querying never writes a sidecar |
| `stats` | `binscout stats fw.elf` | storage stats: binary size, sidecar DB size, analysis counts |
| `annotate` | `binscout annotate fw.elf 0x400000 --rename main --comment "entry"` | read/write annotation at an address |
| `search-bytes` | `binscout search-bytes fw.elf "48 8B ??" --range 0x400000 0x401000` | paged `??`-wildcard byte-pattern matches with `--section`/`--range` filters |
| `annotations-export` | `binscout annotations-export fw.elf` | portable annotation document (revision, SHA-256, size, mapping, sorted rows); read-only |
| `annotations-import` | `binscout annotations-import fw.elf --input doc.json [--overwrite]` | atomically merge a document; returns `rows`/`changed`, default fails on conflicts |
| `diff` | `binscout diff old.elf new.elf [--db-a A.redb --db-b B.redb]` | function-level diff between two binaries (`matched`/`added`/`removed`/`changed` with match reason); both projects open read-only, never creating or modifying a sidecar; the global `--raw` mapping or `--fat-arch` selection (if any) applies to both, with per-side `--db-a`/`--db-b` instead of the global `--db` |
| `patch` | `binscout patch fw.elf 0x400000 --asm "jmp 0x401020"` | assemble replacement bytes at one x86 address (`nop`, `ret`, `int3`, `jmp ADDR`, `call ADDR`) or aarch64 address (`nop`, `ret`, `brk #IMM`, `b ADDR`, `bl ADDR`; 4-aligned, byte count a multiple of 4) and export the patch (`va`, `old_hex`, `new_hex`, `size_ok`); never writes the binary or the sidecar |

Paged lists cap at 1024 rows. Addresses accept `0x`-hex or decimal strings.

Annotate without flags reads; `--rename ""` / `--comment ""` clears,
omitting the flag leaves that field alone.
`rename` only accepts known function entries; `comment` accepts any address.

## MCP server

`binscout-mcp` serves 43 tools over stdio (newline-delimited JSON-RPC):
`project_info`, `load`, `functions`, `func`, `blocks`, `block_insns`,
`diagnostics`, `disasm`, `bytes`, `cfg`, `structure`, `pseudo`,
`callees`, `callers`, `slice`, `xrefs`, `strings`, `stack_strings`,
`symbols`, `stats`,
`sections`, `ir`, `ir_coverage`, `flirt_hints`, `sig_gen`, `go_funcs`,
`headers`, `rename`, `annotation`, `comment`, `set_type_hint`,
`get_type_hint`, `define_func`, `undefine_func`, `search_bytes`,
`crypto_scan`, `scan_yara`,
`annotations_export`, `annotations_import`, `diff`, `diff_func`,
`patch`, `batch`. Each takes `binary` plus
optional `db` (and an optional `raw` mapping object or `fat_arch` slice
selection plus optional `pdb`/`debug_file` debug inputs on binary-taking
tools) and returns one JSON document as text; failures are tool errors.

```json
{
  "mcpServers": {
    "binscout": { "command": "/path/to/binscout-mcp" }
  }
}
```

## Develop

```sh
cargo test          # full suite (unit + CLI/MCP e2e over fixtures)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo doc --no-deps # warning-free; `#![warn(missing_docs)]` is on
```

## Project database

Analysis snapshots live in a `redb` sidecar next to the binary:
`<binary>.rsdbg.redb` by default, overridden per-invocation with `--db
PATH` (CLI) or the `db` parameter (MCP). `load` writes the snapshot;
`rename`/`comment` persist immediately; every other command only reads.
`binscout stats <binary>` reports the binary size, the sidecar size
(`db_size`, `0` before the first `load`), and the analysis counts, so the
storage cost of a snapshot stays visible.

The sidecar is a cache: delete it to drop analysis and annotations, and
it is rebuilt on the next `load`. Snapshots are keyed by binary
content, loader mapping (auto versus explicit raw arch/base/entry),
and analysis revision: the same bytes opened under a different
mapping re-analyze rather than reuse layouts, and opening a sidecar
holding annotations under an incompatible mapping fails with a
separate-DB error instead of remapping them. Sidecars from older
schema versions rebuild the same way. Never commit sidecars — keep
them out of version control:

```gitignore
*.rsdbg.redb
```

## License

Dual-licensed under either of:

- [MIT](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
