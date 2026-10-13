# binscout

[![CI](https://github.com/mimi1vx/binscout/actions/workflows/ci.yml/badge.svg)](https://github.com/mimi1vx/binscout/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/mimi1vx/binscout#license)

Headless, agent-first binary analysis. Open a binary (ELF/PE/Mach-O/LE/raw),
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
binscout [--db PATH] <command> <binary> [args]
```

`--db` overrides the sidecar DB (default `<binary>.rsdbg.redb`).

| Command | Example | Output |
|---|---|---|
| `load` | `binscout load fw.elf` | project info; caches the analysis snapshot |
| `functions` | `binscout functions fw.elf --offset 0 --limit 50` | function rows, renames resolved |
| `func` | `binscout func fw.elf 0x400000` | blocks with instructions, edges, calls |
| `disasm` | `binscout disasm fw.elf 0x400000 32` | decoded instructions (`addr` = hex or decimal, then byte count) |
| `cfg` | `binscout cfg fw.elf 0x400000` | block nodes plus `(from, to)` edges |
| `xrefs` | `binscout xrefs fw.elf --to 0x400000 --kind code` | filtered/paged cross-references |
| `strings` | `binscout strings fw.elf --limit 20` | extracted strings by address |
| `symbols` | `binscout symbols fw.elf` | imports and exports |
| `sections` | `binscout sections fw.elf` | section table: name, `vaddr` (flat VA = `IMAGE_BASE + RVA` on PE), in-memory/file sizes, permissions |
| `ir` | `binscout ir fw.elf 0x400000 32` | P-code-inspired lift of the range |
| `stats` | `binscout stats fw.elf` | storage stats: binary size, sidecar DB size, analysis counts |
| `annotate` | `binscout annotate fw.elf 0x400000 --rename main --comment "entry"` | read/write annotation at an address |

Annotate without flags reads; `--rename ""` / omitting `--comment` clears.
`rename` only accepts known function entries; `comment` accepts any address.

## MCP server

`binscout-mcp` serves 13 tools over stdio (newline-delimited JSON-RPC):
`project_info`, `functions`, `func`, `disasm`, `cfg`, `xrefs`, `strings`,
`symbols`, `sections`, `ir`, `stats`, `rename`, `comment`. Each takes `binary` plus optional `db`
and returns one JSON document as text; failures are tool errors.

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
it is rebuilt on the next `load`. Never commit sidecars — keep them out
of version control:

```gitignore
*.rsdbg.redb
```

## License

Dual-licensed under either of:

- [MIT](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
