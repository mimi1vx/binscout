# binscout

Headless, agent-first binary analysis. Open a binary (ELF/PE/Mach-O/LE/raw),
get functions, CFGs, xrefs, strings, symbols, and IR — over a JSON CLI or an
MCP server over stdio. Annotations (renames, comments) live in a `redb`
sidecar; the binary is never written.

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
| `ir` | `binscout ir fw.elf 0x400000 32` | P-code-inspired lift of the range |
| `annotate` | `binscout annotate fw.elf 0x400000 --rename main --comment "entry"` | read/write annotation at an address |

Annotate without flags reads; `--rename ""` / omitting `--comment` clears.
`rename` only accepts known function entries; `comment` accepts any address.

## MCP server

`binscout-mcp` serves 11 tools over stdio (newline-delimited JSON-RPC):
`project_info`, `functions`, `func`, `disasm`, `cfg`, `xrefs`, `strings`,
`symbols`, `ir`, `rename`, `comment`. Each takes `binary` plus optional `db`
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
