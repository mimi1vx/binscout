# MCP tools

`binscout-mcp` serves 20 tools over stdio (newline-delimited JSON-RPC).
Each takes `binary` plus an optional `db` path and returns one JSON
document as text; failures are tool errors. Attach it to any MCP client:

```json
{
  "mcpServers": {
    "binscout": { "command": "/path/to/binscout-mcp" }
  }
}
```

| Tool | Parameters | Does |
|---|---|---|
| `project_info` | binary | Open a binary and report arch, format, entry, and analysis counts |
| `functions` | binary, query/caller/callee/range_lo/range_hi, offset/limit | List functions with rename-resolved names, filtered (`query` case-insensitive substring; `caller`/`callee` addresses resolving to call-graph neighbors; `range_lo` + `range_hi` bounding entries) and paged |
| `func` | binary, addr | Full detail of one function: blocks with instructions, edges, calls |
| `disasm` | binary, addr, len | Disassemble `len` bytes at `addr` with the binary architecture; the valid prefix plus `error_at` for the first bad opcode (ranges cap at 1 MiB) |
| `cfg` | binary, addr | Control-flow graph of one function: block nodes plus block edges |
| `diagnostics` | binary, kind?, func?, offset/limit | Provenance records (unresolved indirect sites, decode failures) ordered by (`kind`, `addr`) under the page envelope, filtered by `kind` and containing-function `func`; queries never write a sidecar |
| `xrefs` | binary, to/from/kind, offset/limit | Cross-references filtered by endpoint and kind, paged behind a `total` match count |
| `strings` | binary, pattern/min-len/section/include_code, start/limit | Extracted strings ordered by address, filtered and paged; executable-memory hits hidden unless `pattern`, `section`, or `include_code` is given (`offset` is a deprecated alias of `start`) |
| `symbols` | binary | Imports and exports of the binary |
| `sections` | binary | Section table: name, virtual address (`IMAGE_BASE + RVA` on PE), in-memory/file sizes, permissions |
| `ir` | binary, addr, len | Lift `len` bytes at `addr` to P-code-inspired IR (`error_at` on trailing bad bytes, ranges cap at 1 MiB) |
| `ir_coverage` | arch, binary?/addr?/len? | Machine-readable lift coverage for one arch (implemented families, partial mappings, limitations); no binary is opened without the range, which adds decoded/lifted/unlifted counts from actual lifts plus a bounded mnemonic summary |
| `stats` | binary | Storage stats: binary size, sidecar DB size, and analysis counts |
| `rename` | binary, addr, name | Rename a function in the project DB (binary untouched); empty name clears |
| `comment` | binary, addr, comment | Comment any address in the project DB (binary untouched); empty comment clears |
| `annotations_export` | binary | Emit the portable annotation interchange document; read-only, never creates a sidecar |
| `annotations_import` | binary, document, overwrite? | Atomically merge a document; returns row/change counts, default fails on conflicts |

Addresses are `0x`-hex or decimal strings. `kind` is one of `code`,
`data`, or `string`. Calls are serialized behind one lock because `redb`
allows a single open handle per file per process.

## Protocol-1 tools (all implemented)

All protocol-1 tools are implemented (20 tools today): `blocks`,
`block_insns`, `search_bytes`, `diagnostics`, `ir_coverage`,
`annotations_export`, and `annotations_import` have all landed with
their roadmap steps, alongside the optional `raw`
(`arch`/`base`/`entry?`) mapping object on every binary-taking tool.
See [JSON protocol](json-protocol.md) for the full request/response
definitions. `func` returns the compact metadata shape.
