# MCP tools

`binscout-mcp` serves 22 tools over stdio (newline-delimited JSON-RPC).
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
| `project_info` | binary | Open a binary and report arch, format, entry, mapping (`mode`, `base`), diagnostic totals, and `analysis_revision` |
| `functions` | binary, query/caller/callee/range_lo/range_hi, offset/limit | List functions with rename-resolved names, filtered (`query` case-insensitive substring; `caller`/`callee` addresses resolving to call-graph neighbors; `range_lo` + `range_hi` bounding entries) and paged |
| `func` | binary, addr | Compact metadata of one function: entry, name, block/insn/call counts, discovery `reasons` |
| `blocks` | binary, addr, offset?/limit? | Block summaries of the containing function by block start, under the page envelope |
| `block_insns` | binary, addr, block, offset?/limit? | That block's instructions in address order, under the page envelope; `block` must belong to the function |
| `disasm` | binary, addr, len | Disassemble `len` bytes at `addr` with the binary architecture; the valid prefix plus `error_at` for the first bad opcode (ranges cap at 1 MiB) |
| `cfg` | binary, addr | Control-flow graph of one function: block nodes plus block edges; `inferred_edges` holds provenance-marked single-slot resolutions (raw-only, same-function) |
| `callees` | binary, addr, depth?/offset?/limit? | Transitive callees out to `depth` hops (direct are depth 1), ordered by entry with shortest distance, under the page envelope; `addr` snaps to its containing function |
| `callers` | binary, addr, depth?/offset?/limit? | Transitive callers out to `depth` hops, ordered by entry with shortest distance, under the page envelope; `addr` snaps to its containing function |
| `diagnostics` | binary, kind?, func?, offset/limit | Provenance records (unresolved indirect sites, decode failures) ordered by (`kind`, `addr`) under the page envelope, filtered by `kind` and containing-function `func`; queries never write a sidecar |
| `xrefs` | binary, to/from/kind, offset/limit | Cross-references filtered by endpoint and kind (`code`, `data`, `string`, `inferred-code`), paged behind a `total` match count |
| `strings` | binary, pattern/min-len/section/include_code, start/limit | Extracted strings ordered by address, filtered and paged; executable-memory hits hidden unless `pattern`, `section`, or `include_code` is given (`offset` is a deprecated alias of `start`); `decode` (`xor:<byte>`, `add:<byte>`, `rot:<0-7>`) re-extracts over a read-only in-memory transform with original offsets |
| `symbols` | binary | Imports and exports of the binary |
| `sections` | binary | Section table: name, virtual address (`IMAGE_BASE + RVA` on PE), in-memory/file sizes, permissions |
| `ir` | binary, addr, len | Lift `len` bytes at `addr` to P-code-inspired IR (`error_at` on trailing bad bytes, ranges cap at 1 MiB) |
| `ir_coverage` | arch, binary?/addr?/len? | Machine-readable lift coverage for one arch (implemented families, partial mappings, limitations); no binary is opened without the range, which adds decoded/lifted/unlifted counts from actual lifts plus a bounded mnemonic summary |
| `stats` | binary | Storage stats: binary size, sidecar DB size, and analysis counts |
| `rename` | binary, addr, name | Rename a function in the project DB (binary untouched); empty name clears |
| `comment` | binary, addr, comment | Comment any address in the project DB (binary untouched); empty comment clears |
| `search_bytes` | binary, pattern, section?/range_start?/range_end?, offset?/limit? | Paged `??`-wildcard byte-pattern matches ordered by virtual address; scans cap at 256 MiB of mapped bytes with an explicit `Limit` error |
| `annotations_export` | binary | Emit the portable annotation interchange document; read-only, never creates a sidecar |
| `annotations_import` | binary, document, overwrite? | Atomically merge a document; returns row/change counts, default fails on conflicts |

Addresses are `0x`-hex or decimal strings. `kind` filters accept
`code`, `data`, `string`, and `inferred-code` (case-insensitive);
stored rows keep the historical `Code`/`Data`/`String` spelling while
inferred rows serialize as kebab-case `inferred-code`. Calls are
serialized behind one lock because `redb` allows a single open handle
per file per process.

## Raw mapping and inferred edges

Every binary-taking tool accepts an optional `raw` object
(`arch`/`base`/`entry?`) with the same rules as the CLI flags:
`arch` and `base` are required in raw mode, and raw-only options
without `raw` are errors. `func` returns the compact metadata shape;
`cfg` separates direct `edges` from provenance-marked
`inferred_edges`. Inferred edges come only from the single-slot
absolute indirect-jump resolver: raw mappings only, same-function
targets only. Anything the resolver cannot prove keeps its
`unresolved-indirect-jump` diagnostic and stays edgeless. See
[JSON protocol](json-protocol.md) for the full request/response
definitions.
