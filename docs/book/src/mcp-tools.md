# MCP tools

`binscout-mcp` serves 28 tools over stdio (newline-delimited JSON-RPC).
Each takes `binary` plus an optional `db` path (`diff` takes
`binary_a`/`binary_b` plus optional `db_a`/`db_b`) and returns one JSON
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
| `project_info` | binary | Open a binary and report arch, format, entry, mapping (`mode`, `base`), diagnostic totals, and `analysis_revision`; read-only, never saves the snapshot — call `load` once to persist the sidecar so later opens replay it instead of re-analyzing |
| `load` | binary | Persist the analysis snapshot to the project DB (binary untouched); CLI `load` parity, warms the sidecar so later opens replay it instead of re-analyzing |
| `functions` | binary, query/caller/callee/range_lo/range_hi, offset/limit | List functions with rename-resolved names, filtered (`query` case-insensitive substring; `caller`/`callee` addresses resolving to call-graph neighbors; `range_lo` + `range_hi` bounding entries) and paged |
| `func` | binary, addr | Compact metadata of one function: entry, name, block/insn/call counts, discovery `reasons` |
| `blocks` | binary, addr, offset?/limit? | Block summaries of the containing function by block start, under the page envelope |
| `block_insns` | binary, addr, block, offset?/limit? | That block's instructions in address order, under the page envelope; `block` must belong to the function |
| `disasm` | binary, addr, len | Disassemble `len` bytes at `addr` with the binary architecture; the valid prefix plus `error_at` for the first bad opcode (ranges cap at 1 MiB) |
| `cfg` | binary, addr | Control-flow graph of one function: block nodes plus block edges; `inferred_edges` holds provenance-marked indirect-jump resolutions (single-slot absolutes and guarded scaled-index tables; raw-only, same-function) |
| `structure` | binary, addr | Approximate control-flow structure of one function: syntactic loops (back-edge headers with latches) and ifs (two-successor branch sites with then/else targets) plus an approximation warning; `addr` snaps to its containing function |
| `pseudo` | binary, addr | Approximate pseudo-C of one function: one lossy C-like line per IR row plus assembled text, with an approximation warning; `addr` snaps to its containing function |
| `callees` | binary, addr, depth?/offset?/limit? | Transitive callees out to `depth` hops (direct are depth 1), ordered by entry with shortest distance, under the page envelope; `addr` snaps to its containing function |
| `callers` | binary, addr, depth?/offset?/limit? | Transitive callers out to `depth` hops, ordered by entry with shortest distance, under the page envelope; `addr` snaps to its containing function |
| `slice` | binary, addr, depth?/offset?/limit? | Backward slice of `addr`: every instruction that can reach it via xref edges (any kind) and intra-function CFG predecessors out to `depth` hops (direct are depth 1), ordered by address with shortest distance, under the page envelope; any address is a valid root |
| `diagnostics` | binary, kind?, func?, offset/limit | Provenance records (unresolved indirect sites, decode failures) ordered by (`kind`, `addr`) under the page envelope, filtered by `kind` and containing-function `func`; queries never write a sidecar |
| `xrefs` | binary, to/from/kind, offset/limit | Cross-references filtered by endpoint and kind (`code`, `data`, `string`, `import`, `inferred-code`), paged behind a `total` match count |
| `strings` | binary, pattern/min_len/section/include_code/decode, start/limit | Extracted strings ordered by address, filtered and paged; executable-memory hits hidden unless `pattern`, `section`, or `include_code` is given (`offset` is a deprecated alias of `start`); `decode` (`xor:<byte>`, `add:<byte>`, `rot:<0-7>`) re-extracts over a read-only in-memory transform with original offsets |
| `symbols` | binary | Imports, exports, and symbol-table code addresses of the binary (`symbols`: one `name`/`address`/`address_hex` row per defined text symbol, locals included, deduplicated by address); Mach-O imports carry the `address`/`address_hex` of their `__stubs`/`__auth_stubs` entry (null when unmapped), and each mapped stub seeds its own import-named function; symbol addresses seed `symbol`-reasoned functions named below exports and above stubs |
| `sections` | binary | Section table: name, virtual address (`IMAGE_BASE + RVA` on PE), in-memory/file sizes, permissions |
| `ir` | binary, addr, len | Lift `len` bytes at `addr` to P-code-inspired IR (`error_at` on trailing bad bytes, ranges cap at 1 MiB) |
| `ir_coverage` | arch, binary?/addr?/len? | Machine-readable lift coverage for one arch (implemented families, partial mappings, limitations); no binary is opened without the range, which adds decoded/lifted/unlifted counts from actual lifts plus a bounded mnemonic summary |
| `flirt_hints` | binary, addr?, offset?/limit? | FLIRT-like library hints: corpus signature matches over each function's leading bytes, paged under the protocol-1 envelope; `addr` keeps only the containing function's hints; suggested names stay hints, querying never writes a sidecar |
| `stats` | binary | Storage stats: binary size, sidecar DB size, and analysis counts |
| `rename` | binary, addr, name | Rename a function in the project DB (binary untouched); empty name clears |
| `comment` | binary, addr, comment | Comment any address in the project DB (binary untouched); empty comment clears; structured struct-layout hints (`type-hint:{...}`, see [JSON protocol](json-protocol.md)) pass through opaquely |
| `search_bytes` | binary, pattern, section?/range_start?/range_end?, offset?/limit? | Paged `??`-wildcard byte-pattern matches ordered by virtual address; scans cap at 256 MiB of mapped bytes with an explicit `Limit` error |
| `annotations_export` | binary | Emit the portable annotation interchange document; read-only, never creates a sidecar |
| `annotations_import` | binary, document, overwrite? | Atomically merge a document; returns row/change counts, default fails on conflicts |
| `diff` | binary_a, binary_b, db_a?/db_b?, raw?/fat_arch? | Function-level diff between two binaries (`matched`/`added`/`removed`/`changed` with match reason); both projects open read-only, never creating or modifying a sidecar; the shared `raw`/`fat_arch` selection (if any) applies to both |

Addresses are `0x`-hex or decimal strings. `kind` filters accept
`code`, `data`, `string`, `import`, and `inferred-code`
(case-insensitive);
stored rows keep the historical `Code`/`Data`/`String` spelling while
inferred rows serialize as kebab-case `inferred-code`. One server process
keeps a 4-entry LRU of open projects keyed by binary, sidecar, and
mapping and revalidated by file length plus mtime, so repeat calls skip
re-analysis; each entry has its own lock and each sidecar file its own
handle mutex, so calls on different binaries proceed concurrently while
calls sharing a binary or sidecar serialize (`redb` allows a single open
handle per file per process).

## Raw mapping and inferred edges

Every binary-taking tool accepts an optional `raw` object
(`arch`/`base`/`entry?`) with the same rules as the CLI flags:
`arch` and `base` are required in raw mode, and raw-only options
without `raw` are errors. Fat Mach-O containers take an optional
`fat_arch` string with the same arch names as the CLI flag; without
it a fat input errors listing the available archs, and with it a thin
input errors. `func` returns the compact metadata shape;
`cfg` separates direct `edges` from provenance-marked
`inferred_edges`. Inferred edges come from the indirect-jump
resolver: single-slot absolute jumps plus guarded scaled-index
tables (x86-only, 2–8 consecutive valid slots per table site),
raw mappings only, same-function targets only. Anything the
resolver cannot prove keeps its `unresolved-indirect-jump`
diagnostic and stays edgeless. See
[JSON protocol](json-protocol.md) for the full request/response
definitions.
