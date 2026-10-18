# MCP tools

`binscout-mcp` serves 35 tools over stdio (newline-delimited JSON-RPC).
Each takes `binary` plus an optional `db` path (`diff` takes
`binary_a`/`binary_b` plus optional `db_a`/`db_b`; `batch` takes one
envelope plus a list of read-only ops) and returns one JSON
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
| `functions` | binary, query/caller/callee/range_lo/range_hi, offset/limit, envelope? | List functions with rename-resolved names, filtered (`query` case-insensitive substring; `caller`/`callee` addresses resolving to call-graph neighbors; `range_lo` + `range_hi` bounding entries, inclusive) and paged (`range_start`/`range_end` are deprecated aliases of the range bounds, warning on stderr; `envelope:true` returns the protocol-1 page envelope with an exact `total` and compact `calls_count` rows instead of the bare array with the full `calls` target array) |
| `func` | binary, addr | Compact metadata of one function: entry, name, block/insn/call counts, discovery `reasons` |
| `blocks` | binary, addr, offset?/limit? | Block summaries of the containing function by block start, under the page envelope |
| `block_insns` | binary, addr, block, offset?/limit? | That block's instructions in address order, under the page envelope; `block` must belong to the function |
| `disasm` | binary, addr, len | Disassemble `len` bytes at `addr` with the binary architecture; the valid prefix plus `error_at` for the first bad opcode (ranges cap at 1 MiB) |
| `bytes` | binary, addr, len, as?/endian? | Raw bytes at `addr` (`len` caps at 1 MiB, BSS tails read as zeros) with VA/file provenance (`file_off` null for zero-fill, `section` null when section-less) plus `bytes_hex` and typed `values` (`u8`/`u16`/`u32`/`u64`/`ptr`/`cstr`/`utf16`, `le`/`be` byte order) |
| `cfg` | binary, addr | Control-flow graph of one function: block nodes plus block edges; `inferred_edges` holds provenance-marked indirect-jump resolutions (single-slot absolutes and guarded scaled-index tables; raw-only, same-function); `query_addr` echoes the address passed in `addr` |
| `structure` | binary, addr | Approximate control-flow structure of one function: syntactic loops (back-edge headers with latches) and ifs (two-successor branch sites with then/else targets) plus an approximation warning; `addr` snaps to its containing function, `query_addr` echoes it |
| `pseudo` | binary, addr | Approximate pseudo-C of one function: one lossy C-like line per IR row plus assembled text, with an approximation warning; `addr` snaps to its containing function, `query_addr` echoes it |
| `callees` | binary, addr, depth?/offset?/limit? | Transitive callees out to `depth` hops (direct are depth 1), ordered by entry with shortest distance, under the page envelope; `addr` snaps to its containing function |
| `callers` | binary, addr, depth?/offset?/limit? | Transitive callers out to `depth` hops, ordered by entry with shortest distance, under the page envelope; `addr` snaps to its containing function |
| `slice` | binary, addr, depth?/offset?/limit? | Backward slice of `addr`: every instruction that can reach it via xref edges (any kind) and intra-function CFG predecessors out to `depth` hops (direct are depth 1), ordered by address with shortest distance, under the page envelope; any address is a valid root |
| `diagnostics` | binary, kind?, func?, offset/limit | Provenance records (unresolved indirect sites, decode failures) ordered by (`kind`, `addr`) under the page envelope, filtered by `kind` and containing-function `func`; queries never write a sidecar |
| `xrefs` | binary, to/from/kind, offset/limit | Cross-references filtered by endpoint and kind (`code`, `data`, `string`, `import`, `inferred-code`), paged behind a `total` match count |
| `strings` | binary, pattern/min_len/section/include_code/decode, start/limit | Extracted strings ordered by address, filtered and paged; executable-memory hits hidden unless `pattern`, `section`, or `include_code` is given (`offset` is a deprecated alias of `start`, warning on stderr; `envelope:true` returns the protocol-1 page envelope with an exact `total` instead of the bare array); `decode` (`xor:<byte>`, `xor:0x<HEXKEY>` rolling multi-byte key, `add:<byte>`, `rot:<0-7>`, or bare `base64`) re-extracts over a read-only in-memory transform with original offsets |
| `stack_strings` | binary | Recovered stack-constructed strings: runs of `mov [rsp/rbp+off], imm` within one block, reassembled with function and address; read-only, never writes the binary or the sidecar |
| `symbols` | binary | Imports, exports, and symbol-table code addresses of the binary (`symbols`: one `name`/`address`/`address_hex` row per defined text symbol, locals included, deduplicated by address); Mach-O imports carry the `address`/`address_hex` of their `__stubs`/`__auth_stubs` entry (null when unmapped), and each mapped stub seeds its own import-named function; symbol addresses seed `symbol`-reasoned functions named below exports and above stubs |
| `sections` | binary | Section table: name, virtual address (`IMAGE_BASE + RVA` on PE), in-memory/file sizes, permissions |
| `ir` | binary, addr, len | Lift `len` bytes at `addr` to P-code-inspired IR (`error_at` on trailing bad bytes, ranges cap at 1 MiB) |
| `ir_coverage` | arch, binary?/addr?/len? | Machine-readable lift coverage for one arch (implemented families, partial mappings, limitations); no binary is opened without the range, which adds decoded/lifted/unlifted counts from actual lifts plus a bounded mnemonic summary |
| `flirt_hints` | binary, addr?, sigs?, offset?/limit? | FLIRT-like library hints: corpus signature matches over each function's leading bytes, paged under the protocol-1 envelope; `addr` keeps only the containing function's hints; `sigs` adds a user signature file path (our JSON, as emitted by `sig_gen`, or an IDA `.pat` file by extension); suggested names stay hints, querying never writes a sidecar |
| `sig_gen` | binary | Emit a JSON signature document for the binary's named functions (masked leading bytes with `len`/`crc`): the `sigs` input that `flirt_hints` reads back; read-only, never writes the binary or the sidecar |
| `go_funcs` | binary | Recover Go functions from the `pclntab` table (linker names plus exact entry/end ranges) for stripped Go binaries; empty array when no table is located; read-only, never writes the binary or the sidecar |
| `stats` | binary | Storage stats: binary size, sidecar DB size, and analysis counts |
| `headers` | binary | Header metadata: triage staples (PE mitigations/imphash/PDB, ELF interp/needed/RELRO/NX/PIE, Mach-O load commands/codesign) plus `sha256`/`md5`; computed on demand, never persisted |
| `rename` | binary, addr, name | Rename a function in the project DB (binary untouched); empty name clears |
| `annotation` | binary, addr | Read the annotation at one address (rename/comment with addr twins; nulls when unset); read-only, never creates or modifies the sidecar; CLI `annotate` without flags parity |
| `comment` | binary, addr, comment | Comment any address in the project DB (binary untouched); empty comment clears; structured struct-layout hints (`type-hint:{...}`, see [JSON protocol](json-protocol.md)) pass through opaquely |
| `define_func` | binary, addr, mode? | Assert "there is code here": store a user function seed and re-analyze so it materializes; `mode` (`arm`/`thumb`) selects the 32-bit ARM decode, other arches reject it |
| `undefine_func` | binary, addr | Assert "this isn't a function": exclude the seed (kept as data) and re-analyze |
| `search_bytes` | binary, pattern, section?/range_start?/range_end?, offset?/limit? | Paged `??`-wildcard byte-pattern matches ordered by virtual address (`range_start` + `range_end` bound the half-open `[lo, hi)` range; `range_lo`/`range_hi` are deprecated aliases, warning on stderr); scans cap at 256 MiB of mapped bytes with an explicit `Limit` error |
| `annotations_export` | binary | Emit the portable annotation interchange document; read-only, never creates a sidecar |
| `annotations_import` | binary, document, overwrite? | Atomically merge a document; returns row/change counts, default fails on conflicts |
| `diff` | binary_a, binary_b, db_a?/db_b?, raw?/fat_arch? | Function-level diff between two binaries (`matched`/`added`/`removed`/`changed` with match reason); both projects open read-only, never creating or modifying a sidecar; the shared `raw`/`fat_arch` selection (if any) applies to both |
| `batch` | binary, db?/raw?/fat_arch?, ops (1–32) | Up to 32 read-only ops over one open project, run in order; returns `{"results": [{"ok"} \| {"error"}]}` with per-op limits unchanged and total output capped at 1 MiB (see below) |

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

## Batch

One MCP round trip for the `func` → `cfg` → `pseudo` → `xrefs`
per-function loop: the envelope opens the binary once and every op runs
in order under that entry lock, so results come back positionally in
`results`:

```json
{"binary": "fw.elf", "ops": [
  {"tool": "func", "params": {"addr": "0x401000"}},
  {"tool": "xrefs", "params": {"to": "0x402000"}},
  {"tool": "func", "params": {"addr": "0xdead"}}
]}
```

```json
{"results": [
  {"ok": {"entry": 4198400, "entry_hex": "0x401000", "blocks": 1, "insns": 3, "calls": 0}},
  {"ok": {"total": 0, "xrefs": []}},
  {"error": "not found: no function contains 0xdead"}
]}
```

Rules:

- Ops carry only tool-specific parameters: the envelope owns the binary
  identity, so `binary`/`db`/`raw`/`fat_arch` (and `diff`'s `binary_a`
  and friends) are rejected inside `params`. (`ir_coverage` takes
  `arch` plus optional `addr`/`len`; the binary always comes from the
  envelope.)
- Read-only tools only: `load`, `rename`, `comment`, `define_func`,
  `undefine_func`, and `annotations_import` are rejected per op (writes
  stay explicit top-level calls), as are the two-binary `diff`,
  nested `batch`, and unknown names. Per-op failures are `{"error"}`
  elements with the same message text the single tool would report;
  only envelope misuse (empty or over-32 op lists, open failures) is a
  tool error.
- Per-op row and range limits apply unchanged; the sum of the
  compact-serialized results caps at 1 MiB. The op that would overflow
  returns a limit error and every later op returns a skipped error, so
  a 32-wide `cfg` fan-out degrades from the tail instead of failing
  the call.

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
