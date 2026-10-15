# JSON protocol

Every command prints exactly one JSON value to stdout and exits 0.
A runtime failure prints a single `{"error": "..."}` value and exits 1,
so stdout is always valid JSON. (Clap usage errors for unknown
flags/subcommands still go to stderr with exit 2.)

Real example — opening the repo's `tests/fixtures/raw-x64.bin`:

```sh
$ binscout load tests/fixtures/raw-x64.bin
{"analysis_revision":3,"annotations":0,"arch":"x86_64","base":null,"base_hex":null,"binary":"tests/fixtures/raw-x64.bin","blocks":1,"content_hash":13197063251454239466,"db_path":"tests/fixtures/raw-x64.rsdbg.redb","diagnostics":0,"diagnostics_omitted":0,"diagnostics_truncated":false,"entry":null,"entry_hex":null,"format":"raw","functions":1,"inferred_omitted":0,"inferred_truncated":false,"insns":3,"mode":"auto","protocol":1,"reason":null,"size":3,"strings":0,"supported":true,"version":"0.3.0","xrefs":0}
```

`mode` is `"auto"` or `"raw"`; `base`/`base_hex` are null in auto
mode. `protocol` is the wire revision below; `analysis_revision` is
the engine revision that produced the snapshot. `diagnostics` counts
retained provenance records (`diagnostics_truncated` plus
`diagnostics_omitted` when the 100,000-record cap drops rows);
`inferred_truncated`/`inferred_omitted` do the same for the
single-slot resolver's edge budget.

## Stability guarantees

These stability guarantees hold across wire revisions:

- One JSON value on CLI stdout per command. Runtime failure:
  `{"error": "..."}` on stdout, exit 1. Clap usage errors
  (unknown flags/subcommands, unparsable numbers): stderr, exit 2.
- The analyzed binary is never written. The only write target is the
  `redb` sidecar (default `<binary>.rsdbg.redb`, overridable with global
  `--db PATH` on the CLI or the `db` parameter on MCP tools). `load`
  opens and saves a snapshot; every other read command opens without
  saving and never creates a sidecar; `rename`/`comment` persist
  immediately. Failed validations never write.
- MCP tools return one JSON document as text per call; failures are
  tool errors, never silent empty results. Calls serialize behind one
  lock because `redb` allows a single open handle per file per process.

## Addresses

Address inputs accept `0x`-prefixed hex (`0x401000`, case-insensitive
prefix) or plain decimal (`4198400`); surrounding whitespace is trimmed.
Anything else is an `Invalid` error.

Address outputs pair every integer field with its canonical `0x`-hex
twin: `addr`/`addr_hex`, `entry`/`entry_hex`, `from`/`from_hex`,
`vaddr`/`vaddr_hex`, and so on. The hex form is lowercase with no
leading zeros (`0x401000`, `0x0` for zero). The integer keeps numeric
range queries working; the string keeps joins unambiguous. Optional
addresses stay null on both sides instead of inventing an address.

## Three versions

- Crate `version` (e.g. `"0.3.0"`): the shipped software, also served
  via CLI `--version` and `project_info`.
- Wire `protocol` (integer, currently `1`): the JSON shape contract
  defined on this page. It appears in `project_info`, `stats`, and
  every page envelope. Additive fields do not bump it; any shape
  change or removal does.
- Sidecar schema: an internal storage detail recorded in the sidecar
  `meta` table only. It never appears on the wire and evolves
  independently of both versions above.

## Page envelope

New and revised paged queries share one envelope:

```json
{"protocol": 1, "total": 0, "offset": 0, "limit": 50, "next_offset": null, "items": []}
```

| Field | Type | Meaning |
|---|---|---|
| `protocol` | integer | Wire revision (see above). |
| `total` | integer | Exact count of filter-matched rows **before** paging. |
| `offset` | integer | Requested offset, echoed back. |
| `limit` | integer | **Effective** limit: the requested limit clipped to the 1024-row cap. |
| `next_offset` | integer or null | Offset for the next page, or null when there is none. |
| `items` | array | This page's rows, in deterministic address order. |

Rules:

- Filtering happens before paging, so `offset`/`limit` apply to dense
  matching rows and `total` is the filtered count.
- Rows order by primary address ascending: functions by entry, blocks
  by start, instructions by address, byte-search matches by virtual
  address, diagnostics by (`kind`, `addr`).
- `next_offset` is null when the page is exhausted
  (`offset + limit >= total`) or when the effective limit is zero;
  otherwise it is `offset + limit` using the **effective** limit.
- A clipped request reports the clipped `limit`, so `next_offset`
  arithmetic stays consistent (`--limit 5000` returns `"limit": 1024`).
- An offset past the end is not an error: it returns the echoed
  `offset`, `items: []`, and `next_offset: null` with the exact `total`.
- A zero limit returns the exact `total`, `items: []`, and
  `next_offset: null`. Pattern/filter validation still applies, so a
  zero-limit request with an invalid filter errors rather than
  returning an empty page.

Empty page — a query with no matches (`diagnostics` on a clean
analysis):

```json
{"protocol": 1, "total": 0, "offset": 0, "limit": 50, "next_offset": null, "items": []}
```

Zero limit — the count is exact but no rows come back (`blocks` on a
3-block function with `--limit 0`):

```json
{"protocol": 1, "total": 3, "offset": 0, "limit": 0, "next_offset": null, "items": []}
```

Clipped limit — `--limit 5000` on 2500 byte-search matches caps at
1024 rows (first row shown, remainder omitted here):

```json
{"protocol": 1, "total": 2500, "offset": 0, "limit": 1024, "next_offset": 1024, "items": [
  {"addr": 4198400, "addr_hex": "0x401000", "file_off": 4096, "section": ".text", "len": 3}
]}
```

Final page — the last row of 3 (`--offset 2 --limit 50`;
`2 + 50 >= 3`, so `next_offset` is null):

```json
{"protocol": 1, "total": 3, "offset": 2, "limit": 50, "next_offset": null, "items": [
  {"id": "block@0x401000+0x401020", "start": 4198432, "start_hex": "0x401020", "end": 4198440, "end_hex": "0x401028", "insns": 4, "succs": [4198440]}
]}
```

## Breaking-change boundary (protocol 1)

Intentional breaking changes, each with migration notes:

- `func` returns compact metadata instead of the full
  block-with-instructions dump (before/after below). Use `blocks` plus
  `block_insns` for bounded inspection; `cfg` remains the explicit
  full-graph export and can still be large.
- New paged queries (`blocks`, `block_insns`, `diagnostics`,
  `search-bytes`) use the envelope above.
- `project_info` and `stats` gain additive fields only (`protocol`,
  mapping identity, diagnostic totals); no existing field changes.

Before — `func` today embeds every instruction of every block:

```json
{"id": "func@0x401000", "entry": 4198400, "entry_hex": "0x401000",
 "containing_entry": 4198400, "containing_entry_hex": "0x401000",
 "name": "main",
 "blocks": [{"id": "block@0x401000+0x401000", "start": 4198400, "start_hex": "0x401000",
              "end": 4198403, "end_hex": "0x401003",
              "insns": [/* every decoded instruction */], "succs": []}],
 "edges": [], "calls": [4198400]}
```

After — `func` is a bounded summary. `blocks`/`insns` are counts,
`calls` is a count (not the unbounded target array),
`inferred_edges` counts provenance-marked single-slot resolutions in
that function, and `reasons` is the sorted, deduplicated discovery
vocabulary (`entry`, `export`, `direct-call`, `prologue`). The
redundant `containing_entry` twin is dropped; any interior address
still snaps to the canonical `entry`:

```json
{"id": "func@0x401000", "entry": 4198400, "entry_hex": "0x401000",
 "name": "main", "blocks": 1, "insns": 3, "calls": 0,
 "inferred_edges": 0, "reasons": ["entry"]}
```

Explicitly unchanged in this contract (no style churn): the bare-array
`functions` list with `--offset`/`--limit`; the `{"total", "xrefs"}`
`xrefs` envelope; the bare-array `strings` list with
`--start`/`--limit` (`--offset` stays a deprecated alias that warns);
`symbols`, `sections`, `disasm`/`ir` with `error_at` and the 1 MiB
range cap; `cfg` node/edge shape; `annotate` read/write semantics
(`rename` only on known function entries, `comment` on any address,
empty string clears, 8 KiB text cap); all exit codes and error
channels. A future alignment of the grandfathered list shapes would
bump `protocol`.

## Query contracts

`B` is the binary path; every binary-taking operation also accepts the
common `--db PATH` / `db` sidecar override and the raw-mapping options.

### Raw mapping

Opt-in firmware/raw workflow. CLI global flags (like `--db`):

```sh
binscout [--db PATH] [--raw --arch ARCH --base ADDR [--entry ADDR]] <command> B [...]
```

MCP: optional `raw: {"arch": ..., "base": ..., "entry"?}` object on
every binary-taking tool. `arch` is one of `x86_64`, `x86_32`,
`aarch64`, `arm32`, `thumb`; `base`/`entry` parse as addresses.
`arch` and `base` are required in raw mode; raw-only options without
`--raw`/`raw` are errors, as are unknown arches, unmapped or
misaligned entries, and base-plus-length overflow. Without raw mode,
auto-detection and the raw x86-64-at-0 fallback are unchanged.
Explicit raw mode never falls back to another mode on failure.
`project_info` reports the effective mapping: `mode` (`"auto"` or
`"raw"`) plus `base`/`base_hex` (null in auto mode); `arch`,
`format`, and `entry`/`entry_hex` keep their current fields.

```sh
$ binscout --raw --arch x86_64 --base 0x400000 load tests/fixtures/raw-x64.bin --db /tmp/raw.redb
{"analysis_revision":3,"annotations":0,"arch":"x86_64","base":4194304,"base_hex":"0x400000","binary":"tests/fixtures/raw-x64.bin","blocks":1,"content_hash":13197063251454239466,"db_path":"/tmp/raw.redb","diagnostics":0,"diagnostics_omitted":0,"diagnostics_truncated":false,"entry":null,"entry_hex":null,"format":"raw","functions":1,"inferred_omitted":0,"inferred_truncated":false,"insns":3,"mode":"raw","protocol":1,"reason":null,"size":3,"strings":0,"supported":true,"version":"0.3.0","xrefs":0}
```

Same bytes under a different mapping never reuse cached layouts: the
open re-analyzes. A sidecar holding annotations opened under an
incompatible mapping fails with a separate-DB error instead of
remapping them (see [CLI reference](cli-reference.md)).

### `blocks` / `block_insns`

```sh
binscout blocks B ADDR [--offset N] [--limit N]
binscout block-insns B ADDR BLOCK [--offset N] [--limit N]
```

MCP tools `blocks` (`binary`, `db`?, `raw`?, `addr`, `offset?`,
`limit?`) and `block_insns` (plus `block`: the block start address).
`ADDR` snaps to its containing function (`NotFound` when in no
function); `BLOCK` must be a block start belonging to that function
(`NotFound` otherwise). `blocks` pages `BlockSummary` rows
(`id`, `start`/`start_hex`, `end`/`end_hex`, `insns` count, `succs`)
by start; `block_insns` pages that block's instructions in address
order. Both use the page envelope; per-page work scales with the
page, never with whole-function size.

### `callees` / `callers`

```sh
binscout callees B ADDR [--depth N] [--offset N] [--limit N]
binscout callers B ADDR [--depth N] [--limit N]
```

MCP tools `callees`/`callers` (`binary`, `db`?, `raw`?, `addr`,
`depth?`, `offset?`, `limit?`). `ADDR` snaps to its containing
function (`NotFound` when in no function); `depth` bounds the walk to
that many call edges (direct neighbors are depth 1, zero yields an
empty page, past the 64-hop cap is an `Invalid` error). Items order by
entry with the shortest distance in `depth` plus the rename-resolved
`name` and the `entry`/`entry_hex` twins, paged under the envelope;
querying never writes a sidecar.

### `slice`

```sh
binscout slice B TO [--depth N] [--offset N] [--limit N]
```

MCP tool `slice` (`binary`, `db`?, `raw`?, `to`, `depth?`,
`offset?`, `limit?`). `TO` is any address (data/string targets lie in
no function, which is a valid root, not an error); `depth` bounds the
reverse walk over xref edges of every kind plus intra-function CFG
predecessors to that many hops (direct predecessors are depth 1, zero
yields an empty page, past the 64-hop cap is an `Invalid` error).
Items order by address with the shortest distance in `depth`, each
carrying `addr`/`addr_hex`, the containing function (`func`/`func_hex`,
null when in no function) plus its rename-resolved `name`, paged under
the envelope; querying never writes a sidecar.

### `diagnostics`

```sh
binscout diagnostics B [--kind KIND] [--func ADDR] [--offset N] [--limit N]
```

MCP tool `diagnostics` (`binary`, `db`?, `raw`?, `kind?`, `func?`,
`offset?`, `limit?`). `kind` is one of `unresolved-indirect-jump`,
`unresolved-indirect-call`, `decode-failure`; anything else is an
`Invalid` error. `func` snaps to its containing function and keeps
only that function's sites (`NotFound` when in no function). Items
order by (`kind`, `addr`); each row carries `kind`, `addr`/`addr_hex`,
and the containing function entry (or null) plus kind-specific
detail. Filtering precedes pagination under the page envelope, and
querying never writes a sidecar. Compact `func` rows carry the
`reasons` set; `project_info`/`stats` gain `diagnostics` (retained
record count), `diagnostics_truncated` (bool),
`diagnostics_omitted` (rows dropped at the record cap), and
`analysis_revision`. Zero retained diagnostics is not proof of
complete recovery.

### `ir-coverage`

```sh
binscout ir-coverage ARCH [B ADDR LEN]
```

MCP tool `ir_coverage` (`arch`, `binary`?, `db`?, `addr`?, `len`?):
no binary is opened unless a range is given, and a range requires all
of `binary`/`addr`/`len`. The response names the `arch`, the
implemented opcode families, the explicitly partial mappings, and the
limitations (operand strings, flags, stack/calling-convention
effects, no SSA/PHI production); unknown mnemonics stay a `NOP` with
a warning, distinguishable from a genuine `NOP`. With a range, it
adds per-range `decoded`/`lifted`/`unlifted` counts from actual lift
results plus a bounded mnemonic summary. (`ARCH` is positional on the
CLI because `--arch` is the global raw-mapping flag.)

### `search-bytes`

```sh
binscout search-bytes B PATTERN [--section S] [--range LO HI] [--offset N] [--limit N]
```

MCP tool `search_bytes` (`binary`, `db`?, `raw`?, `pattern`,
`section`?, `range_start`?, `range_end`?, `offset?`, `limit?`).
`PATTERN` is a positional whitespace-separated full-byte token
string, each two hex digits (case-insensitive) or a `??` wildcard
(e.g. `48 8B ?? ??`). Empty, all-wildcard, odd-length, non-hex, or
over-4096-byte patterns are `Invalid` errors. `--range` is half-open
`[LO, HI)` over virtual addresses (unlike the inclusive `--range` on
`functions`); `--section` is an exact section-name match. Matches
report `addr` / `addr_hex`, `file_off` (null when unavailable),
`section` (null when unmapped to a named section), and match `len`,
ordered by virtual address with overlapping matches included. Gaps
between mappings are never bridged, virtual BSS is never
materialized, and scans past 256 MiB of unique file-backed mapped
bytes fail with `Limit` instead of truncating silently. Results page
under the envelope (capped at 1024 rows); the exact `total` may
require a full bounded scan.

```sh
$ binscout search-bytes fw.bin 90 --range 0x0 0x2
{"items":[{"addr":0,"addr_hex":"0x0","file_off":0,"len":1,"section":null},{"addr":1,"addr_hex":"0x1","file_off":1,"len":1,"section":null}],"limit":50,"next_offset":null,"offset":0,"protocol":1,"total":2}
```

### `annotations-export` / `annotations-import`

```sh
binscout annotations-export B
binscout annotations-import B --input PATH [--overwrite]
```

MCP tools `annotations_export` (`binary`, `db`?, `raw`?) returning
the document, and `annotations_import` (`binary`, `db`?, `raw`?,
`document`, `overwrite`?) taking it. The export is read-only and
capped at 16 MiB serialized:

```json
{"revision": 1, "sha256": "…64 hex…", "size": 3,
 "mapping": {"mode": "auto"},
 "annotations": [{"addr": 4198400, "rename": "main"}]}
```

Rows sort by address and only nonempty annotations appear; unset
fields are omitted (no nulls). Host paths and analysis snapshots are
excluded. Under explicit raw mapping the document records
`"mapping": {"mode": "explicit", "arch": "x86_64", "base": 4194304,
"entry": null}`. Import validates the whole document before a single
atomic write: identity (`sha256` + `size` + `mapping`) must match
exactly, duplicate addresses and oversized documents are rejected,
`rename` targets must be known function entries while comments keep
the any-address contract. Default merge fails on differing existing
field values (equal values are idempotent); `--overwrite` replaces
supplied fields only, absent fields leave existing values alone, and
empty strings clear. Untouched annotations remain; a failure in the
last row leaves the DB unchanged. Import returns merge counts:

```json
{"rows": 1, "changed": 0}
```

### Inferred edges (single-slot resolver)

One conservative indirect-jump pattern resolves to a real edge:
a single-slot absolute indirect jump (x86-32 `jmp m32` through an
absolute slot, x86-64 `jmp m64` through a RIP-relative slot) in an
explicit raw mapping, with the slot value landing on executable
mapped bytes in the same function. Everything else — indexed
multi-entry tables, cross-function targets, truncated or unmapped
slots, non-executable targets, container (non-raw) binaries — keeps
its `unresolved-indirect-jump` diagnostic and stays edgeless, e.g.:

```json
{"addr": 4194304, "addr_hex": "0x400000", "detail": "indirect jump without a direct target; the site stays edgeless", "func": 4194304, "func_hex": "0x400000", "kind": "unresolved-indirect-jump"}
```

Resolved edges carry their provenance separately from direct flow:
`cfg` lists them in `inferred_edges` (never in `edges`), compact
`func` counts them in `inferred_edges`, and `xrefs` tags them
`inferred-code` alongside the `Data` xref into the slot:

```json
{"containing_entry": 4194304, "containing_entry_hex": "0x400000", "edges": [], "entry": 4194304, "entry_hex": "0x400000", "inferred_edges": [[4194304, 4194322]], "nodes": [{"end": 4194310, "end_hex": "0x400006", "insns": 1, "start": 4194304, "start_hex": "0x400000", "succs": []}, {"end": 4194325, "end_hex": "0x400015", "insns": 3, "start": 4194322, "start_hex": "0x400012", "succs": []}]}
{"total": 2, "xrefs": [
  {"from": 4194304, "from_hex": "0x400000", "kind": "Data", "to": 4194314, "to_hex": "0x40000a"},
  {"from": 4194304, "from_hex": "0x400000", "kind": "inferred-code", "to": 4194322, "to_hex": "0x400012"}]}
```

Caps: one edge per site, 100,000 recovered edges per project. When
the project budget exhausts, the site stays unresolved with its
diagnostic retained and the excess counted in `inferred_omitted`
with `inferred_truncated` set — never silently clipped from the
inferred graph.

## Errors and validation

Library variants and their surfaces:

| `Error` | CLI | MCP |
|---|---|---|
| `NotFound` (`not found: …`) | `{"error": …}`, exit 1 | tool error |
| `Unsupported` (`unsupported: …`) | `{"error": …}`, exit 1 | tool error |
| `Invalid` (`invalid opcode: …`) | `{"error": …}`, exit 1 | `invalid_params` |
| `Limit` (`limit exceeded: …`) | `{"error": …}`, exit 1 | tool error |
| `Storage` (`storage: …`) | `{"error": …}`, exit 1 | tool error |

Validation rules: bad addresses, unknown xref/diagnostic kinds,
overlong or uncompilable string patterns, malformed byte-search
patterns, unmapped or over-cap (`> 1 MiB`) decode ranges, unknown
functions/blocks, rename of a non-entry, over-8 KiB annotation text,
raw-option misuse, and annotation identity/conflict failures all
error as above without writing. Clipping a limit to 1024 rows,
paging past the end, and zero limits are normal pages, not errors.
Non-numeric `--offset`/`--limit` values never reach validation:
`clap` rejects them on stderr with exit 2.
