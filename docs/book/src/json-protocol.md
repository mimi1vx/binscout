# JSON protocol

Every command prints exactly one JSON value to stdout and exits 0.
A runtime failure prints a single `{"error": "..."}` value and exits 1,
so stdout is always valid JSON. (Clap usage errors for unknown
flags/subcommands still go to stderr with exit 2.)

Real example — opening the repo's `tests/fixtures/raw-x64.bin`:

```sh
$ binscout load tests/fixtures/raw-x64.bin
{"annotations":0,"arch":"x86_64","binary":"tests/fixtures/raw-x64.bin","blocks":1,"content_hash":13197063251454239466,"db_path":"tests/fixtures/raw-x64.rsdbg.redb","entry":null,"entry_hex":null,"format":"raw","functions":1,"insns":3,"reason":null,"size":3,"strings":0,"supported":true,"version":"0.3.0","xrefs":0}
```

## Stability guarantees

These hold before and after the protocol-1 changes below:

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
`calls` is a count (not the unbounded target array), and `reasons`
is the sorted, deduplicated discovery vocabulary (`entry`, `export`,
`direct-call`, `prologue`). The redundant `containing_entry` twin is
dropped; any interior address still snaps to the canonical `entry`:

```json
{"id": "func@0x401000", "entry": 4198400, "entry_hex": "0x401000",
 "name": "main", "blocks": 1, "insns": 3, "calls": 0,
 "reasons": ["entry"]}
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

## New query contracts (design targets)

Names, parameters, and shapes below are frozen by this contract but
**not yet implemented**; each is built and tested by its roadmap step.
`B` is the binary path; every binary-taking operation also accepts the
common `--db PATH` / `db` sidecar override and the raw-mapping options.

### Raw mapping (target: explicit raw opens)

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

### `blocks` / `block_insns` (target: bounded function views)

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

### `diagnostics` (implemented: paged provenance)

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

### `ir-coverage` (implemented: machine-readable lift coverage)

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

### `search-bytes` (target: bounded byte-pattern search)

```sh
binscout search-bytes B PATTERN [--section S] [--range LO HI] [--offset N] [--limit N]
```

MCP tool `search_bytes` (`binary`, `db`?, `raw`?, `pattern`,
`section`?, `range_start`?, `range_end`?, `offset?`, `limit?`).
`PATTERN` is whitespace-separated full-byte tokens, each two hex
digits (case-insensitive) or a `??` wildcard (e.g. `48 8B ?? ??`).
Empty, all-wildcard, odd-length, non-hex, or over-4096-byte patterns
are `Invalid` errors. `--range` is half-open `[LO, HI)` over virtual
addresses (unlike the inclusive `--range` on `functions`);
`--section` is an exact section-name match. Matches report `addr` /
`addr_hex`, `file_off` (null when unavailable), `section` (null when
unmapped to a named section), and match `len`, ordered by virtual
address with overlapping matches included. Gaps between mappings are
never bridged, virtual BSS is never materialized, and scans past
256 MiB of unique file-backed mapped bytes fail with `Limit` instead
of truncating silently. Results page under the envelope (capped at
1024 rows); the exact `total` may require a full bounded scan.

### `annotations-export` / `annotations-import` (target: portable annotations)

```sh
binscout annotations-export B
binscout annotations-import B --input PATH [--overwrite]
```

MCP tools `annotations_export` (`binary`, `db`?, `raw`?) returning
the document, and `annotations_import` (`binary`, `db`?, `raw`?,
`document`, `overwrite`?) taking it. The export is read-only and
capped at 16 MiB serialized:

```json
{"format_revision": 1, "sha256": "…64 hex…", "binary_len": 3,
 "mapping": {"mode": "auto", "arch": "x86_64", "base": null, "base_hex": null, "entry": null, "entry_hex": null},
 "annotations": [{"addr": 4198400, "addr_hex": "0x401000", "rename": "main", "comment": null}]}
```

Rows sort by address and only nonempty annotations appear; host
paths and analysis snapshots are excluded. Import validates the
whole document before a single atomic write: identity
(`sha256` + `binary_len` + `mapping`) must match exactly, duplicate
addresses and oversized documents are rejected, `rename` targets must
be known function entries while comments keep the any-address
contract. Default merge fails on differing existing field values
(equal values are idempotent); `--overwrite` replaces supplied fields
only, absent fields leave existing values alone, and empty strings
clear. Untouched annotations remain; a failure in the last row leaves
the DB unchanged. Import returns merge counts
(`imported`, `overwritten`, current `annotations` total).

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
