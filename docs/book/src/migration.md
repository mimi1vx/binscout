# Migration guidance

This release changes the default `func` response, adds bounded
inspection views, and ships explicit raw mapping, fat Mach-O slice
selection, Mach-O stub-to-import mapping, ARM64 `adrp`-pair resolution,
diagnostics,
IR coverage, byte search, a hexdump view with typed values (`bytes`),
annotation transfer, and a raw-only
indirect-jump resolver (single-slot absolutes plus guarded
scaled-index tables). Everything below runs as shown against
the current binaries.

## Tool count and versions

The MCP server exposes 37 tools: `project_info`, `load`, `functions`,
`func`, `blocks`, `block_insns`, `diagnostics`, `disasm`, `bytes`, `cfg`,
`structure`, `pseudo`, `callees`, `callers`, `slice`,
`xrefs`, `strings`, `symbols`, `stats`, `sections`, `ir`,
`ir_coverage`, `flirt_hints`, `rename`, `comment`, `annotation`,
`set_type_hint`, `get_type_hint`,
`define_func`, `undefine_func`, `search_bytes`,
`annotations_export`, `annotations_import`, `diff`, `stack_strings`, `batch`. The CLI has the same
capabilities as 30 subcommands (`load` covers `project_info`;
`annotate` covers `rename`/`comment`/`annotation`); the MCP `load` tool is the
sidecar-warming counterpart of the CLI `load`.

Three versions move independently:

- Crate `version` (e.g. `"0.3.0"`): the shipped software.
- Wire `protocol` (currently `1`): the JSON shape contract. It
  appears in `project_info`, `stats`, and every page envelope.
- Sidecar schema (currently 5) and analysis revision (currently 5):
  internal storage details. They never appear on the wire; a stored
  mismatch re-analyzes instead of replaying layouts.

## `func` before and after

`func` used to embed every instruction of every block plus the full
edge list and call-target array. It now returns compact metadata;
page the details with `blocks` and `block_insns`, or export the
full graph explicitly with `cfg` (which can still be large):

```sh
$ binscout --raw --arch x86_64 --base 0x400000 func blob.bin --db /tmp/blob.redb 0x400000
{"blocks":2,"calls":0,"entry":4194304,"entry_hex":"0x400000","id":"func@0x400000","inferred_edges":1,"insns":4,"name":null,"reasons":["entry"]}
$ binscout --raw --arch x86_64 --base 0x400000 blocks blob.bin --db /tmp/blob.redb 0x400000
{"items":[{"end":4194310,"end_hex":"0x400006","id":"block@0x400000+0x400000","insns":1,"start":4194304,"start_hex":"0x400000","succs":[]},{"end":4194325,"end_hex":"0x400015","id":"block@0x400000+0x400012","insns":3,"start":4194322,"start_hex":"0x400012","succs":[]}],"limit":50,"next_offset":null,"offset":0,"protocol":1,"total":2}
$ binscout --raw --arch x86_64 --base 0x400000 block-insns blob.bin --db /tmp/blob.redb 0x400000 0x400000
{"items":[{"addr":4194304,"addr_hex":"0x400000","branch_target":null,"branch_target_hex":null,"bytes":[255,37,4,0,0,0],"mem_target":4194314,"mem_target_hex":"0x40000a","mnem":"jmp","ops":["qword ptr [0x40000a]"],"size":6}],"limit":50,"next_offset":null,"offset":0,"protocol":1,"total":1}
```

`reasons` names how the function was discovered (`entry`,
`export`, `direct-call`, `prologue`); it is evidence, not a
confidence score. Any address inside the function snaps to its
containing entry. `blocks` and `block_insns` share the page
envelope (`protocol`, `total`, `offset`, `limit`, `next_offset`,
`items`) with `diagnostics` and `search-bytes`; limits clip to
1024 rows.

## Raw mapping and cache identity

Firmware and blob workflows pass the mapping explicitly on every
binary-taking command (CLI flags or the MCP `raw` object):

```sh
$ binscout --raw --arch x86_64 --base 0x400000 load tests/fixtures/raw-x64.bin --db /tmp/blob.redb
{"analysis_revision":7,"annotations":0,"arch":"x86_64","base":4194304,"base_hex":"0x400000","binary":"tests/fixtures/raw-x64.bin","blocks":1,"content_hash":13197063251454239466,"db_path":"/tmp/blob.redb","diagnostics":0,"diagnostics_omitted":0,"diagnostics_truncated":false,"entry":null,"entry_hex":null,"format":"raw","functions":1,"inferred_omitted":0,"inferred_truncated":false,"insns":3,"mode":"raw","protocol":1,"reason":null,"size":3,"strings":0,"supported":true,"version":"0.5.1","xrefs":0}
```

`arch` is one of `x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`;
`arch` and `base` are required in raw mode, and raw-only options
without `--raw`/`raw` are errors — as are unknown arches, unmapped
or misaligned entries, and base-plus-length overflow. Without raw
mode, container auto-detection is unchanged.

Cache identity covers binary content, loader mapping, and analysis
revision: the same bytes opened under a different mapping
re-analyze rather than reuse layouts. A sidecar holding
annotations opened under an incompatible mapping fails instead of
remapping them — keep one `--db PATH` per mapping:

```sh
$ binscout func blob.bin --db /tmp/blob.redb 0x0
{"error":"storage: mapping mismatch: project db holds 1 annotation(s) under explicit raw x86_64 base 0x400000, but current open requests auto; use a separate --db PATH for this mapping (annotations are never remapped)"}
```

Old sidecars (schema before 5, analysis revision before 5)
rebuild the same way: annotations carry over, the binary
re-analyzes. Diagnosing a stale cache never requires deleting
anything by hand — `load` rewrites it.

## Diagnostics: what absence does not mean

`diagnostics` pages provenance records — `unresolved-indirect-jump`,
`unresolved-indirect-call`, `decode-failure` — filtered by `--kind`
and containing-function `--func`. Querying never writes a sidecar.
Zero retained records is not proof of complete recovery: records
cap at 100,000 per project (`diagnostics_truncated` plus
`diagnostics_omitted` count the dropped rows), and hard analysis
budgets still fail with `Limit` rather than masquerading as a
successful partial analysis.

## IR coverage: implemented versus complete

`ir-coverage` needs no binary: it names the implemented opcode
families, the explicitly partial mappings, and the standing limits
(operand strings reused verbatim, unmodeled flags, unmodeled
stack/calling-convention effects, no SSA/PHI production). Unknown
mnemonics lift to `NOP` with a warning, distinguishable from a
genuine `NOP`:

```sh
$ binscout ir-coverage x86_64 fw.bin 0x0 3 --db fw.redb
{"arch": "x86_64", "range": {"addr": 0, "addr_hex": "0x0", "decoded": 3,
 "error_at": null, "lifted": 3, "truncated": false, "unlifted": 0,
 "unlifted_mnemonics": []}, ...}
```

With a range it adds `decoded`/`lifted`/`unlifted` counts from
actual lifts plus a bounded mnemonic summary. A range requires
all of `BINARY ADDR LEN` together. Implemented families are not
semantically complete — listed mnemonics lift without warning,
but the bounds above still apply.

## Byte-pattern search

`PATTERN` is positional: whitespace-separated full-byte tokens,
each two hex digits or a `??` wildcard. Empty, all-wildcard,
odd-length, non-hex, or over-4096-byte patterns are `Invalid`
errors. `--range LO HI` is half-open `[LO, HI)` over virtual
addresses (unlike the inclusive `--range` on `functions`);
`--section` is an exact section-name match:

```sh
$ binscout search-bytes fw.bin "68 00 21 ?? 00" --section .text
{"items":[{"addr":4198403,"addr_hex":"0x401003","file_off":515,"len":5,"section":".text"},{"addr":4198408,"addr_hex":"0x401008","file_off":520,"len":5,"section":".text"}],"limit":50,"next_offset":null,"offset":0,"protocol":1,"total":2}
```

Matches include overlaps, order by virtual address, and never
bridge mapping gaps; virtual BSS is never materialized. Scans
past 256 MiB of unique file-backed mapped bytes fail with
`Limit` instead of truncating silently.

## Annotation transfer

`annotations-export` prints one JSON document to stdout
(read-only, never creates a sidecar); `annotations-import`
reads it from `--input` (MCP takes the document directly).
Identity is `sha256` + `size` + `mapping`, and the whole document
validates before a single atomic write — a failure in the last
row leaves the DB unchanged:

```sh
$ binscout annotate fw.bin --db fw.redb 0x401000 --rename main
{"addr":4198400,"addr_hex":"0x401000","comment":null,"name":"main"}
$ binscout annotations-export fw.bin --db fw.redb
{"annotations":[{"addr":4198400,"rename":"main"}],"mapping":{"mode":"auto"},"revision":1,"sha256":"e70b2763e393b6d267d8e3b18f2d121018aa0c3b272cc7684d6d5d5f5fc23587","size":2048}
$ binscout annotations-import fw.bin --db fresh.redb --input doc.json
{"changed":1,"rows":1}
```

Only nonempty annotations appear and unset fields are omitted.
`rename` targets must be known function entries; comments keep
the any-address contract. Default merge fails on differing
existing field values (equal values are idempotent);
`--overwrite` replaces supplied fields only, absent fields leave
existing values alone, and empty strings clear. Documents cap at
16 MiB serialized; duplicate addresses, malformed identity, and
unsupported revisions are rejected.

## Inferred edges: scope and provenance

The resolver handles two patterns — a single-slot
absolute indirect jump (x86-32 `jmp m32` through an absolute
slot, x86-64 `jmp m64` through a RIP-relative slot) in an
explicit raw mapping, with the slot value landing on executable
mapped bytes in the same function, and a guarded scaled-index
table (`jmp [index*scale+base]`, x86-only: scale 4 on x86-32,
scale 8 on x86-64) behind a direct conditional bound-check guard
within 4 decoded predecessors. Unguarded indexes,
cross-function targets, truncated or unmapped slots,
non-executable targets, and container (non-raw) binaries all
keep their `unresolved-indirect-jump` diagnostic and stay
edgeless:

```sh
$ binscout --raw --arch x86_64 --base 0x400000 diagnostics blob.bin --db /tmp/blob.redb --kind unresolved-indirect-jump
{"items":[{"addr":4194304,"addr_hex":"0x400000","detail":"indirect jump without a direct target; the site stays edgeless","func":4194304,"func_hex":"0x400000","kind":"unresolved-indirect-jump"}],"limit":50,"next_offset":null,"offset":0,"protocol":1,"total":1}
```

Resolved edges stay separated from direct flow: `cfg` lists them
in `inferred_edges` (never `edges`), `func` counts them, and
`xrefs` tags them `inferred-code` next to the `Data` xref into
the slot:

```sh
$ binscout --raw --arch x86_64 --base 0x400000 cfg blob.bin --db /tmp/blob.redb 0x400000
{"containing_entry":4194304,"containing_entry_hex":"0x400000","edges":[],"entry":4194304,"entry_hex":"0x400000","inferred_edges":[[4194304,4194322]],"nodes":[{"end":4194310,"end_hex":"0x400006","insns":1,"start":4194304,"start_hex":"0x400000","succs":[]},{"end":4194325,"end_hex":"0x400015","insns":3,"start":4194322,"start_hex":"0x400012","succs":[]}]}
$ binscout --raw --arch x86_64 --base 0x400000 xrefs blob.bin --db /tmp/blob.redb
{"total":2,"xrefs":[{"from":4194304,"from_hex":"0x400000","kind":"Data","to":4194314,"to_hex":"0x40000a"},{"from":4194304,"from_hex":"0x400000","kind":"inferred-code","to":4194322,"to_hex":"0x400012"}]}
```

Caps are one edge per single-slot site and 2–8 consecutive
valid slots per table site (a singleton run is a stray pointer;
a run still valid at 8 slots is open-ended, so the site stays
unresolved rather than partially recovered); 100,000 per project;
exhaustion keeps the site unresolved with `inferred_truncated`
set and the excess in `inferred_omitted`.

## Opt-in envelope preview (protocol-2 track)

`functions` and `strings` still return bare arrays by default, but both
accept an opt-in envelope: `--envelope` on the CLI, `envelope: true` on
the MCP tools. The envelope is the protocol-1 page shape with an exact
`total`, so agents learn the match count without paging to the end:

```sh
$ binscout functions fw.elf --envelope --limit 1
{"items":[{"blocks":1,"calls_count":0,"entry":4198400,"entry_hex":"0x401000","id":"func@0x401000","insns":3,"name":"main"}],"limit":1,"next_offset":1,"offset":0,"protocol":1,"total":2}
$ binscout strings fw.elf --envelope --limit 0
{"items":[],"limit":0,"next_offset":null,"offset":0,"protocol":1,"total":5}
```

Planned breaking changes, staged behind this flag so no default output
moves until the version bump:

- `functions` rows trade the unbounded `calls` target array for
  `calls_count` (envelope rows already do this; the legacy bare array
  keeps `calls`). Direct callees remain one `callees` query away
  (`depth` 1 orders the same targets by entry with their distance).
- `functions` and `strings` adopt the page envelope as their default
  shape (`xrefs` keeps its own `{"total", "xrefs"}` wrapper until the
  same migration aligns it).

Additive and already shipped (no migration needed): `cfg`,
`structure`, `pseudo` (and the library `func_detail`) echo the
requested address in `query_addr`/`query_addr_hex`; `functions`
accepts `range_start`/`range_end` as aliases of its inclusive
`range_lo`/`range_hi`, `search_bytes` accepts `range_lo`/`range_hi`
as aliases of its half-open `range_start`/`range_end` (canonical
names win, aliases warn on stderr); the MCP `annotation` tool reads
the current rename/comment row (CLI `annotate` without flags parity),
read-only. The type-hint API stays a comment-channel convention (see
[JSON protocol](json-protocol.md)); it is out of scope for this track.
