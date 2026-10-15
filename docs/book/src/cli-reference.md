# CLI reference

```sh
binscout [--db PATH] [--raw --arch ARCH --base ADDR [--entry ADDR]] <command> <binary> [args]
```

`--db` overrides the sidecar database (default `<binary>.rsdbg.redb`).
`--raw` selects explicit raw mapping for firmware/blob workflows:
`--arch` is one of `x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`;
`--base` (and optional `--entry`) parse as addresses. `--arch`/`--base`/`--entry`
without `--raw` are errors, as are unknown arches, unmapped or
misaligned entries, and base-plus-length overflow. Without `--raw`,
container auto-detection (and the raw x86-64-at-0 fallback) is
unchanged, and explicit raw mode never falls back to another mode on
failure.
See [JSON protocol](json-protocol.md) for the output contract.
| Command | Example | Output |
|---|---|---|
| `load` | `binscout load fw.elf` | project info (`protocol`, `mode`, `arch`, `base`, diagnostic totals, `analysis_revision`); caches the analysis snapshot |
| `functions` | `binscout functions fw.elf --query main --limit 50` | function rows, renames resolved; `--query` is a case-insensitive substring over the resolved name, `--caller`/`--callee` keep call-graph neighbors of the function containing that address, `--range LO HI` keeps entries in the inclusive bounds; page with `--offset`/`--limit` |
| `func` | `binscout func fw.elf 0x400000` | compact metadata: entry, name, block/insn/call counts, discovery `reasons` |
| `blocks` | `binscout blocks fw.elf 0x400000 --offset 0 --limit 50` | block summaries (`id`, `start`/`start_hex`, `end`/`end_hex`, `insns` count, `succs`) of the containing function by block start, under the page envelope |
| `block-insns` | `binscout block-insns fw.elf 0x400000 0x400000 --limit 50` | that block's instructions in address order, under the page envelope; the block must belong to the function |
| `disasm` | `binscout disasm fw.elf 0x400000 32` | decoded instructions (`addr` = hex or decimal, then byte count); the valid prefix plus `error_at` for the first bad opcode, ranges cap at 1 MiB |
| `cfg` | `binscout cfg fw.elf 0x400000` | block nodes plus `(from, to)` edges; `inferred_edges` holds provenance-marked single-slot resolutions (raw-only, same-function) |
| `callees` | `binscout callees fw.elf 0x400000 --depth 5` | transitive callees out to `--depth` hops (direct are depth 1), ordered by entry with shortest distance, under the page envelope |
| `callers` | `binscout callers fw.elf 0x400000 --depth 5` | transitive callers out to `--depth` hops, ordered by entry with shortest distance, under the page envelope |
| `slice` | `binscout slice fw.elf 0x400000 --depth 5` | backward slice of an address: every instruction that can reach it via xref edges (any kind) and intra-function CFG predecessors out to `--depth` hops (direct are depth 1), ordered by address with shortest distance, under the page envelope |
| `diagnostics` | `binscout diagnostics fw.elf --kind decode-failure --func 0x400000` | provenance records (unresolved indirect sites, decode failures) ordered by (`kind`, `addr`) under the page envelope; `--kind` is one of `unresolved-indirect-jump`, `unresolved-indirect-call`, `decode-failure`, `--func` keeps only that function's sites; queries never write a sidecar |
| `search-bytes` | `binscout search-bytes fw.elf "48 8B ??" --range 0x400000 0x401000` | paged `??`-wildcard matches (`addr`/`addr_hex`, `file_off`, `section`, `len`) ordered by virtual address; `--section` is an exact section-name match, `--range LO HI` is half-open `[LO, HI)`; scans cap at 256 MiB of mapped bytes with an explicit `Limit` error |
| `xrefs` | `binscout xrefs fw.elf --to 0x400000 --kind code` | cross-references filtered by `--to`/`--from`/`--kind` (`code`, `data`, `string`, `inferred-code`), paged with `--offset`/`--limit` behind a `{"total", "xrefs"}` envelope |
| `strings` | `binscout strings fw.elf --pattern SAVE --min-len 6` | filtered strings by address (`--pattern` substring or `regex:` expression, `--min-len`, `--section`, `--include-code`; executable-memory hits hidden by default; paged by `--start`/`--limit`, `--offset` deprecated; `--decode xor:<byte>`, `add:<byte>`, or `rot:<0-7>` re-extracts over a read-only in-memory transform with original offsets) |
| `symbols` | `binscout symbols fw.elf` | imports and exports |
| `sections` | `binscout sections fw.elf` | section table: name, `vaddr`, in-memory/file sizes, permissions |
| `ir` | `binscout ir fw.elf 0x400000 32` | P-code-inspired lift of the range (`error_at` on trailing bad bytes, ranges cap at 1 MiB) |
| `ir-coverage` | `binscout ir-coverage x86_64 [fw.elf 0x400000 32]` | machine-readable lift coverage for one arch (`x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`); no binary is opened without the range, which adds decoded/lifted/unlifted counts from actual lifts plus a bounded mnemonic summary |
| `stats` | `binscout stats fw.elf` | storage stats: binary size, sidecar DB size, analysis counts |
| `annotate` | `binscout annotate fw.elf 0x400000 --rename main --comment "entry"` | read/write annotation at an address |
| `annotations-export` | `binscout annotations-export fw.elf` | portable annotation document (revision, sha256, size, mapping, sorted rows); read-only, never creates a sidecar |
| `annotations-import` | `binscout annotations-import fw.elf --input doc.json [--overwrite]` | atomically merge a document; returns row/change counts, default fails on conflicts |

Paged lists cap at 1024 rows. Addresses accept `0x`-hex or decimal
strings. `func`/`cfg`/`blocks` snap any address inside the function to
its containing entry (`NotFound` when in no function); `block-insns`
additionally requires its block to be a block start belonging to that
function. `annotate` without flags reads; `--rename ""` clears
the rename, omitting `--comment` leaves the comment alone. `rename` only
accepts known function entries; `comment` accepts any address.

`sections` rows carry `name`, `vaddr` (the flat virtual address the loader
mapped the section at), `size` (in-memory bytes), `file_off`/`file_size`
(locating the raw bytes in the file), and `readable`/`writable`/`executable`.
On PE, `vaddr = IMAGE_BASE + RVA`: `.text` at RVA `0x1000` in a
`0x400000`-based image lives at `0x401000`, with `file_off` pointing at its
`PointerToRawData`. Raw blobs have no section table and report `[]`.

## Cache identity

Snapshots are keyed by binary content, loader mapping (auto versus
explicit raw arch/base/entry), and analysis revision. The same bytes
opened under a different mapping re-analyze rather than reuse
layouts; opening a sidecar that holds annotations under an
incompatible mapping fails with a separate-DB error instead of
remapping them:

```sh
$ binscout func fw.bin --db fw-mapped.redb 0x0
{"error":"storage: mapping mismatch: project db holds 1 annotation(s) under explicit raw x86_64 base 0x400000, but current open requests auto; use a separate --db PATH for this mapping (annotations are never remapped)"}
```

Sidecars written by older schema versions rebuild the same way: the
binary re-analyzes. See [Sidecar format](sidecar-format.md).
