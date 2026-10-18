# CLI reference

```sh
binscout [--db PATH] [--raw --arch ARCH --base ADDR [--entry ADDR]] [--fat-arch ARCH] <command> <binary> [args]
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
`--fat-arch` selects a slice of a fat Mach-O container: `x86_64`,
`x86_32`, `aarch64`, `arm32` (plus `lipo` aliases like `arm64`,
case-insensitive); it is required for fat inputs, which error
listing the available archs without it, and rejected for thin
(non-fat) inputs. `--raw` and `--fat-arch`
are exclusive. Different slices never share cached snapshots.
See [JSON protocol](json-protocol.md) for the output contract.
| Command | Example | Output |
|---|---|---|
| `load` | `binscout load fw.elf` | project info (`protocol`, `mode`, `arch`, `base`, diagnostic totals, `analysis_revision`); caches the analysis snapshot |
| `functions` | `binscout functions fw.elf --query main --limit 50` | function rows, renames resolved; `--query` is a case-insensitive substring over the resolved name, `--caller`/`--callee` keep call-graph neighbors of the function containing that address, `--range LO HI` keeps entries in the inclusive bounds; page with `--offset`/`--limit`, or `--envelope` for the protocol-1 page envelope with an exact `total` and compact `calls_count` rows |
| `func` | `binscout func fw.elf 0x400000` | compact metadata: entry, name, block/insn/call counts, discovery `reasons` |
| `blocks` | `binscout blocks fw.elf 0x400000 --offset 0 --limit 50` | block summaries (`id`, `start`/`start_hex`, `end`/`end_hex`, `insns` count, `succs`) of the containing function by block start, under the page envelope |
| `block-insns` | `binscout block-insns fw.elf 0x400000 0x400000 --limit 50` | that block's instructions in address order, under the page envelope; the block must belong to the function |
| `disasm` | `binscout disasm fw.elf 0x400000 32` | decoded instructions (`addr` = hex or decimal, then byte count); the valid prefix plus `error_at` for the first bad opcode, ranges cap at 1 MiB |
| `bytes` | `binscout bytes fw.elf 0x400000 --len 32 [--as u16] [--endian be]` | raw bytes at `addr` (`--len` capped at 1 MiB, BSS tails read as zeros) with VA/file provenance (`file_off` null for zero-fill, `section` null when section-less) plus `bytes_hex` and typed `values` (`u8`/`u16`/`u32`/`u64`/`ptr`/`cstr`/`utf16`, `le`/`be` byte order); `--as-type ADDR` renders the struct fields of the stored type hint at `ADDR` over the range start (`--len` must cover the struct size) |
| `cfg` | `binscout cfg fw.elf 0x400000` | block nodes plus `(from, to)` edges; `inferred_edges` holds provenance-marked indirect-jump resolutions (single-slot absolutes and guarded scaled-index tables; raw-only, same-function); `query_addr` echoes the requested address |
| `structure` | `binscout structure fw.elf 0x400000` | approximate control-flow structure: syntactic loops (back-edge headers with latches) and ifs (two-successor branch sites with then/else targets) plus an approximation warning; `query_addr` echoes the requested address |
| `pseudo` | `binscout pseudo fw.elf 0x400000` | approximate pseudo-C of one function: one lossy C-like line per IR row plus assembled text, with an approximation warning; `query_addr` echoes the requested address |
| `callees` | `binscout callees fw.elf 0x400000 --depth 5` | transitive callees out to `--depth` hops (direct are depth 1), ordered by entry with shortest distance, under the page envelope |
| `callers` | `binscout callers fw.elf 0x400000 --depth 5` | transitive callers out to `--depth` hops, ordered by entry with shortest distance, under the page envelope |
| `slice` | `binscout slice fw.elf 0x400000 --depth 5` | backward slice of an address: every instruction that can reach it via xref edges (any kind) and intra-function CFG predecessors out to `--depth` hops (direct are depth 1), ordered by address with shortest distance, under the page envelope |
| `diagnostics` | `binscout diagnostics fw.elf --kind decode-failure --func 0x400000` | provenance records (unresolved indirect sites, decode failures) ordered by (`kind`, `addr`) under the page envelope; `--kind` is one of `unresolved-indirect-jump`, `unresolved-indirect-call`, `decode-failure`, `--func` keeps only that function's sites; queries never write a sidecar |
| `search-bytes` | `binscout search-bytes fw.elf "48 8B ??" --range 0x400000 0x401000` | paged `??`-wildcard matches (`addr`/`addr_hex`, `file_off`, `section`, `len`) ordered by virtual address; `--section` is an exact section-name match, `--range LO HI` is half-open `[LO, HI)`; scans cap at 256 MiB of mapped bytes with an explicit `Limit` error |
| `xrefs` | `binscout xrefs fw.elf --to 0x400000 --kind code` | cross-references filtered by `--to`/`--from`/`--kind` (`code`, `data`, `string`, `import`, `inferred-code`), paged with `--offset`/`--limit` behind a `{"total", "xrefs"}` envelope |
| `strings` | `binscout strings fw.elf --pattern SAVE --min-len 6` | filtered strings by address (`--pattern` substring or `regex:` expression, `--min-len`, `--section`, `--include-code`; executable-memory hits hidden by default; paged by `--start`/`--limit`, `--offset` deprecated, or `--envelope` for the protocol-1 page envelope with an exact `total`; `--decode xor:<byte>`, `xor:0x<HEXKEY>` (rolling multi-byte key), `add:<byte>`, `rot:<0-7>`, or bare `base64` re-extracts over a read-only in-memory transform with original offsets) |
| `stack-strings` | `binscout stack-strings fw.elf` | recovered stack-constructed strings: runs of `mov [rsp/rbp+off], imm` within one block, reassembled with function and address; read-only, never writes the binary or the sidecar |
| `symbols` | `binscout symbols fw.elf` | imports, exports, and symbol-table code addresses (`symbols`: one `name`/`address`/`address_hex` row per defined text symbol, locals included, deduplicated by address); Mach-O imports carry the `address`/`address_hex` of their `__stubs`/`__auth_stubs` entry (null when unmapped), and each mapped stub seeds its own import-named function; symbol addresses seed `symbol`-reasoned functions named below exports and above stubs |
| `sections` | `binscout sections fw.elf` | section table: name, `vaddr`, in-memory/file sizes, permissions |
| `ir` | `binscout ir fw.elf 0x400000 32` | P-code-inspired lift of the range (`error_at` on trailing bad bytes, ranges cap at 1 MiB) |
| `ir-coverage` | `binscout ir-coverage x86_64 [fw.elf 0x400000 32]` | machine-readable lift coverage for one arch (`x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`); no binary is opened without the range, which adds decoded/lifted/unlifted counts from actual lifts plus a bounded mnemonic summary |
| `flirt-hints` | `binscout flirt-hints fw.elf [--addr 0x400000] [--sigs sigs.json]` | FLIRT-like library hints (read-only): corpus signature matches over each function's leading bytes, paged under the protocol-1 envelope; `--addr` keeps only the containing function's hints; `--sigs` adds a user signature file (our JSON, as emitted by `sig-gen`, or an IDA `.pat` file by extension); suggested names stay hints, querying never writes a sidecar |
| `sig-gen` | `binscout sig-gen fw.elf` | Emit a JSON signature document for the binary's named functions (masked leading bytes with `len`/`crc`): the `--sigs` input that `flirt-hints` reads back; read-only, never writes the binary or a sidecar |
| `go-funcs` | `binscout go-funcs fw.elf` | Recover Go functions from the `pclntab` table (linker names plus exact entry/end ranges) for stripped Go binaries; empty array when no table is located; read-only, never writes the binary or a sidecar |
| `stats` | `binscout stats fw.elf` | storage stats: binary size, sidecar DB size, analysis counts |
| `headers` | `binscout headers fw.exe` | header metadata: triage staples (PE timestamp/mitigations/Rich/imphash/PDB/version-info/delay-load/forwarders, ELF interp/needed/RUNPATH/RELRO/NX/PIE/build-id, Mach-O load commands/dylibs/min-OS/codesign/entitlements/UUID) plus `sha256`/`md5`; computed on demand, never persisted; querying never writes a sidecar |
| `annotate` | `binscout annotate fw.elf 0x400000 --rename main --comment "entry"` | read/write annotation at an address |
| `type-hint` | `binscout type-hint fw.elf 0x400000 --json '{"kind":"struct","name":"Foo","size":8,"fields":[]}'` | read/write the structured struct-layout hint at an address (`--json` stores, empty `--json` clears the hint; `--get` or bare reads `{"addr", "addr_hex", "hint"}`); same any-address, 8 KiB-cap, immediate-persist rules as `comment` |
| `define-func` | `binscout define-func fw.elf 0x401000 [--mode thumb]` | assert "there is code here": store a user function seed and re-analyze so the function materializes; any address accepted, undecodable seeds inert; `--mode arm`/`thumb` selects the 32-bit ARM decode (other arches reject it) |
| `undefine-func` | `binscout undefine-func fw.elf 0x401000` | assert "this isn't a function": exclude the seed and re-analyze; the row is kept as data |
| `annotations-export` | `binscout annotations-export fw.elf` | portable annotation document (revision, sha256, size, mapping, sorted rows); read-only, never creates a sidecar |
| `annotations-import` | `binscout annotations-import fw.elf --input doc.json [--overwrite]` | atomically merge a document; returns row/change counts, default fails on conflicts |
| `diff` | `binscout diff old.elf new.elf [--db-a A.redb --db-b B.redb] [--offset N --limit N] [--transfer-renames]` | function-level diff between two binaries (`matched`/`added`/`removed`/`changed` with match reason, plus BinDiff-style neighbour propagation); each list pages under the protocol-1 envelope; `--transfer-renames` embeds the side-B rename document for `annotations-import`; both projects open read-only, never creating or modifying a sidecar; per-side `--db-a`/`--db-b` instead of the global `--db`, the global `--raw` mapping or `--fat-arch` selection (if any) applies to both |
| `diff-func` | `binscout diff-func old.elf new.elf ADDR_A ADDR_B [--db-a A.redb --db-b B.redb]` | block- and instruction-level delta between two functions (blocks match by hash then by position, each matched block carries a bounded edit script); addresses snap to their containing entries; read-only like `diff` |

Paged lists cap at 1024 rows. Addresses accept `0x`-hex or decimal
strings. `func`/`cfg`/`blocks` snap any address inside the function to
its containing entry (`NotFound` when in no function); `block-insns`
additionally requires its block to be a block start belonging to that
function. `annotate` without flags reads; `--rename ""` clears
the rename, omitting `--comment` leaves the comment alone. `rename` only
accepts known function entries; `comment` accepts any address.
`define-func`/`undefine-func` persist a seed row and re-analyze
immediately (printing `{"addr", "addr_hex", "mode", "excluded"}`), so the
snapshot's derived rows always match its stored seeds; the seed set joins
analysis with the `user` discovery reason (see [JSON
protocol](json-protocol.md)).
Structured struct-layout hints (`type-hint:{...}`, see [JSON
protocol](json-protocol.md)) pass through `--comment` opaquely, e.g.
`--comment 'type-hint:{"kind":"struct","name":"Foo","size":24,"fields":[]}'`.

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
