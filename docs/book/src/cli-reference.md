# CLI reference

```sh
binscout [--db PATH] <command> <binary> [args]
```

`--db` overrides the sidecar database (default `<binary>.rsdbg.redb`).
See [JSON protocol](json-protocol.md) for the output contract.
| Command | Example | Output |
|---|---|---|
| `load` | `binscout load fw.elf` | project info; caches the analysis snapshot |
| `functions` | `binscout functions fw.elf --query main --limit 50` | function rows, renames resolved; `--query` is a case-insensitive substring over the resolved name, `--caller`/`--callee` keep call-graph neighbors of the function containing that address, `--range LO HI` keeps entries in the inclusive bounds; page with `--offset`/`--limit` |
| `func` | `binscout func fw.elf 0x400000` | blocks with instructions, edges, calls |
| `disasm` | `binscout disasm fw.elf 0x400000 32` | decoded instructions (`addr` = hex or decimal, then byte count); the valid prefix plus `error_at` for the first bad opcode, ranges cap at 1 MiB |
| `cfg` | `binscout cfg fw.elf 0x400000` | block nodes plus `(from, to)` edges |
| `xrefs` | `binscout xrefs fw.elf --to 0x400000 --kind code` | cross-references filtered by `--to`/`--from`/`--kind` (`code`, `data`, `string`), paged with `--offset`/`--limit` behind a `{"total", "xrefs"}` envelope |
| `strings` | `binscout strings fw.elf --pattern SAVE --min-len 6` | filtered strings by address (`--pattern` substring or `regex:` expression, `--min-len`, `--section`, `--include-code`; executable-memory hits hidden by default; paged by `--start`/`--limit`, `--offset` deprecated) |
| `symbols` | `binscout symbols fw.elf` | imports and exports |
| `sections` | `binscout sections fw.elf` | section table: name, `vaddr`, in-memory/file sizes, permissions |
| `ir` | `binscout ir fw.elf 0x400000 32` | P-code-inspired lift of the range (`error_at` on trailing bad bytes, ranges cap at 1 MiB) |
| `stats` | `binscout stats fw.elf` | storage stats: binary size, sidecar DB size, analysis counts |
| `annotate` | `binscout annotate fw.elf 0x400000 --rename main --comment "entry"` | read/write annotation at an address |

Paged lists cap at 1024 rows. Addresses accept `0x`-hex or decimal
strings. `func`/`cfg` snap any address inside the function to its
containing entry. `annotate` without flags reads; `--rename ""` clears
the rename, omitting `--comment` leaves the comment alone. `rename` only
accepts known function entries; `comment` accepts any address.

`sections` rows carry `name`, `vaddr` (the flat virtual address the loader
mapped the section at), `size` (in-memory bytes), `file_off`/`file_size`
(locating the raw bytes in the file), and `readable`/`writable`/`executable`.
On PE, `vaddr = IMAGE_BASE + RVA`: `.text` at RVA `0x1000` in a
`0x400000`-based image lives at `0x401000`, with `file_off` pointing at its
`PointerToRawData`. Raw blobs have no section table and report `[]`.

## Frozen upcoming commands (not yet implemented)

The protocol-1 contract freezes these names and shapes; they land with
their roadmap steps. See [JSON protocol](json-protocol.md) for the full
request/response definitions.

| Command | Step | Does |
|---|---|---|
| `blocks B ADDR` | bounded function views | page block summaries of the containing function |
| `block-insns B ADDR BLOCK` | bounded function views | page one block's instructions in address order |
| `diagnostics B` | diagnostic queries | page provenance records, filterable by `--kind`/`--func` |
| `ir-coverage --arch ARCH` | IR coverage | lift coverage without opening a binary; optional range counts |
| `search-bytes B PATTERN` | byte search | paged `??`-wildcard matches with section/range filters |
| `annotations-export B` | annotation transfer | emit the portable JSON annotation document |
| `annotations-import B` | annotation transfer | atomically merge a document (`--input`, `--overwrite`) |

Raw mapping also arrives as global flags
`[--raw --arch ARCH --base ADDR [--entry ADDR]]` on every binary-taking
command. Until these ship, `func` keeps its current full-detail shape.
