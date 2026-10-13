# CLI reference

```sh
binscout [--db PATH] <command> <binary> [args]
```

`--db` overrides the sidecar database (default `<binary>.rsdbg.redb`).
See [JSON protocol](json-protocol.md) for the output contract.

| Command | Example | Output |
|---|---|---|
| `load` | `binscout load fw.elf` | project info; caches the analysis snapshot |
| `functions` | `binscout functions fw.elf --offset 0 --limit 50` | function rows, renames resolved |
| `func` | `binscout func fw.elf 0x400000` | blocks with instructions, edges, calls |
| `disasm` | `binscout disasm fw.elf 0x400000 32` | decoded instructions (`addr` = hex or decimal, then byte count) |
| `cfg` | `binscout cfg fw.elf 0x400000` | block nodes plus `(from, to)` edges |
| `xrefs` | `binscout xrefs fw.elf --to 0x400000 --kind code` | filtered/paged cross-references |
| `strings` | `binscout strings fw.elf --pattern SAVE --min-len 6` | filtered strings by address (`--pattern` substring or `regex:` expression, `--min-len`, `--section`, `--include-code`; executable-memory hits hidden by default; paged by `--start`/`--limit`, `--offset` deprecated) |
| `symbols` | `binscout symbols fw.elf` | imports and exports |
| `sections` | `binscout sections fw.elf` | section table: name, `vaddr`, in-memory/file sizes, permissions |
| `ir` | `binscout ir fw.elf 0x400000 32` | P-code-inspired lift of the range |
| `stats` | `binscout stats fw.elf` | storage stats: binary size, sidecar DB size, analysis counts |
| `annotate` | `binscout annotate fw.elf 0x400000 --rename main --comment "entry"` | read/write annotation at an address |

Addresses accept `0x`-hex or decimal strings. `annotate` without flags
reads; `--rename ""` clears the rename, omitting `--comment` leaves the
comment alone. `rename` only accepts known function entries; `comment`
accepts any address.

`sections` rows carry `name`, `vaddr` (the flat virtual address the loader
mapped the section at), `size` (in-memory bytes), `file_off`/`file_size`
(locating the raw bytes in the file), and `readable`/`writable`/`executable`.
On PE, `vaddr = IMAGE_BASE + RVA`: `.text` at RVA `0x1000` in a
`0x400000`-based image lives at `0x401000`, with `file_off` pointing at its
`PointerToRawData`. Raw blobs have no section table and report `[]`.
