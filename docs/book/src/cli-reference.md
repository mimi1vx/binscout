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
| `strings` | `binscout strings fw.elf --limit 20` | extracted strings by address |
| `symbols` | `binscout symbols fw.elf` | imports and exports |
| `ir` | `binscout ir fw.elf 0x400000 32` | P-code-inspired lift of the range |
| `annotate` | `binscout annotate fw.elf 0x400000 --rename main --comment "entry"` | read/write annotation at an address |

Addresses accept `0x`-hex or decimal strings. `annotate` without flags
reads; `--rename ""` clears the rename, omitting `--comment` leaves the
comment alone. `rename` only accepts known function entries; `comment`
accepts any address.
