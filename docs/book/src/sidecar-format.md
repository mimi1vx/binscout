# Sidecar format

Analysis results and annotations persist in a `redb` database next to the
binary: `<binary>.rsdbg.redb` by default, overridden per-invocation with
`--db PATH` (CLI) or the `db` parameter (MCP tools). The analyzed binary
itself is only ever read.

On open, the stored content hash, loader mapping (auto versus
explicit raw arch/base/entry), and analysis revision are compared
against the request; a mismatch means the snapshot is discarded and
the binary re-analyzes. Annotations carry over by address when the
mapping is unchanged. A sidecar holding annotations opened under an
incompatible mapping fails with a separate-DB error instead of
remapping them. A sidecar written by an older schema version (current
version 5, analysis revision 4) behaves the same way: annotations
carry over and the binary re-analyzes. Row values are JSON.

| Table | Key | Value |
|---|---|---|
| `meta` | string | schema version, path, hash, size, arch, format, entry, mapping, analysis revision |
| `binaries` | `0` | snapshot metadata |
| `functions` | entry address | function row (name, callees, discovery reasons, inferred successors) |
| `blocks` | block key | block row (address range, successors, inferred successors) |
| `xrefs` | xref key | cross-reference row (direct and `inferred-code` kinds) |
| `strings` | row index | extracted-string row |
| `diagnostics` | record key | provenance row (unresolved indirect sites, decode failures) |
| `annotations` | address | rename and/or comment |

Block rows store address ranges plus per-instruction boundaries, not
rendered instructions: the open path re-decodes each recorded address
from the binary, so snapshots stay small no matter how large the
disassembly grows.

Delete the sidecar to drop cached analysis and annotations; it is rebuilt
on the next `load`.

## Size and upkeep

`binscout stats <binary>` reports the binary size (`size`), the sidecar
size (`db_size`, `0` before the first `load`), and the analysis counts
(`functions`/`blocks`/`insns`/`xrefs`/`strings`/`annotations`), so the
storage cost of a snapshot stays visible. Snapshots store block address
ranges rather than rendered instructions, so sidecars stay proportional
to the binary; CI caps the synthetic fixtures at 5 MiB to catch snapshot
bloat.

`save` rewrites every table, so repeated re-analysis can leave free pages
behind. There is no separate vacuum step: `redb` has no `VACUUM` command.
Call `binscout::db::compact_db` (wrapping `redb::Database::compact`) to
reclaim the space when a sidecar grows unexpectedly.

Never commit sidecars. Keep them out of version control:

```gitignore
*.rsdbg.redb
```
