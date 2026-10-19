# Sidecar format

Analysis results and annotations persist in a `redb` database next to the
binary: `.rsdbg.redb` appended to the full file name by default
(`foo.exe` → `foo.exe.rsdbg.redb`), overridden per-invocation with
`--db PATH` (CLI) or the `db` parameter (MCP tools). The analyzed binary
itself is only ever read.

On open, the stored content hash, loader mapping (auto versus
explicit raw arch/base/entry), explicit debug inputs (`--pdb` /
`--debug-file` content identity), and analysis revision are compared
against the request; a mismatch means the snapshot is discarded and
the binary re-analyzes. Annotations and user seeds carry over by address
when the mapping is unchanged (a debug-input mismatch re-analyzes but
never errors). A sidecar holding annotations or seeds
opened under an incompatible mapping fails with a separate-DB error
instead of remapping them. A sidecar written by an older schema version (current
version 8, analysis revision 11) behaves the same way: annotations and
seeds carry over and the binary re-analyzes. Metadata, annotations, and
user seeds persist as JSON rows; derived rows (functions, xrefs, strings)
persist as chunked compact binary blobs with integer chunk keys, while
diagnostics stay key-only rows with tuple keys.
User seeds hash into the snapshot identity (`seeds_hash` in the
metadata): every seed change re-analyzes before saving, so derived rows
always match the stored seeds.

| Table | Key | Value |
|---|---|---|
| `meta` | string | schema version, path, hash, size, arch, format, entry, mapping, analysis revision, seed identity |
| `binaries` | `0` | snapshot metadata |
| `functions` | entry address | function row (name, callees, discovery reasons, decode-arch override) plus its block layouts (address range plus per-instruction sizes, successors, inferred successors) |
| `xrefs` | chunk index | cross-reference blob chunk (fixed `(from, kind, to)` entries: direct, `import`, and `inferred-code` kinds) |
| `strings` | chunk index | extracted-string blob chunk |
| `diagnostics` | `(addr, kind)` | key-only provenance row (unresolved indirect sites, noreturn cuts, decode failures) |
| `annotations` | address | rename and/or comment |
| `func_seeds` | address | user function seed (decode mode, excluded flag) |

Block layouts store address ranges plus per-instruction sizes, not
rendered instructions: the open path re-decodes each recorded address
from the binary, so snapshots stay small no matter how large the
disassembly grows. Function bodies pack a function with its blocks so no
per-block key repeats the entry address. Xrefs and strings pack many
entries per small chunked blob row, holding row visits to the dozens on
cache-hit opens; only diagnostics stay key-only, holding the whole row in
the key.

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
