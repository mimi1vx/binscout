# Sidecar format

Analysis results and annotations persist in a `redb` database next to the
binary: `<binary>.rsdbg.redb` by default, overridden per-invocation with
`--db PATH` (CLI) or the `db` parameter (MCP tools). The analyzed binary
itself is only ever read.

On open, the stored content hash is compared against the file; a mismatch
means the binary changed and it is re-analyzed. Row values are JSON.

| Table | Key | Value |
|---|---|---|
| `meta` | string | schema version, path, hash, size, arch, format, entry |
| `binaries` | `0` | snapshot metadata |
| `functions` | entry address | function row (name, callees) |
| `blocks` | block key | block row (instructions, successors) |
| `xrefs` | xref key | cross-reference row |
| `strings` | row index | extracted-string row |
| `annotations` | address | rename and/or comment |

Delete the sidecar to drop cached analysis and annotations; it is rebuilt
on the next `load`.

## Size and upkeep

`binscout stats <binary>` reports the binary size (`size`), the sidecar
size (`db_size`, `0` before the first `load`), and the analysis counts
(`functions`/`blocks`/`insns`/`xrefs`/`strings`/`annotations`), so the
storage cost of a snapshot stays visible. As a cautionary datum, a
1.5 MB real-world binary once produced a 136 MB snapshot; CI caps the
synthetic fixtures well below that (5 MiB) to catch snapshot bloat.

`save` rewrites every table, so repeated re-analysis can leave free pages
behind. There is no separate vacuum step: `redb` has no `VACUUM` command.
Call `binscout::db::compact_db` (wrapping `redb::Database::compact`) to
reclaim the space when a sidecar grows unexpectedly.

Never commit sidecars. Keep them out of version control:

```gitignore
*.rsdbg.redb
```
