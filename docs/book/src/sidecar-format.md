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
