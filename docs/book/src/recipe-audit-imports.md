# Audit imports

Goal: enumerate what a binary depends on from the outside world —
imported DLLs/APIs, exported surface, and the indirect-call sites
where that outside world is actually reached.

Use this for a first-pass dependency and attack-surface review:
which external functions the binary can call, which exports it
exposes, and where import-like indirect calls occur.

## Chain

`symbols` → `sections` → `diagnostics --kind
unresolved-indirect-call` → `func` / `disasm` per site →
`xrefs --from` → `callers` → `annotate --comment`.

Imports are metadata (names, not addresses), so the chain pivots
through indirect-call sites rather than xrefing an import directly.

## 1. Enumerate the external surface

```sh
$ binscout symbols fw.exe
$ binscout sections fw.exe
```

`symbols` returns `{"imports": [...], "exports": [...]}`. Each
import carries its `library` and `name`; ordinal-only imports carry
`ordinal` plus `unresolved: true`, and recognized C++ manglings
additionally carry `demangled`. Exports name the callable surface
the binary exposes to others. `sections` returns the section table
(`name`, `vaddr`, in-memory/file sizes, `readable` / `writable` /
`executable`); on PE, `vaddr = IMAGE_BASE + RVA`. Raw blobs have no
table and report `[]`. Flag writable-and-executable sections on
sight.

MCP: `symbols` (`binary`), `sections` (`binary`).

## 2. List the indirect-call sites

```sh
$ binscout diagnostics fw.exe --kind unresolved-indirect-call
$ binscout diagnostics fw.exe --kind unresolved-indirect-call --func 0x401000
```

Import and PLT/IAT calls have no direct target, so they appear here:
each row carries `kind`, `addr` / `addr_hex`, the containing
function (`func` / `func_hex`, null when in no function), and
kind-specific `detail`. `--kind` accepts only
`unresolved-indirect-jump`, `unresolved-indirect-call`, and
`decode-failure`; `--func` snaps to its containing function and keeps
only that function's sites (`NotFound` when in no function). Rows
order by (`kind`, `addr`) under the page envelope. Querying never
writes a sidecar. Zero retained records is not proof of complete
recovery — records cap at 100,000 per project.

MCP: `diagnostics` (`binary`, `kind:
"unresolved-indirect-call"`, `func?`, `offset?`, `limit?`).

## 3. Ground each site in code

```sh
$ binscout func fw.exe 0x401010
$ binscout disasm fw.exe 0x401010 16
$ binscout xrefs fw.exe --from 0x401010
```

`func` identifies the containing function and its discovery
`reasons`. `disasm` shows the calling instruction and its operands
(the valid prefix plus `error_at` on trailing bad bytes; ranges cap
at 1 MiB). `xrefs --from` lists what that site points at — look for
`data`-kind rows into import tables alongside the unresolved call.
Use `ir` with the same `ADDR LEN` shape when comparing call shapes
across sites.

MCP: `func` (`binary`, `addr`), `disasm` (`binary`, `addr`, `len`),
`xrefs` (`binary`, `from`).

## 4. Find who can reach the risky call

```sh
$ binscout callers fw.exe 0x401010 --depth 5
$ binscout search-bytes fw.exe "FF 15 ?? ?? ?? ??" --section .text
```

`callers` orders transitive callers by entry with shortest distance
under the page envelope; direct callers are depth 1. `search-bytes`
is the optional pattern complement: whitespace-separated full-byte
tokens with `??` wildcards (empty, all-wildcard, or malformed
patterns are `Invalid`), `--section` for an exact section match and
`--range LO HI` as half-open `[LO, HI)`; scans cap at 256 MiB of
mapped bytes with an explicit `Limit` error.

MCP: `callers` (`binary`, `addr`, `depth?`), `search_bytes`
(`binary`, `pattern`, `section?`, `range_start?`, `range_end?`).

## 5. Record the verdict

```sh
$ binscout annotate fw.exe 0x401010 --comment "indirect call: audit IAT slot for TESTDLL.dll ordinals"
$ binscout annotations-export fw.exe
```

`comment` accepts any address (empty string clears); `rename` only
known function entries. `annotations-export` emits the portable
handoff document (read-only, never creates a sidecar).

## Failure modes

- `symbols` with empty imports: statically linked or raw blob —
  pivot to `strings` for embedded library markers and
  `diagnostics` for the indirect-site inventory.
- `diagnostics --func` outside any function: `NotFound` — the site
  address is data, not code; query without `--func` instead.
- Ordinal-only imports (`unresolved: true`) with no `demangled`:
  expected, not a parse failure — there is no name to demangle.

See [CLI reference](cli-reference.md) for flag details and
[JSON protocol](json-protocol.md) for the page envelope.
