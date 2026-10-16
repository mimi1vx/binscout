# Find main

Goal: locate the program's real entry logic — the startup entry point
versus the application `main` — using only headless queries.

Use this when opening an unfamiliar binary: confirm where execution
starts, list candidate mains, and pick the function worth renaming
and reading first.

## Chain

`load` → `symbols` → `functions --query` → `func` → `callers` /
`callee` filter → `flirt-hints` (optional) → `cfg` / `blocks` →
`annotate --rename`.

Each step narrows the candidate set; stop as soon as one function
explains the entry's callees.

## 1. Open and read the entry

```sh
$ binscout load fw.exe
$ binscout symbols fw.exe
```

`load` reports `arch`, `format`, `entry` / `entry_hex`, `mode`, and
diagnostic totals, and caches the snapshot. `symbols` returns
`{"imports": [...], "exports": [...]}` — exports often name the
candidate mains directly (for example, `basic_entry` in the
`pe32-basic.exe` fixture at entry `0x401000`).

MCP: `project_info` (`binary`), then `symbols` (`binary`).

## 2. List name candidates

```sh
$ binscout functions fw.exe --query main --limit 50
$ binscout func fw.exe 0x401000
```

`--query` is a case-insensitive substring over the rename-resolved
name. No match is not an error — it is an empty list, meaning the
binary strips names or calls it something else; fall through to step 3.
`func` returns compact metadata (`entry` / `entry_hex`, `name`,
`blocks` / `insns` / `calls` counts, `inferred_edges` count,
`reasons` such as `entry`, `export`, `direct-call`, `prologue`).
Any address inside the function snaps to its containing entry;
an address in no function is `NotFound`.

MCP: `functions` (`binary`, `query: "main"`), then `func` (`binary`,
`addr`).

## 3. Confirm via the callgraph

```sh
$ binscout callees fw.exe 0x401000 --depth 1
$ binscout callers fw.exe 0x401000 --depth 5
$ binscout functions fw.exe --callee 0x401000 --limit 50
```

The entry's direct `callees` (depth 1) are the startup-called
functions — the real main is usually among them. Conversely,
`callers` of a candidate main should lead back toward the entry or
a CRT startup wrapper. The `--caller` / `--callee` filters on
`functions` keep call-graph neighbors of the function containing
that address without a second round trip. Results page under the
protocol-1 envelope (`protocol`, `total`, `offset`, `limit`,
`next_offset`, `items`) ordered by entry with shortest distance;
direct neighbors are depth 1.

MCP: `callees` / `callers` (`binary`, `addr`, `depth?`, `offset?`,
`limit?`); `functions` with `caller` / `callee`.

## 4. Exclude library startup (optional)

```sh
$ binscout flirt-hints fw.exe --addr 0x401000
```

`flirt-hints` pairs each function entry with a corpus `signature`
id, its `suggested_name`, and the `reason` it stays a hint. A hit
saying "this looks like CRT startup" is evidence to keep looking,
not a rename: suggested names are never applied automatically.

MCP: `flirt_hints` (`binary`, `addr?`, `offset?`, `limit?`).
Querying never writes a sidecar.

## 5. Read, then name it

```sh
$ binscout cfg fw.exe 0x401000
$ binscout blocks fw.exe 0x401000 --limit 50
$ binscout annotate fw.exe 0x401000 --rename main --comment "entry via callees of startup"
```

`cfg` is the explicit full-graph export (block nodes plus
`(from, to)` edges; `inferred_edges` holds raw-only same-function
single-slot resolutions). `blocks` pages the same function safely
when the graph is large. `annotate` without flags reads; `--rename`
writes only on known function entries (empty string clears),
`--comment` accepts any address.

MCP: `cfg` (`binary`, `addr`), `blocks` (`binary`, `addr`),
then `rename` (`binary`, `addr`, `name`) / `comment` (`binary`,
`addr`, `comment`).

## Failure modes

- `func` / `cfg` / `blocks` on an address in no function: `NotFound`
  — the address is data, a string, or unmapped, not code.
- `functions --query` with no hits: empty list, not an error —
  pivot to `callees` of the entry instead of guessing names.
- `flirt-hints` with no hits: empty page — the corpus does not
  cover this compiler/CRT, not proof of hand-written code.

See [CLI reference](cli-reference.md) for flag details and
[JSON protocol](json-protocol.md) for the page envelope.
