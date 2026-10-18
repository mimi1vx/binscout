# Trace string

Goal: go from an interesting string ("SAVE", an error message, a URL,
a registry key) to the code that uses it, and from there to the
function worth reading.

Use this when a string names the behavior under investigation and the
question is "what code touches this?".

## Chain

`strings --pattern` → `xrefs --to --kind string` → `func` →
`block-insns` / `disasm` → `slice ADDR` → `callers`.

Each step moves one hop: text, to reference site, to containing
function, to backward reachability.

## 1. Find the string

```sh
$ binscout strings fw.exe --pattern SAVE --min-len 6
```

`--pattern` is a case-sensitive substring (or a `regex:` expression);
`--min-len` drops short noise, `--section` keeps one section exactly
(such as `.rdata`). Hits in executable memory are hidden unless
`--pattern`, `--section`, or `--include-code` is given. Page with
`--start` / `--limit` (`--offset` is a deprecated alias that warns).
For single-byte-obfuscated text, `--decode xor:<byte>`, `add:<byte>`,
or `rot:<0-7>` (`0x`-hex or decimal byte) re-extracts over a
read-only in-memory transform with original offsets; the binary is
never written. Rolling multi-byte keys (`--decode xor:0x<HEXKEY>`
with 4+ hex digits) and base64-blob plaintext (`--decode base64`)
work the same way.

```sh
$ binscout strings fw.exe --pattern "regex:GAM.*invalid"
$ binscout strings fw.exe --decode xor:0x42 --pattern SAVE
$ binscout strings fw.exe --decode xor:0xDEADBEEF --pattern SAVE
$ binscout strings fw.exe --decode base64 --pattern token
```

MCP: `strings` (`binary`, `pattern?`, `min_len?`, `section?`,
`include_code?`, `decode?`, `start?`, `limit?`).

## 2. Find who references it

```sh
$ binscout xrefs fw.exe --to 0x402100 --kind string
```

`xrefs` filters by `--to` / `--from` / `--kind` (`code`, `data`,
`string`, `import`, `inferred-code`, case-insensitive) and pages behind a
`{"total", "xrefs"}` envelope. Rows carry `from` / `from_hex`,
`to` / `to_hex`, and `kind`. A string typically has `string`-kind
rows from the referencing instructions (the `pe32-basic.exe`
fixture references its `SAVE%d.GAM is invalid` marker twice from
`.text`) plus `data`-kind rows where the address is materialized.

MCP: `xrefs` (`binary`, `to`, `kind: "string"`, `offset?`,
`limit?`).

## 3. Land in the containing function

```sh
$ binscout func fw.exe 0x401000
$ binscout block-insns fw.exe 0x401000 0x401000 --limit 50
$ binscout disasm fw.exe 0x401000 32
```

`func` snaps any address inside the function to its containing entry
(`NotFound` when in no function) and returns counts plus discovery
`reasons`. `block-insns` pages that block's instructions in address
order — the block must belong to the function. `disasm` decodes
`len` bytes at `addr` with the binary architecture, returning the
valid prefix plus `error_at` for the first bad opcode (ranges cap at
1 MiB). Use `ir` with the same `ADDR LEN` shape when the question is
about effects rather than bytes.

MCP: `func` (`binary`, `addr`), `block_insns` (`binary`, `addr`,
`block`), `disasm` / `ir` (`binary`, `addr`, `len`).

## 4. Walk backward to the decision

```sh
$ binscout slice fw.exe 0x401003 --depth 5
$ binscout callers fw.exe 0x401000 --depth 5
```

`slice` returns every instruction that can reach `ADDR` via xref edges
(any kind) plus intra-function CFG predecessors, out to `--depth`
hops (direct predecessors are depth 1), ordered by address with
shortest distance under the page envelope. Any address is a valid
root — data and string targets lie in no function. `callers` climbs
from the sink function toward its callers out to `--depth` hops.
Depth past the 64-hop cap is an `Invalid` error; zero yields an
empty page.

MCP: `slice` (`binary`, `addr`, `depth?`), `callers` (`binary`,
`addr`, `depth?`).

## 5. Mark the sink

```sh
$ binscout annotate fw.exe 0x401000 --comment "handles SAVE marker; reached via string xref"
```

`comment` accepts any address; `rename` only known function entries.
Querying (`strings`, `xrefs`, `slice`, `callers`) never writes a
sidecar — only `annotate` (or MCP `rename` / `comment`) persists.

## Failure modes

- `strings` with no hits: widen `--pattern` (substring, not glob),
  lower `--min-len`, or drop `--section` before concluding the
  string is absent or obfuscated.
- `xrefs --to` with `total: 0`: the string is unreferenced dead
  data — check `--kind data` without the kind filter before
  assuming the address is wrong.
- `slice` past the depth cap: `Invalid` — lower `--depth` and page
  outward instead.

See [CLI reference](cli-reference.md) for flag details and
[JSON protocol](json-protocol.md) for the page envelope.
