# MCP tools

`binscout-mcp` serves 11 tools over stdio (newline-delimited JSON-RPC).
Each takes `binary` plus an optional `db` path and returns one JSON
document as text; failures are tool errors. Attach it to any MCP client:

```json
{
  "mcpServers": {
    "binscout": { "command": "/path/to/binscout-mcp" }
  }
}
```

| Tool | Parameters | Does |
|---|---|---|
| `project_info` | binary | Open a binary and report arch, format, entry, and analysis counts |
| `functions` | binary, offset/limit | List functions with rename-resolved names, paged |
| `func` | binary, addr | Full detail of one function: blocks with instructions, edges, calls |
| `disasm` | binary, addr, len | Disassemble `len` bytes at `addr` with the binary architecture |
| `cfg` | binary, addr | Control-flow graph of one function: block nodes plus block edges |
| `xrefs` | binary, to/from/kind, offset/limit | Cross-references filtered by endpoint and kind, paged |
| `strings` | binary, pattern/min-len/section/include_code, start/limit | Extracted strings ordered by address, filtered and paged; executable-memory hits hidden unless `pattern`, `section`, or `include_code` is given |
| `symbols` | binary | Imports and exports of the binary |
| `ir` | binary, addr, len | Lift `len` bytes at `addr` to P-code-inspired IR |
| `rename` | binary, addr, name | Rename a function in the project DB (binary untouched); empty name clears |
| `comment` | binary, addr, comment | Comment any address in the project DB (binary untouched); empty comment clears |

Addresses are `0x`-hex or decimal strings. `kind` is one of `code`,
`data`, or `string`. Calls are serialized behind one lock because `redb`
allows a single open handle per file per process.
