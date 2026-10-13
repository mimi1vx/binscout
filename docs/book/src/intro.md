# Introduction

binscout is headless, agent-first binary analysis. Open a binary —
ELF, PE, Mach-O, LE, or flat raw bytes — and get functions, control-flow
graphs, cross-references, strings, symbols, and IR out.

There are two interfaces over the same engine:

- `binscout`, a JSON CLI: every command prints exactly one JSON value to
  stdout.
- `binscout-mcp`, an MCP server over stdio with 12 tools, one per
  capability.

Annotations (function renames, free-text comments) live in a `redb`
sidecar next to the binary. The analyzed binary is never written.

Start with [Installation](install.md), then the
[CLI reference](cli-reference.md).
