# Installation

Requires a Rust toolchain (stable).

From the Git repository:

```sh
cargo install --git https://github.com/mimi1vx/binscout
```

Or from a checkout:

```sh
git clone https://github.com/mimi1vx/binscout
cd binscout
cargo install --path .
```

This installs two binaries: `binscout` (the JSON CLI) and `binscout-mcp`
(the MCP server). Verify with:

```sh
binscout --help
```
