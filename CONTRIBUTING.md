# Contributing to binscout

## Gate

Every change must pass all four locally before review:

```sh
cargo test                              # unit + CLI/MCP e2e over fixtures
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo doc --no-deps                     # warning-free; `#![warn(missing_docs)]` is on
```

## Issues

Work is tracked with [beads](https://github.com/Dicklesworthstone/beads_rust)
(`br`/`bd`, stored in `.beads/`):

```sh
br ready                    # find unblocked work
br update <id> --status=in_progress
br close <id> --reason="..."
br sync --flush-only         # export before commit
```

## Pull requests

- Keep changes small and scoped; every changed line should trace to the
  issue. Don't reformat adjacent code.
- File bugs and feature requests as issues first so there is a record.
- New behavior needs a test (see `tests/`); new public API needs rustdoc.

## License

Dual MIT OR Apache-2.0, applied repo-wide (`LICENSE-MIT`,
`LICENSE-APACHE`). New files carry no license headers.
