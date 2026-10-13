# Contributing

The full guide lives in
[CONTRIBUTING.md](https://github.com/mimi1vx/binscout/blob/master/CONTRIBUTING.md).
The short version — the gate for any change:

```sh
cargo test          # full suite (unit + CLI/MCP e2e over fixtures)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo doc --no-deps # warning-free (`#![warn(missing_docs)]` is on)
```

Work is tracked as issues; file bugs and feature requests on GitHub and
keep changes small and scoped. The project is dual-licensed MIT OR
Apache-2.0 — new files carry no headers, the license applies repo-wide.
