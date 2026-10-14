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

Work is tracked with `br`/`bd` issues; file bugs and feature requests as
issues first and keep changes small and scoped. Commits follow
[Conventional Commits](https://www.conventionalcommits.org/): `feat:`
bumps minor, `fix:` bumps patch. New behavior needs a test; new public
API needs rustdoc. The project is dual-licensed MIT OR
Apache-2.0 — new files carry no headers, the license applies repo-wide.
