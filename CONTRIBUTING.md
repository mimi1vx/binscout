# Contributing to binscout

## Gate

Every change must pass all four locally before review:

```sh
cargo test                              # unit + CLI/MCP e2e over fixtures
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo doc --no-deps                     # warning-free; `#![warn(missing_docs)]` is on
```

## Supply chain

```sh
cargo deny check                        # licenses, advisories, bans, sources per deny.toml
```

License allow-list (`[licenses] allow` in `deny.toml`): MIT,
Apache-2.0, 0BSD, Unlicense, Zlib, Unicode-3.0, NCSA,
LGPL-2.1-or-later. A new license fails the check; add it to `allow`
with a justification comment naming the crate that pulls it in.

Duplicates (`[bans] multiple-versions = "deny"`, wildcards denied):
run `cargo update` first. If versions cannot converge, add a scoped
`[[bans.skip]]` with reason + upstream link + revisit note. Current
skips: syn 2/3 (major-version ecosystem split; tracing/windows chains
still pin 2, rest of graph on 3) and hashbrown 0.15.5/0.17.1 (blocked
on petgraph unifying its direct pin vs indexmap range).

CI (`.github/workflows/deny.yml`: PR + push to master + weekly Mon
06:00 UTC) fails on any `cargo deny check` error. Advisories always
fail on vulnerabilities; yanked is set to deny. Unused skip entries
warn, so remove them once `cargo update` converges the duplicate.

## Issues

Work is tracked with [beads](https://github.com/Dicklesworthstone/beads_rust)
(`br`/`bd`, stored in `.beads/`):

```sh
br ready                    # find unblocked work
br update <id> --status=in_progress
br close <id> --reason="..."
br sync --flush-only         # export before commit
```

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/).
Releases are automated by [release-plz](https://release-plz.dev), which
derives the version bump from merged commit messages: `feat:` triggers a
minor bump, `fix:` a patch bump. `chore:`, `docs:`, `test:`, and
`refactor:` trigger no release, so vague messages (`update stuff`)
produce wrong or missing bumps.

## Pull requests

- Keep changes small and scoped; every changed line should trace to the
  issue. Don't reformat adjacent code.
- File bugs and feature requests as issues first so there is a record.
- New behavior needs a test (see `tests/`); new public API needs rustdoc.

## License

Dual MIT OR Apache-2.0, applied repo-wide (`LICENSE-MIT`,
`LICENSE-APACHE`). New files carry no license headers.
