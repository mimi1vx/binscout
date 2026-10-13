# binscout — agent instructions

Rust crate `binscout` (edition 2024). Two binaries: `binscout` (JSON CLI, `src/main.rs` → `src/cli.rs`) and `binscout-mcp` (`src/bin/binscout-mcp.rs` → `src/mcp.rs`). Core API is `Project` in `src/lib.rs`; modules: `analysis`, `db` (redb sidecar), `disasm`, `ir`, `loader` (+ `loader/le`, `loader/strings`), `error`, `mcp`.

## Gate (in this order)

```sh
cargo test                              # unit + CLI/MCP e2e, hermetic synthetic fixtures
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo doc --no-deps                     # must be warning-free; `#![warn(missing_docs)]` is on
```

Same four run in `.github/workflows/ci.yml`. Releases via release-plz (`release-plz.toml`): `feat:` → minor, `fix:` → patch, other types → no release — write Conventional Commits accordingly.

## Contracts agents get wrong

- CLI prints exactly one JSON value to stdout per command; runtime failure prints `{"error": "..."}` with exit 1 (clap usage errors go to stderr, exit 2). Keep it that way.
- Never write the analyzed binary. Only write is the redb sidecar, default `<binary>.rsdbg.redb`, overridable with global `--db PATH`. `load` opens + saves snapshot; other read commands open without saving; `rename`/`comment` persist immediately.
- `rename` only accepts known function entries (`Error::NotFound` otherwise); `comment` accepts any address. Empty string clears. Addresses parse as `0x`-hex or decimal (`parse_addr`).
- Unrecognized bytes fall back to raw x86-64 at base 0 (`load_or_raw`); only `Error::Invalid` falls back — unsupported arch/format still errors. LE uses the custom `loader/le` reader (`object` crate has no LE support). Supported disasm arches: x86_64, x86_32, aarch64, arm32, thumb (ARM ELF containers default to arm32; Thumb via raw mapping).
- Caps: `loader.rs` `MAX_SEGMENTS/SECTIONS/MAPPED_BYTES(256MiB)/IMPORTS/EXPORTS`; `lib.rs` `MAX_RANGE_BYTES` (1 MiB per `bytes_at`) and `MAX_ROWS` (1024 per paged query).
- Tests: use `tests/common/mod.rs` helpers (`write_fixture` + `temp_db` / `open_test_project`) so fixture dirs stay clean of sidecars; binaries via `CARGO_BIN_EXE_binscout` and sibling `mcp_bin()`. New behavior needs a test in `tests/`; new public API needs rustdoc; new files carry no license headers; keep diffs scoped (CONTRIBUTING.md).

<!-- br-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`/`bd`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

### Essential Commands

```bash
# View ready issues (open, unblocked, not deferred)
br ready              # or: bd ready

# List and search
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br search "keyword"   # Full-text search

# Create and update
br create --title="..." --description="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason="Completed"
br close <id1> <id2>  # Close multiple issues at once

# Sync with git
br sync --flush-only  # Export DB to JSONL
br sync --status      # Check sync status
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Always run `br sync --flush-only` at session end

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only open, unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers 0-4, not words)
- **Types**: task, bug, feature, epic, chore, docs, question
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads changes to JSONL
git commit -m "..."     # Commit everything
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always sync before ending session

<!-- end-br-agent-instructions -->
