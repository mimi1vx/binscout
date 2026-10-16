# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1](https://github.com/mimi1vx/binscout/compare/v0.5.0...v0.5.1) - 2026-10-16

### Other

- document supply-chain policy in CONTRIBUTING.md
- add weekly cargo-deny supply-chain workflow
- add cargo-deny supply-chain policy with scoped duplicate skips

## [0.5.0](https://github.com/mimi1vx/binscout/compare/v0.4.0...v0.5.0) - 2026-10-16

### Added

- add approximate pseudo-C rendering over IR
- add approximate structured-view over IR (loops/ifs JSON)
- add bounded jump-table recovery for guarded scaled-index switches
- add type-hint comments for struct layout as structured comments
- add bindiff-lite function-level diff between binaries
- add backward slicing to to-addr
- add FLIRT-like library-function hints (read-only)
- add scoped flag/stack-pointer effects to IR
- add COFF loader support via object FileKind
- add read-only string decode view for XOR/add/rot
- add depth-bounded transitive callgraph queries
- expand IR coverage for FPU/SIMD/crypto/system mnemonics

### Other

- sync README and book with current tools, drop performance decision record
- add headless agent cookbook (find-main, trace-string, audit-imports)
- correct MCP tool count to 24 after slice and flirt-hints
- Merge branch 'wip/ljy6-slicing'
- Merge branch 'wip/ljy7-flirt'

## [0.4.0](https://github.com/mimi1vx/binscout/compare/v0.3.0...v0.4.0) - 2026-10-15

### Added

- resolve single-slot absolute indirect jumps with bounded evidence
- expose annotation transfer through CLI and MCP
- add byte-pattern search CLI command and MCP tool
- expose paged diagnostics and function discovery provenance
- publish machine-readable IR coverage and per-range lift accounting
- implement identity-checked atomic annotation export/import
- implement bounded literal/wildcard byte search over mapped bytes
- make CLI/MCP function inspection bounded by default
- capture and persist analysis diagnostics and discovery evidence
- expose explicit raw mapping and bounded function pages
- make snapshot reuse raw-mapping aware

### Fixed

- reject uppercase annotation digests as malformed identity
- keep indirect-jump sites single-visit in release builds
- tolerate empty blocks and missing functions in analysis

### Other

- enforce doc warnings and cancel superseded runs
- ignore local _testdata LE oracle corpus
- include inferred-code in MCP xrefs kind filter
- publish agent-first migration guidance and release notes
- record measured MCP optimization no-go
- benchmark repeated MCP investigation workflows
- normalize import ordering per rustfmt
- freeze protocol-1 JSON/CLI/MCP contract

## [0.3.0](https://github.com/mimi1vx/binscout/compare/v0.2.1...v0.3.0) - 2026-10-14

### Added

- analyze x86 LE (DOS4GW) binaries instead of refusing them
- LE discovery with scan fallback for DOS4GW outer MZ

### Fixed

- persist block layouts instead of rendered instructions
- contain yaxpeax-arm decode panics as Error::Invalid

### Other

- sync README and book with function filters, paging caps, and current output

## [0.2.1](https://github.com/mimi1vx/binscout/compare/v0.2.0...v0.2.1) - 2026-10-14

### Added

- decode only first instruction via disasm_first

### Fixed

- enforce input and aggregate metadata memory budgets
- keep LE length-prefixed names inside declared tables
- bound memory, remove analysis bottlenecks, harden tail reads

### Other

- cache cargo builds and group dependabot updates
- chore(deps) minor versions update
- avoid cloning whole result sets for paged queries
- skip stale snapshot decoding after metadata mismatch
- reuse one lazy matcher per string-search query
- index LE import identity instead of Vec membership scans

## [0.2.0](https://github.com/mimi1vx/binscout/compare/v0.1.1...v0.2.0) - 2026-10-13

### Added

- *(stats)* DB stats command, size gate, and sidecar docs
- *(disasm)* arm32/thumb support and dual addr_hex encoding
- *(disasm)* partial prefix decode with error_at instead of abort (D2/A6)
- *(symbols)* ordinal imports with unresolved flag + C++ demangle (L3/A8)
- *(sections)* sections tool + addr-mapping truth (L2/A2)
- *(strings)* pattern/min-len/section filters + start paging (D3/A7)
- *(xrefs)* absolute imm32 data + string xref recovery (X2/A4)
- *(functions)* mid-function snap + query/caller/callee/range filters

### Fixed

- close attacker-reachable panics and correct IR classification
- xrefs total-count envelope + normalization lock-in (X1/A3)
- LE explicit-unsupported, kill raw-fallback mis-parse (L1/A1)

### Other

- *(ir)* cover lift_arm32 in ISA coverage docs
- *(deps)* bump actions/upload-pages-artifact from 3 to 5
- *(deps)* bump actions/checkout from 4 to 7
- *(deps)* bump actions/deploy-pages from 4 to 5
- add dependabot for cargo and github-actions
- add binscout agent instructions to AGENTS.md
- *(fixtures)* synthetic PE32/LE/garbage fixtures + harness (F0)

## [0.1.1](https://github.com/mimi1vx/binscout/compare/v0.1.0...v0.1.1) - 2026-10-13

### Other

- crates.io install and conventional-commit note
- add release-plz config and OIDC workflow
