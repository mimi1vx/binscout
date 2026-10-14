# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
