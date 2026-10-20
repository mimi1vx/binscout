# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0](https://github.com/mimi1vx/binscout/compare/v0.7.0...v0.8.0) - 2026-10-20

### Added

- MIPS lui+addiu/addu/lw pair resolution (rsdbg-e1eu)
- MIPS lui+addiu/addu/lw pair resolution (rsdbg-e1eu)
- RISC-V auipc pair resolution for exact global addresses (rsdbg-6ea4)
- full PowerPC 32/64 support via powerpc crate (rsdbg-9syq)
- MIPS32 support via rabbitizer (rsdbg-1wik)
- PowerPC 32/64 decode skeleton via powerpc crate (rsdbg-9syq)
- RISC-V 32/64 support via rvdasm (rsdbg-78i2)
- DWARF and PDB debug info seeds names and bounds
- ARM/Thumb interworking inside ELF plus movw/movt pair resolution
- recover switch tables in real binaries (PIE, MSVC, ARM, AArch64)
- decode x86 structured operands and resolve const indirect calls
- lay relocatable objects at synthetic addresses, apply relocations
- YARA rule scanning via yara-x behind optional yara feature
- patch export without writing the binary (rsdbg-em6.25)
- type-hint CLI/MCP surface and typed bytes view (rsdbg-em6.22)
- user signature files, sig-gen, Go pclntab recovery (rsdbg-em6.17)
- diff-func block deltas, match propagation, rename transfer, paging (rsdbg-em6.16)
- seed functions from .pdata, TLS callbacks, init arrays, LC_FUNCTION_STARTS, pointer scan (rsdbg-em6.12)
- noreturn call handling with propagation (rsdbg-em6.10)
- string coverage UTF-8/BMP, rolling XOR, base64, stack strings (rsdbg-em6.18)
- MCP batch tool for one-open read fan-out (rsdbg-em6.20)
- Mach-O chained fixups stub mapping (rsdbg-em6.15)
- CLI/MCP parity fixes and opt-in envelope preview (rsdbg-em6.27)
- header metadata command and MCP tool (rsdbg-em6.19)
- user-defined function seeds persisted in sidecar
- enrich xref rows and add strings --with-xrefs
- enrich listings and pseudo-C with names, comments, string previews
- add per-section entropy and crypto-constant scan
- emit machine-readable error kinds in CLI and MCP
- bytes/hexdump command with typed views and VA<->file offset
- x86-64 absolute imm32/disp32 operands as data refs (non-PIE)

### Fixed

- use hardware PC for Thumb 16-bit cond-branch and cbz/cbnz targets
- include entropy in cached sections rows, cover with parity test
- translate Mach-O LC_MAIN entryoff to VA
- re-apply fmt normalization reverted on two lines
- integrate with master API (DecodeSpec by value, 35-tool count, batch stack_strings, fmt)
- *(diff)* fingerprint xref scan and fuzzy pass with retain
- Mach-O stub addresses resolve via indirect symbol table by name
- ownership of blocks below first entry consistent (function_owner vs containing_function)
- snapshot identity — carry sha256/len, gate stale annotations, exclude binary_path from meta equality
- canonicalize fat-slice cache identity and reject fat-arch on thin binaries

### Other

- restore rustfmt import order in tests/ir.rs (rsdbg-6ea4)
- fix disassembler mode count and MIPS fixture comments
- fix deny gate for yara-x subtree
- tombi format Cargo.toml (gimli feature order)
- rustfmt fallout from em6.23 merge; chore: close em6.9, em6.13, em6.21, em6.23
- Merge work/em6.23-debuginfo: DWARF and PDB debug info seeds names and bounds (rsdbg-em6.23)
- Merge work/em6.9-jumptables: switch-table recovery for real binaries (rsdbg-em6.9)
- Merge work/em6.13-thumb: ARM/Thumb interworking plus movw/movt pair resolution (rsdbg-em6.13)
- pin ordered-lookup helpers to collecting predecessors (5tk.11)
- fix comment alignment in tests/fixtures/builders.rs
- Merge wt/yara-scan: YARA rule scanning via yara-x (rsdbg-em6.26)
- Merge work/em6.5: enrich xref rows and strings with-xrefs (rsdbg-em6.5)
- Merge work/em6.7: per-section entropy and crypto-constant scan (rsdbg-em6.7)
- Merge work/em6.8: emit machine-readable error kinds (rsdbg-em6.8)
- Merge work/5tk.11: replace linear scans with ordered lookups (rsdbg-5tk.11)
- Merge work/5tk.13: scope flirt-hints and caller/callee filters to anchor sets (rsdbg-5tk.13)
- Merge work/5tk.5: fingerprint xref scan and fuzzy pass with retain (rsdbg-5tk.5)
- Merge work/em6.22: type-hint CLI/MCP surface and typed bytes view (rsdbg-em6.22)
- Merge work/em6.17: user signature files, sig-gen, Go pclntab recovery (rsdbg-em6.17)
- allow BSL-1.0 license for xxhash-rust
- Section metadata-only, resolve bytes via segments (rsdbg-5tk.9, part 2)
- lazy SHA-256, xxh3 content hash, single-alloc open (rsdbg-5tk.9, part 1)
- Merge master into work/em6.18 (em6.15, em6.20, 5tk.3)
- Merge master into work/5tk.3 (em6.15, em6.20)
- staged loader-only open skipping cache-hit re-decode (rsdbg-5tk.3)
- Merge work/em6.27: CLI/MCP parity fixes and opt-in envelope (rsdbg-em6.27)
- compact binary sidecar encoding (rsdbg-5tk.8)
- Merge work/em6.11: user-defined function seeds (rsdbg-em6.11)
- memchr-anchored prologue scan and rarest-literal search anchor
- skip sidecar rewrite on cache-hit load and compact after rewrite
- scope flirt-hints and caller/callee filters to anchor sets
- rustfmt tests/xref_index.rs after merge
- Merge work/em6.6: enriched listings and pseudo-C (rsdbg-em6.6)
- Merge work/5tk.7: allocation-free control-flow lookup (rsdbg-5tk.7)
- allocation-free control-flow lookup via ir::control_op
- index xref queries with binary search and lazy to-index
- replace linear scans on hot query paths with ordered lookups
- reuse x86 formatter scratch across single-instruction decodes
- fix strings/decode, fat_arch, AddrParams, and performance drift

## [0.7.0](https://github.com/mimi1vx/binscout/compare/v0.6.0...v0.7.0) - 2026-10-17

### Added

- name ELF PLT and PE IAT import call sites with import xrefs
- seed and name functions from object symbol tables

### Fixed

- document FuncRow.name as rename-resolved
- scope arch-less FLIRT signatures to x86
- handle EPIPE on stdout without panicking
- ARM32 Load/Store IR I/O split and bracket-aware split_asm
- count diff summary before truncation
- make annotate rename+comment atomic
- repair merge resolutions for MCP cache and ARM seed work
- ARM32 pc-writes, Thumb IT blocks, Thumb-bit seeds
- mask ARM Thumb interworking bit on entry and export seeds
- predicate Thumb terminators inside IT blocks
- treat ARM32 writes to pc as control flow
- resolve indirect jumps from a worklist with a shared gate
- reject --db paths resolving to the analyzed binary
- scale ARM blx immediates as halfwords and align Thumb PC
- lift AArch64 pointer-auth branches and returns
- strip CET/MPX/HLE prefix words so x86 branches lift correctly

### Other

- cache MCP project opens in a 4-entry LRU with per-sidecar locks
- cache MCP project opens in a 4-entry LRU with per-sidecar locks
- apply cargo fmt to ARM control-flow fixes

## [0.6.0](https://github.com/mimi1vx/binscout/compare/v0.5.1...v0.6.0) - 2026-10-16

### Added

- select fat Mach-O slices via --fat-arch
- map macOS stubs to imports and name stub functions
- [**breaking**] rename slice address field to->addr
- resolve ARM64 adrp pairs in xrefs, IR and pseudo

### Fixed

- append-suffix sidecar naming

### Other

- reconcile docs with fat-slice, stub, adrp and sidecar changes
- changelog for five-issue fixes

### Changed

- BREAKING: `slice` address field renamed `to` -> `addr` (CLI positional `binscout slice B ADDR`, MCP `slice` param `addr`, `slice_page(addr)` / `slice_to(addr)`); no `to` alias is kept.
- sidecar database now appends instead of replacing the extension (`foo.exe` -> `foo.exe.rsdbg.redb`), so same-named binaries with different extensions no longer share a sidecar; there is no fallback to the old path.

### Added

- select fat Mach-O slices with global `--fat-arch ARCH` (CLI) / `fat_arch` (MCP); fat inputs without it error listing the available archs.
- resolve Mach-O `__stubs`/`__auth_stubs` entries to imports: stub functions carry import names and `symbols` import rows carry `address`/`address_hex` (conservative — unmapped imports stay null, never misattributed).
- resolve ARM64 `adrp`+`add`/`ldr` pairs to the final address in xrefs (`Data`/`String`), IR rows (`target`), and pseudo-C (`// => 0x...`); the page-base xref row is retained.

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
