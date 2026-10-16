# Architecture

One engine, two interfaces. Data flows one way — loader, disassembler,
IR, analysis, database — and both the CLI (`binscout`) and the MCP server
(`binscout-mcp`) are thin adapters over it.

- **Loader** (`loader`): sniffs ELF, PE, Mach-O, COFF, and LE, falling back to
  flat raw bytes when nothing matches: unrecognized input opens as
  x86-64 at base 0, LE images analyze as 32-bit x86. Explicit
  base/architecture mapping goes through `open_raw`, exposed as CLI
  `--raw --arch ARCH --base ADDR [--entry ADDR]` and the MCP `raw`
  object on every binary-taking tool. Produces
  segments, sections, imports/exports, and printable strings (ASCII plus
  UTF-16LE/BE over the ASCII subset). Inputs over 512 MiB are rejected
  before parsing.
- **Disassembler** (`disasm`): x86_64 and 32-bit x86 via iced-x86, AArch64,
  32-bit ARM, and Thumb via yaxpeax-arm. Each instruction becomes an `Insn` with its bytes,
  mnemonic, operand strings, and resolved branch/data targets
  (including typed absolute-slot targets for single-slot indirect
  jumps, which the resolver below consumes).
- **IR** (`ir`): lifts one instruction to one P-code-inspired `IrInsn`
  (`COPY`, `LOAD`, `BRANCH`, `CALL`, ...). Unknown mnemonics become `NOP`
  with a warning instead of failing, so analysis proceeds over partial
  lifts. `ir_coverage` reports the implemented opcode families,
  explicit partial mappings, and limits (operand strings, flags,
  stack/calling-convention effects, no SSA/PHI) without opening a
  binary; with a range it adds decoded/lifted/unlifted counts from
  actual lifts.
- **Analysis** (`analysis`): recursive descent from the entry point and
  export addresses over decoded instructions, plus a prologue scan for
  functions unreachable from those seeds. Builds per-function CFGs, a
  callgraph, and code/data/string cross-references. Records discovery
  `reasons` per function (`entry`, `export`, `direct-call`,
  `prologue`), retains bounded diagnostics (unresolved indirect
  sites, decode failures; 100,000-record cap with truncation counts),
  and resolves single-slot absolute indirect jumps and guarded
  scaled-index tables in raw mappings to
  provenance-marked `inferred-code` edges and xrefs (one edge per
  single-slot site, 2–8 slots per table site, 100,000 per project;
  unprovable sites stay unresolved and
  edgeless). Analysis revision 4; older snapshots re-analyze.
- **Search** (`search`): bounded literal/`??`-wildcard scan over mapped
  file-backed bytes (pattern cap 4096 bytes, 256 MiB scan cap,
  1024-row pages; gaps never bridged, BSS never materialized).
- **Annotations** (`annotations`): versioned JSON export/import
  (revision 1, SHA-256 + size + mapping identity, 16 MiB document
  cap, atomic all-or-nothing merge with fail-on-conflict default).
- **Database** (`db`): caches the snapshot and the user annotations in a
  `redb` sidecar; see [Sidecar format](sidecar-format.md). Cache
  identity covers content, loader mapping, and analysis revision —
  a changed binary, a different raw mapping, or an older schema
  (current version 5) re-analyzes instead of replaying layouts.
