# Architecture

One engine, two interfaces. Data flows one way — loader, disassembler,
IR, analysis, database — and both the CLI (`binscout`) and the MCP server
(`binscout-mcp`) are thin adapters over it.

- **Loader** (`loader`): sniffs ELF, PE, Mach-O, and LE, falling back to
  flat raw bytes with a caller-supplied architecture and base. Produces
  segments, sections, imports/exports, and printable strings (ASCII plus
  UTF-16LE/BE over the ASCII subset).
- **Disassembler** (`disasm`): x86_64 and 32-bit x86 via iced-x86, AArch64
  via yaxpeax-arm. Each instruction becomes an `Insn` with its bytes,
  mnemonic, operand strings, and resolved branch/data targets.
- **IR** (`ir`): lifts one instruction to one P-code-inspired `IrInsn`
  (`COPY`, `LOAD`, `BRANCH`, `CALL`, ...). Unknown mnemonics become `NOP`
  with a warning instead of failing, so analysis proceeds over partial
  lifts.
- **Analysis** (`analysis`): recursive descent from the entry point and
  export addresses over decoded instructions, plus a prologue scan for
  functions unreachable from those seeds. Builds per-function CFGs, a
  callgraph, and code/data/string cross-references.
- **Database** (`db`): caches the snapshot and the user annotations in a
  `redb` sidecar; see [Sidecar format](sidecar-format.md). A content hash
  gates reuse — a changed binary is re-analyzed.
