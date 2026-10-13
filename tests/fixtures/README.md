# fixtures (F0)

Synthetic, license-clean binaries built from scratch by `builders.rs` (pure
`Vec<u8>` manipulation, fixed timestamps, no randomness). Checked-in blobs
are byte-identical to builder output (`fixture_blobs_byte_identical` in
`tests/scaffold.rs`); regenerate with
`FIXTURE_REGEN=1 cargo test --test scaffold`.

All PE32 fixtures: `I386`, `ImageBase 0x400000`, `.text` at `0x401000`,
`.rdata` at `0x402000`, `.data` at `0x403000`.

- `raw-x64.bin`: 3 bytes `nop; nop; ret` for raw-mode loader tests (M1).
- `pe32-basic.exe`: entry func (`push ebp; mov ebp,esp; 2x push imm32; ret`),
  one export (`basic_entry`), marker `SAVE%d.GAM is invalid` at `0x402100`
  referenced twice, writable `DATA_FIXTURE_SEED` in `.data`. Ground truth for
  X2/A4 (`le32_refs` helper in `tests/common/mod.rs` expects exactly 2 refs).
- `pe32-ordinals.exe`: imports `TESTDLL.dll!#1`, `#2` (ordinal-only) plus
  `?myfunc@@YAXH@Z` (C++ mangled). Ground truth for L3/A8.
- `le-unsupported.exe`: minimal MZ->LE image (one R-X object, entry bundle).
  Loader-level truth; L1/A1 makes `Project::open` reject it.
- `text-garbage.bin`: x86-64 prologue, invalid opcode `0xD6`, noise strings
  `VWf3` and `D$ f`, trailing nops+ret. Decode-stop truth for D2/A6,
  byte-noise truth for D3/A7.

Helpers in `tests/common/mod.rs`: `fixture_bytes` (build from scratch),
`write_fixture` / `open_test_project` (hermetic temp-dir open), `le32_refs`
(absolute-imm32 ground-truth scan).
