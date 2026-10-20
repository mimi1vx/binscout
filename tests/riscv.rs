//! rsdbg-78i2: RISC-V 32/64 end-to-end coverage.
//!
//! - ELF `EM_RISCV` containers map to `Riscv64` (and decode through it).
//! - A synthetic RV64 function analyzes with exact function/block counts,
//!   with `jal`/`jalr` split into call/branch/return by operand.
//! - `addi sp, sp, <imm>` prologue seeds discovery when no entry is set.
//! - Traps and compressed forms decode under their canonical names.
//! - `auipc`+`addi`/`lw`/`sw` pairs resolve exact globals with data and
//!   string xrefs, plus IR/pseudo annotation like the `adrp` path.

mod common;

use binscout::analysis::{DiscoveryReason, XrefKind, analyze};
use binscout::disasm::{Arch, disasm_range};
use binscout::ir::lift_range;
use binscout::loader::{BinaryFormat, LoadedBinary, Segment, load};
use binscout::pseudo::render_function;

fn text_seg(vaddr: u64, code: Vec<u8>) -> Segment {
    Segment {
        vaddr,
        mem_size: code.len() as u64,
        data: code,
        readable: true,
        writable: false,
        executable: true,
    }
}

fn rv64_bin(entry: Option<u64>, code: Vec<u8>) -> LoadedBinary {
    rv64_bin_segs(entry, vec![text_seg(0x10000, code)])
}

fn data_seg(vaddr: u64, size: usize, at: usize, bytes: &[u8]) -> Segment {
    let mut data = vec![0u8; size];
    data[at..at + bytes.len()].copy_from_slice(bytes);
    Segment {
        vaddr,
        mem_size: data.len() as u64,
        data,
        readable: true,
        writable: true,
        executable: false,
    }
}

fn rv64_bin_segs(entry: Option<u64>, segments: Vec<Segment>) -> LoadedBinary {
    LoadedBinary {
        format: BinaryFormat::Elf,
        arch: Arch::Riscv64,
        entry,
        segments,
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        symbols: Vec::new(),
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        debug_funcs: Vec::new(),
        relocatable: false,
        arm_hints: Default::default(),
    }
}

/// `main` calls `leaf`, restores the frame, and returns:
/// - `0x10000`: `addi sp, sp, -16`
/// - `0x10004`: `jal ra, +16` (leaf at `0x10014`)
/// - `0x10008`: `lw a0, 0(sp)`
/// - `0x1000c`: `addi sp, sp, 16`
/// - `0x10010`: `ret`
/// - `0x10014` (leaf): `addi a0, a0, 1; ret`
fn main_and_leaf() -> Vec<u8> {
    vec![
        0x13, 0x01, 0x01, 0xFF, // 0x10000: addi sp, sp, -16
        0xEF, 0x00, 0x00, 0x01, // 0x10004: jal ra, +16 -> 0x10014
        0x03, 0x25, 0x01, 0x00, // 0x10008: lw a0, 0(sp)
        0x13, 0x01, 0x01, 0x01, // 0x1000c: addi sp, sp, 16
        0x67, 0x80, 0x00, 0x00, // 0x10010: ret
        0x93, 0x05, 0x15, 0x00, // 0x10014: addi a0, a0, 1 (leaf)
        0x67, 0x80, 0x00, 0x00, // 0x10018: ret
    ]
}

#[test]
fn riscv64_elf_container_maps_and_decodes() {
    // Same headers with a RISCV machine id: parses to the Riscv64 target.
    let mut elf = common::minimal_elf();
    elf[18..20].copy_from_slice(&243u16.to_le_bytes());
    let bin = load(&elf).expect("riscv ELF must load");
    assert_eq!(bin.format, BinaryFormat::Elf);
    assert_eq!(bin.arch, Arch::Riscv64);
}

#[test]
fn riscv_call_splits_callee_and_returns() {
    let bin = rv64_bin(Some(0x10000), main_and_leaf());
    let a = analyze(&bin).expect("rv64 analyzes");
    assert_eq!(a.functions.len(), 2);
    let main = &a.functions[&0x10000];
    // The jal call edge splits the block: call block plus tail.
    assert_eq!(main.blocks.len(), 2);
    let leaf = &a.functions[&0x10014];
    assert_eq!(leaf.blocks.len(), 1);
    // The jal becomes a call edge to the leaf, not a fallthrough block.
    assert!(a.calls_of(0x10000).contains(&0x10014));
}

#[test]
fn riscv_prologue_seeds_discovery_without_entry() {
    // Entry at the leaf: main is unreachable from it, so only the
    // prologue scan (addi sp, sp, -16) finds main.
    let bin = rv64_bin(Some(0x10014), main_and_leaf());
    let a = analyze(&bin).expect("rv64 analyzes");
    assert!(a.functions.contains_key(&0x10000), "prologue seeds main");
    assert!(a.functions.contains_key(&0x10014), "call target found");
    let main = &a.functions[&0x10000];
    assert!(
        main.reasons.contains(&DiscoveryReason::Prologue),
        "main carries a prologue reason, got {:?}",
        main.reasons
    );
}

fn has_xref(a: &binscout::analysis::Analysis, from: u64, kind: XrefKind, to: u64) -> bool {
    a.xrefs
        .iter()
        .any(|x| x.from == from && x.kind == kind && x.to == to)
}

#[test]
fn riscv_trap_and_compressed_decode() {
    // ecall traps; ebreak and c.ebreak are its breakpoint forms.
    for (bytes, mnem) in [
        (&[0x73, 0x00, 0x00, 0x00][..], "ecall"),
        (&[0x73, 0x00, 0x10, 0x00][..], "ebreak"),
        (&[0x02, 0x90][..], "c.ebreak"),
    ] {
        let v = disasm_range(Arch::Riscv64, bytes, 0x10000, 8).expect("decodes");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mnem, mnem, "{bytes:02x?}");
    }
}

#[test]
fn auipc_pairs_yield_data_and_string_xrefs() {
    // Three pairs resolve the same string global at 0x12034; each auipc
    // row keeps its page fallback.
    let text = vec![
        0x17, 0x25, 0x00, 0x00, // 0x10000: auipc a0, 2 (page 0x12000)
        0x03, 0x25, 0x45, 0x03, // 0x10004: lw a0, 52(a0) -> 0x12034
        0x97, 0x25, 0x00, 0x00, // 0x10008: auipc a1, 2 (page 0x12008)
        0x93, 0x85, 0xC5, 0x02, // 0x1000c: addi a1, a1, 44 -> 0x12034
        0x17, 0x26, 0x00, 0x00, // 0x10010: auipc a2, 2 (page 0x12010)
        0x23, 0x22, 0xA6, 0x02, // 0x10014: sw a0, 36(a2) -> 0x12034
        0x67, 0x80, 0x00, 0x00, // 0x10018: ret
    ];
    let bin = rv64_bin_segs(
        Some(0x10000),
        vec![
            text_seg(0x10000, text),
            data_seg(0x12000, 0x100, 0x34, b"riscv-pair-string\0"),
        ],
    );
    let a = analyze(&bin).expect("rv64 analyzes");
    assert_eq!(a.functions.len(), 1);
    assert!(
        has_xref(&a, 0x10000, XrefKind::Data, 0x12000),
        "auipc page fallback"
    );
    for site in [0x10004, 0x1000c, 0x10014] {
        assert!(
            has_xref(&a, site, XrefKind::Data, 0x12034),
            "pair at {site:#x} references the combined address"
        );
        assert!(
            has_xref(&a, site, XrefKind::String, 0x12034),
            "combined address inside a string yields a string ref"
        );
    }
    let f = a.functions.get(&0x10000).expect("function");
    let owned: Vec<binscout::disasm::Insn> =
        f.blocks.values().flat_map(|b| b.insns.clone()).collect();
    let rows = lift_range(Arch::Riscv64, &owned);
    assert_eq!(rows.len(), owned.len());
    for (idx, row) in [(1, 0x10004), (3, 0x1000c), (5, 0x10014)] {
        assert_eq!(
            rows[idx].target,
            Some(0x12034),
            "second pair row at {row:#x} lifts with the resolved address"
        );
    }
    let render = render_function(Arch::Riscv64, f);
    assert!(
        render.text.contains("// => 0x12034"),
        "pseudo annotates the pair address, got:\n{}",
        render.text
    );
}
