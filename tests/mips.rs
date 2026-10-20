//! rsdbg-1wik: MIPS32 end-to-end coverage.
//!
//! - ELF `EM_MIPS` containers map to `Mips32` (little-endian only;
//!   big-endian and 64-bit MIPS stay unsupported).
//! - A synthetic function analyzes with exact function/block counts,
//!   with `jal` splitting into a call edge and `jr $ra` returning.
//! - Branch delay slots share their branch's block: no block starts at a
//!   delay-slot address, and conditional branches keep both successors.
//! - `addiu sp, sp, <imm>` prologue seeds discovery when no entry is set.
//! - Traps and canonical names decode without pseudo-aliases.

mod common;

use binscout::analysis::{DiscoveryReason, XrefKind, analyze, analyze_raw};
use binscout::disasm::{Arch, disasm_range};
use binscout::loader::{BinaryFormat, LoadedBinary, Segment, load};

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

fn mips_bin(entry: Option<u64>, code: Vec<u8>) -> LoadedBinary {
    LoadedBinary {
        format: BinaryFormat::Elf,
        arch: Arch::Mips32,
        entry,
        segments: vec![text_seg(0x10000, code)],
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

/// Minimal ELF with one `PT_LOAD` at `0x10000`: class/data/machine
/// are parameters so little/big-endian and 64-bit MIPS are covered.
fn minimal_elf_mips(class: u8, data: u8, machine: u16) -> Vec<u8> {
    let le = data == 1;
    let mut f = vec![0u8; if class == 1 { 52 + 32 } else { 64 + 56 }];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = class;
    f[5] = data;
    f[6] = 1;
    let put16 = |v: &mut [u8], off: usize, x: u16| {
        let b = if le { x.to_le_bytes() } else { x.to_be_bytes() };
        v[off..off + 2].copy_from_slice(&b);
    };
    let put32 = |v: &mut [u8], off: usize, x: u32| {
        let b = if le { x.to_le_bytes() } else { x.to_be_bytes() };
        v[off..off + 4].copy_from_slice(&b);
    };
    let put64 = |v: &mut [u8], off: usize, x: u64| {
        let b = if le { x.to_le_bytes() } else { x.to_be_bytes() };
        v[off..off + 8].copy_from_slice(&b);
    };
    put16(&mut f, 16, 2);
    put16(&mut f, 18, machine);
    put32(&mut f, 20, 1);
    if class == 1 {
        put32(&mut f, 24, 0x10000);
        put32(&mut f, 28, 52);
        put16(&mut f, 40, 52);
        put16(&mut f, 42, 32);
        put16(&mut f, 44, 1);
        put16(&mut f, 46, 40);
        let p = 52;
        put32(&mut f, p, 1);
        put32(&mut f, p + 4, 52 + 32);
        put32(&mut f, p + 8, 0x10000);
        put32(&mut f, p + 12, 0x10000);
        put32(&mut f, p + 16, 4);
        put32(&mut f, p + 20, 4);
        put32(&mut f, p + 24, 5);
        put32(&mut f, p + 28, 0x1000);
    } else {
        put64(&mut f, 24, 0x10000);
        put64(&mut f, 32, 64);
        put16(&mut f, 52, 64);
        put16(&mut f, 54, 56);
        put16(&mut f, 56, 1);
        put16(&mut f, 58, 64);
        let p = 64;
        put32(&mut f, p, 1);
        put32(&mut f, p + 4, 5);
        put64(&mut f, p + 8, 64 + 56);
        put64(&mut f, p + 16, 0x10000);
        put64(&mut f, p + 24, 0x10000);
        put64(&mut f, p + 32, 4);
        put64(&mut f, p + 40, 4);
        put64(&mut f, p + 48, 0x1000);
    }
    f.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    f
}

/// `main` calls `leaf`, restores the frame, and returns; every control
/// instruction is followed by its delay slot (`nop`):
/// - `0x10000`: `addiu sp, sp, -16`
/// - `0x10004`: `jal leaf` (leaf at `0x10024`)
/// - `0x10008`: delay slot
/// - `0x1000c`: `lw a0, 0(sp)`
/// - `0x10010`: `nop` (padding, not a delay slot: `lw` is sequential)
/// - `0x10014`: `addiu sp, sp, 16`
/// - `0x10018`: `nop` (padding, not a delay slot)
/// - `0x1001c`: `jr ra`
/// - `0x10020`: delay slot
/// - `0x10024` (leaf): `addiu a0, a0, 1; jr ra` plus delay slot.
fn main_and_leaf() -> Vec<u8> {
    vec![
        0xF0, 0xFF, 0xBD, 0x27, // 0x10000: addiu sp, sp, -16
        0x09, 0x40, 0x00, 0x0C, // 0x10004: jal 0x10024
        0x00, 0x00, 0x00, 0x00, // 0x10008: delay slot (nop)
        0x00, 0x00, 0xA4, 0x8F, // 0x1000c: lw a0, 0(sp)
        0x00, 0x00, 0x00, 0x00, // 0x10010: delay slot (nop)
        0x10, 0x00, 0xBD, 0x27, // 0x10014: addiu sp, sp, 16
        0x00, 0x00, 0x00, 0x00, // 0x10018: delay slot (nop)
        0x08, 0x00, 0xE0, 0x03, // 0x1001c: jr ra
        0x00, 0x00, 0x00, 0x00, // 0x10020: delay slot (nop)
        0x01, 0x00, 0x84, 0x24, // 0x10024: addiu a0, a0, 1 (leaf)
        0x08, 0x00, 0xE0, 0x03, // 0x10028: jr ra
        0x00, 0x00, 0x00, 0x00, // 0x1002c: delay slot (nop)
    ]
}

#[test]
fn mips32_elf_container_maps_and_decodes() {
    // 32-bit little-endian MIPS: parses to the Mips32 target.
    let bin = load(&minimal_elf_mips(1, 1, 8)).expect("mips ELF must load");
    assert_eq!(bin.format, BinaryFormat::Elf);
    assert_eq!(bin.arch, Arch::Mips32);
}

#[test]
fn mips32_big_endian_and_64bit_stay_unsupported() {
    // Same headers big-endian: the decoder reads little-endian words
    // only, so the container is rejected instead of mis-decoded.
    let err = load(&minimal_elf_mips(1, 2, 8)).expect_err("BE mips must fail");
    assert!(err.to_string().contains("big-endian"), "{err:?}");
    // 64-bit MIPS has no slice: still unsupported.
    let err = load(&minimal_elf_mips(2, 1, 8)).expect_err("mips64 must fail");
    assert!(err.to_string().contains("Mips64"), "{err:?}");
}

#[test]
fn mips_call_splits_callee_and_returns() {
    let bin = mips_bin(Some(0x10000), main_and_leaf());
    let a = analyze(&bin).expect("mips analyzes");
    assert_eq!(a.functions.len(), 2);
    let main = &a.functions[&0x10000];
    // The jal call edge splits the block: call block plus tail.
    assert_eq!(main.blocks.len(), 2);
    let leaf = &a.functions[&0x10024];
    assert_eq!(leaf.blocks.len(), 1);
    // The jal becomes a call edge to the leaf, not a fallthrough block.
    assert!(a.calls_of(0x10000).contains(&0x10024));
}

#[test]
fn mips_delay_slot_shares_branch_block() {
    let bin = mips_bin(Some(0x10000), main_and_leaf());
    let a = analyze(&bin).expect("mips analyzes");
    let main = &a.functions[&0x10000];
    // Delay slots never start a block: 0x10008 is the jal's slot.
    assert!(!main.blocks.contains_key(&0x10008));
    assert!(!main.blocks.contains_key(&0x10010));
    assert!(!main.blocks.contains_key(&0x10020));
    let head = &main.blocks[&0x10000];
    assert_eq!(head.insns.len(), 3);
    assert_eq!(head.insns[1].mnem, "jal");
    assert_eq!(head.insns[1].branch_target, Some(0x10024));
    assert_eq!(head.insns[2].mnem, "nop");
    // The tail block ends with the return plus its delay slot.
    let tail = &main.blocks[&0x1000c];
    let last = tail.insns.last().expect("tail nonempty");
    let prev = &tail.insns[tail.insns.len() - 2];
    assert_eq!(prev.mnem, "jr");
    assert_eq!(last.mnem, "nop");
}

/// A conditional branch reads through its delay slot for control flow:
/// the `beq` block keeps both successors and reports one `if`.
fn mips_conditional_branch_keeps_both_successors() -> Vec<u8> {
    vec![
        0x03, 0x00, 0x80, 0x10, // 0x10000: beq a0, zero, +3 (target 0x10010)
        0x00, 0x00, 0x00, 0x00, // 0x10004: delay slot
        0x08, 0x00, 0xE0, 0x03, // 0x10008: jr ra (else)
        0x00, 0x00, 0x00, 0x00, // 0x1000c: delay slot
        0x01, 0x00, 0x04, 0x24, // 0x10010: addiu a0, zero, 1 (then)
        0x08, 0x00, 0xE0, 0x03, // 0x10014: jr ra
        0x00, 0x00, 0x00, 0x00, // 0x10018: delay slot
    ]
}

#[test]
fn mips_if_detection_reads_through_delay_slot() {
    let bin = mips_bin(
        Some(0x10000),
        mips_conditional_branch_keeps_both_successors(),
    );
    let a = analyze(&bin).expect("mips analyzes");
    let main = &a.functions[&0x10000];
    assert_eq!(main.blocks.len(), 3);
    let head = &main.blocks[&0x10000];
    assert_eq!(head.insns.len(), 2);
    assert_eq!(head.insns[0].mnem, "beq");
    // Both edges survive: taken to 0x10010, fallthrough to 0x10008.
    let mut succs = main.successors(0x10000);
    succs.sort_unstable();
    assert_eq!(succs, [0x10008, 0x10010]);
    let structure = main.structure(Arch::Mips32);
    assert_eq!(structure.ifs.len(), 1);
    assert_eq!(structure.ifs[0].cond, 0x10000);
}

#[test]
fn mips_prologue_seeds_discovery_without_entry() {
    // Entry at the leaf: main is unreachable from it, so only the
    // prologue scan (addiu sp, sp, -16) finds main.
    let bin = mips_bin(Some(0x10024), main_and_leaf());
    let a = analyze(&bin).expect("mips analyzes");
    assert!(a.functions.contains_key(&0x10000), "prologue seeds main");
    assert!(a.functions.contains_key(&0x10024), "call target found");
    let main = &a.functions[&0x10000];
    assert!(
        main.reasons.contains(&DiscoveryReason::Prologue),
        "main carries a prologue reason, got {:?}",
        main.reasons
    );
}

#[test]
fn mips_branch_targets_resolve() {
    // jal carries its absolute target; jr is indirect; beq resolves
    // PC-relative; zero-zero beq lifts as an unconditional branch.
    let v = disasm_range(Arch::Mips32, &[0x09, 0x40, 0x00, 0x0C], 0x10004, 8).expect("decodes");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "jal");
    assert_eq!(v[0].branch_target, Some(0x10024));
    let v = disasm_range(Arch::Mips32, &[0x08, 0x00, 0xE0, 0x03], 0x10000, 8).expect("decodes");
    assert_eq!(v[0].mnem, "jr");
    assert_eq!(v[0].branch_target, None);
    // beq a0, a0, +2 (offset counts from the delay slot).
    let v = disasm_range(Arch::Mips32, &[0x02, 0x00, 0x84, 0x10], 0x10000, 8).expect("decodes");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "beq");
    assert_eq!(v[0].branch_target, Some(0x1000c));
}

#[test]
fn mips_traps_and_canonical_names_decode() {
    // syscall traps; `b`-family words print canonical (no pseudos).
    for (bytes, mnem) in [
        (&[0x0C, 0x00, 0x00, 0x00][..], "syscall"),
        (&[0x03, 0x00, 0x00, 0x10][..], "beq"),
        (&[0x01, 0x00, 0x11, 0x04][..], "bgezal"),
    ] {
        let v = disasm_range(Arch::Mips32, bytes, 0x10000, 8).expect("decodes");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mnem, mnem, "{bytes:02x?}");
    }
}

#[test]
fn mips_lui_addiu_pair_links_string_at_final_address() {
    // lui $t0, 0x4 (base 0x40000); addiu $t0, $t0, 0x10; jr ra;
    // delay slot; "hello!\0" at 0x40010. The pair resolves to the string
    // start while the base row is retained.
    let mut b = vec![
        0x04, 0x00, 0x08, 0x3C, // lui $t0, 0x4
        0x10, 0x00, 0x08, 0x25, // addiu $t0, $t0, 0x10
        0x08, 0x00, 0xE0, 0x03, // jr ra
        0x00, 0x00, 0x00, 0x00, // delay slot
    ];
    b.extend(*b"hello!\0");
    let va = 0x40000u64;
    assert_eq!(va + b.len() as u64, 0x40017);
    let a = analyze_raw(&b, va, Arch::Mips32, Some(va)).expect("mips blob analyzes");
    assert!(
        a.strings
            .iter()
            .any(|h| h.value == "hello!" && h.vaddr == Some(0x40010)),
        "string at the pair final address: {:?}",
        a.strings
    );
    let data = a.xrefs_page(Some(XrefKind::Data), 0, 64);
    assert!(
        data.iter().any(|x| x.from == va + 4 && x.to == 0x40010),
        "pair final address from the addiu: {data:?}"
    );
    assert!(
        data.iter().any(|x| x.from == va && x.to == va),
        "lui base row retained: {data:?}"
    );
    let srefs = a.xrefs_page(Some(XrefKind::String), 0, 64);
    assert!(srefs.iter().any(|x| x.from == va + 4 && x.to == 0x40010));
}

#[test]
fn mips_lui_lw_pair_links_data() {
    // lui $t0, 0x4; lw $t1, 0x10($t0); jr ra; delay slot; data at 0x40010.
    // The load references the exact address 0x40010, not just the base.
    let mut b = vec![
        0x04, 0x00, 0x08, 0x3C, // lui $t0, 0x4
        0x10, 0x00, 0x09, 0x8D, // lw $t1, 0x10($t0)
        0x08, 0x00, 0xE0, 0x03, // jr ra
        0x00, 0x00, 0x00, 0x00, // delay slot
    ];
    b.extend(*b"hello!\0");
    let va = 0x40000u64;
    assert_eq!(va + b.len() as u64, 0x40017);
    let a = analyze_raw(&b, va, Arch::Mips32, Some(va)).expect("mips blob analyzes");
    let data = a.xrefs_page(Some(XrefKind::Data), 0, 64);
    assert!(
        data.iter().any(|x| x.from == va + 4 && x.to == 0x40010),
        "pair final address from the lw: {data:?}"
    );
}
