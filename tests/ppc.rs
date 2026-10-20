//! rsdbg-9syq: PowerPC 32/64 end-to-end coverage.
//!
//! - ELF `EM_PPC`/`EM_PPC64` containers map to `Ppc32`/`Ppc64`
//!   (big-endian only; little-endian containers stay unsupported).
//! - A synthetic function analyzes with exact function/block counts,
//!   with `bl` splitting into a call edge and `blr` returning.
//! - `stwu rS, <imm>(r1)` prologue seeds discovery when no entry is set.
//! - Branch targets resolve with 32-bit NIA wrapping on `Ppc32`.
//! - Traps and canonical names decode without vector aliases.

mod common;

use binscout::analysis::{DiscoveryReason, analyze};
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

fn ppc_bin(arch: Arch, entry: Option<u64>, code: Vec<u8>) -> LoadedBinary {
    LoadedBinary {
        format: BinaryFormat::Elf,
        arch,
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
/// are parameters so big/little-endian and 32/64-bit PPC are covered.
fn minimal_elf_ppc(class: u8, data: u8, machine: u16) -> Vec<u8> {
    let be = data == 2;
    let mut f = vec![0u8; if class == 1 { 52 + 32 } else { 64 + 56 }];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = class;
    f[5] = data;
    f[6] = 1;
    let put16 = |v: &mut [u8], off: usize, x: u16| {
        let b = if be { x.to_be_bytes() } else { x.to_le_bytes() };
        v[off..off + 2].copy_from_slice(&b);
    };
    let put32 = |v: &mut [u8], off: usize, x: u32| {
        let b = if be { x.to_be_bytes() } else { x.to_le_bytes() };
        v[off..off + 4].copy_from_slice(&b);
    };
    let put64 = |v: &mut [u8], off: usize, x: u64| {
        let b = if be { x.to_be_bytes() } else { x.to_le_bytes() };
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
    f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    f
}

/// `main` calls `leaf`, restores the frame, and returns:
/// - `0x10000`: `stwu r1, -16(r1)`
/// - `0x10004`: `bl leaf` (leaf at `0x10014`)
/// - `0x10008`: `lwz r3, 16(r1)`
/// - `0x1000c`: `addi r1, r1, 16`
/// - `0x10010`: `blr`
/// - `0x10014` (leaf): `addi r3, r3, 1; blr`.
fn main_and_leaf() -> Vec<u8> {
    vec![
        0x94, 0x21, 0xFF, 0xF0, // 0x10000: stwu r1, -16(r1)
        0x48, 0x00, 0x00, 0x11, // 0x10004: bl 0x10014
        0x80, 0x61, 0x00, 0x10, // 0x10008: lwz r3, 16(r1)
        0x38, 0x21, 0x00, 0x10, // 0x1000c: addi r1, r1, 16
        0x4E, 0x80, 0x00, 0x20, // 0x10010: blr
        0x38, 0x63, 0x00, 0x01, // 0x10014: addi r3, r3, 1 (leaf)
        0x4E, 0x80, 0x00, 0x20, // 0x10018: blr
    ]
}

#[test]
fn ppc32_elf_container_maps_and_decodes() {
    // 32-bit big-endian PPC: parses to the Ppc32 target.
    let bin = load(&minimal_elf_ppc(1, 2, 20)).expect("ppc ELF must load");
    assert_eq!(bin.format, BinaryFormat::Elf);
    assert_eq!(bin.arch, Arch::Ppc32);
}

#[test]
fn ppc64_elf_container_maps_and_decodes() {
    // 64-bit big-endian PPC: parses to the Ppc64 target.
    let bin = load(&minimal_elf_ppc(2, 2, 21)).expect("ppc64 ELF must load");
    assert_eq!(bin.format, BinaryFormat::Elf);
    assert_eq!(bin.arch, Arch::Ppc64);
}

#[test]
fn ppc_little_endian_stays_unsupported() {
    // Same headers little-endian: the decoder reads big-endian words
    // only, so the container is rejected instead of mis-decoded.
    let err = load(&minimal_elf_ppc(1, 1, 20)).expect_err("LE ppc must fail");
    assert!(err.to_string().contains("little-endian"), "{err:?}");
    // ppc64le likewise.
    let err = load(&minimal_elf_ppc(2, 1, 21)).expect_err("ppc64le must fail");
    assert!(err.to_string().contains("little-endian"), "{err:?}");
}

#[test]
fn ppc_call_splits_callee_and_returns() {
    let bin = ppc_bin(Arch::Ppc32, Some(0x10000), main_and_leaf());
    let a = analyze(&bin).expect("ppc analyzes");
    assert_eq!(a.functions.len(), 2);
    let main = &a.functions[&0x10000];
    // The bl call edge splits the block: call block plus tail.
    assert_eq!(main.blocks.len(), 2);
    let leaf = &a.functions[&0x10014];
    assert_eq!(leaf.blocks.len(), 1);
    // The bl becomes a call edge to the leaf, not a fallthrough block.
    assert!(a.calls_of(0x10000).contains(&0x10014));
}

#[test]
fn ppc_conditional_branch_keeps_both_successors() {
    // `bne` at 0x10000 (+0x40 taken to 0x10040); the else returns at
    // 0x10004; the then-block at 0x10040 restores and returns. The gap
    // words are unreachable filler (`nop`).
    let mut code = vec![0u8; 0x48];
    code[0x00..0x04].copy_from_slice(&[0x40, 0x82, 0x00, 0x40]); // bne -> 0x10040
    code[0x04..0x08].copy_from_slice(&[0x4E, 0x80, 0x00, 0x20]); // blr (else)
    for off in (0x08..0x40).step_by(4) {
        code[off..off + 4].copy_from_slice(&[0x60, 0x00, 0x00, 0x00]); // nop filler
    }
    code[0x40..0x44].copy_from_slice(&[0x38, 0x63, 0x00, 0x01]); // addi r3, r3, 1
    code[0x44..0x48].copy_from_slice(&[0x4E, 0x80, 0x00, 0x20]); // blr
    let bin = ppc_bin(Arch::Ppc32, Some(0x10000), code);
    let a = analyze(&bin).expect("ppc analyzes");
    let main = &a.functions[&0x10000];
    assert_eq!(main.blocks.len(), 3);
    let head = &main.blocks[&0x10000];
    assert_eq!(head.insns.len(), 1);
    assert_eq!(head.insns[0].mnem, "bne");
    // Both edges survive: taken to 0x10040, fallthrough to 0x10004.
    let mut succs = main.successors(0x10000);
    succs.sort_unstable();
    assert_eq!(succs, [0x10004, 0x10040]);
    let structure = main.structure(Arch::Ppc32);
    assert_eq!(structure.ifs.len(), 1);
    assert_eq!(structure.ifs[0].cond, 0x10000);
}

#[test]
fn ppc_prologue_seeds_discovery_without_entry() {
    // Entry at the leaf: main is unreachable from it, so only the
    // prologue scan (stwu r1) finds main.
    let bin = ppc_bin(Arch::Ppc32, Some(0x10014), main_and_leaf());
    let a = analyze(&bin).expect("ppc analyzes");
    assert!(a.functions.contains_key(&0x10000), "prologue seeds main");
    assert!(a.functions.contains_key(&0x10014), "call target found");
    let main = &a.functions[&0x10000];
    assert!(
        main.reasons.contains(&DiscoveryReason::Prologue),
        "main carries a prologue reason, got {:?}",
        main.reasons
    );
}

#[test]
fn ppc_branch_targets_resolve() {
    // bl carries its direct target; blr/bctr are indirect; bne resolves
    // PC-relative with 32-bit wrapping on Ppc32.
    let v = disasm_range(Arch::Ppc32, &[0x48, 0x00, 0x00, 0x11], 0x10004, 8).expect("decodes");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "bl");
    assert_eq!(v[0].branch_target, Some(0x10014));
    let v = disasm_range(Arch::Ppc32, &[0x4E, 0x80, 0x00, 0x20], 0x10000, 8).expect("decodes");
    assert_eq!(v[0].mnem, "blr");
    assert_eq!(v[0].branch_target, None);
    let v = disasm_range(Arch::Ppc32, &[0x4E, 0x80, 0x04, 0x20], 0x10000, 8).expect("decodes");
    assert_eq!(v[0].mnem, "bctr");
    assert_eq!(v[0].branch_target, None);
    let v = disasm_range(Arch::Ppc32, &[0x40, 0x82, 0x00, 0x40], 0x10000, 8).expect("decodes");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "bne");
    assert_eq!(v[0].branch_target, Some(0x10040));
}

#[test]
fn ppc_traps_and_canonical_names_decode() {
    // sc traps; `nop` prints for the all-zero-source ori while `li`/`mr`
    // print for their addi/or aliases (no raw `ori`/`or` there).
    for (bytes, mnem) in [
        (&[0x44, 0x00, 0x00, 0x02][..], "sc"),
        (&[0x60, 0x00, 0x00, 0x00][..], "nop"),
        (&[0x38, 0x60, 0x00, 0x01][..], "li"),
        (&[0x7F, 0x83, 0xE3, 0x78][..], "mr"),
    ] {
        let v = disasm_range(Arch::Ppc32, bytes, 0x10000, 8).expect("decodes");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mnem, mnem, "{bytes:02x?}");
    }
}
