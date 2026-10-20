//! rsdbg-9syq: PowerPC decoder decision spike.
//!
//! Exercises the `powerpc` 0.4.1 backend through the existing [`Arch`]
//! patterns: fixed 4-byte big-endian decode, direct-branch targets
//! (`b`/`bl`/`bc` with LK/AA folded in), register-indirect forms
//! (`blr`/`bctr` carry no target), 32-bit NIA wrapping, prefix decode,
//! and the ELF machine mapping (`EM_PPC`/`EM_PPC64`).
//!
//! The lifter is still a skeleton ([`binscout::ir::lift_ppc`] emits
//! fallback NOP for everything), so these tests pin the disassembler
//! contract only: mnemonics are the powerpc crate's `simplified` names.

use binscout::disasm::{Arch, disasm_first, disasm_range, disasm_range_partial};
use binscout::ir::{control_op, is_mapped, lift};

fn w(word: u32) -> [u8; 4] {
    word.to_be_bytes()
}

#[test]
fn ppc32_unconditional_branch_targets() {
    // `b 0x100` at 0x0: opcode 18, LI = 0x40 (0x40 << 2 = 0x100).
    let insns = disasm_range(Arch::Ppc32, &w(0x4800_0100), 0x0, 16).unwrap();
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].mnem, "b");
    assert_eq!(insns[0].size, 4);
    assert_eq!(insns[0].branch_target, Some(0x100));

    // `bl 0x100`: LK set, same target.
    let insns = disasm_range(Arch::Ppc32, &w(0x4800_0101), 0x0, 16).unwrap();
    assert_eq!(insns[0].mnem, "bl");
    assert_eq!(insns[0].branch_target, Some(0x100));

    // Absolute `ba 0x100`: AA set, target is absolute, not relative.
    let insns = disasm_range(Arch::Ppc32, &w(0x4800_0102), 0x5000, 16).unwrap();
    assert_eq!(insns[0].mnem, "ba");
    assert_eq!(insns[0].branch_target, Some(0x100));

    // Backward `b`: at 0x100, LI = -0x40 (offset -0x100).
    let insns = disasm_range(Arch::Ppc32, &w(0x4BFF_FF00), 0x100, 16).unwrap();
    assert_eq!(insns[0].mnem, "b");
    assert_eq!(insns[0].branch_target, Some(0x0));
}

#[test]
fn ppc32_conditional_branch_targets() {
    // `bne` (bc 4,2) with BD = 0x10 (offset +0x40) at 0x0.
    let insns = disasm_range(Arch::Ppc32, &w(0x4082_0040), 0x0, 16).unwrap();
    assert_eq!(insns[0].mnem, "bne");
    assert_eq!(insns[0].branch_target, Some(0x40));

    // Conditional with link still targets directly (`bnel`-family Call).
    let insns = disasm_range(Arch::Ppc32, &w(0x4082_0041), 0x0, 16).unwrap();
    assert_eq!(insns[0].branch_target, Some(0x40));
    assert!(insns[0].mnem.ends_with('l'));
}

#[test]
fn ppc32_indirect_branches_carry_no_target() {
    for word in [0x4E80_0020, 0x4E80_0021, 0x4E80_0420, 0x4E80_0421] {
        let insns = disasm_range(Arch::Ppc32, &w(word), 0x1000, 16).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(
            insns[0].branch_target, None,
            "indirect form {word:#x} ({} {}) must not resolve",
            insns[0].mnem, word
        );
    }
    let blr = disasm_range(Arch::Ppc32, &w(0x4E80_0020), 0x1000, 16).unwrap();
    assert_eq!(blr[0].mnem, "blr");
    let bctr = disasm_range(Arch::Ppc32, &w(0x4E80_0420), 0x1000, 16).unwrap();
    assert_eq!(bctr[0].mnem, "bctr");
}

#[test]
fn ppc32_wraps_at_32_bits_but_ppc64_does_not() {
    // At 0xFFFF_FF00, `b +0x100` wraps the 32-bit NIA to 0x0.
    let bytes = w(0x4800_0100);
    let insns = disasm_range(Arch::Ppc32, &bytes, 0xFFFF_FF00, 16).unwrap();
    assert_eq!(insns[0].branch_target, Some(0x0));
    // Same bytes as PPC64 keep the full 64-bit address.
    let insns = disasm_range(Arch::Ppc64, &bytes, 0xFFFF_FF00, 16).unwrap();
    assert_eq!(insns[0].branch_target, Some(0x1_0000_0000));
}

#[test]
fn ppc_prefix_decode_and_first_word() {
    // `nop` (ori r0, r0, 0) then an illegal word then `b`: the prefix
    // holds one instruction and names the bad address.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&w(0x6000_0000));
    bytes.extend_from_slice(&w(0x0000_0000));
    bytes.extend_from_slice(&w(0x4800_0100));
    let partial = disasm_range_partial(Arch::Ppc32, &bytes, 0x2000, 16).unwrap();
    assert_eq!(partial.insns.len(), 1);
    assert_eq!(partial.insns[0].mnem, "nop");
    let err = partial.error_at.expect("bad word must end the prefix");
    assert_eq!(err.addr, 0x2004);
    assert!(err.message.contains("ppc32"), "message: {}", err.message);

    // Strict decode of the same bytes fails instead of truncating.
    let err = disasm_range(Arch::Ppc32, &bytes, 0x2000, 16).unwrap_err();
    assert!(err.to_string().contains("ppc32"), "error: {err}");

    // A short tail (< 4 bytes) is a truncated word, not silent data.
    let err = disasm_range(Arch::Ppc32, &[0x48, 0x00, 0x01], 0x0, 16).unwrap_err();
    assert!(err.to_string().contains("truncated"), "error: {err}");

    // First-word API mirrors the range decoder; empty input is None.
    let first = disasm_first(Arch::Ppc32, &w(0x4800_0100), 0x3000)
        .unwrap()
        .unwrap();
    assert_eq!(first.mnem, "b");
    assert_eq!(first.branch_target, Some(0x3100));
    assert!(disasm_first(Arch::Ppc32, &[], 0x0).unwrap().is_none());
    assert!(
        disasm_first(Arch::Ppc32, &w(0x0000_0000), 0x0)
            .unwrap_err()
            .to_string()
            .contains("ppc32")
    );
}

#[test]
fn ppc_lifter_skeleton_falls_back() {
    // Until control-flow lifting lands, every PPC row is fallback NOP:
    // `is_mapped` stays false so the fallback contract holds exactly.
    let insns = disasm_range(Arch::Ppc32, &w(0x4800_0101), 0x0, 16).unwrap();
    assert_eq!(insns[0].mnem, "bl");
    assert!(!is_mapped(Arch::Ppc32, "bl"));
    assert!(!is_mapped(Arch::Ppc64, "blr"));
    let rows = lift(Arch::Ppc32, &insns[0]);
    assert_eq!(rows.len(), 1);
    assert!(rows[0].warning.is_some());
    assert_eq!(control_op(Arch::Ppc32, &insns[0]), None);
}
