use binscout::disasm::{Arch, Disassembler, disasm_range};
use binscout::error::Error;

fn x86(bytes: &[u8], va: u64) -> Vec<binscout::disasm::Insn> {
    disasm_range(Arch::X86_64, bytes, va, 100).expect("valid x86_64 must decode")
}

fn x86_32(bytes: &[u8], va: u64) -> Vec<binscout::disasm::Insn> {
    disasm_range(Arch::X86_32, bytes, va, 100).expect("valid x86_32 must decode")
}

fn arm(bytes: &[u8], va: u64) -> Vec<binscout::disasm::Insn> {
    disasm_range(Arch::Aarch64, bytes, va, 100).expect("valid aarch64 must decode")
}

#[test]
fn x86_32_prologue_snapshot() {
    // push ebp ; mov ebp, esp
    let v = x86_32(&[0x55, 0x89, 0xe5], 0x1000);
    assert_eq!(v.len(), 2);
    assert_eq!(
        v.iter().map(|i| (i.addr, i.size)).collect::<Vec<_>>(),
        [(0x1000, 1), (0x1001, 2)]
    );
    assert_eq!(
        v.iter().map(|i| i.mnem.as_str()).collect::<Vec<_>>(),
        ["push", "mov"]
    );
    assert_eq!(v[0].ops, ["ebp"]);
    assert_eq!(v[1].ops, ["ebp", "esp"]);
}

#[test]
fn x86_bitness_changes_validity() {
    // push es is valid in 32-bit, invalid in 64-bit.
    let v = x86_32(&[0x06], 0x1000);
    assert_eq!(v[0].mnem, "push");
    let err = disasm_range(Arch::X86_64, &[0x06], 0x1000, 100).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
}

#[test]
fn x86_32_call_branch_target() {
    let v = x86_32(&[0xe8, 0, 0, 0, 0], 0x2000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "call");
    assert_eq!(v[0].branch_target, Some(0x2005));
}

#[test]
fn x86_nop_nop_ret_snapshot() {
    let v = x86(&[0x90, 0x90, 0xc3], 0x1000);
    assert_eq!(v.len(), 3);
    assert_eq!(
        v.iter().map(|i| (i.addr, i.size)).collect::<Vec<_>>(),
        [(0x1000, 1), (0x1001, 1), (0x1002, 1)]
    );
    assert_eq!(
        v.iter().map(|i| i.mnem.as_str()).collect::<Vec<_>>(),
        ["nop", "nop", "ret"]
    );
    assert!(
        v.iter()
            .all(|i| i.ops.is_empty() && i.branch_target.is_none())
    );
    assert_eq!(v[0].bytes, [0x90]);
    assert_eq!(v[2].bytes, [0xc3]);
}

#[test]
fn x86_call_branch_target() {
    let v = x86(&[0xe8, 0, 0, 0, 0], 0x2000);
    assert_eq!(v.len(), 1);
    let insn = &v[0];
    assert_eq!(insn.mnem, "call");
    assert_eq!(insn.size, 5);
    assert_eq!(insn.branch_target, Some(0x2005));
}

#[test]
fn x86_mov_operands() {
    let v = x86(&[0x48, 0x89, 0xd8], 0x1000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "mov");
    assert_eq!(v[0].ops, ["rax", "rbx"]);
    assert_eq!(v[0].branch_target, None);
}

#[test]
fn x86_invalid_opcode_errors() {
    let err = disasm_range(Arch::X86_64, &[0x06], 0x1000, 100).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
}

#[test]
fn x86_cap_errors() {
    let err = disasm_range(Arch::X86_64, &[0x90, 0x90, 0xc3], 0x1000, 2).unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
}

#[test]
fn arm_nop_ret_snapshot() {
    // nop ; ret
    let v = arm(&[0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6], 0x4000);
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].addr, 0x4000);
    assert_eq!(v[1].addr, 0x4004);
    assert!(v.iter().all(|i| i.size == 4));
    assert_eq!(
        v.iter().map(|i| i.mnem.as_str()).collect::<Vec<_>>(),
        ["nop", "ret"]
    );
    assert!(v.iter().all(|i| i.branch_target.is_none()));
}

#[test]
fn arm_bl_branch_target() {
    // bl .+16
    let v = arm(&[0x04, 0, 0, 0x94], 0x4000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "bl");
    assert_eq!(v[0].branch_target, Some(0x4010));
}

#[test]
fn arm_cbz_branch_target() {
    // cbz x0, .+0
    let v = arm(&[0x00, 0, 0, 0xb4], 0x4000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "cbz");
    assert_eq!(v[0].ops, ["x0", "$+0x0"]);
    assert_eq!(v[0].branch_target, Some(0x4000));
}

#[test]
fn arm_invalid_opcode_errors() {
    let err = disasm_range(Arch::Aarch64, &[0xff, 0xff, 0xff, 0xff], 0x4000, 100).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
}

#[test]
fn arm_truncated_tail_errors() {
    let err = disasm_range(Arch::Aarch64, &[0x1f, 0x20], 0x4000, 100).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
}

#[test]
fn arm_cap_errors() {
    let err = disasm_range(
        Arch::Aarch64,
        &[0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5],
        0x4000,
        1,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
}

#[test]
fn empty_range_decodes_empty() {
    for arch in [Arch::X86_64, Arch::X86_32, Arch::Aarch64] {
        let v = disasm_range(arch, &[], 0x1000, 100).expect("empty must decode");
        assert!(v.is_empty());
    }
}

#[test]
fn trait_dispatch_per_arch() {
    let x = Arch::X86_64
        .disassembler()
        .disasm_range(&[0x90], 0x1000)
        .expect("x86 trait dispatch must work");
    assert_eq!(x[0].mnem, "nop");
    let a = Arch::Aarch64
        .disassembler()
        .disasm_range(&[0x1f, 0x20, 0x03, 0xd5], 0x4000)
        .expect("arm trait dispatch must work");
    assert_eq!(a[0].mnem, "nop");
}
