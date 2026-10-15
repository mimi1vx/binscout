use binscout::disasm::{Arch, Disassembler, disasm_range, disasm_range_partial};
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

fn arm32(bytes: &[u8], va: u64) -> Vec<binscout::disasm::Insn> {
    disasm_range(Arch::Arm32, bytes, va, 100).expect("valid arm32 must decode")
}

fn thumb(bytes: &[u8], va: u64) -> Vec<binscout::disasm::Insn> {
    disasm_range(Arch::Thumb, bytes, va, 100).expect("valid thumb must decode")
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
    for arch in [
        Arch::X86_64,
        Arch::X86_32,
        Arch::Aarch64,
        Arch::Arm32,
        Arch::Thumb,
    ] {
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
    let a32 = Arch::Arm32
        .disassembler()
        .disasm_range(&[0x01, 0x00, 0xa0, 0xe1], 0x10000)
        .expect("arm32 trait dispatch must work");
    assert_eq!(a32[0].mnem, "mov");
    let t = Arch::Thumb
        .disassembler()
        .disasm_range(&[0x00, 0xbf], 0x20000)
        .expect("thumb trait dispatch must work");
    assert_eq!(t[0].mnem, "nop");
}

// --- D2/A6: partial prefix + error_at ---

#[test]
fn partial_returns_prefix_and_error_at_on_x86_garbage() {
    // push rbp; mov rbp,rsp; then 0xD6 (invalid in 64-bit); then a nop.
    let bytes = [0x55, 0x48, 0x89, 0xE5, 0xD6, 0x90];
    let p =
        disasm_range_partial(Arch::X86_64, &bytes, 0x1000, 100).expect("partial keeps the prefix");
    assert_eq!(p.insns.len(), 2);
    assert_eq!(p.insns[0].mnem, "push");
    let err = p.error_at.expect("error_at set on garbage");
    assert_eq!(err.addr, 0x1004);
    assert!(err.message.contains("0x1004"), "got {:?}", err.message);
    assert!(
        !err.message.contains('/'),
        "no host paths: {:?}",
        err.message
    );
    // Strict still aborts on the same bytes.
    let strict = disasm_range(Arch::X86_64, &bytes, 0x1000, 100).unwrap_err();
    assert!(matches!(strict, Error::Invalid(_)), "got {strict:?}");
    assert_eq!(
        strict.to_string(),
        format!("invalid opcode: {}", err.message)
    );
}

#[test]
fn partial_clean_range_reports_null_error() {
    let p = disasm_range_partial(Arch::X86_64, &[0x90, 0x90, 0xc3], 0x1000, 100)
        .expect("clean partial decodes");
    assert_eq!(p.insns.len(), 3);
    assert!(p.error_at.is_none());
    let p = disasm_range_partial(Arch::X86_32, &[0x55, 0x89, 0xe5], 0x1000, 100)
        .expect("clean x86-32 partial decodes");
    assert_eq!(p.insns.len(), 2);
    assert!(p.error_at.is_none());
    let p = disasm_range_partial(
        Arch::Aarch64,
        &[0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6],
        0x4000,
        100,
    )
    .expect("clean aarch64 partial decodes");
    assert_eq!(p.insns.len(), 2);
    assert!(p.error_at.is_none());
    assert!(
        disasm_range_partial(Arch::X86_64, &[], 0x1000, 100)
            .expect("empty partial decodes")
            .error_at
            .is_none()
    );
}

#[test]
fn partial_first_byte_invalid_reports_empty_prefix() {
    let p = disasm_range_partial(Arch::X86_64, &[0x06], 0x1000, 100)
        .expect("partial on bad first byte");
    assert!(p.insns.is_empty());
    let err = p.error_at.expect("error_at set");
    assert_eq!(err.addr, 0x1000);
}

#[test]
fn partial_aarch64_invalid_and_truncated_tail() {
    let p = disasm_range_partial(Arch::Aarch64, &[0xff, 0xff, 0xff, 0xff], 0x4000, 100)
        .expect("partial on bad word");
    assert!(p.insns.is_empty());
    assert_eq!(p.error_at.expect("error_at").addr, 0x4000);
    // nop then a short tail: prefix of 1 plus error at the tail word.
    let p = disasm_range_partial(
        Arch::Aarch64,
        &[0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20],
        0x4000,
        100,
    )
    .expect("partial on truncated tail");
    assert_eq!(p.insns.len(), 1);
    assert_eq!(p.error_at.expect("error_at").addr, 0x4004);
}

#[test]
fn partial_cap_still_errors() {
    let err = disasm_range_partial(Arch::X86_64, &[0x90, 0x90, 0xc3], 0x1000, 2).unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
    let err = disasm_range_partial(
        Arch::Aarch64,
        &[0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5],
        0x4000,
        1,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
}

#[test]
fn partial_trait_dispatch_per_arch() {
    let p = Arch::X86_64
        .disassembler()
        .disasm_range_partial(&[0x90, 0x06], 0x1000)
        .expect("trait partial must work");
    assert_eq!(p.insns.len(), 1);
    assert_eq!(p.error_at.expect("error_at").addr, 0x1001);
}

#[test]
fn arm32_prologue_snapshot() {
    // mov r0, r1 ; bx lr
    let v = arm32(&[0x01, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1], 0x10000);
    assert_eq!(v.len(), 2);
    assert_eq!(
        v.iter().map(|i| (i.addr, i.size)).collect::<Vec<_>>(),
        [(0x10000, 4), (0x10004, 4)]
    );
    assert_eq!(
        v.iter().map(|i| i.mnem.as_str()).collect::<Vec<_>>(),
        ["mov", "bx"]
    );
    assert_eq!(v[0].ops, ["r0", "r1"]);
    assert_eq!(v[1].ops, ["lr"]);
    assert!(v.iter().all(|i| i.branch_target.is_none()));
}

#[test]
fn arm32_b_bl_branch_targets() {
    // b . targets itself; bl with a zero field targets addr+8.
    let v = arm32(&[0xfe, 0xff, 0xff, 0xea], 0x10000);
    assert_eq!(v[0].mnem, "b");
    assert_eq!(v[0].branch_target, Some(0x10000));
    let v = arm32(&[0x00, 0x00, 0x00, 0xeb], 0x10000);
    assert_eq!(v[0].mnem, "bl");
    assert_eq!(v[0].branch_target, Some(0x10008));
}

#[test]
fn arm32_invalid_opcode_errors() {
    let err = disasm_range(Arch::Arm32, &[0xff, 0xff, 0xff, 0xff], 0x10000, 100).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
}

#[test]
fn arm32_truncated_tail_errors() {
    let err = disasm_range(Arch::Arm32, &[0x01, 0x00], 0x10000, 100).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
}

#[test]
fn arm32_cap_errors() {
    let err = disasm_range(
        Arch::Arm32,
        &[0x01, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1],
        0x10000,
        1,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
}

#[test]
fn thumb_mixed_width_snapshot() {
    // nop (2B) ; bl #0 (4B) ; bx lr (2B)
    let v = thumb(&[0x00, 0xbf, 0x00, 0xf0, 0x00, 0xf8, 0x70, 0x47], 0x20000);
    assert_eq!(v.len(), 3);
    assert_eq!(
        v.iter().map(|i| (i.addr, i.size)).collect::<Vec<_>>(),
        [(0x20000, 2), (0x20002, 4), (0x20006, 2)]
    );
    assert_eq!(
        v.iter().map(|i| i.mnem.as_str()).collect::<Vec<_>>(),
        ["nop", "bl.w", "bx"]
    );
    assert_eq!(v[1].branch_target, Some(0x20006));
    assert_eq!(v[1].bytes, [0x00, 0xf0, 0x00, 0xf8]);
}

#[test]
fn thumb_b_and_cbz_branch_targets() {
    // b . targets itself (halfword offset -2 from PC).
    let v = thumb(&[0xfe, 0xe7], 0x20000);
    assert_eq!(v[0].mnem, "b");
    assert_eq!(v[0].branch_target, Some(0x20000));
    // cbz r0, #4 targets PC+4.
    let v = thumb(&[0x08, 0xb1], 0x20000);
    assert_eq!(v[0].mnem, "cbz");
    assert_eq!(v[0].branch_target, Some(0x20008));
}

#[test]
fn thumb_invalid_opcode_errors() {
    let err = disasm_range(Arch::Thumb, &[0xff, 0xff, 0xff, 0xff], 0x20000, 100).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
}

#[test]
fn thumb_truncated_tail_errors() {
    // Lone first halfword of a 32-bit instruction.
    let err = disasm_range(Arch::Thumb, &[0x00, 0xf0], 0x20000, 100).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
    let err = disasm_range(Arch::Thumb, &[0x00], 0x20000, 100).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
}

#[test]
fn thumb_cap_errors() {
    let err = disasm_range(Arch::Thumb, &[0x00, 0xbf, 0x00, 0xbf], 0x20000, 1).unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
}

#[test]
fn partial_arm32_invalid_and_truncated_tail() {
    let p = disasm_range_partial(Arch::Arm32, &[0xff, 0xff, 0xff, 0xff], 0x10000, 100)
        .expect("partial on bad word");
    assert!(p.insns.is_empty());
    assert_eq!(p.error_at.expect("error_at").addr, 0x10000);
    // mov then a short tail: prefix of 1 plus error at the tail word.
    let p = disasm_range_partial(
        Arch::Arm32,
        &[0x01, 0x00, 0xa0, 0xe1, 0x01, 0x00],
        0x10000,
        100,
    )
    .expect("partial on truncated tail");
    assert_eq!(p.insns.len(), 1);
    assert_eq!(p.error_at.expect("error_at").addr, 0x10004);
}

#[test]
fn partial_thumb_mixed_prefix_and_split_tail() {
    // nop (2B) ; bl #0 (4B) ; then a 32-bit prefix with no second half.
    let p = disasm_range_partial(
        Arch::Thumb,
        &[0x00, 0xbf, 0x00, 0xf0, 0x00, 0xf8, 0x00, 0xf0],
        0x20000,
        100,
    )
    .expect("partial keeps the mixed prefix");
    assert_eq!(p.insns.len(), 2);
    assert_eq!(p.insns[1].size, 4);
    assert_eq!(p.error_at.expect("error_at").addr, 0x20006);
    // Strict aborts on the same bytes.
    let strict = disasm_range(
        Arch::Thumb,
        &[0x00, 0xbf, 0x00, 0xf0, 0x00, 0xf8, 0x00, 0xf0],
        0x20000,
        100,
    )
    .unwrap_err();
    assert!(matches!(strict, Error::Invalid(_)), "got {strict:?}");
}

#[test]
fn partial_thumb_cap_still_errors() {
    let err = disasm_range_partial(Arch::Thumb, &[0x00, 0xbf, 0x00, 0xbf], 0x20000, 1).unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
    let err = disasm_range_partial(
        Arch::Arm32,
        &[0x01, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1],
        0x10000,
        1,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
}

#[test]
fn x86_rep_lock_prefixes_expose_real_mnemonic() {
    // rep movsb: the prefix is not the mnemonic.
    let v = x86(&[0xf3, 0xa4], 0x1000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "movsb");
    assert_eq!(v[0].ops, ["[rdi]", "[rsi]"]);
    // repe cmpsb keeps the compare operands.
    let v = x86(&[0xf3, 0xa6], 0x1000);
    assert_eq!(v[0].mnem, "cmpsb");
    // lock add [rax], eax lifts the add with memory operands intact.
    let v = x86(&[0xf0, 0x01, 0x00], 0x1000);
    assert_eq!(v[0].mnem, "add");
    assert_eq!(v[0].ops, ["[rax]", "eax"]);
    // rep ret still returns.
    let v = x86(&[0xf3, 0xc3], 0x1000);
    assert_eq!(v[0].mnem, "ret");
    assert!(v[0].ops.is_empty());
}
