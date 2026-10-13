use binscout::disasm::{Arch, Disassembler, disasm_range};
use binscout::ir::{IrOp, lift, lift_range};

fn x86(bytes: &[u8], va: u64) -> Vec<binscout::ir::IrInsn> {
    let insns = disasm_range(Arch::X86_64, bytes, va, 100).expect("valid x86_64 must decode");
    assert_eq!(insns.len(), 1);
    lift(Arch::X86_64, &insns[0])
}

fn arm(bytes: &[u8], va: u64) -> Vec<binscout::ir::IrInsn> {
    let insns = disasm_range(Arch::Aarch64, bytes, va, 100).expect("valid aarch64 must decode");
    assert_eq!(insns.len(), 1);
    lift(Arch::Aarch64, &insns[0])
}

fn arm32(bytes: &[u8], va: u64) -> Vec<binscout::ir::IrInsn> {
    let insns = disasm_range(Arch::Arm32, bytes, va, 100).expect("valid arm32 must decode");
    assert_eq!(insns.len(), 1);
    lift(Arch::Arm32, &insns[0])
}

fn thumb(bytes: &[u8], va: u64) -> Vec<binscout::ir::IrInsn> {
    let dis = Arch::Thumb.disassembler();
    let insns = dis
        .disasm_range(bytes, va)
        .expect("valid thumb must decode");
    lift(Arch::Thumb, &insns[0])
}

#[test]
fn x86_mov_lifts_copy() {
    let v = x86(&[0x48, 0x89, 0xd8], 0x1000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].op, IrOp::Copy);
    assert_eq!(v[0].addr, 0x1000);
    assert_eq!(v[0].outputs, ["rax"]);
    assert_eq!(v[0].inputs, ["rbx"]);
    assert_eq!(v[0].target, None);
    assert_eq!(v[0].warning, None);
}

#[test]
fn x86_add_lifts_add() {
    let v = x86(&[0x48, 0x01, 0xd8], 0x1000);
    assert_eq!(v[0].op, IrOp::Add);
    assert_eq!(v[0].outputs, ["rax"]);
    assert_eq!(v[0].inputs, ["rbx"]);
}

#[test]
fn x86_jmp_lifts_branch() {
    let v = x86(&[0xeb, 0x00], 0x1000);
    assert_eq!(v[0].op, IrOp::Branch);
    assert_eq!(v[0].target, Some(0x1002));
    assert_eq!(v[0].warning, None);
}

#[test]
fn x86_call_lifts_call() {
    let v = x86(&[0xe8, 0, 0, 0, 0], 0x2000);
    assert_eq!(v[0].op, IrOp::Call);
    assert_eq!(v[0].target, Some(0x2005));
}

#[test]
fn x86_ret_lifts_return() {
    let v = x86(&[0xc3], 0x1000);
    assert_eq!(v[0].op, IrOp::Return);
    assert_eq!(v[0].target, None);
    assert_eq!(v[0].warning, None);
}

#[test]
fn x86_unknown_lifts_nop_with_warning() {
    // cpuid decodes but has no IR mapping.
    let v = x86(&[0x0f, 0xa2], 0x1000);
    assert_eq!(v[0].op, IrOp::Nop);
    assert!(v[0].warning.is_some(), "expected warning, got {:?}", v[0]);
}

#[test]
fn arm_ldr_lifts_load() {
    // ldr x0, [x1]
    let v = arm(&[0x20, 0x00, 0x40, 0xf9], 0x4000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].op, IrOp::Load);
    assert_eq!(v[0].addr, 0x4000);
    assert_eq!(v[0].outputs, ["x0"]);
    assert_eq!(v[0].inputs, ["[x1]"]);
    assert_eq!(v[0].warning, None);
}

#[test]
fn arm_add_lifts_add() {
    // add x0, x1, x2
    let v = arm(&[0x20, 0x00, 0x02, 0x8b], 0x4000);
    assert_eq!(v[0].op, IrOp::Add);
    assert_eq!(v[0].outputs, ["x0"]);
    assert_eq!(v[0].inputs, ["x1", "x2"]);
}

#[test]
fn arm_b_lifts_branch() {
    // b .+16
    let v = arm(&[0x04, 0x00, 0x00, 0x14], 0x4000);
    assert_eq!(v[0].op, IrOp::Branch);
    assert_eq!(v[0].target, Some(0x4010));
}

#[test]
fn arm_blr_lifts_indirect_call() {
    // blr x1
    let v = arm(&[0x20, 0x00, 0x3f, 0xd6], 0x4000);
    assert_eq!(v[0].op, IrOp::Call);
    assert_eq!(v[0].target, None);
    assert_eq!(v[0].inputs, ["x1"]);
}

#[test]
fn arm_ret_lifts_return() {
    let v = arm(&[0xc0, 0x03, 0x5f, 0xd6], 0x4000);
    assert_eq!(v[0].op, IrOp::Return);
    assert_eq!(v[0].warning, None);
}

#[test]
fn arm_cbz_lifts_cbranch() {
    // cbz x0, .+0
    let v = arm(&[0x00, 0x00, 0x00, 0xb4], 0x4000);
    assert_eq!(v[0].op, IrOp::CBranch);
    assert_eq!(v[0].target, Some(0x4000));
}

#[test]
fn arm32_mov_lifts_copy() {
    // mov r0, r1
    let v = arm32(&[0x01, 0x00, 0xa0, 0xe1], 0x10000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].op, IrOp::Copy);
    assert_eq!(v[0].outputs, ["r0"]);
    assert_eq!(v[0].inputs, ["r1"]);
    assert_eq!(v[0].warning, None);
}

#[test]
fn arm32_bl_lifts_call() {
    // bl with a zero field at 0x10000 targets 0x10008.
    let v = arm32(&[0x00, 0x00, 0x00, 0xeb], 0x10000);
    assert_eq!(v[0].op, IrOp::Call);
    assert_eq!(v[0].target, Some(0x10008));
}

#[test]
fn arm32_bx_lr_lifts_return() {
    let v = arm32(&[0x1e, 0xff, 0x2f, 0xe1], 0x10000);
    assert_eq!(v[0].op, IrOp::Return);
    assert_eq!(v[0].warning, None);
}

#[test]
fn thumb_cbz_lifts_cbranch() {
    // cbz r0, #4 at 0x20000 targets 0x20008.
    let v = thumb(&[0x08, 0xb1], 0x20000);
    assert_eq!(v[0].op, IrOp::CBranch);
    assert_eq!(v[0].target, Some(0x20008));
}

#[test]
fn thumb_bl_lifts_call() {
    // bl #0 at 0x20000 targets 0x20004.
    let v = thumb(&[0x00, 0xf0, 0x00, 0xf8], 0x20000);
    assert_eq!(v[0].op, IrOp::Call);
    assert_eq!(v[0].target, Some(0x20004));
}

#[test]
fn lift_range_preserves_order() {
    // nop ; ret
    let insns = Arch::X86_64
        .disassembler()
        .disasm_range(&[0x90, 0xc3], 0x1000)
        .expect("valid range must decode");
    let v = lift_range(Arch::X86_64, &insns);
    assert_eq!(v.len(), 2);
    assert_eq!((v[0].op, v[0].addr), (IrOp::Nop, 0x1000));
    assert_eq!((v[1].op, v[1].addr), (IrOp::Return, 0x1001));
}
