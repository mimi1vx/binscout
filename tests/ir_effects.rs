use binscout::disasm::{Arch, disasm_range};
use binscout::ir::{IrOp, coverage, lift, lift_x86};

mod common;

use common::{cleanup, temp_db, tmpdir, write_bin};

/// Synthetic instruction: raw mnemonic plus operand strings, no decoding.
fn synth(mnem: &str, ops: &[&str]) -> binscout::disasm::Insn {
    binscout::disasm::Insn {
        addr: 0x1000,
        size: 1,
        bytes: vec![0x90],
        mnem: mnem.to_string(),
        ops: ops.iter().map(|s| (*s).to_string()).collect(),
        branch_target: None,
        mem_target: None,
        table_base: None,
        import: None,
    }
}

fn one(arch: Arch, bytes: &[u8], va: u64) -> binscout::ir::IrInsn {
    let insns = disasm_range(arch, bytes, va, 8).expect("bytes must decode");
    assert_eq!(insns.len(), 1, "{bytes:02x?}");
    let v = lift(arch, &insns[0]);
    assert_eq!(v.len(), 1);
    v.into_iter().next().unwrap()
}

#[test]
fn x86_integer_add_sub_cmp_set_flags() {
    for (bytes, op) in [
        (&[0x48, 0x01, 0xd8][..], IrOp::Add),       // add rax, rbx
        (&[0x48, 0x29, 0xd8][..], IrOp::Sub),       // sub rax, rbx
        (&[0x48, 0x39, 0xd8][..], IrOp::Cmp),       // cmp rax, rbx
        (&[0x48, 0x85, 0xd8][..], IrOp::Cmp),       // test rax, rbx
        (&[0x0f, 0xba, 0xe0, 0x01][..], IrOp::Cmp), // bt eax, 1
    ] {
        let r = one(Arch::X86_64, bytes, 0x1000);
        assert_eq!(r.op, op, "{bytes:02x?}");
        assert!(r.effects.sets_flags, "{bytes:02x?}");
        assert_eq!(r.warning, None);
    }
    // lea is address math, mov copies, nop is effect-free: no flags.
    let r = one(Arch::X86_64, &[0x48, 0x8d, 0x03], 0x1000);
    assert_eq!(r.op, IrOp::Add);
    assert!(!r.effects.sets_flags);
    for bytes in [&[0x48, 0x89, 0xd8][..], &[0x90][..]] {
        let r = one(Arch::X86_64, bytes, 0x1000);
        assert!(!r.effects.sets_flags, "{bytes:02x?}");
    }
}

#[test]
fn x86_fp_simd_forms_report_no_flags() {
    // Same ops, but FP/SIMD/FPU-condition writers target no EFLAGS.
    for m in [
        "fadd", "faddp", "fiadd", "addps", "vaddps", "paddb", "fsub", "fisub", "subps", "vsubps",
        "psubb", "fcom", "fcomp", "ftst", "fxam", "ficom", "pcmpeqb", "vpcmpeqb", "pcmpgtb",
        "cmpeqps", "vcmpeqps",
    ] {
        let v = lift(Arch::X86_64, &synth(m, &[]));
        assert_eq!(v.len(), 1, "{m}");
        assert!(!v[0].effects.sets_flags, "{m} op {:?}", v[0].op);
        assert_eq!(v[0].warning, None, "{m}");
    }
    // The EFLAGS-writing FP compares do report flags.
    let r = one(Arch::X86_64, &[0x0f, 0x2e, 0xc0], 0x1000); // comiss
    assert_eq!(r.op, IrOp::Cmp);
    assert!(r.effects.sets_flags);
    for m in ["fcomi", "fucomip", "vtestps", "vptest", "ucomisd"] {
        let v = lift(Arch::X86_64, &synth(m, &[]));
        assert_eq!(v[0].op, IrOp::Cmp, "{m}");
        assert!(v[0].effects.sets_flags, "{m}");
    }
}

#[test]
fn x86_push_pop_call_ret_sp_deltas_64() {
    for (bytes, delta) in [
        (&[0x50][..], Some(-8)),             // push rax
        (&[0x58][..], Some(8)),              // pop rax
        (&[0x9c][..], Some(-8)),             // pushfq
        (&[0x9d][..], Some(8)),              // popfq
        (&[0xe8, 0, 0, 0, 0][..], Some(-8)), // call +0
        (&[0xc3][..], Some(8)),              // ret
    ] {
        let r = one(Arch::X86_64, bytes, 0x1000);
        assert_eq!(r.effects.sp_delta, delta, "{bytes:02x?}");
        assert!(!r.effects.sets_flags, "{bytes:02x?}");
        assert_eq!(r.warning, None);
    }
    // ret with an immediate pops extra arguments: unmodeled.
    let r = one(Arch::X86_64, &[0xc2, 0x08, 0x00], 0x1000);
    assert_eq!(r.op, IrOp::Return);
    assert_eq!(r.effects.sp_delta, None);
    // Traps push privileged state, not a plain slot: unmodeled.
    for bytes in [&[0x0f, 0x05][..], &[0xcd, 0x80][..]] {
        let r = one(Arch::X86_64, bytes, 0x1000);
        assert_eq!(r.op, IrOp::Call, "{bytes:02x?}");
        assert_eq!(r.effects.sp_delta, None, "{bytes:02x?}");
    }
    // Plain flow carries no stack effect.
    let r = one(Arch::X86_64, &[0xeb, 0x00], 0x1000);
    assert_eq!(r.op, IrOp::Branch);
    assert_eq!(r.effects.sp_delta, None);
}

#[test]
fn x86_sp_deltas_32() {
    for (bytes, delta) in [
        (&[0x50][..], Some(-4)), // push eax
        (&[0x58][..], Some(4)),  // pop eax
        (&[0xe8, 0, 0, 0, 0][..], Some(-4)),
        (&[0xc3][..], Some(4)),
        (&[0x60][..], Some(-32)), // pushad
        (&[0x61][..], Some(32)),  // popad
    ] {
        let r = one(Arch::X86_32, bytes, 0x1000);
        assert_eq!(r.effects.sp_delta, delta, "{bytes:02x?}");
    }
    // 16-bit multi-push constants need no mode.
    assert_eq!(
        lift(Arch::X86_64, &synth("pusha", &[]))[0].effects.sp_delta,
        Some(-16)
    );
    assert_eq!(
        lift(Arch::X86_32, &synth("popa", &[]))[0].effects.sp_delta,
        Some(16)
    );
    // lift_x86 is mode-agnostic by design: flags are complete, but
    // slot-sized deltas are assigned by lift(), so direct rows report none.
    let v = lift_x86(&synth("push", &["rax"]));
    assert!(!v[0].effects.sets_flags);
    assert_eq!(v[0].effects.sp_delta, None);
    assert_eq!(
        lift(Arch::X86_64, &synth("push", &["rax"]))[0]
            .effects
            .sp_delta,
        Some(-8)
    );
}

#[test]
fn aarch64_flag_writers() {
    for m in [
        "adds", "adcs", "subs", "sbcs", "negs", "ngcs", "cmp", "cmn", "tst", "ccmp", "ccmn",
        "cmtst", "fcmp", "fcmpe", "fccmp", "fccmpe",
    ] {
        let v = lift(Arch::Aarch64, &synth(m, &[]));
        assert_eq!(v.len(), 1, "{m}");
        assert!(v[0].effects.sets_flags, "{m} op {:?}", v[0].op);
        assert_eq!(v[0].warning, None, "{m}");
    }
    for (m, op) in [
        ("add", IrOp::Add),
        ("adc", IrOp::Add),
        ("fadd", IrOp::Add),
        ("sub", IrOp::Sub),
        ("sbc", IrOp::Sub),
        ("neg", IrOp::Sub),
        ("fsub", IrOp::Sub),
        ("cmeq", IrOp::Cmp),
        ("cmgt", IrOp::Cmp),
        ("cas", IrOp::Cmp),
        ("ldadd", IrOp::Add),
    ] {
        let v = lift(Arch::Aarch64, &synth(m, &[]));
        assert_eq!(v[0].op, op, "{m}");
        assert!(!v[0].effects.sets_flags, "{m}");
    }
    // Calls and returns are link-register moves: no SP effect, no flags.
    for m in ["bl", "blr", "ret", "svc"] {
        let v = lift(Arch::Aarch64, &synth(m, &[]));
        assert_eq!(v[0].effects.sp_delta, None, "{m}");
        assert!(!v[0].effects.sets_flags, "{m}");
    }
}

#[test]
fn arm32_flag_writers() {
    for arch in [Arch::Arm32, Arch::Thumb] {
        for m in ["adds", "subs", "rsbs", "cmp", "cmn", "tst", "teq"] {
            let v = lift(arch, &synth(m, &[]));
            assert!(v[0].effects.sets_flags, "{arch:?} {m} op {:?}", v[0].op);
            assert_eq!(v[0].warning, None, "{arch:?} {m}");
        }
        for m in ["add", "addeq", "sub", "rsb", "movs", "svc", "qadd"] {
            let v = lift(arch, &synth(m, &[]));
            assert!(!v[0].effects.sets_flags, "{arch:?} {m} op {:?}", v[0].op);
        }
        // Multi-register push/pop need register-list decoding: none.
        for m in ["push", "pop"] {
            let v = lift(arch, &synth(m, &["{r4, lr}"]));
            assert_eq!(v[0].effects.sp_delta, None, "{arch:?} {m}");
            assert!(!v[0].effects.sets_flags, "{arch:?} {m}");
        }
        for m in ["bl", "svc"] {
            let v = lift(arch, &synth(m, &[]));
            assert_eq!(v[0].effects.sp_delta, None, "{arch:?} {m}");
        }
    }
}

#[test]
fn unmapped_and_plain_ops_carry_no_effects() {
    let v = lift(Arch::X86_64, &synth("cpuid", &[]));
    assert_eq!(v[0].op, IrOp::Nop);
    assert!(v[0].warning.is_some());
    assert!(!v[0].effects.sets_flags);
    assert_eq!(v[0].effects.sp_delta, None);
    for m in ["mov", "jmp", "nop"] {
        let v = lift(Arch::X86_64, &synth(m, &[]));
        assert!(!v[0].effects.sets_flags, "{m}");
        assert_eq!(v[0].effects.sp_delta, None, "{m}");
    }
}

#[test]
fn legacy_rows_decode_with_default_effects() {
    let ir: binscout::ir::IrInsn = serde_json::from_value(serde_json::json!({
        "addr": 8192, "op": "Return", "inputs": [], "outputs": [],
        "target": null, "warning": null,
    }))
    .expect("legacy ir without effects");
    assert!(!ir.effects.sets_flags);
    assert_eq!(ir.effects.sp_delta, None);
    let v = serde_json::to_value(&ir).expect("json");
    assert_eq!(v["effects"]["sets_flags"], false);
    assert!(v["effects"]["sp_delta"].is_null());
}

#[test]
fn effects_visible_through_project_ir() {
    // push rax ; ret as a raw fallback blob.
    let dir = tmpdir("ir-effects-e2e");
    let bin = write_bin(&dir, "stack.bin", &[0x50, 0xc3]);
    let db = temp_db(&dir, "stack");
    let p = binscout::Project::open_with_db(&bin, &db).expect("raw fallback opens");
    let v = p.ir_at(0, 2).expect("ir rows");
    let rows = v["ir"].as_array().expect("ir array");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["op"], "Store");
    assert_eq!(rows[0]["effects"]["sp_delta"], -8);
    assert_eq!(rows[1]["op"], "Return");
    assert_eq!(rows[1]["effects"]["sp_delta"], 8);
    assert!(!db.exists(), "reads never create the sidecar");
    cleanup(&dir);
}

#[test]
fn coverage_documents_scoped_effects() {
    use binscout::ir::CoverageStatus;
    let c = coverage(Arch::X86_64);
    assert!(
        c.limitations.iter().any(|l| l.contains("sets_flags")),
        "{:?}",
        c.limitations
    );
    assert!(c.limitations.iter().any(|l| l.contains("sp_delta")));
    for op in [
        IrOp::Add,
        IrOp::Sub,
        IrOp::Cmp,
        IrOp::Load,
        IrOp::Store,
        IrOp::Call,
        IrOp::Return,
    ] {
        let f = c
            .families
            .iter()
            .find(|f| f.op == op)
            .unwrap_or_else(|| panic!("no {op:?} family"));
        assert!(f.note.is_some(), "{op:?}");
        assert_ne!(f.status, CoverageStatus::Unmapped, "{op:?}");
    }
}
