use binscout::disasm::{Arch, Disassembler, disasm_range};
use binscout::ir::{IrOp, coverage, is_mapped, lift, lift_range};

mod common;

use std::collections::HashSet;

use common::{cleanup, temp_db, tmpdir, write_bin};

const ALL_ARCHES: [Arch; 5] = [
    Arch::X86_64,
    Arch::X86_32,
    Arch::Aarch64,
    Arch::Arm32,
    Arch::Thumb,
];

fn arch_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "x86_64",
        Arch::X86_32 => "x86_32",
        Arch::Aarch64 => "aarch64",
        Arch::Arm32 => "arm32",
        Arch::Thumb => "thumb",
    }
}

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
    }
}

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

#[test]
fn x86_popcnt_is_not_a_load() {
    // popcnt eax, eax decodes but is a bit-count, not a stack pop.
    let v = x86(&[0xf3, 0x0f, 0xb8, 0xc0], 0x1000);
    assert_eq!(v[0].op, IrOp::Nop);
    assert!(v[0].warning.is_some());
}

/// Unmapped mnemonic per arch for the fallback checks below.
fn unmapped_mnem(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 | Arch::X86_32 => "cpuid",
        Arch::Aarch64 | Arch::Arm32 | Arch::Thumb => "mrs",
    }
}

fn family(c: &binscout::ir::Coverage, op: IrOp) -> &binscout::ir::FamilyCoverage {
    c.families
        .iter()
        .find(|f| f.op == op)
        .unwrap_or_else(|| panic!("no {op:?} family"))
}

#[test]
fn coverage_publishes_all_families_limits_and_fallback() {
    use binscout::ir::{COVERAGE_LIMITATIONS, CoverageStatus};
    for arch in ALL_ARCHES {
        let c = coverage(arch);
        assert_eq!(c.arch, arch_name(arch));
        // One family per op, in IrOp declaration order, Phi never lifted.
        assert_eq!(c.families.len(), 19, "{arch:?}");
        assert_eq!(family(&c, IrOp::Phi).status, CoverageStatus::Unmapped);
        assert!(family(&c, IrOp::Phi).mnemonics.is_empty());
        assert_eq!(
            c.limitations,
            COVERAGE_LIMITATIONS
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(c.fallback.op, IrOp::Nop);
        assert_eq!(c.fallback.status, CoverageStatus::Unmapped);
        assert!(c.fallback.warning.contains("unlifted"), "{arch:?}");
        assert!(!c.fallback.distinguish.is_empty());
        // Only ARM32/Thumb read base forms through suffix stripping.
        assert_eq!(
            c.arch_note.is_some(),
            matches!(arch, Arch::Arm32 | Arch::Thumb),
            "{arch:?}"
        );
    }
}

#[test]
fn genuine_nop_and_fallback_nop_are_distinguishable() {
    for arch in ALL_ARCHES {
        // Genuine `nop` lifts clean in every mode.
        let v = lift(arch, &synth("nop", &[]));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].op, IrOp::Nop, "{arch:?}");
        assert_eq!(v[0].warning, None, "{arch:?}");
        assert!(is_mapped(arch, "nop"), "{arch:?}");
        // An unmapped mnemonic falls back to NOP with a warning.
        let unmapped = unmapped_mnem(arch);
        let v = lift(arch, &synth(unmapped, &[]));
        assert_eq!(v[0].op, IrOp::Nop, "{arch:?}");
        let want = format!("unlifted '{unmapped}'; emitted NOP");
        assert_eq!(v[0].warning.as_deref(), Some(want.as_str()), "{arch:?}");
        assert!(!is_mapped(arch, unmapped), "{arch:?}");
        // The published tables agree: `nop` advertised, fallback not.
        let c = coverage(arch);
        assert!(
            family(&c, IrOp::Nop).mnemonics.contains(&"nop".to_string()),
            "{arch:?}"
        );
        assert!(
            c.families
                .iter()
                .flat_map(|f| f.mnemonics.iter())
                .all(|m| m != unmapped),
            "{arch:?}"
        );
    }
    // Real bytes end to end: x86 `nop` vs `cpuid`, aarch64 `nop`.
    let v = x86(&[0x90], 0x1000);
    assert_eq!((v[0].op, v[0].warning.clone()), (IrOp::Nop, None));
    let v = x86(&[0x0f, 0xa2], 0x1000);
    assert_eq!(v[0].op, IrOp::Nop);
    assert!(v[0].warning.is_some());
    let v = arm(&[0x1f, 0x20, 0x03, 0xd5], 0x4000);
    assert_eq!((v[0].op, v[0].warning.clone()), (IrOp::Nop, None));
}

#[test]
fn advertised_families_match_actual_lifts() {
    use binscout::ir::CoverageStatus;
    for arch in ALL_ARCHES {
        let c = coverage(arch);
        // No literal mnemonic belongs to two families.
        let mut seen: HashSet<&str> = HashSet::new();
        for f in &c.families {
            for m in &f.mnemonics {
                assert!(seen.insert(m.as_str()), "{arch:?} {m} in two families");
            }
        }
        // Every listed mnemonic (and pattern example) lifts with no warning
        // to its family's op.
        for f in &c.families {
            if f.status == CoverageStatus::Unmapped {
                continue;
            }
            for m in &f.mnemonics {
                assert!(is_mapped(arch, m), "{arch:?} {m} not mapped");
                let v = lift(arch, &synth(m, &[]));
                assert_eq!(v.len(), 1, "{arch:?} {m}");
                assert_eq!(v[0].warning, None, "{arch:?} {m}");
                assert_eq!(v[0].op, f.op, "{arch:?} {m}");
            }
        }
        // Pattern members lift too (AArch64 `b.<cond>` / `bc.<cond>`).
        for f in &c.families {
            for p in &f.patterns {
                let example = p.replace("<cond>", "eq");
                assert!(is_mapped(arch, &example), "{arch:?} {p}");
                let v = lift(arch, &synth(&example, &[]));
                assert_eq!(v[0].warning, None, "{arch:?} {p}");
                assert_eq!(v[0].op, f.op, "{arch:?} {p}");
            }
        }
        // Suffixed ARM32/Thumb forms count as mapped through base reduction.
        if matches!(arch, Arch::Arm32 | Arch::Thumb) {
            for m in ["addeq", "bl.w", "beq", "movs"] {
                assert!(is_mapped(arch, m), "{arch:?} {m}");
            }
        }
    }
}

#[test]
fn partial_means_mapped_but_semantically_incomplete() {
    use binscout::ir::CoverageStatus;
    for arch in ALL_ARCHES {
        let c = coverage(arch);
        // CMP records the comparison; flag effects are unmodeled everywhere.
        assert_eq!(
            family(&c, IrOp::Cmp).status,
            CoverageStatus::Partial,
            "{arch:?}"
        );
        let v = lift(arch, &synth("cmp", &[]));
        assert_eq!(v[0].op, IrOp::Cmp, "{arch:?}");
        assert_eq!(v[0].warning, None, "{arch:?}");
        // Rotates approximate to shifts.
        assert_eq!(
            family(&c, IrOp::Shr).status,
            CoverageStatus::Partial,
            "{arch:?}"
        );
        // Implemented families still disclaim completeness globally.
        assert!(c.limitations.iter().any(|l| l.contains("SSA")), "{arch:?}");
        assert!(
            c.limitations
                .iter()
                .any(|l| l.contains("not semantically complete")),
            "{arch:?}"
        );
    }
}

#[test]
fn range_accounting_agrees_with_actual_lifts() {
    // cpuid (unmapped) x2, nop, ret: raw fallback maps at base 0.
    let dir = tmpdir("ir-coverage-range");
    let bin = write_bin(&dir, "mixed.bin", &[0x0f, 0xa2, 0x0f, 0xa2, 0x90, 0xc3]);
    let db = temp_db(&dir, "mixed");
    let p = binscout::Project::open_with_db(&bin, &db).expect("raw fallback opens");
    assert_eq!(p.binary().arch, Arch::X86_64);

    let v = p
        .ir_coverage_at(Arch::X86_64, 0, 6)
        .expect("coverage range");
    assert_eq!(v["arch"], "x86_64");
    let range = &v["range"];
    assert_eq!(
        (range["addr"].as_u64(), range["addr_hex"].as_str()),
        (Some(0), Some("0x0"))
    );
    assert_eq!(range["decoded"], 4);
    assert_eq!(range["lifted"], 2);
    assert_eq!(range["unlifted"], 2);
    assert_eq!(
        range["unlifted_mnemonics"],
        serde_json::json!([{"mnemonic": "cpuid", "count": 2, "warning": "unlifted 'cpuid'; emitted NOP"}])
    );
    assert_eq!(range["truncated"], false);
    assert!(range["error_at"].is_null());

    // Same counts fall out of the actual `ir` rows.
    let ir = p.ir_at(0, 6).expect("ir rows");
    let rows = ir["ir"].as_array().expect("ir array");
    assert_eq!(rows.len(), range["decoded"].as_u64().unwrap() as usize);
    let warned = rows.iter().filter(|r| !r["warning"].is_null()).count();
    assert_eq!(warned, range["unlifted"].as_u64().unwrap() as usize);

    // Coverage arch must match the binary arch.
    assert!(p.ir_coverage_at(Arch::Aarch64, 0, 6).is_err());
    // Range reads never save the sidecar.
    assert!(!db.exists(), "reads never create the sidecar");
    cleanup(&dir);
}
