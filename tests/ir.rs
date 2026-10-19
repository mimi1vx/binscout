use binscout::disasm::{Arch, Disassembler, disasm_range};
use binscout::ir::{IrOp, control_op, coverage, is_mapped, lift, lift_range};

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
        table_base: None,
        import: None,
        target_name: None,
        comment: None,
        string: None,
        operands: Vec::new(),
        thumb: false,
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
fn arm32_ldr_address_stays_one_input() {
    // ldr r0, [r1, #4]: the bracketed address is a single input, the
    // destination the only output.
    let v = arm32(&[0x04, 0x00, 0x91, 0xe5], 0x10000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].op, IrOp::Load);
    assert_eq!(v[0].outputs, ["r0"]);
    assert_eq!(v[0].inputs, ["[r1, 0x4]"]);
    assert_eq!(v[0].warning, None);
}

#[test]
fn arm32_ldr_pc_stays_branch_with_one_address_operand() {
    // ldr pc, [pc, #-4]: a pc destination is control flow, and the
    // bracketed address still arrives as one operand.
    let v = arm32(&[0x04, 0xf0, 0x1f, 0xe5], 0x10000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].op, IrOp::Branch);
    assert!(v[0].outputs.is_empty());
    assert_eq!(v[0].inputs, ["pc", "[pc, -0x4]"]);
    assert_eq!(v[0].warning, None);
}

#[test]
fn arm32_ldm_writeback_splits_base_and_list() {
    // ldm r0!, {r1, r2}: the base is read, the list is written, and the
    // write-back base is written too.
    let v = arm32(&[0x06, 0x00, 0xb0, 0xe8], 0x10000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].op, IrOp::Load);
    assert_eq!(v[0].inputs, ["r0"]);
    assert_eq!(v[0].outputs, ["r1", "r2", "r0"]);
    assert_eq!(v[0].warning, None);
    // Without write-back the base is read-only.
    let v = arm32(&[0x06, 0x00, 0x90, 0xe8], 0x10000);
    assert_eq!(v[0].op, IrOp::Load);
    assert_eq!(v[0].inputs, ["r0"]);
    assert_eq!(v[0].outputs, ["r1", "r2"]);
    assert_eq!(v[0].warning, None);
}

#[test]
fn arm32_store_mirrors_load() {
    // str r0, [r1, #4]: stored value and address are both inputs.
    let v = arm32(&[0x04, 0x00, 0x81, 0xe5], 0x10000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].op, IrOp::Store);
    assert_eq!(v[0].inputs, ["r0", "[r1, 0x4]"]);
    assert!(v[0].outputs.is_empty());
    assert_eq!(v[0].warning, None);
    // stm r0!, {r1, r2}: base plus list are inputs, the write-back
    // base is also an output.
    let v = arm32(&[0x06, 0x00, 0xa0, 0xe8], 0x10000);
    assert_eq!(v[0].op, IrOp::Store);
    assert_eq!(v[0].inputs, ["r0", "r1", "r2"]);
    assert_eq!(v[0].outputs, ["r0"]);
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

#[test]
fn x86_sse_basic_lifts() {
    // movaps/addps anchors plus one member per packed family.
    let cases: &[(&[u8], IrOp)] = &[
        (&[0x0f, 0x28, 0xc0], IrOp::Copy),       // movaps
        (&[0x0f, 0x58, 0xc0], IrOp::Add),        // addps
        (&[0x0f, 0x5c, 0xc0], IrOp::Sub),        // subps
        (&[0x0f, 0x59, 0xc0], IrOp::Mul),        // mulps
        (&[0x0f, 0x5e, 0xc0], IrOp::Div),        // divps
        (&[0x66, 0x0f, 0xdb, 0xc0], IrOp::And),  // pand
        (&[0x0f, 0x56, 0xc0], IrOp::Or),         // orps
        (&[0x0f, 0x57, 0xc0], IrOp::Xor),        // xorps
        (&[0x66, 0x0f, 0xf1, 0xc0], IrOp::Shl),  // psllw
        (&[0x66, 0x0f, 0xd1, 0xc0], IrOp::Shr),  // psrlw
        (&[0x66, 0x0f, 0x74, 0xc0], IrOp::Cmp),  // pcmpeqb
        (&[0x0f, 0xc6, 0xc0, 0x00], IrOp::Copy), // shufps
        (&[0xf3, 0x0f, 0x10, 0xc0], IrOp::Copy), // movss
    ];
    for (bytes, want) in cases {
        let v = x86(bytes, 0x1000);
        assert_eq!(v.len(), 1, "{bytes:02x?}");
        assert_eq!(v[0].op, *want, "{bytes:02x?}");
        assert_eq!(v[0].warning, None, "{bytes:02x?}");
    }
}

#[test]
fn x86_imm_folded_cmp_pseudo_ops_lift() {
    // iced-x86 folds the imm predicate into the mnemonic: there is no plain
    // `cmpps` row, only cmpeqps/cmpltps/...; the vowels match by pattern.
    let v = x86(&[0x0f, 0xc2, 0xc0, 0x00], 0x1000); // cmpeqps
    assert_eq!(v[0].op, IrOp::Cmp);
    assert_eq!(v[0].warning, None);
    let v = x86(&[0xc5, 0xf8, 0xc2, 0xc0, 0x00], 0x1000); // vcmpeqps
    assert_eq!(v[0].op, IrOp::Cmp);
    assert_eq!(v[0].warning, None);
    for m in [
        "cmpeqps",
        "cmpltps",
        "cmpunordss",
        "cmpnlesd",
        "cmpeqpd",
        "cmpordps",
        "vcmpeqps",
        "vcmpltpd",
        "vcmpneqss",
        "vcmpordsd",
        "cmp",
        "test",
        "cmpsb",
        "scasd",
    ] {
        assert!(is_mapped(Arch::X86_64, m), "{m}");
        let v = lift(Arch::X86_64, &synth(m, &[]));
        assert_eq!(v[0].op, IrOp::Cmp, "{m}");
        assert_eq!(v[0].warning, None, "{m}");
    }
    // Near-miss non-compares stay out.
    for m in ["cmpxchg", "cpuid", "popcnt"] {
        assert!(!is_mapped(Arch::X86_64, m), "{m}");
    }
}

#[test]
fn x86_avx_crypto_lifts() {
    let cases: &[(&[u8], IrOp)] = &[
        (&[0xc5, 0xf8, 0x58, 0xc0], IrOp::Add),             // vaddps
        (&[0xc5, 0xf8, 0x28, 0xc0], IrOp::Copy),            // vmovaps
        (&[0xc5, 0xf9, 0xef, 0xc0], IrOp::Xor),             // vpxor
        (&[0xc4, 0xe2, 0x79, 0x18, 0xc0], IrOp::Copy),      // vbroadcastss
        (&[0x66, 0x0f, 0x38, 0xdc, 0xc0], IrOp::Xor),       // aesenc
        (&[0x66, 0x0f, 0x38, 0xdd, 0xc0], IrOp::Xor),       // aesenclast
        (&[0x66, 0x0f, 0x3a, 0xdf, 0xc0, 0x01], IrOp::Xor), // aeskeygenassist
        (&[0x66, 0x0f, 0x3a, 0x44, 0xc0, 0x00], IrOp::Xor), // pclmullqlqdq
        (&[0x0f, 0x38, 0xcb, 0xc0], IrOp::Xor),             // sha256rnds2
        (&[0x0f, 0x3a, 0xcc, 0xc0, 0x00], IrOp::Xor),       // sha1rnds4
        (&[0xf2, 0x0f, 0x38, 0xf1, 0xc0], IrOp::Xor),       // crc32
    ];
    for (bytes, want) in cases {
        let v = x86(bytes, 0x1000);
        assert_eq!(v.len(), 1, "{bytes:02x?}");
        assert_eq!(v[0].op, *want, "{bytes:02x?}");
        assert_eq!(v[0].warning, None, "{bytes:02x?}");
    }
}

#[test]
fn x86_int_bit_string_lifts() {
    let cases: &[(&[u8], IrOp)] = &[
        (&[0x0f, 0x45, 0xc3], IrOp::Copy),             // cmovne
        (&[0x0f, 0x95, 0xc0], IrOp::Copy),             // setne
        (&[0x0f, 0xc8], IrOp::Copy),                   // bswap
        (&[0x99], IrOp::Copy),                         // cdq
        (&[0x0f, 0xa4, 0xd8, 0x01], IrOp::Shl),        // shld
        (&[0x0f, 0xac, 0xd8, 0x01], IrOp::Shr),        // shrd
        (&[0x0f, 0xba, 0xe0, 0x01], IrOp::Cmp),        // bt
        (&[0x0f, 0xab, 0xd8], IrOp::Or),               // bts
        (&[0x0f, 0xb3, 0xd8], IrOp::And),              // btr
        (&[0x0f, 0xbb, 0xd8], IrOp::Xor),              // btc
        (&[0xc4, 0xe2, 0x78, 0xf3, 0xd8], IrOp::And),  // blsi
        (&[0x0f, 0xc7, 0xf0], IrOp::Copy),             // rdrand
        (&[0x0f, 0x31], IrOp::Copy),                   // rdtsc
        (&[0xa4], IrOp::Copy),                         // movsb
        (&[0xab], IrOp::Store),                        // stosd
        (&[0xac], IrOp::Load),                         // lodsb
        (&[0xae], IrOp::Cmp),                          // scasb
        (&[0xa6], IrOp::Cmp),                          // cmpsb
        (&[0xec], IrOp::Load),                         // in al, dx
        (&[0xd7], IrOp::Load),                         // xlat
        (&[0x66, 0x0f, 0x38, 0x2a, 0x00], IrOp::Load), // movntdqa
        (&[0x0f, 0xae, 0x00], IrOp::Store),            // fxsave
        (&[0x0f, 0x07], IrOp::Return),                 // sysret
    ];
    for (bytes, want) in cases {
        let v = x86(bytes, 0x1000);
        assert_eq!(v.len(), 1, "{bytes:02x?}");
        assert_eq!(v[0].op, *want, "{bytes:02x?}");
        assert_eq!(v[0].warning, None, "{bytes:02x?}");
    }
    // Prefixed string/atomic forms lift through the stripped mnemonic.
    let v = x86(&[0xf3, 0xa4], 0x1000); // rep movsb
    assert_eq!((v[0].op, v[0].warning.clone()), (IrOp::Copy, None));
    let v = x86(&[0xf0, 0x01, 0x00], 0x1000); // lock add [rax], eax
    assert_eq!((v[0].op, v[0].warning.clone()), (IrOp::Add, None));
    let v = x86(&[0xf3, 0xc3], 0x1000); // rep ret
    assert_eq!((v[0].op, v[0].warning.clone()), (IrOp::Return, None));
}

#[test]
fn x86_fpu_lifts() {
    let cases: &[(&[u8], IrOp)] = &[
        (&[0xd9, 0x00], IrOp::Load),  // fld dword [rax]
        (&[0xd9, 0xe8], IrOp::Copy),  // fld1
        (&[0xd8, 0xc1], IrOp::Add),   // fadd
        (&[0xde, 0xc1], IrOp::Add),   // faddp
        (&[0xda, 0x00], IrOp::Add),   // fiadd
        (&[0xd8, 0xe0], IrOp::Sub),   // fsub
        (&[0xd8, 0xc9], IrOp::Mul),   // fmul
        (&[0xde, 0xf9], IrOp::Div),   // fdivp
        (&[0xd9, 0x18], IrOp::Store), // fstp dword [rax]
        (&[0xdf, 0x38], IrOp::Store), // fistp qword [rax]
        (&[0xd8, 0x10], IrOp::Cmp),   // fcom
        (&[0xdb, 0xf0], IrOp::Cmp),   // fcomi
        (&[0xda, 0xc0], IrOp::Copy),  // fcmovb
        (&[0xd9, 0xc9], IrOp::Copy),  // fxch
        (&[0xd9, 0xe1], IrOp::Copy),  // fabs
        (&[0xd9, 0xe0], IrOp::Sub),   // fchs
        (&[0xd9, 0x28], IrOp::Load),  // fldcw
        (&[0xd9, 0x38], IrOp::Store), // fnstcw
    ];
    for (bytes, want) in cases {
        let v = x86(bytes, 0x1000);
        assert_eq!(v.len(), 1, "{bytes:02x?}");
        assert_eq!(v[0].op, *want, "{bytes:02x?}");
        assert_eq!(v[0].warning, None, "{bytes:02x?}");
    }
    // fnstsw ax writes ax: single-operand copy.
    let v = x86(&[0xdf, 0xe0], 0x1000);
    assert_eq!(v[0].op, IrOp::Copy);
    assert_eq!(v[0].outputs, ["ax"]);
}

#[test]
fn x86_system_nop_lifts() {
    for bytes in [
        vec![0x0f, 0xae, 0xf0], // mfence
        vec![0x0f, 0xae, 0xe8], // lfence
        vec![0x0f, 0xae, 0xf8], // sfence
        vec![0x0f, 0xae, 0x38], // clflush
        vec![0x0f, 0x18, 0x00], // prefetchnta
        vec![0x0f, 0x77],       // emms
        vec![0xfc],             // cld
        vec![0x9e],             // sahf
        vec![0xc5, 0xf8, 0x77], // vzeroupper
        vec![0x9b],             // fwait
        vec![0xd9, 0xd0],       // fnop
    ] {
        let v = x86(&bytes, 0x1000);
        assert_eq!(
            (v[0].op, v[0].warning.clone()),
            (IrOp::Nop, None),
            "{bytes:02x?}"
        );
    }
    // Deliberately unmapped: queries, counts, atomics, faults.
    for bytes in [
        vec![0x0f, 0xa2],             // cpuid
        vec![0xf3, 0x0f, 0xb8, 0xc0], // popcnt
        vec![0x0f, 0x0b],             // ud2
        vec![0x0f, 0xc1, 0xc0],       // xadd
        vec![0x0f, 0xb1, 0xc0],       // cmpxchg
    ] {
        let v = x86(&bytes, 0x1000);
        assert_eq!(v[0].op, IrOp::Nop, "{bytes:02x?}");
        assert!(v[0].warning.is_some(), "{bytes:02x?}");
    }
}

#[test]
fn arm_fp_simd_lifts() {
    let cases: &[(&[u8], IrOp)] = &[
        (&[0x00, 0x28, 0x21, 0x1e], IrOp::Add),   // fadd s0, s1, s2
        (&[0x00, 0x38, 0x21, 0x1e], IrOp::Sub),   // fsub
        (&[0x00, 0x08, 0x22, 0x1e], IrOp::Mul),   // fmul
        (&[0x00, 0x18, 0x21, 0x1e], IrOp::Div),   // fdiv
        (&[0x00, 0x00, 0x22, 0x1e], IrOp::Copy),  // scvtf
        (&[0x20, 0x20, 0x21, 0x1e], IrOp::Cmp),   // fcmp
        (&[0x20, 0x00, 0x82, 0x9a], IrOp::Copy),  // csel
        (&[0x20, 0x84, 0x21, 0x4e], IrOp::Add),   // add v0.16b, v1.16b, v2.16b
        (&[0x0f, 0xe4, 0x00, 0x0f], IrOp::Copy),  // movi
        (&[0x00, 0x07, 0x40, 0x0c], IrOp::Load),  // ld4
        (&[0x00, 0x07, 0x00, 0x0d], IrOp::Store), // st1
        (&[0x00, 0xc0, 0x40, 0x0d], IrOp::Load),  // ld1r
    ];
    for (bytes, want) in cases {
        let v = arm(bytes, 0x4000);
        assert_eq!(v.len(), 1, "{bytes:02x?}");
        assert_eq!(v[0].op, *want, "{bytes:02x?}");
        assert_eq!(v[0].warning, None, "{bytes:02x?}");
    }
    // Aliases and scalar/SIMD rows without hand-encoded bytes.
    for (m, want) in [
        ("fmov", IrOp::Copy),
        ("fabs", IrOp::Copy),
        ("fneg", IrOp::Sub),
        ("mvn", IrOp::Copy),
        ("sxtb", IrOp::Copy),
        ("ubfx", IrOp::Copy),
        ("bfi", IrOp::Copy),
        ("cinc", IrOp::Copy),
        ("cset", IrOp::Copy),
        ("fcsel", IrOp::Copy),
        ("fmax", IrOp::Copy),
        ("smaxv", IrOp::Copy),
        ("umax", IrOp::Copy),
        ("clz", IrOp::Copy),
        ("cnt", IrOp::Copy),
        ("rbit", IrOp::Copy),
        ("dup", IrOp::Copy),
        ("smov", IrOp::Copy),
        ("ext", IrOp::Copy),
        ("tbl", IrOp::Copy),
        ("addv", IrOp::Add),
        ("faddp", IrOp::Add),
        ("fmla", IrOp::Mul),
        ("fmadd", IrOp::Mul),
        ("udot", IrOp::Mul),
        ("pmull", IrOp::Mul),
        ("mneg", IrOp::Mul),
        ("ngc", IrOp::Sub),
        ("fabd", IrOp::Sub),
        ("subp", IrOp::Sub),
        ("shl", IrOp::Shl),
        ("sqrshl", IrOp::Shl),
        ("shrn", IrOp::Shr),
        ("uqrshrn", IrOp::Shr),
        ("cmeq", IrOp::Cmp),
        ("cmhi", IrOp::Cmp),
        ("fcmp", IrOp::Cmp),
        ("fccmp", IrOp::Cmp),
        ("ccmp", IrOp::Cmp),
        ("bsl", IrOp::Or),
        ("eor3", IrOp::Xor),
        ("mvni", IrOp::Xor),
        ("crc32b", IrOp::Xor),
        ("crc32cx", IrOp::Xor),
        ("aese", IrOp::Xor),
        ("sha256h", IrOp::Xor),
        ("sha512su0", IrOp::Xor),
        ("sm4e", IrOp::Xor),
        ("xar", IrOp::Xor),
    ] {
        assert!(is_mapped(Arch::Aarch64, m), "{m}");
        let v = lift(Arch::Aarch64, &synth(m, &[]));
        assert_eq!(v[0].op, want, "{m}");
        assert_eq!(v[0].warning, None, "{m}");
    }
}

#[test]
fn arm_atomics_and_system_lifts() {
    // w/zr-destination store-only forms lift as STORE.
    for (m, want) in [
        ("ldadd", IrOp::Add),
        ("ldaddl", IrOp::Add),
        ("ldaddalb", IrOp::Add),
        ("ldclr", IrOp::And),
        ("ldeor", IrOp::Xor),
        ("ldeoralh", IrOp::Xor),
        ("ldset", IrOp::Or),
        ("stadd", IrOp::Store),
        ("staddl", IrOp::Store),
        ("steorh", IrOp::Store),
        ("cas", IrOp::Cmp),
        ("casal", IrOp::Cmp),
        ("swp", IrOp::Copy),
        ("swpalh", IrOp::Copy),
        ("ldpsw", IrOp::Load),
        ("ldaxr", IrOp::Load),
        ("stlxr", IrOp::Store),
        ("sys", IrOp::Nop),
        ("sysl", IrOp::Nop),
        ("rmif", IrOp::Nop),
        ("hlt", IrOp::Nop),
        ("clrex", IrOp::Nop),
        ("sb", IrOp::Nop),
        ("yield", IrOp::Nop),
        ("sevl", IrOp::Nop),
        ("psb", IrOp::Nop),
        ("esb", IrOp::Nop),
        ("csdb", IrOp::Nop),
        ("dcps1", IrOp::Nop),
    ] {
        assert!(is_mapped(Arch::Aarch64, m), "{m}");
        let v = lift(Arch::Aarch64, &synth(m, &[]));
        assert_eq!(v[0].op, want, "{m}");
        assert_eq!(v[0].warning, None, "{m}");
    }
    // Real bytes: waits, prefetches, halts.
    for (bytes, want) in [
        (&[0x5f, 0x20, 0x03, 0xd5][..], IrOp::Nop), // wfe
        (&[0x3f, 0x20, 0x03, 0xd5][..], IrOp::Nop), // yield
        (&[0x00, 0x00, 0x80, 0xf9][..], IrOp::Nop), // prfm
        (&[0x00, 0x00, 0x42, 0xd4][..], IrOp::Nop), // hlt
    ] {
        let v = arm(bytes, 0x4000);
        assert_eq!(
            (v[0].op, v[0].warning.clone()),
            (want, None),
            "{bytes:02x?}"
        );
    }
    // mrs/msr/udf stay unmapped.
    for m in ["mrs", "msr", "udf"] {
        assert!(!is_mapped(Arch::Aarch64, m), "{m}");
    }
}

#[test]
fn arm32_extended_lifts() {
    let cases: &[(&[u8], IrOp)] = &[
        (&[0x11, 0x0f, 0x6f, 0xe1], IrOp::Copy), // clz
        (&[0x91, 0x00, 0x02, 0xe1], IrOp::Copy), // swp
        (&[0x90, 0x21, 0x43, 0xe0], IrOp::Mul),  // umaal
        (&[0x90, 0x31, 0x62, 0xe0], IrOp::Mul),  // mls
        (&[0x81, 0x32, 0x00, 0xe1], IrOp::Mul),  // smlabb
        (&[0x81, 0x32, 0x20, 0xe1], IrOp::Mul),  // smlawb
        (&[0x81, 0x30, 0x42, 0xe1], IrOp::Mul),  // smlalbb
        (&[0x81, 0x21, 0x60, 0xe1], IrOp::Mul),  // smulbb
        (&[0x52, 0x00, 0x41, 0xe1], IrOp::Add),  // qdadd
        (&[0x9f, 0x0f, 0x91, 0xe1], IrOp::Load), // ldrex
    ];
    for (bytes, want) in cases {
        let v = arm32(bytes, 0x10000);
        assert_eq!(v.len(), 1, "{bytes:02x?}");
        assert_eq!(v[0].op, *want, "{bytes:02x?}");
        assert_eq!(v[0].warning, None, "{bytes:02x?}");
    }
    // Addressing-mode spellings of ldm/stm join the tables; pc-naming
    // still steers to RETURN (CBRANCH when predicated).
    for m in ["ldmia", "ldmdb", "ldmda", "stmia", "stmdb", "stmda"] {
        assert!(is_mapped(Arch::Arm32, m), "{m}");
        assert!(is_mapped(Arch::Thumb, m), "{m}");
    }
    let v = lift(Arch::Arm32, &synth("ldmia", &["{r4, pc}"]));
    assert_eq!(v[0].op, IrOp::Return);
    let v = lift(Arch::Arm32, &synth("ldmiaeq", &["{r4, pc}"]));
    assert_eq!(v[0].op, IrOp::CBranch);
    let v = lift(Arch::Arm32, &synth("stmdb", &["sp!", "{r4, lr}"]));
    assert_eq!(v[0].op, IrOp::Store);
    for (m, want) in [
        ("ldrt", IrOp::Load),
        ("ldrsbt", IrOp::Load),
        ("strt", IrOp::Store),
        ("strex", IrOp::Store),
        ("qadd", IrOp::Add),
        ("qadd16", IrOp::Add),
        ("uqadd8", IrOp::Add),
        ("qdsub", IrOp::Sub),
        ("qsub8", IrOp::Sub),
        ("rev", IrOp::Copy),
        ("sxth", IrOp::Copy),
        ("uxtb", IrOp::Copy),
        ("bkpt", IrOp::Nop),
        ("it", IrOp::Nop),
        ("hint", IrOp::Nop),
        ("wfe", IrOp::Nop),
        ("cpsid", IrOp::Nop),
        ("setend", IrOp::Nop),
    ] {
        assert!(is_mapped(Arch::Arm32, m), "{m}");
        let v = lift(Arch::Arm32, &synth(m, &[]));
        assert_eq!(v[0].op, want, "{m}");
        assert_eq!(v[0].warning, None, "{m}");
    }
}

#[test]
fn thumb_extended_lifts() {
    let cases: &[(&[u8], IrOp)] = &[
        (&[0x08, 0xba][..], IrOp::Copy),             // rev
        (&[0x48, 0xba][..], IrOp::Copy),             // rev16
        (&[0xc9, 0xba][..], IrOp::Copy),             // revsh
        (&[0x09, 0xb2][..], IrOp::Copy),             // sxth
        (&[0x49, 0xb2][..], IrOp::Copy),             // sxtb
        (&[0x89, 0xb2][..], IrOp::Copy),             // uxth
        (&[0xc9, 0xb2][..], IrOp::Copy),             // uxtb
        (&[0x20, 0xbf][..], IrOp::Nop),              // wfe
        (&[0x08, 0xbf][..], IrOp::Nop),              // it
        (&[0x72, 0xb6][..], IrOp::Nop),              // cpsid
        (&[0x62, 0xb6][..], IrOp::Nop),              // cpsie
        (&[0x50, 0xb6][..], IrOp::Nop),              // setend
        (&[0x00, 0xbe][..], IrOp::Nop),              // bkpt
        (&[0x80, 0xbf][..], IrOp::Nop),              // hint
        (&[0x91, 0xfb, 0xf2, 0xf0][..], IrOp::Div),  // sdiv.w
        (&[0xb1, 0xfb, 0xf2, 0xf0][..], IrOp::Div),  // udiv.w
        (&[0x90, 0xfa, 0xa0, 0xf0][..], IrOp::Copy), // rbit.w
        (&[0xaf, 0xf3, 0xf0, 0x80][..], IrOp::Nop),  // dbg.w
        (&[0x00, 0xdf][..], IrOp::Call),             // svc
    ];
    for (bytes, want) in cases {
        let v = thumb(bytes, 0x20000);
        assert_eq!(v.len(), 1, "{bytes:02x?}");
        assert_eq!(v[0].op, *want, "{bytes:02x?}");
        assert_eq!(v[0].warning, None, "{bytes:02x?}");
    }
}

#[test]
fn arm_adrp_add_pair_second_row_carries_final_address() {
    // adrp x0, #0 at 0x4000 (page 0x4000); add x0, x0, #0x10 => 0x4010.
    let bytes = [0x00, 0x00, 0x00, 0x90, 0x00, 0x40, 0x00, 0x91];
    let insns = disasm_range(Arch::Aarch64, &bytes, 0x4000, 100).expect("pair decodes");
    assert_eq!(insns.len(), 2);
    let v = lift_range(Arch::Aarch64, &insns);
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].op, IrOp::Copy);
    assert_eq!(v[0].target, None);
    assert_eq!(v[1].op, IrOp::Add);
    assert_eq!(v[1].target, Some(0x4010));
    assert_eq!(v[1].warning, None);
    // Unresolvable pair keeps current behavior: mismatched base leaves no target.
    let bad = [0x00, 0x00, 0x00, 0x90, 0x20, 0x40, 0x00, 0x91];
    let insns = disasm_range(Arch::Aarch64, &bad, 0x4000, 100).expect("pair decodes");
    let v = lift_range(Arch::Aarch64, &insns);
    assert_eq!(v[1].op, IrOp::Add);
    assert_eq!(v[1].target, None);
}

#[test]
fn arm_pac_control_flow_lifts() {
    // Pointer-authenticated returns end the function like `ret`.
    for m in ["retaa", "retab", "eretaa", "eretab"] {
        assert!(is_mapped(Arch::Aarch64, m), "{m}");
        let v = lift(Arch::Aarch64, &synth(m, &[]));
        assert_eq!(v.len(), 1, "{m}");
        assert_eq!(v[0].op, IrOp::Return, "{m}");
        assert_eq!(v[0].target, None, "{m}");
        assert_eq!(v[0].warning, None, "{m}");
    }
    // Pointer-authenticated branches/calls are always indirect: operands
    // kept, no target, mirroring `br`/`blr`.
    for (m, ops, want) in [
        ("braa", &["x16", "x15"][..], IrOp::Branch),
        ("brab", &["x16", "x15"][..], IrOp::Branch),
        ("braaz", &["x16"][..], IrOp::Branch),
        ("brabz", &["x16"][..], IrOp::Branch),
        ("blraa", &["x16", "x15"][..], IrOp::Call),
        ("blrab", &["x16", "x15"][..], IrOp::Call),
        ("blraaz", &["x16"][..], IrOp::Call),
        ("blrabz", &["x16"][..], IrOp::Call),
    ] {
        assert!(is_mapped(Arch::Aarch64, m), "{m}");
        let v = lift(Arch::Aarch64, &synth(m, ops));
        assert_eq!(v.len(), 1, "{m}");
        assert_eq!(v[0].op, want, "{m}");
        assert_eq!(v[0].target, None, "{m}");
        assert_eq!(v[0].inputs, ops, "{m}");
        assert_eq!(v[0].warning, None, "{m}");
    }
    // Real bytes end to end: retab (0xD65F0FFF), braaz x16, blraaz x16.
    let v = arm(&[0xFF, 0x0F, 0x5F, 0xD6], 0x4000);
    assert_eq!((v[0].op, v[0].warning.clone()), (IrOp::Return, None));
    let v = arm(&[0x1F, 0x0A, 0x1F, 0xD6], 0x4000);
    assert_eq!(v[0].op, IrOp::Branch);
    assert_eq!(v[0].target, None);
    assert_eq!(v[0].inputs, ["x16"]);
    assert_eq!(v[0].warning, None);
    let v = arm(&[0x1F, 0x0A, 0x3F, 0xD6], 0x4000);
    assert_eq!(v[0].op, IrOp::Call);
    assert_eq!(v[0].target, None);
    assert_eq!(v[0].inputs, ["x16"]);
    assert_eq!(v[0].warning, None);
}

/// `control_op` agrees with `lift` on one instruction: `Some((op, target))`
/// exactly when the lifted first row is a control op, `None` otherwise.
fn assert_control_matches_lift(arch: Arch, insn: &binscout::disasm::Insn) {
    let rows = lift(arch, insn);
    assert_eq!(rows.len(), 1, "{:?} {}", arch, insn.mnem);
    let expected = match rows[0].op {
        IrOp::Branch | IrOp::CBranch | IrOp::Call | IrOp::Return => {
            Some((rows[0].op, rows[0].target))
        }
        _ => None,
    };
    assert_eq!(
        control_op(arch, insn),
        expected,
        "{:?} {} {:?}",
        arch,
        insn.mnem,
        insn.ops
    );
}

fn synth_target(mnem: &str, ops: &[&str], target: Option<u64>) -> binscout::disasm::Insn {
    let mut insn = synth(mnem, ops);
    insn.branch_target = target;
    insn
}

#[test]
fn control_op_matches_lift() {
    use Arch::{Aarch64, Arm32, Thumb, X86_32, X86_64};
    // Every control-flow arm of each lifter, direct (with target) and
    // indirect (without), plus fallthrough samples and unmapped mnemonics.
    let cases: &[(Arch, &str, &[&str], Option<u64>)] = &[
        (X86_64, "jmp", &["0x1005"], Some(0x1005)),
        (X86_64, "jmp", &["rax"], None),
        (X86_64, "call", &["0x1005"], Some(0x1005)),
        (X86_64, "call", &["rax"], None),
        (X86_64, "syscall", &[], None),
        (X86_64, "sysenter", &[], None),
        (X86_64, "int", &["0x3"], None),
        (X86_64, "int3", &[], None),
        (X86_64, "ret", &[], None),
        (X86_64, "retn", &[], None),
        (X86_64, "retf", &[], None),
        (X86_64, "iret", &[], None),
        (X86_64, "iretd", &[], None),
        (X86_64, "iretq", &[], None),
        (X86_64, "sysret", &[], None),
        (X86_64, "sysexit", &[], None),
        (X86_64, "mov", &["rax", "rbx"], None),
        (X86_64, "pop", &["rax"], None),
        (X86_64, "push", &["rax"], None),
        (X86_64, "add", &["rax", "rbx"], None),
        (X86_64, "cmp", &["rax", "rbx"], None),
        (X86_64, "test", &["rax", "rax"], None),
        (X86_64, "nop", &[], None),
        (X86_64, "pause", &[], None),
        (X86_64, "cpuid", &[], None),
        (X86_64, "ud2", &[], None),
        (X86_32, "jmp", &["0x1005"], Some(0x1005)),
        (X86_32, "call", &["0x1005"], Some(0x1005)),
        (X86_32, "je", &["0x1005"], Some(0x1005)),
        (X86_32, "ret", &[], None),
        (X86_32, "mov", &["eax", "ebx"], None),
        (Aarch64, "b", &["0x4010"], Some(0x4010)),
        (Aarch64, "br", &["x16"], None),
        (Aarch64, "braa", &["x16", "x15"], None),
        (Aarch64, "brab", &["x16", "x15"], None),
        (Aarch64, "braaz", &["x16"], None),
        (Aarch64, "brabz", &["x16"], None),
        (Aarch64, "cbz", &["w0", "0x4010"], Some(0x4010)),
        (Aarch64, "cbnz", &["x0", "0x4010"], Some(0x4010)),
        (Aarch64, "tbz", &["w0", "#0", "0x4010"], Some(0x4010)),
        (Aarch64, "tbnz", &["x0", "#3", "0x4010"], Some(0x4010)),
        (Aarch64, "b.eq", &["0x4010"], Some(0x4010)),
        (Aarch64, "b.hs", &["0x4010"], Some(0x4010)),
        (Aarch64, "bc.eq", &["0x4010"], Some(0x4010)),
        (Aarch64, "bl", &["0x4010"], Some(0x4010)),
        (Aarch64, "blr", &["x16"], None),
        (Aarch64, "blraa", &["x16", "x15"], None),
        (Aarch64, "blrab", &["x16", "x15"], None),
        (Aarch64, "blraaz", &["x16"], None),
        (Aarch64, "blrabz", &["x16"], None),
        (Aarch64, "svc", &["#0"], None),
        (Aarch64, "hvc", &["#0"], None),
        (Aarch64, "smc", &["#0"], None),
        (Aarch64, "ret", &[], None),
        (Aarch64, "eret", &[], None),
        (Aarch64, "retaa", &[], None),
        (Aarch64, "eretab", &[], None),
        (Aarch64, "mov", &["x0", "x1"], None),
        (Aarch64, "add", &["x0", "x0", "#0x10"], None),
        (Aarch64, "ldr", &["x0", "[x1]"], None),
        (Aarch64, "nop", &[], None),
        (Aarch64, "mrs", &["x0", "tpidr_el0"], None),
        (Arm32, "b", &["0x5008"], Some(0x5008)),
        (Arm32, "beq", &["0x5008"], Some(0x5008)),
        (Arm32, "bne", &["0x5008"], Some(0x5008)),
        (Arm32, "bl", &["0x5008"], Some(0x5008)),
        (Arm32, "bleq", &["0x5008"], Some(0x5008)),
        (Arm32, "blx", &["0x5008"], Some(0x5008)),
        (Arm32, "bx", &["lr"], None),
        (Arm32, "bx", &["r0"], None),
        (Arm32, "bxne", &["lr"], None),
        (Arm32, "cbz", &["r0", "0x5008"], Some(0x5008)),
        (Arm32, "cbnz", &["r0", "0x5008"], Some(0x5008)),
        (Arm32, "tbb", &["[r0, r1]"], None),
        (Arm32, "tbh", &["[r0, r1, lsl #1]"], None),
        (Arm32, "svc", &["#0"], None),
        (Arm32, "mov", &["pc", "lr"], None),
        (Arm32, "movne", &["pc", "lr"], None),
        (Arm32, "adds", &["pc", "r0", "r1"], None),
        (Arm32, "ldr", &["pc", "[pc, #-4]"], Some(0x5008)),
        (Arm32, "pop", &["{r4, pc}"], None),
        (Arm32, "popeq", &["{r4, pc}"], None),
        (Arm32, "mov", &["r0", "r1"], None),
        (Arm32, "ldr", &["r0", "[pc, #4]"], None),
        (Arm32, "push", &["{r4, lr}"], None),
        (Arm32, "nop", &[], None),
        (Arm32, "xyzzy", &[], None),
        (Thumb, "b", &["0x5008"], Some(0x5008)),
        (Thumb, "bne", &["0x5008"], Some(0x5008)),
        (Thumb, "bl", &["0x5008"], Some(0x5008)),
        (Thumb, "blx", &["0x5008"], Some(0x5008)),
        (Thumb, "bl.w", &["0x5008"], Some(0x5008)),
        (Thumb, "bx", &["lr"], None),
        (Thumb, "cbz", &["r0", "0x5008"], Some(0x5008)),
        (Thumb, "tbb", &["[r0, r1]"], None),
        (Thumb, "svc", &["#0"], None),
        (Thumb, "mov", &["pc", "lr"], None),
        (Thumb, "pop", &["{r4, pc}"], None),
        (Thumb, "it", &["tt"], None),
        (Thumb, "movs", &["r0", "r1"], None),
        (Thumb, "nop", &[], None),
    ];
    for (arch, mnem, ops, target) in cases {
        let insn = synth_target(mnem, ops, *target);
        assert_control_matches_lift(*arch, &insn);
    }
    // Every x86 conditional-jump mnemonic takes the conditional branch arm.
    for m in [
        "jo", "jno", "jb", "jnae", "jc", "jnb", "jae", "jnc", "je", "jz", "jne", "jnz", "jbe",
        "jna", "jnbe", "ja", "js", "jns", "jp", "jpe", "jnp", "jpo", "jl", "jnge", "jnl", "jge",
        "jle", "jng", "jnle", "jg", "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne",
    ] {
        let insn = synth_target(m, &["0x1005"], Some(0x1005));
        assert_control_matches_lift(X86_64, &insn);
        assert_eq!(
            control_op(X86_64, &insn),
            Some((IrOp::CBranch, Some(0x1005))),
            "{m}"
        );
    }
    // Real decoder output end to end: every instruction decoded from these
    // blobs must agree too, so mnemonic-format drift cannot hide a gap in
    // the synthetic corpus above.
    let x86_blob: &[u8] = &[
        0x48, 0x89, 0xd8, // mov rax, rbx
        0x74, 0x02, // je +2
        0xe8, 0x00, 0x00, 0x00, 0x00, // call +0
        0xeb, 0x00, // jmp +0
        0xc3, // ret
        0x90, // nop
        0x0f, 0xa2, // cpuid (unmapped)
    ];
    let insns = disasm_range(X86_64, x86_blob, 0x1000, 100).expect("x86 decodes");
    assert!(insns.len() >= 7, "{}", insns.len());
    for insn in &insns {
        assert_control_matches_lift(X86_64, insn);
    }
    let insns = X86_32
        .disassembler()
        .disasm_range(x86_blob, 0x1000)
        .expect("x86_32 decodes");
    for insn in &insns {
        assert_control_matches_lift(X86_32, insn);
    }
    let arm_blob: &[u8] = &[
        0x04, 0x00, 0x00, 0x14, // b #0x10
        0x04, 0x00, 0x00, 0x94, // bl #0x10
        0x40, 0x00, 0x00, 0x34, // cbz w0, #0x10
        0x40, 0x00, 0x00, 0x54, // b.eq #0x10
        0xc0, 0x03, 0x5f, 0xd6, // ret
        0x00, 0x00, 0x1f, 0xd6, // br x0
        0x00, 0x00, 0x3f, 0xd6, // blr x0
        0x01, 0x00, 0x00, 0xd4, // svc #0
        0xe0, 0x03, 0x01, 0xaa, // mov x0, x1
        0xe0, 0x41, 0x30, 0xd5, // mrs x0, tpidr_el0 (unmapped)
    ];
    let insns = disasm_range(Aarch64, arm_blob, 0x4000, 100).expect("aarch64 decodes");
    assert_eq!(insns.len(), 10);
    let mut saw_control = 0;
    let mut saw_seq = 0;
    for insn in &insns {
        assert_control_matches_lift(Aarch64, insn);
        if control_op(Aarch64, insn).is_some() {
            saw_control += 1;
        } else {
            saw_seq += 1;
        }
    }
    assert!(saw_control >= 7, "{saw_control}");
    assert!(saw_seq >= 2, "{saw_seq}");
    let arm32_blob: &[u8] = &[
        0x02, 0x00, 0x00, 0xea, // b #0x10
        0x02, 0x00, 0x00, 0xeb, // bl #0x10
        0x02, 0x00, 0x00, 0x1a, // bne #0x10
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
        0x0e, 0xf0, 0xa0, 0xe1, // mov pc, lr
        0x04, 0xf0, 0x1f, 0xe5, // ldr pc, [pc, #-4]
        0x00, 0x00, 0x00, 0xef, // svc #0
        0x02, 0x00, 0x81, 0xe0, // add r0, r1, r2
    ];
    let insns = disasm_range(Arm32, arm32_blob, 0x5000, 100).expect("arm32 decodes");
    assert_eq!(insns.len(), 8);
    for insn in &insns {
        assert_control_matches_lift(Arm32, insn);
    }
    let thumb_blob: &[u8] = &[
        0x08, 0xe0, // b #0x10
        0x00, 0xf0, 0x00, 0xf8, // bl #0
        0x70, 0x47, // bx lr
        0x08, 0xb1, // cbz r0, #8
        0x00, 0xdf, // svc #0
        0x08, 0x46, // mov r0, r1
    ];
    let insns = Thumb
        .disassembler()
        .disasm_range(thumb_blob, 0x5000)
        .expect("thumb decodes");
    assert!(insns.len() >= 6, "{}", insns.len());
    for insn in &insns {
        assert_control_matches_lift(Thumb, insn);
    }
}
