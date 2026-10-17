//! rsdbg-zvm.4: ARM32 writes to `pc` must end the block as control flow.
//!
//! `mov pc, lr` (unconditional) is a return; any other `pc`-writing
//! Copy/Load/ALU instruction (`ldr pc, [pc, #-4]`, `add pc, pc, ...`,
//! conditional `mov pc, lr`) is an indirect branch (conditional when the
//! mnemonic carries a condition suffix). Otherwise the walker falls through
//! into literal pools and jump tables, decoding data as code.

use binscout::analysis::{DiagnosticKind, analyze_raw};
use binscout::disasm::Arch;

fn arm32(bytes: &[u8], base: u64) -> binscout::analysis::Analysis {
    analyze_raw(bytes, base, Arch::Arm32, Some(base)).expect("synthetic arm32 must analyze")
}

fn dump(a: &binscout::analysis::Analysis) {
    for (entry, f) in &a.functions {
        eprintln!("func {entry:#x}:");
        for (start, b) in &f.blocks {
            for i in &b.insns {
                eprintln!(
                    "  {start:#x}: {:#x} {} {:?}",
                    i.addr,
                    i.mnem,
                    i.ops.join(", ")
                );
            }
        }
    }
    for d in &a.diagnostics.records {
        eprintln!("diag {:#x} {:?}", d.addr, d.kind);
    }
}

// `mov r0, r1; ldr pc, [pc, #-4]` + literal word: the literal is data.
#[test]
fn ldr_pc_ends_function_and_marks_indirect_jump() {
    let mut b = vec![
        0x01, 0x00, 0xA0, 0xE1, // mov r0, r1
        0x04, 0xF0, 0x1F, 0xE5, // ldr pc, [pc, #-4]
    ];
    b.extend_from_slice(&0x1000u32.to_le_bytes()); // literal pool word
    let a = arm32(&b, 0x1000);
    dump(&a);
    let f = a.functions.get(&0x1000).expect("function at base");
    assert_eq!(
        f.insn_count(),
        2,
        "literal pool word must not decode as code"
    );
    assert!(
        !f.blocks
            .values()
            .flat_map(|b| b.insns.iter())
            .any(|i| i.addr == 0x1008),
        "literal address must hold no instruction"
    );
    assert!(
        a.diagnostics
            .records
            .iter()
            .any(|d| d.addr == 0x1004 && d.kind == DiagnosticKind::UnresolvedIndirectJump),
        "ldr pc needs an indirect-jump diagnostic"
    );
}

// `mov r0, #1; mov pc, lr; mov r0, #2`: unconditional mov-to-pc returns.
#[test]
fn mov_pc_lr_is_a_return() {
    let b = vec![
        0x01, 0x00, 0xA0, 0xE3, // mov r0, #1
        0x0E, 0xF0, 0xA0, 0xE1, // mov pc, lr
        0x02, 0x00, 0xA0, 0xE3, // mov r0, #2 (dead)
    ];
    let a = arm32(&b, 0x1000);
    dump(&a);
    let f = a.functions.get(&0x1000).expect("function at base");
    assert_eq!(f.insn_count(), 2, "mov pc, lr must end the function");
    assert!(
        a.diagnostics.records.is_empty(),
        "a clean return records nothing"
    );
}

// `moveq pc, lr` is a conditional return: fallthrough survives, and the
// predicated site stays visible as an indirect-jump diagnostic.
#[test]
fn cond_mov_pc_lr_is_a_conditional_branch() {
    let b = vec![
        0x0E, 0xF0, 0xA0, 0x01, // moveq pc, lr
        0x02, 0x00, 0xA0, 0xE3, // mov r0, #2
    ];
    let a = arm32(&b, 0x1000);
    dump(&a);
    let f = a.functions.get(&0x1000).expect("function at base");
    assert_eq!(f.insn_count(), 2, "conditional return must fall through");
    assert!(
        a.diagnostics
            .records
            .iter()
            .any(|d| d.addr == 0x1000 && d.kind == DiagnosticKind::UnresolvedIndirectJump),
        "conditional mov pc needs an indirect-jump diagnostic"
    );
}

// `mov r0, r1; add pc, pc, r0, lsl #2` (switch-table dispatch): indirect
// branch, no fallthrough into the table.
#[test]
fn alu_pc_write_is_an_indirect_branch() {
    let b = vec![
        0x01, 0x00, 0xA0, 0xE1, // mov r0, r1
        0x00, 0xF1, 0x8F, 0xE0, // add pc, pc, r0, lsl #2
        0x00, 0x00, 0x00, 0x00, // table bytes, not code
    ];
    let a = arm32(&b, 0x1000);
    dump(&a);
    let f = a.functions.get(&0x1000).expect("function at base");
    assert_eq!(f.insn_count(), 2, "table bytes must not decode as code");
    assert!(
        a.diagnostics
            .records
            .iter()
            .any(|d| d.addr == 0x1004 && d.kind == DiagnosticKind::UnresolvedIndirectJump),
        "add pc needs an indirect-jump diagnostic"
    );
}
