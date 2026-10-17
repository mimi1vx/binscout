//! rsdbg-zvm.5: Thumb IT blocks predicate the following instructions.
//!
//! `cmp r0, #0; it eq; bx lr; movs r0, #0; bx lr`: the first `bx lr` is
//! predicated (conditional return), so the tail stays reachable. A stateless
//! decode sees an unconditional `bx lr` and truncates the function.

use binscout::analysis::{DiagnosticKind, analyze_raw};
use binscout::disasm::Arch;

#[test]
fn it_block_keeps_both_returns_reachable() {
    let b = vec![
        0x00, 0x28, // cmp r0, #0
        0x08, 0xBF, // it eq
        0x70, 0x47, // bx lr (predicated: conditional return)
        0x00, 0x20, // movs r0, #0
        0x70, 0x47, // bx lr
    ];
    let a =
        analyze_raw(&b, 0x2000, Arch::Thumb, Some(0x2000)).expect("synthetic thumb must analyze");
    for (entry, f) in &a.functions {
        eprintln!("func {entry:#x}:");
        for (start, blk) in &f.blocks {
            for i in &blk.insns {
                eprintln!(
                    "  {start:#x}: {:#x} {} {:?}",
                    i.addr,
                    i.mnem,
                    i.ops.join(", ")
                );
            }
        }
        eprintln!("  edges: {:?}", f.edges());
    }
    for d in &a.diagnostics.records {
        eprintln!("diag {:#x} {:?}", d.addr, d.kind);
    }
    assert_eq!(a.functions.len(), 1, "one function, tail included");
    let f = a.functions.get(&0x2000).expect("function at base");
    assert_eq!(
        f.insn_count(),
        5,
        "predicated bx lr must not end the function"
    );
    assert!(
        f.blocks
            .values()
            .flat_map(|b| b.insns.iter())
            .any(|i| i.addr == 0x2008),
        "second bx lr must be reachable"
    );
    assert!(
        a.diagnostics
            .records
            .iter()
            .any(|d| d.addr == 0x2004 && d.kind == DiagnosticKind::UnresolvedIndirectJump),
        "predicated bx lr needs an indirect-jump diagnostic"
    );
    let pred_block = f
        .blocks
        .values()
        .find(|b| b.insns.iter().any(|i| i.addr == 0x2004));
    let pred_block = pred_block.expect("block holding the predicated bx lr");
    assert!(
        f.successors(pred_block.start).contains(&0x2006),
        "predicated terminator keeps a fallthrough edge to {:#x}",
        0x2006
    );
}
