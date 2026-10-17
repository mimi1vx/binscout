//! rsdbg-zvm.6: ARM ELF Thumb interworking bit on seeds must not decode
//! as ARM garbage.
//!
//! `e_entry`/`STT_FUNC` carry bit 0 set for Thumb functions. Containers
//! default to arm32, so an odd seed must be masked to even (with a
//! diagnostic), never decoded at the odd address.

use binscout::analysis::analyze;
use binscout::disasm::Arch;
use binscout::loader::{BinaryFormat, LoadedBinary, Segment};

#[test]
fn odd_arm_entry_is_masked_with_diagnostic() {
    // arm32 `mov r0, r1; bx lr` at 0x8000.
    let code = vec![0x01, 0x00, 0xA0, 0xE1, 0x1E, 0xFF, 0x2F, 0xE1];
    let bin = LoadedBinary {
        format: BinaryFormat::Elf,
        arch: Arch::Arm32,
        entry: Some(0x8001),
        segments: vec![Segment {
            vaddr: 0x8000,
            mem_size: code.len() as u64,
            data: code,
            readable: true,
            writable: false,
            executable: true,
        }],
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        symbols: Vec::new(),
    };
    let a = analyze(&bin).expect("synthetic arm elf must analyze");
    for (entry, f) in &a.functions {
        eprintln!("func {entry:#x}: {} insns", f.insn_count());
    }
    for d in &a.diagnostics.records {
        eprintln!("diag {:#x} {:?}", d.addr, d.kind);
    }
    assert!(
        a.functions.contains_key(&0x8000),
        "masked entry must decode as a function"
    );
    assert!(
        !a.functions.contains_key(&0x8001),
        "no garbage function at the odd Thumb-bit address"
    );
    assert!(
        a.diagnostics.records.iter().any(
            |d| d.addr == 0x8001 && d.kind == binscout::analysis::DiagnosticKind::DecodeFailure
        ),
        "masking the interworking bit must leave a decode-failure diagnostic"
    );
    assert_eq!(
        a.functions
            .get(&0x8000)
            .expect("function at masked entry")
            .reason_list(),
        [binscout::analysis::DiscoveryReason::Entry],
        "masked entry keeps its Entry reason"
    );
}
