//! rsdbg-zvm.6: ARM ELF Thumb interworking bit on seeds must not decode
//! as ARM garbage.
//!
//! `e_entry`/`STT_FUNC` carry bit 0 set for Thumb functions. The bit
//! selects a Thumb-mode seed at the masked address (see rsdbg-em6.13),
//! never an ARM decode at the odd address. When the bytes fail to decode
//! as Thumb, the walker reports the failure at the masked address.

use binscout::analysis::{DiscoveryReason, analyze};
use binscout::disasm::Arch;
use binscout::loader::{BinaryFormat, LoadedBinary, Segment};

#[test]
fn odd_arm_entry_seeds_thumb_mode() {
    // arm32 `mov r0, r1; bx lr` at 0x8000 (decodes as one Thumb
    // instruction, then fails: Thumb coverage, not ARM garbage).
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
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        debug_funcs: Vec::new(),
        relocatable: false,
        arm_hints: Default::default(),
    };
    let a = analyze(&bin).expect("synthetic arm elf must analyze");
    assert!(
        a.functions.contains_key(&0x8000),
        "masked entry must decode as a function"
    );
    assert!(
        !a.functions.contains_key(&0x8001),
        "no garbage function at the odd Thumb-bit address"
    );
    assert_eq!(
        a.functions
            .get(&0x8000)
            .expect("function at masked entry")
            .decode_arch,
        Some(Arch::Thumb),
        "Thumb-bit entry decodes as Thumb, not ARM"
    );
    assert!(
        a.functions
            .get(&0x8000)
            .expect("function at masked entry")
            .blocks
            .values()
            .flat_map(|b| &b.insns)
            .all(|i| i.thumb),
        "every row of the entry function carries its Thumb decode mode"
    );
    assert_eq!(
        a.functions
            .get(&0x8000)
            .expect("function at masked entry")
            .reason_list(),
        [DiscoveryReason::Entry],
        "masked entry keeps its Entry reason"
    );
}
