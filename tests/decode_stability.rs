use binscout::analysis::{XrefKind, analyze_raw};
use binscout::disasm::{Arch, disasm_first, disasm_range};

// Blob exercising every flow kind plus a data/string ref (base 0x1000):
//   1000: xor eax,eax | cmp eax,1 | je 0x1010
//   1007: call 0x101e | jmp 0x1000 | nop | nop
//   1010: lea rdi,[rip+1] (-> "hello" at 0x1018) | ret | "hello\0"
//   101e: push rbp | mov rbp,rsp | pop rbp | ret
fn blob() -> Vec<u8> {
    vec![
        0x31, 0xC0, // 0x1000: xor eax,eax
        0x83, 0xF8, 0x01, // 0x1002: cmp eax,1
        0x74, 0x09, // 0x1005: je 0x1010
        0xE8, 0x12, 0x00, 0x00, 0x00, // 0x1007: call 0x101e
        0xEB, 0xF2, // 0x100c: jmp 0x1000
        0x90, 0x90, // 0x100e: nop; nop
        0x48, 0x8D, 0x3D, 0x01, 0x00, 0x00, 0x00, // 0x1010: lea rdi,[rip+1]
        0xC3, // 0x1017: ret
        0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00, // 0x1018: "hello\0"
        0x55, // 0x101e: push rbp
        0x48, 0x89, 0xE5, // 0x101f: mov rbp,rsp
        0x5D, // 0x1022: pop rbp
        0xC3, // 0x1023: ret
    ]
}

#[test]
fn sequential_single_decodes_match_range() {
    // The single-instruction path reuses one formatter/text buffer across
    // calls: sequential decodes must equal the range decode exactly.
    let b = blob();
    let code = &b[..0x18];
    let range = disasm_range(Arch::X86_64, code, 0x1000, 64).expect("decodes");
    assert_eq!(range.len(), 9);
    let mut off = 0usize;
    for want in &range {
        let got = disasm_first(Arch::X86_64, &code[off..], want.addr)
            .expect("decodes")
            .expect("non-empty");
        assert_eq!(&got, want, "single decode diverged at {:#x}", want.addr);
        off += got.size as usize;
    }
    assert_eq!(off, code.len());
}

/// One decoded row pinned by [`analyze_output_pins_flows_targets_xrefs`].
struct Row {
    addr: u64,
    mnem: String,
    ops: Vec<String>,
    branch: Option<u64>,
    mem: Option<u64>,
}

#[test]
fn analyze_output_pins_flows_targets_xrefs() {
    // Pins the full analysis output on a blob exercising every flow kind,
    // so future memory-layout refactors (e.g. moving instead of cloning
    // instructions into blocks) cannot change rows silently.
    let b = blob();
    assert_eq!(b.len(), 0x24);
    let a = analyze_raw(&b, 0x1000, Arch::X86_64, Some(0x1000)).expect("analyzes");

    let mut entries: Vec<u64> = a.functions.keys().copied().collect();
    entries.sort_unstable();
    assert_eq!(entries, [0x1000, 0x101E]);
    assert_eq!(a.call_edges(), [(0x1000, 0x101E)]);

    let flat: Vec<Row> = entries
        .iter()
        .flat_map(|e| {
            let f = &a.functions[e];
            let mut starts: Vec<u64> = f.blocks.keys().copied().collect();
            starts.sort_unstable();
            starts.into_iter().flat_map(|s| {
                f.blocks[&s].insns.iter().map(|i| Row {
                    addr: i.addr,
                    mnem: i.mnem.clone(),
                    ops: i.ops.clone(),
                    branch: i.branch_target,
                    mem: i.mem_target,
                })
            })
        })
        .collect();
    assert_eq!(
        flat.iter()
            .map(|r| (r.addr, r.mnem.as_str()))
            .collect::<Vec<_>>(),
        [
            (0x1000, "xor"),
            (0x1002, "cmp"),
            (0x1005, "je"),
            (0x1007, "call"),
            (0x100C, "jmp"),
            (0x1010, "lea"),
            (0x1017, "ret"),
            (0x101E, "push"),
            (0x101F, "mov"),
            (0x1022, "pop"),
            (0x1023, "ret"),
        ]
    );
    assert_eq!(
        flat.iter()
            .map(|r| (r.addr, r.branch, r.mem))
            .collect::<Vec<_>>(),
        [
            (0x1000, None, None),
            (0x1002, None, None),
            (0x1005, Some(0x1010), None),
            (0x1007, Some(0x101E), None),
            (0x100C, Some(0x1000), None),
            (0x1010, None, Some(0x1018)),
            (0x1017, None, None),
            (0x101E, None, None),
            (0x101F, None, None),
            (0x1022, None, None),
            (0x1023, None, None),
        ]
    );
    // Spot-check operand rendering survives the formatter reuse.
    let ops_of = |addr: u64| {
        flat.iter()
            .find(|r| r.addr == addr)
            .map(|r| r.ops.clone())
            .expect("addr present")
    };
    assert_eq!(ops_of(0x1000), ["eax", "eax"]);
    assert_eq!(ops_of(0x1002), ["eax", "1"]);

    let mut xrefs: Vec<(u64, XrefKind, u64)> = a
        .xrefs_page(None, 0, 1024)
        .iter()
        .map(|x| (x.from, x.kind, x.to))
        .collect();
    xrefs.sort();
    assert_eq!(
        xrefs,
        [
            (0x1005, XrefKind::Code, 0x1010),
            (0x1007, XrefKind::Code, 0x101E),
            (0x100C, XrefKind::Code, 0x1000),
            (0x1010, XrefKind::Data, 0x1018),
            (0x1010, XrefKind::String, 0x1018),
        ]
    );
}
