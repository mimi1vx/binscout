use binscout::analysis::{XrefKind, analyze_raw};
use binscout::disasm::{Arch, disasm_range};

fn x64(bytes: &[u8], base: u64, entry: Option<u64>) -> binscout::analysis::Analysis {
    analyze_raw(bytes, base, Arch::X86_64, entry).expect("golden blob must analyze")
}

// func@0x1000 calls func@0x1010:
//   1000: push rbp | mov rbp,rsp | call 0x1010 | pop rbp | ret | nop*5
//   1010: push rbp | mov rbp,rsp | mov eax,1   | pop rbp | ret
fn two_funcs() -> Vec<u8> {
    let mut b = vec![
        0x55, 0x48, 0x89, 0xE5, 0xE8, 0x07, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0x90, 0x90, 0x90, 0x90,
        0x90,
    ];
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ]);
    b
}

#[test]
fn call_discovers_callee_and_callgraph_edge() {
    let a = x64(&two_funcs(), 0x1000, Some(0x1000));
    let s = a.summary();
    assert_eq!(s.functions, 2);
    assert!(a.functions.contains_key(&0x1000));
    assert!(a.functions.contains_key(&0x1010));
    assert_eq!(a.call_edges(), [(0x1000, 0x1010)]);
    assert_eq!(a.calls_of(0x1000), [0x1010]);
    assert!(a.calls_of(0x1010).is_empty());
    let codes = a.xrefs_page(Some(XrefKind::Code), 0, 64);
    assert!(codes.iter().any(|x| x.from == 0x1004 && x.to == 0x1010));
    assert_eq!(a.functions[&0x1000].id(), "func@0x1000");
}

#[test]
fn conditional_branch_splits_three_blocks() {
    // xor eax,eax | cmp eax,1 | je 0x200d | mov eax,1 | ret | mov eax,2 | ret
    let b = vec![
        0x31, 0xC0, 0x83, 0xF8, 0x01, 0x74, 0x06, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xB8, 0x02,
        0x00, 0x00, 0x00, 0xC3,
    ];
    let a = x64(&b, 0x2000, Some(0x2000));
    assert_eq!(a.summary().functions, 1);
    let f = &a.functions[&0x2000];
    assert_eq!(f.blocks.len(), 3);
    let mut succs = f.successors(0x2000);
    succs.sort_unstable();
    assert_eq!(succs, [0x2007, 0x200D]);
    let to_target = a.xrefs_to(0x200D);
    assert!(
        to_target
            .iter()
            .any(|x| x.from == 0x2005 && x.kind == XrefKind::Code)
    );
    let rows = a.blocks_page(0x2000, 0, 16).expect("function exists");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].start, 0x2000);
    assert_eq!(rows[0].end, 0x2007);
    assert!(a.blocks_page(0x9999, 0, 16).is_none());
}

#[test]
fn prologue_scan_finds_unreachable_function() {
    // entry=None: ret | nop*7 | push rbp | mov rbp,rsp | ret
    let mut b = vec![0xC3];
    b.extend([0x90; 7]);
    b.extend([0x55, 0x48, 0x89, 0xE5, 0xC3]);
    let a = x64(&b, 0x3000, None);
    assert!(a.functions.contains_key(&0x3000));
    assert!(a.functions.contains_key(&0x3008));
    assert_eq!(a.summary().functions, 2);
}

#[test]
fn rip_relative_load_links_string_ref() {
    // lea rdi,[rip+5] | ret | nop*4 | "test!\0"  (target 0x4007+5 = 0x400c)
    let mut b = vec![0x48, 0x8D, 0x3D, 0x05, 0x00, 0x00, 0x00, 0xC3];
    b.extend([0x90; 4]);
    b.extend(*b"test!\0");
    let va = 0x4000;
    let insns = disasm_range(Arch::X86_64, &b, va, 16).expect("decodes");
    assert_eq!(insns[0].mem_target, Some(0x400C));
    assert_eq!(insns[0].branch_target, None);

    let a = x64(&b, va, Some(va));
    let hit = a
        .strings
        .iter()
        .find(|h| h.value == "test!")
        .expect("string found");
    assert_eq!(hit.vaddr, Some(0x400C));
    let data = a.xrefs_page(Some(XrefKind::Data), 0, 64);
    assert!(data.iter().any(|x| x.from == va && x.to == 0x400C));
    let srefs = a.xrefs_page(Some(XrefKind::String), 0, 64);
    assert!(srefs.iter().any(|x| x.from == va && x.to == 0x400C));
}

#[test]
fn arm64_bl_discovers_callee() {
    // bl 0x5008 | ret | movz x0,#1 | ret
    let b = vec![
        0x02, 0x00, 0x00, 0x94, 0xC0, 0x03, 0x5F, 0xD6, 0x20, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F,
        0xD6,
    ];
    let a = analyze_raw(&b, 0x5000, Arch::Aarch64, Some(0x5000)).expect("arm blob analyzes");
    assert_eq!(a.summary().functions, 2);
    assert_eq!(a.call_edges(), [(0x5000, 0x5008)]);
    let codes = a.xrefs_page(Some(XrefKind::Code), 0, 64);
    assert!(codes.iter().any(|x| x.from == 0x5000 && x.to == 0x5008));
}

#[test]
fn arm64_adr_reports_data_target() {
    // adr x0, +8 at 0x6000: imm21=8 -> immlo=0, immhi=2 -> 0x10000040
    let v = disasm_range(Arch::Aarch64, &[0x40, 0x00, 0x00, 0x10], 0x6000, 4).expect("adr decodes");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].branch_target, None);
    assert_eq!(v[0].mem_target, Some(0x6008));
}

#[test]
fn query_pages_and_summary() {
    let a = x64(&two_funcs(), 0x1000, Some(0x1000));
    let s = a.summary();
    assert_eq!(s.functions, 2);
    assert!(s.blocks >= 2 && s.insns >= 2 && s.xrefs >= 1);
    assert_eq!(s.xrefs, a.xrefs.len());
    let first = a.functions_page(0, 1);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].entry, 0x1000);
    let second = a.functions_page(1, 1);
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].entry, 0x1010);
    assert!(a.functions_page(9, 4).is_empty());
    let insns = a.block_insns(0x1000, 0x1000, 0, 2).expect("block exists");
    assert_eq!(insns.len(), 2);
    assert!(a.block_insns(0x1000, 0x9999, 0, 8).is_none());
    let from_call = a.xrefs_from(0x1004);
    assert!(!from_call.is_empty());
}
