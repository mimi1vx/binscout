mod common;

use binscout::analysis::{XrefKind, analyze_raw};
use binscout::disasm::{Arch, disasm_range};

use common::builders;

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
fn arm32_bl_discovers_callee() {
    // bl 0x5008 | bx lr | bx lr
    let b = vec![
        0x00, 0x00, 0x00, 0xEB, 0x1E, 0xFF, 0x2F, 0xE1, 0x1E, 0xFF, 0x2F, 0xE1,
    ];
    let a = analyze_raw(&b, 0x5000, Arch::Arm32, Some(0x5000)).expect("arm32 blob analyzes");
    assert_eq!(a.summary().functions, 2);
    assert_eq!(a.call_edges(), [(0x5000, 0x5008)]);
    let codes = a.xrefs_page(Some(XrefKind::Code), 0, 64);
    assert!(codes.iter().any(|x| x.from == 0x5000 && x.to == 0x5008));
}

#[test]
fn arm32_prologue_scan_seeds_unreachable_function() {
    // bx lr | push {r4-r7, lr} | bx lr: the middle function is only found
    // via the prologue scan.
    let b = vec![
        0x1E, 0xFF, 0x2F, 0xE1, 0xF0, 0x40, 0x2D, 0xE9, 0x1E, 0xFF, 0x2F, 0xE1,
    ];
    let a = analyze_raw(&b, 0x5000, Arch::Arm32, Some(0x5000)).expect("arm32 blob analyzes");
    assert_eq!(a.summary().functions, 2);
    assert!(a.functions.contains_key(&0x5004));
}

#[test]
fn thumb_bl_discovers_callee() {
    // bl #0 | bx lr: bl at 0x5000 targets 0x5004.
    let b = vec![0x00, 0xF0, 0x00, 0xF8, 0x70, 0x47];
    let a = analyze_raw(&b, 0x5000, Arch::Thumb, Some(0x5000)).expect("thumb blob analyzes");
    assert_eq!(a.summary().functions, 2);
    assert_eq!(a.call_edges(), [(0x5000, 0x5004)]);
    let codes = a.xrefs_page(Some(XrefKind::Code), 0, 64);
    assert!(codes.iter().any(|x| x.from == 0x5000 && x.to == 0x5004));
}

#[test]
fn thumb_prologue_scan_seeds_unreachable_function() {
    // bx lr | push {r4-r7, lr} | bx lr, all 16-bit.
    let b = vec![0x70, 0x47, 0xF0, 0xB5, 0x70, 0x47];
    let a = analyze_raw(&b, 0x5000, Arch::Thumb, Some(0x5000)).expect("thumb blob analyzes");
    assert_eq!(a.summary().functions, 2);
    assert!(a.functions.contains_key(&0x5002));
}

#[test]
fn arm32_literal_ldr_reports_data_xref() {
    // ldr r0, [pc, #4] at 0x5000 reads 0x500c; bx lr ends the function.
    let b = vec![
        0x04, 0x00, 0x9F, 0xE5, 0x1E, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let a = analyze_raw(&b, 0x5000, Arch::Arm32, Some(0x5000)).expect("arm32 blob analyzes");
    let data = a.xrefs_page(Some(XrefKind::Data), 0, 64);
    assert!(data.iter().any(|x| x.from == 0x5000 && x.to == 0x500c));
}

#[test]
fn containing_function_snaps_mid_function_but_not_gaps() {
    let a = x64(&two_funcs(), 0x1000, Some(0x1000));
    assert_eq!(a.containing_function(0x1000), Some(0x1000));
    assert_eq!(a.containing_function(0x1005), Some(0x1000));
    assert_eq!(a.containing_function(0x1010), Some(0x1010));
    assert_eq!(a.containing_function(0x1014), Some(0x1010));
    assert_eq!(a.containing_function(0x0FFF), None);
    // Padding between func@0x1000's end (0x100B) and 0x1010 belongs to none.
    assert_eq!(a.containing_function(0x100C), None);
    assert_eq!(a.containing_function(0x2000), None);
}

#[test]
fn callers_mirror_callees() {
    let a = x64(&two_funcs(), 0x1000, Some(0x1000));
    assert_eq!(a.callers_of(0x1010), [0x1000]);
    assert!(a.callers_of(0x1000).is_empty());
    assert!(a.callers_of(0x9999).is_empty());
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

// X2/A4: PE32 absolute `push imm32` refs recover as data + string xrefs.
// Ground truth (`le32_refs`) holds exactly two LE32 occurrences of the
// marker VA in `.text`; decoded `from` is the push start, one byte before
// each window.
#[test]
fn pe32_basic_absolute_imm32_recovers_data_and_string_xrefs() {
    let bytes = common::fixture_bytes(builders::BASIC_NAME);
    let bin = binscout::loader::load(&bytes).expect("synthetic PE32 must load");
    let text = &bin.sections[0].data;
    assert_eq!(bin.sections[0].vaddr, builders::TEXT_VA);
    let windows = common::le32_refs(text, builders::TEXT_VA, builders::BASIC_STRING_VA);
    assert_eq!(windows.len(), 2, "ground truth: two push-imm32 refs");

    let a = binscout::analysis::analyze(&bin).expect("PE32 analyzes");
    let to_str = a.xrefs_to(builders::BASIC_STRING_VA);
    let data: Vec<_> = to_str.iter().filter(|x| x.kind == XrefKind::Data).collect();
    let strings: Vec<_> = to_str
        .iter()
        .filter(|x| x.kind == XrefKind::String)
        .collect();
    assert!(
        data.len() >= 2,
        "two push-imm32 data refs expected: {to_str:?}"
    );
    assert!(
        strings.len() >= 2,
        "two string refs into the marker expected: {to_str:?}"
    );
    let text_end = builders::TEXT_VA + text.len() as u64;
    for x in data.iter().chain(strings.iter()) {
        assert!(
            (builders::TEXT_VA..text_end).contains(&x.from),
            "ref must originate inside .text: {x:?}"
        );
    }
    let mut froms: Vec<u64> = data.iter().map(|x| x.from).collect();
    froms.sort_unstable();
    let mut expect: Vec<u64> = windows.iter().map(|w| w - 1).collect();
    expect.sort_unstable();
    assert_eq!(froms, expect, "decoded refs match the LE32 ground truth");
}

// X1/A3: count_xrefs is the unpaged match count behind the `total`
// envelope field, so paging never scans blind.
#[test]
fn count_xrefs_matches_query_before_paging() {
    let dir = common::tmpdir("x1-count");
    let p = common::open_test_project(&dir, builders::BASIC_NAME);
    let to = Some(builders::BASIC_STRING_VA);
    assert_eq!(p.count_xrefs(to, None, None), 4);
    assert_eq!(
        p.count_xrefs(to, None, Some(XrefKind::String)),
        2,
        "two string refs into the marker"
    );
    let page = p.query_xrefs(to, None, None, 1, 1);
    assert_eq!(page.len(), 1, "paged rows shrink but the total does not");
    assert_eq!(p.count_xrefs(to, None, None), 4);
    common::cleanup(&dir);
}

// X2/A4: byte-noise strings in undecodable trailers must not become refs.
#[test]
fn garbage_fixture_yields_no_string_xrefs() {
    let dir = common::tmpdir("x2-garbage");
    let p = common::open_test_project(&dir, builders::GARBAGE_NAME);
    assert!(
        p.analysis()
            .xrefs_page(Some(XrefKind::String), 0, 64)
            .is_empty(),
        "garbage must produce zero false string xrefs"
    );
    common::cleanup(&dir);
}
