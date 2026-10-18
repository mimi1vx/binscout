mod common;

use binscout::analysis::{DiagnosticKind, XrefKind, analyze_raw, function_owner};
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
fn prologue_scan_on_ret_heavy_blob_seeds_only_real_prologues() {
    // Reported slow path at CI scale: 64 KiB of `ret` holds no x86 prologue
    // first byte, so the streaming scan skips it and seeds only the planted
    // prologues (plus the base-fallback function).
    let mut b = vec![0xC3u8; 64 * 1024];
    let p1 = 0x1000usize;
    b[p1..p1 + 5].copy_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0xC3]);
    let p2 = 0x2000usize;
    b[p2..p2 + 4].copy_from_slice(&[0x48, 0x89, 0xE5, 0xC3]);
    let p3 = 0x3000usize;
    b[p3..p3 + 5].copy_from_slice(&[0xF3, 0x0F, 0x1E, 0xFA, 0xC3]);
    let base = 0x3000u64;
    let a = x64(&b, base, None);
    let mut got: Vec<u64> = a.functions.keys().copied().collect();
    got.sort_unstable();
    assert_eq!(
        got,
        [base, base + p1 as u64, base + p2 as u64, base + p3 as u64]
    );
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
fn arm64_adrp_add_pair_links_string_at_final_address() {
    // adrp x0, #0 at 0x4000 (page 0x4000); add x0, x0, #0x10; ret; nop;
    // "hello!\0" at 0x4010. The pair resolves to the string start while
    // the page-base row is retained.
    let mut b = vec![
        0x00, 0x00, 0x00, 0x90, // adrp x0, #0
        0x00, 0x40, 0x00, 0x91, // add x0, x0, #0x10
        0xC0, 0x03, 0x5F, 0xD6, // ret
        0x1F, 0x20, 0x03, 0xD5, // nop (padding to 0x4010)
    ];
    b.extend(*b"hello!\0");
    let va = 0x4000u64;
    assert_eq!(va + b.len() as u64, 0x4017);
    let a = analyze_raw(&b, va, Arch::Aarch64, Some(va)).expect("arm blob analyzes");
    assert!(
        a.strings
            .iter()
            .any(|h| h.value == "hello!" && h.vaddr == Some(0x4010)),
        "string at the pair final address: {:?}",
        a.strings
    );
    let data = a.xrefs_page(Some(XrefKind::Data), 0, 64);
    assert!(
        data.iter().any(|x| x.from == 0x4004 && x.to == 0x4010),
        "pair final address from the add: {data:?}"
    );
    assert!(
        data.iter().any(|x| x.from == 0x4000 && x.to == 0x4000),
        "page-base row retained: {data:?}"
    );
    let srefs = a.xrefs_page(Some(XrefKind::String), 0, 64);
    assert!(
        srefs.iter().any(|x| x.from == 0x4004 && x.to == 0x4010),
        "string ref follows the pair Data xref: {srefs:?}"
    );
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
    let text = common::section_bytes(&bin, 0);
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

// Reference linear scan without the below-first fallback: unowned below.
fn linear_owner(entries: &[u64], va: u64) -> Option<u64> {
    entries.iter().rfind(|e| **e <= va).copied()
}

#[test]
fn function_owner_boundary_cases() {
    let entries = vec![0x1000, 0x1010, 0x1030];
    // Below first is unowned, matching `containing_function`.
    assert_eq!(function_owner(&entries, 0x0FFF), None);
    assert_eq!(function_owner(&entries, 0x0000), None);
    // Exactly at entries.
    assert_eq!(function_owner(&entries, 0x1000), Some(0x1000));
    assert_eq!(function_owner(&entries, 0x1010), Some(0x1010));
    assert_eq!(function_owner(&entries, 0x1030), Some(0x1030));
    // In gaps snaps to greatest entry below.
    assert_eq!(function_owner(&entries, 0x1005), Some(0x1000));
    assert_eq!(function_owner(&entries, 0x101F), Some(0x1010));
    assert_eq!(function_owner(&entries, 0x102F), Some(0x1010));
    // Above last snaps to last.
    assert_eq!(function_owner(&entries, 0x1031), Some(0x1030));
    assert_eq!(function_owner(&entries, 0xFFFF), Some(0x1030));
    // Empty entries own nothing.
    let empty: Vec<u64> = vec![];
    assert_eq!(function_owner(&empty, 0x1000), None);
    // Single entry owns itself and above, nothing below.
    let single = vec![0x2000];
    assert_eq!(function_owner(&single, 0x1FFF), None);
    assert_eq!(function_owner(&single, 0x2000), Some(0x2000));
    assert_eq!(function_owner(&single, 0x2001), Some(0x2000));
}

#[test]
fn function_owner_matches_linear_scan_on_generated_set() {
    let entries: Vec<u64> = (0..128).map(|i| 0x1000 + i * 0x11).collect();
    let last = *entries.last().expect("non-empty");
    let mut addrs: Vec<u64> = vec![0, 0x0FFF, last + 1, last + 0x20, u64::MAX];
    for e in &entries {
        addrs.push(*e);
        addrs.push(e.wrapping_sub(1));
        addrs.push(e.wrapping_add(1));
    }
    // Deterministic xorshift sweep across and beyond the entry range.
    let mut x: u64 = 0x1234_5678_9ABC_DEF1;
    for _ in 0..4096 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        addrs.push(0x0F00 + (x % (last - 0x0F00 + 0x40)));
    }
    for va in addrs {
        assert_eq!(
            function_owner(&entries, va),
            linear_owner(&entries, va),
            "owner mismatch at {va:#x}"
        );
    }
}

#[test]
fn backward_jump_below_first_entry_stays_unowned() {
    // Seed at 0x1010 jumps back below the lowest entry; the target decodes
    // but must stay unowned so block ownership, `func` lookups, and slice
    // `func` fields agree (all null below the first entry).
    // 0x1000: call 0x1010 | 0x1005: ret | 0x1006..0x100F: nop * 10 |
    // 0x1010: jmp 0x1000.
    let mut b = vec![0xE8, 0x0B, 0x00, 0x00, 0x00, 0xC3];
    b.extend([0x90; 10]);
    b.extend([0xE9, 0xEB, 0xFF, 0xFF, 0xFF]);
    assert_eq!(b.len(), 0x15);
    let a = x64(&b, 0x1000, Some(0x1010));
    assert_eq!(function_owner(&[0x1010], 0x1000), None);
    assert_eq!(function_owner(&[0x1010], 0x1010), Some(0x1010));
    assert_eq!(a.containing_function(0x1000), None);
    assert_eq!(a.containing_function(0x1005), None);
    assert_eq!(a.containing_function(0x1010), Some(0x1010));
    for f in a.functions.values() {
        for block in f.blocks.values() {
            assert!(
                0x1000 < block.start || 0x1000 >= block.end(),
                "unowned addr in block {:#x}",
                block.start
            );
        }
    }
    let dir = common::tmpdir("owner-below-first");
    let bin = common::write_bin(&dir, "below.bin", &b);
    let db = common::temp_db(&dir, "below");
    let opts = binscout::loader::RawOptions {
        base: 0x1000,
        arch: binscout::disasm::Arch::X86_64,
        entry: Some(0x1010),
    };
    let p = binscout::Project::open_raw(&bin, &db, opts).expect("raw open");
    assert_eq!(p.analysis().containing_function(0x1000), None);
    assert!(p.func_detail(0x1000).is_err());
    let page = p.slice_page(0x1010, 5, 0, 64).expect("slice pages");
    let row = page
        .items
        .iter()
        .find(|n| n.addr == 0x1000)
        .expect("call xref reaches below-entry addr");
    assert_eq!(row.func, None);
    assert_eq!(row.func, p.analysis().containing_function(row.addr));
    for n in &page.items {
        assert_eq!(n.func, p.analysis().containing_function(n.addr));
    }
    common::cleanup(&dir);
}

// One 11-byte frame function: push rbp; mov rbp,rsp; mov eax,1; pop rbp; ret.
// Holds `48 89 E5` with a leading `55`, so the prologue scan seeds every copy.
fn frame_func() -> Vec<u8> {
    vec![
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ]
}

fn many_frame_blob(n: usize) -> Vec<u8> {
    let mut b = Vec::with_capacity(n * 11);
    for _ in 0..n {
        b.extend(frame_func());
    }
    b
}

#[test]
fn many_function_ownership_matches_reference_and_golden() {
    const N: usize = 256;
    const BASE: u64 = 0x1000;
    const STRIDE: u64 = 11;
    let blob = many_frame_blob(N);
    let a = x64(&blob, BASE, Some(BASE));
    let entries: Vec<u64> = (0..N as u64).map(|i| BASE + i * STRIDE).collect();
    assert_eq!(a.summary().functions, N);
    assert_eq!(a.summary().blocks, N);
    let found: Vec<u64> = a.functions.keys().copied().collect();
    assert_eq!(found, entries, "every frame copy is its own function");
    // Golden: one single-block function each, no CFG/callgraph edges.
    for e in &entries {
        let f = &a.functions[e];
        assert_eq!(f.blocks.len(), 1, "func {e:#x} holds one block");
        assert!(f.blocks.contains_key(e), "block starts at entry {e:#x}");
        assert_eq!(f.insn_count(), 5);
        assert!(f.edges().is_empty());
        assert!(a.calls_of(*e).is_empty());
    }
    assert!(a.call_edges().is_empty());
    // Every block start attributes to the reference linear owner.
    for (entry, f) in &a.functions {
        for start in f.blocks.keys() {
            assert_eq!(function_owner(&entries, *start), Some(*entry));
            assert_eq!(linear_owner(&entries, *start), Some(*entry));
        }
    }
    // Generated sweep across the whole span agrees differentially.
    let last = BASE + (N as u64 - 1) * STRIDE;
    let mut x: u64 = 0xDEAD_BEEF_CAFE_F00D;
    for _ in 0..2048 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let va = (BASE - 0x10).wrapping_add(x % (last - BASE + 0x30));
        assert_eq!(function_owner(&entries, va), linear_owner(&entries, va));
    }
}

#[test]
fn arm32_hostile_word_ends_path_without_abort() {
    // The entry word panics inside yaxpeax-arm; the contained Invalid ends
    // the path via decode_one instead of aborting the process.
    let hostile = vec![0xF9, 0xF0, 0x00, 0x00];
    let a = analyze_raw(&hostile, 0x1000, Arch::Arm32, Some(0x1000)).expect("hostile analyzes");
    assert_eq!(a.summary().insns, 0);
    // A valid prefix before the hostile word is kept; the path ends there.
    let mut prefixed = vec![0x01, 0x00, 0xA0, 0xE1];
    prefixed.extend(&hostile);
    let a = analyze_raw(&prefixed, 0x1000, Arch::Arm32, Some(0x1000)).expect("prefixed analyzes");
    assert_eq!(a.summary().insns, 1);
    assert_eq!(a.functions[&0x1000].insn_count(), 1);
}

#[test]
fn arm64_pac_retab_ends_function() {
    // nop; retab; 7x nop at 0x1000: `retab` terminates like `ret`, so the
    // fallthrough nops are never swallowed into func@0x1000.
    let mut b = vec![0x1F, 0x20, 0x03, 0xD5, 0xFF, 0x0F, 0x5F, 0xD6];
    for _ in 0..7 {
        b.extend([0x1F, 0x20, 0x03, 0xD5]);
    }
    let a = analyze_raw(&b, 0x1000, Arch::Aarch64, Some(0x1000)).expect("arm blob analyzes");
    assert!(a.functions.contains_key(&0x1000));
    assert_eq!(a.functions[&0x1000].insn_count(), 2);
    assert_eq!(a.summary().functions, 1);
}

#[test]
fn arm64_pac_indirect_call_and_branch_diagnose() {
    // blraaz x16; ret: indirect call site, then return.
    let b = vec![0x1F, 0x0A, 0x3F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6];
    let a = analyze_raw(&b, 0x1000, Arch::Aarch64, Some(0x1000)).expect("arm blob analyzes");
    assert_eq!(a.functions[&0x1000].insn_count(), 2);
    assert!(
        a.diagnostics
            .records
            .iter()
            .any(|d| d.addr == 0x1000 && d.kind == DiagnosticKind::UnresolvedIndirectCall),
        "blraaz must diagnose: {:?}",
        a.diagnostics.records
    );
    assert!(a.call_edges().is_empty());
    // braaz x16: indirect branch ends the path.
    let b = vec![0x1F, 0x0A, 0x1F, 0xD6];
    let a = analyze_raw(&b, 0x2000, Arch::Aarch64, Some(0x2000)).expect("arm blob analyzes");
    assert_eq!(a.functions[&0x2000].insn_count(), 1);
    assert!(
        a.diagnostics
            .records
            .iter()
            .any(|d| d.addr == 0x2000 && d.kind == DiagnosticKind::UnresolvedIndirectJump),
        "braaz must diagnose: {:?}",
        a.diagnostics.records
    );
}
