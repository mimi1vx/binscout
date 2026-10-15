//! Single-slot absolute indirect-jump resolution (plan §16).
//!
//! Synthetic raw blobs pin the exact recovered edge/xref sets for the two
//! approved positives (x86-32 absolute slot, x86-64 RIP-relative slot) and
//! keep every near-miss unresolved: unmapped slot, truncated slot (which
//! still carries a `Data` xref — necessary but not sufficient evidence),
//! non-decoding and non-executable targets, immediate-reporting `mov`,
//! indexed multi-entry tables, cross-function targets, and non-raw
//! containers. Fresh analyses and saved/reopened snapshots agree; direct
//! control flow is unchanged.

mod common;

use binscout::analysis::{
    Analysis, DiagnosticKind, DiscoveryReason, MAX_INFERRED_EDGES, MAX_INFERRED_PER_SITE, XrefKind,
    analyze, analyze_raw,
};
use binscout::disasm::Arch;
use binscout::loader::{BinaryFormat, LoadedBinary, RawOptions, Segment};

fn x32(bytes: &[u8], base: u64, entry: Option<u64>) -> Analysis {
    analyze_raw(bytes, base, Arch::X86_32, entry).expect("synthetic blob must analyze")
}

fn x64(bytes: &[u8], base: u64, entry: Option<u64>) -> Analysis {
    analyze_raw(bytes, base, Arch::X86_64, entry).expect("synthetic blob must analyze")
}

fn diagnostics_of(a: &Analysis) -> Vec<(u64, DiagnosticKind)> {
    a.diagnostics
        .records
        .iter()
        .map(|d| (d.addr, d.kind))
        .collect()
}

fn xref_tuples(a: &Analysis) -> Vec<(u64, XrefKind, u64)> {
    a.xrefs.iter().map(|x| (x.from, x.kind, x.to)).collect()
}

fn inferred_of(a: &Analysis) -> Vec<(u64, u64, u64)> {
    // `(func_entry, from_block, to_block)` over every function.
    let mut out = Vec::new();
    for f in a.functions.values() {
        for (b, t) in f.inferred_edges() {
            out.push((f.entry, b, t));
        }
    }
    out
}

fn blocks_of(a: &Analysis, entry: u64) -> Vec<u64> {
    a.functions[&entry]
        .blocks
        .keys()
        .copied()
        .collect::<Vec<_>>()
}

fn insn_at(a: &Analysis, entry: u64, addr: u64) -> &binscout::disasm::Insn {
    a.functions[&entry]
        .blocks
        .values()
        .flat_map(|b| &b.insns)
        .find(|i| i.addr == addr)
        .expect("site instruction must be decoded")
}

#[test]
fn caps_match_the_investigation_ceiling() {
    assert_eq!(MAX_INFERRED_PER_SITE, 1);
    assert_eq!(MAX_INFERRED_EDGES, 100_000);
}

// P1: 0x401000: jmp dword ptr [0x401006]; slot -> 0x40100a; ret.
fn p1() -> Vec<u8> {
    vec![
        0xFF, 0x25, 0x06, 0x10, 0x40, 0x00, // jmp [0x401006]
        0x0A, 0x10, 0x40, 0x00, // slot: 0x40100a
        0xC3, // ret
    ]
}

#[test]
fn x86_32_single_slot_resolves_with_exact_edge_and_xref_sets() {
    let a = x32(&p1(), 0x401000, Some(0x401000));
    // Typed evidence chain, never operand text.
    let site = insn_at(&a, 0x401000, 0x401000);
    assert_eq!(site.mnem, "jmp");
    assert_eq!(site.branch_target, None);
    assert_eq!(site.mem_target, Some(0x401006));

    assert!(a.diagnostics.records.is_empty());
    assert!(!a.diagnostics.inferred_truncated);
    assert_eq!(a.diagnostics.inferred_omitted, 0);
    assert_eq!(a.functions.keys().copied().collect::<Vec<_>>(), [0x401000]);
    // Slot bytes never decode: exactly the site block and the target block.
    assert_eq!(blocks_of(&a, 0x401000), [0x401000, 0x40100a]);
    let f = &a.functions[&0x401000];
    assert!(f.edges().is_empty(), "no direct edge may appear");
    assert_eq!(f.inferred_edges(), [(0x401000, 0x40100a)]);
    assert_eq!(
        xref_tuples(&a),
        [
            (0x401000, XrefKind::Data, 0x401006),
            (0x401000, XrefKind::InferredCode, 0x40100a),
        ]
    );
    assert!(a.call_edges().is_empty());
    assert!(a.calls_of(0x401000).is_empty());
}

// P2: 0x400000: jmp qword ptr [rip+4]; slot -> 0x400012; ret.
fn p2() -> Vec<u8> {
    let mut b = vec![
        0xFF, 0x25, 0x04, 0x00, 0x00, 0x00, // jmp [rip+4], slot at 0x40000a
    ];
    b.extend([0x90; 4]); // pad to the slot
    b.extend([0x12, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]); // slot: 0x400012
    b.push(0xC3); // ret
    b
}

#[test]
fn x86_64_single_slot_resolves_with_exact_edge_and_xref_sets() {
    let a = x64(&p2(), 0x400000, Some(0x400000));
    let site = insn_at(&a, 0x400000, 0x400000);
    assert_eq!(site.mnem, "jmp");
    assert_eq!(site.branch_target, None);
    assert_eq!(site.mem_target, Some(0x40000a));

    assert!(a.diagnostics.records.is_empty());
    assert_eq!(blocks_of(&a, 0x400000), [0x400000, 0x400012]);
    let f = &a.functions[&0x400000];
    assert!(f.edges().is_empty(), "no direct edge may appear");
    assert_eq!(f.inferred_edges(), [(0x400000, 0x400012)]);
    assert_eq!(
        xref_tuples(&a),
        [
            (0x400000, XrefKind::Data, 0x40000a),
            (0x400000, XrefKind::InferredCode, 0x400012),
        ]
    );
    assert!(a.call_edges().is_empty());
}

#[test]
fn unmapped_slot_stays_unresolved_without_data_xref() {
    // jmp [rip+disp] with slot 0x900000: 0x400006 + 0x4ffffa.
    let a = x64(
        &[0xFF, 0x25, 0xFA, 0xFF, 0x4F, 0x00, 0xC3],
        0x400000,
        Some(0x400000),
    );
    assert_eq!(
        diagnostics_of(&a),
        [(0x400000, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
    assert!(
        a.xrefs_from(0x400000).is_empty(),
        "unmapped slot leaves no xref at all"
    );
    assert_eq!(blocks_of(&a, 0x400000), [0x400000]);
}

#[test]
fn truncated_slot_stays_unresolved_despite_data_xref() {
    // 8-byte blob: the slot at 0x401006 needs bytes 6..10, only 6..8 are
    // file-backed. `contains` still fires (mem_size), so the Data xref is
    // present — necessary but not sufficient evidence.
    let a = x32(
        &[0xFF, 0x25, 0x06, 0x10, 0x40, 0x00, 0x90, 0x90],
        0x401000,
        Some(0x401000),
    );
    assert_eq!(
        diagnostics_of(&a),
        [(0x401000, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert_eq!(xref_tuples(&a), [(0x401000, XrefKind::Data, 0x401006)]);
    assert!(inferred_of(&a).is_empty());
    assert!(a.xrefs_page(Some(XrefKind::InferredCode), 0, 64).is_empty());
}

#[test]
fn non_decoding_target_stays_unresolved() {
    // Slot -> 0x400012, whose single byte 0x06 is invalid in 64-bit.
    let mut b = vec![0xFF, 0x25, 0x04, 0x00, 0x00, 0x00];
    b.extend([0x90; 4]);
    b.extend([0x12, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]);
    b.push(0x06);
    assert_eq!(b.len(), 19);
    let a = x64(&b, 0x400000, Some(0x400000));
    assert_eq!(
        diagnostics_of(&a),
        [(0x400000, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert_eq!(xref_tuples(&a), [(0x400000, XrefKind::Data, 0x40000a)]);
    assert!(inferred_of(&a).is_empty());
}

#[test]
fn non_executable_target_stays_unresolved() {
    // Raw mapping, two segments: the slot is file-backed but its value
    // 0x402000 lives in non-executable bytes holding a ret.
    let exec = vec![
        0xFF, 0x25, 0x06, 0x10, 0x40, 0x00, // jmp [0x401006]
        0x00, 0x20, 0x40, 0x00, // slot: 0x402000
    ];
    let bin = LoadedBinary {
        format: BinaryFormat::Raw,
        arch: Arch::X86_32,
        entry: Some(0x401000),
        segments: vec![
            Segment {
                vaddr: 0x401000,
                mem_size: exec.len() as u64,
                data: exec,
                readable: true,
                writable: false,
                executable: true,
            },
            Segment {
                vaddr: 0x402000,
                mem_size: 1,
                data: vec![0xC3],
                readable: true,
                writable: false,
                executable: false,
            },
        ],
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
    };
    let a = analyze(&bin).expect("synthetic segments must analyze");
    assert_eq!(
        diagnostics_of(&a),
        [(0x401000, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert_eq!(xref_tuples(&a), [(0x401000, XrefKind::Data, 0x401006)]);
    assert!(inferred_of(&a).is_empty());
}

#[test]
fn immediate_reporting_mov_is_not_a_jump_site() {
    // mov eax,0 reports mem_target Some(0) via the Immediate32 rule, but
    // the mnem/lift gate excludes it: no site, no edge, no xref.
    let a = x32(
        &[0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3],
        0x401000,
        Some(0x401000),
    );
    let mov = insn_at(&a, 0x401000, 0x401000);
    assert_eq!(mov.mnem, "mov");
    assert_eq!(mov.mem_target, Some(0));
    assert!(a.diagnostics.records.is_empty());
    assert!(a.xrefs.is_empty());
    assert!(inferred_of(&a).is_empty());
}

// N1: cmp/jae guard over jmp [eax*4+0x401012]; default mov/ret; 4-entry
// table; two ret bodies. The guard does not help: no typed base.
fn n1() -> Vec<u8> {
    let mut b = vec![
        0x83, 0xF8, 0x03, // 0x401000: cmp eax,3
        0x73, 0x07, // 0x401003: jae 0x40100c
        0xFF, 0x24, 0x85, 0x12, 0x10, 0x40, 0x00, // 0x401005: jmp [eax*4+table]
        0xB8, 0x01, 0x00, 0x00, 0x00, // 0x40100c: mov eax,1
        0xC3, // 0x401011: ret
    ];
    // 0x401012: table -> 0x401022 / 0x401023.
    for _ in 0..2 {
        b.extend([0x22, 0x10, 0x40, 0x00, 0x23, 0x10, 0x40, 0x00]);
    }
    b.extend([0xC3, 0xC3]); // bodies (never decoded: no typed base)
    b
}

#[test]
fn indexed_x86_32_table_stays_unresolved() {
    let bytes = n1();
    assert_eq!(bytes.len(), 0x24);
    let a = x32(&bytes, 0x401000, Some(0x401000));
    // The indexed site reports no typed slot: parsing the base out of the
    // operand string is forbidden.
    let site = insn_at(&a, 0x401000, 0x401005);
    assert_eq!(site.branch_target, None);
    assert_eq!(site.mem_target, None);
    assert!(diagnostics_of(&a).contains(&(0x401005, DiagnosticKind::UnresolvedIndirectJump)));
    assert!(inferred_of(&a).is_empty());
    assert!(a.xrefs_page(Some(XrefKind::InferredCode), 0, 64).is_empty());
    // The guarded default path still decodes directly.
    assert!(blocks_of(&a, 0x401000).contains(&0x40100c));
}

// N2: cmp/jae guard over jmp [rax*8+0x400012]; default mov/ret; 4-entry
// table; two ret bodies.
fn n2() -> Vec<u8> {
    let mut b = vec![
        0x83, 0xFF, 0x03, // 0x400000: cmp edi,3
        0x73, 0x08, // 0x400003: jae 0x40000d
        0x48, 0xFF, 0x24, 0xC5, 0x12, 0x00, 0x40, 0x00, // 0x400005: jmp [rax*8+table]
        0xBF, 0x01, 0x00, 0x00, 0x00, // 0x40000d: mov edi,1
    ];
    // 0x400012: table -> 0x400032 / 0x400033.
    for _ in 0..2 {
        b.extend([
            0x32, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x33, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
    }
    b.extend([0xC3, 0xC3]); // bodies (never decoded: no typed base)
    b
}

#[test]
fn indexed_x86_64_table_stays_unresolved() {
    let bytes = n2();
    assert_eq!(bytes.len(), 0x34);
    let a = x64(&bytes, 0x400000, Some(0x400000));
    let site = insn_at(&a, 0x400000, 0x400005);
    assert_eq!(site.branch_target, None);
    assert_eq!(site.mem_target, None);
    assert!(diagnostics_of(&a).contains(&(0x400005, DiagnosticKind::UnresolvedIndirectJump)));
    assert!(inferred_of(&a).is_empty());
    assert!(a.xrefs_page(Some(XrefKind::InferredCode), 0, 64).is_empty());
}

#[test]
fn cross_function_target_stays_unresolved() {
    // Site in func@0x400000, slot -> 0x400012 which is a prologue-seeded
    // second entry: same bytes as a positive, wrong owner.
    let mut b = vec![0xFF, 0x25, 0x04, 0x00, 0x00, 0x00];
    b.extend([0x90; 4]);
    b.extend([0x12, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]);
    b.extend([0x55, 0x48, 0x89, 0xE5, 0xC3]);
    let a = x64(&b, 0x400000, Some(0x400000));
    assert_eq!(
        a.functions.keys().copied().collect::<Vec<_>>(),
        [0x400000, 0x400012],
        "no inferred entry may appear"
    );
    assert_eq!(
        a.functions[&0x400012].reason_list(),
        [DiscoveryReason::Prologue]
    );
    assert!(a.call_edges().is_empty(), "no inferred callgraph edge");
    assert_eq!(
        diagnostics_of(&a),
        [(0x400000, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
    assert_eq!(xref_tuples(&a), [(0x400000, XrefKind::Data, 0x40000a)]);
}

#[test]
fn container_format_stays_unresolved_by_design() {
    // Byte-identical to the P2 positive, but a container's slot values are
    // not known final (relocations never apply to segment bytes).
    let bytes = p2();
    let bin = LoadedBinary {
        format: BinaryFormat::Elf,
        arch: Arch::X86_64,
        entry: Some(0x400000),
        segments: vec![Segment {
            vaddr: 0x400000,
            mem_size: bytes.len() as u64,
            data: bytes,
            readable: true,
            writable: false,
            executable: true,
        }],
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
    };
    let a = analyze(&bin).expect("synthetic container must analyze");
    assert_eq!(
        diagnostics_of(&a),
        [(0x400000, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
}

// Two Pass-A-visible sites plus a direct call: entry calls func@0x40001a;
// each function jumps through its own slot at a same-function ret.
fn two_site() -> Vec<u8> {
    let mut b = vec![
        0xE8, 0x15, 0x00, 0x00, 0x00, // 0x400000: call 0x40001a
        0xFF, 0x25, 0x05, 0x00, 0x00, 0x00, // 0x400005: jmp [rip+5], slot 0x400010
    ];
    b.extend([0x90; 5]); // 0x40000b: pad
    b.extend([0x18, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]); // 0x400010: -> 0x400018
    b.push(0xC3); // 0x400018: ret
    b.push(0x90); // 0x400019: pad
    b.extend([0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); // 0x40001a: jmp [rip+0], slot 0x400020
    b.extend([0x28, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]); // 0x400020: -> 0x400028
    b.push(0xC3); // 0x400028: ret
    b
}

#[test]
fn two_sites_resolve_alongside_direct_flow() {
    let bytes = two_site();
    assert_eq!(bytes.len(), 41);
    let a = x64(&bytes, 0x400000, Some(0x400000));
    // Direct flow is unchanged: entries, reasons, call edge, and the
    // call-fallthrough CFG edge stay exactly as without inference.
    assert_eq!(
        a.functions.keys().copied().collect::<Vec<_>>(),
        [0x400000, 0x40001a]
    );
    let f0 = &a.functions[&0x400000];
    let f1 = &a.functions[&0x40001a];
    assert_eq!(f0.reason_list(), [DiscoveryReason::Entry]);
    assert_eq!(f1.reason_list(), [DiscoveryReason::DirectCall]);
    assert_eq!(a.call_edges(), [(0x400000, 0x40001a)]);
    assert_eq!(f0.edges(), [(0x400000, 0x400005)]);
    assert!(f1.edges().is_empty());
    // One inferred edge per site, each in its own function.
    assert_eq!(f0.inferred_edges(), [(0x400005, 0x400018)]);
    assert_eq!(f1.inferred_edges(), [(0x40001a, 0x400028)]);
    assert_eq!(
        inferred_of(&a),
        [
            (0x400000, 0x400005, 0x400018),
            (0x40001a, 0x40001a, 0x400028),
        ]
    );
    assert_eq!(blocks_of(&a, 0x400000), [0x400000, 0x400005, 0x400018]);
    assert_eq!(blocks_of(&a, 0x40001a), [0x40001a, 0x400028]);
    assert_eq!(
        xref_tuples(&a),
        [
            (0x400000, XrefKind::Code, 0x40001a),
            (0x400005, XrefKind::Data, 0x400010),
            (0x400005, XrefKind::InferredCode, 0x400018),
            (0x40001a, XrefKind::Data, 0x400020),
            (0x40001a, XrefKind::InferredCode, 0x400028),
        ]
    );
    assert!(a.diagnostics.records.is_empty());
    assert!(!a.diagnostics.inferred_truncated);
    assert_eq!(a.diagnostics.inferred_omitted, 0);
}

#[test]
fn inferred_xref_wire_name_and_kind_filter() {
    let a = x64(&p2(), 0x400000, Some(0x400000));
    let row = a
        .xrefs_page(Some(XrefKind::InferredCode), 0, 64)
        .into_iter()
        .next()
        .expect("one inferred xref");
    assert_eq!((row.from, row.to), (0x400000, 0x400012));
    let v = serde_json::to_value(row).expect("xref serializes");
    assert_eq!(v["kind"], "inferred-code");
    assert_eq!(v["from"], 0x400000);
    assert_eq!(v["to"], 0x400012);
    // Old CamelCase rows still decode (forward-compatible reads).
    let back: binscout::analysis::Xref =
        serde_json::from_value(serde_json::json!({"from": 1u64, "to": 2u64, "kind": "Code"}))
            .expect("direct kind must decode");
    assert_eq!(back.kind, XrefKind::Code);
    // The direct kind filter is unaffected.
    assert_eq!(a.xrefs_page(Some(XrefKind::Code), 0, 64).len(), 0);
    assert_eq!(a.xrefs_page(Some(XrefKind::Data), 0, 64).len(), 1);
    assert_eq!(a.xrefs_page(None, 0, 64).len(), 2);
}

#[test]
fn fresh_save_and_reopen_agree_on_inferred_edges() {
    let bytes = two_site();
    let dir = common::tmpdir("jump-roundtrip");
    let bin = common::write_bin(&dir, "two.bin", &bytes);
    let db = common::temp_db(&dir, "two");
    let opts = RawOptions {
        base: 0x400000,
        arch: Arch::X86_64,
        entry: Some(0x400000),
    };
    let p = binscout::Project::open_raw(&bin, &db, opts).expect("raw open must analyze");
    let fresh = p.analysis().clone();
    assert_eq!(
        inferred_of(&fresh),
        [
            (0x400000, 0x400005, 0x400018),
            (0x40001a, 0x40001a, 0x400028),
        ]
    );
    p.save().expect("save inferred snapshot");
    drop(p);
    let q = binscout::Project::open_raw(&bin, &db, opts).expect("reopen must hit");
    let snap = q.analysis();
    assert_eq!(snap.diagnostics, fresh.diagnostics);
    assert_eq!(snap.xrefs, fresh.xrefs);
    for (entry, func) in &fresh.functions {
        let g = &snap.functions[entry];
        assert_eq!(g.inferred_edges(), func.inferred_edges());
        assert_eq!(g.edges(), func.edges());
        assert_eq!(
            g.blocks.keys().collect::<Vec<_>>(),
            func.blocks.keys().collect::<Vec<_>>()
        );
    }
    // Query layer agrees too: kind filter, detail, CFG, and info flags.
    assert_eq!(q.count_xrefs(None, None, Some(XrefKind::InferredCode)), 2);
    assert_eq!(
        q.query_xrefs(None, None, Some(XrefKind::InferredCode), 0, 64)
            .len(),
        2
    );
    for entry in [0x400000u64, 0x40001au64] {
        let detail = q.func_detail(entry).expect("detail");
        assert_eq!(detail["inferred_edges"].as_array().expect("array").len(), 1);
        let cfg = q.cfg_of(entry).expect("cfg");
        assert_eq!(cfg["inferred_edges"].as_array().expect("array").len(), 1);
        let meta = q.func_meta(entry).expect("meta");
        assert_eq!(meta.inferred_edges, 1);
    }
    let info = q.project_info();
    assert!(!info.inferred_truncated);
    assert_eq!(info.inferred_omitted, 0);
    assert_eq!(
        info.analysis_revision,
        binscout::analysis::ANALYSIS_REVISION
    );
    common::cleanup(&dir);
}
