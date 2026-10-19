//! Guarded switch-table recovery across architectures (plan §12, em6.9).
//!
//! Synthetic blobs pin the exact recovered edge/xref sets for every approved
//! shape: the two single-slot positives (x86-32 absolute slot, x86-64
//! RIP-relative slot, raw only), the absolute scaled-index tables (x86-32
//! `*4` and x86-64 `*8`, any format), the GCC/Clang PIE x86-64 relative
//! table (`lea`/`movsxd`/`add`/`jmp`), the MSVC x64 image-base-relative
//! table (`mov`/`add`/`jmp` over `r8`), ARM Thumb `tbb`/`tbh`, and AArch64
//! `adrp`/`adr` relative tables. Table bounds come from the dominating
//! guard (`cmp idx, max` gives `max + 1` entries, capped at
//! [`MAX_TABLE_ENTRIES_PER_SITE`]); every near-miss stays unresolved with
//! its diagnostic: unmapped/truncated slots and bases, bad entries,
//! singleton and over-cap bounds, missing guards, strided scales,
//! register mismatches, and cross-function targets. Fresh analyses and
//! saved/reopened snapshots agree; direct control flow is unchanged.

mod common;

use binscout::analysis::{
    Analysis, DiagnosticKind, DiscoveryReason, MAX_INFERRED_EDGES, MAX_INFERRED_PER_SITE,
    MAX_TABLE_ENTRIES_PER_SITE, MAX_TABLE_GUARD_BACKTRACK, MIN_TABLE_ENTRIES_PER_SITE, XrefKind,
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
    assert_eq!(MAX_TABLE_ENTRIES_PER_SITE, 1024);
    assert_eq!(MIN_TABLE_ENTRIES_PER_SITE, 2);
    assert_eq!(MAX_TABLE_GUARD_BACKTRACK, 10);
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
        symbols: Vec::new(),
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        debug_funcs: Vec::new(),
        relocatable: false,
        arm_hints: Default::default(),
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
// table; two ret bodies. The guard plus the typed table base resolves all
// four slots (two unique targets); diagnostics shrink to empty.
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
fn indexed_x86_32_table_resolves_with_exact_edge_and_xref_sets() {
    let bytes = n1();
    assert_eq!(bytes.len(), 0x24);
    let a = x32(&bytes, 0x401000, Some(0x401000));
    // Typed evidence chain, never operand text: the indexed site reports
    // the decoder's displacement as table_base, not as mem_target.
    let site = insn_at(&a, 0x401000, 0x401005);
    assert_eq!(site.mnem, "jmp");
    assert_eq!(site.branch_target, None);
    assert_eq!(site.mem_target, None);
    assert_eq!(site.table_base, Some(0x401012));

    // Diagnostics shrink: the site leaves the unresolved set.
    assert!(a.diagnostics.records.is_empty());
    assert!(!a.diagnostics.inferred_truncated);
    assert_eq!(a.diagnostics.inferred_omitted, 0);
    assert_eq!(a.functions.keys().copied().collect::<Vec<_>>(), [0x401000]);
    assert_eq!(
        blocks_of(&a, 0x401000),
        [0x401000, 0x401005, 0x40100c, 0x401022, 0x401023]
    );
    let f = &a.functions[&0x401000];
    let mut edges = f.edges();
    edges.sort_unstable();
    assert_eq!(edges, [(0x401000, 0x401005), (0x401000, 0x40100c)]);
    assert_eq!(
        f.inferred_edges(),
        [(0x401005, 0x401022), (0x401005, 0x401023)]
    );
    assert_eq!(
        xref_tuples(&a),
        [
            (0x401003, XrefKind::Code, 0x40100c),
            (0x401005, XrefKind::Data, 0x401012),
            (0x401005, XrefKind::Data, 0x401016),
            (0x401005, XrefKind::Data, 0x40101a),
            (0x401005, XrefKind::Data, 0x40101e),
            (0x401005, XrefKind::InferredCode, 0x401022),
            (0x401005, XrefKind::InferredCode, 0x401023),
        ]
    );
    assert!(a.call_edges().is_empty());
    assert!(a.calls_of(0x401000).is_empty());
}

// N2: cmp/jae guard over jmp [rax*8+0x400012]; default mov/ret; 4-entry
// table; two ret bodies. Same typed-base recovery as N1 at 8-byte width.
// The guard compares eax (32-bit alias of the rax index).
fn n2() -> Vec<u8> {
    let mut b = vec![
        0x83, 0xF8, 0x03, // 0x400000: cmp eax,3
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
fn indexed_x86_64_table_resolves_with_exact_edge_and_xref_sets() {
    let bytes = n2();
    assert_eq!(bytes.len(), 0x34);
    let a = x64(&bytes, 0x400000, Some(0x400000));
    let site = insn_at(&a, 0x400000, 0x400005);
    assert_eq!(site.mnem, "jmp");
    assert_eq!(site.branch_target, None);
    assert_eq!(site.mem_target, None);
    assert_eq!(site.table_base, Some(0x400012));

    // Diagnostics shrink: the site leaves the unresolved set.
    assert!(a.diagnostics.records.is_empty());
    assert!(!a.diagnostics.inferred_truncated);
    assert_eq!(a.diagnostics.inferred_omitted, 0);
    assert_eq!(
        blocks_of(&a, 0x400000),
        [0x400000, 0x400005, 0x40000d, 0x400032, 0x400033]
    );
    let f = &a.functions[&0x400000];
    let mut edges = f.edges();
    edges.sort_unstable();
    assert_eq!(
        edges,
        [
            (0x400000, 0x400005),
            (0x400000, 0x40000d),
            (0x40000d, 0x400032),
        ]
    );
    assert_eq!(
        f.inferred_edges(),
        [(0x400005, 0x400032), (0x400005, 0x400033)]
    );
    assert_eq!(
        xref_tuples(&a),
        [
            (0x400003, XrefKind::Code, 0x40000d),
            (0x400005, XrefKind::Data, 0x400012),
            (0x400005, XrefKind::Data, 0x40001a),
            (0x400005, XrefKind::Data, 0x400022),
            (0x400005, XrefKind::Data, 0x40002a),
            (0x400005, XrefKind::InferredCode, 0x400032),
            (0x400005, XrefKind::InferredCode, 0x400033),
        ]
    );
    assert!(a.call_edges().is_empty());
}

// Bare indexed jump with no bound check: the typed base is present but the
// index is unbounded, so the site stays unresolved. N1 minus cmp/jae.
#[test]
fn unguarded_indexed_table_stays_unresolved() {
    let mut b = vec![
        0xFF, 0x24, 0x85, 0x07, 0x10, 0x40, 0x00, // 0x401000: jmp [eax*4+table]
    ];
    for _ in 0..2 {
        b.extend([0x22, 0x10, 0x40, 0x00, 0x23, 0x10, 0x40, 0x00]);
    }
    b.extend([0xC3, 0xC3]);
    let a = x32(&b, 0x401000, Some(0x401000));
    let site = insn_at(&a, 0x401000, 0x401000);
    assert_eq!(site.table_base, Some(0x401007));
    assert_eq!(site.mem_target, None);
    assert_eq!(
        diagnostics_of(&a),
        [(0x401000, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
    assert!(a.xrefs_page(Some(XrefKind::InferredCode), 0, 64).is_empty());
}

// Guarded table whose base points outside every segment.
#[test]
fn unmapped_table_base_stays_unresolved() {
    let a = x32(
        &[
            0x83, 0xF8, 0x03, // cmp eax,3
            0x73, 0x07, // jae default
            0xFF, 0x24, 0x85, 0x00, 0x00, 0x90, 0x00, // jmp [eax*4+0x900000]
            0xB8, 0x01, 0x00, 0x00, 0x00, // default: mov eax,1
            0xC3,
        ],
        0x401000,
        Some(0x401000),
    );
    let site = insn_at(&a, 0x401000, 0x401005);
    assert_eq!(site.table_base, Some(0x900000));
    assert_eq!(
        diagnostics_of(&a),
        [(0x401005, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
    assert!(a.xrefs_page(Some(XrefKind::InferredCode), 0, 64).is_empty());
}

// Guarded table whose second slot is truncated: the one valid slot is a
// stray pointer, not a table (singleton runs never resolve).
#[test]
fn truncated_second_slot_stays_unresolved() {
    // jmp [eax*4+0x401012]: slot 0 is a valid same-function target (the
    // default mov), slot 1 is one byte short of file-backed. The single
    // valid slot is a stray pointer, not a table. The ret before the table
    // keeps slot bytes out of the decoded path, so the set is exact.
    let b = vec![
        0x83, 0xF8, 0x03, // cmp eax,3
        0x73, 0x07, // jae 0x40100c
        0xFF, 0x24, 0x85, 0x12, 0x10, 0x40, 0x00, // jmp [eax*4+0x401012]
        0xB8, 0x01, 0x00, 0x00, 0x00, // 0x40100c: default mov
        0xC3, // ret: table bytes never decode as code
        0x0C, 0x10, 0x40, 0x00, // slot 0 -> 0x40100c
        0x1C, 0x10, // slot 1 truncated (2 of 4 bytes)
    ];
    assert_eq!(b.len(), 0x18);
    let a = x32(&b, 0x401000, Some(0x401000));
    assert_eq!(
        diagnostics_of(&a),
        [(0x401005, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
}

// Guarded table whose second slot holds an unmapped pointer: same
// singleton-run rejection through a garbage value instead of truncation.
#[test]
fn singleton_valid_run_stays_unresolved() {
    // Same shape with a full garbage second slot (unmapped 0x900000).
    let b = vec![
        0x83, 0xF8, 0x03, // cmp eax,3
        0x73, 0x07, // jae 0x40100c
        0xFF, 0x24, 0x85, 0x12, 0x10, 0x40, 0x00, // jmp [eax*4+0x401012]
        0xB8, 0x01, 0x00, 0x00, 0x00, // 0x40100c: default mov
        0xC3, // ret: table bytes never decode as code
        0x0C, 0x10, 0x40, 0x00, // slot 0 -> 0x40100c
        0x00, 0x00, 0x90, 0x00, // slot 1 -> unmapped 0x900000
    ];
    assert_eq!(b.len(), 0x1a);
    let a = x32(&b, 0x401000, Some(0x401000));
    assert_eq!(
        diagnostics_of(&a),
        [(0x401005, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
}

// Guarded table whose first entry targets non-executable bytes.
#[test]
fn non_executable_table_entry_stays_unresolved() {
    let exec = vec![
        0x83, 0xF8, 0x03, // cmp eax,3
        0x73, 0x07, // jae default
        0xFF, 0x24, 0x85, 0x12, 0x10, 0x40, 0x00, // jmp [eax*4+0x401012]
        0xB8, 0x01, 0x00, 0x00, 0x00, // default
        0xC3, // pad
        0x00, 0x20, 0x40, 0x00, // slot 0 -> 0x402000 (non-executable ret)
        0x01, 0x20, 0x40, 0x00, // slot 1 -> 0x402001
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
                mem_size: 2,
                data: vec![0xC3, 0xC3],
                readable: true,
                writable: false,
                executable: false,
            },
        ],
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
    let a = analyze(&bin).expect("synthetic segments must analyze");
    assert_eq!(
        diagnostics_of(&a),
        [(0x401005, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
}

// Guarded x86-64 table whose second entry does not decode (0x06 is invalid
// in 64-bit); the first entry is valid, pinning the mid-run break.
#[test]
fn non_decoding_table_entry_stays_unresolved() {
    // Slot 0 targets a ret body; slot 1 targets 0x400024, whose byte 0x06
    // is invalid in 64-bit. The ret before the table keeps slot bytes out
    // of the decoded path, so the set is exact.
    let mut b = vec![
        0x83, 0xFF, 0x03, // cmp edi,3
        0x73, 0x08, // jae 0x40000d
        0x48, 0xFF, 0x24, 0xC5, 0x13, 0x00, 0x40, 0x00, // jmp [rax*8+table]
        0xBF, 0x01, 0x00, 0x00, 0x00, // 0x40000d: default mov
        0xC3, // ret
    ];
    let table = 0x400000 + b.len() as u64;
    assert_eq!(table, 0x400013);
    b.extend([0x23, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]); // slot 0 -> body
    b.extend([0x24, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]); // slot 1 -> 0x400024
    b.extend([0xC3, 0x06]); // body ret + invalid opcode
    assert_eq!(b.len(), 37);
    let a = x64(&b, 0x400000, Some(0x400000));
    let site = insn_at(&a, 0x400000, 0x400005);
    assert_eq!(site.table_base, Some(0x400013));
    assert_eq!(
        diagnostics_of(&a),
        [(0x400005, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
}

// Guarded table whose first entry is a prologue-seeded second function:
// same-function only, no new entries from inference. The table lives in a
// non-executable segment (realistic `.rodata` shape) so its slot bytes
// never decode as code and the prologue stays unreached until round two.
#[test]
fn cross_function_table_entry_stays_unresolved() {
    let exec = vec![
        0x83, 0xFF, 0x03, // 0x400000: cmp edi,3
        0x73, 0x08, // jae 0x40000d
        0x48, 0xFF, 0x24, 0xC5, 0x12, 0x00, 0x50, 0x00, // jmp [rax*8+0x500012]
        0xBF, 0x01, 0x00, 0x00, 0x00, // 0x40000d: default mov
        0xC3, // ret
        0x90, // pad
        0x55, 0x48, 0x89, 0xE5, // 0x400014: prologue-seeded entry
        0xC3, // ret
    ];
    let mut data = vec![0x90; 0x12];
    data.extend([0x14, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]); // slot 0
    data.extend([0x15, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]); // slot 1
    let bin = LoadedBinary {
        format: BinaryFormat::Raw,
        arch: Arch::X86_64,
        entry: Some(0x400000),
        segments: vec![
            Segment {
                vaddr: 0x400000,
                mem_size: exec.len() as u64,
                data: exec,
                readable: true,
                writable: false,
                executable: true,
            },
            Segment {
                vaddr: 0x500000,
                mem_size: data.len() as u64,
                data,
                readable: true,
                writable: false,
                executable: false,
            },
        ],
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
    let a = analyze(&bin).expect("synthetic segments must analyze");
    assert_eq!(
        a.functions.keys().copied().collect::<Vec<_>>(),
        [0x400000, 0x400014],
        "no inferred entry may appear"
    );
    assert_eq!(
        a.functions[&0x400014].reason_list(),
        [DiscoveryReason::Prologue]
    );
    assert_eq!(
        diagnostics_of(&a),
        [(0x400005, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
}

// Guarded table whose bound exceeds the per-site cap: exact-or-reject keeps
// the whole site unresolved instead of partially recovering. The guard
// claims 11 entries but only 9 validate, so the table is incomplete under
// bound semantics either way; the dedicated cap pin is
// `table_bound_exceeding_cap_stays_unresolved` below.
#[test]
fn oversize_table_stays_unresolved() {
    let mut b = vec![
        0x83, 0xF8, 0x0A, // cmp eax,10
        0x73, 0x07, // jae default
        0xFF, 0x24, 0x85, 0x13, 0x10, 0x40, 0x00, // jmp [eax*4+0x401013]
        0xB8, 0x01, 0x00, 0x00, 0x00, // default
        0xC3, // ret
        0x90, // pad to the table
    ];
    assert_eq!(b.len(), 0x13);
    for _ in 0..9 {
        b.extend([0x37, 0x10, 0x40, 0x00]); // every slot -> 0x401037
    }
    b.push(0xC3); // single body
    assert_eq!(b.len(), 0x13 + 36 + 1);
    let a = x32(&b, 0x401000, Some(0x401000));
    let site = insn_at(&a, 0x401000, 0x401005);
    assert_eq!(site.table_base, Some(0x401013));
    assert_eq!(
        diagnostics_of(&a),
        [(0x401005, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
    assert!(a.xrefs_page(Some(XrefKind::InferredCode), 0, 64).is_empty());
}

// Strided index (`*2` at 4-byte width): the decoder reports no typed base.
#[test]
fn wrong_scale_table_stays_unresolved() {
    let mut b = vec![
        0x83, 0xF8, 0x03, 0x73, 0x07, // cmp/jae
        0xFF, 0x24, 0x45, 0x12, 0x10, 0x40, 0x00, // jmp [eax*2+0x401012]
        0xB8, 0x01, 0x00, 0x00, 0x00, // default
        0xC3, // ret: table bytes never decode as code
    ];
    for _ in 0..2 {
        b.extend([0x24, 0x10, 0x40, 0x00, 0x25, 0x10, 0x40, 0x00]);
    }
    assert_eq!(b.len(), 0x12 + 16);
    let a = x32(&b, 0x401000, Some(0x401000));
    let site = insn_at(&a, 0x401000, 0x401005);
    assert_eq!(site.mem_target, None);
    assert_eq!(site.table_base, None);
    assert_eq!(
        diagnostics_of(&a),
        [(0x401005, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
}

// Byte-identical to the N1 positive but parsed as an ELF container:
// absolute tables resolve in every format now (linked images hold final
// absolute addresses; PIE addends fail validation rather than guessing).
#[test]
fn container_absolute_table_resolves_like_raw() {
    let bytes = n1();
    let bin = LoadedBinary {
        format: BinaryFormat::Elf,
        arch: Arch::X86_32,
        entry: Some(0x401000),
        segments: vec![Segment {
            vaddr: 0x401000,
            mem_size: bytes.len() as u64,
            data: bytes,
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
    let a = analyze(&bin).expect("synthetic container must analyze");
    assert!(a.diagnostics.records.is_empty());
    assert_eq!(
        a.functions[&0x401000].inferred_edges(),
        [(0x401005, 0x401022), (0x401005, 0x401023)]
    );
    assert_eq!(
        xref_tuples(&a),
        [
            (0x401003, XrefKind::Code, 0x40100c),
            (0x401005, XrefKind::Data, 0x401012),
            (0x401005, XrefKind::Data, 0x401016),
            (0x401005, XrefKind::Data, 0x40101a),
            (0x401005, XrefKind::Data, 0x40101e),
            (0x401005, XrefKind::InferredCode, 0x401022),
            (0x401005, XrefKind::InferredCode, 0x401023),
        ]
    );
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
        symbols: Vec::new(),
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        debug_funcs: Vec::new(),
        relocatable: false,
        arm_hints: Default::default(),
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

#[test]
fn many_register_indirect_sites_visit_once_each() {
    // rsdbg-5tk.2: `jmp rax` carries no typed slot, so no site can resolve.
    // Resolution must visit each site once (worklist), not rescan all
    // diagnostics per site (O(J*D): 20k sites took 5.75 s release). Each
    // `push rbp; mov rbp,rsp; jmp rax` frame seeds one function via the
    // prologue scan, yielding one unresolved site per frame.
    const SITES: usize = 20_000;
    const BASE: u64 = 0x400000;
    let mut bytes = Vec::with_capacity(SITES * 6);
    for _ in 0..SITES {
        bytes.extend_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0xff, 0xe0]);
    }
    let start = std::time::Instant::now();
    let a = x64(&bytes, BASE, Some(BASE));
    let elapsed = start.elapsed();
    assert_eq!(a.functions.len(), SITES);
    assert_eq!(
        diagnostics_of(&a)
            .iter()
            .filter(|(_, k)| *k == DiagnosticKind::UnresolvedIndirectJump)
            .count(),
        SITES
    );
    assert!(inferred_of(&a).is_empty());
    assert!(!a.diagnostics.inferred_truncated);
    assert_eq!(a.diagnostics.inferred_omitted, 0);
    // Complexity guard, not a benchmark: debug builds run an order of
    // magnitude slower, so each profile gets its own budget. Pre-fix this
    // took 5.75 s release (18 s at 40k); post-fix it tracks the
    // ret/call-rax control at ~0.2 s release.
    #[cfg(debug_assertions)]
    let budget = std::time::Duration::from_secs(30);
    #[cfg(not(debug_assertions))]
    let budget = std::time::Duration::from_secs(1);
    assert!(
        elapsed < budget,
        "20k unresolvable sites took {elapsed:?} (budget {budget:?})"
    );
}

#[test]
fn ordered_lookup_helpers_match_collecting_predecessors() {
    // rsdbg-5tk.11: `inferred_succs`/`inferred_len` and
    // `containing_function` replaced full collects and linear scans on hot
    // paths (layout, budget check, diagnostics, slicing). Pin them to the
    // same rows: per-block ranges must reassemble the full edge set (n1
    // has two targets from one site block), every decoded address must
    // attribute to its owning function, and gap bytes to none.
    for a in [
        x32(&p1(), 0x401000, Some(0x401000)),
        x64(&p2(), 0x400000, Some(0x400000)),
        x32(&n1(), 0x401000, Some(0x401000)),
    ] {
        for f in a.functions.values() {
            assert_eq!(f.inferred_len(), f.inferred_edges().len());
            let mut reassembled: Vec<(u64, u64)> = Vec::new();
            for &start in f.blocks.keys() {
                reassembled.extend(f.inferred_succs(start).into_iter().map(|t| (start, t)));
            }
            reassembled.sort_unstable();
            assert_eq!(reassembled, f.inferred_edges());
            for b in f.blocks.values() {
                for i in &b.insns {
                    assert_eq!(a.containing_function(i.addr), Some(f.entry));
                }
            }
        }
    }
    let a = x32(&p1(), 0x401000, Some(0x401000));
    assert_eq!(a.containing_function(0x401000), Some(0x401000));
    assert_eq!(a.containing_function(0x40100a), Some(0x401000));
    assert_eq!(
        a.containing_function(0x401008),
        None,
        "slot bytes are a gap"
    );
    assert_eq!(a.containing_function(0x400000), None, "below first entry");
}

// Q1: GCC/Clang PIE x86-64 switch (raw, base 0x400000):
// cmp edi,2; jae default; mov eax,edi; lea rcx,[rip+JT]; movsxd
// rax,[rcx+rax*4]; add rax,rcx; jmp rax. The table holds 32-bit offsets
// from its own base; three bodies follow the table.
fn q1() -> Vec<u8> {
    let mut b = vec![
        0x83, 0xFF, 0x02, // 0x400000: cmp edi,2
        0x73, 0x12, // 0x400003: jae 0x400017
        0x89, 0xF8, // 0x400005: mov eax,edi
        0x48, 0x8D, 0x0D, 0x0F, 0x00, 0x00, 0x00, // 0x400007: lea rcx,[rip+0xF] -> 0x40001D
        0x48, 0x63, 0x04, 0x81, // 0x40000E: movsxd rax,[rcx+rax*4]
        0x48, 0x01, 0xC8, // 0x400012: add rax,rcx
        0xFF, 0xE0, // 0x400015: jmp rax
        0xBF, 0x01, 0x00, 0x00, 0x00, // 0x400017: mov edi,1
        0xC3, // 0x40001C: ret
    ];
    assert_eq!(b.len(), 0x1D);
    b.extend([0x0C, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00]); // slots 0-1
    b.extend([0x0E, 0x00, 0x00, 0x00]); // slot 2
    b.extend([0xC3, 0xC3, 0xC3]); // bodies 0x400029/2A/2B
    assert_eq!(b.len(), 44);
    b
}

#[test]
fn pie_x86_64_relative_table_resolves() {
    let a = x64(&q1(), 0x400000, Some(0x400000));
    let site = insn_at(&a, 0x400000, 0x400015);
    assert_eq!(site.mnem, "jmp");
    assert_eq!(site.branch_target, None);
    assert_eq!(site.mem_target, None);
    assert_eq!(site.table_base, None);
    let lea = insn_at(&a, 0x400000, 0x400007);
    assert_eq!(lea.mem_target, Some(0x40001D));

    assert!(a.diagnostics.records.is_empty());
    assert_eq!(a.functions.keys().copied().collect::<Vec<_>>(), [0x400000]);
    assert_eq!(
        blocks_of(&a, 0x400000),
        [0x400000, 0x400005, 0x400017, 0x400029, 0x40002A, 0x40002B]
    );
    let f = &a.functions[&0x400000];
    assert_eq!(f.edges(), [(0x400000, 0x400005), (0x400000, 0x400017)]);
    assert_eq!(
        f.inferred_edges(),
        [
            (0x400005, 0x400029),
            (0x400005, 0x40002A),
            (0x400005, 0x40002B)
        ]
    );
    assert_eq!(
        xref_tuples(&a),
        [
            (0x400003, XrefKind::Code, 0x400017),
            (0x400007, XrefKind::Data, 0x40001D),
            (0x400015, XrefKind::Data, 0x40001D),
            (0x400015, XrefKind::Data, 0x400021),
            (0x400015, XrefKind::Data, 0x400025),
            (0x400015, XrefKind::InferredCode, 0x400029),
            (0x400015, XrefKind::InferredCode, 0x40002A),
            (0x400015, XrefKind::InferredCode, 0x40002B),
        ]
    );
    assert!(a.call_edges().is_empty());
}

// Q1 with the index copy removed (`mov eax,edi` replaced by two nops):
// the compared register must alias the indexed register directly, so the
// altered shape stays unresolved.
#[test]
fn pie_index_mismatch_stays_unresolved() {
    let mut b = q1();
    b[5] = 0x90;
    b[6] = 0x90; // mov eax,edi -> nop;nop: index rax no longer copies edi
    let a = x64(&b, 0x400000, Some(0x400000));
    assert_eq!(
        diagnostics_of(&a),
        [(0x400015, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
}

// Q2: MSVC x64 switch as a synthetic PE container (base 0x140000000):
// cmp eax,2; jae default; mov ecx,[r8+rax*4+0x18]; add rcx,r8; jmp rcx.
// The table holds 32-bit RVAs from the image base (`r8`); the displacement
// is the table RVA, so the image base (lowest mapped address) recovers it.
fn q2() -> Vec<u8> {
    let mut b = vec![
        0x83, 0xF8, 0x02, // cmp eax,2
        0x73, 0x0D, // jae default (+0x12)
        0x41, 0x8B, 0x8C, 0x80, 0x18, 0x00, 0x00, 0x00, // mov ecx,[r8+rax*4+0x18]
        0x4C, 0x01, 0xC1, // add rcx,r8
        0xFF, 0xE1, // jmp rcx
        0xB8, 0x01, 0x00, 0x00, 0x00, // default: mov eax,1
        0xC3, // ret
    ];
    assert_eq!(b.len(), 0x18);
    b.extend([0x24, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00]); // slots 0-1
    b.extend([0x26, 0x00, 0x00, 0x00]); // slot 2
    b.extend([0xC3, 0xC3, 0xC3]); // bodies
    assert_eq!(b.len(), 39);
    b
}

fn pe_container(bytes: Vec<u8>, base: u64, arch: Arch) -> Analysis {
    let bin = LoadedBinary {
        format: BinaryFormat::Pe,
        arch,
        entry: Some(base),
        segments: vec![Segment {
            vaddr: base,
            mem_size: bytes.len() as u64,
            data: bytes,
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
    analyze(&bin).expect("synthetic container must analyze")
}

#[test]
fn msvc_x64_image_relative_table_resolves() {
    const BASE: u64 = 0x140000000;
    let a = pe_container(q2(), BASE, Arch::X86_64);
    let site = insn_at(&a, BASE, BASE + 0x10);
    assert_eq!(site.mnem, "jmp");
    assert_eq!(site.branch_target, None);

    assert!(a.diagnostics.records.is_empty());
    assert_eq!(a.functions.keys().copied().collect::<Vec<_>>(), [BASE]);
    assert_eq!(
        blocks_of(&a, BASE),
        [
            BASE,
            BASE + 5,
            BASE + 0x12,
            BASE + 0x24,
            BASE + 0x25,
            BASE + 0x26
        ]
    );
    let f = &a.functions[&BASE];
    assert_eq!(f.edges(), [(BASE, BASE + 5), (BASE, BASE + 0x12)]);
    assert_eq!(
        f.inferred_edges(),
        [
            (BASE + 5, BASE + 0x24),
            (BASE + 5, BASE + 0x25),
            (BASE + 5, BASE + 0x26)
        ]
    );
    assert_eq!(
        xref_tuples(&a),
        [
            (BASE + 3, XrefKind::Code, BASE + 0x12),
            (BASE + 0x10, XrefKind::Data, BASE + 0x18),
            (BASE + 0x10, XrefKind::Data, BASE + 0x1C),
            (BASE + 0x10, XrefKind::Data, BASE + 0x20),
            (BASE + 0x10, XrefKind::InferredCode, BASE + 0x24),
            (BASE + 0x10, XrefKind::InferredCode, BASE + 0x25),
            (BASE + 0x10, XrefKind::InferredCode, BASE + 0x26),
        ]
    );
    assert!(a.call_edges().is_empty());
}

// Q4a: Thumb `tbb [pc, r0]` (base 0x20000):
// cmp r0,#2; bhi default; tbb [pc,r0]; table(3B)+pad; default movs/bx;
// three `bx lr` bodies. Targets are `base + 2 * byte`.
fn q4a() -> Vec<u8> {
    vec![
        0x02, 0x28, // 0x20000: cmp r0,#2
        0x02, 0xD8, // 0x20002: bhi 0x2000C
        0xDF, 0xE8, 0x00, 0xF0, // 0x20004: tbb [pc, r0]
        0x04, 0x05, 0x06, 0x00, // 0x20008: table + pad
        0x01, 0x20, // 0x2000C: movs r0,#1
        0x70, 0x47, // 0x2000E: bx lr
        0x70, 0x47, // 0x20010
        0x70, 0x47, // 0x20012
        0x70, 0x47, // 0x20014
    ]
}

fn thumb(bytes: &[u8], base: u64, entry: Option<u64>) -> Analysis {
    analyze_raw(bytes, base, Arch::Thumb, entry).expect("synthetic blob must analyze")
}

#[test]
fn thumb_tbb_table_resolves() {
    let a = thumb(&q4a(), 0x20000, Some(0x20000));
    let site = insn_at(&a, 0x20000, 0x20004);
    assert_eq!(site.mnem, "tbb");
    assert_eq!(site.branch_target, None);

    assert!(a.diagnostics.records.is_empty());
    assert_eq!(a.functions.keys().copied().collect::<Vec<_>>(), [0x20000]);
    assert_eq!(
        blocks_of(&a, 0x20000),
        [0x20000, 0x20004, 0x2000C, 0x20010, 0x20012, 0x20014]
    );
    let f = &a.functions[&0x20000];
    assert_eq!(f.edges(), [(0x20000, 0x20004), (0x20000, 0x2000C)]);
    assert_eq!(
        f.inferred_edges(),
        [(0x20004, 0x20010), (0x20004, 0x20012), (0x20004, 0x20014)]
    );
    assert_eq!(
        xref_tuples(&a),
        [
            (0x20002, XrefKind::Code, 0x2000C),
            (0x20004, XrefKind::Data, 0x20008),
            (0x20004, XrefKind::Data, 0x20009),
            (0x20004, XrefKind::Data, 0x2000A),
            (0x20004, XrefKind::InferredCode, 0x20010),
            (0x20004, XrefKind::InferredCode, 0x20012),
            (0x20004, XrefKind::InferredCode, 0x20014),
        ]
    );
    assert!(a.call_edges().is_empty());
}

// Q4b: Thumb `tbh [pc, r0, lsl #1]` (base 0x21000): same guard shape with
// halfword slots; targets are `base + 2 * halfword`.
fn q4b() -> Vec<u8> {
    vec![
        0x02, 0x28, // 0x21000: cmp r0,#2
        0x03, 0xD8, // 0x21002: bhi 0x2100E
        0xDF, 0xE8, 0x10, 0xF1, // 0x21004: tbh [pc, r0, lsl #1]
        0x05, 0x00, 0x06, 0x00, 0x07, 0x00, // 0x21008: table
        0x01, 0x20, // 0x2100E: movs r0,#1
        0x70, 0x47, // 0x21010: bx lr
        0x70, 0x47, // 0x21012
        0x70, 0x47, // 0x21014
        0x70, 0x47, // 0x21016
    ]
}

#[test]
fn thumb_tbh_table_resolves() {
    let a = thumb(&q4b(), 0x21000, Some(0x21000));
    let site = insn_at(&a, 0x21000, 0x21004);
    assert_eq!(site.mnem, "tbh");
    assert_eq!(site.branch_target, None);

    assert!(a.diagnostics.records.is_empty());
    assert_eq!(a.functions.keys().copied().collect::<Vec<_>>(), [0x21000]);
    assert_eq!(
        blocks_of(&a, 0x21000),
        [0x21000, 0x21004, 0x2100E, 0x21012, 0x21014, 0x21016]
    );
    let f = &a.functions[&0x21000];
    assert_eq!(f.edges(), [(0x21000, 0x21004), (0x21000, 0x2100E)]);
    assert_eq!(
        f.inferred_edges(),
        [(0x21004, 0x21012), (0x21004, 0x21014), (0x21004, 0x21016)]
    );
    assert_eq!(
        xref_tuples(&a),
        [
            (0x21002, XrefKind::Code, 0x2100E),
            (0x21004, XrefKind::Data, 0x21008),
            (0x21004, XrefKind::Data, 0x2100A),
            (0x21004, XrefKind::Data, 0x2100C),
            (0x21004, XrefKind::InferredCode, 0x21012),
            (0x21004, XrefKind::InferredCode, 0x21014),
            (0x21004, XrefKind::InferredCode, 0x21016),
        ]
    );
    assert!(a.call_edges().is_empty());
}

// Q4 with the guard removed (cmp/bhi replaced by nops): a detected but
// unbounded `tbb` keeps its diagnostic instead of resolving.
#[test]
fn thumb_unguarded_tbb_stays_unresolved() {
    let mut b = q4a();
    b[0] = 0x00;
    b[1] = 0xBF; // cmp -> nop
    b[2] = 0x00;
    b[3] = 0xBF; // bhi -> nop
    let a = thumb(&b, 0x20000, Some(0x20000));
    assert_eq!(
        diagnostics_of(&a),
        [(0x20004, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
}

// Q5: AArch64 switch (base 0x4000):
// cmp w0,#2; b.hi default; mov w8,w0; adrp x9,JT; add x9,x9,#0x38;
// adr x10,base; ldrb w11,[x9,x8]; add x10,x10,x11,lsl #2; br x10.
// The table holds byte offsets scaled by 4 from the `adr` base.
fn q5() -> Vec<u8> {
    let mut b = vec![
        0x1F, 0x08, 0x00, 0x71, // 0x4000: cmp w0,#2
        0x68, 0x01, 0x00, 0x54, // 0x4004: b.hi 0x4030
        0xE8, 0x03, 0x00, 0x2A, // 0x4008: mov w8,w0
        0x09, 0x00, 0x00, 0x90, // 0x400C: adrp x9,0x4000
        0x29, 0xE1, 0x00, 0x91, // 0x4010: add x9,x9,#0x38
        0x8A, 0x00, 0x00, 0x10, // 0x4014: adr x10,0x4024
        0x2B, 0x69, 0x68, 0x38, // 0x4018: ldrb w11,[x9,x8]
        0x4A, 0x09, 0x0B, 0x8B, // 0x401C: add x10,x10,x11,lsl #2
        0x40, 0x01, 0x1F, 0xD6, // 0x4020: br x10
        0xC0, 0x03, 0x5F, 0xD6, // 0x4024: ret
        0xC0, 0x03, 0x5F, 0xD6, // 0x4028: ret
        0xC0, 0x03, 0x5F, 0xD6, // 0x402C: ret
        0x20, 0x00, 0x80, 0x52, // 0x4030: movz w0,#1
        0xC0, 0x03, 0x5F, 0xD6, // 0x4034: ret
    ];
    assert_eq!(b.len(), 0x38);
    b.extend([0x00, 0x01, 0x02]); // JT 0x4038
    assert_eq!(b.len(), 59);
    b
}

fn a64(bytes: &[u8], base: u64, entry: Option<u64>) -> Analysis {
    analyze_raw(bytes, base, Arch::Aarch64, entry).expect("synthetic blob must analyze")
}

#[test]
fn aarch64_relative_table_resolves() {
    let a = a64(&q5(), 0x4000, Some(0x4000));
    let site = insn_at(&a, 0x4000, 0x4020);
    assert_eq!(site.mnem, "br");
    assert_eq!(site.branch_target, None);

    assert!(a.diagnostics.records.is_empty());
    assert_eq!(a.functions.keys().copied().collect::<Vec<_>>(), [0x4000]);
    assert_eq!(
        blocks_of(&a, 0x4000),
        [0x4000, 0x4008, 0x4024, 0x4028, 0x402C, 0x4030]
    );
    let f = &a.functions[&0x4000];
    assert_eq!(f.edges(), [(0x4000, 0x4008), (0x4000, 0x4030)]);
    assert_eq!(
        f.inferred_edges(),
        [(0x4008, 0x4024), (0x4008, 0x4028), (0x4008, 0x402C)]
    );
    assert_eq!(
        xref_tuples(&a),
        [
            (0x4004, XrefKind::Code, 0x4030),
            (0x400C, XrefKind::Data, 0x4000),
            (0x4010, XrefKind::Data, 0x4038),
            (0x4014, XrefKind::Data, 0x4024),
            (0x4020, XrefKind::Data, 0x4038),
            (0x4020, XrefKind::Data, 0x4039),
            (0x4020, XrefKind::Data, 0x403A),
            (0x4020, XrefKind::InferredCode, 0x4024),
            (0x4020, XrefKind::InferredCode, 0x4028),
            (0x4020, XrefKind::InferredCode, 0x402C),
        ]
    );
    assert!(a.call_edges().is_empty());
}

// Bound over the per-site cap (`cmp eax, 2000` claims 2001 entries):
// exact-or-reject keeps the site unresolved without scanning.
#[test]
fn table_bound_exceeding_cap_stays_unresolved() {
    let b = vec![
        0x3D, 0xD0, 0x07, 0x00, 0x00, // 0x401000: cmp eax,2000
        0x73, 0x07, // jae default
        0xFF, 0x24, 0x85, 0x15, 0x10, 0x40, 0x00, // jmp [eax*4+0x401015]
        0xB8, 0x01, 0x00, 0x00, 0x00, // default: mov eax,1
        0xC3, // ret
        0x90, // pad to the table
        0x1C, 0x10, 0x40, 0x00, // slot 0 -> body
        0x1D, 0x10, 0x40, 0x00, // slot 1 -> body+1
        0xC3, 0xC3, // bodies (never decoded: no typed base)
    ];
    let a = x32(&b, 0x401000, Some(0x401000));
    let site = insn_at(&a, 0x401000, 0x401007);
    assert_eq!(site.table_base, Some(0x401015));
    assert_eq!(
        diagnostics_of(&a),
        [(0x401007, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(inferred_of(&a).is_empty());
    assert!(a.xrefs_page(Some(XrefKind::InferredCode), 0, 64).is_empty());
}
