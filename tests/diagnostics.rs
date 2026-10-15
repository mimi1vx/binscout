//! Diagnostics and discovery-provenance tests (plan §6).
//!
//! Synthetic x86-64 blobs pin the exact deterministic reason and
//! diagnostic sets: direct calls, indirect jumps/calls, invalid decodes,
//! prologue seeds, and exports. Fresh analyses and saved/reopened
//! snapshots must agree bit-identically; the record cap truncates with an
//! explicit omitted count while hard analysis budgets stay errors.

mod common;

use binscout::analysis::{
    Analysis, Diagnostic, DiagnosticKind, DiscoveryReason, MAX_DIAGNOSTICS, XrefKind, analyze,
    analyze_raw,
};
use binscout::disasm::Arch;
use binscout::error::Error;
use binscout::loader::{BinaryFormat, ExportRef, LoadedBinary, RawOptions, Segment};
use redb::ReadableTable;

fn x64(bytes: &[u8], base: u64, entry: Option<u64>) -> Analysis {
    analyze_raw(bytes, base, Arch::X86_64, entry).expect("synthetic blob must analyze")
}

fn reasons_of(a: &Analysis, entry: u64) -> Vec<DiscoveryReason> {
    a.functions
        .get(&entry)
        .expect("function must exist")
        .reason_list()
}

fn diagnostics_of(a: &Analysis) -> Vec<(u64, DiagnosticKind)> {
    a.diagnostics
        .records
        .iter()
        .map(|d| (d.addr, d.kind))
        .collect()
}

fn assert_sorted_deduped(a: &Analysis) {
    let mut ds = a.diagnostics.records.clone();
    ds.sort_unstable();
    ds.dedup();
    assert_eq!(
        a.diagnostics.records, ds,
        "diagnostics must be sorted and deduplicated"
    );
    for f in a.functions.values() {
        let rs = f.reason_list();
        let mut sorted = rs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(rs, sorted, "reasons must be sorted and deduplicated");
        assert!(!rs.is_empty(), "every function carries a reason");
    }
}

// func@0x1000 calls func@0x1010; no gaps, no indirect control flow.
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
fn direct_call_yields_entry_and_direct_call_reasons_with_no_diagnostics() {
    let a = x64(&two_funcs(), 0x1000, Some(0x1000));
    assert_eq!(reasons_of(&a, 0x1000), [DiscoveryReason::Entry]);
    assert_eq!(reasons_of(&a, 0x1010), [DiscoveryReason::DirectCall]);
    assert!(a.diagnostics.records.is_empty());
    assert!(!a.diagnostics.truncated);
    assert_eq!(a.diagnostics.omitted, 0);
    assert_sorted_deduped(&a);
}

#[test]
fn prologue_scan_seeds_unreachable_function_with_prologue_reason() {
    // ret | nop*7 | push rbp | mov rbp,rsp | ret: the frame is only found
    // via the prologue scan.
    let mut b = vec![0xC3];
    b.extend([0x90; 7]);
    b.extend([0x55, 0x48, 0x89, 0xE5, 0xC3]);
    let a = x64(&b, 0x3000, None);
    assert_eq!(reasons_of(&a, 0x3000), [DiscoveryReason::Entry]);
    assert_eq!(reasons_of(&a, 0x3008), [DiscoveryReason::Prologue]);
    assert!(a.diagnostics.records.is_empty());
    assert_sorted_deduped(&a);
}

#[test]
fn export_and_direct_call_reasons_coexist_sorted() {
    let bytes = two_funcs();
    let bin = LoadedBinary {
        format: BinaryFormat::Raw,
        arch: Arch::X86_64,
        entry: Some(0x1000),
        segments: vec![Segment {
            vaddr: 0x1000,
            mem_size: bytes.len() as u64,
            data: bytes,
            readable: true,
            writable: false,
            executable: true,
        }],
        sections: Vec::new(),
        imports: Vec::new(),
        exports: vec![ExportRef {
            name: "myexport".to_string(),
            address: Some(0x1010),
            ordinal: None,
            demangled: None,
        }],
    };
    let a = analyze(&bin).expect("raw with export must analyze");
    assert_eq!(reasons_of(&a, 0x1000), [DiscoveryReason::Entry]);
    assert_eq!(
        reasons_of(&a, 0x1010),
        [DiscoveryReason::Export, DiscoveryReason::DirectCall]
    );
    assert_sorted_deduped(&a);
}

#[test]
fn entry_and_direct_call_reasons_coexist_on_recursive_entry() {
    // 0x1000 calls 0x1008; 0x1008 calls 0x1000 back.
    let b = vec![
        0xE8, 0x03, 0x00, 0x00, 0x00, // call 0x1008
        0xC3, // ret
        0x90, 0x90, // pad
        0xE8, 0xF3, 0xFF, 0xFF, 0xFF, // call 0x1000
        0xC3, // ret
    ];
    let a = x64(&b, 0x1000, Some(0x1000));
    assert_eq!(
        reasons_of(&a, 0x1000),
        [DiscoveryReason::Entry, DiscoveryReason::DirectCall]
    );
    assert_eq!(reasons_of(&a, 0x1008), [DiscoveryReason::DirectCall]);
    assert_sorted_deduped(&a);
}

#[test]
fn indirect_call_records_site_and_stays_edgeless() {
    // call rax | ret.
    let a = x64(&[0xFF, 0xD0, 0xC3], 0x1000, Some(0x1000));
    assert_eq!(
        diagnostics_of(&a),
        [(0x1000, DiagnosticKind::UnresolvedIndirectCall)]
    );
    assert!(!a.diagnostics.truncated);
    assert_eq!(a.diagnostics.omitted, 0);
    assert_eq!(reasons_of(&a, 0x1000), [DiscoveryReason::Entry]);
    // Unresolved control flow is never upgraded to a proven edge.
    assert!(a.call_edges().is_empty());
    assert!(a.calls_of(0x1000).is_empty());
    assert!(
        a.xrefs_page(Some(XrefKind::Code), 0, 64)
            .iter()
            .all(|x| x.from != 0x1000),
        "indirect call must not produce a code xref"
    );
    assert_sorted_deduped(&a);
}

#[test]
fn indirect_jump_records_site_and_stays_edgeless() {
    // jmp rax (fallthrough bytes never decode: the path ends).
    let a = x64(&[0xFF, 0xE0, 0xC3], 0x1000, Some(0x1000));
    assert_eq!(
        diagnostics_of(&a),
        [(0x1000, DiagnosticKind::UnresolvedIndirectJump)]
    );
    let f = &a.functions[&0x1000];
    assert_eq!(f.insn_count(), 1);
    assert!(f.edges().is_empty());
    assert!(a.call_edges().is_empty());
    assert_sorted_deduped(&a);
}

#[test]
fn decode_failure_records_queued_address_only() {
    // nop | invalid (0x06 is push-es, invalid in 64-bit) | ret: the ret is
    // never queued, so only the invalid address is recorded.
    let a = x64(&[0x90, 0x06, 0xC3], 0x1000, Some(0x1000));
    assert_eq!(
        diagnostics_of(&a),
        [(0x1001, DiagnosticKind::DecodeFailure)]
    );
    assert_eq!(a.functions[&0x1000].insn_count(), 1);
    assert_sorted_deduped(&a);
}

#[test]
fn valid_termination_is_not_a_decode_failure() {
    let a = x64(&[0xC3], 0x1000, Some(0x1000));
    assert!(a.diagnostics.records.is_empty());
    assert_eq!(reasons_of(&a, 0x1000), [DiscoveryReason::Entry]);
    let b = x64(&[0x90, 0x90, 0xC3], 0x1000, Some(0x1000));
    assert!(b.diagnostics.records.is_empty());
}

#[test]
fn empty_decode_still_reports_seed_failure() {
    // The entry byte itself is invalid: no functions, but the failure is
    // retained as evidence rather than a silent empty result.
    let a = x64(&[0x06], 0x1000, Some(0x1000));
    assert!(a.functions.is_empty());
    assert_eq!(
        diagnostics_of(&a),
        [(0x1000, DiagnosticKind::DecodeFailure)]
    );
}

#[test]
fn fresh_save_and_reopen_agree_on_diagnostics_and_reasons() {
    // call rax | ret | pad | frame func: Entry + Prologue reasons and one
    // indirect-call site in a single blob.
    let mut b = vec![0xFF, 0xD0, 0xC3];
    b.extend([0x90; 5]);
    b.extend([0x55, 0x48, 0x89, 0xE5, 0xC3]);
    let dir = common::tmpdir("diag-roundtrip");
    let bin = common::write_bin(&dir, "r.bin", &b);
    let db = common::temp_db(&dir, "r");
    let opts = RawOptions {
        base: 0x1000,
        arch: Arch::X86_64,
        entry: Some(0x1000),
    };

    let mut p = binscout::Project::open_raw(&bin, &db, opts).expect("raw open must analyze");
    let fresh: Analysis = p.analysis().clone();
    assert_eq!(
        diagnostics_of(&fresh),
        [(0x1000, DiagnosticKind::UnresolvedIndirectCall)]
    );
    assert_eq!(reasons_of(&fresh, 0x1000), [DiscoveryReason::Entry]);
    assert_eq!(reasons_of(&fresh, 0x1008), [DiscoveryReason::Prologue]);

    // Renames must not disturb provenance.
    p.rename_function(0x1008, "framed").expect("rename");
    drop(p);
    let q = binscout::Project::open_raw(&bin, &db, opts).expect("reopen must hit");
    assert_eq!(q.analysis().diagnostics, fresh.diagnostics);
    for (entry, func) in &fresh.functions {
        assert_eq!(
            q.analysis().functions[entry].reason_list(),
            func.reason_list(),
            "reasons must survive save/reopen at {entry:#x}"
        );
    }
    assert_eq!(q.function_name(0x1008).as_deref(), Some("framed"));

    // Same-mapping re-analysis after a patch keeps the shape: diagnostics
    // follow the bytes, annotations follow the address.
    let mut patched = b.clone();
    patched[0] = 0x90;
    patched[1] = 0x90;
    std::fs::write(&bin, &patched).expect("patch fixture");
    let r = binscout::Project::open_raw(&bin, &db, opts).expect("stale must reanalyze");
    assert!(r.analysis().diagnostics.records.is_empty());
    assert_eq!(r.function_name(0x1008).as_deref(), Some("framed"));
    common::cleanup(&dir);
}

#[test]
fn revision_mismatch_reanalyzes_instead_of_synthesizing_clean() {
    const BINARIES: redb::TableDefinition<u64, String> = redb::TableDefinition::new("binaries");

    let dir = common::tmpdir("diag-rev");
    let b = vec![0xFF, 0xD0, 0xC3];
    let bin = common::write_bin(&dir, "r.bin", &b);
    let db = common::temp_db(&dir, "r");
    let opts = RawOptions {
        base: 0x1000,
        arch: Arch::X86_64,
        entry: Some(0x1000),
    };
    let p = binscout::Project::open_raw(&bin, &db, opts).expect("open");
    let fresh_diagnostics = p.analysis().diagnostics.clone();
    assert_eq!(fresh_diagnostics.records.len(), 1);
    p.save().expect("save");
    drop(p);

    // Simulate a pre-diagnostics snapshot: a stale analysis revision must
    // re-analyze from the bytes, never synthesize a clean record set.
    {
        let handle = binscout::db::open_db(&db).expect("open db");
        let wtxn = handle.begin_write().expect("begin write");
        {
            let mut t = wtxn.open_table(BINARIES).expect("open binaries");
            let raw: String = t.get(0u64).expect("read").expect("row 0").value();
            let mut v: serde_json::Value = serde_json::from_str(&raw).expect("meta is json");
            v["analysis_rev"] = 1.into();
            t.insert(0u64, v.to_string()).expect("rewrite rev");
        }
        wtxn.commit().expect("commit");
    }

    let q = binscout::Project::open_raw(&bin, &db, opts).expect("stale must reanalyze");
    assert_eq!(q.analysis().diagnostics, fresh_diagnostics);
    common::cleanup(&dir);
}

#[test]
fn missing_diagnostics_table_errors_instead_of_clean_synthesis() {
    const DIAGNOSTICS: redb::TableDefinition<String, String> =
        redb::TableDefinition::new("diagnostics");

    let dir = common::tmpdir("diag-missing-table");
    let b = vec![0xFF, 0xD0, 0xC3];
    let bin = common::write_bin(&dir, "r.bin", &b);
    let db = common::temp_db(&dir, "r");
    let opts = RawOptions {
        base: 0x1000,
        arch: Arch::X86_64,
        entry: Some(0x1000),
    };
    let p = binscout::Project::open_raw(&bin, &db, opts).expect("open");
    assert_eq!(p.analysis().diagnostics.records.len(), 1);
    p.save().expect("save");
    drop(p);

    {
        let handle = binscout::db::open_db(&db).expect("open db");
        let wtxn = handle.begin_write().expect("begin write");
        wtxn.delete_table(DIAGNOSTICS).expect("drop diagnostics");
        wtxn.commit().expect("commit");
    }

    // Same bytes and mapping: the snapshot claims a hit but its
    // diagnostics table is gone, so the open must error rather than
    // report a clean bill of analysis.
    let err = binscout::Project::open_raw(&bin, &db, opts).unwrap_err();
    assert!(
        err.to_string().contains("diagnostics"),
        "missing diagnostics must error, got: {err:?}"
    );
    common::cleanup(&dir);
}

#[test]
fn diagnostic_cap_truncates_with_omitted_count_and_continues() {
    // `call rax` falls through, so N chained calls yield N sites.
    fn chain(n: usize) -> Vec<u8> {
        let mut b = Vec::with_capacity(n * 2);
        for _ in 0..n {
            b.extend([0xFF, 0xD0]);
        }
        b
    }
    let exact = x64(&chain(MAX_DIAGNOSTICS), 0x1000, Some(0x1000));
    assert_eq!(exact.diagnostics.records.len(), MAX_DIAGNOSTICS);
    assert!(!exact.diagnostics.truncated);
    assert_eq!(exact.diagnostics.omitted, 0);
    assert_sorted_deduped(&exact);

    let over = x64(&chain(MAX_DIAGNOSTICS + 1), 0x1000, Some(0x1000));
    assert_eq!(over.diagnostics.records.len(), MAX_DIAGNOSTICS);
    assert!(over.diagnostics.truncated);
    assert_eq!(over.diagnostics.omitted, 1);
    // Analysis continued past the cap: every call still decoded.
    assert_eq!(over.functions[&0x1000].insn_count(), MAX_DIAGNOSTICS + 1);
    assert_sorted_deduped(&over);

    // The truncated set round-trips through the sidecar bit-identically.
    let dir = common::tmpdir("diag-cap");
    let over_bytes = chain(MAX_DIAGNOSTICS + 1);
    let bin = common::write_bin(&dir, "r.bin", &over_bytes);
    let db = common::temp_db(&dir, "r");
    let opts = RawOptions {
        base: 0x1000,
        arch: Arch::X86_64,
        entry: Some(0x1000),
    };
    let p = binscout::Project::open_raw(&bin, &db, opts).expect("open");
    assert!(p.analysis().diagnostics.truncated);
    p.save().expect("save truncated snapshot");
    drop(p);
    let q = binscout::Project::open_raw(&bin, &db, opts).expect("reopen");
    assert_eq!(q.analysis().diagnostics, over.diagnostics);
    assert_eq!(q.analysis().diagnostics.omitted, 1);
    common::cleanup(&dir);
}

#[test]
fn hard_instruction_budget_stays_an_error() {
    // One nop past the decoded-instruction cap: Error::Limit, never a
    // truncated partial analysis masquerading as clean.
    let b = vec![0x90u8; binscout::analysis::MAX_TOTAL_INSNS + 1];
    let err = analyze_raw(&b, 0x1000, Arch::X86_64, Some(0x1000)).unwrap_err();
    assert!(
        matches!(err, Error::Limit(_)),
        "instruction budget must stay Limit, got: {err:?}"
    );
}

#[test]
fn diagnostics_serialize_with_hex_twins() {
    let d = Diagnostic {
        addr: 0x1000,
        kind: DiagnosticKind::UnresolvedIndirectCall,
    };
    let v = serde_json::to_value(d).expect("diagnostic serializes");
    assert_eq!(v["addr"], 0x1000);
    assert_eq!(v["addr_hex"], "0x1000");
    // Rows without the twin still deserialize (forward-compatible reads).
    let back: Diagnostic = serde_json::from_value(serde_json::json!({
        "addr": 0x1000u64,
        "kind": "UnresolvedIndirectCall",
    }))
    .expect("diagnostic without twin must decode");
    assert_eq!(back, d);
}

// §7 query layer: one blob with all three diagnostic kinds across two
// functions. Base 0x1000, entry 0x1000:
// 0x1000: call 0x1010; 0x1005: call rax (indirect call site);
// 0x1007: 0x06, invalid in 64-bit (decode failure, in no function);
// 0x1010: jmp rax (indirect jump site).
fn three_site_blob() -> Vec<u8> {
    let mut b = vec![0xE8, 0x0B, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x06];
    b.extend([0x90; 8]);
    b.extend([0xFF, 0xE0]);
    b
}

fn three_site_opts() -> RawOptions {
    RawOptions {
        base: 0x1000,
        arch: Arch::X86_64,
        entry: Some(0x1000),
    }
}

fn open_three_site(tag: &str) -> (binscout::Project, std::path::PathBuf) {
    let dir = common::tmpdir(tag);
    let bin = common::write_bin(&dir, "three.bin", &three_site_blob());
    let db = common::temp_db(&dir, "three");
    let p = binscout::Project::open_raw(&bin, &db, three_site_opts()).expect("open");
    (p, dir)
}

fn site_tuples(
    page: &binscout::Page<binscout::analysis::DiagnosticRow>,
) -> Vec<(u64, DiagnosticKind)> {
    page.items.iter().map(|r| (r.addr, r.kind)).collect()
}

#[test]
fn query_orders_by_kind_then_addr_and_pages() {
    let (p, dir) = open_three_site("diag-query-order");
    let page = p.query_diagnostics(None, None, 0, 50).expect("query");
    assert_eq!(page.protocol, binscout::WIRE_PROTOCOL);
    assert_eq!(page.total, 3);
    assert_eq!(
        site_tuples(&page),
        [
            (0x1010, DiagnosticKind::UnresolvedIndirectJump),
            (0x1005, DiagnosticKind::UnresolvedIndirectCall),
            (0x1007, DiagnosticKind::DecodeFailure),
        ]
    );
    // Paging slices the same order: successive pages concatenate exactly.
    let first = p.query_diagnostics(None, None, 0, 2).expect("page 1");
    assert_eq!(first.limit, 2);
    assert_eq!(first.next_offset, Some(2));
    let second = p.query_diagnostics(None, None, 2, 2).expect("page 2");
    assert_eq!(second.next_offset, None);
    let mut joined = site_tuples(&first);
    joined.extend(site_tuples(&second));
    assert_eq!(joined, site_tuples(&page));
    // Zero limit and past-end offsets are normal empty pages, not errors.
    let zero = p.query_diagnostics(None, None, 0, 0).expect("zero");
    assert_eq!((zero.total, zero.limit, zero.items.len()), (3, 0, 0));
    assert_eq!(zero.next_offset, None);
    let past = p.query_diagnostics(None, None, 99, 50).expect("past end");
    assert_eq!((past.total, past.items.len()), (3, 0));
    assert_eq!(past.next_offset, None);
    common::cleanup(&dir);
}

#[test]
fn query_kind_filter_precedes_pagination() {
    let (p, dir) = open_three_site("diag-query-kind");
    for (kind, addr) in [
        (DiagnosticKind::UnresolvedIndirectJump, 0x1010u64),
        (DiagnosticKind::UnresolvedIndirectCall, 0x1005u64),
        (DiagnosticKind::DecodeFailure, 0x1007u64),
    ] {
        let page = p
            .query_diagnostics(Some(kind), None, 0, 50)
            .expect("filter");
        assert_eq!(page.total, 1, "filtered total for {kind:?}");
        assert_eq!(site_tuples(&page), [(addr, kind)]);
        // The filtered total survives a zero limit: the count is exact
        // but no rows come back.
        let zero = p.query_diagnostics(Some(kind), None, 0, 0).expect("zero");
        assert_eq!((zero.total, zero.items.len()), (1, 0));
    }
    common::cleanup(&dir);
}

#[test]
fn query_func_filter_snaps_and_rejects_gaps() {
    let (p, dir) = open_three_site("diag-query-func");
    // Only the indirect call site lies in func 0x1000; the decode
    // failure at 0x1007 is in no function.
    let page = p
        .query_diagnostics(None, Some(0x1000), 0, 50)
        .expect("func");
    assert_eq!(page.total, 1);
    assert_eq!(
        site_tuples(&page),
        [(0x1005, DiagnosticKind::UnresolvedIndirectCall)]
    );
    // An interior address snaps to the same entry.
    let snapped = p
        .query_diagnostics(None, Some(0x1006), 0, 50)
        .expect("snap");
    assert_eq!(site_tuples(&snapped), site_tuples(&page));
    // The jump site's function keeps only its own row.
    let other = p
        .query_diagnostics(None, Some(0x1011), 0, 50)
        .expect("other");
    assert_eq!(
        site_tuples(&other),
        [(0x1010, DiagnosticKind::UnresolvedIndirectJump)]
    );
    // A failure site in no function, and an unmapped address, are
    // NotFound rather than empty pages.
    for addr in [0x1007u64, 0x2000] {
        let err = p.query_diagnostics(None, Some(addr), 0, 50).unwrap_err();
        assert!(
            matches!(err, Error::NotFound(_)),
            "func {addr:#x} must be NotFound, got: {err:?}"
        );
    }
    common::cleanup(&dir);
}

#[test]
fn query_rows_carry_hex_twins_func_and_detail() {
    let (p, dir) = open_three_site("diag-query-rows");
    let page = p.query_diagnostics(None, None, 0, 50).expect("query");
    let v = serde_json::to_value(&page).expect("page serializes");
    let items = v["items"].as_array().expect("items array");
    assert_eq!(items.len(), 3);
    let call = &items[1];
    assert_eq!(call["kind"], "unresolved-indirect-call");
    assert_eq!(call["addr"], 0x1005);
    assert_eq!(call["addr_hex"], "0x1005");
    assert_eq!(call["func"], 0x1000);
    assert_eq!(call["func_hex"], "0x1000");
    assert!(
        call["detail"].as_str().is_some_and(|d| !d.is_empty()),
        "kind-specific detail: {call}"
    );
    // The decode failure lies in no function: null on both sides.
    let failure = &items[2];
    assert_eq!(failure["kind"], "decode-failure");
    assert!(failure["func"].is_null() && failure["func_hex"].is_null());
    common::cleanup(&dir);
}

#[test]
fn func_meta_carries_reasons_and_survives_rename_and_reopen() {
    let (mut p, dir) = open_three_site("diag-meta-rename");
    let meta = p.func_meta(0x1010).expect("meta");
    assert_eq!(meta.reasons, [DiscoveryReason::DirectCall]);
    let v = serde_json::to_value(&meta).expect("meta serializes");
    assert_eq!(v["reasons"], serde_json::json!(["direct-call"]));
    let entry_meta =
        serde_json::to_value(p.func_meta(0x1000).expect("entry meta")).expect("meta serializes");
    assert_eq!(entry_meta["reasons"], serde_json::json!(["entry"]));
    // Renames change the name, never the provenance.
    p.rename_function(0x1010, "jump_target").expect("rename");
    let meta = p.func_meta(0x1010).expect("meta after rename");
    assert_eq!(meta.name.as_deref(), Some("jump_target"));
    assert_eq!(meta.reasons, [DiscoveryReason::DirectCall]);
    // Reasons and diagnostics survive a snapshot reopen bit-identically.
    let before = p.query_diagnostics(None, None, 0, 50).expect("before");
    p.save().expect("save");
    drop(p);
    let dir_bin = dir.join("three.bin");
    let db = common::temp_db(&dir, "three");
    let q = binscout::Project::open_raw(&dir_bin, &db, three_site_opts()).expect("reopen");
    assert_eq!(q.function_name(0x1010).as_deref(), Some("jump_target"));
    assert_eq!(
        q.func_meta(0x1010).expect("reopened meta").reasons,
        [DiscoveryReason::DirectCall]
    );
    assert_eq!(
        q.query_diagnostics(None, None, 0, 50).expect("after"),
        before
    );
    common::cleanup(&dir);
}

#[test]
fn project_info_carries_diagnostic_totals_and_revision() {
    let (p, dir) = open_three_site("diag-info");
    let info = p.project_info();
    assert_eq!(info.diagnostics, 3);
    assert!(!info.diagnostics_truncated);
    assert_eq!(info.diagnostics_omitted, 0);
    assert_eq!(
        info.analysis_revision,
        binscout::analysis::ANALYSIS_REVISION
    );
    let v = serde_json::to_value(&info).expect("info serializes");
    assert_eq!(v["diagnostics"], 3);
    assert_eq!(v["diagnostics_truncated"], false);
    assert_eq!(v["diagnostics_omitted"], 0);
    assert_eq!(
        v["analysis_revision"],
        binscout::analysis::ANALYSIS_REVISION
    );
    // `stats` reports the same four fields.
    let stats = p.stats_json().expect("stats");
    for k in [
        "diagnostics",
        "diagnostics_truncated",
        "diagnostics_omitted",
        "analysis_revision",
    ] {
        assert_eq!(stats[k], v[k], "stats {k} matches project_info");
    }
    common::cleanup(&dir);
}

#[test]
fn truncated_totals_round_trip_through_info_and_pages() {
    // `call rax` falls through, so chained calls yield one site each.
    let mut b = Vec::with_capacity((MAX_DIAGNOSTICS + 1) * 2);
    for _ in 0..MAX_DIAGNOSTICS + 1 {
        b.extend([0xFF, 0xD0]);
    }
    let dir = common::tmpdir("diag-info-cap");
    let bin = common::write_bin(&dir, "chain.bin", &b);
    let db = common::temp_db(&dir, "chain");
    let opts = RawOptions {
        base: 0x1000,
        arch: Arch::X86_64,
        entry: Some(0x1000),
    };
    let p = binscout::Project::open_raw(&bin, &db, opts).expect("open");
    let info = p.project_info();
    assert_eq!(info.diagnostics, MAX_DIAGNOSTICS);
    assert!(info.diagnostics_truncated);
    assert_eq!(info.diagnostics_omitted, 1);
    // The page total is the retained (capped) count.
    let page = p
        .query_diagnostics(Some(DiagnosticKind::UnresolvedIndirectCall), None, 0, 50)
        .expect("filtered page");
    assert_eq!(page.total, MAX_DIAGNOSTICS);
    assert_eq!(page.items.len(), 50);
    assert_eq!(page.next_offset, Some(50));
    p.save().expect("save truncated snapshot");
    drop(p);
    let q = binscout::Project::open_raw(&bin, &db, opts).expect("reopen");
    assert_eq!(q.project_info(), info);
    common::cleanup(&dir);
}

#[test]
fn querying_never_writes_a_sidecar() {
    let dir = common::tmpdir("diag-no-write");
    let bin = common::write_bin(&dir, "three.bin", &three_site_blob());
    let db = common::temp_db(&dir, "fresh");
    let p = binscout::Project::open_raw(&bin, &db, three_site_opts()).expect("open");
    let _ = p.query_diagnostics(None, None, 0, 50).expect("query");
    let _ = p.func_meta(0x1000).expect("meta");
    let _ = p.project_info();
    assert!(!db.exists(), "queries must never create the sidecar");
    common::cleanup(&dir);
}

#[test]
fn wire_spellings_are_kebab_case_with_camel_aliases() {
    assert_eq!(
        serde_json::to_value(DiscoveryReason::DirectCall).expect("reason serializes"),
        serde_json::json!("direct-call")
    );
    assert_eq!(
        serde_json::to_value(DiagnosticKind::DecodeFailure).expect("kind serializes"),
        serde_json::json!("decode-failure")
    );
    // Rows persisted under the historical CamelCase spelling still decode.
    let reason: DiscoveryReason =
        serde_json::from_value(serde_json::json!("DirectCall")).expect("alias decodes");
    assert_eq!(reason, DiscoveryReason::DirectCall);
    let kind: DiagnosticKind =
        serde_json::from_value(serde_json::json!("DecodeFailure")).expect("alias decodes");
    assert_eq!(kind, DiagnosticKind::DecodeFailure);
}
