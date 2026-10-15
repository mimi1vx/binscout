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
