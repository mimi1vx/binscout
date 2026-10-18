//! Patch-diff depth e2e: neighbour propagation, diff-func block detail,
//! rename transfer, and paged diff lists (lib, CLI, and MCP surfaces).

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use common::{binscout_bin, cleanup, mcp_bin, temp_db, tmpdir, write_bin};

/// Propagation fixture A: caller P calls leaf Q; caller T1 calls leaf S.
/// P and S are byte-identical in B; Q and T1 differ enough to dodge every
/// content pass, so only neighbour propagation can pair them.
fn prop_a() -> Vec<u8> {
    let mut b = vec![
        0x55, 0x48, 0x89, 0xE5, 0xE8, 0x02, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ];
    b.extend([0x55, 0x48, 0x89, 0xE5, 0xC3]);
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0xE8, 0x02, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ]);
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ]);
    b
}

/// Propagation fixture B: same callers P and T2 (T2 carries extra
/// arithmetic so content matching misses), widened leaf Q', identical S'.
fn prop_b() -> Vec<u8> {
    let mut b = vec![
        0x55, 0x48, 0x89, 0xE5, 0xE8, 0x02, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ];
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xC0, 0x05, 0x48, 0x83, 0xE8, 0x03, 0x5D, 0xC3,
    ]);
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xC0, 0x05, 0x48, 0x83, 0xE8, 0x03, 0xE8, 0x02, 0x00,
        0x00, 0x00, 0x5D, 0xC3,
    ]);
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ]);
    b
}

/// Two-block branch fixture A: conditional jump over a one-instruction
/// block, with distinct fallthrough/taken bodies.
fn branch_a() -> Vec<u8> {
    vec![
        0x55, 0x48, 0x89, 0xE5, // prologue
        0x31, 0xC0, // xor eax,eax
        0x85, 0xC0, // test eax,eax
        0x74, 0x06, // jz +6 -> 0x10
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 @0x0A
        0xC3, // ret @0x0F
        0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax,2 @0x10
        0xC3, // ret @0x15
    ]
}

/// Same skeleton with a different middle block (xor/inc instead of mov)
/// and an IR-distinct taken block (xor-zero instead of mov), so the head
/// hash-matches while the other two blocks pair by position.
fn branch_b() -> Vec<u8> {
    vec![
        0x55, 0x48, 0x89, 0xE5, // prologue
        0x31, 0xC0, // xor eax,eax
        0x85, 0xC0, // test eax,eax
        0x74, 0x05, // jz +5 -> 0x0F
        0x31, 0xC0, // xor eax,eax @0x0A
        0xFF, 0xC0, // inc eax
        0xC3, // ret @0x0E
        0x31, 0xC0, // xor eax,eax @0x0F
        0xC3, // ret @0x11
    ]
}

/// Tiny rename-transfer pair: identical first leaf, changed second leaf
/// (bumped immediate, same IR).
fn transfer_a() -> Vec<u8> {
    let mut b = vec![
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ];
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ]);
    b
}

fn transfer_b() -> Vec<u8> {
    let mut b = vec![
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ];
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x03, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ]);
    b
}

fn open_pair(
    dir: &std::path::Path,
    a_bytes: &[u8],
    b_bytes: &[u8],
) -> (binscout::Project, binscout::Project) {
    let a = write_bin(dir, "a.bin", a_bytes);
    let b = write_bin(dir, "b.bin", b_bytes);
    let pa = binscout::Project::open_with_db(&a, &temp_db(dir, "a")).expect("open a");
    let pb = binscout::Project::open_with_db(&b, &temp_db(dir, "b")).expect("open b");
    (pa, pb)
}

/// Run the CLI; assert stdout is one valid JSON value.
fn run(args: &[&str]) -> (bool, Value) {
    let out = Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value)
}

#[test]
fn propagation_pairs_unique_neighbours() {
    let dir = tmpdir("diffdepth-prop");
    let (pa, pb) = open_pair(&dir, &prop_a(), &prop_b());
    assert_eq!(pa.analysis().functions.len(), 4, "fixture A shape");
    assert_eq!(pb.analysis().functions.len(), 4, "fixture B shape");

    let r = binscout::diff::diff_projects(&pa, &pb);
    assert_eq!(
        r.summary,
        binscout::diff::DiffSummary {
            matched: 2,
            changed: 2,
            added: 0,
            removed: 0,
            truncated: false,
        }
    );
    // Q/Q' propagate from their matched caller P; T1/T2 from their matched
    // callee S. Sorted by (entry_a, entry_b), Q sorts first.
    assert_eq!(r.changed.total, 2);
    let first = &r.changed.items[0];
    let second = &r.changed.items[1];
    assert_eq!((first.entry_a, first.entry_b), (0x0B, 0x0B));
    assert_eq!(first.reason, binscout::diff::MatchReason::Propagated);
    assert!(first.similarity.is_none());
    assert_eq!((second.entry_a, second.entry_b), (0x10, 0x19));
    assert_eq!(second.reason, binscout::diff::MatchReason::Propagated);
    assert!(second.similarity.is_none());
    cleanup(&dir);
}

#[test]
fn diff_func_reports_hash_and_position_blocks_with_edits() {
    let dir = tmpdir("diffdepth-branch");
    let (pa, pb) = open_pair(&dir, &branch_a(), &branch_b());

    let r = binscout::diff::diff_func(&pa, 0x0, &pb, 0x0).expect("diff-func");
    assert_eq!((r.entry_a, r.entry_b), (0x0, 0x0));
    assert_eq!(r.summary.matched_blocks, 3);
    assert_eq!(r.summary.added_blocks, 0);
    assert_eq!(r.summary.removed_blocks, 0);
    assert!(!r.summary.truncated);

    // Head block hash-matches (same IR under shifted targets); the two
    // IR-distinct blocks pair by address-order position.
    let kinds: Vec<binscout::diff::BlockMatchKind> = r.blocks.iter().map(|b| b.kind).collect();
    assert_eq!(
        kinds,
        vec![
            binscout::diff::BlockMatchKind::Hash,
            binscout::diff::BlockMatchKind::Position,
            binscout::diff::BlockMatchKind::Position,
        ]
    );
    // Head block: four identical rows plus the shifted jump as changed.
    assert_eq!(r.blocks[0].edits.len(), 5);
    assert!(
        r.blocks[0]
            .edits
            .iter()
            .filter(|e| e.kind == binscout::diff::EditKind::Same)
            .count()
            == 4
    );
    // Middle block: mov aligned against xor/inc becomes changed + added,
    // with the shared ret staying same.
    let kinds: Vec<binscout::diff::EditKind> = r.blocks[1].edits.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![
            binscout::diff::EditKind::Changed,
            binscout::diff::EditKind::Added,
            binscout::diff::EditKind::Same,
        ]
    );
    // Taken block: mov against xor-zero becomes changed, ret stays same.
    let kinds: Vec<binscout::diff::EditKind> = r.blocks[2].edits.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![
            binscout::diff::EditKind::Changed,
            binscout::diff::EditKind::Same,
        ]
    );
    assert_eq!(r.summary.same_insns, 6);
    assert_eq!(r.summary.changed_insns, 3);
    assert_eq!(r.summary.added_insns, 1);
    assert_eq!(r.summary.removed_insns, 0);

    // Interior addresses snap to their containing entries.
    let snapped = binscout::diff::diff_func(&pa, 0x2, &pb, 0xD).expect("snap");
    assert_eq!((snapped.entry_a, snapped.entry_b), (0x0, 0x0));

    // Unknown addresses are NotFound, not a panic.
    assert!(binscout::diff::diff_func(&pa, 0x9999, &pb, 0x0).is_err());
    cleanup(&dir);
}

#[test]
fn diff_func_on_changed_pair_shows_ir_match_edits() {
    let dir = tmpdir("diffdepth-irpair");
    let (pa, pb) = open_pair(&dir, &transfer_a(), &transfer_b());

    let r = binscout::diff::diff_func(&pa, 0xB, &pb, 0xB).expect("diff-func");
    assert!(r.paired);
    assert_eq!(r.reason, Some(binscout::diff::MatchReason::IrMatch));
    assert_eq!(r.blocks.len(), 1);
    assert_eq!(r.blocks[0].kind, binscout::diff::BlockMatchKind::Hash);
    // push/mov/mov-imm/pop/ret: only the bumped immediate differs, and the
    // IR keys agree there, so it reports changed rather than added/removed.
    assert_eq!(r.blocks[0].edits.len(), 5);
    let changed: Vec<_> = r.blocks[0]
        .edits
        .iter()
        .filter(|e| e.kind == binscout::diff::EditKind::Changed)
        .collect();
    assert_eq!(changed.len(), 1);
    assert_ne!(changed[0].text_a, changed[0].text_b);
    assert!(!r.blocks[0].truncated);

    // The byte-identical pair reports no reason but still pairs.
    let same = binscout::diff::diff_func(&pa, 0x0, &pb, 0x0).expect("identical");
    assert!(same.paired);
    assert_eq!(same.reason, None);

    // An unpaired combination still gets a block delta.
    let mixed = binscout::diff::diff_func(&pa, 0x0, &pb, 0xB).expect("mixed");
    assert!(!mixed.paired);
    assert_eq!(mixed.reason, None);
    assert!(!mixed.blocks.is_empty());
    cleanup(&dir);
}

#[test]
fn transfer_renames_round_trips_through_import() {
    let dir = tmpdir("diffdepth-transfer");
    let (mut pa, mut pb) = open_pair(&dir, &transfer_a(), &transfer_b());
    pa.rename_function(0x0, "first").expect("rename kept");
    pa.rename_function(0xB, "second").expect("rename changed");

    let doc = binscout::diff::transfer_renames(&pa, &pb).expect("transfer");
    assert_eq!(doc.annotations.len(), 2);
    assert_eq!(doc.annotations[0].addr, 0x0);
    assert_eq!(doc.annotations[0].rename.as_deref(), Some("first"));
    assert_eq!(doc.annotations[1].addr, 0xB);
    assert_eq!(doc.annotations[1].rename.as_deref(), Some("second"));
    assert!(doc.func_seeds.is_empty());

    // The document imports into B through the standard machinery.
    let text = serde_json::to_string(&doc).expect("doc serializes");
    let summary = pb.import_annotations(&text, false).expect("import");
    assert_eq!(summary.rows, 2);
    assert_eq!(summary.changed, 2);
    assert_eq!(pb.function_name(0x0).as_deref(), Some("first"));
    assert_eq!(pb.function_name(0xB).as_deref(), Some("second"));
    cleanup(&dir);
}

#[test]
fn transfer_carries_no_rows_without_renames() {
    let dir = tmpdir("diffdepth-transfer-empty");
    let (pa, pb) = open_pair(&dir, &transfer_a(), &transfer_b());
    let doc = binscout::diff::transfer_renames(&pa, &pb).expect("transfer");
    assert!(doc.annotations.is_empty());
    cleanup(&dir);
}

#[test]
fn diff_pages_lists_under_the_envelope() {
    let dir = tmpdir("diffdepth-pages");
    const N: usize = 1100;
    const STUB: &[u8] = &[0x55, 0x48, 0x89, 0xE5, 0xC3];
    let mut blob = Vec::with_capacity(N * STUB.len());
    for _ in 0..N {
        blob.extend_from_slice(STUB);
    }
    let (pa, pb) = open_pair(&dir, &[0xC3], &blob);

    let p1 = binscout::diff::diff_projects_page(&pa, &pb, 0, 50);
    assert_eq!(p1.added.total, N);
    assert_eq!(p1.added.items.len(), 50);
    assert_eq!(p1.added.offset, 0);
    assert_eq!(p1.added.limit, 50);
    assert_eq!(p1.added.next_offset, Some(50));
    assert_eq!(p1.added.protocol, binscout::WIRE_PROTOCOL);
    assert_eq!(p1.added.items[0].entry, 0);
    assert_eq!(p1.added.items[49].entry, 49 * STUB.len() as u64);
    assert!(p1.summary.truncated);

    let p2 = binscout::diff::diff_projects_page(&pa, &pb, 1050, 100);
    assert_eq!(p2.added.total, N);
    assert_eq!(p2.added.items.len(), 50);
    assert_eq!(p2.added.next_offset, None);

    // Limits clip to the shared budget; the envelope reports the clip.
    let p3 = binscout::diff::diff_projects_page(&pa, &pb, 0, 5000);
    assert_eq!(p3.added.total, N);
    assert_eq!(p3.added.limit, 1024);
    assert_eq!(p3.added.items.len(), 1024);
    assert_eq!(p3.added.next_offset, Some(1024));

    // An offset past the end is a normal empty page.
    let p4 = binscout::diff::diff_projects_page(&pa, &pb, 5000, 10);
    assert_eq!(p4.added.total, N);
    assert!(p4.added.items.is_empty());
    assert_eq!(p4.added.next_offset, None);
    cleanup(&dir);
}

#[test]
fn cli_diff_func_reports_blocks_and_writes_nothing() {
    let dir = tmpdir("diffdepth-cli");
    let a = write_bin(&dir, "a.bin", &transfer_a())
        .display()
        .to_string();
    let b = write_bin(&dir, "b.bin", &transfer_b())
        .display()
        .to_string();
    let db_a = temp_db(&dir, "a").display().to_string();
    let db_b = temp_db(&dir, "b").display().to_string();

    let (ok, v) = run(&[
        "diff-func",
        &a,
        &b,
        "0xB",
        "0xB",
        "--db-a",
        &db_a,
        "--db-b",
        &db_b,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["entry_a"], 0xB);
    assert_eq!(v["entry_a_hex"], "0xb");
    assert_eq!(v["paired"], true);
    assert_eq!(v["reason"], "ir-match");
    assert_eq!(v["blocks"][0]["kind"], "hash");
    assert_eq!(v["summary"]["matched_blocks"], 1);
    assert_eq!(v["transfer"], Value::Null);

    // Paged diff plus transfer document in one report.
    let (ok, v) = run(&[
        "diff", &a, &b, "--db-a", &db_a, "--db-b", &db_b, "--offset", "0", "--limit", "10",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["added"]["total"], 0);
    assert_eq!(v["added"]["protocol"], 1);
    assert_eq!(v["changed"]["total"], 1);
    assert_eq!(v["changed"]["items"][0]["entry_a"], 0xB);
    assert_eq!(v["transfer"], Value::Null);

    // Read-only: no sidecars created.
    assert!(!std::path::Path::new(&db_a).exists(), "sidecar A");
    assert!(!std::path::Path::new(&db_b).exists(), "sidecar B");

    // Bad function addresses fail as JSON, not a usage error.
    let (ok, v) = run(&["diff-func", &a, &b, "0x9999", "0x0"]);
    assert!(!ok && v.get("error").is_some(), "{v}");

    // The global --db cannot serve two projects here either.
    let (ok, v) = run(&["--db", &db_a, "diff-func", &a, &b, "0x0", "0x0"]);
    assert!(!ok && v.get("error").is_some(), "{v}");
    cleanup(&dir);
}

#[test]
fn cli_diff_transfer_embeds_an_importable_document() {
    let dir = tmpdir("diffdepth-cli-transfer");
    let a = write_bin(&dir, "a.bin", &transfer_a());
    let b = write_bin(&dir, "b.bin", &transfer_b());
    // Seed a rename on side A through a persisted sidecar.
    let db_a = temp_db(&dir, "persist-a");
    {
        let mut pa = binscout::Project::open_with_db(&a, &db_a).expect("open a");
        pa.rename_function(0xB, "ported").expect("rename");
    }

    let (ok, v) = run(&[
        "diff",
        &a.display().to_string(),
        &b.display().to_string(),
        "--db-a",
        &db_a.display().to_string(),
        "--transfer-renames",
    ]);
    assert!(ok, "{v}");
    assert_eq!(
        v["transfer"]["annotations"].as_array().expect("rows").len(),
        1
    );
    assert_eq!(v["transfer"]["annotations"][0]["addr"], 0xB);
    assert_eq!(v["transfer"]["annotations"][0]["rename"], "ported");
    assert_eq!(v["transfer"]["revision"], 1);

    // The embedded document applies to B through annotations-import.
    let doc_path = dir.join("transfer.json");
    std::fs::write(&doc_path, v["transfer"].to_string()).expect("write doc");
    let db_b = temp_db(&dir, "persist-b").display().to_string();
    let (ok, v) = run(&[
        "annotations-import",
        &b.display().to_string(),
        "--db",
        &db_b,
        "--input",
        &doc_path.display().to_string(),
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["changed"], 1);
    let pb = binscout::Project::open_with_db(&b, temp_db(&dir, "persist-b").as_path())
        .expect("reopen b");
    assert_eq!(pb.function_name(0xB).as_deref(), Some("ported"));
    cleanup(&dir);
}

/// One request line plus notification; returns response lines in order.
fn session(lines: &[String]) -> Vec<Value> {
    let mut child = Command::new(mcp_bin())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn binscout-mcp");
    {
        let stdin = child.stdin.as_mut().expect("piped stdin");
        for line in lines {
            writeln!(stdin, "{line}").expect("write request");
        }
    }
    let out = child.wait_with_output().expect("server exits on stdin EOF");
    assert!(out.status.success(), "server exit: {}", out.status);
    let text = String::from_utf8(out.stdout).expect("stdout utf-8");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| panic!("response not JSON: {l:?}")))
        .collect()
}

fn req(id: u64, method: &str, params: Value) -> String {
    serde_json::to_string(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .expect("request serializes")
}

fn call(id: u64, name: &str, args: Value) -> String {
    req(id, "tools/call", json!({"name": name, "arguments": args}))
}

fn tool_text(resp: &Value) -> &str {
    let result = resp.get("result").expect("tool must return result");
    assert_ne!(
        result.get("isError"),
        Some(&Value::Bool(true)),
        "tool error: {resp}"
    );
    result["content"][0]["text"].as_str().expect("text content")
}

#[test]
fn mcp_diff_pages_and_diff_func_reports_detail() {
    let dir = tmpdir("diffdepth-mcp");
    let a = write_bin(&dir, "a.bin", &transfer_a())
        .display()
        .to_string();
    let b = write_bin(&dir, "b.bin", &transfer_b())
        .display()
        .to_string();
    let args = |extra: Value| {
        let mut base = json!({"binary_a": a, "binary_b": b});
        base.as_object_mut()
            .expect("obj")
            .extend(extra.as_object().expect("obj").clone());
        base
    };
    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(
            10,
            "diff",
            args(json!({"limit": 1, "transfer_renames": true})),
        ),
        call(
            11,
            "diff_func",
            args(json!({"addr_a": "0xB", "addr_b": "0xB"})),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 3, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();

    let diff: Value = serde_json::from_str(tool_text(by_id[&10])).expect("diff json");
    assert_eq!(diff["changed"]["total"], 1);
    assert_eq!(diff["changed"]["items"].as_array().expect("items").len(), 1);
    assert_eq!(diff["changed"]["limit"], 1);
    assert_eq!(diff["transfer"]["annotations"][0]["rename"], Value::Null);
    assert!(
        diff["transfer"]["annotations"]
            .as_array()
            .expect("rows")
            .is_empty()
    );

    let func: Value = serde_json::from_str(tool_text(by_id[&11])).expect("diff_func json");
    assert_eq!(func["entry_a"], 0xB);
    assert_eq!(func["paired"], true);
    assert_eq!(func["blocks"][0]["kind"], "hash");
    cleanup(&dir);
}
