//! Bindiff-lite e2e: two builds of one synthetic fixture report
//! added/removed/changed; CLI and MCP surfaces stay read-only JSON.

mod common;

use std::process::Command;

use serde_json::Value;

use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

/// Build A: `f_main@0x0` calls `f_ret1@0x14` (`mov eax,1` leaf);
/// `f_old@0x1F` is a framed `xor eax,eax` leaf removed in B.
fn blob_a() -> Vec<u8> {
    let mut b = vec![
        0x55, 0x48, 0x89, 0xE5, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ];
    b.extend([0x90; 9]);
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ]);
    b.extend([0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3]);
    b
}

/// Build B: same `f_main`, `f_ret2@0x14` bumps the immediate to 2
/// (same IR, changed bytes), `f_new@0x1F` is a framed add/sub leaf.
/// The body avoids interior prologue patterns (`48 83 EC` would seed a
/// fourth function), so B holds exactly three functions like A.
fn blob_b() -> Vec<u8> {
    let mut b = vec![
        0x55, 0x48, 0x89, 0xE5, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ];
    b.extend([0x90; 9]);
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ]);
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xC0, 0x05, 0x48, 0x83, 0xE8, 0x03, 0x5D, 0xC3,
    ]);
    b
}

fn open_pair(dir: &std::path::Path) -> (binscout::Project, binscout::Project) {
    let a = write_bin(dir, "a.bin", &blob_a());
    let b = write_bin(dir, "b.bin", &blob_b());
    let pa = binscout::Project::open_with_db(&a, &temp_db(dir, "a")).expect("open a");
    let pb = binscout::Project::open_with_db(&b, &temp_db(dir, "b")).expect("open b");
    (pa, pb)
}

#[test]
fn lib_diff_reports_added_removed_changed() {
    let dir = tmpdir("diff-lib");
    let (pa, pb) = open_pair(&dir);
    assert_eq!(pa.analysis().functions.len(), 3, "fixture A shape");
    assert_eq!(pb.analysis().functions.len(), 3, "fixture B shape");

    let r = binscout::diff::diff_projects(&pa, &pb);
    assert_eq!(
        r.summary,
        binscout::diff::DiffSummary {
            matched: 1,
            changed: 1,
            added: 1,
            removed: 1,
            truncated: false,
        }
    );

    // Same IR under bumped immediates pairs by content, not by entry math.
    assert_eq!(r.changed.total, 1);
    assert_eq!(r.changed.items.len(), 1);
    let c = &r.changed.items[0];
    assert_eq!((c.entry_a, c.entry_b), (0x14, 0x14));
    assert_eq!(c.reason, binscout::diff::MatchReason::IrMatch);
    assert!(c.similarity.is_none(), "only fuzzy sets similarity");
    assert_eq!(c.ir_hash_a, c.ir_hash_b);
    assert_ne!(c.bytes_hash_a, c.bytes_hash_b);

    // IR-dissimilar leaves stay unpaired (similarity 4/6 < 0.8).
    assert_eq!(r.removed.total, 1);
    assert_eq!(r.removed.items[0].entry, 0x1F);
    assert_eq!(r.added.total, 1);
    assert_eq!(r.added.items[0].entry, 0x1F);

    // Reads never create sidecars.
    assert!(!temp_db(&dir, "a").exists());
    assert!(!temp_db(&dir, "b").exists());
    cleanup(&dir);
}

#[test]
fn lib_diff_same_export_new_body_is_name_match() {
    use common::builders::BASIC_ENTRY_VA;
    let dir = tmpdir("diff-name");
    let mut v2 = common::fixture_bytes("pe32-basic.exe");
    // `.text` starts at file offset 0x200 (see builders: headers pad to
    // `HEADERS_SIZE`, each section holds 0x200 raw bytes). Replace the
    // entry body (push ebp; mov ebp,esp; push x2; ret) with an xor-zero
    // stub plus unreachable rets: same export, alien IR.
    const TEXT_OFF: usize = 0x200;
    let at = TEXT_OFF;
    v2[at..at + 3].copy_from_slice(&[0x31, 0xC0, 0xC3]);
    for b in v2.iter_mut().skip(at + 3).take(0x200 - 3) {
        *b = 0xC3;
    }
    let v1 = write_bin(&dir, "v1.exe", &common::fixture_bytes("pe32-basic.exe"));
    let v2p = write_bin(&dir, "v2.exe", &v2);
    let p1 = binscout::Project::open_with_db(&v1, &temp_db(&dir, "v1")).expect("open v1");
    let p2 = binscout::Project::open_with_db(&v2p, &temp_db(&dir, "v2")).expect("open v2");
    assert_eq!(p1.analysis().functions.len(), 1);
    assert_eq!(p2.analysis().functions.len(), 1);

    let r = binscout::diff::diff_projects(&p1, &p2);
    assert_eq!(r.summary.matched, 0);
    assert_eq!(r.summary.added, 0);
    assert_eq!(r.summary.removed, 0);
    assert_eq!(r.changed.total, 1);
    let c = &r.changed.items[0];
    assert_eq!((c.entry_a, c.entry_b), (BASIC_ENTRY_VA, BASIC_ENTRY_VA));
    assert_eq!(c.reason, binscout::diff::MatchReason::NameMatch);
    assert_eq!(c.name_a.as_deref(), Some("basic_entry"));
    assert_eq!(c.name_b.as_deref(), Some("basic_entry"));
    cleanup(&dir);
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
fn lib_diff_func_rows_carry_renames_without_affecting_pairing() {
    let dir = tmpdir("diff-rename");
    let a = write_bin(&dir, "a.bin", &blob_a());
    let b = write_bin(&dir, "b.bin", &blob_b());
    let mut pa = binscout::Project::open_with_db(&a, &temp_db(&dir, "a")).expect("open a");
    let mut pb = binscout::Project::open_with_db(&b, &temp_db(&dir, "b")).expect("open b");

    // Raw blobs carry no symbol names. Renames are per-side display
    // labels: they must surface in the one-sided rows yet never affect
    // content pairing.
    pa.rename_function(0x1F, "old_gone")
        .expect("rename removed");
    pb.rename_function(0x1F, "new_here").expect("rename added");
    pa.rename_function(0x14, "alpha").expect("rename changed A");
    pb.rename_function(0x14, "beta").expect("rename changed B");

    let r = binscout::diff::diff_projects(&pa, &pb);
    assert_eq!(r.summary.matched, 1);
    assert_eq!(r.summary.changed, 1);
    assert_eq!(r.summary.added, 1);
    assert_eq!(r.summary.removed, 1);

    // One-sided rows carry the rename-resolved display name.
    assert_eq!(r.removed.total, 1);
    assert_eq!(r.removed.items[0].entry, 0x1F);
    assert_eq!(r.removed.items[0].name.as_deref(), Some("old_gone"));
    assert_eq!(r.added.total, 1);
    assert_eq!(r.added.items[0].entry, 0x1F);
    assert_eq!(r.added.items[0].name.as_deref(), Some("new_here"));

    // Differing renames do not break content pairing.
    assert_eq!(r.changed.total, 1);
    let c = &r.changed.items[0];
    assert_eq!((c.entry_a, c.entry_b), (0x14, 0x14));
    assert_eq!(c.reason, binscout::diff::MatchReason::IrMatch);
    cleanup(&dir);
}

#[test]
fn cli_diff_reports_added_removed_changed_and_writes_nothing() {
    let dir = tmpdir("diff-cli");
    let a = write_bin(&dir, "a.bin", &blob_a()).display().to_string();
    let b = write_bin(&dir, "b.bin", &blob_b()).display().to_string();
    let db_a = temp_db(&dir, "a").display().to_string();
    let db_b = temp_db(&dir, "b").display().to_string();
    let before_a = blob_a();
    let before_b = blob_b();

    let (ok, v) = run(&["diff", &a, &b, "--db-a", &db_a, "--db-b", &db_b]);
    assert!(ok, "{v}");
    assert_eq!(v["summary"]["matched"], 1);
    assert_eq!(v["summary"]["changed"], 1);
    assert_eq!(v["summary"]["added"], 1);
    assert_eq!(v["summary"]["removed"], 1);
    assert_eq!(v["summary"]["truncated"], false);
    assert_eq!(v["changed"]["items"][0]["reason"], "ir-match");
    assert_eq!(v["changed"]["items"][0]["entry_a"], 0x14);
    assert_eq!(v["changed"]["items"][0]["entry_a_hex"], "0x14");
    assert!(v["changed"]["items"][0]["similarity"].is_null());
    assert_eq!(v["removed"]["items"][0]["entry"], 0x1F);
    assert_eq!(v["removed"]["items"][0]["entry_hex"], "0x1f");
    assert_eq!(v["added"]["items"][0]["entry"], 0x1F);
    assert_eq!(v["arch_a"], "x86_64");
    assert_eq!(v["arch_b"], "x86_64");

    // Same pair under one explicit raw mapping agrees.
    let (ok, raw) = run(&[
        "--raw", "--arch", "x86_64", "--base", "0x0", "diff", &a, &b, "--db-a", &db_a, "--db-b",
        &db_b,
    ]);
    assert!(ok, "{raw}");
    assert_eq!(raw["summary"], v["summary"]);

    // Read-only: no sidecars, binaries untouched.
    assert!(!std::path::Path::new(&db_a).exists(), "sidecar A");
    assert!(!std::path::Path::new(&db_b).exists(), "sidecar B");
    assert_eq!(std::fs::read(dir.join("a.bin")).expect("reread"), before_a);
    assert_eq!(std::fs::read(dir.join("b.bin")).expect("reread"), before_b);

    // The global --db cannot serve two projects.
    let (ok, v) = run(&["--db", &db_a, "diff", &a, &b]);
    assert!(!ok && v.get("error").is_some(), "{v}");
    cleanup(&dir);
}

#[test]
fn diff_match_threshold_is_documented_value() {
    assert_eq!(binscout::diff::FUZZY_SIMILARITY_THRESHOLD, 0.8);
}

/// Caller plus leaf on both sides; the caller is byte-identical while
/// the leaves differ by one `nop` (5 shared ops of 6: similarity 5/6).
/// Only the fuzzy pass can pair the leaves, and both carry one
/// incoming call xref, so the pass runs on real non-zero xref shapes.
fn fuzzy_caller_blob(leaf: &[u8]) -> Vec<u8> {
    let mut b = vec![
        0x55, 0x48, 0x89, 0xE5, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ];
    b.extend([0x90; 9]);
    b.extend_from_slice(leaf);
    b
}

#[test]
fn lib_diff_fuzzy_pairs_leaf_with_extra_nop() {
    // Framed `xor eax,eax` leaf vs the same leaf plus `nop`: bytes and
    // IR both differ and raw blobs carry no names, so only the fuzzy
    // pass (similarity 5/6 >= 0.8, equal empty shapes) can pair them.
    let dir = tmpdir("diff-fuzzy-leaf");
    let a = write_bin(
        &dir,
        "a.bin",
        &[0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3],
    );
    let b = write_bin(
        &dir,
        "b.bin",
        &[0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x90, 0x5D, 0xC3],
    );
    let pa = binscout::Project::open_with_db(&a, &temp_db(&dir, "a")).expect("open a");
    let pb = binscout::Project::open_with_db(&b, &temp_db(&dir, "b")).expect("open b");
    assert_eq!(pa.analysis().functions.len(), 1, "fixture A shape");
    assert_eq!(pb.analysis().functions.len(), 1, "fixture B shape");

    let r = binscout::diff::diff_projects(&pa, &pb);
    assert_eq!(r.summary.matched, 0);
    assert_eq!(r.summary.added, 0);
    assert_eq!(r.summary.removed, 0);
    assert_eq!(r.changed.items.len(), 1);
    let c = &r.changed.items[0];
    assert_eq!((c.entry_a, c.entry_b), (0, 0));
    assert_eq!(c.reason, binscout::diff::MatchReason::Fuzzy);
    let sim = c.similarity.expect("fuzzy records similarity");
    assert!((sim - 5.0 / 6.0).abs() < 1e-9, "got {sim}");
    assert_ne!(c.bytes_hash_a, c.bytes_hash_b);
    assert_ne!(c.ir_hash_a, c.ir_hash_b);
    cleanup(&dir);
}

#[test]
fn lib_diff_fuzzy_pairs_called_leaf_with_extra_nop() {
    let dir = tmpdir("diff-fuzzy-caller");
    let leaf_a = [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3];
    let leaf_b = [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x90, 0x5D, 0xC3];
    let a = write_bin(&dir, "a.bin", &fuzzy_caller_blob(&leaf_a));
    let b = write_bin(&dir, "b.bin", &fuzzy_caller_blob(&leaf_b));
    let pa = binscout::Project::open_with_db(&a, &temp_db(&dir, "a")).expect("open a");
    let pb = binscout::Project::open_with_db(&b, &temp_db(&dir, "b")).expect("open b");
    assert_eq!(pa.analysis().functions.len(), 2, "fixture A shape");
    assert_eq!(pb.analysis().functions.len(), 2, "fixture B shape");

    let r = binscout::diff::diff_projects(&pa, &pb);
    assert_eq!(
        r.summary,
        binscout::diff::DiffSummary {
            matched: 1,
            changed: 1,
            added: 0,
            removed: 0,
            truncated: false,
        }
    );
    assert_eq!(r.changed.items.len(), 1);
    let c = &r.changed.items[0];
    assert_eq!((c.entry_a, c.entry_b), (0x14, 0x14));
    assert_eq!(c.reason, binscout::diff::MatchReason::Fuzzy);
    let sim = c.similarity.expect("fuzzy records similarity");
    assert!((sim - 5.0 / 6.0).abs() < 1e-9, "got {sim}");
    cleanup(&dir);
}

#[test]
fn lib_diff_large_identical_pair_matches_all() {
    // 2000 identical frame stubs: the binary-search xref counts and the
    // hash passes at scale, with nothing escaping to the fuzzy pass.
    const N: usize = 2000;
    const STUB: &[u8] = &[0x55, 0x48, 0x89, 0xE5, 0xC3];
    let dir = tmpdir("diff-scale");
    let mut blob = Vec::with_capacity(N * STUB.len());
    for _ in 0..N {
        blob.extend_from_slice(STUB);
    }
    let a = write_bin(&dir, "a.bin", &blob);
    let b = write_bin(&dir, "b.bin", &blob);
    let pa = binscout::Project::open_with_db(&a, &temp_db(&dir, "a")).expect("open a");
    let pb = binscout::Project::open_with_db(&b, &temp_db(&dir, "b")).expect("open b");
    assert_eq!(pa.analysis().functions.len(), N, "fixture A shape");
    assert_eq!(pb.analysis().functions.len(), N, "fixture B shape");

    let r = binscout::diff::diff_projects(&pa, &pb);
    assert_eq!(r.summary.matched, N);
    assert_eq!(r.summary.changed, 0);
    assert_eq!(r.summary.added, 0);
    assert_eq!(r.summary.removed, 0);
    assert!(!r.summary.truncated);
    cleanup(&dir);
}

#[test]
fn lib_diff_summary_counts_survive_truncation() {
    // Side A holds one bare `ret`; side B holds 1500 identical frame
    // stubs (`push rbp; mov rbp,rsp; ret`, each seeding its own function
    // via the prologue scan). Nothing pairs, so all 1500 land in `added`:
    // the summary must report the exact total while the list clips to
    // the shared 1024-row page budget.
    let dir = tmpdir("diff-trunc");
    const N: usize = 1500;
    const STUB: &[u8] = &[0x55, 0x48, 0x89, 0xE5, 0xC3];
    let mut blob = Vec::with_capacity(N * STUB.len());
    for _ in 0..N {
        blob.extend_from_slice(STUB);
    }
    let a = write_bin(&dir, "a.bin", &[0xC3]);
    let b = write_bin(&dir, "b.bin", &blob);
    let pa = binscout::Project::open_with_db(&a, &temp_db(&dir, "a")).expect("open a");
    let pb = binscout::Project::open_with_db(&b, &temp_db(&dir, "b")).expect("open b");
    assert_eq!(pa.analysis().functions.len(), 1, "fixture A shape");
    assert_eq!(pb.analysis().functions.len(), N, "fixture B shape");

    let r = binscout::diff::diff_projects(&pa, &pb);
    assert_eq!(r.summary.matched, 0);
    assert_eq!(r.summary.changed, 0);
    assert_eq!(r.summary.removed, 1);
    assert_eq!(r.summary.added, N);
    assert!(r.summary.truncated);
    assert_eq!(r.added.total, N, "exact total survives paging");
    assert_eq!(r.added.items.len(), 1024, "first page clips to the budget");
    assert_eq!(r.added.next_offset, Some(1024));
    assert_eq!(r.removed.total, 1);
    assert_eq!(r.removed.items.len(), 1);
    assert!(r.changed.items.is_empty());
    assert_eq!(r.changed.total, 0);
    // Truncation keeps entry order from the head.
    assert_eq!(r.added.items.first().map(|f| f.entry), Some(0));
    assert_eq!(
        r.added.items.last().map(|f| f.entry),
        Some(1023 * STUB.len() as u64)
    );

    // Second page walks on from next_offset with its own total.
    let p2 = binscout::diff::diff_projects_page(&pa, &pb, 1024, 1024);
    assert_eq!(p2.added.total, N);
    assert_eq!(p2.added.items.len(), N - 1024);
    assert_eq!(p2.added.next_offset, None);

    // Reads never create sidecars.
    assert!(!temp_db(&dir, "a").exists());
    assert!(!temp_db(&dir, "b").exists());
    cleanup(&dir);
}
