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
    assert_eq!(r.changed.len(), 1);
    let c = &r.changed[0];
    assert_eq!((c.entry_a, c.entry_b), (0x14, 0x14));
    assert_eq!(c.reason, binscout::diff::MatchReason::IrMatch);
    assert!(c.similarity.is_none(), "only fuzzy sets similarity");
    assert_eq!(c.ir_hash_a, c.ir_hash_b);
    assert_ne!(c.bytes_hash_a, c.bytes_hash_b);

    // IR-dissimilar leaves stay unpaired (similarity 4/6 < 0.8).
    assert_eq!(r.removed.len(), 1);
    assert_eq!(r.removed[0].entry, 0x1F);
    assert_eq!(r.added.len(), 1);
    assert_eq!(r.added[0].entry, 0x1F);

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
    assert_eq!(r.changed.len(), 1);
    let c = &r.changed[0];
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
    assert_eq!(v["changed"][0]["reason"], "ir-match");
    assert_eq!(v["changed"][0]["entry_a"], 0x14);
    assert_eq!(v["changed"][0]["entry_a_hex"], "0x14");
    assert!(v["changed"][0]["similarity"].is_null());
    assert_eq!(v["removed"][0]["entry"], 0x1F);
    assert_eq!(v["removed"][0]["entry_hex"], "0x1f");
    assert_eq!(v["added"][0]["entry"], 0x1F);
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
