//! M6 CLI e2e: every command prints exactly one valid JSON document;
//! failures print `{"error": ...}` with a nonzero exit.

mod common;

use std::path::Path;
use std::process::Command;

use serde_json::Value;

use common::{binscout_bin, cleanup, minimal_elf, temp_db, tmpdir, write_bin, write_fixture};

/// Run the CLI; assert stdout is one valid JSON value. Returns exit success
/// plus the parsed document.
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

fn s(v: &str) -> String {
    v.to_string()
}

/// Raw `nop; nop; ret` fixture plus a temp DB path.
fn raw_case(tag: &str) -> (String, String, String, std::path::PathBuf) {
    let dir = tmpdir(tag);
    let db = temp_db(&dir, "t");
    (
        s("tests/fixtures/raw-x64.bin"),
        db.display().to_string(),
        dir.display().to_string(),
        dir,
    )
}

#[test]
fn load_reports_project_info() {
    let (bin, db, _dir, dir) = raw_case("load");
    let (ok, v) = run(&["--db", &db, "load", &bin]);
    assert!(ok, "{v}");
    assert_eq!(v["arch"], "x86_64");
    assert_eq!(v["format"], "raw");
    assert_eq!(v["functions"], 1);
    assert_eq!(v["insns"], 3);
    assert!(Path::new(&db).exists(), "load caches the snapshot");
    cleanup(&dir);
}

#[test]
fn all_query_commands_return_json() {
    let (bin, db, _dir, dir) = raw_case("query");
    let db_args = ["--db".to_string(), db.clone()];
    let cases: Vec<Vec<String>> = vec![
        vec!["functions".into(), bin.clone()],
        vec!["func".into(), bin.clone(), "0x0".into()],
        vec!["blocks".into(), bin.clone(), "0x0".into()],
        vec![
            "block-insns".into(),
            bin.clone(),
            "0x0".into(),
            "0x0".into(),
        ],
        vec!["disasm".into(), bin.clone(), "0x0".into(), "3".into()],
        vec![
            "bytes".into(),
            bin.clone(),
            "0x0".into(),
            "--len".into(),
            "3".into(),
        ],
        vec!["cfg".into(), bin.clone(), "0x0".into()],
        vec!["structure".into(), bin.clone(), "0x0".into()],
        vec!["pseudo".into(), bin.clone(), "0x0".into()],
        vec!["slice".into(), bin.clone(), "0x0".into()],
        vec!["xrefs".into(), bin.clone()],
        vec!["strings".into(), bin.clone()],
        vec!["symbols".into(), bin.clone()],
        vec!["sections".into(), bin.clone()],
        vec!["diagnostics".into(), bin.clone()],
        vec!["ir".into(), bin.clone(), "0x0".into(), "3".into()],
        vec!["stats".into(), bin.clone()],
        vec!["headers".into(), bin.clone()],
        vec!["annotate".into(), bin.clone(), "0x0".into()],
        vec!["annotations-export".into(), bin.clone()],
    ];
    for mut c in cases {
        let mut args: Vec<String> = db_args.to_vec();
        args.append(&mut c);
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let (ok, v) = run(&arg_refs);
        assert!(ok, "{} failed: {v}", args[2]);
    }
    cleanup(&dir);
}

#[test]
fn query_results_have_expected_shape() {
    let (bin, db, _dir, dir) = raw_case("shape");
    let d = db.as_str();
    let (ok, v) = run(&["--db", d, "functions", &bin]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("functions is an array").len(), 1);
    assert_eq!(v[0]["entry"], 0);

    let (ok, v) = run(&["--db", d, "func", &bin, "0x0"]);
    assert!(ok, "{v}");
    // Compact metadata: counts only, no embedded block/insn arrays.
    assert_eq!(v["entry"], 0);
    assert_eq!(v["entry_hex"], "0x0");
    assert_eq!(v["blocks"], 1);
    assert_eq!(v["insns"], 3);
    assert_eq!(v["calls"], 0);
    assert!(v.get("containing_entry").is_none(), "no snap twin: {v}");
    assert!(v.get("edges").is_none(), "no edges array: {v}");
    assert!(
        v.get("blocks").is_some_and(|b| b.is_number()),
        "blocks is a count: {v}"
    );

    let (ok, v) = run(&["--db", d, "blocks", &bin, "0x0"]);
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 1);
    assert_eq!(v["items"].as_array().expect("items array").len(), 1);
    assert_eq!(v["items"][0]["start"], 0);
    assert_eq!(v["items"][0]["insns"], 3);
    assert!(v["items"][0].get("succs").is_some(), "{v}");

    let (ok, v) = run(&["--db", d, "block-insns", &bin, "0x0", "0x0"]);
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 3);
    let items = v["items"].as_array().expect("items array");
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["mnem"], "nop");
    assert_eq!(items[2]["mnem"], "ret");

    let (ok, v) = run(&["--db", d, "disasm", &bin, "0", "3"]);
    assert!(ok, "{v}");
    let insns = v["insns"].as_array().expect("disasm envelope insns");
    assert_eq!(insns.len(), 3);
    assert_eq!(insns[0]["mnem"], "nop");
    assert_eq!(insns[2]["mnem"], "ret");
    assert!(
        v["error_at"].is_null(),
        "clean range error_at:null, got {v}"
    );

    let (ok, v) = run(&["--db", d, "cfg", &bin, "0x0"]);
    assert!(ok, "{v}");
    assert!(v.get("nodes").is_some() && v.get("edges").is_some());

    let (ok, v) = run(&["--db", d, "ir", &bin, "0x0", "3"]);
    assert!(ok, "{v}");
    assert_eq!(v["insns"], 3);
    assert_eq!(v["ir"].as_array().expect("ir array").len(), 3);
    assert_eq!(v["ir"][2]["op"], "Return");
    assert!(v["error_at"].is_null(), "clean ir error_at:null, got {v}");

    let (ok, v) = run(&["--db", d, "symbols", &bin]);
    assert!(ok, "{v}");
    assert_eq!(v["imports"].as_array().expect("imports").len(), 0);
    assert_eq!(v["exports"].as_array().expect("exports").len(), 0);
    cleanup(&dir);
}

// D2/A6 golden: garbage range returns the valid prefix plus error_at;
// a clean prefix of the same file reports error_at:null.
#[test]
fn disasm_partial_returns_prefix_and_error_at() {
    let dir = tmpdir("disasm-partial");
    let bin = write_fixture(&dir, common::builders::GARBAGE_NAME);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "garbage").display().to_string();
    let d = db.as_str();
    let bytes = std::fs::read(&bin).expect("garbage fixture");

    // Full range: 2 valid insns (push rbp; mov rbp,rsp) then 0xD6 stop.
    let (ok, v) = run(&["--db", d, "disasm", &bin_s, "0", &bytes.len().to_string()]);
    assert!(ok, "{v}");
    let insns = v["insns"].as_array().expect("envelope insns");
    assert_eq!(insns.len(), 2);
    assert_eq!(insns[0]["mnem"], "push");
    let err = v["error_at"].as_object().expect("error_at set");
    assert_eq!(err["addr"], 4);
    assert!(err["message"].as_str().expect("message").contains("0x4"));

    // Clean prefix before the stop byte: same insns, error_at null.
    let stop = bytes.iter().position(|b| *b == 0xD6).expect("stop byte");
    let (ok, v) = run(&["--db", d, "disasm", &bin_s, "0", &stop.to_string()]);
    assert!(ok, "{v}");
    assert_eq!(v["insns"].as_array().expect("insns").len(), 2);
    assert!(
        v["error_at"].is_null(),
        "clean prefix error_at:null, got {v}"
    );

    // IR lifts the same prefix and carries the same error_at.
    let (ok, v) = run(&["--db", d, "ir", &bin_s, "0", &bytes.len().to_string()]);
    assert!(ok, "{v}");
    assert_eq!(v["insns"], 2);
    assert_eq!(v["error_at"]["addr"], 4);
    cleanup(&dir);
}

// O3/A11: `stats` prints db_size plus the project_info counts; db_size
// is 0 before the first save and matches the sidecar file after `load`.
#[test]
fn stats_prints_db_size_and_counts() {
    let dir = tmpdir("stats");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "stats").display().to_string();
    let d = db.as_str();

    // Before any save there is no sidecar: db_size 0, counts still report.
    let (ok, v) = run(&["--db", d, "stats", &bin_s]);
    assert!(ok, "{v}");
    assert_eq!(v["db_size"], 0);
    assert_eq!(v["db_path"].as_str(), Some(db.as_str()));
    assert_eq!(v["functions"], 1);
    assert!(v["content_hash"].is_number());

    // `load` caches the snapshot; stats then matches the file on disk.
    let (ok, info) = run(&["--db", d, "load", &bin_s]);
    assert!(ok, "{info}");
    let file_size = std::fs::metadata(&db).expect("sidecar").len();
    assert!(file_size > 0);
    let (ok, v) = run(&["--db", d, "stats", &bin_s]);
    assert!(ok, "{v}");
    assert_eq!(v["db_size"], file_size);
    for k in ["functions", "blocks", "insns", "xrefs", "strings"] {
        assert_eq!(v[k], info[k], "stats {k} matches load");
    }
    cleanup(&dir);
}

#[test]
fn failures_are_json_envelopes() {
    let (bin, db, _dir, dir) = raw_case("errors");
    let d = db.as_str();
    // Missing binary.
    let (ok, v) = run(&["--db", d, "load", "no/such/file"]);
    assert!(!ok);
    assert!(v.get("error").is_some(), "{v}");
    // Unknown function.
    let (ok, v) = run(&["--db", d, "func", &bin, "0xdead"]);
    assert!(!ok);
    assert!(v.get("error").is_some(), "{v}");
    // Unknown function through the paged views.
    let (ok, v) = run(&["--db", d, "blocks", &bin, "0xdead"]);
    assert!(!ok);
    assert!(v.get("error").is_some(), "{v}");
    let (ok, v) = run(&["--db", d, "block-insns", &bin, "0xdead", "0x0"]);
    assert!(!ok);
    assert!(v.get("error").is_some(), "{v}");
    // Block interior (not a block start) of a known function.
    let (ok, v) = run(&["--db", d, "block-insns", &bin, "0x0", "0x1"]);
    assert!(!ok);
    assert!(v.get("error").is_some(), "{v}");
    // Malformed address.
    let (ok, v) = run(&["--db", d, "func", &bin, "zz"]);
    assert!(!ok);
    assert!(v.get("error").is_some(), "{v}");
    // Range past the mapping.
    let (ok, v) = run(&["--db", d, "disasm", &bin, "0x0", "99"]);
    assert!(!ok);
    assert!(v.get("error").is_some(), "{v}");
    // Bad xref kind.
    let (ok, v) = run(&["--db", d, "xrefs", &bin, "--kind", "nope"]);
    assert!(!ok);
    assert!(v.get("error").is_some(), "{v}");
    cleanup(&dir);
}

#[test]
fn annotate_round_trip_and_binary_untouched() {
    let dir = tmpdir("annotate");
    let before = std::fs::read("tests/fixtures/raw-x64.bin").expect("fixture");
    let bin = write_bin(&dir, "a.bin", &before);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "a").display().to_string();

    let (ok, v) = run(&["--db", &db, "annotate", &bin_s, "0x0", "--rename", "main"]);
    assert!(ok, "{v}");
    assert_eq!(v["name"], "main");

    let (ok, v) = run(&[
        "--db",
        &db,
        "annotate",
        &bin_s,
        "1",
        "--comment",
        "second nop",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["comment"], "second nop");

    // Rename resolves through function listings.
    let (ok, v) = run(&["--db", &db, "functions", &bin_s]);
    assert!(ok, "{v}");
    assert_eq!(v[0]["name"], "main");

    // Clearing drops the annotation.
    let (ok, _) = run(&["--db", &db, "annotate", &bin_s, "0x0", "--rename", ""]);
    assert!(ok);
    let (ok, v) = run(&["--db", &db, "annotate", &bin_s, "0x0"]);
    assert!(ok, "{v}");
    assert!(v.get("name").is_none() || v["name"].is_null());

    assert_eq!(
        std::fs::read(&bin).expect("reread"),
        before,
        "binary untouched"
    );
    cleanup(&dir);
}

#[test]
fn annotate_rename_and_comment_are_atomic() {
    let dir = tmpdir("annotate-atomic");
    let before = std::fs::read("tests/fixtures/raw-x64.bin").expect("fixture");
    let bin = write_bin(&dir, "a.bin", &before);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "a").display().to_string();

    let big = "x".repeat(9000);
    let (ok, v) = run(&[
        "--db",
        &db,
        "annotate",
        &bin_s,
        "0x0",
        "--rename",
        "foo",
        "--comment",
        big.as_str(),
    ]);
    assert!(!ok, "oversize comment must fail: {v}");
    assert!(v.get("error").is_some(), "{v}");

    let (ok, v) = run(&["--db", &db, "annotate", &bin_s, "0x0"]);
    assert!(ok, "{v}");
    assert!(
        v.get("name").is_none() || v["name"].is_null(),
        "rename must not persist after failed annotate: {v}"
    );
    assert!(v.get("comment").is_none() || v["comment"].is_null(), "{v}");
    cleanup(&dir);
}

#[test]
fn func_and_cfg_snap_to_containing_function() {
    let (bin, db, _dir, dir) = raw_case("snap");
    let d = db.as_str();
    // raw-x64.bin is one function (nop; nop; ret) at 0x0; 0x1 is mid-function.
    let (ok, v) = run(&["--db", d, "func", &bin, "0x1"]);
    assert!(ok, "{v}");
    assert_eq!(v["entry"], 0);
    assert_eq!(v["entry_hex"], "0x0");
    assert!(v.get("containing_entry").is_none(), "no snap twin: {v}");
    let (ok, v) = run(&["--db", d, "blocks", &bin, "1"]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 1);
    assert_eq!(v["items"][0]["start"], 0);
    let (ok, v) = run(&["--db", d, "block-insns", &bin, "1", "0x0"]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 3);
    let (ok, v) = run(&["--db", d, "cfg", &bin, "1"]);
    assert!(ok, "{v}");
    assert_eq!(v["entry"], 0);
    assert_eq!(v["containing_entry"], 0);
    // Past the function's end is still not-found.
    let (ok, v) = run(&["--db", d, "func", &bin, "0x3"]);
    assert!(!ok);
    assert!(v.get("error").is_some(), "{v}");
    cleanup(&dir);
}

/// Two x86-64 functions: 0x0 calls 0x10 (raw fallback maps at base 0, so the
/// relative call still lands on the second function).
fn two_func_blob() -> Vec<u8> {
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
fn functions_caller_callee_and_range_filters() {
    let dir = tmpdir("funcfilter");
    let bin = write_bin(&dir, "two.bin", &two_func_blob());
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "two").display().to_string();
    let d = db.as_str();

    let (ok, v) = run(&["--db", d, "functions", &bin_s]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("functions array").len(), 2);

    // --caller keeps functions that call the anchor: only 0x0 calls 0x10.
    let (ok, v) = run(&["--db", d, "functions", &bin_s, "--caller", "0x10"]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("array").len(), 1);
    assert_eq!(v[0]["entry"], 0);

    // --callee keeps functions called by the anchor: 0x0 calls 0x10.
    let (ok, v) = run(&["--db", d, "functions", &bin_s, "--callee", "0"]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("array").len(), 1);
    assert_eq!(v[0]["entry"], 0x10);

    // --range bounds entries, inclusive on both ends.
    let (ok, v) = run(&["--db", d, "functions", &bin_s, "--range", "0x10", "0x10"]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("array").len(), 1);
    assert_eq!(v[0]["entry"], 0x10);

    // Reversed bounds normalize instead of matching nothing.
    let (ok, v) = run(&["--db", d, "functions", &bin_s, "--range", "0x10", "0x0"]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("array").len(), 2);

    // Paging applies after filtering.
    let (ok, v) = run(&[
        "--db",
        d,
        "functions",
        &bin_s,
        "--range",
        "0",
        "16",
        "--limit",
        "1",
        "--offset",
        "1",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("array").len(), 1);
    assert_eq!(v[0]["entry"], 0x10);

    // An anchor in no function matches nothing (still success, empty page).
    let (ok, v) = run(&["--db", d, "functions", &bin_s, "--caller", "0xdead"]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("array").len(), 0);
    cleanup(&dir);
}

#[test]
fn functions_query_matches_resolved_names() {
    let (bin, db, _dir, dir) = raw_case("query-names");
    let (ok, _) = run(&["--db", &db, "annotate", &bin, "0x0", "--rename", "main"]);
    assert!(ok);

    // Case-insensitive substring over the rename.
    let (ok, v) = run(&["--db", &db, "functions", &bin, "--query", "MAI"]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("array").len(), 1);
    assert_eq!(v[0]["name"], "main");

    let (ok, v) = run(&["--db", &db, "functions", &bin, "--query", "zzz"]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("array").len(), 0);
    cleanup(&dir);

    // Export names match too: pe32-basic.exe exports `basic_entry`.
    let dir = tmpdir("query-export");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "basic").display().to_string();
    let (ok, v) = run(&["--db", &db, "functions", &bin_s, "--query", "basic"]);
    assert!(ok, "{v}");
    let rows = v.as_array().expect("array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["entry"], 0x401000);
    cleanup(&dir);
}

#[test]
fn elf_fixture_reports_format_and_symbols() {
    let dir = tmpdir("elf");
    let bin = write_bin(&dir, "t.elf", &minimal_elf());
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "t").display().to_string();

    let (ok, v) = run(&["--db", &db, "load", &bin_s]);
    assert!(ok, "{v}");
    assert_eq!(v["format"], "elf");
    assert_eq!(v["arch"], "x86_64");
    assert_eq!(v["entry"], 0x400000);

    let (ok, v) = run(&["--db", &db, "symbols", &bin_s]);
    assert!(ok, "{v}");
    assert!(v.get("imports").is_some() && v.get("exports").is_some());

    let (ok, v) = run(&["--db", &db, "func", &bin_s, "0x400000"]);
    assert!(ok, "{v}");
    assert_eq!(v["entry"], 0x400000);
    assert_eq!(v["entry_hex"], "0x400000");
    assert!(v["blocks"].is_number() && v["insns"].is_number(), "{v}");
    cleanup(&dir);
}

#[test]
fn le_load_reports_format_and_entry() {
    let dir = tmpdir("le");
    let bin = write_bin(
        &dir,
        "le.exe",
        &common::fixture_bytes(common::builders::LE_NAME),
    );
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "le").display().to_string();

    let (ok, v) = run(&["--db", &db, "load", &bin_s]);
    assert!(ok, "{v}");
    assert_eq!(v["format"], "le");
    assert_eq!(v["arch"], "x86_32");
    assert_eq!(v["entry"], 0x10000);
    cleanup(&dir);
}

// X1/A3: hex and decimal addresses filter identically, kind is
// case-insensitive, and the envelope carries the pre-paging total.
#[test]
fn xrefs_hex_equals_decimal_kind_case_insensitive_with_total() {
    let dir = tmpdir("xrefs-norm");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "x").display().to_string();
    let d = db.as_str();
    let va = common::builders::BASIC_STRING_VA;
    let hex = format!("{va:#x}");
    let dec = va.to_string();

    let (ok, h) = run(&["--db", d, "xrefs", &bin_s, "--to", &hex]);
    assert!(ok, "{h}");
    let (ok, n) = run(&["--db", d, "xrefs", &bin_s, "--to", &dec]);
    assert!(ok, "{n}");
    assert_eq!(h, n, "hex and decimal must filter identically");
    assert_eq!(h["total"], 4);
    assert_eq!(h["xrefs"].as_array().expect("xrefs array").len(), 4);

    for (a, b) in [("String", "string"), ("DATA", "data")] {
        let (ok, upper) = run(&["--db", d, "xrefs", &bin_s, "--to", &hex, "--kind", a]);
        assert!(ok, "{upper}");
        let (ok, lower) = run(&["--db", d, "xrefs", &bin_s, "--to", &hex, "--kind", b]);
        assert!(ok, "{lower}");
        assert_eq!(upper, lower, "--kind {a} must equal --kind {b}");
    }
    let (ok, s) = run(&["--db", d, "xrefs", &bin_s, "--to", &hex, "--kind", "String"]);
    assert!(ok, "{s}");
    assert_eq!(s["total"], 2);
    assert!(
        s["xrefs"]
            .as_array()
            .expect("xrefs array")
            .iter()
            .all(|x| x["kind"] == "String"),
        "{s}"
    );

    // Paging shrinks the rows but not the total.
    let (ok, p) = run(&["--db", d, "xrefs", &bin_s, "--to", &hex, "--limit", "1"]);
    assert!(ok, "{p}");
    assert_eq!(p["total"], 4);
    assert_eq!(p["xrefs"].as_array().expect("xrefs array").len(), 1);

    // Bad kind stays a JSON error envelope.
    let (ok, v) = run(&["--db", d, "xrefs", &bin_s, "--kind", "nope"]);
    assert!(!ok);
    assert!(v.get("error").is_some(), "{v}");
    cleanup(&dir);
}

/// Minimal 32-bit ARM ELF with `code` as its single R+X load segment.
fn minimal_arm_elf(code: &[u8]) -> Vec<u8> {
    fn put16(v: &mut [u8], off: usize, x: u16) {
        v[off..off + 2].copy_from_slice(&x.to_le_bytes());
    }
    fn put32(v: &mut [u8], off: usize, x: u32) {
        v[off..off + 4].copy_from_slice(&x.to_le_bytes());
    }
    let mut f = vec![0u8; 84];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 1;
    f[5] = 1;
    f[6] = 1;
    put16(&mut f, 16, 2);
    put16(&mut f, 18, 40);
    put32(&mut f, 20, 1);
    put32(&mut f, 24, 0x10000);
    put32(&mut f, 28, 52);
    put16(&mut f, 40, 52);
    put16(&mut f, 42, 32);
    put16(&mut f, 44, 1);
    let p = 52;
    put32(&mut f, p, 1);
    put32(&mut f, p + 4, 84);
    put32(&mut f, p + 8, 0x10000);
    put32(&mut f, p + 12, 0x10000);
    put32(&mut f, p + 16, code.len() as u32);
    put32(&mut f, p + 20, code.len() as u32);
    put32(&mut f, p + 24, 5);
    put32(&mut f, p + 28, 0x1000);
    f.extend_from_slice(code);
    f
}

#[test]
fn load_hostile_arm_elf_stays_json() {
    // The entry word panics inside yaxpeax-arm; load and disasm must finish
    // with valid JSON, never abort the process.
    let dir = tmpdir("arm-hostile");
    let bin = write_bin(
        &dir,
        "hostile-arm.elf",
        &minimal_arm_elf(&[0xF9, 0xF0, 0x00, 0x00]),
    );
    let db = temp_db(&dir, "hostile");
    let bin_s = bin.display().to_string();
    let db_s = db.display().to_string();
    let (ok, v) = run(&["--db", &db_s, "load", &bin_s]);
    assert!(ok, "{v}");
    assert_eq!(v["arch"], "arm32");
    assert_eq!(v["functions"], 0);
    // The hostile word ends the prefix: valid JSON with error_at, not an abort.
    let (ok, d) = run(&["--db", &db_s, "disasm", &bin_s, "0x10000", "1"]);
    assert!(ok, "{d}");
    assert!(d.get("error_at").is_some(), "{d}");
    // Valid ARM control decodes through the same path.
    let control = write_bin(
        &dir,
        "control-arm.elf",
        &minimal_arm_elf(&[0x01, 0x00, 0xA0, 0xE1, 0x1E, 0xFF, 0x2F, 0xE1]),
    );
    let control_s = control.display().to_string();
    let db2 = temp_db(&dir, "control");
    let db2_s = db2.display().to_string();
    let (ok, v) = run(&["--db", &db2_s, "load", &control_s]);
    assert!(ok, "{v}");
    assert_eq!(v["insns"], 2);
    cleanup(&dir);
}

/// Synthetic code per arch for raw CLI/MCP parity.
fn raw_arch_bytes(arch: &str) -> Vec<u8> {
    match arch {
        "x86_64" | "x86_32" => vec![0x90, 0x90, 0xC3],
        "aarch64" => vec![0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6],
        "arm32" => vec![0x01, 0x00, 0xA0, 0xE1, 0x1E, 0xFF, 0x2F, 0xE1],
        "thumb" => vec![0x00, 0xBF, 0x70, 0x47],
        // riscv `c.nop; ret` (jalr x0, 0(x1)).
        "riscv32" | "riscv64" => vec![0x01, 0x00, 0x67, 0x80, 0x00, 0x00],
        // mips `nop; jr ra`.
        "mips32" => vec![0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0xE0, 0x03],
        _ => unreachable!("test arch"),
    }
}

fn raw_arch_base(arch: &str) -> &'static str {
    match arch {
        "x86_64" => "0x1000",
        "x86_32" => "0x2000",
        "aarch64" => "0x10000",
        "arm32" => "0x11000",
        "thumb" => "0x20000",
        "riscv32" => "0x30000",
        "riscv64" => "0x31000",
        "mips32" => "0x32000",
        _ => unreachable!("test arch"),
    }
}

#[test]
fn raw_flags_report_mapping_across_arches() {
    for arch in [
        "x86_64", "x86_32", "aarch64", "arm32", "thumb", "riscv32", "riscv64", "mips32",
    ] {
        let dir = tmpdir("cli-raw-parity");
        let base = raw_arch_base(arch);
        let bin = write_bin(&dir, "r.bin", &raw_arch_bytes(arch));
        let bin_s = bin.display().to_string();
        let db = temp_db(&dir, "r").display().to_string();
        let d = db.as_str();

        let (ok, v) = run(&[
            "--db", d, "--raw", "--arch", arch, "--base", base, "load", &bin_s,
        ]);
        assert!(ok, "{arch}: {v}");
        assert_eq!(v["arch"], arch, "{arch}");
        assert_eq!(v["format"], "raw", "{arch}");
        assert_eq!(v["mode"], "raw", "{arch}");
        assert_eq!(
            v["base_hex"],
            format!(
                "0x{:x}",
                u64::from_str_radix(base.trim_start_matches("0x"), 16).expect("base")
            ),
            "{arch}"
        );
        assert_eq!(v["functions"], 1, "{arch}");

        // Reads under the same mapping agree and disassemble at the base.
        let (ok, f) = run(&[
            "--db",
            d,
            "--raw",
            "--arch",
            arch,
            "--base",
            base,
            "functions",
            &bin_s,
        ]);
        assert!(ok, "{arch}: {f}");
        assert_eq!(f.as_array().expect("array").len(), 1, "{arch}");
        let (ok, s) = run(&[
            "--db", d, "--raw", "--arch", arch, "--base", base, "stats", &bin_s,
        ]);
        assert!(ok, "{arch}: {s}");
        assert_eq!(s["mode"], "raw", "{arch}");
        assert_eq!(s["arch"], arch, "{arch}");
        cleanup(&dir);
    }
}

#[test]
fn raw_flag_errors_are_json() {
    let dir = tmpdir("cli-raw-errors");
    let bin = write_bin(&dir, "r.bin", &[0x90, 0x90, 0xC3]);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "r").display().to_string();
    let d = db.as_str();

    // Missing --arch in raw mode.
    let (ok, v) = run(&["--db", d, "--raw", "--base", "0x1000", "load", &bin_s]);
    assert!(!ok && v.get("error").is_some(), "missing arch: {v}");
    // Unknown arch.
    let (ok, v) = run(&[
        "--db", d, "--raw", "--arch", "mips", "--base", "0x1000", "load", &bin_s,
    ]);
    assert!(!ok && v.get("error").is_some(), "unknown arch: {v}");
    // Raw-only options without --raw.
    let (ok, v) = run(&["--db", d, "--arch", "x86_64", "load", &bin_s]);
    assert!(
        !ok && v.get("error").is_some(),
        "raw-only without --raw: {v}"
    );
    // Misaligned entry for aarch64.
    let aarch = write_bin(&dir, "a.bin", &raw_arch_bytes("aarch64"));
    let aarch_s = aarch.display().to_string();
    let (ok, v) = run(&[
        "--db", d, "--raw", "--arch", "aarch64", "--base", "0x10000", "--entry", "0x10001", "load",
        &aarch_s,
    ]);
    assert!(!ok && v.get("error").is_some(), "misaligned entry: {v}");
    // Out-of-range entry.
    let (ok, v) = run(&[
        "--db", d, "--raw", "--arch", "x86_64", "--base", "0x1000", "--entry", "0x2000", "load",
        &bin_s,
    ]);
    assert!(!ok && v.get("error").is_some(), "out-of-range entry: {v}");
    // Base-plus-length overflow.
    let (ok, v) = run(&[
        "--db",
        d,
        "--raw",
        "--arch",
        "x86_64",
        "--base",
        "0xFFFFFFFFFFFFFFFF",
        "load",
        &bin_s,
    ]);
    assert!(!ok && v.get("error").is_some(), "overflow: {v}");
    assert!(!Path::new(d).exists(), "failed raw opens must not write");
    cleanup(&dir);
}

#[test]
fn raw_reads_do_not_write_sidecars() {
    let dir = tmpdir("cli-raw-no-save");
    let bin = write_bin(&dir, "r.bin", &[0x90, 0x90, 0xC3]);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "fresh");
    let db_s = db.display().to_string();
    let (ok, _) = run(&[
        "--db",
        &db_s,
        "--raw",
        "--arch",
        "x86_64",
        "--base",
        "0x1000",
        "functions",
        &bin_s,
    ]);
    assert!(ok);
    assert!(!db.exists(), "raw reads never create the sidecar");
    cleanup(&dir);
}

#[test]
fn auto_mode_without_flags_is_unchanged() {
    // Raw blob without flags keeps the auto fallback and reports auto/null.
    let (bin, db, _dir, dir) = raw_case("auto-mode");
    let (ok, v) = run(&["--db", &db, "load", &bin]);
    assert!(ok, "{v}");
    assert_eq!(v["mode"], "auto");
    assert!(v["base"].is_null() && v["base_hex"].is_null());
    cleanup(&dir);
}

/// `call +0xB; call rax; invalid; nop*8; jmp rax`: two functions, one
/// site of each diagnostic kind (raw fallback maps at base 0, so the
/// relative call lands on the second function). Mirrors
/// `tests/diagnostics.rs`.
fn three_site_blob() -> Vec<u8> {
    let mut b = vec![0xE8, 0x0B, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x06];
    b.extend([0x90; 8]);
    b.extend([0xFF, 0xE0]);
    b
}

// Paged provenance over the CLI: envelope shape, kind/func filters with
// filter-then-page totals, JSON error envelopes, and read-only queries.
#[test]
fn diagnostics_envelope_filters_and_errors() {
    let dir = tmpdir("cli-diagnostics");
    let bin = write_bin(&dir, "three.bin", &three_site_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "three").display().to_string();
    let d = db.as_str();

    // Unfiltered: all three sites ordered by (kind, addr).
    let (ok, v) = run(&["--db", d, "diagnostics", &bin]);
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 3);
    let items = v["items"].as_array().expect("items array");
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["kind"], "unresolved-indirect-jump");
    assert_eq!(items[0]["addr"], 0x10);
    assert_eq!(items[0]["addr_hex"], "0x10");
    assert_eq!(items[0]["func"], 0x10);
    assert!(items[0]["detail"].as_str().is_some_and(|s| !s.is_empty()));
    // The decode failure lies in no function: null on both sides.
    assert_eq!(items[2]["kind"], "decode-failure");
    assert!(items[2]["func"].is_null() && items[2]["func_hex"].is_null());

    // Kind filter precedes pagination: exact filtered total, zero limit
    // still counts.
    let (ok, v) = run(&["--db", d, "diagnostics", &bin, "--kind", "decode-failure"]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 1);
    assert_eq!(v["items"].as_array().expect("items").len(), 1);
    let (ok, v) = run(&[
        "--db",
        d,
        "diagnostics",
        &bin,
        "--kind",
        "unresolved-indirect-call",
        "--limit",
        "0",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 1);
    assert!(v["items"].as_array().expect("items").is_empty());

    // Func filter keeps only that function's sites; interior snaps.
    let (ok, v) = run(&["--db", d, "diagnostics", &bin, "--func", "0x0"]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 1);
    assert_eq!(v["items"][0]["addr"], 0x5);
    let (ok, snap) = run(&["--db", d, "diagnostics", &bin, "--func", "0x6"]);
    assert!(ok, "{snap}");
    assert_eq!(snap, v, "interior address must snap");

    // Kind and func compose: filtering still precedes paging.
    let (ok, v) = run(&[
        "--db",
        d,
        "diagnostics",
        &bin,
        "--kind",
        "decode-failure",
        "--func",
        "0x0",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 0);
    assert!(v["items"].as_array().expect("items").is_empty());

    // Invalid kind, unparseable func, and gap func are JSON errors.
    let (ok, v) = run(&["--db", d, "diagnostics", &bin, "--kind", "nope"]);
    assert!(!ok && v.get("error").is_some(), "{v}");
    let (ok, v) = run(&["--db", d, "diagnostics", &bin, "--func", "zz"]);
    assert!(!ok && v.get("error").is_some(), "{v}");
    let (ok, v) = run(&["--db", d, "diagnostics", &bin, "--func", "0x7"]);
    assert!(!ok && v.get("error").is_some(), "{v}");

    // `func` rows carry the discovery vocabulary; `project_info` the totals.
    let (ok, v) = run(&["--db", d, "func", &bin, "0x10"]);
    assert!(ok, "{v}");
    assert_eq!(v["reasons"], serde_json::json!(["direct-call"]));
    assert!(
        !Path::new(d).exists(),
        "diagnostics/func reads never create the sidecar"
    );
    let (ok, v) = run(&["--db", d, "load", &bin]);
    assert!(ok, "{v}");
    assert_eq!(v["diagnostics"], 3);
    assert_eq!(v["diagnostics_truncated"], false);
    assert_eq!(v["diagnostics_omitted"], 0);
    assert_eq!(
        v["analysis_revision"],
        binscout::analysis::ANALYSIS_REVISION
    );

    // Only `load` caches the snapshot.
    assert!(Path::new(d).exists(), "load caches the snapshot");
    cleanup(&dir);
}

#[test]
fn diagnostics_reads_do_not_write_sidecars() {
    let dir = tmpdir("cli-diag-no-save");
    let bin = write_bin(&dir, "three.bin", &three_site_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "fresh");
    let db_s = db.display().to_string();
    let (ok, v) = run(&["--db", &db_s, "diagnostics", &bin]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 3);
    assert!(!db.exists(), "diagnostics reads never create the sidecar");
    cleanup(&dir);
}

/// `nop` x 1500, then `jmp +0` x 1200 (each targeting the next), then
/// `ret`: one function with 1201 blocks / 2701 instructions, past the
/// 1024-row page cap. Mirrors `tests/function_pages.rs`.
fn big_blob() -> Vec<u8> {
    let mut b = vec![0x90u8; 1500];
    for _ in 0..1200 {
        b.extend([0xEB, 0x00]);
    }
    b.push(0xC3);
    b
}

/// Raw stdout bytes of one CLI invocation (validates the byte-size side
/// of bounded inspection, not just the row counts).
fn run_raw(args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    // Must still be exactly one JSON value.
    let _: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), text)
}

// Bounded function inspection: compact `func` plus paged `blocks` and
// `block-insns` over a 1201-block synthetic function. `func` carries
// counts only (no instruction arrays); pages follow the protocol-1
// envelope and clip to the 1024-row cap; `cfg` stays the explicit
// full-graph export.
#[test]
fn bounded_func_and_pages_stay_capped() {
    let dir = tmpdir("func-bounded");
    let bin = write_bin(&dir, "big.bin", &big_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "big").display().to_string();
    let d = db.as_str();

    // Compact func: counts, no arrays, tiny response for a huge function.
    let (ok, text) = run_raw(&["--db", d, "func", &bin, "0x0"]);
    assert!(ok, "{text}");
    let v: Value = serde_json::from_str(text.trim_end()).expect("json");
    assert_eq!(v["blocks"], 1201);
    assert_eq!(v["insns"], 2701);
    assert_eq!(v["calls"], 0);
    assert!(
        text.len() < 1024,
        "compact func must stay small, got {} bytes",
        text.len()
    );

    // Successive block pages rebuild the full 1201-block order.
    let mut starts: Vec<u64> = Vec::new();
    let mut offset = 0usize;
    loop {
        let (ok, v) = run(&[
            "--db",
            d,
            "blocks",
            &bin,
            "0x0",
            "--offset",
            &offset.to_string(),
            "--limit",
            "100",
        ]);
        assert!(ok, "{v}");
        assert_eq!(v["protocol"], 1);
        assert_eq!(v["total"], 1201);
        assert_eq!(v["offset"], offset);
        starts.extend(
            v["items"]
                .as_array()
                .expect("items array")
                .iter()
                .map(|b| b["start"].as_u64().expect("start")),
        );
        match v["next_offset"].as_u64() {
            Some(next) => offset = next as usize,
            None => break,
        }
    }
    assert_eq!(starts.len(), 1201);
    assert!(starts.windows(2).all(|w| w[0] < w[1]), "ordered, no gaps");

    // Over-cap limits clip to 1024 rows and report the clipped limit.
    let (ok, v) = run(&["--db", d, "blocks", &bin, "0x0", "--limit", "5000"]);
    assert!(ok, "{v}");
    assert_eq!(v["limit"], 1024);
    assert_eq!(v["items"].as_array().expect("items").len(), 1024);
    assert_eq!(v["next_offset"], 1024);

    // The 1501-instruction opening block pages under the same cap.
    let first = starts[0].to_string();
    let (ok, v) = run(&[
        "--db",
        d,
        "block-insns",
        &bin,
        "0x0",
        &first,
        "--limit",
        "5000",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["limit"], 1024);
    assert_eq!(v["items"].as_array().expect("items").len(), 1024);
    assert_eq!(v["next_offset"], 1024);
    assert_eq!(v["total"], 1501);

    // Zero limit and past-end offsets are normal empty pages, not errors.
    let (ok, v) = run(&["--db", d, "blocks", &bin, "0x0", "--limit", "0"]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 1201);
    assert_eq!(v["limit"], 0);
    assert!(v["items"].as_array().expect("items").is_empty());
    assert!(v["next_offset"].is_null());
    let (ok, v) = run(&["--db", d, "blocks", &bin, "0x0", "--offset", "99999"]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 1201);
    assert!(v["items"].as_array().expect("items").is_empty());

    // `cfg` remains the explicit full-graph export for the same function.
    let (ok, v) = run(&["--db", d, "cfg", &bin, "0x0"]);
    assert!(ok, "{v}");
    assert_eq!(v["nodes"].as_array().expect("nodes").len(), 1201);

    // Raw/DB options apply to the new commands: same blob under an
    // explicit mapping agrees on counts.
    let (ok, v) = run(&[
        "--db", d, "--raw", "--arch", "x86_64", "--base", "0x1000", "--entry", "0x1000", "func",
        &bin, "0x1000",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["blocks"], 1201);
    let (ok, v) = run(&[
        "--db", d, "--raw", "--arch", "x86_64", "--base", "0x1000", "--entry", "0x1000", "blocks",
        &bin, "0x1000", "--limit", "1",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 1201);
    cleanup(&dir);
}

/// cpuid (unmapped) x2, nop, ret as a raw blob at base 0.
fn coverage_blob() -> Vec<u8> {
    vec![0x0F, 0xA2, 0x0F, 0xA2, 0x90, 0xC3]
}

#[test]
fn ir_coverage_arch_only_needs_no_binary() {
    for arch in ["x86_64", "x86_32", "aarch64", "arm32", "thumb"] {
        let (ok, v) = run(&["ir-coverage", arch]);
        assert!(ok, "{arch}: {v}");
        assert_eq!(v["arch"], arch, "{arch}");
        assert_eq!(
            v["families"].as_array().expect("families").len(),
            19,
            "{arch}"
        );
        assert!(
            v["limitations"].as_array().expect("limitations").len() >= 3,
            "{arch}"
        );
        assert_eq!(v["fallback"]["op"], "Nop", "{arch}");
        assert!(v.get("range").is_none(), "{arch}: no range without binary");
    }
    // Unknown arch stays a JSON error envelope.
    let (ok, v) = run(&["ir-coverage", "mips"]);
    assert!(!ok && v.get("error").is_some(), "{v}");
}

#[test]
fn ir_coverage_range_counts_and_errors() {
    let dir = tmpdir("ir-coverage");
    let bin = write_bin(&dir, "mixed.bin", &coverage_blob());
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "mixed").display().to_string();
    let d = db.as_str();

    let (ok, v) = run(&["--db", d, "ir-coverage", "x86_64", &bin_s, "0", "6"]);
    assert!(ok, "{v}");
    assert_eq!(v["arch"], "x86_64");
    assert_eq!(v["range"]["decoded"], 4);
    assert_eq!(v["range"]["lifted"], 2);
    assert_eq!(v["range"]["unlifted"], 2);
    assert_eq!(v["range"]["unlifted_mnemonics"][0]["mnemonic"], "cpuid");
    assert!(v["range"]["error_at"].is_null());
    assert!(
        !Path::new(d).exists(),
        "range reads never create the sidecar"
    );

    // Partial ranges and arch mismatches stay JSON errors.
    let (ok, v) = run(&["--db", d, "ir-coverage", "x86_64", &bin_s]);
    assert!(!ok && v.get("error").is_some(), "binary alone: {v}");
    let (ok, v) = run(&["--db", d, "ir-coverage", "x86_64", &bin_s, "0"]);
    assert!(!ok && v.get("error").is_some(), "binary+addr alone: {v}");
    let (ok, v) = run(&["--db", d, "ir-coverage", "aarch64", &bin_s, "0", "6"]);
    assert!(!ok && v.get("error").is_some(), "arch mismatch: {v}");
    cleanup(&dir);
}
// `search-bytes` CLI: PE + raw parity with `Project::search_bytes`,
// filters, documented errors, and no-sidecar reads.
#[test]
fn search_bytes_parity_filters_and_errors() {
    use common::builders::{BASIC_STRING_RDATA_OFF, TEXT_VA};
    let dir = tmpdir("cli-search-bytes");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db = temp_db(&dir, "sb").display().to_string();
    let d = db.as_str();

    // PE parity: literal frame setup at the `.text` base.
    let (ok, v) = run(&["--db", d, "search-bytes", &bin, "55 89 e5"]);
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 1);
    assert_eq!(v["items"][0]["addr"], TEXT_VA);
    assert_eq!(v["items"][0]["addr_hex"], "0x401000");
    assert_eq!(v["items"][0]["section"], ".text");
    assert_eq!(v["items"][0]["file_off"], 0x200);
    assert_eq!(v["items"][0]["len"], 3);

    // Wildcard parity: two `push imm32` sites.
    let (ok, v) = run(&["--db", d, "search-bytes", &bin, "68 ?? ?? ?? ??"]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 2);
    assert_eq!(v["items"][0]["addr"], TEXT_VA + 3);

    // Section filter narrows to `.rdata` for the SAVE marker.
    let (ok, v) = run(&[
        "--db",
        d,
        "search-bytes",
        &bin,
        "53 41 56 45",
        "--section",
        ".rdata",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 1);
    assert_eq!(
        v["items"][0]["file_off"],
        0x400 + BASIC_STRING_RDATA_OFF as u64
    );
    let (ok, v) = run(&[
        "--db",
        d,
        "search-bytes",
        &bin,
        "53 41 56 45",
        "--section",
        ".text",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 0);

    // Half-open range: containing range hits, short range misses, swapped
    // bounds normalize, empty ranges error.
    let (ok, v) = run(&[
        "--db",
        d,
        "search-bytes",
        &bin,
        "55 89 e5",
        "--range",
        "0x401000",
        "0x401003",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 1);
    let (ok, v) = run(&[
        "--db",
        d,
        "search-bytes",
        &bin,
        "55 89 e5",
        "--range",
        "0x401000",
        "0x401002",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 0);
    let (ok, v) = run(&[
        "--db",
        d,
        "search-bytes",
        &bin,
        "55 89 e5",
        "--range",
        "0x401003",
        "0x401000",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 1);
    let (ok, v) = run(&[
        "--db",
        d,
        "search-bytes",
        &bin,
        "55 89 e5",
        "--range",
        "0x401000",
        "0x401000",
    ]);
    assert!(!ok && v.get("error").is_some(), "empty range: {v}");

    // Paging follows the envelope: clipped limit, zero limit, past-end.
    let (ok, v) = run(&[
        "--db",
        d,
        "search-bytes",
        &bin,
        "68 ?? ?? ?? ??",
        "--offset",
        "0",
        "--limit",
        "1",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 2);
    assert_eq!(v["next_offset"], 1);
    assert_eq!(v["items"].as_array().expect("items").len(), 1);

    // Malformed patterns error as JSON with exit 1.
    for bad in ["zz", "??", "5", "48,8B", ""] {
        let (ok, v) = run(&["--db", d, "search-bytes", &bin, bad]);
        assert!(!ok && v.get("error").is_some(), "{bad:?}: {v}");
    }
    // Unknown section errors as JSON with exit 1.
    let (ok, v) = run(&["--db", d, "search-bytes", &bin, "90", "--section", "nope"]);
    assert!(!ok && v.get("error").is_some(), "unknown section: {v}");
    // A half-given `--range` never reaches validation: clap exits 2.
    let out = Command::new(binscout_bin())
        .args(["--db", d, "search-bytes", &bin, "90", "--range", "0x401000"])
        .output()
        .expect("spawn binscout");
    assert_eq!(out.status.code(), Some(2), "partial --range exits 2");
    let (ok, v) = run(&[
        "--db",
        d,
        "search-bytes",
        &bin,
        "90",
        "--range",
        "zz",
        "0x401010",
    ]);
    assert!(!ok && v.get("error").is_some(), "bad range addr: {v}");

    // Repeated queries never create a sidecar.
    assert!(!Path::new(d).exists(), "searches never create the sidecar");

    // Raw parity under an explicit mapping: overlapping matches included.
    let raw = write_bin(&dir, "r.bin", &[0x90, 0x90, 0x90, 0xC3, 0x90, 0x90]);
    let raw_s = raw.display().to_string();
    let (ok, v) = run(&[
        "--db",
        d,
        "--raw",
        "--arch",
        "x86_64",
        "--base",
        "0x1000",
        "search-bytes",
        &raw_s,
        "90 90",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 3);
    assert_eq!(v["items"][0]["addr"], 0x1000);
    assert_eq!(v["items"][0]["file_off"], 0);
    assert!(v["items"][0]["section"].is_null(), "{v}");
    assert!(
        !Path::new(d).exists(),
        "raw searches never create the sidecar"
    );

    // Non-numeric paging never reaches validation: clap exits 2 on stderr.
    let out = Command::new(binscout_bin())
        .args(["--db", d, "search-bytes", &bin, "90", "--offset", "nope"])
        .output()
        .expect("spawn binscout");
    assert_eq!(out.status.code(), Some(2), "clap misuse exits 2");
    cleanup(&dir);
}

#[test]
fn annotations_export_import_round_trip_across_dbs() {
    use common::builders::{BASIC_ENTRY_VA, BASIC_STRING_VA};
    let dir = tmpdir("cli-annotations-roundtrip");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let bin_s = bin.display().to_string();
    let db_a = temp_db(&dir, "a").display().to_string();
    let db_b = temp_db(&dir, "b").display().to_string();
    let entry_hex = format!("{BASIC_ENTRY_VA:#x}");
    let string_hex = format!("{BASIC_STRING_VA:#x}");

    // Seed two annotations through the interface.
    let (ok, v) = run(&[
        "--db",
        &db_a,
        "annotate",
        &bin_s,
        &entry_hex,
        "--rename",
        "ported_entry",
    ]);
    assert!(ok, "{v}");
    let (ok, v) = run(&[
        "--db",
        &db_a,
        "annotate",
        &bin_s,
        &string_hex,
        "--comment",
        "ported note",
    ]);
    assert!(ok, "{v}");

    // Export prints one JSON document: revision, identity, sorted rows.
    let (ok, doc) = run(&["--db", &db_a, "annotations-export", &bin_s]);
    assert!(ok, "{doc}");
    assert_eq!(doc["revision"], 1);
    assert_eq!(doc["sha256"].as_str().expect("sha256").len(), 64);
    let rows = doc["annotations"].as_array().expect("rows array");
    assert_eq!(rows.len(), 2);
    assert!(
        rows[0]["addr"].as_u64() < rows[1]["addr"].as_u64(),
        "rows sorted: {doc}"
    );
    assert!(
        !doc.to_string().contains(&dir.display().to_string()),
        "no host paths in document"
    );

    // Export alone never creates a sidecar.
    let fresh = temp_db(&dir, "fresh").display().to_string();
    let (ok, empty) = run(&["--db", &fresh, "annotations-export", &bin_s]);
    assert!(ok, "{empty}");
    assert_eq!(empty["annotations"].as_array().expect("rows").len(), 0);
    assert!(
        !Path::new(&fresh).exists(),
        "export never creates a sidecar"
    );

    // Round-trip across DBs: the test saves stdout itself (the shell
    // redirection equivalent); the server takes no output path.
    let input = dir.join("doc.json");
    std::fs::write(&input, doc.to_string()).expect("write input doc");
    let input_s = input.display().to_string();
    let (ok, summary) = run(&[
        "--db",
        &db_b,
        "annotations-import",
        &bin_s,
        "--input",
        &input_s,
    ]);
    assert!(ok, "{summary}");
    assert_eq!(summary["rows"], 2);
    assert_eq!(summary["changed"], 2);

    // The annotations resolve through the interface on the new DB.
    let (ok, v) = run(&["--db", &db_b, "functions", &bin_s]);
    assert!(ok, "{v}");
    assert_eq!(v[0]["name"], "ported_entry");
    let (ok, v) = run(&["--db", &db_b, "annotate", &bin_s, &string_hex]);
    assert!(ok, "{v}");
    assert_eq!(v["comment"], "ported note");

    // Idempotent re-import changes nothing.
    let (ok, summary) = run(&[
        "--db",
        &db_b,
        "annotations-import",
        &bin_s,
        "--input",
        &input_s,
    ]);
    assert!(ok, "{summary}");
    assert_eq!(summary["changed"], 0);

    assert_eq!(
        std::fs::read(&bin).expect("reread"),
        common::fixture_bytes("pe32-basic.exe"),
        "binary untouched"
    );
    cleanup(&dir);
}

#[test]
fn annotations_import_conflicts_mismatches_and_atomicity() {
    use common::builders::BASIC_ENTRY_VA;
    let dir = tmpdir("cli-annotations-errors");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "a").display().to_string();
    let d = db.as_str();
    let entry_hex = format!("{BASIC_ENTRY_VA:#x}");

    let (ok, _) = run(&[
        "--db", d, "annotate", &bin_s, &entry_hex, "--rename", "seeded",
    ]);
    assert!(ok);
    let (ok, doc) = run(&["--db", d, "annotations-export", &bin_s]);
    assert!(ok, "{doc}");
    let seeded_rows = doc["annotations"].clone();

    // Write a tampered Value to an input path for one import attempt.
    let attempt = |tag: &str, v: &serde_json::Value| -> (bool, serde_json::Value) {
        let path = dir.join(format!("{tag}.json"));
        std::fs::write(&path, v.to_string()).expect("write input doc");
        run(&[
            "--db",
            d,
            "annotations-import",
            &bin_s,
            "--input",
            &path.display().to_string(),
        ])
    };
    // Current annotations through the interface (atomicity oracle).
    let current_rows = || {
        let (ok, v) = run(&["--db", d, "annotations-export", &bin_s]);
        assert!(ok, "{v}");
        v["annotations"].clone()
    };

    // Differing rename under default: conflict, nothing changes.
    let mut conflict = doc.clone();
    for row in conflict["annotations"].as_array_mut().expect("rows") {
        if row["addr"].as_u64() == Some(BASIC_ENTRY_VA) {
            row["rename"] = "other_name".into();
        }
    }
    let (ok, v) = attempt("conflict", &conflict);
    assert!(!ok && v.get("error").is_some(), "conflict: {v}");
    assert_eq!(current_rows(), seeded_rows, "conflict writes nothing");

    // Same document with --overwrite: supplied rename wins.
    let path = dir.join("conflict.json");
    let (ok, v) = run(&[
        "--db",
        d,
        "annotations-import",
        &bin_s,
        "--input",
        &path.display().to_string(),
        "--overwrite",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["changed"], 1);
    let (ok, v) = run(&["--db", d, "annotate", &bin_s, &entry_hex]);
    assert!(ok, "{v}");
    assert_eq!(v["name"], "other_name");

    // Invalid final row (unknown rename target): no partial write.
    let (ok, doc) = run(&["--db", d, "annotations-export", &bin_s]);
    assert!(ok, "{doc}");
    let mut ghost = doc.clone();
    ghost["annotations"]
        .as_array_mut()
        .expect("rows")
        .push(serde_json::json!({"addr": 0xdead_beefu64, "rename": "ghost"}));
    let (ok, v) = attempt("ghost", &ghost);
    assert!(!ok && v.get("error").is_some(), "unknown rename: {v}");
    let (ok, v) = run(&["--db", d, "annotations-export", &bin_s]);
    assert!(ok, "{v}");
    assert_eq!(
        v["annotations"], doc["annotations"],
        "final-row failure writes nothing"
    );

    // Identity mismatch: tampered sha256.
    let mut bad_sha = doc.clone();
    bad_sha["sha256"] = "00".repeat(32).into();
    let (ok, v) = attempt("bad-sha", &bad_sha);
    assert!(!ok && v.get("error").is_some(), "identity mismatch: {v}");

    // Mapping mismatch: the auto-exported document under an explicit raw mapping.
    let raw_input = dir.join("doc.json");
    std::fs::write(&raw_input, doc.to_string()).expect("write input doc");
    let raw_s = raw_input.display().to_string();
    let (ok, v) = run(&[
        "--db",
        d,
        "--raw",
        "--arch",
        "x86_64",
        "--base",
        "0x0",
        "annotations-import",
        &bin_s,
        "--input",
        &raw_s,
    ]);
    assert!(!ok && v.get("error").is_some(), "mapping mismatch: {v}");
    assert!(
        v["error"]
            .as_str()
            .is_some_and(|m| m.contains("mapping mismatch")),
        "mapping mismatch message: {v}"
    );

    // Garbled, missing, directory, and oversized inputs fail as JSON envelopes.
    std::fs::write(dir.join("garbage.json"), "{not json").expect("write");
    let (ok, v) = run(&[
        "--db",
        d,
        "annotations-import",
        &bin_s,
        "--input",
        &dir.join("garbage.json").display().to_string(),
    ]);
    assert!(!ok && v.get("error").is_some(), "garbled: {v}");
    let (ok, v) = run(&[
        "--db",
        d,
        "annotations-import",
        &bin_s,
        "--input",
        &dir.join("no-such.json").display().to_string(),
    ]);
    assert!(!ok && v.get("error").is_some(), "missing input: {v}");
    let (ok, v) = run(&[
        "--db",
        d,
        "annotations-import",
        &bin_s,
        "--input",
        &dir.display().to_string(),
    ]);
    assert!(!ok && v.get("error").is_some(), "directory input: {v}");
    let big = vec![b'x'; binscout::annotations::MAX_TRANSFER_BYTES + 1];
    std::fs::write(dir.join("big.json"), &big).expect("write oversized");
    let (ok, v) = run(&[
        "--db",
        d,
        "annotations-import",
        &bin_s,
        "--input",
        &dir.join("big.json").display().to_string(),
    ]);
    assert!(!ok && v.get("error").is_some(), "oversized: {v}");
    assert!(
        v["error"].as_str().is_some_and(|m| m.contains("cap")),
        "oversized message names the cap: {v}"
    );

    // A missing --input never reaches validation: clap exits 2 on stderr.
    let out = Command::new(binscout_bin())
        .args(["--db", d, "annotations-import", &bin_s])
        .output()
        .expect("spawn binscout");
    assert_eq!(out.status.code(), Some(2), "missing --input exits 2");

    assert_eq!(
        std::fs::read(&bin).expect("reread"),
        common::fixture_bytes("pe32-basic.exe"),
        "binary untouched"
    );
    cleanup(&dir);
}

// rsdbg-zvm.17: `--db` resolving to the analyzed binary must fail before
// any write, leaving the input byte-identical. The victim holds a valid
// sidecar's bytes so the pre-fix path (raw fallback + `save` rewrite)
// would actually have overwritten it.
#[test]
fn db_same_as_binary_is_rejected_and_binary_untouched() {
    let dir = tmpdir("db-is-binary");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "seed").display().to_string();
    let (ok, _) = run(&["--db", &db, "load", &bin_s]);
    assert!(ok, "seed load must succeed");
    // Victim file carrying a valid redb's bytes: the exact trigger shape.
    let victim = dir.join("victim.redb");
    std::fs::copy(&db, &victim).expect("seed victim");
    let victim_s = victim.display().to_string();
    let before = std::fs::read(&victim).expect("read victim");

    let out = Command::new(binscout_bin())
        .args(["--db", &victim_s, "load", &victim_s])
        .output()
        .expect("spawn binscout");
    assert_eq!(out.status.code(), Some(1), "runtime failure exits 1");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let v: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    assert!(
        v["error"]
            .as_str()
            .is_some_and(|m| m.contains("--db must not be the analyzed binary")),
        "guard message: {v}"
    );
    assert_eq!(
        std::fs::read(&victim).expect("reread"),
        before,
        "binary byte-identical"
    );

    // Read-only commands reject it too: the guard lives in open, not save.
    let (ok, v) = run(&["--db", &victim_s, "functions", &victim_s]);
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert_eq!(
        std::fs::read(&victim).expect("reread"),
        before,
        "binary byte-identical"
    );
    cleanup(&dir);
}

// rsdbg-zvm.17: symlink and hard-link aliases of the binary reach the
// same guard.
#[cfg(unix)]
#[test]
fn db_alias_of_binary_is_rejected_and_binary_untouched() {
    let dir = tmpdir("db-alias-binary");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let before = std::fs::read(&bin).expect("read fixture");
    let bin_s = bin.display().to_string();
    let link = dir.join("link-to-bin");
    std::os::unix::fs::symlink(&bin, &link).expect("symlink");
    let link_s = link.display().to_string();
    let hard = dir.join("hard-to-bin");
    std::fs::hard_link(&bin, &hard).expect("hard link");
    let hard_s = hard.display().to_string();

    for alias in [&link_s, &hard_s] {
        let out = Command::new(binscout_bin())
            .args(["--db", alias, "load", &bin_s])
            .output()
            .expect("spawn binscout");
        assert_eq!(
            out.status.code(),
            Some(1),
            "{alias}: runtime failure exits 1"
        );
        let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
        let v: Value = serde_json::from_str(text.trim_end())
            .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
        assert!(
            v["error"]
                .as_str()
                .is_some_and(|m| m.contains("--db must not be the analyzed binary")),
            "{alias}: guard message: {v}"
        );
    }
    assert_eq!(
        std::fs::read(&bin).expect("reread"),
        before,
        "binary byte-identical"
    );
    cleanup(&dir);
}

// rsdbg-zvm.11 (unix only): a closed stdout pipe must not panic (exit
// 101) via `println!`. Spawn with piped stdout, drop the read end before
// the child writes, then assert a quiet exit and no panic on stderr.
// Success keeps exit 0, the error envelope keeps exit 1.
#[cfg(unix)]
#[test]
fn closed_stdout_pipe_exits_quietly_without_panic() {
    use std::process::Stdio;
    let dir = tmpdir("epipe");
    let bin = write_bin(&dir, "r.bin", &[0x90, 0x90, 0xC3]);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "e").display().to_string();
    let raw = [
        "--db",
        db.as_str(),
        "--raw",
        "--arch",
        "x86_64",
        "--base",
        "0x1000",
    ];

    // Success path: `functions` analysis succeeds, stdout is gone.
    let mut success_args: Vec<&str> = raw.to_vec();
    success_args.extend(["functions", bin_s.as_str()]);
    let mut child = Command::new(binscout_bin())
        .args(&success_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn binscout");
    drop(child.stdout.take());
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(0), "closed-pipe success exits 0");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "no panic on stderr: {stderr}");

    // Error path: bad address fails, error envelope goes nowhere.
    let mut error_args: Vec<&str> = raw.to_vec();
    error_args.extend(["func", bin_s.as_str(), "zz"]);
    let mut child = Command::new(binscout_bin())
        .args(&error_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn binscout");
    drop(child.stdout.take());
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(1), "closed-pipe failure exits 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "no panic on stderr: {stderr}");
    cleanup(&dir);
}

/// Loader-only opens skip instruction re-decode on a cache hit while
/// producing byte-identical JSON (rsdbg-5tk.3).
///
/// Warms the sidecar through a full open (plus one rename/comment so the
/// annotation export is non-trivial), then compares every loader-only
/// command's output between a full [`binscout::Project`] open and the
/// [`binscout::LoaderOpened::Cached`] view.
#[test]
fn loader_only_open_matches_full_open() {
    let dir = tmpdir("loader-only");
    // 64 x86-64 prologue bodies with zero padding, two strings, and a
    // distinctive byte pattern for search-bytes.
    let mut blob = Vec::new();
    for _ in 0..64 {
        blob.extend_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3]);
        blob.extend_from_slice(&[0u8; 250]);
    }
    let string_base = blob.len() as u64;
    blob.extend_from_slice(b"loader-only-golden\x00second-string-here\x00");
    blob.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let bin = write_bin(&dir, "loader.bin", &blob);
    let db = temp_db(&dir, "loader");

    // Warm the sidecar through a full open; the rename/comment also
    // exercises the annotation export with live rows.
    {
        let mut full = binscout::Project::open_with_db(&bin, &db).expect("fixture must open");
        assert_eq!(
            full.project_info().functions,
            64,
            "prologue scan finds every body"
        );
        full.rename_function(0x0, "entry_fn")
            .expect("rename base function");
        full.set_comment(0x0, "loader probe")
            .expect("comment base function");
        full.save().expect("warm the sidecar");
    }

    let full = binscout::Project::open_with_db(&bin, &db).expect("reopen must hit");
    assert!(full.snapshot_fresh(), "second open replays the snapshot");
    let loader = match binscout::open_mapped_loader_only(
        &bin,
        Some(&db),
        None,
        None,
        &binscout::DebugOptions::default(),
    )
    .expect("loader-only open")
    {
        binscout::LoaderOpened::Cached(p) => p,
        binscout::LoaderOpened::Fresh(_) => panic!("warmed sidecar must hit"),
    };
    assert!(loader.snapshot_fresh(), "loader hit is fresh");

    assert_eq!(loader.sections_json(), full.sections_json(), "sections");
    assert_eq!(loader.symbols_json(), full.symbols_json(), "symbols");
    assert_eq!(
        serde_json::to_value(loader.stats_json().expect("loader stats")).expect("stats serializes"),
        serde_json::to_value(full.stats_json().expect("full stats")).expect("stats serializes"),
        "stats"
    );
    assert_eq!(
        serde_json::to_value(loader.project_info()).expect("loader info serializes"),
        serde_json::to_value(full.project_info()).expect("full info serializes"),
        "project_info"
    );
    assert_eq!(
        loader.headers_json().expect("loader headers"),
        full.headers_json().expect("full headers"),
        "headers"
    );
    assert_eq!(
        loader.export_annotations().expect("loader export"),
        full.export_annotations().expect("full export"),
        "annotations-export"
    );

    let as_u8 = binscout::BytesAs::U8;
    let as_cstr = binscout::BytesAs::CStr;
    let le = binscout::BytesEndian::Le;
    for (addr, len, as_view) in [(0u64, 16usize, as_u8), (string_base, 32usize, as_cstr)] {
        assert_eq!(
            serde_json::to_value(
                loader
                    .bytes_view(addr, len, as_view, le)
                    .expect("loader bytes")
            )
            .expect("bytes serializes"),
            serde_json::to_value(full.bytes_view(addr, len, as_view, le).expect("full bytes"))
                .expect("bytes serializes"),
            "bytes at {addr:#x}"
        );
    }
    assert_eq!(
        loader
            .bytes_view(u64::MAX, 16, as_u8, le)
            .unwrap_err()
            .to_string(),
        full.bytes_view(u64::MAX, 16, as_u8, le)
            .unwrap_err()
            .to_string(),
        "bytes error envelope"
    );

    for (pattern, section, range) in [
        ("de ad be ef", None, None),
        ("de ad ?? ef", None, Some((0u64, blob.len() as u64))),
    ] {
        assert_eq!(
            serde_json::to_value(
                loader
                    .search_bytes(pattern, section, range, 0, 50)
                    .expect("loader search")
            )
            .expect("search serializes"),
            serde_json::to_value(
                full.search_bytes(pattern, section, range, 0, 50)
                    .expect("full search")
            )
            .expect("search serializes"),
            "search-bytes {pattern:?}"
        );
    }
    assert_eq!(
        loader
            .search_bytes("zz", None, None, 0, 50)
            .unwrap_err()
            .to_string(),
        full.search_bytes("zz", None, None, 0, 50)
            .unwrap_err()
            .to_string(),
        "search-bytes error envelope"
    );

    let plain = binscout::analysis::StringsFilter::default();
    let patterned = binscout::analysis::StringsFilter {
        pattern: Some("loader".to_string()),
        ..binscout::analysis::StringsFilter::default()
    };
    for filter in [&plain, &patterned] {
        assert_eq!(
            loader.query_strings(filter).expect("loader strings"),
            full.query_strings(filter).expect("full strings"),
            "strings"
        );
        assert_eq!(
            serde_json::to_value(
                loader
                    .query_strings_envelope(filter)
                    .expect("loader envelope")
            )
            .expect("envelope serializes"),
            serde_json::to_value(full.query_strings_envelope(filter).expect("full envelope"))
                .expect("envelope serializes"),
            "strings envelope"
        );
        let decode =
            binscout::loader::strings::parse_decode_spec("xor:0x42").expect("decode spec parses");
        assert_eq!(
            loader
                .query_strings_decoded(filter, decode.clone())
                .expect("loader decoded"),
            full.query_strings_decoded(filter, decode.clone())
                .expect("full decoded"),
            "strings --decode"
        );
        assert_eq!(
            serde_json::to_value(
                loader
                    .query_strings_decoded_envelope(filter, decode.clone())
                    .expect("loader decoded envelope")
            )
            .expect("envelope serializes"),
            serde_json::to_value(
                full.query_strings_decoded_envelope(filter, decode)
                    .expect("full decoded envelope")
            )
            .expect("envelope serializes"),
            "strings --decode envelope"
        );
    }
    cleanup(&dir);
}
