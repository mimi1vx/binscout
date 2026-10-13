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
        vec!["disasm".into(), bin.clone(), "0x0".into(), "3".into()],
        vec!["cfg".into(), bin.clone(), "0x0".into()],
        vec!["xrefs".into(), bin.clone()],
        vec!["strings".into(), bin.clone()],
        vec!["symbols".into(), bin.clone()],
        vec!["sections".into(), bin.clone()],
        vec!["ir".into(), bin.clone(), "0x0".into(), "3".into()],
        vec!["annotate".into(), bin.clone(), "0x0".into()],
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
    assert_eq!(v["entry"], 0);
    assert_eq!(v["blocks"].as_array().expect("blocks array").len(), 1);
    assert_eq!(v["blocks"][0]["insns"].as_array().expect("insns").len(), 3);

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
fn func_and_cfg_snap_to_containing_function() {
    let (bin, db, _dir, dir) = raw_case("snap");
    let d = db.as_str();
    // raw-x64.bin is one function (nop; nop; ret) at 0x0; 0x1 is mid-function.
    let (ok, v) = run(&["--db", d, "func", &bin, "0x1"]);
    assert!(ok, "{v}");
    assert_eq!(v["entry"], 0);
    assert_eq!(v["containing_entry"], 0);
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
    cleanup(&dir);
}

#[test]
fn le_load_fails_with_unsupported_envelope() {
    let dir = tmpdir("le");
    let bin = write_bin(
        &dir,
        "le.exe",
        &common::fixture_bytes(common::builders::LE_NAME),
    );
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "le").display().to_string();

    let (ok, v) = run(&["--db", &db, "load", &bin_s]);
    assert!(!ok, "LE load must fail, got {v}");
    let msg = v["error"].as_str().expect("error envelope");
    assert!(msg.contains("unsupported"), "{v}");
    assert!(msg.contains("LE"), "{v}");
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
