//! M6 CLI e2e: every command prints exactly one valid JSON document;
//! failures print `{"error": ...}` with a nonzero exit.

mod common;

use std::path::Path;
use std::process::Command;

use serde_json::Value;

use common::{binscout_bin, cleanup, minimal_elf, temp_db, tmpdir, write_bin};

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
    let insns = v.as_array().expect("disasm array");
    assert_eq!(insns.len(), 3);
    assert_eq!(insns[0]["mnem"], "nop");
    assert_eq!(insns[2]["mnem"], "ret");

    let (ok, v) = run(&["--db", d, "cfg", &bin, "0x0"]);
    assert!(ok, "{v}");
    assert!(v.get("nodes").is_some() && v.get("edges").is_some());

    let (ok, v) = run(&["--db", d, "ir", &bin, "0x0", "3"]);
    assert!(ok, "{v}");
    assert_eq!(v["insns"], 3);
    assert_eq!(v["ir"].as_array().expect("ir array").len(), 3);
    assert_eq!(v["ir"][2]["op"], "Return");

    let (ok, v) = run(&["--db", d, "symbols", &bin]);
    assert!(ok, "{v}");
    assert_eq!(v["imports"].as_array().expect("imports").len(), 0);
    assert_eq!(v["exports"].as_array().expect("exports").len(), 0);
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
