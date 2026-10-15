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
        vec!["cfg".into(), bin.clone(), "0x0".into()],
        vec!["xrefs".into(), bin.clone()],
        vec!["strings".into(), bin.clone()],
        vec!["symbols".into(), bin.clone()],
        vec!["sections".into(), bin.clone()],
        vec!["diagnostics".into(), bin.clone()],
        vec!["ir".into(), bin.clone(), "0x0".into(), "3".into()],
        vec!["stats".into(), bin.clone()],
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
        _ => unreachable!("test arch"),
    }
}

#[test]
fn raw_flags_report_mapping_across_arches() {
    for arch in ["x86_64", "x86_32", "aarch64", "arm32", "thumb"] {
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
    assert_eq!(v["analysis_revision"], 2);

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
