//! FLIRT-like library hints: corpus matches reported as read-only hints,
//! never applied as renames or comments.

mod common;

use std::process::Command;

use serde_json::Value;

use binscout::analysis::analyze_raw;
use binscout::disasm::Arch;
use binscout::flirt::{SIGNATURES, hints_for_analysis};
use binscout::loader::RawOptions;

use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

const BASE: u64 = 0x1000;

/// Blob: F@+0x0 (entry, frame, calls G and H) + G@+0x20 (framed
/// zero-return leaf) + H@+0x40 (`mov eax,0x1234; ret`, matches nothing).
fn crt_blob() -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    // F: push rbp; mov rbp,rsp; call G; call H; pop rbp; ret.
    b.extend([0x55, 0x48, 0x89, 0xE5]);
    let rel_g = 0x20i32 - 0x09;
    b.extend([0xE8]);
    b.extend(rel_g.to_le_bytes());
    let rel_h = 0x40i32 - 0x0E;
    b.extend([0xE8]);
    b.extend(rel_h.to_le_bytes());
    b.extend([0x5D, 0xC3]);
    b.extend(vec![0x90; 0x20 - b.len()]);
    // G: framed zero-return leaf (corpus `frame_ret0`).
    b.extend([0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3]);
    b.extend(vec![0x90; 0x40 - b.len()]);
    // H: mov eax,0x1234; ret (no corpus signature).
    b.extend([0xB8, 0x34, 0x12, 0x00, 0x00, 0xC3]);
    b
}

fn entries() -> (u64, u64, u64) {
    (BASE, BASE + 0x20, BASE + 0x40)
}

#[test]
fn crt_idioms_flagged_as_hints() {
    let a = analyze_raw(&crt_blob(), BASE, Arch::X86_64, Some(BASE)).expect("crt blob analyzes");
    let (f, g, h) = entries();
    assert_eq!(a.summary().functions, 3);
    let hints = hints_for_analysis(&a);
    let sigs = |entry: u64| -> Vec<&str> {
        hints
            .iter()
            .filter(|x| x.entry == entry)
            .map(|x| x.signature.as_str())
            .collect()
    };
    // Specific leaf first, generic prologue alongside it.
    assert_eq!(sigs(g), ["frame_ret0", "frame_rbp"]);
    assert_eq!(sigs(f), ["frame_rbp"]);
    assert!(sigs(h).is_empty(), "unlisted shape matches nothing");
    for hint in &hints {
        assert!(!hint.suggested_name.is_empty());
        assert!(!hint.reason.is_empty());
    }
    assert!(
        SIGNATURES.iter().any(|s| s.id == "frame_ret0"),
        "corpus documents the flagged idiom"
    );
}

#[test]
fn hints_never_write_annotations() {
    let dir = tmpdir("flirt-readonly");
    let bin = write_bin(&dir, "crt.bin", &crt_blob());
    let db = temp_db(&dir, "crt");
    let p = binscout::Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: BASE,
            arch: Arch::X86_64,
            entry: Some(BASE),
        },
    )
    .expect("raw open");
    let (_, g, h) = entries();
    let page = p.query_flirt_hints(None, 0, 50).expect("hints page");
    assert_eq!(page.total, 3, "F:1 + G:2 + H:0");
    assert_eq!(page.protocol, 1);
    let single = p.query_flirt_hints(Some(g), 0, 50).expect("single hints");
    assert_eq!(single.total, 2);
    let none = p.query_flirt_hints(Some(h), 0, 50).expect("no-match hints");
    assert_eq!(none.total, 0);
    assert!(p.query_flirt_hints(Some(0xdead), 0, 50).is_err());
    assert!(p.annotation(g).is_none(), "hints never rename");
    assert!(p.annotations().is_empty(), "hints never comment");
    assert!(!db.exists(), "querying hints never creates a sidecar");
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
fn cli_flirt_hints_json() {
    let dir = tmpdir("flirt-cli");
    let bin = write_bin(&dir, "crt.bin", &crt_blob());
    let db = temp_db(&dir, "crt");
    let (bin_s, db_s) = (bin.display().to_string(), db.display().to_string());
    let raw = [
        "--raw", "--arch", "x86_64", "--base", "0x1000", "--entry", "0x1000",
    ];

    let mut all: Vec<String> = vec![
        "--db".into(),
        db_s.clone(),
        "flirt-hints".into(),
        bin_s.clone(),
    ];
    all.extend(raw.iter().map(|s| s.to_string()));
    let args: Vec<&str> = all.iter().map(String::as_str).collect();
    let (ok, v) = run(&args);
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 3);
    let items = v["items"].as_array().expect("items");
    assert_eq!(items.len(), 3);
    let g = items
        .iter()
        .find(|i| i["signature"] == "frame_ret0")
        .expect("frame_ret0 hint");
    assert_eq!(g["entry"], BASE + 0x20);
    assert_eq!(g["entry_hex"], "0x1020");
    assert_eq!(g["suggested_name"], "frame_ret_0");
    assert!(g["reason"].as_str().is_some_and(|r| !r.is_empty()));

    let mut one: Vec<String> = vec![
        "--db".into(),
        db_s.clone(),
        "flirt-hints".into(),
        bin_s.clone(),
        "--addr".into(),
        "0x1040".into(),
    ];
    one.extend(raw.iter().map(|s| s.to_string()));
    let args: Vec<&str> = one.iter().map(String::as_str).collect();
    let (ok, v) = run(&args);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 0, "unlisted shape reports no hints");

    let mut bad: Vec<String> = vec![
        "--db".into(),
        db_s.clone(),
        "flirt-hints".into(),
        bin_s.clone(),
        "--addr".into(),
        "0xdead".into(),
    ];
    bad.extend(raw.iter().map(|s| s.to_string()));
    let args: Vec<&str> = bad.iter().map(String::as_str).collect();
    let (ok, v) = run(&args);
    assert!(!ok, "unknown function errors");
    assert!(v.get("error").is_some(), "{v}");
    assert!(!db.exists(), "flirt-hints never writes a sidecar");
    cleanup(&dir);
}
