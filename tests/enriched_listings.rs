//! Render-time listing enrichment: names, comments, and string previews.
//!
//! A synthetic x86-64 blob holds a caller with a string load plus calls to
//! a renamed and an unnamed function. `block-insns`/`disasm` rows must
//! carry the additive `target_name`/`comment`/`string` fields while every
//! pre-existing field stays byte-identical, and `pseudo` must render the
//! callee name plus the string literal in line text.

mod common;

use std::process::Command;

use serde_json::Value;

use binscout::disasm::Arch;
use binscout::loader::RawOptions;

use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

const BASE: u64 = 0x400000;
const STR_OFF: u64 = 0x20;

/// Raw string bytes placed at `BASE + STR_OFF`.
fn string_bytes() -> Vec<u8> {
    let mut v = b"Hello \"quoted\" back\\slash ".to_vec();
    v.extend(std::iter::repeat_n(b'x', 80));
    v.push(0);
    v
}

/// Expected `string` preview: escaped, clipped to 64 characters.
fn expected_preview() -> String {
    let prefix = "Hello \\\"quoted\\\" back\\\\slash ";
    let tail = "x".repeat(64 - prefix.chars().count());
    format!("{prefix}{tail}")
}

/// `call` rel32 from instruction at `from` (the `E8` byte) to `target`.
fn call_bytes(from: u64, target: u64) -> Vec<u8> {
    let rel = target.wrapping_sub(from + 5) as u32;
    let mut v = vec![0xE8];
    v.extend_from_slice(&rel.to_le_bytes());
    v
}

/// Caller at `BASE` (mov, call, call, ret), callees `B`/`C` (ret each),
/// NOP padding, then the string at `BASE + STR_OFF`.
fn blob() -> (Vec<u8>, u64, u64, u64) {
    let str_va = BASE + STR_OFF;
    let b = BASE + 16;
    let c = BASE + 17;
    let mut v = Vec::new();
    v.push(0xBF); // mov edi, STR
    v.extend_from_slice(&(str_va as u32).to_le_bytes());
    v.extend(call_bytes(BASE + 5, b));
    v.extend(call_bytes(BASE + 10, c));
    v.push(0xC3); // ret
    assert_eq!(v.len(), 16);
    v.push(0xC3); // B: ret
    v.push(0xC3); // C: ret
    while v.len() < STR_OFF as usize {
        v.push(0x90);
    }
    v.extend(string_bytes());
    (v, b, c, str_va)
}

fn open_project(dir: &std::path::Path) -> (binscout::Project, u64, u64, u64) {
    let (bytes, b, c, str_va) = blob();
    let bin = write_bin(dir, "enriched.bin", &bytes);
    let db = temp_db(dir, "enriched");
    let mut p = binscout::Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: BASE,
            arch: Arch::X86_64,
            entry: Some(BASE),
        },
    )
    .expect("blob opens");
    p.rename_function(b, "helper").expect("rename B");
    p.set_comment(BASE + 5, "calls the helper")
        .expect("comment call site");
    (p, b, c, str_va)
}

#[test]
fn block_insns_rows_carry_names_comments_and_strings() {
    let dir = tmpdir("enriched-block");
    let (p, b, _c, str_va) = open_project(&dir);
    let preview = expected_preview();
    assert_eq!(preview.chars().count(), 64);

    let page = p
        .func_block_insns_page(BASE, BASE, 0, 10)
        .expect("first block");
    assert_eq!(page.total, 2);
    let v = serde_json::to_value(&page).expect("page serializes");

    let mov = &v["items"][0];
    assert_eq!(mov["addr"], BASE);
    assert_eq!(mov["addr_hex"], "0x400000");
    assert_eq!(mov["size"], 5);
    assert_eq!(mov["mnem"], "mov");
    assert_eq!(mov["ops"], serde_json::json!(["edi", "0x400020"]));
    assert!(mov["branch_target"].is_null());
    assert_eq!(mov["mem_target"], str_va);
    assert_eq!(mov["mem_target_hex"], "0x400020");
    assert!(mov["table_base"].is_null());
    assert!(mov.get("target_name").is_none(), "{mov}");
    assert!(mov.get("comment").is_none(), "{mov}");
    assert_eq!(mov["string"], preview);

    let call = &v["items"][1];
    assert_eq!(call["addr"], BASE + 5);
    assert_eq!(call["mnem"], "call");
    assert_eq!(call["branch_target"], b);
    assert_eq!(call["target_name"], "helper");
    assert_eq!(call["comment"], "calls the helper");
    assert!(call.get("string").is_none(), "{call}");
    cleanup(&dir);
}

#[test]
fn unnamed_call_targets_fall_back_to_func_at() {
    let dir = tmpdir("enriched-fallback");
    let (p, _b, c, _s) = open_project(&dir);

    let partial = p.disasm_at(BASE, 18).expect("linear disasm");
    assert_eq!(partial.insns.len(), 6);
    let v = serde_json::to_value(&partial).expect("partial serializes");
    let call_c = &v["insns"][2];
    assert_eq!(call_c["addr"], BASE + 10);
    assert_eq!(call_c["branch_target"], c);
    assert_eq!(call_c["target_name"], format!("func@{c:#x}"));

    let detail = p.func_detail(BASE).expect("detail");
    let blocks = detail["blocks"].as_array().expect("blocks");
    let call_b = blocks
        .iter()
        .flat_map(|b| b["insns"].as_array().expect("insns").iter())
        .find(|i| i["addr"] == BASE + 5)
        .expect("call row");
    assert_eq!(call_b["target_name"], "helper");
    assert_eq!(call_b["comment"], "calls the helper");
    cleanup(&dir);
}

#[test]
fn pseudo_renders_callee_names_and_string_literals() {
    let dir = tmpdir("enriched-pseudo");
    let (p, b, _c, _s) = open_project(&dir);
    let preview = expected_preview();

    let v = p.pseudo_of(BASE).expect("pseudo");
    let lines = v["pseudo"]["lines"].as_array().expect("lines");

    let call = lines
        .iter()
        .find(|l| l["addr"] == BASE + 5)
        .expect("call line");
    assert_eq!(call["text"], "call helper(); // calls the helper");
    assert_eq!(call["target_name"], "helper");
    assert_eq!(call["comment"], "calls the helper");
    assert!(call.get("string").is_none(), "{call}");

    let mov = lines.iter().find(|l| l["addr"] == BASE).expect("mov line");
    assert_eq!(mov["string"], preview);
    assert!(
        mov["text"]
            .as_str()
            .expect("text")
            .ends_with(&format!("// \"{preview}\"")),
        "{}",
        mov["text"]
    );
    assert!(mov.get("target_name").is_none(), "{mov}");

    assert_eq!(v["pseudo"]["warning"], binscout::pseudo::PSEUDO_WARNING);
    let _ = b;
    cleanup(&dir);
}

#[test]
fn legacy_rows_without_new_keys_still_decode() {
    let insn: binscout::disasm::Insn = serde_json::from_value(serde_json::json!({
        "addr": 4096, "size": 1, "bytes": [144], "mnem": "nop", "ops": [],
        "branch_target": null, "mem_target": null,
    }))
    .expect("legacy insn");
    assert_eq!(insn.target_name, None);
    assert_eq!(insn.comment, None);
    assert_eq!(insn.string, None);

    let line: binscout::pseudo::PseudoLine = serde_json::from_value(serde_json::json!({
        "addr": 4096, "text": "return;", "warning": null,
    }))
    .expect("legacy pseudo line");
    assert_eq!(line.target_name, None);
    assert_eq!(line.comment, None);
    assert_eq!(line.string, None);
}

/// Run the CLI; assert stdout is one valid JSON value.
fn run(args: &[&str]) -> (bool, Value) {
    let out = Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout utf-8");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value)
}

#[test]
fn cli_block_insns_and_pseudo_agree_with_library() {
    let dir = tmpdir("enriched-cli");
    let (bytes, _b, _c, _s) = blob();
    let bin = write_bin(&dir, "enriched.bin", &bytes)
        .display()
        .to_string();
    let db = temp_db(&dir, "enriched").display().to_string();
    // Rename/comment through the CLI so the read paths below enrich.
    let raw = [
        "--raw", "--arch", "x86_64", "--base", "0x400000", "--entry", "0x400000",
    ];
    let with_db = |extra: &[&str]| -> Vec<String> {
        let mut args = vec!["--db".to_string(), db.clone()];
        args.extend(raw.iter().map(|s| s.to_string()));
        args.extend(extra.iter().map(|s| s.to_string()));
        args
    };
    let rename = with_db(&["annotate", &bin, "0x400010", "--rename", "helper"]);
    let (ok, _) = run(&rename.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(ok);
    let comment = with_db(&[
        "annotate",
        &bin,
        "0x400005",
        "--comment",
        "calls the helper",
    ]);
    let (ok, _) = run(&comment.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(ok);

    let args = with_db(&["block-insns", &bin, "0x400000", "0x400000"]);
    let (ok, v) = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(ok, "{v}");
    assert_eq!(v["items"][1]["target_name"], "helper");
    assert_eq!(v["items"][1]["comment"], "calls the helper");
    assert_eq!(v["items"][0]["string"], expected_preview());

    let args = with_db(&["pseudo", &bin, "0x400000"]);
    let (ok, v) = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(ok, "{v}");
    let lines = v["pseudo"]["lines"].as_array().expect("lines");
    let call = lines
        .iter()
        .find(|l| l["addr"] == 0x400005)
        .expect("call line");
    assert_eq!(call["text"], "call helper(); // calls the helper");
    cleanup(&dir);
}
