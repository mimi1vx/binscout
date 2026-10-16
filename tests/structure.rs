//! Approximate structural view: syntactic loops/ifs over CFG+IR plus CLI/MCP e2e.
//!
//! Covers back-edge loop detection (self-edge latch), two-successor if
//! detection (taken vs fallthrough), the always-present approximation
//! warning, determinism, snapping, and error envelopes on both surfaces.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use binscout::analysis::{STRUCTURE_WARNING, analyze_raw};
use binscout::disasm::Arch;
use binscout::loader::RawOptions;

use common::{binscout_bin, cleanup, mcp_bin, temp_db, tmpdir, write_bin};

const BASE: u64 = 0x1000;

/// Loop blob: xor eax,eax | inc eax | cmp eax,3 | jl +0x1002 | ret.
/// Blocks 0x1000/0x1002/0x1009; 0x1002 -> 0x1002 is a self-edge latch.
fn loop_blob() -> Vec<u8> {
    vec![
        0x31, 0xC0, // 0x1000: xor eax, eax
        0xFF, 0xC0, // 0x1002: inc eax
        0x83, 0xF8, 0x03, // 0x1004: cmp eax, 3
        0x7C, 0xF9, // 0x1007: jl 0x1002
        0xC3, // 0x1009: ret
    ]
}

/// Branch blob: xor eax,eax | cmp eax,1 | je +6 | mov eax,1 | ret |
/// mov eax,2 | ret. No cycle; one if with then 0x200D else 0x2007.
fn branch_blob() -> Vec<u8> {
    vec![
        0x31, 0xC0, 0x83, 0xF8, 0x01, 0x74, 0x06, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xB8, 0x02,
        0x00, 0x00, 0x00, 0xC3,
    ]
}

#[test]
fn loop_detects_self_edge_latch_and_if() {
    let a = analyze_raw(&loop_blob(), BASE, Arch::X86_64, Some(BASE)).expect("loop analyzes");
    assert_eq!(a.summary().functions, 1);
    let s = a.structure_of(BASE).expect("entry structures");
    assert!(
        s.warning.contains("approximate"),
        "warning must say approximate: {}",
        s.warning
    );
    assert_eq!(s.warning, STRUCTURE_WARNING);
    assert_eq!(s.loops.len(), 1);
    assert_eq!(s.loops[0].header, BASE + 0x02);
    assert_eq!(s.loops[0].latches, vec![BASE + 0x02]);
    // The jl site is also a two-successor CBranch: taken loops back.
    assert_eq!(s.ifs.len(), 1);
    assert_eq!(s.ifs[0].cond, BASE + 0x02);
    assert_eq!(s.ifs[0].then_target, BASE + 0x02);
    assert_eq!(s.ifs[0].else_target, BASE + 0x09);
    // Deterministic: repeated queries agree exactly.
    assert_eq!(a.structure_of(BASE), a.structure_of(BASE));
    assert!(a.structure_of(0xdead).is_none(), "unknown entry is None");
}

#[test]
fn branch_blob_yields_if_without_loop() {
    let a =
        analyze_raw(&branch_blob(), 0x2000, Arch::X86_64, Some(0x2000)).expect("branch analyzes");
    let s = a.structure_of(0x2000).expect("entry structures");
    assert!(s.loops.is_empty(), "je diamond has no cycle: {s:?}");
    assert_eq!(s.ifs.len(), 1);
    assert_eq!(s.ifs[0].cond, 0x2000);
    assert_eq!(s.ifs[0].then_target, 0x200D);
    assert_eq!(s.ifs[0].else_target, 0x2007);
    assert_eq!(s.warning, STRUCTURE_WARNING);
}

#[test]
fn straight_code_has_empty_rows_but_warning() {
    let a = analyze_raw(&[0x90, 0x90, 0xC3], 0, Arch::X86_64, Some(0)).expect("straight analyzes");
    let s = a.structure_of(0).expect("entry structures");
    assert!(s.loops.is_empty());
    assert!(s.ifs.is_empty());
    assert_eq!(s.warning, STRUCTURE_WARNING);
}

#[test]
fn empty_function_structures_to_warning_only() {
    use binscout::analysis::{Analysis, Diagnostics, Function};
    use std::collections::BTreeMap;
    let functions = BTreeMap::from([(
        0x1000u64,
        Function::from_parts(0x1000, None, BTreeMap::new(), &[], vec![], &[]),
    )]);
    let a = Analysis::from_parts(
        Arch::X86_64,
        functions,
        &[],
        Vec::new(),
        Vec::new(),
        Diagnostics::empty(),
    );
    let s = a.structure_of(0x1000).expect("empty function structures");
    assert!(s.loops.is_empty() && s.ifs.is_empty());
    assert_eq!(s.warning, STRUCTURE_WARNING);
}

#[test]
fn project_snaps_and_stays_read_only() {
    let dir = tmpdir("structure-pages");
    let bin = write_bin(&dir, "loop.bin", &loop_blob());
    let db = temp_db(&dir, "loop");
    let p = binscout::Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: BASE,
            arch: Arch::X86_64,
            entry: Some(BASE),
        },
    )
    .expect("loop opens");

    let v = p.structure_of(BASE).expect("structure");
    assert_eq!(v["entry"], BASE);
    assert_eq!(v["entry_hex"], format!("{BASE:#x}"));
    assert_eq!(v["structure"]["warning"], STRUCTURE_WARNING);
    assert_eq!(v["structure"]["loops"][0]["header"], BASE + 0x02);
    assert_eq!(
        v["structure"]["loops"][0]["header_hex"],
        format!("{:#x}", BASE + 0x02)
    );
    assert_eq!(v["structure"]["ifs"][0]["cond"], BASE + 0x02);
    assert_eq!(v["structure"]["ifs"][0]["then_target"], BASE + 0x02);
    assert_eq!(v["structure"]["ifs"][0]["else_target"], BASE + 0x09);

    // Interior address snaps to the entry.
    let snapped = p.structure_of(BASE + 1).expect("snap");
    assert_eq!(snapped, v, "snap must equal the entry view");

    assert!(
        p.structure_of(0xdead).is_err(),
        "outside any function is NotFound"
    );
    assert!(!db.exists(), "reads never create the sidecar");
    cleanup(&dir);
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
fn cli_structure_envelope_and_errors() {
    let dir = tmpdir("cli-structure");
    let bin = write_bin(&dir, "loop.bin", &loop_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "loop").display().to_string();
    let d = db.as_str();
    let base = format!("{BASE:#x}");
    let raw = [
        "--raw", "--arch", "x86_64", "--base", &base, "--entry", &base,
    ];
    let with_raw = |extra: &[&str]| -> Vec<String> {
        let mut args = vec!["--db".to_string(), d.to_string()];
        args.extend(raw.iter().map(|s| s.to_string()));
        args.extend(extra.iter().map(|s| s.to_string()));
        args
    };

    let args = with_raw(&["structure", &bin, &format!("{BASE:#x}")]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&refs);
    assert!(ok, "{v}");
    assert_eq!(v["entry"], BASE);
    assert_eq!(v["structure"]["warning"], STRUCTURE_WARNING);
    assert_eq!(v["structure"]["loops"][0]["header"], BASE + 0x02);
    assert_eq!(v["structure"]["loops"][0]["latches"][0], BASE + 0x02);
    assert_eq!(v["structure"]["ifs"][0]["then_target"], BASE + 0x02);

    // Hex and decimal roots agree.
    let args = with_raw(&["structure", &bin, &BASE.to_string()]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, n) = run(&refs);
    assert!(ok, "{n}");
    assert_eq!(v, n, "hex and decimal must agree");

    // Unknown function and bad addresses are JSON errors.
    let args = with_raw(&["structure", &bin, "0xdead"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&refs);
    assert!(!ok && v.get("error").is_some(), "{v}");
    let args = with_raw(&["structure", &bin, "zz"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&refs);
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert!(
        !std::path::Path::new(d).exists(),
        "structure reads never create the sidecar"
    );
    cleanup(&dir);
}

fn req(id: u64, method: &str, params: Value) -> String {
    serde_json::to_string(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .expect("request serializes")
}

fn call(id: u64, name: &str, args: Value) -> String {
    req(id, "tools/call", json!({"name": name, "arguments": args}))
}

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
    String::from_utf8(out.stdout)
        .expect("stdout utf-8")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("response line JSON"))
        .collect()
}

fn tool_text(resp: &Value) -> &str {
    let result = resp.get("result").expect("tool result");
    assert_ne!(result.get("isError"), Some(&Value::Bool(true)), "{resp}");
    result["content"][0]["text"].as_str().expect("text content")
}

fn tool_once(tool_id: u64, tool: &str, args: Value) -> Value {
    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(tool_id, tool, args),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let text = tool_text(&resps[1]).to_owned();
    serde_json::from_str(&text).expect("tool json")
}

#[test]
fn mcp_structure_parity_and_errors() {
    let dir = tmpdir("mcp-structure");
    let bin = write_bin(&dir, "loop.bin", &loop_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "loop").display().to_string();
    let base = format!("{BASE:#x}");
    let raw = json!({"arch": "x86_64", "base": base, "entry": base});

    let v = tool_once(
        10,
        "structure",
        json!({"binary": bin, "db": db, "raw": raw, "addr": format!("{BASE:#x}")}),
    );
    assert_eq!(v["entry"], BASE);
    assert_eq!(v["structure"]["warning"], STRUCTURE_WARNING);
    assert_eq!(v["structure"]["loops"][0]["header"], BASE + 0x02);
    assert_eq!(v["structure"]["ifs"][0]["then_target"], BASE + 0x02);

    // CLI parity on the same DB and filters.
    let bbin = binscout_bin();
    let out = Command::new(bbin)
        .args([
            "--db",
            &db,
            "--raw",
            "--arch",
            "x86_64",
            "--base",
            &base,
            "--entry",
            &base,
            "structure",
            &bin,
            &format!("{BASE:#x}"),
        ])
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout utf-8");
    let from_cli: Value = serde_json::from_str(text.trim_end()).expect("cli json");
    assert_eq!(from_cli, v, "CLI and MCP must agree");

    // Errors are protocol-level, never results.
    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(
            20,
            "structure",
            json!({"binary": bin, "db": db, "raw": raw, "addr": "0xdead"}),
        ),
        call(
            21,
            "structure",
            json!({"binary": bin, "db": db, "raw": raw, "addr": "zz"}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 3, "{resps:?}");
    for resp in resps.iter().skip(1) {
        assert!(resp.get("error").is_some(), "must error: {resp:?}");
        assert!(resp.get("result").is_none());
    }
    assert!(
        !std::path::Path::new(&db).exists(),
        "structure queries never create the sidecar"
    );
    cleanup(&dir);
}
