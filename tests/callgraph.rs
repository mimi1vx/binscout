//! Transitive callgraph: depth-bounded `callees*`/`callers*` over a
//! diamond fixture (A calls B,C; B,C call D) plus CLI/MCP e2e.
//!
//! Covers BFS levels, depth caps, cycle guards, paging, snapping, and
//! error envelopes on both surfaces.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use binscout::analysis::{MAX_CALL_DEPTH, analyze_raw};
use binscout::disasm::Arch;
use binscout::loader::RawOptions;

use common::{binscout_bin, cleanup, mcp_bin, temp_db, tmpdir, write_bin};

const BASE: u64 = 0x1000;

/// Diamond blob: A@+0x0 calls B@+0x20 and C@+0x40; B and C call D@+0x60.
fn diamond_blob() -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    // A: push rbp; mov rbp,rsp; call B; call C; pop rbp; ret.
    b.extend([0x55, 0x48, 0x89, 0xE5]);
    let rel_b = 0x20i32 - 0x09;
    b.extend([0xE8]);
    b.extend(rel_b.to_le_bytes());
    let rel_c = 0x40i32 - 0x0E;
    b.extend([0xE8]);
    b.extend(rel_c.to_le_bytes());
    b.extend([0x5D, 0xC3]);
    b.extend(vec![0x90; 0x20 - b.len()]);
    // B: frame + call D.
    b.extend([0x55, 0x48, 0x89, 0xE5]);
    let rel_d_b = 0x60i32 - 0x29;
    b.extend([0xE8]);
    b.extend(rel_d_b.to_le_bytes());
    b.extend([0x5D, 0xC3]);
    b.extend(vec![0x90; 0x40 - b.len()]);
    // C: frame + call D.
    b.extend([0x55, 0x48, 0x89, 0xE5]);
    let rel_d_c = 0x60i32 - 0x49;
    b.extend([0xE8]);
    b.extend(rel_d_c.to_le_bytes());
    b.extend([0x5D, 0xC3]);
    b.extend(vec![0x90; 0x60 - b.len()]);
    // D: leaf frame.
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ]);
    b
}

fn entries() -> (u64, u64, u64, u64) {
    (BASE, BASE + 0x20, BASE + 0x40, BASE + 0x60)
}

#[test]
fn diamond_edges_and_bfs_levels() {
    let a = analyze_raw(&diamond_blob(), BASE, Arch::X86_64, Some(BASE)).expect("diamond analyzes");
    let (root, b, c, d) = entries();
    assert_eq!(a.summary().functions, 4);
    let mut edges = a.call_edges();
    edges.sort_unstable();
    assert_eq!(edges, [(root, b), (root, c), (b, d), (c, d)]);

    assert_eq!(a.callees_transitive(root, 0), Vec::new());
    assert_eq!(a.callees_transitive(root, 1), [(b, 1), (c, 1)]);
    assert_eq!(a.callees_transitive(root, 2), [(b, 1), (c, 1), (d, 2)]);
    assert_eq!(
        a.callees_transitive(root, 64),
        a.callees_transitive(root, 2)
    );

    assert_eq!(a.callers_transitive(d, 1), [(b, 1), (c, 1)]);
    assert_eq!(a.callers_transitive(d, 2), [(root, 2), (b, 1), (c, 1)]);
    assert!(a.callees_transitive(d, 5).is_empty());
    assert!(a.callers_transitive(root, 5).is_empty());
    assert!(a.callees_transitive(0xdead, 5).is_empty());
}

#[test]
fn cycle_guard_excludes_root_and_terminates() {
    use binscout::analysis::{Analysis, Diagnostics, Function};
    use std::collections::BTreeMap;
    let mut functions: BTreeMap<u64, Function> = BTreeMap::new();
    for e in [0x1000, 0x2000] {
        functions.insert(
            e,
            Function::from_parts(e, None, BTreeMap::new(), &[], vec![], &[]),
        );
    }
    let a = Analysis::from_parts(
        Arch::X86_64,
        functions,
        &[(0x1000, 0x2000), (0x2000, 0x1000)],
        Vec::new(),
        Vec::new(),
        Diagnostics::empty(),
    );
    assert_eq!(a.callees_transitive(0x1000, 64), [(0x2000, 1)]);
    assert_eq!(a.callers_transitive(0x1000, 64), [(0x2000, 1)]);
}

#[test]
fn project_pages_depth_errors_and_snapping() {
    use binscout::error::Error;
    let dir = tmpdir("callgraph-pages");
    let bin = write_bin(&dir, "diamond.bin", &diamond_blob());
    let db = temp_db(&dir, "diamond");
    let p = binscout::Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: BASE,
            arch: Arch::X86_64,
            entry: Some(BASE),
        },
    )
    .expect("diamond opens");
    let (root, b, c, d) = entries();

    let page = p.callees_page(root, 1, 0, 50).expect("depth-1 page");
    assert_eq!(page.total, 2);
    assert_eq!(page.protocol, 1);
    assert_eq!(
        page.items
            .iter()
            .map(|r| (r.entry, r.depth))
            .collect::<Vec<_>>(),
        [(b, 1), (c, 1)]
    );
    // Interior address snaps to the root.
    let snapped = p.callees_page(root + 1, 2, 0, 50).expect("snap page");
    assert_eq!(snapped.total, 3);
    assert!(
        snapped.items.iter().any(|r| r.entry == d && r.depth == 2),
        "D at depth 2: {snapped:?}"
    );

    let back = p.callers_page(d, 2, 0, 50).expect("callers page");
    assert_eq!(back.total, 3);
    assert_eq!(
        back.items
            .iter()
            .map(|r| (r.entry, r.depth))
            .collect::<Vec<_>>(),
        [(root, 2), (b, 1), (c, 1)]
    );

    // Depth zero is an empty page, not an error.
    let empty = p.callees_page(root, 0, 0, 50).expect("depth-0 page");
    assert_eq!(empty.total, 0);
    assert!(empty.items.is_empty());

    // Paging precedes nothing: total stays exact across pages.
    let first = p.callees_page(root, 5, 0, 2).expect("first page");
    assert_eq!(first.total, 3);
    assert_eq!(first.items.len(), 2);
    assert_eq!(first.next_offset, Some(2));
    let second = p.callees_page(root, 5, 2, 2).expect("second page");
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.next_offset, None);

    // Over-cap depth errors without writing.
    let err = p.callees_page(root, MAX_CALL_DEPTH + 1, 0, 10).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
    let err = p.callers_page(root, usize::MAX, 0, 10).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
    assert!(matches!(
        p.callees_page(0xdead, 5, 0, 10).unwrap_err(),
        Error::NotFound(_)
    ));
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
fn cli_callees_callers_envelope_and_errors() {
    let dir = tmpdir("cli-callgraph");
    let bin = write_bin(&dir, "diamond.bin", &diamond_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "diamond").display().to_string();
    let d = db.as_str();
    let (root, b, c, leaf) = entries();
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

    // Depth 1: direct only; default depth is the full closure.
    let args = with_raw(&["callees", &bin, &format!("{root:#x}"), "--depth", "1"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&refs);
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 2);
    assert_eq!(v["items"][0]["entry"], b);
    assert_eq!(v["items"][0]["depth"], 1);
    assert_eq!(v["items"][0]["entry_hex"], format!("{b:#x}"));
    assert_eq!(v["items"][1]["entry"], c);

    let args = with_raw(&["callees", &bin, &format!("{root:#x}"), "--depth", "5"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&refs);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 3);
    assert_eq!(v["items"][2]["entry"], leaf);
    assert_eq!(v["items"][2]["depth"], 2);

    // Interior snaps; callers mirror.
    let args = with_raw(&["callers", &bin, &format!("{:#x}", leaf + 1), "--depth", "5"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&refs);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 3);
    assert_eq!(v["items"][0]["entry"], root);
    assert_eq!(v["items"][0]["depth"], 2);

    // Paging keeps the exact total.
    let args = with_raw(&[
        "callees",
        &bin,
        &format!("{root:#x}"),
        "--depth",
        "5",
        "--limit",
        "2",
    ]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&refs);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 3);
    assert_eq!(v["items"].as_array().expect("items").len(), 2);
    assert_eq!(v["next_offset"], 2);

    // Unknown function and over-cap depth are JSON errors.
    let args = with_raw(&["callees", &bin, "0xdead", "--depth", "5"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&refs);
    assert!(!ok && v.get("error").is_some(), "{v}");
    let args = with_raw(&[
        "callees",
        &bin,
        &format!("{root:#x}"),
        "--depth",
        &format!("{}", MAX_CALL_DEPTH + 1),
    ]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&refs);
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert!(
        !std::path::Path::new(d).exists(),
        "callgraph reads never create the sidecar"
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
fn mcp_callees_callers_parity_and_errors() {
    let dir = tmpdir("mcp-callgraph");
    let bin = write_bin(&dir, "diamond.bin", &diamond_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "diamond").display().to_string();
    let (root, b, c, leaf) = entries();
    let base = format!("{BASE:#x}");
    let raw = json!({"arch": "x86_64", "base": base, "entry": base});

    let v = tool_once(
        10,
        "callees",
        json!({"binary": bin, "db": db, "raw": raw, "addr": format!("{root:#x}"), "depth": 1}),
    );
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 2);
    assert_eq!(v["items"][0]["entry"], b);
    assert_eq!(v["items"][0]["depth"], 1);

    let v = tool_once(
        11,
        "callees",
        json!({"binary": bin, "db": db, "raw": raw, "addr": format!("{root:#x}"), "depth": 5}),
    );
    assert_eq!(v["total"], 3);
    assert_eq!(v["items"][2]["entry"], leaf);
    assert_eq!(v["items"][2]["depth"], 2);
    assert_eq!(v["items"][1]["entry"], c);

    let v = tool_once(
        12,
        "callers",
        json!({"binary": bin, "db": db, "raw": raw, "addr": format!("{leaf:#x}"), "depth": 5}),
    );
    assert_eq!(v["total"], 3);
    assert_eq!(v["items"][0]["entry"], root);
    assert_eq!(v["items"][0]["depth"], 2);

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
            "callees",
            &bin,
            &format!("{root:#x}"),
            "--depth",
            "5",
        ])
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout utf-8");
    let from_cli: Value = serde_json::from_str(text.trim_end()).expect("cli json");
    let from_mcp = tool_once(
        13,
        "callees",
        json!({"binary": bin, "db": db, "raw": raw, "addr": format!("{root:#x}"), "depth": 5}),
    );
    assert_eq!(from_cli, from_mcp, "CLI and MCP must agree");

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
            "callees",
            json!({"binary": bin, "db": db, "raw": raw, "addr": "0xdead", "depth": 5}),
        ),
        call(
            21,
            "callees",
            json!({"binary": bin, "db": db, "raw": raw, "addr": format!("{root:#x}"), "depth": MAX_CALL_DEPTH + 1}),
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
        "callgraph queries never create the sidecar"
    );
    cleanup(&dir);
}
