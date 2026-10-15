//! Backward slicing: bounded reverse reachability to a `to:` address over
//! xref edges (any kind) plus intra-function CFG predecessors, plus
//! CLI/MCP e2e.
//!
//! Covers BFS levels, depth caps, cycle guards, paging, hex/decimal
//! parity, and error envelopes on both surfaces. The PE fixture test
//! traces the two string refs back through the frame setup to the
//! loader entry.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use binscout::analysis::{MAX_SLICE_DEPTH, analyze_raw};
use binscout::disasm::Arch;
use binscout::loader::RawOptions;

use common::{binscout_bin, cleanup, mcp_bin, temp_db, tmpdir, write_bin};

const BASE: u64 = 0x2000;

/// Branch blob: xor eax,eax | cmp eax,1 | je +6 | mov eax,1 | ret |
/// mov eax,2 | ret. Three blocks; 0x200D is reachable via the je xref
/// and via the CFG predecessor edge alike.
fn branch_blob() -> Vec<u8> {
    vec![
        0x31, 0xC0, 0x83, 0xF8, 0x01, 0x74, 0x06, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xB8, 0x02,
        0x00, 0x00, 0x00, 0xC3,
    ]
}

/// Two x86-64 functions: 0x1000 calls 0x1010 (call site 0x1004).
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
fn slice_walks_xrefs_then_cfg_predecessors() {
    // Call edge first: slicing to the callee entry reaches the call
    // site, then walks back through the caller's frame setup.
    let a = analyze_raw(&two_func_blob(), 0x1000, Arch::X86_64, Some(0x1000))
        .expect("two-func blob analyzes");
    assert_eq!(a.slice_to(0x1010, 0), Vec::new());
    assert_eq!(a.slice_to(0x1010, 1), [(0x1004, 1)]);
    assert_eq!(
        a.slice_to(0x1010, 3),
        [(0x1000, 3), (0x1001, 2), (0x1004, 1)]
    );

    // Branch target: the je site arrives via its Code xref; the fallthrough
    // block start arrives via the CFG predecessor edge only (fallthrough
    // is not an xref).
    let a = analyze_raw(&branch_blob(), BASE, Arch::X86_64, Some(BASE)).expect("branch analyzes");
    assert_eq!(a.slice_to(BASE + 0x0D, 1), [(BASE + 0x05, 1)]);
    assert_eq!(
        a.slice_to(BASE + 0x0D, 3),
        [(BASE, 3), (BASE + 0x02, 2), (BASE + 0x05, 1)]
    );
    assert_eq!(a.slice_to(BASE + 0x07, 1), [(BASE + 0x05, 1)]);
    // The root itself is never reported, even at saturating depth.
    assert_eq!(a.slice_to(BASE + 0x0D, 64), a.slice_to(BASE + 0x0D, 3));
    // An address with no referrers and no block yields nothing.
    assert!(a.slice_to(0xdead, 5).is_empty());
}

#[test]
fn slice_cycle_guard_excludes_root_and_terminates() {
    use binscout::analysis::{Analysis, Diagnostics, Function, Xref, XrefKind};
    use std::collections::BTreeMap;
    let mut functions: BTreeMap<u64, Function> = BTreeMap::new();
    for e in [0x1000u64, 0x2000] {
        functions.insert(
            e,
            Function::from_parts(e, None, BTreeMap::new(), &[], vec![], &[]),
        );
    }
    // No blocks: only xref edges apply; the 0x1000 -> 0x2000 edge would
    // revisit the root from 0x2000 without the visited set.
    let xrefs = vec![
        Xref {
            from: 0x2000,
            to: 0x1000,
            kind: XrefKind::Code,
        },
        Xref {
            from: 0x1000,
            to: 0x2000,
            kind: XrefKind::Code,
        },
    ];
    let a = Analysis::from_parts(
        Arch::X86_64,
        functions,
        &[(0x1000, 0x2000), (0x2000, 0x1000)],
        xrefs,
        Vec::new(),
        Diagnostics::empty(),
    );
    assert_eq!(a.slice_to(0x1000, 64), [(0x2000, 1)]);
    assert_eq!(a.slice_to(0x2000, 64), [(0x1000, 1)]);
}

#[test]
fn slice_traces_pe_string_refs_to_loader_entry() {
    use common::builders::{BASIC_ENTRY_VA, BASIC_STRING_VA};
    let dir = tmpdir("slice-pe-string");
    let p = common::open_test_project(&dir, common::builders::BASIC_NAME);
    // .text is one straight-line block: push ebp @+0, mov ebp,esp @+1,
    // push imm32 @+3 and @+8, ret. Both pushes reference the marker.
    let push_a = BASIC_ENTRY_VA + 3;
    let push_b = BASIC_ENTRY_VA + 8;

    let page = p
        .slice_page(BASIC_STRING_VA, 1, 0, 50)
        .expect("depth-1 page");
    assert_eq!(page.protocol, 1);
    assert_eq!(page.total, 2);
    assert_eq!(
        page.items
            .iter()
            .map(|r| (r.addr, r.depth))
            .collect::<Vec<_>>(),
        [(push_a, 1), (push_b, 1)]
    );
    for row in &page.items {
        assert_eq!(row.func, Some(BASIC_ENTRY_VA), "{row:?}");
    }

    // Depth 2 pulls the mov before the first push; depth 3 reaches the
    // loader entry itself through the frame setup.
    let page = p.slice_page(BASIC_STRING_VA, 5, 0, 50).expect("full slice");
    assert_eq!(page.total, 4);
    assert_eq!(
        page.items
            .iter()
            .map(|r| (r.addr, r.depth))
            .collect::<Vec<_>>(),
        [
            (BASIC_ENTRY_VA, 3),
            (BASIC_ENTRY_VA + 1, 2),
            (push_a, 1),
            (push_b, 1),
        ]
    );
    assert!(
        page.items.iter().all(|r| r.func == Some(BASIC_ENTRY_VA)),
        "every slice row lies in the loader function: {page:?}"
    );
    assert!(
        page.items
            .iter()
            .any(|r| r.addr == BASIC_ENTRY_VA && r.name.as_deref() == Some("basic_entry")),
        "entry row carries the export name: {page:?}"
    );

    // Depth zero is an empty page; over-cap depth is Invalid; an
    // unreferenced address is an empty page, not an error.
    let empty = p
        .slice_page(BASIC_STRING_VA, 0, 0, 50)
        .expect("depth-0 page");
    assert_eq!(empty.total, 0);
    assert!(empty.items.is_empty());
    let err = p
        .slice_page(BASIC_STRING_VA, MAX_SLICE_DEPTH + 1, 0, 10)
        .unwrap_err();
    assert!(
        matches!(err, binscout::error::Error::Invalid(_)),
        "got {err:?}"
    );
    let bare = p.slice_page(0xdead, 5, 0, 10).expect("bare page");
    assert_eq!(bare.total, 0);
    assert!(
        !temp_db(&dir, common::builders::BASIC_NAME).exists(),
        "reads never create the sidecar"
    );
    cleanup(&dir);
}

#[test]
fn slice_pages_keep_exact_total_and_read_only() {
    let dir = tmpdir("slice-pages");
    let bin = write_bin(&dir, "two.bin", &two_func_blob());
    let db = temp_db(&dir, "two");
    let p = binscout::Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: 0x1000,
            arch: Arch::X86_64,
            entry: Some(0x1000),
        },
    )
    .expect("two-func opens");

    let first = p.slice_page(0x1010, 5, 0, 2).expect("first page");
    assert_eq!(first.total, 3);
    assert_eq!(first.items.len(), 2);
    assert_eq!(first.next_offset, Some(2));
    let second = p.slice_page(0x1010, 5, 2, 2).expect("second page");
    assert_eq!(second.total, 3);
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.next_offset, None);
    // Over-cap limits clip to the 1024-row cap.
    let clipped = p.slice_page(0x1010, 5, 0, 5000).expect("clipped page");
    assert_eq!(clipped.limit, 1024);
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
fn cli_slice_envelope_parity_and_errors() {
    use common::builders::{BASIC_ENTRY_VA, BASIC_STRING_VA};
    let dir = tmpdir("cli-slice");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME)
        .display()
        .to_string();
    let db = temp_db(&dir, "basic").display().to_string();
    let d = db.as_str();
    let marker_hex = format!("{BASIC_STRING_VA:#x}");
    let marker_dec = BASIC_STRING_VA.to_string();

    let (ok, v) = run(&["--db", d, "slice", &bin, &marker_hex, "--depth", "1"]);
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 2);
    assert_eq!(v["items"][0]["addr"], BASIC_ENTRY_VA + 3);
    assert_eq!(v["items"][0]["depth"], 1);
    assert_eq!(
        v["items"][0]["addr_hex"],
        format!("{:#x}", BASIC_ENTRY_VA + 3)
    );
    assert_eq!(v["items"][0]["func"], BASIC_ENTRY_VA);
    assert_eq!(v["items"][1]["addr"], BASIC_ENTRY_VA + 8);

    // Hex and decimal roots agree; full depth reaches the loader entry.
    let (ok, n) = run(&["--db", d, "slice", &bin, &marker_dec, "--depth", "1"]);
    assert!(ok, "{n}");
    assert_eq!(v, n, "hex and decimal must slice identically");
    let (ok, v) = run(&["--db", d, "slice", &bin, &marker_hex, "--depth", "5"]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 4);
    assert_eq!(v["items"][0]["addr"], BASIC_ENTRY_VA);
    assert_eq!(v["items"][0]["depth"], 3);

    // Paging keeps the exact total.
    let (ok, v) = run(&[
        "--db",
        d,
        "slice",
        &bin,
        &marker_hex,
        "--depth",
        "5",
        "--limit",
        "3",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 4);
    assert_eq!(v["items"].as_array().expect("items").len(), 3);
    assert_eq!(v["next_offset"], 3);

    // Unreferenced roots are empty pages; bad addresses and over-cap
    // depths are JSON errors.
    let (ok, v) = run(&["--db", d, "slice", &bin, "0xdead", "--depth", "5"]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 0);
    let (ok, v) = run(&["--db", d, "slice", &bin, "zz", "--depth", "5"]);
    assert!(!ok && v.get("error").is_some(), "{v}");
    let (ok, v) = run(&[
        "--db",
        d,
        "slice",
        &bin,
        &marker_hex,
        "--depth",
        &format!("{}", MAX_SLICE_DEPTH + 1),
    ]);
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert!(
        !std::path::Path::new(d).exists(),
        "slice reads never create the sidecar"
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
fn mcp_slice_parity_and_errors() {
    use common::builders::{BASIC_ENTRY_VA, BASIC_STRING_VA};
    let dir = tmpdir("mcp-slice");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME)
        .display()
        .to_string();
    let db = temp_db(&dir, "basic").display().to_string();
    let marker_hex = format!("{BASIC_STRING_VA:#x}");

    let v = tool_once(
        10,
        "slice",
        json!({"binary": bin, "db": db, "to": marker_hex, "depth": 1}),
    );
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 2);
    assert_eq!(v["items"][0]["addr"], BASIC_ENTRY_VA + 3);
    assert_eq!(v["items"][0]["depth"], 1);
    assert_eq!(v["items"][0]["func"], BASIC_ENTRY_VA);

    let v = tool_once(
        11,
        "slice",
        json!({"binary": bin, "db": db, "to": marker_hex, "depth": 5}),
    );
    assert_eq!(v["total"], 4);
    assert_eq!(v["items"][0]["addr"], BASIC_ENTRY_VA);
    assert_eq!(v["items"][0]["depth"], 3);

    // CLI parity on the same DB and filters.
    let bbin = binscout_bin();
    let out = Command::new(bbin)
        .args(["--db", &db, "slice", &bin, &marker_hex, "--depth", "5"])
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout utf-8");
    let from_cli: Value = serde_json::from_str(text.trim_end()).expect("cli json");
    let from_mcp = tool_once(
        13,
        "slice",
        json!({"binary": bin, "db": db, "to": marker_hex, "depth": 5}),
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
            "slice",
            json!({"binary": bin, "db": db, "to": "zz", "depth": 5}),
        ),
        call(
            21,
            "slice",
            json!({"binary": bin, "db": db, "to": marker_hex, "depth": MAX_SLICE_DEPTH + 1}),
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
        "slice queries never create the sidecar"
    );
    cleanup(&dir);
}
