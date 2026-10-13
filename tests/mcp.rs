//! M6 MCP e2e: spawn `binscout-mcp` over stdio, run the JSON-RPC handshake,
//! list the 11 tools, and call every one against fixtures.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use common::{cleanup, mcp_bin, temp_db, tmpdir, write_bin};

/// One request line plus notification; returns response lines in order.
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
    let text = String::from_utf8(out.stdout).expect("stdout utf-8");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|_| panic!("response line must be JSON: {l:?}"))
        })
        .collect()
}

fn req(id: u64, method: &str, params: Value) -> String {
    serde_json::to_string(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .expect("request serializes")
}

fn call(id: u64, name: &str, args: Value) -> String {
    req(id, "tools/call", json!({"name": name, "arguments": args}))
}

/// Tool result text payload (asserts `isError` is absent/false).
fn tool_text(resp: &Value) -> &str {
    let result = resp
        .get("result")
        .unwrap_or_else(|| panic!("tool must return result: {resp}"));
    assert_ne!(
        result.get("isError"),
        Some(&Value::Bool(true)),
        "tool error: {resp}"
    );
    result["content"][0]["text"].as_str().expect("text content")
}

#[test]
fn handshake_lists_eleven_tools() {
    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        req(2, "tools/list", json!({})),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    assert!(resps[0].get("result").is_some(), "{resps:?}");
    let tools = resps[1]["result"]["tools"]
        .as_array()
        .expect("tools array")
        .clone();
    let mut names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            "cfg",
            "comment",
            "disasm",
            "func",
            "functions",
            "ir",
            "project_info",
            "rename",
            "strings",
            "symbols",
            "xrefs",
        ],
        "exactly the 11 M6 tools"
    );
}

#[test]
fn all_tools_return_json_over_stdio() {
    let dir = tmpdir("mcp");
    let fixture = std::fs::read("tests/fixtures/raw-x64.bin").expect("fixture");
    let bin = write_bin(&dir, "m.bin", &fixture).display().to_string();
    let db = temp_db(&dir, "m").display().to_string();
    let b = || Value::String(bin.clone());
    let d = || Value::String(db.clone());

    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(10, "project_info", json!({"binary": b(), "db": d()})),
        call(11, "functions", json!({"binary": b(), "db": d()})),
        call(12, "func", json!({"binary": b(), "db": d(), "addr": "0x0"})),
        call(
            13,
            "disasm",
            json!({"binary": b(), "db": d(), "addr": "0x0", "len": 3}),
        ),
        call(14, "cfg", json!({"binary": b(), "db": d(), "addr": "0x0"})),
        call(15, "xrefs", json!({"binary": b(), "db": d()})),
        call(16, "strings", json!({"binary": b(), "db": d()})),
        call(17, "symbols", json!({"binary": b(), "db": d()})),
        call(
            18,
            "ir",
            json!({"binary": b(), "db": d(), "addr": "0x0", "len": 3}),
        ),
        call(
            19,
            "rename",
            json!({"binary": b(), "db": d(), "addr": "0x0", "name": "main"}),
        ),
        call(
            20,
            "comment",
            json!({"binary": b(), "db": d(), "addr": "1", "comment": "via mcp"}),
        ),
        call(
            21,
            "func",
            json!({"binary": b(), "db": d(), "addr": "0xdead"}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 13, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();

    let info: Value = serde_json::from_str(tool_text(by_id[&10])).expect("project_info json");
    assert_eq!(info["format"], "raw");

    let funcs: Value = serde_json::from_str(tool_text(by_id[&11])).expect("functions json");
    assert_eq!(funcs.as_array().expect("array").len(), 1);

    let dis: Value = serde_json::from_str(tool_text(by_id[&13])).expect("disasm json");
    assert_eq!(dis.as_array().expect("array").len(), 3);

    let renamed: Value = serde_json::from_str(tool_text(by_id[&19])).expect("rename json");
    assert_eq!(renamed["name"], "main");
    let commented: Value = serde_json::from_str(tool_text(by_id[&20])).expect("comment json");
    assert_eq!(commented["comment"], "via mcp");

    // Unknown function is a protocol-level error, not a result.
    assert!(by_id[&21].get("error").is_some(), "{:?}", by_id[&21]);
    assert!(by_id[&21].get("result").is_none());

    assert_eq!(
        std::fs::read(dir.join("m.bin")).expect("reread"),
        fixture,
        "binary untouched"
    );
    cleanup(&dir);
}

#[test]
fn le_project_info_is_a_tool_error() {
    let dir = tmpdir("mcp-le");
    let bin = write_bin(
        &dir,
        "le.exe",
        &common::fixture_bytes(common::builders::LE_NAME),
    )
    .display()
    .to_string();
    let db = temp_db(&dir, "le").display().to_string();

    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(10, "project_info", json!({"binary": bin, "db": db})),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let resp = &resps[1];
    assert!(
        resp.get("result").is_none(),
        "LE must not return info: {resp}"
    );
    let msg = resp["error"]["message"].as_str().expect("error message");
    assert!(msg.contains("unsupported"), "{resp}");
    assert!(msg.contains("LE"), "{resp}");
    cleanup(&dir);
}
