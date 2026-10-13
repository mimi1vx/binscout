//! M6 MCP e2e: spawn `binscout-mcp` over stdio, run the JSON-RPC handshake,
//! list the 12 tools, and call every one against fixtures.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use common::{cleanup, mcp_bin, temp_db, tmpdir, write_bin, write_fixture};

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
fn handshake_lists_twelve_tools() {
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
            "sections",
            "strings",
            "symbols",
            "xrefs",
        ],
        "exactly the 12 tools"
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
        call(18, "sections", json!({"binary": b(), "db": d()})),
        call(
            19,
            "ir",
            json!({"binary": b(), "db": d(), "addr": "0x0", "len": 3}),
        ),
        call(
            20,
            "rename",
            json!({"binary": b(), "db": d(), "addr": "0x0", "name": "main"}),
        ),
        call(
            21,
            "comment",
            json!({"binary": b(), "db": d(), "addr": "1", "comment": "via mcp"}),
        ),
        call(
            22,
            "func",
            json!({"binary": b(), "db": d(), "addr": "0xdead"}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 14, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();

    let info: Value = serde_json::from_str(tool_text(by_id[&10])).expect("project_info json");
    assert_eq!(info["format"], "raw");

    let funcs: Value = serde_json::from_str(tool_text(by_id[&11])).expect("functions json");
    assert_eq!(funcs.as_array().expect("array").len(), 1);

    let dis: Value = serde_json::from_str(tool_text(by_id[&13])).expect("disasm json");
    assert_eq!(dis["insns"].as_array().expect("envelope insns").len(), 3);
    assert!(dis["error_at"].is_null(), "clean disasm error_at:null");

    let renamed: Value = serde_json::from_str(tool_text(by_id[&20])).expect("rename json");
    assert_eq!(renamed["name"], "main");
    let commented: Value = serde_json::from_str(tool_text(by_id[&21])).expect("comment json");
    assert_eq!(commented["comment"], "via mcp");

    let sections: Value = serde_json::from_str(tool_text(by_id[&18])).expect("sections json");
    assert_eq!(
        sections,
        serde_json::json!([]),
        "raw blob has no section table"
    );

    // Unknown function is a protocol-level error, not a result.
    assert!(by_id[&22].get("error").is_some(), "{:?}", by_id[&22]);
    assert!(by_id[&22].get("result").is_none());

    assert_eq!(
        std::fs::read(dir.join("m.bin")).expect("reread"),
        fixture,
        "binary untouched"
    );
    cleanup(&dir);
}

#[test]
fn functions_filters_and_mid_function_snap() {
    // One session, but every call is order-independent: the server may run
    // requests concurrently, so no call may depend on another's writes.
    // pe32-basic.exe exports `basic_entry` at 0x401000.
    let dir = tmpdir("mcp-funcfilter");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db = temp_db(&dir, "basic").display().to_string();
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
        call(
            10,
            "functions",
            json!({"binary": b(), "db": d(), "query": "BASIC"}),
        ),
        call(
            11,
            "functions",
            json!({"binary": b(), "db": d(), "query": "zzz"}),
        ),
        call(
            12,
            "functions",
            json!({"binary": b(), "db": d(), "range_lo": "0x401000", "range_hi": "0x401000"}),
        ),
        call(
            13,
            "functions",
            json!({"binary": b(), "db": d(), "caller": "0x401000"}),
        ),
        call(
            14,
            "func",
            json!({"binary": b(), "db": d(), "addr": "0x401001"}),
        ),
        call(
            15,
            "cfg",
            json!({"binary": b(), "db": d(), "addr": "0x401001"}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 7, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();

    let q: Value = serde_json::from_str(tool_text(by_id[&10])).expect("query json");
    assert_eq!(q.as_array().expect("array").len(), 1);
    assert_eq!(q[0]["entry"], 0x401000);

    let q: Value = serde_json::from_str(tool_text(by_id[&11])).expect("query json");
    assert_eq!(q.as_array().expect("array").len(), 0);

    let q: Value = serde_json::from_str(tool_text(by_id[&12])).expect("range json");
    assert_eq!(q.as_array().expect("array").len(), 1);

    // The single-function fixture calls nothing, so nothing calls the entry:
    // empty page, still success.
    let q: Value = serde_json::from_str(tool_text(by_id[&13])).expect("caller json");
    assert_eq!(q.as_array().expect("array").len(), 0);

    // 0x401001 is mid-function (inside the entry block): snaps instead of
    // reporting not-found.
    let f: Value = serde_json::from_str(tool_text(by_id[&14])).expect("func json");
    assert_eq!(f["entry"], 0x401000);
    assert_eq!(f["containing_entry"], 0x401000);

    let c: Value = serde_json::from_str(tool_text(by_id[&15])).expect("cfg json");
    assert_eq!(c["entry"], 0x401000);
    assert_eq!(c["containing_entry"], 0x401000);
    cleanup(&dir);
}

// D2/A6: MCP disasm returns the valid prefix plus error_at on garbage,
// null on a clean prefix.
#[test]
fn disasm_partial_prefix_and_error_at() {
    let dir = tmpdir("mcp-disasm-partial");
    let bin = write_fixture(&dir, common::builders::GARBAGE_NAME)
        .display()
        .to_string();
    let db = temp_db(&dir, "garbage").display().to_string();
    let b = || Value::String(bin.clone());
    let d = || Value::String(db.clone());
    let bytes = common::fixture_bytes(common::builders::GARBAGE_NAME);
    let stop = bytes.iter().position(|b| *b == 0xD6).expect("stop byte");

    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(
            10,
            "disasm",
            json!({"binary": b(), "db": d(), "addr": "0", "len": bytes.len()}),
        ),
        call(
            11,
            "disasm",
            json!({"binary": b(), "db": d(), "addr": "0", "len": stop}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 3, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();

    let full: Value = serde_json::from_str(tool_text(by_id[&10])).expect("partial json");
    assert_eq!(full["insns"].as_array().expect("insns").len(), 2);
    assert_eq!(full["error_at"]["addr"], 4);

    let clean: Value = serde_json::from_str(tool_text(by_id[&11])).expect("clean json");
    assert_eq!(clean["insns"].as_array().expect("insns").len(), 2);
    assert!(
        clean["error_at"].is_null(),
        "clean error_at:null, got {clean}"
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

#[test]
fn strings_filters_pattern_section_and_paging() {
    // pe32-basic.exe carries the SAVE marker in .rdata; text-garbage.bin is
    // executable-memory noise, hidden unless the query opts back in.
    let dir = tmpdir("mcp-strings");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db = temp_db(&dir, "basic").display().to_string();
    let garbage = write_fixture(&dir, "text-garbage.bin")
        .display()
        .to_string();
    let garbage_db = temp_db(&dir, "garbage").display().to_string();
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
        call(
            10,
            "strings",
            json!({"binary": b(), "db": d(), "pattern": "SAVE", "min_len": 6}),
        ),
        call(
            11,
            "strings",
            json!({"binary": b(), "db": d(), "section": ".rdata", "limit": 1}),
        ),
        call(
            12,
            "strings",
            json!({"binary": b(), "db": d(), "start": 1, "limit": 1}),
        ),
        call(
            13,
            "strings",
            json!({"binary": b(), "db": d(), "offset": 1, "limit": 1}),
        ),
        call(
            14,
            "strings",
            json!({"binary": Value::String(garbage.clone()), "db": Value::String(garbage_db.clone())}),
        ),
        call(
            15,
            "strings",
            json!({"binary": b(), "db": d(), "pattern": "regex:(["}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 7, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();

    let found: Value = serde_json::from_str(tool_text(by_id[&10])).expect("pattern json");
    assert_eq!(found.as_array().expect("array").len(), 1);
    assert_eq!(found[0]["value"], common::builders::BASIC_STRING);

    let sec: Value = serde_json::from_str(tool_text(by_id[&11])).expect("section json");
    assert_eq!(sec.as_array().expect("array").len(), 1);
    assert_eq!(sec[0]["section"], ".rdata");

    let via_start: Value = serde_json::from_str(tool_text(by_id[&12])).expect("start json");
    let via_offset: Value = serde_json::from_str(tool_text(by_id[&13])).expect("offset json");
    assert_eq!(
        via_start, via_offset,
        "deprecated offset must page like start"
    );

    let noise: Value = serde_json::from_str(tool_text(by_id[&14])).expect("garbage json");
    assert_eq!(noise.as_array().expect("array").len(), 0);

    // A bad regex is a protocol-level error, not a result.
    assert!(by_id[&15].get("error").is_some(), "{:?}", by_id[&15]);
    assert!(by_id[&15].get("result").is_none());
    cleanup(&dir);
}

// X1/A3: MCP `to`/`from` accept hex or decimal interchangeably, `kind`
// is case-insensitive, and results carry the pre-paging total.
#[test]
fn xrefs_hex_equals_decimal_kind_case_insensitive_with_total() {
    let dir = tmpdir("mcp-xrefs-norm");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db = temp_db(&dir, "basic").display().to_string();
    let b = || Value::String(bin.clone());
    let d = || Value::String(db.clone());
    let va = common::builders::BASIC_STRING_VA;
    let hex = format!("{va:#x}");
    let dec = va.to_string();

    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(10, "xrefs", json!({"binary": b(), "db": d(), "to": hex})),
        call(11, "xrefs", json!({"binary": b(), "db": d(), "to": dec})),
        call(
            12,
            "xrefs",
            json!({"binary": b(), "db": d(), "to": hex, "kind": "String"}),
        ),
        call(
            13,
            "xrefs",
            json!({"binary": b(), "db": d(), "to": hex, "kind": "string"}),
        ),
        call(
            14,
            "xrefs",
            json!({"binary": b(), "db": d(), "to": hex, "limit": 1}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 6, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();

    let h: Value = serde_json::from_str(tool_text(by_id[&10])).expect("hex json");
    let n: Value = serde_json::from_str(tool_text(by_id[&11])).expect("dec json");
    assert_eq!(h, n, "hex and decimal must filter identically");
    assert_eq!(h["total"], 4);
    assert_eq!(h["xrefs"].as_array().expect("xrefs array").len(), 4);

    let upper: Value = serde_json::from_str(tool_text(by_id[&12])).expect("kind json");
    let lower: Value = serde_json::from_str(tool_text(by_id[&13])).expect("kind json");
    assert_eq!(upper, lower, "kind case must not matter");
    assert_eq!(upper["total"], 2);

    let paged: Value = serde_json::from_str(tool_text(by_id[&14])).expect("paged json");
    assert_eq!(paged["total"], 4);
    assert_eq!(paged["xrefs"].as_array().expect("xrefs array").len(), 1);
    cleanup(&dir);
}
