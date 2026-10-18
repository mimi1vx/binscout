//! M6 MCP e2e: spawn `binscout-mcp` over stdio, run the JSON-RPC handshake,
//! list the 33 tools, and call every one against fixtures.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use common::{binscout_bin, cleanup, mcp_bin, temp_db, tmpdir, write_bin, write_fixture};

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

/// One tool call in a fresh server process: handshake plus a single
/// `tools/call`, returning the parsed JSON text payload. Each call reopens
/// the same DB file, so sequential `tool_once` calls prove writes survive a
/// DB reopen.
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
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();
    let text = tool_text(by_id[&tool_id]).to_owned();
    serde_json::from_str(&text).expect("tool json")
}

#[test]
fn handshake_lists_thirty_three_tools() {
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
            "annotation",
            "annotations_export",
            "annotations_import",
            "batch",
            "block_insns",
            "blocks",
            "bytes",
            "callees",
            "callers",
            "cfg",
            "comment",
            "define_func",
            "diagnostics",
            "diff",
            "disasm",
            "flirt_hints",
            "func",
            "functions",
            "headers",
            "ir",
            "ir_coverage",
            "load",
            "project_info",
            "pseudo",
            "rename",
            "search_bytes",
            "sections",
            "slice",
            "stack_strings",
            "stats",
            "strings",
            "structure",
            "symbols",
            "undefine_func",
            "xrefs",
        ],
        "exactly the 35 tools"
    );
    let search = tools
        .iter()
        .find(|t| t["name"] == "search_bytes")
        .expect("search_bytes listed");
    let props = search["inputSchema"]["properties"]
        .as_object()
        .expect("input schema properties");
    for key in [
        "binary",
        "db",
        "raw",
        "pattern",
        "section",
        "range_start",
        "range_end",
        "offset",
        "limit",
    ] {
        assert!(props.contains_key(key), "search_bytes exposes {key}");
    }
    let import = tools
        .iter()
        .find(|t| t["name"] == "annotations_import")
        .expect("annotations_import listed");
    let props = import["inputSchema"]["properties"]
        .as_object()
        .expect("input schema properties");
    for key in ["binary", "db", "raw", "document", "overwrite"] {
        assert!(props.contains_key(key), "annotations_import exposes {key}");
    }
    let export = tools
        .iter()
        .find(|t| t["name"] == "annotations_export")
        .expect("annotations_export listed");
    let props = export["inputSchema"]["properties"]
        .as_object()
        .expect("input schema properties");
    for key in ["binary", "db", "raw"] {
        assert!(props.contains_key(key), "annotations_export exposes {key}");
    }
    let bytes = tools
        .iter()
        .find(|t| t["name"] == "bytes")
        .expect("bytes listed");
    let props = bytes["inputSchema"]["properties"]
        .as_object()
        .expect("input schema properties");
    for key in [
        "binary", "db", "raw", "fat_arch", "addr", "len", "as", "endian",
    ] {
        assert!(props.contains_key(key), "bytes exposes {key}");
    }
    let diff = tools
        .iter()
        .find(|t| t["name"] == "diff")
        .expect("diff listed");
    let props = diff["inputSchema"]["properties"]
        .as_object()
        .expect("input schema properties");
    for key in ["binary_a", "binary_b", "db_a", "db_b", "raw"] {
        assert!(props.contains_key(key), "diff exposes {key}");
    }
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
            23,
            "blocks",
            json!({"binary": b(), "db": d(), "addr": "0x0"}),
        ),
        call(
            24,
            "block_insns",
            json!({"binary": b(), "db": d(), "addr": "0x0", "block": "0x0"}),
        ),
        call(
            13,
            "disasm",
            json!({"binary": b(), "db": d(), "addr": "0x0", "len": 3}),
        ),
        call(
            32,
            "bytes",
            json!({"binary": b(), "db": d(), "addr": "0x0", "len": 3, "as": "u8"}),
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
        call(
            25,
            "blocks",
            json!({"binary": b(), "db": d(), "addr": "0xdead"}),
        ),
        call(
            26,
            "block_insns",
            json!({"binary": b(), "db": d(), "addr": "0x0", "block": "0x1"}),
        ),
        call(27, "diagnostics", json!({"binary": b(), "db": d()})),
        call(28, "flirt_hints", json!({"binary": b(), "db": d()})),
        call(
            30,
            "structure",
            json!({"binary": b(), "db": d(), "addr": "0x0"}),
        ),
        call(
            31,
            "pseudo",
            json!({"binary": b(), "db": d(), "addr": "0x0"}),
        ),
        call(
            29,
            "diff",
            json!({"binary_a": b(), "binary_b": b(), "db_a": d(), "db_b": d()}),
        ),
        call(33, "headers", json!({"binary": b(), "db": d()})),
        call(34, "stack_strings", json!({"binary": b(), "db": d()})),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 26, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();

    let info: Value = serde_json::from_str(tool_text(by_id[&10])).expect("project_info json");
    assert_eq!(info["format"], "raw");

    let headers: Value = serde_json::from_str(tool_text(by_id[&33])).expect("headers json");
    assert_eq!(headers["format"], "raw");
    assert_eq!(headers["md5"].as_str().expect("md5").len(), 32);
    assert_eq!(headers["sha256"].as_str().expect("sha256").len(), 64);
    assert!(headers["pe"].is_null());

    let stack: Value = serde_json::from_str(tool_text(by_id[&34])).expect("stack_strings json");
    assert!(
        stack.as_array().expect("array").is_empty(),
        "clean blob builds no stack strings"
    );

    let funcs: Value = serde_json::from_str(tool_text(by_id[&11])).expect("functions json");
    assert_eq!(funcs.as_array().expect("array").len(), 1);

    // Compact func: counts only, no embedded block/insn arrays.
    let func: Value = serde_json::from_str(tool_text(by_id[&12])).expect("func json");
    assert_eq!(func["entry"], 0);
    assert_eq!(func["blocks"], 1);
    assert_eq!(func["insns"], 3);
    assert_eq!(func["calls"], 0);
    assert!(func.get("containing_entry").is_none(), "{func}");
    assert!(func.get("edges").is_none(), "{func}");

    let blocks: Value = serde_json::from_str(tool_text(by_id[&23])).expect("blocks json");
    assert_eq!(blocks["protocol"], 1);
    assert_eq!(blocks["total"], 1);
    assert_eq!(blocks["items"][0]["start"], 0);
    assert_eq!(blocks["items"][0]["insns"], 3);

    let insns: Value = serde_json::from_str(tool_text(by_id[&24])).expect("block_insns json");
    assert_eq!(insns["protocol"], 1);
    assert_eq!(insns["total"], 3);
    assert_eq!(insns["items"].as_array().expect("items").len(), 3);

    let diags: Value = serde_json::from_str(tool_text(by_id[&27])).expect("diagnostics json");
    assert_eq!(diags["protocol"], 1);
    assert_eq!(diags["total"], 0, "clean blob has no diagnostics");
    assert!(diags["items"].as_array().expect("items").is_empty());
    assert!(diags["next_offset"].is_null());

    let dis: Value = serde_json::from_str(tool_text(by_id[&13])).expect("disasm json");
    assert_eq!(dis["insns"].as_array().expect("envelope insns").len(), 3);
    assert!(dis["error_at"].is_null(), "clean disasm error_at:null");

    let bytes: Value = serde_json::from_str(tool_text(by_id[&32])).expect("bytes json");
    assert_eq!(bytes["addr"], 0);
    assert_eq!(bytes["addr_hex"], "0x0");
    assert_eq!(bytes["file_off"], 0);
    assert!(bytes["section"].is_null(), "{bytes}");
    assert_eq!(bytes["len"], 3);
    assert_eq!(bytes["bytes_hex"], "9090c3");
    assert_eq!(bytes["values"], json!([144, 144, 195]));

    let flirt: Value = serde_json::from_str(tool_text(by_id[&28])).expect("flirt_hints json");
    assert_eq!(flirt["protocol"], 1);
    assert_eq!(flirt["total"], 0, "nop;nop;ret matches no signature");

    let structure: Value = serde_json::from_str(tool_text(by_id[&30])).expect("structure json");
    assert_eq!(structure["entry"], 0);
    assert!(
        structure["structure"]["loops"]
            .as_array()
            .expect("loops")
            .is_empty()
    );
    assert!(
        structure["structure"]["ifs"]
            .as_array()
            .expect("ifs")
            .is_empty()
    );
    assert!(
        structure["structure"]["warning"]
            .as_str()
            .expect("warning")
            .contains("approximate"),
        "{structure}"
    );

    let pseudo: Value = serde_json::from_str(tool_text(by_id[&31])).expect("pseudo json");
    assert_eq!(pseudo["entry"], 0);
    assert!(
        pseudo["pseudo"]["warning"]
            .as_str()
            .expect("warning")
            .contains("approximate"),
        "{pseudo}"
    );
    assert_eq!(pseudo["pseudo"]["lines"][2]["text"], "return;");

    // Self-diff over one binary: the single function matches itself.
    let diff: Value = serde_json::from_str(tool_text(by_id[&29])).expect("diff json");
    assert_eq!(diff["summary"]["matched"], 1);
    assert_eq!(diff["summary"]["changed"], 0);
    assert_eq!(diff["summary"]["added"], 0);
    assert_eq!(diff["summary"]["removed"], 0);
    assert_eq!(diff["summary"]["truncated"], false);

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
    // Unknown function/block through the paged views error the same way.
    assert!(by_id[&25].get("error").is_some(), "{:?}", by_id[&25]);
    assert!(by_id[&25].get("result").is_none());
    assert!(by_id[&26].get("error").is_some(), "{:?}", by_id[&26]);
    assert!(by_id[&26].get("result").is_none());

    assert_eq!(
        std::fs::read(dir.join("m.bin")).expect("reread"),
        fixture,
        "binary untouched"
    );
    cleanup(&dir);
}

// `define_func` materializes a function and `undefine_func` retracts it.
// Sequential `tool_once` sessions (one server process each) keep this
// deterministic and prove the seeds survive a DB reopen.
#[test]
fn define_undefine_round_trip() {
    let dir = tmpdir("mcp-define");
    let fixture = std::fs::read("tests/fixtures/raw-x64.bin").expect("fixture");
    let bin = write_bin(&dir, "m.bin", &fixture).display().to_string();
    let db = temp_db(&dir, "m").display().to_string();

    let v = tool_once(
        10,
        "define_func",
        json!({"binary": bin, "db": db, "addr": "0x2"}),
    );
    assert_eq!(v["addr"], 2);
    assert_eq!(v["addr_hex"], "0x2");
    assert!(v["mode"].is_null(), "{v}");
    assert_eq!(v["excluded"], false);

    let func = tool_once(11, "func", json!({"binary": bin, "db": db, "addr": "0x2"}));
    assert_eq!(func["entry"], 2);
    assert_eq!(func["reasons"], json!(["user"]));

    let v = tool_once(
        12,
        "undefine_func",
        json!({"binary": bin, "db": db, "addr": "0x2"}),
    );
    assert_eq!(v["addr"], 2);
    assert_eq!(v["excluded"], true);

    let funcs = tool_once(13, "functions", json!({"binary": bin, "db": db}));
    assert_eq!(funcs.as_array().expect("array").len(), 1);

    assert_eq!(
        std::fs::read(dir.join("m.bin")).expect("reread"),
        fixture,
        "binary untouched"
    );
    cleanup(&dir);
}

// O3/A11: MCP `stats` reports db_size plus the project_info counts.
#[test]
fn stats_reports_db_size_and_counts() {
    let dir = tmpdir("mcp-stats");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db = temp_db(&dir, "stats").display().to_string();

    let v = tool_once(10, "stats", json!({"binary": bin, "db": db}));
    // No save yet: db_size 0, counts still report.
    assert_eq!(v["db_size"], 0);
    assert_eq!(v["functions"], 1);

    let info = tool_once(11, "project_info", json!({"binary": bin, "db": db}));
    let v = tool_once(12, "stats", json!({"binary": bin, "db": db}));
    for k in ["functions", "blocks", "insns", "xrefs", "strings"] {
        assert_eq!(v[k], info[k], "stats {k} matches project_info");
    }

    // A rename persists the sidecar; stats then matches the file on disk.
    let entry_hex = format!("{:#x}", common::builders::BASIC_ENTRY_VA);
    tool_once(
        13,
        "rename",
        json!({"binary": bin, "db": db, "addr": entry_hex, "name": "stats_probe"}),
    );
    let v = tool_once(14, "stats", json!({"binary": bin, "db": db}));
    let file_size = std::fs::metadata(&db).expect("sidecar").len();
    assert!(file_size > 0);
    assert_eq!(v["db_size"], file_size);
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
    // reporting not-found. Compact func carries counts, no snap twin.
    let f: Value = serde_json::from_str(tool_text(by_id[&14])).expect("func json");
    assert_eq!(f["entry"], 0x401000);
    assert_eq!(f["entry_hex"], "0x401000");
    assert!(f.get("containing_entry").is_none(), "{f}");
    assert!(f["blocks"].is_number() && f["insns"].is_number(), "{f}");

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
fn le_project_info_reports_le_format() {
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
    let text = tool_text(resp);
    let info: Value = serde_json::from_str(text).expect("project_info json");
    assert_eq!(info["format"], "le", "{resp}");
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

// O2/A10: annotation round-trip lock-in over MCP. Rename and comment share
// one function entry so each tool's `annotation_json` response point-queries
// the other's field (there is no dedicated annotate-read tool). Every step
// runs in a fresh server process, so each read proves the prior write
// survived a DB reopen; clearing restores nulls.
#[test]
fn annotate_round_trip_rename_comment_reopen_clear() {
    let dir = tmpdir("mcp-annotate");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db = temp_db(&dir, "annotate").display().to_string();
    let entry = common::builders::BASIC_ENTRY_VA;
    let entry_hex = format!("{entry:#x}");

    // Rename: addr->name, response is the immediate point-query.
    let v = tool_once(
        10,
        "rename",
        json!({"binary": bin, "db": db, "addr": entry_hex, "name": "mcp_renamed"}),
    );
    assert_eq!(v["name"], "mcp_renamed");
    assert!(v["comment"].is_null());

    // Comment the same addr in a fresh session: the response still carries
    // the rename, proving it survived a reopen.
    let v = tool_once(
        11,
        "comment",
        json!({"binary": bin, "db": db, "addr": entry_hex, "comment": "mcp note"}),
    );
    assert_eq!(v["comment"], "mcp note");
    assert_eq!(v["name"], "mcp_renamed", "rename must survive reopen");

    // Idempotent rename in a fresh session: proves the comment survived.
    let v = tool_once(
        12,
        "rename",
        json!({"binary": bin, "db": db, "addr": entry_hex, "name": "mcp_renamed"}),
    );
    assert_eq!(v["name"], "mcp_renamed");
    assert_eq!(v["comment"], "mcp note", "comment must survive reopen");

    // The rename resolves through listings after a reopen.
    let v = tool_once(
        13,
        "functions",
        json!({"binary": bin, "db": db, "query": "mcp_renamed"}),
    );
    let rows = v.as_array().expect("functions array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["entry"].as_u64(), Some(entry));
    assert_eq!(rows[0]["name"], "mcp_renamed");

    // Clear the rename: name nulls, comment remains.
    let v = tool_once(
        14,
        "rename",
        json!({"binary": bin, "db": db, "addr": entry_hex, "name": ""}),
    );
    assert!(v["name"].is_null());
    assert_eq!(v["comment"], "mcp note");

    // Clear the comment: both null.
    let v = tool_once(
        15,
        "comment",
        json!({"binary": bin, "db": db, "addr": entry_hex, "comment": ""}),
    );
    assert!(v["name"].is_null() && v["comment"].is_null());

    // Cleared state survives a reopen: no query hit, name falls back to the
    // export.
    let v = tool_once(
        16,
        "functions",
        json!({"binary": bin, "db": db, "query": "mcp_renamed"}),
    );
    assert_eq!(v.as_array().expect("array").len(), 0);
    let v = tool_once(
        17,
        "func",
        json!({"binary": bin, "db": db, "addr": entry_hex}),
    );
    assert_eq!(v["entry"].as_u64(), Some(entry));
    assert_eq!(v["name"], common::builders::BASIC_EXPORT);
    cleanup(&dir);
}

fn mcp_raw_bytes(arch: &str) -> Vec<u8> {
    match arch {
        "x86_64" | "x86_32" => vec![0x90, 0x90, 0xC3],
        "aarch64" => vec![0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6],
        "arm32" => vec![0x01, 0x00, 0xA0, 0xE1, 0x1E, 0xFF, 0x2F, 0xE1],
        "thumb" => vec![0x00, 0xBF, 0x70, 0x47],
        _ => unreachable!("test arch"),
    }
}

fn mcp_raw_base(arch: &str) -> &'static str {
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
fn raw_mapping_reports_across_arches() {
    for arch in ["x86_64", "x86_32", "aarch64", "arm32", "thumb"] {
        let dir = tmpdir("mcp-raw-parity");
        let bin = write_bin(&dir, "r.bin", &mcp_raw_bytes(arch))
            .display()
            .to_string();
        let db = temp_db(&dir, "r").display().to_string();
        let base = mcp_raw_base(arch);

        let info = tool_once(
            10,
            "project_info",
            json!({"binary": bin, "db": db, "raw": {"arch": arch, "base": base}}),
        );
        assert_eq!(info["arch"], arch, "{arch}");
        assert_eq!(info["format"], "raw", "{arch}");
        assert_eq!(info["mode"], "raw", "{arch}");
        assert_eq!(info["functions"], 1, "{arch}");

        let funcs = tool_once(
            11,
            "functions",
            json!({"binary": bin, "db": db, "raw": {"arch": arch, "base": base}}),
        );
        assert_eq!(funcs.as_array().expect("array").len(), 1, "{arch}");

        let stats = tool_once(
            12,
            "stats",
            json!({"binary": bin, "db": db, "raw": {"arch": arch, "base": base}}),
        );
        assert_eq!(stats["mode"], "raw", "{arch}");
        assert_eq!(stats["arch"], arch, "{arch}");
        cleanup(&dir);
    }
}

#[test]
fn raw_errors_are_tool_errors() {
    let dir = tmpdir("mcp-raw-errors");
    let bin = write_bin(&dir, "r.bin", &[0x90, 0x90, 0xC3])
        .display()
        .to_string();
    let db = temp_db(&dir, "r").display().to_string();

    // Missing base in raw mode.
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
            "project_info",
            json!({"binary": bin, "db": db, "raw": {"arch": "x86_64"}}),
        ),
        call(
            11,
            "project_info",
            json!({"binary": bin, "db": db, "raw": {"arch": "mips", "base": "0x1000"}}),
        ),
        call(
            12,
            "project_info",
            json!({"binary": bin, "db": db, "raw": {"arch": "aarch64", "base": "0x10000", "entry": "0x10001"}}),
        ),
        call(
            13,
            "project_info",
            json!({"binary": bin, "db": db, "raw": {"arch": "x86_64", "base": "0x1000", "entry": "0x2000"}}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 5, "{resps:?}");
    for resp in resps.iter().skip(1) {
        assert!(
            resp.get("error").is_some(),
            "raw misuse must error: {resp:?}"
        );
        assert!(resp.get("result").is_none());
    }
    cleanup(&dir);
}

#[test]
fn raw_reads_do_not_write_sidecars() {
    let dir = tmpdir("mcp-raw-no-save");
    let bin_path = write_bin(&dir, "r.bin", &[0x90, 0x90, 0xC3]);
    let bin = bin_path.display().to_string();
    let db_path = temp_db(&dir, "fresh");
    let db = db_path.display().to_string();

    let funcs = tool_once(
        10,
        "functions",
        json!({"binary": bin, "db": db, "raw": {"arch": "x86_64", "base": "0x1000"}}),
    );
    assert_eq!(funcs.as_array().expect("array").len(), 1);
    assert!(!db_path.exists(), "raw reads never create the sidecar");
    cleanup(&dir);
}

/// `nop` x 1500, then `jmp +0` x 1200 (each targeting the next), then
/// `ret`: one function with 1201 blocks / 2701 instructions, past the
/// 1024-row page cap. Mirrors `tests/function_pages.rs` and the CLI
/// bounded-inspection test.
fn big_blob() -> Vec<u8> {
    let mut b = vec![0x90u8; 1500];
    for _ in 0..1200 {
        b.extend([0xEB, 0x00]);
    }
    b.push(0xC3);
    b
}

// Bounded function inspection over MCP: compact `func` plus paged
// `blocks`/`block_insns` on the 1201-block synthetic function. Mirrors
// the CLI coverage: no instruction arrays in `func`, envelope shape and
// row caps on pages, byte-size sanity, and matching counts with the CLI.
#[test]
fn bounded_func_and_pages_stay_capped() {
    let dir = tmpdir("mcp-func-bounded");
    let bin = write_bin(&dir, "big.bin", &big_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "big").display().to_string();

    // Compact func: counts only; the text payload stays small for a
    // 2701-instruction function.
    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(10, "func", json!({"binary": bin, "db": db, "addr": "0x0"})),
        call(
            11,
            "blocks",
            json!({"binary": bin, "db": db, "addr": "0x0", "limit": 5000}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 3, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();
    let raw_text = tool_text(by_id[&10]).to_owned();
    assert!(
        raw_text.len() < 1024,
        "compact func must stay small, got {} bytes",
        raw_text.len()
    );
    let func: Value = serde_json::from_str(&raw_text).expect("func json");
    assert_eq!(func["blocks"], 1201);
    assert_eq!(func["insns"], 2701);
    assert_eq!(func["calls"], 0);
    assert!(func.get("containing_entry").is_none(), "{func}");

    let blocks: Value = serde_json::from_str(tool_text(by_id[&11])).expect("blocks json");
    assert_eq!(blocks["protocol"], 1);
    assert_eq!(blocks["total"], 1201);
    assert_eq!(blocks["limit"], 1024);
    assert_eq!(blocks["items"].as_array().expect("items").len(), 1024);
    assert_eq!(blocks["next_offset"], 1024);

    // Successive pages rebuild the full block order; the opening block's
    // 1501 instructions page under the same cap.
    let first = blocks["items"][0]["start"].as_u64().expect("start");
    let mut starts: Vec<u64> = Vec::new();
    let mut offset = 0usize;
    loop {
        let page = tool_once(
            12,
            "blocks",
            json!({"binary": bin, "db": db, "addr": "0x0", "offset": offset, "limit": 100}),
        );
        assert_eq!(page["total"], 1201);
        assert_eq!(page["offset"], offset);
        starts.extend(
            page["items"]
                .as_array()
                .expect("items")
                .iter()
                .map(|b| b["start"].as_u64().expect("start")),
        );
        match page["next_offset"].as_u64() {
            Some(next) => offset = next as usize,
            None => break,
        }
    }
    assert_eq!(starts.len(), 1201);
    assert_eq!(starts[0], first);
    assert!(starts.windows(2).all(|w| w[0] < w[1]), "ordered, no gaps");

    let page = tool_once(
        13,
        "block_insns",
        json!({"binary": bin, "db": db, "addr": "0x0", "block": first.to_string(), "limit": 5000}),
    );
    assert_eq!(page["total"], 1501);
    assert_eq!(page["limit"], 1024);
    assert_eq!(page["items"].as_array().expect("items").len(), 1024);

    // Zero limit and past-end offsets are normal empty pages, not errors.
    let page = tool_once(
        14,
        "blocks",
        json!({"binary": bin, "db": db, "addr": "0x0", "limit": 0}),
    );
    assert_eq!(page["total"], 1201);
    assert_eq!(page["limit"], 0);
    assert!(page["items"].as_array().expect("items").is_empty());
    assert!(page["next_offset"].is_null());
    cleanup(&dir);
}

#[test]
fn ir_coverage_arch_only_and_range() {
    // Arch-only: no binary opened, no range section.
    let v = tool_once(10, "ir_coverage", json!({"arch": "aarch64"}));
    assert_eq!(v["arch"], "aarch64");
    assert_eq!(v["families"].as_array().expect("families").len(), 19);
    assert_eq!(v["fallback"]["op"], "Nop");
    assert!(v.get("range").is_none(), "{v}");

    // Range: per-range counts from actual lifts over a raw fallback blob
    // (cpuid x2 unmapped, nop + ret lifted).
    let dir = tmpdir("mcp-ir-coverage");
    let bin = write_bin(&dir, "mixed.bin", &[0x0F, 0xA2, 0x0F, 0xA2, 0x90, 0xC3])
        .display()
        .to_string();
    let db = temp_db(&dir, "mixed").display().to_string();
    let v = tool_once(
        11,
        "ir_coverage",
        json!({"arch": "x86_64", "binary": bin.clone(), "db": db.clone(), "addr": "0", "len": 6}),
    );
    assert_eq!(v["arch"], "x86_64");
    assert_eq!(v["range"]["decoded"], 4);
    assert_eq!(v["range"]["lifted"], 2);
    assert_eq!(v["range"]["unlifted"], 2);
    assert_eq!(v["range"]["unlifted_mnemonics"][0]["mnemonic"], "cpuid");
    cleanup(&dir);

    // Partial ranges, arch mismatches, and unknown arches are tool errors.
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
            "ir_coverage",
            json!({"arch": "x86_64", "binary": bin.clone()}),
        ),
        call(
            11,
            "ir_coverage",
            json!({"arch": "aarch64", "binary": bin, "db": db, "addr": "0", "len": 6}),
        ),
        call(12, "ir_coverage", json!({"arch": "mips"})),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 4, "{resps:?}");
    for resp in resps.iter().skip(1) {
        assert!(resp.get("error").is_some(), "must error: {resp:?}");
        assert!(resp.get("result").is_none());
    }
    cleanup(&dir);
}

/// Run the CLI; assert stdout is one valid JSON value.
fn cli(args: &[&str]) -> (bool, Value) {
    let out = Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value)
}

/// `call +0xB; call rax; invalid; nop*8; jmp rax`: two functions, one
/// site of each diagnostic kind (raw fallback maps at base 0, so the
/// relative call lands on the second function). Mirrors
/// `tests/diagnostics.rs` and `tests/cli.rs`.
fn three_site_blob() -> Vec<u8> {
    let mut b = vec![0xE8, 0x0B, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x06];
    b.extend([0x90; 8]);
    b.extend([0xFF, 0xE0]);
    b
}

// §7 adapter parity: CLI `diagnostics` and MCP `diagnostics` return
// identical records over the same blob, filters, and pages; invalid
// filters are errors on both surfaces; `func`/`project_info` carry the
// new provenance fields; queries never write a sidecar.
#[test]
fn diagnostics_filters_and_cli_parity() {
    let dir = tmpdir("mcp-diagnostics");
    let bin = write_bin(&dir, "three.bin", &three_site_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "three").display().to_string();

    // Same filters through both surfaces must agree byte-for-byte.
    for (cli_args, mcp_args) in [
        (
            vec!["diagnostics".to_string(), bin.clone()],
            json!({"binary": bin, "db": db}),
        ),
        (
            vec![
                "diagnostics".to_string(),
                bin.clone(),
                "--kind".to_string(),
                "decode-failure".to_string(),
            ],
            json!({"binary": bin, "db": db, "kind": "decode-failure"}),
        ),
        (
            vec![
                "diagnostics".to_string(),
                bin.clone(),
                "--func".to_string(),
                "0x0".to_string(),
            ],
            json!({"binary": bin, "db": db, "func": "0x0"}),
        ),
        (
            vec![
                "diagnostics".to_string(),
                bin.clone(),
                "--offset".to_string(),
                "1".to_string(),
                "--limit".to_string(),
                "1".to_string(),
            ],
            json!({"binary": bin, "db": db, "offset": 1, "limit": 1}),
        ),
    ] {
        let mut full: Vec<String> = vec!["--db".to_string(), db.clone()];
        full.extend(cli_args);
        let refs: Vec<&str> = full.iter().map(String::as_str).collect();
        let (ok, from_cli) = cli(&refs);
        assert!(ok, "{from_cli}");
        let id = 10;
        let from_mcp = tool_once(id, "diagnostics", mcp_args);
        assert_eq!(
            from_cli, from_mcp,
            "CLI and MCP must return identical records"
        );
    }

    // Filtered envelope shape through MCP.
    let v = tool_once(
        11,
        "diagnostics",
        json!({"binary": bin, "db": db, "kind": "unresolved-indirect-call"}),
    );
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 1);
    assert_eq!(v["items"][0]["addr"], 0x5);
    assert_eq!(v["items"][0]["func"], 0x0);
    assert_eq!(v["items"][0]["kind"], "unresolved-indirect-call");

    // `func` rows carry reasons and `project_info` the totals.
    let f = tool_once(12, "func", json!({"binary": bin, "db": db, "addr": "0x10"}));
    assert_eq!(f["reasons"], json!(["direct-call"]));
    let info = tool_once(13, "project_info", json!({"binary": bin, "db": db}));
    assert_eq!(info["diagnostics"], 3);
    assert_eq!(info["diagnostics_truncated"], false);
    assert_eq!(info["diagnostics_omitted"], 0);
    assert_eq!(
        info["analysis_revision"],
        binscout::analysis::ANALYSIS_REVISION
    );

    // Invalid kind, unparseable func, and gap func are tool errors.
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
            "diagnostics",
            json!({"binary": bin, "db": db, "kind": "nope"}),
        ),
        call(
            21,
            "diagnostics",
            json!({"binary": bin, "db": db, "func": "zz"}),
        ),
        call(
            22,
            "diagnostics",
            json!({"binary": bin, "db": db, "func": "0x7"}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 4, "{resps:?}");
    for resp in resps.iter().skip(1) {
        assert!(resp.get("error").is_some(), "must error: {resp:?}");
        assert!(resp.get("result").is_none());
    }

    assert!(
        !std::path::Path::new(&db).exists(),
        "diagnostics queries never create the sidecar"
    );
    cleanup(&dir);
}
// `search_bytes` MCP: PE + raw parity with the CLI, filters, documented
// errors, and no-sidecar reads.
#[test]
fn search_bytes_parity_filters_and_errors() {
    use common::builders::TEXT_VA;
    let dir = tmpdir("mcp-search-bytes");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db_path = temp_db(&dir, "sb");
    let db = db_path.display().to_string();

    // PE parity: literal frame setup at the `.text` base.
    let page = tool_once(
        10,
        "search_bytes",
        json!({"binary": bin, "db": db, "pattern": "55 89 e5"}),
    );
    assert_eq!(page["protocol"], 1);
    assert_eq!(page["total"], 1);
    assert_eq!(page["items"][0]["addr"], TEXT_VA);
    assert_eq!(page["items"][0]["addr_hex"], "0x401000");
    assert_eq!(page["items"][0]["section"], ".text");
    assert_eq!(page["items"][0]["len"], 3);

    // Wildcard + section + range filters in one session shape.
    let page = tool_once(
        11,
        "search_bytes",
        json!({"binary": bin, "db": db, "pattern": "68 ?? ?? ?? ??"}),
    );
    assert_eq!(page["total"], 2);
    let page = tool_once(
        12,
        "search_bytes",
        json!({"binary": bin, "db": db, "pattern": "53 41 56 45", "section": ".rdata"}),
    );
    assert_eq!(page["total"], 1);
    let page = tool_once(
        13,
        "search_bytes",
        json!({"binary": bin, "db": db, "pattern": "55 89 e5", "range_start": "0x401000", "range_end": "0x401003"}),
    );
    assert_eq!(page["total"], 1);
    let page = tool_once(
        14,
        "search_bytes",
        json!({"binary": bin, "db": db, "pattern": "55 89 e5", "range_start": "0x401000", "range_end": "0x401002"}),
    );
    assert_eq!(page["total"], 0);

    // Raw parity under an explicit mapping.
    let raw = write_bin(&dir, "r.bin", &[0x90, 0x90, 0x90, 0xC3, 0x90, 0x90])
        .display()
        .to_string();
    let page = tool_once(
        15,
        "search_bytes",
        json!({"binary": raw, "db": db, "raw": {"arch": "x86_64", "base": "0x1000"}, "pattern": "90 90"}),
    );
    assert_eq!(page["total"], 3);
    assert_eq!(page["items"][0]["addr"], 0x1000);
    assert_eq!(page["items"][0]["file_off"], 0);
    assert!(page["items"][0]["section"].is_null(), "{page}");

    assert!(
        !db_path.exists(),
        "repeated queries never create the sidecar"
    );

    // Documented failures are protocol-level errors, never results.
    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(
            30,
            "search_bytes",
            json!({"binary": bin, "db": db, "pattern": "zz"}),
        ),
        call(
            31,
            "search_bytes",
            json!({"binary": bin, "db": db, "pattern": "??"}),
        ),
        call(
            32,
            "search_bytes",
            json!({"binary": bin, "db": db, "pattern": "90", "section": "nope"}),
        ),
        call(
            33,
            "search_bytes",
            json!({"binary": bin, "db": db, "pattern": "90", "range_start": "0x401000"}),
        ),
        call(
            34,
            "search_bytes",
            json!({"binary": bin, "db": db, "pattern": "55 89 e5", "range_start": "0x401000", "range_end": "0x401000"}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 6, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();
    for id in [30, 31, 32, 33, 34] {
        assert!(by_id[&id].get("error").is_some(), "{:?}", by_id[&id]);
        assert!(by_id[&id].get("result").is_none());
    }
    assert!(!db_path.exists(), "failed queries never create the sidecar");
    cleanup(&dir);
}

#[test]
fn annotations_export_import_parity_and_atomicity() {
    use common::builders::{BASIC_ENTRY_VA, BASIC_STRING_VA};
    let dir = tmpdir("mcp-annotations");
    let fixture = common::fixture_bytes("pe32-basic.exe");
    let bin = write_bin(&dir, "a.exe", &fixture).display().to_string();
    let db_a = temp_db(&dir, "a").display().to_string();
    let db_b = temp_db(&dir, "b").display().to_string();
    let entry_hex = format!("{BASIC_ENTRY_VA:#x}");
    let string_hex = format!("{BASIC_STRING_VA:#x}");

    // Seed through the interface; each call reopens the same DB file.
    tool_once(
        10,
        "rename",
        json!({"binary": bin, "db": db_a, "addr": entry_hex, "name": "ported_entry"}),
    );
    tool_once(
        11,
        "comment",
        json!({"binary": bin, "db": db_a, "addr": string_hex, "comment": "ported note"}),
    );

    // Export returns the portable document; CLI parity on the same DB.
    let doc = tool_once(12, "annotations_export", json!({"binary": bin, "db": db_a}));
    assert_eq!(doc["revision"], 1);
    assert_eq!(doc["sha256"].as_str().expect("sha256").len(), 64);
    let rows = doc["annotations"].as_array().expect("rows");
    assert_eq!(rows.len(), 2);
    assert!(
        rows[0]["addr"].as_u64() < rows[1]["addr"].as_u64(),
        "rows sorted: {doc}"
    );
    let (ok, cli_doc) = cli(&["--db", &db_a, "annotations-export", &bin]);
    assert!(ok, "{cli_doc}");
    assert_eq!(doc, cli_doc, "MCP export matches CLI export");

    // Export alone never creates a sidecar.
    let fresh = temp_db(&dir, "fresh").display().to_string();
    let empty = tool_once(
        13,
        "annotations_export",
        json!({"binary": bin, "db": fresh}),
    );
    assert_eq!(empty["annotations"].as_array().expect("rows").len(), 0);
    assert!(
        !std::path::Path::new(&fresh).exists(),
        "export never creates the sidecar"
    );

    // Import into a fresh DB; re-export proves equivalence.
    let summary = tool_once(
        14,
        "annotations_import",
        json!({"binary": bin, "db": db_b, "document": doc.to_string()}),
    );
    assert_eq!(summary["rows"], 2);
    assert_eq!(summary["changed"], 2);
    let doc2 = tool_once(15, "annotations_export", json!({"binary": bin, "db": db_b}));
    assert_eq!(doc, doc2, "fresh-DB import reproduces the document");
    let summary = tool_once(
        16,
        "annotations_import",
        json!({"binary": bin, "db": db_b, "document": doc.to_string()}),
    );
    assert_eq!(summary["changed"], 0, "re-import is idempotent");

    // Documented failures are protocol-level errors, never results.
    // `Invalid` (malformed, conflict, duplicate) is `invalid_params`
    // (-32602); `Storage`/`NotFound`/`Limit` (identity, mapping, unknown
    // rename, oversize) is a tool error (-32603). Every failure must
    // leave the target DB untouched.
    let mut conflict = doc.clone();
    for row in conflict["annotations"].as_array_mut().expect("rows") {
        if row["addr"].as_u64() == Some(BASIC_ENTRY_VA) {
            row["rename"] = "other_name".into();
        }
    }
    let mut duplicate = doc.clone();
    let first = duplicate["annotations"].as_array().expect("rows")[0].clone();
    duplicate["annotations"]
        .as_array_mut()
        .expect("rows")
        .push(first);
    let mut ghost = doc.clone();
    ghost["annotations"]
        .as_array_mut()
        .expect("rows")
        .push(serde_json::json!({"addr": 0xdead_beefu64, "rename": "ghost"}));
    let mut bad_sha = doc.clone();
    bad_sha["sha256"] = "00".repeat(32).into();
    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(
            30,
            "annotations_import",
            json!({"binary": bin, "db": db_b, "document": "{not json"}),
        ),
        call(
            31,
            "annotations_import",
            json!({"binary": bin, "db": db_b, "document": conflict.to_string()}),
        ),
        call(
            32,
            "annotations_import",
            json!({"binary": bin, "db": db_b, "document": duplicate.to_string()}),
        ),
        call(
            33,
            "annotations_import",
            json!({"binary": bin, "db": db_b, "document": ghost.to_string()}),
        ),
        call(
            34,
            "annotations_import",
            json!({"binary": bin, "db": db_b, "document": bad_sha.to_string()}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 6, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();
    for id in [30u64, 31, 32] {
        assert_eq!(by_id[&id]["error"]["code"], -32602, "{:?}", by_id[&id]);
        assert!(by_id[&id].get("result").is_none());
    }
    for id in [33u64, 34] {
        assert_eq!(by_id[&id]["error"]["code"], -32603, "{:?}", by_id[&id]);
        assert!(by_id[&id].get("result").is_none());
    }
    let doc_after = tool_once(17, "annotations_export", json!({"binary": bin, "db": db_b}));
    assert_eq!(doc, doc_after, "failed imports write nothing");

    // Same conflict with overwrite: supplied rename wins, comment kept.
    let summary = tool_once(
        18,
        "annotations_import",
        json!({"binary": bin, "db": db_b, "document": conflict.to_string(), "overwrite": true}),
    );
    assert_eq!(summary["changed"], 1);
    let renamed = tool_once(
        19,
        "func",
        json!({"binary": bin, "db": db_b, "addr": entry_hex}),
    );
    assert_eq!(renamed["name"], "other_name");

    // Mapping mismatch under an explicit raw mapping: tool error, no sidecar.
    let db_c = temp_db(&dir, "c").display().to_string();
    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(
            40,
            "annotations_import",
            json!({"binary": bin, "db": db_c, "raw": {"arch": "x86_64", "base": "0x0"}, "document": doc.to_string()}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    assert_eq!(resps[1]["error"]["code"], -32603, "{:?}", resps[1]);
    assert!(
        resps[1]["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("mapping mismatch")),
        "mapping mismatch message: {:?}",
        resps[1]
    );
    assert!(
        !std::path::Path::new(&db_c).exists(),
        "failed import writes nothing"
    );

    // Oversized document: the transport materializes the full `document`
    // string before validation (residual allocation risk documented on the
    // tool), but the core 16 MiB cap still rejects it with no write.
    let db_d = temp_db(&dir, "d").display().to_string();
    let huge = "x".repeat(binscout::annotations::MAX_TRANSFER_BYTES + 1);
    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(
            50,
            "annotations_import",
            json!({"binary": bin, "db": db_d, "document": huge}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    assert_eq!(
        resps[1]["error"]["code"],
        -32603,
        "{:?}",
        resps[1].get("error").map(|e| &e["code"])
    );
    assert!(
        !std::path::Path::new(&db_d).exists(),
        "rejected input writes nothing"
    );

    assert_eq!(
        std::fs::read(dir.join("a.exe")).expect("reread"),
        fixture,
        "binary untouched"
    );
    cleanup(&dir);
}
