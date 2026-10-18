//! em6.27 CLI/MCP parity: annotation getter, range aliases, opt-in
//! envelopes, and the `query_addr` echo.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use common::{cleanup, mcp_bin, temp_db, tmpdir, write_bin, write_fixture};

/// Run the CLI; assert stdout is one valid JSON value.
fn run(args: &[&str]) -> (bool, Value) {
    let out = Command::new(common::binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value)
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
    let text = String::from_utf8(out.stdout).expect("stdout utf-8");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|_| panic!("response line must be JSON: {l:?}"))
        })
        .collect()
}

/// One tool call in a fresh server process; asserts success and returns the
/// parsed JSON text payload.
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
    let result = by_id[&tool_id]
        .get("result")
        .unwrap_or_else(|| panic!("tool must return result: {:?}", by_id[&tool_id]));
    assert_ne!(
        result.get("isError"),
        Some(&Value::Bool(true)),
        "tool error: {:?}",
        by_id[&tool_id]
    );
    serde_json::from_str(result["content"][0]["text"].as_str().expect("text")).expect("tool json")
}

/// `call +0xB; call rax; invalid; nop*8; jmp rax`: two functions, one site
/// of each diagnostic kind (mirrors `tests/mcp.rs`).
fn three_site_blob() -> Vec<u8> {
    let mut b = vec![0xE8, 0x0B, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x06];
    b.extend([0x90; 8]);
    b.extend([0xFF, 0xE0]);
    b
}

// Item 2: MCP `annotation` reads the current annotation without writing.
// Fresh addresses report nulls and create no sidecar; after writes it
// matches the CLI `annotate` read path byte-for-byte.
#[test]
fn annotation_getter_readonly_and_cli_parity() {
    use common::builders::BASIC_ENTRY_VA;
    let dir = tmpdir("parity-annotation");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "a").display().to_string();
    let entry_hex = format!("{BASIC_ENTRY_VA:#x}");

    // Fresh read: nulls, and no sidecar created.
    let v = tool_once(
        10,
        "annotation",
        json!({"binary": bin_s, "db": db, "addr": entry_hex}),
    );
    assert!(v["name"].is_null(), "{v}");
    assert!(v["comment"].is_null(), "{v}");
    assert_eq!(v["addr"], BASIC_ENTRY_VA);
    assert_eq!(v["addr_hex"], entry_hex);
    assert!(
        !std::path::Path::new(&db).exists(),
        "annotation reads never create the sidecar"
    );
    let (ok, from_cli) = run(&["--db", &db, "annotate", &bin_s, &entry_hex]);
    assert!(ok, "{from_cli}");
    assert_eq!(v, from_cli, "MCP and CLI reads must agree");

    // After writes through both surfaces, the getter sees the merged row.
    let (ok, _) = run(&[
        "--db", &db, "annotate", &bin_s, &entry_hex, "--rename", "probe",
    ]);
    assert!(ok);
    let v = tool_once(
        11,
        "comment",
        json!({"binary": bin_s, "db": db, "addr": entry_hex, "comment": "note"}),
    );
    assert_eq!(v["comment"], "note");
    let v = tool_once(
        12,
        "annotation",
        json!({"binary": bin_s, "db": db, "addr": entry_hex}),
    );
    assert_eq!(v["name"], "probe");
    assert_eq!(v["comment"], "note");
    let (ok, from_cli) = run(&["--db", &db, "annotate", &bin_s, &entry_hex]);
    assert!(ok, "{from_cli}");
    assert_eq!(v, from_cli, "MCP and CLI reads must agree");
    cleanup(&dir);
}

// Item 3: range aliases agree with the canonical names on both tools, with
// the documented semantics (inclusive for `functions`, half-open for
// `search_bytes`).
#[test]
fn range_aliases_and_semantics() {
    use common::builders::{BASIC_ENTRY_VA, TEXT_VA};
    let dir = tmpdir("parity-range");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "r").display().to_string();
    let entry_hex = format!("{BASIC_ENTRY_VA:#x}");

    // Inclusive bounds: [entry, entry] keeps the single function.
    let canon = tool_once(
        10,
        "functions",
        json!({"binary": bin_s, "db": db, "range_lo": entry_hex, "range_hi": entry_hex}),
    );
    assert_eq!(canon.as_array().expect("array").len(), 1);
    let alias = tool_once(
        11,
        "functions",
        json!({"binary": bin_s, "db": db, "range_start": entry_hex, "range_end": entry_hex}),
    );
    assert_eq!(
        canon, alias,
        "range_start/range_end must alias range_lo/range_hi"
    );

    // Half-open over match VAs: the 3-byte frame at TEXT_VA is fully
    // inside [TEXT_VA, TEXT_VA+3) but not inside [TEXT_VA+1, TEXT_VA+4).
    let lo = format!("{TEXT_VA:#x}");
    let hi = format!("{:#x}", TEXT_VA + 3);
    let after = format!("{:#x}", TEXT_VA + 1);
    let after_hi = format!("{:#x}", TEXT_VA + 4);
    let canon = tool_once(
        12,
        "search_bytes",
        json!({"binary": bin_s, "db": db, "pattern": "55 89 e5", "range_start": lo, "range_end": hi}),
    );
    assert_eq!(canon["total"], 1);
    assert_eq!(canon["items"][0]["addr"], TEXT_VA);
    let alias = tool_once(
        13,
        "search_bytes",
        json!({"binary": bin_s, "db": db, "pattern": "55 89 e5", "range_lo": lo, "range_hi": hi}),
    );
    assert_eq!(
        canon, alias,
        "range_lo/range_hi must alias range_start/range_end"
    );
    let shifted = tool_once(
        14,
        "search_bytes",
        json!({"binary": bin_s, "db": db, "pattern": "55 89 e5", "range_start": after, "range_end": after_hi}),
    );
    assert_eq!(
        shifted["total"], 0,
        "match starting before lo is not fully inside"
    );
    assert!(
        !std::path::Path::new(&db).exists(),
        "filtered queries never create the sidecar"
    );
    cleanup(&dir);
}

// Items 6+7: the opt-in envelope wraps the same matches with an exact
// total; `functions` envelope rows carry `calls_count` instead of the
// unbounded `calls` array. Legacy defaults stay byte-identical.
#[test]
fn envelope_opt_in_with_compact_calls() {
    let dir = tmpdir("parity-envelope");
    let bin = write_bin(&dir, "three.bin", &three_site_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "e").display().to_string();

    // Legacy defaults: bare arrays, full `calls` target array.
    let (ok, legacy) = run(&["--db", &db, "functions", &bin]);
    assert!(ok, "{legacy}");
    let rows = legacy.as_array().expect("bare array");
    assert_eq!(rows.len(), 2);
    assert!(rows[0].get("calls").is_some(), "{rows:?}");
    assert!(rows[0].get("calls_count").is_none(), "{rows:?}");
    let legacy_mcp = tool_once(10, "functions", json!({"binary": bin, "db": db}));
    assert_eq!(legacy, legacy_mcp);

    // Opt-in envelope: same match set, exact total, compact rows.
    let (ok, env) = run(&["--db", &db, "functions", &bin, "--envelope"]);
    assert!(ok, "{env}");
    assert_eq!(env["protocol"], 1);
    assert_eq!(env["total"], 2);
    assert_eq!(env["offset"], 0);
    assert_eq!(env["items"].as_array().expect("items").len(), 2);
    assert!(env["next_offset"].is_null());
    for item in env["items"].as_array().expect("items") {
        assert!(item.get("calls").is_none(), "{item}");
        assert!(item["calls_count"].is_number(), "{item}");
    }
    // Compact count matches the legacy array length for the same row.
    assert_eq!(
        env["items"][0]["calls_count"],
        legacy[0]["calls"].as_array().expect("calls").len()
    );
    let env_mcp = tool_once(
        11,
        "functions",
        json!({"binary": bin, "db": db, "envelope": true}),
    );
    assert_eq!(env, env_mcp, "CLI and MCP envelopes must agree");

    // Cross-check: `calls_count` of the root equals its depth-1 callees.
    let entry = env["items"][0]["entry"].as_u64().expect("entry");
    let callees = tool_once(
        12,
        "callees",
        json!({"binary": bin, "db": db, "addr": format!("{entry:#x}"), "depth": 1}),
    );
    assert_eq!(
        callees["total"], env["items"][0]["calls_count"],
        "depth-1 callees must match calls_count"
    );

    // paging still works under the envelope; limit 0 reports the total.
    let (ok, page) = run(&["--db", &db, "functions", &bin, "--envelope", "--limit", "1"]);
    assert!(ok, "{page}");
    assert_eq!(page["total"], 2);
    assert_eq!(page["items"].as_array().expect("items").len(), 1);
    assert_eq!(page["next_offset"], 1);
    let (ok, zero) = run(&["--db", &db, "functions", &bin, "--envelope", "--limit", "0"]);
    assert!(ok, "{zero}");
    assert_eq!(zero["total"], 2);
    assert!(zero["items"].as_array().expect("items").is_empty());

    // Filtered envelope: the query total matches the legacy array length.
    let (ok, q) = run(&[
        "--db",
        &db,
        "functions",
        &bin,
        "--query",
        "zzz",
        "--envelope",
    ]);
    assert!(ok, "{q}");
    assert_eq!(q["total"], 0);
    assert!(q["items"].as_array().expect("items").is_empty());
    assert!(q["next_offset"].is_null());

    // Strings envelope: total matches the legacy array, rows identical.
    let (ok, slegacy) = run(&["--db", &db, "strings", &bin]);
    assert!(ok, "{slegacy}");
    let (ok, senv) = run(&["--db", &db, "strings", &bin, "--envelope"]);
    assert!(ok, "{senv}");
    assert_eq!(senv["protocol"], 1);
    assert_eq!(senv["total"], slegacy.as_array().expect("array").len());
    assert_eq!(senv["items"], slegacy);
    let senv_mcp = tool_once(
        13,
        "strings",
        json!({"binary": bin, "db": db, "envelope": true}),
    );
    assert_eq!(senv, senv_mcp, "CLI and MCP envelopes must agree");
    cleanup(&dir);
}

// Item 8: `query_addr` echoes the address the caller passed while `entry`
// stays the canonical function entry.
#[test]
fn query_addr_echo_on_single_function_views() {
    use common::builders::{BASIC_ENTRY_VA, TEXT_VA};
    let dir = tmpdir("parity-query-addr");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "q").display().to_string();
    // Mid-function interior address (sibling byte of the entry block).
    let mid = TEXT_VA + 1;
    let mid_hex = format!("{mid:#x}");
    let entry_hex = format!("{BASIC_ENTRY_VA:#x}");

    for tool in ["cfg", "structure", "pseudo"] {
        let v = tool_once(
            20,
            tool,
            json!({"binary": bin_s, "db": db, "addr": mid_hex}),
        );
        assert_eq!(v["entry"], BASIC_ENTRY_VA, "{tool}: {v}");
        assert_eq!(v["containing_entry"], BASIC_ENTRY_VA, "{tool}: {v}");
        assert_eq!(v["query_addr"], mid, "{tool}: {v}");
        assert_eq!(v["query_addr_hex"], mid_hex, "{tool}: {v}");
        let (ok, from_cli) = run(&["--db", &db, tool, &bin_s, &mid_hex]);
        assert!(ok, "{from_cli}");
        assert_eq!(v, from_cli, "{tool}: CLI and MCP must agree");
        // Canonical entry request echoes the entry itself.
        let v = tool_once(
            21,
            tool,
            json!({"binary": bin_s, "db": db, "addr": entry_hex}),
        );
        assert_eq!(v["query_addr"], BASIC_ENTRY_VA, "{tool}: {v}");
    }
    assert!(
        !std::path::Path::new(&db).exists(),
        "single-function views never create the sidecar"
    );
    cleanup(&dir);
}
