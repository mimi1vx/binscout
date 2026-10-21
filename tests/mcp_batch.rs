//! MCP `batch` e2e: one envelope opens the binary once, ops run in order
//! and return `{"results": [{"ok": ...} | {"error": ...}]}`.

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

/// One tool call in a fresh server process, returning the parsed JSON text
/// payload.
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

fn op(tool: &str, params: Value) -> Value {
    json!({"tool": tool, "params": params})
}

// The motivating loop (func/cfg/pseudo/xrefs) runs over one open: values
// match the single-tool calls, a failing op keeps its position, and later
// ops still run.
#[test]
fn batch_fan_out_matches_single_calls_with_ordered_errors() {
    let dir = tmpdir("mcp-batch-fanout");
    let bin = write_bin(&dir, "m.bin", &[0x90, 0x90, 0xC3])
        .display()
        .to_string();
    let db_path = temp_db(&dir, "m");
    let db = db_path.display().to_string();
    let b = || Value::String(bin.clone());
    let d = || Value::String(db.clone());

    let ops = vec![
        op("project_info", json!({})),
        op("func", json!({"addr": "0x0"})),
        op("cfg", json!({"addr": "0x0"})),
        op("pseudo", json!({"addr": "0x0"})),
        op("xrefs", json!({})),
        op("func", json!({"addr": "0xdead"})),
        op("strings", json!({})),
        op("stack_strings", json!({})),
    ];
    let batch = tool_once(10, "batch", json!({"binary": b(), "db": d(), "ops": ops}));
    let results = batch["results"].as_array().expect("results array");
    assert_eq!(results.len(), 8);
    for (i, r) in results.iter().enumerate() {
        if i == 5 {
            assert!(
                r["error"].as_str().is_some_and(|m| m.contains("not found")),
                "unknown func is a per-op error: {r}"
            );
        } else {
            assert!(r.get("ok").is_some(), "op {i} must succeed: {r}");
            assert!(r.get("error").is_none(), "op {i}: {r}");
        }
    }

    // Same queries through the single tools agree exactly.
    let singles = [
        tool_once(11, "project_info", json!({"binary": b(), "db": d()})),
        tool_once(12, "func", json!({"binary": b(), "db": d(), "addr": "0x0"})),
        tool_once(13, "cfg", json!({"binary": b(), "db": d(), "addr": "0x0"})),
        tool_once(
            14,
            "pseudo",
            json!({"binary": b(), "db": d(), "addr": "0x0"}),
        ),
        tool_once(15, "xrefs", json!({"binary": b(), "db": d()})),
        tool_once(16, "strings", json!({"binary": b(), "db": d()})),
        tool_once(17, "stack_strings", json!({"binary": b(), "db": d()})),
    ];
    for (i, single) in singles.iter().enumerate() {
        let at = if i < 5 { i } else { i + 1 };
        assert_eq!(
            &results[at]["ok"], single,
            "batch op {at} matches single call"
        );
    }

    assert!(!db_path.exists(), "batch reads never create the sidecar");
    assert_eq!(
        std::fs::read(dir.join("m.bin")).expect("reread"),
        [0x90, 0x90, 0xC3],
        "binary untouched"
    );
    cleanup(&dir);
}

// Writes stay explicit: every mutating tool, the two-binary diff, nesting,
// unknown names, and smuggled envelope keys are per-op errors, never values.
#[test]
fn batch_rejects_writes_diff_and_unknown() {
    let dir = tmpdir("mcp-batch-reject");
    let bin = write_bin(&dir, "m.bin", &[0x90, 0x90, 0xC3])
        .display()
        .to_string();
    let db_path = temp_db(&dir, "m");
    let db = db_path.display().to_string();

    let ops = vec![
        op("rename", json!({"addr": "0x0", "name": "x"})),
        op("comment", json!({"addr": "0x0", "comment": "x"})),
        op("define_func", json!({"addr": "0x2"})),
        op("undefine_func", json!({"addr": "0x2"})),
        op("annotations_import", json!({"document": "{}"})),
        op("load", json!({})),
        op("diff", json!({})),
        op("batch", json!({"ops": []})),
        op("nope", json!({})),
        op("func", json!({"addr": "0x0", "binary": bin})),
    ];
    let batch = tool_once(10, "batch", json!({"binary": bin, "db": db, "ops": ops}));
    let results = batch["results"].as_array().expect("results array");
    assert_eq!(results.len(), 10);
    for (i, r) in results.iter().enumerate().take(6) {
        assert!(
            r["error"].as_str().is_some_and(|m| m.contains("explicit")),
            "write op {i} must stay explicit: {r}"
        );
        assert!(r.get("ok").is_none(), "op {i}: {r}");
    }
    assert!(
        results[6]["error"]
            .as_str()
            .is_some_and(|m| m.contains("two binaries")),
        "diff: {:?}",
        results[6]
    );
    assert!(
        results[7]["error"]
            .as_str()
            .is_some_and(|m| m.contains("nest")),
        "nesting: {:?}",
        results[7]
    );
    assert!(
        results[8]["error"]
            .as_str()
            .is_some_and(|m| m.contains("unknown batch op")),
        "unknown: {:?}",
        results[8]
    );
    assert!(
        results[9]["error"]
            .as_str()
            .is_some_and(|m| m.contains("envelope")),
        "smuggled identity: {:?}",
        results[9]
    );
    assert!(
        !db_path.exists(),
        "rejected batch writes nothing and creates no sidecar"
    );
    cleanup(&dir);
}

// Envelope misuse is a tool error, not a result: empty and over-cap op
// lists plus a missing binary all fail the call.
#[test]
fn batch_envelope_validation_is_a_tool_error() {
    let dir = tmpdir("mcp-batch-envelope");
    let bin = write_bin(&dir, "m.bin", &[0x90, 0x90, 0xC3])
        .display()
        .to_string();
    let db = temp_db(&dir, "m").display().to_string();
    let many: Vec<Value> = (0..33)
        .map(|_| op("func", json!({"addr": "0x0"})))
        .collect();

    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(10, "batch", json!({"binary": bin, "db": db, "ops": []})),
        call(11, "batch", json!({"binary": bin, "db": db, "ops": many})),
        call(
            12,
            "batch",
            json!({"binary": dir.join("missing.bin").display().to_string(), "ops": [op("func", json!({"addr": "0x0"}))]}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 4, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();
    assert_eq!(by_id[&10]["error"]["code"], -32602, "{:?}", by_id[&10]);
    assert_eq!(by_id[&11]["error"]["code"], -32602, "{:?}", by_id[&11]);
    assert!(by_id[&12].get("error").is_some(), "{:?}", by_id[&12]);
    for id in [10u64, 11, 12] {
        assert!(by_id[&id].get("result").is_none());
    }
    cleanup(&dir);
}

// Parity guard: every supported read op returns exactly what its single
// tool returns, so the mirrored validation cannot drift silently.
#[test]
fn batch_parity_across_read_tools() {
    use common::builders::{BASIC_ENTRY_VA, BASIC_STRING_VA, TEXT_VA};
    let dir = tmpdir("mcp-batch-parity");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db = temp_db(&dir, "basic").display().to_string();
    let entry = format!("{BASIC_ENTRY_VA:#x}");
    let string_va = format!("{BASIC_STRING_VA:#x}");
    let text = format!("{TEXT_VA:#x}");

    let blocks = tool_once(
        10,
        "blocks",
        json!({"binary": bin, "db": db, "addr": entry, "limit": 1}),
    );
    let first_block = blocks["items"][0]["start"].as_u64().expect("block start");

    let cases: Vec<(&str, Value)> = vec![
        ("project_info", json!({})),
        ("functions", json!({})),
        ("functions", json!({"query": "basic"})),
        (
            "functions",
            json!({"range_lo": entry, "range_hi": entry, "envelope": true}),
        ),
        ("func", json!({"addr": entry})),
        ("blocks", json!({"addr": entry})),
        (
            "block_insns",
            json!({"addr": entry, "block": first_block.to_string()}),
        ),
        ("diagnostics", json!({})),
        ("disasm", json!({"addr": entry, "len": 3})),
        ("bytes", json!({"addr": entry, "len": 3})),
        ("cfg", json!({"addr": entry})),
        ("structure", json!({"addr": entry})),
        ("pseudo", json!({"addr": entry})),
        ("callees", json!({"addr": entry, "depth": 2})),
        ("callers", json!({"addr": entry, "depth": 2})),
        ("slice", json!({"addr": entry, "depth": 2})),
        ("xrefs", json!({"to": string_va})),
        ("strings", json!({"pattern": "SAVE"})),
        ("symbols", json!({})),
        ("stats", json!({})),
        ("headers", json!({})),
        ("sections", json!({})),
        ("ir", json!({"addr": entry, "len": 3})),
        ("ir_coverage", json!({"arch": "x86_32"})),
        (
            "ir_coverage",
            json!({"arch": "x86_32", "addr": text, "len": 3}),
        ),
        ("annotation", json!({"addr": entry})),
        ("flirt_hints", json!({})),
        ("search_bytes", json!({"pattern": "55 89 e5"})),
        ("annotations_export", json!({})),
    ];
    let ops: Vec<Value> = cases
        .iter()
        .map(|(tool, params)| op(tool, params.clone()))
        .collect();
    let batch = tool_once(11, "batch", json!({"binary": bin, "db": db, "ops": ops}));
    let results = batch["results"].as_array().expect("results array");
    assert_eq!(results.len(), cases.len());
    for (i, (tool, params)) in cases.iter().enumerate() {
        assert!(
            results[i].get("ok").is_some(),
            "batch {tool} must succeed: {:?}",
            results[i]
        );
        let mut full = params.as_object().expect("object").clone();
        // Arch-only coverage opens no binary on either surface.
        let arch_only =
            *tool == "ir_coverage" && !params.as_object().expect("object").contains_key("addr");
        if !arch_only {
            full.insert("binary".to_string(), Value::String(bin.clone()));
            full.insert("db".to_string(), Value::String(db.clone()));
        }
        let single = tool_once(20 + i as u64, tool, Value::Object(full));
        assert_eq!(
            &results[i]["ok"], &single,
            "batch {tool} {params} matches single call"
        );
    }
    cleanup(&dir);
}

/// Batch `project_info` and `stats` carry the exact `content_hash_hex` twin.
#[test]
fn batch_project_info_and_stats_carry_hash_hex() {
    let dir = tmpdir("mcp-batch-hash-hex");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db = temp_db(&dir, "hash-hex").display().to_string();

    let ops = vec![op("project_info", json!({})), op("stats", json!({}))];
    let batch = tool_once(10, "batch", json!({"binary": bin, "db": db, "ops": ops}));
    let results = batch["results"].as_array().expect("results array");
    assert_eq!(results.len(), 2);
    for r in results {
        let ok = &r["ok"];
        let hash = ok["content_hash"].as_u64().expect("u64 hash: {r}");
        assert_eq!(
            ok["content_hash_hex"].as_str(),
            Some(format!("{hash:#x}").as_str()),
            "{r}"
        );
    }
    cleanup(&dir);
}

/// `nop` x 1500, then `jmp +0` x 1200, then `ret`: one function whose full
/// `cfg` export (~150 KiB) overflows the 1 MiB batch cap after a few ops,
/// so the tail returns limit/skipped errors instead of values.
#[test]
fn batch_output_cap_skips_tail() {
    let mut blob = vec![0x90u8; 1500];
    for _ in 0..1200 {
        blob.extend([0xEB, 0x00]);
    }
    blob.push(0xC3);
    let dir = tmpdir("mcp-batch-cap");
    let bin = write_bin(&dir, "big.bin", &blob).display().to_string();
    let db = temp_db(&dir, "big").display().to_string();

    let ops: Vec<Value> = (0..32).map(|_| op("cfg", json!({"addr": "0x0"}))).collect();
    let batch = tool_once(10, "batch", json!({"binary": bin, "db": db, "ops": ops}));
    let results = batch["results"].as_array().expect("results array");
    assert_eq!(results.len(), 32);
    assert!(results[0].get("ok").is_some(), "{:?}", results[0]);
    let single = tool_once(11, "cfg", json!({"binary": bin, "db": db, "addr": "0x0"}));
    assert_eq!(results[0]["ok"], single);

    let first_err = results
        .iter()
        .position(|r| r.get("error").is_some())
        .expect("cap must trigger");
    assert!(first_err > 0, "first ops fit under the cap");
    assert!(
        results[first_err]["error"]
            .as_str()
            .is_some_and(|m| m.contains("batch output")),
        "{:?}",
        results[first_err]
    );
    for r in results.iter().skip(first_err + 1) {
        assert!(
            r["error"]
                .as_str()
                .is_some_and(|m| m.contains("batch output")),
            "tail stays skipped: {r}"
        );
        assert!(r.get("ok").is_none(), "{r}");
    }
    let ok_bytes: usize = results
        .iter()
        .filter_map(|r| r.get("ok"))
        .map(|v| serde_json::to_string(v).expect("serializes").len())
        .sum();
    assert!(
        ok_bytes <= binscout::mcp::MAX_BATCH_BYTES,
        "ok payloads stay under the cap, got {ok_bytes}"
    );
    cleanup(&dir);
}

#[test]
fn batch_stack_strings_pages_envelope() {
    let dir = tmpdir("mcp-batch-stack");
    // Same mov-built blob as tests/stack_strings.rs: three recoveries.
    let blob = vec![
        0xC6, 0x44, 0x24, 0x00, 0x48, 0xC6, 0x44, 0x24, 0x01, 0x65, 0xC6, 0x44, 0x24, 0x02, 0x79,
        0xC6, 0x44, 0x24, 0x03, 0x21, 0xC7, 0x44, 0x24, 0x08, 0x74, 0x65, 0x73, 0x74, 0xC6, 0x40,
        0x10, 0x41, 0xB8, 0x41, 0x00, 0x00, 0x00, 0xC6, 0x44, 0x24, 0x20, 0x5A, 0xC7, 0x45, 0xF0,
        0x61, 0x62, 0x63, 0x64, 0xC3,
    ];
    let bin = write_bin(&dir, "stack.bin", &blob).display().to_string();
    let db = temp_db(&dir, "stack").display().to_string();
    let ops = vec![op("stack_strings", json!({"limit": 1}))];
    let batch = tool_once(10, "batch", json!({"binary": bin, "db": db, "ops": ops}));
    let results = batch["results"].as_array().expect("results");
    assert_eq!(results.len(), 1);
    let page = &results[0]["ok"];
    assert_eq!(page["protocol"], 1);
    assert!(page["total"].as_u64().expect("total") >= 2);
    assert_eq!(page["items"].as_array().expect("items").len(), 1);
    assert_eq!(page["next_offset"], 1);
    cleanup(&dir);
}

#[test]
fn batch_slice_unmapped_root_is_op_error() {
    let dir = tmpdir("mcp-batch-slice-unmapped");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db = temp_db(&dir, "basic").display().to_string();
    let ops = vec![op("slice", json!({"addr": "0xdead", "depth": 5}))];
    let batch = tool_once(10, "batch", json!({"binary": bin, "db": db, "ops": ops}));
    let results = batch["results"].as_array().expect("results");
    assert_eq!(results.len(), 1);
    assert!(
        results[0]["error"]
            .as_str()
            .is_some_and(|m| m.contains("not mapped")),
        "{:?}",
        results[0]
    );
    assert!(results[0].get("ok").is_none(), "{:?}", results[0]);
    cleanup(&dir);
}

// Batch mirrors the single-tool range semantics: inclusive and half-open
// pairs agree where they overlap, empty and mixed pairs are per-op errors.
#[test]
fn batch_range_names_carry_semantics() {
    use common::builders::{BASIC_ENTRY_VA, TEXT_VA};
    let dir = tmpdir("mcp-batch-range");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db = temp_db(&dir, "r").display().to_string();
    let entry_hex = format!("{BASIC_ENTRY_VA:#x}");
    let entry_next = format!("{:#x}", BASIC_ENTRY_VA + 1);
    let text_hex = format!("{TEXT_VA:#x}");

    let ops = vec![
        op(
            "functions",
            json!({"range_lo": entry_hex, "range_hi": entry_hex}),
        ),
        op(
            "functions",
            json!({"range_start": entry_hex, "range_end": entry_next}),
        ),
        op(
            "search_bytes",
            json!({"pattern": "55", "range_lo": text_hex, "range_hi": text_hex}),
        ),
        op(
            "functions",
            json!({"range_start": entry_hex, "range_end": entry_hex}),
        ),
        op(
            "search_bytes",
            json!({"pattern": "55", "range_start": text_hex, "range_end": text_hex}),
        ),
        op(
            "functions",
            json!({"range_lo": entry_hex, "range_hi": entry_hex, "range_start": entry_hex, "range_end": entry_next}),
        ),
        op(
            "search_bytes",
            json!({"pattern": "55", "range_lo": text_hex, "range_hi": text_hex, "range_start": text_hex, "range_end": text_hex}),
        ),
    ];
    let batch = tool_once(10, "batch", json!({"binary": bin, "db": db, "ops": ops}));
    let results = batch["results"].as_array().expect("results");
    assert_eq!(results.len(), 7);

    assert_eq!(
        results[0]["ok"]["items"].as_array().expect("items").len(),
        1
    );
    assert_eq!(results[0]["ok"], results[1]["ok"]);
    assert_eq!(results[2]["ok"]["total"], 1);
    assert_eq!(results[2]["ok"]["items"][0]["addr"], TEXT_VA);
    assert!(
        results[3]["error"]
            .as_str()
            .is_some_and(|m| m.contains("empty range")),
        "{}",
        results[3]
    );
    assert!(
        results[4]["error"]
            .as_str()
            .is_some_and(|m| m.contains("empty search range")),
        "{}",
        results[4]
    );
    for r in [&results[5], &results[6]] {
        assert!(
            r["error"]
                .as_str()
                .is_some_and(|m| m.contains("give either range_lo/range_hi")),
            "{r}"
        );
    }
    cleanup(&dir);
}
