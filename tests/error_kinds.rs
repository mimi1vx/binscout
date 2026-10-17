//! Machine-readable error kinds: every [`binscout::error::Error`]
//! surfaces a stable `kind` on the CLI (`{"error", "kind"}`) and in MCP
//! error `data` (`{"kind": ...}`), so agents branch without parsing.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use common::{binscout_bin, cleanup, mcp_bin, temp_db, tmpdir, write_bin};

/// Committed 3-byte raw x86-64 fixture: one function at 0x0.
const RAW: &str = "tests/fixtures/raw-x64.bin";

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

/// One failing tool call in a fresh server process: handshake plus a
/// single `tools/call`, returning the JSON-RPC error object.
fn tool_err_once(tool_id: u64, tool: &str, args: Value) -> Value {
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
    let resp = resps
        .iter()
        .find(|r| r["id"].as_u64() == Some(tool_id))
        .unwrap_or_else(|| panic!("no response for {tool_id}: {resps:?}"))
        .clone();
    assert!(resp.get("result").is_none(), "must error: {resp}");
    resp["error"].clone()
}

#[test]
fn error_kind_covers_every_variant() {
    use binscout::error::Error;
    for (err, want) in [
        (Error::NotFound("x".into()), "not_found"),
        (Error::Unsupported("x".into()), "unsupported"),
        (Error::Invalid("x".into()), "invalid"),
        (Error::Limit("x".into()), "limit"),
        (Error::Storage("x".into()), "storage"),
        (Error::Io("x".into()), "io"),
    ] {
        assert_eq!(err.kind(), want);
    }
}

// `{"error", "kind"}` per trigger: unknown function, bad address,
// over-cap range, directory input, corrupt sidecar, ENOTDIR input.
#[test]
fn cli_failures_carry_machine_readable_kind() {
    let dir = tmpdir("err-kinds");
    let db = temp_db(&dir, "t").display().to_string();
    let d = db.as_str();
    // Garbage sidecar plus a path whose parent is a file (ENOTDIR).
    let blob = write_bin(&dir, "b.bin", &[0x90, 0x90, 0xC3]);
    let garbage = temp_db(&dir, "garbage");
    std::fs::write(&garbage, b"not a redb file").expect("garbage db");
    let garbage_s = garbage.display().to_string();
    let enotdir = format!("{}/child", blob.display());

    for (args, kind, prefix) in [
        (vec!["func", RAW, "0xdead"], "not_found", "not found"),
        (vec!["func", RAW, "zz"], "invalid", "invalid opcode"),
        (
            vec!["bytes", RAW, "0x0", "--len", "2097152"],
            "limit",
            "limit exceeded",
        ),
    ] {
        let mut full = vec!["--db", d];
        full.extend(args);
        let (ok, v) = run(&full);
        assert!(!ok, "{kind}: {v}");
        assert_eq!(v["kind"], kind, "{v}");
        assert!(
            v["error"].as_str().is_some_and(|m| m.contains(prefix)),
            "{v}"
        );
    }

    // Directory input is unsupported ("not a file").
    let dir_s = dir.display().to_string();
    let (ok, v) = run(&["--db", d, "load", &dir_s]);
    assert!(!ok, "{v}");
    assert_eq!(v["kind"], "unsupported", "{v}");

    // Corrupt sidecar is a storage failure.
    let raw_s = RAW.to_string();
    let (ok, v) = run(&["--db", &garbage_s, "load", &raw_s]);
    assert!(!ok, "{v}");
    assert_eq!(v["kind"], "storage", "{v}");
    assert!(
        v["error"].as_str().is_some_and(|m| m.contains("storage")),
        "{v}"
    );

    // A path through a regular file never resolves: OS I/O failure.
    let (ok, v) = run(&["--db", d, "load", &enotdir]);
    assert!(!ok, "{v}");
    assert_eq!(v["kind"], "io", "{v}");
    assert!(v["error"].as_str().is_some_and(|m| m.contains("io")), "{v}");

    assert!(!dir.join("t.redb").exists(), "failures never save");
    cleanup(&dir);
}

// Same six triggers over MCP: `invalid`/`limit` are `invalid_params`
// (-32602), `not_found` is `resource_not_found` (older peers keep
// -32002, newer ones upgrade to -32602), the rest are `internal_error`.
#[test]
fn mcp_errors_carry_kind_in_data() {
    let dir = tmpdir("mcp-err-kinds");
    let blob = write_bin(&dir, "b.bin", &[0x90, 0x90, 0xC3])
        .display()
        .to_string();
    let db = temp_db(&dir, "t").display().to_string();
    let garbage = temp_db(&dir, "garbage");
    std::fs::write(&garbage, b"not a redb file").expect("garbage db");
    let garbage_s = garbage.display().to_string();
    let dir_s = dir.display().to_string();
    let enotdir = format!("{blob}/child");

    let not_found = tool_err_once(
        10,
        "func",
        json!({"binary": blob, "db": db, "addr": "0xdead"}),
    );
    assert_eq!(not_found["data"]["kind"], "not_found", "{not_found}");
    assert!(
        [-32002, -32602].contains(&not_found["code"].as_i64().expect("code")),
        "{not_found}"
    );

    let invalid = tool_err_once(11, "func", json!({"binary": blob, "db": db, "addr": "zz"}));
    assert_eq!(invalid["code"], -32602, "{invalid}");
    assert_eq!(invalid["data"]["kind"], "invalid", "{invalid}");

    let limit = tool_err_once(
        12,
        "bytes",
        json!({"binary": blob, "db": db, "addr": "0x0", "len": 2097152}),
    );
    assert_eq!(limit["code"], -32602, "{limit}");
    assert_eq!(limit["data"]["kind"], "limit", "{limit}");

    let unsupported = tool_err_once(13, "project_info", json!({"binary": dir_s, "db": db}));
    assert_eq!(unsupported["code"], -32603, "{unsupported}");
    assert_eq!(unsupported["data"]["kind"], "unsupported", "{unsupported}");

    let storage = tool_err_once(14, "project_info", json!({"binary": RAW, "db": garbage_s}));
    assert_eq!(storage["code"], -32603, "{storage}");
    assert_eq!(storage["data"]["kind"], "storage", "{storage}");

    let io = tool_err_once(15, "project_info", json!({"binary": enotdir, "db": db}));
    assert_eq!(io["code"], -32603, "{io}");
    assert_eq!(io["data"]["kind"], "io", "{io}");

    cleanup(&dir);
}
