//! MCP server-cache regression tests: the in-process LRU, the `load`
//! tool, and per-project isolation.
//!
//! The cache is process-local, so every test here drives one server
//! process: batch `session`s for single calls, or an interactive
//! [`LiveSession`] when file state must change between two calls of one
//! process. Timing appears only in `second_functions_call_is_faster`, with
//! a 10x margin on a ~3 MB input where analysis dominates by two orders
//! of magnitude; every other test asserts exact behavior, never speed.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use common::{binscout_bin, cleanup, mcp_bin, temp_db, tmpdir, write_bin, write_fixture};

fn req(id: u64, method: &str, params: Value) -> String {
    serde_json::to_string(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .expect("request serializes")
}

fn call(id: u64, name: &str, args: Value) -> String {
    req(id, "tools/call", json!({"name": name, "arguments": args}))
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

/// One tool call in a fresh server process, returning the parsed JSON text
/// payload (asserts `isError` is absent/false).
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
    ok_payload(&resps[1])
}

/// Parsed JSON text payload of a successful tool response.
fn ok_payload(resp: &Value) -> Value {
    let result = resp
        .get("result")
        .unwrap_or_else(|| panic!("tool must return result: {resp}"));
    assert_ne!(
        result.get("isError"),
        Some(&Value::Bool(true)),
        "tool error: {resp}"
    );
    let text = result["content"][0]["text"].as_str().expect("text content");
    serde_json::from_str(text).expect("tool json")
}

/// Interactive server process: requests interleave with filesystem
/// changes, so cache hits and revalidation are observable in one process.
struct LiveSession {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl LiveSession {
    fn start() -> Self {
        let mut child = Command::new(mcp_bin())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn binscout-mcp");
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut sess = Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        sess.send(&req(
            0,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ));
        let _ = sess.recv_line();
        sess.send(
            &serde_json::to_string(
                &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            )
            .expect("n"),
        );
        sess
    }

    fn send(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").expect("write request");
        self.stdin.flush().expect("flush request");
    }

    fn recv_line(&mut self) -> Value {
        loop {
            let mut line = String::new();
            self.stdout.read_line(&mut line).expect("read response");
            if line.trim().is_empty() {
                continue;
            }
            return serde_json::from_str(&line)
                .unwrap_or_else(|_| panic!("response line must be JSON: {line:?}"));
        }
    }

    /// One tool call; returns the full response plus client-side
    /// round-trip time.
    fn call(&mut self, tool: &str, args: Value) -> (Value, Duration) {
        self.next_id += 1;
        let id = self.next_id;
        let t = Instant::now();
        self.send(&call(id, tool, args));
        loop {
            let resp = self.recv_line();
            if resp.get("id").and_then(Value::as_u64) == Some(id) {
                return (resp, t.elapsed());
            }
        }
    }

    fn close(self) {
        drop(self.stdin);
        let out = self.child.wait_with_output().expect("server exits");
        assert!(out.status.success(), "server exit: {}", out.status);
    }
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

#[test]
fn load_tool_lists_with_binary_params() {
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
    let load = resps[1]["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t["name"] == "load")
        .expect("load listed")
        .clone();
    let props = load["inputSchema"]["properties"]
        .as_object()
        .expect("input schema properties");
    for key in ["binary", "db", "raw", "fat_arch"] {
        assert!(props.contains_key(key), "load exposes {key}");
    }
}

// `load` persists the snapshot (CLI `load` parity) and later opens replay
// it: the second load in a fresh process returns identical project_info.
#[test]
fn load_saves_sidecar_with_cli_parity() {
    let dir = tmpdir("mcp-cache-load");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db_path = temp_db(&dir, "load");
    let db = db_path.display().to_string();
    assert!(!db_path.exists());

    let v = tool_once(10, "load", json!({"binary": bin, "db": db}));
    assert_eq!(v["functions"], 1);
    assert!(db_path.exists(), "load must persist the sidecar");

    let (ok, from_cli) = cli(&["--db", &db, "load", &bin]);
    assert!(ok, "{from_cli}");
    assert_eq!(v, from_cli, "MCP load matches CLI load");

    // Fresh process replays the snapshot instead of re-analyzing.
    let again = tool_once(11, "load", json!({"binary": bin, "db": db}));
    assert_eq!(v, again);
    cleanup(&dir);
}

// Reads never create the sidecar, with or without the cache: the cache is
// memory-only, persistence stays explicit (`load`, rename/comment/import).
#[test]
fn reads_do_not_create_sidecars() {
    let dir = tmpdir("mcp-cache-no-save");
    let bin = write_fixture(&dir, "pe32-basic.exe").display().to_string();
    let db_path = temp_db(&dir, "read");
    let db = db_path.display().to_string();

    // One session (shared cache) plus fresh processes: no read may save.
    let mut sess = LiveSession::start();
    let (r1, _) = sess.call("project_info", json!({"binary": bin, "db": db}));
    let (r2, _) = sess.call("functions", json!({"binary": bin, "db": db}));
    sess.close();
    assert!(ok_payload(&r1)["functions"] == 1);
    assert_eq!(ok_payload(&r2)["items"].as_array().expect("array").len(), 1);
    assert!(!db_path.exists(), "cached reads never create the sidecar");

    tool_once(10, "strings", json!({"binary": bin, "db": db}));
    tool_once(11, "xrefs", json!({"binary": bin, "db": db}));
    assert!(!db_path.exists(), "fresh-process reads never create it");
    cleanup(&dir);
}

// Same binary under two raw mappings stays two entries: rename and
// function addresses never cross the mapping boundary.
#[test]
fn mappings_stay_isolated() {
    let dir = tmpdir("mcp-cache-mapping");
    let bin = write_bin(&dir, "r.bin", &[0x90, 0x90, 0xC3])
        .display()
        .to_string();
    let db_a = temp_db(&dir, "a").display().to_string();
    let db_b = temp_db(&dir, "b").display().to_string();
    let raw_a = json!({"arch": "x86_64", "base": "0x1000"});
    let raw_b = json!({"arch": "x86_64", "base": "0x2000"});

    let mut sess = LiveSession::start();
    let (fa, _) = sess.call(
        "functions",
        json!({"binary": bin, "db": db_a, "raw": raw_a}),
    );
    let (fb, _) = sess.call(
        "functions",
        json!({"binary": bin, "db": db_b, "raw": raw_b}),
    );
    assert_eq!(ok_payload(&fa)["items"][0]["entry"], 0x1000);
    assert_eq!(ok_payload(&fb)["items"][0]["entry"], 0x2000);

    // Rename under mapping A; mapping B still resolves the export-free
    // fallback name (null), proving entries do not share annotations.
    let (renamed, _) = sess.call(
        "rename",
        json!({"binary": bin, "db": db_a, "raw": raw_a, "addr": "0x1000", "name": "mapped_main"}),
    );
    assert_eq!(ok_payload(&renamed)["name"], "mapped_main");
    let (fa2, _) = sess.call(
        "functions",
        json!({"binary": bin, "db": db_a, "raw": raw_a, "query": "mapped_main"}),
    );
    assert_eq!(
        ok_payload(&fa2)["items"].as_array().expect("array").len(),
        1
    );
    let (fb2, _) = sess.call(
        "functions",
        json!({"binary": bin, "db": db_b, "raw": raw_b, "query": "mapped_main"}),
    );
    assert_eq!(
        ok_payload(&fb2)["items"].as_array().expect("array").len(),
        0
    );
    sess.close();
    cleanup(&dir);
}

// A rewritten binary revalidates mid-session: the second `func` reflects
// the new bytes, never the cached analysis.
#[test]
fn edited_binary_revalidates() {
    let dir = tmpdir("mcp-cache-stale");
    let bin_path = write_bin(&dir, "r.bin", &[0x90, 0x90, 0xC3]);
    let bin = bin_path.display().to_string();
    let db = temp_db(&dir, "stale").display().to_string();

    let mut sess = LiveSession::start();
    let (first, _) = sess.call("func", json!({"binary": bin, "db": db, "addr": "0x0"}));
    assert_eq!(ok_payload(&first)["insns"], 3);

    std::fs::write(&bin_path, [0x90, 0xC3]).expect("rewrite binary");
    let (second, _) = sess.call("func", json!({"binary": bin, "db": db, "addr": "0x0"}));
    assert_eq!(ok_payload(&second)["insns"], 2);
    sess.close();
    cleanup(&dir);
}

// Deterministic no-reanalysis proof: after one `functions` call the
// binary becomes unreadable, yet the same-process second call succeeds
// with byte-identical output — the open never re-ran.
#[cfg(unix)]
#[test]
fn cached_call_survives_unreadable_binary() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmpdir("mcp-cache-hit");
    let bin_path = write_bin(&dir, "r.bin", &[0x90, 0x90, 0xC3]);
    let bin = bin_path.display().to_string();
    let db = temp_db(&dir, "hit").display().to_string();

    let mut sess = LiveSession::start();
    let (first, _) = sess.call("functions", json!({"binary": bin, "db": db}));
    std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
    // Strictness check: when the file is truly unreadable (non-root), the
    // successful cached call below proves the open never re-ran. As root
    // the chmod is a no-op and only output equality is asserted.
    let strict = std::fs::File::open(&bin_path).is_err();
    let (second, _) = sess.call("functions", json!({"binary": bin, "db": db}));
    std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
    sess.close();
    eprintln!("cache-hit proof strict (unreadable file): {strict}");
    assert!(strict, "test must run as non-root to prove the cache hit");
    assert_eq!(
        first["result"], second["result"],
        "cached call must not re-read the binary"
    );
    assert_eq!(
        ok_payload(&second)["items"]
            .as_array()
            .expect("array")
            .len(),
        1
    );
    cleanup(&dir);
}

/// ~2.9 MB raw x86-64 blob: 900k `nop` falling into `ret` (one function,
/// 900_001 decoded instructions, under the 1M cap) plus 2M padding bytes
/// that analysis never decodes.
fn big_blob() -> Vec<u8> {
    let mut b = vec![0x90u8; 900_000];
    b.push(0xC3);
    b.extend(std::iter::repeat_n(0xCC, 2_000_000));
    b
}

// Second-call speedup: the first `functions` call analyzes ~3 MB, the
// repeats only stat plus query. Margin is structural (analysis vs HashMap
// lookup), asserted at 10x with the faster of two cached reps.
#[test]
fn second_functions_call_is_ten_times_faster() {
    let dir = tmpdir("mcp-cache-speed");
    let bytes = big_blob();
    assert!(bytes.len() > 2_000_000, "must stay multi-MB");
    let bin = write_bin(&dir, "big.bin", &bytes).display().to_string();
    let db = temp_db(&dir, "big").display().to_string();

    let mut sess = LiveSession::start();
    let (r1, t1) = sess.call("functions", json!({"binary": bin, "db": db}));
    let (r2, t2) = sess.call("functions", json!({"binary": bin, "db": db}));
    let (r3, t3) = sess.call("functions", json!({"binary": bin, "db": db}));
    sess.close();

    let v1 = ok_payload(&r1);
    assert_eq!(v1, ok_payload(&r2));
    assert_eq!(v1, ok_payload(&r3));
    assert_eq!(v1["items"].as_array().expect("array").len(), 1);

    let cached = t2.min(t3);
    eprintln!(
        "functions over {} bytes: first {:.1}ms, cached {:.1}ms/{:.1}ms (ratio {:.0}x)",
        bytes.len(),
        t1.as_secs_f64() * 1000.0,
        t2.as_secs_f64() * 1000.0,
        t3.as_secs_f64() * 1000.0,
        t1.as_secs_f64() / cached.as_secs_f64().max(f64::MIN_POSITIVE),
    );
    assert!(
        cached * 10 <= t1,
        "cached call {cached:?} must be 10x faster than first {t1:?}"
    );
    assert!(!std::path::Path::new(&db).exists(), "reads never save");
    cleanup(&dir);
}
