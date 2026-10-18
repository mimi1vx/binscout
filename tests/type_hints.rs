//! Type-hint comments: structured struct-layout/sizeof hints in the
//! comment channel.
//!
//! Covers the idea-10 acceptance checks: format/parse round-trips, plain
//! comments staying unhinted, corrupt hints erroring (never silent),
//! shape validation, free-text coexistence, and export/import carrying a
//! struct hint between projects while the rename-target contract holds.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use binscout::Project;
use binscout::annotations::{
    TYPE_HINT_PREFIX, TypeField, TypeHint, format_type_hint, parse_type_hint, parse_type_hint_json,
    type_hint_json,
};
use binscout::db::MAX_ANNOTATION_BYTES;
use binscout::error::Error;

fn sample_hint() -> TypeHint {
    TypeHint {
        name: "Foo".to_string(),
        size: 24,
        fields: vec![
            TypeField {
                name: "a".to_string(),
                offset: 0,
                size: 8,
            },
            TypeField {
                name: "b".to_string(),
                offset: 8,
                size: 4,
            },
        ],
    }
}

#[test]
fn format_parse_round_trip() {
    let hint = sample_hint();
    let text = format_type_hint(&hint).expect("valid hint");
    assert!(text.starts_with(TYPE_HINT_PREFIX), "{text}");
    assert_eq!(parse_type_hint(&text).expect("parses"), Some(hint));
}

#[test]
fn plain_comments_are_not_hints() {
    assert_eq!(parse_type_hint("just a note").expect("plain"), None);
    assert_eq!(parse_type_hint("").expect("empty"), None);
    // Prefix-like text without the exact marker stays plain.
    assert_eq!(
        parse_type_hint("type-hint without colon {\"kind\":\"struct\"}").expect("plain"),
        None
    );
}

#[test]
fn corrupt_hints_error_instead_of_decoding_silently() {
    for bad in [
        "type-hint:{not json",
        "type-hint:{\"kind\":\"union\",\"name\":\"U\",\"size\":8}",
        "type-hint:{\"kind\":\"struct\",\"name\":\"\",\"size\":8}",
        "type-hint:{\"kind\":\"struct\",\"name\":\"S\",\"size\":0}",
        "type-hint:{\"kind\":\"struct\",\"name\":\"S\",\"size\":8,\
         \"fields\":[{\"name\":\"f\",\"offset\":4,\"size\":8}]}",
    ] {
        let err = parse_type_hint(bad).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)), "{bad}: got {err:?}");
    }
}

#[test]
fn shape_validation_rejects_bad_hints() {
    let overrun = TypeHint {
        name: "S".to_string(),
        size: 8,
        fields: vec![TypeField {
            name: "f".to_string(),
            offset: 4,
            size: 8,
        }],
    };
    let err = format_type_hint(&overrun).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");

    let overflow = TypeHint {
        name: "S".to_string(),
        size: u64::MAX,
        fields: vec![TypeField {
            name: "f".to_string(),
            offset: u64::MAX,
            size: 1,
        }],
    };
    let err = format_type_hint(&overflow).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");

    for bad in [
        TypeHint {
            name: String::new(),
            size: 8,
            fields: vec![],
        },
        TypeHint {
            name: "S".to_string(),
            size: 0,
            fields: vec![],
        },
        TypeHint {
            name: "S".to_string(),
            size: 8,
            fields: vec![TypeField {
                name: String::new(),
                offset: 0,
                size: 4,
            }],
        },
        TypeHint {
            name: "S".to_string(),
            size: 8,
            fields: vec![TypeField {
                name: "f".to_string(),
                offset: 0,
                size: 0,
            }],
        },
    ] {
        let err = format_type_hint(&bad).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
    }
}

#[test]
fn oversized_hints_hit_the_comment_cap() {
    let hint = TypeHint {
        name: "x".repeat(MAX_ANNOTATION_BYTES),
        size: 8,
        fields: vec![],
    };
    let err = format_type_hint(&hint).unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
}

#[test]
fn overlapping_union_fields_are_allowed() {
    let hint = TypeHint {
        name: "U".to_string(),
        size: 8,
        fields: vec![
            TypeField {
                name: "as_u64".to_string(),
                offset: 0,
                size: 8,
            },
            TypeField {
                name: "as_bytes".to_string(),
                offset: 0,
                size: 8,
            },
        ],
    };
    let text = format_type_hint(&hint).expect("unions allowed");
    assert_eq!(parse_type_hint(&text).expect("parses"), Some(hint));
}

#[test]
fn trailing_free_text_coexists_with_the_hint() {
    let hint = sample_hint();
    let text = format!(
        "{}\nnoted by analyst",
        format_type_hint(&hint).expect("hint")
    );
    assert_eq!(parse_type_hint(&text).expect("parses"), Some(hint));
}

#[test]
fn hint_survives_export_import_round_trip() {
    let dir = common::tmpdir("typehint-roundtrip");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "a");
    let unmapped = 0xdead_beefu64;

    let hint = sample_hint();
    let mut p = Project::open_with_db(&bin, &db).expect("open");
    // Any-address contract: hints store away from any function or string.
    p.set_type_hint(unmapped, &hint).expect("set hint");
    p.set_comment(common::builders::BASIC_STRING_VA, "plain note")
        .expect("plain comment");
    assert_eq!(p.type_hint_at(unmapped).expect("read"), Some(hint.clone()));
    assert_eq!(
        p.type_hint_at(common::builders::BASIC_STRING_VA)
            .expect("read"),
        None,
        "plain comments stay unhinted"
    );
    let doc = p.export_annotations().expect("export");
    assert!(doc.contains(TYPE_HINT_PREFIX), "hint in document");
    drop(p);

    let db2 = common::temp_db(&dir, "b");
    let mut q = Project::open_with_db(&bin, &db2).expect("open fresh");
    let summary = q.import_annotations(&doc, false).expect("import");
    assert_eq!(summary.rows, 2);
    assert_eq!(summary.changed, 2);
    assert_eq!(q.type_hint_at(unmapped).expect("read"), Some(hint.clone()));
    drop(q);

    let r = Project::open_with_db(&bin, &db2).expect("reopen");
    assert_eq!(r.type_hint_at(unmapped).expect("read"), Some(hint.clone()));
    assert_eq!(
        r.annotation(unmapped)
            .and_then(|a| a.comment.as_deref())
            .expect("comment stored"),
        format_type_hint(&hint).expect("hint"),
    );

    // Rename-target contract untouched: unknown entries still fail.
    let mut s = Project::open_with_db(&bin, &db2).expect("reopen");
    let err = s.rename_function(0x1234_5678u64, "ghost").unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    common::cleanup(&dir);
}

#[test]
fn cli_carries_hints_through_comment_opaquely() {
    let dir = common::tmpdir("typehint-cli");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "a");
    let hint_text = format_type_hint(&sample_hint()).expect("hint");

    let run = |args: &[&str]| {
        let out = Command::new(common::binscout_bin())
            .args(args)
            .output()
            .expect("spawn binscout");
        let text = String::from_utf8(out.stdout).expect("utf-8 stdout");
        let value: serde_json::Value =
            serde_json::from_str(text.trim_end()).expect("one JSON value");
        (out.status.success(), value)
    };
    let db_s = db.display().to_string();
    let bin_s = bin.display().to_string();

    let (ok, v) = run(&[
        "--db",
        &db_s,
        "annotate",
        &bin_s,
        "0xdeadbeef",
        "--comment",
        &hint_text,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["comment"], hint_text);

    let (ok, v) = run(&["--db", &db_s, "annotations-export", &bin_s]);
    assert!(ok, "{v}");
    let rows = v["annotations"].as_array().expect("rows");
    assert!(
        rows.iter().any(|r| r["comment"] == hint_text),
        "hint survives CLI export: {v}"
    );
    common::cleanup(&dir);
}

#[test]
fn wire_json_helpers_round_trip() {
    let hint = sample_hint();
    let value = type_hint_json(&hint);
    assert_eq!(value["kind"], "struct");
    assert_eq!(value["name"], "Foo");
    assert_eq!(value["size"], 24);
    assert_eq!(value["fields"].as_array().expect("fields").len(), 2);
    let text = value.to_string();
    assert_eq!(parse_type_hint_json(&text).expect("parses"), hint);
    // Leading/trailing whitespace is tolerated, like the comment channel.
    assert_eq!(
        parse_type_hint_json(&format!("  {text}\n")).expect("parses"),
        hint
    );
    for bad in [
        "{not json",
        "{\"kind\":\"union\",\"name\":\"U\",\"size\":8}",
        "{\"kind\":\"struct\",\"name\":\"\",\"size\":8}",
        "{\"kind\":\"struct\",\"name\":\"S\",\"size\":0}",
    ] {
        assert!(parse_type_hint_json(bad).is_err(), "{bad}");
    }
}

#[test]
fn core_set_type_hint_json_shapes_and_clear() {
    let dir = common::tmpdir("typehint-json-core");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "a");
    let mut p = Project::open_with_db(&bin, &db).expect("open");
    let addr = 0xdead_beefu64;

    let json = "{\"kind\":\"struct\",\"name\":\"S\",\"size\":8,\
        \"fields\":[{\"name\":\"a\",\"offset\":0,\"size\":4}]}";
    p.set_type_hint_json(addr, json).expect("set");
    let hint = p.type_hint_at(addr).expect("read").expect("hint");
    assert_eq!(hint.name, "S");
    assert_eq!(type_hint_json(&hint)["kind"], "struct");

    // Malformed JSON, wrong kinds, and shape violations fail without writing.
    for bad in [
        "{not json",
        "{\"kind\":\"union\",\"name\":\"U\",\"size\":8}",
        "{\"kind\":\"struct\",\"name\":\"S\",\"size\":8,\
         \"fields\":[{\"name\":\"f\",\"offset\":4,\"size\":8}]}",
    ] {
        assert!(p.set_type_hint_json(0x1000, bad).is_err(), "{bad}");
        assert_eq!(p.type_hint_at(0x1000).expect("read"), None);
    }

    // Empty clears the hint.
    p.set_type_hint_json(addr, "").expect("clear");
    assert_eq!(p.type_hint_at(addr).expect("read"), None);
    // Empty is a no-op (not a wipe) over a plain comment.
    p.set_comment(addr, "analyst note").expect("comment");
    p.set_type_hint_json(addr, "   ").expect("clear no-op");
    assert_eq!(
        p.annotation(addr).and_then(|a| a.comment.clone()),
        Some("analyst note".to_string())
    );
    assert_eq!(p.type_hint_at(addr).expect("read"), None);
    common::cleanup(&dir);
}

/// Run the CLI; stdout must be exactly one JSON value.
fn run(args: &[&str]) -> (bool, Value, String) {
    let out = Command::new(common::binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value, text)
}

#[test]
fn cli_type_hint_set_get_clear_round_trip() {
    let dir = common::tmpdir("typehint-cli-rw");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "a");
    let db_s = db.display().to_string();
    let bin_s = bin.display().to_string();
    let json = "{\"kind\":\"struct\",\"name\":\"S\",\"size\":8,\
        \"fields\":[{\"name\":\"a\",\"offset\":0,\"size\":4},{\"name\":\"b\",\"offset\":4,\"size\":4}]}";

    let (ok, v, text) = run(&[
        "--db",
        &db_s,
        "type-hint",
        &bin_s,
        "0xdeadbeef",
        "--json",
        json,
    ]);
    assert!(ok, "{v}");
    assert_eq!(text.trim_end().lines().count(), 1);
    assert_eq!(v["addr"], 0xdead_beefu64);
    assert_eq!(v["addr_hex"], "0xdeadbeef");
    assert_eq!(v["hint"]["name"], "S");
    assert_eq!(v["hint"]["fields"].as_array().expect("fields").len(), 2);

    // Bare reads and --get agree, and missing hints read as null.
    for args in [
        vec!["--db", &db_s, "type-hint", &bin_s, "0xdeadbeef"],
        vec!["--db", &db_s, "type-hint", &bin_s, "0xdeadbeef", "--get"],
    ] {
        let (ok, v, text) = run(&args);
        assert!(ok, "{args:?}: {v}");
        assert_eq!(text.trim_end().lines().count(), 1);
        assert_eq!(v["hint"]["name"], "S");
    }
    let (ok, v, _) = run(&["--db", &db_s, "type-hint", &bin_s, "0x1234", "--get"]);
    assert!(ok, "{v}");
    assert!(v["hint"].is_null(), "{v}");

    // --json with --get is a usage error, not a silent pick-one.
    let (ok, v, _) = run(&[
        "--db",
        &db_s,
        "type-hint",
        &bin_s,
        "0xdeadbeef",
        "--json",
        json,
        "--get",
    ]);
    assert!(!ok && v.get("error").is_some(), "{v}");

    // Malformed JSON fails without writing the binary or a hint.
    let (ok, v, text) = run(&[
        "--db",
        &db_s,
        "type-hint",
        &bin_s,
        "0x1000",
        "--json",
        "{not json",
    ]);
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert_eq!(text.trim_end().lines().count(), 1);

    // Empty --json clears the hint but leaves plain comments alone.
    let (ok, v, _) = run(&[
        "--db",
        &db_s,
        "annotate",
        &bin_s,
        "0x2000",
        "--comment",
        "analyst note",
    ]);
    assert!(ok, "{v}");
    let (ok, v, _) = run(&["--db", &db_s, "type-hint", &bin_s, "0x2000", "--json", ""]);
    assert!(ok, "{v}");
    assert!(v["hint"].is_null(), "{v}");
    let (ok, v, _) = run(&["--db", &db_s, "annotate", &bin_s, "0x2000"]);
    assert!(ok, "{v}");
    assert_eq!(v["comment"], "analyst note");

    let (ok, v, _) = run(&[
        "--db",
        &db_s,
        "type-hint",
        &bin_s,
        "0xdeadbeef",
        "--json",
        "",
    ]);
    assert!(ok, "{v}");
    assert!(v["hint"].is_null(), "{v}");
    common::cleanup(&dir);
}

#[test]
fn cli_raw_hint_comments_read_through_the_new_surface() {
    let dir = common::tmpdir("typehint-cli-backcompat");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "a");
    let db_s = db.display().to_string();
    let bin_s = bin.display().to_string();
    let hint_text = format_type_hint(&sample_hint()).expect("hint");

    // Legacy path: raw type-hint: comment via annotate.
    let (ok, v, _) = run(&[
        "--db",
        &db_s,
        "annotate",
        &bin_s,
        "0x3000",
        "--comment",
        &hint_text,
    ]);
    assert!(ok, "{v}");

    // New surface reads it back, including with trailing free text.
    let (ok, v, _) = run(&["--db", &db_s, "type-hint", &bin_s, "0x3000", "--get"]);
    assert!(ok, "{v}");
    assert_eq!(v["hint"]["name"], "Foo");

    let with_note = format!("{hint_text}\nnoted by analyst");
    let (ok, v, _) = run(&[
        "--db",
        &db_s,
        "annotate",
        &bin_s,
        "0x3001",
        "--comment",
        &with_note,
    ]);
    assert!(ok, "{v}");
    let (ok, v, _) = run(&["--db", &db_s, "type-hint", &bin_s, "0x3001"]);
    assert!(ok, "{v}");
    assert_eq!(v["hint"]["name"], "Foo");

    // Corrupt hints still error instead of decoding silently.
    let (ok, v, _) = run(&[
        "--db",
        &db_s,
        "annotate",
        &bin_s,
        "0x3002",
        "--comment",
        "type-hint:{bad",
    ]);
    assert!(ok, "{v}");
    let (ok, v, _) = run(&["--db", &db_s, "type-hint", &bin_s, "0x3002", "--get"]);
    assert!(!ok && v.get("error").is_some(), "{v}");
    common::cleanup(&dir);
}

#[test]
fn cli_bytes_as_type_renders_struct_fields() {
    let dir = common::tmpdir("typehint-bytes");
    let bytes: Vec<u8> = (1u8..=16).collect();
    let bin = common::write_bin(&dir, "s.bin", &bytes);
    let db = common::temp_db(&dir, "a");
    let db_s = db.display().to_string();
    let bin_s = bin.display().to_string();
    let json = "{\"kind\":\"struct\",\"name\":\"Regs\",\"size\":16,\"fields\":[\
        {\"name\":\"lo\",\"offset\":0,\"size\":8},\
        {\"name\":\"hi\",\"offset\":8,\"size\":8},\
        {\"name\":\"wide\",\"offset\":0,\"size\":16},\
        {\"name\":\"one\",\"offset\":0,\"size\":1}]}";

    let (ok, v, _) = run(&["--db", &db_s, "type-hint", &bin_s, "0x100", "--json", json]);
    assert!(ok, "{v}");

    let (ok, v, text) = run(&[
        "--db",
        &db_s,
        "bytes",
        &bin_s,
        "0x0",
        "--len",
        "16",
        "--as-type",
        "0x100",
    ]);
    assert!(ok, "{v}");
    assert_eq!(text.trim_end().lines().count(), 1);
    assert_eq!(v["bytes_hex"], "0102030405060708090a0b0c0d0e0f10");
    assert_eq!(v["values"].as_array().expect("values").len(), 16);
    assert_eq!(v["hint"]["name"], "Regs");
    assert_eq!(v["hint_addr"], 0x100);
    assert_eq!(v["hint_addr_hex"], "0x100");
    let fields = v["fields"].as_array().expect("fields");
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0]["name"], "lo");
    assert_eq!(fields[0]["addr"], 0);
    assert_eq!(fields[0]["addr_hex"], "0x0");
    assert_eq!(fields[0]["bytes_hex"], "0102030405060708");
    assert_eq!(fields[0]["value"], 0x0807060504030201u64);
    assert_eq!(fields[1]["value"], 0x100f0e0d0c0b0a09u64);
    assert_eq!(fields[2]["name"], "wide");
    assert!(
        fields[2]["value"].is_null(),
        "wider than 8 bytes: {}",
        fields[2]
    );
    assert_eq!(fields[2]["bytes_hex"], "0102030405060708090a0b0c0d0e0f10");
    assert_eq!(fields[3]["value"], 1);

    // Big-endian order applies to field integers too.
    let (ok, be, _) = run(&[
        "--db",
        &db_s,
        "bytes",
        &bin_s,
        "0x0",
        "--len",
        "16",
        "--as-type",
        "0x100",
        "--endian",
        "be",
    ]);
    assert!(ok, "{be}");
    assert_eq!(be["fields"][0]["value"], 0x0102030405060708u64);

    // A cached open renders the same rows (loader-only path).
    let (ok, _, _) = run(&["--db", &db_s, "load", &bin_s]);
    assert!(ok, "load must succeed");
    let (ok, cached, _) = run(&[
        "--db",
        &db_s,
        "bytes",
        &bin_s,
        "0x0",
        "--len",
        "16",
        "--as-type",
        "0x100",
    ]);
    assert!(ok, "{cached}");
    assert_eq!(cached["fields"], v["fields"]);
    assert_eq!(cached["hint"], v["hint"]);

    // The range must cover the struct; unknown and corrupt hints fail.
    let (ok, v, _) = run(&[
        "--db",
        &db_s,
        "bytes",
        &bin_s,
        "0x0",
        "--len",
        "8",
        "--as-type",
        "0x100",
    ]);
    assert!(!ok && v.get("error").is_some(), "short range: {v}");
    let (ok, v, _) = run(&[
        "--db",
        &db_s,
        "bytes",
        &bin_s,
        "0x0",
        "--len",
        "16",
        "--as-type",
        "0x200",
    ]);
    assert!(!ok && v.get("error").is_some(), "missing hint: {v}");
    let (ok, w, _) = run(&[
        "--db",
        &db_s,
        "annotate",
        &bin_s,
        "0x300",
        "--comment",
        "type-hint:{bad",
    ]);
    assert!(ok, "{w}");
    let (ok, v, _) = run(&[
        "--db",
        &db_s,
        "bytes",
        &bin_s,
        "0x0",
        "--len",
        "16",
        "--as-type",
        "0x300",
    ]);
    assert!(!ok && v.get("error").is_some(), "corrupt hint: {v}");
    common::cleanup(&dir);
}

/// One MCP request line plus notification; response lines in order.
fn mcp_session(lines: &[String]) -> Vec<Value> {
    let mut child = Command::new(common::mcp_bin())
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

fn mcp_req(id: u64, method: &str, params: Value) -> String {
    serde_json::to_string(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .expect("request serializes")
}

fn mcp_call(id: u64, name: &str, args: Value) -> String {
    mcp_req(id, "tools/call", json!({"name": name, "arguments": args}))
}

/// One tool call in a fresh server: handshake plus a single `tools/call`,
/// returning the parsed JSON text payload.
fn tool_once(tool_id: u64, tool: &str, args: Value) -> Value {
    let lines = vec![
        mcp_req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        mcp_call(tool_id, tool, args),
    ];
    let resps = mcp_session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let result = resps[1]
        .get("result")
        .unwrap_or_else(|| panic!("{tool} must return result: {:?}", resps[1]));
    assert_ne!(
        result.get("isError"),
        Some(&Value::Bool(true)),
        "tool error: {result}"
    );
    let text = result["content"][0]["text"].as_str().expect("text content");
    serde_json::from_str(text).expect("tool json")
}

#[test]
fn mcp_set_get_type_hint_round_trip() {
    let dir = common::tmpdir("typehint-mcp");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "a");
    let bin_s = bin.display().to_string();
    let db_s = db.display().to_string();
    let json = "{\"kind\":\"struct\",\"name\":\"S\",\"size\":8,\
        \"fields\":[{\"name\":\"a\",\"offset\":0,\"size\":4}]}";

    let v = tool_once(
        10,
        "set_type_hint",
        json!({"binary": bin_s, "db": db_s, "addr": "0xdeadbeef", "hint": json}),
    );
    assert_eq!(v["addr"], 0xdead_beefu64);
    assert_eq!(v["hint"]["name"], "S");

    let v = tool_once(
        11,
        "get_type_hint",
        json!({"binary": bin_s, "db": db_s, "addr": "0xdeadbeef"}),
    );
    assert_eq!(v["hint"]["name"], "S");
    assert_eq!(v["hint"]["fields"].as_array().expect("fields").len(), 1);

    // Plain comments read as null.
    let v = tool_once(
        12,
        "comment",
        json!({"binary": bin_s, "db": db_s, "addr": "0x2000", "comment": "note"}),
    );
    assert_eq!(v["comment"], "note");
    let v = tool_once(
        13,
        "get_type_hint",
        json!({"binary": bin_s, "db": db_s, "addr": "0x2000"}),
    );
    assert!(v["hint"].is_null(), "{v}");

    // Empty hint clears; batch serves get_type_hint but rejects the write.
    let v = tool_once(
        14,
        "set_type_hint",
        json!({"binary": bin_s, "db": db_s, "addr": "0xdeadbeef", "hint": ""}),
    );
    assert!(v["hint"].is_null(), "{v}");

    let lines = vec![
        mcp_req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        mcp_call(
            20,
            "batch",
            json!({
                "binary": bin_s, "db": db_s,
                "ops": [
                    {"tool": "get_type_hint", "params": {"addr": "0x2000"}},
                    {"tool": "set_type_hint", "params": {"addr": "0x1", "hint": json}},
                ],
            }),
        ),
    ];
    let resps = mcp_session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let text = resps[1]["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let batch: Value = serde_json::from_str(text).expect("batch json");
    let results = batch["results"].as_array().expect("results");
    assert!(results[0]["ok"]["hint"].is_null(), "{batch}");
    assert!(
        results[1]["error"]
            .as_str()
            .expect("err")
            .contains("explicit"),
        "{batch}"
    );
    common::cleanup(&dir);
}

#[test]
fn mcp_bytes_as_type_and_errors() {
    let dir = common::tmpdir("typehint-mcp-bytes");
    let bytes: Vec<u8> = (1u8..=8).collect();
    let bin = common::write_bin(&dir, "s.bin", &bytes);
    let db = common::temp_db(&dir, "a");
    let bin_s = bin.display().to_string();
    let db_s = db.display().to_string();
    let json = "{\"kind\":\"struct\",\"name\":\"S\",\"size\":8,\
        \"fields\":[{\"name\":\"a\",\"offset\":0,\"size\":4}]}";

    let v = tool_once(
        10,
        "set_type_hint",
        json!({"binary": bin_s, "db": db_s, "addr": "0x100", "hint": json}),
    );
    assert_eq!(v["hint"]["name"], "S");

    let v = tool_once(
        11,
        "bytes",
        json!({"binary": bin_s, "db": db_s, "addr": "0x0", "len": 8, "as_type": "0x100"}),
    );
    assert_eq!(v["hint_addr"], 0x100);
    assert_eq!(v["fields"][0]["value"], 0x04030201u64);

    // Missing hints and short ranges are tool errors, like other bad input.
    for (id, args) in [
        (
            12,
            json!({"binary": bin_s, "db": db_s, "addr": "0x0", "len": 8, "as_type": "0x200"}),
        ),
        (
            13,
            json!({"binary": bin_s, "db": db_s, "addr": "0x0", "len": 4, "as_type": "0x100"}),
        ),
        (
            14,
            json!({"binary": bin_s, "db": db_s, "addr": "0x0", "len": 8, "as_type": "zz"}),
        ),
    ] {
        let lines = vec![
            mcp_req(
                1,
                "initialize",
                json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
            ),
            serde_json::to_string(
                &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            )
            .expect("n"),
            mcp_call(id, "bytes", args),
        ];
        let resps = mcp_session(&lines);
        assert_eq!(resps.len(), 2, "{resps:?}");
        assert!(resps[1].get("error").is_some(), "{:?}", resps[1]);
    }

    // Malformed hint JSON is invalid_params, not an internal error.
    let lines = vec![
        mcp_req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        mcp_call(
            15,
            "set_type_hint",
            json!({"binary": bin_s, "db": db_s, "addr": "0x1", "hint": "{bad"}),
        ),
    ];
    let resps = mcp_session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let err = resps[1].get("error").expect("tool error");
    assert_eq!(err["code"], -32602, "{err}");
    common::cleanup(&dir);
}
