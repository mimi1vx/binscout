//! bytes/hexdump command: typed views, VA<->file offset, error envelopes.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use binscout::{BytesAs, BytesEndian, Project};
use common::{binscout_bin, cleanup, mcp_bin, temp_db, tmpdir, write_bin, write_fixture};

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn put64(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

/// Minimal 64-bit LE ELF with a BSS-like tail: one `PT_LOAD` at `BASE`
/// with `p_filesz=3` but `p_memsz=16`.
fn bss_elf(base: u64) -> Vec<u8> {
    let mut f = vec![0u8; 0x78];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2;
    f[5] = 1;
    f[6] = 1;
    put16(&mut f, 16, 2);
    put16(&mut f, 18, 62);
    put32(&mut f, 20, 1);
    put64(&mut f, 24, base);
    put64(&mut f, 32, 64);
    put16(&mut f, 52, 64);
    put16(&mut f, 54, 56);
    put16(&mut f, 56, 1);
    let p = 64;
    put32(&mut f, p, 1);
    put32(&mut f, p + 4, 5);
    put64(&mut f, p + 8, 0x78);
    put64(&mut f, p + 16, base);
    put64(&mut f, p + 32, 3);
    put64(&mut f, p + 40, 16);
    put64(&mut f, p + 48, 0x1000);
    f.extend_from_slice(&[0x90, 0x90, 0xC3]);
    f
}

fn open_raw(dir: &std::path::Path, tag: &str, bytes: &[u8]) -> Project {
    let bin = write_bin(dir, &format!("{tag}.bin"), bytes);
    let db = temp_db(dir, tag);
    Project::open_with_db(&bin, &db).expect("raw blob must open")
}

#[test]
fn bytes_view_u8_shape_and_provenance() {
    let dir = tmpdir("bytes-u8");
    let p = open_raw(&dir, "r", &[0x90, 0x90, 0xC3]);
    let v = p
        .bytes_view(0, 3, BytesAs::U8, BytesEndian::Le)
        .expect("range must read");
    assert_eq!(v.addr, 0);
    assert_eq!(v.bytes, vec![0x90, 0x90, 0xC3]);
    assert_eq!(v.bytes_hex(), "9090c3");
    assert_eq!(v.file_off, Some(0));
    assert_eq!(v.section, None);
    assert_eq!(
        v.values,
        vec![
            Value::from(0x90u64),
            Value::from(0x90u64),
            Value::from(0xC3u64)
        ]
    );
    let json = serde_json::to_value(&v).expect("view serializes");
    assert_eq!(json["addr"], 0);
    assert_eq!(json["addr_hex"], "0x0");
    assert_eq!(json["file_off"], 0);
    assert!(json["section"].is_null());
    assert_eq!(json["len"], 3);
    assert_eq!(json["bytes_hex"], "9090c3");
    assert_eq!(json["values"], json!([144, 144, 195]));
    cleanup(&dir);
}

#[test]
fn bytes_view_multibyte_endian_and_truncation() {
    let dir = tmpdir("bytes-multi");
    let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let p = open_raw(&dir, "r", &bytes);
    let le = p
        .bytes_view(0, 8, BytesAs::U16, BytesEndian::Le)
        .expect("u16 le");
    assert_eq!(
        Value::Array(le.values.clone()),
        json!([0x0201, 0x0403, 0x0605, 0x0807])
    );
    let be = p
        .bytes_view(0, 8, BytesAs::U16, BytesEndian::Be)
        .expect("u16 be");
    assert_eq!(
        Value::Array(be.values.clone()),
        json!([0x0102, 0x0304, 0x0506, 0x0708])
    );
    let w32 = p
        .bytes_view(0, 8, BytesAs::U32, BytesEndian::Le)
        .expect("u32 le");
    assert_eq!(
        Value::Array(w32.values.clone()),
        json!([0x04030201u64, 0x08070605u64])
    );
    let w64 = p
        .bytes_view(0, 8, BytesAs::U64, BytesEndian::Le)
        .expect("u64 le");
    assert_eq!(
        Value::Array(w64.values.clone()),
        json!([0x0807060504030201u64])
    );
    let ptr = p
        .bytes_view(0, 8, BytesAs::Ptr, BytesEndian::Le)
        .expect("ptr");
    assert_eq!(ptr.values, w64.values, "x86_64 pointers are 8 bytes");
    // Trailing partial units are dropped, never an error.
    let odd = p
        .bytes_view(0, 3, BytesAs::U16, BytesEndian::Le)
        .expect("odd u16");
    assert_eq!(Value::Array(odd.values.clone()), json!([0x0201]));
    assert_eq!(odd.bytes_hex(), "010203");
    cleanup(&dir);
}

#[test]
fn bytes_view_ptr_width_follows_arch() {
    let dir = tmpdir("bytes-ptr32");
    let bytes = [0x01, 0x02, 0x03, 0x04, 0x78, 0x56, 0x34, 0x12];
    let bin = write_bin(&dir, "r32.bin", &bytes);
    let db = temp_db(&dir, "r32");
    let p = Project::open_raw(
        &bin,
        &db,
        binscout::loader::RawOptions {
            base: 0x1000,
            arch: binscout::disasm::Arch::X86_32,
            entry: None,
        },
    )
    .expect("raw x86_32 must open");
    let v = p
        .bytes_view(0x1000, 8, BytesAs::Ptr, BytesEndian::Le)
        .expect("ptr");
    assert_eq!(
        Value::Array(v.values.clone()),
        json!([0x04030201u64, 0x12345678u64])
    );
    assert_eq!(v.file_off, Some(0));
    cleanup(&dir);
}

#[test]
fn bytes_view_cstr_and_utf16_strings() {
    let dir = tmpdir("bytes-str");
    let p = open_raw(&dir, "r", b"Hi\0trailing");
    let v = p
        .bytes_view(0, 11, BytesAs::CStr, BytesEndian::Le)
        .expect("cstr");
    assert_eq!(Value::Array(v.values.clone()), json!(["Hi"]));
    // No NUL in range: the whole range decodes.
    let v = p
        .bytes_view(3, 8, BytesAs::CStr, BytesEndian::Le)
        .expect("cstr");
    assert_eq!(Value::Array(v.values.clone()), json!(["trailing"]));
    // Lossy on invalid UTF-8.
    let q = open_raw(&dir, "q", &[0x41, 0xFF, 0x00]);
    let v = q
        .bytes_view(0, 3, BytesAs::CStr, BytesEndian::Le)
        .expect("cstr");
    assert_eq!(Value::Array(v.values.clone()), json!(["A\u{fffd}"]));

    let u = open_raw(&dir, "u", &[0x48, 0x00, 0x69, 0x00, 0x00, 0x00, 0x41, 0x00]);
    let v = u
        .bytes_view(0, 8, BytesAs::Utf16, BytesEndian::Le)
        .expect("utf16 le");
    assert_eq!(Value::Array(v.values.clone()), json!(["Hi"]));
    let b = open_raw(&dir, "b", &[0x00, 0x48, 0x00, 0x69, 0x00, 0x00]);
    let v = b
        .bytes_view(0, 6, BytesAs::Utf16, BytesEndian::Be)
        .expect("utf16 be");
    assert_eq!(Value::Array(v.values.clone()), json!(["Hi"]));
    cleanup(&dir);
}

#[test]
fn parse_bytes_as_and_endian() {
    use binscout::{parse_bytes_as, parse_bytes_endian};
    for (s, want) in [
        ("u8", BytesAs::U8),
        ("U16", BytesAs::U16),
        ("u32", BytesAs::U32),
        ("u64", BytesAs::U64),
        ("ptr", BytesAs::Ptr),
        ("CSTR", BytesAs::CStr),
        ("utf16", BytesAs::Utf16),
    ] {
        assert_eq!(parse_bytes_as(s).expect("known view"), want);
    }
    assert!(parse_bytes_as("u128").is_err());
    assert!(parse_bytes_as("").is_err());
    assert_eq!(parse_bytes_endian("LE").expect("le"), BytesEndian::Le);
    assert_eq!(parse_bytes_endian("be").expect("be"), BytesEndian::Be);
    assert!(parse_bytes_endian("mid").is_err());
}

#[test]
fn file_off_and_va_round_trip_on_pe() {
    use common::builders::{BASIC_STRING_RDATA_OFF, BASIC_STRING_VA, TEXT_VA};
    let dir = tmpdir("bytes-off");
    let p = common::open_test_project(&dir, "pe32-basic.exe");
    assert_eq!(p.file_off_of(TEXT_VA), Some(0x200));
    assert_eq!(p.va_of_file_off(0x200), Some(TEXT_VA));
    assert_eq!(p.section_of(TEXT_VA), Some(".text"));
    let rdata_off = 0x400 + BASIC_STRING_RDATA_OFF as u64;
    assert_eq!(p.file_off_of(BASIC_STRING_VA), Some(rdata_off));
    assert_eq!(p.va_of_file_off(rdata_off), Some(BASIC_STRING_VA));
    assert_eq!(p.section_of(BASIC_STRING_VA), Some(".rdata"));
    // Unmapped VA and past-end offsets have no provenance.
    assert_eq!(p.file_off_of(0xdead_beef), None);
    assert_eq!(p.section_of(0xdead_beef), None);
    assert_eq!(p.va_of_file_off(u64::MAX), None);
    // Round trip both ways through the view.
    let v = p
        .bytes_view(TEXT_VA, 3, BytesAs::U8, BytesEndian::Le)
        .expect("text view");
    assert_eq!(v.file_off, Some(0x200));
    assert_eq!(v.section.as_deref(), Some(".text"));
    assert_eq!(p.va_of_file_off(v.file_off.expect("backed")), Some(TEXT_VA));
    cleanup(&dir);
}

#[test]
fn bss_tail_reads_zeros_with_null_provenance() {
    const BASE: u64 = 0x400000;
    let dir = tmpdir("bytes-bss");
    let bin = write_bin(&dir, "bss.elf", &bss_elf(BASE));
    let db = temp_db(&dir, "bss");
    let p = Project::open_with_db(&bin, &db).expect("bss ELF must open");
    // Wholly zero-filled tail: zeros with null file_off/section.
    let v = p
        .bytes_view(BASE + 8, 4, BytesAs::U8, BytesEndian::Le)
        .expect("tail must read");
    assert_eq!(v.bytes, vec![0u8; 4]);
    assert_eq!(Value::Array(v.values.clone()), json!([0, 0, 0, 0]));
    assert_eq!(v.file_off, None);
    assert_eq!(v.section, None);
    assert_eq!(p.file_off_of(BASE + 8), None);
    assert_eq!(p.section_of(BASE + 8), None);
    // Mixed file/zero range: starts backed, tails zero.
    let v = p
        .bytes_view(BASE + 1, 5, BytesAs::U8, BytesEndian::Le)
        .expect("mixed must read");
    assert_eq!(v.bytes, vec![0x90, 0xC3, 0x00, 0x00, 0x00]);
    assert_eq!(p.file_off_of(BASE + 1), p.file_off_of(BASE).map(|o| o + 1));
    cleanup(&dir);
}

/// Run the CLI; stdout must be exactly one JSON value.
fn run(args: &[&str]) -> (bool, Value, String) {
    let out = Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value, text)
}

#[test]
fn cli_bytes_json_shape_and_no_sidecar() {
    let dir = tmpdir("cli-bytes");
    let before = std::fs::read("tests/fixtures/raw-x64.bin").expect("fixture");
    let bin = write_bin(&dir, "a.bin", &before);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "a").display().to_string();
    let d = db.as_str();

    let (ok, v, text) = run(&["--db", d, "bytes", &bin_s, "0x0", "--len", "3"]);
    assert!(ok, "{v}");
    assert_eq!(text.trim_end().lines().count(), 1);
    assert_eq!(v["addr"], 0);
    assert_eq!(v["addr_hex"], "0x0");
    assert_eq!(v["file_off"], 0);
    assert!(v["section"].is_null(), "{v}");
    assert_eq!(v["len"], 3);
    assert_eq!(v["bytes_hex"], "9090c3");
    assert_eq!(v["values"], json!([144, 144, 195]));

    // Typed views and decimal addresses agree with hex.
    let (ok, v, _) = run(&[
        "--db", d, "bytes", &bin_s, "0", "--len", "3", "--as", "u16", "--endian", "be",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["values"], json!([0x9090]));

    // PE string decodes as one cstr row with section provenance.
    let pe = write_fixture(&dir, "pe32-basic.exe");
    let pe_s = pe.display().to_string();
    let hex = format!("{:#x}", common::builders::BASIC_STRING_VA);
    let (ok, v, _) = run(&[
        "--db", d, "bytes", &pe_s, &hex, "--len", "64", "--as", "cstr",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["section"], ".rdata");
    assert!(v["file_off"].is_number(), "{v}");
    assert_eq!(v["values"], json!([common::builders::BASIC_STRING]));

    assert!(
        !std::path::Path::new(d).exists(),
        "bytes reads never create the sidecar"
    );
    assert_eq!(
        std::fs::read(&bin).expect("reread"),
        before,
        "binary untouched"
    );
    cleanup(&dir);
}

#[test]
fn cli_bytes_errors_are_json_envelopes() {
    let dir = tmpdir("cli-bytes-err");
    let bin = write_bin(&dir, "a.bin", &[0x90, 0x90, 0xC3]);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "a").display().to_string();
    let d = db.as_str();

    // Unmapped range.
    let (ok, v, text) = run(&["--db", d, "bytes", &bin_s, "0xdead", "--len", "3"]);
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert_eq!(text.trim_end().lines().count(), 1);
    // Zero and over-cap lengths (1 MiB cap, like disasm/ir).
    let (ok, v, _) = run(&["--db", d, "bytes", &bin_s, "0x0", "--len", "0"]);
    assert!(!ok && v.get("error").is_some(), "{v}");
    let (ok, v, _) = run(&["--db", d, "bytes", &bin_s, "0x0", "--len", "1048577"]);
    assert!(!ok && v.get("error").is_some(), "over-cap: {v}");
    // Bad view, endian, and address strings.
    for args in [
        vec![
            "--db", d, "bytes", &bin_s, "0x0", "--len", "3", "--as", "u128",
        ],
        vec![
            "--db", d, "bytes", &bin_s, "0x0", "--len", "3", "--endian", "mid",
        ],
        vec!["--db", d, "bytes", &bin_s, "zz", "--len", "3"],
    ] {
        let (ok, v, text) = run(&args);
        assert!(!ok && v.get("error").is_some(), "{args:?}: {v}");
        assert_eq!(text.trim_end().lines().count(), 1);
    }
    assert!(
        !std::path::Path::new(d).exists(),
        "failed bytes reads never create the sidecar"
    );
    cleanup(&dir);
}

#[test]
fn cli_bytes_bss_tail_is_zeros_with_null_file_off() {
    const BASE: u64 = 0x400000;
    let dir = tmpdir("cli-bytes-bss");
    let bin = write_bin(&dir, "bss.elf", &bss_elf(BASE));
    let before = std::fs::read(&bin).expect("read back");
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "bss").display().to_string();
    let d = db.as_str();
    let tail = format!("{:#x}", BASE + 8);

    let (ok, v, text) = run(&["--db", d, "bytes", &bin_s, &tail, "--len", "4"]);
    assert!(ok, "{v}");
    assert_eq!(text.trim_end().lines().count(), 1);
    assert_eq!(v["bytes_hex"], "00000000");
    assert_eq!(v["values"], json!([0, 0, 0, 0]));
    assert!(v["file_off"].is_null(), "{v}");
    assert!(v["section"].is_null(), "{v}");

    assert_eq!(
        std::fs::read(&bin).expect("reread"),
        before,
        "binary untouched"
    );
    assert!(!std::path::Path::new(d).exists(), "no sidecar written");
    cleanup(&dir);
}

/// One MCP request line plus notification; response lines in order.
fn mcp_session(lines: &[String]) -> Vec<Value> {
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

fn mcp_req(id: u64, method: &str, params: Value) -> String {
    serde_json::to_string(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .expect("request serializes")
}

fn mcp_call(id: u64, name: &str, args: Value) -> String {
    mcp_req(id, "tools/call", json!({"name": name, "arguments": args}))
}

/// One `bytes`-capable round trip: returns the tool result text parsed as JSON.
fn bytes_text(args: Value) -> Value {
    let lines = vec![
        mcp_req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        mcp_call(10, "bytes", args),
    ];
    let resps = mcp_session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();
    let result = by_id[&10]
        .get("result")
        .unwrap_or_else(|| panic!("bytes must return result: {:?}", by_id[&10]));
    assert_ne!(
        result.get("isError"),
        Some(&Value::Bool(true)),
        "tool error: {result}"
    );
    let text = result["content"][0]["text"].as_str().expect("text content");
    serde_json::from_str(text).expect("tool json")
}

#[test]
fn mcp_bytes_typed_views_and_defaults() {
    let dir = tmpdir("mcp-bytes");
    let bin = write_bin(&dir, "m.bin", &[0x01, 0x02, 0x03, 0x04]);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "m").display().to_string();

    // Defaults: u8 LE.
    let v = bytes_text(json!({"binary": bin_s, "db": db, "addr": "0x0", "len": 4}));
    assert_eq!(v["addr"], 0);
    assert_eq!(v["addr_hex"], "0x0");
    assert_eq!(v["file_off"], 0);
    assert!(v["section"].is_null(), "{v}");
    assert_eq!(v["bytes_hex"], "01020304");
    assert_eq!(v["values"], json!([1, 2, 3, 4]));

    // Explicit view: u32 BE over the same bytes.
    let v = bytes_text(
        json!({"binary": bin_s, "db": db, "addr": "0", "len": 4, "as": "u32", "endian": "be"}),
    );
    assert_eq!(v["values"], json!([0x01020304u64]));

    assert!(!std::path::Path::new(&db).exists(), "reads never save");
    cleanup(&dir);
}

#[test]
fn mcp_bytes_unmapped_is_protocol_error() {
    let dir = tmpdir("mcp-bytes-err");
    let bin = write_bin(&dir, "m.bin", &[0x90, 0x90, 0xC3]);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "m").display().to_string();
    let lines = vec![
        mcp_req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        mcp_call(
            10,
            "bytes",
            json!({"binary": bin_s, "db": db, "addr": "0xdead", "len": 3}),
        ),
    ];
    let resps = mcp_session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();
    assert!(by_id[&10].get("error").is_some(), "{:?}", by_id[&10]);
    assert!(by_id[&10].get("result").is_none());
    cleanup(&dir);
}

#[test]
fn bytes_view_values_hex_twins_integer_views() {
    let dir = tmpdir("bytes-values-hex");
    let wide = 0x8010_0000_0000_0001u64;
    let p = open_raw(&dir, "w", &wide.to_le_bytes());
    let v = p
        .bytes_view(0, 8, BytesAs::U64, BytesEndian::Le)
        .expect("u64 view");
    assert_eq!(Value::Array(v.values.clone()), json!([wide]));
    assert_eq!(v.values_hex, Some(vec!["0x8010000000000001".to_string()]));
    let json = serde_json::to_value(&v).expect("view serializes");
    assert_eq!(json["values_hex"], json!(["0x8010000000000001"]));
    let ptr = p
        .bytes_view(0, 8, BytesAs::Ptr, BytesEndian::Le)
        .expect("ptr view");
    assert_eq!(ptr.values_hex, Some(vec!["0x8010000000000001".to_string()]));
    let q = open_raw(&dir, "b", &[0x90, 0x90, 0xC3]);
    let v = q
        .bytes_view(0, 3, BytesAs::U8, BytesEndian::Le)
        .expect("u8 view");
    assert_eq!(Value::Array(v.values.clone()), json!([144, 144, 195]));
    assert_eq!(
        v.values_hex,
        Some(vec![
            "0x90".to_string(),
            "0x90".to_string(),
            "0xc3".to_string()
        ])
    );
    let s = q
        .bytes_view(0, 3, BytesAs::CStr, BytesEndian::Le)
        .expect("cstr view");
    assert_eq!(s.values_hex, None);
    let json = serde_json::to_value(&s).expect("view serializes");
    assert!(json.get("values_hex").is_none(), "{json}");
    cleanup(&dir);
}

#[test]
fn cli_bytes_values_hex_shape() {
    let dir = tmpdir("cli-bytes-hex");
    let wide = 0x8010_0000_0000_0001u64;
    let bin = write_bin(&dir, "w.bin", &wide.to_le_bytes());
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "w").display().to_string();
    let d = db.as_str();
    let (ok, v, text) = run(&[
        "--db", d, "bytes", &bin_s, "0x0", "--len", "8", "--as", "u64",
    ]);
    assert!(ok, "{v}");
    assert_eq!(text.trim_end().lines().count(), 1);
    assert_eq!(v["values"], json!([wide]));
    assert_eq!(v["values_hex"], json!(["0x8010000000000001"]));
    let bin2 = write_bin(&dir, "b.bin", &[0x90, 0x90, 0xC3]);
    let bin2_s = bin2.display().to_string();
    let (ok, v, _) = run(&["--db", d, "bytes", &bin2_s, "0x0", "--len", "3"]);
    assert!(ok, "{v}");
    assert_eq!(v["values"], json!([144, 144, 195]));
    assert_eq!(v["values_hex"], json!(["0x90", "0x90", "0xc3"]));
    let (ok, v, _) = run(&[
        "--db", d, "bytes", &bin2_s, "0x0", "--len", "3", "--as", "cstr",
    ]);
    assert!(ok, "{v}");
    assert!(v.get("values_hex").is_none(), "{v}");
    cleanup(&dir);
}
