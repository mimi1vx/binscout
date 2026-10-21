//! Debug info (em6.23): embedded DWARF, `--debug-file`, and `--pdb`.
//!
//! The ELF/DWARF fixtures below are hand-built byte vectors (no toolchain,
//! no network): one linked x86-64 ELF with four `DW_TAG_subprogram` rows
//! exercising linkage-name preference, `high_pc`-as-address,
//! `high_pc`-as-length, nameless seeds, and the skipped range-list form.
//! The PDB path uses the checked-in `pdb-mini` pair, generated once with
//! `clang --target=x86_64-windows-msvc -gcodeview` plus `lld-link /debug`
//! from a two-function TU (see `tests/fixtures/README.md`); the tests only
//! read it.

use binscout::analysis::DiscoveryReason;

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

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

fn mcp_tool_text(resp: &Value) -> &str {
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

fn mcp_tool_once(tool_id: u64, tool: &str, args: Value) -> Value {
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
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();
    let text = mcp_tool_text(by_id[&tool_id]).to_owned();
    serde_json::from_str(&text).expect("tool json")
}

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn put64(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

fn uleb(out: &mut Vec<u8>, mut x: u64) {
    loop {
        let mut b = (x & 0x7f) as u8;
        x >>= 7;
        if x != 0 {
            b |= 0x80;
        }
        out.push(b);
        if x == 0 {
            break;
        }
    }
}

/// `.debug_abbrev` for the fixture: CU plus four subprogram shapes.
fn debug_abbrev() -> Vec<u8> {
    let mut b = Vec::new();
    // CU: name (string), low_pc (addr).
    b.extend_from_slice(&[1, 0x11, 1, 0x03, 0x08, 0x11, 0x01, 0, 0]);
    // Subprogram: name, linkage_name, low_pc, high_pc-as-length.
    b.extend_from_slice(&[
        2, 0x2e, 0, 0x03, 0x08, 0x6e, 0x08, 0x11, 0x01, 0x12, 0x0f, 0, 0,
    ]);
    // Subprogram: name, low_pc, high_pc-as-address.
    b.extend_from_slice(&[3, 0x2e, 0, 0x03, 0x08, 0x11, 0x01, 0x12, 0x01, 0, 0]);
    // Subprogram: low_pc only (nameless seed).
    b.extend_from_slice(&[4, 0x2e, 0, 0x11, 0x01, 0, 0]);
    // Subprogram: name, low_pc, high_pc-as-range-list (skipped end).
    b.extend_from_slice(&[5, 0x2e, 0, 0x03, 0x08, 0x11, 0x01, 0x12, 0x17, 0, 0]);
    b.push(0);
    b
}

/// `.debug_info` for the fixture: one CU with four subprograms.
fn debug_info() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&4u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(8);
    // CU.
    uleb(&mut body, 1);
    body.extend_from_slice(b"test.c\0");
    body.extend_from_slice(&0x400000u64.to_le_bytes());
    // alpha: linkage name wins, high_pc is a 1-byte length.
    uleb(&mut body, 2);
    body.extend_from_slice(b"alpha\0");
    body.extend_from_slice(b"_Z5alphav\0");
    body.extend_from_slice(&0x400000u64.to_le_bytes());
    uleb(&mut body, 1);
    // beta: high_pc is an address.
    uleb(&mut body, 3);
    body.extend_from_slice(b"beta\0");
    body.extend_from_slice(&0x400010u64.to_le_bytes());
    body.extend_from_slice(&0x400012u64.to_le_bytes());
    // Nameless subprogram: seed, no name.
    uleb(&mut body, 4);
    body.extend_from_slice(&0x400020u64.to_le_bytes());
    // delta: high_pc is a range-list offset, so the end stays unknown.
    uleb(&mut body, 5);
    body.extend_from_slice(b"delta\0");
    body.extend_from_slice(&0x400030u64.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(0);
    let mut out = Vec::new();
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Linked x86-64 ELF whose `.text` holds four one-instruction functions;
/// with `debug` it carries the fixture `.debug_info`/`.debug_abbrev`.
fn dwarf_elf(debug: bool) -> Vec<u8> {
    let info = debug_info();
    let abbrev = debug_abbrev();
    let shstr = b"\0.text\0.debug_info\0.debug_abbrev\0.shstrtab\0";
    // Section file offsets.
    let text_off = 0x100usize;
    let info_off = text_off + 0x40;
    let abbrev_off = info_off + info.len();
    let shstr_off = abbrev_off + abbrev.len();
    let shoff = 0x300usize;
    let shnum = if debug { 5 } else { 3 };
    let total = shoff + shnum * 64;
    let mut f = vec![0u8; total];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2;
    f[5] = 1;
    f[6] = 1;
    put16(&mut f, 16, 2);
    put16(&mut f, 18, 62);
    put32(&mut f, 20, 1);
    put64(&mut f, 24, 0x400000);
    put64(&mut f, 32, 0x40);
    put64(&mut f, 40, shoff as u64);
    put16(&mut f, 52, 64);
    put16(&mut f, 54, 56);
    put16(&mut f, 56, 1);
    put16(&mut f, 58, 64);
    put16(&mut f, 60, shnum as u16);
    put16(&mut f, 62, if debug { 4 } else { 2 });
    // PT_LOAD covering .text.
    put32(&mut f, 0x40, 1);
    put32(&mut f, 0x44, 5);
    put64(&mut f, 0x48, text_off as u64);
    put64(&mut f, 0x50, 0x400000);
    put64(&mut f, 0x60, 0x40);
    put64(&mut f, 0x68, 0x40);
    put64(&mut f, 0x70, 0x1000);
    // .text: ret at +0, nop+ret at +0x10, ret at +0x20 and +0x30.
    f[text_off] = 0xC3;
    f[text_off + 0x10] = 0x90;
    f[text_off + 0x11] = 0xC3;
    f[text_off + 0x20] = 0xC3;
    f[text_off + 0x30] = 0xC3;
    for i in 0..0x40 {
        if f[text_off + i] == 0 {
            f[text_off + i] = 0x90;
        }
    }
    write_sh(
        &mut f,
        shoff,
        ShSpec {
            idx: 1,
            name: 1,
            ty: 1,
            flags: 0x6,
            addr: 0x400000,
            off: text_off,
            size: 0x40,
        },
    );
    if debug {
        f[info_off..info_off + info.len()].copy_from_slice(&info);
        f[abbrev_off..abbrev_off + abbrev.len()].copy_from_slice(&abbrev);
        f[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);
        write_sh(
            &mut f,
            shoff,
            ShSpec {
                idx: 2,
                name: 7,
                ty: 1,
                flags: 0,
                addr: 0,
                off: info_off,
                size: info.len(),
            },
        );
        write_sh(
            &mut f,
            shoff,
            ShSpec {
                idx: 3,
                name: 19,
                ty: 1,
                flags: 0,
                addr: 0,
                off: abbrev_off,
                size: abbrev.len(),
            },
        );
        write_sh(
            &mut f,
            shoff,
            ShSpec {
                idx: 4,
                name: 33,
                ty: 3,
                flags: 0,
                addr: 0,
                off: shstr_off,
                size: shstr.len(),
            },
        );
    } else {
        let mini = b"\0.text\0.shstrtab\0";
        f[shstr_off..shstr_off + mini.len()].copy_from_slice(mini);
        write_sh(
            &mut f,
            shoff,
            ShSpec {
                idx: 2,
                name: 7,
                ty: 3,
                flags: 0,
                addr: 0,
                off: shstr_off,
                size: mini.len(),
            },
        );
    }
    f
}

struct ShSpec {
    idx: usize,
    name: u32,
    ty: u32,
    flags: u64,
    addr: u64,
    off: usize,
    size: usize,
}

fn write_sh(f: &mut [u8], shoff: usize, s: ShSpec) {
    let o = shoff + s.idx * 64;
    put32(f, o, s.name);
    put32(f, o + 4, s.ty);
    put64(f, o + 8, s.flags);
    put64(f, o + 16, s.addr);
    put64(f, o + 24, s.off as u64);
    put64(f, o + 32, s.size as u64);
    put64(f, o + 48, 16);
}

#[test]
fn dwarf_loader_collects_subprogram_rows() {
    let elf = dwarf_elf(true);
    let bin = binscout::loader::load(&elf).expect("fixture must load");
    let funcs = &bin.debug_funcs;
    assert_eq!(funcs.len(), 4, "one row per subprogram: {funcs:?}");
    assert_eq!(funcs[0].address, 0x400000);
    assert_eq!(funcs[0].name.as_deref(), Some("_Z5alphav"));
    assert_eq!(funcs[0].end, Some(0x400001));
    assert_eq!(funcs[1].address, 0x400010);
    assert_eq!(funcs[1].name.as_deref(), Some("beta"));
    assert_eq!(funcs[1].end, Some(0x400012));
    assert_eq!(funcs[2].address, 0x400020);
    assert_eq!(funcs[2].name, None);
    assert_eq!(funcs[2].end, None);
    assert_eq!(funcs[3].address, 0x400030);
    assert_eq!(funcs[3].name.as_deref(), Some("delta"));
    assert_eq!(funcs[3].end, None);
}

#[test]
fn dwarf_seeds_carry_debug_reason_and_names() {
    let dir = common::tmpdir("dwarf-seeds");
    let bin = common::write_bin(&dir, "dwarf.elf", &dwarf_elf(true));
    let db = common::temp_db(&dir, "dwarf");
    let p = binscout::Project::open_with_db(&bin, &db).expect("fixture must open");
    for (addr, name) in [
        (0x400000u64, Some("_Z5alphav")),
        (0x400010, Some("beta")),
        (0x400020, None),
        (0x400030, Some("delta")),
    ] {
        let meta = p.func_meta(addr).expect("debug seed must decode");
        assert_eq!(meta.entry, addr);
        assert_eq!(p.function_name(addr).as_deref(), name);
        assert!(
            meta.reasons.contains(&DiscoveryReason::Debug),
            "{addr:#x} reasons lack debug: {:?}",
            meta.reasons
        );
    }
    assert_eq!(p.project_info().debug_funcs, 4);
    common::cleanup(&dir);
}

#[test]
fn debug_file_attaches_names_to_stripped_binary() {
    let dir = common::tmpdir("debug-file");
    let stripped = common::write_bin(&dir, "stripped.elf", &dwarf_elf(false));
    let ext = common::write_bin(&dir, "full.elf", &dwarf_elf(true));
    let db = common::temp_db(&dir, "stripped");
    let plain = binscout::Project::open_with_db(&stripped, &db).expect("stripped must open");
    assert_eq!(plain.project_info().debug_funcs, 0);
    assert_eq!(plain.function_name(0x400010), None);
    let debug = binscout::DebugOptions {
        pdb: None,
        debug_file: Some(ext.clone()),
    };
    let db2 = common::temp_db(&dir, "stripped-debug");
    let p = binscout::Project::open_with_db_and_debug(&stripped, &db2, &debug)
        .expect("external DWARF must attach");
    assert_eq!(p.project_info().debug_funcs, 4);
    assert_eq!(p.function_name(0x400010).as_deref(), Some("beta"));
    let meta = p.func_meta(0x400010).expect("beta must decode");
    assert!(meta.reasons.contains(&DiscoveryReason::Debug));
    common::cleanup(&dir);
}

#[test]
fn debug_file_without_dwarf_sections_errors() {
    let dir = common::tmpdir("debug-file-empty");
    let stripped = common::write_bin(&dir, "stripped.elf", &dwarf_elf(false));
    let debug = binscout::DebugOptions {
        pdb: None,
        debug_file: Some(stripped.clone()),
    };
    let db = common::temp_db(&dir, "stripped");
    let err = binscout::Project::open_with_db_and_debug(&stripped, &db, &debug).unwrap_err();
    assert!(
        err.to_string().contains("no DWARF sections"),
        "unexpected: {err:?}"
    );
    common::cleanup(&dir);
}

#[test]
fn debug_file_must_be_an_object() {
    let dir = common::tmpdir("debug-file-garbage");
    let stripped = common::write_bin(&dir, "stripped.elf", &dwarf_elf(false));
    let garbage = common::write_bin(&dir, "garbage.bin", b"not an object at all");
    let debug = binscout::DebugOptions {
        pdb: None,
        debug_file: Some(garbage),
    };
    let db = common::temp_db(&dir, "stripped");
    let err = binscout::Project::open_with_db_and_debug(&stripped, &db, &debug).unwrap_err();
    assert!(
        err.to_string().contains("not an object"),
        "unexpected: {err:?}"
    );
    common::cleanup(&dir);
}

#[test]
fn pdb_end_to_end_names_and_bounds() {
    let dir = common::tmpdir("pdb-e2e");
    let exe = common::write_bin(&dir, "mini.exe", include_bytes!("fixtures/pdb-mini.exe"));
    let pdb_path = dir.join("mini.pdb");
    std::fs::write(&pdb_path, include_bytes!("fixtures/pdb-mini.pdb")).expect("write pdb");
    let db = common::temp_db(&dir, "pdb");
    let debug = binscout::DebugOptions {
        pdb: Some(pdb_path.clone()),
        debug_file: None,
    };
    let p =
        binscout::Project::open_with_db_and_debug(&exe, &db, &debug).expect("pdb open must work");
    assert_eq!(p.project_info().debug_funcs, 2, "two pdb rows attach");
    let rows = p.functions_filtered(&binscout::FunctionFilter::default(), 0, 1024);
    let names: Vec<String> = rows
        .iter()
        .filter_map(|f| f["name"].as_str().map(str::to_string))
        .collect();
    assert!(
        names.iter().any(|n| n.contains("main")),
        "main must be named: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.contains("helper")),
        "helper must be named: {names:?}"
    );
    for f in &rows {
        if f["name"].as_str().is_some_and(|n| n.contains("main")) {
            let entry = f["entry"].as_u64().expect("entry");
            let meta = p.func_meta(entry).expect("main must decode");
            assert!(meta.reasons.contains(&DiscoveryReason::Debug));
        }
    }
    common::cleanup(&dir);
}

#[test]
fn pdb_funcs_map_procedures_to_bounds() {
    let pe = include_bytes!("fixtures/pdb-mini.exe");
    let pdb = binscout::loader::debuginfo::DebugFile {
        bytes: include_bytes!("fixtures/pdb-mini.pdb").to_vec(),
        label: "--pdb pdb-mini.pdb".to_string(),
    };
    let mut meta = 0u64;
    let funcs =
        binscout::loader::debuginfo::pdb_funcs(pe, &pdb, binscout::disasm::Arch::X86_64, &mut meta)
            .expect("fixture pdb must parse");
    // Two publics plus two procedures dedupe to two rows; the helper
    // public (no length) loses to the procedure (with length), so both
    // rows keep exact bounds.
    assert_eq!(funcs.len(), 2, "publics+procedures dedupe: {funcs:?}");
    let helper = funcs
        .iter()
        .find(|f| f.name.as_deref().is_some_and(|n| n.contains("helper")))
        .expect("helper row: {funcs:?}");
    assert_eq!(helper.address, 0x140001000);
    assert_eq!(helper.end, Some(0x140001010));
    let main = funcs
        .iter()
        .find(|f| f.name.as_deref().is_some_and(|n| n.contains("main")))
        .expect("main row: {funcs:?}");
    let end = main.end.expect("procedures carry lengths");
    assert!(end > main.address, "end must follow start");
}

#[test]
fn pdb_rejects_garbage_elf_and_raw() {
    let dir = common::tmpdir("pdb-rejects");
    // Garbage bytes are not a PDB.
    let garbage = common::write_bin(&dir, "garbage.pdb", b"not a pdb");
    let exe = common::write_bin(&dir, "mini.exe", include_bytes!("fixtures/pdb-mini.exe"));
    let debug = binscout::DebugOptions {
        pdb: Some(garbage),
        debug_file: None,
    };
    let db = common::temp_db(&dir, "pdb");
    let err = binscout::Project::open_with_db_and_debug(&exe, &db, &debug).unwrap_err();
    assert!(err.to_string().contains("bad PDB"), "unexpected: {err:?}");

    // ELF binaries reject --pdb.
    let elf = common::write_bin(&dir, "plain.elf", &dwarf_elf(false));
    let pdb_path = dir.join("mini.pdb");
    std::fs::write(&pdb_path, include_bytes!("fixtures/pdb-mini.pdb")).expect("write pdb");
    let debug = binscout::DebugOptions {
        pdb: Some(pdb_path),
        debug_file: None,
    };
    let db = common::temp_db(&dir, "elf");
    let err = binscout::Project::open_with_db_and_debug(&elf, &db, &debug).unwrap_err();
    assert!(
        err.to_string().contains("needs a PE binary"),
        "unexpected: {err:?}"
    );
    common::cleanup(&dir);
}

#[test]
fn pdb_missing_file_is_not_found_never_a_fetch() {
    let dir = common::tmpdir("pdb-missing");
    let exe = common::write_bin(&dir, "mini.exe", include_bytes!("fixtures/pdb-mini.exe"));
    // A URL-looking value is just a nonexistent local path: no fetch is
    // ever attempted, so this fails fast with NotFound.
    for missing in [
        dir.join("no-such.pdb"),
        std::path::PathBuf::from("https://example.invalid/x.pdb"),
    ] {
        let debug = binscout::DebugOptions {
            pdb: Some(missing),
            debug_file: None,
        };
        let db = common::temp_db(&dir, "pdb");
        let err = binscout::Project::open_with_db_and_debug(&exe, &db, &debug).unwrap_err();
        assert!(
            matches!(err, binscout::error::Error::NotFound(_)),
            "local-only open, no fetch: {err:?}"
        );
    }
    common::cleanup(&dir);
}

#[test]
fn debug_inputs_join_snapshot_identity() {
    let dir = common::tmpdir("debug-identity");
    let stripped = common::write_bin(&dir, "stripped.elf", &dwarf_elf(false));
    let ext = common::write_bin(&dir, "full.elf", &dwarf_elf(true));
    let debug = binscout::DebugOptions {
        pdb: None,
        debug_file: Some(ext.clone()),
    };
    let db = common::temp_db(&dir, "idem");

    // Open with debug info and persist.
    let p = binscout::Project::open_with_db_and_debug(&stripped, &db, &debug)
        .expect("debug open must work");
    assert_eq!(p.function_name(0x400010).as_deref(), Some("beta"));
    p.save().expect("save snapshot");

    // Same inputs replay the snapshot.
    let q = binscout::Project::open_with_db_and_debug(&stripped, &db, &debug)
        .expect("same inputs must reopen");
    assert!(q.snapshot_fresh(), "same debug inputs must hit");
    assert_eq!(q.function_name(0x400010).as_deref(), Some("beta"));

    // Dropping the inputs re-analyzes instead of replaying debug names.
    let r = binscout::Project::open_with_db(&stripped, &db).expect("plain reopen must work");
    assert!(!r.snapshot_fresh(), "dropped inputs must miss");
    assert_eq!(r.function_name(0x400010), None);
    common::cleanup(&dir);
}

#[test]
fn cli_debug_file_flag_names_functions() {
    let dir = common::tmpdir("cli-debug-file");
    let stripped = common::write_bin(&dir, "stripped.elf", &dwarf_elf(false));
    let ext = common::write_bin(&dir, "full.elf", &dwarf_elf(true));
    let db = common::temp_db(&dir, "cli");
    let out = std::process::Command::new(common::binscout_bin())
        .args([
            "--db",
            &db.to_string_lossy(),
            "--debug-file",
            &ext.to_string_lossy(),
            "func",
            &stripped.to_string_lossy(),
            "0x400010",
        ])
        .output()
        .expect("run binscout");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON value");
    assert_eq!(v["name"], "beta");
    assert!(
        v["reasons"]
            .as_array()
            .expect("reasons array")
            .iter()
            .any(|r| r == "debug"),
        "reasons must include debug: {v}"
    );
    common::cleanup(&dir);
}

#[test]
fn cli_pdb_flag_names_pe_functions() {
    let dir = common::tmpdir("cli-pdb");
    let exe = common::write_bin(&dir, "mini.exe", include_bytes!("fixtures/pdb-mini.exe"));
    let pdb_path = dir.join("mini.pdb");
    std::fs::write(&pdb_path, include_bytes!("fixtures/pdb-mini.pdb")).expect("write pdb");
    let db = common::temp_db(&dir, "cli");
    let out = std::process::Command::new(common::binscout_bin())
        .args([
            "--db",
            &db.to_string_lossy(),
            "--pdb",
            &pdb_path.to_string_lossy(),
            "functions",
            &exe.to_string_lossy(),
            "--limit",
            "100",
        ])
        .output()
        .expect("run binscout");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON value");
    let rows = v["items"].as_array().expect("functions is an array");
    assert!(
        rows.iter()
            .any(|r| r["name"].as_str().is_some_and(|n| n.contains("main")))
    );
    assert!(
        rows.iter()
            .any(|r| r["name"].as_str().is_some_and(|n| n.contains("helper")))
    );
    common::cleanup(&dir);
}

#[test]
fn cli_pdb_garbage_is_invalid() {
    let dir = common::tmpdir("cli-pdb-garbage");
    let exe = common::write_bin(&dir, "mini.exe", include_bytes!("fixtures/pdb-mini.exe"));
    let garbage = common::write_bin(&dir, "garbage.pdb", b"not a pdb");
    let db = common::temp_db(&dir, "cli");
    let out = std::process::Command::new(common::binscout_bin())
        .args([
            "--db",
            &db.to_string_lossy(),
            "--pdb",
            &garbage.to_string_lossy(),
            "load",
            &exe.to_string_lossy(),
        ])
        .output()
        .expect("run binscout");
    assert!(!out.status.success(), "garbage pdb must fail");
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON value");
    assert_eq!(v["kind"], "invalid");
    common::cleanup(&dir);
}

#[test]
fn cli_pdb_with_raw_is_rejected() {
    let dir = common::tmpdir("cli-pdb-raw");
    let raw = common::write_bin(&dir, "raw.bin", b"\x90\x90\xc3");
    let garbage = common::write_bin(&dir, "x.pdb", b"not a pdb");
    let db = common::temp_db(&dir, "cli");
    let out = std::process::Command::new(common::binscout_bin())
        .args([
            "--db",
            &db.to_string_lossy(),
            "--raw",
            "--arch",
            "x86_64",
            "--base",
            "0x0",
            "--pdb",
            &garbage.to_string_lossy(),
            "load",
            &raw.to_string_lossy(),
        ])
        .output()
        .expect("run binscout");
    assert!(!out.status.success(), "--pdb with --raw must fail");
    common::cleanup(&dir);
}

#[test]
fn mcp_func_debug_file_names_stripped() {
    let dir = common::tmpdir("mcp-debug-file");
    let stripped = common::write_bin(&dir, "stripped.elf", &dwarf_elf(false));
    let full = common::write_bin(&dir, "full.elf", &dwarf_elf(true));
    let db = common::temp_db(&dir, "mcp");
    let v = mcp_tool_once(
        10,
        "func",
        json!({
            "binary": stripped.display().to_string(),
            "db": db.display().to_string(),
            "addr": "0x400010",
            "debug_file": full.display().to_string(),
        }),
    );
    assert_eq!(v["name"], "beta");
    assert!(
        v["reasons"]
            .as_array()
            .expect("reasons array")
            .iter()
            .any(|r| r == "debug"),
        "reasons include debug: {v}"
    );
    common::cleanup(&dir);
}

#[test]
fn mcp_func_without_debug_file_is_null() {
    let dir = common::tmpdir("mcp-debug-missing");
    let stripped = common::write_bin(&dir, "stripped.elf", &dwarf_elf(false));
    let db = common::temp_db(&dir, "mcp");
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
            "func",
            json!({
                "binary": stripped.display().to_string(),
                "db": db.display().to_string(),
                "addr": "0x400010",
            }),
        ),
    ];
    let resps = mcp_session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let resp = &resps[1];
    if let Some(result) = resp.get("result") {
        let text = result["content"][0]["text"].as_str().expect("text");
        let v: Value = serde_json::from_str(text).expect("tool json");
        assert!(v["name"].is_null(), "stripped name must be null: {v}");
    } else {
        assert!(
            resp["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("not found")),
            "stripped 0x400010 stays unnamed: {resp}"
        );
    }
    common::cleanup(&dir);
}

#[test]
fn mcp_func_cache_separates_debug_inputs() {
    let dir = common::tmpdir("mcp-debug-cache");
    let stripped = common::write_bin(&dir, "stripped.elf", &dwarf_elf(false));
    let full = common::write_bin(&dir, "full.elf", &dwarf_elf(true));
    let db = common::temp_db(&dir, "mcp");
    let bin = stripped.display().to_string();
    let db_s = db.display().to_string();
    let full_s = full.display().to_string();
    let b = || Value::String(bin.clone());
    let d = || Value::String(db_s.clone());
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
            "func",
            json!({"binary": b(), "db": d(), "addr": "0x400010"}),
        ),
        mcp_call(
            11,
            "func",
            json!({"binary": b(), "db": d(), "addr": "0x400010", "debug_file": full_s}),
        ),
    ];
    let resps = mcp_session(&lines);
    assert_eq!(resps.len(), 3, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("id"), r))
        .collect();
    let plain_resp = by_id[&10];
    if let Some(result) = plain_resp.get("result") {
        let text = result["content"][0]["text"].as_str().expect("text");
        let plain: Value = serde_json::from_str(text).expect("plain json");
        assert!(plain["name"].is_null(), "plain open stays unnamed: {plain}");
    } else {
        assert!(
            plain_resp["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("not found")),
            "plain open stays unnamed: {plain_resp}"
        );
    }
    let with: Value = serde_json::from_str(mcp_tool_text(by_id[&11])).expect("debug json");
    assert_eq!(with["name"], "beta");
    common::cleanup(&dir);
}

#[test]
fn mcp_functions_pdb_matches_cli() {
    let dir = common::tmpdir("mcp-pdb");
    let exe = common::write_bin(&dir, "mini.exe", include_bytes!("fixtures/pdb-mini.exe"));
    let pdb_path = dir.join("mini.pdb");
    std::fs::write(&pdb_path, include_bytes!("fixtures/pdb-mini.pdb")).expect("write pdb");
    let cli_db = common::temp_db(&dir, "cli");
    let out = Command::new(common::binscout_bin())
        .args([
            "--db",
            &cli_db.to_string_lossy(),
            "--pdb",
            &pdb_path.to_string_lossy(),
            "functions",
            &exe.to_string_lossy(),
            "--limit",
            "100",
        ])
        .output()
        .expect("run binscout");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cli: Value = serde_json::from_slice(&out.stdout).expect("cli json");
    let mut cli_names: Vec<String> = cli["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|r| r["name"].as_str().map(str::to_string))
        .collect();
    cli_names.sort();
    let mcp_db = common::temp_db(&dir, "mcp");
    let v = mcp_tool_once(
        10,
        "functions",
        json!({
            "binary": exe.display().to_string(),
            "db": mcp_db.display().to_string(),
            "pdb": pdb_path.display().to_string(),
            "limit": 100,
        }),
    );
    let mut mcp_names: Vec<String> = v["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|r| r["name"].as_str().map(str::to_string))
        .collect();
    mcp_names.sort();
    assert_eq!(mcp_names, cli_names, "MCP pdb names match CLI");
    assert!(mcp_names.iter().any(|n| n.contains("main")));
    assert!(mcp_names.iter().any(|n| n.contains("helper")));
    common::cleanup(&dir);
}

#[test]
fn mcp_batch_envelope_debug_file() {
    let dir = common::tmpdir("mcp-batch-debug");
    let stripped = common::write_bin(&dir, "stripped.elf", &dwarf_elf(false));
    let full = common::write_bin(&dir, "full.elf", &dwarf_elf(true));
    let db = common::temp_db(&dir, "mcp");
    let v = mcp_tool_once(
        10,
        "batch",
        json!({
            "binary": stripped.display().to_string(),
            "db": db.display().to_string(),
            "debug_file": full.display().to_string(),
            "ops": [{"tool": "func", "params": {"addr": "0x400010"}}],
        }),
    );
    let results = v["results"].as_array().expect("results");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["ok"]["name"], "beta");
    common::cleanup(&dir);
}

#[test]
fn mcp_batch_rejects_per_op_debug_keys() {
    let dir = common::tmpdir("mcp-batch-debug-reject");
    let stripped = common::write_bin(&dir, "stripped.elf", &dwarf_elf(false));
    let full = common::write_bin(&dir, "full.elf", &dwarf_elf(true));
    let db = common::temp_db(&dir, "mcp");
    let v = mcp_tool_once(
        10,
        "batch",
        json!({
            "binary": stripped.display().to_string(),
            "db": db.display().to_string(),
            "ops": [{"tool": "func", "params": {"addr": "0x400010", "debug_file": full.display().to_string()}}],
        }),
    );
    let results = v["results"].as_array().expect("results");
    assert_eq!(results.len(), 1);
    assert!(
        results[0]["error"]
            .as_str()
            .is_some_and(|m| m.contains("envelope")),
        "per-op debug_file names the envelope: {}",
        results[0]
    );
    common::cleanup(&dir);
}

#[test]
fn mcp_pdb_plus_raw_errors() {
    let dir = common::tmpdir("mcp-pdb-raw");
    let raw = common::write_bin(&dir, "raw.bin", b"\x90\x90\xc3");
    let pdb = common::write_bin(&dir, "x.pdb", b"not a pdb");
    let db = common::temp_db(&dir, "mcp");
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
            "func",
            json!({
                "binary": raw.display().to_string(),
                "db": db.display().to_string(),
                "addr": "0x0",
                "raw": {"arch": "x86_64", "base": "0x0"},
                "pdb": pdb.display().to_string(),
            }),
        ),
    ];
    let resps = mcp_session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    assert!(
        resps[1].get("error").is_some(),
        "pdb+raw must error: {resps:?}"
    );
    common::cleanup(&dir);
}

#[test]
fn mcp_tools_list_exposes_debug_params() {
    let lines = vec![
        mcp_req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        mcp_req(2, "tools/list", json!({})),
    ];
    let resps = mcp_session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let tools = resps[1]["result"]["tools"]
        .as_array()
        .expect("tools")
        .clone();
    for name in ["func", "functions", "batch"] {
        let tool = tools.iter().find(|t| t["name"] == name).expect(name);
        let props = tool["inputSchema"]["properties"]
            .as_object()
            .expect("props");
        assert!(props.contains_key("pdb"), "{name} exposes pdb");
        assert!(
            props.contains_key("debug_file"),
            "{name} exposes debug_file"
        );
    }
}
