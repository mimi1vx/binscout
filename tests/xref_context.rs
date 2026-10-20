//! Xref and string listing context: enriched rows carry the containing
//! function, display names, and string previews so agents skip follow-up
//! lookups; `strings --with-xrefs` lists referrers per string.

mod common;

use std::process::Command;

use serde_json::{Value, json};

use binscout::analysis::{StringsFilter, XrefKind};
use binscout::{Project, StringRow, XrefRow};

use common::{binscout_bin, builders, cleanup, temp_db, tmpdir, write_bin, write_fixture};

fn filter_all() -> StringsFilter {
    StringsFilter {
        pattern: None,
        min_len: None,
        section: None,
        include_code: true,
        start: 0,
        limit: 50,
    }
}

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

#[test]
fn xref_rows_carry_listing_context() {
    let dir = tmpdir("xref-ctx");
    let db = temp_db(&dir, "basic");
    let bin = write_fixture(&dir, builders::BASIC_NAME);
    let p = Project::open_with_db(&bin, &db).expect("fixture must open");

    let (total, rows) = p.query_xref_rows_page(
        Some(builders::BASIC_STRING_VA),
        None,
        Some(XrefKind::String),
        0,
        50,
    );
    assert_eq!(total, 2);
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.to, builders::BASIC_STRING_VA);
        assert_eq!(row.kind, XrefKind::String);
        assert_eq!(row.from_func, Some(builders::BASIC_ENTRY_VA));
        assert_eq!(row.from_func_name.as_deref(), Some(builders::BASIC_EXPORT));
        assert_eq!(row.to_name, None);
        assert_eq!(row.to_string.as_deref(), Some(builders::BASIC_STRING));
    }
    assert_eq!(
        rows.iter().map(|r| r.from).collect::<Vec<_>>(),
        [builders::TEXT_VA + 3, builders::TEXT_VA + 8]
    );

    // Golden row: every field, including hex twins.
    assert_eq!(
        serde_json::to_value(&rows[0]).expect("row serializes"),
        json!({
            "from": builders::TEXT_VA + 3, "from_hex": "0x401003",
            "to": builders::BASIC_STRING_VA, "to_hex": "0x402100",
            "kind": "String",
            "from_func": builders::BASIC_ENTRY_VA, "from_func_hex": "0x401000",
            "from_func_name": builders::BASIC_EXPORT,
            "to_name": null, "to_string": builders::BASIC_STRING,
        })
    );

    // Data-kind rows share the referrer but carry no string preview.
    let (_, data) = p.query_xref_rows_page(
        Some(builders::BASIC_STRING_VA),
        None,
        Some(XrefKind::Data),
        0,
        50,
    );
    assert_eq!(data.len(), 2);
    assert!(data.iter().all(|r| r.to_string.is_none()));
    assert!(
        data.iter()
            .all(|r| r.from_func == Some(builders::BASIC_ENTRY_VA))
    );
    cleanup(&dir);
}

#[test]
fn xref_rows_resolve_code_target_names() {
    // Raw x86-64: `call +5` at 0 targets 0xa (its own function via the
    // prologue-scan fallback), `ret` at 5, padding, `ret` at 0xa.
    let dir = tmpdir("xref-ctx-code");
    let bin = write_bin(
        &dir,
        "call.bin",
        &[
            0xE8, 0x05, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3,
        ],
    );
    let db = temp_db(&dir, "call");
    let mut p = Project::open_with_db(&bin, &db).expect("raw blob must open");

    let (_, rows) = p.query_xref_rows_page(None, None, Some(XrefKind::Code), 0, 50);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].from, 0);
    assert_eq!(rows[0].to, 0xa);
    assert_eq!(rows[0].from_func, Some(0));
    assert_eq!(rows[0].from_func_name, None);
    assert_eq!(rows[0].to_name.as_deref(), Some("func@0xa"));

    // Rename-resolved names win over the fallback on both ends.
    p.rename_function(0xa, "callee").expect("rename works");
    p.rename_function(0, "entry_fn").expect("rename works");
    let (_, rows) = p.query_xref_rows_page(None, None, Some(XrefKind::Code), 0, 50);
    assert_eq!(rows[0].to_name.as_deref(), Some("callee"));
    assert_eq!(rows[0].from_func_name.as_deref(), Some("entry_fn"));
    cleanup(&dir);
}

/// Minimal PE32+ (x86-64) with one import (`test64.dll!foo`) called via
/// `call [rip+slot]` from the entry point.
fn pe64_with_iat_call() -> Vec<u8> {
    const BASE: u64 = 0x140_000_000;
    const TEXT_RVA: u32 = 0x1000;
    const RDATA_RVA: u32 = 0x2000;
    const SLOT_RVA: u32 = RDATA_RVA + 0x38;
    const SLOT: u64 = BASE + SLOT_RVA as u64;
    const ENTRY: u64 = BASE + TEXT_RVA as u64;
    fn put16(v: &mut [u8], off: usize, x: u16) {
        v[off..off + 2].copy_from_slice(&x.to_le_bytes());
    }
    fn put32(v: &mut [u8], off: usize, x: u32) {
        v[off..off + 4].copy_from_slice(&x.to_le_bytes());
    }
    fn put64(v: &mut [u8], off: usize, x: u64) {
        v[off..off + 8].copy_from_slice(&x.to_le_bytes());
    }
    let mut f = vec![0u8; 0x200];
    f[0] = b'M';
    f[1] = b'Z';
    put32(&mut f, 0x3C, 0x80);
    f[0x80..0x84].copy_from_slice(b"PE\0\0");
    let c = 0x84;
    put16(&mut f, c, 0x8664);
    put16(&mut f, c + 2, 2);
    put32(&mut f, c + 4, 0x1234_5678);
    put16(&mut f, c + 16, 0xF0);
    put16(&mut f, c + 18, 0x22);
    let o = 0x98;
    put16(&mut f, o, 0x20B);
    put32(&mut f, o + 16, TEXT_RVA);
    put32(&mut f, o + 20, TEXT_RVA);
    put64(&mut f, o + 24, BASE);
    put32(&mut f, o + 32, 0x1000);
    put32(&mut f, o + 36, 0x200);
    put32(&mut f, o + 60, 0x200);
    put32(&mut f, o + 108, 16);
    put32(&mut f, o + 120, RDATA_RVA);
    put32(&mut f, o + 124, 40);
    let s = 0x188;
    f[s..s + 5].copy_from_slice(b".text");
    put32(&mut f, s + 8, 0x200);
    put32(&mut f, s + 12, TEXT_RVA);
    put32(&mut f, s + 16, 0x200);
    put32(&mut f, s + 20, 0x200);
    put32(&mut f, s + 36, 0x6000_0020);
    let s = 0x188 + 40;
    f[s..s + 6].copy_from_slice(b".rdata");
    put32(&mut f, s + 8, 0x200);
    put32(&mut f, s + 12, RDATA_RVA);
    put32(&mut f, s + 16, 0x200);
    put32(&mut f, s + 20, 0x400);
    put32(&mut f, s + 36, 0x4000_0040);

    let mut text = vec![0u8; 0x200];
    let disp = (SLOT.wrapping_sub(ENTRY + 6)) as u32;
    text[0] = 0xFF;
    text[1] = 0x15;
    text[2..6].copy_from_slice(&disp.to_le_bytes());
    text[6] = 0xC3;

    let mut r = vec![0u8; 0x200];
    put32(&mut r, 0x00, RDATA_RVA + 0x28);
    put32(&mut r, 0x0C, RDATA_RVA + 0x60);
    put32(&mut r, 0x10, SLOT_RVA);
    put64(&mut r, 0x28, (RDATA_RVA + 0x48) as u64);
    put64(&mut r, 0x30, 0);
    put64(&mut r, 0x38, (RDATA_RVA + 0x48) as u64);
    put64(&mut r, 0x40, 0);
    put16(&mut r, 0x48, 0);
    r[0x4A..0x4E].copy_from_slice(b"foo\0");
    r[0x60..0x6B].copy_from_slice(b"test64.dll\0");

    f.extend_from_slice(&text);
    f.extend_from_slice(&r);
    f
}

#[test]
fn xref_row_names_import_targets() {
    let dir = tmpdir("xref-ctx-import");
    let bin = write_bin(&dir, "iat.exe", &pe64_with_iat_call());
    let db = temp_db(&dir, "iat");
    let p = Project::open_with_db(&bin, &db).expect("PE64 project must open");
    let slot = 0x140_000_000u64 + 0x2038;

    let (total, rows) = p.query_xref_rows_page(Some(slot), None, Some(XrefKind::Import), 0, 50);
    assert_eq!(total, 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].to_name.as_deref(), Some("foo"));
    assert_eq!(rows[0].to_string, None);
    assert!(rows[0].from_func.is_some());
    cleanup(&dir);
}

#[test]
fn strings_with_xrefs_lists_referrers() {
    let dir = tmpdir("strings-xrefs");
    let db = temp_db(&dir, "basic");
    let bin = write_fixture(&dir, builders::BASIC_NAME);
    let p = Project::open_with_db(&bin, &db).expect("fixture must open");

    let rows = p
        .query_strings_rows(&filter_all(), true)
        .expect("query works");
    let hit = rows
        .iter()
        .find(|r| r.hit.vaddr == Some(builders::BASIC_STRING_VA))
        .expect("marker string present");
    let refs = hit.xrefs.as_ref().expect("flag sets the list");
    assert_eq!(refs.len(), 2);
    assert_eq!(
        refs.iter().map(|r| r.from).collect::<Vec<_>>(),
        [builders::TEXT_VA + 3, builders::TEXT_VA + 8]
    );
    for r in refs {
        assert_eq!(r.kind, XrefKind::String);
        assert_eq!(r.from_func, Some(builders::BASIC_ENTRY_VA));
        assert_eq!(r.from_func_name.as_deref(), Some(builders::BASIC_EXPORT));
    }

    // Without the flag the list is absent and the JSON matches StringHit.
    let plain = p
        .query_strings_rows(&filter_all(), false)
        .expect("query works");
    let hit = plain
        .iter()
        .find(|r| r.hit.vaddr == Some(builders::BASIC_STRING_VA))
        .expect("marker string present");
    assert_eq!(hit.xrefs, None);
    assert_eq!(
        serde_json::to_value(hit).expect("row serializes"),
        serde_json::to_value(&hit.hit).expect("hit serializes"),
    );
    cleanup(&dir);
}

#[test]
fn strings_decoded_rows_carry_optional_refs() {
    use binscout::loader::strings::DecodeSpec;
    let dir = tmpdir("strings-xrefs-decode");
    let db = temp_db(&dir, "basic");
    let bin = write_fixture(&dir, builders::BASIC_NAME);
    let p = Project::open_with_db(&bin, &db).expect("fixture must open");

    let filter = StringsFilter {
        pattern: Some(builders::BASIC_STRING.to_string()),
        ..filter_all()
    };
    // An unrelated transform hides the marker: refs resolve but find
    // nothing, which must stay a normal empty page, not an error.
    let rows = p
        .query_strings_decoded_rows(&filter, DecodeSpec::Xor(0x41), true)
        .expect("decoded query works");
    assert!(
        rows.iter()
            .all(|r| r.xrefs.as_ref().is_some_and(Vec::is_empty))
    );
    cleanup(&dir);
}

#[test]
fn old_rows_decode_without_context_fields() {
    let row: XrefRow =
        serde_json::from_str(r#"{"from":1,"to":2,"kind":"String"}"#).expect("old rows decode");
    assert_eq!(row.from_func, None);
    assert_eq!(row.from_func_name, None);
    assert_eq!(row.to_name, None);
    assert_eq!(row.to_string, None);

    let hit: StringRow =
        serde_json::from_str(r#"{"offset":1,"vaddr":4096,"encoding":"Ascii","value":"hi"}"#)
            .expect("old rows decode");
    assert_eq!(hit.xrefs, None);
}

#[test]
fn cli_xrefs_carry_context_and_strings_with_xrefs() {
    let dir = tmpdir("xref-ctx-cli");
    let bin = write_fixture(&dir, builders::BASIC_NAME);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "x").display().to_string();
    let d = db.as_str();
    let hex = format!("{:#x}", builders::BASIC_STRING_VA);

    let (ok, v) = run(&["--db", d, "xrefs", &bin_s, "--to", &hex, "--kind", "string"]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 2);
    for row in v["items"].as_array().expect("items array") {
        assert_eq!(row["from_func"], builders::BASIC_ENTRY_VA);
        assert_eq!(row["from_func_hex"], "0x401000");
        assert_eq!(row["from_func_name"], builders::BASIC_EXPORT);
        assert_eq!(row["to_name"], Value::Null);
        assert_eq!(row["to_string"], builders::BASIC_STRING);
    }

    let (ok, v) = run(&["--db", d, "strings", &bin_s, "--pattern", "SAVE"]);
    assert!(ok, "{v}");
    assert!(
        v["items"][0].get("xrefs").is_none(),
        "flag off omits the list: {v}"
    );

    let (ok, v) = run(&[
        "--db",
        d,
        "strings",
        &bin_s,
        "--pattern",
        "SAVE",
        "--with-xrefs",
    ]);
    assert!(ok, "{v}");
    let refs = v["items"][0]["xrefs"].as_array().expect("xrefs list");
    assert_eq!(refs.len(), 2);
    assert_eq!(refs[0]["from_func_name"], builders::BASIC_EXPORT);
    cleanup(&dir);
}
