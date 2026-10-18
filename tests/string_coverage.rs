//! String coverage (rsdbg-em6.18): multibyte UTF-8 and BMP-letter
//! extraction, rolling multi-byte XOR, and the base64 decoded view.
//!
//! Raw blobs map at base 0 with executable segments, so every query
//! below opts in with `include_code`; offsets double as vaddrs.

mod common;

use std::process::Command;

use serde_json::Value;

use binscout::analysis::StringsFilter;
use binscout::loader::strings::{DecodeSpec, Encoding};

use common::{cleanup, temp_db, tmpdir, write_bin};

fn filter() -> StringsFilter {
    StringsFilter {
        include_code: true,
        limit: 1024,
        ..StringsFilter::default()
    }
}

fn run_cli(args: &[&str]) -> (bool, Value) {
    let out = Command::new(common::binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value)
}

#[test]
fn utf8_cjk_cyrillic_emoji_extracted() {
    let dir = tmpdir("strcov-utf8");
    let mut buf = vec![0x00];
    buf.extend_from_slice(b"hello ");
    buf.extend_from_slice("世界".as_bytes());
    buf.push(0x00);
    buf.extend_from_slice("Привет".as_bytes());
    buf.push(0x00);
    buf.extend_from_slice("🎉party".as_bytes());
    buf.push(0x00);
    let bin = write_bin(&dir, "utf8.bin", &buf);
    let db = temp_db(&dir, "utf8");
    let p = binscout::Project::open_with_db(&bin, &db).expect("blob must open");
    let rows = p.query_strings(&filter()).expect("query works");

    let utf8: Vec<(&str, usize)> = rows
        .iter()
        .filter(|h| h.encoding == Encoding::Utf8)
        .map(|h| (h.value.as_str(), h.offset))
        .collect();
    assert_eq!(
        utf8,
        [("hello 世界", 1), ("Привет", 14), ("🎉party", 27),],
        "multibyte runs report whole with original offsets: {utf8:?}"
    );
    for (value, offset) in &utf8 {
        assert!(
            !value.is_ascii(),
            "Utf8 hits always hold non-ASCII: {value:?}"
        );
        let hit = rows
            .iter()
            .find(|h| h.offset == *offset && h.encoding == Encoding::Utf8)
            .expect("hit present");
        assert_eq!(hit.vaddr, Some(*offset as u64), "raw base is 0");
    }
    // The ASCII channel still reports the printable prefixes untouched.
    let ascii: Vec<&str> = rows
        .iter()
        .filter(|h| h.encoding == Encoding::Ascii)
        .map(|h| h.value.as_str())
        .collect();
    assert!(ascii.contains(&"hello "), "{ascii:?}");
    assert!(ascii.contains(&"party"), "{ascii:?}");

    // A pattern matches decoded multibyte text.
    let found = p
        .query_strings(&StringsFilter {
            pattern: Some("世界".to_string()),
            ..filter()
        })
        .expect("pattern query works");
    assert_eq!(
        found.iter().map(|h| h.value.as_str()).collect::<Vec<_>>(),
        ["hello 世界"]
    );
    cleanup(&dir);
}

#[test]
fn utf16le_bmp_pure_scripts_reported() {
    let dir = tmpdir("strcov-bmp");
    let mut buf = vec![0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00];
    buf.extend_from_slice(&[0xFF, 0xFF]);
    buf.extend_from_slice(&[
        0x1F, 0x04, 0x40, 0x04, 0x38, 0x04, 0x32, 0x04, 0x35, 0x04, 0x42, 0x04,
    ]);
    // "一二三四" LE: every unit carries a control/high byte, so no ASCII
    // run can cover the span (printable-bytes-only CJK would read as
    // ASCII instead — the documented shadowing edge). NUL separators:
    // `(FF,00)` would decode to ÿ and hijack the cursor one byte early.
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x4E, 0x8C, 0x4E, 0x09, 0x4E, 0xDB, 0x56]);
    let bin = write_bin(&dir, "bmp.bin", &buf);
    let db = temp_db(&dir, "bmp");
    let p = binscout::Project::open_with_db(&bin, &db).expect("blob must open");
    let rows = p.query_strings(&filter()).expect("query works");

    let at = |offset: usize| {
        rows.iter()
            .find(|h| h.offset == offset)
            .unwrap_or_else(|| panic!("hit at {offset}: {rows:?}"))
    };
    assert_eq!(at(0).encoding, Encoding::Utf16Le);
    assert_eq!(at(0).value, "ABCD");
    assert_eq!(at(10).encoding, Encoding::Utf16LeBmp);
    assert_eq!(at(10).value, "Привет");
    assert_eq!(at(24).encoding, Encoding::Utf16LeBmp);
    assert_eq!(at(24).value, "一二三四");
    // Classic LE never merges into BMP readings.
    assert!(
        rows.iter().all(|h| h.encoding != Encoding::Utf16Be),
        "{rows:?}"
    );
    cleanup(&dir);
}

#[test]
fn ascii_only_has_no_multibyte_hits() {
    let dir = tmpdir("strcov-ascii");
    let bin = write_bin(&dir, "ascii.bin", b"\x00test words here\x00another one\x00");
    let db = temp_db(&dir, "ascii");
    let p = binscout::Project::open_with_db(&bin, &db).expect("blob must open");
    let rows = p.query_strings(&filter()).expect("query works");
    assert!(!rows.is_empty());
    assert!(
        rows.iter().all(|h| h.encoding == Encoding::Ascii),
        "pure ASCII must not cast multibyte readings: {rows:?}"
    );
    cleanup(&dir);
}

#[test]
fn bmp_shadow_of_ascii_is_suppressed() {
    // "hello world" casts a Han-letter shadow at the odd offset, but the
    // ASCII reading explains every byte, so only the Ascii hit reports.
    let dir = tmpdir("strcov-shadow");
    let bin = write_bin(&dir, "shadow.bin", b"\x00hello world, this is ascii\x00");
    let db = temp_db(&dir, "shadow");
    let p = binscout::Project::open_with_db(&bin, &db).expect("blob must open");
    let rows = p.query_strings(&filter()).expect("query works");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].encoding, Encoding::Ascii);
    assert_eq!(rows[0].value, "hello world, this is ascii");
    cleanup(&dir);
}

#[test]
fn degenerate_periodic_bmp_blob_stays_silent() {
    // 4 KiB of two alternating Han units: single-script and consistent,
    // but degenerate fill, so the diversity guard rejects the whole run.
    let dir = tmpdir("strcov-degen");
    let mut buf = Vec::new();
    for i in 0..2048usize {
        let u: u16 = if i % 2 == 0 { 0x4E16 } else { 0x754C };
        buf.extend_from_slice(&u.to_le_bytes());
    }
    let bin = write_bin(&dir, "degen.bin", &buf);
    let db = temp_db(&dir, "degen");
    let p = binscout::Project::open_with_db(&bin, &db).expect("blob must open");
    let rows = p.query_strings(&filter()).expect("query works");
    assert!(
        rows.iter().all(|h| h.encoding != Encoding::Utf16LeBmp),
        "degenerate runs must not report: {rows:?}"
    );
    cleanup(&dir);
}

#[test]
fn rolling_xor_multi_byte_key_decodes() {
    const MARKER: &str = "rolling-treasure-42";
    const OFF: usize = 64;
    let dir = tmpdir("strcov-xorm");
    let mut blob = vec![0xFFu8; 256];
    for (i, b) in MARKER.bytes().enumerate() {
        blob[OFF + i] = b ^ [0x41, 0x42][i % 2];
    }
    let bin = write_bin(&dir, "xorm.bin", &blob);
    let db = temp_db(&dir, "xorm");
    let before = std::fs::read(&bin).expect("fixture readable");
    let p = binscout::Project::open_with_db(&bin, &db).expect("blob must open");

    let plain = p.query_strings(&filter()).expect("plain query works");
    assert!(!plain.iter().any(|h| h.value == MARKER));

    let rows = p
        .query_strings_decoded(&filter(), DecodeSpec::XorMulti(vec![0x41, 0x42]))
        .expect("decoded query works");
    let ascii: Vec<&str> = rows
        .iter()
        .filter(|h| h.encoding == Encoding::Ascii)
        .map(|h| h.value.as_str())
        .collect();
    assert_eq!(ascii, [MARKER]);
    let hit = rows
        .iter()
        .find(|h| h.encoding == Encoding::Ascii && h.value == MARKER)
        .expect("ascii marker");
    assert_eq!(hit.offset, OFF);
    assert_eq!(hit.vaddr, Some(OFF as u64));

    // A single-byte key is a different transform and misses the marker.
    let wrong = p
        .query_strings_decoded(&filter(), DecodeSpec::Xor(0x41))
        .expect("wrong-key view works");
    assert!(!wrong.iter().any(|h| h.value == MARKER));

    // CLI: the hex-key form decodes, the decoded view stays read-only.
    let bin_s = bin.display().to_string();
    let db_s = temp_db(&dir, "xorm-cli").display().to_string();
    let (ok, v) = run_cli(&[
        "--db",
        &db_s,
        "strings",
        &bin_s,
        "--decode",
        "xor:0x4142",
        "--include-code",
    ]);
    assert!(ok, "{v}");
    let vals: Vec<&str> = v
        .as_array()
        .expect("array")
        .iter()
        .filter(|r| r["encoding"] == "Ascii")
        .map(|r| r["value"].as_str().expect("row value"))
        .collect();
    assert_eq!(vals, [MARKER]);

    assert_eq!(std::fs::read(&bin).expect("fixture readable"), before);
    assert!(!db.exists(), "reads never create the sidecar");
    cleanup(&dir);
}

#[test]
fn base64_decoded_view_reports_plaintext() {
    let dir = tmpdir("strcov-b64");
    let mut buf = vec![0x00];
    buf.extend_from_slice(b"aGVsbG8td29ybGQ=");
    buf.push(0x00);
    buf.extend_from_slice(b"cGxlYXN1cmUu");
    buf.push(0x00);
    buf.extend_from_slice(b"AAAAAAAA");
    buf.push(0x00);
    buf.extend_from_slice(b"!!!!");
    buf.push(0x00);
    let bin = write_bin(&dir, "b64.bin", &buf);
    let db = temp_db(&dir, "b64");
    let p = binscout::Project::open_with_db(&bin, &db).expect("blob must open");

    // Plain extraction sees the blobs as ASCII, never as decoded views.
    let plain = p.query_strings(&filter()).expect("plain query works");
    assert!(
        plain.iter().all(|h| h.encoding != Encoding::Base64),
        "{plain:?}"
    );
    assert!(plain.iter().any(|h| h.value == "aGVsbG8td29ybGQ="));

    let rows = p
        .query_strings_decoded(&filter(), DecodeSpec::Base64)
        .expect("base64 view works");
    assert_eq!(
        rows.iter()
            .map(|h| (h.value.as_str(), h.offset, h.encoding))
            .collect::<Vec<_>>(),
        [
            ("hello-world", 1, Encoding::Base64),
            ("pleasure.", 18, Encoding::Base64),
        ],
        "blobs decode with original offsets: {rows:?}"
    );
    assert_eq!(rows[0].vaddr, Some(1));
    // "AAAAAAAA" is a syntactic candidate decoding to NULs: rejected by
    // the printable-text gate. "!!!!" is not a candidate at all.

    let bin_s = bin.display().to_string();
    let db_s = temp_db(&dir, "b64-cli").display().to_string();
    let (ok, v) = run_cli(&[
        "--db",
        &db_s,
        "strings",
        &bin_s,
        "--decode",
        "base64",
        "--include-code",
    ]);
    assert!(ok, "{v}");
    let mut vals: Vec<&str> = v
        .as_array()
        .expect("array")
        .iter()
        .map(|r| r["value"].as_str().expect("row value"))
        .collect();
    vals.sort_unstable();
    assert_eq!(vals, ["hello-world", "pleasure."]);
    cleanup(&dir);
}
