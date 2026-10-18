//! String-ref decryption helper: the `strings --decode` view re-extracts
//! over an in-memory single-byte transform (XOR/add/rot allowlist) with
//! original offsets, and never writes the binary.

mod common;

use std::process::Command;

use serde_json::Value;

use binscout::analysis::StringsFilter;
use binscout::loader::strings::{DecodeSpec, Encoding, parse_decode_spec};

use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

/// Marker hidden with a single-byte transform inside `0xFF` padding (which
/// decodes to non-printable bytes under every tested spec, so the decoded
/// page holds exactly the marker).
const MARKER: &str = "hidden-treasure-marker";
const MARKER_OFF: usize = 64;

/// Raw blob: `0xFF` pad with `MARKER` encoded at `MARKER_OFF`.
fn obfuscated_blob(encode: impl Fn(u8) -> u8) -> Vec<u8> {
    let mut blob = vec![0xFFu8; 256];
    for (i, b) in MARKER.bytes().enumerate() {
        blob[MARKER_OFF + i] = encode(b);
    }
    blob
}

fn filter() -> StringsFilter {
    StringsFilter {
        // Raw-blob segments decode as executable; opt in so assertions see
        // genuinely absent rows rather than hidden ones.
        include_code: true,
        limit: 1024,
        ..StringsFilter::default()
    }
}

/// ASCII-channel values: decoded ASCII text carries a shifted
/// BMP-letter twin, so decode assertions pin the Ascii rows.
fn ascii_values(rows: &[binscout::loader::strings::StringHit]) -> Vec<&str> {
    rows.iter()
        .filter(|h| h.encoding == Encoding::Ascii)
        .map(|h| h.value.as_str())
        .collect()
}

/// Run the CLI; returns exit success and parsed stdout JSON.
fn run_cli(args: &[&str]) -> (bool, Value) {
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
fn xor_obfuscated_marker_decodes_via_new_flag() {
    let dir = tmpdir("strdec-xor");
    let bin = write_bin(&dir, "xor.bin", &obfuscated_blob(|b| b ^ 0x41));
    let db = temp_db(&dir, "xor");
    let before = std::fs::read(&bin).expect("fixture readable");
    let p = binscout::Project::open_with_db(&bin, &db).expect("blob must open");

    let plain = p.query_strings(&filter()).expect("plain query works");
    assert!(
        !plain.iter().any(|h| h.value == MARKER),
        "encoded marker must be invisible without decode: {plain:?}"
    );

    let rows = p
        .query_strings_decoded(&filter(), DecodeSpec::Xor(0x41))
        .expect("decoded query works");
    // ASCII-channel assertion: decoded ASCII text carries a shifted
    // BMP-letter twin, so the decode contract pins the Ascii hit.
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
    assert_eq!(
        hit.offset, MARKER_OFF,
        "offsets refer to the original binary"
    );
    assert_eq!(
        hit.vaddr,
        Some(MARKER_OFF as u64),
        "raw blobs map at base 0"
    );

    // The decoded view is read-only: binary bytes untouched, no sidecar made.
    assert_eq!(std::fs::read(&bin).expect("fixture readable"), before);
    assert!(!db.exists(), "reads never create the sidecar");
    cleanup(&dir);
}

#[test]
fn add_and_rot_views_decode_their_encodings() {
    let dir = tmpdir("strdec-addrot");
    let add_bin = write_bin(&dir, "add.bin", &obfuscated_blob(|b| b.wrapping_sub(7)));
    let add_db = temp_db(&dir, "add");
    let p = binscout::Project::open_with_db(&add_bin, &add_db).expect("blob must open");
    let rows = p
        .query_strings_decoded(&filter(), DecodeSpec::Add(7))
        .expect("add view works");
    assert_eq!(ascii_values(&rows), [MARKER]);

    let rot_bin = write_bin(&dir, "rot.bin", &obfuscated_blob(|b| b.rotate_right(3)));
    let rot_db = temp_db(&dir, "rot");
    let p = binscout::Project::open_with_db(&rot_bin, &rot_db).expect("blob must open");
    let rows = p
        .query_strings_decoded(&filter(), DecodeSpec::Rot(3))
        .expect("rot view works");
    assert_eq!(ascii_values(&rows), [MARKER]);

    // Wrong keys stay obfuscated: the marker is absent, never mis-decoded.
    let rows = p
        .query_strings_decoded(&filter(), DecodeSpec::Xor(0x42))
        .expect("wrong-key view works");
    assert!(!rows.iter().any(|h| h.value == MARKER));
    cleanup(&dir);
}

#[test]
fn pattern_filters_decoded_text() {
    let dir = tmpdir("strdec-pattern");
    let bin = write_bin(&dir, "pat.bin", &obfuscated_blob(|b| b ^ 0x41));
    let db = temp_db(&dir, "pat");
    let p = binscout::Project::open_with_db(&bin, &db).expect("blob must open");
    let rows = p
        .query_strings_decoded(
            &StringsFilter {
                pattern: Some("treasure".to_string()),
                ..filter()
            },
            DecodeSpec::Xor(0x41),
        )
        .expect("pattern+decode works");
    assert_eq!(
        rows.iter().map(|h| h.value.as_str()).collect::<Vec<_>>(),
        [MARKER]
    );
    let miss = p
        .query_strings_decoded(
            &StringsFilter {
                pattern: Some("zzz-nope".to_string()),
                ..filter()
            },
            DecodeSpec::Xor(0x41),
        )
        .expect("pattern+decode works");
    assert!(miss.is_empty());
    cleanup(&dir);
}

#[test]
fn cli_decode_flag_and_bad_spec_envelope() {
    let dir = tmpdir("strdec-cli");
    let bin = write_bin(&dir, "cli.bin", &obfuscated_blob(|b| b ^ 0x41));
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "cli").display().to_string();

    let (ok, v) = run_cli(&[
        "--db",
        &db,
        "strings",
        &bin_s,
        "--decode",
        "xor:0x41",
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

    let (ok, v) = run_cli(&["--db", &db, "strings", &bin_s, "--decode", "aes:0x41"]);
    assert!(!ok, "off-allowlist spec must fail, got {v}");
    assert!(v.get("error").is_some(), "{v}");
    cleanup(&dir);
}

#[test]
fn decode_spec_allowlist_parses_only_xor_add_rot() {
    assert!(parse_decode_spec("xor:0x41").is_ok());
    assert!(parse_decode_spec("add:65").is_ok());
    assert!(parse_decode_spec("rot:3").is_ok());
    for bad in ["aes:1", "xor", "xor:256", "rot:8", "xor:0x41:extra", ""] {
        assert!(
            matches!(
                parse_decode_spec(bad).unwrap_err(),
                binscout::error::Error::Invalid(_)
            ),
            "{bad:?} must be Invalid"
        );
    }
}
