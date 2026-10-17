//! Triage helpers: per-section entropy plus the `crypto-scan` constant scan.

mod common;

use std::path::Path;
use std::process::Command;

use binscout::Project;
use binscout::disasm::Arch;
use binscout::error::Error;
use binscout::loader::{RawOptions, section_entropy};

use common::{binscout_bin, builders, cleanup, temp_db, tmpdir, write_bin, write_fixture};

fn run(args: &[&str]) -> (bool, serde_json::Value) {
    let out = Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: serde_json::Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value)
}

fn open_raw(dir: &std::path::Path, name: &str, bytes: &[u8], base: u64) -> Project {
    let bin = write_bin(dir, name, bytes);
    let db = temp_db(dir, name);
    Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base,
            arch: Arch::X86_64,
            entry: None,
        },
    )
    .expect("raw open")
}

/// Raw blob with embedded crypto constants plus a `push` referencing the
/// AES S-box: `push 0x1010` at 0, S-box at 16, sigma at 48, SHA-256 K (LE)
/// at 64, TEA delta (BE) at 80, Blowfish P (LE) at 84.
fn triage_blob() -> Vec<u8> {
    let mut b = vec![0x90u8; 100];
    b[0..5].copy_from_slice(&[0x68, 0x10, 0x10, 0x00, 0x00]);
    b[16..32].copy_from_slice(&[
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76,
    ]);
    b[32..48].fill(0x00);
    b[48..64].copy_from_slice(b"expand 32-byte k");
    b[64..80].copy_from_slice(&[
        0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71, 0xcf, 0xfb, 0xc0, 0xb5, 0xa5, 0xdb, 0xb5,
        0xe9,
    ]);
    b[80..84].copy_from_slice(&[0x9e, 0x37, 0x79, 0xb9]);
    b[84..100].copy_from_slice(&[
        0x88, 0x6a, 0x3f, 0x24, 0xd3, 0x08, 0xa3, 0x85, 0x2e, 0x8a, 0x19, 0x13, 0x44, 0x73, 0x70,
        0x03,
    ]);
    b
}

#[test]
fn section_entropy_values() {
    assert_eq!(section_entropy(&[]), 0.0, "empty input");
    assert_eq!(section_entropy(&[0x41; 64]), 0.0, "uniform input");
    let balanced: Vec<u8> = (0..=255u8).collect();
    assert!(
        (section_entropy(&balanced) - 8.0).abs() < 1e-9,
        "256 distinct bytes carry 8 bits: {}",
        section_entropy(&balanced)
    );
    let mut half = vec![0x00u8; 32];
    half.extend_from_slice(&[0xffu8; 32]);
    assert!(
        (section_entropy(&half) - 1.0).abs() < 1e-9,
        "fair coin carries 1 bit: {}",
        section_entropy(&half)
    );
}

#[test]
fn sections_rows_carry_entropy() {
    let dir = tmpdir("crypto-entropy");
    let p = common::open_test_project(&dir, builders::BASIC_NAME);
    let rows = p.sections_json();
    let rows = rows.as_array().expect("sections is an array");
    assert_eq!(rows.len(), 3, "{rows:?}");
    for row in rows {
        let e = row["entropy"].as_f64().expect("entropy is a number");
        assert!((0.0..=8.0).contains(&e), "entropy in bits per byte: {row}");
    }
    let text = rows
        .iter()
        .find(|r| r["name"] == ".text")
        .expect(".text row");
    assert!(
        text["entropy"].as_f64().expect("number") > 0.0,
        "code is not uniform: {text}"
    );
    let raw = open_raw(&dir, "r.bin", &[0x90; 8], 0x1000);
    assert_eq!(
        raw.sections_json(),
        serde_json::Value::Array(Vec::new()),
        "raw still reports no sections"
    );
    cleanup(&dir);
}

#[test]
fn crypto_scan_raw_finds_embedded_constants() {
    let dir = tmpdir("crypto-raw");
    let p = open_raw(&dir, "t.bin", &triage_blob(), 0x1000);
    let page = p.crypto_scan(None, None, 0, 50).expect("scan");
    assert_eq!(page.protocol, binscout::WIRE_PROTOCOL);
    assert_eq!(page.total, 5, "{:?}", page.items);
    assert_eq!(page.next_offset, None);
    let want = [
        ("aes-sbox", 0x1010u64, 16usize),
        ("chacha-sigma", 0x1030, 16),
        ("sha256-k", 0x1040, 16),
        ("tea-delta", 0x1050, 4),
        ("blowfish-p", 0x1054, 16),
    ];
    for (hit, (name, addr, len)) in page.items.iter().zip(want) {
        assert_eq!(hit.name, name);
        assert_eq!(hit.addr, addr);
        assert_eq!(hit.len, len);
        assert!(hit.section.is_none(), "raw has no sections");
    }
    assert_eq!(page.items[0].file_off, Some(16));
    let sbox = &page.items[0];
    assert!(
        sbox.xrefs_count >= 1,
        "the push of 0x1010 references the S-box: {sbox:?}"
    );
    let v = serde_json::to_value(&page).expect("serializes");
    assert_eq!(v["items"][0]["addr_hex"], "0x1010");
    assert_eq!(v["items"][0]["name"], "aes-sbox");
    assert!(v["items"][0]["xrefs_count"].is_number(), "{v}");
    cleanup(&dir);
}

#[test]
fn crypto_scan_filters_and_pages() {
    let dir = tmpdir("crypto-filter");
    let p = open_raw(&dir, "t.bin", &triage_blob(), 0x1000);
    let only = p.crypto_scan(Some("sha256-k"), None, 0, 50).expect("named");
    assert_eq!(only.total, 1);
    assert_eq!(only.items[0].addr, 0x1040);
    assert!(matches!(
        p.crypto_scan(Some("nope"), None, 0, 10).unwrap_err(),
        Error::NotFound(_)
    ));
    let err = p.crypto_scan(None, Some(".text"), 0, 10).unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "raw has no sections");
    let p1 = p.crypto_scan(None, None, 0, 2).expect("page 1");
    assert_eq!(p1.total, 5);
    assert_eq!(p1.next_offset, Some(2));
    assert_eq!(p1.items.len(), 2);
    let p2 = p.crypto_scan(None, None, 2, 50).expect("page 2");
    assert_eq!(p2.items.len(), 3);
    assert_eq!(p2.next_offset, None);
    assert_eq!(p2.items[0].addr, 0x1040);
    let past = p.crypto_scan(None, None, 5, 50).expect("past end");
    assert!(past.items.is_empty());
    assert_eq!(past.next_offset, None);
    let clipped = p.crypto_scan(None, None, 0, 5000).expect("clipped");
    assert_eq!(clipped.total, 5);
    assert_eq!(clipped.limit, 1024);
    assert_eq!(clipped.items.len(), 5);
    cleanup(&dir);
}

#[test]
fn crypto_scan_attributes_pe_section() {
    let dir = tmpdir("crypto-pe");
    // Patch the AES S-box prefix into `.rdata` slack (file 0x580, VA
    // RDATA_VA + 0x180), past the export directory the loader clamps to.
    let mut bytes = common::fixture_bytes(builders::BASIC_NAME);
    let off = 0x400 + 0x180;
    bytes[off..off + 16].copy_from_slice(&[
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76,
    ]);
    let bin = write_bin(&dir, "patched.exe", &bytes);
    let db = temp_db(&dir, "patched");
    let p = Project::open_with_db(&bin, &db).expect("patched fixture opens");
    let page = p
        .crypto_scan(Some("aes-sbox"), Some(".rdata"), 0, 50)
        .expect("section scan");
    assert_eq!(page.total, 1, "{:?}", page.items);
    let hit = &page.items[0];
    assert_eq!(hit.addr, builders::RDATA_VA + 0x180);
    assert_eq!(hit.section.as_deref(), Some(".rdata"));
    assert_eq!(hit.file_off, Some(0x580));
    assert_eq!(hit.xrefs_count, 0, "slack bytes are unreferenced");
    let all = p.crypto_scan(None, None, 0, 50).expect("unfiltered");
    assert!(
        all.items
            .iter()
            .any(|h| h.addr == builders::RDATA_VA + 0x180),
        "unfiltered scan contains the slack hit: {:?}",
        all.items
    );
    cleanup(&dir);
}

#[test]
fn crypto_scan_cli_parity_errors_and_read_only() {
    let dir = tmpdir("crypto-cli");
    let bin = write_bin(&dir, "t.bin", &triage_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "t").display().to_string();
    let d = db.as_str();

    let (ok, v) = run(&[
        "--db",
        d,
        "--raw",
        "--arch",
        "x86_64",
        "--base",
        "0x1000",
        "crypto-scan",
        &bin,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 5);
    assert_eq!(v["items"][0]["name"], "aes-sbox");
    assert_eq!(v["items"][0]["addr"], 0x1010);
    assert_eq!(v["items"][0]["addr_hex"], "0x1010");
    assert!(v["items"][0]["xrefs_count"].is_number(), "{v}");

    let (ok, v) = run(&[
        "--db",
        d,
        "--raw",
        "--arch",
        "x86_64",
        "--base",
        "0x1000",
        "crypto-scan",
        &bin,
        "--name",
        "sha256-k",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["total"], 1);
    assert_eq!(v["items"][0]["addr"], 0x1040);

    let (ok, v) = run(&[
        "--db",
        d,
        "--raw",
        "--arch",
        "x86_64",
        "--base",
        "0x1000",
        "crypto-scan",
        &bin,
        "--name",
        "nope",
    ]);
    assert!(!ok && v.get("error").is_some(), "unknown name: {v}");

    let (ok, v) = run(&[
        "--db",
        d,
        "--raw",
        "--arch",
        "x86_64",
        "--base",
        "0x1000",
        "crypto-scan",
        &bin,
        "--section",
        "nope",
    ]);
    assert!(!ok && v.get("error").is_some(), "unknown section: {v}");

    assert!(
        !Path::new(d).exists(),
        "crypto scans never create the sidecar"
    );
    assert!(write_fixture(&dir, builders::BASIC_NAME).exists());
    cleanup(&dir);
}
