//! L2/A2: `sections` reproduces the fixture builder's section table exactly.

mod common;

use std::process::Command;

use common::{binscout_bin, builders, cleanup, temp_db, tmpdir, write_fixture};

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

/// One expected section row: name, flat VA, in-memory size, file offset,
/// raw byte count, and R/W/X permissions.
struct Expected {
    name: &'static str,
    vaddr: u64,
    size: u64,
    file_off: u64,
    file_size: usize,
    readable: bool,
    writable: bool,
    executable: bool,
}

/// Expected section rows for `pe32-basic.exe`, from the builder constants:
/// names, flat VAs (`IMAGE_BASE + RVA`), `0x200` in-memory and raw bytes,
/// file offsets `0x200/0x400/0x600`, and permissions.
fn expected() -> Vec<Expected> {
    vec![
        Expected {
            name: ".text",
            vaddr: builders::TEXT_VA,
            size: 0x200,
            file_off: 0x200,
            file_size: 0x200,
            readable: true,
            writable: false,
            executable: true,
        },
        Expected {
            name: ".rdata",
            vaddr: builders::RDATA_VA,
            size: 0x200,
            file_off: 0x400,
            file_size: 0x200,
            readable: true,
            writable: false,
            executable: false,
        },
        Expected {
            name: ".data",
            vaddr: builders::DATA_VA,
            size: 0x200,
            file_off: 0x600,
            file_size: 0x200,
            readable: true,
            writable: true,
            executable: false,
        },
    ]
}

fn check_rows(rows: &serde_json::Value) {
    let rows = rows.as_array().expect("sections is an array");
    assert_eq!(rows.len(), 3, "{rows:?}");
    for (row, e) in rows.iter().zip(expected()) {
        assert_eq!(row["name"], e.name, "{row}");
        assert_eq!(row["vaddr"], e.vaddr, "{row}");
        assert_eq!(row["size"], e.size, "{row}");
        assert_eq!(row["file_off"], e.file_off, "{row}");
        assert_eq!(row["file_size"], e.file_size, "{row}");
        let entropy = row["entropy"].as_f64().expect("entropy is a number");
        assert!(
            (0.0..=8.0).contains(&entropy),
            "entropy is Shannon bits per byte: {row}"
        );
        assert_eq!(row["readable"], e.readable, "{row}");
        assert_eq!(row["writable"], e.writable, "{row}");
        assert_eq!(row["executable"], e.executable, "{row}");
    }
}

#[test]
fn sections_json_matches_builder_table() {
    let dir = tmpdir("sections-lib");
    let p = common::open_test_project(&dir, builders::BASIC_NAME);
    check_rows(&p.sections_json());
    cleanup(&dir);
}

#[test]
fn sections_cli_matches_builder_table() {
    let dir = tmpdir("sections-cli");
    let bin = write_fixture(&dir, builders::BASIC_NAME);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "basic").display().to_string();
    let (ok, v) = run(&["--db", &db, "sections", &bin_s]);
    assert!(ok, "{v}");
    check_rows(&v);
    cleanup(&dir);
}

#[test]
fn sections_empty_without_table() {
    // Raw blobs have no section table.
    let dir = tmpdir("sections-raw");
    let p = common::open_test_project(&dir, builders::GARBAGE_NAME);
    assert_eq!(
        p.sections_json(),
        serde_json::Value::Array(Vec::new()),
        "raw must report no sections"
    );
    cleanup(&dir);
}

/// The loader-only cache hit reports the same section rows (including
/// `entropy`) as a full open: `sections` serves from the cached path once
/// `load` has warmed the sidecar.
#[test]
fn sections_cached_matches_full_open() {
    let dir = tmpdir("sections-cached");
    let bin = write_fixture(&dir, builders::BASIC_NAME);
    let db = temp_db(&dir, "basic");
    let full = binscout::Project::open_with_db(&bin, &db).expect("fixture must open");
    full.save().expect("warm the sidecar");
    let want = full.sections_json();
    let cached = match binscout::open_mapped_loader_only(&bin, Some(&db), None, None)
        .expect("loader-only open")
    {
        binscout::LoaderOpened::Cached(p) => p,
        binscout::LoaderOpened::Fresh(_) => panic!("warmed sidecar must hit"),
    };
    let got = cached.sections_json();
    assert_eq!(got, want, "cached sections match the full open");
    for row in got.as_array().expect("sections is an array") {
        assert!(
            row["entropy"].is_number(),
            "cached rows carry entropy: {row}"
        );
    }
    cleanup(&dir);
}
