//! YARA rule scanning: VA/section/function mapping, paging, and errors.

mod common;

use std::process::Command;

use binscout::disasm::Arch;
use binscout::error::Error;
use binscout::loader::RawOptions;

use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

fn open_raw(dir: &std::path::Path, name: &str, bytes: &[u8], base: u64) -> binscout::Project {
    let bin = write_bin(dir, name, bytes);
    let db = temp_db(dir, name);
    binscout::Project::open_raw(
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

fn write_rules(dir: &std::path::Path, name: &str, text: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("write rules");
    path
}

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

#[test]
fn missing_rules_file_is_not_found() {
    let dir = tmpdir("yara-missing");
    let p = open_raw(&dir, "b.bin", b"hello world", 0x1000);
    let err = p
        .scan_yara(
            std::path::Path::new("/nonexistent-yara-rules.yar"),
            None,
            None,
            0,
            50,
        )
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    cleanup(&dir);
}

#[test]
fn unknown_section_is_not_found() {
    let dir = tmpdir("yara-section");
    let p = open_raw(&dir, "b.bin", b"hello world", 0x1000);
    let rules = write_rules(
        &dir,
        "r.yar",
        r#"rule hello { strings: $a = "hello" condition: $a }"#,
    );
    let err = p.scan_yara(&rules, None, Some("nope"), 0, 50).unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    cleanup(&dir);
}

#[test]
fn bad_rule_is_invalid_when_enabled() {
    let dir = tmpdir("yara-bad");
    let p = open_raw(&dir, "b.bin", b"hello world", 0x1000);
    let rules = write_rules(&dir, "bad.yar", "rule broken { condition: ");
    let err = p.scan_yara(&rules, None, None, 0, 50).unwrap_err();
    if cfg!(feature = "yara") {
        assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
    } else {
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
    }
    cleanup(&dir);
}

#[test]
fn unknown_rule_is_not_found_when_enabled() {
    let dir = tmpdir("yara-unknown-rule");
    let p = open_raw(&dir, "b.bin", b"hello world", 0x1000);
    let rules = write_rules(
        &dir,
        "r.yar",
        r#"rule hello { strings: $a = "hello" condition: $a }"#,
    );
    let err = p.scan_yara(&rules, Some("nope"), None, 0, 50).unwrap_err();
    if cfg!(feature = "yara") {
        assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    } else {
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
    }
    cleanup(&dir);
}

#[test]
fn string_match_maps_to_va() {
    let dir = tmpdir("yara-va");
    let p = open_raw(&dir, "b.bin", b"xxhello world", 0x1000);
    let rules = write_rules(
        &dir,
        "r.yar",
        r#"rule hello { strings: $a = "hello" condition: $a }"#,
    );
    if cfg!(feature = "yara") {
        let page = p.scan_yara(&rules, None, None, 0, 50).expect("scan");
        assert_eq!(page.protocol, binscout::WIRE_PROTOCOL);
        assert_eq!(page.total, 1);
        assert_eq!(page.offset, 0);
        assert_eq!(page.limit, 50);
        assert_eq!(page.next_offset, None);
        let hit = &page.items[0];
        assert_eq!(hit.rule, "hello");
        assert_eq!(hit.pattern, "$a");
        assert_eq!(hit.addr, 0x1002);
        assert_eq!(hit.file_off, Some(2));
        assert_eq!(hit.section, None);
        assert_eq!(hit.len, 5);
        let v = serde_json::to_value(&page).expect("serializes");
        assert_eq!(v["items"][0]["addr_hex"], "0x1002");
        assert_eq!(v["items"][0]["rule"], "hello");
    } else {
        let err = p.scan_yara(&rules, None, None, 0, 50).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
    }
    cleanup(&dir);
}

#[test]
fn fixture_string_maps_to_section() {
    use common::builders::{BASIC_STRING, BASIC_STRING_VA};
    let dir = tmpdir("yara-section-map");
    let p = common::open_test_project(&dir, common::builders::BASIC_NAME);
    let text = format!(r#"rule save {{ strings: $a = "{BASIC_STRING}" condition: $a }}"#);
    let rules = write_rules(&dir, "r.yar", &text);
    if cfg!(feature = "yara") {
        let page = p.scan_yara(&rules, None, None, 0, 50).expect("scan");
        assert_eq!(page.total, 1);
        let hit = &page.items[0];
        assert_eq!(hit.addr, BASIC_STRING_VA);
        assert_eq!(hit.section.as_deref(), Some(".rdata"));
        assert_eq!(hit.func, None, "data match lies in no function");
    } else {
        let err = p.scan_yara(&rules, None, None, 0, 50).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
    }
    cleanup(&dir);
}

#[test]
fn code_match_maps_to_function() {
    use common::builders::{BASIC_ENTRY_VA, TEXT_VA};
    let dir = tmpdir("yara-func");
    let p = common::open_test_project(&dir, common::builders::BASIC_NAME);
    let rules = write_rules(
        &dir,
        "r.yar",
        r#"rule prologue { strings: $a = { 55 89 E5 } condition: $a }"#,
    );
    if cfg!(feature = "yara") {
        let page = p.scan_yara(&rules, None, None, 0, 50).expect("scan");
        assert!(page.total >= 1, "prologue occurs at least once: {page:?}");
        let hit = page
            .items
            .iter()
            .find(|h| h.addr == TEXT_VA)
            .expect("prologue at .text start");
        assert_eq!(hit.section.as_deref(), Some(".text"));
        assert_eq!(hit.func, Some(BASIC_ENTRY_VA));
        assert!(hit.func_name.is_some(), "entry has an export name");
    } else {
        let err = p.scan_yara(&rules, None, None, 0, 50).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
    }
    cleanup(&dir);
}

#[test]
fn paging_clips_to_max_rows() {
    let dir = tmpdir("yara-paging");
    let bytes = vec![b'A'; 8];
    let p = open_raw(&dir, "b.bin", &bytes, 0x2000);
    let rules = write_rules(
        &dir,
        "r.yar",
        r#"rule many { strings: $a = "A" condition: $a }"#,
    );
    if cfg!(feature = "yara") {
        let first = p.scan_yara(&rules, None, None, 0, 3).expect("scan");
        assert_eq!(first.total, 8);
        assert_eq!(first.items.len(), 3);
        assert_eq!(first.next_offset, Some(3));
        assert_eq!(first.items[0].addr, 0x2000);
        let second = p.scan_yara(&rules, None, None, 3, 3).expect("scan");
        assert_eq!(second.items[0].addr, 0x2003);
        assert_eq!(second.next_offset, Some(6));
        let clipped = p.scan_yara(&rules, None, None, 0, 5000).expect("scan");
        assert_eq!(clipped.limit, 1024, "limit clips to MAX_ROWS");
        assert_eq!(clipped.next_offset, None);
    } else {
        let err = p.scan_yara(&rules, None, None, 0, 3).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
    }
    cleanup(&dir);
}

#[test]
fn cli_scan_yara_parity() {
    let dir = tmpdir("yara-cli");
    let bin = write_bin(&dir, "b.bin", b"xxhello world");
    let db = temp_db(&dir, "b").display().to_string();
    let rules = write_rules(
        &dir,
        "r.yar",
        r#"rule hello { strings: $a = "hello" condition: $a }"#,
    );
    let rules_s = rules.display().to_string();
    let bin_s = bin.display().to_string();
    let (ok, v) = run(&[
        "--db",
        &db,
        "scan-yara",
        &bin_s,
        &rules_s,
        "--offset",
        "0",
        "--limit",
        "50",
    ]);
    if cfg!(feature = "yara") {
        assert!(ok, "{v}");
        assert_eq!(v["protocol"], 1);
        assert_eq!(v["total"], 1);
        // Raw blob via CLI without --raw falls back to raw x86-64 at base 0.
        assert_eq!(v["items"][0]["rule"], "hello");
        assert_eq!(v["items"][0]["addr"], 2);
        assert_eq!(v["items"][0]["addr_hex"], "0x2");
    } else {
        assert!(!ok, "{v}");
        assert_eq!(v["kind"], "unsupported");
    }
    cleanup(&dir);
}
