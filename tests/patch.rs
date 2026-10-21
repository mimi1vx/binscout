//! Patch export e2e: preview shape, NOP-pad, `size_ok`, `--out`
//! formats, and the never-write-the-binary guards.

mod common;

use std::path::Path;
use std::process::Command;

use serde_json::Value;

use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

/// Run the CLI; assert stdout is one valid JSON value. Returns exit success
/// plus the parsed document.
fn run(args: &[String]) -> (bool, Value) {
    let out = Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value)
}

/// Raw `jz +2; nop; nop` at `0x400000` plus a temp DB path. The `jz` is the
/// two-byte boundary every preview test patches.
fn jcc_case(tag: &str) -> (String, String, std::path::PathBuf) {
    let dir = tmpdir(tag);
    let bin = write_bin(&dir, "j.bin", &[0x74, 0x02, 0x90, 0x90]);
    let db = temp_db(&dir, "j");
    (bin.display().to_string(), db.display().to_string(), dir)
}

/// Raw x86-64 patch argv for `bin`/`addr` plus caller `extra` flags.
fn patch_args(bin: &str, db: &str, addr: &str, extra: &[&str]) -> Vec<String> {
    let mut args = vec![
        "--db".to_string(),
        db.to_string(),
        "--raw".to_string(),
        "--arch".to_string(),
        "x86_64".to_string(),
        "--base".to_string(),
        "0x400000".to_string(),
        "patch".to_string(),
        bin.to_string(),
        addr.to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

#[test]
fn patch_bytes_preview_shape_and_nop_boundary() {
    let (bin, db, dir) = jcc_case("patch-shape");
    let (ok, v) = run(&patch_args(&bin, &db, "0x400000", &["--bytes", "90 90"]));
    assert!(ok, "{v}");
    assert_eq!(v["va"], 0x400000u64);
    assert_eq!(v["va_hex"], "0x400000");
    assert_eq!(v["file_off"], 0);
    assert_eq!(v["old_hex"], "7402");
    assert_eq!(v["new_hex"], "9090");
    assert_eq!(v["size_ok"], true);
    // Read-only: the binary is untouched and no sidecar is created.
    assert_eq!(
        std::fs::read(dir.join("j.bin")).expect("reread"),
        vec![0x74, 0x02, 0x90, 0x90]
    );
    assert!(!Path::new(&db).exists(), "patch must not save");
    cleanup(&dir);
}

#[test]
fn patch_asm_fixed_insns_pad_to_boundary() {
    let (bin, db, dir) = jcc_case("patch-pad");
    for (asm, new_hex) in [("nop", "9090"), ("ret", "c390"), ("int3", "cc90")] {
        let (ok, v) = run(&patch_args(&bin, &db, "0x400000", &["--asm", asm]));
        assert!(ok, "{asm}: {v}");
        assert_eq!(v["old_hex"], "7402", "{asm}");
        assert_eq!(v["new_hex"], new_hex, "{asm}");
        assert_eq!(v["size_ok"], true, "{asm}");
    }
    cleanup(&dir);
}

#[test]
fn patch_asm_branches_encode_relative_and_overflow() {
    let (bin, db, dir) = jcc_case("patch-branch");
    // jmp rel32 from 0x400000 to 0x401020: rel = 0x101b; 5 bytes > 2.
    let (ok, v) = run(&patch_args(
        &bin,
        &db,
        "0x400000",
        &["--asm", "jmp 0x401020"],
    ));
    assert!(ok, "{v}");
    assert_eq!(v["new_hex"], "e91b100000");
    assert_eq!(v["size_ok"], false);
    // call rel32 from 0x400000 to 0x400010: rel = 0x0b; also overflows.
    let (ok, v) = run(&patch_args(
        &bin,
        &db,
        "0x400000",
        &["--asm", "call 0x400010"],
    ));
    assert!(ok, "{v}");
    assert_eq!(v["new_hex"], "e80b000000");
    assert_eq!(v["size_ok"], false);
    cleanup(&dir);
}

#[test]
fn patch_bytes_overflow_reports_not_ok() {
    let (bin, db, dir) = jcc_case("patch-overflow");
    let (ok, v) = run(&patch_args(&bin, &db, "0x400000", &["--bytes", "90 90 90"]));
    assert!(ok, "{v}");
    assert_eq!(v["new_hex"], "909090");
    assert_eq!(v["size_ok"], false);
    cleanup(&dir);
}

#[test]
fn patch_rejects_non_x86_arch() {
    let dir = tmpdir("patch-riscv");
    let bin = write_bin(&dir, "r.bin", &[0x00, 0x00, 0x00, 0x00]);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "r").display().to_string();
    let (ok, v) = run(&[
        "--db".to_string(),
        db,
        "--raw".to_string(),
        "--arch".to_string(),
        "riscv64".to_string(),
        "--base".to_string(),
        "0x1000".to_string(),
        "patch".to_string(),
        bin_s,
        "0x1000".to_string(),
        "--asm".to_string(),
        "nop".to_string(),
    ]);
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert_eq!(v["kind"], "unsupported", "{v}");
    cleanup(&dir);
}

/// Raw aarch64 `nop; ret` at `0x1000` plus a temp DB path.
fn aarch64_case(tag: &str) -> (String, String, std::path::PathBuf) {
    let dir = tmpdir(tag);
    let bin = write_bin(
        &dir,
        "a.bin",
        &[0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6],
    );
    let db = temp_db(&dir, "a");
    (bin.display().to_string(), db.display().to_string(), dir)
}

/// Raw aarch64 patch argv for `bin`/`addr` plus caller `extra` flags.
fn aarch64_args(bin: &str, db: &str, addr: &str, extra: &[&str]) -> Vec<String> {
    let mut args = vec![
        "--db".to_string(),
        db.to_string(),
        "--raw".to_string(),
        "--arch".to_string(),
        "aarch64".to_string(),
        "--base".to_string(),
        "0x1000".to_string(),
        "patch".to_string(),
        bin.to_string(),
        addr.to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

#[test]
fn patch_aarch64_asm_fixed_and_branch_insns() {
    let (bin, db, dir) = aarch64_case("patch-a64-asm");
    for (asm, new_hex) in [
        ("nop", "1f2003d5"),
        ("ret", "c0035fd6"),
        ("brk #0", "000020d4"),
        ("b 0x1010", "04000014"),
        ("bl 0xff0", "fcffff97"),
    ] {
        let (ok, v) = run(&aarch64_args(&bin, &db, "0x1000", &["--asm", asm]));
        assert!(ok, "{asm}: {v}");
        assert_eq!(v["old_hex"], "1f2003d5", "{asm}");
        assert_eq!(v["new_hex"], new_hex, "{asm}");
        assert_eq!(v["size_ok"], true, "{asm}");
    }
    cleanup(&dir);
}

#[test]
fn patch_aarch64_rejects_bad_branch_targets() {
    let (bin, db, dir) = aarch64_case("patch-a64-branch");
    for asm in ["b 0x1002", "bl 0x1003"] {
        let (ok, v) = run(&aarch64_args(&bin, &db, "0x1000", &["--asm", asm]));
        assert!(!ok && v.get("error").is_some(), "{asm:?}: {v}");
        assert_eq!(v["kind"], "invalid", "{asm:?}: {v}");
    }
    let (ok, v) = run(&aarch64_args(
        &bin,
        &db,
        "0x1000",
        &["--asm", "b 0x10001000"],
    ));
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert_eq!(v["kind"], "invalid", "{v}");
    cleanup(&dir);
}

#[test]
fn patch_aarch64_bytes_length_and_align() {
    let (bin, db, dir) = aarch64_case("patch-a64-bytes");
    let (ok, v) = run(&aarch64_args(
        &bin,
        &db,
        "0x1000",
        &["--bytes", "c0 03 5f d6"],
    ));
    assert!(ok, "{v}");
    assert_eq!(v["new_hex"], "c0035fd6");
    assert_eq!(v["size_ok"], true);
    let (ok, v) = run(&aarch64_args(&bin, &db, "0x1000", &["--bytes", "90"]));
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert_eq!(v["kind"], "invalid", "{v}");
    let (ok, v) = run(&aarch64_args(
        &bin,
        &db,
        "0x1000",
        &["--bytes", "1f 20 03 d5 1f 20 03 d5"],
    ));
    assert!(ok, "{v}");
    assert_eq!(v["new_hex"], "1f2003d51f2003d5");
    assert_eq!(v["size_ok"], false);
    let (ok, v) = run(&aarch64_args(
        &bin,
        &db,
        "0x1002",
        &["--bytes", "c0 03 5f d6"],
    ));
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert_eq!(v["kind"], "invalid", "{v}");
    let (ok, v) = run(&aarch64_args(
        &bin,
        &db,
        "0x2000",
        &["--bytes", "c0 03 5f d6"],
    ));
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert_eq!(v["kind"], "not_found", "{v}");
    cleanup(&dir);
}

#[test]
fn patch_aarch64_out_writes_ips_without_touching_binary() {
    let (bin, db, dir) = aarch64_case("patch-a64-out");
    let before = std::fs::read(&bin).expect("read fixture");
    let ips_out = dir.join("p.ips").display().to_string();
    let (ok, v) = run(&aarch64_args(
        &bin,
        &db,
        "0x1000",
        &["--asm", "nop", "--out", &ips_out, "--format", "ips"],
    ));
    assert!(ok, "{v}");
    assert_eq!(v["format"], "ips");
    assert!(
        std::fs::read(&ips_out)
            .expect("read ips")
            .starts_with(b"PATCH")
    );
    assert_eq!(std::fs::read(&bin).expect("reread"), before);
    assert!(!Path::new(&db).exists(), "patch must not save");
    cleanup(&dir);
}

#[test]
fn patch_rejects_bad_boundary_and_unmapped() {
    // 0x06 is invalid in 64-bit mode: no boundary, no preview.
    let dir = tmpdir("patch-bad");
    let bad = write_bin(&dir, "b.bin", &[0x06]).display().to_string();
    let db = temp_db(&dir, "b").display().to_string();
    let args: Vec<String> = [
        "--db", &db, "--raw", "--arch", "x86_64", "--base", "0x400000", "patch", &bad, "0x400000",
        "--bytes", "90",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let (ok, v) = run(&args);
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert_eq!(v["kind"], "invalid", "{v}");

    let (bin, db2, dir2) = jcc_case("patch-unmapped");
    let (ok, v) = run(&patch_args(&bin, &db2, "0x500000", &["--bytes", "90"]));
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert_eq!(v["kind"], "not_found", "{v}");
    cleanup(&dir2);
    cleanup(&dir);
}

#[test]
fn patch_rejects_malformed_sources() {
    let (bin, db, dir) = jcc_case("patch-malformed");
    for bytes in ["zz", "9", "90 ??", "0x90", ""] {
        let (ok, v) = run(&patch_args(&bin, &db, "0x400000", &["--bytes", bytes]));
        assert!(!ok && v.get("error").is_some(), "{bytes:?}: {v}");
        assert_eq!(v["kind"], "invalid", "{bytes:?}: {v}");
    }
    for asm in ["mov eax, 1", "jmp", "jmp 0x1 0x2", "nop 5", "jecxz 0x10"] {
        let (ok, v) = run(&patch_args(&bin, &db, "0x400000", &["--asm", asm]));
        assert!(!ok && v.get("error").is_some(), "{asm:?}: {v}");
        assert_eq!(v["kind"], "invalid", "{asm:?}: {v}");
    }
    // --format without --out is a caller error.
    let (ok, v) = run(&patch_args(
        &bin,
        &db,
        "0x400000",
        &["--bytes", "90 90", "--format", "ips"],
    ));
    assert!(!ok && v.get("error").is_some(), "{v}");
    // Both/neither source: clap usage error, exit 2.
    for extra in [vec!["--asm", "nop", "--bytes", "90"], vec![]] {
        let args = patch_args(&bin, &db, "0x400000", &extra);
        let out = Command::new(binscout_bin())
            .args(&args)
            .output()
            .expect("spawn binscout");
        assert_eq!(out.status.code(), Some(2), "{extra:?}");
    }
    cleanup(&dir);
}

#[test]
fn patch_out_writes_json_and_ips() {
    let (bin, db, dir) = jcc_case("patch-out");
    let json_out = dir.join("p.json").display().to_string();
    let (ok, v) = run(&patch_args(
        &bin,
        &db,
        "0x400000",
        &["--bytes", "90 90", "--out", &json_out],
    ));
    assert!(ok, "{v}");
    assert_eq!(v["out"], json_out);
    assert_eq!(v["format"], "json");
    assert!(v["bytes_written"].as_u64().expect("bytes_written") > 0);
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&json_out).expect("read json"))
        .expect("patch file is JSON");
    assert_eq!(doc["arch"], "x86_64");
    assert_eq!(doc["va_hex"], "0x400000");
    assert_eq!(doc["file_off"], 0);
    assert_eq!(doc["old_hex"], "7402");
    assert_eq!(doc["new_hex"], "9090");
    assert_eq!(doc["size_ok"], true);

    let ips_out = dir.join("p.ips").display().to_string();
    let (ok, v) = run(&patch_args(
        &bin,
        &db,
        "0x400000",
        &["--bytes", "cc 90", "--out", &ips_out, "--format", "ips"],
    ));
    assert!(ok, "{v}");
    assert_eq!(v["format"], "ips");
    assert_eq!(
        std::fs::read(&ips_out).expect("read ips"),
        b"PATCH\x00\x00\x00\x00\x02\xcc\x90EOF"
    );
    // Neither the binary nor a sidecar changed.
    assert_eq!(
        std::fs::read(dir.join("j.bin")).expect("reread"),
        vec![0x74, 0x02, 0x90, 0x90]
    );
    assert!(!Path::new(&db).exists(), "patch must not save");
    cleanup(&dir);
}

#[test]
fn patch_out_refuses_overflow() {
    let (bin, db, dir) = jcc_case("patch-no-overflow");
    let out = dir.join("q.json").display().to_string();
    let (ok, v) = run(&patch_args(
        &bin,
        &db,
        "0x400000",
        &["--bytes", "90 90 90", "--out", &out],
    ));
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert!(
        v["error"].as_str().expect("message").contains("exceed"),
        "{v}"
    );
    assert!(!Path::new(&out).exists(), "no partial patch file");
    cleanup(&dir);
}

#[test]
fn patch_out_refuses_binary() {
    let (bin, db, dir) = jcc_case("patch-guard");
    let before = std::fs::read(&bin).expect("read fixture");
    let (ok, v) = run(&patch_args(
        &bin,
        &db,
        "0x400000",
        &["--bytes", "90 90", "--out", &bin],
    ));
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert!(
        v["error"]
            .as_str()
            .expect("message")
            .contains("--out must not be the analyzed binary"),
        "{v}"
    );
    assert_eq!(std::fs::read(&bin).expect("reread"), before);
    cleanup(&dir);
}

// rsdbg-zvm.17 guard pattern, reused for --out: symlink and hard-link
// aliases of the binary reach the same refusal.
#[cfg(unix)]
#[test]
fn patch_out_refuses_binary_aliases() {
    let (bin, db, dir) = jcc_case("patch-alias");
    let before = std::fs::read(&bin).expect("read fixture");
    let link = dir.join("link-to-bin").display().to_string();
    std::os::unix::fs::symlink(&bin, &link).expect("symlink");
    let hard = dir.join("hard-to-bin").display().to_string();
    std::fs::hard_link(&bin, &hard).expect("hard link");
    for alias in [&link, &hard] {
        let (ok, v) = run(&patch_args(
            &bin,
            &db,
            "0x400000",
            &["--bytes", "90 90", "--out", alias],
        ));
        assert!(!ok, "{alias}: {v}");
        assert!(
            v["error"]
                .as_str()
                .expect("message")
                .contains("--out must not be the analyzed binary"),
            "{alias}: {v}"
        );
    }
    assert_eq!(std::fs::read(&bin).expect("reread"), before);
    cleanup(&dir);
}

#[test]
fn patch_bss_reports_null_offset_and_refuses_file() {
    // ELF with .text-sized file bytes but a wider in-memory segment: the
    // zero-padded tail decodes (x86 zeros are `add`) yet has no file
    // offset, so the preview works and only the file write is refused.
    let mut elf = common::minimal_elf();
    elf[104..112].copy_from_slice(&0x10u64.to_le_bytes());
    let dir = tmpdir("patch-bss");
    let bin = write_bin(&dir, "b.elf", &elf).display().to_string();
    let db = temp_db(&dir, "b").display().to_string();
    let args: Vec<String> = ["--db", &db, "patch", &bin, "0x400003", "--bytes", "90 90"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (ok, v) = run(&args);
    assert!(ok, "{v}");
    assert_eq!(v["old_hex"], "0000");
    assert_eq!(v["new_hex"], "9090");
    assert_eq!(v["size_ok"], true);
    assert!(v["file_off"].is_null(), "{v}");

    let out = dir.join("b.json").display().to_string();
    let args: Vec<String> = [
        "--db", &db, "patch", &bin, "0x400003", "--bytes", "90 90", "--out", &out,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let (ok, v) = run(&args);
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert!(
        v["error"]
            .as_str()
            .expect("message")
            .contains("not file-backed"),
        "{v}"
    );
    assert!(!Path::new(&out).exists(), "no partial patch file");
    cleanup(&dir);
}
