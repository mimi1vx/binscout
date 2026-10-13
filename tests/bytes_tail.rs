//! bytes_at zero-tail tests: segments whose `mem_size` exceeds the
//! file-backed prefix must read as zeros without panicking.

mod common;

use std::process::Command;

use binscout::Project;
use binscout::error::Error;
use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

const BASE: u64 = 0x400000;
const FILE_LEN: usize = 3;
const MEM_SIZE: u64 = 16;

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn put64(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

/// Minimal 64-bit LE ELF with a BSS-like tail: one `PT_LOAD`
/// (`nop; nop; ret`) at `BASE` with `p_filesz=3` but `p_memsz=16`.
fn bss_elf() -> Vec<u8> {
    let mut f = vec![0u8; 0x78];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2;
    f[5] = 1;
    f[6] = 1;
    put16(&mut f, 16, 2);
    put16(&mut f, 18, 62);
    put32(&mut f, 20, 1);
    put64(&mut f, 24, BASE);
    put64(&mut f, 32, 64);
    put16(&mut f, 52, 64);
    put16(&mut f, 54, 56);
    put16(&mut f, 56, 1);
    let p = 64;
    put32(&mut f, p, 1);
    put32(&mut f, p + 4, 5);
    put64(&mut f, p + 8, 0x78);
    put64(&mut f, p + 16, BASE);
    put64(&mut f, p + 32, FILE_LEN as u64);
    put64(&mut f, p + 40, MEM_SIZE);
    put64(&mut f, p + 48, 0x1000);
    f.extend_from_slice(&[0x90, 0x90, 0xC3]);
    f
}

fn open_bss(tag: &str) -> (Project, std::path::PathBuf, std::path::PathBuf) {
    let dir = tmpdir(tag);
    let bin = write_bin(&dir, "bss.elf", &bss_elf());
    let db = temp_db(&dir, "bss");
    let p = Project::open_with_db(&bin, &db).expect("bss ELF must open");
    assert_eq!(p.binary().segments.len(), 1);
    assert_eq!(p.binary().segments[0].data.len(), FILE_LEN);
    assert_eq!(p.binary().segments[0].mem_size, MEM_SIZE);
    (p, bin, dir)
}

#[test]
fn bytes_at_mixed_file_zero_range() {
    let (p, _bin, dir) = open_bss("bytes-mixed");
    let got = p.bytes_at(BASE + 1, 5).expect("mixed range must read");
    assert_eq!(got, vec![0x90, 0xC3, 0x00, 0x00, 0x00]);
    cleanup(&dir);
}

#[test]
fn bytes_at_wholly_zero_filled_tail() {
    let (p, _bin, dir) = open_bss("bytes-tail");
    let got = p.bytes_at(BASE + 8, 4).expect("tail must read as zeros");
    assert_eq!(got, vec![0u8; 4]);
    cleanup(&dir);
}

#[test]
fn bytes_at_off_exactly_at_data_len() {
    let (p, _bin, dir) = open_bss("bytes-exact");
    let got = p
        .bytes_at(BASE + FILE_LEN as u64, 4)
        .expect("read at file end must be zeros");
    assert_eq!(got, vec![0u8; 4]);
    cleanup(&dir);
}

#[test]
fn bytes_at_off_beyond_data_len() {
    let (p, _bin, dir) = open_bss("bytes-beyond");
    let got = p
        .bytes_at(BASE + 5, 4)
        .expect("read past file data must be zeros");
    assert_eq!(got, vec![0u8; 4]);
    cleanup(&dir);
}

#[test]
fn bytes_at_unmapped_range_errors() {
    let (p, _bin, dir) = open_bss("bytes-unmapped");
    let err = p.bytes_at(BASE + MEM_SIZE, 1).unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    let err = p.bytes_at(BASE + MEM_SIZE + 16, 4).unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    cleanup(&dir);
}

fn run(args: &[&str]) -> (bool, serde_json::Value, String) {
    let out = Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: serde_json::Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value, text)
}

#[test]
fn cli_disasm_and_ir_on_zero_tail_emit_valid_json() {
    let dir = tmpdir("cli-zero-tail");
    let bin = write_bin(&dir, "bss.elf", &bss_elf());
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "bss").display().to_string();
    let d = db.as_str();
    let tail_addr = format!("{:#x}", BASE + 5);

    let (ok, v, text) = run(&["--db", d, "disasm", &bin_s, &tail_addr, "4"]);
    assert!(ok, "{v}");
    assert_eq!(text.trim_end().lines().count(), 1);
    assert!(v.get("insns").is_some() && v.get("error_at").is_some());

    let (ok, v, text) = run(&["--db", d, "ir", &bin_s, &tail_addr, "4"]);
    assert!(ok, "{v}");
    assert_eq!(text.trim_end().lines().count(), 1);
    assert!(v.get("ir").is_some() && v.get("error_at").is_some());

    let past_end = format!("{:#x}", BASE + MEM_SIZE);
    let (ok, v, text) = run(&["--db", d, "disasm", &bin_s, &past_end, "1"]);
    assert!(!ok, "unmapped disasm must fail, got {v}");
    assert!(v.get("error").is_some(), "{v}");
    assert_eq!(text.trim_end().lines().count(), 1);

    let (ok, v, text) = run(&["--db", d, "ir", &bin_s, &past_end, "1"]);
    assert!(!ok, "unmapped ir must fail, got {v}");
    assert!(v.get("error").is_some(), "{v}");
    assert_eq!(text.trim_end().lines().count(), 1);

    assert_eq!(
        std::fs::read(&bin).expect("reread"),
        bss_elf(),
        "binary untouched"
    );
    cleanup(&dir);
}
