//! Go `pclntab` recovery: synthetic tables for every supported magic,
//! scanned from raw blobs and read from a `.gopclntab` section.

mod common;

use std::process::Command;

use serde_json::Value;

use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

const BASE: u64 = 0x400_000;
/// Offset of the synthetic `pclntab` inside the raw blob.
const TAB_OFF: usize = 0x200;

/// Header words for the 1.18+ layout (pointer-sized words, functab fields
/// fixed 4-byte): nfunc, nfiles, textstart(ignored), funcnameoff, cuoff,
/// filetab, pctab, functab/funcdata.
fn build_new(magic: u32) -> Vec<u8> {
    let ptr = 8usize;
    let mut t = vec![0u8; 8 + 8 * ptr];
    t[0..4].copy_from_slice(&magic.to_le_bytes());
    t[6] = 1; // quantum
    t[7] = 8; // ptrsize
    let word = |t: &mut Vec<u8>, i: usize, v: u64| {
        t[8 + i * ptr..8 + i * ptr + 8].copy_from_slice(&v.to_le_bytes());
    };
    let functab_off = (8 + 8 * ptr) as u64;
    let names_off = functab_off + 5 * 4 + 2 * 12; // past functab + 2 func structs
    word(&mut t, 0, 2); // nfunc
    word(&mut t, 1, 1); // nfiles
    word(&mut t, 2, 0); // textstart (ignored: caller passes the base)
    word(&mut t, 3, names_off);
    word(&mut t, 4, names_off); // cutab (unused, in range)
    word(&mut t, 5, names_off); // filetab (unused, in range)
    word(&mut t, 6, names_off); // pctab (unused, in range)
    word(&mut t, 7, functab_off);
    // functab: {entryoff, funcoff} x2 plus the end PC.
    let mut ft = Vec::new();
    for v in [0x100u32, 20, 0x140, 32, 0x180] {
        ft.extend_from_slice(&v.to_le_bytes());
    }
    t.extend_from_slice(&ft);
    // func0 at functab+20: entry, nameoff, pad.
    t.extend_from_slice(&0x100u32.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    // func1 at functab+32: entry, nameoff, pad.
    t.extend_from_slice(&0x140u32.to_le_bytes());
    t.extend_from_slice(&10u32.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    // funcnametab.
    t.extend_from_slice(b"main.main\0main.helper\0");
    t
}

/// 1.16–1.17 layout (pointer-sized words and functab fields, full VAs).
fn build_go116() -> Vec<u8> {
    let ptr = 8usize;
    let mut t = vec![0u8; 8 + 7 * ptr];
    t[0..4].copy_from_slice(&0xfffffffa_u32.to_le_bytes());
    t[6] = 1;
    t[7] = 8;
    let word = |t: &mut Vec<u8>, i: usize, v: u64| {
        t[8 + i * ptr..8 + i * ptr + 8].copy_from_slice(&v.to_le_bytes());
    };
    let functab_off = (8 + 7 * ptr) as u64;
    let names_off = functab_off + 5 * 8 + 2 * 16; // past functab + 2 func structs
    word(&mut t, 0, 2);
    word(&mut t, 1, 1);
    word(&mut t, 2, names_off);
    word(&mut t, 3, names_off);
    word(&mut t, 4, names_off);
    word(&mut t, 5, names_off);
    word(&mut t, 6, functab_off);
    for v in [BASE + 0x100, 40, BASE + 0x140, 56, BASE + 0x180] {
        t.extend_from_slice(&v.to_le_bytes());
    }
    // func0 at functab+40: entry u64, nameoff u32, pad.
    t.extend_from_slice(&(BASE + 0x100).to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    // func1 at functab+56.
    t.extend_from_slice(&(BASE + 0x140).to_le_bytes());
    t.extend_from_slice(&7u32.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    t.extend_from_slice(b"go16.a\0go16.b\0");
    t
}

/// 1.2–1.15 layout (pointer-sized words/fields, names into the whole
/// table, full VAs).
fn build_go12() -> Vec<u8> {
    let mut t = vec![0u8; 12];
    t[0..4].copy_from_slice(&0xfffffffb_u32.to_le_bytes());
    t[6] = 1;
    t[7] = 4;
    t[8..12].copy_from_slice(&2u32.to_le_bytes()); // nfunc
    let functab_off = 12usize;
    // functab: {entry, funcoff} x2 plus the end PC (full VAs).
    let names_off = (functab_off + 5 * 4 + 4) as u64 + 24; // past fileoff + 2 func structs
    for v in [BASE + 0x100, 36u64, BASE + 0x140, 48, BASE + 0x180] {
        t.extend_from_slice(&(v as u32).to_le_bytes());
    }
    t.extend_from_slice(&0u32.to_le_bytes()); // fileoff (unused)
    // func0 at 36: entry u32, nameoff u32, args u32.
    t.extend_from_slice(&((BASE + 0x100) as u32).to_le_bytes());
    t.extend_from_slice(&(names_off as u32).to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    // func1 at 48.
    t.extend_from_slice(&((BASE + 0x140) as u32).to_le_bytes());
    t.extend_from_slice(&(names_off as u32 + 8).to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    // funcnametab at names_off.
    assert_eq!(t.len(), names_off as usize);
    t.extend_from_slice(b"go12.a\0go12.b\0");
    t
}

/// Raw blob: `ret` at the base plus the table at [`TAB_OFF`].
fn raw_with_table(table: &[u8]) -> Vec<u8> {
    let mut b = vec![0x90; TAB_OFF + table.len() + 0x40];
    b[0] = 0xC3;
    b[TAB_OFF..TAB_OFF + table.len()].copy_from_slice(table);
    b
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

fn go_funcs_cli(dir: &std::path::Path, tag: &str, blob: &[u8]) -> (bool, Value) {
    let bin = write_bin(dir, &format!("{tag}.bin"), blob);
    let db = temp_db(dir, tag);
    let (bin_s, db_s) = (bin.display().to_string(), db.display().to_string());
    let args = vec![
        "--db".to_string(),
        db_s,
        "go-funcs".to_string(),
        bin_s,
        "--raw".to_string(),
        "--arch".to_string(),
        "x86_64".to_string(),
        "--base".to_string(),
        "0x400000".to_string(),
        "--entry".to_string(),
        "0x400000".to_string(),
    ];
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&args)
}

#[test]
fn new_format_magics_recover_names_and_boundaries() {
    for (magic, tag) in [(0xfffffff0, "go118"), (0xfffffff1, "go120")] {
        let dir = tmpdir(&format!("go-{tag}"));
        let (ok, v) = go_funcs_cli(&dir, tag, &raw_with_table(&build_new(magic)));
        assert!(ok, "{v}");
        assert_eq!(v["protocol"], 1);
        assert_eq!(v["total"], 2);
        let funcs = v["items"].as_array().expect("items");
        assert_eq!(funcs.len(), 2, "{v}");
        assert_eq!(funcs[0]["name"], "main.main");
        assert_eq!(funcs[0]["entry"], BASE + 0x100);
        assert_eq!(funcs[0]["entry_hex"], "0x400100");
        assert_eq!(funcs[0]["end"], BASE + 0x140);
        assert_eq!(funcs[0]["size"], 0x40);
        assert_eq!(funcs[1]["name"], "main.helper");
        assert_eq!(funcs[1]["entry"], BASE + 0x140);
        assert_eq!(funcs[1]["end"], BASE + 0x180);
        cleanup(&dir);
    }
}

#[test]
fn old_format_magics_recover_names_and_boundaries() {
    let dir = tmpdir("go-old");
    let (ok, v) = go_funcs_cli(&dir, "go116", &raw_with_table(&build_go116()));
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 2);
    let funcs = v["items"].as_array().expect("items");
    assert_eq!(funcs.len(), 2, "{v}");
    assert_eq!(funcs[0]["name"], "go16.a");
    assert_eq!(funcs[0]["entry"], BASE + 0x100);
    assert_eq!(funcs[0]["end"], BASE + 0x140);
    assert_eq!(funcs[1]["name"], "go16.b");

    let (ok, v) = go_funcs_cli(&dir, "go12", &raw_with_table(&build_go12()));
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 2);
    let funcs = v["items"].as_array().expect("items");
    assert_eq!(funcs.len(), 2, "{v}");
    assert_eq!(funcs[0]["name"], "go12.a");
    assert_eq!(funcs[0]["entry"], BASE + 0x100);
    assert_eq!(funcs[0]["end"], BASE + 0x140);
    cleanup(&dir);
}

#[test]
fn truncated_table_scans_clean() {
    let dir = tmpdir("go-trunc");
    let mut table = build_new(0xfffffff1);
    table.truncate(40); // magic + partial header: no valid table
    let (ok, v) = go_funcs_cli(&dir, "trunc", &raw_with_table(&table));
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 0);
    assert!(v["items"].as_array().expect("items").is_empty());
    cleanup(&dir);
}

/// Minimal ELF64 with a `.gopclntab` section: exercises the section path
/// (rather than the magic scan) end to end through the real loader.
fn elf_with_gopclntab(table: &[u8]) -> Vec<u8> {
    fn put16(v: &mut [u8], off: usize, x: u16) {
        v[off..off + 2].copy_from_slice(&x.to_le_bytes());
    }
    fn put32(v: &mut [u8], off: usize, x: u32) {
        v[off..off + 4].copy_from_slice(&x.to_le_bytes());
    }
    fn put64(v: &mut [u8], off: usize, x: u64) {
        v[off..off + 8].copy_from_slice(&x.to_le_bytes());
    }
    // Layout: ehdr(64) phdr(56) shstrtab shdrs(3x64) code(1) table.
    let shstr: &[u8] = b"\0.gopclntab\0.shstrtab\0";
    let ehsize = 64usize;
    let phsize = 56usize;
    let shoff = ehsize + phsize;
    let shentsize = 64usize;
    let shnum = 3usize;
    let code_off = shoff + shnum * shentsize;
    let tab_off = code_off + 1;
    let filesz = tab_off + table.len();
    let mut f = vec![0u8; filesz];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2;
    f[5] = 1;
    f[6] = 1;
    put16(&mut f, 16, 2); // EXEC
    put16(&mut f, 18, 62); // x86-64
    put32(&mut f, 20, 1);
    put64(&mut f, 24, BASE + code_off as u64); // entry: the ret below
    put64(&mut f, 32, 64); // phoff
    put64(&mut f, 40, shoff as u64); // shoff
    put16(&mut f, 52, 64); // ehsize
    put16(&mut f, 54, 56); // phentsize
    put16(&mut f, 56, 1); // phnum
    put16(&mut f, 58, 64); // shentsize
    put16(&mut f, 60, 3); // shnum
    put16(&mut f, 62, 2); // shstrndx
    // One PT_LOAD covering the file, R-X.
    let p = ehsize;
    put32(&mut f, p, 1);
    put32(&mut f, p + 4, 5);
    put64(&mut f, p + 8, 0); // offset
    put64(&mut f, p + 16, BASE); // vaddr
    put64(&mut f, p + 32, filesz as u64);
    put64(&mut f, p + 40, filesz as u64);
    put64(&mut f, p + 48, 0x1000);
    // Shdr 0: null. Shdr 1: .gopclntab. Shdr 2: .shstrtab.
    let s1 = shoff + shentsize;
    put32(&mut f, s1, 1); // sh_name -> ".gopclntab"
    put32(&mut f, s1 + 4, 1); // PROGBITS
    put64(&mut f, s1 + 8, 2); // ALLOC
    put64(&mut f, s1 + 16, BASE + tab_off as u64);
    put64(&mut f, s1 + 24, tab_off as u64);
    put64(&mut f, s1 + 32, table.len() as u64);
    let s2 = shoff + 2 * shentsize;
    put32(&mut f, s2, 12); // sh_name -> ".shstrtab"
    put32(&mut f, s2 + 4, 3); // STRTAB
    put64(&mut f, s2 + 24, (ehsize + phsize) as u64);
    put64(&mut f, s2 + 32, shstr.len() as u64);
    f[ehsize + phsize..ehsize + phsize + shstr.len()].copy_from_slice(shstr);
    f[code_off] = 0xC3;
    f[tab_off..tab_off + table.len()].copy_from_slice(table);
    f
}

#[test]
fn section_path_serves_stripped_style_binaries() {
    let dir = tmpdir("go-section");
    let bin = write_bin(&dir, "go.elf", &elf_with_gopclntab(&build_new(0xfffffff1)));
    let db = temp_db(&dir, "go");
    let (bin_s, db_s) = (bin.display().to_string(), db.display().to_string());
    let args: Vec<&str> = vec!["--db", &db_s, "go-funcs", &bin_s];
    let (ok, v) = run(&args);
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 2);
    let funcs = v["items"].as_array().expect("items");
    assert_eq!(funcs.len(), 2, "{v}");
    assert_eq!(funcs[0]["name"], "main.main");
    assert_eq!(funcs[0]["entry"], BASE + 0x100);
    assert_eq!(funcs[0]["end"], BASE + 0x140);
    cleanup(&dir);
}

#[test]
fn corrupt_section_table_errors() {
    let dir = tmpdir("go-corrupt");
    let bin = write_bin(&dir, "go.elf", &elf_with_gopclntab(&[0u8; 64]));
    let db = temp_db(&dir, "go");
    let (bin_s, db_s) = (bin.display().to_string(), db.display().to_string());
    let args: Vec<&str> = vec!["--db", &db_s, "go-funcs", &bin_s];
    let (ok, v) = run(&args);
    assert!(!ok, "located-but-corrupt table must fail");
    assert!(v.get("error").is_some(), "{v}");
    cleanup(&dir);
}
