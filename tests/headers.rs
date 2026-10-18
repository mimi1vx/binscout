//! `headers` surface: on-demand triage metadata plus file hashes.
//!
//! Fixtures are built in-code (no binaries checked in): the PE/ELF/LE
//! fixtures come from `tests/fixtures/builders.rs` and `minimal_elf`,
//! while the RELRO/NX/PIE ELF and the Mach-O triage image are assembled
//! below. Assertions pin exact values (timestamp, interp, dylibs, UUID),
//! never just shapes.

mod common;

use serde_json::Value;

use common::{binscout_bin, cleanup, open_test_project, tmpdir, write_bin, write_fixture};

fn headers_of(bin: &std::path::Path, db: &std::path::Path) -> Value {
    let proj = binscout::Project::open_with_db(bin, db).expect("fixture must open");
    serde_json::to_value(proj.headers_json().expect("headers")).expect("json")
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

/// ELF64 `ET_DYN` with INTERP, NEEDED x2, RUNPATH, BIND_NOW, RELRO, NX
/// stack, GNU build-id and section headers (no `.symtab`): exercises every
/// parsed ELF field. Base VA `0x400000`, file offsets identity-mapped.
fn rich_elf() -> Vec<u8> {
    const BASE: u64 = 0x400_000;
    let interp = b"/lib64/ld-linux-x86-64.so.2\0";
    // "\0libc.so.6\0libm.so.6\0/run/path\0": NEEDED1=1, NEEDED2=11, RUNPATH=21.
    let dynstr = b"\0libc.so.6\0libm.so.6\0/run/path\0";
    let build_id: Vec<u8> = (0..20u8).collect();
    let code = [0x90u8, 0x90, 0xC3];
    // Note payload: namesz=4, descsz=20, type=3, "GNU\0", 20 id bytes.
    let mut note = Vec::new();
    note.extend_from_slice(&4u32.to_le_bytes());
    note.extend_from_slice(&20u32.to_le_bytes());
    note.extend_from_slice(&3u32.to_le_bytes());
    note.extend_from_slice(b"GNU\0");
    note.extend_from_slice(&build_id);

    let ehsize = 64usize;
    let phnum = 6usize;
    let phoff = ehsize;
    let phsize = 56usize;
    let data_off = ehsize + phnum * phsize;
    let interp_off = data_off;
    // Dynamic: NEEDED, NEEDED, STRTAB, STRSZ, RUNPATH, FLAGS_1, NULL.
    let dyn_off = interp_off + interp.len();
    let dyn_count = 7usize;
    let dynstr_off = dyn_off + dyn_count * 16;
    let note_off = dynstr_off + dynstr.len();
    let code_off = note_off + note.len();
    let shstr = b"\0.interp\0.dynstr\0.note.gnu.build-id\0.text\0.shstrtab\0";
    let shstr_off = code_off + code.len();
    let shoff = shstr_off + shstr.len();
    let shnum = 6usize;
    let shstrndx = 5usize;

    let mut f = vec![0u8; shoff + shnum * 64];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2; // 64-bit
    f[5] = 1; // LE
    f[6] = 1;
    put16(&mut f, 16, 3); // ET_DYN
    put16(&mut f, 18, 62); // x86-64
    put32(&mut f, 20, 1);
    put64(&mut f, 24, BASE + code_off as u64); // entry at .text
    put64(&mut f, 32, phoff as u64);
    put64(&mut f, 40, shoff as u64);
    put16(&mut f, 52, 64);
    put16(&mut f, 54, 56);
    put16(&mut f, 56, phnum as u16);
    put16(&mut f, 58, 64);
    put16(&mut f, 60, shnum as u16);
    put16(&mut f, 62, shstrndx as u16);

    // Program headers: LOAD covers everything, then INTERP/DYNAMIC/NOTE/RELRO/STACK.
    let mut ph =
        |i: usize, ty: u32, flags: u32, off: usize, va: u64, filesz: usize, memsz: usize| {
            let b = phoff + i * phsize;
            put32(&mut f, b, ty);
            put32(&mut f, b + 4, flags);
            put64(&mut f, b + 8, off as u64);
            put64(&mut f, b + 16, va);
            put64(&mut f, b + 24, va);
            put64(&mut f, b + 32, filesz as u64);
            put64(&mut f, b + 40, memsz as u64);
            put64(&mut f, b + 48, 0x1000);
        };
    let total = shoff + shnum * 64;
    ph(0, 1, 5, 0, BASE, total, total); // PT_LOAD R+X
    ph(
        1,
        3,
        4,
        interp_off,
        BASE + interp_off as u64,
        interp.len(),
        interp.len(),
    );
    ph(
        2,
        2,
        6,
        dyn_off,
        BASE + dyn_off as u64,
        dyn_count * 16,
        dyn_count * 16,
    );
    ph(
        3,
        4,
        4,
        note_off,
        BASE + note_off as u64,
        note.len(),
        note.len(),
    );
    ph(
        4,
        0x6474_e552,
        4,
        dyn_off,
        BASE + dyn_off as u64,
        dyn_count * 16,
        dyn_count * 16,
    );
    ph(5, 0x6474_e551, 6, 0, 0, 0, 0); // PT_GNU_STACK RW (NX)

    // Dynamic entries.
    let strtab_va = BASE + dynstr_off as u64;
    let mut dyn_entry = |i: usize, tag: i64, val: u64| {
        let b = dyn_off + i * 16;
        put64(&mut f, b, tag as u64);
        put64(&mut f, b + 8, val);
    };
    dyn_entry(0, 1, 1); // NEEDED libc
    dyn_entry(1, 1, 11); // NEEDED libm
    dyn_entry(2, 5, strtab_va); // STRTAB
    dyn_entry(3, 10, dynstr.len() as u64); // STRSZ
    dyn_entry(4, 29, 21); // RUNPATH
    dyn_entry(5, 0x6fff_fffb, 1); // FLAGS_1 DF_1_NOW
    dyn_entry(6, 0, 0); // NULL

    f[interp_off..interp_off + interp.len()].copy_from_slice(interp);
    f[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(dynstr);
    f[note_off..note_off + note.len()].copy_from_slice(&note);
    f[code_off..code_off + code.len()].copy_from_slice(&code);
    f[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

    // Section headers: null, .interp, .dynstr, .note.gnu.build-id, .text, .shstrtab.
    let mut sh = |i: usize, name: usize, ty: u32, flags: u64, off: usize, size: usize, va: u64| {
        let b = shoff + i * 64;
        put32(&mut f, b, name as u32);
        put32(&mut f, b + 4, ty);
        put64(&mut f, b + 8, flags);
        put64(&mut f, b + 16, va);
        put64(&mut f, b + 24, off as u64);
        put64(&mut f, b + 32, size as u64);
        put32(&mut f, b + 48, 1);
    };
    sh(0, 0, 0, 0, 0, 0, 0);
    sh(
        1,
        1,
        1,
        2,
        interp_off,
        interp.len(),
        BASE + interp_off as u64,
    );
    sh(2, 9, 1, 2, dynstr_off, dynstr.len(), strtab_va);
    sh(3, 17, 7, 2, note_off, note.len(), BASE + note_off as u64);
    sh(4, 36, 1, 6, code_off, code.len(), BASE + code_off as u64);
    sh(5, 42, 3, 0, shstr_off, shstr.len(), 0);
    f
}

fn put32macho(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn put64macho(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// Thin Mach-O x86-64 with UUID, BUILD_VERSION, one dylib and a code
/// signature carrying entitlements: exercises every Mach-O field.
fn triage_macho() -> (Vec<u8>, usize) {
    let code = [0x90u8, 0x90, 0xC3, 0x90];
    let dylib = b"/usr/lib/libSystem.B.dylib\0";
    let ent = b"<?xml plist test entitlements?>";
    // Command sizes: seg(72+80) uuid(24) buildver(24) dylib(24+padded name) codesig(16).
    let name_padded = dylib.len().div_ceil(8) * 8;
    let dylib_size = 24 + name_padded;
    let seg_size = 72 + 80;
    let sizeofcmds = seg_size + 24 + 24 + dylib_size + 16;
    let code_off = 32 + sizeofcmds;
    let sig_off = code_off + code.len();
    // Superblob: header(8) + 1 index(8) + blob header(8) + entitlements.
    let blob_len = 8 + ent.len();
    let sig_size = 8 + 8 + blob_len;

    let mut f = Vec::new();
    put32macho(&mut f, 0xFEED_FACF); // 64-bit LE
    put32macho(&mut f, 0x0100_0007); // x86-64
    put32macho(&mut f, 3);
    put32macho(&mut f, 2); // MH_EXECUTE
    put32macho(&mut f, 5); // ncmds
    put32macho(&mut f, sizeofcmds as u32);
    put32macho(&mut f, 0); // flags
    put32macho(&mut f, 0); // reserved

    // LC_SEGMENT_64 + one __text section.
    put32macho(&mut f, 0x19);
    put32macho(&mut f, seg_size as u32);
    f.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    put64macho(&mut f, 0x1000); // vmaddr
    put64macho(&mut f, code.len() as u64); // vmsize
    put64macho(&mut f, code_off as u64); // fileoff
    put64macho(&mut f, code.len() as u64); // filesize
    put32macho(&mut f, 5);
    put32macho(&mut f, 5);
    put32macho(&mut f, 1); // nsects
    put32macho(&mut f, 0); // flags
    f.extend_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
    f.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    put64macho(&mut f, 0x1000);
    put64macho(&mut f, code.len() as u64);
    put32macho(&mut f, code_off as u32);
    put32macho(&mut f, 2); // align
    put32macho(&mut f, 0); // reloff
    put32macho(&mut f, 0); // nreloc
    put32macho(&mut f, 0x8000_0400); // pure instructions
    put32macho(&mut f, 0);
    put32macho(&mut f, 0);
    put32macho(&mut f, 0);

    // LC_UUID: 00..0f.
    put32macho(&mut f, 0x1b);
    put32macho(&mut f, 24);
    f.extend_from_slice(&(0..16u8).collect::<Vec<u8>>());

    // LC_BUILD_VERSION: macos 14.0, sdk 14.2.
    put32macho(&mut f, 0x32);
    put32macho(&mut f, 24);
    put32macho(&mut f, 1); // macos
    put32macho(&mut f, 14 << 16); // 14.0
    put32macho(&mut f, (14 << 16) | (2 << 8)); // 14.2
    put32macho(&mut f, 0); // ntools

    // LC_LOAD_DYLIB.
    put32macho(&mut f, 0xc);
    put32macho(&mut f, dylib_size as u32);
    put32macho(&mut f, 24); // name offset
    put32macho(&mut f, 0); // timestamp
    put32macho(&mut f, 0); // current version
    put32macho(&mut f, 0); // compat version
    f.extend_from_slice(dylib);
    f.extend(std::iter::repeat_n(0, name_padded - dylib.len()));

    // LC_CODE_SIGNATURE.
    put32macho(&mut f, 0x1d);
    put32macho(&mut f, 16);
    put32macho(&mut f, sig_off as u32);
    put32macho(&mut f, sig_size as u32);

    assert_eq!(f.len(), code_off, "commands must end at code");
    f.extend_from_slice(&code);
    // Superblob with one entitlements slot.
    f.extend_from_slice(&0xfade_0cc0u32.to_be_bytes());
    f.extend_from_slice(&(8 + 8 + blob_len as u32).to_be_bytes());
    f.extend_from_slice(&1u32.to_be_bytes());
    f.extend_from_slice(&5u32.to_be_bytes()); // CSSLOT_ENTITLEMENTS
    f.extend_from_slice(&20u32.to_be_bytes()); // blob offset past header + index
    f.extend_from_slice(&0xfade_7171u32.to_be_bytes());
    f.extend_from_slice(&(blob_len as u32).to_be_bytes());
    f.extend_from_slice(ent);
    (f, blob_len)
}

#[test]
fn pe_basic_headers_pin_fixture_values() {
    let dir = tmpdir("headers-pe");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let db = common::temp_db(&dir, "basic");
    let v = headers_of(&bin, &db);
    assert_eq!(v["format"], "pe");
    assert_eq!(v["size"], 2048);
    assert_eq!(v["sha256"].as_str().expect("sha256").len(), 64);
    assert_eq!(v["md5"].as_str().expect("md5").len(), 32);
    let pe = &v["pe"];
    assert_eq!(pe["timestamp"], 0x1234_5678);
    assert_eq!(pe["subsystem"], 3);
    assert_eq!(pe["subsystem_name"], "WINDOWS_CUI");
    assert_eq!(pe["dll_characteristics"], 0);
    assert_eq!(pe["aslr"], false);
    assert_eq!(pe["dep"], false);
    assert_eq!(pe["cfg"], false);
    assert_eq!(pe["high_entropy_va"], false);
    assert_eq!(pe["rich"]["present"], false);
    assert!(pe["imphash"].is_null(), "basic fixture has no imports");
    assert_eq!(pe["authenticode"]["present"], false);
    assert_eq!(pe["authenticode"]["size"], 0);
    assert!(pe["pdb"].is_null());
    assert_eq!(pe["version_info"]["present"], false);
    assert!(pe["delay_load"].as_array().expect("array").is_empty());
    assert!(
        pe["export_forwarders"]
            .as_array()
            .expect("array")
            .is_empty()
    );
    assert!(v["elf"].is_null() && v["macho"].is_null());
    cleanup(&dir);
}

#[test]
fn pe_ordinals_imphash_is_pinned() {
    let dir = tmpdir("headers-ord");
    let bin = write_fixture(&dir, "pe32-ordinals.exe");
    let db = common::temp_db(&dir, "ord");
    let v = headers_of(&bin, &db);
    assert_eq!(v["format"], "pe");
    // Independently verified with Python hashlib over the loader's
    // `library.name` table order (`testdll.dll.1,2,?myfunc…`).
    assert_eq!(v["pe"]["imphash"], "4a7adcd188dec44fcc029c7dfab11da9");
    cleanup(&dir);
}

#[test]
fn elf_minimal_fields_degrade_cleanly() {
    let dir = tmpdir("headers-elf-min");
    let bin = write_bin(&dir, "minimal.elf", &common::minimal_elf());
    let db = common::temp_db(&dir, "min");
    let v = headers_of(&bin, &db);
    assert_eq!(v["format"], "elf");
    let elf = &v["elf"];
    assert!(elf["interp"].is_null());
    assert!(elf["needed"].as_array().expect("array").is_empty());
    assert!(elf["runpath"].is_null() && elf["rpath"].is_null());
    assert_eq!(elf["relro"], "none");
    assert_eq!(elf["nx"], false);
    assert_eq!(elf["pie"], false, "minimal fixture is ET_EXEC");
    assert!(elf["build_id"].is_null());
    assert_eq!(elf["stripped"], true);
    assert!(v["pe"].is_null() && v["macho"].is_null());
    cleanup(&dir);
}

#[test]
fn elf_rich_fields_parse() {
    let dir = tmpdir("headers-elf-rich");
    let bin = write_bin(&dir, "rich.elf", &rich_elf());
    let db = common::temp_db(&dir, "rich");
    let v = headers_of(&bin, &db);
    assert_eq!(v["format"], "elf");
    let elf = &v["elf"];
    assert_eq!(elf["interp"], "/lib64/ld-linux-x86-64.so.2");
    assert_eq!(elf["needed"], serde_json::json!(["libc.so.6", "libm.so.6"]));
    assert_eq!(elf["runpath"], "/run/path");
    assert!(elf["rpath"].is_null());
    assert_eq!(elf["relro"], "full", "RELRO plus DF_1_NOW");
    assert_eq!(elf["nx"], true);
    assert_eq!(elf["pie"], true, "ET_DYN with an interpreter");
    assert_eq!(elf["build_id"], "000102030405060708090a0b0c0d0e0f10111213");
    assert_eq!(elf["stripped"], true, "sections exist but no .symtab");
    cleanup(&dir);
}

#[test]
fn macho_triage_fields_parse() {
    let dir = tmpdir("headers-macho");
    let (bytes, blob_len) = triage_macho();
    let bin = write_bin(&dir, "triage.macho", &bytes);
    let db = common::temp_db(&dir, "macho");
    let v = headers_of(&bin, &db);
    assert_eq!(v["format"], "macho");
    let macho = &v["macho"];
    assert_eq!(
        macho["commands"],
        serde_json::json!([
            "LC_SEGMENT_64",
            "LC_UUID",
            "LC_BUILD_VERSION",
            "LC_LOAD_DYLIB",
            "LC_CODE_SIGNATURE"
        ])
    );
    assert_eq!(
        macho["dylibs"],
        serde_json::json!(["/usr/lib/libSystem.B.dylib"])
    );
    assert_eq!(macho["platform"], "macos");
    assert_eq!(macho["min_os"], "14.0");
    assert_eq!(macho["sdk"], "14.2");
    assert_eq!(macho["code_signature"]["present"], true);
    assert!(macho["code_signature"]["size"].as_u64().expect("size") > 0);
    assert_eq!(macho["entitlements"]["present"], true);
    assert_eq!(macho["entitlements"]["size"], blob_len as u64);
    assert_eq!(macho["uuid"], "00010203-0405-0607-0809-0a0b0c0d0e0f");
    assert!(v["pe"].is_null() && v["elf"].is_null());
    cleanup(&dir);
}

#[test]
fn raw_and_garbage_degrade_to_hashes_only() {
    let dir = tmpdir("headers-raw");
    // `raw-x64.bin` is checked in but has no builder; read it directly.
    let raw = std::fs::read("tests/fixtures/raw-x64.bin").expect("checked-in fixture");
    let raw_bin = write_bin(&dir, "raw.bin", &raw);
    let garbage_bin = write_fixture(&dir, "text-garbage.bin");
    for (name, bin) in [("raw-x64.bin", raw_bin), ("text-garbage.bin", garbage_bin)] {
        let db = common::temp_db(&dir, name);
        let v = headers_of(&bin, &db);
        assert!(
            v["pe"].is_null() && v["elf"].is_null() && v["macho"].is_null(),
            "{name}"
        );
        assert_eq!(v["md5"].as_str().expect("md5").len(), 32);
        assert_eq!(v["sha256"].as_str().expect("sha256").len(), 64);
    }
    cleanup(&dir);
}

#[test]
fn headers_read_never_creates_sidecar() {
    let dir = tmpdir("headers-readonly");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let db = common::temp_db(&dir, "basic");
    let proj = binscout::Project::open_with_db(&bin, &db).expect("open");
    proj.headers_json().expect("headers");
    assert!(!db.exists(), "reads never create the sidecar");
    cleanup(&dir);
}

#[test]
fn cli_headers_prints_one_json_value() {
    use std::process::Command;
    let dir = tmpdir("headers-cli");
    let bin = write_fixture(&dir, "pe32-basic.exe");
    let db = common::temp_db(&dir, "basic");
    let out = Command::new(binscout_bin())
        .args([
            "headers",
            &bin.display().to_string(),
            "--db",
            &db.display().to_string(),
        ])
        .output()
        .expect("run binscout headers");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("stdout is one JSON value");
    assert_eq!(v["format"], "pe");
    assert_eq!(v["pe"]["timestamp"], 0x1234_5678);
    assert!(!db.exists(), "reads never create the sidecar");
    cleanup(&dir);
}

#[test]
fn open_test_project_helper_opens_headers() {
    let dir = tmpdir("headers-helper");
    let proj = open_test_project(&dir, "le-minimal.exe");
    let v = proj.headers_json().expect("headers");
    assert_eq!(v["format"], "le");
    assert!(v["pe"].is_null() && v["elf"].is_null() && v["macho"].is_null());
    cleanup(&dir);
}
