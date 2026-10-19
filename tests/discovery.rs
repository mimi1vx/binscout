//! Discovery sources (EM6.12): `.pdata`/TLS/ELF-init/function-starts/pointer.
//!
//! Synthetic containers (no checked-in blobs): PE64 with exception + TLS
//! directories, ELF64 with dynamic init tags, Mach-O64 with
//! `LC_FUNCTION_STARTS`, plus a raw pointer-scan table. Each loader table
//! seeds analysis with its own [`DiscoveryReason`]; the pointer scan stays
//! off unless [`AnalyzeOptions::pointer_scan`] opts in.

mod common;

use binscout::analysis::{AnalyzeOptions, DiscoveryReason, analyze, analyze_with_options};
use binscout::disasm::Arch;
use binscout::loader::{BinaryFormat, LoadedBinary, Segment, load};

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn put64(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

/// Minimal PE64 with `.pdata` (two `RUNTIME_FUNCTION`s) and a TLS
/// directory whose callback array points at the second function.
///
/// Layout (`IMAGE_BASE = 0x140000000`): `.text` at RVA `0x1000`
/// (`ret` at `0x1000` and `0x1010`), `.pdata` at `0x2000` (two records),
/// `.rdata` at `0x3000` (TLS dir plus null-terminated callbacks).
/// Headers pad to file offset `0x200`; each section holds `0x200` raw
/// bytes.
fn pe64_pdata_tls() -> Vec<u8> {
    const IMAGE_BASE: u64 = 0x1_4000_0000;
    const TEXT_RVA: u32 = 0x1000;
    const PDATA_RVA: u32 = 0x2000;
    const RDATA_RVA: u32 = 0x3000;
    const TEXT_OFF: usize = 0x200;
    const PDATA_OFF: usize = 0x400;
    const RDATA_OFF: usize = 0x600;
    const RAW: usize = 0x200;
    let mut f = vec![0u8; 0x80];
    f[0] = b'M';
    f[1] = b'Z';
    put32(&mut f, 0x3C, 0x80);
    f.extend_from_slice(b"PE\0\0");
    let c = f.len();
    f.extend(vec![0u8; 20]);
    put16(&mut f, c, 0x8664);
    put16(&mut f, c + 2, 3);
    put16(&mut f, c + 16, 0xF0);
    put16(&mut f, c + 18, 0x0022);
    let o = f.len();
    f.extend(vec![0u8; 0xF0]);
    put16(&mut f, o, 0x20B);
    put32(&mut f, o + 4, 0x200);
    put32(&mut f, o + 16, TEXT_RVA);
    put32(&mut f, o + 20, TEXT_RVA);
    put64(&mut f, o + 24, IMAGE_BASE);
    put32(&mut f, o + 32, 0x1000);
    put32(&mut f, o + 36, 0x200);
    put32(&mut f, o + 56, 0x4000);
    put32(&mut f, o + 60, 0x200);
    put16(&mut f, o + 68, 3);
    put32(&mut f, o + 108, 16);
    // Data directories: exception (3) and TLS (9).
    put32(&mut f, o + 112 + 3 * 8, PDATA_RVA);
    put32(&mut f, o + 112 + 3 * 8 + 4, 24);
    put32(&mut f, o + 112 + 9 * 8, RDATA_RVA);
    put32(&mut f, o + 112 + 9 * 8 + 4, 40);
    let s = f.len();
    f.extend(vec![0u8; 3 * 40]);
    let mut sh = |idx: usize, name: &[u8], rva: u32, off: usize, vsize: u32, chars: u32| {
        let b = s + idx * 40;
        f[b..b + name.len()].copy_from_slice(name);
        put32(&mut f, b + 8, vsize);
        put32(&mut f, b + 12, rva);
        put32(&mut f, b + 16, RAW as u32);
        put32(&mut f, b + 20, off as u32);
        put32(&mut f, b + 36, chars);
    };
    sh(0, b".text", TEXT_RVA, TEXT_OFF, 0x20, 0x6000_0020);
    sh(1, b".pdata", PDATA_RVA, PDATA_OFF, 24, 0x4000_0040);
    sh(2, b".rdata", RDATA_RVA, RDATA_OFF, 0x100, 0x4000_0040);
    assert_eq!(f.len(), 0x200, "headers must end at 0x200");
    // Sections.
    let mut text = vec![0x90u8; RAW];
    text[0] = 0xC3;
    text[0x10] = 0xC3;
    let mut pdata = vec![0u8; RAW];
    put32(&mut pdata, 0, TEXT_RVA);
    put32(&mut pdata, 4, TEXT_RVA + 1);
    put32(&mut pdata, 12, TEXT_RVA + 0x10);
    put32(&mut pdata, 16, TEXT_RVA + 0x11);
    let mut rdata = vec![0u8; RAW];
    let callbacks_va = IMAGE_BASE + u64::from(RDATA_RVA) + 0x40;
    put64(&mut rdata, 24, callbacks_va);
    put64(&mut rdata, 0x40, IMAGE_BASE + u64::from(TEXT_RVA) + 0x10);
    f.extend_from_slice(&text);
    f.extend_from_slice(&pdata);
    f.extend_from_slice(&rdata);
    assert_eq!(f.len(), 0x800);
    f
}

fn reasons_of(bin: &LoadedBinary, entry: u64) -> Vec<DiscoveryReason> {
    let a = analyze(bin).expect("synthetic must analyze");
    a.functions
        .get(&entry)
        .unwrap_or_else(|| panic!("no function at {entry:#x}"))
        .reason_list()
}

/// Pointer-scan table: one executable `ret` at `0x1000`, one data segment
/// at `0x2000` holding an aligned pointer to it plus zero/junk slots.
fn pointer_binary() -> LoadedBinary {
    LoadedBinary {
        format: BinaryFormat::Raw,
        arch: Arch::X86_64,
        entry: Some(0x1000),
        segments: vec![
            Segment {
                vaddr: 0x1000,
                mem_size: 1,
                data: vec![0xC3],
                readable: true,
                writable: false,
                executable: true,
            },
            Segment {
                vaddr: 0x2000,
                mem_size: 24,
                data: {
                    let mut d = vec![0u8; 24];
                    d[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
                    d[8..16].copy_from_slice(&0xdead_beefu64.to_le_bytes());
                    d[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
                    d
                },
                readable: true,
                writable: true,
                executable: false,
            },
        ],
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        symbols: Vec::new(),
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        debug_funcs: Vec::new(),
        relocatable: false,
        arm_hints: Default::default(),
    }
}

#[test]
fn pointer_scan_is_gated_by_flag() {
    let bin = pointer_binary();
    let off = analyze(&bin).expect("default analyzes");
    assert!(
        !off.functions
            .values()
            .flat_map(|f| f.reason_list())
            .any(|r| r == DiscoveryReason::Pointer),
        "pointer scan must stay off by default"
    );
    let on = analyze_with_options(&bin, &[], AnalyzeOptions::with_pointer_scan())
        .expect("pointer scan analyzes");
    let target = on.functions.get(&0x1000).expect("target exists");
    assert!(
        target.reason_list().contains(&DiscoveryReason::Pointer),
        "pointer target must carry Pointer reason, got {:?}",
        target.reason_list()
    );
}

#[test]
fn new_reasons_serialize_kebab() {
    assert_eq!(
        serde_json::to_value(DiscoveryReason::Pdata).expect("serializes"),
        serde_json::json!("pdata")
    );
    assert_eq!(
        serde_json::to_value(DiscoveryReason::TlsCallback).expect("serializes"),
        serde_json::json!("tls-callback")
    );
    assert_eq!(
        serde_json::to_value(DiscoveryReason::InitArray).expect("serializes"),
        serde_json::json!("init-array")
    );
    assert_eq!(
        serde_json::to_value(DiscoveryReason::FunctionStarts).expect("serializes"),
        serde_json::json!("function-starts")
    );
    assert_eq!(
        serde_json::to_value(DiscoveryReason::Pointer).expect("serializes"),
        serde_json::json!("pointer")
    );
}

#[test]
fn table_seeds_become_entries_with_reasons() {
    let mk =
        |pdata: Vec<(u64, u64)>, tls: Vec<u64>, init: Vec<u64>, starts: Vec<u64>| LoadedBinary {
            format: BinaryFormat::Raw,
            arch: Arch::X86_64,
            entry: None,
            segments: vec![Segment {
                vaddr: 0x1000,
                mem_size: 0x30,
                data: vec![0xC3u8; 0x30],
                readable: true,
                writable: false,
                executable: true,
            }],
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            pdata_funcs: pdata,
            tls_callbacks: tls,
            init_funcs: init,
            func_starts: starts,
            debug_funcs: Vec::new(),
            relocatable: false,
            arm_hints: Default::default(),
        };
    assert!(
        reasons_of(&mk(vec![(0x1010, 0x1020)], vec![], vec![], vec![],), 0x1010)
            .contains(&DiscoveryReason::Pdata)
    );
    assert!(
        reasons_of(&mk(vec![], vec![0x1010], vec![], vec![]), 0x1010)
            .contains(&DiscoveryReason::TlsCallback)
    );
    assert!(
        reasons_of(&mk(vec![], vec![], vec![0x1010], vec![]), 0x1010)
            .contains(&DiscoveryReason::InitArray)
    );
    assert!(
        reasons_of(&mk(vec![], vec![], vec![], vec![0x1010]), 0x1010)
            .contains(&DiscoveryReason::FunctionStarts)
    );
}

#[test]
fn pe_pdata_and_tls_seed_with_reasons() {
    let bytes = pe64_pdata_tls();
    let bin = load(&bytes).expect("synthetic PE64 must load");
    assert_eq!(bin.format, BinaryFormat::Pe);
    assert_eq!(bin.arch, Arch::X86_64);
    const IMAGE_BASE: u64 = 0x1_4000_0000;
    let f0 = IMAGE_BASE + 0x1000;
    let f1 = IMAGE_BASE + 0x1010;
    assert_eq!(
        bin.pdata_funcs,
        vec![(f0, f0 + 1), (f1, f1 + 1)],
        "pdata must decode both ranges"
    );
    assert_eq!(bin.tls_callbacks, vec![f1], "TLS must decode one callback");
    let a = analyze(&bin).expect("PE64 must analyze");
    let r0 = a
        .functions
        .get(&f0)
        .unwrap_or_else(|| panic!("no function at {f0:#x}"))
        .reason_list();
    assert!(r0.contains(&DiscoveryReason::Pdata), "pdata reason: {r0:?}");
    let r1 = a
        .functions
        .get(&f1)
        .unwrap_or_else(|| panic!("no function at {f1:#x}"))
        .reason_list();
    assert!(r1.contains(&DiscoveryReason::Pdata), "pdata reason: {r1:?}");
    assert!(
        r1.contains(&DiscoveryReason::TlsCallback),
        "TLS reason: {r1:?}"
    );
}

/// Minimal 64-bit LE ELF with dynamic init tags and an `.init_array`
/// section.
///
/// Code (`ret; ret`) at `0x400000`; `.init_array` at `0x401000` holds both
/// code addresses; `PT_DYNAMIC` repeats them via `DT_INIT`/`DT_FINI` and
/// `DT_INIT_ARRAY`/`DT_INIT_ARRAYSZ`. Three program headers
/// (`PT_LOAD` code, `PT_LOAD` data, `PT_DYNAMIC`) plus four section
/// headers (null, `.text`, `.init_array`, `.shstrtab`).
fn elf64_init() -> Vec<u8> {
    const CODE_VA: u64 = 0x400000;
    const DATA_VA: u64 = 0x401000;
    const CODE_OFF: usize = 0xE8;
    const DATA_OFF: usize = 0xF0;
    const DYN_OFF: usize = 0x100;
    const SHSTR_OFF: usize = 0x150;
    const SH_OFF: usize = 0x170;
    let mut f = vec![0u8; 0x40];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2;
    f[5] = 1;
    f[6] = 1;
    put16(&mut f, 16, 2);
    put16(&mut f, 18, 62);
    put32(&mut f, 20, 1);
    put64(&mut f, 24, CODE_VA);
    put64(&mut f, 32, 0x40);
    put64(&mut f, 40, SH_OFF as u64);
    put16(&mut f, 52, 64);
    put16(&mut f, 54, 56);
    put16(&mut f, 56, 3);
    put16(&mut f, 58, 64);
    put16(&mut f, 60, 4);
    put16(&mut f, 62, 3);
    // Program headers.
    f.extend(vec![0u8; 3 * 56]);
    let mut ph = |idx: usize, typ: u32, flags: u32, off: usize, va: u64, filesz: u64| {
        let b = 0x40 + idx * 56;
        put32(&mut f, b, typ);
        put32(&mut f, b + 4, flags);
        put64(&mut f, b + 8, off as u64);
        put64(&mut f, b + 16, va);
        put64(&mut f, b + 24, va);
        put64(&mut f, b + 32, filesz);
        put64(&mut f, b + 40, filesz);
        put64(&mut f, b + 48, 0x1000);
    };
    ph(0, 1, 5, CODE_OFF, CODE_VA, 2);
    ph(1, 1, 6, DATA_OFF, DATA_VA, 0x60);
    ph(2, 2, 6, DYN_OFF, DATA_VA + 0x10, 80);
    assert_eq!(f.len(), CODE_OFF);
    f.extend_from_slice(&[0xC3, 0xC3]);
    f.resize(DATA_OFF, 0);
    // `.init_array`: both code addresses.
    f.extend_from_slice(&CODE_VA.to_le_bytes());
    f.extend_from_slice(&(CODE_VA + 1).to_le_bytes());
    assert_eq!(f.len(), DYN_OFF);
    // Dynamic array: INIT, FINI, INIT_ARRAY, INIT_ARRAYSZ, NULL.
    let mut dyn_ = |tag: i64, val: u64| {
        f.extend_from_slice(&tag.to_le_bytes());
        f.extend_from_slice(&val.to_le_bytes());
    };
    dyn_(12, CODE_VA);
    dyn_(13, CODE_VA + 1);
    dyn_(25, DATA_VA);
    dyn_(27, 16);
    dyn_(0, 0);
    assert_eq!(f.len(), DYN_OFF + 80);
    f.resize(SHSTR_OFF, 0);
    let shstr = b"\0.text\0.init_array\0.shstrtab\0";
    f.extend_from_slice(shstr);
    assert_eq!(shstr.len(), 29);
    f.resize(SH_OFF, 0);
    // Section headers.
    f.extend(vec![0u8; 4 * 64]);
    let mut sh = |idx: usize, name: u32, typ: u32, flags: u64, addr: u64, off: usize, size: u64| {
        let b = SH_OFF + idx * 64;
        put32(&mut f, b, name);
        put32(&mut f, b + 4, typ);
        put64(&mut f, b + 8, flags);
        put64(&mut f, b + 16, addr);
        put64(&mut f, b + 24, off as u64);
        put64(&mut f, b + 32, size);
        put32(&mut f, b + 48, 16);
    };
    sh(0, 0, 0, 0, 0, 0, 0);
    sh(1, 1, 1, 0x6, CODE_VA, CODE_OFF, 2);
    sh(2, 7, 1, 0x3, DATA_VA, DATA_OFF, 16);
    sh(3, 19, 3, 0, 0, SHSTR_OFF, 29);
    assert_eq!(f.len(), SH_OFF + 256);
    f
}

#[test]
fn elf_init_seeds_with_reason() {
    let bytes = elf64_init();
    let bin = load(&bytes).expect("synthetic ELF64 must load");
    assert_eq!(bin.format, BinaryFormat::Elf);
    assert_eq!(bin.arch, Arch::X86_64);
    assert!(
        bin.init_funcs.contains(&0x400000) && bin.init_funcs.contains(&0x400001),
        "init must decode both targets, got {:?}",
        bin.init_funcs
    );
    let a = analyze(&bin).expect("ELF64 must analyze");
    for va in [0x400000, 0x400001] {
        let r = a
            .functions
            .get(&va)
            .unwrap_or_else(|| panic!("no function at {va:#x}"))
            .reason_list();
        assert!(
            r.contains(&DiscoveryReason::InitArray),
            "init reason: {r:?}"
        );
    }
}

/// Minimal 64-bit Mach-O with `LC_FUNCTION_STARTS`.
///
/// `__TEXT` at `0x1000` holds three `ret`s; the starts payload encodes
/// deltas `[1, 1]` for starts at `0x1001`/`0x1002`, leaving the `0x1000`
/// fallback entry with `Entry` only.
fn macho_function_starts_bin() -> Vec<u8> {
    let seg_cmd = 72 + 80;
    let starts_cmd = 16usize;
    let head_end = 32 + seg_cmd + starts_cmd;
    assert_eq!(head_end, 0xC8);
    let code_off = head_end;
    let payload_off = code_off + 4;
    let mut f = vec![0u8; head_end];
    put32(&mut f, 0, 0xFEED_FACF);
    put32(&mut f, 4, 0x0100_0007);
    put32(&mut f, 8, 3);
    put32(&mut f, 12, 2);
    put32(&mut f, 16, 2);
    put32(&mut f, 20, (seg_cmd + starts_cmd) as u32);
    let c = 32;
    put32(&mut f, c, 0x19);
    put32(&mut f, c + 4, seg_cmd as u32);
    f[c + 8..c + 14].copy_from_slice(b"__TEXT");
    put64(&mut f, c + 24, 0x1000);
    put64(&mut f, c + 32, 0x1000);
    put64(&mut f, c + 40, code_off as u64);
    put64(&mut f, c + 48, 4);
    put32(&mut f, c + 56, 5);
    put32(&mut f, c + 60, 5);
    put32(&mut f, c + 64, 1);
    let s = c + 72;
    f[s..s + 6].copy_from_slice(b"__text");
    f[s + 16..s + 22].copy_from_slice(b"__TEXT");
    put64(&mut f, s + 32, 0x1000);
    put64(&mut f, s + 40, 4);
    put32(&mut f, s + 48, code_off as u32);
    put32(&mut f, s + 52, 2);
    put32(&mut f, s + 64, 0x8000_0400);
    let c = 32 + seg_cmd;
    put32(&mut f, c, 0x26);
    put32(&mut f, c + 4, starts_cmd as u32);
    put32(&mut f, c + 8, payload_off as u32);
    put32(&mut f, c + 12, 2);
    f.extend_from_slice(&[0xC3, 0xC3, 0xC3, 0x90]);
    f.extend_from_slice(&[0x01, 0x01]);
    assert_eq!(f.len(), payload_off + 2);
    f
}

#[test]
fn macho_function_starts_seed_with_reason() {
    let bytes = macho_function_starts_bin();
    let bin = load(&bytes).expect("synthetic Mach-O must load");
    assert_eq!(bin.format, BinaryFormat::MachO);
    assert_eq!(bin.func_starts, vec![0x1001, 0x1002]);
    let a = analyze(&bin).expect("Mach-O must analyze");
    for va in [0x1001, 0x1002] {
        let r = a
            .functions
            .get(&va)
            .unwrap_or_else(|| panic!("no function at {va:#x}"))
            .reason_list();
        assert!(
            r.contains(&DiscoveryReason::FunctionStarts),
            "starts reason: {r:?}"
        );
    }
}

#[test]
fn new_reasons_survive_save_and_reopen() {
    let dir = common::tmpdir("discovery-save");
    let path = common::write_bin(&dir, "pe64.exe", &pe64_pdata_tls());
    let db = common::temp_db(&dir, "pe64");
    let p = binscout::Project::open_with_db(&path, &db).expect("PE64 must open");
    const IMAGE_BASE: u64 = 0x1_4000_0000;
    let f1 = IMAGE_BASE + 0x1010;
    let before = p
        .analysis()
        .functions
        .get(&f1)
        .unwrap_or_else(|| panic!("no function at {f1:#x}"))
        .reason_list();
    assert!(before.contains(&DiscoveryReason::Pdata), "{before:?}");
    assert!(before.contains(&DiscoveryReason::TlsCallback), "{before:?}");
    p.save().expect("save works");
    drop(p);
    let q = binscout::Project::open_with_db(&path, &db).expect("reopen works");
    let after = q
        .analysis()
        .functions
        .get(&f1)
        .unwrap_or_else(|| panic!("no function at {f1:#x}"))
        .reason_list();
    assert_eq!(before, after, "reasons must survive save/reopen");
    common::cleanup(&dir);
}
