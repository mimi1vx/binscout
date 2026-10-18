//! M1 loader tests on synthetic minimal images (no external fixtures:
//! license-clean in-memory binaries per format, plus the committed
//! `raw-x64.bin` for raw mode).

mod common;

use binscout::disasm::{Arch, disasm_range};
use binscout::error::Error;
use binscout::loader::{
    BinaryFormat, RawOptions, load, load_raw,
    strings::{Encoding, extract, extract_page},
};
use common::builders;

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn put64(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

/// Minimal 64-bit LE ELF: one `PT_LOAD` (`nop; nop; ret`) at `0x400000`.
fn minimal_elf() -> Vec<u8> {
    let mut f = vec![0u8; 0x78];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2; // 64-bit
    f[5] = 1; // little-endian
    f[6] = 1; // version
    put16(&mut f, 16, 2); // EXEC
    put16(&mut f, 18, 62); // x86-64
    put32(&mut f, 20, 1);
    put64(&mut f, 24, 0x400000); // entry
    put64(&mut f, 32, 64); // phoff
    put16(&mut f, 52, 64); // ehsize
    put16(&mut f, 54, 56); // phentsize
    put16(&mut f, 56, 1); // phnum
    let p = 64;
    put32(&mut f, p, 1); // PT_LOAD
    put32(&mut f, p + 4, 5); // R+X
    put64(&mut f, p + 8, 0x78); // file offset
    put64(&mut f, p + 16, 0x400000); // vaddr
    put64(&mut f, p + 32, 3); // filesz
    put64(&mut f, p + 40, 3); // memsz
    put64(&mut f, p + 48, 0x1000); // align
    f.extend_from_slice(&[0x90, 0x90, 0xC3]);
    f
}

/// Minimal PE32+ (x86-64): one `.text` (`nop; nop; ret`), no imports/exports.
fn minimal_pe() -> Vec<u8> {
    let mut f = vec![0u8; 0x80];
    f[0] = b'M';
    f[1] = b'Z';
    put32(&mut f, 0x3C, 0x80); // e_lfanew
    f.extend_from_slice(b"PE\0\0");
    let c = f.len();
    f.extend(vec![0u8; 20]);
    put16(&mut f, c, 0x8664); // AMD64
    put16(&mut f, c + 2, 1); // sections
    put16(&mut f, c + 16, 0xF0); // optional size
    put16(&mut f, c + 18, 0x0022); // EXECUTABLE_IMAGE
    let o = f.len();
    f.extend(vec![0u8; 0xF0]);
    put16(&mut f, o, 0x20B); // PE32+
    put32(&mut f, o + 4, 0x200); // SizeOfCode
    put32(&mut f, o + 16, 0x1000); // entry RVA
    put32(&mut f, o + 20, 0x1000); // BaseOfCode
    put64(&mut f, o + 24, 0x0001_4000_0000); // ImageBase
    put32(&mut f, o + 32, 0x1000); // SectionAlignment
    put32(&mut f, o + 36, 0x200); // FileAlignment
    put32(&mut f, o + 56, 0x2000); // SizeOfImage
    put32(&mut f, o + 60, 0x200); // SizeOfHeaders
    put16(&mut f, o + 68, 3); // console
    put64(&mut f, o + 72, 0x100000); // stack reserve
    put64(&mut f, o + 80, 0x1000); // stack commit
    put64(&mut f, o + 88, 0x100000); // heap reserve
    put32(&mut f, o + 108, 16); // RVA+Sizes
    let s = f.len();
    f.extend(vec![0u8; 40]);
    f[s..s + 5].copy_from_slice(b".text");
    put32(&mut f, s + 8, 3); // VirtualSize
    put32(&mut f, s + 12, 0x1000); // VirtualAddress
    put32(&mut f, s + 16, 0x200); // SizeOfRawData
    put32(&mut f, s + 20, 0x200); // PointerToRawData
    put32(&mut f, s + 36, 0x6000_0020); // CODE|EXECUTE|READ
    assert_eq!(f.len(), 0x1B0, "headers must end at 0x1B0");
    f.resize(0x200, 0);
    f.extend_from_slice(&[0x90, 0x90, 0xC3]);
    f.resize(0x400, 0);
    f
}

/// Minimal 64-bit Mach-O (x86-64): one `__TEXT` segment + `__text` section.
fn minimal_macho() -> Vec<u8> {
    let mut f = vec![0u8; 32];
    put32(&mut f, 0, 0xFEED_FACF);
    put32(&mut f, 4, 0x0100_0007); // x86-64
    put32(&mut f, 8, 3);
    put32(&mut f, 12, 2); // MH_EXECUTE
    put32(&mut f, 16, 1); // ncmds
    put32(&mut f, 20, 152); // sizeofcmds
    let c = f.len();
    f.extend(vec![0u8; 72]);
    put32(&mut f, c, 0x19); // LC_SEGMENT_64
    put32(&mut f, c + 4, 152);
    f[c + 8..c + 14].copy_from_slice(b"__TEXT");
    put64(&mut f, c + 24, 0x1000); // vmaddr
    put64(&mut f, c + 32, 0x1000); // vmsize
    put64(&mut f, c + 40, 0xB8); // fileoff
    put64(&mut f, c + 48, 4); // filesize
    put32(&mut f, c + 56, 5); // maxprot
    put32(&mut f, c + 60, 5); // initprot
    put32(&mut f, c + 64, 1); // nsects
    let s = f.len();
    f.extend(vec![0u8; 80]);
    f[s..s + 6].copy_from_slice(b"__text");
    f[s + 16..s + 22].copy_from_slice(b"__TEXT");
    put64(&mut f, s + 32, 0x1000); // addr
    put64(&mut f, s + 40, 4); // size
    put32(&mut f, s + 48, 0xB8); // offset
    put32(&mut f, s + 52, 2); // align
    put32(&mut f, s + 64, 0x8000_0400); // pure instructions
    assert_eq!(f.len(), 0xB8, "headers must end at 0xB8");
    f.extend_from_slice(&[0x90, 0x90, 0xC3, 0x90]);
    f
}

/// LC_MAIN Mach-O with a spec-correct file-offset entry: `__TEXT` maps at
/// VA `0x10000` from file offset `0xD0`, and `entryoff` is that file offset
/// (`object` 0.40 `entry()` returns it raw, so the loader must translate it
/// to the VA itself).
fn macho_lc_main() -> Vec<u8> {
    const ENTRY_VA: u64 = 0x10000;
    let seg_cmd = 72 + 80;
    let main_cmd = 24usize;
    let head_end = 32 + seg_cmd + main_cmd;
    assert_eq!(head_end, 0xD0, "entry file offset must differ from its VA");
    let mut f = vec![0u8; head_end];
    put32(&mut f, 0, 0xFEED_FACF);
    put32(&mut f, 4, 0x0100_0007); // x86-64
    put32(&mut f, 8, 3);
    put32(&mut f, 12, 2); // MH_EXECUTE
    put32(&mut f, 16, 2); // ncmds
    put32(&mut f, 20, (seg_cmd + main_cmd) as u32);
    let c = 32;
    put32(&mut f, c, 0x19); // LC_SEGMENT_64
    put32(&mut f, c + 4, seg_cmd as u32);
    f[c + 8..c + 14].copy_from_slice(b"__TEXT");
    put64(&mut f, c + 24, ENTRY_VA);
    put64(&mut f, c + 32, 0x1000);
    put64(&mut f, c + 40, head_end as u64);
    put64(&mut f, c + 48, 4);
    put32(&mut f, c + 56, 5);
    put32(&mut f, c + 60, 5);
    put32(&mut f, c + 64, 1);
    let s = c + 72;
    f[s..s + 6].copy_from_slice(b"__text");
    f[s + 16..s + 22].copy_from_slice(b"__TEXT");
    put64(&mut f, s + 32, ENTRY_VA);
    put64(&mut f, s + 40, 4);
    put32(&mut f, s + 48, head_end as u32);
    put32(&mut f, s + 52, 2);
    put32(&mut f, s + 64, 0x8000_0400);
    let c = 32 + seg_cmd;
    put32(&mut f, c, 0x8000_0028); // LC_MAIN
    put32(&mut f, c + 4, main_cmd as u32);
    put64(&mut f, c + 8, head_end as u64); // entryoff: file offset per spec
    put64(&mut f, c + 16, 0);
    f.extend_from_slice(&[0x90, 0x90, 0xC3, 0x90]);
    f
}

#[test]
fn elf_loads_segment_and_entry() {
    let bin = load(&minimal_elf()).expect("synthetic ELF must load");
    assert_eq!(bin.format, BinaryFormat::Elf);
    assert_eq!(bin.arch, Arch::X86_64);
    assert_eq!(bin.entry, Some(0x400000));
    assert_eq!(bin.segments.len(), 1);
    let seg = &bin.segments[0];
    assert_eq!(seg.vaddr, 0x400000);
    assert_eq!(seg.mem_size, 3);
    assert_eq!(seg.data, [0x90, 0x90, 0xC3]);
    assert!(seg.readable && seg.executable && !seg.writable);
    assert!(bin.imports.is_empty());
    assert!(bin.exports.is_empty());
    let insns = disasm_range(bin.arch, &seg.data, seg.vaddr, 100).expect("code must decode");
    assert_eq!(
        insns.iter().map(|i| i.mnem.as_str()).collect::<Vec<_>>(),
        ["nop", "nop", "ret"]
    );
}

#[test]
fn pe_loads_section_and_entry() {
    let bin = load(&minimal_pe()).expect("synthetic PE must load");
    assert_eq!(bin.format, BinaryFormat::Pe);
    assert_eq!(bin.arch, Arch::X86_64);
    assert_eq!(bin.entry, Some(0x0001_4000_1000));
    assert!(!bin.segments.is_empty());
    assert_eq!(bin.sections.len(), 1);
    assert_eq!(bin.sections[0].name, ".text");
    // PE addresses are flat VAs (ImageBase + RVA).
    assert_eq!(bin.sections[0].vaddr, 0x0001_4000_1000);
    assert_eq!(&bin.sections[0].data[..3], &[0x90, 0x90, 0xC3]);
    assert!(bin.sections[0].executable);
    assert!(bin.imports.is_empty());
    assert!(bin.exports.is_empty());
}

#[test]
fn macho_loads_segment_and_section() {
    let bin = load(&minimal_macho()).expect("synthetic Mach-O must load");
    assert_eq!(bin.format, BinaryFormat::MachO);
    assert_eq!(bin.arch, Arch::X86_64);
    assert_eq!(bin.entry, None);
    assert_eq!(bin.segments.len(), 1);
    assert_eq!(bin.segments[0].vaddr, 0x1000);
    assert_eq!(bin.sections.len(), 1);
    assert_eq!(bin.sections[0].name, "__text");
    assert_eq!(&bin.sections[0].data, &[0x90, 0x90, 0xC3, 0x90]);
}

#[test]
fn macho_lc_main_entryoff_translates_to_va() {
    // `entryoff` is file offset 0xD0, not VA 0x10000: the loader maps it
    // through `__TEXT` so the entry seeds real code.
    let bytes = macho_lc_main();
    let bin = load(&bytes).expect("LC_MAIN Mach-O must load");
    assert_eq!(bin.format, BinaryFormat::MachO);
    assert_eq!(bin.arch, Arch::X86_64);
    assert_eq!(bin.entry, Some(0x10000));

    // End to end: the project opens with the VA entry, and analysis seeds
    // a function there (a raw file offset would miss every segment).
    let dir = common::tmpdir("macho-lc-main");
    let path = common::write_bin(&dir, "lc-main-macho", &bytes);
    let db = common::temp_db(&dir, "lc-main-macho");
    let p = binscout::Project::open_with_db(&path, &db).expect("LC_MAIN image must open");
    assert_eq!(p.binary().entry, Some(0x10000));
    assert!(p.analysis().functions.contains_key(&0x10000));
    common::cleanup(&dir);
}

#[test]
fn coff_loads_section_at_zero_with_no_entry() {
    let bytes = common::fixture_bytes(builders::COFF_NAME);
    let bin = load(&bytes).expect("synthetic COFF must load");
    assert_eq!(bin.format, BinaryFormat::Coff);
    assert_eq!(bin.arch, Arch::X86_64);
    // Relocatable objects link at address 0 and carry no entry point.
    assert_eq!(bin.entry, None);
    assert_eq!(bin.segments.len(), 1);
    let seg = &bin.segments[0];
    assert_eq!(seg.vaddr, 0);
    assert_eq!(seg.mem_size, 3);
    assert_eq!(seg.data, [0x90, 0x90, 0xC3]);
    assert!(seg.readable && seg.executable && !seg.writable);
    assert_eq!(bin.sections.len(), 1);
    assert_eq!(bin.sections[0].name, ".text");
    assert_eq!(bin.sections[0].vaddr, 0);
    assert_eq!(&bin.sections[0].data, &[0x90, 0x90, 0xC3]);
    assert!(bin.sections[0].executable);
    // `object` exposes no COFF import/export tables.
    assert!(bin.imports.is_empty());
    assert!(bin.exports.is_empty());
    let insns = disasm_range(bin.arch, &seg.data, seg.vaddr, 100).expect("code must decode");
    assert_eq!(
        insns.iter().map(|i| i.mnem.as_str()).collect::<Vec<_>>(),
        ["nop", "nop", "ret"]
    );
}

#[test]
fn coff_i386_maps_to_x86_32() {
    // Same headers with an I386 machine id: parses to the x86_32 target.
    let mut bytes = common::fixture_bytes(builders::COFF_NAME);
    put16(&mut bytes, 0, 0x14C);
    let bin = load(&bytes).expect("i386 COFF must load");
    assert_eq!(bin.format, BinaryFormat::Coff);
    assert_eq!(bin.arch, Arch::X86_32);
}

#[test]
fn coff_unsupported_arch_errors_without_raw_fallback() {
    // PowerPC COFF: recognized container, but no disassembler.
    let mut bytes = common::fixture_bytes(builders::COFF_NAME);
    put16(&mut bytes, 0, 0x1F0);
    assert!(binscout::loader::is_recognized(&bytes));
    let err = load(&bytes).unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
}

#[test]
fn coff_truncated_stays_invalid_at_project_level() {
    // COFF magic intact but headers cut: recognized, so `load_or_raw`
    // must report the parse error instead of raw fallback, and the
    // failed open must not create a sidecar.
    let dir = common::tmpdir("coff-truncated");
    let mut bytes = common::fixture_bytes(builders::COFF_NAME);
    bytes.truncate(30);
    assert!(binscout::loader::is_recognized(&bytes));
    let err = load(&bytes).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "truncated COFF must be invalid, got {err:?}"
    );
    let bin = common::write_bin(&dir, "truncated.obj", &bytes);
    let db = common::temp_db(&dir, "truncated");
    let err = binscout::Project::open_with_db(&bin, &db).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "recognized-but-malformed COFF must stay invalid, never raw fallback: got {err:?}"
    );
    assert!(!db.exists(), "failed open must not create a sidecar");
    common::cleanup(&dir);
}

#[test]
fn coff_opens_end_to_end_with_project() {
    // Full open path: section maps, analysis runs, format surfaces.
    let dir = common::tmpdir("coff-e2e");
    let p = common::open_test_project(&dir, builders::COFF_NAME);
    assert_eq!(p.binary().format, BinaryFormat::Coff);
    assert_eq!(p.binary().arch, Arch::X86_64);
    assert_eq!(p.project_info().format, "coff");
    common::cleanup(&dir);
}

#[test]
fn raw_mode_maps_single_segment_with_base_and_entry() {
    let raw = include_bytes!("fixtures/raw-x64.bin");
    let bin = load_raw(
        raw,
        RawOptions {
            base: 0x1000,
            arch: Arch::X86_64,
            entry: Some(0x1000),
        },
    )
    .expect("raw fixture must load");
    assert_eq!(bin.format, BinaryFormat::Raw);
    assert_eq!(bin.arch, Arch::X86_64);
    assert_eq!(bin.entry, Some(0x1000));
    assert_eq!(bin.segments.len(), 1);
    assert_eq!(bin.segments[0].vaddr, 0x1000);
    assert_eq!(bin.segments[0].data, *raw);
    assert!(bin.sections.is_empty());
    let insns =
        disasm_range(bin.arch, &bin.segments[0].data, 0x1000, 100).expect("raw must decode");
    assert_eq!(
        insns.iter().map(|i| i.mnem.as_str()).collect::<Vec<_>>(),
        ["nop", "nop", "ret"]
    );
}

#[test]
fn strings_extract_ascii_utf16_and_paginate() {
    // "hello" ASCII, "ABCD" LE (exactly min_len so the shifted BE ghost
    // "BCD" stays under it), then "s000".."s009". The LE run also carries
    // a shifted BMP-letter twin at the odd offset, like the documented
    // shifted BE twin.
    let mut bytes = b"\x00hello\x00\xFF".to_vec();
    bytes.extend_from_slice(&[0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00, 0xFF]);
    for i in 0..10 {
        bytes.extend_from_slice(format!("s{i:03}\x00").as_bytes());
    }
    let hits = extract(&bytes, 4, 10_000, None);
    assert_eq!(hits.len(), 13);
    assert_eq!(hits[0].value, "hello");
    assert_eq!(hits[0].encoding, Encoding::Ascii);
    assert_eq!(hits[1].value, "䇿䈀䌀䐀");
    assert_eq!(hits[1].encoding, Encoding::Utf16LeBmp);
    assert_eq!(hits[1].offset, 7);
    assert_eq!(hits[2].value, "ABCD");
    assert_eq!(hits[2].encoding, Encoding::Utf16Le);
    assert!(
        hits.iter().all(|h| h.encoding != Encoding::Utf16Be),
        "no BE ghosts expected at min_len"
    );
    assert!(hits.windows(2).all(|w| w[0].offset <= w[1].offset));

    // BE runs inherently contain a shifted LE twin; assert presence.
    let be_bytes = [0xFF, 0x00, 0x45, 0x00, 0x46, 0x00, 0x47, 0x00, 0x48, 0xFF];
    let be_hits = extract(&be_bytes, 4, 100, Some(0x2000));
    let be = be_hits
        .iter()
        .find(|h| h.encoding == Encoding::Utf16Be)
        .expect("BE hit");
    assert_eq!(be.value, "EFGH");
    assert_eq!(be.offset, 1);
    assert_eq!(be.vaddr, Some(0x2001));

    let page = extract_page(&bytes, 4, 10_000, None, 0, 3);
    assert_eq!(page, hits[..3]);

    let past_end = extract_page(&bytes, 4, 10_000, None, hits.len() + 5, 5);
    assert!(past_end.is_empty());

    let capped = extract(&bytes, 4, 2, None);
    assert_eq!(capped, hits[..2]);
}

#[test]
fn short_runs_excluded() {
    let hits = extract(b"\x00ab\x00abc\x00abcd\x00", 4, 100, None);
    // Short ASCII runs stay excluded; the NUL-separated letters also
    // chain into one shifted BMP-letter reading (same artifact class as
    // the shifted BE twin), pinned here so it cannot drift silently.
    // (The run starts at offset 3: the lone unit at offset 0 advances
    // the cursor past the offset-1 start, exactly like rejected short
    // runs in the classic passes.)
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].value, "愀换愀换");
    assert_eq!(hits[0].encoding, Encoding::Utf16LeBmp);
    assert_eq!(hits[0].offset, 3);
    assert_eq!(hits[1].value, "abcd");
    assert_eq!(hits[1].encoding, Encoding::Ascii);
}

#[test]
fn unsupported_arch_errors() {
    // Valid ELF headers with a MIPS machine id: parses, but has no disassembler.
    let mut elf = minimal_elf();
    put16(&mut elf, 18, 8);
    let err = load(&elf).unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
}

#[test]
fn arm_elf_maps_to_arm32() {
    // Same headers with an ARM machine id: parses to the ARM32 target.
    let mut elf = minimal_elf();
    put16(&mut elf, 18, 40);
    let bin = load(&elf).expect("arm ELF must load");
    assert_eq!(bin.format, BinaryFormat::Elf);
    assert_eq!(bin.arch, Arch::Arm32);
}

#[test]
fn pe32_ordinals_carry_unresolved_and_demangled() {
    // L3/A8: ordinal-only imports resolve-or-`unresolved:true`, C++ names
    // carry `demangled` alongside the raw mangling.
    let bytes = common::fixture_bytes(builders::ORDINALS_NAME);
    let bin = load(&bytes).expect("ordinals PE32 must load");
    assert_eq!(bin.format, BinaryFormat::Pe);

    let ordinals: Vec<_> = bin.imports.iter().filter(|i| i.ordinal.is_some()).collect();
    assert!(
        ordinals.len() >= 2,
        "2+ ordinal rows expected: {:?}",
        bin.imports
    );
    for imp in &ordinals {
        assert!(imp.unresolved, "ordinal import must be unresolved: {imp:?}");
        assert!(imp.demangled.is_none(), "ordinals never demangle: {imp:?}");
        assert_eq!(imp.library, builders::ORDINALS_DLL);
    }
    let names: Vec<&str> = ordinals.iter().map(|i| i.name.as_str()).collect();
    for ord in builders::ORDINALS_ORDINALS {
        assert!(
            names.contains(&format!("#{ord}").as_str()),
            "ordinal #{ord} missing: {names:?}"
        );
    }

    let mangled = bin
        .imports
        .iter()
        .find(|i| i.name == builders::ORDINALS_MANGLED)
        .expect("mangled import present");
    assert!(!mangled.unresolved, "named import resolves: {mangled:?}");
    assert_eq!(mangled.ordinal, None);
    let demangled = mangled.demangled.as_ref().expect("C++ demangled");
    assert!(
        demangled.contains("myfunc"),
        "demangled names myfunc: {demangled:?}"
    );

    // `symbols_json` surfaces the same rows agents see via CLI/MCP.
    let dir = common::tmpdir("l3-symbols");
    let p = common::open_test_project(&dir, builders::ORDINALS_NAME);
    let symbols = p.symbols_json();
    let imports = symbols["imports"].as_array().expect("imports array");
    assert_eq!(imports.len(), bin.imports.len());
    let unresolved = imports
        .iter()
        .filter(|r| r["unresolved"].as_bool().unwrap_or(false))
        .count();
    assert!(unresolved >= 2, "2+ unresolved rows: {imports:?}");
    assert!(
        imports.iter().any(|r| r["demangled"]
            .as_str()
            .is_some_and(|d| d.contains("myfunc"))),
        "one demangled C++ row: {imports:?}"
    );
    common::cleanup(&dir);
}

#[test]
fn le_zero_module_and_object_do_not_panic() {
    use binscout::loader::Segment;
    use binscout::loader::convert_le;
    use binscout::loader::le::{LeEntry, LeFixup, LeImage, LeObject, LeTarget};

    let img = LeImage {
        page_size: 0x1000,
        cpu: 2,
        os: 3,
        module_flags: 0,
        objects: vec![LeObject {
            index: 1,
            virtual_size: 0x1000,
            reloc_base: 0x10000,
            flags: 0x2005,
            readable: true,
            writable: false,
            executable: true,
        }],
        segments: vec![Segment {
            vaddr: 0x10000,
            mem_size: 0x1000,
            data: vec![0x90],
            readable: true,
            writable: false,
            executable: true,
        }],
        entry: Some(0x10000),
        fixups: vec![LeFixup {
            page: 1,
            sources: vec![0],
            target: LeTarget::ImportOrdinal {
                module: 0,
                ordinal: 7,
            },
            additive: None,
        }],
        entries: vec![
            LeEntry {
                ordinal: 1,
                object: 0,
                offset: 0,
                exported: true,
            },
            LeEntry {
                ordinal: 2,
                object: 9,
                offset: 0,
                exported: true,
            },
        ],
        import_modules: vec!["KERNEL".to_string()],
        import_procs: Vec::new(),
    };
    let bin = convert_le(img);
    assert_eq!(bin.imports.len(), 1);
    assert_eq!(bin.imports[0].library, "mod#0");
    assert!(bin.exports.is_empty());
}
