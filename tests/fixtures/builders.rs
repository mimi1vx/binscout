//! Synthetic fixture builders (F0): deterministic PE32/LE/garbage blobs.
//!
//! Every builder is pure `Vec<u8>` manipulation with fixed timestamps and no
//! randomness, so repeated calls return byte-identical output. The generated
//! blobs under `tests/fixtures/` are checked in for manual inspection; the
//! `fixture_blobs_byte_identical` test in `tests/scaffold.rs` asserts they
//! match builder output. Regenerate with
//! `FIXTURE_REGEN=1 cargo test --test scaffold`.
//!
//! Layout (both PE32 fixtures, `IMAGE_BASE = 0x400000`):
//! `.text` at RVA `0x1000` (VA `0x401000`), `.rdata` at `0x2000`
//! (VA `0x402000`), `.data` at `0x3000` (VA `0x403000`); headers pad to file
//! offset `0x200`, each section holds `0x200` raw bytes.

/// Name of the basic PE32 fixture: code + export + string refs.
pub const BASIC_NAME: &str = "pe32-basic.exe";
/// Name of the ordinals PE32 fixture: ordinal + mangled imports.
pub const ORDINALS_NAME: &str = "pe32-ordinals.exe";
/// Name of the minimal LE fixture (one R-X object, analyzed as x86_32).
pub const LE_NAME: &str = "le-minimal.exe";
/// Name of the minimal COFF fixture (AMD64 relocatable object, one `.text`).
pub const COFF_NAME: &str = "coff-minimal.obj";
/// Name of the raw garbage fixture (`.text`-noise + invalid opcode).
pub const GARBAGE_NAME: &str = "text-garbage.bin";

/// All fixture names in build order.
pub const FIXTURE_NAMES: [&str; 5] = [BASIC_NAME, ORDINALS_NAME, LE_NAME, COFF_NAME, GARBAGE_NAME];

/// PE image base both PE32 fixtures link at.
pub const IMAGE_BASE: u64 = 0x400_000;
/// RVA of `.text`.
pub const TEXT_RVA: u32 = 0x1000;
/// RVA of `.rdata`.
pub const RDATA_RVA: u32 = 0x2000;
/// RVA of `.data`.
pub const DATA_RVA: u32 = 0x3000;
/// Virtual address of `.text` (`IMAGE_BASE + TEXT_RVA`).
pub const TEXT_VA: u64 = IMAGE_BASE + TEXT_RVA as u64;
/// Virtual address of `.rdata`.
pub const RDATA_VA: u64 = IMAGE_BASE + RDATA_RVA as u64;
/// Virtual address of `.data`.
pub const DATA_VA: u64 = IMAGE_BASE + DATA_RVA as u64;

/// Fixed PE timestamp so builds are deterministic.
pub const TIMESTAMP: u32 = 0x1234_5678;

/// Marker string in `pe32-basic.exe` `.rdata`, referenced twice from `.text`.
pub const BASIC_STRING: &str = "SAVE%d.GAM is invalid";
/// File offset of [`BASIC_STRING`] within `.rdata`.
pub const BASIC_STRING_RDATA_OFF: usize = 0x100;
/// Virtual address of [`BASIC_STRING`].
pub const BASIC_STRING_VA: u64 = RDATA_VA + BASIC_STRING_RDATA_OFF as u64;
/// Entry-point VA of `pe32-basic.exe` (also its single export target).
pub const BASIC_ENTRY_VA: u64 = TEXT_VA;
/// DLL name reported by the basic fixture's export directory.
pub const BASIC_DLL: &str = "basic.dll";
/// The single export of `pe32-basic.exe`.
pub const BASIC_EXPORT: &str = "basic_entry";
/// Writable `.data` marker present in both PE32 fixtures.
pub const DATA_MARKER: &str = "DATA_FIXTURE_SEED";

/// Import library of the ordinals fixture.
pub const ORDINALS_DLL: &str = "TESTDLL.dll";
/// Ordinal-only imports of the ordinals fixture.
pub const ORDINALS_ORDINALS: [u16; 2] = [1, 2];
/// C++ mangled import of the ordinals fixture (`void __cdecl myfunc(int)`).
pub const ORDINALS_MANGLED: &str = "?myfunc@@YAXH@Z";
/// Entry-point VA of the ordinals fixture.
pub const ORDINALS_ENTRY_VA: u64 = TEXT_VA;

/// ASCII noise run embedded in [`GARBAGE_NAME`].
pub const GARBAGE_STR1: &str = "VWf3";
/// Second ASCII noise run embedded in [`GARBAGE_NAME`].
pub const GARBAGE_STR2: &str = "D$ f";

/// Build one fixture from scratch; panics on unknown names.
#[must_use]
pub fn build(name: &str) -> Vec<u8> {
    match name {
        BASIC_NAME => pe32_basic(),
        ORDINALS_NAME => pe32_ordinals(),
        LE_NAME => le_minimal(),
        COFF_NAME => coff_minimal(),
        GARBAGE_NAME => text_garbage(),
        _ => panic!("unknown fixture {name:?}; known: {FIXTURE_NAMES:?}"),
    }
}

/// Build all fixtures as `(name, bytes)` pairs.
#[must_use]
pub fn build_all() -> Vec<(&'static str, Vec<u8>)> {
    FIXTURE_NAMES.map(|n| (n, build(n))).to_vec()
}

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

const FILE_ALIGN: u32 = 0x200;
const SEC_RAW: usize = 0x200;
const HEADERS_SIZE: usize = 0x200;
const TEXT_FILE_OFF: usize = HEADERS_SIZE;
const RDATA_FILE_OFF: usize = HEADERS_SIZE + SEC_RAW;
const DATA_FILE_OFF: usize = HEADERS_SIZE + 2 * SEC_RAW;

/// Minimal PE32 headers: DOS + `PE\0\0` + COFF(I386) + PE32 optional header
/// with export/import data directories, then three section headers.
fn pe_headers(
    entry_rva: u32,
    export_rva: u32,
    export_size: u32,
    import_rva: u32,
    import_size: u32,
) -> Vec<u8> {
    let mut f = vec![0u8; HEADERS_SIZE];
    f[0] = b'M';
    f[1] = b'Z';
    put32(&mut f, 0x3C, 0x80); // e_lfanew
    f[0x80..0x84].copy_from_slice(b"PE\0\0");
    let c = 0x84;
    put16(&mut f, c, 0x14C); // I386
    put16(&mut f, c + 2, 3); // sections
    put32(&mut f, c + 4, TIMESTAMP);
    put16(&mut f, c + 16, 0xE0); // optional size
    put16(&mut f, c + 18, 0x010F); // EXECUTABLE_IMAGE|32BIT_MACHINE
    let o = 0x98;
    put16(&mut f, o, 0x10B); // PE32
    f[o + 2] = 1; // linker version
    put32(&mut f, o + 4, 0x200); // SizeOfCode
    put32(&mut f, o + 8, 0x400); // SizeOfInitializedData
    put32(&mut f, o + 16, entry_rva);
    put32(&mut f, o + 20, TEXT_RVA); // BaseOfCode
    put32(&mut f, o + 24, RDATA_RVA); // BaseOfData
    put32(&mut f, o + 28, IMAGE_BASE as u32);
    put32(&mut f, o + 32, 0x1000); // SectionAlignment
    put32(&mut f, o + 36, FILE_ALIGN);
    put16(&mut f, o + 40, 4); // OS version
    put16(&mut f, o + 48, 4); // subsystem version
    put32(&mut f, o + 56, 0x4000); // SizeOfImage
    put32(&mut f, o + 60, HEADERS_SIZE as u32);
    put16(&mut f, o + 68, 3); // console
    put32(&mut f, o + 72, 0x100_000); // stack reserve
    put32(&mut f, o + 76, 0x1000); // stack commit
    put32(&mut f, o + 80, 0x100_000); // heap reserve
    put32(&mut f, o + 84, 0x1000); // heap commit
    put32(&mut f, o + 92, 16); // RVA+Sizes
    put32(&mut f, o + 96, export_rva);
    put32(&mut f, o + 100, export_size);
    put32(&mut f, o + 104, import_rva);
    put32(&mut f, o + 108, import_size);
    section_header(
        &mut f,
        0x178,
        b".text",
        TEXT_RVA,
        TEXT_FILE_OFF,
        0x6000_0020,
    );
    section_header(
        &mut f,
        0x178 + 40,
        b".rdata",
        RDATA_RVA,
        RDATA_FILE_OFF,
        0x4000_0040,
    );
    section_header(
        &mut f,
        0x178 + 80,
        b".data",
        DATA_RVA,
        DATA_FILE_OFF,
        0xC000_0040,
    );
    f
}

fn section_header(f: &mut [u8], off: usize, name: &[u8], rva: u32, file_off: usize, chars: u32) {
    f[off..off + name.len()].copy_from_slice(name);
    put32(f, off + 8, SEC_RAW as u32); // VirtualSize covers the raw bytes
    put32(f, off + 12, rva);
    put32(f, off + 16, SEC_RAW as u32);
    put32(f, off + 20, file_off as u32);
    put32(f, off + 36, chars);
}

/// `.text` for [`BASIC_NAME`]: frame setup, two `push imm32` of
/// [`BASIC_STRING_VA`], `ret`.
fn basic_text() -> Vec<u8> {
    let mut code = vec![0x55, 0x89, 0xE5]; // push ebp; mov ebp, esp
    for _ in 0..2 {
        code.push(0x68); // push imm32
        code.extend_from_slice(&(BASIC_STRING_VA as u32).to_le_bytes());
    }
    code.push(0xC3); // ret
    code.resize(SEC_RAW, 0);
    code
}

/// `.rdata` for [`BASIC_NAME`]: one export directory for [`BASIC_EXPORT`]
/// plus [`BASIC_STRING`] at [`BASIC_STRING_RDATA_OFF`].
fn basic_rdata() -> Vec<u8> {
    let mut r = vec![0u8; SEC_RAW];
    let dll_off = 0x34;
    let name_off = 0x3E;
    put32(&mut r, 0x04, TIMESTAMP);
    put32(&mut r, 0x0C, RDATA_RVA + dll_off as u32); // Name
    put32(&mut r, 0x10, 1); // Base
    put32(&mut r, 0x14, 1); // NumberOfFunctions
    put32(&mut r, 0x18, 1); // NumberOfNames
    put32(&mut r, 0x1C, RDATA_RVA + 0x28); // AddressOfFunctions
    put32(&mut r, 0x20, RDATA_RVA + 0x2C); // AddressOfNames
    put32(&mut r, 0x24, RDATA_RVA + 0x30); // AddressOfNameOrdinals
    put32(&mut r, 0x28, TEXT_RVA); // function[0] = entry RVA
    put32(&mut r, 0x2C, RDATA_RVA + name_off as u32); // names[0]
    put16(&mut r, 0x30, 0); // ordinals[0]
    r[dll_off..dll_off + BASIC_DLL.len()].copy_from_slice(BASIC_DLL.as_bytes());
    r[name_off..name_off + BASIC_EXPORT.len()].copy_from_slice(BASIC_EXPORT.as_bytes());
    let s = BASIC_STRING_RDATA_OFF;
    r[s..s + BASIC_STRING.len()].copy_from_slice(BASIC_STRING.as_bytes());
    r
}

/// `.text` for [`ORDINALS_NAME`]: frame setup + `ret`.
fn ordinals_text() -> Vec<u8> {
    let mut code = vec![0x55, 0x89, 0xE5, 0xC3]; // push ebp; mov ebp,esp; ret
    code.resize(SEC_RAW, 0);
    code
}

/// `.rdata` for [`ORDINALS_NAME`]: one import descriptor for [`ORDINALS_DLL`]
/// with two ordinal entries plus one [`ORDINALS_MANGLED`] Hint/Name.
fn ordinals_rdata() -> Vec<u8> {
    let mut r = vec![0u8; SEC_RAW];
    let ilt_off = 0x28;
    let iat_off = 0x38;
    let hint_off = 0x48;
    let dll_off = 0x5C;
    // Import descriptor + null terminator.
    put32(&mut r, 0x00, RDATA_RVA + ilt_off as u32); // OriginalFirstThunk
    put32(&mut r, 0x0C, RDATA_RVA + dll_off as u32); // Name
    put32(&mut r, 0x10, RDATA_RVA + iat_off as u32); // FirstThunk
                                                     // ILT/IAT: two ordinals, one named, null.
    for (i, ord) in ORDINALS_ORDINALS.iter().enumerate() {
        let e = 0x8000_0000 | u32::from(*ord);
        put32(&mut r, ilt_off + 4 * i, e);
        put32(&mut r, iat_off + 4 * i, e);
    }
    let named = RDATA_RVA + hint_off as u32;
    put32(&mut r, ilt_off + 8, named);
    put32(&mut r, iat_off + 8, named);
    // Hint/Name: hint 0 + NUL-terminated mangled name.
    put16(&mut r, hint_off, 0);
    r[hint_off + 2..hint_off + 2 + ORDINALS_MANGLED.len()]
        .copy_from_slice(ORDINALS_MANGLED.as_bytes());
    r[dll_off..dll_off + ORDINALS_DLL.len()].copy_from_slice(ORDINALS_DLL.as_bytes());
    r
}

/// `.data` shared by both PE32 fixtures: [`DATA_MARKER`] then zeros.
fn data_section() -> Vec<u8> {
    let mut d = vec![0u8; SEC_RAW];
    d[..DATA_MARKER.len()].copy_from_slice(DATA_MARKER.as_bytes());
    d
}

/// `pe32-basic.exe`: entry func with two string pushes, one export.
#[must_use]
pub fn pe32_basic() -> Vec<u8> {
    // Export size covers the directory plus its address/name/ordinal tables
    // and both name strings (`object` clamps export reads to this size).
    let mut f = pe_headers(TEXT_RVA, RDATA_RVA, 0x4A, 0, 0);
    f.extend_from_slice(&basic_text());
    f.extend_from_slice(&basic_rdata());
    f.extend_from_slice(&data_section());
    f
}

/// `pe32-ordinals.exe`: ordinal + mangled imports, no exports.
#[must_use]
pub fn pe32_ordinals() -> Vec<u8> {
    let mut f = pe_headers(TEXT_RVA, 0, 0, RDATA_RVA, 40);
    f.extend_from_slice(&ordinals_text());
    f.extend_from_slice(&ordinals_rdata());
    f.extend_from_slice(&data_section());
    f
}

const LE_OFF: usize = 0x40;
const LE_CODE: [u8; 4] = [0x55, 0x89, 0xE5, 0xC3]; // push ebp; mov ebp,esp; ret

/// `le-minimal.exe`: minimal MZ->LE image mirroring the `loader_le` test
/// harness (one R-X object, default entry bundle, no fixups).
#[must_use]
pub fn le_minimal() -> Vec<u8> {
    let entry: Vec<u8> = vec![0x01, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
    let obj_rel = 0xAC;
    let page_rel = obj_rel + 24;
    let fp_rel = page_rel + 8;
    let fr_rel = fp_rel + 8;
    let entry_rel = fr_rel;
    let code_rel = entry_rel + entry.len();

    let mut f = vec![0u8; LE_OFF];
    f[0] = b'M';
    f[1] = b'Z';
    put32(&mut f, 0x3C, LE_OFF as u32);
    f.resize(LE_OFF + code_rel + LE_CODE.len(), 0);
    let h = LE_OFF;
    f[h] = b'L';
    f[h + 1] = b'E';
    put16(&mut f, h + 0x08, 2); // cpu 386
    put16(&mut f, h + 0x0A, 3); // os DOS4
    put32(&mut f, h + 0x14, 1); // pages
    put32(&mut f, h + 0x18, 1); // eip object
    put32(&mut f, h + 0x1C, 0); // eip
    put32(&mut f, h + 0x20, 1); // esp object
    put32(&mut f, h + 0x24, 0x1000); // esp
    put32(&mut f, h + 0x28, 0x1000); // page size
    put32(&mut f, h + 0x30, 8); // fixup size
    put32(&mut f, h + 0x38, (code_rel - obj_rel) as u32); // loader size
    put32(&mut f, h + 0x40, obj_rel as u32);
    put32(&mut f, h + 0x44, 1);
    put32(&mut f, h + 0x48, page_rel as u32);
    put32(&mut f, h + 0x5C, entry_rel as u32);
    put32(&mut f, h + 0x68, fp_rel as u32);
    put32(&mut f, h + 0x6C, fr_rel as u32);
    put32(&mut f, h + 0x80, code_rel as u32); // data pages (header-relative)
    put32(&mut f, h + 0x84, 1);

    let p = LE_OFF + obj_rel;
    put32(&mut f, p, 0x1000); // virt size
    put32(&mut f, p + 4, 0x10000); // reloc base
    put32(&mut f, p + 8, 0x2005); // R-X + big
    put32(&mut f, p + 12, 1); // page index
    put32(&mut f, p + 16, 1); // page count

    let p = LE_OFF + page_rel;
    put16(&mut f, p + 4, LE_CODE.len() as u16);
    f[LE_OFF + entry_rel..LE_OFF + entry_rel + entry.len()].copy_from_slice(&entry);
    f[LE_OFF + code_rel..].copy_from_slice(&LE_CODE);
    f
}

/// `coff-minimal.obj`: AMD64 relocatable object with one `.text`
/// (`nop; nop; ret`) and no symbol table. Relocatable sections link at
/// address 0, so the segment and the section both map at VA 0 and the
/// entry point is `None`; imports/exports are empty (`object` exposes no
/// COFF import/export tables).
#[must_use]
pub fn coff_minimal() -> Vec<u8> {
    let mut f = vec![0u8; 60];
    put16(&mut f, 0, 0x8664); // AMD64
    put16(&mut f, 2, 1); // one section
    put32(&mut f, 4, TIMESTAMP);
    // PointerToSymbolTable + NumberOfSymbols stay 0 (no symbols);
    // SizeOfOptionalHeader stays 0 (object file, no optional header).
    f[20..28].copy_from_slice(b".text\0\0\0");
    put32(&mut f, 28, 3); // VirtualSize
    put32(&mut f, 32, 0); // VirtualAddress (relocatable: links at 0)
    put32(&mut f, 36, 3); // SizeOfRawData
    put32(&mut f, 40, 60); // PointerToRawData
    put32(&mut f, 56, 0x6000_0020); // CNT_CODE|EXECUTE|READ
    f.extend_from_slice(&[0x90, 0x90, 0xC3]);
    f
}

/// `text-garbage.bin`: valid x86-64 prologue, an invalid opcode (`0xD6`
/// SALC is invalid in 64-bit mode) as the D2 decoder stop, [`GARBAGE_STR1`]
/// and [`GARBAGE_STR2`] noise runs, then trailing nops+ret.
#[must_use]
pub fn text_garbage() -> Vec<u8> {
    let mut b = vec![0x55, 0x48, 0x89, 0xE5]; // push rbp; mov rbp,rsp
    b.push(0xD6); // invalid in 64-bit: decoder stop for D2
    b.extend_from_slice(GARBAGE_STR1.as_bytes()); // VWf3
    b.push(0x00); // separator so the noise runs stay distinct hits
    b.extend_from_slice(GARBAGE_STR2.as_bytes()); // D$ f
    b.extend_from_slice(&[0x90, 0x90, 0xC3]);
    b
}
