//! Import call sites: PE IAT slots and ELF GOT slots resolve to
//! `ImportRef.address`, with `import`-kind xrefs from callers and import
//! names on instruction and pseudo rows.

mod common;

use std::process::Command;

use binscout::analysis::{DiagnosticKind, XrefKind, analyze};
use binscout::disasm::Arch;
use binscout::loader::{BinaryFormat, ImportRef, LoadedBinary, Segment, load};
use binscout::{Project, parse_xref_kind};

use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn put64(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

const PE64_BASE: u64 = 0x140_000_000;
const PE64_TEXT_RVA: u32 = 0x1000;
const PE64_RDATA_RVA: u32 = 0x2000;
const PE64_SLOT_RVA: u32 = PE64_RDATA_RVA + 0x38;
const PE64_SLOT: u64 = PE64_BASE + PE64_SLOT_RVA as u64;
const PE64_ENTRY: u64 = PE64_BASE + PE64_TEXT_RVA as u64;

/// Minimal PE32+ (x86-64) with one import (`test64.dll!foo`) called via
/// `call [rip+slot]` from the entry point.
fn pe64_with_iat_call() -> Vec<u8> {
    let mut f = vec![0u8; 0x200];
    f[0] = b'M';
    f[1] = b'Z';
    put32(&mut f, 0x3C, 0x80);
    f[0x80..0x84].copy_from_slice(b"PE\0\0");
    let c = 0x84;
    put16(&mut f, c, 0x8664); // AMD64
    put16(&mut f, c + 2, 2); // sections
    put32(&mut f, c + 4, 0x1234_5678);
    put16(&mut f, c + 16, 0xF0); // optional size
    put16(&mut f, c + 18, 0x22); // EXECUTABLE_IMAGE|LARGE_ADDRESS_AWARE
    let o = 0x98;
    put16(&mut f, o, 0x20B); // PE32+
    put32(&mut f, o + 16, PE64_TEXT_RVA); // entry
    put32(&mut f, o + 20, PE64_TEXT_RVA); // BaseOfCode
    put64(&mut f, o + 24, PE64_BASE);
    put32(&mut f, o + 32, 0x1000);
    put32(&mut f, o + 36, 0x200);
    put32(&mut f, o + 60, 0x200); // SizeOfHeaders
    put32(&mut f, o + 108, 16); // RVA+Sizes
    put32(&mut f, o + 120, PE64_RDATA_RVA); // import dir RVA
    put32(&mut f, o + 124, 40); // import dir size
    let s = 0x188;
    f[s..s + 5].copy_from_slice(b".text");
    put32(&mut f, s + 8, 0x200);
    put32(&mut f, s + 12, PE64_TEXT_RVA);
    put32(&mut f, s + 16, 0x200);
    put32(&mut f, s + 20, 0x200);
    put32(&mut f, s + 36, 0x6000_0020);
    let s = 0x188 + 40;
    f[s..s + 6].copy_from_slice(b".rdata");
    put32(&mut f, s + 8, 0x200);
    put32(&mut f, s + 12, PE64_RDATA_RVA);
    put32(&mut f, s + 16, 0x200);
    put32(&mut f, s + 20, 0x400);
    put32(&mut f, s + 36, 0x4000_0040);

    let mut text = vec![0u8; 0x200];
    let next_ip = PE64_ENTRY + 6;
    let disp = PE64_SLOT.wrapping_sub(next_ip) as u32;
    text[0] = 0xFF;
    text[1] = 0x15; // call [rip+disp]
    text[2..6].copy_from_slice(&disp.to_le_bytes());
    text[6] = 0xC3; // ret

    let mut r = vec![0u8; 0x200];
    put32(&mut r, 0x00, PE64_RDATA_RVA + 0x28); // OriginalFirstThunk
    put32(&mut r, 0x0C, PE64_RDATA_RVA + 0x60); // Name
    put32(&mut r, 0x10, PE64_SLOT_RVA); // FirstThunk
    put64(&mut r, 0x28, (PE64_RDATA_RVA + 0x48) as u64); // ILT
    put64(&mut r, 0x30, 0);
    put64(&mut r, 0x38, (PE64_RDATA_RVA + 0x48) as u64); // IAT
    put64(&mut r, 0x40, 0);
    put16(&mut r, 0x48, 0); // hint
    r[0x4A..0x4E].copy_from_slice(b"foo\0");
    r[0x60..0x6B].copy_from_slice(b"test64.dll\0");

    f.extend_from_slice(&text);
    f.extend_from_slice(&r);
    f
}

const ELF_TEXT_VA: u64 = 0x4000B0;
const ELF_STUB_VA: u64 = 0x4000B6;
const ELF_GOT: u64 = 0x401000;

/// Minimal ELF64 (x86-64) with one import (`foo`): the entry calls a PLT
/// stub that jumps through its GOT slot. The second `.rela.plt` entry is
/// a non-`JUMP_SLOT` type and must not map.
fn elf64_with_plt() -> Vec<u8> {
    let mut f = vec![0u8; 0xB0];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2; // 64-bit
    f[5] = 1; // LE
    f[6] = 1; // version
    put16(&mut f, 16, 2); // EXEC
    put16(&mut f, 18, 62); // x86-64
    put32(&mut f, 20, 1);
    put64(&mut f, 24, ELF_TEXT_VA); // entry
    put64(&mut f, 32, 64); // phoff
    put16(&mut f, 52, 64);
    put16(&mut f, 54, 56);
    put16(&mut f, 56, 2);
    put16(&mut f, 58, 64);
    // phdrs: R+E file range, RW GOT range.
    let p = 64;
    put32(&mut f, p, 1);
    put32(&mut f, p + 4, 5);
    put64(&mut f, p + 8, 0);
    put64(&mut f, p + 16, 0x400000);
    put64(&mut f, p + 32, 0xBC);
    put64(&mut f, p + 40, 0xBC);
    put64(&mut f, p + 48, 0x1000);
    let got_off = 0xC0usize;
    let p = 64 + 56;
    put32(&mut f, p, 1);
    put32(&mut f, p + 4, 6);
    put64(&mut f, p + 8, got_off as u64);
    put64(&mut f, p + 16, ELF_GOT);
    put64(&mut f, p + 32, 8);
    put64(&mut f, p + 40, 8);
    put64(&mut f, p + 48, 8);
    // Caller: call stub; ret. Stub: jmp [rip+GOT].
    f.extend_from_slice(&[0xE8, 0x01, 0x00, 0x00, 0x00, 0xC3]); // 0xB0..0xB6
    let disp = (ELF_GOT.wrapping_sub(ELF_STUB_VA + 6)) as u32;
    f.extend_from_slice(&[0xFF, 0x25]); // 0xB6
    f.extend_from_slice(&disp.to_le_bytes()); // 0xB8..0xBC
    f.extend_from_slice(&[0u8; 4]); // pad to GOT
    assert_eq!(f.len(), got_off);
    f.extend_from_slice(&[0u8; 8]); // GOT slot
    // .rela.plt: JUMP_SLOT for the slot, GLOB_DAT noise that must not map.
    let rela_off = f.len();
    let mut rela = Vec::new();
    rela.extend_from_slice(&ELF_GOT.to_le_bytes());
    rela.extend_from_slice(&((1u64 << 32) | 7).to_le_bytes()); // sym 1, JUMP_SLOT
    rela.extend_from_slice(&0u64.to_le_bytes());
    rela.extend_from_slice(&(ELF_GOT + 8).to_le_bytes());
    rela.extend_from_slice(&((1u64 << 32) | 6).to_le_bytes()); // sym 1, GLOB_DAT
    rela.extend_from_slice(&0u64.to_le_bytes());
    f.extend_from_slice(&rela);
    // .dynsym: null + foo (GLOBAL FUNC, UNDEF).
    let dynsym_off = f.len();
    f.extend_from_slice(&[0u8; 24]);
    let mut sym = vec![0u8; 24];
    put32(&mut sym, 0, 1); // st_name
    sym[4] = 0x12; // GLOBAL FUNC
    f.extend_from_slice(&sym);
    // .dynstr, .shstrtab.
    let dynstr_off = f.len();
    f.extend_from_slice(b"\0foo\0");
    let shstr_off = f.len();
    let shstr = b"\0.text\0.rela.plt\0.dynsym\0.dynstr\0.shstrtab\0";
    f.extend_from_slice(shstr);
    while !f.len().is_multiple_of(8) {
        f.push(0);
    }
    let shoff = f.len();
    // Section headers: null, .text, .rela.plt, .dynsym, .dynstr, .shstrtab.
    let mut sh = |name: u32,
                  ty: u32,
                  flags: u64,
                  addr: u64,
                  off: u64,
                  size: u64,
                  link: u32,
                  info: u32,
                  align: u64,
                  entsize: u64| {
        let mut h = vec![0u8; 64];
        put32(&mut h, 0, name);
        put32(&mut h, 4, ty);
        put64(&mut h, 8, flags);
        put64(&mut h, 16, addr);
        put64(&mut h, 24, off);
        put64(&mut h, 32, size);
        put32(&mut h, 40, link);
        put32(&mut h, 44, info);
        put64(&mut h, 48, align);
        put64(&mut h, 56, entsize);
        f.extend_from_slice(&h);
    };
    sh(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    sh(1, 1, 6, ELF_TEXT_VA, 0xB0, 0xC, 0, 0, 1, 0);
    sh(7, 4, 0, 0, rela_off as u64, 48, 3, 0, 8, 24);
    sh(17, 11, 0, 0, dynsym_off as u64, 48, 4, 1, 8, 24);
    sh(25, 3, 0, 0, dynstr_off as u64, 5, 0, 0, 1, 0);
    sh(
        33,
        3,
        0,
        0,
        shstr_off as u64,
        shstr.len() as u64,
        0,
        0,
        1,
        0,
    );
    put64(&mut f, 40, shoff as u64); // shoff
    put16(&mut f, 60, 6); // shnum
    put16(&mut f, 62, 5); // shstrndx
    f
}

/// Handbuilt x86-64 ELF-shaped binary: entry calls a stub whose body is
/// `prefix + jmp [rip+slot]`. Exercises plain, `bnd`, and CET-`endbr64`
/// stub shapes without a container.
fn stub_binary(prefix: &[u8]) -> LoadedBinary {
    let entry_va = 0x400000u64;
    let stub_va = 0x400010u64;
    let slot_va = 0x401000u64;
    let mut code = vec![0xE8];
    let rel = (stub_va.wrapping_sub(entry_va + 5)) as u32;
    code.extend_from_slice(&rel.to_le_bytes());
    code.push(0xC3);
    while code.len() < (stub_va - entry_va) as usize {
        code.push(0x90);
    }
    let next_ip = stub_va + prefix.len() as u64 + 6;
    let mut stub = prefix.to_vec();
    stub.push(0xFF);
    stub.push(0x25);
    let disp = (slot_va.wrapping_sub(next_ip)) as u32;
    stub.extend_from_slice(&disp.to_le_bytes());
    code.extend_from_slice(&stub);
    LoadedBinary {
        format: BinaryFormat::Elf,
        arch: Arch::X86_64,
        entry: Some(entry_va),
        segments: vec![
            Segment {
                vaddr: entry_va,
                mem_size: code.len() as u64,
                data: code,
                readable: true,
                writable: false,
                executable: true,
            },
            Segment {
                vaddr: slot_va,
                mem_size: 8,
                data: vec![0u8; 8],
                readable: true,
                writable: true,
                executable: false,
            },
        ],
        sections: Vec::new(),
        imports: vec![ImportRef {
            library: String::new(),
            name: "foo".to_string(),
            ordinal: None,
            unresolved: false,
            demangled: None,
            address: Some(slot_va),
        }],
        exports: Vec::new(),
        symbols: Vec::new(),
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        debug_funcs: Vec::new(),
        relocatable: false,
    }
}

fn import_xrefs_to(a: &binscout::analysis::Analysis, to: u64) -> Vec<binscout::analysis::Xref> {
    a.xrefs_to(to)
        .into_iter()
        .filter(|x| x.kind == XrefKind::Import)
        .collect()
}

#[test]
fn pe32_ordinals_imports_carry_iat_slots() {
    let bytes = common::fixture_bytes(common::builders::ORDINALS_NAME);
    let bin = load(&bytes).expect("ordinals fixture must load");
    assert_eq!(bin.format, BinaryFormat::Pe);
    assert_eq!(bin.imports.len(), 3);
    let base = common::builders::RDATA_VA + 0x38;
    assert_eq!(
        bin.imports.iter().map(|i| i.address).collect::<Vec<_>>(),
        [Some(base), Some(base + 4), Some(base + 8)]
    );
}

#[test]
fn pe64_iat_call_yields_import_xref() {
    let bin = load(&pe64_with_iat_call()).expect("synthetic PE64 must load");
    assert_eq!(bin.format, BinaryFormat::Pe);
    assert_eq!(bin.imports.len(), 1);
    assert_eq!(bin.imports[0].name, "foo");
    assert_eq!(bin.imports[0].address, Some(PE64_SLOT));

    let a = analyze(&bin).expect("synthetic PE64 must analyze");
    let rows = import_xrefs_to(&a, PE64_SLOT);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].from, PE64_ENTRY);
    // The indirect call keeps its data row and its diagnostic.
    assert!(
        a.xrefs
            .iter()
            .any(|x| x.from == PE64_ENTRY && x.to == PE64_SLOT && x.kind == XrefKind::Data)
    );
    assert!(
        a.diagnostics
            .records
            .iter()
            .any(|d| d.addr == PE64_ENTRY && d.kind == DiagnosticKind::UnresolvedIndirectCall)
    );
    // Stored rows carry the import name.
    let func = a.functions.get(&PE64_ENTRY).expect("entry is a function");
    let call = func
        .blocks
        .values()
        .flat_map(|b| &b.insns)
        .find(|i| i.addr == PE64_ENTRY)
        .expect("call row stored");
    assert_eq!(call.import.as_deref(), Some("foo"));
}

#[test]
fn elf_plt_call_yields_import_xref_and_plt_name() {
    let bin = load(&elf64_with_plt()).expect("synthetic ELF64 must load");
    assert_eq!(bin.format, BinaryFormat::Elf);
    assert_eq!(bin.imports.len(), 1);
    assert_eq!(bin.imports[0].name, "foo");
    assert_eq!(bin.imports[0].address, Some(ELF_GOT));

    let a = analyze(&bin).expect("synthetic ELF64 must analyze");
    assert_eq!(
        a.functions
            .get(&ELF_STUB_VA)
            .expect("PLT stub is a function")
            .name
            .as_deref(),
        Some("foo@plt")
    );
    let mut froms: Vec<u64> = import_xrefs_to(&a, ELF_GOT)
        .iter()
        .map(|x| x.from)
        .collect();
    froms.sort_unstable();
    assert_eq!(froms, [ELF_TEXT_VA, ELF_STUB_VA]);
    // Direct call keeps its code row; the stub keeps its data row.
    assert!(
        a.xrefs
            .iter()
            .any(|x| x.from == ELF_TEXT_VA && x.to == ELF_STUB_VA && x.kind == XrefKind::Code)
    );
    assert!(
        a.xrefs
            .iter()
            .any(|x| x.from == ELF_STUB_VA && x.to == ELF_GOT && x.kind == XrefKind::Data)
    );
}

#[test]
fn stub_shapes_plain_bnd_and_endbr_resolve() {
    // Plain `jmp [rip+slot]`.
    let a = analyze(&stub_binary(&[])).expect("plain stub analyzes");
    assert_eq!(
        a.functions
            .get(&0x400010)
            .expect("stub is a function")
            .name
            .as_deref(),
        Some("foo@plt")
    );
    assert_eq!(import_xrefs_to(&a, 0x401000).len(), 2);
    // MPX `bnd jmp [rip+slot]` (PLT stub shape) keeps its mem target.
    let a = analyze(&stub_binary(&[0xF2])).expect("bnd stub analyzes");
    assert_eq!(
        a.functions
            .get(&0x400010)
            .expect("bnd stub is a function")
            .name
            .as_deref(),
        Some("foo@plt")
    );
    assert_eq!(import_xrefs_to(&a, 0x401000).len(), 2);
    // CET `.plt.sec` shape: `endbr64; jmp [rip+slot]`.
    let body = [0xF3, 0x0F, 0x1E, 0xFA];
    let a = analyze(&stub_binary(&body)).expect("endbr stub analyzes");
    assert_eq!(
        a.functions
            .get(&0x400010)
            .expect("endbr stub is a function")
            .name
            .as_deref(),
        Some("foo@plt")
    );
    let mut froms: Vec<u64> = import_xrefs_to(&a, 0x401000)
        .iter()
        .map(|x| x.from)
        .collect();
    froms.sort_unstable();
    assert_eq!(froms, [0x400000, 0x400014]);
}

#[test]
fn project_queries_filter_import_kind_and_carry_names() {
    let dir = tmpdir("import-xrefs-project");
    let bin_path = write_bin(&dir, "iat.exe", &pe64_with_iat_call());
    let db = temp_db(&dir, "iat");
    let p = Project::open_with_db(&bin_path, &db).expect("PE64 project must open");
    assert_eq!(
        p.count_xrefs(Some(PE64_SLOT), None, Some(XrefKind::Import)),
        1
    );
    let rows = p.query_xrefs(Some(PE64_SLOT), None, Some(XrefKind::Import), 0, 50);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].from, PE64_ENTRY);
    assert_eq!(p.count_xrefs(Some(PE64_SLOT), None, None), 2);

    let partial = p.disasm_at(PE64_ENTRY, 7).expect("disasm works");
    assert_eq!(partial.insns[0].import.as_deref(), Some("foo"));
    assert_eq!(partial.insns[1].import, None);
    let pseudo = p.pseudo_of(PE64_ENTRY).expect("pseudo works");
    let line = pseudo["pseudo"]["lines"]
        .as_array()
        .expect("pseudo lines")
        .iter()
        .find(|l| l["addr"] == PE64_ENTRY)
        .expect("call line present");
    assert_eq!(line["import"], "foo");
    cleanup(&dir);
}

#[test]
fn cli_xrefs_accepts_import_kind() {
    let dir = tmpdir("import-xrefs-cli");
    let bin_path = write_bin(&dir, "iat.exe", &pe64_with_iat_call());
    let db = temp_db(&dir, "iat");
    let bin = bin_path.display().to_string();
    let out = Command::new(binscout_bin())
        .args([
            "--db",
            &db.display().to_string(),
            "xrefs",
            &bin,
            "--to",
            &format!("{PE64_SLOT:#x}"),
            "--kind",
            "import",
        ])
        .output()
        .expect("spawn binscout");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON value");
    assert_eq!(v["total"], 1);
    assert_eq!(v["xrefs"][0]["from"], PE64_ENTRY);
    assert_eq!(v["xrefs"][0]["kind"], "Import");
    cleanup(&dir);
}

#[test]
fn parse_xref_kind_accepts_import() {
    assert_eq!(
        parse_xref_kind("import").expect("import parses"),
        XrefKind::Import
    );
    assert_eq!(
        parse_xref_kind("IMPORT").expect("case-insensitive"),
        XrefKind::Import
    );
    assert!(parse_xref_kind("imports").is_err());
}
