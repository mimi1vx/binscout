//! Relocatable objects (rsdbg-em6.14): two-section ELF .o and multi-section
//! COFF .obj with a cross-section call through a relocation plus an
//! external call. Sections lay out at synthetic non-overlapping addresses,
//! relocations patch the mapped bytes, defined symbols seed functions, and
//! the undefined symbol becomes an import with a synthetic stub.

mod common;

use binscout::analysis::{DiscoveryReason, XrefKind, analyze};
use binscout::disasm::disasm_range;
use binscout::loader::{RELOC_BASE, load};

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn put64(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

/// `.text`: call foo (rel32 @1) + call ext_helper (rel32 @6) + ret.
fn text_code() -> Vec<u8> {
    let mut c = vec![0xE8];
    c.extend_from_slice(&[0, 0, 0, 0]);
    c.push(0xE8);
    c.extend_from_slice(&[0, 0, 0, 0]);
    c.push(0xC3);
    c
}

/// `.text.foo` / `.foo`: push rbp; mov rbp,rsp; ret.
fn callee_code() -> Vec<u8> {
    vec![0x55, 0x48, 0x89, 0xE5, 0xC3]
}

/// ELF64 ET_REL with `.text` + `.text.foo`, `.rela.text` targeting `foo`
/// (PLT32) and undefined `ext_helper` (PLT32), plus symtab/strtab/shstrtab.
fn elf_two_section_o() -> Vec<u8> {
    let text = text_code();
    let callee = callee_code();
    assert_eq!(text.len(), 11);
    assert_eq!(callee.len(), 5);

    let strtab: Vec<u8> = {
        let mut s = vec![0u8];
        s.extend_from_slice(b"main\0");
        s.extend_from_slice(b"foo\0");
        s.extend_from_slice(b"ext_helper\0");
        s
    };
    // offsets: main=1, foo=6, ext_helper=10
    assert_eq!(strtab.len(), 21);
    let shstrtab: Vec<u8> = {
        let mut s = vec![0u8];
        s.extend_from_slice(b".text\0");
        s.extend_from_slice(b".text.foo\0");
        s.extend_from_slice(b".rela.text\0");
        s.extend_from_slice(b".symtab\0");
        s.extend_from_slice(b".strtab\0");
        s.extend_from_slice(b".shstrtab\0");
        s
    };
    assert_eq!(shstrtab.len(), 54);

    let text_off = 64usize;
    let callee_off = text_off + text.len();
    let rela_off = callee_off + callee.len();
    let symtab_off = rela_off + 48;
    let strtab_off = symtab_off + 144;
    let shstrtab_off = strtab_off + strtab.len();
    let shoff = shstrtab_off + shstrtab.len();

    let mut f = vec![0u8; shoff];
    // ELF header
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2; // 64-bit
    f[5] = 1; // LE
    f[6] = 1; // version
    put16(&mut f, 16, 1); // ET_REL
    put16(&mut f, 18, 62); // x86-64
    put32(&mut f, 20, 1);
    put64(&mut f, 40, shoff as u64);
    put16(&mut f, 52, 64);
    put16(&mut f, 58, 64);
    put16(&mut f, 60, 7);
    put16(&mut f, 62, 6);
    f[text_off..text_off + text.len()].copy_from_slice(&text);
    f[callee_off..callee_off + callee.len()].copy_from_slice(&callee);

    // .rela.text: two Rela64 (offset, info, addend)
    // syms: 0 null, 1 .text sec, 2 .text.foo sec, 3 main, 4 foo, 5 ext
    let mut rela = |idx: usize, offset: u64, sym: u64| {
        let o = rela_off + idx * 24;
        put64(&mut f, o, offset);
        put64(&mut f, o + 8, (sym << 32) | 4); // R_X86_64_PLT32
        f[o + 16..o + 24].copy_from_slice(&(-4i64).to_le_bytes());
    };
    rela(0, 1, 4);
    rela(1, 6, 5);

    // .symtab: 6 x Elf64_Sym (24 bytes)
    let mut sym = |idx: usize, name: u32, info: u8, shndx: u16, value: u64, size: u64| {
        let o = symtab_off + idx * 24;
        put32(&mut f, o, name);
        f[o + 4] = info;
        put16(&mut f, o + 6, shndx);
        put64(&mut f, o + 8, value);
        put64(&mut f, o + 16, size);
    };
    sym(0, 0, 0, 0, 0, 0);
    sym(1, 0, 3, 1, 0, 0); // SECTION .text
    sym(2, 0, 3, 2, 0, 0); // SECTION .text.foo
    sym(3, 1, 0x12, 1, 0, 11); // main
    sym(4, 6, 0x12, 2, 0, 5); // foo
    sym(5, 10, 0x10, 0, 0, 0); // ext_helper UNDEF
    f[strtab_off..strtab_off + strtab.len()].copy_from_slice(&strtab);
    f[shstrtab_off..shstrtab_off + shstrtab.len()].copy_from_slice(&shstrtab);

    assert_eq!(f.len(), shoff);
    // Section headers appended at shoff.
    let mut hdr = vec![0u8; 7 * 64];
    {
        let mut w = |idx: usize,
                     name: u32,
                     stype: u32,
                     flags: u64,
                     offset: usize,
                     size: usize,
                     link: u32,
                     info: u32| {
            let o = idx * 64;
            put32(&mut hdr, o, name);
            put32(&mut hdr, o + 4, stype);
            put64(&mut hdr, o + 8, flags);
            put64(&mut hdr, o + 16, 0);
            put64(&mut hdr, o + 24, offset as u64);
            put64(&mut hdr, o + 32, size as u64);
            put32(&mut hdr, o + 40, link);
            put32(&mut hdr, o + 44, info);
            put64(&mut hdr, o + 48, if stype == 3 { 1 } else { 8 });
            put64(
                &mut hdr,
                o + 56,
                if stype == 4 || stype == 2 { 24 } else { 0 },
            );
        };
        w(0, 0, 0, 0, 0, 0, 0, 0);
        w(1, 1, 1, 0x6, text_off, text.len(), 0, 0);
        w(2, 7, 1, 0x6, callee_off, callee.len(), 0, 0);
        w(3, 17, 4, 0, rela_off, 48, 4, 1);
        w(4, 28, 2, 0, symtab_off, 144, 5, 3);
        w(5, 36, 3, 0, strtab_off, strtab.len(), 0, 0);
        w(6, 44, 3, 0, shstrtab_off, shstrtab.len(), 0, 0);
    }
    f.extend_from_slice(&hdr);
    f
}

/// COFF AMD64 .obj with `.text` (call foo @1, call ext @6, ret) and `.foo`
/// (ret block), relocations + symbol table with a long external name.
fn coff_two_section_obj() -> Vec<u8> {
    let text = text_code();
    let callee = callee_code();
    let nsec: u16 = 2;
    let text_off: usize = 20 + 2 * 40;
    let callee_off: usize = text_off + text.len();
    let reloc_off: usize = callee_off + callee.len();
    let symtab_off: usize = reloc_off + 2 * 10;
    // symbols: main(0), foo(1), ext_helper(2, via string table)
    let nsyms: u32 = 3;
    let strtab_off: usize = symtab_off + nsyms as usize * 18;

    let mut f = vec![0u8; strtab_off];
    put16(&mut f, 0, 0x8664);
    put16(&mut f, 2, nsec);
    put32(&mut f, 4, 0x1234_5678);
    put32(&mut f, 8, symtab_off as u32);
    put32(&mut f, 12, nsyms);
    // Section headers
    let mut sh = |idx: usize,
                  name: &[u8],
                  vsize: u32,
                  raw: u32,
                  off: usize,
                  relocs: u32,
                  reloc_ptr: usize,
                  chars: u32| {
        let o = 20 + idx * 40;
        f[o..o + name.len()].copy_from_slice(name);
        put32(&mut f, o + 8, vsize);
        put32(&mut f, o + 12, 0); // relocatable: VA 0
        put32(&mut f, o + 16, raw);
        put32(&mut f, o + 20, off as u32);
        put32(&mut f, o + 24, reloc_ptr as u32);
        put32(&mut f, o + 32, relocs);
        put32(&mut f, o + 36, chars);
    };
    sh(
        0,
        b".text",
        text.len() as u32,
        text.len() as u32,
        text_off,
        2,
        reloc_off,
        0x6000_0020,
    );
    sh(
        1,
        b".foo",
        callee.len() as u32,
        callee.len() as u32,
        callee_off,
        0,
        0,
        0x6000_0020,
    );
    f[text_off..text_off + text.len()].copy_from_slice(&text);
    f[callee_off..callee_off + callee.len()].copy_from_slice(&callee);
    // Relocations: (vaddr, sym, type)
    let mut rel = |idx: usize, vaddr: u32, sym: u32| {
        let o = reloc_off + idx * 10;
        put32(&mut f, o, vaddr);
        put32(&mut f, o + 4, sym);
        put16(&mut f, o + 8, 0x0004); // IMAGE_REL_AMD64_REL32
    };
    rel(0, 1, 1); // call foo
    rel(1, 6, 2); // call ext_helper
    // Symbol table
    let mut sym_inline = |idx: usize, name: &[u8], val: u32, sec: u16| {
        let o = symtab_off + idx * 18;
        f[o..o + name.len()].copy_from_slice(name);
        put32(&mut f, o + 8, val);
        put16(&mut f, o + 12, sec);
        put16(&mut f, o + 14, 0x20);
        f[o + 16] = 2; // EXTERNAL
    };
    sym_inline(0, b"main", 0, 1);
    sym_inline(1, b"foo", 0, 2);
    // ext_helper via string table (offset 4)
    {
        let o = symtab_off + 2 * 18;
        put32(&mut f, o, 0);
        put32(&mut f, o + 4, 4);
        put32(&mut f, o + 8, 0);
        put16(&mut f, o + 12, 0); // UNDEF
        put16(&mut f, o + 14, 0x20);
        f[o + 16] = 2;
    }
    // String table: size + "ext_helper\0"
    let body = b"ext_helper\0";
    let total = (4 + body.len()) as u32;
    f.extend_from_slice(&total.to_le_bytes());
    f.extend_from_slice(body);
    f
}

#[test]
fn relocatable_objects_synthetic_layout_and_symbolic_refs() {
    for (tag, bytes, second_name) in [
        ("elf", elf_two_section_o(), ".text.foo"),
        ("coff", coff_two_section_obj(), ".foo"),
    ] {
        let bin = load(&bytes).unwrap_or_else(|e| panic!("{tag} must load: {e:?}"));
        assert!(bin.relocatable, "{tag}: must flag the synthetic layout");
        assert_eq!(bin.entry, None, "{tag}: no entry point");

        // Executable sections lay out in order at RELOC_BASE, 16-aligned.
        let execs: Vec<_> = bin.sections.iter().filter(|s| s.executable).collect();
        assert_eq!(execs.len(), 2, "{tag}: two executable sections");
        assert_eq!(execs[0].vaddr, RELOC_BASE, "{tag}: first section base");
        assert_eq!(execs[1].name, second_name, "{tag}: second section name");
        assert_eq!(
            execs[1].vaddr,
            RELOC_BASE + 0x10,
            "{tag}: second section aligned past the 11-byte .text"
        );
        assert_eq!(bin.segments.len(), 2, "{tag}: one segment per section");
        assert_eq!(bin.segments[0].vaddr, RELOC_BASE);
        assert_eq!(bin.segments[1].vaddr, RELOC_BASE + 0x10);
        assert_eq!(common::section_bytes(&bin, 0).len(), 11);
        assert_eq!(common::section_bytes(&bin, 1).len(), 5);

        // Defined symbols remap through their section's base.
        let addr = |name: &str| {
            bin.symbols
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("{tag}: symbol {name} missing"))
                .address
        };
        assert_eq!(addr("main"), RELOC_BASE, "{tag}: main at .text base");
        assert_eq!(addr("foo"), RELOC_BASE + 0x10, "{tag}: foo at second base");

        // The undefined symbol becomes an import with a synthetic stub
        // past the last section.
        assert_eq!(bin.imports.len(), 1, "{tag}: one external import");
        assert_eq!(bin.imports[0].name, "ext_helper");
        let stub = bin.imports[0].address.expect("{tag}: stub address");
        assert_eq!(stub, RELOC_BASE + 0x20, "{tag}: stub past sections");
        assert!(bin.exports.is_empty(), "{tag}: no exports");

        // Patched bytes decode to the real targets.
        let main_bytes = common::section_bytes(&bin, 0);
        let insns = disasm_range(bin.arch, main_bytes, RELOC_BASE, 10).expect("{tag}: decodes");
        assert_eq!(insns.len(), 3, "{tag}: call, call, ret");
        assert_eq!(
            insns[0].branch_target,
            Some(RELOC_BASE + 0x10),
            "{tag}: first call targets foo"
        );
        assert_eq!(
            insns[1].branch_target,
            Some(stub),
            "{tag}: second targets stub"
        );

        // Analysis: both symbols seed functions, the internal call is a
        // callgraph edge, and the external call is Code + Import to stub.
        let a = analyze(&bin).expect("{tag}: analysis must run");
        assert!(
            a.functions.contains_key(&RELOC_BASE),
            "{tag}: main function"
        );
        assert!(
            a.functions.contains_key(&(RELOC_BASE + 0x10)),
            "{tag}: foo function"
        );
        let main = &a.functions[&RELOC_BASE];
        assert_eq!(main.name.as_deref(), Some("main"));
        assert!(main.reason_list().contains(&DiscoveryReason::Symbol));
        assert_eq!(a.calls_of(RELOC_BASE), vec![RELOC_BASE + 0x10]);
        let callee_func = &a.functions[&(RELOC_BASE + 0x10)];
        assert_eq!(callee_func.name.as_deref(), Some("foo"));
        assert!(callee_func.reason_list().contains(&DiscoveryReason::Symbol));
        assert!(
            callee_func
                .reason_list()
                .contains(&DiscoveryReason::DirectCall)
        );
        assert!(
            a.xrefs.iter().any(|x| x.from == RELOC_BASE
                && x.to == RELOC_BASE + 0x10
                && x.kind == XrefKind::Code),
            "{tag}: internal Code xref"
        );
        assert!(
            a.xrefs
                .iter()
                .any(|x| x.from == RELOC_BASE + 5 && x.to == stub && x.kind == XrefKind::Code),
            "{tag}: external Code xref"
        );
        assert!(
            a.xrefs
                .iter()
                .any(|x| x.from == RELOC_BASE + 5 && x.to == stub && x.kind == XrefKind::Import),
            "{tag}: external Import xref"
        );
        // The stub itself is undefined: no function seeds there.
        assert!(!a.functions.contains_key(&stub), "{tag}: no stub function");
    }
}
