//! Mach-O stub-to-import mapping: `__stubs`/`__auth_stubs` entries resolve
//! through the indirect symbol table to an import of the same name, and any
//! doubt maps nothing (never misattributes). Binaries bound with
//! `LC_DYLD_CHAINED_FIXUPS` have no indirect table; their stubs resolve
//! through the chained binds instead (see the `chained_*` builders/tests).

mod common;

use binscout::analysis::{DiagnosticKind, XrefKind, analyze};
use binscout::disasm::Arch;
use binscout::loader::{
    BinaryFormat, ExportRef, ImportRef, LoadedBinary, Segment, SymbolRef, load,
};

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn put64(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

const STUB_ADDR: u64 = 0x2000;
const STRIDE: u32 = 6;

/// Thin x86-64 Mach-O with `syms` undefined symbols and a `__stubs` section
/// of `stubs` entries (stride [`STRIDE`]); no dyld info, so `object` reports
/// imports in symtab order. `stub_flags` overrides the section type
/// (`0x8` = `S_SYMBOL_STUBS`); `stub_name` overrides the section name.
/// `indirect` is the `LC_DYSYMTAB` indirect table (one symtab index per
/// entry, so indirect order may differ from symtab order) and
/// `indirect_base` the section `reserved1` start index.
fn macho_with_stubs(
    syms: &[&str],
    stubs: u32,
    stub_flags: u32,
    stub_name: &[u8],
    indirect_base: u32,
    indirect: &[u32],
) -> Vec<u8> {
    assert_eq!(
        indirect.len(),
        indirect_base as usize + stubs as usize,
        "indirect table must cover reserved1..reserved1+stubs"
    );
    let header = 32usize;
    let seg_cmd = 72 + 2 * 80;
    let sym_cmd = 24usize;
    let dysym_cmd = 80usize;
    let head_end = header + seg_cmd + sym_cmd + dysym_cmd;

    let mut strtab = vec![0u8];
    let mut syms_raw = Vec::new();
    for s in syms {
        let off = strtab.len() as u32;
        strtab.extend_from_slice(s.as_bytes());
        strtab.push(0);
        // nlist_64: undefined external symbol (N_UNDF|N_EXT, NO_SECT, value 0).
        let mut n = [0u8; 16];
        put32(&mut n, 0, off);
        n[4] = 0x01;
        syms_raw.extend_from_slice(&n);
    }

    let code = [0x90u8, 0x90, 0xC3];
    let stub_size = stubs as usize * STRIDE as usize;
    let symoff = head_end;
    let stroff = symoff + syms_raw.len();
    let code_off = stroff + strtab.len();
    let stub_off = code_off + code.len();
    let indirect_off = stub_off + stub_size;
    let total = indirect_off + indirect.len() * 4;

    let mut f = vec![0u8; total];
    put32(&mut f, 0, 0xFEED_FACF); // 64-bit LE magic
    put32(&mut f, 4, 0x0100_0007); // x86-64
    put32(&mut f, 8, 3);
    put32(&mut f, 12, 2); // MH_EXECUTE
    put32(&mut f, 16, 3); // ncmds
    put32(&mut f, 20, (seg_cmd + sym_cmd + dysym_cmd) as u32);

    let c = header;
    put32(&mut f, c, 0x19); // LC_SEGMENT_64
    put32(&mut f, c + 4, seg_cmd as u32);
    f[c + 8..c + 14].copy_from_slice(b"__TEXT");
    put64(&mut f, c + 24, 0x1000); // vmaddr
    put64(&mut f, c + 32, 0x1000); // vmsize
    put64(&mut f, c + 40, head_end as u64); // fileoff
    put64(&mut f, c + 48, (total - head_end) as u64); // filesize
    put32(&mut f, c + 56, 5);
    put32(&mut f, c + 60, 5);
    put32(&mut f, c + 64, 2); // nsects

    let s = c + 72;
    f[s..s + 6].copy_from_slice(b"__text");
    f[s + 16..s + 22].copy_from_slice(b"__TEXT");
    put64(&mut f, s + 32, 0x1000);
    put64(&mut f, s + 40, code.len() as u64);
    put32(&mut f, s + 48, code_off as u32);
    put32(&mut f, s + 64, 0x8000_0400);

    let s = c + 72 + 80;
    let name_len = stub_name.len().min(16);
    f[s..s + name_len].copy_from_slice(&stub_name[..name_len]);
    f[s + 16..s + 22].copy_from_slice(b"__TEXT");
    put64(&mut f, s + 32, STUB_ADDR);
    put64(&mut f, s + 40, stub_size as u64);
    put32(&mut f, s + 48, stub_off as u32);
    put32(&mut f, s + 64, stub_flags);
    put32(&mut f, s + 68, indirect_base); // reserved1
    put32(&mut f, s + 72, STRIDE); // reserved2 = stub byte size

    let c = header + seg_cmd;
    put32(&mut f, c, 0x2); // LC_SYMTAB
    put32(&mut f, c + 4, sym_cmd as u32);
    put32(&mut f, c + 8, symoff as u32);
    put32(&mut f, c + 12, syms.len() as u32);
    put32(&mut f, c + 16, stroff as u32);
    put32(&mut f, c + 20, strtab.len() as u32);

    let c = header + seg_cmd + sym_cmd;
    put32(&mut f, c, 0xB); // LC_DYSYMTAB
    put32(&mut f, c + 4, dysym_cmd as u32);
    put32(&mut f, c + 56, indirect_off as u32); // indirectsymoff
    put32(&mut f, c + 60, indirect.len() as u32); // nindirectsyms

    f[symoff..symoff + syms_raw.len()].copy_from_slice(&syms_raw);
    f[stroff..stroff + strtab.len()].copy_from_slice(&strtab);
    f[code_off..code_off + code.len()].copy_from_slice(&code);
    for (i, b) in f[stub_off..stub_off + stub_size].iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    for (i, entry) in indirect.iter().enumerate() {
        put32(&mut f, indirect_off + i * 4, *entry);
    }
    f
}

/// 32-bit (`MH_MAGIC`) twin of [`macho_with_stubs`] with a `__stubs`
/// section of `stubs` entries: 28-byte header, `LC_SEGMENT` sections, and
/// 12-byte `nlist`s. Covers the 32-bit indirect-resolution path.
fn macho32_with_stubs(syms: &[&str], stubs: u32, indirect_base: u32, indirect: &[u32]) -> Vec<u8> {
    assert_eq!(
        indirect.len(),
        indirect_base as usize + stubs as usize,
        "indirect table must cover reserved1..reserved1+stubs"
    );
    let header = 28usize;
    let seg_cmd = 56 + 2 * 68;
    let sym_cmd = 24usize;
    let dysym_cmd = 80usize;
    let head_end = header + seg_cmd + sym_cmd + dysym_cmd;

    let mut strtab = vec![0u8];
    let mut syms_raw = Vec::new();
    for s in syms {
        let off = strtab.len() as u32;
        strtab.extend_from_slice(s.as_bytes());
        strtab.push(0);
        // nlist_32: undefined external symbol (N_UNDF|N_EXT, NO_SECT, value 0).
        let mut n = [0u8; 12];
        put32(&mut n, 0, off);
        n[4] = 0x01;
        syms_raw.extend_from_slice(&n);
    }

    let code = [0x90u8, 0x90, 0xC3];
    let stub_size = stubs as usize * STRIDE as usize;
    let symoff = head_end;
    let stroff = symoff + syms_raw.len();
    let code_off = stroff + strtab.len();
    let stub_off = code_off + code.len();
    let indirect_off = stub_off + stub_size;
    let total = indirect_off + indirect.len() * 4;

    let mut f = vec![0u8; total];
    put32(&mut f, 0, 0xFEED_FACE); // 32-bit LE magic
    put32(&mut f, 4, 7); // x86
    put32(&mut f, 8, 3);
    put32(&mut f, 12, 2); // MH_EXECUTE
    put32(&mut f, 16, 3); // ncmds
    put32(&mut f, 20, (seg_cmd + sym_cmd + dysym_cmd) as u32);

    let c = header;
    put32(&mut f, c, 0x1); // LC_SEGMENT
    put32(&mut f, c + 4, seg_cmd as u32);
    f[c + 8..c + 14].copy_from_slice(b"__TEXT");
    put32(&mut f, c + 24, 0x1000); // vmaddr
    put32(&mut f, c + 28, 0x1000); // vmsize
    put32(&mut f, c + 32, head_end as u32); // fileoff
    put32(&mut f, c + 36, (total - head_end) as u32); // filesize
    put32(&mut f, c + 40, 5);
    put32(&mut f, c + 44, 5);
    put32(&mut f, c + 48, 2); // nsects

    let s = c + 56;
    f[s..s + 6].copy_from_slice(b"__text");
    f[s + 16..s + 22].copy_from_slice(b"__TEXT");
    put32(&mut f, s + 32, 0x1000);
    put32(&mut f, s + 36, code.len() as u32);
    put32(&mut f, s + 40, code_off as u32);
    put32(&mut f, s + 56, 0x8000_0400);

    let s = c + 56 + 68;
    f[s..s + 7].copy_from_slice(b"__stubs");
    f[s + 16..s + 22].copy_from_slice(b"__TEXT");
    put32(&mut f, s + 32, STUB_ADDR as u32);
    put32(&mut f, s + 36, stub_size as u32);
    put32(&mut f, s + 40, stub_off as u32);
    put32(&mut f, s + 56, 0x8); // S_SYMBOL_STUBS
    put32(&mut f, s + 60, indirect_base); // reserved1
    put32(&mut f, s + 64, STRIDE); // reserved2 = stub byte size

    let c = header + seg_cmd;
    put32(&mut f, c, 0x2); // LC_SYMTAB
    put32(&mut f, c + 4, sym_cmd as u32);
    put32(&mut f, c + 8, symoff as u32);
    put32(&mut f, c + 12, syms.len() as u32);
    put32(&mut f, c + 16, stroff as u32);
    put32(&mut f, c + 20, strtab.len() as u32);

    let c = header + seg_cmd + sym_cmd;
    put32(&mut f, c, 0xB); // LC_DYSYMTAB
    put32(&mut f, c + 4, dysym_cmd as u32);
    put32(&mut f, c + 56, indirect_off as u32); // indirectsymoff
    put32(&mut f, c + 60, indirect.len() as u32); // nindirectsyms

    f[symoff..symoff + syms_raw.len()].copy_from_slice(&syms_raw);
    f[stroff..stroff + strtab.len()].copy_from_slice(&strtab);
    f[code_off..code_off + code.len()].copy_from_slice(&code);
    for (i, b) in f[stub_off..stub_off + stub_size].iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    for (i, entry) in indirect.iter().enumerate() {
        put32(&mut f, indirect_off + i * 4, *entry);
    }
    f
}

#[test]
fn stubs_map_in_order_when_counts_match() {
    let bin = load(&macho_with_stubs(
        &["_a", "_b"],
        2,
        0x8,
        b"__stubs",
        0,
        &[0, 1],
    ))
    .expect("synthetic Mach-O must load");
    assert_eq!(bin.format, BinaryFormat::MachO);
    assert_eq!(bin.imports.len(), 2);
    assert_eq!(bin.imports[0].name, "_a");
    assert_eq!(bin.imports[1].name, "_b");
    assert_eq!(bin.imports[0].address, Some(STUB_ADDR));
    assert_eq!(bin.imports[1].address, Some(STUB_ADDR + STRIDE as u64));
}

#[test]
fn stubs_pair_by_indirect_name_not_position() {
    // Symtab order is [_a, _b] but the indirect table reads [_b, _a]:
    // stub 0 resolves _b, stub 1 resolves _a. Positional pairing would
    // swap the addresses.
    let bin = load(&macho_with_stubs(
        &["_a", "_b"],
        2,
        0x8,
        b"__stubs",
        0,
        &[1, 0],
    ))
    .expect("synthetic Mach-O must load");
    assert_eq!(bin.imports.len(), 2);
    assert_eq!(bin.imports[0].name, "_a");
    assert_eq!(bin.imports[1].name, "_b");
    assert_eq!(bin.imports[0].address, Some(STUB_ADDR + STRIDE as u64));
    assert_eq!(bin.imports[1].address, Some(STUB_ADDR));
}

#[test]
fn stubs_pair_by_indirect_name_on_32_bit() {
    // Same reversed-indirect shape through 32-bit headers, sections, and
    // 12-byte `nlist`s: stub 0 resolves _b, stub 1 resolves _a.
    let bin = load(&macho32_with_stubs(&["_a", "_b"], 2, 0, &[1, 0]))
        .expect("synthetic 32-bit Mach-O must load");
    assert_eq!(bin.format, BinaryFormat::MachO);
    assert_eq!(bin.arch, binscout::disasm::Arch::X86_32);
    assert_eq!(bin.imports.len(), 2);
    assert_eq!(bin.imports[0].name, "_a");
    assert_eq!(bin.imports[1].name, "_b");
    assert_eq!(bin.imports[0].address, Some(STUB_ADDR + STRIDE as u64));
    assert_eq!(bin.imports[1].address, Some(STUB_ADDR));
}

#[test]
fn reserved1_base_offsets_indirect_lookup() {
    // reserved1 = 2: the two stubs resolve through table entries 2 and 3.
    let bin = load(&macho_with_stubs(
        &["_a", "_b"],
        2,
        0x8,
        b"__stubs",
        2,
        &[0, 0, 1, 0],
    ))
    .expect("synthetic Mach-O must load");
    assert_eq!(bin.imports[0].name, "_a");
    assert_eq!(bin.imports[1].name, "_b");
    assert_eq!(bin.imports[0].address, Some(STUB_ADDR + STRIDE as u64));
    assert_eq!(bin.imports[1].address, Some(STUB_ADDR));
}

#[test]
fn duplicate_indirect_target_maps_nothing() {
    // Both stubs resolve _a while _b gets no stub: no bijection, so no
    // address anywhere rather than a doubled one.
    let bin = load(&macho_with_stubs(
        &["_a", "_b"],
        2,
        0x8,
        b"__stubs",
        0,
        &[0, 0],
    ))
    .expect("synthetic Mach-O must load");
    assert_eq!(bin.imports.len(), 2);
    assert!(bin.imports.iter().all(|i| i.address.is_none()));
}

#[test]
fn out_of_range_indirect_index_maps_nothing() {
    // Second stub points past the two-entry indirect table.
    let bin = load(&macho_with_stubs(
        &["_a", "_b"],
        2,
        0x8,
        b"__stubs",
        0,
        &[0, 7],
    ))
    .expect("synthetic Mach-O must load");
    assert_eq!(bin.imports.len(), 2);
    assert!(bin.imports.iter().all(|i| i.address.is_none()));
}

#[test]
fn count_mismatch_maps_nothing() {
    // Three imports but two stub entries (the real-`/bin/ls` shape: data
    // binds have no stub): no address anywhere, never a wrong one.
    let bin = load(&macho_with_stubs(
        &["_a", "_b", "_c"],
        2,
        0x8,
        b"__stubs",
        0,
        &[0, 1],
    ))
    .expect("synthetic Mach-O must load");
    assert_eq!(bin.imports.len(), 3);
    assert!(bin.imports.iter().all(|i| i.address.is_none()));
}

#[test]
fn non_stub_section_type_maps_nothing() {
    // `__stub_helper`-shaped section (regular type, like the real x86_64
    // `ls` slice): the name alone never qualifies.
    let bin = load(&macho_with_stubs(
        &["_a", "_b"],
        2,
        0x0,
        b"__stub_helper",
        0,
        &[0, 1],
    ))
    .expect("synthetic Mach-O must load");
    assert_eq!(bin.imports.len(), 2);
    assert!(bin.imports.iter().all(|i| i.address.is_none()));
}

#[test]
fn unaligned_stub_section_maps_nothing() {
    // 2 entries at stride 6 but section size rounded up: `size % stride !=
    // 0` vetoes the whole mapping.
    let mut f = macho_with_stubs(&["_a", "_b"], 2, 0x8, b"__stubs", 0, &[0, 1]);
    // Second section's size field: header + segment header + one section.
    let size_off = 32 + 72 + 80 + 40;
    let size = u64::from_le_bytes(f[size_off..size_off + 8].try_into().unwrap());
    f[size_off..size_off + 8].copy_from_slice(&(size - 1).to_le_bytes());
    let bin = load(&f).expect("synthetic Mach-O must load");
    assert!(bin.imports.iter().all(|i| i.address.is_none()));
}

#[test]
fn missing_indirect_table_maps_nothing() {
    // Zeroed indirectsymoff/nindirectsyms: no table to resolve through.
    let mut f = macho_with_stubs(&["_a", "_b"], 2, 0x8, b"__stubs", 0, &[0, 1]);
    // Dysymtab command at header + segment + symtab commands; indirect
    // fields at +56.
    let fields = 32 + (72 + 2 * 80) + 24 + 56;
    f[fields..fields + 8].copy_from_slice(&[0; 8]);
    let bin = load(&f).expect("synthetic Mach-O must load");
    assert!(bin.imports.iter().all(|i| i.address.is_none()));
}

#[test]
fn import_json_pairs_address_with_hex() {
    let bin = load(&macho_with_stubs(
        &["_a", "_b"],
        2,
        0x8,
        b"__stubs",
        0,
        &[0, 1],
    ))
    .expect("synthetic Mach-O must load");
    let v = serde_json::to_value(&bin.imports).expect("imports serialize");
    let rows = v.as_array().expect("imports array");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["address"], STUB_ADDR);
    assert_eq!(rows[0]["address_hex"], format!("{STUB_ADDR:#x}"));
    assert_eq!(rows[1]["address_hex"], format!("{:#x}", STUB_ADDR + 6));

    // Legacy rows without `address` still decode, defaulting to `None`.
    let legacy: binscout::loader::ImportRef = serde_json::from_value(serde_json::json!({
        "library": "", "name": "_a", "unresolved": false,
    }))
    .expect("legacy import decodes");
    assert_eq!(legacy.address, None);
    let v = serde_json::to_value(&legacy).expect("legacy serializes");
    assert!(v["address"].is_null() && v["address_hex"].is_null());
}

/// x86-64 code with two stub slots: the entry calls both, each stub is a
/// `ret`. `stub_addrs` assigns the import addresses (`None` = unmapped).
fn stub_binary(stub_addrs: [Option<u64>; 2]) -> LoadedBinary {
    // 0x1000: call 0x1010; 0x1005: call 0x1011; 0x100a: ret;
    // 0x100b..0x100f: nop padding; 0x1010/0x1011: stub rets.
    let mut code = vec![
        0xE8, 0x0B, 0x00, 0x00, 0x00, // call 0x1010
        0xE8, 0x07, 0x00, 0x00, 0x00, // call 0x1011
        0xC3, // ret
    ];
    code.extend_from_slice(&[0x90; 5]);
    code.extend_from_slice(&[0xC3, 0xC3]); // stubs
    assert_eq!(code.len(), 0x12);
    let names = ["_a", "_b"];
    let imports = names
        .into_iter()
        .zip(stub_addrs)
        .map(|(name, address)| ImportRef {
            library: String::new(),
            name: name.to_string(),
            ordinal: None,
            unresolved: false,
            demangled: None,
            address,
        })
        .collect();
    LoadedBinary {
        format: BinaryFormat::MachO,
        arch: Arch::X86_64,
        entry: Some(0x1000),
        segments: vec![Segment {
            vaddr: 0x1000,
            mem_size: code.len() as u64,
            data: code,
            readable: true,
            writable: false,
            executable: true,
        }],
        sections: Vec::new(),
        imports,
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
fn stub_functions_carry_import_names() {
    let bin = stub_binary([Some(0x1010), Some(0x1011)]);
    let analysis = analyze(&bin).expect("stub binary analyzes");
    assert_eq!(
        analysis
            .functions
            .get(&0x1010)
            .expect("stub _a is a function")
            .name
            .as_deref(),
        Some("_a")
    );
    assert_eq!(
        analysis
            .functions
            .get(&0x1011)
            .expect("stub _b is a function")
            .name
            .as_deref(),
        Some("_b")
    );
    assert_eq!(
        analysis
            .functions
            .get(&0x1000)
            .expect("entry is a function")
            .name,
        None
    );
}

#[test]
fn unmapped_stubs_stay_unnamed_with_null_addresses() {
    // Same bytes, no stub mapping (the count-mismatch shape): the stubs are
    // still functions via direct calls, but their names stay null and the
    // import rows carry null addresses.
    let bin = stub_binary([None, None]);
    let analysis = analyze(&bin).expect("stub binary analyzes");
    for stub in [0x1010, 0x1011] {
        assert_eq!(
            analysis
                .functions
                .get(&stub)
                .expect("stub is a function")
                .name,
            None,
            "unmapped stub {stub:#x} stays unnamed"
        );
    }
    let v = serde_json::to_value(&bin.imports).expect("imports serialize");
    let rows = v.as_array().expect("imports array");
    assert!(
        rows.iter()
            .all(|r| r["address"].is_null() && r["address_hex"].is_null())
    );
}

#[test]
fn symbols_json_carries_stub_addresses() {
    let dir = common::tmpdir("macho-stubs-symbols");
    let bin_path = common::write_bin(
        &dir,
        "stubs.macho",
        &macho_with_stubs(&["_a", "_b"], 2, 0x8, b"__stubs", 0, &[0, 1]),
    );
    let db_path = common::temp_db(&dir, "stubs");
    let p = binscout::Project::open_with_db(&bin_path, &db_path).expect("fixture must open");
    let symbols = p.symbols_json();
    let imports = symbols["imports"].as_array().expect("imports array");
    assert_eq!(imports.len(), 2);
    assert_eq!(imports[0]["address"], STUB_ADDR);
    assert_eq!(imports[0]["address_hex"], format!("{STUB_ADDR:#x}"));
    assert_eq!(imports[1]["address"], STUB_ADDR + STRIDE as u64);
    assert_eq!(
        imports[1]["address_hex"],
        format!("{:#x}", STUB_ADDR + STRIDE as u64)
    );
    common::cleanup(&dir);
}

/// Chained-fixups Mach-O addresses shared by the builder and the tests.
const CHAINED_TEXT: u64 = 0x1_0000;
const CHAINED_STUBS: u64 = 0x1_0008;
const CHAINED_GOT: u64 = 0x1_1000;

/// Thin Mach-O bound with `LC_DYLD_CHAINED_FIXUPS` (no symtab, no indirect
/// table): three imports (`_foo`, `_bar`, `_baz`) in a `DYLD_CHAINED_IMPORT`
/// table, `__DATA` chained bind pointers (`DYLD_CHAINED_PTR_64`) at
/// [`CHAINED_GOT`]+0/8/16, and two `__stubs` entries at [`CHAINED_STUBS`]
/// loading the first two slots. `_baz` is a data-only bind with no stub —
/// the real-`/bin/ls` shape — so it must stay unmapped while the stubbed
/// imports map.
///
/// `cputype` selects the arch (`0x0100_000C` arm64 with `adrp`/`ldr`/`br`
/// stubs, `0x0100_0007` x86-64 with `jmp [rip+disp]` stubs); `text` is the
/// 8-byte `__text` body and `stubs` the two entries (`stride` bytes each).
fn macho_chained(cputype: u32, text: &[u8; 8], stubs: &[u8], stride: u32) -> Vec<u8> {
    assert_eq!(stubs.len(), 2 * stride as usize);
    let header = 32usize;
    let text_seg = 72 + 2 * 80;
    let data_seg = 72 + 80;
    let link_seg = 72usize;
    let dylib_cmd = 48usize;
    let chained_cmd = 16usize;
    let main_cmd = 24usize;
    let ncmds = 6u32;
    let sizeofcmds = (text_seg + data_seg + link_seg + dylib_cmd + chained_cmd + main_cmd) as u32;
    let head_end = header + sizeofcmds as usize;

    let stub_size = stubs.len();
    let text_off = head_end;
    let stub_off = text_off + text.len();
    let data_off = stub_off + stub_size;
    // Three 8-byte bind pointers: ordinals 0 and 1 chained (next = 2
    // strides of 4 bytes = 8 bytes), ordinal 2 terminates.
    let data: [u64; 3] = [
        0x8010_0000_0000_0000,
        0x8010_0000_0000_0001,
        0x8000_0000_0000_0002,
    ];
    let link_off = data_off + data.len() * 8;

    // Fixups payload: header (28) + starts image (4 + 3*4) + one starts
    // segment (24 + 2*1) + imports (3*4) + symbol strings.
    let symbols = b"\0_foo\0_bar\0_baz\0";
    let starts_off = 28usize;
    let segstarts_off = starts_off + 4 + 3 * 4;
    let imports_off = segstarts_off + 24 + 2;
    let symbols_off = imports_off + 3 * 4;
    let payload_len = symbols_off + symbols.len();

    let total = link_off + payload_len;
    let mut f = vec![0u8; total];
    put32(&mut f, 0, 0xFEED_FACF);
    put32(&mut f, 4, cputype);
    put32(&mut f, 8, 0);
    put32(&mut f, 12, 2); // MH_EXECUTE
    put32(&mut f, 16, ncmds);
    put32(&mut f, 20, sizeofcmds);

    // __TEXT with __text + __stubs.
    let mut c = header;
    put32(&mut f, c, 0x19); // LC_SEGMENT_64
    put32(&mut f, c + 4, text_seg as u32);
    f[c + 8..c + 14].copy_from_slice(b"__TEXT");
    put64(&mut f, c + 24, CHAINED_TEXT);
    put64(&mut f, c + 32, 0x1000);
    put64(&mut f, c + 40, text_off as u64);
    put64(&mut f, c + 48, (text.len() + stub_size) as u64);
    put32(&mut f, c + 56, 5);
    put32(&mut f, c + 60, 5);
    put32(&mut f, c + 64, 2);
    let mut s = c + 72;
    f[s..s + 6].copy_from_slice(b"__text");
    f[s + 16..s + 22].copy_from_slice(b"__TEXT");
    put64(&mut f, s + 32, CHAINED_TEXT);
    put64(&mut f, s + 40, text.len() as u64);
    put32(&mut f, s + 48, text_off as u32);
    put32(&mut f, s + 64, 0x8000_0400);
    s += 80;
    f[s..s + 7].copy_from_slice(b"__stubs");
    f[s + 16..s + 22].copy_from_slice(b"__TEXT");
    put64(&mut f, s + 32, CHAINED_STUBS);
    put64(&mut f, s + 40, stub_size as u64);
    put32(&mut f, s + 48, stub_off as u32);
    put32(&mut f, s + 64, 0x8); // S_SYMBOL_STUBS
    put32(&mut f, s + 68, 0);
    put32(&mut f, s + 72, stride);

    // __DATA with __got.
    c += text_seg;
    put32(&mut f, c, 0x19);
    put32(&mut f, c + 4, data_seg as u32);
    f[c + 8..c + 14].copy_from_slice(b"__DATA");
    put64(&mut f, c + 24, CHAINED_GOT);
    put64(&mut f, c + 32, 0x1000);
    put64(&mut f, c + 40, data_off as u64);
    put64(&mut f, c + 48, (data.len() * 8) as u64);
    put32(&mut f, c + 56, 3);
    put32(&mut f, c + 60, 3);
    put32(&mut f, c + 64, 1);
    s = c + 72;
    f[s..s + 5].copy_from_slice(b"__got");
    f[s + 16..s + 22].copy_from_slice(b"__DATA");
    put64(&mut f, s + 32, CHAINED_GOT);
    put64(&mut f, s + 40, (data.len() * 8) as u64);
    put32(&mut f, s + 48, data_off as u32);

    // __LINKEDIT carrying the fixups payload.
    c += data_seg;
    put32(&mut f, c, 0x19);
    put32(&mut f, c + 4, link_seg as u32);
    f[c + 8..c + 18].copy_from_slice(b"__LINKEDIT");
    put64(&mut f, c + 24, 0x1_2000);
    put64(&mut f, c + 32, 0x1000);
    put64(&mut f, c + 40, link_off as u64);
    put64(&mut f, c + 48, payload_len as u64);
    put32(&mut f, c + 56, 1);
    put32(&mut f, c + 60, 1);
    put32(&mut f, c + 64, 0);

    // One provider library for the import table's dylib ordinal 1.
    c += link_seg;
    put32(&mut f, c, 0xC); // LC_LOAD_DYLIB
    put32(&mut f, c + 4, dylib_cmd as u32);
    put32(&mut f, c + 8, 24);
    let lib = b"libSystem.B.dylib\0";
    f[c + 24..c + 24 + lib.len()].copy_from_slice(lib);

    // LC_DYLD_CHAINED_FIXUPS pointing at the payload.
    c += dylib_cmd;
    put32(&mut f, c, 0x8000_0034);
    put32(&mut f, c + 4, chained_cmd as u32);
    put32(&mut f, c + 8, link_off as u32);
    put32(&mut f, c + 12, payload_len as u32);

    // LC_MAIN so the image has an entry point at __text: entryoff is the
    // spec file offset of main, which the loader translates to CHAINED_TEXT.
    c += chained_cmd;
    put32(&mut f, c, 0x8000_0028);
    put32(&mut f, c + 4, main_cmd as u32);
    put64(&mut f, c + 8, text_off as u64);
    put64(&mut f, c + 16, 0);

    // Bodies.
    f[text_off..text_off + 8].copy_from_slice(text);
    f[stub_off..stub_off + stub_size].copy_from_slice(stubs);
    for (i, slot) in data.iter().enumerate() {
        f[data_off + i * 8..data_off + i * 8 + 8].copy_from_slice(&slot.to_le_bytes());
    }

    // Payload.
    let p = link_off;
    put32(&mut f, p, 0); // fixups_version
    put32(&mut f, p + 4, starts_off as u32);
    put32(&mut f, p + 8, imports_off as u32);
    put32(&mut f, p + 12, symbols_off as u32);
    put32(&mut f, p + 16, 3); // imports_count
    put32(&mut f, p + 20, 1); // DYLD_CHAINED_IMPORT
    put32(&mut f, p + 24, 0); // uncompressed symbols
    // Starts image: 3 segments, only __DATA (index 1) has fixups.
    put32(&mut f, p + starts_off, 3);
    put32(&mut f, p + starts_off + 4, 0);
    put32(&mut f, p + starts_off + 8, 16);
    put32(&mut f, p + starts_off + 12, 0);
    // Starts segment: one 4K page, DYLD_CHAINED_PTR_64, chain at offset 0.
    let g = p + segstarts_off;
    put32(&mut f, g, 26);
    f[g + 4..g + 6].copy_from_slice(&0x1000u16.to_le_bytes());
    f[g + 6..g + 8].copy_from_slice(&2u16.to_le_bytes());
    put64(&mut f, g + 8, 0);
    put32(&mut f, g + 16, 0);
    f[g + 20..g + 22].copy_from_slice(&1u16.to_le_bytes());
    f[g + 22..g + 24].copy_from_slice(&0u16.to_le_bytes());
    // Imports: library ordinal 1, names at pool offsets 1/6/11.
    put32(&mut f, p + imports_off, (1 << 9) | 1);
    put32(&mut f, p + imports_off + 4, (6 << 9) | 1);
    put32(&mut f, p + imports_off + 8, (11 << 9) | 1);
    f[symbols_off + p..symbols_off + p + symbols.len()].copy_from_slice(symbols);
    f
}

/// arm64 chained fixture: `__text` calls the first stub, each `__stubs`
/// entry is `adrp x16; ldr x16, [x16, #off]; br x16` (stride 12).
fn macho_chained_arm64() -> Vec<u8> {
    // bl CHAINED_STUBS from CHAINED_TEXT (imm26 = 2); ret.
    let text = [0x02, 0x00, 0x00, 0x94, 0xC0, 0x03, 0x5F, 0xD6];
    // adrp x16, 0x11000 from the 0x10000 page (imm 1); ldr x16, [x16, #off].
    let adrp = [0x10u8, 0x00, 0x00, 0xB0];
    let br = [0x00u8, 0x02, 0x1F, 0xD6];
    let mut stubs = Vec::new();
    stubs.extend_from_slice(&adrp);
    stubs.extend_from_slice(&[0x10u8, 0x02, 0x40, 0xF9]); // ldr x16, [x16]
    stubs.extend_from_slice(&br);
    stubs.extend_from_slice(&adrp);
    stubs.extend_from_slice(&[0x10u8, 0x06, 0x40, 0xF9]); // ldr x16, [x16, #8]
    stubs.extend_from_slice(&br);
    macho_chained(0x0100_000C, &text, &stubs, 12)
}

/// x86-64 chained fixture: `__text` calls the first stub, each `__stubs`
/// entry is `jmp [rip+disp]` (stride 6).
fn macho_chained_x86_64() -> Vec<u8> {
    // call CHAINED_STUBS (rel 3); ret; nops.
    let text = [0xE8, 0x03, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90];
    let mut stubs = vec![0xFF, 0x25];
    stubs.extend_from_slice(&0xFF2u32.to_le_bytes()); // -> 0x11000
    stubs.extend_from_slice(&[0xFF, 0x25]);
    stubs.extend_from_slice(&0xFF4u32.to_le_bytes()); // -> 0x11008
    macho_chained(0x0100_0007, &text, &stubs, 6)
}

#[test]
fn chained_arm64_stubs_map_with_data_bind_unmapped() {
    let bin = load(&macho_chained_arm64()).expect("chained arm64 must load");
    assert_eq!(bin.format, BinaryFormat::MachO);
    assert_eq!(bin.arch, Arch::Aarch64);
    assert_eq!(
        bin.imports
            .iter()
            .map(|i| i.name.as_str())
            .collect::<Vec<_>>(),
        ["_foo", "_bar", "_baz"]
    );
    assert_eq!(bin.imports[0].library, "libSystem.B.dylib");
    assert_eq!(
        bin.imports.iter().map(|i| i.address).collect::<Vec<_>>(),
        [Some(CHAINED_STUBS), Some(CHAINED_STUBS + 12), None]
    );
}

#[test]
fn chained_x86_64_stubs_map_with_data_bind_unmapped() {
    let bin = load(&macho_chained_x86_64()).expect("chained x86-64 must load");
    assert_eq!(bin.format, BinaryFormat::MachO);
    assert_eq!(bin.arch, Arch::X86_64);
    assert_eq!(bin.imports.len(), 3);
    assert_eq!(
        bin.imports.iter().map(|i| i.address).collect::<Vec<_>>(),
        [Some(CHAINED_STUBS), Some(CHAINED_STUBS + 6), None]
    );
}

#[test]
fn chained_arm64_stubs_name_functions_and_tag_calls() {
    let bin = load(&macho_chained_arm64()).expect("chained arm64 must load");
    let analysis = analyze(&bin).expect("chained arm64 must analyze");
    for (stub, name) in [(CHAINED_STUBS, "_foo"), (CHAINED_STUBS + 12, "_bar")] {
        assert_eq!(
            analysis
                .functions
                .get(&stub)
                .expect("stub is a function")
                .name
                .as_deref(),
            Some(name),
            "stub {stub:#x} carries its import name"
        );
    }
    // The entry calls the first stub: the call row carries the import and
    // an Import xref runs caller -> stub entry.
    let entry = analysis
        .functions
        .get(&CHAINED_TEXT)
        .expect("entry is a function");
    let call = entry
        .blocks
        .values()
        .flat_map(|b| &b.insns)
        .find(|i| i.addr == CHAINED_TEXT)
        .expect("call row stored");
    assert_eq!(call.import.as_deref(), Some("_foo"));
    assert!(
        analysis
            .xrefs
            .iter()
            .any(|x| x.from == CHAINED_TEXT && x.to == CHAINED_STUBS && x.kind == XrefKind::Import),
        "caller -> stub Import xref"
    );
    // The stub's load still resolves to its GOT slot as a Data xref.
    assert!(
        analysis.xrefs.iter().any(|x| x.from == CHAINED_STUBS + 4
            && x.to == CHAINED_GOT
            && x.kind == XrefKind::Data),
        "stub ldr -> GOT Data xref"
    );
    // The data-only bind has no stub, no function, and no Import xref.
    assert!(!analysis.functions.contains_key(&(CHAINED_GOT + 16)));
    assert!(
        analysis
            .xrefs
            .iter()
            .all(|x| x.kind != XrefKind::Import || x.to != CHAINED_GOT + 16),
        "no Import xref targets the stub-less slot"
    );
}

#[test]
fn chained_unknown_pointer_format_maps_nothing() {
    // Bogus pointer format: the chain walk dies on the first entry, so no
    // slot resolves and every import stays unmapped — but the image still
    // loads with its imports listed.
    let mut f = macho_chained_arm64();
    // Builder layout (arm64): headers end at 32 + 544 = 576, __text is 8
    // bytes and the two 12-byte stubs 24, __DATA is 24 bytes, so the
    // payload starts at 632; the starts segment sits 44 in, with
    // pointer_format 6 past that.
    let fmt_off = 576 + 8 + 24 + 24 + 44 + 6;
    assert_eq!(&f[fmt_off..fmt_off + 2], &[2, 0], "PTR64 format field");
    f[fmt_off..fmt_off + 2].copy_from_slice(&99u16.to_le_bytes());
    let bin = load(&f).expect("bogus-format image must still load");
    assert_eq!(bin.imports.len(), 3);
    assert!(bin.imports.iter().all(|i| i.address.is_none()));
}

#[test]
fn macho_stub_jumps_are_not_unresolved() {
    let mut bad_all: Vec<(u64, u64)> = Vec::new();
    for (bytes, stride) in [
        (macho_chained_arm64(), 12u64),
        (macho_chained_x86_64(), 6u64),
    ] {
        let bin = load(&bytes).expect("chained fixture must load");
        let analysis = analyze(&bin).expect("chained fixture must analyze");
        let bad: Vec<u64> = analysis
            .diagnostics
            .records
            .iter()
            .filter(|d| d.kind == DiagnosticKind::UnresolvedIndirectJump)
            .map(|d| d.addr)
            .filter(|a| *a >= CHAINED_STUBS && *a < CHAINED_STUBS + 2 * stride)
            .collect();
        bad_all.extend(bad.into_iter().map(|a| (stride, a)));
    }
    assert!(
        bad_all.is_empty(),
        "stub-range indirect jumps stay unresolved: {bad_all:#x?}"
    );
}

#[test]
fn macho_header_symbol_is_not_seeded() {
    let mut code = vec![0x90u8; 0x20];
    code[0] = 0x06;
    code[0x10] = 0xC3;
    let bin = LoadedBinary {
        format: BinaryFormat::MachO,
        arch: Arch::X86_64,
        entry: None,
        segments: vec![Segment {
            vaddr: 0x1000,
            mem_size: code.len() as u64,
            data: code,
            readable: true,
            writable: false,
            executable: true,
        }],
        sections: Vec::new(),
        imports: Vec::new(),
        exports: vec![
            ExportRef {
                name: "__mh_execute_header".to_string(),
                address: Some(0x1000),
                ordinal: None,
                demangled: None,
            },
            ExportRef {
                name: "_real".to_string(),
                address: Some(0x1010),
                ordinal: None,
                demangled: None,
            },
        ],
        symbols: vec![SymbolRef {
            name: "__mh_execute_header".to_string(),
            address: 0x1000,
            demangled: None,
        }],
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        debug_funcs: Vec::new(),
        relocatable: false,
        arm_hints: Default::default(),
    };
    assert!(bin.exports.iter().any(|e| e.name == "__mh_execute_header"));
    assert!(bin.symbols.iter().any(|s| s.name == "__mh_execute_header"));
    let analysis = analyze(&bin).expect("header fixture must analyze");
    assert!(
        !analysis
            .diagnostics
            .records
            .iter()
            .any(|d| d.addr == 0x1000 && d.kind == DiagnosticKind::DecodeFailure),
        "image-base decode failure from the header symbol"
    );
    assert!(
        !analysis.functions.contains_key(&0x1000),
        "header symbol must not seed a function"
    );
    assert!(
        analysis.functions.contains_key(&0x1010),
        "ordinary export still seeds"
    );
}
