//! Mach-O stub-to-import mapping: `__stubs`/`__auth_stubs` entries resolve
//! through the indirect symbol table to an import of the same name, and any
//! doubt maps nothing (never misattributes).

mod common;

use binscout::analysis::analyze;
use binscout::disasm::Arch;
use binscout::loader::{BinaryFormat, ImportRef, LoadedBinary, Segment, load};

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
