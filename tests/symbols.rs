//! Symbol-table discovery tests (EM6.1).
//!
//! Inline COFF builders (no checked-in blobs): a relocatable object with a
//! real symbol table drives `load` + `analyze` end to end. A static
//! function nothing calls is discovered and named only through its symbol;
//! naming precedence, the symbol cap, ARM Thumb-bit masking, and the
//! executable-section filter are pinned alongside.

mod common;

use binscout::analysis::{DiscoveryReason, analyze};
use binscout::disasm::Arch;
use binscout::error::Error;
use binscout::loader::{
    BinaryFormat, ExportRef, ImportRef, LoadedBinary, MAX_SYMBOLS, Section, Segment, SymbolRef,
    canonical_code_addr, load,
};

const TIMESTAMP: u32 = 0x1234_5678;
const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_ARMNT: u16 = 0x1C4;
const CLASS_EXTERNAL: u8 = 2;
const CLASS_STATIC: u8 = 3;
const TYPE_FUNCTION: u16 = 0x20;

struct CoffSym<'a> {
    name: &'a str,
    value: u32,
    section: u16,
    typ: u16,
    class: u8,
    aux_section_len: Option<u32>,
}

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

/// Minimal relocatable COFF: two sections (`.text` at VA 0, `.data` at VA
/// `0x1000`) plus a symbol table. All names fit the 8-byte inline field,
/// so the string table is just its length word.
fn coff_with_symbols(machine: u16, text: &[u8], data: &[u8], syms: &[CoffSym<'_>]) -> Vec<u8> {
    let nsec: u16 = 2;
    let text_off: usize = 20 + 2 * 40;
    let data_off: usize = text_off + text.len();
    let symtab_off: usize = data_off + data.len();

    let mut f = vec![0u8; symtab_off];
    put16(&mut f, 0, machine);
    put16(&mut f, 2, nsec);
    put32(&mut f, 4, TIMESTAMP);
    put32(&mut f, 8, symtab_off as u32);

    let mut nsyms: u32 = 0;
    let mut symtab: Vec<u8> = Vec::new();
    for s in syms {
        assert!(s.name.len() <= 8, "COFF inline name overflow");
        let mut e = vec![0u8; 18];
        e[..s.name.len()].copy_from_slice(s.name.as_bytes());
        put32(&mut e, 8, s.value);
        put16(&mut e, 12, s.section);
        put16(&mut e, 14, s.typ);
        e[16] = s.class;
        let has_aux = s.aux_section_len.is_some();
        if has_aux {
            e[17] = 1;
        }
        symtab.extend_from_slice(&e);
        nsyms += 1;
        if let Some(len) = s.aux_section_len {
            let mut aux = vec![0u8; 18];
            put32(&mut aux, 0, len);
            // `number` echoes the section index like real linkers emit.
            put16(&mut aux, 12, s.section);
            symtab.extend_from_slice(&aux);
            nsyms += 1;
        }
    }
    put32(&mut f, 12, nsyms);

    // `.text`: code, read+execute. `.data`: zeros, read+write.
    let mut sh =
        |idx: usize, name: &[u8], vsize: u32, vaddr: u32, raw: u32, off: usize, chars: u32| {
            let o = 20 + idx * 40;
            f[o..o + name.len()].copy_from_slice(name);
            put32(&mut f, o + 8, vsize);
            put32(&mut f, o + 12, vaddr);
            put32(&mut f, o + 16, raw);
            put32(&mut f, o + 20, off as u32);
            put32(&mut f, o + 36, chars);
        };
    sh(
        0,
        b".text",
        text.len() as u32,
        0,
        text.len() as u32,
        text_off,
        0x6000_0020,
    );
    sh(
        1,
        b".data",
        data.len() as u32,
        0x1000,
        data.len() as u32,
        data_off,
        0xC000_0040,
    );
    f[text_off..text_off + text.len()].copy_from_slice(text);
    f[data_off..data_off + data.len()].copy_from_slice(data);

    f.extend_from_slice(&symtab);
    f.extend_from_slice(&4u32.to_le_bytes()); // empty string table
    f
}

/// AMD64 object: global `efunc` at 0, static `sthelp` at 2 (called by
/// nothing), and `datalbl` carrying function type in non-executable
/// `.data` (must be filtered out).
fn coff_static_case() -> Vec<u8> {
    let text = [0x90, 0xC3, 0x90, 0x90, 0xC3, 0x00, 0x00, 0x00];
    let data = [0u8; 4];
    coff_with_symbols(
        MACHINE_AMD64,
        &text,
        &data,
        &[
            CoffSym {
                name: ".text",
                value: 0,
                section: 1,
                typ: 0,
                class: CLASS_STATIC,
                aux_section_len: Some(text.len() as u32),
            },
            CoffSym {
                name: "efunc",
                value: 0,
                section: 1,
                typ: TYPE_FUNCTION,
                class: CLASS_EXTERNAL,
                aux_section_len: None,
            },
            CoffSym {
                name: "sthelp",
                value: 2,
                section: 1,
                typ: TYPE_FUNCTION,
                class: CLASS_STATIC,
                aux_section_len: None,
            },
            CoffSym {
                name: ".data",
                value: 0,
                section: 2,
                typ: 0,
                class: CLASS_STATIC,
                aux_section_len: Some(data.len() as u32),
            },
            CoffSym {
                name: "datalbl",
                value: 0,
                section: 2,
                typ: TYPE_FUNCTION,
                class: CLASS_STATIC,
                aux_section_len: None,
            },
        ],
    )
}

#[test]
fn static_symbol_seeds_unnamed_function() {
    use binscout::loader::RELOC_BASE;
    let bin = load(&coff_static_case()).expect("symbol COFF must load");
    assert_eq!(bin.format, BinaryFormat::Coff);
    assert_eq!(bin.entry, None);
    assert!(bin.relocatable);
    // Section symbols and the non-executable `datalbl` stay out; the two
    // `.text` functions remain in table order at synthetic addresses.
    let addrs: Vec<(String, u64)> = bin
        .symbols
        .iter()
        .map(|s| (s.name.clone(), s.address))
        .collect();
    assert_eq!(
        addrs,
        [
            ("efunc".to_string(), RELOC_BASE),
            ("sthelp".to_string(), RELOC_BASE + 2)
        ]
    );

    // Nothing calls `sthelp`: without the symbol seed it would be one
    // unreachable prologue-less blob. The seed makes it a named entry.
    let a = analyze(&bin).expect("analysis must run");
    assert_eq!(a.functions.len(), 2);
    let entry = a.functions.get(&RELOC_BASE).expect("efunc entry");
    assert_eq!(entry.name.as_deref(), Some("efunc"));
    assert!(entry.reason_list().contains(&DiscoveryReason::Symbol));
    let helper = a.functions.get(&(RELOC_BASE + 2)).expect("static entry");
    assert_eq!(helper.name.as_deref(), Some("sthelp"));
    assert_eq!(helper.reason_list(), [DiscoveryReason::Symbol]);
}

#[test]
fn symbols_output_exposes_locals_with_hex_twins() {
    use binscout::loader::RELOC_BASE;
    let dir = common::tmpdir("symbols-output");
    let path = common::write_bin(&dir, "sym.obj", &coff_static_case());
    let db = common::temp_db(&dir, "sym");
    let p = binscout::Project::open_with_db(&path, &db).expect("fixture must open");
    let v = p.symbols_json();
    assert!(v["imports"].as_array().expect("imports").is_empty());
    assert!(v["exports"].as_array().expect("exports").is_empty());
    let rows = v["symbols"].as_array().expect("symbols array");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["name"], "efunc");
    assert_eq!(rows[0]["address"], RELOC_BASE);
    assert_eq!(rows[0]["address_hex"], "0x10000");
    assert_eq!(rows[1]["name"], "sthelp");
    assert_eq!(rows[1]["address"], RELOC_BASE + 2);
    assert_eq!(rows[1]["address_hex"], "0x10002");
    // Project display names resolve through the symbol table.
    assert_eq!(p.function_name(RELOC_BASE + 2).as_deref(), Some("sthelp"));
    common::cleanup(&dir);
}

#[test]
fn rename_still_wins_over_symbol_name() {
    use binscout::loader::RELOC_BASE;
    let dir = common::tmpdir("symbols-rename");
    let path = common::write_bin(&dir, "sym.obj", &coff_static_case());
    let db = common::temp_db(&dir, "sym");
    let mut p = binscout::Project::open_with_db(&path, &db).expect("fixture must open");
    p.rename_function(RELOC_BASE + 2, "custom")
        .expect("rename works");
    assert_eq!(p.function_name(RELOC_BASE + 2).as_deref(), Some("custom"));
    p.rename_function(RELOC_BASE + 2, "").expect("clear works");
    assert_eq!(p.function_name(RELOC_BASE + 2).as_deref(), Some("sthelp"));
    common::cleanup(&dir);
}

fn table_binary() -> LoadedBinary {
    // Three isolated `ret` slots; no calls, no prologues, no entry.
    let code = vec![0xC3u8; 0x30];
    LoadedBinary {
        format: BinaryFormat::Coff,
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
        sections: vec![Section {
            name: ".text".to_string(),
            vaddr: 0x1000,
            size: 0x30,
            file_off: 0,
            file_size: 0x30,
            entropy: 0.0,
            readable: true,
            writable: false,
            executable: true,
        }],
        imports: vec![ImportRef {
            library: "m".to_string(),
            name: "stub_imp".to_string(),
            ordinal: None,
            unresolved: false,
            demangled: None,
            address: Some(0x1020),
        }],
        exports: vec![ExportRef {
            name: "exp_name".to_string(),
            address: Some(0x1000),
            ordinal: None,
            demangled: None,
        }],
        symbols: vec![
            SymbolRef {
                name: "sym_shadowed".to_string(),
                address: 0x1000,
                demangled: None,
            },
            SymbolRef {
                name: "sym_named".to_string(),
                address: 0x1010,
                demangled: None,
            },
            SymbolRef {
                name: "sym_over_stub".to_string(),
                address: 0x1020,
                demangled: None,
            },
        ],
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        debug_funcs: Vec::new(),
        relocatable: false,
    }
}

#[test]
fn naming_precedence_is_export_over_symbol_over_stub() {
    let a = analyze(&table_binary()).expect("table binary must analyze");
    let at = |addr: u64| a.functions.get(&addr).expect("function must exist");
    // Export beats the symbol at the same address.
    assert_eq!(at(0x1000).name.as_deref(), Some("exp_name"));
    assert_eq!(
        at(0x1000).reason_list(),
        [DiscoveryReason::Export, DiscoveryReason::Symbol]
    );
    // A bare symbol names its function.
    assert_eq!(at(0x1010).name.as_deref(), Some("sym_named"));
    assert_eq!(at(0x1010).reason_list(), [DiscoveryReason::Symbol]);
    // Symbol beats the stub import name at the same address.
    assert_eq!(at(0x1020).name.as_deref(), Some("sym_over_stub"));
    assert!(at(0x1020).reason_list().contains(&DiscoveryReason::Symbol));
}

#[test]
fn symbol_cap_errors_past_max_unique_rows() {
    // MAX_SYMBOLS + 1 distinct executable addresses: the load must fail
    // with the symbols cap, not the metadata budget.
    let n = MAX_SYMBOLS + 1;
    let text = vec![0xC3u8; n + 1];
    let names: Vec<String> = (0..n).map(|i| format!("s{i}")).collect();
    let mut all = vec![CoffSym {
        name: ".text",
        value: 0,
        section: 1,
        typ: 0,
        class: CLASS_STATIC,
        aux_section_len: Some(text.len() as u32),
    }];
    all.extend(names.iter().enumerate().map(|(i, name)| CoffSym {
        name,
        value: i as u32,
        section: 1,
        typ: TYPE_FUNCTION,
        class: CLASS_STATIC,
        aux_section_len: None,
    }));
    let err = load(&coff_with_symbols(MACHINE_AMD64, &text, &[0u8; 4], &all)).unwrap_err();
    assert!(
        matches!(err, Error::Limit(_)),
        "over-cap symbols must be Limit, got {err:?}"
    );
    assert!(
        err.to_string().contains("symbols exceed cap"),
        "cap message must name symbols, got {err:?}"
    );
}

#[test]
fn thumb_bit_masks_arm_symbol_addresses() {
    assert_eq!(canonical_code_addr(Arch::Arm32, 0x1001), 0x1000);
    assert_eq!(canonical_code_addr(Arch::Arm32, 0x1000), 0x1000);
    for arch in [Arch::X86_64, Arch::X86_32, Arch::Aarch64, Arch::Thumb] {
        assert_eq!(canonical_code_addr(arch, 0x1001), 0x1001);
    }

    // ARM COFF object whose Thumb function links at an odd address: the
    // stored row, the seed, and the name all use the cleared address.
    let word = 0xE1A0_0000u32.to_le_bytes(); // mov r0, r0 (ARM nop)
    let text = [word, word].concat();
    let bin = load(&coff_with_symbols(
        MACHINE_ARMNT,
        &text,
        &[],
        &[
            CoffSym {
                name: ".text",
                value: 0,
                section: 1,
                typ: 0,
                class: CLASS_STATIC,
                aux_section_len: Some(text.len() as u32),
            },
            CoffSym {
                name: "tfunc",
                value: 5,
                section: 1,
                typ: TYPE_FUNCTION,
                class: CLASS_STATIC,
                aux_section_len: None,
            },
        ],
    ))
    .expect("ARM COFF must load");
    assert_eq!(bin.arch, Arch::Arm32);
    assert_eq!(bin.symbols.len(), 1);
    assert_eq!(bin.symbols[0].name, "tfunc");
    assert_eq!(bin.symbols[0].address, binscout::loader::RELOC_BASE + 4);
    let a = analyze(&bin).expect("ARM analysis must run");
    let f = a
        .functions
        .get(&(binscout::loader::RELOC_BASE + 4))
        .expect("masked entry must exist");
    assert_eq!(f.name.as_deref(), Some("tfunc"));
    assert_eq!(f.reason_list(), [DiscoveryReason::Symbol]);
}
