//! LE import dedupe: `convert_le` keeps first-occurrence order while the
//! identity index replaces the `Vec::contains` scan.

use binscout::loader::{
    ImportRef, MAX_IMPORTS, Segment, convert_le,
    le::{LeFixup, LeImage, LeObject, LeTarget},
    load,
};

fn ord(module: u32, ordinal: u32) -> LeFixup {
    LeFixup {
        page: 1,
        sources: vec![0],
        target: LeTarget::ImportOrdinal { module, ordinal },
        additive: None,
    }
}

fn named(module: u32, name_offset: u32) -> LeFixup {
    LeFixup {
        page: 1,
        sources: vec![0],
        target: LeTarget::ImportName {
            module,
            name_offset,
        },
        additive: None,
    }
}

fn internal() -> LeFixup {
    LeFixup {
        page: 1,
        sources: vec![0],
        target: LeTarget::Internal {
            object: 1,
            offset: 0,
        },
        additive: None,
    }
}

fn entry_fix() -> LeFixup {
    LeFixup {
        page: 1,
        sources: vec![0],
        target: LeTarget::Entry { ordinal: 1 },
        additive: None,
    }
}

fn imp(library: &str, name: &str, ordinal: Option<u32>, unresolved: bool) -> ImportRef {
    ImportRef {
        library: library.to_string(),
        name: name.to_string(),
        ordinal,
        unresolved,
        demangled: None,
    }
}

fn test_img(modules: Vec<&str>, fixups: Vec<LeFixup>) -> LeImage {
    LeImage {
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
        fixups,
        entries: Vec::new(),
        import_modules: modules.into_iter().map(str::to_string).collect(),
        import_procs: Vec::new(),
    }
}

fn resolve(modules: &[String], module: u32) -> String {
    module
        .checked_sub(1)
        .and_then(|i| modules.get(i as usize))
        .cloned()
        .unwrap_or_else(|| format!("mod#{module}"))
}

/// Pre-index reference: the old `Vec::contains` behavior, cap break included.
fn naive_imports(modules: &[String], fixups: &[LeFixup]) -> Vec<ImportRef> {
    let mut imports = Vec::new();
    for fix in fixups {
        let imp = match &fix.target {
            LeTarget::Internal { .. } | LeTarget::Entry { .. } => continue,
            LeTarget::ImportOrdinal { module, ordinal } => imp(
                &resolve(modules, *module),
                &format!("#{ordinal}"),
                Some(*ordinal),
                true,
            ),
            LeTarget::ImportName {
                module,
                name_offset,
            } => imp(
                &resolve(modules, *module),
                &format!("@{name_offset:#x}"),
                None,
                false,
            ),
        };
        if !imports.contains(&imp) {
            imports.push(imp);
        }
        if imports.len() >= MAX_IMPORTS {
            break;
        }
    }
    imports
}

#[test]
fn mixed_fixups_keep_first_occurrence_order() {
    let modules = vec!["KERNEL".to_string(), "USER".to_string()];
    let fixups = vec![
        internal(),
        ord(1, 7),
        named(1, 0x10),
        ord(1, 7),
        ord(2, 7),
        named(2, 0x10),
        ord(1, 9),
        entry_fix(),
        named(1, 0x10),
        // Same numeric id as the `@0x10` name fixup, but an ordinal kind:
        // `#16` must stay a distinct row.
        ord(1, 16),
    ];
    let bin = convert_le(test_img(vec!["KERNEL", "USER"], fixups.clone()));
    assert_eq!(
        bin.imports,
        vec![
            imp("KERNEL", "#7", Some(7), true),
            imp("KERNEL", "@0x10", None, false),
            imp("USER", "#7", Some(7), true),
            imp("USER", "@0x10", None, false),
            imp("KERNEL", "#9", Some(9), true),
            imp("KERNEL", "#16", Some(16), true),
        ]
    );
    assert_eq!(bin.imports, naive_imports(&modules, &fixups));
}

#[test]
fn duplicate_module_names_at_distinct_indices_dedupe() {
    let modules = vec!["KERNEL".to_string(), "KERNEL".to_string()];
    let fixups = vec![ord(1, 7), ord(2, 7), named(1, 0x20), named(2, 0x20)];
    let bin = convert_le(test_img(vec!["KERNEL", "KERNEL"], fixups.clone()));
    assert_eq!(
        bin.imports,
        vec![
            imp("KERNEL", "#7", Some(7), true),
            imp("KERNEL", "@0x20", None, false),
        ]
    );
    assert_eq!(bin.imports, naive_imports(&modules, &fixups));
}

#[test]
fn fallback_name_colliding_with_real_library_dedupes() {
    let modules = vec!["mod#2".to_string()];
    // Module 2 is out of range so it falls back to `mod#2`, colliding with
    // the real module-1 name; module 0 and 3 exercise other fallbacks.
    let fixups = vec![ord(2, 5), ord(1, 5), ord(3, 5), ord(1, 6), ord(0, 5)];
    let bin = convert_le(test_img(vec!["mod#2"], fixups.clone()));
    assert_eq!(
        bin.imports,
        vec![
            imp("mod#2", "#5", Some(5), true),
            imp("mod#3", "#5", Some(5), true),
            imp("mod#2", "#6", Some(6), true),
            imp("mod#0", "#5", Some(5), true),
        ]
    );
    assert_eq!(bin.imports, naive_imports(&modules, &fixups));
}

#[test]
fn heavily_duplicated_single_import_stays_single() {
    let modules = vec!["M".to_string()];
    let mut fixups = vec![ord(1, 42), named(1, 0x30)];
    fixups.extend((0..50_000).map(|i| {
        if i % 2 == 0 {
            ord(1, 42)
        } else {
            named(1, 0x30)
        }
    }));
    let bin = convert_le(test_img(vec!["M"], fixups.clone()));
    assert_eq!(
        bin.imports,
        vec![
            imp("M", "#42", Some(42), true),
            imp("M", "@0x30", None, false),
        ]
    );
    assert_eq!(bin.imports, naive_imports(&modules, &fixups));
}

#[test]
fn cap_breaks_at_max_imports_preserving_first_occurrence() {
    let mut fixups = Vec::with_capacity(MAX_IMPORTS + 1000);
    for i in 0..MAX_IMPORTS as u32 {
        fixups.push(LeFixup {
            page: 1,
            sources: Vec::new(),
            target: LeTarget::ImportOrdinal {
                module: 1,
                ordinal: i,
            },
            additive: None,
        });
    }
    // Uniques past the cap plus duplicates of early rows: all must be
    // ignored once the break fires, with no error.
    for i in MAX_IMPORTS as u32..MAX_IMPORTS as u32 + 500 {
        fixups.push(ord(1, i));
    }
    for i in 0..500u32 {
        fixups.push(ord(1, i));
    }
    let bin = convert_le(test_img(vec!["M"], fixups));
    assert_eq!(bin.imports.len(), MAX_IMPORTS);
    assert_eq!(bin.imports[0], imp("M", "#0", Some(0), true));
    assert_eq!(
        bin.imports[MAX_IMPORTS - 1],
        imp(
            "M",
            &format!("#{}", MAX_IMPORTS - 1),
            Some(MAX_IMPORTS as u32 - 1),
            true
        )
    );
    assert!(
        bin.imports
            .iter()
            .all(|i| i.name != format!("#{MAX_IMPORTS}")),
        "post-cap rows must not surface"
    );
}

// Minimal LE builder for the bytes-to-imports path (`load`), mirroring the
// synthetic harness in `tests/loader_le.rs`: one object/page, no import
// tables (modules resolve to the `mod#N` fallback).
const LE_OFF: usize = 0x40;
const CODE: [u8; 4] = [0x55, 0x89, 0xE5, 0xC3];

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn build_le(fixup_rec: &[u8]) -> Vec<u8> {
    let entry = [0x01, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut f = vec![0u8; LE_OFF];
    f[0] = b'M';
    f[1] = b'Z';
    put32(&mut f, 0x3C, LE_OFF as u32);

    let obj_rel = 0xAC;
    let page_rel = obj_rel + 24;
    let fp_rel = page_rel + 8;
    let fr_rel = fp_rel + 8;
    let entry_rel = fr_rel + fixup_rec.len();
    let code_rel = entry_rel + entry.len();

    f.resize(LE_OFF + code_rel + CODE.len(), 0);
    let h = LE_OFF;
    f[h] = b'L';
    f[h + 1] = b'E';
    put32(&mut f, h + 0x04, 0);
    put16(&mut f, h + 0x08, 2);
    put16(&mut f, h + 0x0A, 3);
    put32(&mut f, h + 0x14, 1);
    put32(&mut f, h + 0x18, 1);
    put32(&mut f, h + 0x1C, 0);
    put32(&mut f, h + 0x20, 1);
    put32(&mut f, h + 0x24, 0x1000);
    put32(&mut f, h + 0x28, 0x1000);
    put32(&mut f, h + 0x2C, 0);
    put32(&mut f, h + 0x30, 8 + fixup_rec.len() as u32);
    put32(&mut f, h + 0x38, (code_rel - obj_rel) as u32);
    put32(&mut f, h + 0x40, obj_rel as u32);
    put32(&mut f, h + 0x44, 1);
    put32(&mut f, h + 0x48, page_rel as u32);
    put32(&mut f, h + 0x5C, entry_rel as u32);
    put32(&mut f, h + 0x68, fp_rel as u32);
    put32(&mut f, h + 0x6C, fr_rel as u32);
    put32(&mut f, h + 0x80, code_rel as u32);
    put32(&mut f, h + 0x84, 1);

    let p = LE_OFF + obj_rel;
    put32(&mut f, p, 0x1000);
    put32(&mut f, p + 4, 0x10000);
    put32(&mut f, p + 8, 0x2005);
    put32(&mut f, p + 12, 1);
    put32(&mut f, p + 16, 1);

    let p = LE_OFF + page_rel;
    put32(&mut f, p, 0);
    put16(&mut f, p + 4, CODE.len() as u16);
    put16(&mut f, p + 6, 0);

    let p = LE_OFF + fp_rel;
    put32(&mut f, p, 0);
    put32(&mut f, p + 4, fixup_rec.len() as u32);

    f[LE_OFF + fr_rel..LE_OFF + fr_rel + fixup_rec.len()].copy_from_slice(fixup_rec);
    f[LE_OFF + entry_rel..LE_OFF + entry_rel + entry.len()].copy_from_slice(&entry);
    f[LE_OFF + code_rel..].copy_from_slice(&CODE);
    f
}

#[test]
fn load_maps_le_import_fixups_to_ordered_imports() {
    // Two 32-bit import-ordinal records (module 1, ordinals 7 and 9), each
    // repeated once: `src=0x07, flags=0x01, off:u16, mod:u8, ord:u16le`.
    let rec = [
        0x07, 0x01, 0x00, 0x00, 0x01, 0x07, 0x00, //
        0x07, 0x01, 0x00, 0x00, 0x01, 0x07, 0x00, //
        0x07, 0x01, 0x01, 0x00, 0x01, 0x09, 0x00, //
    ];
    let bin = load(&build_le(&rec)).expect("synthetic LE must load");
    assert_eq!(
        bin.imports,
        vec![
            imp("mod#1", "#7", Some(7), true),
            imp("mod#1", "#9", Some(9), true),
        ]
    );
}
