//! M1 LE parser tests on synthetic minimal images (no external fixtures:
//! DOS4GW samples are license-unclean, so the harness builds LE files in
//! memory per the OS/2 LE layout).

mod common;

use binscout::disasm::{Arch, disasm_range};
use binscout::error::Error;
use binscout::loader::le::{LeFixup, LeTarget, is_le, parse_le};

const LE_OFF: usize = 0x40;
const CODE: [u8; 4] = [0x55, 0x89, 0xE5, 0xC3]; // push ebp; mov ebp,esp; ret

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

struct Opts {
    fixup_rec: Vec<u8>,
    entry: Vec<u8>,
    page_flags: u16,
    eip_obj: u32,
    eip: u32,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            fixup_rec: Vec::new(),
            // cnt=1, type=3 (32-bit), obj=1, flags=exported, off=0, terminator.
            entry: vec![0x01, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
            page_flags: 0,
            eip_obj: 1,
            eip: 0,
        }
    }
}

fn build(o: &Opts) -> Vec<u8> {
    let mut f = vec![0u8; LE_OFF];
    f[0] = b'M';
    f[1] = b'Z';
    put16(&mut f, 0x18, 0x40); // e_lfarlc: new-header stub, e_lfanew trusted
    put32(&mut f, 0x3C, LE_OFF as u32);

    let obj_rel = 0xAC;
    let page_rel = obj_rel + 24;
    let fp_rel = page_rel + 8;
    let fr_rel = fp_rel + 8;
    let entry_rel = fr_rel + o.fixup_rec.len();
    let code_rel = entry_rel + o.entry.len();

    f.resize(LE_OFF + code_rel + CODE.len(), 0);
    let h = LE_OFF;
    f[h] = b'L';
    f[h + 1] = b'E';
    put32(&mut f, h + 0x04, 0); // level
    put16(&mut f, h + 0x08, 2); // cpu 386
    put16(&mut f, h + 0x0A, 3); // os DOS4
    put32(&mut f, h + 0x14, 1); // pages
    put32(&mut f, h + 0x18, o.eip_obj);
    put32(&mut f, h + 0x1C, o.eip);
    put32(&mut f, h + 0x20, 1); // esp obj
    put32(&mut f, h + 0x24, 0x1000); // esp
    put32(&mut f, h + 0x28, 0x1000); // page size
    put32(&mut f, h + 0x2C, 0); // shift
    put32(&mut f, h + 0x30, 8 + o.fixup_rec.len() as u32); // fixup size
    put32(&mut f, h + 0x38, (code_rel - obj_rel) as u32); // loader size
    put32(&mut f, h + 0x40, obj_rel as u32);
    put32(&mut f, h + 0x44, 1);
    put32(&mut f, h + 0x48, page_rel as u32);
    put32(&mut f, h + 0x5C, entry_rel as u32);
    put32(&mut f, h + 0x68, fp_rel as u32);
    put32(&mut f, h + 0x6C, fr_rel as u32);
    put32(&mut f, h + 0x80, (LE_OFF + code_rel) as u32); // data pages
    put32(&mut f, h + 0x84, 1);

    let p = LE_OFF + obj_rel;
    put32(&mut f, p, 0x1000); // virt size
    put32(&mut f, p + 4, 0x10000); // reloc base
    put32(&mut f, p + 8, 0x2005); // R-X + big
    put32(&mut f, p + 12, 1); // page index
    put32(&mut f, p + 16, 1); // page count

    let p = LE_OFF + page_rel;
    put32(&mut f, p, 0); // raw offset (at data base)
    put16(&mut f, p + 4, CODE.len() as u16);
    put16(&mut f, p + 6, o.page_flags);

    let p = LE_OFF + fp_rel;
    put32(&mut f, p, 0);
    put32(&mut f, p + 4, o.fixup_rec.len() as u32);

    f[LE_OFF + fr_rel..LE_OFF + fr_rel + o.fixup_rec.len()].copy_from_slice(&o.fixup_rec);
    f[LE_OFF + entry_rel..LE_OFF + entry_rel + o.entry.len()].copy_from_slice(&o.entry);
    f[LE_OFF + code_rel..].copy_from_slice(&CODE);
    f
}

fn minimal() -> Vec<u8> {
    build(&Opts::default())
}

#[test]
fn minimal_parses_and_maps_segments() {
    let img = parse_le(&minimal()).expect("synthetic LE must parse");
    assert_eq!(img.page_size, 0x1000);
    assert_eq!(img.cpu, 2);
    assert_eq!(img.objects.len(), 1);
    assert_eq!(img.objects[0].reloc_base, 0x10000);
    assert!(img.objects[0].readable && img.objects[0].executable);
    assert!(!img.objects[0].writable);

    assert_eq!(img.segments.len(), 1);
    let s = &img.segments[0];
    assert_eq!(s.vaddr, 0x10000);
    assert_eq!(s.mem_size, 0x1000);
    assert_eq!(s.data.len(), 0x1000);
    assert_eq!(&s.data[..4], &CODE);
    assert!(s.data[4..].iter().all(|b| *b == 0));

    assert_eq!(img.entry, Some(0x10000));
    assert!(img.fixups.is_empty());
    assert_eq!(img.entries.len(), 1);
    assert_eq!(img.entries[0].ordinal, 1);
    assert_eq!(img.entries[0].object, 1);
    assert_eq!(img.entries[0].offset, 0);
    assert!(img.entries[0].exported);
    assert_eq!(img.arch(), Arch::X86_32);
}

#[test]
fn segment_code_disassembles_as_x86_32() {
    let img = parse_le(&minimal()).expect("synthetic LE must parse");
    let v = disasm_range(Arch::X86_32, &img.segments[0].data[..4], 0x10000, 100)
        .expect("LE code must decode");
    assert_eq!(
        v.iter().map(|i| i.mnem.as_str()).collect::<Vec<_>>(),
        ["push", "mov", "ret"]
    );
}

#[test]
fn fixup_records_walk_internal_additive_and_list() {
    // rec1: 32-bit offset @0 -> internal obj1+0.
    // rec2: 32-bit offset @4 (+0x10 additive) -> internal obj1+8.
    // rec3: source list [4, 8] -> internal obj1+0.
    let rec = vec![
        0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // rec1
        0x07, 0x04, 0x04, 0x00, 0x01, 0x08, 0x00, 0x10, 0x00, // rec2
        0x27, 0x00, 0x02, 0x01, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, // rec3
    ];
    let img = parse_le(&build(&Opts {
        fixup_rec: rec,
        ..Opts::default()
    }))
    .expect("LE with fixups must parse");
    assert_eq!(
        img.fixups,
        [
            LeFixup {
                page: 1,
                sources: vec![0],
                target: LeTarget::Internal {
                    object: 1,
                    offset: 0
                },
                additive: None,
            },
            LeFixup {
                page: 1,
                sources: vec![4],
                target: LeTarget::Internal {
                    object: 1,
                    offset: 8
                },
                additive: Some(0x10),
            },
            LeFixup {
                page: 1,
                sources: vec![4, 8],
                target: LeTarget::Internal {
                    object: 1,
                    offset: 0
                },
                additive: None,
            },
        ]
    );
}

#[test]
fn zero_page_materializes_zeros() {
    let img = parse_le(&build(&Opts {
        page_flags: 3,
        ..Opts::default()
    }))
    .expect("zero page must parse");
    assert_eq!(img.segments[0].data.len(), 0x1000);
    assert!(img.segments[0].data.iter().all(|b| *b == 0));
}

#[test]
fn no_entry_object_gives_none() {
    let img = parse_le(&build(&Opts {
        eip_obj: 0,
        ..Opts::default()
    }))
    .expect("library-style LE must parse");
    assert_eq!(img.entry, None);
}

#[test]
fn is_le_detection() {
    assert!(is_le(&minimal()));
    assert!(!is_le(&[]));
    assert!(!is_le(&[0u8; 0x40]));
    let mut bad = minimal();
    bad[LE_OFF] = b'X';
    assert!(!is_le(&bad));
}

fn invalid(img: &[u8]) -> String {
    let err = parse_le(img).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
    err.to_string()
}

#[test]
fn malformed_inputs_are_invalid() {
    assert!(matches!(parse_le(&[]).unwrap_err(), Error::Invalid(_)));
    // Truncated header.
    invalid(&minimal()[..0x50]);
    // Bad magic.
    let mut bad = minimal();
    bad[LE_OFF] = b'X';
    invalid(&bad);
    // e_lfanew out of range with no scan candidate left intact.
    let mut bad = minimal();
    put32(&mut bad, 0x3C, 0xFFFF);
    bad[LE_OFF] = b'X';
    invalid(&bad);
    // Object table out of range.
    let mut bad = minimal();
    put32(&mut bad, LE_OFF + 0x40, 0x5000);
    invalid(&bad);
    // Entry object out of range / offset beyond object.
    invalid(&build(&Opts {
        eip_obj: 5,
        ..Opts::default()
    }));
    invalid(&build(&Opts {
        eip: 0x1000,
        ..Opts::default()
    }));
    // Fixup page table decreasing.
    let mut bad = minimal();
    put32(&mut bad, LE_OFF + 0xCC, 3);
    invalid(&bad);
    // Unknown entry bundle type.
    invalid(&build(&Opts {
        entry: vec![0x01, 0x09, 0x00],
        ..Opts::default()
    }));
    // Truncated fixup record.
    invalid(&build(&Opts {
        fixup_rec: vec![0x07, 0x00],
        ..Opts::default()
    }));
    // Unknown fixup source type.
    invalid(&build(&Opts {
        fixup_rec: vec![0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00],
        ..Opts::default()
    }));
    // Truncated code page.
    let full = minimal();
    invalid(&full[..full.len() - 2]);
}

#[test]
fn forwarders_are_unsupported_not_misparsed() {
    let err = parse_le(&build(&Opts {
        entry: vec![0x01, 0x04, 0x00, 0x00, 0x00],
        ..Opts::default()
    }))
    .unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
}

#[test]
fn non_x86_cpu_is_unsupported() {
    let mut bad = minimal();
    put16(&mut bad, LE_OFF + 0x08, 9);
    let err = parse_le(&bad).unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
}

/// LE with import tables between the fixup records and the entry table.
///
/// `fixup_size` covers records + both name tables so the procedure table
/// ends exactly at the fixup-section end (`parse_le` derives
/// `section_end` that way); module names run `mod_abs..proc_abs` and
/// procedure names `proc_abs..section_end`.
fn build_with_imports(
    fixup_rec: &[u8],
    mod_table: &[u8],
    proc_table: &[u8],
    imp_count: u32,
) -> Vec<u8> {
    let entry: Vec<u8> = vec![0x01, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut f = vec![0u8; LE_OFF];
    f[0] = b'M';
    f[1] = b'Z';
    put16(&mut f, 0x18, 0x40); // e_lfarlc: new-header stub, e_lfanew trusted
    put32(&mut f, 0x3C, LE_OFF as u32);

    let obj_rel = 0xAC;
    let page_rel = obj_rel + 24;
    let fp_rel = page_rel + 8;
    let fr_rel = fp_rel + 8;
    let mod_rel = fr_rel + fixup_rec.len();
    let proc_rel = mod_rel + mod_table.len();
    let entry_rel = proc_rel + proc_table.len();
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
    put32(
        &mut f,
        h + 0x30,
        (8 + fixup_rec.len() + mod_table.len() + proc_table.len()) as u32,
    );
    put32(&mut f, h + 0x38, (code_rel - obj_rel) as u32);
    put32(&mut f, h + 0x40, obj_rel as u32);
    put32(&mut f, h + 0x44, 1);
    put32(&mut f, h + 0x48, page_rel as u32);
    put32(&mut f, h + 0x5C, entry_rel as u32);
    put32(&mut f, h + 0x68, fp_rel as u32);
    put32(&mut f, h + 0x6C, fr_rel as u32);
    put32(&mut f, h + 0x70, mod_rel as u32);
    put32(&mut f, h + 0x74, imp_count);
    put32(&mut f, h + 0x78, proc_rel as u32);
    put32(&mut f, h + 0x80, (LE_OFF + code_rel) as u32);
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
    f[LE_OFF + mod_rel..LE_OFF + mod_rel + mod_table.len()].copy_from_slice(mod_table);
    f[LE_OFF + proc_rel..LE_OFF + proc_rel + proc_table.len()].copy_from_slice(proc_table);
    f[LE_OFF + entry_rel..LE_OFF + entry_rel + entry.len()].copy_from_slice(&entry);
    f[LE_OFF + code_rel..].copy_from_slice(&CODE);
    f
}

#[test]
fn import_names_ending_exactly_at_boundary_parse() {
    // Every name ends exactly at its table end: all names and order kept.
    let img = parse_le(&build_with_imports(
        &[],
        &[1, b'a', 1, b'b'],
        &[1, b'c', 2, b'd', b'e'],
        2,
    ))
    .expect("boundary-exact import tables must parse");
    assert_eq!(img.import_modules, ["a", "b"]);
    assert_eq!(img.import_procs, ["c", "de"]);
}

#[test]
fn import_name_crossing_into_next_table_is_invalid() {
    // Module name declares 5 bytes but only 1 (`X`) lives in the module
    // table; the bytes stay in the file (procedure table `abc` follows),
    // so only a table-end check rejects it.
    let err = parse_le(&build_with_imports(
        &[],
        &[5, b'X'],
        &[3, b'a', b'b', b'c'],
        1,
    ))
    .unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "cross-table name must be invalid, got {err:?}"
    );
    assert!(
        err.to_string().contains("crosses table boundary"),
        "unexpected message: {err:?}"
    );
}

#[test]
fn zero_length_name_parses_and_empty_module_table_mismatches() {
    // Zero-length entry is valid and preserved.
    let img = parse_le(&build_with_imports(&[], &[0], &[], 1))
        .expect("zero-length import name must parse");
    assert_eq!(img.import_modules, [""]);
    assert!(img.import_procs.is_empty());
    // Empty module table yields no names, so the count check fails
    // (Invalid, no panic) instead of reading into the next table.
    let err = parse_le(&build_with_imports(&[], &[], &[1, b'z'], 1)).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "empty module table must be invalid, got {err:?}"
    );
}

#[test]
fn truncated_import_name_data_is_invalid() {
    // Module name claims 3 bytes but only 1 precedes the procedure table.
    let err = parse_le(&build_with_imports(&[], &[3, b'a'], &[1, b'z'], 1)).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "truncated import name must be invalid, got {err:?}"
    );
}

#[test]
fn truncated_file_with_imports_is_invalid_without_panic() {
    let mut full = build_with_imports(&[], &[3, b'f', b'o', b'o'], &[3, b'b', b'a', b'r'], 1);
    full.truncate(full.len() - 2);
    let err = parse_le(&full).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "truncated LE must be invalid, got {err:?}"
    );
}

#[test]
fn malformed_import_tables_stay_explicitly_unsupported_at_project_level() {
    let dir = common::tmpdir("le-import-boundary");
    let bytes = build_with_imports(&[], &[5, b'X'], &[3, b'a', b'b', b'c'], 1);
    assert!(is_le(&bytes));
    let bin = common::write_bin(&dir, "cross-table-le.bin", &bytes);
    let db = common::temp_db(&dir, "cross-table-le");
    let err = binscout::Project::open_with_db(&bin, &db).unwrap_err();
    assert!(
        matches!(err, Error::Unsupported(_)),
        "recognized LE must stay unsupported, never raw fallback: got {err:?}"
    );
    assert!(!db.exists(), "unsupported open must not create a sidecar");
    common::cleanup(&dir);
}
