//! Debug-info names and bounds: embedded DWARF plus explicit `--pdb` /
//! `--debug-file` inputs.
//!
//! DWARF (`DW_TAG_subprogram` `low_pc`/`high_pc` + name) and PDB (public and
//! procedure symbols) seed exact function starts and names for free; type
//! recovery (`TypeHint`) is a later pass and intentionally out of scope.
//! Both sources are local files only: `--pdb` and `--debug-file` open a
//! filesystem path, never a URL, and no fetch is ever attempted.
//!
//! Budgets: DWARF sections borrow the object bytes (no copy except capped
//! decompression of compressed sections); DIE and PDB symbol streams
//! truncate at [`MAX_DEBUG_FUNCS`], keeping the table-ordered prefix like
//! the `.pdata`/`LC_FUNCTION_STARTS` collectors. A corrupt embedded section
//! truncates that source (the binary still analyzes); an explicit
//! `--debug-file` without DWARF sections or a `--pdb` that fails to parse
//! errors, so a mistyped path fails loudly instead of silently analyzing
//! without names.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use fallible_iterator::FallibleIterator as _;
use object::{Object, ObjectSection};

use super::{
    BinaryFormat, MAX_MAPPED_BYTES, MAX_NAME_BYTES, Section, Segment, account_meta,
    canonical_code_addr, decode_owned_name, demangle_bounded,
};
use crate::disasm::Arch;
use crate::error::{Error, Result};

/// Cap on collected debug functions per binary.
///
/// Matches [`super::MAX_SYMBOLS`]: one row per function, bounded like any
/// other table-derived seed source. Sources beyond the cap truncate, keeping
/// the table-ordered prefix.
pub const MAX_DEBUG_FUNCS: usize = 100_000;
/// Cap on visited DWARF DIEs per object.
///
/// Bounds the per-open scan on huge debug binaries: DIE visits are cheap but
/// unbounded in aggregate, so iteration stops past the cap keeping the
/// prefix (compile-unit order).
pub const MAX_DEBUG_DIES: u64 = 2_000_000;

/// One debug-info function: a start address with an optional exact end.
///
/// `name` is `None` for nameless subprograms (still useful seeds); `end` is
/// `None` when the source names no bound (PDB publics, `low_pc`-only DIEs,
/// range-list `high_pc` forms, which this pass does not resolve).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugFunc {
    /// Function name as recorded (`DW_AT_linkage_name` preferred over
    /// `DW_AT_name`; PDB procedure/public name), if any.
    pub name: Option<String>,
    /// Canonical code address (Thumb bit cleared on ARM, see
    /// [`canonical_code_addr`]).
    pub address: u64,
    /// Exclusive end address, when the source states one.
    pub end: Option<u64>,
}

/// One explicit debug file: bytes plus the flag rendering for errors.
#[derive(Debug, Clone, Default)]
pub struct DebugFile {
    /// File contents (capped at [`super::MAX_INPUT_BYTES`] by the caller).
    pub bytes: Vec<u8>,
    /// Flag rendering for errors (e.g. `--pdb path/to/x.pdb`).
    pub label: String,
}

/// Explicit debug inputs for a container open.
///
/// `pdb` needs a PE image (RVA to VA via the image base); `external` is any
/// linked DWARF-bearing object (a dSYM DWARF file or an unstripped copy)
/// whose addresses already live in the target VA space. Raw `.dwo`
/// (split-DWARF objects) are out of scope: their addresses are
/// section-relative, not linked VAs.
#[derive(Debug, Clone, Default)]
pub struct DebugInputs {
    /// PDB bytes for `--pdb` (PE only).
    pub pdb: Option<DebugFile>,
    /// External DWARF object bytes for `--debug-file` (any container).
    pub external: Option<DebugFile>,
}

impl DebugInputs {
    /// No explicit debug files.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// True when neither `--pdb` nor `--debug-file` is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pdb.is_none() && self.external.is_none()
    }
}

/// Collect debug functions for a parsed container: embedded DWARF, then the
/// `--debug-file` object, then `--pdb` symbols.
///
/// Starts keep collection order (embedded, external, PDB); duplicates by
/// address keep the first row. Only starts landing in an executable range
/// survive, and output stops at [`MAX_DEBUG_FUNCS`]. `--pdb` on a non-PE
/// container errors; relocatable objects never reach this path with debug
/// info (their section-relative DWARF addresses do not map onto the
/// synthetic layout).
///
/// # Errors
/// [`Error::Invalid`] when `--pdb` names a non-PE binary or fails to parse,
/// or when `--debug-file` parses but carries no DWARF sections;
/// [`Error::Limit`] when owned name bytes exceed the metadata budget.
#[allow(
    clippy::too_many_arguments,
    reason = "loader plumbing: parsed file plus bytes, format, arch, tables, inputs, budgets"
)]
pub fn collect_debug_funcs<'a>(
    file: &object::File<'a, &'a [u8]>,
    obj_bytes: &[u8],
    format: BinaryFormat,
    arch: Arch,
    sections: &[Section],
    segments: &[Segment],
    debug: &DebugInputs,
    meta: &mut u64,
) -> Result<Vec<DebugFunc>> {
    let mut raw: Vec<DebugFunc> = Vec::new();
    raw.extend(dwarf_in_object(file, "embedded DWARF", arch, meta)?);
    if let Some(ext) = &debug.external {
        let ext_file = object::File::parse(ext.bytes.as_slice())
            .map_err(|e| Error::Invalid(format!("{}: not an object: {e}", ext.label)))?;
        if !has_dwarf_sections(&ext_file) {
            return Err(Error::Invalid(format!("{}: no DWARF sections", ext.label)));
        }
        raw.extend(dwarf_in_object(&ext_file, &ext.label, arch, meta)?);
    }
    if let Some(pdb) = &debug.pdb {
        if format != BinaryFormat::Pe {
            return Err(Error::Invalid(format!(
                "{}: PDB input needs a PE binary, got {}",
                pdb.label,
                format_name(format)
            )));
        }
        raw.extend(pdb_funcs(obj_bytes, pdb, arch, meta)?);
    }
    Ok(finalize(raw, sections, segments))
}

/// Keep executable-range starts, deduplicated by address, capped.
///
/// Dedupe keeps the first row (embedded DWARF wins over `--debug-file`,
/// which wins over PDB); output stops at [`MAX_DEBUG_FUNCS`].
pub fn finalize(
    funcs: Vec<DebugFunc>,
    sections: &[Section],
    segments: &[Segment],
) -> Vec<DebugFunc> {
    let ranges = super::merged_exec_ranges(sections, segments);
    let in_exec = |addr: u64| ranges.iter().any(|(lo, hi)| addr >= *lo && addr < *hi);
    let mut seen: HashSet<u64> = HashSet::new();
    let mut out: Vec<DebugFunc> = Vec::new();
    for f in funcs {
        if out.len() >= MAX_DEBUG_FUNCS {
            break;
        }
        if !in_exec(f.address) || !seen.insert(f.address) {
            continue;
        }
        out.push(f);
    }
    out
}

/// Short container name for `--pdb`-on-wrong-format errors.
fn format_name(format: BinaryFormat) -> &'static str {
    match format {
        BinaryFormat::Elf => "ELF",
        BinaryFormat::Pe => "PE",
        BinaryFormat::MachO => "Mach-O",
        BinaryFormat::Coff => "COFF",
        BinaryFormat::Le => "LE",
        BinaryFormat::Raw => "raw",
    }
}

/// True when the object carries a `.debug_info` section.
fn has_dwarf_sections<'a>(file: &object::File<'a, &'a [u8]>) -> bool {
    file.section_by_name(".debug_info").is_some()
}

/// Collect `DW_TAG_subprogram` starts/names/bounds from object bytes.
///
/// Best-effort: a corrupt section or DIE stream truncates the source
/// (keeping the prefix), so debug info never breaks analysis of a parseable
/// binary. `DW_AT_high_pc` range-list forms need `.debug_ranges`
/// resolution and stay `None`; raw `.dwo` addresses are section-relative
/// and never match linked VAs, so skeleton-only CUs contribute nothing.
///
/// # Errors
/// [`Error::Invalid`] when the bytes are not an object; [`Error::Limit`]
/// when a debug name or section exceeds its budget.
pub fn dwarf_funcs(
    obj_bytes: &[u8],
    label: &str,
    arch: Arch,
    meta: &mut u64,
) -> Result<Vec<DebugFunc>> {
    let file = object::File::parse(obj_bytes)
        .map_err(|e| Error::Invalid(format!("{label}: not an object: {e}")))?;
    dwarf_in_object(&file, label, arch, meta)
}

/// [`dwarf_funcs`] over an already-parsed object.
///
/// # Errors
/// Same as [`dwarf_funcs`].
fn dwarf_in_object<'a>(
    file: &object::File<'a, &'a [u8]>,
    label: &str,
    arch: Arch,
    meta: &mut u64,
) -> Result<Vec<DebugFunc>> {
    use gimli::{EndianSlice, RunTimeEndian, SectionId};

    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    // Borrow section bytes (zero-copy); compressed sections decompress under
    // a cap. Missing sections read as empty, which gimli treats as absent.
    let mut sections: HashMap<&'static str, Cow<'_, [u8]>> = HashMap::new();
    for name in [
        ".debug_info",
        ".debug_abbrev",
        ".debug_str",
        ".debug_str_offsets",
        ".debug_addr",
        ".debug_line_str",
    ] {
        if let Some(section) = file.section_by_name(name) {
            sections.insert(name, section_data_capped(&section, label)?);
        }
    }
    let dwarf = gimli::Dwarf::load(
        |id: SectionId| -> std::result::Result<EndianSlice<RunTimeEndian>, gimli::Error> {
            let bytes: &[u8] = sections.get(id.name()).map_or(&[], |c| c);
            Ok(EndianSlice::new(bytes, endian))
        },
    )
    .map_err(|e| Error::Invalid(format!("{label}: bad DWARF: {e}")))?;

    let mut out: Vec<DebugFunc> = Vec::new();
    let mut visited: u64 = 0;
    let mut units = dwarf.units();
    while out.len() < MAX_DEBUG_FUNCS && visited < MAX_DEBUG_DIES {
        let header = match units.next() {
            Ok(Some(h)) => h,
            _ => break,
        };
        let unit = match dwarf.unit(header) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let mut entries = unit.entries();
        while out.len() < MAX_DEBUG_FUNCS && visited < MAX_DEBUG_DIES {
            visited += 1;
            let entry = match entries.next_dfs() {
                Ok(Some(e)) => e,
                _ => break,
            };
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            let low = entry
                .attr_value(gimli::DW_AT_low_pc)
                .and_then(|v| dwarf.attr_address(&unit, v).ok().flatten());
            let Some(low) = low else { continue };
            let end = high_pc_end(entry, low);
            let name = match subprogram_name(entry, &dwarf, &unit, meta) {
                Ok(n) => n,
                Err(Error::Limit(_)) => {
                    return Err(Error::Limit(format!("{label}: debug names exceed budget")));
                }
                Err(_) => None,
            };
            let address = canonical_code_addr(arch, low);
            out.push(DebugFunc {
                name,
                address,
                end: end.map(|e| {
                    if matches!(arch, Arch::Arm32 | Arch::Thumb) {
                        e & !1
                    } else {
                        e
                    }
                }),
            });
        }
    }
    Ok(out)
}

/// Resolve `DW_AT_high_pc` to an exclusive end address.
///
/// Address form reads directly; constant forms (`udata`, `data1/2/4/8`)
/// are lengths off `low_pc`. Section-offset (range-list) forms need
/// `.debug_ranges` resolution and stay `None` in this pass; bogus values
/// (overflow, end at or below start) also stay `None`.
fn high_pc_end<R: gimli::Reader>(
    entry: &gimli::DebuggingInformationEntry<R>,
    low: u64,
) -> Option<u64> {
    let value = entry.attr_value(gimli::DW_AT_high_pc);
    let value = value?;
    let len = match value {
        gimli::AttributeValue::Addr(a) => return (a > low).then_some(a),
        gimli::AttributeValue::Udata(l) => l,
        gimli::AttributeValue::Data1(l) => u64::from(l),
        gimli::AttributeValue::Data2(l) => u64::from(l),
        gimli::AttributeValue::Data4(l) => u64::from(l),
        gimli::AttributeValue::Data8(l) => l,
        _ => return None,
    };
    low.checked_add(len).filter(|e| *e > low)
}

/// Subprogram name: `DW_AT_linkage_name` wins over `DW_AT_name`.
///
/// Unresolvable string forms keep the seed with no name rather than
/// dropping a good start.
///
/// # Errors
/// [`Error::Limit`] when a name exceeds its budget.
fn subprogram_name<R: gimli::Reader>(
    entry: &gimli::DebuggingInformationEntry<R>,
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    meta: &mut u64,
) -> Result<Option<String>> {
    let value = entry
        .attr_value(gimli::DW_AT_linkage_name)
        .or_else(|| entry.attr_value(gimli::DW_AT_name));
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = match dwarf.attr_string(unit, value) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let raw_cow = match bytes.to_slice() {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    let raw: &[u8] = &raw_cow;
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() > MAX_NAME_BYTES {
        return Err(Error::Limit(format!(
            "debug name of {} bytes exceeds {MAX_NAME_BYTES}",
            raw.len()
        )));
    }
    let owned = String::from_utf8_lossy(raw).into_owned();
    account_meta(meta, owned.len())?;
    Ok(Some(owned))
}

/// Borrow section bytes, decompressing compressed debug sections under a cap.
///
/// Compressed sections bigger than [`MAX_MAPPED_BYTES`] uncompressed are
/// skipped with [`Error::Limit`]: names degrade, analysis still runs.
///
/// # Errors
/// [`Error::Limit`] on oversize sections; [`Error::Invalid`] on unreadable
/// section data.
fn section_data_capped<'a>(
    section: &object::Section<'a, 'a, &'a [u8]>,
    label: &str,
) -> Result<Cow<'a, [u8]>> {
    if section.size() > MAX_MAPPED_BYTES {
        return Err(Error::Limit(format!(
            "{label}: debug section exceeds 256 MiB"
        )));
    }
    section
        .uncompressed_data()
        .map_err(|_| Error::Invalid(format!("{label}: bad DWARF section")))
}

/// Parse the PE image base (`OptionalHeader.ImageBase`), bounds-checked.
///
/// # Errors
/// [`Error::Invalid`] on short or non-PE bytes.
pub fn pe_image_base(pe_bytes: &[u8]) -> Result<u64> {
    let get = |off: usize, len: usize| -> Result<&[u8]> {
        pe_bytes
            .get(off..off + len)
            .ok_or_else(|| Error::Invalid("bad PE headers".to_string()))
    };
    let e_lfanew = u32::from_le_bytes(get(0x3C, 4)?.try_into().expect("len")) as usize;
    if get(e_lfanew, 4)? != b"PE\0\0" {
        return Err(Error::Invalid("bad PE signature".to_string()));
    }
    let opt_off = e_lfanew
        .checked_add(24)
        .ok_or_else(|| Error::Invalid("bad PE headers".to_string()))?;
    let magic = u16::from_le_bytes(get(opt_off, 2)?.try_into().expect("len"));
    match magic {
        0x10b => Ok(u32::from_le_bytes(get(opt_off + 28, 4)?.try_into().expect("len")) as u64),
        0x20b => Ok(u64::from_le_bytes(
            get(opt_off + 24, 8)?.try_into().expect("len"),
        )),
        _ => Err(Error::Invalid("bad PE optional header".to_string())),
    }
}

/// Collect PDB public and procedure symbols against PE image bytes.
///
/// Globals (function `Public` rows and `Procedure` rows) plus every module
/// stream's procedures seed names and bounds; RVA to VA runs through the
/// PDB address map (OMAP-aware) plus the PE image base. The public `code`
/// flag is unreliable across linkers (omitted by some), so function publics
/// are kept for any executable-mapped address and the executable-range
/// filter plus the decode check decide; unmapped section offsets, thunks,
/// data publics, and managed-IL rows are skipped, as are zero-length ends.
/// Collection stops at [`MAX_DEBUG_FUNCS`], keeping the table-ordered
/// prefix. MSVC-mangled names demangle best-effort; already-demangled
/// procedure names pass through.
///
/// # Errors
/// [`Error::Invalid`] on non-PE image bytes or an unparsable PDB;
/// [`Error::Limit`] when owned name bytes exceed the metadata budget.
pub fn pdb_funcs(
    pe_bytes: &[u8],
    pdb: &DebugFile,
    arch: Arch,
    meta: &mut u64,
) -> Result<Vec<DebugFunc>> {
    let base =
        pe_image_base(pe_bytes).map_err(|e| Error::Invalid(format!("{}: {e}", pdb.label)))?;
    let mut pdb_file = pdb::PDB::open(std::io::Cursor::new(pdb.bytes.as_slice()))
        .map_err(|e| Error::Invalid(format!("{}: bad PDB: {e}", pdb.label)))?;
    let address_map = pdb_file
        .address_map()
        .map_err(|e| Error::Invalid(format!("{}: bad PDB: {e}", pdb.label)))?;
    let mut cache: HashMap<String, Option<String>> = HashMap::new();
    let mut out: Vec<DebugFunc> = Vec::new();
    let mut index: HashMap<u64, usize> = HashMap::new();
    // Record one row, preferring bounded rows on address collisions: a
    // length-less public loses to the procedure at the same start, so the
    // richer bound survives regardless of stream order.
    let push = |offset: pdb::PdbInternalSectionOffset,
                len: u32,
                raw_name: &[u8],
                out: &mut Vec<DebugFunc>,
                index: &mut HashMap<u64, usize>,
                meta: &mut u64,
                cache: &mut HashMap<String, Option<String>>|
     -> Result<bool> {
        if out.len() >= MAX_DEBUG_FUNCS {
            return Ok(true);
        }
        let Some(rva) = offset.to_rva(&address_map) else {
            return Ok(false);
        };
        let Some(va) = base.checked_add(rva.0 as u64) else {
            return Ok(false);
        };
        let address = canonical_code_addr(arch, va);
        if raw_name.is_empty() {
            return Ok(false);
        }
        let name = decode_owned_name(raw_name, meta)?;
        let demangled = demangle_bounded(&name, meta, cache)?;
        let end = if len > 0 {
            va.checked_add(u64::from(len)).filter(|e| *e > va).map(|e| {
                if matches!(arch, Arch::Arm32 | Arch::Thumb) {
                    e & !1
                } else {
                    e
                }
            })
        } else {
            None
        };
        let row = DebugFunc {
            name: Some(demangled.unwrap_or(name)),
            address,
            end,
        };
        match index.get(&address) {
            Some(&i) => {
                if out[i].end.is_none() && row.end.is_some() {
                    out[i] = row;
                }
            }
            None => {
                index.insert(address, out.len());
                out.push(row);
            }
        }
        Ok(false)
    };

    let globals = pdb_file
        .global_symbols()
        .map_err(|e| Error::Invalid(format!("{}: bad PDB: {e}", pdb.label)))?;
    let mut iter = globals.iter();
    while out.len() < MAX_DEBUG_FUNCS {
        let sym = match iter.next() {
            Ok(Some(s)) => s,
            _ => break,
        };
        let data = match sym.parse() {
            Ok(d) => d,
            Err(_) => continue,
        };
        let stop = match data {
            pdb::SymbolData::Public(p) if p.function && !p.msil => push(
                p.offset,
                0,
                p.name.as_bytes(),
                &mut out,
                &mut index,
                meta,
                &mut cache,
            )?,
            pdb::SymbolData::Procedure(p) => push(
                p.offset,
                p.len,
                p.name.as_bytes(),
                &mut out,
                &mut index,
                meta,
                &mut cache,
            )?,
            _ => false,
        };
        if stop {
            break;
        }
    }

    let dbi = pdb_file
        .debug_information()
        .map_err(|e| Error::Invalid(format!("{}: bad PDB: {e}", pdb.label)))?;
    let mut modules = dbi
        .modules()
        .map_err(|e| Error::Invalid(format!("{}: bad PDB: {e}", pdb.label)))?;
    while out.len() < MAX_DEBUG_FUNCS {
        let module = match modules.next() {
            Ok(Some(m)) => m,
            _ => break,
        };
        let info = match pdb_file.module_info(&module) {
            Ok(Some(i)) => i,
            _ => continue,
        };
        let mut syms = match info.symbols() {
            Ok(s) => s,
            Err(_) => continue,
        };
        while out.len() < MAX_DEBUG_FUNCS {
            let sym = match syms.next() {
                Ok(Some(s)) => s,
                _ => break,
            };
            let data = match sym.parse() {
                Ok(d) => d,
                Err(_) => continue,
            };
            let stop = match data {
                pdb::SymbolData::Procedure(p) => push(
                    p.offset,
                    p.len,
                    p.name.as_bytes(),
                    &mut out,
                    &mut index,
                    meta,
                    &mut cache,
                )?,
                pdb::SymbolData::Public(p) if p.function && !p.msil => push(
                    p.offset,
                    0,
                    p.name.as_bytes(),
                    &mut out,
                    &mut index,
                    meta,
                    &mut cache,
                )?,
                _ => false,
            };
            if stop {
                break;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe32_bytes(image_base: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C] = 0x80;
        let nt = 0x80;
        b[nt..nt + 4].copy_from_slice(b"PE\0\0");
        b[nt + 4..nt + 6].copy_from_slice(&0x14Cu16.to_le_bytes());
        b[nt + 24..nt + 26].copy_from_slice(&0x10Bu16.to_le_bytes());
        b[nt + 24 + 28..nt + 24 + 32].copy_from_slice(&image_base.to_le_bytes());
        b
    }

    #[test]
    fn image_base_parses_pe32_and_pe64() {
        assert_eq!(
            pe_image_base(&pe32_bytes(0x400000)).expect("pe32"),
            0x400000
        );
        let mut b = pe32_bytes(0);
        let nt = 0x80;
        b[nt + 24..nt + 26].copy_from_slice(&0x20Bu16.to_le_bytes());
        b[nt + 24 + 24..nt + 24 + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        assert_eq!(pe_image_base(&b).expect("pe64"), 0x140000000);
    }

    #[test]
    fn image_base_rejects_garbage() {
        assert!(pe_image_base(&[]).is_err());
        assert!(pe_image_base(&vec![0u8; 0x200]).is_err());
        let mut b = pe32_bytes(0x400000);
        b[0x80] = b'X';
        assert!(pe_image_base(&b).is_err());
    }

    #[test]
    fn garbage_pdb_is_invalid_not_a_fetch() {
        let pe = pe32_bytes(0x400000);
        let pdb = DebugFile {
            bytes: b"not a pdb".to_vec(),
            label: "--pdb fake.pdb".to_string(),
        };
        let mut meta = 0u64;
        let err = pdb_funcs(&pe, &pdb, Arch::X86_32, &mut meta).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)), "{err:?}");
    }
}
