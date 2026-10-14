//! Pure-Rust OS/2 Linear Executable (LE) reader (M1, `rsdbg-m1-loader-0tp.1`).
//!
//! `object` 0.40 has no LE support (only the `IMAGE_OS2_SIGNATURE_LE`
//! constant), so this parses the frozen 1990s layout directly: MZ stub →
//! `e_lfanew` → `LE` header → object table → object page map → fixup records
//! → 32-bit entry (`object:offset` → flat VA). Read-only, x86-only.
//!
//! Offsets to loader tables and the data-pages base are relative to the LE
//! header. The page-map width is auto-detected: LX 8-byte entries map as
//! `data_base + (page_offset << page_shift)`, LE 4-byte entries as
//! `data_base + (high + low - 1) * page_size` with the last physical page
//! truncated to the `0x2C` byte count; iterated (`1`) pages are rejected
//! with [`Error::Unsupported`] rather than
//! misparsed.

use crate::disasm::Arch;
use crate::error::{Error, Result};
use crate::loader::Segment;

/// MZ magic (`MZ`).
const MZ_MAGIC: u16 = 0x5A4D;
/// LE magic bytes (`L`, `E`).
const LE_MAGIC: [u8; 2] = [0x4C, 0x45];
/// Offset of `e_lfanew` in the MZ stub.
const E_LFANEW_OFF: usize = 0x3C;
/// Offset of `e_lfarlc` (relocation-table offset) in the MZ stub.
const MZ_RELOC_OFF: usize = 0x18;
/// Minimum `e_lfarlc` for a new-header stub that really holds `e_lfanew`.
///
/// Plain DOS stubs (a DOS4GW outer MZ uses `0x1E`) leave relocation
/// entries at `0x3C`, not an `e_lfanew` pointer.
const MZ_RELOC_MIN: u16 = 0x40;
/// Minimum MZ stub size that still holds `e_lfanew`.
const MZ_MIN: usize = 0x40;
/// Header bytes read (up to `#preload pages`); entry/import/fixup/data
/// offsets all live below this.
const HEADER_MIN: usize = 0x88;
/// Object table entry size.
const OBJECT_REC: usize = 24;
/// Object page table entry size: 4-byte LE entries, 8-byte LX entries.
const PAGE_REC_32: usize = 4;
const PAGE_REC_64: usize = 8;

const MAX_OBJECTS: usize = 4096;
const MAX_PAGES: usize = 1_048_576;
const MAX_FIXUPS: usize = 2_000_000;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_STRINGS: usize = 100_000;
/// Cap on materialized segment bytes (zero-fill tails stay virtual).
const MAX_SEGMENT_BYTES: u64 = 256 * 1024 * 1024;

// LE header field offsets (relative to the LE header start).
const O_BORD: usize = 0x02;
const O_LEVEL: usize = 0x04;
const O_CPU: usize = 0x08;
const O_OS: usize = 0x0A;
const O_FLAGS: usize = 0x10;
const O_NUM_PAGES: usize = 0x14;
const O_EIP_OBJ: usize = 0x18;
const O_EIP: usize = 0x1C;
const O_PAGE_SIZE: usize = 0x28;
/// Raw word at `0x2C`: dual meaning picked by page-map width.
///
/// LE 4-byte entries read it as bytes on the last page (`0` = full page);
/// LX 8-byte entries read it as the page shift.
const O_PAGE_FIELD: usize = 0x2C;
const O_FIXUP_SIZE: usize = 0x30;
const O_OBJ_OFF: usize = 0x40;
const O_NUM_OBJ: usize = 0x44;
const O_PAGE_OFF: usize = 0x48;
const O_ITER_MAP_OFF: usize = 0x4C;
const O_RESOURCE_OFF: usize = 0x50;
const O_RESIDENT_OFF: usize = 0x58;
const O_ENTRY_OFF: usize = 0x5C;
const O_DIRECTIVES_OFF: usize = 0x60;
const O_FIXUP_PAGE_OFF: usize = 0x68;
const O_FIXUP_REC_OFF: usize = 0x6C;
const O_IMP_MOD_OFF: usize = 0x70;
const O_IMP_MOD_COUNT: usize = 0x74;
const O_IMP_PROC_OFF: usize = 0x78;
const O_DATA_OFF: usize = 0x80;

// Object flags (low bits match the LX/LE spec).
const OBJ_READ: u32 = 0x0001;
const OBJ_WRITE: u32 = 0x0002;
const OBJ_EXEC: u32 = 0x0004;

// Fixup target-flags bits (second record byte).
const F_TARGET_MASK: u8 = 0x03;
const F_ADDITIVE: u8 = 0x04;
const F_T32: u8 = 0x10;
const F_A32: u8 = 0x20;
const F_WIDE_OBJ: u8 = 0x40;
const F_ORD8: u8 = 0x80;
// Fixup source-type bits (first record byte).
const SRC_TYPE_MASK: u8 = 0x0F;
const SRC_LIST: u8 = 0x20;

/// One row of the object table (1-based `index`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeObject {
    /// 1-based object-table index.
    pub index: u32,
    /// In-memory size.
    pub virtual_size: u32,
    /// Relocation base address.
    pub reloc_base: u32,
    /// Raw object flags.
    pub flags: u32,
    /// Object is readable.
    pub readable: bool,
    /// Object is writable.
    pub writable: bool,
    /// Object is executable.
    pub executable: bool,
}

/// Fixup target after resolving the per-record flag bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeTarget {
    /// Fixup inside the image.
    Internal {
        /// 1-based target object.
        object: u32,
        /// Offset within the target object.
        offset: u32,
    },
    /// Fixup to an ordinal import.
    ImportOrdinal {
        /// 1-based import module index.
        module: u32,
        /// Export ordinal.
        ordinal: u32,
    },
    /// Fixup to a named import.
    ImportName {
        /// 1-based import module index.
        module: u32,
        /// Offset into the import-names table.
        name_offset: u32,
    },
    /// Fixup to an entry-table export.
    Entry {
        /// Export ordinal.
        ordinal: u32,
    },
}

/// One fixup record: every `sources` offset in `page` (1-based) is fixed up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeFixup {
    /// 1-based page number.
    pub page: u32,
    /// Offsets within the page to fix up.
    pub sources: Vec<u16>,
    /// Resolved fixup target.
    pub target: LeTarget,
    /// Optional addend (`None` when the record carries none).
    pub additive: Option<u32>,
}

/// One 16/32-bit entry-table export (ordinals start at 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeEntry {
    /// Export ordinal (starts at 1).
    pub ordinal: u32,
    /// 1-based target object.
    pub object: u32,
    /// Offset within the target object.
    pub offset: u32,
    /// Whether the entry is exported (vs. shared).
    pub exported: bool,
}

/// Parsed LE image mapped to loader [`Segment`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeImage {
    /// Object page size in bytes.
    pub page_size: u32,
    /// CPU type field (1-4 select x86).
    pub cpu: u16,
    /// Target OS field.
    pub os: u16,
    /// Raw module flags.
    pub module_flags: u32,
    /// Object table in index order.
    pub objects: Vec<LeObject>,
    /// Mapped loader segments.
    pub segments: Vec<Segment>,
    /// Flat VA of `CS:EIP` (`None` for libraries without an entry).
    pub entry: Option<u64>,
    /// Applied fixup records.
    pub fixups: Vec<LeFixup>,
    /// Entry-table exports.
    pub entries: Vec<LeEntry>,
    /// Import module names in table order.
    pub import_modules: Vec<String>,
    /// Import procedure names in table order.
    pub import_procs: Vec<String>,
}

impl LeImage {
    /// LE code is 32-bit x86 (covers DOS4GW code with [`Arch::X86_32`]).
    #[must_use]
    pub fn arch(&self) -> Arch {
        Arch::X86_32
    }
}

/// True when `bytes` looks like an LE image (no errors).
///
/// Fast path: MZ stub with a trustworthy `e_lfanew` pointing at `LE`.
/// Scan fallback: DOS4GW outer stubs carry no new header, so garbage
/// `e_lfanew` is ignored and the file is searched for a validated LE
/// header instead.
#[must_use]
pub fn is_le(bytes: &[u8]) -> bool {
    resolve_le_offset(bytes).is_some()
}

/// Parse an LE file into [`LeImage`].
///
/// # Errors
/// [`Error::Invalid`] on malformed input,
/// [`Error::Unsupported`] on valid LE the
/// reader does not handle (non-x86 CPU, iterated pages, forwarders),
/// [`Error::Limit`] when table, byte, name, or aggregate metadata caps are
/// exceeded.
pub fn parse_le(bytes: &[u8]) -> Result<LeImage> {
    if bytes.len() as u64 > super::MAX_INPUT_BYTES {
        return Err(Error::Limit("input exceeds 512 MiB".to_string()));
    }
    let le_off = resolve_le_offset(bytes).ok_or_else(|| invalid("missing MZ stub"))?;
    let hdr = bytes
        .get(le_off..)
        .filter(|h| h.len() >= HEADER_MIN && h[0..2] == LE_MAGIC)
        .ok_or_else(|| invalid("bad LE magic or truncated LE header"))?;

    if hdr[O_BORD] != 0 {
        return Err(unsupported("non-little-endian LE"));
    }
    if u32_at(hdr, O_LEVEL)? != 0 {
        return Err(unsupported("LE format level != 0"));
    }
    let cpu = u16_at(hdr, O_CPU)?;
    if !(1..=4).contains(&cpu) {
        return Err(unsupported(format!("non-x86 LE CPU type {cpu}")));
    }
    let os = u16_at(hdr, O_OS)?;
    let module_flags = u32_at(hdr, O_FLAGS)?;
    let page_size = u32_at(hdr, O_PAGE_SIZE)?;
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(invalid(format!("bogus LE page size {page_size}")));
    }
    let page_field = u32_at(hdr, O_PAGE_FIELD)?;
    let num_pages = u32_at(hdr, O_NUM_PAGES)? as usize;
    if num_pages > MAX_PAGES {
        return Err(Error::Limit(format!("LE pages {num_pages} exceed cap")));
    }
    let num_obj = u32_at(hdr, O_NUM_OBJ)? as usize;
    if num_obj == 0 || num_obj > MAX_OBJECTS {
        return Err(Error::Limit(format!("LE objects {num_obj} out of range")));
    }
    let fixup_size = u32_at(hdr, O_FIXUP_SIZE)? as usize;
    let imp_count = u32_at(hdr, O_IMP_MOD_COUNT)? as usize;

    // Data-pages base is header-relative (a file-absolute read overlaps
    // the fixup tables on DOS4GW images).
    let data_base = (le_off as u64)
        .checked_add(u32_at(hdr, O_DATA_OFF)? as u64)
        .ok_or_else(|| invalid("LE data pages offset overflow"))?;
    if data_base > bytes.len() as u64 {
        return Err(invalid("LE data pages offset out of range"));
    }

    // Absolute file offset of an LE-header-relative table field.
    let rel = |off: usize| -> Result<usize> {
        let r = u32_at(hdr, off)? as usize;
        le_off
            .checked_add(r)
            .filter(|abs| *abs <= bytes.len())
            .ok_or_else(|| invalid("LE table offset out of range"))
    };

    // Object table.
    let obj_abs = rel(O_OBJ_OFF)?;
    let mut objects = Vec::with_capacity(num_obj);
    let mut seg_bytes: u64 = 0;
    for i in 0..num_obj {
        let o = obj_abs
            .checked_add(i * OBJECT_REC)
            .and_then(|p| bytes.get(p..p + OBJECT_REC))
            .ok_or_else(|| invalid("object table out of range"))?;
        let virtual_size = u32_at(o, 0)?;
        let reloc_base = u32_at(o, 4)?;
        let flags = u32_at(o, 8)?;
        let page_idx = u32_at(o, 12)? as usize;
        let page_cnt = u32_at(o, 16)? as usize;
        if page_cnt > 0 {
            if page_idx == 0 || page_idx - 1 + page_cnt > num_pages {
                return Err(invalid("object page range out of range"));
            }
            seg_bytes = seg_bytes
                .checked_add((page_cnt as u64) * (page_size as u64))
                .ok_or_else(|| Error::Limit("LE segment size overflow".to_string()))?;
        }
        objects.push(LeObject {
            index: (i + 1) as u32,
            virtual_size,
            reloc_base,
            flags,
            readable: flags & OBJ_READ != 0,
            writable: flags & OBJ_WRITE != 0,
            executable: flags & OBJ_EXEC != 0,
        });
    }
    if seg_bytes > MAX_SEGMENT_BYTES {
        return Err(Error::Limit("LE segments exceed 256 MiB".to_string()));
    }

    // Object page map: width auto-detected (table-gap shortcut, else full
    // validation of both widths).
    let page_rel = u32_at(hdr, O_PAGE_OFF)? as usize;
    let page_abs = rel(O_PAGE_OFF)?;
    let map = PageMap {
        bytes,
        page_abs,
        num_pages,
        page_size,
        page_field,
        data_base,
    };
    let width = detect_page_width(hdr, page_rel, fixup_size as u32, imp_count as u32, &map)?;
    let pages = if width == PAGE_REC_32 {
        parse_page_32(&map)?
    } else {
        parse_page_64(&map)?
    };

    // Segments: concatenate each object's pages, zero-padding every page to
    // page_size. Invalid (`2`) pages are zero-filled like zero pages (`3`):
    // the loader leaves them unmapped, and zeros are the neutral read-only
    // stand-in.
    let mut segments = Vec::with_capacity(num_obj);
    for (i, obj) in objects.iter().enumerate() {
        let o = bytes
            .get(obj_abs + i * OBJECT_REC..)
            .ok_or_else(|| invalid("object table out of range"))?;
        let page_idx = u32_at(o, 12)? as usize;
        let page_cnt = u32_at(o, 16)? as usize;
        let mut data = Vec::new();
        for p in 0..page_cnt {
            let pg = &pages[page_idx - 1 + p];
            if pg.zero {
                data.resize(data.len() + page_size as usize, 0);
            } else {
                let start = pg.offset as usize;
                let end = start
                    .checked_add(pg.size)
                    .ok_or_else(|| invalid("LE page end overflow"))?;
                let chunk = bytes
                    .get(start..end)
                    .ok_or_else(|| invalid("LE page data out of range"))?;
                data.extend_from_slice(chunk);
                data.resize(data.len() + page_size as usize - pg.size, 0);
            }
        }
        data.truncate((obj.virtual_size as usize).min(data.len()));
        segments.push(Segment {
            vaddr: obj.reloc_base as u64,
            mem_size: obj.virtual_size as u64,
            data,
            readable: obj.readable,
            writable: obj.writable,
            executable: obj.executable,
        });
    }

    // Fixup page table + records.
    let mut fixups = Vec::new();
    if fixup_size > 0 {
        let fp_abs = rel(O_FIXUP_PAGE_OFF)?;
        let fr_abs = rel(O_FIXUP_REC_OFF)?;
        let mut table = Vec::with_capacity(num_pages + 1);
        for i in 0..=num_pages {
            table.push(
                fp_abs
                    .checked_add(i * 4)
                    .and_then(|p| bytes.get(p..p + 4))
                    .map(u32_from)
                    .ok_or_else(|| invalid("fixup page table out of range"))?,
            );
        }
        let rec_len = table[num_pages] as usize;
        if table.windows(2).any(|w| w[0] > w[1]) || rec_len > fixup_size {
            return Err(invalid("LE fixup page table inconsistent"));
        }
        let rec = bytes
            .get(fr_abs..fr_abs + rec_len)
            .ok_or_else(|| invalid("fixup record table out of range"))?;
        for (p, w) in table.windows(2).enumerate() {
            walk_fixup_page(
                rec,
                w[0] as usize,
                w[1] as usize,
                (p + 1) as u32,
                &mut fixups,
            )?;
        }
    }

    // Import tables (length-prefixed, non-NUL-terminated). Module and
    // procedure names share one aggregate budget so hostile tables cannot
    // split 100k names across both halves to dodge it.
    let (import_modules, import_procs) = if imp_count == 0 {
        (Vec::new(), Vec::new())
    } else {
        let mod_abs = rel(O_IMP_MOD_OFF)?;
        let proc_abs = rel(O_IMP_PROC_OFF)?;
        let section_end = rel(O_FIXUP_PAGE_OFF)?
            .checked_add(fixup_size)
            .filter(|e| *e <= bytes.len())
            .ok_or_else(|| invalid("LE fixup section out of range"))?;
        if !(mod_abs <= proc_abs && proc_abs <= section_end) {
            return Err(invalid("LE import tables out of order"));
        }
        let mut meta: u64 = 0;
        let mods = parse_names(bytes, mod_abs, proc_abs, &mut meta)?;
        if mods.len() != imp_count {
            return Err(invalid("LE import module count mismatch"));
        }
        let procs = parse_names(bytes, proc_abs, section_end, &mut meta)?;
        let proc_len = section_end - proc_abs;
        for f in &fixups {
            if let LeTarget::ImportName { name_offset, .. } = f.target
                && name_offset as usize >= proc_len
            {
                return Err(invalid("LE fixup name offset out of range"));
            }
        }
        (mods, procs)
    };

    // Entry bundles (ordinals start at 1; unused/16-bit/callgate/32-bit).
    let mut entries = Vec::new();
    if u32_at(hdr, O_ENTRY_OFF)? != 0 {
        parse_entries(bytes, rel(O_ENTRY_OFF)?, &mut entries)?;
    }

    // 32-bit entry object:offset -> flat VA.
    let eip_obj = u32_at(hdr, O_EIP_OBJ)?;
    let eip = u32_at(hdr, O_EIP)?;
    let entry = if eip_obj == 0 {
        None
    } else {
        let obj = objects
            .get(eip_obj as usize - 1)
            .ok_or_else(|| invalid("LE entry object out of range"))?;
        if eip >= obj.virtual_size {
            return Err(invalid("LE entry offset beyond object"));
        }
        Some(obj.reloc_base as u64 + eip as u64)
    };

    Ok(LeImage {
        page_size,
        cpu,
        os,
        module_flags,
        objects,
        segments,
        entry,
        fixups,
        entries,
        import_modules,
        import_procs,
    })
}

/// Fast LE offset: MZ stub with a trustworthy `e_lfanew` pointing at `LE`.
///
/// Absent (`None`) when the stub is short, non-MZ, old-DOS-style
/// (`e_lfarlc < 0x40`, so `0x3C` is relocation garbage), or the pointer
/// leaves the file or misses the magic. Magic-only on purpose: truncated
/// headers still count as recognized here; [`parse_le`] reports them.
fn fast_le_offset(bytes: &[u8]) -> Option<usize> {
    let stub = bytes.get(..MZ_MIN)?;
    if u16_from(&stub[0..2]) != MZ_MAGIC {
        return None;
    }
    if u16_from(&stub[MZ_RELOC_OFF..MZ_RELOC_OFF + 2]) < MZ_RELOC_MIN {
        return None;
    }
    let le_off = u32_from(&stub[E_LFANEW_OFF..E_LFANEW_OFF + 4]) as usize;
    if le_off < MZ_MIN {
        return None;
    }
    bytes
        .get(le_off..le_off + 2)
        .filter(|m| *m == LE_MAGIC)
        .map(|_| le_off)
}

/// First validated LE header offset anywhere in `bytes` (`None` if none).
///
/// Every `LE` magic occurrence is checked field-by-field (byte order,
/// format level, CPU/OS, page size, object/page caps, table ranges), so
/// stray `LE` bytes in code or data do not hit. Only MZ-led files are
/// scanned: LE images always carry the outer DOS stub.
fn scan_le_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.len() >= 2 && u16_from(&bytes[0..2]) != MZ_MAGIC {
        return None;
    }
    let mut off = 0;
    while off + HEADER_MIN <= bytes.len() {
        if bytes[off..off + 2] == LE_MAGIC && valid_le_candidate(bytes, off) {
            return Some(off);
        }
        off += 1;
    }
    None
}

/// Header plausibility for one scan candidate at `off`.
///
/// Mirrors the [`parse_le`] prefix checks (plus OS range and table fit)
/// without allocating or walking tables.
fn valid_le_candidate(bytes: &[u8], off: usize) -> bool {
    let Some(hdr) = bytes.get(off..off + HEADER_MIN) else {
        return false;
    };
    if hdr[O_BORD] != 0 || u32_from(&hdr[O_LEVEL..O_LEVEL + 4]) != 0 {
        return false;
    }
    if !(1..=4).contains(&u16_from(&hdr[O_CPU..O_CPU + 2])) {
        return false;
    }
    if !(1..=4).contains(&u16_from(&hdr[O_OS..O_OS + 2])) {
        return false;
    }
    let page_size = u32_from(&hdr[O_PAGE_SIZE..O_PAGE_SIZE + 4]);
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return false;
    }
    let num_pages = u32_from(&hdr[O_NUM_PAGES..O_NUM_PAGES + 4]) as usize;
    if num_pages > MAX_PAGES {
        return false;
    }
    let num_obj = u32_from(&hdr[O_NUM_OBJ..O_NUM_OBJ + 4]) as usize;
    if num_obj == 0 || num_obj > MAX_OBJECTS {
        return false;
    }
    // Mandatory tables must fit; active optional tables must start in range.
    // (`O_DATA_OFF` stays unchecked: the data-pages extent needs the page
    // map to bound. The 8-byte entry size is an upper bound that also
    // covers 4-byte LE maps.)
    let table = |field: usize, size: usize| -> bool {
        let rel = u32_from(&hdr[field..field + 4]) as usize;
        off.checked_add(rel)
            .and_then(|abs| abs.checked_add(size))
            .is_some_and(|end| end <= bytes.len())
    };
    if !table(O_OBJ_OFF, num_obj * OBJECT_REC) || !table(O_PAGE_OFF, num_pages * PAGE_REC_64) {
        return false;
    }
    if u32_from(&hdr[O_FIXUP_SIZE..O_FIXUP_SIZE + 4]) > 0
        && (!table(O_FIXUP_PAGE_OFF, 0) || !table(O_FIXUP_REC_OFF, 0))
    {
        return false;
    }
    if u32_from(&hdr[O_IMP_MOD_COUNT..O_IMP_MOD_COUNT + 4]) > 0
        && (!table(O_IMP_MOD_OFF, 0) || !table(O_IMP_PROC_OFF, 0))
    {
        return false;
    }
    if u32_from(&hdr[O_ENTRY_OFF..O_ENTRY_OFF + 4]) != 0 && !table(O_ENTRY_OFF, 0) {
        return false;
    }
    true
}

/// LE header offset: trustworthy `e_lfanew` first, validated scan second.
fn resolve_le_offset(bytes: &[u8]) -> Option<usize> {
    fast_le_offset(bytes).or_else(|| scan_le_offset(bytes))
}

/// One mapped object page: `size` file bytes at absolute `offset`
/// (`data_base`-relative math already applied), or a zero-filled page.
struct LePage {
    offset: u64,
    size: usize,
    zero: bool,
}

/// Shared inputs for page-map width detection and parsing.
struct PageMap<'a> {
    bytes: &'a [u8],
    page_abs: usize,
    num_pages: usize,
    page_size: u32,
    /// Raw `0x2C` word; each width validates its own reading.
    page_field: u32,
    data_base: u64,
}

/// Gap between the page map and the next defined loader table, if any.
///
/// Candidate tables (header-relative): iterate map, resource, resident
/// names, entry, directives, fixup-page/record, import-module/proc. Only
/// tables before the page map are ignored; a zero entry offset or an empty
/// fixup/import section means undefined.
fn next_table_gap(
    hdr: &[u8],
    page_rel: usize,
    fixup_size: u32,
    imp_count: u32,
) -> Result<Option<usize>> {
    let mut next: Option<usize> = None;
    let mut consider = |field: usize, defined: bool| -> Result<()> {
        if defined {
            let v = u32_at(hdr, field)? as usize;
            if v > page_rel {
                next = Some(next.map_or(v, |n| n.min(v)));
            }
        }
        Ok(())
    };
    consider(O_ITER_MAP_OFF, u32_at(hdr, O_ITER_MAP_OFF)? != 0)?;
    consider(O_RESOURCE_OFF, u32_at(hdr, O_RESOURCE_OFF)? != 0)?;
    consider(O_RESIDENT_OFF, u32_at(hdr, O_RESIDENT_OFF)? != 0)?;
    consider(O_ENTRY_OFF, u32_at(hdr, O_ENTRY_OFF)? != 0)?;
    consider(O_DIRECTIVES_OFF, u32_at(hdr, O_DIRECTIVES_OFF)? != 0)?;
    consider(O_FIXUP_PAGE_OFF, fixup_size > 0)?;
    consider(O_FIXUP_REC_OFF, fixup_size > 0)?;
    consider(O_IMP_MOD_OFF, imp_count > 0)?;
    consider(O_IMP_PROC_OFF, imp_count > 0)?;
    Ok(next.map(|n| n - page_rel))
}

/// Page-map entry width: 4-byte LE or 8-byte LX.
///
/// The table gap decides when it fits exactly one width; otherwise both
/// widths are fully validated and exactly one must pass. Ambiguous or
/// bogus maps are errors, never silent raw fallbacks.
fn detect_page_width(
    hdr: &[u8],
    page_rel: usize,
    fixup_size: u32,
    imp_count: u32,
    map: &PageMap,
) -> Result<usize> {
    if map.num_pages == 0 {
        return Ok(PAGE_REC_64);
    }
    if let Some(gap) = next_table_gap(hdr, page_rel, fixup_size, imp_count)? {
        if gap == map.num_pages * PAGE_REC_32 {
            return Ok(PAGE_REC_32);
        }
        if gap == map.num_pages * PAGE_REC_64 {
            return Ok(PAGE_REC_64);
        }
    }
    match (parse_page_32(map).is_ok(), parse_page_64(map).is_ok()) {
        (true, false) => Ok(PAGE_REC_32),
        (false, true) => Ok(PAGE_REC_64),
        (true, true) => Err(invalid("ambiguous LE page-map width")),
        (false, false) => Err(invalid("bogus LE page map")),
    }
}

/// Parse 4-byte LE page entries (`high u16`, `low u8`, `type u8`).
///
/// Legal (`0`) pages sit at `data_base + (high + low - 1) * page_size`;
/// the last physical page is truncated to the `0x2C` byte count.
/// Invalid (`2`) and zero (`3`) pages are zero-filled.
fn parse_page_32(map: &PageMap) -> Result<Vec<LePage>> {
    let last_bytes = bytes_on_last_page(map.page_field, map.page_size)?;
    let mut nums = Vec::with_capacity(map.num_pages);
    for i in 0..map.num_pages {
        let e = map
            .page_abs
            .checked_add(i * PAGE_REC_32)
            .and_then(|p| map.bytes.get(p..p + PAGE_REC_32))
            .ok_or_else(|| invalid("page table out of range"))?;
        let num = u16_from(&e[0..2]) as u64 + e[2] as u64;
        match e[3] {
            0 => {
                if num == 0 {
                    return Err(invalid("LE page number out of range"));
                }
                nums.push(num);
            }
            1 => return Err(unsupported("LE iterated data pages")),
            2 | 3 => nums.push(0),
            t => return Err(invalid(format!("unknown LE page type {t}"))),
        }
    }
    let last = nums.iter().copied().filter(|n| *n > 0).max();
    let mut pages = Vec::with_capacity(map.num_pages);
    for num in nums {
        if num == 0 {
            pages.push(LePage {
                offset: 0,
                size: map.page_size as usize,
                zero: true,
            });
            continue;
        }
        let off = map
            .data_base
            .checked_add(
                (num - 1)
                    .checked_mul(map.page_size as u64)
                    .ok_or_else(|| invalid("LE page offset overflow"))?,
            )
            .ok_or_else(|| invalid("LE page offset overflow"))?;
        let size = if Some(num) == last {
            last_bytes as usize
        } else {
            map.page_size as usize
        };
        let end = off
            .checked_add(size as u64)
            .ok_or_else(|| invalid("LE page end overflow"))?;
        if end > map.bytes.len() as u64 {
            return Err(invalid("LE page data out of range"));
        }
        pages.push(LePage {
            offset: off,
            size,
            zero: false,
        });
    }
    Ok(pages)
}

/// Parse 8-byte LX page entries (`offset u32`, `size u16`, `flags u16`).
fn parse_page_64(map: &PageMap) -> Result<Vec<LePage>> {
    let shift = page_shift(map.page_field)?;
    let mut pages = Vec::with_capacity(map.num_pages);
    for i in 0..map.num_pages {
        let e = map
            .page_abs
            .checked_add(i * PAGE_REC_64)
            .and_then(|p| map.bytes.get(p..p + PAGE_REC_64))
            .ok_or_else(|| invalid("page table out of range"))?;
        let (raw, size, flags) = (u32_at(e, 0)?, u16_at(e, 4)? as usize, u16_at(e, 6)?);
        match flags {
            0 => {
                let shifted = (raw as u64)
                    .checked_shl(shift)
                    .ok_or_else(|| invalid("LE page offset overflow"))?;
                let off = map
                    .data_base
                    .checked_add(shifted)
                    .ok_or_else(|| invalid("LE page offset overflow"))?;
                let end = off
                    .checked_add(size as u64)
                    .ok_or_else(|| invalid("LE page end overflow"))?;
                if size > map.page_size as usize || end > map.bytes.len() as u64 {
                    return Err(invalid("LE page data out of range"));
                }
                pages.push(LePage {
                    offset: off,
                    size,
                    zero: false,
                });
            }
            2 | 3 => pages.push(LePage {
                offset: 0,
                size: map.page_size as usize,
                zero: true,
            }),
            1 => return Err(unsupported("LE iterated data pages")),
            _ => return Err(invalid(format!("unknown LE page flags {flags}"))),
        }
    }
    Ok(pages)
}

/// LX reading of the raw `0x2C` word: page shift (8-byte page-map entries).
fn page_shift(raw: u32) -> Result<u32> {
    if raw > 16 {
        return Err(invalid(format!("bogus LE page shift {raw}")));
    }
    Ok(raw)
}

/// LE reading of the raw `0x2C` word: bytes on the last page (4-byte
/// page-map entries). `0` means a full final page.
fn bytes_on_last_page(raw: u32, page_size: u32) -> Result<u32> {
    if raw == 0 {
        return Ok(page_size);
    }
    if raw > page_size {
        return Err(invalid(format!("bogus LE last-page bytes {raw}")));
    }
    Ok(raw)
}

fn walk_fixup_page(
    rec: &[u8],
    start: usize,
    end: usize,
    page: u32,
    out: &mut Vec<LeFixup>,
) -> Result<()> {
    if end > rec.len() {
        return Err(invalid("LE fixup page range out of range"));
    }
    let mut pos = start;
    while pos < end {
        let src = u8_at(rec, pos)?;
        let flags = u8_at(rec, pos + 1).map_err(|_| invalid("truncated LE fixup"))?;
        if !matches!(
            src & SRC_TYPE_MASK,
            0x00 | 0x02 | 0x03 | 0x05 | 0x06 | 0x07 | 0x08
        ) {
            return Err(invalid(format!("unknown LE fixup source {src:#x}")));
        }
        // Source-list flag lives in the SRC byte; width flags in FLAGS.
        let list = src & SRC_LIST != 0;
        let single = if list {
            None
        } else {
            Some(u16_at(rec, pos + 2).map_err(|_| invalid("truncated LE fixup"))?)
        };
        let mut cur = pos + if list { 3 } else { 4 };
        let target = parse_target(rec, &mut cur, end, flags, src)?;
        let additive = if flags & F_ADDITIVE != 0 {
            let w = if flags & F_A32 != 0 { 4 } else { 2 };
            let v = match w {
                4 => u32_at(rec, cur).map_err(|_| invalid("truncated LE fixup additive"))?,
                _ => u16_at(rec, cur).map_err(|_| invalid("truncated LE fixup additive"))? as u32,
            };
            cur += w;
            Some(v)
        } else {
            None
        };
        let sources = if list {
            let n = u8_at(rec, pos + 2).map_err(|_| invalid("truncated LE fixup"))? as usize;
            let mut v = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                v.push(u16_at(rec, cur).map_err(|_| invalid("truncated LE fixup list"))?);
                cur += 2;
                if v.len() > 65536 {
                    return Err(Error::Limit("LE fixup source list too long".to_string()));
                }
            }
            v
        } else {
            vec![single.ok_or_else(|| invalid("LE fixup missing source"))?]
        };
        if cur > end {
            return Err(invalid("LE fixup record crosses page boundary"));
        }
        out.push(LeFixup {
            page,
            sources,
            target,
            additive,
        });
        if out.len() > MAX_FIXUPS {
            return Err(Error::Limit("LE fixups exceed cap".to_string()));
        }
        if cur <= pos {
            return Err(invalid("LE fixup made no progress"));
        }
        pos = cur;
    }
    Ok(())
}

fn parse_target(rec: &[u8], cur: &mut usize, end: usize, flags: u8, src: u8) -> Result<LeTarget> {
    let wide = flags & F_WIDE_OBJ != 0;
    let t32 = flags & F_T32 != 0;
    let take = |cur: &mut usize, n: usize| -> Result<u32> {
        let next = cur
            .checked_add(n)
            .filter(|e| *e <= end && *e <= rec.len())
            .ok_or_else(|| invalid("truncated LE fixup target"))?;
        let v = match n {
            1 => u8_at(rec, *cur)? as u32,
            2 => u16_at(rec, *cur)? as u32,
            4 => u32_at(rec, *cur)?,
            _ => return Err(invalid("bad LE fixup width")),
        };
        *cur = next;
        Ok(v)
    };
    let obj_w = if wide { 2 } else { 1 };
    let off_w = if t32 { 4 } else { 2 };
    match flags & F_TARGET_MASK {
        0 => {
            let object = take(cur, obj_w)?;
            // Selector-only fixups carry no target offset.
            let offset = if src & SRC_TYPE_MASK == 0x02 {
                0
            } else {
                take(cur, off_w)?
            };
            Ok(LeTarget::Internal { object, offset })
        }
        1 => {
            let module = take(cur, obj_w)?;
            let ordinal = if flags & F_ORD8 != 0 {
                take(cur, 1)?
            } else {
                take(cur, off_w)?
            };
            Ok(LeTarget::ImportOrdinal { module, ordinal })
        }
        2 => {
            let module = take(cur, obj_w)?;
            let name_offset = take(cur, off_w)?;
            Ok(LeTarget::ImportName {
                module,
                name_offset,
            })
        }
        3 => Ok(LeTarget::Entry {
            ordinal: take(cur, obj_w)?,
        }),
        _ => Err(invalid("bad LE fixup target type")),
    }
}

fn parse_entries(bytes: &[u8], mut pos: usize, out: &mut Vec<LeEntry>) -> Result<()> {
    let mut ordinal: u32 = 1;
    loop {
        let cnt = u8_at(bytes, pos).map_err(|_| invalid("truncated LE entry table"))? as u32;
        pos += 1;
        if cnt == 0 {
            break;
        }
        let ty = u8_at(bytes, pos).map_err(|_| invalid("truncated LE entry table"))?;
        pos += 1;
        if ty & 0x80 != 0 {
            return Err(unsupported("LE entry parameter typing info"));
        }
        match ty & 0x7F {
            0 => {
                ordinal = ordinal
                    .checked_add(cnt)
                    .ok_or_else(|| Error::Limit("LE ordinals overflow".to_string()))?;
            }
            1..=3 => {
                let object =
                    u16_at(bytes, pos).map_err(|_| invalid("truncated LE entry table"))? as u32;
                pos += 2;
                let wide = ty == 3;
                for _ in 0..cnt {
                    let exported =
                        u8_at(bytes, pos).map_err(|_| invalid("truncated LE entry"))? & 0x01 != 0;
                    pos += 1;
                    let offset = if wide {
                        u32_at(bytes, pos).map_err(|_| invalid("truncated LE entry"))?
                    } else {
                        u16_at(bytes, pos).map_err(|_| invalid("truncated LE entry"))? as u32
                    };
                    pos += if wide { 4 } else { 2 };
                    if ty == 2 {
                        // Callgate selector slot, loader-filled; skip.
                        bytes
                            .get(pos..pos + 2)
                            .ok_or_else(|| invalid("truncated LE entry"))?;
                        pos += 2;
                    }
                    out.push(LeEntry {
                        ordinal,
                        object,
                        offset,
                        exported,
                    });
                    ordinal = ordinal
                        .checked_add(1)
                        .ok_or_else(|| Error::Limit("LE ordinals overflow".to_string()))?;
                    if out.len() > MAX_ENTRIES {
                        return Err(Error::Limit("LE entries exceed cap".to_string()));
                    }
                }
            }
            4 => return Err(unsupported("LE forwarder entries")),
            t => return Err(invalid(format!("unknown LE entry bundle type {t}"))),
        }
    }
    Ok(())
}

fn parse_names(bytes: &[u8], start: usize, end: usize, meta: &mut u64) -> Result<Vec<String>> {
    if start > end || end > bytes.len() {
        return Err(invalid("LE name table out of range"));
    }
    let mut out = Vec::new();
    let mut pos = start;
    while pos < end {
        let len = u8_at(bytes, pos)? as usize & 0x7F;
        pos += 1;
        let name_end = pos
            .checked_add(len)
            .ok_or_else(|| invalid("LE name entry out of range"))?;
        if name_end > end {
            return Err(invalid("LE name entry crosses table boundary"));
        }
        let s = bytes
            .get(pos..name_end)
            .ok_or_else(|| invalid("LE name entry out of range"))?;
        pos = name_end;
        // Length-prefixed names top out at 127 raw bytes, but the lossy
        // decode can still triple them; enforce both before owning.
        if s.len() > super::MAX_NAME_BYTES {
            return Err(Error::Limit("LE name exceeds cap".to_string()));
        }
        let decoded = String::from_utf8_lossy(s).into_owned();
        if decoded.len() > super::MAX_NAME_BYTES {
            return Err(Error::Limit("LE decoded name exceeds cap".to_string()));
        }
        *meta = meta
            .checked_add(decoded.len() as u64)
            .filter(|m| *m <= super::MAX_METADATA_BYTES)
            .ok_or_else(|| Error::Limit("LE names exceed 16 MiB".to_string()))?;
        out.push(decoded);
        if out.len() > MAX_STRINGS {
            return Err(Error::Limit("LE name table too large".to_string()));
        }
    }
    Ok(out)
}

fn u8_at(b: &[u8], off: usize) -> Result<u8> {
    b.get(off)
        .copied()
        .ok_or_else(|| invalid("unexpected end of LE data"))
}

fn u16_at(b: &[u8], off: usize) -> Result<u16> {
    let w = b
        .get(off..off + 2)
        .ok_or_else(|| invalid("unexpected end of LE data"))?;
    Ok(u16_from(w))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32> {
    let w = b
        .get(off..off + 4)
        .ok_or_else(|| invalid("unexpected end of LE data"))?;
    Ok(u32_from(w))
}

fn u16_from(w: &[u8]) -> u16 {
    u16::from_le_bytes([w[0], w[1]])
}

fn u32_from(w: &[u8]) -> u32 {
    u32::from_le_bytes([w[0], w[1], w[2], w[3]])
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::Invalid(msg.into())
}

fn unsupported(msg: impl Into<String>) -> Error {
    Error::Unsupported(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Embedded LE offset: outer DOS stub plus padding, DOS4GW-style.
    const DOS_LE_OFF: usize = 0x200;
    const DOS_CODE: [u8; 4] = [0x55, 0x89, 0xE5, 0xC3];

    fn t_put16(v: &mut [u8], off: usize, x: u16) {
        v[off..off + 2].copy_from_slice(&x.to_le_bytes());
    }

    fn t_put32(v: &mut [u8], off: usize, x: u32) {
        v[off..off + 4].copy_from_slice(&x.to_le_bytes());
    }

    /// Outer MZ with no new header (`e_lfarlc` = `0x1E`, relocation garbage
    /// at `0x3C`) plus one valid LE image at [`DOS_LE_OFF`].
    fn dos4gw_outer() -> Vec<u8> {
        // Same relative layout as the `loader_le` harness: object, page,
        // fixup-page tables, empty fixup records, default entry, code.
        let entry: Vec<u8> = vec![0x01, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let obj_rel = 0xAC;
        let page_rel = obj_rel + 24;
        let fp_rel = page_rel + 8;
        let fr_rel = fp_rel + 8;
        let entry_rel = fr_rel;
        let code_rel = entry_rel + entry.len();

        let mut f = vec![0u8; DOS_LE_OFF];
        f[0] = b'M';
        f[1] = b'Z';
        t_put16(&mut f, 0x18, 0x1E);
        t_put32(&mut f, 0x3C, 0x09B4_0000);
        f.resize(DOS_LE_OFF + code_rel + DOS_CODE.len(), 0);

        let h = DOS_LE_OFF;
        f[h] = b'L';
        f[h + 1] = b'E';
        t_put32(&mut f, h + 0x04, 0);
        t_put16(&mut f, h + 0x08, 2);
        t_put16(&mut f, h + 0x0A, 1);
        t_put32(&mut f, h + 0x14, 1);
        t_put32(&mut f, h + 0x18, 1);
        t_put32(&mut f, h + 0x20, 1);
        t_put32(&mut f, h + 0x24, 0x1000);
        t_put32(&mut f, h + 0x28, 0x1000);
        t_put32(&mut f, h + 0x30, 8);
        t_put32(&mut f, h + 0x38, (code_rel - obj_rel) as u32);
        t_put32(&mut f, h + 0x40, obj_rel as u32);
        t_put32(&mut f, h + 0x44, 1);
        t_put32(&mut f, h + 0x48, page_rel as u32);
        t_put32(&mut f, h + 0x5C, entry_rel as u32);
        t_put32(&mut f, h + 0x68, fp_rel as u32);
        t_put32(&mut f, h + 0x6C, fr_rel as u32);
        t_put32(&mut f, h + 0x80, code_rel as u32);
        t_put32(&mut f, h + 0x84, 1);

        let p = DOS_LE_OFF + obj_rel;
        t_put32(&mut f, p, 0x1000);
        t_put32(&mut f, p + 4, 0x10000);
        t_put32(&mut f, p + 8, 0x2005);
        t_put32(&mut f, p + 12, 1);
        t_put32(&mut f, p + 16, 1);

        let p = DOS_LE_OFF + page_rel;
        t_put32(&mut f, p, 0);
        t_put16(&mut f, p + 4, DOS_CODE.len() as u16);

        let p = DOS_LE_OFF + fp_rel;
        t_put32(&mut f, p, 0);
        t_put32(&mut f, p + 4, 0);

        f[DOS_LE_OFF + entry_rel..DOS_LE_OFF + entry_rel + entry.len()].copy_from_slice(&entry);
        f[DOS_LE_OFF + code_rel..].copy_from_slice(&DOS_CODE);
        f
    }

    #[test]
    fn page_field_lx_shift_validation() {
        assert_eq!(page_shift(0).unwrap(), 0);
        assert_eq!(page_shift(16).unwrap(), 16);
        assert!(page_shift(17).is_err());
        // Orion2's `0x2C` = 113 is bogus as a shift ...
        assert!(page_shift(0x71).is_err());
    }

    #[test]
    fn page_field_le_last_page_bytes() {
        // ... but valid as LE bytes-on-last-page (`page_size` `0x1000`).
        assert_eq!(bytes_on_last_page(0x71, 0x1000).unwrap(), 0x71);
        assert_eq!(bytes_on_last_page(0, 0x1000).unwrap(), 0x1000);
        assert!(bytes_on_last_page(0x1001, 0x1000).is_err());
    }

    /// 4-byte-page-map image: DOS4GW-style outer stub, one object over two
    /// pages (full + truncated tail), default entry bundle. `page_pad`
    /// inserts dead bytes between the page map and the fixup table to
    /// force the validation fallback instead of the table-gap shortcut.
    fn dos4gw_outer_32(page_pad: usize) -> Vec<u8> {
        const PS: usize = 512;
        const TAIL: usize = 100;
        let entry: Vec<u8> = vec![0x01, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let obj_rel = 0xAC;
        let page_rel = obj_rel + 24;
        let fp_rel = page_rel + 2 * PAGE_REC_32 + page_pad;
        let fr_rel = fp_rel + 12;
        let entry_rel = fr_rel;
        let code_rel = entry_rel + entry.len();

        let mut f = vec![0u8; DOS_LE_OFF];
        f[0] = b'M';
        f[1] = b'Z';
        t_put16(&mut f, 0x18, 0x1E);
        t_put32(&mut f, 0x3C, 0x09B4_0000);
        f.resize(DOS_LE_OFF + code_rel + PS + TAIL, 0);

        let h = DOS_LE_OFF;
        f[h] = b'L';
        f[h + 1] = b'E';
        t_put32(&mut f, h + 0x04, 0);
        t_put16(&mut f, h + 0x08, 2);
        t_put16(&mut f, h + 0x0A, 1);
        t_put32(&mut f, h + 0x14, 2);
        t_put32(&mut f, h + 0x18, 1);
        t_put32(&mut f, h + 0x20, 1);
        t_put32(&mut f, h + 0x24, 0x1000);
        t_put32(&mut f, h + 0x28, PS as u32);
        t_put32(&mut f, h + 0x2C, TAIL as u32);
        t_put32(&mut f, h + 0x30, 8);
        t_put32(&mut f, h + 0x38, (code_rel - obj_rel + PS + TAIL) as u32);
        t_put32(&mut f, h + 0x40, obj_rel as u32);
        t_put32(&mut f, h + 0x44, 1);
        t_put32(&mut f, h + 0x48, page_rel as u32);
        t_put32(&mut f, h + 0x5C, entry_rel as u32);
        t_put32(&mut f, h + 0x68, fp_rel as u32);
        t_put32(&mut f, h + 0x6C, fr_rel as u32);
        t_put32(&mut f, h + 0x80, code_rel as u32);
        t_put32(&mut f, h + 0x84, 2);

        let p = DOS_LE_OFF + obj_rel;
        t_put32(&mut f, p, (PS + TAIL) as u32);
        t_put32(&mut f, p + 4, 0x10000);
        t_put32(&mut f, p + 8, 0x2005);
        t_put32(&mut f, p + 12, 1);
        t_put32(&mut f, p + 16, 2);

        // Page 1: `{high:0, low:1, type:0}`; page 2 (last): `{0,2,0}`.
        let p = DOS_LE_OFF + page_rel;
        f[p] = 0;
        f[p + 1] = 0;
        f[p + 2] = 1;
        f[p + 3] = 0;
        f[p + 4] = 0;
        f[p + 5] = 0;
        f[p + 6] = 2;
        f[p + 7] = 0;

        let p = DOS_LE_OFF + fp_rel;
        t_put32(&mut f, p, 0);
        t_put32(&mut f, p + 4, 0);
        t_put32(&mut f, p + 8, 0);

        f[DOS_LE_OFF + entry_rel..DOS_LE_OFF + entry_rel + entry.len()].copy_from_slice(&entry);
        let code = DOS_LE_OFF + code_rel;
        f[code..code + PS].fill(0x90);
        f[code + PS..code + PS + 4].copy_from_slice(&DOS_CODE);
        f
    }

    #[test]
    fn four_byte_page_map_maps_pages_with_truncated_tail() {
        let bytes = dos4gw_outer_32(0);
        let img = parse_le(&bytes).expect("4-byte LE image must parse");
        assert_eq!(img.entry, Some(0x10000));
        let s = &img.segments[0];
        assert_eq!(s.data.len(), 512 + 100);
        assert!(s.data[..512].iter().all(|b| *b == 0x90));
        assert_eq!(&s.data[512..516], &DOS_CODE);
        assert!(s.data[516..].iter().all(|b| *b == 0));
    }

    #[test]
    fn page_width_falls_back_to_validation() {
        // Two pad bytes break the table-gap shortcut (gap 10 fits neither
        // width for 2 pages); full validation must still pick 4-byte.
        let bytes = dos4gw_outer_32(2);
        let img = parse_le(&bytes).expect("validation fallback must pick 4-byte");
        assert_eq!(img.segments[0].data.len(), 512 + 100);
        assert_eq!(&img.segments[0].data[512..516], &DOS_CODE);
    }

    #[test]
    fn four_byte_zero_and_invalid_pages_stay_virtual() {
        let mut bytes = dos4gw_outer_32(0);
        // Page 1 invalid (`2`), page 2 zero-filled (`3`).
        bytes[DOS_LE_OFF + 0xAC + 24 + 3] = 2;
        bytes[DOS_LE_OFF + 0xAC + 24 + 7] = 3;
        let img = parse_le(&bytes).expect("zero/invalid pages must parse");
        let s = &img.segments[0];
        assert_eq!(s.data.len(), 512 + 100);
        assert!(s.data.iter().all(|b| *b == 0));
    }

    #[test]
    fn four_byte_iterated_page_is_unsupported() {
        let mut bytes = dos4gw_outer_32(0);
        bytes[DOS_LE_OFF + 0xAC + 24 + 3] = 1;
        assert!(matches!(parse_le(&bytes), Err(Error::Unsupported(_))));
    }

    #[test]
    fn four_byte_unknown_page_type_is_invalid() {
        let mut bytes = dos4gw_outer_32(0);
        bytes[DOS_LE_OFF + 0xAC + 24 + 3] = 5;
        assert!(matches!(parse_le(&bytes), Err(Error::Invalid(_))));
    }

    #[test]
    fn dos4gw_outer_mz_scans_to_embedded_le() {
        let bytes = dos4gw_outer();
        assert_eq!(fast_le_offset(&bytes), None, "garbage e_lfanew is ignored");
        assert_eq!(scan_le_offset(&bytes), Some(DOS_LE_OFF));
        assert!(is_le(&bytes));
        let img = parse_le(&bytes).expect("scan-found LE must parse");
        assert_eq!(img.cpu, 2);
        assert_eq!(img.os, 1);
        assert_eq!(img.objects.len(), 1);
        assert_eq!(img.entry, Some(0x10000));
        assert_eq!(&img.segments[0].data[..4], &DOS_CODE);
    }
}
