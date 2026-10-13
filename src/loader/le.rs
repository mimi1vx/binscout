//! Pure-Rust OS/2 Linear Executable (LE) reader (M1, `rsdbg-m1-loader-0tp.1`).
//!
//! `object` 0.40 has no LE support (only the `IMAGE_OS2_SIGNATURE_LE`
//! constant), so this parses the frozen 1990s layout directly: MZ stub →
//! `e_lfanew` → `LE` header → object table → object page map → fixup records
//! → 32-bit entry (`object:offset` → flat VA). Read-only, x86-only.
//!
//! Offsets to loader tables are relative to the LE header; the data-pages
//! base is file-absolute. Page file offsets are computed as
//! `data_base + (page_offset << page_shift)`, which matches single-section
//! DOS4GW files; iterated (`1`) and range (`4`) pages are rejected with
//! [`Error::Unsupported`] rather than
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
/// Minimum MZ stub size that still holds `e_lfanew`.
const MZ_MIN: usize = 0x40;
/// Header bytes read (up to `#preload pages`); entry/import/fixup/data
/// offsets all live below this.
const HEADER_MIN: usize = 0x88;
/// Object table entry size.
const OBJECT_REC: usize = 24;
/// Object page table entry size.
const PAGE_REC: usize = 8;

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
const O_PAGE_SHIFT: usize = 0x2C;
const O_FIXUP_SIZE: usize = 0x30;
const O_OBJ_OFF: usize = 0x40;
const O_NUM_OBJ: usize = 0x44;
const O_PAGE_OFF: usize = 0x48;
const O_ENTRY_OFF: usize = 0x5C;
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

/// True when `bytes` looks like MZ + `e_lfanew` → `LE` (no errors).
#[must_use]
pub fn is_le(bytes: &[u8]) -> bool {
    let Some(le_off) = mz_le_offset(bytes) else {
        return false;
    };
    bytes.get(le_off..le_off + 2).is_some_and(|m| m == LE_MAGIC)
}

/// Parse an LE file into [`LeImage`].
///
/// # Errors
/// [`Error::Invalid`] on malformed input,
/// [`Error::Unsupported`] on valid LE the
/// reader does not handle (non-x86 CPU, iterated pages, forwarders),
/// [`Error::Limit`] when table caps are exceeded.
pub fn parse_le(bytes: &[u8]) -> Result<LeImage> {
    let le_off = mz_le_offset(bytes).ok_or_else(|| invalid("missing MZ stub"))?;
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
    let page_shift = u32_at(hdr, O_PAGE_SHIFT)?;
    if page_shift > 16 {
        return Err(invalid(format!("bogus LE page shift {page_shift}")));
    }
    let num_pages = u32_at(hdr, O_NUM_PAGES)? as usize;
    if num_pages > MAX_PAGES {
        return Err(Error::Limit(format!("LE pages {num_pages} exceed cap")));
    }
    let num_obj = u32_at(hdr, O_NUM_OBJ)? as usize;
    if num_obj == 0 || num_obj > MAX_OBJECTS {
        return Err(Error::Limit(format!("LE objects {num_obj} out of range")));
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

    // Object page map.
    let page_abs = rel(O_PAGE_OFF)?;
    let mut pages = Vec::with_capacity(num_pages);
    for i in 0..num_pages {
        let e = page_abs
            .checked_add(i * PAGE_REC)
            .and_then(|p| bytes.get(p..p + PAGE_REC))
            .ok_or_else(|| invalid("page table out of range"))?;
        pages.push((u32_at(e, 0)?, u16_at(e, 4)? as usize, u16_at(e, 6)?));
    }

    // Segments: concatenate each object's pages, zero-padding to page_size.
    // Invalid (`2`) pages are zero-filled like zero pages (`3`): the loader
    // leaves them unmapped, and zeros are the neutral read-only stand-in.
    let data_base = u32_at(hdr, O_DATA_OFF)? as u64;
    if data_base > bytes.len() as u64 {
        return Err(invalid("LE data pages offset out of range"));
    }
    let mut segments = Vec::with_capacity(num_obj);
    for (i, obj) in objects.iter().enumerate() {
        let o = bytes
            .get(obj_abs + i * OBJECT_REC..)
            .ok_or_else(|| invalid("object table out of range"))?;
        let page_idx = u32_at(o, 12)? as usize;
        let page_cnt = u32_at(o, 16)? as usize;
        let mut data = Vec::new();
        for p in 0..page_cnt {
            let (raw, size, flags) = pages[page_idx - 1 + p];
            match flags {
                0 => {
                    let shifted = (raw as u64)
                        .checked_shl(page_shift)
                        .ok_or_else(|| invalid("LE page offset overflow"))?;
                    let off = data_base
                        .checked_add(shifted)
                        .ok_or_else(|| invalid("LE page offset overflow"))?;
                    let end = off
                        .checked_add(size as u64)
                        .ok_or_else(|| invalid("LE page end overflow"))?;
                    if size > page_size as usize || end > bytes.len() as u64 {
                        return Err(invalid("LE page data out of range"));
                    }
                    let start = off as usize;
                    data.extend_from_slice(&bytes[start..start + size]);
                    data.resize(data.len() + page_size as usize - size, 0);
                }
                2 | 3 => data.resize(data.len() + page_size as usize, 0),
                1 => return Err(unsupported("LE iterated data pages")),
                _ => return Err(invalid(format!("unknown LE page flags {flags}"))),
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
    let fixup_size = u32_at(hdr, O_FIXUP_SIZE)? as usize;
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

    // Import tables (length-prefixed, non-NUL-terminated).
    let imp_count = u32_at(hdr, O_IMP_MOD_COUNT)? as usize;
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
        let mods = parse_names(bytes, mod_abs, proc_abs)?;
        if mods.len() != imp_count {
            return Err(invalid("LE import module count mismatch"));
        }
        let procs = parse_names(bytes, proc_abs, section_end)?;
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

fn mz_le_offset(bytes: &[u8]) -> Option<usize> {
    let stub = bytes.get(..MZ_MIN)?;
    if u16_from(&stub[0..2]) != MZ_MAGIC {
        return None;
    }
    Some(u32_from(&stub[E_LFANEW_OFF..E_LFANEW_OFF + 4]) as usize)
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

fn parse_names(bytes: &[u8], start: usize, end: usize) -> Result<Vec<String>> {
    if start > end || end > bytes.len() {
        return Err(invalid("LE name table out of range"));
    }
    let mut out = Vec::new();
    let mut pos = start;
    while pos < end {
        let len = u8_at(bytes, pos)? as usize & 0x7F;
        pos += 1;
        let s = bytes
            .get(pos..pos + len)
            .ok_or_else(|| invalid("LE name entry out of range"))?;
        pos += len;
        out.push(String::from_utf8_lossy(s).into_owned());
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
