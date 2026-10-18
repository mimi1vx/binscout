//! Go `pclntab` recovery: function names and exact boundaries for
//! stripped Go binaries.
//!
//! The Go linker emits a `pclntab` table (section `.gopclntab` when section
//! headers survive) holding, per function, its entry/end PCs in `functab`
//! and its name via `funcnametab`. Layout follows the Go runtime's own
//! reader (`debug/gosym`, which parses the same bytes): a 4-byte magic
//! selects the version, a small header points at the `funcnametab` and
//! `functab` regions, and each functab pair yields one `[entry, end)`
//! range plus a name offset.
//!
//! Supported magics (little-endian only):
//!
//! | magic | Go versions | functab entry size |
//! |-------|-------------|--------------------|
//! | `0xfffffffb` | 1.2–1.15 | pointer size |
//! | `0xfffffffa` | 1.16–1.17 | pointer size |
//! | `0xfffffff0` | 1.18–1.19 | 4 bytes |
//! | `0xfffffff1` | 1.20+ | 4 bytes |
//!
//! Lookup prefers the `.gopclntab` section and falls back to scanning
//! readable segments for the magic at 4-byte alignment with full header
//! validation, so stripped (section-less) binaries still resolve. Every
//! recovered entry must lie in an executable segment; otherwise the
//! candidate is rejected. For 1.18+ tables the stored offsets are
//! relative to the text base, taken as the `.text` section VA when
//! present, else the lowest executable segment VA (exact for standard
//! builds; `cgo` binaries may shift `runtime.text` — names still match,
//! VAs may not).
//!
//! Read-only: the binary and the sidecar are never written. Big-endian
//! tables (s390x) are rejected as unsupported.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::loader::LoadedBinary;

/// `pclntab` magic for Go 1.2–1.15.
pub const GO12_MAGIC: u32 = 0xfffffffb;
/// `pclntab` magic for Go 1.16–1.17.
pub const GO116_MAGIC: u32 = 0xfffffffa;
/// `pclntab` magic for Go 1.18–1.19.
pub const GO118_MAGIC: u32 = 0xfffffff0;
/// `pclntab` magic for Go 1.20+.
pub const GO120_MAGIC: u32 = 0xfffffff1;

/// All supported magics, little-endian.
const KNOWN_MAGICS: [u32; 4] = [GO12_MAGIC, GO116_MAGIC, GO118_MAGIC, GO120_MAGIC];

/// One Go function: its linker name plus the exact `[entry, end)` range
/// from `functab`.
///
/// JSON pairs `entry` with `entry_hex` and `end` with `end_hex`, plus the
/// `size` (`end - entry`); twins are recomputed on serialize and ignored
/// on deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GoFunc {
    /// Function entry address.
    pub entry: u64,
    /// Function end address (exclusive: the next functab entry).
    pub end: u64,
    /// Linker name from `funcnametab` (e.g. `main.main`).
    pub name: String,
}

impl Serialize for GoFunc {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("GoFunc", 6)?;
        st.serialize_field("entry", &self.entry)?;
        st.serialize_field("entry_hex", &crate::addr_hex(self.entry))?;
        st.serialize_field("end", &self.end)?;
        st.serialize_field("end_hex", &crate::addr_hex(self.end))?;
        st.serialize_field("size", &self.size())?;
        st.serialize_field("name", &self.name)?;
        st.end()
    }
}

impl GoFunc {
    /// Byte size of the `[entry, end)` range.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.entry)
    }
}

/// Table class selected by the header magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TableClass {
    /// Go 1.2–1.15: pointer-sized functab fields and header words, names
    /// addressed into the whole table.
    Go12,
    /// Go 1.16–1.17: like 1.2 with a separate `funcnametab` region.
    Go116,
    /// Go 1.18+: fixed 4-byte functab fields, PCs relative to the text base.
    New,
}

impl TableClass {
    /// Classify a little-endian magic.
    fn classify(magic: u32) -> Option<Self> {
        match magic {
            GO12_MAGIC => Some(Self::Go12),
            GO116_MAGIC => Some(Self::Go116),
            GO118_MAGIC | GO120_MAGIC => Some(Self::New),
            _ => None,
        }
    }
}

/// Little-endian `u32` at `off`, bounds-checked.
fn le_u32_at(data: &[u8], off: usize) -> Result<u32> {
    let end = off
        .checked_add(4)
        .ok_or_else(|| Error::Invalid("truncated Go pclntab (u32 past end)".to_string()))?;
    if end > data.len() {
        return Err(Error::Invalid(
            "truncated Go pclntab (u32 past end)".to_string(),
        ));
    }
    Ok(u32::from_le_bytes(
        data[off..end].try_into().expect("4 bytes"),
    ))
}

/// Pointer-sized word at `off` (`ptrsize` 4 or 8), bounds-checked.
fn word_at(data: &[u8], off: usize, ptrsize: u8) -> Result<u64> {
    if ptrsize == 4 {
        return Ok(u64::from(le_u32_at(data, off)?));
    }
    let end = off
        .checked_add(8)
        .ok_or_else(|| Error::Invalid("truncated Go pclntab (word past end)".to_string()))?;
    if end > data.len() {
        return Err(Error::Invalid(
            "truncated Go pclntab (word past end)".to_string(),
        ));
    }
    Ok(u64::from_le_bytes(
        data[off..end].try_into().expect("8 bytes"),
    ))
}

/// NUL-terminated lossy string at `off` (stays inside `data`).
fn cstr_at(data: &[u8], off: usize) -> Result<String> {
    let rest = data
        .get(off..)
        .ok_or_else(|| Error::Invalid("Go funcnametab offset past end".to_string()))?;
    let end = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Error::Invalid("unterminated Go function name".to_string()))?;
    Ok(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// File-backed bytes of section `name`, resolved through the covering
/// segment (sections are metadata-only).
fn section_data<'a>(binary: &'a LoadedBinary, name: &str) -> Option<&'a [u8]> {
    let sec = binary.sections.iter().find(|s| s.name == name)?;
    if sec.file_size == 0 {
        return None;
    }
    let seg = binary.segments.iter().find(|g| {
        g.vaddr <= sec.vaddr
            && sec
                .vaddr
                .saturating_sub(g.vaddr)
                .saturating_add(sec.file_size)
                <= g.data.len() as u64
    })?;
    let off = (sec.vaddr - seg.vaddr) as usize;
    Some(&seg.data[off..off + sec.file_size as usize])
}

/// Text base for 1.18+ PC offsets: `.text` VA when sections survive, else
/// the lowest executable segment VA, else the lowest segment VA.
fn text_start(binary: &LoadedBinary) -> u64 {
    if let Some(sec) = binary.sections.iter().find(|s| s.name == ".text") {
        return sec.vaddr;
    }
    binary
        .segments
        .iter()
        .filter(|g| g.executable)
        .map(|g| g.vaddr)
        .min()
        .or_else(|| binary.segments.iter().map(|g| g.vaddr).min())
        .unwrap_or(0)
}

/// Whether `va` lies in an executable segment.
fn in_executable(binary: &LoadedBinary, va: u64) -> bool {
    binary
        .segments
        .iter()
        .any(|g| g.executable && va >= g.vaddr && va.saturating_sub(g.vaddr) < g.mem_size)
}

/// Parse one `pclntab` image (starting at its magic) into Go functions.
///
/// `text_base` anchors 1.18+ relative PCs. Every bound is checked: any
/// truncation, implausible count, out-of-range offset, or entry outside
/// executable memory is [`Error::Invalid`].
fn parse_table(data: &[u8], text_base: u64, binary: &LoadedBinary) -> Result<Vec<GoFunc>> {
    if data.len() < 16 {
        return Err(Error::Invalid(
            "Go pclntab shorter than its header".to_string(),
        ));
    }
    let magic = le_u32_at(data, 0)?;
    let Some(class) = TableClass::classify(magic) else {
        if KNOWN_MAGICS.contains(&u32::from_be_bytes(data[0..4].try_into().expect("4 bytes"))) {
            return Err(Error::Unsupported(
                "big-endian Go pclntab is not supported".to_string(),
            ));
        }
        return Err(Error::Invalid(format!(
            "unknown Go pclntab magic {magic:#010x}"
        )));
    };
    if data[4] != 0 || data[5] != 0 {
        return Err(Error::Invalid("Go pclntab with nonzero pad".to_string()));
    }
    let quantum = data[6];
    if quantum != 1 && quantum != 2 && quantum != 4 {
        return Err(Error::Invalid(format!("bad Go pclntab quantum {quantum}")));
    }
    let ptrsize = data[7];
    if ptrsize != 4 && ptrsize != 8 {
        return Err(Error::Invalid(format!("bad Go pclntab ptrsize {ptrsize}")));
    }
    // Header words are pointer-sized in every version; functab fields are
    // pointer-sized before 1.18 and fixed 4-byte after.
    let word = |i: usize| word_at(data, 8 + i * usize::from(ptrsize), ptrsize);
    let (nfunc, names_off, functab_off, funcdata_off, field, name_sz0) = match class {
        TableClass::New => {
            let n = word(0)?;
            let names = word(3)?;
            let functab = word(7)?;
            (n, names, functab, functab, 4usize, 4u64)
        }
        TableClass::Go116 => {
            let n = word(0)?;
            let names = word(2)?;
            let functab = word(6)?;
            (
                n,
                names,
                functab,
                functab,
                usize::from(ptrsize),
                u64::from(ptrsize),
            )
        }
        TableClass::Go12 => {
            let n = word(0)?;
            (
                n,
                0,
                8 + u64::from(ptrsize),
                0,
                usize::from(ptrsize),
                u64::from(ptrsize),
            )
        }
    };
    if nfunc == 0 {
        return Err(Error::Invalid("Go pclntab with no functions".to_string()));
    }
    let functab_len = (nfunc
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(field as u64)))
    .ok_or_else(|| Error::Invalid("Go pclntab functab size overflows".to_string()))?;
    let functab_off = usize::try_from(functab_off)
        .map_err(|_| Error::Invalid("Go pclntab functab past end".to_string()))?;
    let functab_end = functab_off
        .checked_add(
            usize::try_from(functab_len)
                .map_err(|_| Error::Invalid("Go pclntab functab size overflows".to_string()))?,
        )
        .ok_or_else(|| Error::Invalid("Go pclntab functab past end".to_string()))?;
    if functab_end > data.len() {
        return Err(Error::Invalid("Go pclntab functab past end".to_string()));
    }
    let names_off = usize::try_from(names_off)
        .map_err(|_| Error::Invalid("Go funcnametab past end".to_string()))?;
    if names_off > data.len() {
        return Err(Error::Invalid("Go funcnametab past end".to_string()));
    }
    let funcdata_off = usize::try_from(funcdata_off)
        .map_err(|_| Error::Invalid("Go funcdata past end".to_string()))?;
    if funcdata_off > data.len() {
        return Err(Error::Invalid("Go funcdata past end".to_string()));
    }
    let names = &data[names_off..];
    let read_pc = |i: u64| -> Result<u64> {
        let off = functab_off
            .checked_add(
                usize::try_from(
                    i.checked_mul(2)
                        .and_then(|n| n.checked_mul(field as u64))
                        .ok_or_else(|| {
                            Error::Invalid("Go pclntab functab offset overflows".to_string())
                        })?,
                )
                .map_err(|_| Error::Invalid("Go pclntab functab offset overflows".to_string()))?,
            )
            .ok_or_else(|| Error::Invalid("Go pclntab functab offset overflows".to_string()))?;
        let raw = if field == 4 {
            u64::from(le_u32_at(data, off)?)
        } else {
            word_at(data, off, ptrsize)?
        };
        Ok(if class == TableClass::New {
            text_base.wrapping_add(raw)
        } else {
            raw
        })
    };
    let read_funcoff = |i: u64| -> Result<u64> {
        let off = functab_off
            .checked_add(
                usize::try_from(
                    i.checked_mul(2)
                        .and_then(|n| n.checked_add(1))
                        .and_then(|n| n.checked_mul(field as u64))
                        .ok_or_else(|| {
                            Error::Invalid("Go pclntab functab offset overflows".to_string())
                        })?,
                )
                .map_err(|_| Error::Invalid("Go pclntab functab offset overflows".to_string()))?,
            )
            .ok_or_else(|| Error::Invalid("Go pclntab functab offset overflows".to_string()))?;
        if field == 4 {
            Ok(u64::from(le_u32_at(data, off)?))
        } else {
            word_at(data, off, ptrsize)
        }
    };
    let mut pcs = Vec::with_capacity(nfunc.min(1 << 20) as usize + 1);
    for i in 0..=nfunc {
        let pc = read_pc(i)?;
        if !in_executable(binary, pc) {
            return Err(Error::Invalid(format!(
                "Go pclntab entry {pc:#x} outside executable memory"
            )));
        }
        pcs.push(pc);
    }
    let mut funcs = Vec::with_capacity(nfunc.min(1 << 20) as usize);
    for i in 0..nfunc {
        let funcoff = read_funcoff(i)?;
        let name_off = funcdata_off
            .checked_add(
                usize::try_from(funcoff)
                    .map_err(|_| Error::Invalid("Go funcdata offset past end".to_string()))?,
            )
            .and_then(|o| o.checked_add(name_sz0 as usize))
            .ok_or_else(|| Error::Invalid("Go funcdata offset past end".to_string()))?;
        let name_rel = le_u32_at(data, name_off)? as usize;
        let name = cstr_at(names, name_rel)?;
        funcs.push(GoFunc {
            entry: pcs[i as usize],
            end: pcs[i as usize + 1],
            name,
        });
    }
    Ok(funcs)
}

/// Recover Go functions from `binary`: names plus exact `[entry, end)`
/// ranges from the `pclntab` functab/funcnametab.
///
/// Prefers the `.gopclntab` section; without section headers, scans
/// readable segments for a supported magic with full header validation.
/// Returns an empty vector when no table is located (not a Go binary, or
/// no recognizable table) — only a located-but-corrupt table errors.
///
/// Read-only: never writes the binary or the sidecar.
///
/// # Errors
/// [`Error::Invalid`] on a corrupt located table,
/// [`Error::Unsupported`] on a big-endian table.
pub fn recover(binary: &LoadedBinary) -> Result<Vec<GoFunc>> {
    let text_base = text_start(binary);
    if let Some(data) = section_data(binary, ".gopclntab") {
        return parse_table(data, text_base, binary);
    }
    for seg in &binary.segments {
        if seg.data.len() < 16 {
            continue;
        }
        let mut off = 0;
        while off + 4 <= seg.data.len() {
            let magic = u32::from_le_bytes(seg.data[off..off + 4].try_into().expect("4 bytes"));
            if KNOWN_MAGICS.contains(&magic)
                && let Ok(funcs) = parse_table(&seg.data[off..], text_base, binary)
            {
                return Ok(funcs);
            }
            off += 4;
        }
    }
    Ok(Vec::new())
}
