//! Bounded literal/wildcard byte search over mapped file bytes.
//!
//! [`BytePattern::parse`] accepts whitespace-separated full-byte tokens
//! (`48 8B ?? ??`); scanning walks each segment's file-backed prefix once in
//! ascending VA order, so gaps between mappings are never bridged, virtual
//! BSS is never materialized, and overlapping section views cannot report a
//! match twice. Sections only attribute matches (name plus file offset).

use crate::error::{Error, Result};
use crate::loader::{BinaryFormat, LoadedBinary};
use memchr::memchr;

/// Cap on pattern length in bytes.
pub const MAX_PATTERN_BYTES: usize = 4096;
/// Cap on unique file-backed mapped bytes scanned per request.
pub const MAX_SCAN_BYTES: u64 = crate::loader::MAX_MAPPED_BYTES;

/// Expected-frequency cost per byte for anchor selection: higher means the
/// byte is expected more often in mapped binaries, so the lowest-cost
/// literal is the rarest anchor. Padding and terminator bytes (`00 FF CC
/// C3 90`) cost most, hot x86 opcode bytes next, ASCII text mid, and all
/// other (control/high) bytes share the rare baseline.
const ANCHOR_COST: [u16; 256] = {
    let mut t = [10u16; 256];
    t[0x00] = 250;
    t[0xFF] = 240;
    t[0xCC] = 230;
    t[0xC3] = 220;
    t[0x90] = 200;
    t[0x48] = 150;
    t[0x89] = 150;
    t[0x8B] = 150;
    t[0xE8] = 150;
    t[0x55] = 140;
    t[0x8D] = 130;
    t[0x83] = 130;
    t[0x81] = 130;
    t[0xEC] = 130;
    t[0xE5] = 130;
    t[0xF3] = 120;
    t[0x0F] = 120;
    t[0x1E] = 120;
    t[0xFA] = 120;
    t[0xE9] = 110;
    t[0xEB] = 110;
    t[0x74] = 110;
    t[0x75] = 110;
    t[0x5D] = 110;
    t[0xC9] = 110;
    t[0xC2] = 110;
    let mut b = 0x20;
    while b <= 0x7E {
        t[b] = 50;
        b += 1;
    }
    t
};

/// Rarest literal in `pattern` as `(index, byte)`; ties keep the earliest
/// index. Every pattern holds at least one literal (see
/// [`BytePattern::parse`]).
fn rarest_anchor(pattern: &[Option<u8>]) -> (usize, u8) {
    let mut best: Option<(usize, u8)> = None;
    for (i, tok) in pattern.iter().enumerate() {
        let Some(b) = tok else { continue };
        let better = match best {
            None => true,
            Some((bi, bb)) => (ANCHOR_COST[*b as usize], i) < (ANCHOR_COST[bb as usize], bi),
        };
        if better {
            best = Some((i, *b));
        }
    }
    best.expect("pattern holds a literal")
}

/// Parsed search pattern: literal bytes plus `??` wildcards.
///
/// At least one literal is guaranteed: [`BytePattern::parse`] rejects empty
/// and all-wildcard input, so every pattern has a literal anchor byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePattern {
    bytes: Vec<Option<u8>>,
}

impl BytePattern {
    /// Parse whitespace-separated full-byte tokens.
    ///
    /// Each token is two hex digits (case-insensitive) or a `??` wildcard.
    ///
    /// # Errors
    /// [`Error::Invalid`] on empty, all-wildcard, odd-length, non-hex, or
    /// over-[`MAX_PATTERN_BYTES`] input.
    pub fn parse(text: &str) -> Result<Self> {
        let mut bytes = Vec::new();
        for tok in text.split_whitespace() {
            if tok.eq_ignore_ascii_case("??") {
                bytes.push(None);
            } else if tok.len() == 2
                && let Some(b) = parse_hex_byte(tok)
            {
                bytes.push(Some(b));
            } else {
                return Err(Error::Invalid(format!("bad search token: {tok:?}")));
            }
            if bytes.len() > MAX_PATTERN_BYTES {
                return Err(Error::Invalid(format!(
                    "search pattern exceeds {MAX_PATTERN_BYTES} bytes"
                )));
            }
        }
        if bytes.is_empty() {
            return Err(Error::Invalid("empty search pattern".to_string()));
        }
        if bytes.iter().all(Option::is_none) {
            return Err(Error::Invalid(
                "search pattern needs at least one literal byte".to_string(),
            ));
        }
        Ok(Self { bytes })
    }

    /// Pattern length in bytes, wildcards included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the pattern holds no tokens (unreachable via [`BytePattern::parse`]).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Pattern tokens in order (`None` is a wildcard).
    #[must_use]
    pub fn bytes(&self) -> &[Option<u8>] {
        &self.bytes
    }
}

/// Parse exactly two hex digits as one byte.
fn parse_hex_byte(tok: &str) -> Option<u8> {
    let mut v: u8 = 0;
    for c in tok.chars() {
        v = v.checked_mul(16)?.checked_add(c.to_digit(16)? as u8)?;
    }
    Some(v)
}

/// One pattern occurrence: virtual address plus file provenance.
///
/// JSON pairs `addr` with `addr_hex`; `addr_hex` is recomputed on serialize
/// and ignored on deserialize. `file_off` is the byte's file offset: from
/// the covering section for containers, from the blob start for raw
/// mappings, null when neither applies. `section` is the covering
/// section's name, null for raw blobs and section-less ranges.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct ByteMatch {
    /// Virtual address of the first matched byte.
    pub addr: u64,
    /// File offset of the first matched byte, if known.
    pub file_off: Option<u64>,
    /// Covering section name, if any.
    pub section: Option<String>,
    /// Match length in bytes (the pattern length).
    pub len: usize,
}

impl serde::Serialize for ByteMatch {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("ByteMatch", 5)?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("file_off", &self.file_off)?;
        st.serialize_field("section", &self.section)?;
        st.serialize_field("len", &self.len)?;
        st.end()
    }
}

/// Scan `binary` for `pattern`, returning the exact total plus the requested page.
///
/// `section` keeps matches fully inside a file-backed section of that exact
/// name ([`Error::NotFound`] when no section matches); `range` is half-open
/// `[lo, hi)` over match VAs (a match must end at or before `hi`; `lo > hi`
/// is normalized, `lo == hi` is [`Error::Invalid`]). `limit` is pre-clipped
/// by the caller to the page cap; matches materialize lazily so only the
/// page window is built while `total` still counts every match. Matches
/// never span segments, gaps, or BSS tails.
///
/// # Errors
/// Pattern, section, and range validation plus [`Error::Limit`] past
/// [`MAX_SCAN_BYTES`] unique scanned bytes.
pub(crate) fn run(
    binary: &LoadedBinary,
    pattern: &BytePattern,
    section: Option<&str>,
    range: Option<(u64, u64)>,
    offset: usize,
    limit: usize,
) -> Result<(usize, Vec<ByteMatch>)> {
    run_limited(
        binary,
        pattern,
        section,
        range,
        offset,
        limit,
        MAX_SCAN_BYTES,
    )
}

/// `run` with an explicit scan budget (tests drive [`Error::Limit`] with small caps).
fn run_limited(
    binary: &LoadedBinary,
    pattern: &BytePattern,
    section: Option<&str>,
    range: Option<(u64, u64)>,
    offset: usize,
    limit: usize,
    max_scan: u64,
) -> Result<(usize, Vec<ByteMatch>)> {
    let allowed = allowed_ranges(binary, section, range)?;
    let mut pieces: Vec<(u64, &[u8], u64)> = Vec::new();
    for seg in &binary.segments {
        if seg.data.is_empty() {
            continue;
        }
        let start = seg.vaddr;
        let end = start.saturating_add(seg.data.len() as u64);
        for (lo, hi) in &allowed {
            let s = start.max(*lo);
            let e = end.min(*hi);
            if s < e {
                let a = (s - start) as usize;
                let b = (e - start) as usize;
                pieces.push((s, &seg.data[a..b], seg.vaddr));
            }
        }
    }
    pieces.sort_by_key(|p| p.0);

    let anchor = rarest_anchor(pattern.bytes());
    let (k, byte) = anchor;
    let m = pattern.len();

    let mut total = 0usize;
    let mut items = Vec::new();
    let mut covered = 0u64;
    let mut scanned = 0u64;
    for (va, hay, seg_vaddr) in pieces {
        let skip = covered.saturating_sub(va) as usize;
        if skip >= hay.len() {
            continue;
        }
        let (hay, va) = (&hay[skip..], va + skip as u64);
        scanned = scanned
            .checked_add(hay.len() as u64)
            .filter(|s| *s <= max_scan)
            .ok_or_else(|| Error::Limit("byte search exceeds 256 MiB scan budget".to_string()))?;
        scan_piece(
            binary, pattern, hay, va, seg_vaddr, k, byte, m, offset, limit, &mut total, &mut items,
        );
        covered = covered.max(va.saturating_add(hay.len() as u64));
    }
    Ok((total, items))
}

/// Half-open VA intervals a match must lie fully inside.
fn allowed_ranges(
    binary: &LoadedBinary,
    section: Option<&str>,
    range: Option<(u64, u64)>,
) -> Result<Vec<(u64, u64)>> {
    let mut intervals = if let Some(name) = section {
        let mut iv: Vec<(u64, u64)> = binary
            .sections
            .iter()
            .filter(|s| s.name == name && s.file_size != 0)
            .map(|s| (s.vaddr, s.vaddr.saturating_add(s.file_size)))
            .collect();
        if !binary.sections.iter().any(|s| s.name == name) {
            return Err(Error::NotFound(format!("no section {name:?}")));
        }
        iv.sort_unstable();
        iv
    } else {
        vec![(0, u64::MAX)]
    };
    if let Some((mut lo, mut hi)) = range {
        if lo > hi {
            std::mem::swap(&mut lo, &mut hi);
        }
        if lo == hi {
            return Err(Error::Invalid("empty search range".to_string()));
        }
        intervals = intervals
            .into_iter()
            .filter_map(|(a, b)| {
                let s = a.max(lo);
                let e = b.min(hi);
                (s < e).then_some((s, e))
            })
            .collect();
    }
    Ok(intervals)
}

/// Anchor occurrences in one deduplicated piece, verifying full windows.
#[allow(clippy::too_many_arguments)]
fn scan_piece(
    binary: &LoadedBinary,
    pattern: &BytePattern,
    hay: &[u8],
    va: u64,
    seg_vaddr: u64,
    anchor_idx: usize,
    anchor: u8,
    m: usize,
    offset: usize,
    limit: usize,
    total: &mut usize,
    items: &mut Vec<ByteMatch>,
) {
    if hay.len() < m {
        return;
    }
    let mut i = 0usize;
    while i + m <= hay.len() {
        let Some(j) = memchr(anchor, &hay[i + anchor_idx..]) else {
            break;
        };
        i += j;
        if i + m > hay.len() {
            break;
        }
        if pattern
            .bytes
            .iter()
            .zip(&hay[i..i + m])
            .all(|(p, b)| p.is_none_or(|x| x == *b))
        {
            let addr = va + i as u64;
            if *total >= offset && items.len() < limit {
                let (file_off, section) = attribute(binary, addr, seg_vaddr);
                items.push(ByteMatch {
                    addr,
                    file_off,
                    section,
                    len: m,
                });
            }
            *total += 1;
        }
        i += 1;
    }
}

/// Section name plus file offset for `addr`, if attributable.
fn attribute(binary: &LoadedBinary, addr: u64, seg_vaddr: u64) -> (Option<u64>, Option<String>) {
    for sec in &binary.sections {
        if sec.file_size == 0 || addr < sec.vaddr {
            continue;
        }
        let d = addr - sec.vaddr;
        if d < sec.file_size {
            return (sec.file_off.checked_add(d), Some(sec.name.clone()));
        }
    }
    if binary.format == BinaryFormat::Raw {
        return (Some(addr - seg_vaddr), None);
    }
    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::Arch;
    use crate::loader::{BinaryFormat, RawOptions, Section, Segment, load_raw};

    fn raw_bin(bytes: &[u8]) -> LoadedBinary {
        load_raw(
            bytes,
            RawOptions {
                base: 0x1000,
                arch: Arch::X86_64,
                entry: None,
            },
        )
        .expect("raw fixture loads")
    }

    #[test]
    fn parse_accepts_mixed_case_and_whitespace() {
        let p = BytePattern::parse("  48 8b\t??\nAB ").expect("valid");
        assert_eq!(
            p.bytes(),
            &[Some(0x48), Some(0x8b), None, Some(0xAB)],
            "hex is case-insensitive"
        );
        assert_eq!(p.len(), 4);
        assert!(!p.is_empty());
    }

    #[test]
    fn parse_rejects_bad_input() {
        for bad in [
            "", "   ", "??", "?? ?? ??", "5", "abc", "zz", "0x55", "5?", "?5", "555", "48 8B ?",
        ] {
            assert!(
                BytePattern::parse(bad).is_err(),
                "must reject {bad:?} (odd/non-hex/empty/all-wildcard)"
            );
        }
    }

    #[test]
    fn parse_enforces_length_cap() {
        let ok = vec!["ab"; MAX_PATTERN_BYTES].join(" ");
        assert_eq!(BytePattern::parse(&ok).expect("4096 passes").len(), 4096);
        let over = vec!["ab"; MAX_PATTERN_BYTES + 1].join(" ");
        assert!(matches!(
            BytePattern::parse(&over).unwrap_err(),
            Error::Invalid(_)
        ));
    }

    #[test]
    fn scan_budget_counts_unique_bytes() {
        let bin = raw_bin(&[0x90; 64]);
        let pat = BytePattern::parse("90").expect("parse");
        let (total, _) =
            run_limited(&bin, &pat, None, None, 0, usize::MAX, 64).expect("exact budget passes");
        assert_eq!(total, 64);
        assert!(matches!(
            run_limited(&bin, &pat, None, None, 0, usize::MAX, 63).unwrap_err(),
            Error::Limit(_)
        ));
    }

    #[test]
    fn scan_never_bridges_segments() {
        let bin = LoadedBinary {
            format: BinaryFormat::Raw,
            arch: Arch::X86_64,
            entry: None,
            segments: vec![
                Segment {
                    vaddr: 0x1000,
                    mem_size: 2,
                    data: vec![0xAA, 0xAA],
                    readable: true,
                    writable: true,
                    executable: true,
                },
                Segment {
                    vaddr: 0x2000,
                    mem_size: 2,
                    data: vec![0xBB, 0xBB],
                    readable: true,
                    writable: true,
                    executable: true,
                },
            ],
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            pdata_funcs: Vec::new(),
            tls_callbacks: Vec::new(),
            init_funcs: Vec::new(),
            func_starts: Vec::new(),
            relocatable: false,
        };
        let spanning = BytePattern::parse("AA AA BB BB").expect("parse");
        let (total, _) = run(&bin, &spanning, None, None, 0, 100).expect("scan");
        assert_eq!(total, 0, "gap bytes must not fuse segments");
        let (total, items) = run(
            &bin,
            &BytePattern::parse("AA").expect("parse"),
            None,
            None,
            0,
            100,
        )
        .expect("scan");
        assert_eq!(total, 2);
        assert_eq!(items[0].addr, 0x1000);
    }

    #[test]
    fn overlapping_segment_views_scan_once() {
        let bin = LoadedBinary {
            format: BinaryFormat::Raw,
            arch: Arch::X86_64,
            entry: None,
            segments: vec![
                Segment {
                    vaddr: 0x1000,
                    mem_size: 4,
                    data: vec![0x90, 0x90, 0x90, 0x90],
                    readable: true,
                    writable: true,
                    executable: true,
                },
                Segment {
                    vaddr: 0x1002,
                    mem_size: 4,
                    data: vec![0x90, 0x90, 0x90, 0x90],
                    readable: true,
                    writable: true,
                    executable: true,
                },
            ],
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            pdata_funcs: Vec::new(),
            tls_callbacks: Vec::new(),
            init_funcs: Vec::new(),
            func_starts: Vec::new(),
            relocatable: false,
        };
        let (total, _) = run(
            &bin,
            &BytePattern::parse("90").expect("parse"),
            None,
            None,
            0,
            100,
        )
        .expect("scan");
        assert_eq!(total, 6, "union 0x1000..0x1006 scanned once, not 4+4");
    }

    #[test]
    fn bss_section_filters_to_empty_page() {
        let bin = LoadedBinary {
            format: BinaryFormat::Elf,
            arch: Arch::X86_64,
            entry: None,
            segments: vec![Segment {
                vaddr: 0x400000,
                mem_size: 0x110,
                data: vec![0x90; 16],
                readable: true,
                writable: false,
                executable: true,
            }],
            sections: vec![Section {
                name: ".bss".to_string(),
                vaddr: 0x400010,
                size: 0x100,
                file_off: 0,
                file_size: 0,
                entropy: 0.0,
                readable: true,
                writable: true,
                executable: false,
            }],
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            pdata_funcs: Vec::new(),
            tls_callbacks: Vec::new(),
            init_funcs: Vec::new(),
            func_starts: Vec::new(),
            relocatable: false,
        };
        let pat = BytePattern::parse("90").expect("parse");
        let (total, _) = run(&bin, &pat, Some(".bss"), None, 0, 10).expect("bss filter");
        assert_eq!(
            total, 0,
            "virtual-only section contributes no searchable bytes"
        );
        let err = run(&bin, &pat, Some(".text"), None, 0, 10).unwrap_err();
        assert!(
            matches!(err, Error::NotFound(_)),
            "unknown section: {err:?}"
        );
    }

    #[test]
    fn range_normalizes_and_rejects_empty() {
        let bin = raw_bin(&[0x55, 0x89, 0xE5]);
        let pat = BytePattern::parse("55 89 e5").expect("parse");
        let swapped = run(&bin, &pat, None, Some((0x1003, 0x1000)), 0, 10).expect("swapped");
        let straight = run(&bin, &pat, None, Some((0x1000, 0x1003)), 0, 10).expect("straight");
        assert_eq!(swapped, straight);
        assert!(matches!(
            run(&bin, &pat, None, Some((0x1000, 0x1000)), 0, 10).unwrap_err(),
            Error::Invalid(_)
        ));
    }
}
