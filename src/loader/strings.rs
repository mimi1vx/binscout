//! Printable-string extractor (M1, `rsdbg-m1-loader-0tp`).
//!
//! Three passes over the buffer — ASCII plus UTF-16LE/BE restricted to the
//! ASCII subset (`c, 0x00` / `0x00, c`) — reporting runs of at least
//! `min_len` characters, sorted by offset and capped at `max_hits`.
//! Overlapping hits from different encodings may occur at the same offset
//! (e.g. an LE run contains a shifted BE run); all are reported.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Default minimum run length in characters.
pub const DEFAULT_MIN_LEN: usize = 4;
/// Default cap on hits per scan.
pub const DEFAULT_MAX_HITS: usize = 10_000;
/// Cap on `--pattern` length; longer patterns are rejected, never truncated.
pub const MAX_PATTERN_LEN: usize = 1024;
/// Prefix opting a `--pattern` into regex matching (`regex:` + expression).
pub const REGEX_PREFIX: &str = "regex:";

/// Encoding of an extracted string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Encoding {
    /// Single-byte printable runs.
    Ascii,
    /// UTF-16LE runs over the ASCII subset.
    Utf16Le,
    /// UTF-16BE runs over the ASCII subset.
    Utf16Be,
}

/// One extracted string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringHit {
    /// Byte offset within the scanned buffer.
    pub offset: usize,
    /// Virtual address when the caller scans with a known base
    /// (`base_va + offset`); `None` for whole-file scans.
    pub vaddr: Option<u64>,
    /// Detected encoding.
    pub encoding: Encoding,
    /// Decoded text.
    pub value: String,
    /// Containing section name (`None` for whole-file scans and raw blobs,
    /// which have no section table). Old sidecar rows predate this field
    /// and decode as `None`.
    #[serde(default)]
    pub section: Option<String>,
    /// Whether the hit lies in executable memory, resolved at extraction
    /// from the section (or segment, when there is no section table).
    /// Old sidecar rows predate this field and decode as `false` (shown).
    #[serde(default)]
    pub executable: bool,
}

/// Test `value` against a `strings` query pattern.
///
/// A `regex:`-prefixed pattern compiles the rest as a [`regex`] expression
/// (unanchored, case-sensitive unless `(?i)` is given); anything else is a
/// case-sensitive substring. An empty pattern matches everything. The
/// `regex` crate runs in linear time, so opt-in regexes cannot backtrack
/// into a ReDoS.
///
/// # Errors
/// [`Error::Invalid`] when the pattern exceeds [`MAX_PATTERN_LEN`] or a
/// `regex:` expression fails to compile. A bad regex is an error, never a
/// silent fallback to substring matching.
pub fn matches_pattern(value: &str, pattern: &str) -> Result<bool> {
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(Error::Invalid(format!(
            "pattern exceeds {MAX_PATTERN_LEN} bytes"
        )));
    }
    if pattern.is_empty() {
        return Ok(true);
    }
    match pattern.strip_prefix(REGEX_PREFIX) {
        Some(expr) => regex::Regex::new(expr)
            .map(|re| re.is_match(value))
            .map_err(|e| Error::Invalid(format!("bad regex pattern {pattern:?}: {e}"))),
        None => Ok(value.contains(pattern)),
    }
}

/// Scan `bytes` for strings, sorted by offset, capped at `max_hits`.
///
/// `min_len` below 1 is treated as 1. `base_va` maps hit offsets to virtual
/// addresses (pass `Some(seg.vaddr)` for segment scans, `None` for files).
#[must_use]
pub fn extract(
    bytes: &[u8],
    min_len: usize,
    max_hits: usize,
    base_va: Option<u64>,
) -> Vec<StringHit> {
    let min = min_len.max(1);
    let mut hits = Vec::new();
    scan_ascii(bytes, min, &mut hits, base_va);
    scan_utf16(bytes, min, true, &mut hits, base_va);
    scan_utf16(bytes, min, false, &mut hits, base_va);
    hits.sort_by_key(|h| h.offset);
    hits.truncate(max_hits);
    hits
}

/// Page over [`extract`] hits: skip `offset` hits, return at most `limit`.
///
/// The scan still caps at `max_hits` first, so deep pages past the cap come
/// back short or empty.
#[must_use]
pub fn extract_page(
    bytes: &[u8],
    min_len: usize,
    max_hits: usize,
    base_va: Option<u64>,
    offset: usize,
    limit: usize,
) -> Vec<StringHit> {
    extract(bytes, min_len, max_hits, base_va)
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect()
}

fn is_print(b: u8) -> bool {
    matches!(b, 0x20..=0x7E)
}

fn va(base_va: Option<u64>, offset: usize) -> Option<u64> {
    base_va.map(|b| b.wrapping_add(offset as u64))
}

fn scan_ascii(bytes: &[u8], min: usize, out: &mut Vec<StringHit>, base_va: Option<u64>) {
    let mut i = 0;
    while i < bytes.len() {
        if is_print(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_print(bytes[i]) {
                i += 1;
            }
            if i - start >= min {
                out.push(StringHit {
                    offset: start,
                    vaddr: va(base_va, start),
                    encoding: Encoding::Ascii,
                    value: String::from_utf8_lossy(&bytes[start..i]).into_owned(),
                    section: None,
                    executable: false,
                });
            }
        } else {
            i += 1;
        }
    }
}

fn scan_utf16(
    bytes: &[u8],
    min: usize,
    little: bool,
    out: &mut Vec<StringHit>,
    base_va: Option<u64>,
) {
    let mut i = 0;
    while i + 1 < bytes.len() {
        if unit_at(bytes, i, little).is_some() {
            let start = i;
            let mut value = String::new();
            while let Some(c) = unit_at(bytes, i, little) {
                value.push(c as char);
                i += 2;
            }
            if value.len() >= min {
                out.push(StringHit {
                    offset: start,
                    vaddr: va(base_va, start),
                    encoding: if little {
                        Encoding::Utf16Le
                    } else {
                        Encoding::Utf16Be
                    },
                    value,
                    section: None,
                    executable: false,
                });
            }
        } else {
            i += 1;
        }
    }
}

fn unit_at(bytes: &[u8], i: usize, little: bool) -> Option<u8> {
    let pair = bytes.get(i..i + 2)?;
    let (c, z) = if little {
        (pair[0], pair[1])
    } else {
        (pair[1], pair[0])
    };
    (is_print(c) && z == 0).then_some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_runs_need_min_len() {
        let hits = extract(b"\x00hi\x00hello\x00", 4, 100, None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].value, "hello");
        assert_eq!(hits[0].offset, 4);
        assert_eq!(hits[0].encoding, Encoding::Ascii);
        assert_eq!(hits[0].vaddr, None);
    }

    #[test]
    fn utf16_both_endians_detected() {
        // "AB" LE @0, "CD" BE @6.
        let bytes = [0x41, 0x00, 0x42, 0x00, 0xFF, 0xFF, 0x00, 0x43, 0x00, 0x44];
        let hits = extract(&bytes, 2, 100, Some(0x1000));
        assert_eq!(
            hits,
            [
                StringHit {
                    offset: 0,
                    vaddr: Some(0x1000),
                    encoding: Encoding::Utf16Le,
                    value: "AB".to_string(),
                    section: None,
                    executable: false,
                },
                StringHit {
                    offset: 6,
                    vaddr: Some(0x1006),
                    encoding: Encoding::Utf16Be,
                    value: "CD".to_string(),
                    section: None,
                    executable: false,
                },
            ]
        );
    }

    #[test]
    fn paging_slices_hits() {
        let mut bytes = Vec::new();
        for i in 0..10 {
            bytes.extend_from_slice(format!("s{i:03}\x00").as_bytes());
        }
        let page = extract_page(&bytes, 4, 100, None, 3, 4);
        assert_eq!(
            page.iter().map(|h| h.value.as_str()).collect::<Vec<_>>(),
            ["s003", "s004", "s005", "s006"]
        );
        let capped = extract(&bytes, 4, 3, None);
        assert_eq!(capped.len(), 3);
    }

    #[test]
    fn pattern_matches_substring_by_default() {
        assert!(matches_pattern("SAVE%d.GAM is invalid", "SAVE").unwrap());
        assert!(matches_pattern("SAVE%d.GAM is invalid", "GAM is").unwrap());
        assert!(!matches_pattern("SAVE%d.GAM is invalid", "save").unwrap());
        assert!(!matches_pattern("SAVE%d.GAM is invalid", "zzz").unwrap());
        assert!(matches_pattern("anything", "").unwrap());
        // `regex:` inside the value is literal; only a pattern prefix opts in.
        assert!(matches_pattern("regex:SAVE", "SAVE").unwrap());
    }

    #[test]
    fn pattern_regex_prefix_opts_in() {
        assert!(matches_pattern("SAVE%d.GAM is invalid", "regex:SAVE.*invalid").unwrap());
        assert!(matches_pattern("SAVE%d.GAM is invalid", "regex:(?i)save").unwrap());
        assert!(!matches_pattern("SAVE%d.GAM is invalid", "regex:^invalid").unwrap());
    }

    #[test]
    fn pattern_bad_regex_and_overlong_are_errors() {
        assert!(matches_pattern("x", "regex:([").is_err());
        assert!(matches_pattern("x", &"y".repeat(MAX_PATTERN_LEN + 1)).is_err());
        assert!(matches_pattern("x", &"y".repeat(MAX_PATTERN_LEN)).is_ok());
    }

    #[test]
    fn old_rows_decode_without_new_fields() {
        let hit: StringHit =
            serde_json::from_str(r#"{"offset":1,"vaddr":4096,"encoding":"Ascii","value":"hi"}"#)
                .expect("old rows must still decode");
        assert_eq!(hit.section, None);
        assert!(!hit.executable);
    }
}
