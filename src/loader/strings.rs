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
///
/// JSON pairs `vaddr` with `vaddr_hex` (`null` on both sides for whole-file
/// scans with no base); old rows without the twin still deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

impl Serialize for StringHit {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("StringHit", 7)?;
        st.serialize_field("offset", &self.offset)?;
        st.serialize_field("vaddr", &self.vaddr)?;
        st.serialize_field("vaddr_hex", &self.vaddr.map(crate::addr_hex))?;
        st.serialize_field("encoding", &self.encoding)?;
        st.serialize_field("value", &self.value)?;
        st.serialize_field("section", &self.section)?;
        st.serialize_field("executable", &self.executable)?;
        st.end()
    }
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
/// Only the first `max_hits` hits in offset order are decoded, so a small
/// cap bounds intermediate owned strings even on dense inputs; `max_hits`
/// of zero returns empty without scanning.
#[must_use]
pub fn extract(
    bytes: &[u8],
    min_len: usize,
    max_hits: usize,
    base_va: Option<u64>,
) -> Vec<StringHit> {
    if max_hits == 0 {
        return Vec::new();
    }
    let min = min_len.max(1);
    let mut pos_ascii = 0usize;
    let mut pos_le = 0usize;
    let mut pos_be = 0usize;
    let mut next_ascii = next_ascii_run(bytes, min, &mut pos_ascii);
    let mut next_le = next_utf16_run(bytes, min, true, &mut pos_le);
    let mut next_be = next_utf16_run(bytes, min, false, &mut pos_be);
    let mut hits = Vec::new();
    while hits.len() < max_hits {
        let pick = pick_next(next_ascii, next_le, next_be);
        let Some((order, run)) = pick else {
            break;
        };
        hits.push(decode_run(bytes, run, base_va));
        match order {
            0 => next_ascii = next_ascii_run(bytes, min, &mut pos_ascii),
            1 => next_le = next_utf16_run(bytes, min, true, &mut pos_le),
            _ => next_be = next_utf16_run(bytes, min, false, &mut pos_be),
        }
    }
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

/// Byte span of one candidate run, decoded only when selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Run {
    offset: usize,
    end: usize,
    encoding: Encoding,
}

/// Next ASCII run at or after `*pos`, advancing `*pos` past it.
fn next_ascii_run(bytes: &[u8], min: usize, pos: &mut usize) -> Option<Run> {
    while *pos < bytes.len() {
        if is_print(bytes[*pos]) {
            let start = *pos;
            while *pos < bytes.len() && is_print(bytes[*pos]) {
                *pos += 1;
            }
            if *pos - start >= min {
                return Some(Run {
                    offset: start,
                    end: *pos,
                    encoding: Encoding::Ascii,
                });
            }
        } else {
            *pos += 1;
        }
    }
    None
}

/// Next UTF-16 run at or after `*pos`, advancing `*pos` past it.
///
/// Counts units before allocating, so rejected short runs never build a
/// `String`; the end position matches the old push-then-check scan.
fn next_utf16_run(bytes: &[u8], min: usize, little: bool, pos: &mut usize) -> Option<Run> {
    let encoding = if little {
        Encoding::Utf16Le
    } else {
        Encoding::Utf16Be
    };
    while *pos + 1 < bytes.len() {
        if unit_at(bytes, *pos, little).is_some() {
            let start = *pos;
            let mut count = 0usize;
            while unit_at(bytes, *pos, little).is_some() {
                count += 1;
                *pos += 2;
            }
            if count >= min {
                return Some(Run {
                    offset: start,
                    end: *pos,
                    encoding,
                });
            }
        } else {
            *pos += 1;
        }
    }
    None
}

/// Smallest pending run by `(offset, encoding order)`; ASCII (0) then
/// LE (1) then BE (2) reproduces the old append-plus-stable-sort tie-break.
fn pick_next(ascii: Option<Run>, le: Option<Run>, be: Option<Run>) -> Option<(u8, Run)> {
    let mut best: Option<(u8, Run)> = None;
    for (order, cand) in [(0u8, ascii), (1u8, le), (2u8, be)] {
        let Some(run) = cand else {
            continue;
        };
        let replace = match best {
            None => true,
            Some((best_order, best_run)) => (run.offset, order) < (best_run.offset, best_order),
        };
        if replace {
            best = Some((order, run));
        }
    }
    best
}

/// Decode a selected run; spans come from the same scans as before.
fn decode_run(bytes: &[u8], run: Run, base_va: Option<u64>) -> StringHit {
    let value = match run.encoding {
        Encoding::Ascii => String::from_utf8_lossy(&bytes[run.offset..run.end]).into_owned(),
        Encoding::Utf16Le => {
            let mut value = String::with_capacity((run.end - run.offset) / 2);
            let mut i = run.offset;
            while i < run.end {
                if let Some(c) = unit_at(bytes, i, true) {
                    value.push(c as char);
                    i += 2;
                } else {
                    break;
                }
            }
            value
        }
        Encoding::Utf16Be => {
            let mut value = String::with_capacity((run.end - run.offset) / 2);
            let mut i = run.offset;
            while i < run.end {
                if let Some(c) = unit_at(bytes, i, false) {
                    value.push(c as char);
                    i += 2;
                } else {
                    break;
                }
            }
            value
        }
    };
    StringHit {
        offset: run.offset,
        vaddr: va(base_va, run.offset),
        encoding: run.encoding,
        value,
        section: None,
        executable: false,
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
