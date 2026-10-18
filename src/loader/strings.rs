//! Printable-string extractor (M1, `rsdbg-m1-loader-0tp`).
//!
//! Five passes over the buffer — ASCII, UTF-16LE/BE restricted to the
//! ASCII subset (`c, 0x00` / `0x00, c`), UTF-8 runs holding at least one
//! non-ASCII character, and UTF-16LE runs over non-ASCII BMP letters
//! (disjoint from the ASCII-subset LE pass, so classic runs never merge
//! or move) — reporting runs of at least `min_len` characters, sorted by
//! offset and capped at `max_hits`. Overlapping hits from different
//! encodings may occur at the same offset (e.g. an LE run contains a
//! shifted BE run, or an ASCII run prefixes a UTF-8 run); all are
//! reported. Base64 blobs are a separate decoded-view pass (see
//! [`extract_base64`]): `strings --decode base64` only, never stored.

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
    /// UTF-8 runs holding at least one non-ASCII character (CJK,
    /// Cyrillic, emoji, ...). Pure-ASCII runs report as [`Encoding::Ascii`]
    /// only, never here.
    Utf8,
    /// UTF-16LE runs over non-ASCII BMP letters. Disjoint from
    /// [`Encoding::Utf16Le`]: a unit is ASCII-subset or BMP-only, never
    /// both, so the two LE passes partition the buffer and classic runs
    /// never merge into BMP runs or move.
    Utf16LeBmp,
    /// Base64-decoded view: the decoded plaintext of a base64 blob
    /// (see [`extract_base64`]). Only produced by the
    /// [`DecodeSpec::Base64`] decoded view, never stored.
    Base64,
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

/// Decoded-view transform for the `strings --decode` helper.
///
/// Explicit allowlist: single-byte XOR, rolling multi-byte XOR,
/// wrapping add, bitwise left rotation, and base64 detection. Byte
/// transforms apply to an in-memory copy of the mapped bytes before
/// extraction, so the binary and the sidecar are never written; hit
/// offsets and virtual addresses still refer to the original binary.
/// [`DecodeSpec::Base64`] is not a byte transform (see [`apply`](DecodeSpec::apply)):
/// the decoded view instead detects base64 blobs and reports their
/// plaintext (see [`extract_base64`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeSpec {
    /// XOR every byte with the key (`xor:<byte>`).
    Xor(u8),
    /// XOR every byte with the rolling multi-byte key
    /// (`xor:0x<HEXKEY>` with 4+ hex digits, byte `i` uses
    /// `key[i % key.len()]`).
    XorMulti(Vec<u8>),
    /// Wrapping-add the key to every byte (`add:<byte>`).
    Add(u8),
    /// Rotate every byte left by this many bits (`rot:<0-7>`).
    Rot(u8),
    /// Detect base64 blobs and report their decoded plaintext
    /// (bare `base64`, no argument).
    Base64,
}

/// Cap on rolling-XOR key bytes (`xor:0x<HEXKEY>`); longer keys are rejected, never truncated.
pub const MAX_XOR_KEY_LEN: usize = 32;
/// Cap on the ASCII source-run bytes [`extract_base64`] will decode; longer
/// runs are skipped, so one huge printable span cannot blow up the view.
pub const MAX_BASE64_RUN_BYTES: usize = 64 * 1024;

impl DecodeSpec {
    /// Apply the transform to `bytes`, returning the decoded copy.
    ///
    /// Pure and bounded: output length equals input length, no I/O.
    /// [`DecodeSpec::Base64`] has no byte-level transform and returns the
    /// input unchanged; use the strings decoded-view query, which detects
    /// blobs via [`extract_base64`] instead.
    #[must_use]
    pub fn apply(&self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Xor(key) => bytes.iter().map(|b| b ^ key).collect(),
            Self::XorMulti(key) => {
                if key.is_empty() {
                    return bytes.to_vec();
                }
                bytes
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key[i % key.len()])
                    .collect()
            }
            Self::Add(key) => bytes.iter().map(|b| b.wrapping_add(*key)).collect(),
            Self::Rot(n) => bytes.iter().map(|b| b.rotate_left(u32::from(*n))).collect(),
            Self::Base64 => bytes.to_vec(),
        }
    }
}

/// Parse a `strings --decode` spec: `xor:<byte>`, `xor:0x<HEXKEY>`,
/// `add:<byte>`, `rot:<n>`, or bare `base64`.
///
/// Byte/key values parse as `0x`-hex or decimal (`xor:0x41`, `add:65`);
/// `rot` takes `0`-`7` (data obfuscated with a right rotation by `n` needs
/// `rot:<8-n>`). A `0x` value that fits in one byte is the single-byte
/// form (so `xor:0x41` and the zero-padded `xor:0x0041` both mean key
/// `0x41`, as before); a `0x` value of 4+ even hex digits above `0xFF`
/// (up to [`MAX_XOR_KEY_LEN`] bytes) is a rolling multi-byte key
/// (`xor:0x4142` xors bytes alternately with `0x41`, `0x42`). Matching is
/// case-insensitive on the op name. Anything outside the allowlist is an
/// error, never a silent fallback.
///
/// # Errors
/// [`Error::Invalid`] for any other shape or out-of-range value.
pub fn parse_decode_spec(s: &str) -> Result<DecodeSpec> {
    const HELP: &str = "expected one of xor:<byte>, xor:0x<HEXKEY> (4+ hex digits, rolling key, max 32 bytes), add:<byte>, rot:<0-7>, or base64 (byte is 0x-hex or decimal)";
    if s.eq_ignore_ascii_case("base64") {
        return Ok(DecodeSpec::Base64);
    }
    let (op, val) = s
        .split_once(':')
        .ok_or_else(|| Error::Invalid(format!("bad decode spec {s:?}: {HELP}")))?;
    let bad = || Error::Invalid(format!("bad decode spec {s:?}: {HELP}"));
    match op.to_lowercase().as_str() {
        "xor" => parse_xor_spec(val).ok_or_else(bad),
        "add" => {
            let byte = parse_decode_byte(val).ok_or_else(bad)?;
            Ok(DecodeSpec::Add(byte))
        }
        "rot" => {
            let byte = parse_decode_byte(val).ok_or_else(bad)?;
            if byte > 7 {
                return Err(bad());
            }
            Ok(DecodeSpec::Rot(byte))
        }
        _ => Err(bad()),
    }
}

/// Parse the `xor:` value: single byte (`0x`-hex or decimal, as before)
/// or a rolling multi-byte `0x` hex key (see [`parse_decode_spec`]).
fn parse_xor_spec(val: &str) -> Option<DecodeSpec> {
    let t = val.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        if hex.is_empty() || hex.len() > MAX_XOR_KEY_LEN * 2 {
            return None;
        }
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        // Whole value fits in one byte: the single-byte form, including
        // zero-padded spellings (`0x0041` is key `0x41`, as before).
        if let Ok(v) = u64::from_str_radix(hex, 16)
            && let Ok(byte) = u8::try_from(v)
        {
            return Some(DecodeSpec::Xor(byte));
        }
        // Otherwise a rolling key needs 4+ even hex digits.
        if hex.len() < 4 || hex.len() % 2 != 0 {
            return None;
        }
        let mut key = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            key.push(u8::from_str_radix(&hex[i..i + 2], 16).ok()?);
        }
        return Some(DecodeSpec::XorMulti(key));
    }
    parse_decode_byte(t).map(DecodeSpec::Xor)
}

/// Parse a `0x`-hex or decimal byte value (`0`-`255`).
fn parse_decode_byte(s: &str) -> Option<u8> {
    let s = s.trim();
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        s.parse::<u64>().ok()?
    };
    u8::try_from(v).ok()
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
    Ok(PatternMatcher::compile(pattern)?.is_match(value))
}

/// A `strings` query pattern compiled once and reused for every row.
///
/// Compiling per row pays one [`regex`] compilation per eligible hit;
/// compiling eagerly per query changes observable behavior (a malformed or
/// overlong pattern would error even when `section`/`min_len` prefilter every
/// row). Callers therefore compile lazily at the first row reaching pattern
/// evaluation and reuse the matcher after; this type owns the single
/// compilation, the query loop owns the laziness.
#[derive(Debug, Clone)]
pub enum PatternMatcher<'a> {
    /// Empty pattern matches every value without touching the regex engine.
    All,
    /// Case-sensitive substring (`value.contains(pattern)`).
    Substring(&'a str),
    /// `regex:`-prefixed expression, compiled once.
    Regex(regex::Regex),
}

impl<'a> PatternMatcher<'a> {
    /// Compile `pattern` once per query.
    ///
    /// # Errors
    /// [`Error::Invalid`] when the pattern exceeds [`MAX_PATTERN_LEN`] or a
    /// `regex:` expression fails to compile. A bad regex is an error, never
    /// a silent fallback to substring matching.
    pub fn compile(pattern: &'a str) -> Result<Self> {
        if pattern.len() > MAX_PATTERN_LEN {
            return Err(Error::Invalid(format!(
                "pattern exceeds {MAX_PATTERN_LEN} bytes"
            )));
        }
        if pattern.is_empty() {
            return Ok(Self::All);
        }
        match pattern.strip_prefix(REGEX_PREFIX) {
            Some(expr) => regex::Regex::new(expr)
                .map(Self::Regex)
                .map_err(|e| Error::Invalid(format!("bad regex pattern {pattern:?}: {e}"))),
            None => Ok(Self::Substring(pattern)),
        }
    }

    /// Test one row's value against the compiled pattern.
    #[must_use]
    pub fn is_match(&self, value: &str) -> bool {
        match self {
            Self::All => true,
            Self::Substring(needle) => value.contains(needle),
            Self::Regex(re) => re.is_match(value),
        }
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
    let mut pos_utf8 = 0usize;
    let mut pos_bmp = 0usize;
    let mut next_ascii = next_ascii_run(bytes, min, &mut pos_ascii);
    let mut next_le = next_utf16_run(bytes, min, true, &mut pos_le);
    let mut next_be = next_utf16_run(bytes, min, false, &mut pos_be);
    let mut next_utf8 = next_utf8_run(bytes, min, &mut pos_utf8);
    let mut next_bmp = next_utf16_bmp_run(bytes, min, &mut pos_bmp);
    let mut hits = Vec::new();
    while hits.len() < max_hits {
        let pick = pick_next(next_ascii, next_le, next_be, next_utf8, next_bmp);
        let Some((order, run)) = pick else {
            break;
        };
        hits.push(decode_run(bytes, run, base_va));
        match order {
            0 => next_ascii = next_ascii_run(bytes, min, &mut pos_ascii),
            1 => next_le = next_utf16_run(bytes, min, true, &mut pos_le),
            2 => next_be = next_utf16_run(bytes, min, false, &mut pos_be),
            3 => next_utf8 = next_utf8_run(bytes, min, &mut pos_utf8),
            _ => next_bmp = next_utf16_bmp_run(bytes, min, &mut pos_bmp),
        }
    }
    suppress_bmp_shadows(bytes, &mut hits);
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
/// LE (1) then BE (2) then UTF-8 (3) then BMP-LE (4) reproduces the old
/// append-plus-stable-sort tie-break for the classic passes.
fn pick_next(
    ascii: Option<Run>,
    le: Option<Run>,
    be: Option<Run>,
    utf8: Option<Run>,
    bmp: Option<Run>,
) -> Option<(u8, Run)> {
    let mut best: Option<(u8, Run)> = None;
    for (order, cand) in [(0u8, ascii), (1u8, le), (2u8, be), (3u8, utf8), (4u8, bmp)] {
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
        Encoding::Utf8 => std::str::from_utf8(&bytes[run.offset..run.end])
            .expect("utf8 runs hold validated bytes")
            .to_owned(),
        Encoding::Utf16LeBmp => {
            let mut value = String::new();
            let mut i = run.offset;
            while i < run.end {
                if let Some((c, _)) = bmp_unit_at(bytes, i) {
                    value.push(c);
                    i += 2;
                } else {
                    break;
                }
            }
            value
        }
        // `extract` never emits base64 runs (see `extract_base64`, which
        // builds its hits directly); the span still decodes lossy ASCII so
        // the match stays total without a panic path.
        Encoding::Base64 => String::from_utf8_lossy(&bytes[run.offset..run.end]).into_owned(),
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

/// One UTF-16LE BMP-letter unit plus its script, if any.
///
/// Disjoint from [`unit_at`]: ASCII-subset units (`u < 0x80`, including
/// the classic `c, 0x00` pairs and bare controls) report `None` here, so
/// the BMP pass only extends coverage to text the classic pass cannot
/// see (Cyrillic, CJK, ...) and never merges with or moves classic runs.
/// Units outside [`bmp_letter_script`], surrogates, private-use, and
/// non-letters report `None`.
fn bmp_unit_at(bytes: &[u8], i: usize) -> Option<(char, u8)> {
    let pair = bytes.get(i..i + 2)?;
    let u = u16::from_le_bytes([pair[0], pair[1]]);
    if u < 0x80 {
        return None;
    }
    let script = bmp_letter_script(u)?;
    let c = char::from_u32(u32::from(u))?;
    c.is_alphabetic().then_some((c, script))
}

/// Script of a BMP code unit for the letter pass, as a small id.
///
/// Curated letter-heavy blocks (Latin/Greek/Cyrillic/Armenian/Hebrew/
/// Arabic/Devanagari/Thai/Georgian/Hangul/Hiragana/Katakana/Bopomofo/Han):
/// periodic binary data also decodes to BMP letters, but almost never to
/// consecutive letters of ONE script, so runs must be script-consistent
/// (see the BMP pass below). Scripts outside the set (Tifinagh,
/// Ethiopic, Cherokee, ...) never qualify; mixed-script text fragments
/// at script boundaries instead of chaining across them.
#[must_use]
pub fn bmp_letter_script(u: u16) -> Option<u8> {
    Some(match u {
        0x00C0..=0x024F | 0x1E00..=0x1EFF | 0xFF21..=0xFF5A | 0xFF41..=0xFF7A => 1,
        0x0370..=0x03FF => 2,
        0x0400..=0x052F => 3,
        0x0531..=0x0586 => 4,
        0x0590..=0x05FF => 5,
        0x0600..=0x06FF => 6,
        0x0900..=0x097F => 7,
        0x0E00..=0x0E7F => 8,
        0x10A0..=0x10FF => 9,
        0x1100..=0x11FF | 0xAC00..=0xD7AF => 10,
        0x3040..=0x309F => 11,
        0x30A0..=0x30FF => 12,
        0x3100..=0x312F => 13,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF => 14,
        _ => return None,
    })
}

/// Next UTF-16LE BMP-letter run at or after `*pos`, advancing past it.
///
/// Same cursor shape as the classic UTF-16 pass (one byte on a miss, two per
/// unit, rejected short runs still advance past the run), plus two
/// precision rules: every unit must share the first unit's
/// [`bmp_letter_script`], and runs longer than [`MAX_BMP_RUN_CHARS`]
/// characters report as consecutive chunks. Binary chains (word tables,
/// shifted ASCII) mix scripts and stop at the boundary; single-script
/// text (a Cyrillic word, a Han phrase) reports whole; the chunk cap
/// bounds one hit's allocation no matter how long a consistent run gets
/// (periodic binary data can stay consistent for megabytes).
///
/// Cap on BMP-letter characters per reported hit; longer runs chunk.
pub const MAX_BMP_RUN_CHARS: usize = 1024;
/// Runs longer than this many characters must clear the diversity floor
/// below; short runs report unconditionally.
pub const BMP_DIVERSITY_LEN: usize = 64;
/// Distinct units a long BMP run must hold. Periodic binary data (word
/// tables, fill patterns) decodes to long single-script runs of a
/// handful of units; real text of that length does not.
pub const BMP_DIVERSITY_MIN: usize = 8;

/// Drop BMP-letter hits fully explained by ASCII readings.
///
/// A BMP hit whose every span byte either lies in an ASCII hit's span or
/// is not ASCII-printable (NUL separators and the like) is a shifted
/// reading of ASCII text — including readings that bridge NUL gaps
/// between adjacent strings — so it reports nothing new. Genuine
/// non-ASCII regions always keep an uncovered printable byte (their
/// high/control bytes break ASCII runs) and survive. Applied after the
/// cap, so the lazy merge and the eager reference agree trivially.
///
/// `bytes` is the scanned buffer; ASCII spans come from `hits` itself,
/// so coverage is judged within the reported page.
pub fn suppress_bmp_shadows(bytes: &[u8], hits: &mut Vec<StringHit>) {
    if !hits.iter().any(|h| h.encoding == Encoding::Utf16LeBmp) {
        return;
    }
    let ascii: Vec<(usize, usize)> = hits
        .iter()
        .filter(|h| h.encoding == Encoding::Ascii)
        .map(|h| (h.offset, h.offset + h.value.len()))
        .collect();
    if ascii.is_empty() {
        return;
    }
    hits.retain(|h| {
        if h.encoding != Encoding::Utf16LeBmp {
            return true;
        }
        let span = h.value.chars().count() * 2;
        !(0..span).all(|d| {
            let o = h.offset + d;
            !bytes.get(o).is_some_and(|b| is_print(*b))
                || ascii.iter().any(|&(a, b)| a <= o && o < b)
        })
    });
}

/// Distinct units in `bytes[start..end]` (LE pairs), stopping after
/// [`BMP_DIVERSITY_MIN`].
#[must_use]
pub fn bmp_distinct_units(bytes: &[u8], start: usize, end: usize) -> usize {
    let mut seen: [u16; BMP_DIVERSITY_MIN] = [0; BMP_DIVERSITY_MIN];
    let mut count = 0usize;
    let mut i = start;
    while i + 1 < end {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if !seen[..count].contains(&u) {
            if count >= BMP_DIVERSITY_MIN {
                break;
            }
            seen[count] = u;
            count += 1;
        }
        i += 2;
    }
    count
}

fn next_utf16_bmp_run(bytes: &[u8], min: usize, pos: &mut usize) -> Option<Run> {
    while *pos + 1 < bytes.len() {
        if let Some((_, script)) = bmp_unit_at(bytes, *pos) {
            let start = *pos;
            let mut count = 0usize;
            while count < MAX_BMP_RUN_CHARS
                && let Some((_, s)) = bmp_unit_at(bytes, *pos)
            {
                if s != script {
                    break;
                }
                count += 1;
                *pos += 2;
            }
            // Degenerate guard: a long chunk of a few repeated units is
            // fill data, not text. The rescan only runs for long chunks,
            // so short runs cost nothing extra.
            let degenerate = count > BMP_DIVERSITY_LEN
                && bmp_distinct_units(bytes, start, *pos) < BMP_DIVERSITY_MIN;
            if count >= min && !degenerate {
                return Some(Run {
                    offset: start,
                    end: *pos,
                    encoding: Encoding::Utf16LeBmp,
                });
            }
            // A capped chunk ends mid-run, so the remainder rescans as
            // its own chunk; a rejected run already advanced past itself,
            // like the other passes.
        } else {
            *pos += 1;
        }
    }
    None
}

/// One printable UTF-8 character at `i` plus its byte length, if any.
///
/// ASCII bytes take the same printable test as the ASCII pass (controls
/// break runs); bytes `0x80` and up must open a valid 2-4 byte sequence
/// decoding to exactly one non-control, non-BOM character. Invalid
/// leads, stray continuations, overlongs, and surrogates (all rejected
/// by [`str::from_utf8`](std::str::from_utf8)) break runs.
fn utf8_char_at(bytes: &[u8], i: usize) -> Option<(char, usize)> {
    let b = *bytes.get(i)?;
    if is_print(b) {
        return Some((b as char, 1));
    }
    if b < 0x80 {
        return None;
    }
    for len in 2..=4usize {
        let Some(sl) = bytes.get(i..i + len) else {
            continue;
        };
        let Ok(s) = std::str::from_utf8(sl) else {
            continue;
        };
        let mut chars = s.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) if !c.is_control() && c != '\u{FEFF}' => return Some((c, len)),
            (Some(_), None) => return None,
            _ => continue,
        }
    }
    None
}

/// Next UTF-8 run at or after `*pos`, advancing past it.
///
/// Runs mix ASCII-printable and multibyte characters (so `hello世界`
/// reports whole), but only runs holding at least one multibyte
/// character qualify: pure-ASCII text stays [`Encoding::Ascii`]-only and
/// is never double-reported. `min` counts characters.
fn next_utf8_run(bytes: &[u8], min: usize, pos: &mut usize) -> Option<Run> {
    while *pos < bytes.len() {
        if utf8_char_at(bytes, *pos).is_some() {
            let start = *pos;
            let mut count = 0usize;
            let mut multi = false;
            while let Some((_, len)) = utf8_char_at(bytes, *pos) {
                count += 1;
                multi |= len > 1;
                *pos += len;
            }
            if count >= min && multi {
                return Some(Run {
                    offset: start,
                    end: *pos,
                    encoding: Encoding::Utf8,
                });
            }
        } else {
            *pos += 1;
        }
    }
    None
}

/// Whether `s` is shaped like a base64 blob: at least 8 characters, a
/// multiple of 4, alphabet-only with at most two `=` pad characters at
/// the very end.
///
/// Syntactic only: short ASCII words also match, so the decoded view
/// additionally requires the decode to be printable text (see
/// [`extract_base64`]).
#[must_use]
pub fn is_base64_candidate(s: &str) -> bool {
    if s.len() < 8 || !s.len().is_multiple_of(4) {
        return false;
    }
    let pad = s.len() - s.trim_end_matches('=').len();
    if pad > 2 {
        return false;
    }
    let body = &s[..s.len() - pad];
    if body.is_empty() {
        return false;
    }
    body.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Decode a base64 blob without new dependencies.
///
/// Returns `None` unless `s` passes [`is_base64_candidate`]; the output
/// is `3/4` of the input length (minus padding).
#[must_use]
pub fn decode_base64(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some(u32::from(b - b'A')),
            b'a'..=b'z' => Some(u32::from(b - b'a' + 26)),
            b'0'..=b'9' => Some(u32::from(b - b'0' + 52)),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    if !is_base64_candidate(s) {
        return None;
    }
    let raw = s.as_bytes();
    let pad = raw.len() - s.trim_end_matches('=').len();
    let mut out = Vec::with_capacity(raw.len() / 4 * 3);
    let chunks = raw.len() / 4;
    for (qi, q) in raw.chunks(4).enumerate() {
        let q: [u8; 4] = q.try_into().ok()?;
        let last = qi + 1 == chunks;
        let n = q
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if b == b'=' {
                    (last && i >= 4 - pad).then_some(0)
                } else {
                    val(b)
                }
            })
            .collect::<Option<Vec<_>>>()?;
        let v = (n[0] << 18) | (n[1] << 12) | (n[2] << 6) | n[3];
        out.push((v >> 16) as u8);
        if !(last && pad >= 2) {
            out.push((v >> 8) as u8);
        }
        if !(last && pad >= 1) {
            out.push(v as u8);
        }
    }
    Some(out)
}

/// Whether every character of decoded base64 plaintext is printable:
/// ASCII-printable, or non-ASCII and non-control (mirrors the UTF-8
/// pass alphabet, minus the BOM carve-out, which has no decoded form).
fn is_decoded_printable(text: &str) -> bool {
    text.chars().all(|c| {
        if c.is_ascii() {
            is_print(c as u8)
        } else {
            !c.is_control() && c != '\u{FEFF}'
        }
    })
}

/// Scan `bytes` for base64 blobs, reporting their decoded plaintext.
///
/// Each maximal ASCII-printable run (up to [`MAX_BASE64_RUN_BYTES`])
/// passing [`is_base64_candidate`] is decoded; runs whose decoded bytes
/// are printable text of at least `min_len` characters report as
/// [`Encoding::Base64`] hits at the blob's offset. Sorted by offset,
/// capped at `max_hits`; `max_hits` of zero returns empty. Only used by
/// the [`DecodeSpec::Base64`] decoded view, never by stored extraction.
#[must_use]
pub fn extract_base64(
    bytes: &[u8],
    min_len: usize,
    max_hits: usize,
    base_va: Option<u64>,
) -> Vec<StringHit> {
    if max_hits == 0 {
        return Vec::new();
    }
    let min = min_len.max(1);
    let mut hits = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() && hits.len() < max_hits {
        if !is_print(bytes[pos]) {
            pos += 1;
            continue;
        }
        let start = pos;
        while pos < bytes.len() && is_print(bytes[pos]) {
            pos += 1;
        }
        let run = &bytes[start..pos];
        if run.len() < 8 || run.len() > MAX_BASE64_RUN_BYTES {
            continue;
        }
        let Ok(ascii) = std::str::from_utf8(run) else {
            continue;
        };
        if !is_base64_candidate(ascii) {
            continue;
        }
        let Some(decoded) = decode_base64(ascii) else {
            continue;
        };
        let Ok(text) = String::from_utf8(decoded) else {
            continue;
        };
        if text.chars().count() < min || !is_decoded_printable(&text) {
            continue;
        }
        hits.push(StringHit {
            offset: start,
            vaddr: va(base_va, start),
            encoding: Encoding::Base64,
            value: text,
            section: None,
            executable: false,
        });
    }
    hits
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
    fn matcher_agrees_with_matches_pattern() {
        let values = [
            "SAVE%d.GAM is invalid",
            "save game",
            "",
            "regex:SAVE",
            "zzz",
        ];
        let patterns = [
            "SAVE",
            "save",
            "zzz",
            "",
            "regex:SAVE.*invalid",
            "regex:(?i)save",
            "regex:^invalid",
            "regex:([",
        ];
        for pattern in patterns {
            let single: Vec<Result<bool>> =
                values.iter().map(|v| matches_pattern(v, pattern)).collect();
            let reused = PatternMatcher::compile(pattern);
            match (single, reused) {
                (results, Ok(matcher)) => {
                    for (value, expected) in values.iter().zip(results) {
                        assert_eq!(
                            matcher.is_match(value),
                            expected.expect("compiled pattern must match per-row"),
                            "value={value:?} pattern={pattern:?}"
                        );
                    }
                }
                (results, Err(_)) => {
                    assert!(
                        results.iter().all(|r| r.is_err()),
                        "failed compile must fail every row: {pattern:?}"
                    );
                }
            }
        }
        let overlong = "y".repeat(MAX_PATTERN_LEN + 1);
        assert!(PatternMatcher::compile(&overlong).is_err());
    }

    #[test]
    fn matcher_modes_match_everything_or_substring() {
        assert!(
            PatternMatcher::compile("")
                .expect("empty compiles")
                .is_match("anything")
        );
        let sub = PatternMatcher::compile("SAVE").expect("substring compiles");
        assert!(sub.is_match("SAVE%d.GAM is invalid"));
        assert!(!sub.is_match("save game"));
        let re = PatternMatcher::compile("regex:SAVE.*invalid").expect("regex compiles");
        assert!(re.is_match("SAVE%d.GAM is invalid"));
        assert!(!re.is_match("save game"));
    }

    #[test]
    fn old_rows_decode_without_new_fields() {
        let hit: StringHit =
            serde_json::from_str(r#"{"offset":1,"vaddr":4096,"encoding":"Ascii","value":"hi"}"#)
                .expect("old rows must still decode");
        assert_eq!(hit.section, None);
        assert!(!hit.executable);
    }

    #[test]
    fn decode_specs_parse_hex_and_decimal() {
        assert_eq!(
            parse_decode_spec("xor:0x41").expect("hex parses"),
            DecodeSpec::Xor(0x41)
        );
        assert_eq!(
            parse_decode_spec("XOR:65").expect("op is case-insensitive"),
            DecodeSpec::Xor(65)
        );
        assert_eq!(
            parse_decode_spec("xor:0x0041").expect("zero-padded stays single"),
            DecodeSpec::Xor(0x41)
        );
        assert_eq!(
            parse_decode_spec("xor:0x4142").expect("rolling key"),
            DecodeSpec::XorMulti(vec![0x41, 0x42])
        );
        assert_eq!(
            parse_decode_spec("add:7").expect("add parses"),
            DecodeSpec::Add(7)
        );
        assert_eq!(
            parse_decode_spec("rot:3").expect("rot parses"),
            DecodeSpec::Rot(3)
        );
        assert_eq!(
            parse_decode_spec("base64").expect("bare base64"),
            DecodeSpec::Base64
        );
        assert_eq!(
            parse_decode_spec("BASE64").expect("base64 case-insensitive"),
            DecodeSpec::Base64
        );
    }

    #[test]
    fn decode_specs_reject_everything_off_allowlist() {
        for bad in [
            "",
            "xor",
            "aes:0x41",
            "xor:",
            "xor:0x",
            "xor:0x100",
            "xor:0x123",
            "xor:0x414",
            "xor:0xZZZZ",
            "xor:256",
            "xor:-1",
            "xor:zz",
            "add:999",
            "rot:8",
            "rot:0x41",
            "rotl:3",
            "xor:0x41:extra",
            "base64:",
            "base64:x",
        ] {
            assert!(
                parse_decode_spec(bad).is_err(),
                "{bad:?} must be rejected, never a silent fallback"
            );
        }
        // Oversize rolling keys reject instead of truncating.
        let huge = format!("xor:0x{}", "AB".repeat(MAX_XOR_KEY_LEN + 1));
        assert!(parse_decode_spec(&huge).is_err());
        let maxed = format!("xor:0x{}", "AB".repeat(MAX_XOR_KEY_LEN));
        assert!(matches!(
            parse_decode_spec(&maxed).expect("max key parses"),
            DecodeSpec::XorMulti(k) if k.len() == MAX_XOR_KEY_LEN
        ));
    }

    #[test]
    fn xor_multi_rolls_the_key() {
        let spec = DecodeSpec::XorMulti(vec![0x41, 0x42]);
        assert_eq!(spec.apply(b"...."), b"olol");
        assert_eq!(spec.apply(b".."), b"ol");
        assert_eq!(spec.apply(b"....."), b"ololo");
        // Single-byte form is the same as a one-byte rolling key.
        assert_eq!(
            DecodeSpec::Xor(0x41).apply(b"...."),
            DecodeSpec::XorMulti(vec![0x41]).apply(b"....")
        );
    }

    #[test]
    fn base64_candidate_and_decode_vectors() {
        for (blob, plain) in [
            ("TWFuTWFu", "ManMan"),
            ("cGxlYXN1cmUu", "pleasure."),
            ("aGVsbG8td29ybGQ=", "hello-world"),
        ] {
            assert!(is_base64_candidate(blob), "{blob:?} must be a candidate");
            assert_eq!(
                decode_base64(blob).expect("decodes"),
                plain.as_bytes(),
                "{blob:?}"
            );
        }
        for bad in [
            "",
            "abc",
            "AAAAAAAAA",
            "AB=CDEFGH",
            "A=======",
            "========采采采采",
            "a b c d e f g h",
            "xy",
        ] {
            assert!(!is_base64_candidate(bad), "{bad:?} must not be a candidate");
            assert_eq!(decode_base64(bad), None);
        }
        // Syntactically valid but NUL-decoding: the candidate gate passes,
        // the printable-text gate in `extract_base64` rejects.
        assert_eq!(decode_base64("AAAAAAAA").expect("decodes"), vec![0u8; 6]);
    }

    #[test]
    fn utf8_runs_need_multibyte_printable_text() {
        // Mixed ASCII + CJK reports whole.
        let mut bytes = b"\x00hello ".to_vec();
        bytes.extend_from_slice("世界".as_bytes());
        bytes.push(0x00);
        let hits = extract(&bytes, 4, 100, None);
        let utf8: Vec<&StringHit> = hits
            .iter()
            .filter(|h| h.encoding == Encoding::Utf8)
            .collect();
        assert_eq!(utf8.len(), 1);
        assert_eq!(utf8[0].value, "hello 世界");
        assert_eq!(utf8[0].offset, 1);
        // Pure ASCII never double-reports as UTF-8.
        let hits = extract(b"\x00hello world\x00", 4, 100, None);
        assert!(hits.iter().all(|h| h.encoding == Encoding::Ascii));
        // Stray continuations, overlongs, and encoded controls break runs.
        for bad in [
            vec![0x00, 0x80, 0x80, 0x80, 0x80, 0x00],
            vec![0x00, 0xC0, 0xAF, 0xC0, 0xAF, 0xC0, 0xAF, 0xC0, 0xAF, 0x00],
            vec![0x00, 0xC2, 0x80, 0xC2, 0x80, 0xC2, 0x80, 0xC2, 0x80, 0x00],
            vec![0x00, 0xED, 0xA0, 0x80, 0xED, 0xA0, 0x80, 0x00],
        ] {
            assert!(
                extract(&bad, 2, 100, None)
                    .iter()
                    .all(|h| h.encoding != Encoding::Utf8),
                "no UTF-8 hit expected in {bad:02x?}"
            );
        }
    }

    #[test]
    fn bmp_letter_script_table_spot_checks() {
        assert_eq!(bmp_letter_script(0x0430), Some(3));
        assert_eq!(bmp_letter_script(0x4E16), Some(14));
        assert_eq!(bmp_letter_script(0xAC00), Some(10));
        assert_eq!(bmp_letter_script(0x3042), Some(11));
        // Unlisted scripts, surrogates, and controls never qualify.
        assert_eq!(bmp_letter_script(0x2D65), None);
        assert_eq!(bmp_letter_script(0xD800), None);
        assert_eq!(bmp_letter_script(0x0041), None);
        assert_eq!(bmp_letter_script(0xFFFF), None);
    }

    #[test]
    fn bmp_runs_are_script_consistent() {
        // Cyrillic "Привет" LE: one Cyrillic run.
        let cyrillic: Vec<u8> = vec![
            0x1F, 0x04, 0x40, 0x04, 0x38, 0x04, 0x32, 0x04, 0x35, 0x04, 0x42, 0x04,
        ];
        let hits = extract(&cyrillic, 4, 100, None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].encoding, Encoding::Utf16LeBmp);
        assert_eq!(hits[0].value, "Привет");
        // Alternating Han / unlisted-Tifinagh units never chain.
        let mut mixed = Vec::new();
        for _ in 0..6 {
            mixed.extend_from_slice(&[0x16, 0x4E, 0x65, 0x2D]);
        }
        assert!(
            extract(&mixed, 2, 100, None)
                .iter()
                .all(|h| h.encoding != Encoding::Utf16LeBmp),
            "mixed-script units must not chain"
        );
    }

    #[test]
    fn bmp_long_runs_chunk_and_degenerate_rejects() {
        // 1100 diverse Han units chunk into 1024 + 76.
        let mut units: Vec<u8> = Vec::new();
        for i in 0..1100usize {
            let u: u16 = 0x4E00 + (i % 10) as u16;
            units.extend_from_slice(&u.to_le_bytes());
        }
        let hits = extract(&units, 4, 100, None);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].value.chars().count(), MAX_BMP_RUN_CHARS);
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[1].offset, MAX_BMP_RUN_CHARS * 2);
        assert_eq!(hits[1].value.chars().count(), 76);
        // 300 units of two alternating values: degenerate fill, no hits.
        let mut fill = Vec::new();
        for i in 0..300usize {
            let u: u16 = if i % 2 == 0 { 0x4E16 } else { 0x754C };
            fill.extend_from_slice(&u.to_le_bytes());
        }
        assert!(
            extract(&fill, 4, 100, None)
                .iter()
                .all(|h| h.encoding != Encoding::Utf16LeBmp),
            "degenerate periodic runs must not report"
        );
    }

    #[test]
    fn decode_round_trips_reveal_printable_runs() {
        // ASCII-channel assertions: decoded ASCII text also carries a
        // shifted BMP-letter twin (see `short_runs_excluded` in
        // tests/loader.rs), so the decode contract pins the Ascii hit
        // exactly and leaves the twin to the extractor tests.
        fn ascii_values(hits: &[StringHit]) -> Vec<&str> {
            hits.iter()
                .filter(|h| h.encoding == Encoding::Ascii)
                .map(|h| h.value.as_str())
                .collect()
        }
        let plain = b"hidden-marker";
        let xor: Vec<u8> = plain.iter().map(|b| b ^ 0x41).collect();
        let decoded = DecodeSpec::Xor(0x41).apply(&xor);
        assert_eq!(decoded, plain);
        let hits = extract(&decoded, 4, 100, Some(0x1000));
        assert_eq!(ascii_values(&hits), ["hidden-marker"]);
        let marker = hits
            .iter()
            .find(|h| h.encoding == Encoding::Ascii)
            .expect("ascii marker");
        assert_eq!(marker.offset, 0);
        assert_eq!(marker.vaddr, Some(0x1000));

        let added: Vec<u8> = plain.iter().map(|b| b.wrapping_sub(7)).collect();
        let hits = extract(&DecodeSpec::Add(7).apply(&added), 4, 100, None);
        assert_eq!(ascii_values(&hits), ["hidden-marker"]);

        let rord: Vec<u8> = plain.iter().map(|b| b.rotate_right(3)).collect();
        let hits = extract(&DecodeSpec::Rot(3).apply(&rord), 4, 100, None);
        assert_eq!(ascii_values(&hits), ["hidden-marker"]);
    }
}
