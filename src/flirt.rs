//! FLIRT-like library-function identification hints (read-only).
//!
//! Matches each function's leading bytes against a small static table of
//! common CRT/compiler idioms and reports the hits as hints. Hints are
//! evidence only: they never rename functions or write comments, and the
//! suggested names must be applied explicitly through [`crate::Project::rename_function`]
//! when an analyst agrees with them.
//!
//! Matching rule: a signature matches when the function's leading bytes
//! (decoded instructions at and after the entry, in address order, up to
//! [`MAX_SIGNATURE_WINDOW`] bytes) start with the signature's exact bytes,
//! restricted to the signature's architecture when one is set. All matches
//! are reported, longest first, so a specific leaf (e.g. `frame_ret0`)
//! coexists with its generic prologue hint (`frame_rbp`).
//!
//! Initial corpus (deliberately small; exact leading-byte prefixes):
//!
//! | id | bytes | arch | suggested name | idiom |
//! |----|-------|------|----------------|-------|
//! | `frame_rbp` | `55 48 89 E5` | x86_64 | `frame_setup_rbp` | `push rbp; mov rbp, rsp` frame prologue |
//! | `frame_ebp` | `55 89 E5` | x86_32 | `frame_setup_ebp` | `push ebp; mov ebp, esp` frame prologue |
//! | `ret0_xor_eax` | `31 C0 C3` | any x86 | `ret_0` | `xor eax, eax; ret` zero-return stub |
//! | `frame_ret0` | `55 48 89 E5 31 C0 5D C3` | x86_64 | `frame_ret_0` | framed zero-return leaf |
//! | `frame_ret1` | `55 48 89 E5 B8 01 00 00 00 5D C3` | x86_64 | `frame_ret_1` | framed return-1 leaf |
//! | `pad_nop_ret` | `90 C3` | any x86 | `pad_ret_stub` | `nop; ret` padding stub |
//!
//! The corpus covers frame setup plus return-constant leaves and one padding
//! shape: the shapes a first pass over CRT-adjacent compiler output meets.
//! Byte-prefix matching cannot verify boundaries or intent, so every row
//! stays a hint with its `reason` attached.

use std::cmp::Reverse;

use serde::{Deserialize, Serialize};

use crate::analysis::{Analysis, Function};
use crate::disasm::{Arch, Insn};
use crate::error::{Error, Result};

/// Leading bytes examined per function (decoded instructions at and after
/// the entry, in address order). Covers the longest corpus signature with
/// room for wider follow-up patterns.
pub const MAX_SIGNATURE_WINDOW: usize = 32;

/// Cap on signatures in one user file (`--sigs`): a corpus is hundreds of
/// rows, not millions; beyond this the file is rejected.
pub const MAX_USER_SIGNATURES: usize = 4096;

/// Cap on signature-file bytes (JSON or `.pat`): read budget before parsing.
pub const SIG_FILE_MAX_BYTES: usize = 1 << 20;

/// Version of the JSON signature document [`SignatureFile`].
pub const SIGNATURE_FILE_VERSION: u32 = 1;

/// Shortest generated pattern ([`generate_for_function`]): shorter shapes
/// match by accident more often than they identify.
pub const MIN_GEN_PATTERN_LEN: usize = 4;

/// Fewest fixed (non-`??`) bytes in a generated pattern: an all-wildcard
/// shape identifies nothing.
pub const MIN_GEN_FIXED_BYTES: usize = 2;

/// One corpus entry: an exact leading-byte prefix plus its hint text.
///
/// `arch` scopes the match (`None` matches any x86 mode the [`crate::disasm::Insn`] bytes
/// decode under, i.e. [`Arch::is_x86`]); `suggested_name` is a hint only,
/// never applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    /// Stable id used in [`FlirtHint::signature`].
    pub id: &'static str,
    /// Suggested name, reported only (never written to annotations).
    pub suggested_name: &'static str,
    /// Architecture scope, or `None` for any x86 mode.
    pub arch: Option<Arch>,
    /// Exact leading-byte prefix that matches.
    pub bytes: &'static [u8],
    /// Why this shape is a library/compiler hint, not a verified identity.
    pub reason: &'static str,
}

/// The initial CRT/compiler-idiom corpus (see the module docs for the table).
pub static SIGNATURES: &[Signature] = &[
    Signature {
        id: "frame_rbp",
        suggested_name: "frame_setup_rbp",
        arch: Some(Arch::X86_64),
        bytes: &[0x55, 0x48, 0x89, 0xE5],
        reason: "push rbp; mov rbp,rsp frame prologue (compiler frame-setup idiom)",
    },
    Signature {
        id: "frame_ebp",
        suggested_name: "frame_setup_ebp",
        arch: Some(Arch::X86_32),
        bytes: &[0x55, 0x89, 0xE5],
        reason: "push ebp; mov ebp,esp frame prologue (compiler frame-setup idiom)",
    },
    Signature {
        id: "ret0_xor_eax",
        suggested_name: "ret_0",
        arch: None,
        bytes: &[0x31, 0xC0, 0xC3],
        reason: "xor eax,eax; ret zero-return stub (compiler/CRT return-constant idiom)",
    },
    Signature {
        id: "frame_ret0",
        suggested_name: "frame_ret_0",
        arch: Some(Arch::X86_64),
        bytes: &[0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3],
        reason: "framed zero-return leaf (push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret)",
    },
    Signature {
        id: "frame_ret1",
        suggested_name: "frame_ret_1",
        arch: Some(Arch::X86_64),
        bytes: &[
            0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3,
        ],
        reason: "framed return-1 leaf (mov eax,1 under a frame)",
    },
    Signature {
        id: "pad_nop_ret",
        suggested_name: "pad_ret_stub",
        arch: None,
        bytes: &[0x90, 0xC3],
        reason: "nop; ret padding stub (alignment/padding idiom)",
    },
];

/// One library hint: a corpus signature matched at a function entry.
///
/// JSON pairs `entry` with `entry_hex` (`entry_hex` is recomputed on
/// serialize and ignored on deserialize).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FlirtHint {
    /// Function entry address the signature matched at.
    pub entry: u64,
    /// Corpus id (see [`SIGNATURES`]).
    pub signature: String,
    /// Suggested name (hint only, never applied automatically).
    pub suggested_name: String,
    /// Why this shape is a hint, not a verified identity.
    pub reason: String,
}

impl Serialize for FlirtHint {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("FlirtHint", 6)?;
        st.serialize_field("id", &format!("func@{:#x}", self.entry))?;
        st.serialize_field("entry", &self.entry)?;
        st.serialize_field("entry_hex", &crate::addr_hex(self.entry))?;
        st.serialize_field("signature", &self.signature)?;
        st.serialize_field("suggested_name", &self.suggested_name)?;
        st.serialize_field("reason", &self.reason)?;
        st.end()
    }
}

/// Leading bytes of `func`: decoded instruction bytes at and after the entry
/// in address order, capped at [`MAX_SIGNATURE_WINDOW`].
///
/// Blocks iterate in start order (already address order), stopping once the
/// window fills so large functions never decode past the signature prefix.
#[must_use]
pub fn leading_bytes(func: &Function) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_SIGNATURE_WINDOW);
    for insn in func
        .blocks
        .range(func.entry..)
        .flat_map(|(_, b)| b.insns.iter())
        .filter(|i| i.addr >= func.entry)
    {
        if out.len() >= MAX_SIGNATURE_WINDOW {
            break;
        }
        let take = (MAX_SIGNATURE_WINDOW - out.len()).min(insn.bytes.len());
        out.extend_from_slice(&insn.bytes[..take]);
    }
    out
}

/// Whether `arch` falls in a signature's scope: an explicit arch must
/// equal the decode arch, while an unset arch means "any x86" (see
/// [`Arch::is_x86`]) — never ARM-family modes, which can decode the same
/// bytes to unrelated instructions.
fn scope_ok(arch: Arch, sig_arch: Option<Arch>) -> bool {
    match sig_arch {
        Some(a) => a == arch,
        None => arch.is_x86(),
    }
}

/// Whether `leading` starts with `bytes` under `mask` (`None` = all fixed).
fn bytes_match(leading: &[u8], bytes: &[u8], mask: Option<&[bool]>) -> bool {
    if leading.len() < bytes.len() {
        return false;
    }
    match mask {
        None => leading.starts_with(bytes),
        Some(m) => bytes
            .iter()
            .zip(m.iter())
            .zip(leading.iter())
            .all(|((b, fixed), l)| !fixed || b == l),
    }
}

/// Corpus signatures matching `leading` under `arch`, longest first.
#[must_use]
pub fn match_leading(arch: Arch, leading: &[u8]) -> Vec<&'static Signature> {
    let mut hits: Vec<&'static Signature> = SIGNATURES
        .iter()
        .filter(|s| scope_ok(arch, s.arch) && bytes_match(leading, s.bytes, None))
        .collect();
    hits.sort_by_key(|s| Reverse(s.bytes.len()));
    hits
}

/// Hints for one function: every corpus match at its entry, longest first.
///
/// Read-only over decoded bytes; never touches annotations.
#[must_use]
pub fn hints_for_function(arch: Arch, func: &Function) -> Vec<FlirtHint> {
    let leading = leading_bytes(func);
    match_leading(arch, &leading)
        .into_iter()
        .map(|s| FlirtHint {
            entry: func.entry,
            signature: s.id.to_string(),
            suggested_name: s.suggested_name.to_string(),
            reason: s.reason.to_string(),
        })
        .collect()
}

/// Hints for every function in `analysis`, ordered by entry.
///
/// Read-only; the binary and the sidecar are never written.
#[must_use]
pub fn hints_for_analysis(analysis: &Analysis) -> Vec<FlirtHint> {
    hints_for_analysis_with(analysis, &[])
}

/// Hints for every function in `analysis` from the builtin corpus plus
/// `extra` user signatures, ordered by entry.
///
/// Builtin hints come first per function (longest first), then user
/// matches (longest first); both stay hints. Read-only.
#[must_use]
pub fn hints_for_analysis_with(analysis: &Analysis, extra: &[RuntimeSignature]) -> Vec<FlirtHint> {
    analysis
        .functions
        .values()
        .flat_map(|f| hints_for_function_with(analysis.arch, f, extra))
        .collect()
}

/// Hints for one function from the builtin corpus plus `extra` user
/// signatures: builtins first (longest first), then user matches
/// (longest first).
///
/// Read-only over decoded bytes; never touches annotations.
#[must_use]
pub fn hints_for_function_with(
    arch: Arch,
    func: &Function,
    extra: &[RuntimeSignature],
) -> Vec<FlirtHint> {
    let mut out = hints_for_function(arch, func);
    let leading = leading_bytes(func);
    out.extend(
        match_leading_runtime(arch, &leading, extra)
            .into_iter()
            .map(|s| FlirtHint {
                entry: func.entry,
                signature: s.id.clone(),
                suggested_name: s.suggested_name.clone(),
                reason: s.reason.clone(),
            }),
    );
    out
}

/// User-supplied signature: like [`Signature`] but owned, with `??`
/// wildcards (wildcard positions hold `0x00` in `bytes`, marked false in
/// `mask`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSignature {
    /// Stable id, reported as [`FlirtHint::signature`].
    pub id: String,
    /// Suggested name, reported only (never applied).
    pub suggested_name: String,
    /// Architecture scope, or `None` for any x86 mode (same rule as the
    /// builtin corpus: never ARM-family modes).
    pub arch: Option<Arch>,
    /// Pattern bytes in order; wildcard positions hold `0x00`.
    pub bytes: Vec<u8>,
    /// Per-byte mask in order: `true` means the byte must match.
    pub mask: Vec<bool>,
    /// Why this shape is a hint, not a verified identity.
    pub reason: String,
}

impl From<&Signature> for RuntimeSignature {
    fn from(s: &Signature) -> Self {
        Self {
            id: s.id.to_string(),
            suggested_name: s.suggested_name.to_string(),
            arch: s.arch,
            bytes: s.bytes.to_vec(),
            mask: vec![true; s.bytes.len()],
            reason: s.reason.to_string(),
        }
    }
}

/// User signatures matching `leading` under `arch`, longest first.
///
/// Same scope rule as [`match_leading`]: an unset arch matches any x86
/// mode only.
#[must_use]
pub fn match_leading_runtime<'a>(
    arch: Arch,
    leading: &[u8],
    extra: &'a [RuntimeSignature],
) -> Vec<&'a RuntimeSignature> {
    let mut hits: Vec<&RuntimeSignature> = extra
        .iter()
        .filter(|s| scope_ok(arch, s.arch) && bytes_match(leading, &s.bytes, Some(&s.mask)))
        .collect();
    hits.sort_by_key(|s| Reverse(s.bytes.len()));
    hits
}

/// One signature row of the JSON signature document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSignature {
    /// Suggested function name this pattern identifies.
    pub name: String,
    /// Decode arch (`x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`,
    /// `riscv32`, `riscv64`, `mips32`, `ppc32`, `ppc64`; case-insensitive) or null for any x86 mode.
    pub arch: Option<String>,
    /// Whitespace-separated bytes: two hex digits or `??` wildcards.
    pub bytes: String,
    /// Token count of `bytes` (must agree, guards truncation).
    pub len: usize,
    /// CRC32-IEEE over the pattern bytes with wildcards as `0x00`.
    pub crc: u32,
}

/// JSON signature document: what `--sigs` reads and `sig-gen` emits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureFile {
    /// Document version (currently [`SIGNATURE_FILE_VERSION`]).
    pub version: u32,
    /// Signature rows.
    pub signatures: Vec<FileSignature>,
}

/// CRC32-IEEE (HDLC) over `data`: the checksum carried by
/// [`FileSignature::crc`] and recomputed on load.
///
/// Bitwise (no table): signature patterns are at most
/// [`MAX_SIGNATURE_WINDOW`] bytes, so no new dependency is warranted.
#[must_use]
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 * (crc & 1));
        }
    }
    !crc
}

/// Pattern bytes rendered as the [`FileSignature::bytes`] token string
/// (uppercase hex, `??` for masked positions).
#[must_use]
pub fn pattern_hex(bytes: &[u8], mask: &[bool]) -> String {
    bytes
        .iter()
        .zip(mask.iter())
        .map(|(b, fixed)| {
            if *fixed {
                format!("{b:02X}")
            } else {
                "??".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse one [`FileSignature::bytes`] token string.
///
/// Each token is two hex digits (case-insensitive) or a `??` wildcard;
/// returns `(bytes, mask)` with wildcard positions zeroed. At least one
/// literal is required: an all-wildcard shape matches everything.
fn parse_pattern_tokens(text: &str) -> Result<(Vec<u8>, Vec<bool>)> {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    for tok in text.split_whitespace() {
        if tok.eq_ignore_ascii_case("??") {
            bytes.push(0);
            mask.push(false);
        } else if tok.len() == 2
            && let (Some(hi), Some(lo)) = (
                tok.chars().next().and_then(|c| c.to_digit(16)),
                tok.chars().nth(1).and_then(|c| c.to_digit(16)),
            )
        {
            bytes.push((hi * 16 + lo) as u8);
            mask.push(true);
        } else {
            return Err(Error::Invalid(format!("bad signature byte token: {tok:?}")));
        }
        if bytes.len() > MAX_SIGNATURE_WINDOW {
            return Err(Error::Invalid(format!(
                "signature pattern exceeds the {MAX_SIGNATURE_WINDOW}-byte match window"
            )));
        }
    }
    if bytes.is_empty() {
        return Err(Error::Invalid("empty signature pattern".to_string()));
    }
    if mask.iter().all(|m| !m) {
        return Err(Error::Invalid(
            "signature pattern needs at least one literal byte".to_string(),
        ));
    }
    Ok((bytes, mask))
}

/// Validate one JSON signature row into a matchable [`RuntimeSignature`].
fn file_signature_to_runtime(s: &FileSignature) -> Result<RuntimeSignature> {
    if s.name.is_empty() {
        return Err(Error::Invalid("signature with an empty name".to_string()));
    }
    let arch = s.arch.as_deref().map(crate::parse_raw_arch).transpose()?;
    let (bytes, mask) = parse_pattern_tokens(&s.bytes)?;
    if s.len != bytes.len() {
        return Err(Error::Invalid(format!(
            "signature '{}': len {} disagrees with {} pattern bytes",
            s.name,
            s.len,
            bytes.len()
        )));
    }
    let mut concrete = bytes.clone();
    for (b, fixed) in concrete.iter_mut().zip(mask.iter()) {
        if !fixed {
            *b = 0;
        }
    }
    let crc = crc32_ieee(&concrete);
    if s.crc != crc {
        return Err(Error::Invalid(format!(
            "signature '{}': crc {:#010x} disagrees with recomputed {:#010x}",
            s.name, s.crc, crc
        )));
    }
    Ok(RuntimeSignature {
        id: s.name.clone(),
        suggested_name: s.name.clone(),
        arch,
        bytes,
        mask,
        reason: format!("user signature '{}' (custom corpus)", s.name),
    })
}

/// Parse a JSON signature document (the `--sigs` format `sig-gen` emits).
fn parse_json_signatures(text: &str) -> Result<Vec<RuntimeSignature>> {
    let doc: SignatureFile = serde_json::from_str(text)
        .map_err(|e| Error::Invalid(format!("malformed signature document: {e}")))?;
    if doc.version != SIGNATURE_FILE_VERSION {
        return Err(Error::Invalid(format!(
            "unsupported signature version {} (expected {SIGNATURE_FILE_VERSION})",
            doc.version
        )));
    }
    if doc.signatures.len() > MAX_USER_SIGNATURES {
        return Err(Error::Limit(format!(
            "signature document holds {} rows, over the {MAX_USER_SIGNATURES} cap",
            doc.signatures.len()
        )));
    }
    doc.signatures
        .iter()
        .map(file_signature_to_runtime)
        .collect()
}

/// Decode one IDA `.pat` head/tail token: even-length hex pairs with `..`
/// wildcards (wildcard bytes decode to `0x00`).
fn decode_pat_token(tok: &str) -> Result<(Vec<u8>, Vec<bool>)> {
    if !tok.len().is_multiple_of(2) {
        return Err(Error::Invalid(format!(
            "bad .pat pattern token (odd length): {tok:?}"
        )));
    }
    let raw = tok.as_bytes();
    let (chunks, _) = raw.as_chunks::<2>();
    let mut bytes = Vec::with_capacity(chunks.len());
    let mut mask = Vec::with_capacity(chunks.len());
    for pair in chunks {
        if *pair == *b".." {
            bytes.push(0);
            mask.push(false);
        } else if let (Some(hi), Some(lo)) = (
            (pair[0] as char).to_digit(16),
            (pair[1] as char).to_digit(16),
        ) {
            bytes.push((hi * 16 + lo) as u8);
            mask.push(true);
        } else {
            return Err(Error::Invalid(format!("bad .pat pattern token: {tok:?}")));
        }
    }
    Ok((bytes, mask))
}

/// Parse an IDA FLAIR `.pat` document into matchable signatures.
///
/// Each line is `<64-char head> <crc_len> <crc16> <mod_len>
/// [:OFFSET[@] NAME | ^OFFSET NAME]... [tail]`; `---` ends the file and
/// `;`/`#` lines are comments (see the FLAIR `pat.txt` reference). Only
/// the head pattern and the primary public name feed matching: the CRC
/// block, `^` references, and the tail pattern are parsed for shape but
/// ignored, and the import defaults to any-x86 scope (a `.pat` file
/// carries no arch field — prefer JSON with an explicit `arch` for
/// non-x86 corpora).
fn parse_pat_text(text: &str) -> Result<Vec<RuntimeSignature>> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if line.starts_with("---") {
            break;
        }
        if line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }
        let mut toks = line.split_whitespace();
        let missing = |what: &str| Error::Invalid(format!(".pat line {}: missing {what}", idx + 1));
        let head = toks.next().ok_or_else(|| missing("head pattern"))?;
        if head.len() != 64 {
            return Err(Error::Invalid(format!(
                ".pat line {}: head pattern is {} chars, expected 64",
                idx + 1,
                head.len()
            )));
        }
        let (bytes, mask) = decode_pat_token(head)?;
        // CRC length, CRC16, module length: presence-checked, unverified.
        toks.next().ok_or_else(|| missing("crc_len"))?;
        toks.next().ok_or_else(|| missing("crc16"))?;
        toks.next().ok_or_else(|| missing("mod_len"))?;
        let mut primary: Option<(i64, String)> = None;
        while let Some(tok) = toks.next() {
            if let Some(rest) = tok.strip_prefix(':') {
                let (hex, _) = match rest.strip_suffix('@') {
                    Some(h) => (h, true),
                    None => (rest, false),
                };
                let off = i64::from_str_radix(hex, 16).map_err(|_| {
                    Error::Invalid(format!(
                        ".pat line {}: bad public-name offset: {tok:?}",
                        idx + 1
                    ))
                })?;
                let name = toks.next().ok_or_else(|| missing("name after `:OFFSET`"))?;
                if primary.as_ref().is_none_or(|(o, _)| off < *o) {
                    primary = Some((off, name.to_string()));
                }
            } else if let Some(rest) = tok.strip_prefix('^') {
                i64::from_str_radix(rest, 16).map_err(|_| {
                    Error::Invalid(format!(
                        ".pat line {}: bad reference offset: {tok:?}",
                        idx + 1
                    ))
                })?;
                toks.next().ok_or_else(|| missing("name after `^OFFSET`"))?;
            } else {
                decode_pat_token(tok)?;
                if toks.next().is_some() {
                    return Err(Error::Invalid(format!(
                        ".pat line {}: unexpected token after tail",
                        idx + 1
                    )));
                }
                break;
            }
        }
        let Some((off, name)) = primary else {
            return Err(Error::Invalid(format!(
                ".pat line {}: no public name",
                idx + 1
            )));
        };
        if out.len() >= MAX_USER_SIGNATURES {
            return Err(Error::Limit(format!(
                ".pat document exceeds {MAX_USER_SIGNATURES} signatures"
            )));
        }
        let id = if off == 0 {
            name.clone()
        } else {
            format!("{name}+{off:#x}")
        };
        out.push(RuntimeSignature {
            id,
            suggested_name: name.clone(),
            arch: None,
            bytes,
            mask,
            reason: format!(
                ".pat import '{name}' (head bytes only; crc, references, and tail not verified)"
            ),
        });
    }
    Ok(out)
}

/// Load user signatures from `path`: our JSON document by default, IDA
/// `.pat` import when the extension is `.pat` (case-insensitive).
///
/// The file is read with a [`SIG_FILE_MAX_BYTES`] budget and validated
/// before matching: unknown archs, empty or all-wildcard patterns,
/// `len`/`crc` disagreements, and over-cap row counts are errors, never
/// silent skips. Never writes anything; the analyzed binary and the
/// sidecar are untouched.
///
/// # Errors
/// [`Error::NotFound`] when the path does not exist,
/// [`Error::Unsupported`] when it is not a file,
/// [`Error::Limit`] past the size/row budgets,
/// [`Error::Invalid`] on malformed content or failed validation.
pub fn load_signature_file(path: &std::path::Path) -> Result<Vec<RuntimeSignature>> {
    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::NotFound(path.display().to_string()),
        _ => Error::Storage(format!("stat {}: {e}", path.display())),
    })?;
    if !meta.is_file() {
        return Err(Error::Unsupported(format!(
            "not a file: {}",
            path.display()
        )));
    }
    if meta.len() > SIG_FILE_MAX_BYTES as u64 {
        return Err(Error::Limit(format!(
            "signature file of {} bytes exceeds the {SIG_FILE_MAX_BYTES}-byte cap",
            meta.len()
        )));
    }
    let bytes =
        std::fs::read(path).map_err(|e| Error::Storage(format!("read {}: {e}", path.display())))?;
    if bytes.len() > SIG_FILE_MAX_BYTES {
        return Err(Error::Limit(format!(
            "signature file of {} bytes exceeds the {SIG_FILE_MAX_BYTES}-byte cap",
            bytes.len()
        )));
    }
    let text = String::from_utf8(bytes)
        .map_err(|e| Error::Invalid(format!("signature file is not UTF-8: {e}")))?;
    let is_pat = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("pat"));
    if is_pat {
        parse_pat_text(&text)
    } else {
        parse_json_signatures(&text)
    }
}

/// Leading instruction bytes of `func` as `(bytes, fixed)` pairs in
/// address order, capped at [`MAX_SIGNATURE_WINDOW`].
///
/// Masking is conservative but address-aware: instructions with a decoded
/// branch target (calls/jumps, whose embedded displacement varies per
/// build) are fully masked, while an instruction with a decoded data
/// target (`mem_target`) is masked only when that target falls in mapped
/// memory — i.e. the immediate really looks like an address (`mov edi,
/// <str>`), not a small constant in an address-taking form (`mov eax,
/// 1`). Only position-independent bytes stay fixed.
fn masked_leading_with(func: &Function, is_mapped: &dyn Fn(u64) -> bool) -> (Vec<u8>, Vec<bool>) {
    let mut insns: Vec<&Insn> = func
        .blocks
        .values()
        .flat_map(|b| b.insns.iter())
        .filter(|i| i.addr >= func.entry)
        .collect();
    insns.sort_by_key(|i| i.addr);
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    for insn in insns {
        if bytes.len() >= MAX_SIGNATURE_WINDOW {
            break;
        }
        let take = (MAX_SIGNATURE_WINDOW - bytes.len()).min(insn.bytes.len());
        let fixed = insn.branch_target.is_none() && insn.mem_target.is_none_or(|t| !is_mapped(t));
        bytes.extend_from_slice(&insn.bytes[..take]);
        mask.extend(std::iter::repeat_n(fixed, take));
    }
    (bytes, mask)
}

/// Emit a signature row for one named function, or `None` when the shape
/// is too short or too masked to identify anything.
///
/// `arch` is the function's effective decode arch; `name` is the
/// rename-resolved display name; `is_mapped` reports whether a decoded
/// data target lies in mapped memory (the "looks like an address" test:
/// calls/jumps always mask, data targets mask only when mapped).
/// Fixed bytes are the position-independent leading bytes;
/// `len`/`crc` follow the [`FileSignature`] contract so the row
/// round-trips through [`load_signature_file`].
#[must_use]
pub fn generate_for_function(
    arch: Arch,
    func: &Function,
    name: &str,
    is_mapped: impl Fn(u64) -> bool,
) -> Option<FileSignature> {
    let (bytes, mask) = masked_leading_with(func, &is_mapped);
    if bytes.len() < MIN_GEN_PATTERN_LEN {
        return None;
    }
    if mask.iter().filter(|m| **m).count() < MIN_GEN_FIXED_BYTES {
        return None;
    }
    let mut concrete = bytes.clone();
    for (b, fixed) in concrete.iter_mut().zip(mask.iter()) {
        if !fixed {
            *b = 0;
        }
    }
    Some(FileSignature {
        name: name.to_string(),
        arch: Some(crate::db::arch_name(arch).to_string()),
        bytes: pattern_hex(&bytes, &mask),
        len: bytes.len(),
        crc: crc32_ieee(&concrete),
    })
}
