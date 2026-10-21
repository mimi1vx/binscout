//! Patch export: assemble replacement bytes at a VA without writing the binary.
//!
//! A patch covers exactly one instruction: the first decode at the target
//! address sets the boundary (aarch64 instructions are always 4 bytes), the
//! replacement (assembled `--asm` or literal `--bytes`) must fit inside it,
//! and shorter x86 replacements are padded with single-byte NOPs. The result
//! is a [`PatchPreview`] (`va`, `file_off`, `old_hex`, `new_hex`,
//! `size_ok`); an optional `--out` file carries the same bytes as JSON or
//! IPS. The analyzed binary is never written: the output path must differ
//! from it (see [`reject_output_is_binary`]) and overflowing or
//! non-file-backed patches are refused outright.

use serde::Serialize;

use crate::disasm::Arch;
use crate::error::{Error, Result};

/// Single-byte NOP used to pad short x86 replacements up to the
/// instruction boundary.
pub const X86_NOP: u8 = 0x90;

/// A64 `nop` (little-endian bytes of 0xD503201F).
pub const AARCH64_NOP: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];

/// Replacement source for [`crate::Project::patch_preview`]: assembled
/// x86 or aarch64 text or literal bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchInput {
    /// Small x86 (`nop`, `ret`, `int3`, `jmp ADDR`, `call ADDR`) or aarch64
    /// (`nop`, `ret`, `brk #IMM`, `b ADDR`, `bl ADDR`) subset, encoded at
    /// the target address (see [`assemble_x86`] and [`assemble_aarch64`]).
    Asm(String),
    /// Literal replacement bytes (see [`parse_patch_bytes`]).
    Bytes(Vec<u8>),
}

/// One-instruction patch preview: the original bytes, the replacement, and
/// whether it fits.
///
/// `file_off` is the file offset of the range start, or null when the
/// address is not file-backed (BSS/zero-fill tails); JSON pairs `va` with
/// its `0x`-hex twin like every other address in the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchPreview {
    /// Virtual address of the patched instruction.
    pub addr: u64,
    /// File offset of the range start, if file-backed.
    pub file_off: Option<u64>,
    /// Original instruction bytes.
    pub old: Vec<u8>,
    /// Replacement bytes (NOP-padded to `old` when they fit, unpadded
    /// otherwise with `size_ok` false).
    pub new: Vec<u8>,
    /// Whether the replacement fits the instruction boundary.
    pub size_ok: bool,
}

impl PatchPreview {
    /// Continuous lowercase hex of [`PatchPreview::old`].
    #[must_use]
    pub fn old_hex(&self) -> String {
        hex_of(&self.old)
    }

    /// Continuous lowercase hex of [`PatchPreview::new`].
    #[must_use]
    pub fn new_hex(&self) -> String {
        hex_of(&self.new)
    }
}

impl Serialize for PatchPreview {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("PatchPreview", 6)?;
        st.serialize_field("va", &self.addr)?;
        st.serialize_field("va_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("file_off", &self.file_off)?;
        st.serialize_field("old_hex", &self.old_hex())?;
        st.serialize_field("new_hex", &self.new_hex())?;
        st.serialize_field("size_ok", &self.size_ok)?;
        st.end()
    }
}

/// Continuous lowercase hex, as in [`crate::BytesView::bytes_hex`].
fn hex_of(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Patch file format for `--out` (see [`parse_patch_format`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchFileFormat {
    /// One JSON object: the preview fields plus `arch`.
    Json,
    /// IPS record (`PATCH` + one 24-bit-offset entry + `EOF`).
    Ips,
}

/// Parse an `--out` format name (`json` or `ips`, case-insensitive).
///
/// # Errors
/// [`Error::Invalid`] for anything else.
pub fn parse_patch_format(s: &str) -> Result<PatchFileFormat> {
    match s.to_lowercase().as_str() {
        "json" => Ok(PatchFileFormat::Json),
        "ips" => Ok(PatchFileFormat::Ips),
        _ => Err(Error::Invalid(format!(
            "bad patch format: {s:?} (expected json or ips)"
        ))),
    }
}

/// Parse `--bytes` text as whitespace-separated two-hex-digit pairs.
///
/// Case-insensitive; empty input and malformed tokens are errors, never
/// silent truncation.
///
/// # Errors
/// [`Error::Invalid`] on empty input or a non-hex-pair token.
pub fn parse_patch_bytes(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for tok in text.split_whitespace() {
        if tok.len() != 2 || !tok.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Invalid(format!(
                "bad --bytes token {tok:?}: expected two hex digits (e.g. \"90 90\")"
            )));
        }
        let byte = u8::from_str_radix(tok, 16).map_err(|_| {
            Error::Invalid(format!(
                "bad --bytes token {tok:?}: expected two hex digits (e.g. \"90 90\")"
            ))
        })?;
        out.push(byte);
    }
    if out.is_empty() {
        return Err(Error::Invalid(
            "empty --bytes: expected whitespace-separated hex pairs (e.g. \"90 90\")".to_string(),
        ));
    }
    Ok(out)
}

/// Assemble one `--asm` line at `va` with the iced-x86 encoder.
///
/// Only the hot-fix subset is supported: bare `nop`/`ret`/`int3` and
/// `jmp ADDR`/`call ADDR` (absolute targets in `0x`-hex or decimal, encoded
/// relative to `va`, so the RIP displacement is exact; branches optimize to
/// the shortest encoding that reaches). Anything else is an
/// error naming the subset; use [`parse_patch_bytes`] for arbitrary
/// encodings.
///
/// # Errors
/// [`Error::Unsupported`] on non-x86 archs, [`Error::Invalid`] on unknown
/// mnemonics, bad branch targets, or encoder failures.
pub fn assemble_x86(arch: Arch, va: u64, text: &str) -> Result<Vec<u8>> {
    let bitness = match arch {
        Arch::X86_64 => 64,
        Arch::X86_32 => 32,
        _ => {
            return Err(Error::Unsupported(format!(
                "patch --asm is x86-only (binary arch is {})",
                crate::db::arch_name(arch)
            )));
        }
    };
    let text = text.trim();
    let (head, tail) = match text.find(char::is_whitespace) {
        Some(i) => (text[..i].to_string(), text[i..].trim().to_string()),
        None => (text.to_string(), String::new()),
    };
    let mut asm = iced_x86::code_asm::CodeAssembler::new(bitness)
        .map_err(|e| Error::Invalid(format!("cannot assemble {text:?} at {va:#x}: {e}")))?;
    match head.to_ascii_lowercase().as_str() {
        "nop" if tail.is_empty() => asm.nop(),
        "ret" if tail.is_empty() => asm.ret(),
        "int3" if tail.is_empty() => asm.int3(),
        "jmp" if !tail.is_empty() && !tail.contains(char::is_whitespace) => {
            let target = crate::parse_addr(&tail)?;
            asm.jmp(target)
        }
        "call" if !tail.is_empty() && !tail.contains(char::is_whitespace) => {
            let target = crate::parse_addr(&tail)?;
            asm.call(target)
        }
        _ => {
            return Err(Error::Invalid(format!(
                "unsupported --asm {text:?}: expected nop, ret, int3, jmp ADDR, or call ADDR (use --bytes for arbitrary encodings)"
            )));
        }
    }
    .map_err(|e| Error::Invalid(format!("cannot assemble {text:?} at {va:#x}: {e}")))?;
    asm.assemble(va)
        .map_err(|e| Error::Invalid(format!("cannot encode {text:?} at {va:#x}: {e}")))
}

/// Assemble one `--asm` line at `va` for aarch64 (little-endian).
///
/// Only the hot-fix subset is supported: bare `nop`/`ret`, `brk #IMM`
/// (`#` optional, 16-bit immediate), and `b ADDR`/`bl ADDR` (absolute
/// targets in `0x`-hex or decimal, encoded relative to `va`). Anything
/// else is an error naming the subset; use [`parse_patch_bytes`] for
/// arbitrary encodings.
///
/// # Errors
/// [`Error::Invalid`] on unknown mnemonics, bad immediates, or branch
/// targets that are misaligned or out of the ±128MiB range.
pub fn assemble_aarch64(va: u64, text: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    let (head, tail) = match text.find(char::is_whitespace) {
        Some(i) => (text[..i].to_string(), text[i..].trim().to_string()),
        None => (text.to_string(), String::new()),
    };
    let word = match head.to_ascii_lowercase().as_str() {
        "nop" if tail.is_empty() => 0xD503_201Fu32,
        "ret" if tail.is_empty() => 0xD65F_03C0u32,
        "brk" if !tail.is_empty() && !tail.contains(char::is_whitespace) => {
            let imm_text = tail.strip_prefix('#').unwrap_or(&tail);
            let imm = crate::parse_addr(imm_text)?;
            if imm > 0xFFFF {
                return Err(Error::Invalid(format!(
                    "brk immediate {imm_text:?} out of range (expected 0..=0xFFFF)"
                )));
            }
            0xD420_0000u32 | ((imm as u32) << 5)
        }
        "b" | "bl" if !tail.is_empty() && !tail.contains(char::is_whitespace) => {
            let target = crate::parse_addr(&tail)?;
            let off = target as i64 - va as i64;
            if off % 4 != 0 {
                return Err(Error::Invalid(format!(
                    "branch target {target:#x} from {va:#x} is misaligned (offset {off} is not a multiple of 4)"
                )));
            }
            if !(-(1 << 27)..=(1 << 27) - 4).contains(&off) {
                return Err(Error::Invalid(format!(
                    "branch target {target:#x} from {va:#x} is out of range (offset {off} exceeds ±128MiB)"
                )));
            }
            let base = if head.eq_ignore_ascii_case("b") {
                0x1400_0000u32
            } else {
                0x9400_0000u32
            };
            base | (((off >> 2) & 0x03FF_FFFF) as u32)
        }
        _ => {
            return Err(Error::Invalid(format!(
                "unsupported --asm {text:?}: expected nop, ret, brk #IMM, b ADDR, or bl ADDR (use --bytes for arbitrary encodings)"
            )));
        }
    };
    Ok(word.to_le_bytes().to_vec())
}

/// Encode one IPS patch record: `PATCH` + 24-bit big-endian offset +
/// 16-bit big-endian length + data + `EOF`.
///
/// IPS has no per-record address space beyond the 24-bit file offset, so
/// larger offsets and empty/oversize payloads are errors.
///
/// # Errors
/// [`Error::Invalid`] when `file_off` exceeds the 24-bit range or the
/// payload is empty/longer than 65535 bytes.
pub fn ips_bytes(file_off: u64, new_bytes: &[u8]) -> Result<Vec<u8>> {
    if new_bytes.is_empty() || new_bytes.len() > 0xffff {
        return Err(Error::Invalid(format!(
            "IPS patch of {} bytes is out of range (1..=65535)",
            new_bytes.len()
        )));
    }
    let Some(off) = u32::try_from(file_off).ok().filter(|&o| o <= 0x00ff_ffff) else {
        return Err(Error::Invalid(format!(
            "file offset {file_off:#x} exceeds the IPS 24-bit range"
        )));
    };
    let mut out = Vec::with_capacity(5 + 5 + new_bytes.len() + 3);
    out.extend_from_slice(b"PATCH");
    out.extend_from_slice(&off.to_be_bytes()[1..]);
    out.extend_from_slice(&(new_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(new_bytes);
    out.extend_from_slice(b"EOF");
    Ok(out)
}

/// Reject an `--out` path that resolves to the analyzed binary.
///
/// Same identity as the `--db` guard (canonicalized equality, plus
/// `(dev, ino)` on unix for hard links): the patch writer must never
/// overwrite its input, and a missing output path simply does not match.
///
/// # Errors
/// [`Error::Invalid`] when `out` names the same file as `binary`.
pub fn reject_output_is_binary(binary: &std::path::Path, out: &std::path::Path) -> Result<()> {
    if crate::same_file(binary, out) {
        return Err(Error::Invalid(
            "--out must not be the analyzed binary".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_parse_accepts_pairs_and_rejects_junk() {
        assert_eq!(parse_patch_bytes("90 90").expect("pairs"), vec![0x90, 0x90]);
        assert_eq!(
            parse_patch_bytes("  E9\t0b 00 00 00 ").expect("ws/case"),
            vec![0xE9, 0x0b, 0, 0, 0]
        );
        for bad in ["", "   ", "9", "900", "zz", "90 ??", "0x90"] {
            assert!(parse_patch_bytes(bad).is_err(), "{bad:?} must fail");
        }
    }

    #[test]
    fn format_parse_is_case_insensitive() {
        assert_eq!(
            parse_patch_format("json").expect("json"),
            PatchFileFormat::Json
        );
        assert_eq!(
            parse_patch_format("IPS").expect("ips"),
            PatchFileFormat::Ips
        );
        assert!(parse_patch_format("bsdiff").is_err());
    }

    #[test]
    fn asm_encodes_fixed_and_branch_insns() {
        assert_eq!(
            assemble_x86(Arch::X86_64, 0x1000, "nop").expect("nop"),
            vec![0x90]
        );
        assert_eq!(
            assemble_x86(Arch::X86_64, 0x1000, "  RET ").expect("ret"),
            vec![0xC3]
        );
        assert_eq!(
            assemble_x86(Arch::X86_64, 0x1000, "int3").expect("int3"),
            vec![0xCC]
        );
        // jmp rel8 from 0x1000 to 0x1010: assemble() picks the shortest
        // encoding (rel = 0x1010 - 0x1002 = 0x0e).
        assert_eq!(
            assemble_x86(Arch::X86_64, 0x1000, "jmp 0x1010").expect("jmp"),
            vec![0xEB, 0x0E]
        );
        assert_eq!(
            assemble_x86(Arch::X86_32, 0x1000, "call 0x1010").expect("call"),
            vec![0xE8, 0x0B, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn asm_rejects_other_archs_and_mnemonics() {
        let e = assemble_x86(Arch::Aarch64, 0x1000, "nop").expect_err("arm");
        assert!(matches!(e, Error::Unsupported(_)), "{e}");
        for bad in [
            "",
            "mov eax, 1",
            "jmp",
            "jmp 0x1 0x2",
            "nop 5",
            "jecxz 0x10",
        ] {
            assert!(
                matches!(
                    assemble_x86(Arch::X86_64, 0x1000, bad),
                    Err(Error::Invalid(_))
                ),
                "{bad:?} must fail"
            );
        }
    }

    #[test]
    fn aarch64_encodes_fixed_brk_and_branches() {
        assert_eq!(
            assemble_aarch64(0x1000, "nop").expect("nop"),
            vec![0x1f, 0x20, 0x03, 0xd5]
        );
        assert_eq!(
            assemble_aarch64(0x1000, "  RET ").expect("ret"),
            vec![0xc0, 0x03, 0x5f, 0xd6]
        );
        assert_eq!(
            assemble_aarch64(0x1000, "brk #0").expect("brk 0"),
            vec![0x00, 0x00, 0x20, 0xd4]
        );
        assert_eq!(
            assemble_aarch64(0x1000, "brk 0x3e8").expect("brk imm"),
            vec![0x00, 0x7d, 0x20, 0xd4]
        );
        assert_eq!(
            assemble_aarch64(0x1000, "b 0x1010").expect("b"),
            vec![0x04, 0x00, 0x00, 0x14]
        );
        assert_eq!(
            assemble_aarch64(0x1000, "bl 0xff0").expect("bl"),
            vec![0xfc, 0xff, 0xff, 0x97]
        );
        for bad in ["", "mov x0, 0", "b", "b 0x1 0x2", "nop 5", "brk #0x10000"] {
            assert!(
                matches!(assemble_aarch64(0x1000, bad), Err(Error::Invalid(_))),
                "{bad:?} must fail"
            );
        }
        assert!(matches!(
            assemble_aarch64(0x1000, "b 0x1002"),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            assemble_aarch64(0x1000, "b 0x10001000"),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn ips_layout_is_header_offset_len_data_eof() {
        let bytes = ips_bytes(0x120, &[0x90, 0x90]).expect("ips");
        assert_eq!(
            bytes.as_slice(),
            b"PATCH\x00\x01\x20\x00\x02\x90\x90EOF".as_slice()
        );
        assert!(ips_bytes(0x1_000_000, &[0x90]).is_err(), "24-bit cap");
        assert!(ips_bytes(0, &[]).is_err(), "empty payload");
    }

    #[test]
    fn preview_serializes_spec_shape() {
        let v = serde_json::to_value(PatchPreview {
            addr: 0x401000,
            file_off: Some(0x400),
            old: vec![0x74, 0x02],
            new: vec![0x90, 0x90],
            size_ok: true,
        })
        .expect("serializes");
        assert_eq!(
            v,
            serde_json::json!({
                "va": 0x401000u64,
                "va_hex": "0x401000",
                "file_off": 0x400u64,
                "old_hex": "7402",
                "new_hex": "9090",
                "size_ok": true,
            })
        );
    }
}
