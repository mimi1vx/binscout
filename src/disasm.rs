//! M2 disassembler: x86_64 via iced-x86, AArch64/ARM32/Thumb via yaxpeax-arm.
//!
//! [`Disassembler::disasm_range`] decodes `bytes` assumed loaded at virtual
//! address `va`. Decoding stops at the first invalid opcode
//! ([`Error::Invalid`]) or when `max_insns` would be exceeded
//! ([`Error::Limit`]). [`Disassembler::disasm_range_partial`] (and the free
//! [`disasm_range_partial`]) instead return the valid prefix plus
//! [`PartialDisasm::error_at`], so agents keep the decodable instructions
//! rather than losing them to the first bad opcode.

use iced_x86::{
    Decoder, DecoderOptions, Formatter as _, Instruction, IntelFormatter, OpKind, Register,
};
use serde::{Deserialize, Serialize};
use yaxpeax_arch::Decoder as ArmDecoder;
use yaxpeax_arm::armv7::{
    InstDecoder as ArmV7Decoder, Instruction as ArmV7Instruction, Opcode as ArmV7Opcode,
    Operand as ArmV7Operand,
};
use yaxpeax_arm::armv8::a64::{InstDecoder, Opcode, Operand};

use crate::error::{Error, Result};

/// Default cap on instructions per [`Disassembler::disasm_range`] call.
pub const DEFAULT_MAX_INSNS: usize = 100_000;

/// Target architecture for disassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// 64-bit x86.
    X86_64,
    /// 32-bit x86 (LE/DOS code).
    X86_32,
    /// 64-bit ARM.
    Aarch64,
    /// 32-bit ARM (ARM mode, fixed 4-byte instructions).
    Arm32,
    /// 32-bit ARM (Thumb mode, mixed 2/4-byte instructions).
    Thumb,
}

impl Arch {
    /// Default disassembler for this architecture.
    #[must_use]
    pub fn disassembler(self) -> AnyDisasm {
        match self {
            Self::X86_64 => AnyDisasm::X86_64(X86_64Disasm::new()),
            Self::X86_32 => AnyDisasm::X86_32(X86_32Disasm::new()),
            Self::Aarch64 => AnyDisasm::Aarch64(Aarch64Disasm::new()),
            Self::Arm32 => AnyDisasm::Arm32(Arm32Disasm::new()),
            Self::Thumb => AnyDisasm::Thumb(ThumbDisasm::new()),
        }
    }
}

/// One decoded instruction.
///
/// JSON carries every address twice: the integer (`addr`, `branch_target`,
/// `mem_target`) plus its canonical `0x`-hex twin (`addr_hex`, ...), via
/// [`crate::addr_hex`]. Old rows without the twins still deserialize (the
/// twins are recomputed on serialize, never stored).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Insn {
    /// Virtual address of the first byte.
    pub addr: u64,
    /// Length in bytes (x86: 1-15, AArch64/ARM32: always 4, Thumb: 2 or 4).
    pub size: u8,
    /// Raw instruction bytes.
    pub bytes: Vec<u8>,
    /// Lowercase mnemonic (`nop`, `ret`, `bl`, ...).
    pub mnem: String,
    /// Operand strings in assembly order.
    pub ops: Vec<String>,
    /// Absolute target for direct branches/calls, if any.
    pub branch_target: Option<u64>,
    /// Absolute address of a data access, if any: x86 RIP-relative memory
    /// operands, x86-32 absolute immediates and displacements
    /// (`push 0x402100`, `mov eax, [0x403000]`), AArch64
    /// `adr`/`adrp`/literal loads, and ARM32/Thumb PC-relative literal
    /// loads (`ldr r0, [pc, ...]`).
    /// Distinct from [`Insn::branch_target`]: an indirect `call [rip+..]`
    /// reports its pointer slot here and `None` for `branch_target`.
    pub mem_target: Option<u64>,
    /// Typed base of a scaled-index table load (`jmp [index*scale+base]`),
    /// if any: x86 only, from the decoder's memory-operand fields (index
    /// register present, no base register, scale equal to the slot width,
    /// displacement as the table start). Never parsed from operand text;
    /// indexed forms report `None` for [`Insn::mem_target`], and plain
    /// absolute/RIP-relative slots report `None` here. ARM `tbb`/`tbh`
    /// carry no displacement and are excluded.
    #[serde(default)]
    pub table_base: Option<u64>,
}

impl Serialize for Insn {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("Insn", 12)?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("size", &self.size)?;
        st.serialize_field("bytes", &self.bytes)?;
        st.serialize_field("mnem", &self.mnem)?;
        st.serialize_field("ops", &self.ops)?;
        st.serialize_field("branch_target", &self.branch_target)?;
        st.serialize_field(
            "branch_target_hex",
            &self.branch_target.map(crate::addr_hex),
        )?;
        st.serialize_field("mem_target", &self.mem_target)?;
        st.serialize_field("mem_target_hex", &self.mem_target.map(crate::addr_hex))?;
        st.serialize_field("table_base", &self.table_base)?;
        st.serialize_field("table_base_hex", &self.table_base.map(crate::addr_hex))?;
        st.end()
    }
}

/// Address and reason of the first undecodable instruction in a partial
/// decode. The message names only the virtual address and opcode context;
/// it never carries host paths. JSON pairs `addr` with `addr_hex`
/// (see [`Insn`]).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DecodeError {
    /// Virtual address of the failing instruction.
    pub addr: u64,
    /// Human-readable reason (e.g. `x86 invalid opcode at 0x4 (64-bit)`).
    pub message: String,
}

impl Serialize for DecodeError {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("DecodeError", 3)?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("message", &self.message)?;
        st.end()
    }
}

/// Prefix decode: the valid instructions plus the first failure, if any.
///
/// A clean range reports `error_at: None`; a range with trailing garbage
/// keeps every instruction before the first bad opcode and reports it in
/// `error_at`. Instruction-cap overruns are still [`Error::Limit`], never a
/// partial result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialDisasm {
    /// Valid instructions before the first failure (empty when the first
    /// byte fails).
    pub insns: Vec<Insn>,
    /// First failure, or `None` for a clean decode.
    pub error_at: Option<DecodeError>,
}

/// Byte-range disassembler over already-loaded bytes.
pub trait Disassembler {
    /// Decode `bytes` loaded at `va`.
    ///
    /// # Errors
    /// [`Error::Invalid`] on the first undecodable instruction,
    /// [`Error::Limit`] if the range holds more than the cap.
    fn disasm_range(&self, bytes: &[u8], va: u64) -> Result<Vec<Insn>>;

    /// Decode the valid prefix of `bytes` loaded at `va`.
    ///
    /// Returns every instruction before the first bad opcode plus
    /// `error_at` for it (`None` when the whole range decodes).
    ///
    /// # Errors
    /// [`Error::Limit`] if the range holds more than the cap; undecodable
    /// bytes are reported in `error_at`, never as an error.
    fn disasm_range_partial(&self, bytes: &[u8], va: u64) -> Result<PartialDisasm>;
}

/// x86_64 disassembler (iced-x86).
#[derive(Debug, Clone, Copy)]
pub struct X86_64Disasm {
    max_insns: usize,
}

/// 32-bit x86 disassembler (iced-x86; covers DOS4GW/LE code for M1).
#[derive(Debug, Clone, Copy)]
pub struct X86_32Disasm {
    max_insns: usize,
}

/// AArch64 disassembler (yaxpeax-arm).
#[derive(Debug, Clone, Copy)]
pub struct Aarch64Disasm {
    max_insns: usize,
}

/// ARM32 disassembler in ARM mode (yaxpeax-arm armv7, fixed 4-byte words).
#[derive(Debug, Clone, Copy)]
pub struct Arm32Disasm {
    max_insns: usize,
}

/// Thumb disassembler (yaxpeax-arm armv7 in Thumb mode, mixed 2/4-byte).
#[derive(Debug, Clone, Copy)]
pub struct ThumbDisasm {
    max_insns: usize,
}

impl X86_64Disasm {
    /// Default instruction cap ([`DEFAULT_MAX_INSNS`]).
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_insns: DEFAULT_MAX_INSNS,
        }
    }

    /// Custom instruction cap.
    #[must_use]
    pub fn with_limit(max_insns: usize) -> Self {
        Self { max_insns }
    }
}

impl Default for X86_64Disasm {
    fn default() -> Self {
        Self::new()
    }
}

impl X86_32Disasm {
    /// Default instruction cap ([`DEFAULT_MAX_INSNS`]).
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_insns: DEFAULT_MAX_INSNS,
        }
    }

    /// Custom instruction cap.
    #[must_use]
    pub fn with_limit(max_insns: usize) -> Self {
        Self { max_insns }
    }
}

impl Default for X86_32Disasm {
    fn default() -> Self {
        Self::new()
    }
}

impl Aarch64Disasm {
    /// Default instruction cap ([`DEFAULT_MAX_INSNS`]).
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_insns: DEFAULT_MAX_INSNS,
        }
    }

    /// Custom instruction cap.
    #[must_use]
    pub fn with_limit(max_insns: usize) -> Self {
        Self { max_insns }
    }
}

impl Default for Aarch64Disasm {
    fn default() -> Self {
        Self::new()
    }
}

impl Arm32Disasm {
    /// Default instruction cap ([`DEFAULT_MAX_INSNS`]).
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_insns: DEFAULT_MAX_INSNS,
        }
    }

    /// Custom instruction cap.
    #[must_use]
    pub fn with_limit(max_insns: usize) -> Self {
        Self { max_insns }
    }
}

impl Default for Arm32Disasm {
    fn default() -> Self {
        Self::new()
    }
}

impl ThumbDisasm {
    /// Default instruction cap ([`DEFAULT_MAX_INSNS`]).
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_insns: DEFAULT_MAX_INSNS,
        }
    }

    /// Custom instruction cap.
    #[must_use]
    pub fn with_limit(max_insns: usize) -> Self {
        Self { max_insns }
    }
}

impl Default for ThumbDisasm {
    fn default() -> Self {
        Self::new()
    }
}

impl Disassembler for X86_64Disasm {
    fn disasm_range(&self, bytes: &[u8], va: u64) -> Result<Vec<Insn>> {
        disasm_x86(bytes, va, self.max_insns, 64)
    }

    fn disasm_range_partial(&self, bytes: &[u8], va: u64) -> Result<PartialDisasm> {
        disasm_x86_partial(bytes, va, self.max_insns, 64)
    }
}

impl Disassembler for X86_32Disasm {
    fn disasm_range(&self, bytes: &[u8], va: u64) -> Result<Vec<Insn>> {
        disasm_x86(bytes, va, self.max_insns, 32)
    }

    fn disasm_range_partial(&self, bytes: &[u8], va: u64) -> Result<PartialDisasm> {
        disasm_x86_partial(bytes, va, self.max_insns, 32)
    }
}

impl Disassembler for Aarch64Disasm {
    fn disasm_range(&self, bytes: &[u8], va: u64) -> Result<Vec<Insn>> {
        disasm_aarch64(bytes, va, self.max_insns)
    }

    fn disasm_range_partial(&self, bytes: &[u8], va: u64) -> Result<PartialDisasm> {
        disasm_aarch64_partial(bytes, va, self.max_insns)
    }
}

impl Disassembler for Arm32Disasm {
    fn disasm_range(&self, bytes: &[u8], va: u64) -> Result<Vec<Insn>> {
        disasm_arm32(bytes, va, self.max_insns)
    }

    fn disasm_range_partial(&self, bytes: &[u8], va: u64) -> Result<PartialDisasm> {
        disasm_arm32_partial(bytes, va, self.max_insns)
    }
}

impl Disassembler for ThumbDisasm {
    fn disasm_range(&self, bytes: &[u8], va: u64) -> Result<Vec<Insn>> {
        disasm_thumb(bytes, va, self.max_insns)
    }

    fn disasm_range_partial(&self, bytes: &[u8], va: u64) -> Result<PartialDisasm> {
        disasm_thumb_partial(bytes, va, self.max_insns)
    }
}

/// Arch-dispatched disassembler (object-safe use of [`Disassembler`]).
#[derive(Debug, Clone, Copy)]
pub enum AnyDisasm {
    /// 64-bit x86 backend.
    X86_64(X86_64Disasm),
    /// 32-bit x86 backend.
    X86_32(X86_32Disasm),
    /// AArch64 backend.
    Aarch64(Aarch64Disasm),
    /// ARM32 (ARM mode) backend.
    Arm32(Arm32Disasm),
    /// Thumb backend.
    Thumb(ThumbDisasm),
}

impl Disassembler for AnyDisasm {
    fn disasm_range(&self, bytes: &[u8], va: u64) -> Result<Vec<Insn>> {
        match self {
            Self::X86_64(d) => d.disasm_range(bytes, va),
            Self::X86_32(d) => d.disasm_range(bytes, va),
            Self::Aarch64(d) => d.disasm_range(bytes, va),
            Self::Arm32(d) => d.disasm_range(bytes, va),
            Self::Thumb(d) => d.disasm_range(bytes, va),
        }
    }

    fn disasm_range_partial(&self, bytes: &[u8], va: u64) -> Result<PartialDisasm> {
        match self {
            Self::X86_64(d) => d.disasm_range_partial(bytes, va),
            Self::X86_32(d) => d.disasm_range_partial(bytes, va),
            Self::Aarch64(d) => d.disasm_range_partial(bytes, va),
            Self::Arm32(d) => d.disasm_range_partial(bytes, va),
            Self::Thumb(d) => d.disasm_range_partial(bytes, va),
        }
    }
}

/// One-shot decode without holding a disassembler value.
pub fn disasm_range(arch: Arch, bytes: &[u8], va: u64, max_insns: usize) -> Result<Vec<Insn>> {
    match arch {
        Arch::X86_64 => disasm_x86(bytes, va, max_insns, 64),
        Arch::X86_32 => disasm_x86(bytes, va, max_insns, 32),
        Arch::Aarch64 => disasm_aarch64(bytes, va, max_insns),
        Arch::Arm32 => disasm_arm32(bytes, va, max_insns),
        Arch::Thumb => disasm_thumb(bytes, va, max_insns),
    }
}

/// One-shot prefix decode: valid instructions plus `error_at` for the first
/// bad opcode (`None` when the whole range decodes).
///
/// Cap overruns are still [`Error::Limit`]; undecodable bytes are data, not
/// an error.
///
/// # Errors
/// [`Error::Limit`] if the range holds more than `max_insns`.
pub fn disasm_range_partial(
    arch: Arch,
    bytes: &[u8],
    va: u64,
    max_insns: usize,
) -> Result<PartialDisasm> {
    match arch {
        Arch::X86_64 => disasm_x86_partial(bytes, va, max_insns, 64),
        Arch::X86_32 => disasm_x86_partial(bytes, va, max_insns, 32),
        Arch::Aarch64 => disasm_aarch64_partial(bytes, va, max_insns),
        Arch::Arm32 => disasm_arm32_partial(bytes, va, max_insns),
        Arch::Thumb => disasm_thumb_partial(bytes, va, max_insns),
    }
}

/// Decode only the first instruction in `bytes` (loaded at `va`).
///
/// Uses the same decoder options and the same [`Insn`] conversion as the
/// range decoders, but stops after one instruction: trailing bytes are never
/// formatted or allocated, and trailing garbage cannot change the first
/// result. An empty input reports `Ok(None)`; an undecodable or truncated
/// first instruction is [`Error::Invalid`], never a partial result.
///
/// # Errors
/// [`Error::Invalid`] when the first instruction does not decode.
pub fn disasm_first(arch: Arch, bytes: &[u8], va: u64) -> Result<Option<Insn>> {
    match arch {
        Arch::X86_64 => disasm_first_x86(bytes, va, 64),
        Arch::X86_32 => disasm_first_x86(bytes, va, 32),
        Arch::Aarch64 => disasm_first_aarch64(bytes, va),
        Arch::Arm32 => disasm_first_arm32(bytes, va),
        Arch::Thumb => disasm_first_thumb(bytes, va),
    }
}

fn limit_err(max_insns: usize) -> Error {
    Error::Limit(format!("more than {max_insns} instructions in range"))
}

/// Legacy x86 prefixes (plus the CET/MPX/HLE prefix words iced-x86 folds
/// into formatted text: `notrack`, `bnd`, `xacquire`, `xrelease`).
/// [`split_asm`]
/// strips these so the mnemonic is the real operation (`rep movsb` becomes
/// `movsb`, `lock add ..` becomes `add`); no ARM backend prints these words
/// as a mnemonic head, so the strip is x86-only in effect.
const X86_PREFIXES: &[&str] = &[
    "rep", "repe", "repne", "lock", "notrack", "bnd", "xacquire", "xrelease",
];

/// Split `mnem op1, op2` into a lowercase mnemonic and operand strings.
///
/// iced-x86 folds legacy prefixes into the formatted text
/// (`rep movsb`, `lock add ..`), which would otherwise surface as bogus
/// `rep`/`lock` mnemonics. [`X86_PREFIXES`] are stripped here so both the
/// disassembly listing and the IR lift see the real operation; operand
/// immediates leave iced-x86 in MASM suffix form (`402100h`), so each
/// operand goes through [`masm_to_hex`] so agents only ever see `0x` form.
fn split_asm(text: &str) -> (String, Vec<String>) {
    let text = text.trim();
    let (mut head, mut tail) = match text.find(char::is_whitespace) {
        Some(i) => (&text[..i], text[i..].trim()),
        None => (text, ""),
    };
    // At most one prefix is ever present, but loop against the table length
    // so stacked prefixes (`lock` + `rep`) still terminate.
    for _ in 0..X86_PREFIXES.len() {
        if !X86_PREFIXES.contains(&head.to_ascii_lowercase().as_str()) {
            break;
        }
        match tail.find(char::is_whitespace) {
            Some(i) => {
                head = &tail[..i];
                tail = tail[i..].trim();
            }
            None => {
                head = tail;
                tail = "";
                break;
            }
        }
    }
    let ops = if tail.is_empty() {
        Vec::new()
    } else {
        tail.split(',').map(|s| masm_to_hex(s.trim())).collect()
    };
    (head.to_lowercase(), ops)
}

/// Rewrite MASM-suffixed hex inside one operand as canonical `0x`-hex.
///
/// iced-x86's `IntelFormatter` emits `402100h` / `0052C2E0h` (with a leading
/// `0` when the digits start with `A`-`F`, e.g. `0FFFFFFFFh`). Only words
/// that start with a decimal digit qualify, so registers (`ah`, `bh`),
/// keywords (`short`, `near`, `ptr`), and symbols pass through untouched;
/// every other character (brackets, `+`, spaces) is preserved verbatim.
fn masm_to_hex(op: &str) -> String {
    let mut out = String::with_capacity(op.len());
    let mut word = String::new();
    for c in op.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
        } else {
            out.push_str(&masm_word(&word));
            word.clear();
            out.push(c);
        }
    }
    out.push_str(&masm_word(&word));
    out
}

/// Rewrite one word of [`masm_to_hex`]: `402100h` becomes `0x402100`.
fn masm_word(word: &str) -> String {
    let b = word.as_bytes();
    let is_suffixed = b.len() >= 2
        && b[0].is_ascii_digit()
        && (b[b.len() - 1] == b'h' || b[b.len() - 1] == b'H')
        && b[..b.len() - 1].iter().all(|c| c.is_ascii_hexdigit());
    if !is_suffixed {
        return word.to_string();
    }
    let digits = &word[..word.len() - 1];
    match u64::from_str_radix(digits, 16) {
        Ok(v) => crate::addr_hex(v),
        Err(_) => format!("0x{}", digits.to_ascii_lowercase()),
    }
}

fn disasm_x86(bytes: &[u8], va: u64, max_insns: usize, bitness: u32) -> Result<Vec<Insn>> {
    let partial = disasm_x86_partial(bytes, va, max_insns, bitness)?;
    match partial.error_at {
        Some(e) => Err(Error::Invalid(e.message)),
        None => Ok(partial.insns),
    }
}

/// Decode only the first x86 instruction in `bytes` (loaded at `va`).
///
/// Uses the same [`Decoder`] options (`DecoderOptions::NONE`, IP `va`) and
/// the same [`x86_insn`] conversion as [`disasm_x86_partial`], but stops
/// after one instruction instead of formatting the whole window. Returns
/// [`Error::Invalid`] with the same message the range decoder reports when
/// the first instruction is undecodable or truncated.
///
/// # Errors
/// [`Error::Invalid`] when the first instruction does not decode.
fn disasm_first_x86(bytes: &[u8], va: u64, bitness: u32) -> Result<Option<Insn>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    // x86 instructions are at most 15 bytes; the window bound mirrors the
    // old shrink-and-retry prefix and cannot change the first decode.
    let win = &bytes[..bytes.len().min(15)];
    let mut decoder = Decoder::new(bitness, win, DecoderOptions::NONE);
    decoder.set_ip(va);
    let addr = decoder.ip();
    let start = decoder.position();
    let insn = decoder.decode();
    if insn.is_invalid() {
        return Err(Error::Invalid(format!(
            "x86 invalid opcode at {addr:#x} ({bitness}-bit)"
        )));
    }
    let size = insn.len();
    let Some(raw) = win.get(start..start + size).map(<[u8]>::to_vec) else {
        return Err(Error::Invalid(format!(
            "x86 invalid opcode at {addr:#x} ({bitness}-bit)"
        )));
    };
    let mut formatter = IntelFormatter::new();
    let mut text = String::new();
    Ok(Some(x86_insn(
        &insn,
        addr,
        raw,
        bitness,
        &mut formatter,
        &mut text,
    )))
}

/// Convert one decoded iced-x86 instruction to [`Insn`].
///
/// Shared by the range prefix decoder and the first-instruction decoder so
/// both report identical mnemonics, operands, and branch/memory targets.
fn x86_insn(
    insn: &Instruction,
    addr: u64,
    raw: Vec<u8>,
    bitness: u32,
    formatter: &mut IntelFormatter,
    text: &mut String,
) -> Insn {
    text.clear();
    formatter.format(insn, text);
    let (mnem, ops) = split_asm(text);
    let branch_target = match insn.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(insn.near_branch_target())
        }
        _ => None,
    };
    let mem_target = insn
        .is_ip_rel_memory_operand()
        .then(|| insn.ip_rel_memory_address());
    let mem_target = match mem_target {
        Some(_) => mem_target,
        None if bitness == 32 => absolute_target32(insn),
        None => None,
    };
    let table_base = table_base_for(bitness, insn);
    Insn {
        addr,
        size: insn.len() as u8,
        bytes: raw,
        mnem,
        ops,
        branch_target,
        mem_target,
        table_base,
    }
}

/// Prefix decode over x86 bytes: each position decodes independently via
/// iced-x86, so trailing garbage cannot change the first decode (the same
/// prefix property [`crate::analysis`] relies on for single-instruction
/// `decode_one`). The first invalid opcode ends the prefix with `error_at`.
fn disasm_x86_partial(
    bytes: &[u8],
    va: u64,
    max_insns: usize,
    bitness: u32,
) -> Result<PartialDisasm> {
    let mut decoder = Decoder::new(bitness, bytes, DecoderOptions::NONE);
    decoder.set_ip(va);
    let mut formatter = IntelFormatter::new();
    let mut text = String::new();
    let mut out = Vec::new();
    while decoder.position() < bytes.len() {
        if out.len() >= max_insns {
            return Err(limit_err(max_insns));
        }
        let addr = decoder.ip();
        let start = decoder.position();
        let insn = decoder.decode();
        if insn.is_invalid() {
            return Ok(PartialDisasm {
                insns: out,
                error_at: Some(DecodeError {
                    addr,
                    message: format!("x86 invalid opcode at {addr:#x} ({bitness}-bit)"),
                }),
            });
        }
        let size = insn.len();
        let raw = match bytes.get(start..start + size) {
            Some(b) => b.to_vec(),
            None => {
                return Ok(PartialDisasm {
                    insns: out,
                    error_at: Some(DecodeError {
                        addr,
                        message: format!("x86 invalid opcode at {addr:#x} ({bitness}-bit)"),
                    }),
                });
            }
        };
        out.push(x86_insn(
            &insn,
            addr,
            raw,
            bitness,
            &mut formatter,
            &mut text,
        ));
    }
    Ok(PartialDisasm {
        insns: out,
        error_at: None,
    })
}

/// Typed base of a scaled-index table load, if any.
///
/// Reports the displacement of an x86 memory operand with an index register,
/// no base register, and a scale equal to the slot width (4 for 32-bit,
/// 8 for 64-bit): the compiler switch shape `jmp [index*scale+table]`.
/// RIP-relative forms (base `RIP`) and plain absolute slots (no index)
/// report `None` here; those keep their [`Insn::mem_target`] path.
/// Strided scales (e.g. `*2` in 32-bit mode) report `None`: the analysis
/// scan assumes dense slots. 64-bit displacements use the decoder's
/// sign-extended form.
fn table_base_for(bitness: u32, insn: &Instruction) -> Option<u64> {
    let width: u64 = match bitness {
        32 => 4,
        64 => 8,
        _ => return None,
    };
    for op in 0..insn.op_count() {
        if insn.op_kind(op) == OpKind::Memory
            && insn.memory_base() == Register::None
            && insn.memory_index() != Register::None
            && u64::from(insn.memory_index_scale()) == width
        {
            let disp = match bitness {
                32 => u64::from(insn.memory_displacement32()),
                _ => insn.memory_displacement64(),
            };
            return Some(disp);
        }
    }
    None
}

/// Absolute data address referenced by a 32-bit x86 instruction, if any.
///
/// 32-bit code addresses data absolutely (`push 0x402100`,
/// `mov eax, 0x403000`, `mov eax, [0x403000]`); 64-bit code uses
/// RIP-relative operands instead (handled by the caller), so 64-bit
/// immediates are never reported here. Absolute memory operands win over
/// immediates: in `mov [0x403000], 0x1` the store slot is the reference,
/// not the stored constant.
fn absolute_target32(insn: &Instruction) -> Option<u64> {
    for op in 0..insn.op_count() {
        if insn.op_kind(op) == OpKind::Memory
            && insn.memory_base() == Register::None
            && insn.memory_index() == Register::None
        {
            return Some(u64::from(insn.memory_displacement32()));
        }
    }
    for op in 0..insn.op_count() {
        if insn.op_kind(op) == OpKind::Immediate32 {
            return Some(u64::from(insn.immediate32()));
        }
    }
    None
}

fn disasm_aarch64(bytes: &[u8], va: u64, max_insns: usize) -> Result<Vec<Insn>> {
    let partial = disasm_aarch64_partial(bytes, va, max_insns)?;
    match partial.error_at {
        Some(e) => Err(Error::Invalid(e.message)),
        None => Ok(partial.insns),
    }
}

/// Decode only the first AArch64 instruction in `bytes` (loaded at `va`).
///
/// Decodes the leading 4-byte word with the same decoder and the same
/// [`aarch64_insn`] conversion as [`disasm_aarch64_partial`]; trailing bytes
/// cannot change the first word decode. Returns [`Error::Invalid`] with the
/// same message the range decoder reports when the first word is undecodable
/// or truncated.
///
/// # Errors
/// [`Error::Invalid`] when the first word does not decode.
fn disasm_first_aarch64(bytes: &[u8], va: u64) -> Result<Option<Insn>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let mut reader =
        <&[u8] as yaxpeax_arch::ReaderBuilder<u64, u8>>::read_from(&bytes[..4.min(bytes.len())]);
    let decoder = InstDecoder::default();
    let inst = match ArmDecoder::decode(&decoder, &mut reader) {
        Ok(inst) => inst,
        Err(e) => {
            return Err(Error::Invalid(format!(
                "aarch64 decode error at {va:#x}: {e:?}"
            )));
        }
    };
    let Some(raw) = bytes.get(..4).map(<[u8]>::to_vec) else {
        return Err(Error::Invalid(format!(
            "aarch64 decode error at {va:#x}: truncated word"
        )));
    };
    Ok(Some(aarch64_insn(va, raw, &inst)))
}

/// Convert one decoded AArch64 instruction to [`Insn`].
///
/// Shared by the range prefix decoder and the first-instruction decoder so
/// both report identical mnemonics, operands, and branch/memory targets.
fn aarch64_insn(addr: u64, raw: Vec<u8>, inst: &yaxpeax_arm::armv8::a64::Instruction) -> Insn {
    let (mnem, ops) = split_asm(&inst.to_string());
    Insn {
        addr,
        size: 4,
        bytes: raw,
        mnem,
        ops,
        branch_target: arm_branch_target(inst, addr),
        mem_target: arm_data_target(inst, addr),
        table_base: None,
    }
}

/// Prefix decode over AArch64 bytes: fixed 4-byte words decode
/// independently, so the first bad word ends the prefix with `error_at`.
/// A short tail (< 4 bytes) fails its word decode the same way.
fn disasm_aarch64_partial(bytes: &[u8], va: u64, max_insns: usize) -> Result<PartialDisasm> {
    let mut reader = <&[u8] as yaxpeax_arch::ReaderBuilder<u64, u8>>::read_from(bytes);
    let decoder = InstDecoder::default();
    let mut out = Vec::new();
    let mut addr = va;
    let mut off = 0usize;
    while off < bytes.len() {
        if out.len() >= max_insns {
            return Err(limit_err(max_insns));
        }
        let inst = match ArmDecoder::decode(&decoder, &mut reader) {
            Ok(inst) => inst,
            Err(e) => {
                return Ok(PartialDisasm {
                    insns: out,
                    error_at: Some(DecodeError {
                        addr,
                        message: format!("aarch64 decode error at {addr:#x}: {e:?}"),
                    }),
                });
            }
        };
        let Some(raw) = bytes.get(off..off + 4).map(<[u8]>::to_vec) else {
            return Ok(PartialDisasm {
                insns: out,
                error_at: Some(DecodeError {
                    addr,
                    message: format!("aarch64 decode error at {addr:#x}: truncated word"),
                }),
            });
        };
        out.push(aarch64_insn(addr, raw, &inst));
        addr = addr.wrapping_add(4);
        off += 4;
    }
    Ok(PartialDisasm {
        insns: out,
        error_at: None,
    })
}

/// Absolute target of PC-relative data access (`adr`/`adrp`/literal loads),
/// else `None`. Branch opcodes are excluded (see [`arm_branch_target`).
/// `adrp` carries a page offset, so the PC is page-masked first.
fn arm_data_target(inst: &yaxpeax_arm::armv8::a64::Instruction, addr: u64) -> Option<u64> {
    if matches!(
        inst.opcode,
        Opcode::B
            | Opcode::BL
            | Opcode::Bcc(_)
            | Opcode::BCcc(_)
            | Opcode::CBZ
            | Opcode::CBNZ
            | Opcode::TBZ
            | Opcode::TBNZ
    ) {
        return None;
    }
    inst.operands.iter().find_map(|op| match op {
        Operand::PCOffset(off) if inst.opcode == Opcode::ADRP => {
            Some((addr & !0xfff).wrapping_add_signed(*off))
        }
        Operand::PCOffset(off) => Some(addr.wrapping_add_signed(*off)),
        _ => None,
    })
}

/// Absolute target for direct PC-relative branches, else `None`.
fn arm_branch_target(inst: &yaxpeax_arm::armv8::a64::Instruction, addr: u64) -> Option<u64> {
    if !matches!(
        inst.opcode,
        Opcode::B
            | Opcode::BL
            | Opcode::Bcc(_)
            | Opcode::BCcc(_)
            | Opcode::CBZ
            | Opcode::CBNZ
            | Opcode::TBZ
            | Opcode::TBNZ
    ) {
        return None;
    }
    inst.operands.iter().find_map(|op| match op {
        Operand::PCOffset(off) => Some(addr.wrapping_add_signed(*off)),
        _ => None,
    })
}

/// Final address of an `adrp` + `add`/`ldr` pair, if any.
///
/// `adrp` materializes only the 4K page base (see [`Insn::mem_target`]);
/// the page offset rides in the next instruction, so the referenced address
/// spans two instructions. Returns the `adrp` page plus the second
/// instruction's immediate when `first` is an `adrp` with a decoded page
/// base and `second` consumes the same register:
///
/// - `add <dst>, <base>, #<imm>` with exactly three operands (`<base>`
///   equals the `adrp` destination; shifted forms such as `lsl #12` add a
///   fourth operand and are rejected) and
/// - `ldr <dst>, [<base>, #<imm>]`, plus the zero-offset `ldr <dst>,
///   [<base>]` form (final address is the page itself).
///
/// The `add`/`ldr` destination may differ from the `adrp` register (e.g.
/// `ldr w0, [x0, #..]`); only the consumed base register must match.
/// Anything else (wrong mnemonics, register mismatch, unparseable
/// immediates, missing page base) returns `None`; the function never
/// guesses. Pairing (adjacency, same block) is the caller's job.
pub(crate) fn resolve_adrp_pair(first: &Insn, second: &Insn) -> Option<u64> {
    if first.mnem != "adrp" {
        return None;
    }
    let page = first.mem_target?;
    let base = first.ops.first()?;
    match second.mnem.as_str() {
        "add" => {
            if second.ops.len() != 3 || second.ops[1] != *base {
                return None;
            }
            let off = parse_hash_imm(&second.ops[2])?;
            Some(page.wrapping_add(off))
        }
        "ldr" => {
            if second.ops.len() == 2 {
                let reg = second.ops[1].strip_prefix('[')?.strip_suffix(']')?;
                if reg != base.as_str() {
                    return None;
                }
                return Some(page);
            }
            if second.ops.len() != 3 {
                return None;
            }
            let reg = second.ops[1].strip_prefix('[')?;
            if reg.contains(['[', ']']) || reg != base.as_str() {
                return None;
            }
            let off = parse_hash_imm(second.ops[2].strip_suffix(']')?)?;
            Some(page.wrapping_add(off))
        }
        _ => None,
    }
}

/// Strict `#`-immediate (`#0x10`, `#16`): anything else is `None`.
fn parse_hash_imm(op: &str) -> Option<u64> {
    let digits = op.strip_prefix('#')?;
    if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()
    } else {
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse::<u64>().ok()
    }
}

/// Decode exactly one ARMv7 instruction from the start of `bytes`
/// (`thumb` selects the decoder mode), with the same decoder and the same
/// [`armv7_insn`] conversion as [`disasm_armv7_partial`].
///
/// Returns [`Error::Invalid`] with the same message the range decoder
/// reports when the instruction is undecodable or truncated.
///
/// # Errors
/// [`Error::Invalid`] when the first instruction does not decode.
fn decode_single_armv7(bytes: &[u8], va: u64, thumb: bool) -> Result<Insn> {
    let mut reader = <&[u8] as yaxpeax_arch::ReaderBuilder<u32, u8>>::read_from(bytes);
    let decoder = ArmV7Decoder::default().with_thumb_mode(thumb);
    let label = if thumb { "thumb" } else { "arm32" };
    // yaxpeax-arm panics on some words (e.g. STRD with Rt == 15 builds
    // Reg(16)); contain it so hostile bytes report Invalid, never abort.
    let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ArmDecoder::decode(&decoder, &mut reader)
    }));
    let inst = match decoded {
        Ok(Ok(inst)) => inst,
        Ok(Err(e)) => {
            return Err(Error::Invalid(format!(
                "{label} decode error at {va:#x}: {e:?}"
            )));
        }
        Err(_) => {
            return Err(Error::Invalid(format!(
                "{label} decode error at {va:#x}: invalid encoding (decoder panic)"
            )));
        }
    };
    let size: usize = if inst.thumb() && !inst.wide() { 2 } else { 4 };
    let Some(raw) = bytes.get(..size).map(<[u8]>::to_vec) else {
        return Err(Error::Invalid(format!(
            "{label} decode error at {va:#x}: truncated word"
        )));
    };
    Ok(armv7_insn(va, raw, &inst))
}

/// Decode only the first ARM32 instruction in `bytes` (loaded at `va`).
///
/// Decodes the leading 4-byte word; trailing bytes cannot change the first
/// word decode. A short tail fails the word decode the same way the range
/// decoder reports it.
///
/// # Errors
/// [`Error::Invalid`] when the first word does not decode.
fn disasm_first_arm32(bytes: &[u8], va: u64) -> Result<Option<Insn>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(decode_single_armv7(
        &bytes[..4.min(bytes.len())],
        va,
        false,
    )?))
}

/// Decode only the first Thumb instruction in `bytes` (loaded at `va`).
///
/// A 4-byte window decodes both 16- and 32-bit forms; only when it fails is
/// a lone halfword tried, so a 32-bit prefix is never misread as 16-bit —
/// the same fallback [`disasm_thumb`] relies on, minus decoding the rest of
/// the window.
///
/// # Errors
/// [`Error::Invalid`] when neither the 4-byte nor the 2-byte window decodes.
fn disasm_first_thumb(bytes: &[u8], va: u64) -> Result<Option<Insn>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() >= 4 {
        match decode_single_armv7(&bytes[..4], va, true) {
            Ok(insn) => return Ok(Some(insn)),
            Err(Error::Invalid(_)) => {}
            Err(e) => return Err(e),
        }
    }
    if bytes.len() >= 2 {
        return Ok(Some(decode_single_armv7(&bytes[..2], va, true)?));
    }
    Err(Error::Invalid(format!(
        "thumb decode error at {va:#x}: truncated word"
    )))
}

/// Convert one decoded ARMv7 instruction to [`Insn`].
///
/// Shared by the range prefix decoder and the first-instruction decoder so
/// both report identical mnemonics, operands, and branch/memory targets.
fn armv7_insn(addr: u64, raw: Vec<u8>, inst: &ArmV7Instruction) -> Insn {
    let size: usize = if inst.thumb() && !inst.wide() { 2 } else { 4 };
    let (mnem, ops) = split_asm(&inst.to_string());
    Insn {
        addr,
        size: size as u8,
        bytes: raw,
        mnem,
        ops,
        branch_target: armv7_branch_target(inst, addr),
        mem_target: armv7_data_target(inst, addr),
        table_base: None,
    }
}

/// Length of the Thumb IT block opened by `mnem` (1-4), else `None`.
///
/// yaxpeax-arm prints the IT mask in the mnemonic (`it`, `ite`, `itt`,
/// `itet`, ...), so the predicated count is the mask length plus one; the
/// base condition rides in the first operand. Only the `e`/`t` mask guard
/// keeps non-IT mnemonics sharing the prefix out. Thumb-only: ARM mode has
/// no IT instruction, so callers gate on [`Arch::Thumb`].
pub(crate) fn it_block_len(mnem: &str) -> Option<u8> {
    let mask = mnem.strip_prefix("it")?;
    if mask.len() > 3 || !mask.bytes().all(|b| b == b'e' || b == b't') {
        return None;
    }
    Some(mask.len() as u8 + 1)
}

fn disasm_arm32(bytes: &[u8], va: u64, max_insns: usize) -> Result<Vec<Insn>> {
    let partial = disasm_arm32_partial(bytes, va, max_insns)?;
    match partial.error_at {
        Some(e) => Err(Error::Invalid(e.message)),
        None => Ok(partial.insns),
    }
}

/// Prefix decode over ARM32 bytes: fixed 4-byte words decode
/// independently, so the first bad word ends the prefix with `error_at`.
/// A short tail (< 4 bytes) fails its word decode the same way.
fn disasm_arm32_partial(bytes: &[u8], va: u64, max_insns: usize) -> Result<PartialDisasm> {
    disasm_armv7_partial(bytes, va, max_insns, false)
}

fn disasm_thumb(bytes: &[u8], va: u64, max_insns: usize) -> Result<Vec<Insn>> {
    let partial = disasm_thumb_partial(bytes, va, max_insns)?;
    match partial.error_at {
        Some(e) => Err(Error::Invalid(e.message)),
        None => Ok(partial.insns),
    }
}

/// Prefix decode over Thumb bytes: the first halfword decides the length
/// (2 or 4 bytes), so the first bad halfword pair ends the prefix with
/// `error_at`. A short tail, including a lone first halfword of a 32-bit
/// instruction, fails its decode the same way.
fn disasm_thumb_partial(bytes: &[u8], va: u64, max_insns: usize) -> Result<PartialDisasm> {
    disasm_armv7_partial(bytes, va, max_insns, true)
}

/// Shared ARMv7 prefix decode; `thumb` selects the decoder mode.
///
/// The reader is stateful across decodes, and each successful decode
/// consumes exactly its instruction (`inst.thumb() && !inst.wide()` is 2
/// bytes, anything else 4), so the byte window always matches what the
/// decoder read — including a 2-byte tail left by a 32-bit prefix, which
/// fails as exhausted input.
fn disasm_armv7_partial(
    bytes: &[u8],
    va: u64,
    max_insns: usize,
    thumb: bool,
) -> Result<PartialDisasm> {
    let mut reader = <&[u8] as yaxpeax_arch::ReaderBuilder<u32, u8>>::read_from(bytes);
    let decoder = ArmV7Decoder::default().with_thumb_mode(thumb);
    let label = if thumb { "thumb" } else { "arm32" };
    let mut out = Vec::new();
    let mut addr = va;
    let mut off = 0usize;
    while off < bytes.len() {
        if out.len() >= max_insns {
            return Err(limit_err(max_insns));
        }
        // See `decode_single_armv7`: contain yaxpeax-arm panics as the first
        // failure so hostile bytes end the prefix, never abort the process.
        let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ArmDecoder::decode(&decoder, &mut reader)
        }));
        let inst = match decoded {
            Ok(Ok(inst)) => inst,
            Ok(Err(e)) => {
                return Ok(PartialDisasm {
                    insns: out,
                    error_at: Some(DecodeError {
                        addr,
                        message: format!("{label} decode error at {addr:#x}: {e:?}"),
                    }),
                });
            }
            Err(_) => {
                return Ok(PartialDisasm {
                    insns: out,
                    error_at: Some(DecodeError {
                        addr,
                        message: format!(
                            "{label} decode error at {addr:#x}: invalid encoding (decoder panic)"
                        ),
                    }),
                });
            }
        };
        let size: usize = if inst.thumb() && !inst.wide() { 2 } else { 4 };
        let Some(raw) = bytes.get(off..off + size).map(<[u8]>::to_vec) else {
            return Ok(PartialDisasm {
                insns: out,
                error_at: Some(DecodeError {
                    addr,
                    message: format!("{label} decode error at {addr:#x}: truncated word"),
                }),
            });
        };
        out.push(armv7_insn(addr, raw, &inst));
        addr = addr.wrapping_add(size as u64);
        off += size;
    }
    Ok(PartialDisasm {
        insns: out,
        error_at: None,
    })
}

/// Absolute target for direct ARMv7 branches, else `None`.
///
/// `BranchOffset` (ARM `b`/`bl`) counts words from the instruction address:
/// the decoder already folded the architectural PC+8 bias in.
/// `BranchThumbOffset` counts halfwords (`off * 2`) from PC: `addr + 4` in
/// Thumb, `addr + 8` in ARM. Thumb `blx` switches to ARM state, so its PC
/// is aligned (`(addr + 4) & !3`) before adding the offset.
fn armv7_branch_target(inst: &ArmV7Instruction, addr: u64) -> Option<u64> {
    if !matches!(
        inst.opcode,
        ArmV7Opcode::B | ArmV7Opcode::BL | ArmV7Opcode::BLX | ArmV7Opcode::CBZ | ArmV7Opcode::CBNZ
    ) {
        return None;
    }
    inst.operands.iter().find_map(|op| match op {
        ArmV7Operand::BranchOffset(off) => Some(addr.wrapping_add_signed(i64::from(*off) * 4)),
        ArmV7Operand::BranchThumbOffset(off) if inst.thumb() => {
            let base = if matches!(inst.opcode, ArmV7Opcode::BLX) {
                addr.wrapping_add(4) & !3
            } else {
                addr.wrapping_add(4)
            };
            Some(base.wrapping_add_signed(i64::from(*off) * 2))
        }
        ArmV7Operand::BranchThumbOffset(off) => Some(
            addr.wrapping_add(8)
                .wrapping_add_signed(i64::from(*off) * 2),
        ),
        _ => None,
    })
}

/// Absolute target of a PC-relative literal load (`ldr` family with a `pc`
/// base), else `None`. Branch opcodes are excluded (see
/// [`armv7_branch_target`]). ARM reads PC as `addr + 8`; Thumb reads an
/// aligned PC (`addr + 4` rounded down to 4) and the decoder already scaled
/// 16-bit offsets to bytes.
///
/// `adr` is deliberately excluded: its Display folds the add/sub form away
/// (`adr r0, pc, 0x4` for both), so the sign is unrecoverable from the
/// decoded instruction.
fn armv7_data_target(inst: &ArmV7Instruction, addr: u64) -> Option<u64> {
    if matches!(
        inst.opcode,
        ArmV7Opcode::B | ArmV7Opcode::BL | ArmV7Opcode::BLX | ArmV7Opcode::CBZ | ArmV7Opcode::CBNZ
    ) {
        return None;
    }
    if !matches!(
        inst.opcode,
        ArmV7Opcode::LDR
            | ArmV7Opcode::LDRB
            | ArmV7Opcode::LDRH
            | ArmV7Opcode::LDRSB
            | ArmV7Opcode::LDRSH
    ) {
        return None;
    }
    inst.operands.iter().find_map(|op| match op {
        ArmV7Operand::RegDerefPreindexOffset(reg, off, add, _) if reg.number() == 15 => {
            let base = if inst.thumb() {
                addr.wrapping_add(4) & !3
            } else {
                addr.wrapping_add(8)
            };
            let delta = u64::from(*off);
            Some(if *add {
                base.wrapping_add(delta)
            } else {
                base.wrapping_sub(delta)
            })
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_32_push_imm32_reports_mem_target() {
        // push 0x402100 at 0x401003.
        let v = disasm_x86(&[0x68, 0x00, 0x21, 0x40, 0x00], 0x401003, 8, 32).expect("push decodes");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mem_target, Some(0x402100));
        assert_eq!(v[0].branch_target, None);
    }

    #[test]
    fn x86_32_mov_abs_mem_reports_mem_target() {
        // mov eax, [0x403000] at 0x401000.
        let v = disasm_x86(&[0xA1, 0x00, 0x30, 0x40, 0x00], 0x401000, 8, 32)
            .expect("moffs load decodes");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mem_target, Some(0x403000));
    }

    #[test]
    fn x86_64_push_imm32_is_not_a_data_ref() {
        // Same bytes in 64-bit mode: a sign-extended constant, not an address.
        let v = disasm_x86(&[0x68, 0x00, 0x21, 0x40, 0x00], 0x401003, 8, 64).expect("push decodes");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mem_target, None);
    }

    #[test]
    fn arm32_mov_bx_snapshot() {
        // mov r0, r1 ; bx lr at 0x10000.
        let v = disasm_arm32(
            &[0x01, 0x00, 0xA0, 0xE1, 0x1E, 0xFF, 0x2F, 0xE1],
            0x10000,
            8,
        )
        .expect("arm32 must decode");
        assert_eq!(v.len(), 2);
        assert_eq!(
            v.iter().map(|i| (i.addr, i.size)).collect::<Vec<_>>(),
            [(0x10000, 4), (0x10004, 4)]
        );
        assert_eq!(
            v.iter().map(|i| i.mnem.as_str()).collect::<Vec<_>>(),
            ["mov", "bx"]
        );
        assert_eq!(v[0].ops, ["r0", "r1"]);
        assert_eq!(v[0].bytes, [0x01, 0x00, 0xA0, 0xE1]);
        assert!(v.iter().all(|i| i.branch_target.is_none()));
    }

    #[test]
    fn arm32_b_targets_self() {
        // b . at 0x10000: word offset 0 already folds the PC+8 bias in.
        let v = disasm_arm32(&[0xFE, 0xFF, 0xFF, 0xEA], 0x10000, 8).expect("b decodes");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mnem, "b");
        assert_eq!(v[0].branch_target, Some(0x10000));
    }

    #[test]
    fn arm32_bl_folds_pc_bias() {
        // bl with zero field at 0x10000 targets addr+8.
        let v = disasm_arm32(&[0x00, 0x00, 0x00, 0xEB], 0x10000, 8).expect("bl decodes");
        assert_eq!(v[0].mnem, "bl");
        assert_eq!(v[0].branch_target, Some(0x10008));
    }

    #[test]
    fn arm32_literal_ldr_reports_mem_target() {
        // ldr r0, [pc, #4] at 0x10000 reads PC (addr+8) + 4.
        let v = disasm_arm32(&[0x04, 0x00, 0x9F, 0xE5], 0x10000, 8).expect("ldr decodes");
        assert_eq!(v[0].mem_target, Some(0x1000c));
        assert_eq!(v[0].branch_target, None);
        // Sub form subtracts.
        let v = disasm_arm32(&[0x04, 0x00, 0x1F, 0xE5], 0x10000, 8).expect("ldr decodes");
        assert_eq!(v[0].mem_target, Some(0x10004));
    }

    #[test]
    fn thumb_mixed_width_snapshot() {
        // nop (2B) ; bl #0 (4B) ; bx lr (2B) at 0x20000.
        let bytes = [0x00, 0xBF, 0x00, 0xF0, 0x00, 0xF8, 0x70, 0x47];
        let v = disasm_thumb(&bytes, 0x20000, 8).expect("thumb must decode");
        assert_eq!(
            v.iter().map(|i| (i.addr, i.size)).collect::<Vec<_>>(),
            [(0x20000, 2), (0x20002, 4), (0x20006, 2)]
        );
        assert_eq!(v[0].mnem, "nop");
        assert_eq!(v[2].mnem, "bx");
        assert_eq!(v[2].ops, ["lr"]);
        assert_eq!(v[1].branch_target, Some(0x20006));
        assert_eq!(v[1].bytes, [0x00, 0xF0, 0x00, 0xF8]);
    }

    #[test]
    fn thumb_b_targets_pc_relative() {
        // b . (0xE7FE) at 0x20000: halfword offset -2 from PC (addr+4).
        let v = disasm_thumb(&[0xFE, 0xE7], 0x20000, 8).expect("b decodes");
        assert_eq!(v[0].mnem, "b");
        assert_eq!(v[0].branch_target, Some(0x20000));
    }

    #[test]
    fn thumb_literal_ldr_aligns_pc() {
        // ldr r0, [pc, #16] at 0x20001: base is addr+4 rounded down to 4.
        let v = disasm_thumb(&[0x04, 0x48], 0x20001, 8).expect("ldr decodes");
        assert_eq!(v[0].mem_target, Some(((0x20001 + 4) & !3) + 16));
    }

    #[test]
    fn x86_32_scaled_index_reports_typed_table_base() {
        // jmp [eax*4+0x401012]: typed base, never a mem_target, never text.
        let v = disasm_x86(&[0xFF, 0x24, 0x85, 0x12, 0x10, 0x40, 0x00], 0x401005, 8, 32)
            .expect("indexed jmp decodes");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mnem, "jmp");
        assert_eq!(v[0].table_base, Some(0x401012));
        assert_eq!(v[0].mem_target, None);
        assert_eq!(v[0].branch_target, None);
    }

    #[test]
    fn x86_64_scaled_index_reports_typed_table_base() {
        // jmp [rax*8+0x400012]: the 64-bit switch shape.
        let v = disasm_x86(
            &[0x48, 0xFF, 0x24, 0xC5, 0x12, 0x00, 0x40, 0x00],
            0x400005,
            8,
            64,
        )
        .expect("indexed jmp decodes");
        assert_eq!(v[0].table_base, Some(0x400012));
        assert_eq!(v[0].mem_target, None);
        assert_eq!(v[0].branch_target, None);
    }

    #[test]
    fn x86_index_wrong_scale_reports_no_table_base() {
        // jmp [eax*2+0x401012] (scale 2, slot width 4): strided tables
        // are unsupported, so no typed base is reported.
        let v = disasm_x86(&[0xFF, 0x24, 0x45, 0x12, 0x10, 0x40, 0x00], 0x401005, 8, 32)
            .expect("strided jmp decodes");
        assert_eq!(v[0].table_base, None);
        assert_eq!(v[0].mem_target, None);
        assert_eq!(v[0].branch_target, None);
    }

    #[test]
    fn x86_plain_slot_reports_no_table_base() {
        // jmp [0x401006]: the single-slot shape keeps mem_target only.
        let v = disasm_x86(&[0xFF, 0x25, 0x06, 0x10, 0x40, 0x00], 0x401000, 8, 32)
            .expect("absolute jmp decodes");
        assert_eq!(v[0].mem_target, Some(0x401006));
        assert_eq!(v[0].table_base, None);
        // RIP-relative slots stay on the mem_target path too.
        let v = disasm_x86(&[0xFF, 0x25, 0x04, 0x00, 0x00, 0x00], 0x400000, 8, 64)
            .expect("rip-relative jmp decodes");
        assert_eq!(v[0].mem_target, Some(0x40000a));
        assert_eq!(v[0].table_base, None);
    }

    fn adrp_pair(bytes: &[u8], va: u64) -> Vec<Insn> {
        disasm_aarch64(bytes, va, 8).expect("adrp pair must decode")
    }

    #[test]
    fn adrp_add_pair_resolves_final_address() {
        // adrp x0, #0 at 0x4000 (page 0x4000); add x0, x0, #0x10.
        let v = adrp_pair(&[0x00, 0x00, 0x00, 0x90, 0x00, 0x40, 0x00, 0x91], 0x4000);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].mem_target, Some(0x4000));
        assert_eq!(resolve_adrp_pair(&v[0], &v[1]), Some(0x4010));
        // Nonzero page: adrp x2, +0x1000 (page 0x5000); add x2, x2, #0x123.
        let v = adrp_pair(&[0x02, 0x00, 0x00, 0xB0, 0x42, 0x8c, 0x04, 0x91], 0x4000);
        assert_eq!(v[0].mem_target, Some(0x5000));
        assert_eq!(resolve_adrp_pair(&v[0], &v[1]), Some(0x5123));
        // Cross-destination add still resolves: add x1, x0, #0x10.
        let v = adrp_pair(&[0x00, 0x00, 0x00, 0x90, 0x01, 0x40, 0x00, 0x91], 0x4000);
        assert_eq!(resolve_adrp_pair(&v[0], &v[1]), Some(0x4010));
    }

    #[test]
    fn adrp_ldr_pair_resolves_final_address() {
        // adrp x0, #0 at 0x4000; ldr x0, [x0, #0x8].
        let v = adrp_pair(&[0x00, 0x00, 0x00, 0x90, 0x00, 0x04, 0x40, 0xF9], 0x4000);
        assert_eq!(v.len(), 2);
        assert_eq!(resolve_adrp_pair(&v[0], &v[1]), Some(0x4008));
        // Zero-offset form (ldr x0, [x0]) resolves to the page itself.
        let v = adrp_pair(&[0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x40, 0xF9], 0x4000);
        assert_eq!(v[1].ops, ["x0", "[x0]"]);
        assert_eq!(resolve_adrp_pair(&v[0], &v[1]), Some(0x4000));
        // Narrow-destination load resolves too: ldr x1, [x0, #0x10].
        let v = adrp_pair(&[0x00, 0x00, 0x00, 0x90, 0x01, 0x08, 0x40, 0xF9], 0x4000);
        assert_eq!(resolve_adrp_pair(&v[0], &v[1]), Some(0x4010));
    }

    #[test]
    fn adrp_pair_rejects_non_pairs() {
        // Register mismatch: adrp x0 but add x0, x1, #0x10.
        let v = adrp_pair(&[0x00, 0x00, 0x00, 0x90, 0x20, 0x40, 0x00, 0x91], 0x4000);
        assert_eq!(resolve_adrp_pair(&v[0], &v[1]), None);
        // Wrong second mnemonic: sub x0, x0, #0x10.
        let v = adrp_pair(&[0x00, 0x00, 0x00, 0x90, 0x00, 0x40, 0x00, 0xD1], 0x4000);
        assert_eq!(v[1].mnem, "sub");
        assert_eq!(resolve_adrp_pair(&v[0], &v[1]), None);
        // Shifted add (lsl #12) changes the offset encoding: rejected.
        let v = adrp_pair(&[0x00, 0x00, 0x00, 0x90, 0x00, 0x04, 0x40, 0x91], 0x4000);
        assert_eq!(v[1].ops.len(), 4);
        assert_eq!(resolve_adrp_pair(&v[0], &v[1]), None);
        // First instruction is not adrp.
        let v = adrp_pair(&[0x00, 0x40, 0x00, 0x91, 0x00, 0x40, 0x00, 0x91], 0x4000);
        assert_eq!(resolve_adrp_pair(&v[0], &v[1]), None);
        // Missing page base never resolves.
        let v = adrp_pair(&[0x00, 0x00, 0x00, 0x90, 0x00, 0x40, 0x00, 0x91], 0x4000);
        let mut no_page = v[0].clone();
        no_page.mem_target = None;
        assert_eq!(resolve_adrp_pair(&no_page, &v[1]), None);
        // Unparseable immediates never resolve, never panic.
        let mut bad_imm = v[1].clone();
        bad_imm.ops[2] = "#zz".to_string();
        assert_eq!(resolve_adrp_pair(&v[0], &bad_imm), None);
        bad_imm.ops[2] = "x1".to_string();
        assert_eq!(resolve_adrp_pair(&v[0], &bad_imm), None);
        let mut bad_ldr = v[1].clone();
        bad_ldr.mnem = "ldr".to_string();
        bad_ldr.ops = vec!["x0".to_string(), "[x1".to_string(), "#0x8]".to_string()];
        assert_eq!(resolve_adrp_pair(&v[0], &bad_ldr), None);
    }
}
