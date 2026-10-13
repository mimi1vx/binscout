//! M2 disassembler: x86_64 via iced-x86, AArch64 via yaxpeax-arm.
//!
//! [`Disassembler::disasm_range`] decodes `bytes` assumed loaded at virtual
//! address `va`. Decoding stops at the first invalid opcode
//! ([`Error::Invalid`]) or when `max_insns` would be exceeded
//! ([`Error::Limit`]).

use iced_x86::{Decoder, DecoderOptions, Formatter as _, IntelFormatter, OpKind};
use serde::{Deserialize, Serialize};
use yaxpeax_arch::Decoder as ArmDecoder;
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
}

impl Arch {
    /// Default disassembler for this architecture.
    #[must_use]
    pub fn disassembler(self) -> AnyDisasm {
        match self {
            Self::X86_64 => AnyDisasm::X86_64(X86_64Disasm::new()),
            Self::X86_32 => AnyDisasm::X86_32(X86_32Disasm::new()),
            Self::Aarch64 => AnyDisasm::Aarch64(Aarch64Disasm::new()),
        }
    }
}

/// One decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Insn {
    /// Virtual address of the first byte.
    pub addr: u64,
    /// Length in bytes (x86: 1-15, AArch64: always 4).
    pub size: u8,
    /// Raw instruction bytes.
    pub bytes: Vec<u8>,
    /// Lowercase mnemonic (`nop`, `ret`, `bl`, ...).
    pub mnem: String,
    /// Operand strings in assembly order.
    pub ops: Vec<String>,
    /// Absolute target for direct branches/calls, if any.
    pub branch_target: Option<u64>,
    /// Absolute address of PC-relative data access, if any (x86
    /// RIP-relative memory operands; AArch64 `adr`/`adrp`/literal loads).
    /// Distinct from [`Insn::branch_target`]: an indirect `call [rip+..]`
    /// reports its pointer slot here and `None` for `branch_target`.
    pub mem_target: Option<u64>,
}

/// Byte-range disassembler over already-loaded bytes.
pub trait Disassembler {
    /// Decode `bytes` loaded at `va`.
    ///
    /// # Errors
    /// [`Error::Invalid`] on the first undecodable instruction,
    /// [`Error::Limit`] if the range holds more than the cap.
    fn disasm_range(&self, bytes: &[u8], va: u64) -> Result<Vec<Insn>>;
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

impl Disassembler for X86_64Disasm {
    fn disasm_range(&self, bytes: &[u8], va: u64) -> Result<Vec<Insn>> {
        disasm_x86(bytes, va, self.max_insns, 64)
    }
}

impl Disassembler for X86_32Disasm {
    fn disasm_range(&self, bytes: &[u8], va: u64) -> Result<Vec<Insn>> {
        disasm_x86(bytes, va, self.max_insns, 32)
    }
}

impl Disassembler for Aarch64Disasm {
    fn disasm_range(&self, bytes: &[u8], va: u64) -> Result<Vec<Insn>> {
        disasm_aarch64(bytes, va, self.max_insns)
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
}

impl Disassembler for AnyDisasm {
    fn disasm_range(&self, bytes: &[u8], va: u64) -> Result<Vec<Insn>> {
        match self {
            Self::X86_64(d) => d.disasm_range(bytes, va),
            Self::X86_32(d) => d.disasm_range(bytes, va),
            Self::Aarch64(d) => d.disasm_range(bytes, va),
        }
    }
}

/// One-shot decode without holding a disassembler value.
pub fn disasm_range(arch: Arch, bytes: &[u8], va: u64, max_insns: usize) -> Result<Vec<Insn>> {
    match arch {
        Arch::X86_64 => disasm_x86(bytes, va, max_insns, 64),
        Arch::X86_32 => disasm_x86(bytes, va, max_insns, 32),
        Arch::Aarch64 => disasm_aarch64(bytes, va, max_insns),
    }
}

fn limit_err(max_insns: usize) -> Error {
    Error::Limit(format!("more than {max_insns} instructions in range"))
}

/// Split `mnem op1, op2` into a lowercase mnemonic and operand strings.
fn split_asm(text: &str) -> (String, Vec<String>) {
    let text = text.trim();
    let (head, tail) = match text.find(char::is_whitespace) {
        Some(i) => (&text[..i], text[i..].trim()),
        None => (text, ""),
    };
    let ops = if tail.is_empty() {
        Vec::new()
    } else {
        tail.split(',').map(|s| s.trim().to_string()).collect()
    };
    (head.to_lowercase(), ops)
}

fn disasm_x86(bytes: &[u8], va: u64, max_insns: usize, bitness: u32) -> Result<Vec<Insn>> {
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
            return Err(Error::Invalid(format!(
                "x86 invalid opcode at {addr:#x} ({bitness}-bit)"
            )));
        }
        let size = insn.len();
        text.clear();
        formatter.format(&insn, &mut text);
        let (mnem, ops) = split_asm(&text);
        let branch_target = match insn.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Some(insn.near_branch_target())
            }
            _ => None,
        };
        let mem_target = insn
            .is_ip_rel_memory_operand()
            .then(|| insn.ip_rel_memory_address());
        out.push(Insn {
            addr,
            size: size as u8,
            bytes: bytes[start..start + size].to_vec(),
            mnem,
            ops,
            branch_target,
            mem_target,
        });
    }
    Ok(out)
}

fn disasm_aarch64(bytes: &[u8], va: u64, max_insns: usize) -> Result<Vec<Insn>> {
    let mut reader = <&[u8] as yaxpeax_arch::ReaderBuilder<u64, u8>>::read_from(bytes);
    let decoder = InstDecoder::default();
    let mut out = Vec::new();
    let mut addr = va;
    let mut off = 0usize;
    while off < bytes.len() {
        if out.len() >= max_insns {
            return Err(limit_err(max_insns));
        }
        let inst = ArmDecoder::decode(&decoder, &mut reader)
            .map_err(|e| Error::Invalid(format!("aarch64 decode error at {addr:#x}: {e:?}")))?;
        let (mnem, ops) = split_asm(&inst.to_string());
        out.push(Insn {
            addr,
            size: 4,
            bytes: bytes[off..off + 4].to_vec(),
            mnem,
            ops,
            branch_target: arm_branch_target(&inst, addr),
            mem_target: arm_data_target(&inst, addr),
        });
        addr = addr.wrapping_add(4);
        off += 4;
    }
    Ok(out)
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
