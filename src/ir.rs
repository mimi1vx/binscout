//! M3 IR: minimal P-code-inspired lift over [`Insn`].
//!
//! One machine instruction lifts to one [`IrInsn`]. The `Vec` return reserves
//! multi-op expansion (e.g. `push` as adjust-plus-store); M3 always emits a
//! single element. Operands reuse the disassembler's strings verbatim and
//! `target` carries direct branch/call destinations from
//! [`Insn::branch_target`]. Stack-pointer and flag effects are not modeled.
//!
//! [`IrOp::Phi`] is never emitted by these lifters; M4 synthesizes it at CFG
//! merges. Unknown mnemonics become [`IrOp::Nop`] with `warning` set instead
//! of failing, so analysis can proceed over partial lifts.
//!
//! # ISA coverage
//!
//! `lift_x86` covers both 32- and 64-bit x86 (same mnemonic table; only the
//! decoder differs):
//!
//! - `COPY`: `mov`, `movsx`, `movsxd`, `movzx`, `movabs`, `xchg`, `leave`,
//!   `enter`.
//! - `LOAD`: `pop`, `popa`, `popad`, `popcnt`. `STORE`: `push`, `pusha`,
//!   `pushad`.
//! - `ADD`: `add`, `adc`, `adcx`, `adox`, `lea` (address math, not a load),
//!   `inc`. `SUB`: `sub`, `sbb`, `dec`, `neg`. `MUL`: `mul`, `imul`.
//!   `DIV`: `div`, `idiv`. `AND`: `and`. `OR`: `or`. `XOR`: `xor`, `pxor`,
//!   `not`. `SHL`: `shl`, `sal`. `SHR`: `shr`, `sar`, plus rotates `rol`,
//!   `ror`, `rcl`, `rcr` (approximated as shifts; exact bit motion is out of
//!   scope).
//! - `CMP`: `cmp`, `test`. `BRANCH`: direct `jmp` (indirect keeps operands,
//!   no target). `CBRANCH`: all `jcc` forms plus `jcxz`/`jecxz`/`jrcxz` and
//!   `loop`/`loope`/`loopne`. `CALL`: `call`, `syscall`, `sysenter`, `int`,
//!   `int3`. `RETURN`: `ret`, `retn`, `retf`, `iret`, `iretd`, `iretq`.
//! - `NOP`: `nop`, `pause`, `hlt`, `wait`, `endbr32`, `endbr64`.
//!
//! `lift_aarch64` covers A64 mnemonics as printed by the disassembler:
//!
//! - `COPY`: `mov`, `movz`, `movn`, `movk`, `adr`, `adrp`. `LOAD`: `ldr`,
//!   `ldp`, `ldur`, `ldrb`, `ldrh`, `ldrsb`, `ldrsh`, `ldrsw`. `STORE`:
//!   `str`, `stp`, `stur`, `strb`, `strh`.
//! - `ADD`: `add`, `adds`, `adc`, `adcs`. `SUB`: `sub`, `subs`, `sbc`,
//!   `sbcs`, `neg`, `negs`. `MUL`: `mul`, `madd`, `msub`, `smull`, `smulh`,
//!   `umull`, `umulh`. `DIV`: `sdiv`, `udiv`. `AND`: `and`, `ands`, `bic`,
//!   `bics`. `OR`: `orr`, `orn`. `XOR`: `eor`, `eon`. `SHL`: `lsl`, `lslv`.
//!   `SHR`: `lsr`, `lsrv`, `asr`, `asrv`, `ror`, `rorv`.
//! - `CMP`: `cmp`, `cmn`, `tst`. `BRANCH`: direct `b`/`br` (indirect keeps
//!   operands). `CBRANCH`: `cbz`, `cbnz`, `tbz`, `tbnz`, `b.<cond>`,
//!   `bc.<cond>`. `CALL`: direct `bl`/`blr` (indirect keeps operands) plus
//!   `svc`, `hvc`, `smc`. `RETURN`: `ret`, `eret`. `NOP`: `nop`, `hint`,
//!   `dmb`, `dsb`, `isb`, `brk`.
//!
//! `lift_arm32` covers ARMv7/ARM32 and Thumb mnemonics as printed by the
//! disassembler (one `.w`/`.n` width suffix, one condition suffix, and one
//! flag `s` stripped first):
//!
//! - `COPY`: `mov`, `movw`, `movt`, `mvn`, `adr`. `LOAD`: `ldr`, `ldrb`,
//!   `ldrh`, `ldrsb`, `ldrsh`, `ldrd`, `ldm`, `pop` (`pop`/`ldm` naming `pc`
//!   lifts to `RETURN`, or `CBRANCH` when conditioned). `STORE`: `str`,
//!   `strb`, `strh`, `strd`, `stm`, `push`.
//! - `ADD`: `add`, `adc`. `SUB`: `sub`, `sbc`, `rsb`, `rsc`. `MUL`: `mul`,
//!   `mla`. `DIV`: `sdiv`, `udiv`. `AND`: `and`, `bic`. `OR`: `orr`, `orn`.
//!   `XOR`: `eor`. `SHL`: `lsl`. `SHR`: `lsr`, `asr`, `ror`, `rrx`.
//! - `CMP`: `cmp`, `cmn`, `tst`, `teq`. `BRANCH`: plain `b`/`bx` (indirect
//!   keeps operands), `tbb`/`tbh`. `CBRANCH`: conditioned `b`/`bx`,
//!   `cbz`/`cbnz`. `CALL`: direct `bl`/`blx` (indirect keeps operands) plus
//!   `svc`, `hvc`, `smc`. `RETURN`: `pop`/`ldm` with `pc`, plain `bx lr`.
//!   `NOP`: `nop`, `dmb`, `dsb`, `isb`.
//!
//! # Warning semantics
//!
//! Lifting never fails: a mnemonic outside all tables (e.g. x86 `cpuid`,
//! ARM `mrs`) lifts to [`IrOp::Nop`] with `warning` set to
//! `"unlifted '<mnem>'; emitted NOP"`. `warning` is `None` for every mapped
//! mnemonic, so `warning.is_some()` exactly marks approximate coverage.
//! Downstream passes treat unlifted instructions as fall-through (`Seq`),
//! never as control flow.
//!
//! JSON pairs `addr` with `addr_hex` and `target` with `target_hex`
//! (see [`crate::addr_hex`]).
use serde::{Deserialize, Serialize};

use crate::disasm::{Arch, Insn};

/// Minimal P-code-inspired operation set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IrOp {
    /// Register-to-register or memory-to-register copy.
    Copy,
    /// Memory read.
    Load,
    /// Memory write.
    Store,
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
    /// Division.
    Div,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Logical left shift.
    Shl,
    /// Logical right shift.
    Shr,
    /// Comparison (flag effects unmodeled).
    Cmp,
    /// Unconditional direct branch.
    Branch,
    /// Conditional direct branch.
    CBranch,
    /// Direct call.
    Call,
    /// Function return.
    Return,
    /// Merge value, synthesized at CFG joins (never lifted).
    Phi,
    /// Unmapped or effect-free operation.
    Nop,
}

impl IrOp {
    /// Uppercase opcode name (`COPY`, `LOAD`, ...).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Copy => "COPY",
            Self::Load => "LOAD",
            Self::Store => "STORE",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Div => "DIV",
            Self::And => "AND",
            Self::Or => "OR",
            Self::Xor => "XOR",
            Self::Shl => "SHL",
            Self::Shr => "SHR",
            Self::Cmp => "CMP",
            Self::Branch => "BRANCH",
            Self::CBranch => "CBRANCH",
            Self::Call => "CALL",
            Self::Return => "RETURN",
            Self::Phi => "PHI",
            Self::Nop => "NOP",
        }
    }

    /// Whether this op transfers control.
    #[must_use]
    pub fn is_control(self) -> bool {
        matches!(
            self,
            Self::Branch | Self::CBranch | Self::Call | Self::Return
        )
    }
}

/// One lifted IR operation.
///
/// JSON pairs `addr` with `addr_hex` and `target` with `target_hex`
/// (see [`crate::addr_hex`]); old rows without the twins still
/// deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct IrInsn {
    /// Address of the source machine instruction.
    pub addr: u64,
    /// Lifted operation.
    pub op: IrOp,
    /// Input operands (disassembler strings).
    pub inputs: Vec<String>,
    /// Output operands (disassembler strings).
    pub outputs: Vec<String>,
    /// Absolute target for direct branches/calls, if any.
    pub target: Option<u64>,
    /// Set when the mnemonic had no mapping and `op` fell back to [`IrOp::Nop`].
    pub warning: Option<String>,
}

impl Serialize for IrInsn {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("IrInsn", 7)?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("op", &self.op)?;
        st.serialize_field("inputs", &self.inputs)?;
        st.serialize_field("outputs", &self.outputs)?;
        st.serialize_field("target", &self.target)?;
        st.serialize_field("target_hex", &self.target.map(crate::addr_hex))?;
        st.serialize_field("warning", &self.warning)?;
        st.end()
    }
}

/// Lift one instruction for its architecture.
#[must_use]
pub fn lift(arch: Arch, insn: &Insn) -> Vec<IrInsn> {
    match arch {
        Arch::X86_64 | Arch::X86_32 => lift_x86(insn),
        Arch::Aarch64 => lift_aarch64(insn),
        Arch::Arm32 | Arch::Thumb => lift_arm32(insn),
    }
}

/// Lift a decoded range, preserving order.
#[must_use]
pub fn lift_range(arch: Arch, insns: &[Insn]) -> Vec<IrInsn> {
    insns.iter().flat_map(|i| lift(arch, i)).collect()
}

/// Lift one x86 (32- or 64-bit) instruction.
#[must_use]
pub fn lift_x86(insn: &Insn) -> Vec<IrInsn> {
    let mnem = insn.mnem.as_str();
    // Read-modify-write with a single operand reads as well as writes.
    let alu_out_in = |insn: &Insn| -> (Vec<String>, Vec<String>) {
        match insn.ops.as_slice() {
            [] => (Vec::new(), Vec::new()),
            [dst] => (vec![dst.clone()], vec![dst.clone()]),
            [dst, rest @ ..] => (vec![dst.clone()], rest.to_vec()),
        }
    };
    let (op, inputs, outputs, target) = match mnem {
        s if is_x86_copy(s) => {
            let (outputs, inputs) = match insn.ops.as_slice() {
                [] => (Vec::new(), Vec::new()),
                // xchg swaps both operands.
                [a, b] if s == "xchg" => (vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]),
                [single] => (vec![single.clone()], Vec::new()),
                [dst, rest @ ..] => (vec![dst.clone()], rest.to_vec()),
            };
            (IrOp::Copy, inputs, outputs, None)
        }
        s if is_x86_load(s) => (IrOp::Load, Vec::new(), insn.ops.clone(), None),
        s if is_x86_store(s) => (IrOp::Store, insn.ops.clone(), Vec::new(), None),
        s if is_x86_alu(s, IrOp::Add) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Add, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Sub) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Sub, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Mul) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Mul, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Div) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Div, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::And) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::And, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Or) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Or, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Xor) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Xor, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Shl) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Shl, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Shr) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Shr, inputs, outputs, None)
        }
        "cmp" | "test" => (IrOp::Cmp, insn.ops.clone(), Vec::new(), None),
        "jmp" => direct_or_indirect(insn, IrOp::Branch),
        s if is_x86_jcc(s) => (
            IrOp::CBranch,
            insn.ops.clone(),
            Vec::new(),
            insn.branch_target,
        ),
        s if is_x86_call(s) => direct_or_indirect(insn, IrOp::Call),
        s if is_x86_return(s) => (IrOp::Return, Vec::new(), Vec::new(), None),
        s if is_x86_nop(s) => (IrOp::Nop, Vec::new(), Vec::new(), None),
        _ => return unlifted(insn),
    };
    vec![IrInsn {
        addr: insn.addr,
        op,
        inputs,
        outputs,
        target,
        warning: None,
    }]
}

/// Lift one AArch64 instruction.
#[must_use]
pub fn lift_aarch64(insn: &Insn) -> Vec<IrInsn> {
    let mnem = insn.mnem.as_str();
    let (op, inputs, outputs, target) = match mnem {
        s if is_arm_copy(s) => first_out_rest_in(insn, IrOp::Copy),
        s if is_arm_load(s) => first_out_rest_in(insn, IrOp::Load),
        s if is_arm_store(s) => (IrOp::Store, insn.ops.clone(), Vec::new(), None),
        s if is_arm_alu(s, IrOp::Add) => first_out_rest_in(insn, IrOp::Add),
        s if is_arm_alu(s, IrOp::Sub) => first_out_rest_in(insn, IrOp::Sub),
        s if is_arm_alu(s, IrOp::Mul) => first_out_rest_in(insn, IrOp::Mul),
        s if is_arm_alu(s, IrOp::Div) => first_out_rest_in(insn, IrOp::Div),
        s if is_arm_alu(s, IrOp::And) => first_out_rest_in(insn, IrOp::And),
        s if is_arm_alu(s, IrOp::Or) => first_out_rest_in(insn, IrOp::Or),
        s if is_arm_alu(s, IrOp::Xor) => first_out_rest_in(insn, IrOp::Xor),
        s if is_arm_alu(s, IrOp::Shl) => first_out_rest_in(insn, IrOp::Shl),
        s if is_arm_alu(s, IrOp::Shr) => first_out_rest_in(insn, IrOp::Shr),
        "cmp" | "cmn" | "tst" => (IrOp::Cmp, insn.ops.clone(), Vec::new(), None),
        "b" | "br" => direct_or_indirect(insn, IrOp::Branch),
        s if is_arm_cbranch(s) => (
            IrOp::CBranch,
            insn.ops.clone(),
            Vec::new(),
            insn.branch_target,
        ),
        "bl" | "blr" => direct_or_indirect(insn, IrOp::Call),
        s if is_arm_call(s) => (IrOp::Call, insn.ops.clone(), Vec::new(), None),
        s if is_arm_return(s) => (IrOp::Return, Vec::new(), Vec::new(), None),
        s if is_arm_nop(s) => (IrOp::Nop, Vec::new(), Vec::new(), None),
        _ => return unlifted(insn),
    };
    vec![IrInsn {
        addr: insn.addr,
        op,
        inputs,
        outputs,
        target,
        warning: None,
    }]
}

fn first_out_rest_in(insn: &Insn, op: IrOp) -> (IrOp, Vec<String>, Vec<String>, Option<u64>) {
    match insn.ops.as_slice() {
        [] => (op, Vec::new(), Vec::new(), None),
        [dst, rest @ ..] => (op, rest.to_vec(), vec![dst.clone()], None),
    }
}

/// Lift one ARM32/Thumb instruction.
///
/// ARMv7 Display bakes the condition code and flag suffix into the mnemonic
/// (`addeq`, `adds`, `bl.w`), so `split_arm_mnem` reduces it to the base
/// first; a stripped condition turns a plain `b` into a conditional branch
/// and keeps predicated returns on the fallthrough path.
#[must_use]
pub fn lift_arm32(insn: &Insn) -> Vec<IrInsn> {
    let (base, cond) = split_arm_mnem(&insn.mnem);
    let (op, inputs, outputs, target) = match base {
        s if is_arm32_copy(s) => first_out_rest_in(insn, IrOp::Copy),
        s if is_arm32_load(s) => {
            if (s == "pop" || s == "ldm") && ops_contain_pc(insn) {
                if cond {
                    (IrOp::CBranch, insn.ops.clone(), Vec::new(), None)
                } else {
                    (IrOp::Return, Vec::new(), Vec::new(), None)
                }
            } else {
                (IrOp::Load, Vec::new(), insn.ops.clone(), None)
            }
        }
        s if is_arm32_store(s) => (IrOp::Store, insn.ops.clone(), Vec::new(), None),
        s if is_arm32_alu(s, IrOp::Add) => first_out_rest_in(insn, IrOp::Add),
        s if is_arm32_alu(s, IrOp::Sub) => first_out_rest_in(insn, IrOp::Sub),
        s if is_arm32_alu(s, IrOp::Mul) => first_out_rest_in(insn, IrOp::Mul),
        s if is_arm32_alu(s, IrOp::Div) => first_out_rest_in(insn, IrOp::Div),
        s if is_arm32_alu(s, IrOp::And) => first_out_rest_in(insn, IrOp::And),
        s if is_arm32_alu(s, IrOp::Or) => first_out_rest_in(insn, IrOp::Or),
        s if is_arm32_alu(s, IrOp::Xor) => first_out_rest_in(insn, IrOp::Xor),
        s if is_arm32_alu(s, IrOp::Shl) => first_out_rest_in(insn, IrOp::Shl),
        s if is_arm32_alu(s, IrOp::Shr) => first_out_rest_in(insn, IrOp::Shr),
        "cmp" | "cmn" | "tst" | "teq" => (IrOp::Cmp, insn.ops.clone(), Vec::new(), None),
        "b" if cond => (
            IrOp::CBranch,
            insn.ops.clone(),
            Vec::new(),
            insn.branch_target,
        ),
        "b" => direct_or_indirect(insn, IrOp::Branch),
        "bl" | "blx" => direct_or_indirect(insn, IrOp::Call),
        "bx" if !cond && insn.ops.as_slice() == ["lr"] => {
            (IrOp::Return, Vec::new(), Vec::new(), None)
        }
        "bx" if cond => (IrOp::CBranch, insn.ops.clone(), Vec::new(), None),
        "bx" => direct_or_indirect(insn, IrOp::Branch),
        "cbz" | "cbnz" => (
            IrOp::CBranch,
            insn.ops.clone(),
            Vec::new(),
            insn.branch_target,
        ),
        "tbb" | "tbh" => (IrOp::Branch, insn.ops.clone(), Vec::new(), None),
        s if is_arm32_call(s) => (IrOp::Call, insn.ops.clone(), Vec::new(), None),
        s if is_arm32_nop(s) => (IrOp::Nop, Vec::new(), Vec::new(), None),
        _ => return unlifted(insn),
    };
    vec![IrInsn {
        addr: insn.addr,
        op,
        inputs,
        outputs,
        target,
        warning: None,
    }]
}

/// Reduce an ARMv7 mnemonic to its base plus whether it carries a condition
/// code. Strips one `.w`/`.n` width suffix, then one condition suffix
/// (`eq`..`le`, only when the remainder is a known base so `teq`/`bics`
/// survive), then one flag `s` (same guard, so `mrs`/`svc` survive).
fn split_arm_mnem(mnem: &str) -> (&str, bool) {
    let base = mnem
        .strip_suffix(".w")
        .or_else(|| mnem.strip_suffix(".n"))
        .unwrap_or(mnem);
    if base.len() > 2 {
        let (prefix, suffix) = base.split_at(base.len() - 2);
        if ARM_CONDS.contains(&suffix) && arm_base_mnem(prefix) {
            return (prefix, true);
        }
    }
    if let Some(prefix) = base.strip_suffix('s')
        && arm_base_mnem(prefix)
    {
        return (prefix, false);
    }
    (base, false)
}

/// Condition suffixes of [`split_arm_mnem`], matching the decoder's
/// `ConditionCode` names (`hs`/`lo`, never the `cs`/`cc` aliases).
const ARM_CONDS: [&str; 14] = [
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
];

/// Whether `s` is a base mnemonic of [`lift_arm32`].
fn arm_base_mnem(s: &str) -> bool {
    is_arm32_copy(s)
        || is_arm32_load(s)
        || is_arm32_store(s)
        || matches!(
            s,
            "add"
                | "adc"
                | "sub"
                | "sbc"
                | "rsb"
                | "rsc"
                | "mul"
                | "mla"
                | "sdiv"
                | "udiv"
                | "and"
                | "eor"
                | "orr"
                | "bic"
                | "lsl"
                | "lsr"
                | "asr"
                | "ror"
                | "cmp"
                | "cmn"
                | "tst"
                | "teq"
        )
        || matches!(
            s,
            "b" | "bl"
                | "blx"
                | "bx"
                | "cbz"
                | "cbnz"
                | "tbb"
                | "tbh"
                | "svc"
                | "hvc"
                | "smc"
                | "nop"
                | "dmb"
                | "dsb"
                | "isb"
        )
}

/// Whether any operand names `pc` (return-via-`pop`/`ldm` check).
fn ops_contain_pc(insn: &Insn) -> bool {
    insn.ops
        .iter()
        .any(|o| o.split(|c: char| !c.is_alphanumeric()).any(|w| w == "pc"))
}

/// Direct branch/call keeps only `target`; indirect keeps the operands.
fn direct_or_indirect(insn: &Insn, op: IrOp) -> (IrOp, Vec<String>, Vec<String>, Option<u64>) {
    match insn.branch_target {
        Some(t) => (op, Vec::new(), Vec::new(), Some(t)),
        None => (op, insn.ops.clone(), Vec::new(), None),
    }
}

fn unlifted(insn: &Insn) -> Vec<IrInsn> {
    vec![IrInsn {
        addr: insn.addr,
        op: IrOp::Nop,
        inputs: Vec::new(),
        outputs: Vec::new(),
        target: None,
        warning: Some(format!("unlifted '{}'; emitted NOP", insn.mnem)),
    }]
}

fn is_x86_copy(s: &str) -> bool {
    matches!(
        s,
        "mov" | "movsx" | "movsxd" | "movzx" | "movabs" | "xchg" | "leave" | "enter"
    )
}

fn is_x86_load(s: &str) -> bool {
    matches!(s, "pop" | "popa" | "popad" | "popcnt")
}

fn is_x86_store(s: &str) -> bool {
    matches!(s, "push" | "pusha" | "pushad")
}

fn is_x86_alu(s: &str, op: IrOp) -> bool {
    match op {
        IrOp::Add => matches!(s, "add" | "adc" | "adcx" | "adox" | "lea" | "inc"),
        IrOp::Sub => matches!(s, "sub" | "sbb" | "dec" | "neg"),
        IrOp::Mul => matches!(s, "mul" | "imul"),
        IrOp::Div => matches!(s, "div" | "idiv"),
        IrOp::And => matches!(s, "and"),
        IrOp::Or => matches!(s, "or"),
        IrOp::Xor => matches!(s, "xor" | "pxor" | "not"),
        // Rotates approximate to shifts; exact bit motion is out of scope for M3.
        IrOp::Shl => matches!(s, "shl" | "sal"),
        IrOp::Shr => matches!(s, "shr" | "sar" | "rol" | "ror" | "rcl" | "rcr"),
        _ => false,
    }
}

fn is_x86_jcc(s: &str) -> bool {
    matches!(
        s,
        "jo" | "jno"
            | "jb"
            | "jnae"
            | "jc"
            | "jnb"
            | "jae"
            | "jnc"
            | "je"
            | "jz"
            | "jne"
            | "jnz"
            | "jbe"
            | "jna"
            | "jnbe"
            | "ja"
            | "js"
            | "jns"
            | "jp"
            | "jpe"
            | "jnp"
            | "jpo"
            | "jl"
            | "jnge"
            | "jnl"
            | "jge"
            | "jle"
            | "jng"
            | "jnle"
            | "jg"
            | "jcxz"
            | "jecxz"
            | "jrcxz"
            | "loop"
            | "loope"
            | "loopne"
    )
}

fn is_x86_call(s: &str) -> bool {
    matches!(s, "call" | "syscall" | "sysenter" | "int" | "int3")
}

fn is_x86_return(s: &str) -> bool {
    matches!(s, "ret" | "retn" | "retf" | "iret" | "iretd" | "iretq")
}

fn is_x86_nop(s: &str) -> bool {
    matches!(s, "nop" | "pause" | "hlt" | "wait" | "endbr32" | "endbr64")
}

fn is_arm_copy(s: &str) -> bool {
    matches!(s, "mov" | "movz" | "movn" | "movk" | "adr" | "adrp")
}

fn is_arm_load(s: &str) -> bool {
    matches!(
        s,
        "ldr" | "ldp" | "ldur" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrsw"
    )
}

fn is_arm_store(s: &str) -> bool {
    matches!(s, "str" | "stp" | "stur" | "strb" | "strh")
}

fn is_arm_alu(s: &str, op: IrOp) -> bool {
    match op {
        IrOp::Add => matches!(s, "add" | "adds" | "adc" | "adcs"),
        IrOp::Sub => matches!(s, "sub" | "subs" | "sbc" | "sbcs" | "neg" | "negs"),
        IrOp::Mul => matches!(
            s,
            "mul" | "madd" | "msub" | "smull" | "smulh" | "umull" | "umulh"
        ),
        IrOp::Div => matches!(s, "sdiv" | "udiv"),
        IrOp::And => matches!(s, "and" | "ands" | "bic" | "bics"),
        IrOp::Or => matches!(s, "orr" | "orn"),
        IrOp::Xor => matches!(s, "eor" | "eon"),
        IrOp::Shl => matches!(s, "lsl" | "lslv"),
        IrOp::Shr => matches!(s, "lsr" | "lsrv" | "asr" | "asrv" | "ror" | "rorv"),
        _ => false,
    }
}

fn is_arm_cbranch(s: &str) -> bool {
    matches!(s, "cbz" | "cbnz" | "tbz" | "tbnz") || s.starts_with("b.") || s.starts_with("bc.")
}

fn is_arm_call(s: &str) -> bool {
    matches!(s, "svc" | "hvc" | "smc")
}

fn is_arm_return(s: &str) -> bool {
    matches!(s, "ret" | "eret")
}

fn is_arm_nop(s: &str) -> bool {
    matches!(s, "nop" | "hint" | "dmb" | "dsb" | "isb" | "brk")
}

fn is_arm32_copy(s: &str) -> bool {
    matches!(s, "mov" | "movw" | "movt" | "mvn" | "adr")
}

fn is_arm32_load(s: &str) -> bool {
    matches!(
        s,
        "ldr" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrd" | "ldm" | "pop"
    )
}

fn is_arm32_store(s: &str) -> bool {
    matches!(s, "str" | "strb" | "strh" | "strd" | "stm" | "push")
}

fn is_arm32_alu(s: &str, op: IrOp) -> bool {
    match op {
        IrOp::Add => matches!(s, "add" | "adc"),
        IrOp::Sub => matches!(s, "sub" | "sbc" | "rsb" | "rsc"),
        IrOp::Mul => matches!(s, "mul" | "mla"),
        IrOp::Div => matches!(s, "sdiv" | "udiv"),
        IrOp::And => matches!(s, "and" | "bic"),
        IrOp::Or => matches!(s, "orr" | "orn"),
        IrOp::Xor => matches!(s, "eor"),
        IrOp::Shl => matches!(s, "lsl"),
        IrOp::Shr => matches!(s, "lsr" | "asr" | "ror" | "rrx"),
        _ => false,
    }
}

fn is_arm32_call(s: &str) -> bool {
    matches!(s, "svc" | "hvc" | "smc")
}

fn is_arm32_nop(s: &str) -> bool {
    matches!(s, "nop" | "dmb" | "dsb" | "isb")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(mnem: &str, ops: &[&str]) -> Insn {
        Insn {
            addr: 0x1000,
            size: 1,
            bytes: vec![0x90],
            mnem: mnem.to_string(),
            ops: ops.iter().map(|s| (*s).to_string()).collect(),
            branch_target: None,
            mem_target: None,
        }
    }

    #[test]
    fn op_names_are_uppercase() {
        assert_eq!(IrOp::Copy.name(), "COPY");
        assert_eq!(IrOp::CBranch.name(), "CBRANCH");
        assert_eq!(IrOp::Nop.name(), "NOP");
        assert!(IrOp::Call.is_control());
        assert!(!IrOp::Add.is_control());
    }

    #[test]
    fn x86_mov_is_copy() {
        let v = lift_x86(&insn("mov", &["rax", "rbx"]));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].op, IrOp::Copy);
        assert_eq!(v[0].outputs, ["rax"]);
        assert_eq!(v[0].inputs, ["rbx"]);
        assert_eq!(v[0].warning, None);
    }

    #[test]
    fn x86_jcc_is_cbranch() {
        let mut i = insn("je", &["short 0x1002"]);
        i.branch_target = Some(0x1002);
        let v = lift_x86(&i);
        assert_eq!(v[0].op, IrOp::CBranch);
        assert_eq!(v[0].target, Some(0x1002));
    }

    #[test]
    fn x86_unknown_is_nop_with_warning() {
        let v = lift_x86(&insn("cpuid", &[]));
        assert_eq!(v[0].op, IrOp::Nop);
        assert!(v[0].warning.is_some());
    }

    #[test]
    fn arm_b_eq_is_cbranch() {
        let mut i = insn("b.eq", &["$+0x8"]);
        i.branch_target = Some(0x4008);
        let v = lift_aarch64(&i);
        assert_eq!(v[0].op, IrOp::CBranch);
        assert_eq!(v[0].target, Some(0x4008));
    }

    #[test]
    fn arm_unknown_is_nop_with_warning() {
        let v = lift_aarch64(&insn("mrs", &["x0", "tpidr_el0"]));
        assert_eq!(v[0].op, IrOp::Nop);
        assert!(v[0].warning.is_some());
    }

    #[test]
    fn lift_never_emits_phi() {
        for m in ["mov", "add", "jmp", "call", "ret", "nop", "cpuid"] {
            for ir in lift_x86(&insn(m, &[])) {
                assert_ne!(ir.op, IrOp::Phi, "mnem {m}");
            }
        }
        for m in ["ldr", "add", "b", "blr", "ret", "nop", "mrs"] {
            for ir in lift_aarch64(&insn(m, &[])) {
                assert_ne!(ir.op, IrOp::Phi, "mnem {m}");
            }
        }
        for m in [
            "mov", "movs", "addeq", "b", "beq", "bl", "bl.w", "blx", "bx", "cbz", "svc", "push",
            "pop", "nop",
        ] {
            for ir in lift_arm32(&insn(m, &[])) {
                assert_ne!(ir.op, IrOp::Phi, "mnem {m}");
            }
        }
    }

    #[test]
    fn arm32_mnem_suffixes_reduce_to_base() {
        assert_eq!(split_arm_mnem("bl.w"), ("bl", false));
        assert_eq!(split_arm_mnem("beq.w"), ("b", true));
        assert_eq!(split_arm_mnem("addeq"), ("add", true));
        assert_eq!(split_arm_mnem("adds"), ("add", false));
        assert_eq!(split_arm_mnem("movs"), ("mov", false));
        // Guarded strips: teq keeps its own base, mrs/svc keep the `s`.
        assert_eq!(split_arm_mnem("teq"), ("teq", false));
        assert_eq!(split_arm_mnem("mrs"), ("mrs", false));
        assert_eq!(split_arm_mnem("svc"), ("svc", false));
        assert_eq!(split_arm_mnem("bls"), ("b", true));
    }

    #[test]
    fn arm32_bx_lr_is_return_but_predicated_is_cbranch() {
        let mut i = insn("bx", &["lr"]);
        assert_eq!(lift_arm32(&i)[0].op, IrOp::Return);
        i = insn("bxeq", &["lr"]);
        let v = lift_arm32(&i);
        assert_eq!(v[0].op, IrOp::CBranch);
        assert_eq!(v[0].target, None);
        // Indirect bx without lr is a plain indirect branch.
        let i = insn("bx", &["r3"]);
        let v = lift_arm32(&i);
        assert_eq!(v[0].op, IrOp::Branch);
        assert_eq!(v[0].target, None);
    }

    #[test]
    fn arm32_pop_pc_is_return() {
        let i = insn("pop", &["{r4", "pc}"]);
        assert_eq!(lift_arm32(&i)[0].op, IrOp::Return);
        let i = insn("pop", &["{r4", "r5}"]);
        assert_eq!(lift_arm32(&i)[0].op, IrOp::Load);
        let i = insn("push", &["{r4", "lr}"]);
        assert_eq!(lift_arm32(&i)[0].op, IrOp::Store);
    }

    #[test]
    fn arm32_cond_branch_is_cbranch() {
        let mut i = insn("beq", &["$+0x8"]);
        i.branch_target = Some(0x1008);
        let v = lift_arm32(&i);
        assert_eq!(v[0].op, IrOp::CBranch);
        assert_eq!(v[0].target, Some(0x1008));
        let i = insn("cbz", &["r0", "$+0x4"]);
        let v = lift_arm32(&i);
        assert_eq!(v[0].op, IrOp::CBranch);
    }

    #[test]
    fn arm32_unknown_is_nop_with_warning() {
        let v = lift_arm32(&insn("mrs", &["r0", "cpsr"]));
        assert_eq!(v[0].op, IrOp::Nop);
        assert!(v[0].warning.is_some());
    }
}
