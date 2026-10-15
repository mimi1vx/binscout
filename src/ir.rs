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
//! - `LOAD`: `pop`, `popa`, `popad`. `STORE`: `push`, `pusha`,
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

/// Whether `mnem` has a lift mapping for `arch`.
///
/// Anything else lifts to fallback [`IrOp::Nop`] with a warning instead of
/// failing, so `!is_mapped(..)` exactly predicts `warning.is_some()` on the
/// lifted row. ARM32/Thumb reduce the mnemonic through suffix stripping
/// first, so conditioned/suffixed forms (`addeq`, `bl.w`) count as mapped.
#[must_use]
pub fn is_mapped(arch: Arch, mnem: &str) -> bool {
    match arch {
        Arch::X86_64 | Arch::X86_32 => {
            is_x86_copy(mnem)
                || is_x86_load(mnem)
                || is_x86_store(mnem)
                || is_x86_alu(mnem, IrOp::Add)
                || is_x86_alu(mnem, IrOp::Sub)
                || is_x86_alu(mnem, IrOp::Mul)
                || is_x86_alu(mnem, IrOp::Div)
                || is_x86_alu(mnem, IrOp::And)
                || is_x86_alu(mnem, IrOp::Or)
                || is_x86_alu(mnem, IrOp::Xor)
                || is_x86_alu(mnem, IrOp::Shl)
                || is_x86_alu(mnem, IrOp::Shr)
                || X86_CMP.contains(&mnem)
                || mnem == "jmp"
                || is_x86_jcc(mnem)
                || is_x86_call(mnem)
                || is_x86_return(mnem)
                || is_x86_nop(mnem)
        }
        Arch::Aarch64 => {
            is_arm_copy(mnem)
                || is_arm_load(mnem)
                || is_arm_store(mnem)
                || is_arm_alu(mnem, IrOp::Add)
                || is_arm_alu(mnem, IrOp::Sub)
                || is_arm_alu(mnem, IrOp::Mul)
                || is_arm_alu(mnem, IrOp::Div)
                || is_arm_alu(mnem, IrOp::And)
                || is_arm_alu(mnem, IrOp::Or)
                || is_arm_alu(mnem, IrOp::Xor)
                || is_arm_alu(mnem, IrOp::Shl)
                || is_arm_alu(mnem, IrOp::Shr)
                || ARM_CMP.contains(&mnem)
                || matches!(mnem, "b" | "br" | "bl" | "blr")
                || is_arm_cbranch(mnem)
                || is_arm_call(mnem)
                || is_arm_return(mnem)
                || is_arm_nop(mnem)
        }
        Arch::Arm32 | Arch::Thumb => arm_base_mnem(split_arm_mnem(mnem).0),
    }
}

/// How completely one [`IrOp`] family is lifted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageStatus {
    /// Every listed member lifts; notes may still bound the semantics.
    Implemented,
    /// Listed members lift, but known effects are approximated or dropped.
    Partial,
    /// Never produced by the lifters (only [`IrOp::Phi`]).
    Unmapped,
}

/// One lifted family's machine-readable coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyCoverage {
    /// Lifted operation.
    pub op: IrOp,
    /// Whether the family is fully, partially, or never lifted.
    pub status: CoverageStatus,
    /// Liftable mnemonics (ARM32/Thumb: base forms before suffix stripping).
    pub mnemonics: Vec<String>,
    /// Non-literal members (e.g. AArch64 `b.<cond>`).
    pub patterns: Vec<String>,
    /// Bounds that keep `implemented` from meaning semantically complete.
    pub note: Option<String>,
}

/// The unknown-mnemonic rule: unmapped input stays [`IrOp::Nop`] with a
/// warning, distinguishable from a genuine `NOP`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackCoverage {
    /// Always [`IrOp::Nop`].
    pub op: IrOp,
    /// Always [`CoverageStatus::Unmapped`].
    pub status: CoverageStatus,
    /// Warning template (`<mnem>` is the unmapped mnemonic).
    pub warning: String,
    /// How to tell fallback NOP from a genuine one.
    pub distinguish: String,
}

/// Machine-readable lift coverage for one architecture: the [`coverage`]
/// query's row shape.
///
/// This is the machine-readable form of the ISA tables in the module docs,
/// built from the same slices the dispatch predicates consult, so it cannot
/// drift from the lifters. `implemented` never means semantically complete:
/// see `limitations` plus each family's `status`/`note`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// Architecture name (`x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`).
    pub arch: String,
    /// Per-operation families in [`IrOp`] declaration order.
    pub families: Vec<FamilyCoverage>,
    /// Engine-wide bounds (operand strings, flags, stack effects, no SSA).
    pub limitations: Vec<String>,
    /// The unknown-mnemonic rule.
    pub fallback: FallbackCoverage,
    /// Arch-wide mnemonic reading rule, if any (ARM32/Thumb suffixes).
    pub arch_note: Option<String>,
}

/// Engine-wide lift limitations shared by every architecture.
pub const COVERAGE_LIMITATIONS: &[&str] = &[
    "operands reuse the disassembler's strings verbatim; no operand decoding beyond that",
    "flag effects are unmodeled: CMP records the comparison only",
    "stack-pointer and calling-convention effects are unmodeled: push/pop lift as STORE/LOAD, CALL carries no frame effects",
    "no SSA/PHI production: Phi is never emitted by lifters; it is synthesized at CFG merges",
    "implemented families are not semantically complete: listed mnemonics lift without warning, but the bounds above still apply",
];

fn fam(
    op: IrOp,
    status: CoverageStatus,
    mnemonics: &[&str],
    patterns: &[&str],
    note: Option<&str>,
) -> FamilyCoverage {
    FamilyCoverage {
        op,
        status,
        mnemonics: mnemonics.iter().map(|s| (*s).to_string()).collect(),
        patterns: patterns.iter().map(|s| (*s).to_string()).collect(),
        note: note.map(str::to_string),
    }
}

/// Genuine-vs-fallback NOP note shared by every architecture.
const NOP_NOTE: &str = "genuine effect-free mnemonics lift with no warning; unmapped mnemonics also lift to NOP but carry a warning";

fn phi_family() -> FamilyCoverage {
    fam(
        IrOp::Phi,
        CoverageStatus::Unmapped,
        &[],
        &[],
        Some("never emitted by lifters; synthesized at CFG merges"),
    )
}

fn x86_families() -> Vec<FamilyCoverage> {
    use CoverageStatus::{Implemented, Partial};
    vec![
        fam(
            IrOp::Copy,
            Implemented,
            X86_COPY,
            &[],
            Some("xchg swaps both operands; leave/enter copy the frame pointer"),
        ),
        fam(
            IrOp::Load,
            Implemented,
            X86_LOAD,
            &[],
            Some("pop lifts as LOAD; stack-pointer effects unmodeled"),
        ),
        fam(
            IrOp::Store,
            Implemented,
            X86_STORE,
            &[],
            Some("push lifts as STORE; stack-pointer effects unmodeled"),
        ),
        fam(
            IrOp::Add,
            Implemented,
            X86_ADD,
            &[],
            Some("lea lifts as address math, not a load"),
        ),
        fam(IrOp::Sub, Implemented, X86_SUB, &[], None),
        fam(IrOp::Mul, Implemented, X86_MUL, &[], None),
        fam(IrOp::Div, Implemented, X86_DIV, &[], None),
        fam(IrOp::And, Implemented, X86_AND, &[], None),
        fam(IrOp::Or, Implemented, X86_OR, &[], None),
        fam(
            IrOp::Xor,
            Implemented,
            X86_XOR,
            &[],
            Some("not lifts as XOR"),
        ),
        fam(IrOp::Shl, Implemented, X86_SHL, &[], None),
        fam(
            IrOp::Shr,
            Partial,
            X86_SHR,
            &[],
            Some("rol/ror/rcl/rcr approximated as shifts; exact bit motion out of scope"),
        ),
        fam(
            IrOp::Cmp,
            Partial,
            X86_CMP,
            &[],
            Some("flag effects unmodeled"),
        ),
        fam(
            IrOp::Branch,
            Implemented,
            &["jmp"],
            &[],
            Some("indirect forms keep operands without target"),
        ),
        fam(IrOp::CBranch, Implemented, X86_JCC, &[], None),
        fam(
            IrOp::Call,
            Implemented,
            X86_CALL,
            &[],
            Some("indirect calls keep operands without target"),
        ),
        fam(IrOp::Return, Implemented, X86_RETURN, &[], None),
        phi_family(),
        fam(IrOp::Nop, Implemented, X86_NOP, &[], Some(NOP_NOTE)),
    ]
}

fn aarch64_families() -> Vec<FamilyCoverage> {
    use CoverageStatus::{Implemented, Partial};
    vec![
        fam(IrOp::Copy, Implemented, ARM_COPY, &[], None),
        fam(IrOp::Load, Implemented, ARM_LOAD, &[], None),
        fam(IrOp::Store, Implemented, ARM_STORE, &[], None),
        fam(IrOp::Add, Implemented, ARM_ADD, &[], None),
        fam(IrOp::Sub, Implemented, ARM_SUB, &[], None),
        fam(IrOp::Mul, Implemented, ARM_MUL, &[], None),
        fam(IrOp::Div, Implemented, ARM_DIV, &[], None),
        fam(IrOp::And, Implemented, ARM_AND, &[], None),
        fam(IrOp::Or, Implemented, ARM_OR, &[], None),
        fam(IrOp::Xor, Implemented, ARM_XOR, &[], None),
        fam(IrOp::Shl, Implemented, ARM_SHL, &[], None),
        fam(
            IrOp::Shr,
            Partial,
            ARM_SHR,
            &[],
            Some("ror/rorv are rotates, approximated as shifts"),
        ),
        fam(
            IrOp::Cmp,
            Partial,
            ARM_CMP,
            &[],
            Some("flag effects unmodeled"),
        ),
        fam(
            IrOp::Branch,
            Implemented,
            &["b", "br"],
            &[],
            Some("indirect forms keep operands without target"),
        ),
        fam(
            IrOp::CBranch,
            Implemented,
            ARM_CBRANCH,
            ARM_CBRANCH_PATTERNS,
            None,
        ),
        fam(
            IrOp::Call,
            Implemented,
            &["bl", "blr", "svc", "hvc", "smc"],
            &[],
            Some("indirect bl/blr keep operands without target"),
        ),
        fam(IrOp::Return, Implemented, ARM_RETURN, &[], None),
        phi_family(),
        fam(IrOp::Nop, Implemented, ARM_NOP, &[], Some(NOP_NOTE)),
    ]
}

fn arm32_families() -> Vec<FamilyCoverage> {
    use CoverageStatus::{Implemented, Partial};
    vec![
        fam(IrOp::Copy, Implemented, ARM32_COPY, &[], None),
        fam(
            IrOp::Load,
            Implemented,
            ARM32_LOAD,
            &[],
            Some("pop/ldm naming pc lift as RETURN (CBRANCH when predicated), not LOAD"),
        ),
        fam(IrOp::Store, Implemented, ARM32_STORE, &[], None),
        fam(IrOp::Add, Implemented, ARM32_ADD, &[], None),
        fam(IrOp::Sub, Implemented, ARM32_SUB, &[], None),
        fam(IrOp::Mul, Implemented, ARM32_MUL, &[], None),
        fam(IrOp::Div, Implemented, ARM32_DIV, &[], None),
        fam(IrOp::And, Implemented, ARM32_AND, &[], None),
        fam(IrOp::Or, Implemented, ARM32_OR, &[], None),
        fam(IrOp::Xor, Implemented, ARM32_XOR, &[], None),
        fam(IrOp::Shl, Implemented, ARM32_SHL, &[], None),
        fam(
            IrOp::Shr,
            Partial,
            ARM32_SHR,
            &[],
            Some("ror/rrx are rotates, approximated as shifts"),
        ),
        fam(
            IrOp::Cmp,
            Partial,
            ARM32_CMP,
            &[],
            Some("flag effects unmodeled"),
        ),
        fam(
            IrOp::Branch,
            Implemented,
            &["b", "bx", "tbb", "tbh"],
            &[],
            Some("condition-suffixed b/bx lift as CBRANCH; bx lr lifts as RETURN"),
        ),
        fam(
            IrOp::CBranch,
            Implemented,
            &["cbz", "cbnz"],
            &[],
            Some("plus condition-suffixed b/bx and predicated pop/ldm naming pc"),
        ),
        fam(
            IrOp::Call,
            Implemented,
            &["bl", "blx", "svc", "hvc", "smc"],
            &[],
            Some("indirect bl/blx keep operands without target"),
        ),
        fam(
            IrOp::Return,
            Implemented,
            &[],
            &[],
            Some(
                "operand-dependent: bx lr and pop/ldm naming pc (predicated forms lift as CBRANCH)",
            ),
        ),
        phi_family(),
        fam(IrOp::Nop, Implemented, ARM32_NOP, &[], Some(NOP_NOTE)),
    ]
}

/// Machine-readable lift coverage for `arch`, without opening a binary.
///
/// Families publish the same mnemonic slices the dispatch predicates
/// consult, so advertised coverage cannot drift from actual lifts; unknown
/// mnemonics stay fallback [`IrOp::Nop`] with a warning per
/// [`unlifted`](self#warning-semantics) semantics.
#[must_use]
pub fn coverage(arch: Arch) -> Coverage {
    let (families, arch_note) = match arch {
        Arch::X86_64 | Arch::X86_32 => (x86_families(), None),
        Arch::Aarch64 => (aarch64_families(), None),
        Arch::Arm32 | Arch::Thumb => (
            arm32_families(),
            Some(
                "mnemonics are base forms: one .w/.n width suffix, one condition suffix, and one flag s are stripped before lookup; a stripped condition turns plain b into CBRANCH",
            ),
        ),
    };
    Coverage {
        arch: crate::db::arch_name(arch).to_string(),
        families,
        limitations: COVERAGE_LIMITATIONS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        fallback: FallbackCoverage {
            op: IrOp::Nop,
            status: CoverageStatus::Unmapped,
            warning: "unlifted '<mnem>'; emitted NOP".to_string(),
            distinguish:
                "warning.is_some() marks fallback NOP; genuine NOP mnemonics lift with warning None"
                    .to_string(),
        },
        arch_note: arch_note.map(str::to_string),
    }
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
        s if X86_CMP.contains(&s) => (IrOp::Cmp, insn.ops.clone(), Vec::new(), None),
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
        s if ARM_CMP.contains(&s) => (IrOp::Cmp, insn.ops.clone(), Vec::new(), None),
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
        s if ARM32_CMP.contains(&s) => (IrOp::Cmp, insn.ops.clone(), Vec::new(), None),
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

/// Whether `s` is a base mnemonic of [`lift_arm32`]: the load/store/copy
/// tables, any ALU table, the compare table, or the control/nop words
/// matched inline by the lifter.
fn arm_base_mnem(s: &str) -> bool {
    is_arm32_copy(s)
        || is_arm32_load(s)
        || is_arm32_store(s)
        || is_arm32_alu(s, IrOp::Add)
        || is_arm32_alu(s, IrOp::Sub)
        || is_arm32_alu(s, IrOp::Mul)
        || is_arm32_alu(s, IrOp::Div)
        || is_arm32_alu(s, IrOp::And)
        || is_arm32_alu(s, IrOp::Or)
        || is_arm32_alu(s, IrOp::Xor)
        || is_arm32_alu(s, IrOp::Shl)
        || is_arm32_alu(s, IrOp::Shr)
        || ARM32_CMP.contains(&s)
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
    X86_COPY.contains(&s)
}

fn is_x86_load(s: &str) -> bool {
    X86_LOAD.contains(&s)
}

fn is_x86_store(s: &str) -> bool {
    X86_STORE.contains(&s)
}

fn is_x86_alu(s: &str, op: IrOp) -> bool {
    match op {
        IrOp::Add => X86_ADD.contains(&s),
        IrOp::Sub => X86_SUB.contains(&s),
        IrOp::Mul => X86_MUL.contains(&s),
        IrOp::Div => X86_DIV.contains(&s),
        IrOp::And => X86_AND.contains(&s),
        IrOp::Or => X86_OR.contains(&s),
        IrOp::Xor => X86_XOR.contains(&s),
        // Rotates approximate to shifts; exact bit motion is out of scope for M3.
        IrOp::Shl => X86_SHL.contains(&s),
        IrOp::Shr => X86_SHR.contains(&s),
        _ => false,
    }
}

/// Shared dispatch/coverage tables: the `is_x86_*` predicates consult these,
/// and [`coverage`] publishes the same slices, so the machine-readable
/// report cannot drift from the lifters.
const X86_COPY: &[&str] = &[
    "mov", "movsx", "movsxd", "movzx", "movabs", "xchg", "leave", "enter",
];
const X86_LOAD: &[&str] = &["pop", "popa", "popad"];
const X86_STORE: &[&str] = &["push", "pusha", "pushad"];
const X86_ADD: &[&str] = &["add", "adc", "adcx", "adox", "lea", "inc"];
const X86_SUB: &[&str] = &["sub", "sbb", "dec", "neg"];
const X86_MUL: &[&str] = &["mul", "imul"];
const X86_DIV: &[&str] = &["div", "idiv"];
const X86_AND: &[&str] = &["and"];
const X86_OR: &[&str] = &["or"];
const X86_XOR: &[&str] = &["xor", "pxor", "not"];
const X86_SHL: &[&str] = &["shl", "sal"];
const X86_SHR: &[&str] = &["shr", "sar", "rol", "ror", "rcl", "rcr"];
const X86_CMP: &[&str] = &["cmp", "test"];
const X86_JCC: &[&str] = &[
    "jo", "jno", "jb", "jnae", "jc", "jnb", "jae", "jnc", "je", "jz", "jne", "jnz", "jbe", "jna",
    "jnbe", "ja", "js", "jns", "jp", "jpe", "jnp", "jpo", "jl", "jnge", "jnl", "jge", "jle", "jng",
    "jnle", "jg", "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne",
];
const X86_CALL: &[&str] = &["call", "syscall", "sysenter", "int", "int3"];
const X86_RETURN: &[&str] = &["ret", "retn", "retf", "iret", "iretd", "iretq"];
const X86_NOP: &[&str] = &["nop", "pause", "hlt", "wait", "endbr32", "endbr64"];

const ARM_COPY: &[&str] = &["mov", "movz", "movn", "movk", "adr", "adrp"];
const ARM_LOAD: &[&str] = &[
    "ldr", "ldp", "ldur", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw",
];
const ARM_STORE: &[&str] = &["str", "stp", "stur", "strb", "strh"];
const ARM_ADD: &[&str] = &["add", "adds", "adc", "adcs"];
const ARM_SUB: &[&str] = &["sub", "subs", "sbc", "sbcs", "neg", "negs"];
const ARM_MUL: &[&str] = &["mul", "madd", "msub", "smull", "smulh", "umull", "umulh"];
const ARM_DIV: &[&str] = &["sdiv", "udiv"];
const ARM_AND: &[&str] = &["and", "ands", "bic", "bics"];
const ARM_OR: &[&str] = &["orr", "orn"];
const ARM_XOR: &[&str] = &["eor", "eon"];
const ARM_SHL: &[&str] = &["lsl", "lslv"];
const ARM_SHR: &[&str] = &["lsr", "lsrv", "asr", "asrv", "ror", "rorv"];
const ARM_CMP: &[&str] = &["cmp", "cmn", "tst"];
const ARM_CBRANCH: &[&str] = &["cbz", "cbnz", "tbz", "tbnz"];
/// Non-literal AArch64 members: `b.<cond>` / `bc.<cond>` match the
/// [`is_arm_cbranch`] prefix rule, so they publish as patterns, not mnemonics.
const ARM_CBRANCH_PATTERNS: &[&str] = &["b.<cond>", "bc.<cond>"];
const ARM_CALL: &[&str] = &["svc", "hvc", "smc"];
const ARM_RETURN: &[&str] = &["ret", "eret"];
const ARM_NOP: &[&str] = &["nop", "hint", "dmb", "dsb", "isb", "brk"];

const ARM32_COPY: &[&str] = &["mov", "movw", "movt", "mvn", "adr"];
const ARM32_LOAD: &[&str] = &[
    "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrd", "ldm", "pop",
];
const ARM32_STORE: &[&str] = &["str", "strb", "strh", "strd", "stm", "push"];
const ARM32_ADD: &[&str] = &["add", "adc"];
const ARM32_SUB: &[&str] = &["sub", "sbc", "rsb", "rsc"];
const ARM32_MUL: &[&str] = &["mul", "mla"];
const ARM32_DIV: &[&str] = &["sdiv", "udiv"];
const ARM32_AND: &[&str] = &["and", "bic"];
const ARM32_OR: &[&str] = &["orr", "orn"];
const ARM32_XOR: &[&str] = &["eor"];
const ARM32_SHL: &[&str] = &["lsl"];
const ARM32_SHR: &[&str] = &["lsr", "asr", "ror", "rrx"];
const ARM32_CMP: &[&str] = &["cmp", "cmn", "tst", "teq"];
const ARM32_CALL: &[&str] = &["svc", "hvc", "smc"];
const ARM32_NOP: &[&str] = &["nop", "dmb", "dsb", "isb"];

fn is_x86_jcc(s: &str) -> bool {
    X86_JCC.contains(&s)
}

fn is_x86_call(s: &str) -> bool {
    X86_CALL.contains(&s)
}

fn is_x86_return(s: &str) -> bool {
    X86_RETURN.contains(&s)
}

fn is_x86_nop(s: &str) -> bool {
    X86_NOP.contains(&s)
}

fn is_arm_copy(s: &str) -> bool {
    ARM_COPY.contains(&s)
}

fn is_arm_load(s: &str) -> bool {
    ARM_LOAD.contains(&s)
}

fn is_arm_store(s: &str) -> bool {
    ARM_STORE.contains(&s)
}

fn is_arm_alu(s: &str, op: IrOp) -> bool {
    match op {
        IrOp::Add => ARM_ADD.contains(&s),
        IrOp::Sub => ARM_SUB.contains(&s),
        IrOp::Mul => ARM_MUL.contains(&s),
        IrOp::Div => ARM_DIV.contains(&s),
        IrOp::And => ARM_AND.contains(&s),
        IrOp::Or => ARM_OR.contains(&s),
        IrOp::Xor => ARM_XOR.contains(&s),
        IrOp::Shl => ARM_SHL.contains(&s),
        IrOp::Shr => ARM_SHR.contains(&s),
        _ => false,
    }
}

fn is_arm_cbranch(s: &str) -> bool {
    ARM_CBRANCH.contains(&s) || s.starts_with("b.") || s.starts_with("bc.")
}

fn is_arm_call(s: &str) -> bool {
    ARM_CALL.contains(&s)
}

fn is_arm_return(s: &str) -> bool {
    ARM_RETURN.contains(&s)
}

fn is_arm_nop(s: &str) -> bool {
    ARM_NOP.contains(&s)
}

fn is_arm32_copy(s: &str) -> bool {
    ARM32_COPY.contains(&s)
}

fn is_arm32_load(s: &str) -> bool {
    ARM32_LOAD.contains(&s)
}

fn is_arm32_store(s: &str) -> bool {
    ARM32_STORE.contains(&s)
}

fn is_arm32_alu(s: &str, op: IrOp) -> bool {
    match op {
        IrOp::Add => ARM32_ADD.contains(&s),
        IrOp::Sub => ARM32_SUB.contains(&s),
        IrOp::Mul => ARM32_MUL.contains(&s),
        IrOp::Div => ARM32_DIV.contains(&s),
        IrOp::And => ARM32_AND.contains(&s),
        IrOp::Or => ARM32_OR.contains(&s),
        IrOp::Xor => ARM32_XOR.contains(&s),
        IrOp::Shl => ARM32_SHL.contains(&s),
        IrOp::Shr => ARM32_SHR.contains(&s),
        _ => false,
    }
}

fn is_arm32_call(s: &str) -> bool {
    ARM32_CALL.contains(&s)
}

fn is_arm32_nop(s: &str) -> bool {
    ARM32_NOP.contains(&s)
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
