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

use crate::disasm::{Arch, Insn};

/// Minimal P-code-inspired operation set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IrOp {
    Copy,
    Load,
    Store,
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Cmp,
    Branch,
    CBranch,
    Call,
    Return,
    Phi,
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Lift one instruction for its architecture.
#[must_use]
pub fn lift(arch: Arch, insn: &Insn) -> Vec<IrInsn> {
    match arch {
        Arch::X86_64 | Arch::X86_32 => lift_x86(insn),
        Arch::Aarch64 => lift_aarch64(insn),
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
        let mut i = insn("je", &["short 0000000000001002h"]);
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
    }
}
