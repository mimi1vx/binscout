//! Approximate pseudo-C rendering over the thin M3 IR.
//!
//! Each [`IrInsn`] becomes one [`PseudoLine`]: a lossy
//! C-like statement built from the lift's verbatim operand strings. Data
//! operations render as assignments or `OP(args)` calls, control operations
//! as `goto`/`if`/`call`/`return`, and unmapped lifts keep their
//! [`IrInsn::warning`](crate::ir::IrInsn::warning) verbatim in both the
//! line text (as a comment) and the propagated `warning` field.
//!
//! The output is explicitly approximate: operand strings are never parsed,
//! flag and stack-pointer effects are unmodeled (see
//! [`IrEffects`](crate::ir::IrEffects)), and a back edge is not a proven
//! loop. Agents must treat the rows as hints, never as decompiler output.

use serde::{Deserialize, Serialize};

use crate::analysis::Function;
use crate::disasm::Arch;
use crate::ir::{IrInsn, IrOp};

/// Approximate per-function pseudo-C warning.
///
/// The rendering is lossy by design: operand strings pass through verbatim,
/// flags/stack effects are unmodeled, and control sugar (`goto`/`if`) mirrors
/// the lift's direct targets without proving control flow. Never a
/// decompiler.
pub const PSEUDO_WARNING: &str = "approximate pseudo-C over thin IR: lossy rendering of operand strings with unmodeled flags/stack; not a decompiler";

/// One approximate pseudo-C line for a single IR row.
///
/// JSON pairs `addr` with `addr_hex`; `warning` propagates the source
/// [`IrInsn`] warning verbatim (`None` for mapped rows).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PseudoLine {
    /// Address of the source machine instruction.
    pub addr: u64,
    /// Lossy C-like statement (unlifted rows become a `/* ... */` comment).
    pub text: String,
    /// Propagated lift warning, if the source row was unmapped.
    pub warning: Option<String>,
}

impl Serialize for PseudoLine {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("PseudoLine", 4)?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("text", &self.text)?;
        st.serialize_field("warning", &self.warning)?;
        st.end()
    }
}

/// Approximate pseudo-C for a run of IR rows.
///
/// `lines` are in address order; `text` joins them as
/// `{addr:#x}: {text}` rows for copy-paste reading; `warning` is always
/// [`PSEUDO_WARNING`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PseudoRender {
    /// One line per IR row, in address order.
    pub lines: Vec<PseudoLine>,
    /// `{addr:#x}: {text}` rows joined by newlines.
    pub text: String,
    /// Always [`PSEUDO_WARNING`].
    pub warning: String,
}

/// Render one IR row as a lossy C-like statement.
///
/// Data operations keep operand strings verbatim inside assignments or
/// `OP(args)` calls; control operations use the direct `target` when
/// present and fall back to the operand strings for indirect sites.
/// Unmapped rows (`warning.is_some()`) render as a comment carrying the
/// warning text.
#[must_use]
pub fn render_one(row: &IrInsn) -> PseudoLine {
    let warning = row.warning.clone();
    let text = match row.op {
        IrOp::Copy => render_copy(row),
        IrOp::Load => render_load(row),
        IrOp::Store => render_store(row),
        IrOp::Add
        | IrOp::Sub
        | IrOp::Mul
        | IrOp::Div
        | IrOp::And
        | IrOp::Or
        | IrOp::Xor
        | IrOp::Shl
        | IrOp::Shr
        | IrOp::Cmp => render_alu(row),
        IrOp::Branch => match row.target {
            Some(t) => format!("goto {t:#x};"),
            None if row.inputs.is_empty() => "goto ...;".to_string(),
            None => format!("goto *({});", row.inputs.join(", ")),
        },
        IrOp::CBranch => match row.target {
            Some(t) if row.inputs.is_empty() => format!("if (...) goto {t:#x};"),
            Some(t) => format!("if ({}) goto {t:#x};", row.inputs.join(", ")),
            None if row.inputs.is_empty() => "if (...) goto ...;".to_string(),
            None => format!("if ({}) goto ...;", row.inputs.join(", ")),
        },
        IrOp::Call => match row.target {
            Some(t) => format!("call {t:#x}();"),
            None if row.inputs.is_empty() => "call ...();".to_string(),
            None => format!("call *({})();", row.inputs.join(", ")),
        },
        IrOp::Return => "return;".to_string(),
        IrOp::Phi if row.outputs.is_empty() => format!("PHI({});", row.inputs.join(", ")),
        IrOp::Phi => format!(
            "{} = PHI({});",
            row.outputs.join(", "),
            row.inputs.join(", ")
        ),
        IrOp::Nop => match &row.warning {
            Some(w) => format!("/* {w} */"),
            None => "/* nop */;".to_string(),
        },
    };
    PseudoLine {
        addr: row.addr,
        text,
        warning,
    }
}

/// Render a run of IR rows in order.
#[must_use]
pub fn render_rows(rows: &[IrInsn]) -> PseudoRender {
    let lines: Vec<PseudoLine> = rows.iter().map(render_one).collect();
    let text = lines
        .iter()
        .map(|l| format!("{:#x}: {}", l.addr, l.text))
        .collect::<Vec<_>>()
        .join("\n");
    PseudoRender {
        lines,
        text,
        warning: PSEUDO_WARNING.to_string(),
    }
}

/// Render one function's pseudo-C: blocks in ascending start order, each
/// instruction lifted for `arch` (see [`crate::ir::lift`]) and rendered.
///
/// Pure read-only pass; inferred single-slot edges never participate.
#[must_use]
pub fn render_function(arch: Arch, func: &Function) -> PseudoRender {
    let mut rows = Vec::new();
    for block in func.blocks.values() {
        for insn in &block.insns {
            rows.extend(crate::ir::lift(arch, insn));
        }
    }
    render_rows(&rows)
}

fn render_copy(row: &IrInsn) -> String {
    match (row.outputs.as_slice(), row.inputs.as_slice()) {
        ([out], [src]) if out == src && row.inputs.len() == 1 => {
            format!("{out} = COPY({src});")
        }
        ([], []) => "COPY();".to_string(),
        ([], ins) => format!("COPY({});", ins.join(", ")),
        (outs, []) => format!("{} = ...;", outs.join(", ")),
        (outs, ins) => format!("{} = {};", outs.join(", "), ins.join(", ")),
    }
}

fn render_load(row: &IrInsn) -> String {
    match (row.outputs.as_slice(), row.inputs.as_slice()) {
        ([], []) => "LOAD();".to_string(),
        ([], ins) => format!("LOAD({});", ins.join(", ")),
        (outs, []) => format!("{} = LOAD();", outs.join(", ")),
        (outs, ins) => format!("{} = LOAD({});", outs.join(", "), ins.join(", ")),
    }
}

fn render_store(row: &IrInsn) -> String {
    match (row.outputs.as_slice(), row.inputs.as_slice()) {
        ([], []) => "STORE();".to_string(),
        ([], ins) => format!("STORE({});", ins.join(", ")),
        (outs, ins) => format!("STORE({}, {});", outs.join(", "), ins.join(", ")),
    }
}

fn render_alu(row: &IrInsn) -> String {
    let op = row.op.name();
    match (row.outputs.as_slice(), row.inputs.as_slice()) {
        ([], []) => format!("{op}();"),
        ([], ins) => format!("{op}({});", ins.join(", ")),
        (outs, []) => format!("{} = {op}();", outs.join(", ")),
        (outs, ins) => format!("{} = {op}({});", outs.join(", "), ins.join(", ")),
    }
}
