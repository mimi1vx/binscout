//! Stack-constructed string recovery (rsdbg-em6.18, M item).
//!
//! Some binaries build strings at runtime with immediate moves into
//! stack slots (`mov byte/dword ptr [rsp/rbp+off], imm`) instead of
//! storing them in the image. This pass reassembles those writes per
//! basic block from the IR: a `mov` with a memory destination lifts to
//! [`IrOp::Copy`] with the destination in `outputs` and the immediate in
//! `inputs` (so `Copy`, not `Store`, is the carrier — `Store` lifts
//! dataless pushes and unaddressed writes, which carry no slot offset).
//! Writes sharing one base register with contiguous offsets form a run;
//! runs of printable bytes at least
//! [`DEFAULT_MIN_LEN`](crate::loader::strings::DEFAULT_MIN_LEN)
//! characters long report with their function entry and the lowest
//! contributing instruction address.
//!
//! Conservative on purpose: only x86 `rsp`/`esp`/`rbp`/`ebp` slots with
//! an explicit width (`byte`/`word`/`dword`/`qword ptr`) and an
//! immediately-parseable offset participate; register sources need
//! dataflow and are skipped, runs never cross block boundaries, and
//! stack-pointer adjustments (`sub rsp, …`) are not tracked, so slots
//! addressed before and after an adjustment read as different offsets.
//! ARM `str [sp, #off]` forms are out of scope for this pass. A separate
//! query surface from [`extract`](crate::loader::strings::extract), so
//! recovered rows never disturb stored-string goldens.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::analysis::Analysis;
use crate::disasm::Arch;
use crate::ir::{IrOp, lift};

/// One reassembled stack string.
///
/// JSON carries the stable `stackstr@0x...` id plus `func`/`func_hex`
/// and `addr`/`addr_hex` twins; the twins and the id are recomputed on
/// serialize and ignored on deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StackString {
    /// Entry of the function containing the writes.
    pub func: u64,
    /// Lowest contributing instruction address.
    pub addr: u64,
    /// Reassembled printable text.
    pub value: String,
}

impl StackString {
    /// Stable ID (`stackstr@0x...`).
    #[must_use]
    pub fn id(&self) -> String {
        format!("stackstr@{:#x}", self.addr)
    }
}

impl Serialize for StackString {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("StackString", 6)?;
        st.serialize_field("id", &self.id())?;
        st.serialize_field("func", &self.func)?;
        st.serialize_field("func_hex", &crate::addr_hex(self.func))?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("value", &self.value)?;
        st.end()
    }
}

/// Stack base register id: 0 `rsp`, 1 `esp`, 2 `rbp`, 3 `ebp`.
type StackBase = u8;

/// Parse `mov`'s memory destination: width plus `(base, offset)`.
///
/// Accepts `byte`/`word`/`dword`/`qword ptr [rsp/rbp/esp/ebp[+-]off]`
/// (case as rendered by the disassembler, inner whitespace tolerated).
/// Anything else — widthless spans, other bases, indexed or segmented
/// forms, unparsable offsets — reports `None` and the write is skipped.
fn parse_stack_mem(dst: &str) -> Option<(StackBase, i64, usize)> {
    let s = dst.trim();
    let mut prefixed = None;
    for (prefix, w) in [
        ("byte ptr ", 1usize),
        ("word ptr ", 2usize),
        ("dword ptr ", 4usize),
        ("qword ptr ", 8usize),
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            prefixed = Some((w, rest));
            break;
        }
    }
    let (width, rest) = prefixed?;
    let inner = rest.strip_prefix('[')?.strip_suffix(']')?;
    let inner: String = inner.chars().filter(|c| !c.is_whitespace()).collect();
    for (name, id) in [("rsp", 0u8), ("esp", 1u8), ("rbp", 2u8), ("ebp", 3u8)] {
        if inner == name {
            return Some((id, 0, width));
        }
        if let Some(off) = inner.strip_prefix(name) {
            let (Some(sign), Some(mag)) = (off.get(..1), off.get(1..)) else {
                return None;
            };
            let mag = crate::parse_addr(mag).ok()?;
            let mag = i64::try_from(mag).ok()?;
            let off = match sign {
                "+" => mag,
                "-" => mag.checked_neg()?,
                _ => return None,
            };
            return Some((id, off, width));
        }
    }
    None
}

/// Recover stack-constructed strings over an analysis.
///
/// Pure derived view: reads function blocks and lifts instructions, writes
/// nothing. Rows order by (`func`, `addr`).
#[must_use]
pub fn recover(analysis: &Analysis) -> Vec<StackString> {
    let mut out = Vec::new();
    for func in analysis.functions.values() {
        let arch: Arch = func.decode_arch.unwrap_or(analysis.arch);
        for block in func.blocks.values() {
            // (base, offset) bytes in block order; later writes win.
            let mut bytes: BTreeMap<(StackBase, i64), (u8, u64)> = BTreeMap::new();
            for insn in &block.insns {
                for row in lift(arch, insn) {
                    if row.op != IrOp::Copy || row.outputs.len() != 1 || row.inputs.len() != 1 {
                        continue;
                    }
                    let Some((base, off, width)) = parse_stack_mem(&row.outputs[0]) else {
                        continue;
                    };
                    let Ok(imm) = crate::parse_addr(&row.inputs[0]) else {
                        continue;
                    };
                    for (k, b) in imm.to_le_bytes().iter().take(width).enumerate() {
                        let Some(o) = off.checked_add(k as i64) else {
                            continue;
                        };
                        bytes.insert((base, o), (*b, insn.addr));
                    }
                }
            }
            // Maximal contiguous runs per base register.
            let mut run: Vec<(i64, u8, u64)> = Vec::new();
            let mut run_base: Option<StackBase> = None;
            let flush = |run: &mut Vec<(i64, u8, u64)>,
                         run_base: &mut Option<StackBase>,
                         out: &mut Vec<StackString>| {
                if run.len() >= crate::loader::strings::DEFAULT_MIN_LEN
                    && run.iter().all(|&(_, b, _)| matches!(b, 0x20..=0x7E))
                {
                    let raw: Vec<u8> = run.iter().map(|&(_, b, _)| b).collect();
                    if let Ok(value) = String::from_utf8(raw) {
                        let addr = run.iter().map(|&(_, _, a)| a).min().unwrap_or(func.entry);
                        out.push(StackString {
                            func: func.entry,
                            addr,
                            value,
                        });
                    }
                }
                run.clear();
                *run_base = None;
            };
            for ((base, off), (b, addr)) in bytes {
                let contiguous = run_base == Some(base)
                    && run
                        .last()
                        .is_some_and(|&(o, _, _)| o.checked_add(1) == Some(off));
                if !contiguous {
                    flush(&mut run, &mut run_base, &mut out);
                    run_base = Some(base);
                }
                run.push((off, b, addr));
            }
            flush(&mut run, &mut run_base, &mut out);
        }
    }
    out.sort_by_key(|s| (s.func, s.addr));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_mem_parses_width_base_and_offset() {
        assert_eq!(parse_stack_mem("byte ptr [rsp+0x10]"), Some((0, 0x10, 1)));
        assert_eq!(parse_stack_mem("dword ptr [rbp-0x20]"), Some((2, -0x20, 4)));
        assert_eq!(parse_stack_mem("qword ptr [rsp]"), Some((0, 0, 8)));
        assert_eq!(parse_stack_mem("word ptr [ esp + 8 ]"), Some((1, 8, 2)));
        for bad in [
            "",
            "[rsp+0x10]",
            "xmmword ptr [rsp]",
            "byte ptr [rax+0x10]",
            "byte ptr [rsp+rax]",
            "byte ptr [rsp+0x10",
            "byte ptr rsp+0x10]",
            "byte ptr [sp+0x10]",
            "dword ptr [rbp-]",
            "dword ptr [rbp+0x1_0000_0000_0000_0000]",
        ] {
            assert_eq!(parse_stack_mem(bad), None, "{bad:?} must not parse");
        }
    }
}
