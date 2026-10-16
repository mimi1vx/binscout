//! Bindiff-lite: function-level diff between two binaries.
//!
//! Opens two [`crate::Project`]s read-only and matches their
//! functions by content, never by address: two builds of one fixture may
//! shift every entry, so entry equality proves nothing. Each function gets
//! a fingerprint of its raw bytes, its normalized IR, and its xref shape;
//! matching runs in passes from strongest to weakest evidence and the
//! leftovers become `added`/`removed`.
//!
//! Fingerprints (all address-independent, so rebased builds still match):
//!
//! - `bytes_hash`: SHA-256 over the raw instruction bytes in address order.
//! - `ir_hash`: SHA-256 over the lifted [`crate::ir::IrOp`] name
//!   sequence in address order (operands, addresses, and targets excluded;
//!   unmapped mnemonics mark their `Nop` with `!`). Same semantics under
//!   different encodings or base addresses hash equally.
//! - `shape`: `(blocks, insns, calls_out, callers_in, xrefs_out, xrefs_in)`
//!   counts over the function: direct callees/callers plus xrefs
//!   originating/landing in its blocks.
//!
//! Match passes, greedy in entry order with first-come pairing on hash
//! collisions:
//!
//! 1. Equal `bytes_hash` → identical (counted in `summary.matched`, exact
//!    duplicates pair in entry order).
//! 2. Equal `ir_hash` with differing bytes → `changed` (`ir-match`): same
//!    lifted semantics, e.g. a bumped immediate or moved base.
//! 3. Equal raw export/symbol names ([`Function::name`](crate::analysis::Function),
//!    not renames, which are per-side annotations) with differing hashes →
//!    `changed` (`name-match`).
//! 4. Fuzzy: IR-op multiset Jaccard similarity at or above
//!    [`FUZZY_SIMILARITY_THRESHOLD`] *and* equal callgraph/xref shape
//!    (`calls_out`, `callers_in`, `xrefs_out`, `xrefs_in`) → `changed`
//!    (`fuzzy`, with the similarity recorded). The
//!    threshold is deliberately high: below it, near-miss lookalikes (e.g.
//!    two frame leaves sharing 4 of 7 distinct ops) stay `added`/`removed`
//!    rather than pairing.
//!
//! Similarity is `sum(min)/sum(max)` over per-[`crate::ir::IrOp`]
//! histograms (empty vs empty is `1.0`); it ignores order, so small
//! reorderings still match while the shape gate keeps callgraph roles
//! honest.
//!
//! Strictly read-only: this module only reads the two in-memory projects,
//! which callers must open without saving. Each `added`/`removed`/`changed`
//! list caps at the shared 1024-row page budget (`summary.truncated` tells
//! when a cap bit).

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::analysis::Function;
use crate::ir::IrOp;
use crate::{Project, addr_hex};

/// Minimum IR-op multiset Jaccard similarity for a fuzzy `changed` pair.
///
/// `0.8` pairs functions that differ by roughly one instruction in five
/// while keeping distinct small leaves apart: e.g. two frame leaves
/// sharing 4 of 7 distinct ops score `4/7 ≈ 0.57` and stay
/// `added`/`removed`.
pub const FUZZY_SIMILARITY_THRESHOLD: f64 = 0.8;

/// How a `changed` pair was matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchReason {
    /// Same normalized IR, different bytes.
    IrMatch,
    /// Same raw export/symbol name, different content.
    NameMatch,
    /// IR similarity at or above [`FUZZY_SIMILARITY_THRESHOLD`] with equal
    /// callgraph/xref shape.
    Fuzzy,
}

/// One function on one side of the diff.
///
/// JSON pairs `entry` with `entry_hex` (`entry_hex` is recomputed on
/// serialize and ignored on deserialize).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FuncRow {
    /// Function entry address on its own side.
    pub entry: u64,
    /// Raw export/symbol name, if any (never a rename).
    pub name: Option<String>,
    /// SHA-256 over raw instruction bytes in address order.
    pub bytes_hash: String,
    /// SHA-256 over the normalized IR op sequence.
    pub ir_hash: String,
    /// Basic block count.
    pub blocks: usize,
    /// Instruction count across all blocks.
    pub insns: usize,
    /// Direct-callee count.
    pub calls: usize,
}

impl Serialize for FuncRow {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("FuncRow", 8)?;
        st.serialize_field("id", &format!("func@{:#x}", self.entry))?;
        st.serialize_field("entry", &self.entry)?;
        st.serialize_field("entry_hex", &addr_hex(self.entry))?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("bytes_hash", &self.bytes_hash)?;
        st.serialize_field("ir_hash", &self.ir_hash)?;
        st.serialize_field("blocks", &self.blocks)?;
        st.serialize_field("insns", &self.insns)?;
        st.serialize_field("calls", &self.calls)?;
        st.end()
    }
}

/// One matched-but-differing function pair.
///
/// JSON pairs each entry with its `0x`-hex twin (recomputed on serialize,
/// ignored on deserialize).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ChangedRow {
    /// Entry address on side A.
    pub entry_a: u64,
    /// Entry address on side B.
    pub entry_b: u64,
    /// Raw export/symbol name on side A, if any.
    pub name_a: Option<String>,
    /// Raw export/symbol name on side B, if any.
    pub name_b: Option<String>,
    /// Which match pass paired them.
    pub reason: MatchReason,
    /// Jaccard similarity (`Some` only for [`MatchReason::Fuzzy`]).
    pub similarity: Option<f64>,
    /// Side-A bytes hash.
    pub bytes_hash_a: String,
    /// Side-B bytes hash.
    pub bytes_hash_b: String,
    /// Side-A IR hash.
    pub ir_hash_a: String,
    /// Side-B IR hash.
    pub ir_hash_b: String,
}

impl Serialize for ChangedRow {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("ChangedRow", 12)?;
        st.serialize_field("id_a", &format!("func@{:#x}", self.entry_a))?;
        st.serialize_field("entry_a", &self.entry_a)?;
        st.serialize_field("entry_a_hex", &addr_hex(self.entry_a))?;
        st.serialize_field("id_b", &format!("func@{:#x}", self.entry_b))?;
        st.serialize_field("entry_b", &self.entry_b)?;
        st.serialize_field("entry_b_hex", &addr_hex(self.entry_b))?;
        st.serialize_field("name_a", &self.name_a)?;
        st.serialize_field("name_b", &self.name_b)?;
        st.serialize_field("reason", &self.reason)?;
        st.serialize_field("similarity", &self.similarity)?;
        st.serialize_field("bytes_hash_a", &self.bytes_hash_a)?;
        st.serialize_field("bytes_hash_b", &self.bytes_hash_b)?;
        st.serialize_field("ir_hash_a", &self.ir_hash_a)?;
        st.serialize_field("ir_hash_b", &self.ir_hash_b)?;
        st.end()
    }
}

/// Outcome counts for one diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSummary {
    /// Byte-identical pairs.
    pub matched: usize,
    /// Matched-but-differing pairs.
    pub changed: usize,
    /// Functions only in side B.
    pub added: usize,
    /// Functions only in side A.
    pub removed: usize,
    /// Whether any list hit the 1024-row cap.
    pub truncated: bool,
}

/// Function-level diff between two binaries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffReport {
    /// Analyzed path of side A (context only).
    pub binary_a: String,
    /// Analyzed path of side B (context only).
    pub binary_b: String,
    /// Disassembler target of side A.
    pub arch_a: String,
    /// Disassembler target of side B.
    pub arch_b: String,
    /// Outcome counts.
    pub summary: DiffSummary,
    /// Functions only in side B, ordered by entry.
    pub added: Vec<FuncRow>,
    /// Functions only in side A, ordered by entry.
    pub removed: Vec<FuncRow>,
    /// Matched-but-differing pairs, ordered by `(entry_a, entry_b)`.
    pub changed: Vec<ChangedRow>,
}

/// Per-function content fingerprint plus match state.
struct Fingerprint {
    entry: u64,
    name: Option<String>,
    bytes_hash: String,
    ir_hash: String,
    histogram: [usize; N_OPS],
    blocks: usize,
    insns: usize,
    calls_out: usize,
    callers_in: usize,
    xrefs_out: usize,
    xrefs_in: usize,
}

/// Number of [`IrOp`] variants in [`op_index`].
const N_OPS: usize = 19;

/// Histogram slot for one [`IrOp`].
fn op_index(op: IrOp) -> usize {
    match op {
        IrOp::Copy => 0,
        IrOp::Load => 1,
        IrOp::Store => 2,
        IrOp::Add => 3,
        IrOp::Sub => 4,
        IrOp::Mul => 5,
        IrOp::Div => 6,
        IrOp::And => 7,
        IrOp::Or => 8,
        IrOp::Xor => 9,
        IrOp::Shl => 10,
        IrOp::Shr => 11,
        IrOp::Cmp => 12,
        IrOp::Branch => 13,
        IrOp::CBranch => 14,
        IrOp::Call => 15,
        IrOp::Return => 16,
        IrOp::Phi => 17,
        IrOp::Nop => 18,
    }
}

/// Multiset Jaccard similarity over IR-op histograms.
///
/// `sum(min) / sum(max)`; two empty histograms score `1.0`, empty vs
/// non-empty scores `0.0`. Order-insensitive by construction.
fn ir_similarity(a: &[usize; N_OPS], b: &[usize; N_OPS]) -> f64 {
    let mut inter: usize = 0;
    let mut union: usize = 0;
    for i in 0..N_OPS {
        inter += a[i].min(b[i]);
        union += a[i].max(b[i]);
    }
    if union == 0 {
        1.0
    } else {
        inter as f64 / union as f64
    }
}

/// Address range covered by one function's blocks, for xref attribution.
fn func_range(func: &Function) -> Option<(u64, u64)> {
    let mut start = u64::MAX;
    let mut end = 0u64;
    for b in func.blocks.values() {
        start = start.min(b.start);
        end = end.max(b.end());
    }
    (start <= end).then_some((start, end))
}

/// Fingerprint every function in one project, ordered by entry.
fn fingerprints(project: &Project) -> Vec<Fingerprint> {
    let analysis = project.analysis();
    analysis
        .functions
        .values()
        .map(|f| {
            let mut insns: Vec<_> = f.blocks.values().flat_map(|b| b.insns.iter()).collect();
            insns.sort_by_key(|i| i.addr);
            let mut bytes: Vec<u8> = Vec::new();
            let mut ops: Vec<u8> = Vec::new();
            let mut histogram = [0usize; N_OPS];
            for insn in &insns {
                bytes.extend_from_slice(&insn.bytes);
                for lifted in crate::ir::lift(analysis.arch, insn) {
                    histogram[op_index(lifted.op)] += 1;
                    ops.extend_from_slice(lifted.op.name().as_bytes());
                    // Unmapped mnemonics lift as Nop with a warning: mark the
                    // op so mapped and fallback Nops hash apart.
                    ops.push(u8::from(lifted.warning.is_some()));
                    ops.push(b';');
                }
            }
            let range = func_range(f);
            let in_range = |addr: u64| range.is_some_and(|(lo, hi)| addr >= lo && addr < hi);
            let (mut xrefs_out, mut xrefs_in) = (0usize, 0usize);
            for x in &analysis.xrefs {
                if in_range(x.from) {
                    xrefs_out += 1;
                }
                if in_range(x.to) {
                    xrefs_in += 1;
                }
            }
            Fingerprint {
                entry: f.entry,
                name: f.name.clone(),
                bytes_hash: crate::annotations::sha256_hex(&bytes),
                ir_hash: crate::annotations::sha256_hex(&ops),
                histogram,
                blocks: f.blocks.len(),
                insns: insns.len(),
                calls_out: analysis.calls_of(f.entry).len(),
                callers_in: analysis.callers_of(f.entry).len(),
                xrefs_out,
                xrefs_in,
            }
        })
        .collect()
}

/// Drain `queue` of already-used indices, returning the first live one.
fn take_live(queue: &mut VecDeque<usize>, used: &[bool]) -> Option<usize> {
    while let Some(&i) = queue.front() {
        queue.pop_front();
        if !used[i] {
            return Some(i);
        }
    }
    None
}

/// Diff two already-opened projects.
///
/// Both must be opened read-only (no `save`): this only reads the
/// in-memory analyses. Different architectures still diff (hashes are
/// computed per side), but cross-arch IR rarely matches, so expect
/// mostly `added`/`removed`.
#[must_use]
pub fn diff_projects(a: &Project, b: &Project) -> DiffReport {
    let fa = fingerprints(a);
    let fb = fingerprints(b);
    let mut used_b = vec![false; fb.len()];
    let mut matched = 0usize;
    let mut changed: Vec<ChangedRow> = Vec::new();

    // Pass 1: byte-identical pairs.
    let mut by_bytes: BTreeMap<&str, VecDeque<usize>> = BTreeMap::new();
    for (i, f) in fb.iter().enumerate() {
        by_bytes
            .entry(f.bytes_hash.as_str())
            .or_default()
            .push_back(i);
    }
    let mut unmatched_a: Vec<usize> = Vec::new();
    for (i, f) in fa.iter().enumerate() {
        match by_bytes
            .get_mut(f.bytes_hash.as_str())
            .and_then(|q| take_live(q, &used_b))
        {
            Some(j) => {
                used_b[j] = true;
                matched += 1;
            }
            None => unmatched_a.push(i),
        }
    }

    // Pass 2: same normalized IR, different bytes.
    let mut by_ir: BTreeMap<&str, VecDeque<usize>> = BTreeMap::new();
    for (j, f) in fb.iter().enumerate() {
        if !used_b[j] {
            by_ir.entry(f.ir_hash.as_str()).or_default().push_back(j);
        }
    }
    let mut still_a: Vec<usize> = Vec::new();
    for &i in &unmatched_a {
        match by_ir
            .get_mut(fa[i].ir_hash.as_str())
            .and_then(|q| take_live(q, &used_b))
        {
            Some(j) => {
                used_b[j] = true;
                changed.push(changed_row(&fa[i], &fb[j], MatchReason::IrMatch, None));
            }
            None => still_a.push(i),
        }
    }

    // Pass 3: same raw export/symbol name, different content.
    let mut by_name: BTreeMap<&str, VecDeque<usize>> = BTreeMap::new();
    for (j, f) in fb.iter().enumerate() {
        if !used_b[j]
            && let Some(n) = f.name.as_deref()
        {
            by_name.entry(n).or_default().push_back(j);
        }
    }
    let mut rest_a: Vec<usize> = Vec::new();
    for &i in &still_a {
        let hit = fa[i]
            .name
            .as_deref()
            .and_then(|n| by_name.get_mut(n))
            .and_then(|q| take_live(q, &used_b));
        match hit {
            Some(j) => {
                used_b[j] = true;
                changed.push(changed_row(&fa[i], &fb[j], MatchReason::NameMatch, None));
            }
            None => rest_a.push(i),
        }
    }

    // Pass 4: fuzzy IR similarity with equal callgraph shape.
    let mut rest_b: Vec<usize> = fb
        .iter()
        .enumerate()
        .filter(|(j, _)| !used_b[*j])
        .map(|(j, _)| j)
        .collect::<Vec<_>>();
    let mut final_a: Vec<usize> = Vec::new();
    for &i in &rest_a {
        let mut best: Option<(usize, f64)> = None;
        for &j in &rest_b {
            if fa[i].calls_out != fb[j].calls_out
                || fa[i].callers_in != fb[j].callers_in
                || fa[i].xrefs_out != fb[j].xrefs_out
                || fa[i].xrefs_in != fb[j].xrefs_in
            {
                continue;
            }
            let sim = ir_similarity(&fa[i].histogram, &fb[j].histogram);
            if sim >= FUZZY_SIMILARITY_THRESHOLD && best.is_none_or(|(_, s)| sim > s) {
                best = Some((j, sim));
            }
        }
        match best {
            Some((j, sim)) => {
                used_b[j] = true;
                rest_b.retain(|&k| k != j);
                changed.push(changed_row(&fa[i], &fb[j], MatchReason::Fuzzy, Some(sim)));
            }
            None => final_a.push(i),
        }
    }

    changed.sort_by_key(|c| (c.entry_a, c.entry_b));
    let mut removed: Vec<FuncRow> = final_a.iter().map(|&i| func_row(a, &fa[i])).collect();
    let mut added: Vec<FuncRow> = rest_b.iter().map(|&j| func_row(b, &fb[j])).collect();
    removed.sort_by_key(|r| r.entry);
    added.sort_by_key(|r| r.entry);

    // Shared 1024-row page budget per list, mirroring paged queries.
    let cap = crate::MAX_ROWS;
    let truncated = added.len() > cap || removed.len() > cap || changed.len() > cap;
    added.truncate(cap);
    removed.truncate(cap);
    changed.truncate(cap);

    DiffReport {
        binary_a: a.path().display().to_string(),
        binary_b: b.path().display().to_string(),
        arch_a: crate::db::arch_name(a.binary().arch).to_string(),
        arch_b: crate::db::arch_name(b.binary().arch).to_string(),
        summary: DiffSummary {
            matched,
            changed: changed.len(),
            added: added.len(),
            removed: removed.len(),
            truncated,
        },
        added,
        removed,
        changed,
    }
}

/// One-sided row for an unmatched fingerprint.
fn func_row(project: &Project, f: &Fingerprint) -> FuncRow {
    FuncRow {
        entry: f.entry,
        name: project.function_name(f.entry),
        bytes_hash: f.bytes_hash.clone(),
        ir_hash: f.ir_hash.clone(),
        blocks: f.blocks,
        insns: f.insns,
        calls: f.calls_out,
    }
}

/// Changed pair row for two matched fingerprints.
fn changed_row(
    a: &Fingerprint,
    b: &Fingerprint,
    reason: MatchReason,
    similarity: Option<f64>,
) -> ChangedRow {
    ChangedRow {
        entry_a: a.entry,
        entry_b: b.entry,
        name_a: a.name.clone(),
        name_b: b.name.clone(),
        reason,
        similarity,
        bytes_hash_a: a.bytes_hash.clone(),
        bytes_hash_b: b.bytes_hash.clone(),
        ir_hash_a: a.ir_hash.clone(),
        ir_hash_b: b.ir_hash.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{N_OPS, ir_similarity};

    fn hist(pairs: &[(usize, usize)]) -> [usize; N_OPS] {
        let mut h = [0usize; N_OPS];
        for &(i, n) in pairs {
            h[i] = n;
        }
        h
    }

    #[test]
    fn similarity_identical_is_one() {
        let h = hist(&[(0, 2), (16, 1)]);
        assert_eq!(ir_similarity(&h, &h), 1.0);
    }

    #[test]
    fn similarity_empty_pair_is_one_empty_vs_full_is_zero() {
        assert_eq!(ir_similarity(&[0; N_OPS], &[0; N_OPS]), 1.0);
        assert_eq!(ir_similarity(&[0; N_OPS], &hist(&[(0, 1)])), 0.0);
    }

    #[test]
    fn similarity_frame_leaves_stay_below_threshold() {
        // frame_ret0 {Store,Copy,Xor,Load,Return} vs frame add/sub
        // {Store,Copy,Sub,Add,Load,Return}: 4 shared of 7 distinct ops.
        let old = hist(&[(2, 1), (0, 1), (9, 1), (1, 1), (16, 1)]);
        let new = hist(&[(2, 1), (0, 1), (4, 1), (3, 1), (1, 1), (16, 1)]);
        let sim = ir_similarity(&old, &new);
        assert!((sim - 4.0 / 7.0).abs() < 1e-9, "got {sim}");
        assert!(sim < super::FUZZY_SIMILARITY_THRESHOLD);
    }

    #[test]
    fn similarity_single_extra_nop_stays_above_threshold() {
        // 5-op function plus one Nop: 5/6 >= 0.8.
        let a = hist(&[(2, 1), (0, 2), (1, 1), (16, 1)]);
        let b = hist(&[(2, 1), (0, 2), (1, 1), (16, 1), (18, 1)]);
        let sim = ir_similarity(&a, &b);
        assert!((sim - 5.0 / 6.0).abs() < 1e-9, "got {sim}");
        assert!(sim >= super::FUZZY_SIMILARITY_THRESHOLD);
    }
}
