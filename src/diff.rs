//! Bindiff-lite: function-level diff between two binaries, plus
//! per-function block/instruction detail.
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
//! Similarity is `sum(min)/sum(max)` over per-[`crate::ir::IrOp`]
//! histograms (empty vs empty is `1.0`); it ignores order, so small
//! reorderings still match while the shape gate keeps callgraph roles
//! honest.
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
//! 5. Neighbour propagation (BinDiff-style): from matched pairs (identical
//!    and `changed` alike), pair unique unmatched callee/caller neighbours
//!    — when the callees (or callers) of a matched pair hold exactly one
//!    unmatched function on each side, those pair as `changed`
//!    (`propagated`) without consulting content at all. Iterates to a
//!    fixpoint: newly propagated pairs seed further rounds.
//!
//! [`diff_projects_page`] pages each of `added`/`removed`/`changed` under
//! the protocol-1 [`crate::Page`] envelope with exact totals in
//! [`DiffSummary`]; [`diff_projects`] is the first page. [`diff_func`]
//! drills into one function pair: blocks match by IR hash, then leftover
//! blocks pair by address-order position, and every matched block carries
//! a bounded instruction-level edit script. [`transfer_renames`] maps side-A
//! renames through the pairing to side-B entries and wraps them in an
//! [`crate::annotations::AnnotationDocument`] for side B, ready for
//! [`crate::Project::import_annotations`].
//!
//! Strictly read-only: this module only reads the two in-memory projects,
//! which callers must open without saving. The transfer document is data,
//! never a write: callers apply it explicitly through the annotation
//! import machinery.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::analysis::{BasicBlock, Function};
use crate::disasm::{Arch, Insn};
use crate::error::{Error, Result};
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
    /// Unique unmatched callee/caller neighbours of an already-matched
    /// pair, propagated to a fixpoint (see the module docs).
    Propagated,
}

/// One function on one side of the diff.
///
/// JSON pairs `entry` with `entry_hex` (`entry_hex` is recomputed on
/// serialize and ignored on deserialize).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FuncRow {
    /// Function entry address on its own side.
    pub entry: u64,
    /// Rename-resolved display name, if any: the per-side annotation
    /// rename when present, else the raw export/symbol name. Matching
    /// still keys on the raw names (see [`MatchReason::NameMatch`]), so
    /// renames never affect pairing.
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
    /// Matched-but-differing pairs (exact total, even past one page).
    pub changed: usize,
    /// Functions only in side B (exact total, even past one page).
    pub added: usize,
    /// Functions only in side A (exact total, even past one page).
    pub removed: usize,
    /// Whether any list total exceeds the 1024-row single-page budget, so
    /// paging is needed to see every row.
    pub truncated: bool,
}

/// Function-level diff between two binaries.
///
/// `added`/`removed`/`changed` are protocol-1 [`crate::Page`]s over entry-
/// or pair-ordered rows: `total` is the exact match count and `items` holds
/// the requested page. `transfer` carries the side-B annotation document
/// only when the caller asked for it (CLI `--transfer-renames` / MCP
/// `transfer_renames`) and computed it via [`transfer_renames`]; otherwise
/// it is null.
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
    /// Functions only in side B, ordered by entry (paged).
    pub added: crate::Page<FuncRow>,
    /// Functions only in side A, ordered by entry (paged).
    pub removed: crate::Page<FuncRow>,
    /// Matched-but-differing pairs, ordered by `(entry_a, entry_b)` (paged).
    pub changed: crate::Page<ChangedRow>,
    /// Side-B rename transfer document, when requested.
    pub transfer: Option<crate::annotations::AnnotationDocument>,
}

/// How one pair of blocks in [`diff_func`] was matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockMatchKind {
    /// Same per-block normalized-IR hash.
    Hash,
    /// Leftover blocks paired by address-order position in the function.
    Position,
}

/// One row of a block-level instruction edit script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EditKind {
    /// Same bytes at aligned positions.
    Same,
    /// Aligned instructions with differing content (bytes or IR).
    Changed,
    /// Instruction only on side B.
    Added,
    /// Instruction only on side A.
    Removed,
}

/// One instruction-level delta row between two matched blocks.
///
/// JSON pairs each present address with its `0x`-hex twin (recomputed on
/// serialize, ignored on deserialize); absent sides stay null.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InsnEdit {
    /// Row kind.
    pub kind: EditKind,
    /// Address on side A, if the row has an A instruction.
    pub addr_a: Option<u64>,
    /// Address on side B, if the row has a B instruction.
    pub addr_b: Option<u64>,
    /// Disassembly (`mnem` plus operands) on side A, if present.
    pub text_a: Option<String>,
    /// Disassembly on side B, if present.
    pub text_b: Option<String>,
}

impl Serialize for InsnEdit {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("InsnEdit", 7)?;
        st.serialize_field("kind", &self.kind)?;
        st.serialize_field("addr_a", &self.addr_a)?;
        st.serialize_field("addr_a_hex", &self.addr_a.map(addr_hex))?;
        st.serialize_field("addr_b", &self.addr_b)?;
        st.serialize_field("addr_b_hex", &self.addr_b.map(addr_hex))?;
        st.serialize_field("text_a", &self.text_a)?;
        st.serialize_field("text_b", &self.text_b)?;
        st.end()
    }
}

/// One block pair in [`diff_func`]: the bounded instruction edit script
/// between two matched blocks.
///
/// JSON pairs each start with its `0x`-hex twin (recomputed on serialize,
/// ignored on deserialize).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlockDiff {
    /// Block start on side A.
    pub start_a: u64,
    /// Block start on side B.
    pub start_b: u64,
    /// How the blocks were paired.
    pub kind: BlockMatchKind,
    /// Side-A per-block normalized-IR hash.
    pub ir_hash_a: String,
    /// Side-B per-block normalized-IR hash.
    pub ir_hash_b: String,
    /// Whether the edit script hit [`MAX_EDITS_PER_BLOCK`] and clipped.
    pub truncated: bool,
    /// Instruction-level delta in address order.
    pub edits: Vec<InsnEdit>,
}

impl Serialize for BlockDiff {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("BlockDiff", 9)?;
        st.serialize_field("start_a", &self.start_a)?;
        st.serialize_field("start_a_hex", &addr_hex(self.start_a))?;
        st.serialize_field("start_b", &self.start_b)?;
        st.serialize_field("start_b_hex", &addr_hex(self.start_b))?;
        st.serialize_field("kind", &self.kind)?;
        st.serialize_field("ir_hash_a", &self.ir_hash_a)?;
        st.serialize_field("ir_hash_b", &self.ir_hash_b)?;
        st.serialize_field("truncated", &self.truncated)?;
        st.serialize_field("edits", &self.edits)?;
        st.end()
    }
}

/// One unmatched block in [`diff_func`].
///
/// JSON pairs `start` with its `0x`-hex twin (recomputed on serialize,
/// ignored on deserialize).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlockRow {
    /// Block start on its own side.
    pub start: u64,
    /// Instruction count in the block.
    pub insns: usize,
    /// Per-block normalized-IR hash.
    pub ir_hash: String,
}

impl Serialize for BlockRow {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("BlockRow", 4)?;
        st.serialize_field("start", &self.start)?;
        st.serialize_field("start_hex", &addr_hex(self.start))?;
        st.serialize_field("insns", &self.insns)?;
        st.serialize_field("ir_hash", &self.ir_hash)?;
        st.end()
    }
}

/// Outcome counts for one [`diff_func`] pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuncDiffSummary {
    /// Blocks paired by hash or position.
    pub matched_blocks: usize,
    /// Blocks only in side B.
    pub added_blocks: usize,
    /// Blocks only in side A.
    pub removed_blocks: usize,
    /// Edit rows with identical bytes on both sides.
    pub same_insns: usize,
    /// Aligned edit rows with differing content.
    pub changed_insns: usize,
    /// Edit rows only on side B.
    pub added_insns: usize,
    /// Edit rows only on side A.
    pub removed_insns: usize,
    /// Whether any block's edit script hit [`MAX_EDITS_PER_BLOCK`].
    pub truncated: bool,
}

/// Block- and instruction-level delta between two functions.
///
/// `reason` is the function-level pairing reason when [`diff_projects`]
/// pairs this exact combination (`None` for byte-identical pairs);
/// `paired` tells byte-identical pairs apart from unpaired combinations,
/// which still get a full block delta. `name_a`/`name_b` are the
/// rename-resolved display names on each side.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct FuncDiffReport {
    /// Analyzed path of side A (context only).
    pub binary_a: String,
    /// Analyzed path of side B (context only).
    pub binary_b: String,
    /// Disassembler target of side A.
    pub arch_a: String,
    /// Disassembler target of side B.
    pub arch_b: String,
    /// Function entry on side A (query addresses snap to containing entries).
    pub entry_a: u64,
    /// Function entry on side B.
    pub entry_b: u64,
    /// Rename-resolved display name on side A, if any.
    pub name_a: Option<String>,
    /// Rename-resolved display name on side B, if any.
    pub name_b: Option<String>,
    /// Whether the function-level matcher pairs this combination.
    pub paired: bool,
    /// Function-level match reason (`None` for identical or unpaired).
    pub reason: Option<MatchReason>,
    /// Outcome counts.
    pub summary: FuncDiffSummary,
    /// Matched block pairs in side-A address order, each with its edit script.
    pub blocks: Vec<BlockDiff>,
    /// Blocks only in side B, ordered by start.
    pub added_blocks: Vec<BlockRow>,
    /// Blocks only in side A, ordered by start.
    pub removed_blocks: Vec<BlockRow>,
}

impl Serialize for FuncDiffReport {
    /// Custom serialization to add the canonical hex twins.
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("FuncDiffReport", 16)?;
        st.serialize_field("binary_a", &self.binary_a)?;
        st.serialize_field("binary_b", &self.binary_b)?;
        st.serialize_field("arch_a", &self.arch_a)?;
        st.serialize_field("arch_b", &self.arch_b)?;
        st.serialize_field("entry_a", &self.entry_a)?;
        st.serialize_field("entry_a_hex", &addr_hex(self.entry_a))?;
        st.serialize_field("entry_b", &self.entry_b)?;
        st.serialize_field("entry_b_hex", &addr_hex(self.entry_b))?;
        st.serialize_field("name_a", &self.name_a)?;
        st.serialize_field("name_b", &self.name_b)?;
        st.serialize_field("paired", &self.paired)?;
        st.serialize_field("reason", &self.reason)?;
        st.serialize_field("summary", &self.summary)?;
        st.serialize_field("blocks", &self.blocks)?;
        st.serialize_field("added_blocks", &self.added_blocks)?;
        st.serialize_field("removed_blocks", &self.removed_blocks)?;
        st.end()
    }
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

/// Xref counts for one function address range.
///
/// `froms` holds the `from` endpoint of every xref in storage order
/// (`xrefs` sort by `(from, kind, to)`, so it runs non-decreasing) and
/// `tos` every `to` endpoint sorted ascending; both counts then resolve
/// with two binary searches over the half-open `[lo, hi)` range instead
/// of scanning every xref. A function without blocks has no range and
/// holds no xrefs.
fn xref_shape(froms: &[u64], tos: &[u64], range: Option<(u64, u64)>) -> (usize, usize) {
    let Some((lo, hi)) = range else {
        return (0, 0);
    };
    let out = froms.partition_point(|&from| from < hi) - froms.partition_point(|&from| from < lo);
    let inn = tos.partition_point(|&to| to < hi) - tos.partition_point(|&to| to < lo);
    (out, inn)
}

/// Fingerprint every function in one project, ordered by entry.
fn fingerprints(project: &Project) -> Vec<Fingerprint> {
    let analysis = project.analysis();
    let froms: Vec<u64> = analysis.xrefs.iter().map(|x| x.from).collect();
    let mut tos: Vec<u64> = analysis.xrefs.iter().map(|x| x.to).collect();
    tos.sort_unstable();
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
            let (xrefs_out, xrefs_in) = xref_shape(&froms, &tos, func_range(f));
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

/// Diff two already-opened projects, first page of each list.
///
/// Both must be opened read-only (no `save`): this only reads the
/// in-memory analyses. Different architectures still diff (hashes are
/// computed per side), but cross-arch IR rarely matches, so expect
/// mostly `added`/`removed`. This is [`diff_projects_page`] with
/// `offset` 0 and a full-page limit; `transfer` is always null here (see
/// [`transfer_renames`]).
#[must_use]
pub fn diff_projects(a: &Project, b: &Project) -> DiffReport {
    diff_projects_page(a, b, 0, crate::MAX_ROWS)
}

/// Diff two already-opened projects, paging each list.
///
/// `offset`/`limit` apply to each of `added`/`removed`/`changed`
/// independently; every page carries its exact `total` under the
/// protocol-1 envelope, so agents walk large diffs page by page instead
/// of losing rows to the cap. `limit` clips to the shared 1024-row budget.
/// `transfer` is always null here (see [`transfer_renames`]).
#[must_use]
pub fn diff_projects_page(a: &Project, b: &Project, offset: usize, limit: usize) -> DiffReport {
    let fa = fingerprints(a);
    let fb = fingerprints(b);
    let full = match_all(a, b, &fa, &fb);
    let mut used_a = vec![false; fa.len()];
    let mut used_b = vec![false; fb.len()];
    for (i, _) in &full.identical {
        used_a[*i] = true;
    }
    for (i, j, _, _) in &full.changed {
        used_a[*i] = true;
        used_b[*j] = true;
    }
    for (_, j) in &full.identical {
        used_b[*j] = true;
    }
    let mut changed: Vec<ChangedRow> = full
        .changed
        .iter()
        .map(|(i, j, reason, sim)| changed_row(&fa[*i], &fb[*j], *reason, *sim))
        .collect();
    changed.sort_by_key(|c| (c.entry_a, c.entry_b));
    let mut removed: Vec<FuncRow> = fa
        .iter()
        .enumerate()
        .filter(|(i, _)| !used_a[*i])
        .map(|(_, f)| func_row(a, f))
        .collect();
    let mut added: Vec<FuncRow> = fb
        .iter()
        .enumerate()
        .filter(|(j, _)| !used_b[*j])
        .map(|(_, f)| func_row(b, f))
        .collect();
    removed.sort_by_key(|r| r.entry);
    added.sort_by_key(|r| r.entry);

    // Exact pre-page totals so agents see the real change volume; only the
    // page items are clipped.
    let cap = crate::MAX_ROWS;
    let summary = DiffSummary {
        matched: full.identical.len(),
        changed: changed.len(),
        added: added.len(),
        removed: removed.len(),
        truncated: added.len() > cap || removed.len() > cap || changed.len() > cap,
    };
    let added_total = added.len();
    let removed_total = removed.len();
    let changed_total = changed.len();
    let added = crate::page_envelope(
        added_total,
        offset,
        limit,
        added
            .into_iter()
            .skip(offset)
            .take(limit.min(cap))
            .collect(),
    );
    let removed = crate::page_envelope(
        removed_total,
        offset,
        limit,
        removed
            .into_iter()
            .skip(offset)
            .take(limit.min(cap))
            .collect(),
    );
    let changed = crate::page_envelope(
        changed_total,
        offset,
        limit,
        changed
            .into_iter()
            .skip(offset)
            .take(limit.min(cap))
            .collect(),
    );

    DiffReport {
        binary_a: a.path().display().to_string(),
        binary_b: b.path().display().to_string(),
        arch_a: crate::db::arch_name(a.binary().arch).to_string(),
        arch_b: crate::db::arch_name(b.binary().arch).to_string(),
        summary,
        added,
        removed,
        changed,
        transfer: None,
    }
}

/// Full pairing before rows and paging: byte-identical index pairs plus
/// matched-but-differing index pairs with their reason.
struct FullMatch {
    /// Byte-identical `(fa, fb)` index pairs.
    identical: Vec<(usize, usize)>,
    /// Differing `(fa, fb)` index pairs with match reason and similarity.
    changed: Vec<(usize, usize, MatchReason, Option<f64>)>,
}

/// Pair every function of `a` with one of `b` through all five passes.
///
/// Returns index pairs into `fa`/`fb`; callers derive rows, used sets, and
/// pages from these. Passes 1-4 mirror the module docs; pass 5 propagates
/// from every matched pair (identical and changed alike).
fn match_all(a: &Project, b: &Project, fa: &[Fingerprint], fb: &[Fingerprint]) -> FullMatch {
    let mut used_b = vec![false; fb.len()];
    let mut identical: Vec<(usize, usize)> = Vec::new();
    let mut changed: Vec<(usize, usize, MatchReason, Option<f64>)> = Vec::new();

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
                identical.push((i, j));
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
                changed.push((i, j, MatchReason::IrMatch, None));
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
                changed.push((i, j, MatchReason::NameMatch, None));
            }
            None => rest_a.push(i),
        }
    }

    // Pass 4: fuzzy IR similarity with equal callgraph shape. The
    // remaining B side buckets by shape so each A only compares
    // against shape-equal candidates; pairings mark `used_b` in place
    // instead of shifting a live vector per match.
    let mut buckets: HashMap<(usize, usize, usize, usize), Vec<usize>> = HashMap::new();
    for (j, f) in fb.iter().enumerate() {
        if !used_b[j] {
            buckets
                .entry((f.calls_out, f.callers_in, f.xrefs_out, f.xrefs_in))
                .or_default()
                .push(j);
        }
    }
    let mut final_a: Vec<usize> = Vec::new();
    for &i in &rest_a {
        let key = (
            fa[i].calls_out,
            fa[i].callers_in,
            fa[i].xrefs_out,
            fa[i].xrefs_in,
        );
        let mut best: Option<(usize, f64)> = None;
        if let Some(cands) = buckets.get(&key) {
            for &j in cands {
                if used_b[j] {
                    continue;
                }
                let sim = ir_similarity(&fa[i].histogram, &fb[j].histogram);
                if sim >= FUZZY_SIMILARITY_THRESHOLD && best.is_none_or(|(_, s)| sim > s) {
                    best = Some((j, sim));
                }
            }
        }
        match best {
            Some((j, sim)) => {
                used_b[j] = true;
                changed.push((i, j, MatchReason::Fuzzy, Some(sim)));
            }
            None => final_a.push(i),
        }
    }

    // Pass 5: neighbour propagation from every matched pair. A matched
    // pair whose callees (or callers) hold exactly one unmatched function
    // on each side pairs those neighbours; new pairs seed further rounds
    // until no round pairs anything.
    let mut a_by_entry: BTreeMap<u64, usize> = BTreeMap::new();
    for (i, f) in fa.iter().enumerate() {
        a_by_entry.insert(f.entry, i);
    }
    let mut b_by_entry: BTreeMap<u64, usize> = BTreeMap::new();
    for (j, f) in fb.iter().enumerate() {
        b_by_entry.insert(f.entry, j);
    }
    let mut used_a = vec![false; fa.len()];
    for (i, _) in &identical {
        used_a[*i] = true;
    }
    for (i, _, _, _) in &changed {
        used_a[*i] = true;
    }
    let unique_unmatched = |entries: Vec<u64>, by_entry: &BTreeMap<u64, usize>, used: &[bool]| {
        let mut out = Vec::new();
        for e in entries {
            if let Some(&idx) = by_entry.get(&e)
                && !used[idx]
            {
                out.push(idx);
            }
        }
        (out.len() == 1).then(|| out[0])
    };
    loop {
        let pairs: Vec<(u64, u64)> = identical
            .iter()
            .map(|(i, j)| (fa[*i].entry, fb[*j].entry))
            .chain(
                changed
                    .iter()
                    .map(|(i, j, _, _)| (fa[*i].entry, fb[*j].entry)),
            )
            .collect();
        let mut fresh: Vec<(usize, usize)> = Vec::new();
        for (ea, eb) in pairs {
            if let (Some(i), Some(j)) = (
                unique_unmatched(a.analysis().calls_of(ea), &a_by_entry, &used_a),
                unique_unmatched(b.analysis().calls_of(eb), &b_by_entry, &used_b),
            ) {
                fresh.push((i, j));
            }
            if let (Some(i), Some(j)) = (
                unique_unmatched(a.analysis().callers_of(ea), &a_by_entry, &used_a),
                unique_unmatched(b.analysis().callers_of(eb), &b_by_entry, &used_b),
            ) {
                fresh.push((i, j));
            }
        }
        fresh.sort_unstable();
        fresh.dedup();
        let mut progressed = false;
        for (i, j) in fresh {
            if used_a[i] || used_b[j] {
                continue;
            }
            used_a[i] = true;
            used_b[j] = true;
            changed.push((i, j, MatchReason::Propagated, None));
            progressed = true;
        }
        if !progressed {
            break;
        }
    }

    FullMatch { identical, changed }
}

/// Carry side-A renames to side B as an import-ready annotation document.
///
/// Every identical and `changed` pair maps side A's stored rename (raw
/// export/symbol names are never transferred, only analyst renames) onto
/// the side-B entry; the result carries side B's SHA-256, size, and loader
/// mapping, so it imports through [`Project::import_annotations`]
/// unchanged. Pairs with no side-A rename contribute no row. Read-only:
/// neither project nor sidecar is touched — the caller applies the
/// document explicitly (CLI `--transfer-renames` embeds it in the report;
/// `annotations-import` applies a saved copy).
///
/// # Errors
/// [`Error::Storage`] when side B cannot be re-read for its digest,
/// [`Error::Limit`] past rename or document budgets.
pub fn transfer_renames(
    a: &Project,
    b: &Project,
) -> Result<crate::annotations::AnnotationDocument> {
    let fa = fingerprints(a);
    let fb = fingerprints(b);
    let full = match_all(a, b, &fa, &fb);
    let pairs: Vec<(usize, usize)> = full
        .identical
        .iter()
        .copied()
        .chain(full.changed.iter().map(|(i, j, _, _)| (*i, *j)))
        .collect();
    let mut rows = Vec::new();
    for (i, j) in pairs {
        if let Some(name) = a
            .annotations()
            .get(&fa[i].entry)
            .and_then(|ann| ann.name.clone())
            .filter(|s| !s.is_empty())
        {
            rows.push(crate::annotations::AnnotationRow {
                addr: fb[j].entry,
                rename: Some(name),
                comment: None,
            });
        }
    }
    b.transfer_document(rows)
}

/// Block- and instruction-level delta between two functions.
///
/// Both addresses snap to their containing function entries (any address
/// inside the function works); blocks match by per-block normalized-IR
/// hash first, then leftover blocks pair by address-order position, and
/// every matched block carries a bounded instruction edit script (see
/// [`MAX_EDITS_PER_BLOCK`]). `reason` reports the function-level pairing
/// when this exact combination pairs (`None` for byte-identical pairs);
/// unpaired combinations still get a full block delta with `paired` false.
///
/// # Errors
/// [`Error::NotFound`] when either address lies in no function.
pub fn diff_func(a: &Project, addr_a: u64, b: &Project, addr_b: u64) -> Result<FuncDiffReport> {
    let entry_a = a
        .analysis()
        .containing_function(addr_a)
        .ok_or_else(|| Error::NotFound(format!("address {addr_a:#x} lies in no function")))?;
    let entry_b = b
        .analysis()
        .containing_function(addr_b)
        .ok_or_else(|| Error::NotFound(format!("address {addr_b:#x} lies in no function")))?;
    let func_a = a
        .analysis()
        .functions
        .get(&entry_a)
        .ok_or_else(|| Error::NotFound(format!("function {entry_a:#x}")))?;
    let func_b = b
        .analysis()
        .functions
        .get(&entry_b)
        .ok_or_else(|| Error::NotFound(format!("function {entry_b:#x}")))?;

    let fa = fingerprints(a);
    let fb = fingerprints(b);
    let full = match_all(a, b, &fa, &fb);
    let (mut paired, mut reason): (bool, Option<MatchReason>) = (false, None);
    for (i, j) in &full.identical {
        if fa[*i].entry == entry_a && fb[*j].entry == entry_b {
            paired = true;
            break;
        }
    }
    if !paired {
        for (i, j, r, _) in &full.changed {
            if fa[*i].entry == entry_a && fb[*j].entry == entry_b {
                paired = true;
                reason = Some(*r);
                break;
            }
        }
    }

    let arch_a = a.analysis().arch;
    let arch_b = b.analysis().arch;
    let blocks_a: Vec<&BasicBlock> = func_a.blocks.values().collect();
    let blocks_b: Vec<&BasicBlock> = func_b.blocks.values().collect();
    let hashes_a: Vec<String> = blocks_a
        .iter()
        .map(|blk| block_ir_hash(arch_a, blk))
        .collect();
    let hashes_b: Vec<String> = blocks_b
        .iter()
        .map(|blk| block_ir_hash(arch_b, blk))
        .collect();
    let mut used_a_blk = vec![false; blocks_a.len()];
    let mut used_b = vec![false; blocks_b.len()];
    let mut matched: Vec<(usize, usize, BlockMatchKind)> = Vec::new();
    let mut by_hash: BTreeMap<&str, VecDeque<usize>> = BTreeMap::new();
    for (j, h) in hashes_b.iter().enumerate() {
        by_hash.entry(h.as_str()).or_default().push_back(j);
    }
    let mut rest_a: Vec<usize> = Vec::new();
    for (i, h) in hashes_a.iter().enumerate() {
        match by_hash
            .get_mut(h.as_str())
            .and_then(|q| take_live(q, &used_b))
        {
            Some(j) => {
                used_a_blk[i] = true;
                used_b[j] = true;
                matched.push((i, j, BlockMatchKind::Hash));
            }
            None => rest_a.push(i),
        }
    }
    // Leftover blocks pair by address-order position (the `values` order
    // above is block-start order); counts may differ, so extras stay
    // unmatched on the longer side.
    let rest_b: Vec<usize> = (0..blocks_b.len()).filter(|j| !used_b[*j]).collect();
    for (&i, &j) in rest_a.iter().zip(rest_b.iter()) {
        used_a_blk[i] = true;
        used_b[j] = true;
        matched.push((i, j, BlockMatchKind::Position));
    }
    matched.sort_by_key(|(i, _j, _)| blocks_a[*i].start);

    let mut blocks = Vec::with_capacity(matched.len());
    let mut summary = FuncDiffSummary {
        matched_blocks: matched.len(),
        added_blocks: 0,
        removed_blocks: 0,
        same_insns: 0,
        changed_insns: 0,
        added_insns: 0,
        removed_insns: 0,
        truncated: false,
    };
    for (i, j, kind) in matched {
        let (edits, truncated) = block_edits(arch_a, blocks_a[i], arch_b, blocks_b[j]);
        for e in &edits {
            match e.kind {
                EditKind::Same => summary.same_insns += 1,
                EditKind::Changed => summary.changed_insns += 1,
                EditKind::Added => summary.added_insns += 1,
                EditKind::Removed => summary.removed_insns += 1,
            }
        }
        summary.truncated |= truncated;
        blocks.push(BlockDiff {
            start_a: blocks_a[i].start,
            start_b: blocks_b[j].start,
            kind,
            ir_hash_a: hashes_a[i].clone(),
            ir_hash_b: hashes_b[j].clone(),
            truncated,
            edits,
        });
    }
    let mut added_blocks: Vec<BlockRow> = blocks_b
        .iter()
        .enumerate()
        .filter(|(j, _)| !used_b[*j])
        .map(|(j, blk)| BlockRow {
            start: blk.start,
            insns: blk.insns.len(),
            ir_hash: hashes_b[j].clone(),
        })
        .collect();
    let mut removed_blocks: Vec<BlockRow> = blocks_a
        .iter()
        .enumerate()
        .filter(|(i, _)| !used_a_blk[*i])
        .map(|(i, blk)| BlockRow {
            start: blk.start,
            insns: blk.insns.len(),
            ir_hash: hashes_a[i].clone(),
        })
        .collect();
    added_blocks.sort_by_key(|r| r.start);
    removed_blocks.sort_by_key(|r| r.start);
    summary.added_blocks = added_blocks.len();
    summary.removed_blocks = removed_blocks.len();

    Ok(FuncDiffReport {
        binary_a: a.path().display().to_string(),
        binary_b: b.path().display().to_string(),
        arch_a: crate::db::arch_name(arch_a).to_string(),
        arch_b: crate::db::arch_name(arch_b).to_string(),
        entry_a,
        entry_b,
        name_a: a.function_name(entry_a),
        name_b: b.function_name(entry_b),
        paired,
        reason,
        summary,
        blocks,
        added_blocks,
        removed_blocks,
    })
}

/// Cap on emitted edit rows per matched block in [`diff_func`]: longer
/// scripts clip to this with `truncated` set.
pub const MAX_EDITS_PER_BLOCK: usize = 128;

/// LCS cell budget per matched block in [`diff_func`]: blocks whose
/// instruction-count product exceeds this fall back to positional pairing
/// instead of paying quadratic dynamic programming.
const MAX_LCS_CELLS: usize = 4096;

/// Normalized-IR hash of one block: SHA-256 over the concatenated
/// per-instruction op encodings (same encoding as [`fingerprints`], so
/// same semantics under different encodings or bases hash equally).
fn block_ir_hash(arch: Arch, block: &BasicBlock) -> String {
    let mut joined: Vec<u8> = Vec::new();
    for key in insn_ir_keys(arch, &block.insns) {
        joined.extend_from_slice(key.as_bytes());
    }
    crate::annotations::sha256_hex(&joined)
}

/// Per-instruction normalized-IR keys for one block, in address order.
fn insn_ir_keys(arch: Arch, insns: &[Insn]) -> Vec<String> {
    insns
        .iter()
        .map(|insn| {
            let mut key: Vec<u8> = Vec::new();
            for lifted in crate::ir::lift(arch, insn) {
                key.extend_from_slice(lifted.op.name().as_bytes());
                key.push(u8::from(lifted.warning.is_some()));
                key.push(b';');
            }
            String::from_utf8_lossy(&key).into_owned()
        })
        .collect()
}

/// One raw alignment between two blocks' instruction sequences.
enum RawEdit {
    /// Aligned positions (keys may still differ under positional fallback).
    Same(usize, usize),
    /// Side-A position with no B counterpart.
    Del(usize),
    /// Side-B position with no A counterpart.
    Ins(usize),
}

/// Align two key sequences: LCS under [`MAX_LCS_CELLS`], else positional.
///
/// LCS aligns only equal keys, so every `Same` it emits has identical IR;
/// the positional fallback aligns by index and leaves key comparison to
/// the row conversion.
fn raw_edits(a_keys: &[String], b_keys: &[String]) -> Vec<RawEdit> {
    let (m, n) = (a_keys.len(), b_keys.len());
    if (m + 1).saturating_mul(n + 1) > MAX_LCS_CELLS {
        let mut out = Vec::with_capacity(m.max(n));
        for k in 0..m.max(n) {
            match (k < m, k < n) {
                (true, true) => out.push(RawEdit::Same(k, k)),
                (true, false) => out.push(RawEdit::Del(k)),
                (false, true) => out.push(RawEdit::Ins(k)),
                (false, false) => {}
            }
        }
        return out;
    }
    let stride = n + 1;
    let mut dp = vec![0usize; (m + 1) * stride];
    for i in 1..=m {
        for j in 1..=n {
            dp[i * stride + j] = if a_keys[i - 1] == b_keys[j - 1] {
                dp[(i - 1) * stride + j - 1] + 1
            } else {
                dp[(i - 1) * stride + j].max(dp[i * stride + j - 1])
            };
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (m, n);
    while i > 0 && j > 0 {
        if a_keys[i - 1] == b_keys[j - 1] {
            out.push(RawEdit::Same(i - 1, j - 1));
            i -= 1;
            j -= 1;
        } else if dp[(i - 1) * stride + j] >= dp[i * stride + j - 1] {
            out.push(RawEdit::Del(i - 1));
            i -= 1;
        } else {
            out.push(RawEdit::Ins(j - 1));
            j -= 1;
        }
    }
    while i > 0 {
        out.push(RawEdit::Del(i - 1));
        i -= 1;
    }
    while j > 0 {
        out.push(RawEdit::Ins(j - 1));
        j -= 1;
    }
    out.reverse();
    out
}

/// Render one instruction as `mnem` plus comma-separated operands.
fn insn_text(insn: &Insn) -> String {
    if insn.ops.is_empty() {
        insn.mnem.clone()
    } else {
        format!("{} {}", insn.mnem, insn.ops.join(", "))
    }
}

/// Bounded instruction edit script between two matched blocks.
///
/// Returns the rows (clipped to [`MAX_EDITS_PER_BLOCK`] with `truncated`
/// set when longer) for `edits` in address order.
fn block_edits(
    arch_a: Arch,
    a: &BasicBlock,
    arch_b: Arch,
    b: &BasicBlock,
) -> (Vec<InsnEdit>, bool) {
    let keys_a = insn_ir_keys(arch_a, &a.insns);
    let keys_b = insn_ir_keys(arch_b, &b.insns);
    let mut edits: Vec<InsnEdit> = Vec::new();
    let mut dels: Vec<usize> = Vec::new();
    let mut inss: Vec<usize> = Vec::new();
    let flush = |edits: &mut Vec<InsnEdit>, dels: &mut Vec<usize>, inss: &mut Vec<usize>| {
        let mut ds = dels.drain(..);
        let mut is = inss.drain(..);
        loop {
            match (ds.next(), is.next()) {
                (Some(i), Some(j)) => edits.push(InsnEdit {
                    kind: EditKind::Changed,
                    addr_a: Some(a.insns[i].addr),
                    addr_b: Some(b.insns[j].addr),
                    text_a: Some(insn_text(&a.insns[i])),
                    text_b: Some(insn_text(&b.insns[j])),
                }),
                (Some(i), None) => edits.push(InsnEdit {
                    kind: EditKind::Removed,
                    addr_a: Some(a.insns[i].addr),
                    addr_b: None,
                    text_a: Some(insn_text(&a.insns[i])),
                    text_b: None,
                }),
                (None, Some(j)) => edits.push(InsnEdit {
                    kind: EditKind::Added,
                    addr_a: None,
                    addr_b: Some(b.insns[j].addr),
                    text_a: None,
                    text_b: Some(insn_text(&b.insns[j])),
                }),
                (None, None) => break,
            }
        }
    };
    for edit in raw_edits(&keys_a, &keys_b) {
        match edit {
            RawEdit::Same(i, j) => {
                flush(&mut edits, &mut dels, &mut inss);
                let same_ir = keys_a[i] == keys_b[j];
                let same_bytes = a.insns[i].bytes == b.insns[j].bytes;
                edits.push(InsnEdit {
                    kind: if same_ir && same_bytes {
                        EditKind::Same
                    } else {
                        EditKind::Changed
                    },
                    addr_a: Some(a.insns[i].addr),
                    addr_b: Some(b.insns[j].addr),
                    text_a: Some(insn_text(&a.insns[i])),
                    text_b: Some(insn_text(&b.insns[j])),
                });
            }
            RawEdit::Del(i) => dels.push(i),
            RawEdit::Ins(j) => inss.push(j),
        }
    }
    flush(&mut edits, &mut dels, &mut inss);
    let truncated = edits.len() > MAX_EDITS_PER_BLOCK;
    if truncated {
        edits.truncate(MAX_EDITS_PER_BLOCK);
    }
    (edits, truncated)
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
    use super::{N_OPS, ir_similarity, xref_shape};
    use crate::analysis::{Xref, XrefKind};

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

    /// Brute-force oracle for [`xref_shape`]: the old per-function scan.
    fn brute(xrefs: &[Xref], range: Option<(u64, u64)>) -> (usize, usize) {
        let in_range = |addr: u64| range.is_some_and(|(lo, hi)| addr >= lo && addr < hi);
        let mut out = 0;
        let mut inn = 0;
        for x in xrefs {
            out += usize::from(in_range(x.from));
            inn += usize::from(in_range(x.to));
        }
        (out, inn)
    }

    #[test]
    fn xref_shape_matches_scan_on_boundaries_and_gaps() {
        // Duplicate endpoints, shared `from`s, and endpoints landing
        // exactly on range edges pin the half-open semantics.
        let xrefs = [
            (0x1000, 0x2000),
            (0x1000, 0x2005),
            (0x1004, 0x1000),
            (0x1010, 0x3000),
            (0x2000, 0x1004),
        ]
        .map(|(from, to)| Xref {
            from,
            to,
            kind: XrefKind::Code,
        });
        let mut froms: Vec<u64> = xrefs.iter().map(|x| x.from).collect();
        froms.sort_unstable();
        let mut tos: Vec<u64> = xrefs.iter().map(|x| x.to).collect();
        tos.sort_unstable();
        for range in [
            None,
            Some((0x1000, 0x1000)),
            Some((0x1000, 0x1001)),
            Some((0x1000, 0x1010)),
            Some((0x1000, 0x1011)),
            Some((0x1004, 0x2000)),
            Some((0x0, u64::MAX)),
            Some((0x4000, 0x5000)),
        ] {
            assert_eq!(
                xref_shape(&froms, &tos, range),
                brute(&xrefs, range),
                "{range:?}"
            );
        }
        assert_eq!(xref_shape(&[], &[], Some((0, 10))), (0, 0));
    }
}
