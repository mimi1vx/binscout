//! M4 analysis: function discovery, CFGs, callgraph, xrefs, queries.
//!
//! [`analyze`] runs recursive descent over [`LoadedBinary`]: starting from
//! the entry point and export addresses, it decodes one instruction at a time
//! (`decode_one()`), follows direct branches and calls, and falls back to a
//! prologue scan for functions unreachable from those seeds. Decoded code is
//! split into basic blocks, each function gets a CFG and the whole binary a
//! callgraph (both `petgraph` maps), and cross-references are split into
//! code, data, string, and import refs.
//!
//! Control flow reuses the M3 lift ([`lift`](crate::ir::lift)): `Branch`/`CBranch`/`Call`
//! carry their direct target, `Return` ends a path, everything else
//! (including unlifted `Nop`) falls through. Known gaps: indirect jumps and
//! `loop`-style branches have no target, so those edges are missing rather
//! than guessed.
//!
//! Function boundaries are entry/export addresses, direct call targets, and
//! prologue-scan hits outside already-decoded code; every other block belongs
//! to the nearest entry at or below its start. Shared tails can therefore be
//! attributed to one function only.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::sync::OnceLock;

use memchr::{memchr2, memchr3};
use petgraph::graphmap::DiGraphMap;
use serde::{Deserialize, Serialize};

use crate::disasm::{Arch, Insn, resolve_adrp_pair};
use crate::error::{Error, Result};
use crate::ir::IrOp;
use crate::loader::strings::{self, Encoding, StringHit};
use crate::loader::{BinaryFormat, LoadedBinary, RawOptions, Section, Segment, load_raw};

/// Cap on decoded instructions per [`analyze`] call.
pub const MAX_TOTAL_INSNS: usize = 1_000_000;
/// Cap on discovered function entries per [`analyze`] call.
pub const MAX_FUNCTIONS: usize = 100_000;
/// Cap on cross-references of each kind per [`analyze`] call.
pub const MAX_XREFS_PER_KIND: usize = 1_000_000;
/// Cap on discovery seeds (entry/exports/prologues) per call.
pub const MAX_SEEDS: usize = 100_000;
/// Revision of the analysis engine covered by cached snapshots.
///
/// Bumped whenever [`analyze`] output for identical bytes and mappings can
/// change; [`crate::db`] treats a stored revision mismatch as stale and
/// re-analyzes while carrying same-mapping annotations forward.
pub const ANALYSIS_REVISION: u32 = 8;
/// Cap on retained diagnostic records per [`analyze`] call.
///
/// When discovery yields more sites than this, analysis continues and the
/// excess is counted in [`Diagnostics::omitted`] with [`Diagnostics::truncated`]
/// set; hard analysis budgets still
/// return [`Error::Limit`].
pub const MAX_DIAGNOSTICS: usize = 100_000;
/// Cap on recovered single-slot indirect-jump edges per site.
///
/// The approved single-slot pattern is a singleton by construction (one slot
/// holds one target), so a site yields at most one edge; the constant states
/// that structural bound against the investigation's 1024/site ceiling
/// (`1 <= 1024`). Multi-entry tables have their own per-site cap (see
/// [`MAX_TABLE_ENTRIES_PER_SITE`]).
pub const MAX_INFERRED_PER_SITE: usize = 1;
/// Cap on recovered table entries per guarded scaled-index site.
///
/// The scan reads consecutive valid slots from the typed table base and
/// stops at the first slot that fails validation (unmapped, truncated,
/// non-executable, non-decoding, or cross-function). A run that is still
/// valid at this length is not a bounded table but an open-ended index:
/// the whole site stays unresolved rather than partially recovered
/// (exact-or-reject). Runs shorter than [`MIN_TABLE_ENTRIES_PER_SITE`]
/// are indistinguishable from stray pointers and stay unresolved too.
pub const MAX_TABLE_ENTRIES_PER_SITE: usize = 8;
/// Minimum consecutive valid slots for a table site to resolve.
///
/// Singleton runs fall back to the single-slot path (which owns the typed
/// `mem_target` shapes); an indexed site with fewer valid slots than this
/// keeps its diagnostic.
pub const MIN_TABLE_ENTRIES_PER_SITE: usize = 2;
/// How far back from a table site the index-guard search walks.
///
/// Counts decoded instructions in reverse address order within the site's
/// function. A guarded switch checks its index just before indexing
/// (`cmp` + a direct conditional branch to the default path); an unguarded
/// scaled-index jump has an unbounded index and is unrecoverable.
pub const MAX_TABLE_GUARD_BACKTRACK: usize = 4;
/// Cap on recovered single-slot indirect-jump edges per [`analyze`] call.
///
/// On exhaustion the site stays unresolved with its diagnostic retained and
/// the excess is counted in [`Diagnostics::inferred_omitted`] with
/// [`Diagnostics::inferred_truncated`] set, never silently clipped from the
/// inferred graph.
pub const MAX_INFERRED_EDGES: usize = 100_000;
/// Query pages longer than this are truncated.
pub const MAX_PAGE: usize = 1024;
/// Cap on transitive callgraph hops per query.
///
/// Bounds BFS in [`Analysis::callees_transitive`] and
/// [`Analysis::callers_transitive`]: deeper requests clip to this depth
/// so a large depth cannot inflate work past one bounded walk over the
/// function set.
pub const MAX_CALL_DEPTH: usize = 64;
/// Cap on backward-slice hops per query.
///
/// Bounds BFS in [`Analysis::slice_to`]: deeper requests clip to this
/// depth so a large depth cannot inflate work past one bounded walk
/// over the instruction set. Mirrors [`MAX_CALL_DEPTH`]: direct
/// predecessors are depth 1, zero yields an empty set.
pub const MAX_SLICE_DEPTH: usize = 64;

/// What a cross-reference points through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum XrefKind {
    /// Branch/call target reference.
    Code,
    /// Data access reference (PC-relative slot or absolute pointer).
    Data,
    /// Reference into an extracted string.
    String,
    /// Import call-site reference: an indirect `call`/`jmp` through a PE
    /// IAT or ELF GOT slot, or a direct `call`/`jmp` to a PLT stub or
    /// import thunk. `to` is the import's slot address (see
    /// [`ImportRef::address`](crate::loader::ImportRef::address)); the
    /// `Data` slot row (indirect sites) and the `Code` stub row (direct
    /// sites) are retained alongside, so import rows are purely additive.
    Import,
    /// Provenance-marked inferred code edge: a resolved single-slot
    /// absolute indirect jump or a resolved guarded table entry
    /// (`site -> target`). Direct edges stay
    /// [`XrefKind::Code`]; counts jointly against the `Code` per-kind
    /// budget so inferred rows cannot evade the cap by relabeling.
    /// Wire form is kebab-case (`inferred-code`); the direct kinds keep
    /// their historical CamelCase spelling.
    #[serde(rename = "inferred-code")]
    InferredCode,
}

/// One cross-reference: instruction at `from` refers to `to`.
///
/// JSON pairs each endpoint with its `0x`-hex twin (`from_hex`, `to_hex`);
/// old rows without the twins still deserialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Xref {
    /// Address of the referring instruction.
    pub from: u64,
    /// Referenced address (code target, data address, or string start).
    pub to: u64,
    /// How the reference is made.
    pub kind: XrefKind,
}

impl Serialize for Xref {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("Xref", 5)?;
        st.serialize_field("from", &self.from)?;
        st.serialize_field("from_hex", &crate::addr_hex(self.from))?;
        st.serialize_field("to", &self.to)?;
        st.serialize_field("to_hex", &crate::addr_hex(self.to))?;
        st.serialize_field("kind", &self.kind)?;
        st.end()
    }
}

/// Why a function entry was discovered.
///
/// Evidence about how analysis reached an entry, not a confidence score
/// or a verified-boundary claim. Reasons coexist: one entry can be the
/// binary entry point, an export, a direct-call target, and a prologue
/// hit at once. Stored sorted and deduplicated.
///
/// Wire form is kebab-case (`entry`, `export`, `symbol`, `direct-call`,
/// `prologue`); pre-provenance rows in the historical CamelCase spelling
/// still decode via aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryReason {
    /// Binary entry point (or the fallback first executable byte when no
    /// entry or export seeds analysis).
    #[serde(alias = "Entry")]
    Entry,
    /// Export address resolving to executable code.
    #[serde(alias = "Export")]
    Export,
    /// Symbol-table address (locals included) resolving to executable
    /// code.
    #[serde(alias = "Symbol")]
    Symbol,
    /// Direct call target followed during recursive descent.
    #[serde(alias = "DirectCall")]
    DirectCall,
    /// Prologue-scan hit outside round-one reached code.
    #[serde(alias = "Prologue")]
    Prologue,
}

/// What an analysis diagnostic records.
///
/// Evidence about where analysis is incomplete, not a confidence score.
/// Unresolved sites stay unresolved: they never become proven CFG or
/// callgraph edges. A clean decode with a `Return` terminator is valid
/// termination, never a [`DiagnosticKind::DecodeFailure`].
///
/// Wire form is kebab-case (`unresolved-indirect-jump`,
/// `unresolved-indirect-call`, `decode-failure`); rows persisted under
/// the historical CamelCase spelling still decode via aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticKind {
    /// Branch without a direct target (`Branch`/`CBranch` with no target
    /// from the lift: indirect forms and unsupported `loop`-style
    /// branches). The site stays edgeless.
    #[serde(alias = "UnresolvedIndirectJump")]
    UnresolvedIndirectJump,
    /// Call without a direct target. The site stays edgeless.
    #[serde(alias = "UnresolvedIndirectCall")]
    UnresolvedIndirectCall,
    /// Executable bytes at a discovery address that did not decode.
    /// Only queued discovery addresses are recorded, never every
    /// undecoded byte in the binary.
    #[serde(alias = "DecodeFailure")]
    DecodeFailure,
}

/// One analysis diagnostic: an incomplete-analysis site.
///
/// JSON pairs `addr` with `addr_hex`; old rows without the twin still
/// deserialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub struct Diagnostic {
    /// Address of the unresolved instruction or failed decode.
    pub addr: u64,
    /// What is incomplete at `addr`.
    pub kind: DiagnosticKind,
}

impl Serialize for Diagnostic {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("Diagnostic", 3)?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("kind", &self.kind)?;
        st.end()
    }
}

/// One diagnostics row: the site plus its containing function and detail.
///
/// JSON pairs `addr` with `addr_hex` and `func` with `func_hex` (`func`
/// is null on both sides when the site lies in no function).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DiagnosticRow {
    /// What is incomplete at `addr`.
    pub kind: DiagnosticKind,
    /// Address of the unresolved instruction or failed decode.
    pub addr: u64,
    /// Entry of the function containing `addr`, if any.
    pub func: Option<u64>,
    /// Kind-specific detail: what is incomplete at the site.
    pub detail: String,
}

impl Serialize for DiagnosticRow {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("DiagnosticRow", 6)?;
        st.serialize_field("kind", &self.kind)?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("func", &self.func)?;
        st.serialize_field("func_hex", &self.func.map(crate::addr_hex))?;
        st.serialize_field("detail", &self.detail)?;
        st.end()
    }
}

/// Kind-specific detail for a diagnostics row: what is incomplete at the site.
///
/// Static evidence text derived from the kind itself, never a fabricated
/// confidence claim or a proof of complete recovery.
#[must_use]
pub fn diagnostic_detail(kind: DiagnosticKind) -> &'static str {
    match kind {
        DiagnosticKind::UnresolvedIndirectJump => {
            "indirect jump without a direct target; the site stays edgeless"
        }
        DiagnosticKind::UnresolvedIndirectCall => {
            "indirect call without a direct target; the site stays edgeless"
        }
        DiagnosticKind::DecodeFailure => {
            "executable bytes at a queued discovery address that did not decode"
        }
    }
}

/// Bounded diagnostic record set for one analysis.
///
/// `records` stay sorted by `(addr, kind)` with at most [`MAX_DIAGNOSTICS`]
/// entries; on cap exhaustion analysis continues and the excess is counted
/// in [`Diagnostics::omitted`] with [`Diagnostics::truncated`] set. Hard
/// analysis budgets still return [`Error::Limit`]
/// rather than a truncated partial result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostics {
    /// Retained records sorted by `(addr, kind)`.
    pub records: Vec<Diagnostic>,
    /// Whether discovery produced more records than [`MAX_DIAGNOSTICS`].
    pub truncated: bool,
    /// Records omitted by the [`MAX_DIAGNOSTICS`] cap (zero unless
    /// [`Diagnostics::truncated`]).
    pub omitted: usize,
    /// Whether indirect-jump resolution produced more edges than
    /// [`MAX_INFERRED_EDGES`].
    pub inferred_truncated: bool,
    /// Edges omitted by the [`MAX_INFERRED_EDGES`] cap (zero unless
    /// [`Diagnostics::inferred_truncated`]); skipped sites stay unresolved
    /// with their diagnostic retained.
    pub inferred_omitted: usize,
}

impl Diagnostics {
    /// Empty record set: no diagnostics, nothing omitted.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Sort, deduplicate, and cap `records`.
    ///
    /// Fresh analysis passes `false`/`0` and learns the flags here; the
    /// rebuild path re-applies the cap defensively so a forged snapshot
    /// cannot smuggle an unbounded record list past the reader.
    #[must_use]
    pub fn collect(records: Vec<Diagnostic>, truncated: bool, omitted: usize) -> Self {
        let mut sorted = records;
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() > MAX_DIAGNOSTICS {
            let excess = sorted.len() - MAX_DIAGNOSTICS;
            sorted.truncate(MAX_DIAGNOSTICS);
            Self {
                records: sorted,
                truncated: true,
                omitted: omitted.saturating_add(excess),
                inferred_truncated: false,
                inferred_omitted: 0,
            }
        } else {
            Self {
                records: sorted,
                truncated,
                omitted,
                inferred_truncated: false,
                inferred_omitted: 0,
            }
        }
    }
}

/// One basic block: a maximal run with a single entry at `start`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    /// Address of the first instruction; the block's stable key.
    pub start: u64,
    /// Decoded instructions in address order.
    pub insns: Vec<Insn>,
}

impl BasicBlock {
    /// End address (one past the last instruction's last byte).
    #[must_use]
    pub fn end(&self) -> u64 {
        self.insns
            .last()
            .map(|i| i.addr.wrapping_add(u64::from(i.size)))
            .unwrap_or(self.start)
    }

    /// Stable ID: `block@{func_entry:#x}+{start:#x}`.
    #[must_use]
    pub fn id(&self, func_entry: u64) -> String {
        format!("block@{func_entry:#x}+{:#x}", self.start)
    }
}

/// One discovered function with its control-flow graph.
#[derive(Debug, Clone)]
pub struct Function {
    /// Function entry address; the stable key.
    pub entry: u64,
    /// Export, symbol, stub-import, PLT (`sym@plt`), or thunk name when
    /// one resolves to `entry`.
    pub name: Option<String>,
    /// Basic blocks keyed by start address.
    pub blocks: BTreeMap<u64, BasicBlock>,
    cfg: DiGraphMap<u64, ()>,
    /// Provenance-marked inferred block edges (`from_block -> to_block`)
    /// from resolved single-slot indirect jumps and guarded table entries.
    /// Direct edges stay in
    /// `cfg` (see [`Function::edges`]); inferred edges never become
    /// callgraph edges or new function entries.
    inferred: BTreeSet<(u64, u64)>,
    /// How this entry was discovered, sorted and deduplicated.
    ///
    /// Evidence, not confidence: coexisting [`DiscoveryReason`]s record
    /// every seed path that reached this entry.
    pub reasons: BTreeSet<DiscoveryReason>,
}

impl Function {
    /// Stable ID: `func@{entry:#x}`.
    #[must_use]
    pub fn id(&self) -> String {
        format!("func@{:#x}", self.entry)
    }

    /// Total instructions across all blocks.
    #[must_use]
    pub fn insn_count(&self) -> usize {
        self.blocks.values().map(|b| b.insns.len()).sum()
    }

    /// Successor block starts of `block`.
    #[must_use]
    pub fn successors(&self, block: u64) -> Vec<u64> {
        self.cfg.neighbors(block).collect()
    }

    /// Predecessor block starts of `block`.
    ///
    /// Reverse of [`Function::successors`] over the direct CFG only;
    /// inferred single-slot resolutions are covered separately through
    /// their provenance-marked [`XrefKind::InferredCode`] xrefs, so the
    /// backward slice needs no second edge set here.
    #[must_use]
    pub fn predecessors(&self, block: u64) -> Vec<u64> {
        self.cfg
            .neighbors_directed(block, petgraph::Direction::Incoming)
            .collect()
    }

    /// All CFG edges as `(from_block, to_block)` pairs.
    ///
    /// Direct edges only; inferred single-slot resolutions live in
    /// [`Function::inferred_edges`].
    #[must_use]
    pub fn edges(&self) -> Vec<(u64, u64)> {
        self.cfg.all_edges().map(|(a, b, _)| (a, b)).collect()
    }

    /// Inferred block edges as sorted `(from_block, to_block)` pairs.
    ///
    /// Provenance-marked indirect-jump resolutions: at most one per site
    /// for the single-slot shape (see [`MAX_INFERRED_PER_SITE`]), up to
    /// [`MAX_TABLE_ENTRIES_PER_SITE`] for a guarded table site.
    /// Same-function only: these never become callgraph edges or new
    /// function entries.
    #[must_use]
    pub fn inferred_edges(&self) -> Vec<(u64, u64)> {
        self.inferred.iter().copied().collect()
    }

    /// Sorted, deduplicated discovery reasons.
    #[must_use]
    pub fn reason_list(&self) -> Vec<DiscoveryReason> {
        self.reasons.iter().copied().collect()
    }

    /// Rebuild a function from persisted rows (M5 redb round-trip).
    ///
    /// `edges` are `(from_block, to_block)` pairs within this function;
    /// `inferred` are the provenance-marked inferred pairs, replayed with
    /// the same unknown-endpoint drop as `edges`. `reasons` may arrive in
    /// any order with duplicates and are stored sorted and deduplicated.
    #[must_use]
    pub fn from_parts(
        entry: u64,
        name: Option<String>,
        blocks: BTreeMap<u64, BasicBlock>,
        edges: &[(u64, u64)],
        reasons: Vec<DiscoveryReason>,
        inferred: &[(u64, u64)],
    ) -> Self {
        let mut cfg = DiGraphMap::new();
        for &start in blocks.keys() {
            cfg.add_node(start);
        }
        for &(a, b) in edges {
            if blocks.contains_key(&a) && blocks.contains_key(&b) {
                cfg.add_edge(a, b, ());
            }
        }
        let mut inferred_set = BTreeSet::new();
        for &(a, b) in inferred {
            if blocks.contains_key(&a) && blocks.contains_key(&b) {
                inferred_set.insert((a, b));
            }
        }
        Self {
            entry,
            name,
            blocks,
            cfg,
            inferred: inferred_set,
            reasons: reasons.into_iter().collect(),
        }
    }
}

/// Approximate per-function structural warning.
///
/// Loops and ifs are syntactic patterns over the direct CFG plus the M3
/// lift (`Branch`/`CBranch` targets): a back edge is not a proven loop and
/// a two-successor `CBranch` site is not a proven if. Agents must treat the
/// rows as hints, never as decompiler output.
pub const STRUCTURE_WARNING: &str = "approximate structure over CFG+IR: back edges and two-successor branch sites are syntactic hints, not verified loops/ifs; not a decompiler";

/// One syntactic loop: CFG back edges into a shared header.
///
/// `header` is the back-edge target (the cycle entry); `latches` are the
/// sorted sources of back edges into it. A self-edge (`header` in
/// `latches`) is the tightest loop shape.
///
/// JSON pairs `header` with `header_hex`; `latches` stays a plain integer
/// array.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LoopInfo {
    /// Back-edge target: the loop header block start.
    pub header: u64,
    /// Sorted sources of back edges into `header`.
    pub latches: Vec<u64>,
}

impl Serialize for LoopInfo {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("LoopInfo", 3)?;
        st.serialize_field("header", &self.header)?;
        st.serialize_field("header_hex", &crate::addr_hex(self.header))?;
        st.serialize_field("latches", &self.latches)?;
        st.end()
    }
}

/// One syntactic if: a `CBranch`-terminated block with two successors.
///
/// `then_target` is the taken branch (the lift's direct target when it is
/// one of the successors, else the lower successor); `else_target` is the
/// other successor (usually fallthrough).
///
/// JSON pairs each address with its `0x`-hex twin (`cond`/`cond_hex`,
/// `then_target`/`then_hex`, `else_target`/`else_hex`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct IfInfo {
    /// Start of the branching block.
    pub cond: u64,
    /// Taken-branch successor.
    pub then_target: u64,
    /// Fallthrough/other successor.
    pub else_target: u64,
}

impl Serialize for IfInfo {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("IfInfo", 6)?;
        st.serialize_field("cond", &self.cond)?;
        st.serialize_field("cond_hex", &crate::addr_hex(self.cond))?;
        st.serialize_field("then_target", &self.then_target)?;
        st.serialize_field("then_hex", &crate::addr_hex(self.then_target))?;
        st.serialize_field("else_target", &self.else_target)?;
        st.serialize_field("else_hex", &crate::addr_hex(self.else_target))?;
        st.end()
    }
}

/// Approximate control-flow structure of one function.
///
/// `loops` sort by header, `ifs` by `cond`, so repeated queries agree.
/// `warning` is always [`STRUCTURE_WARNING`]: the rows are syntactic
/// hints over the CFG plus the M3 lift, never verified control flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuncStructure {
    /// Syntactic loops ordered by header.
    pub loops: Vec<LoopInfo>,
    /// Syntactic ifs ordered by `cond`.
    pub ifs: Vec<IfInfo>,
    /// Always [`STRUCTURE_WARNING`].
    pub warning: String,
}

impl Function {
    /// Approximate control-flow structure: syntactic loops and ifs.
    ///
    /// Loops are direct-CFG back edges: one iterative depth-first walk over
    /// ascending block starts (gray means on the DFS stack); an edge to a
    /// gray node closes a cycle, grouped by header with sorted latches.
    /// Ifs are blocks whose terminator lifts (see [`crate::ir::lift`]) to
    /// [`IrOp::CBranch`] with exactly two direct-CFG successors. Pure
    /// read-only pass over `blocks`/`cfg` plus the control-flow check; inferred
    /// single-slot edges never participate.
    #[must_use]
    pub fn structure(&self, arch: Arch) -> FuncStructure {
        // Iterative DFS with sorted successors for deterministic output.
        // `gray` holds the current stack path; an edge into it is a back
        // edge (latch = source, header = target).
        let mut gray: BTreeSet<u64> = BTreeSet::new();
        let mut black: BTreeSet<u64> = BTreeSet::new();
        let mut back_edges: Vec<(u64, u64)> = Vec::new();
        for &root in self.blocks.keys() {
            if gray.contains(&root) || black.contains(&root) {
                continue;
            }
            gray.insert(root);
            let mut stack: Vec<(u64, std::vec::IntoIter<u64>)> =
                vec![(root, sorted_succs(self, root))];
            while let Some((node, nexts)) = stack.last_mut() {
                let node = *node;
                match nexts.next() {
                    Some(next) => {
                        if gray.contains(&next) {
                            back_edges.push((node, next));
                        } else if !black.contains(&next) {
                            gray.insert(next);
                            stack.push((next, sorted_succs(self, next)));
                        }
                    }
                    None => {
                        let (done, _) = stack.pop().expect("nonempty stack pops");
                        gray.remove(&done);
                        black.insert(done);
                    }
                }
            }
        }
        let mut by_header: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for (latch, header) in back_edges {
            by_header.entry(header).or_default().push(latch);
        }
        let loops = by_header
            .into_iter()
            .map(|(header, mut latches)| {
                latches.sort_unstable();
                latches.dedup();
                LoopInfo { header, latches }
            })
            .collect();

        let mut ifs: Vec<IfInfo> = Vec::new();
        for (start, block) in &self.blocks {
            let Some(last) = block.insns.last() else {
                continue;
            };
            let Some((IrOp::CBranch, target)) = crate::ir::control_op(arch, last) else {
                continue;
            };
            let mut succs = self.successors(*start);
            if succs.len() != 2 {
                continue;
            }
            succs.sort_unstable();
            let (then_target, else_target) = match target {
                Some(t) if succs.contains(&t) => {
                    (t, if succs[0] == t { succs[1] } else { succs[0] })
                }
                _ => (succs[0], succs[1]),
            };
            ifs.push(IfInfo {
                cond: *start,
                then_target,
                else_target,
            });
        }
        ifs.sort_by_key(|i| i.cond);

        FuncStructure {
            loops,
            ifs,
            warning: STRUCTURE_WARNING.to_string(),
        }
    }
}

/// Sorted direct-CFG successors of `block` for deterministic DFS order.
fn sorted_succs(func: &Function, block: u64) -> std::vec::IntoIter<u64> {
    let mut succs = func.successors(block);
    succs.sort_unstable();
    succs.into_iter()
}

/// Whole-binary analysis result.
#[derive(Debug, Clone)]
pub struct Analysis {
    /// Disassembler target the binary was decoded as.
    pub arch: Arch,
    /// Discovered functions keyed by entry address.
    pub functions: BTreeMap<u64, Function>,
    callgraph: DiGraphMap<u64, ()>,
    /// Code, data, string, and import xrefs sorted by `(from, kind, to)`.
    pub xrefs: Vec<Xref>,
    /// Lazily built secondary index: positions into [`xrefs`](Self::xrefs)
    /// sorted by (`to`, `from`, `kind`), so `to` queries binary-search
    /// instead of scanning. Built once on first use; never persisted (the
    /// sidecar stores rows in `from` order and the index rebuilds on open).
    to_index: OnceLock<Vec<u32>>,
    /// PLT-stub/import-thunk sites: `jmp [slot]` address to `imports`
    /// index (x86 PE/ELF only; see [`import_slots`]).
    pub import_stubs: BTreeMap<u64, usize>,
    /// Extracted strings sorted by address.
    pub strings: Vec<StringHit>,
    /// Bounded discovery evidence: unresolved sites and decode failures.
    pub diagnostics: Diagnostics,
}

impl Analysis {
    /// Entry of the function containing `va`, if any.
    ///
    /// Takes the nearest entry at or below `va` (the same attribution
    /// [`analyze`] uses for block ownership) and returns it only when `va`
    /// lies inside one of that function's blocks. Gaps between functions
    /// report `None` rather than snapping to a neighbor.
    #[must_use]
    pub fn containing_function(&self, va: u64) -> Option<u64> {
        let (&entry, func) = self.functions.range(..=va).next_back()?;
        func.blocks
            .values()
            .any(|b| va >= b.start && va < b.end())
            .then_some(entry)
    }

    /// Direct callees of `entry` (function entries only).
    #[must_use]
    pub fn calls_of(&self, entry: u64) -> Vec<u64> {
        let mut v: Vec<u64> = self.callgraph.neighbors(entry).collect();
        v.sort_unstable();
        v
    }

    /// Count of direct callees of `entry` (function entries only).
    ///
    /// The same set as [`Analysis::calls_of`] without materializing the
    /// sorted target array, for compact metadata over large callgraphs.
    #[must_use]
    pub fn calls_count(&self, entry: u64) -> usize {
        self.callgraph.neighbors(entry).count()
    }

    /// Direct callers of `entry` (function entries only).
    #[must_use]
    pub fn callers_of(&self, entry: u64) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .callgraph
            .neighbors_directed(entry, petgraph::Direction::Incoming)
            .collect();
        v.sort_unstable();
        v
    }

    /// Transitive callees of `entry` as `(target, depth)` pairs.
    ///
    /// Breadth-first walk over the callgraph out to `max_depth` edges from
    /// `entry`; `depth` is the shortest distance (direct callees are depth
    /// 1). The walk clips `max_depth` to [`MAX_CALL_DEPTH`], guards cycles
    /// with a visited set, and never reports `entry` itself even when a
    /// cycle reaches it. Pairs sort by target entry for deterministic
    /// paging; a depth of zero yields an empty set, as does an unknown
    /// entry.
    #[must_use]
    pub fn callees_transitive(&self, entry: u64, max_depth: usize) -> Vec<(u64, usize)> {
        self.reachable(entry, max_depth, petgraph::Direction::Outgoing)
    }

    /// Transitive callers of `entry` as `(target, depth)` pairs.
    ///
    /// Mirror of [`Analysis::callees_transitive`] over incoming edges:
    /// breadth-first, clipped to [`MAX_CALL_DEPTH`], cycle-guarded, never
    /// reporting `entry` itself, sorted by target entry. Depth zero or an
    /// unknown entry yields an empty set.
    #[must_use]
    pub fn callers_transitive(&self, entry: u64, max_depth: usize) -> Vec<(u64, usize)> {
        self.reachable(entry, max_depth, petgraph::Direction::Incoming)
    }

    /// Backward slice of `addr` as `(addr, depth)` pairs.
    ///
    /// Bounded reverse walk over xref edges (every [`XrefKind`]: code,
    /// data, string, and inferred-code) plus intra-function CFG
    /// predecessors at instruction granularity: the previous
    /// instruction in the same block, or the last instruction of each
    /// predecessor block (see [`Function::predecessors`]) at block
    /// starts. Breadth-first out to `max_depth` hops, clipped to
    /// [`MAX_SLICE_DEPTH`], cycle-guarded with a visited set, never
    /// reporting `addr` itself even when a cycle reaches it. Pairs sort
    /// by address for deterministic paging; a depth of zero yields an
    /// empty set. Any address is a valid root (data/string targets lie
    /// in no function and contribute only xref predecessors), so unlike
    /// the callgraph walks there is no unknown-entry case.
    #[must_use]
    pub fn slice_to(&self, addr: u64, max_depth: usize) -> Vec<(u64, usize)> {
        use std::collections::{HashSet, VecDeque};
        let cap = max_depth.min(MAX_SLICE_DEPTH);
        if cap == 0 {
            return Vec::new();
        }
        let idx = self.to_index();
        let mut seen: HashSet<u64> = HashSet::from([addr]);
        let mut queue: VecDeque<(u64, usize)> = VecDeque::from([(addr, 0)]);
        let mut out: Vec<(u64, usize)> = Vec::new();
        while let Some((cur, depth)) = queue.pop_front() {
            if depth >= cap {
                continue;
            }
            let mut next: Vec<u64> = Vec::new();
            let (lo, hi) = self.span_to(idx, cur);
            next.extend(idx[lo..hi].iter().map(|&i| self.xrefs[i as usize].from));
            next.extend(self.insn_preds(cur));
            next.sort_unstable();
            next.dedup();
            for n in next {
                if seen.insert(n) {
                    out.push((n, depth + 1));
                    queue.push_back((n, depth + 1));
                }
            }
        }
        out.sort_unstable();
        out
    }

    /// Instruction predecessors of `cur` within its function, if any.
    ///
    /// The previous instruction in the same block, or at a block start
    /// the last instruction of each direct predecessor block. Empty
    /// when `cur` lies in no function, in no block, or mid-instruction
    /// (an arbitrary root with only xref predecessors).
    fn insn_preds(&self, cur: u64) -> Vec<u64> {
        let Some(entry) = self.containing_function(cur) else {
            return Vec::new();
        };
        let Some(f) = self.functions.get(&entry) else {
            return Vec::new();
        };
        let Some((&start, block)) = f
            .blocks
            .range(..=cur)
            .next_back()
            .filter(|(_, b)| cur < b.end())
        else {
            return Vec::new();
        };
        match block.insns.iter().position(|i| i.addr == cur) {
            Some(i) if i > 0 => vec![block.insns[i - 1].addr],
            Some(_) => {
                let mut preds = f.predecessors(start);
                preds.sort_unstable();
                let mut out = Vec::new();
                for p in preds {
                    if let Some(last) = f.blocks.get(&p).and_then(|b| b.insns.last()) {
                        out.push(last.addr);
                    }
                }
                out
            }
            None => Vec::new(),
        }
    }

    /// Breadth-first reachable set in one callgraph direction.
    fn reachable(
        &self,
        entry: u64,
        max_depth: usize,
        dir: petgraph::Direction,
    ) -> Vec<(u64, usize)> {
        use std::collections::{HashSet, VecDeque};
        let cap = max_depth.min(MAX_CALL_DEPTH);
        if cap == 0 || !self.callgraph.contains_node(entry) {
            return Vec::new();
        }
        let mut seen: HashSet<u64> = HashSet::from([entry]);
        let mut queue: VecDeque<(u64, usize)> = VecDeque::new();
        queue.push_back((entry, 0));
        let mut out: Vec<(u64, usize)> = Vec::new();
        while let Some((cur, depth)) = queue.pop_front() {
            if depth >= cap {
                continue;
            }
            let mut next: Vec<u64> = self.callgraph.neighbors_directed(cur, dir).collect();
            next.sort_unstable();
            for n in next {
                if seen.insert(n) {
                    out.push((n, depth + 1));
                    queue.push_back((n, depth + 1));
                }
            }
        }
        out.sort_unstable();
        out
    }

    /// Approximate control-flow structure of the function at `entry`, if known.
    ///
    /// Read-only [`Function::structure`] over the direct CFG plus the M3
    /// lift: syntactic loops and ifs with the [`STRUCTURE_WARNING`]
    /// marker. `None` for an unknown entry (callers snap addresses with
    /// [`Analysis::containing_function`] first, as
    /// [`crate::Project::structure_of`] does).
    #[must_use]
    pub fn structure_of(&self, entry: u64) -> Option<FuncStructure> {
        self.functions.get(&entry).map(|f| f.structure(self.arch))
    }

    /// All callgraph edges as `(caller, callee)` pairs.
    #[must_use]
    pub fn call_edges(&self) -> Vec<(u64, u64)> {
        self.callgraph.all_edges().map(|(a, b, _)| (a, b)).collect()
    }

    /// Rebuild analysis from persisted rows (M5 redb round-trip).
    ///
    /// Drops call edges pointing at unknown functions, mirroring [`analyze`].
    /// `diagnostics` records are sorted, deduplicated, and capped at
    /// [`MAX_DIAGNOSTICS`] via [`Diagnostics::collect`]. `xrefs` are sorted
    /// into `(from, kind, to)` order when the caller passes them unsorted
    /// (snapshot rows already arrive sorted, so the check is one linear
    /// pass); the binary-search queries require that order.
    #[must_use]
    pub fn from_parts(
        arch: Arch,
        functions: BTreeMap<u64, Function>,
        call_edges: &[(u64, u64)],
        xrefs: Vec<Xref>,
        strings: Vec<StringHit>,
        diagnostics: Diagnostics,
    ) -> Self {
        let mut xrefs = xrefs;
        if !xrefs.is_sorted_by_key(|x| (x.from, x.kind, x.to)) {
            xrefs.sort_by_key(|x| (x.from, x.kind, x.to));
        }
        let mut callgraph = DiGraphMap::<u64, ()>::new();
        for e in functions.keys() {
            callgraph.add_node(*e);
        }
        for &(a, b) in call_edges {
            if functions.contains_key(&a) && functions.contains_key(&b) {
                callgraph.add_edge(a, b, ());
            }
        }
        let inferred_truncated = diagnostics.inferred_truncated;
        let inferred_omitted = diagnostics.inferred_omitted;
        let mut diagnostics = Diagnostics::collect(
            diagnostics.records,
            diagnostics.truncated,
            diagnostics.omitted,
        );
        diagnostics.inferred_truncated = inferred_truncated;
        diagnostics.inferred_omitted = inferred_omitted;
        Self {
            arch,
            functions,
            callgraph,
            xrefs,
            to_index: OnceLock::new(),
            import_stubs: BTreeMap::new(),
            strings,
            diagnostics,
        }
    }
}

/// Persisted block shape: address range, per-instruction boundaries, and
/// successors — no rendered instructions.
///
/// Snapshots store layouts and re-decode instructions from the binary on
/// open (see [`rebuild`]): caching rendered [`Insn`] rows as JSON made a
/// 1.5 MB binary produce a 70+ MB snapshot, so derived text is never
/// persisted. Boundaries are per instruction (not just the range) because
/// recursive descent can record overlapping decodes of one region from
/// different paths; replaying each recorded address reproduces the block
/// bit-identically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockLayout {
    /// Address of the first instruction.
    pub start: u64,
    /// End address (one past the last byte).
    pub end: u64,
    /// `(address, size)` of every instruction in address order.
    pub insns: Vec<InsnLayout>,
    /// Successor block starts.
    pub succs: Vec<u64>,
    /// Inferred successor block starts from resolved single-slot indirect
    /// jumps and guarded table entries; direct successors stay in
    /// [`BlockLayout::succs`].
    ///
    /// Defaults to empty so layouts written before inference still decode;
    /// such snapshots never hit the cache (their analysis revision
    /// mismatches) and re-analyze instead.
    #[serde(default)]
    pub inferred_succs: Vec<u64>,
}

/// Persisted instruction boundary: address plus byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsnLayout {
    /// Virtual address of the first byte.
    pub addr: u64,
    /// Length in bytes.
    pub size: u8,
}

/// Persisted function shape: entry, name, callees, and block layouts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionLayout {
    /// Function entry address.
    pub entry: u64,
    /// Export name or rename, if any.
    pub name: Option<String>,
    /// Sorted direct callees.
    pub calls: Vec<u64>,
    /// Block layouts in address order.
    pub blocks: Vec<BlockLayout>,
    /// Sorted, deduplicated discovery reasons.
    ///
    /// Defaults to empty so layouts written before provenance tracking
    /// still decode; such snapshots never hit the cache (their analysis
    /// revision mismatches) and re-analyze instead.
    #[serde(default)]
    pub reasons: Vec<DiscoveryReason>,
}

/// Flatten an analysis into persistable layouts.
///
/// Successor lists and call targets are sorted so snapshots are
/// deterministic across processes.
#[must_use]
pub fn layout(analysis: &Analysis) -> Vec<FunctionLayout> {
    analysis
        .functions
        .values()
        .map(|f| {
            let mut calls = analysis.calls_of(f.entry);
            calls.sort_unstable();
            let blocks = f
                .blocks
                .values()
                .map(|b| {
                    let mut succs = f.successors(b.start);
                    succs.sort_unstable();
                    let insns = b
                        .insns
                        .iter()
                        .map(|i| InsnLayout {
                            addr: i.addr,
                            size: i.size,
                        })
                        .collect();
                    let mut inferred_succs: Vec<u64> = f
                        .inferred_edges()
                        .into_iter()
                        .filter(|(a, _)| *a == b.start)
                        .map(|(_, t)| t)
                        .collect();
                    inferred_succs.sort_unstable();
                    BlockLayout {
                        start: b.start,
                        end: b.end(),
                        insns,
                        succs,
                        inferred_succs,
                    }
                })
                .collect();
            FunctionLayout {
                entry: f.entry,
                name: f.name.clone(),
                calls,
                blocks,
                reasons: f.reason_list(),
            }
        })
        .collect()
}

/// Rebuild an analysis from persisted layouts by re-decoding each recorded
/// instruction address from `bin`.
///
/// Each address decodes independently with [`crate::disasm::disasm_first`]
/// exactly as the analysis walker does, so the reproduced instructions are
/// bit-identical to a fresh analysis of the same bytes — including blocks
/// where recursive descent recorded overlapping decodes from different
/// paths. A boundary that does not decode, or decodes to a different size,
/// is snapshot corruption and errors with [`Error::Storage`]. Total range
/// bytes are bounded by the mapped segments, so a forged snapshot cannot
/// decode past the binary.
///
/// `diagnostics` records are sorted, deduplicated, and capped at
/// [`MAX_DIAGNOSTICS`] via [`Diagnostics::collect`].
///
/// # Errors
/// [`Error::Storage`] on corrupt layouts (unknown function references are
/// dropped as in [`analyze`], but undecodable ranges error),
/// [`Error::Limit`] when layouts exceed analysis budgets.
pub fn rebuild(
    arch: Arch,
    bin: &LoadedBinary,
    functions: &[FunctionLayout],
    call_edges: &[(u64, u64)],
    xrefs: Vec<Xref>,
    strings: Vec<StringHit>,
    diagnostics: Diagnostics,
) -> Result<Analysis> {
    if functions.len() > MAX_FUNCTIONS {
        return Err(Error::Limit(format!("more than {MAX_FUNCTIONS} functions")));
    }
    if diagnostics.records.len() > MAX_DIAGNOSTICS + diagnostics.omitted {
        // Defensive: a forged snapshot cannot smuggle an unbounded list;
        // the db reader already caps rows, this guards direct callers.
        return Err(Error::Limit(format!(
            "more than {MAX_DIAGNOSTICS} diagnostics"
        )));
    }
    let space = AddrSpace::new(bin);
    let mapped: u64 = bin.segments.iter().map(|s| s.data.len() as u64).sum();
    let mut ranged: u64 = 0;
    let mut rebuilt: BTreeMap<u64, Function> = BTreeMap::new();
    for f in functions {
        let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();
        let mut edges: Vec<(u64, u64)> = Vec::new();
        let mut inferred: Vec<(u64, u64)> = Vec::new();
        for b in &f.blocks {
            let len = b.end.wrapping_sub(b.start);
            ranged = ranged
                .checked_add(len)
                .filter(|m| *m <= mapped)
                .ok_or_else(|| {
                    Error::Storage(format!(
                        "snapshot block {:#x} exceeds mapped bytes",
                        b.start
                    ))
                })?;
            blocks.insert(b.start, decode_block(arch, &space, b)?);
            edges.extend(b.succs.iter().map(|s| (b.start, *s)));
            inferred.extend(b.inferred_succs.iter().map(|s| (b.start, *s)));
        }
        rebuilt.insert(
            f.entry,
            Function::from_parts(
                f.entry,
                f.name.clone(),
                blocks,
                &edges,
                f.reasons.clone(),
                &inferred,
            ),
        );
    }
    Ok({
        let mut analysis =
            Analysis::from_parts(arch, rebuilt, call_edges, xrefs, strings, diagnostics);
        // Snapshots persist layouts, not rendered rows: re-decoded
        // instructions need the same import tags and stub map `analyze`
        // applies, so cached opens answer identically to fresh ones.
        let slots = import_slots(bin);
        let stubs: BTreeMap<u64, usize> = if matches!(arch, Arch::X86_64 | Arch::X86_32) {
            collect_stubs(
                analysis
                    .functions
                    .values()
                    .flat_map(|f| f.blocks.values())
                    .flat_map(|b| b.insns.iter())
                    .map(|insn| {
                        (
                            insn.addr,
                            flow_of(arch, insn),
                            insn.mem_target,
                            insn.mnem.as_str(),
                            insn.size,
                        )
                    }),
                &slots,
            )
        } else {
            BTreeMap::new()
        };
        for f in analysis.functions.values_mut() {
            for b in f.blocks.values_mut() {
                for insn in &mut b.insns {
                    if let Some(i) =
                        import_index(&slots, &stubs, insn.branch_target, insn.mem_target)
                        && let Some(imp) = bin.imports.get(i)
                    {
                        insn.import = Some(imp.name.clone());
                    }
                }
            }
        }
        analysis.import_stubs = stubs;
        analysis
    })
}

/// Re-decode one persisted block instruction by instruction.
///
/// Replays every recorded `(address, size)` boundary independently, so
/// overlapping decodes reproduce exactly. Anything but a clean replay that
/// ends at the stored `end` is corruption.
fn decode_block(arch: Arch, space: &AddrSpace, layout: &BlockLayout) -> Result<BasicBlock> {
    let mut insns = Vec::with_capacity(layout.insns.len());
    for boundary in &layout.insns {
        let bytes = space.code_bytes(boundary.addr).ok_or_else(|| {
            Error::Storage(format!(
                "snapshot block {:#x} leaves executable bytes",
                layout.start
            ))
        })?;
        let Some(insn) = crate::disasm::disasm_first(arch, bytes, boundary.addr).map_err(|e| {
            Error::Storage(format!(
                "snapshot block {:#x} does not decode: {e}",
                layout.start
            ))
        })?
        else {
            return Err(Error::Storage(format!(
                "snapshot block {:#x} has no bytes at {:#x}",
                layout.start, boundary.addr
            )));
        };
        if insn.size != boundary.size {
            return Err(Error::Storage(format!(
                "snapshot block {:#x} decodes {:#x} as {} bytes, not {}",
                layout.start, boundary.addr, insn.size, boundary.size
            )));
        }
        insns.push(insn);
    }
    let block = BasicBlock {
        start: layout.start,
        insns,
    };
    if block.end() != layout.end {
        return Err(Error::Storage(format!(
            "snapshot block {:#x} ends at {:#x}, not {:#x}",
            layout.start,
            block.end(),
            layout.end
        )));
    }
    Ok(block)
}

/// Outcome counts for agent planning and golden tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisSummary {
    /// Discovered functions.
    pub functions: usize,
    /// Basic blocks across all functions.
    pub blocks: usize,
    /// Decoded instructions across all blocks.
    pub insns: usize,
    /// Recorded cross-references.
    pub xrefs: usize,
    /// Extracted strings.
    pub strings: usize,
}

/// One function row for list views.
///
/// JSON pairs `entry` with `entry_hex`; `calls` stays a plain integer array
/// (positional address lists have no per-element twins).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FunctionSummary {
    /// Stable ID (`func@0x...`).
    pub id: String,
    /// Function entry address.
    pub entry: u64,
    /// Rename, if one is set.
    pub name: Option<String>,
    /// Basic block count.
    pub blocks: usize,
    /// Instruction count across all blocks.
    pub insns: usize,
    /// Sorted direct call targets.
    pub calls: Vec<u64>,
}

impl Serialize for FunctionSummary {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("FunctionSummary", 7)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("entry", &self.entry)?;
        st.serialize_field("entry_hex", &crate::addr_hex(self.entry))?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("blocks", &self.blocks)?;
        st.serialize_field("insns", &self.insns)?;
        st.serialize_field("calls", &self.calls)?;
        st.end()
    }
}

/// One block row for list views (instructions come via [`Analysis::block_insns`]).
///
/// JSON pairs `start`/`end` with `start_hex`/`end_hex`; `succs` stays a
/// plain integer array.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlockSummary {
    /// Stable ID (`block@func+start`, both hex).
    pub id: String,
    /// Address of the first instruction.
    pub start: u64,
    /// End address (one past the last instruction's last byte).
    pub end: u64,
    /// Instruction count.
    pub insns: usize,
    /// Successor block starts.
    pub succs: Vec<u64>,
}

impl Serialize for BlockSummary {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("BlockSummary", 7)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("start", &self.start)?;
        st.serialize_field("start_hex", &crate::addr_hex(self.start))?;
        st.serialize_field("end", &self.end)?;
        st.serialize_field("end_hex", &crate::addr_hex(self.end))?;
        st.serialize_field("insns", &self.insns)?;
        st.serialize_field("succs", &self.succs)?;
        st.end()
    }
}

fn truncate_limit(limit: usize) -> usize {
    limit.min(MAX_PAGE)
}

/// Filters for [`Analysis::strings_page_filtered`]: every present field must
/// match. Paging (`start`/`limit`) applies after filtering.
#[derive(Debug, Clone)]
pub struct StringsFilter {
    /// Case-sensitive substring, or `regex:`-prefixed expression; `None`
    /// disables. An explicit pattern also shows executable-memory hits.
    pub pattern: Option<String>,
    /// Keep strings with at least this many characters; `None` disables.
    /// Filters stored hits (extracted at length 4), so smaller values show
    /// everything stored.
    pub min_len: Option<usize>,
    /// Keep strings in exactly this section; `None` hides executable-memory
    /// hits instead of narrowing. Naming an executable section (e.g.
    /// `.text`) shows its strings.
    pub section: Option<String>,
    /// Show strings in executable memory (hidden by default).
    pub include_code: bool,
    /// Rows to skip after filtering (`start` replaces the old `offset`
    /// paging name, which collided with the per-row file offset).
    pub start: usize,
    /// Max rows (capped at [`MAX_PAGE`]).
    pub limit: usize,
}

impl Default for StringsFilter {
    fn default() -> Self {
        Self {
            pattern: None,
            min_len: None,
            section: None,
            include_code: false,
            start: 0,
            limit: 50,
        }
    }
}

fn page_slice<T: Clone>(items: &[T], offset: usize, limit: usize) -> Vec<T> {
    items
        .iter()
        .skip(offset)
        .take(truncate_limit(limit))
        .cloned()
        .collect()
}

/// Count a match stream while collecting one page: one pass, no intermediate
/// vector. `offset` skips that many matches, `cap` is the already-clipped
/// page size, so `limit == 0` still reports the exact count.
fn count_and_page(
    matches: impl Iterator<Item = Xref>,
    offset: usize,
    cap: usize,
) -> (usize, Vec<Xref>) {
    let mut total = 0usize;
    let mut page = Vec::new();
    for x in matches {
        if total >= offset && page.len() < cap {
            page.push(x);
        }
        total += 1;
    }
    (total, page)
}

impl Analysis {
    /// Counters over the whole result.
    #[must_use]
    pub fn summary(&self) -> AnalysisSummary {
        AnalysisSummary {
            functions: self.functions.len(),
            blocks: self.functions.values().map(|f| f.blocks.len()).sum(),
            insns: self.functions.values().map(|f| f.insn_count()).sum(),
            xrefs: self.xrefs.len(),
            strings: self.strings.len(),
        }
    }

    /// Function rows ordered by entry, paged.
    #[must_use]
    pub fn functions_page(&self, offset: usize, limit: usize) -> Vec<FunctionSummary> {
        self.functions
            .values()
            .skip(offset)
            .take(truncate_limit(limit))
            .map(|f| FunctionSummary {
                id: f.id(),
                entry: f.entry,
                name: f.name.clone(),
                blocks: f.blocks.len(),
                insns: f.insn_count(),
                calls: self.calls_of(f.entry),
            })
            .collect()
    }

    /// Block rows for one function ordered by start, paged.
    #[must_use]
    pub fn blocks_page(
        &self,
        func_entry: u64,
        offset: usize,
        limit: usize,
    ) -> Option<Vec<BlockSummary>> {
        let f = self.functions.get(&func_entry)?;
        Some(
            f.blocks
                .values()
                .skip(offset)
                .take(truncate_limit(limit))
                .map(|b| BlockSummary {
                    id: b.id(func_entry),
                    start: b.start,
                    end: b.end(),
                    insns: b.insns.len(),
                    succs: f.successors(b.start),
                })
                .collect(),
        )
    }

    /// Instructions of one block in address order, paged.
    #[must_use]
    pub fn block_insns(
        &self,
        func_entry: u64,
        block_start: u64,
        offset: usize,
        limit: usize,
    ) -> Option<Vec<Insn>> {
        let b = self.functions.get(&func_entry)?.blocks.get(&block_start)?;
        Some(page_slice(&b.insns, offset, limit))
    }

    /// Xrefs of one kind (or all when `kind` is `None`), paged.
    #[must_use]
    pub fn xrefs_page(&self, kind: Option<XrefKind>, offset: usize, limit: usize) -> Vec<Xref> {
        let cap = truncate_limit(limit);
        match kind {
            Some(k) => self
                .xrefs
                .iter()
                .copied()
                .filter(|x| x.kind == k)
                .skip(offset)
                .take(cap)
                .collect(),
            None => self.xrefs.iter().copied().skip(offset).take(cap).collect(),
        }
    }

    /// Positions into [`xrefs`](Self::xrefs) sorted by (`to`, `from`,
    /// `kind`), built once on first use.
    ///
    /// Repeated `to` queries and slices share this one build plus a binary
    /// search each instead of paying a linear scan per request.
    fn to_index(&self) -> &[u32] {
        self.to_index.get_or_init(|| {
            let mut idx: Vec<u32> = (0..self.xrefs.len()).map(|i| i as u32).collect();
            idx.sort_by_key(|&i| {
                let x = &self.xrefs[i as usize];
                (x.to, x.from, x.kind)
            });
            idx
        })
    }

    /// Half-open span of [`xrefs`](Self::xrefs) with `from == addr`, via
    /// binary search (rows are sorted `(from, kind, to)`).
    fn span_from(&self, addr: u64) -> (usize, usize) {
        let lo = self.xrefs.partition_point(|x| x.from < addr);
        let hi = self.xrefs.partition_point(|x| x.from <= addr);
        (lo, hi)
    }

    /// Half-open span of `idx` (see [`to_index`](Self::to_index)) whose rows
    /// point at `addr`.
    fn span_to(&self, idx: &[u32], addr: u64) -> (usize, usize) {
        let lo = idx.partition_point(|&i| self.xrefs[i as usize].to < addr);
        let hi = idx.partition_point(|&i| self.xrefs[i as usize].to <= addr);
        (lo, hi)
    }

    /// Xrefs pointing at `addr`, in `(from, kind)` order.
    ///
    /// Binary-searches the `to_index` span instead of
    /// scanning: for a fixed `to` the index order is `(from, kind)`, the
    /// same rows the old linear filter returned.
    #[must_use]
    pub fn xrefs_to(&self, addr: u64) -> Vec<Xref> {
        let idx = self.to_index();
        let (lo, hi) = self.span_to(idx, addr);
        idx[lo..hi]
            .iter()
            .map(|&i| self.xrefs[i as usize])
            .collect()
    }

    /// Xrefs originating at `addr`, in `(kind, to)` order.
    ///
    /// Binary-searches the `(from, kind, to)`-sorted rows instead of
    /// scanning; the span keeps storage order, as before.
    #[must_use]
    pub fn xrefs_from(&self, addr: u64) -> Vec<Xref> {
        let (lo, hi) = self.span_from(addr);
        self.xrefs[lo..hi].to_vec()
    }

    /// Xrefs matching the endpoint/kind filters with the pre-page count, in
    /// one pass.
    ///
    /// Rows come in storage order, as the old filter-then-page path
    /// reported: a `from` filter narrows to one binary-searched span, the
    /// unfiltered case scans, and a `to`-only filter walks the `to_index`
    /// span when it is already built (same row
    /// order for a fixed `to`) but falls back to one linear scan while it
    /// is cold — a single request does one lookup, which a scan answers
    /// faster than building the index, while slices and repeated lookups
    /// amortize the build. `limit` clips to [`MAX_PAGE`]; an `offset` past
    /// the end yields an empty page with the exact count.
    #[must_use]
    pub fn xrefs_matching_page(
        &self,
        to: Option<u64>,
        from: Option<u64>,
        kind: Option<XrefKind>,
        offset: usize,
        limit: usize,
    ) -> (usize, Vec<Xref>) {
        let cap = truncate_limit(limit);
        if let Some(f) = from {
            let (lo, hi) = self.span_from(f);
            return count_and_page(
                self.xrefs[lo..hi]
                    .iter()
                    .copied()
                    .filter(move |x| to.is_none_or(|t| x.to == t))
                    .filter(move |x| kind.is_none_or(|k| x.kind == k)),
                offset,
                cap,
            );
        }
        if let Some(t) = to {
            if let Some(idx) = self.to_index.get() {
                let (lo, hi) = self.span_to(idx, t);
                return count_and_page(
                    idx[lo..hi]
                        .iter()
                        .map(|&i| self.xrefs[i as usize])
                        .filter(move |x| kind.is_none_or(|k| x.kind == k)),
                    offset,
                    cap,
                );
            }
            return count_and_page(
                self.xrefs
                    .iter()
                    .copied()
                    .filter(|x| x.to == t)
                    .filter(move |x| kind.is_none_or(|k| x.kind == k)),
                offset,
                cap,
            );
        }
        count_and_page(
            self.xrefs
                .iter()
                .copied()
                .filter(move |x| kind.is_none_or(|k| x.kind == k)),
            offset,
            cap,
        )
    }

    /// Diagnostics filtered by kind and containing function, ordered by
    /// (`kind`, `addr`).
    ///
    /// Filtering precedes paging: callers page this exact set, so the
    /// reported total is the filtered count. `func` is an already-snapped
    /// function entry; sites whose
    /// [`Analysis::containing_function`] differs are dropped. Storage
    /// keeps `(addr, kind)` order; this re-sorts by `(kind, addr)` per
    /// the protocol-1 contract.
    #[must_use]
    pub fn diagnostics_matching(
        &self,
        kind: Option<DiagnosticKind>,
        func: Option<u64>,
    ) -> Vec<Diagnostic> {
        let mut out: Vec<Diagnostic> = self
            .diagnostics
            .records
            .iter()
            .copied()
            .filter(|d| kind.is_none_or(|k| d.kind == k))
            .filter(|d| func.is_none_or(|e| self.containing_function(d.addr) == Some(e)))
            .collect();
        out.sort_by_key(|d| (d.kind, d.addr));
        out
    }

    /// Extracted strings ordered by address, paged.
    ///
    /// Shows every hit, including executable-memory noise;
    /// [`Analysis::strings_page_filtered`] is the default-view query behind
    /// the CLI/MCP `strings` command.
    #[must_use]
    pub fn strings_page(&self, offset: usize, limit: usize) -> Vec<StringHit> {
        page_slice(&self.strings, offset, limit)
    }

    /// Extracted strings ordered by address, filtered then paged.
    ///
    /// Strings in executable memory (code bytes decoded as text) are hidden
    /// unless the query opts back in with [`StringsFilter::include_code`]
    /// or narrows with `section`/`pattern` — an explicit search sees
    /// everything. `section` is an exact name match, `min_len` counts
    /// characters, and `pattern` is a case-sensitive substring unless
    /// `regex:`-prefixed (see [`strings::matches_pattern`]).
    /// Filtering happens before paging so `start`/`limit` apply to dense
    /// matching rows.
    ///
    /// # Errors
    /// [`Error::Invalid`] when `pattern` is overlong or a `regex:`
    /// expression fails to compile.
    pub fn strings_page_filtered(&self, filter: &StringsFilter) -> Result<Vec<StringHit>> {
        filter_string_hits(&self.strings, filter)
    }

    /// Decoded-view strings: re-extract over an in-memory decoded copy.
    ///
    /// Each segment's bytes are transformed with `decode` (see
    /// [`strings::DecodeSpec`]), then extracted and section-tagged exactly
    /// like [`analyze`], so single-byte
    /// XOR/add/rot-obfuscated text shows up with its original offsets and
    /// virtual addresses. The same [`StringsFilter`] semantics apply to the
    /// decoded rows (a `pattern` matches decoded text). Strictly read-only:
    /// the binary and the sidecar are never written.
    ///
    /// # Errors
    /// [`Error::Invalid`] when `pattern` is overlong or a `regex:`
    /// expression fails to compile.
    pub fn strings_decoded_view(
        &self,
        bin: &LoadedBinary,
        filter: &StringsFilter,
        decode: strings::DecodeSpec,
    ) -> Result<Vec<StringHit>> {
        let mut hits: Vec<StringHit> = Vec::new();
        for seg in &bin.segments {
            let decoded = decode.apply(&seg.data);
            for mut h in strings::extract(
                &decoded,
                strings::DEFAULT_MIN_LEN,
                strings::DEFAULT_MAX_HITS,
                Some(seg.vaddr),
            ) {
                // Same tagging as `analyze`: sections win, raw blobs and
                // unmapped hits inherit the segment's flags.
                let (section, executable) = locate_hit(&bin.sections, seg, h.vaddr);
                h.section = section;
                h.executable = executable;
                hits.push(h);
            }
        }
        hits.sort_by_key(|h| h.vaddr.unwrap_or(u64::MAX));
        filter_string_hits(&hits, filter)
    }
}

/// Filter stored or decoded-view string hits, then page.
///
/// Shared by [`Analysis::strings_page_filtered`] and
/// [`Analysis::strings_decoded_view`] so the `strings --decode` view keeps
/// the default-view semantics (executable-memory hiding, lazy pattern
/// compile, filter-before-page).
///
/// # Errors
/// [`Error::Invalid`] when `filter.pattern` is overlong or a `regex:`
/// expression fails to compile.
fn filter_string_hits(hits: &[StringHit], filter: &StringsFilter) -> Result<Vec<StringHit>> {
    let show_code = filter.include_code || filter.section.is_some() || filter.pattern.is_some();
    // Compiled once, lazily at the first row reaching pattern evaluation:
    // a malformed/overlong pattern errors only when a row survives the
    // earlier filters, and costs zero compilations otherwise.
    let mut matcher: Option<strings::PatternMatcher<'_>> = None;
    let cap = truncate_limit(filter.limit);
    let start = filter.start;
    let mut out: Vec<StringHit> = Vec::new();
    let mut matched: usize = 0;
    for h in hits {
        if h.executable && !show_code {
            continue;
        }
        if let Some(sec) = &filter.section
            && h.section.as_deref() != Some(sec.as_str())
        {
            continue;
        }
        if let Some(min) = filter.min_len
            && h.value.chars().count() < min
        {
            continue;
        }
        if let Some(pat) = &filter.pattern {
            if matcher.is_none() {
                matcher = Some(strings::PatternMatcher::compile(pat)?);
            }
            let Some(m) = matcher.as_ref() else {
                continue;
            };
            if !m.is_match(&h.value) {
                continue;
            }
        }
        // Storage-order match at dense index `matched`; clone only the
        // selected page. Comparisons stay split (`matched >= start` plus
        // `out.len() < cap`) so `start + cap` can never overflow.
        if matched >= start && out.len() < cap {
            out.push(h.clone());
        }
        matched += 1;
        // No future row can fail once the matcher outcome is settled, so
        // a filled page ends the scan. With an uncompiled pattern the
        // outcome is unset (no eligible row seen yet), and the scan must
        // continue: this keeps zero-limit/beyond-end error semantics
        // identical to the old collect-all pass.
        if out.len() >= cap && (filter.pattern.is_none() || matcher.is_some()) {
            break;
        }
    }
    Ok(out)
}

/// Control-flow effect of one instruction, from its M3 lift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Seq,
    Branch { target: Option<u64> },
    CBranch { target: Option<u64> },
    Call { target: Option<u64> },
    Ret,
}

impl Flow {
    fn ends_block(self) -> bool {
        !matches!(self, Self::Seq)
    }
}

/// Control-flow effect of one instruction, without lifting (see
/// [`crate::ir::control_op`]). Matches `crate::ir::lift` restricted to
/// the control ops (see `control_op_matches_lift` in `tests/ir.rs`);
/// hot paths call this instead of lifting per instruction to skip the
/// IR allocation and the full mnemonic-table walk.
fn flow_of(arch: Arch, insn: &Insn) -> Flow {
    match crate::ir::control_op(arch, insn) {
        Some((IrOp::Branch, target)) => Flow::Branch { target },
        Some((IrOp::CBranch, target)) => Flow::CBranch { target },
        Some((IrOp::Call, target)) => Flow::Call { target },
        Some((IrOp::Return, _)) => Flow::Ret,
        _ => Flow::Seq,
    }
}

/// Resolve a string hit's section name and executability.
///
/// The first section containing `vaddr` wins; hits outside every section
/// (raw blobs, which have no table) inherit their segment's flags, and
/// unmapped hits fail open as non-executable data.
fn locate_hit(sections: &[Section], seg: &Segment, vaddr: Option<u64>) -> (Option<String>, bool) {
    let Some(va) = vaddr else {
        return (None, false);
    };
    if let Some(sec) = sections
        .iter()
        .find(|s| va >= s.vaddr && va.wrapping_sub(s.vaddr) < s.size)
    {
        return (Some(sec.name.clone()), sec.executable);
    }
    (None, seg.executable)
}

/// Addressable view over loaded segments.
struct AddrSpace<'a> {
    exec: Vec<&'a Segment>,
    all: Vec<&'a Segment>,
}

impl<'a> AddrSpace<'a> {
    fn new(bin: &'a LoadedBinary) -> Self {
        Self {
            exec: bin.segments.iter().filter(|s| s.executable).collect(),
            all: bin.segments.iter().collect(),
        }
    }

    fn seg_at(segs: &[&'a Segment], va: u64) -> Option<&'a Segment> {
        segs.iter()
            .find(|s| va >= s.vaddr && va.wrapping_sub(s.vaddr) < s.mem_size)
            .copied()
    }

    /// File-backed bytes at `va` within an executable segment, if any.
    fn code_bytes(&self, va: u64) -> Option<&'a [u8]> {
        let seg = Self::seg_at(&self.exec, va)?;
        let off = va.wrapping_sub(seg.vaddr) as usize;
        seg.data.get(off..)
    }

    /// Exactly `len` file-backed bytes at `va` within a single segment, if
    /// any.
    ///
    /// Data slots live outside executable segments, so unlike
    /// [`AddrSpace::code_bytes`] every segment is eligible; unlike
    /// `bytes_at` this never zero-pads. BSS/zero-fill tails, truncated
    /// tables, and cross-segment spans report `None` so the single-slot
    /// resolver rejects them instead of reading phantom bytes.
    fn file_bytes_at(&self, va: u64, len: usize) -> Option<&'a [u8]> {
        for seg in &self.all {
            let Some(off) = va.checked_sub(seg.vaddr) else {
                continue;
            };
            let Ok(off) = usize::try_from(off) else {
                continue;
            };
            let Some(end) = off.checked_add(len) else {
                continue;
            };
            if end <= seg.data.len() {
                return seg.data.get(off..end);
            }
        }
        None
    }

    /// Whether `va` lies in any loaded segment (backed or zero-fill).
    fn contains(&self, va: u64) -> bool {
        Self::seg_at(&self.all, va).is_some()
    }

    fn first_exec_base(&self) -> Option<u64> {
        self.exec.iter().map(|s| s.vaddr).min()
    }
}

/// Decode the single instruction at `va`.
///
/// Returns `None` when `va` has no executable bytes or they do not decode;
/// undecodable bytes end that path, they are not an error. Decodes only the
/// first instruction via [`crate::disasm::disasm_first`]: trailing bytes
/// cannot change the first decode, so no shrink-and-retry window over the
/// whole executable tail is needed.
fn decode_one(arch: Arch, space: &AddrSpace, va: u64) -> Result<Option<Insn>> {
    let bytes = match space.code_bytes(va) {
        Some(b) if !b.is_empty() => b,
        _ => return Ok(None),
    };
    match crate::disasm::disasm_first(arch, bytes, va) {
        Ok(v) => Ok(v),
        Err(Error::Invalid(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

struct Decoded {
    insn: Insn,
    flow: Flow,
}

/// Normalize a seed address for `arch`, clearing the ARM Thumb
/// interworking bit.
///
/// On ARM ELF, `e_entry` and `STT_FUNC` values carry bit 0 set for Thumb
/// functions, but ARM containers decode as [`Arch::Arm32`]: an odd seed
/// would read misaligned garbage. Returns the (possibly masked) address
/// plus whether the bit was set; callers record a diagnostic for masked
/// seeds. Structured for later interworking support: the flag marks the
/// seeds a Thumb-capable walker would decode as Thumb instead of masking.
fn normalize_arm_seed(arch: Arch, addr: u64) -> (u64, bool) {
    if arch == Arch::Arm32 && addr & 1 == 1 {
        (addr & !1, true)
    } else {
        (addr, false)
    }
}

/// Push one seed address, masking the ARM Thumb bit (see
/// [`normalize_arm_seed`]) and recording the odd address when masked.
fn push_seed(seeds: &mut Vec<u64>, diags: &mut Vec<Diagnostic>, arch: Arch, addr: u64) {
    let (addr, masked) = normalize_arm_seed(arch, addr);
    if masked {
        diags.push(Diagnostic {
            addr: addr | 1,
            kind: DiagnosticKind::DecodeFailure,
        });
    }
    seeds.push(addr);
}

/// Seed addresses from the entry point, exports, symbol-table entries,
/// and Mach-O stub entries resolving to executable code. When none exists
/// (raw blobs, stripped objects), the first executable byte seeds analysis
/// so some function is always found.
///
/// ARM32 seeds pass through [`normalize_arm_seed`]: masked seeds keep their
/// even address here and contribute a [`DiagnosticKind::DecodeFailure`] at
/// the odd address (a queued discovery address never decoded as given).
fn authoritative_seeds(space: &AddrSpace, bin: &LoadedBinary) -> (Vec<u64>, Vec<Diagnostic>) {
    let mut seeds: Vec<u64> = Vec::new();
    let mut diags: Vec<Diagnostic> = Vec::new();
    if let Some(entry) = bin.entry
        && space.code_bytes(entry).is_some()
    {
        push_seed(&mut seeds, &mut diags, bin.arch, entry);
    }
    for exp in &bin.exports {
        if let Some(addr) = exp.address
            && seeds.len() < MAX_SEEDS
            && space.code_bytes(addr).is_some()
        {
            push_seed(&mut seeds, &mut diags, bin.arch, addr);
        }
    }
    // Symbol-table code addresses (locals included): the only seed path
    // for static functions nothing calls. Loader-canonical already
    // (Thumb bit cleared), so they seed exactly as stored.
    for sym in &bin.symbols {
        if seeds.len() < MAX_SEEDS && space.code_bytes(sym.address).is_some() {
            seeds.push(sym.address);
        }
    }
    // Mach-O stub entries carry their import's address (see
    // `LoadedBinary.imports`): seeding them makes each stub its own
    // function even when no call targets it. Unmapped imports
    // (`address: None`) contribute nothing. PE/ELF addresses are data
    // slots, never code, so they must not seed.
    if bin.format == BinaryFormat::MachO {
        for imp in &bin.imports {
            if let Some(addr) = imp.address
                && seeds.len() < MAX_SEEDS
                && space.code_bytes(addr).is_some()
            {
                seeds.push(addr);
            }
        }
    }
    if seeds.is_empty()
        && let Some(base) = space.first_exec_base()
    {
        seeds.push(base);
    }
    seeds.sort_unstable();
    seeds.dedup();
    (seeds, diags)
}

/// Prologue-scan hits outside `reached` that decode. These seed the second
/// round and become entries; hits inside already-reached code stay plain code
/// so mid-function frame setups never split their function.
///
/// Candidates stream in ascending address order through a bounded k-way
/// merge over the executable segments (see [`CandStream`]): only the heap
/// (one entry per segment), the last address, and the accepted seeds are
/// stored, so dense prologue runs cannot inflate collection memory.
/// Rejected candidates (reached or undecodable) consume no budget: the
/// emitted seeds equal the sorted, deduped, filtered prefix the old
/// collect-all pass produced. x86 inputs past the budget previously stopped
/// in collection order; they now stop in the same sorted order as
/// below-budget inputs.
fn prologue_seeds(arch: Arch, space: &AddrSpace, reached: &BTreeSet<u64>) -> Result<Vec<u64>> {
    let mut streams: Vec<CandStream<'_>> = space
        .exec
        .iter()
        .map(|seg| CandStream::new(seg, arch))
        .collect();
    let mut heap: BinaryHeap<(Reverse<u64>, usize)> = BinaryHeap::with_capacity(streams.len());
    for (idx, stream) in streams.iter_mut().enumerate() {
        if let Some(va) = stream.next_candidate() {
            heap.push((Reverse(va), idx));
        }
    }
    let mut seeds: Vec<u64> = Vec::new();
    let mut last: Option<u64> = None;
    while seeds.len() < MAX_SEEDS {
        let Some((Reverse(va), idx)) = heap.pop() else {
            break;
        };
        if let Some(nxt) = streams[idx].next_candidate() {
            heap.push((Reverse(nxt), idx));
        }
        if last == Some(va) {
            continue;
        }
        last = Some(va);
        if !reached.contains(&va) && decode_one(arch, space, va)?.is_some() {
            seeds.push(va);
        }
    }
    Ok(seeds)
}

/// Multi-byte prologue patterns per architecture. Bare single-byte pushes are
/// deliberately excluded: they fire mid-function and would split functions at
/// every frame setup. `0x55`-led frames are still found via the following
/// `mov rbp, rsp`, adjusted back one byte.
fn prologue_patterns(arch: Arch) -> &'static [&'static [u8]] {
    match arch {
        Arch::X86_64 => &[
            &[0x48, 0x89, 0xE5],
            &[0x48, 0x83, 0xEC],
            &[0x48, 0x81, 0xEC],
            &[0xF3, 0x0F, 0x1E, 0xFA],
        ],
        Arch::X86_32 => &[&[0x89, 0xE5], &[0x83, 0xEC], &[0x81, 0xEC]],
        Arch::Aarch64 | Arch::Arm32 | Arch::Thumb => &[],
    }
}

/// How one [`CandStream`] recognizes a prologue at a byte offset.
#[derive(Debug, Clone, Copy)]
enum CandMatch {
    /// AArch64 `stp x29, x30, [sp, #imm]!` word under a mask.
    Aarch64,
    /// ARM32 `stmdb sp!, {..., lr}` word under a mask (any condition,
    /// including never-executed ones the decoder rejects).
    ArmPush,
    /// Thumb 16-bit `push {..., lr}` halfword, else the 32-bit ARM-form
    /// word, at halfword steps.
    Thumb,
    /// x86 byte patterns with a one-byte `push rbp`/`push ebp` step-back.
    X86,
}

/// Next offset at or after `from` (below `limit`) holding a possible x86
/// prologue first byte: `0x48`/`0xF3` on x86-64, `0x89`/`0x83`/`0x81` on
/// x86-32 (see [`prologue_patterns`]). SIMD scan via `memchr`; every
/// [`CandStream::match_at`] hit starts with one of these bytes, so skipped
/// offsets cannot match and the yielded candidates are unchanged.
fn next_x86_first_byte(arch: Arch, data: &[u8], from: usize, limit: usize) -> Option<usize> {
    let hay = data.get(from..limit)?;
    let rel = match arch {
        Arch::X86_64 => memchr2(0x48, 0xF3, hay)?,
        Arch::X86_32 => memchr3(0x89, 0x83, 0x81, hay)?,
        Arch::Aarch64 | Arch::Arm32 | Arch::Thumb => return None,
    };
    Some(from + rel)
}

/// One executable segment's prologue candidates in ascending address order.
///
/// Streams pattern matches without materializing them: offsets are visited
/// in the order their wrapped addresses sort, so merging streams with a
/// min-heap reproduces the old collect-sort-dedup order. Each address maps
/// as `vaddr.wrapping_add(offset)` (x86 additionally `wrapping_sub(1)` over
/// a leading `0x55`); offsets at or past `2^64 - vaddr` wrap low and sort
/// first, so iteration runs in two phases split at that boundary. Holds
/// only a cursor plus at most one deferred x86 edge address.
struct CandStream<'a> {
    data: &'a [u8],
    vaddr: u64,
    arch: Arch,
    kind: CandMatch,
    stride: usize,
    min_width: usize,
    split: usize,
    cur: usize,
    phase: u8,
    stash: Option<u64>,
}

impl<'a> CandStream<'a> {
    /// Stream over `seg`'s matches for `arch`, starting at the lowest
    /// sorting address.
    fn new(seg: &'a Segment, arch: Arch) -> Self {
        let (kind, stride, min_width) = match arch {
            Arch::Aarch64 => (CandMatch::Aarch64, 4, 4),
            Arch::Arm32 => (CandMatch::ArmPush, 4, 4),
            Arch::Thumb => (CandMatch::Thumb, 2, 2),
            Arch::X86_64 | Arch::X86_32 => (CandMatch::X86, 1, 2),
        };
        let len = seg.data.len();
        // First offset whose wrapped address sorts low (`0` when `vaddr`
        // is `0`: no wrap, everything sorts in offset order).
        let wrap_off = u64::MAX.wrapping_sub(seg.vaddr).wrapping_add(1);
        let split = (wrap_off.min(len as u64) as usize)
            .div_ceil(stride)
            .saturating_mul(stride)
            .min(len);
        Self {
            data: &seg.data,
            vaddr: seg.vaddr,
            arch,
            kind,
            stride,
            min_width,
            split,
            cur: split,
            phase: 0,
            stash: None,
        }
    }

    /// Next candidate address in ascending order, if any.
    fn next_candidate(&mut self) -> Option<u64> {
        loop {
            if self.phase == 0 {
                if self.cur >= self.data.len() {
                    self.phase = 1;
                    self.cur = 0;
                    continue;
                }
                let off = if matches!(self.kind, CandMatch::X86) {
                    let Some(hit) =
                        next_x86_first_byte(self.arch, self.data, self.cur, self.data.len())
                    else {
                        self.cur = self.data.len();
                        continue;
                    };
                    self.cur = hit + 1;
                    hit
                } else {
                    let off = self.cur;
                    self.cur += self.stride;
                    off
                };
                if off + self.min_width > self.data.len() {
                    self.cur = self.data.len();
                    continue;
                }
                if let Some(va) = self.match_at(off) {
                    // An x86 step-back exactly on the wrap point lands on
                    // `u64::MAX`, which sorts after the high run: defer it
                    // past phase 1. Only x86 adjusts, so other kinds never
                    // take this branch.
                    if matches!(self.kind, CandMatch::X86)
                        && va == u64::MAX
                        && self.vaddr.wrapping_add(off as u64) == 0
                    {
                        self.stash = Some(va);
                        continue;
                    }
                    return Some(va);
                }
            } else if self.phase == 1 {
                if self.cur >= self.split {
                    self.phase = 2;
                    continue;
                }
                let off = if matches!(self.kind, CandMatch::X86) {
                    let Some(hit) = next_x86_first_byte(self.arch, self.data, self.cur, self.split)
                    else {
                        self.cur = self.split;
                        continue;
                    };
                    self.cur = hit + 1;
                    hit
                } else {
                    let off = self.cur;
                    self.cur += self.stride;
                    off
                };
                if off + self.min_width > self.data.len() {
                    self.cur = self.split;
                    continue;
                }
                if let Some(va) = self.match_at(off) {
                    return Some(va);
                }
            } else {
                return self.stash.take();
            }
        }
    }

    /// Candidate address at `off`, if the bytes match. Bounds-checked per
    /// pattern; mirrors the old eager scan's match rules exactly.
    fn match_at(&self, off: usize) -> Option<u64> {
        let va = self.vaddr.wrapping_add(off as u64);
        match self.kind {
            CandMatch::Aarch64 => {
                let raw = self.data.get(off..off + 4)?;
                let w = u32::from_le_bytes(raw.try_into().ok()?);
                ((w & 0xFFC0_7FFF) == 0xA980_7BFD).then_some(va)
            }
            CandMatch::ArmPush => {
                let raw = self.data.get(off..off + 4)?;
                let w = u32::from_le_bytes(raw.try_into().ok()?);
                is_arm_push_lr(w).then_some(va)
            }
            CandMatch::Thumb => {
                let raw = self.data.get(off..off + 2)?;
                let hw = u16::from_le_bytes(raw.try_into().ok()?);
                if (hw & 0xFF00) == 0xB500 && (hw & 0x0100) != 0 {
                    Some(va)
                } else if off + 4 <= self.data.len() {
                    let raw = self.data.get(off..off + 4)?;
                    let w = u32::from_le_bytes(raw.try_into().ok()?);
                    is_arm_push_lr(w).then_some(va)
                } else {
                    None
                }
            }
            CandMatch::X86 => {
                for pat in prologue_patterns(self.arch) {
                    let Some(win) = self.data.get(off..off + pat.len()) else {
                        continue;
                    };
                    if win == *pat {
                        // `push rbp`/`push ebp` is 0x55 on both x86 targets.
                        if off > 0 && self.data[off - 1] == 0x55 {
                            return Some(va.wrapping_sub(1));
                        }
                        return Some(va);
                    }
                }
                None
            }
        }
    }
}

/// Whether a word is `stmdb sp!, {..., lr}` (any condition): the ARM32
/// frame-setup push, also valid as the 32-bit Thumb `push` encoding.
fn is_arm_push_lr(word: u32) -> bool {
    (word & 0x0FFF_4000) == 0x092D_4000
}

/// Recursive-descent worklist state shared across seed rounds.
struct Walker<'a> {
    arch: Arch,
    space: &'a AddrSpace<'a>,
    decoded: BTreeMap<u64, Decoded>,
    jump_targets: BTreeSet<u64>,
    fallthroughs: BTreeSet<u64>,
    call_targets: BTreeSet<u64>,
    diagnostics: BTreeSet<Diagnostic>,
    /// Remaining predicated slots in the open Thumb IT block, with the
    /// address expecting the next one. The single-instruction decoder is
    /// stateless, so the worklist carries the IT state instead; the address
    /// check keeps stale state from predicating unrelated decodes when the
    /// worklist visits out of linear order (a branch into an IT block then
    /// fails open to the old stateless decode).
    it_remaining: u8,
    it_next: Option<u64>,
}

impl<'a> Walker<'a> {
    fn new(arch: Arch, space: &'a AddrSpace<'a>) -> Self {
        Self {
            arch,
            space,
            decoded: BTreeMap::new(),
            jump_targets: BTreeSet::new(),
            fallthroughs: BTreeSet::new(),
            call_targets: BTreeSet::new(),
            diagnostics: BTreeSet::new(),
            it_remaining: 0,
            it_next: None,
        }
    }

    /// Decode from `seeds`, following direct branches, calls, and fallthrough.
    ///
    /// Records bounded evidence while walking: executable bytes at a queued
    /// address that do not decode become [`DiagnosticKind::DecodeFailure`],
    /// and decoded branches/calls without a direct target become unresolved
    /// jump/call sites. Valid termination (`Return`) and fallthrough record
    /// nothing. Unmapped queued addresses record nothing: they end that
    /// path, they are not decode failures.
    ///
    /// Returns the newly recorded [`DiagnosticKind::UnresolvedIndirectJump`]
    /// sites (re-inserts of already-known sites are not repeated), so
    /// [`resolve_indirect_jumps`] can queue continuations without rescanning
    /// the whole diagnostic set.
    fn run(&mut self, seeds: Vec<u64>) -> Result<Vec<u64>> {
        let mut stack = seeds;
        let mut fresh_jumps: Vec<u64> = Vec::new();
        while let Some(va) = stack.pop() {
            if self.decoded.contains_key(&va) {
                continue;
            }
            if self.decoded.len() >= MAX_TOTAL_INSNS {
                return Err(Error::Limit(format!(
                    "more than {MAX_TOTAL_INSNS} instructions"
                )));
            }
            let Some(bytes) = self.space.code_bytes(va).filter(|b| !b.is_empty()) else {
                continue;
            };
            let insn = match crate::disasm::disasm_first(self.arch, bytes, va) {
                Ok(Some(insn)) => insn,
                Ok(None) => continue,
                Err(Error::Invalid(_)) => {
                    self.diagnostics.insert(Diagnostic {
                        addr: va,
                        kind: DiagnosticKind::DecodeFailure,
                    });
                    continue;
                }
                Err(e) => return Err(e),
            };
            let flow = flow_of(self.arch, &insn);
            // Thumb IT predication: the decoder prints no condition suffix
            // inside an IT block, so a predicated `bx lr` (or `pop {.., pc}`)
            // lifts as an unconditional return. Downgrade predicated
            // terminators to conditional branches: the site keeps its
            // indirect-jump diagnostic and the fallthrough stays reachable.
            // The stored `Insn` keeps its faithful decode; only the flow is
            // predicated (edge building reuses it below).
            let opens_it = if self.arch == Arch::Thumb {
                crate::disasm::it_block_len(&insn.mnem)
            } else {
                None
            };
            let predicated =
                opens_it.is_none() && self.it_remaining > 0 && self.it_next == Some(va);
            if predicated {
                self.it_remaining -= 1;
                self.it_next = Some(va.wrapping_add(u64::from(insn.size)));
            }
            if let Some(n) = opens_it {
                self.it_remaining = n;
                self.it_next = Some(va.wrapping_add(u64::from(insn.size)));
            }
            let flow = if predicated {
                match flow {
                    Flow::Ret => Flow::CBranch { target: None },
                    Flow::Branch { target } => Flow::CBranch { target },
                    other => other,
                }
            } else {
                flow
            };
            match flow {
                Flow::Branch { target: None } | Flow::CBranch { target: None } => {
                    if self.diagnostics.insert(Diagnostic {
                        addr: va,
                        kind: DiagnosticKind::UnresolvedIndirectJump,
                    }) {
                        fresh_jumps.push(va);
                    }
                }
                Flow::Call { target: None } => {
                    self.diagnostics.insert(Diagnostic {
                        addr: va,
                        kind: DiagnosticKind::UnresolvedIndirectCall,
                    });
                }
                _ => {}
            }
            let next = va.wrapping_add(u64::from(insn.size));
            match flow {
                Flow::Seq => stack.push(next),
                Flow::Branch { target } => {
                    if let Some(t) = target {
                        self.jump_targets.insert(t);
                        stack.push(t);
                    }
                }
                Flow::CBranch { target } => {
                    if let Some(t) = target {
                        self.jump_targets.insert(t);
                        stack.push(t);
                    }
                    self.fallthroughs.insert(next);
                    stack.push(next);
                }
                Flow::Call { target } => {
                    if let Some(t) = target {
                        self.jump_targets.insert(t);
                        self.call_targets.insert(t);
                        stack.push(t);
                    }
                    self.fallthroughs.insert(next);
                    stack.push(next);
                }
                Flow::Ret => {}
            }
            self.decoded.insert(va, Decoded { insn, flow });
        }
        Ok(fresh_jumps)
    }
}

/// Owner entry for an address: greatest entry at or below `va`.
///
/// `entries` must be sorted ascending (as built in [`analyze`]).
/// Addresses below the first entry — and every address when `entries`
/// is empty — have no owner (`None`), matching
/// [`Analysis::containing_function`], which reports `None` there so
/// block ownership and `func`/`blocks` lookups agree. Binary search,
/// so block/edge attribution is `O(log F)` per lookup instead of
/// `O(F)`.
#[must_use]
pub fn function_owner(entries: &[u64], va: u64) -> Option<u64> {
    let idx = entries.partition_point(|e| *e <= va);
    if idx == 0 {
        None
    } else {
        Some(entries[idx - 1])
    }
}

/// Recovered indirect-jump resolutions: `(site, target)` pairs in ascending
/// site order plus explicit cap accounting.
///
/// Single-slot sites contribute one pair; guarded table sites contribute one
/// pair per unique entry target (at most [`MAX_TABLE_ENTRIES_PER_SITE`]).
/// `slots` holds the scanned `(site, slot)` table addresses backing the
/// table pairs' `Data` evidence xrefs.
struct InferredJumps {
    /// Resolved `(site, target)` pairs, unique per tuple.
    pairs: Vec<(u64, u64)>,
    /// Scanned `(site, slot)` table addresses for resolved table sites.
    slots: Vec<(u64, u64)>,
    /// Whether the edge budget cut resolution short.
    truncated: bool,
    /// Sites skipped by the edge budget (each keeps its diagnostic).
    omitted: usize,
}

/// Slot width for indirect-jump resolution, or `None` when the resolvers
/// cannot apply.
///
/// Single gate shared by [`resolve_indirect_site`], [`resolve_table_site`],
/// and [`resolve_indirect_jumps`]: only raw x86 mappings have known-final
/// slot values in an approved shape (x86-32 absolute slots are 4 bytes,
/// x86-64 RIP-relative slots 8; other arches report no typed slot, and
/// container slot values are not final until relocations apply, which never
/// happens to segment bytes). The resolvers take the width from here and
/// [`resolve_indirect_jumps`] skips its scan via `is_none`, so the gate
/// cannot drift from the checks.
fn indirect_slot_width(arch: Arch, format: BinaryFormat) -> Option<usize> {
    if format != BinaryFormat::Raw {
        return None;
    }
    match arch {
        Arch::X86_32 => Some(4),
        Arch::X86_64 => Some(8),
        Arch::Aarch64 | Arch::Arm32 | Arch::Thumb => None,
    }
}

/// Check one `UnresolvedIndirectJump` site against the single-slot absolute
/// indirect-jump pattern, returning its target when every check passes.
///
/// All evidence is typed decoder facts, never operand text. Rejections:
/// - R1: `insn.mnem == "jmp"` with a `Branch { None }` lift (excludes
///   immediate-reporting `mov`/`push`, calls, and predicated forms).
/// - R2: `branch_target` is `None` (direct jumps never reach this set).
/// - R3: `mem_target == Some(slot)` (excludes indexed/multi-entry and
///   register-indirect shapes, which report no typed slot; guarded
///   scaled-index tables go through [`resolve_table_site`] instead).
/// - R4: raw mappings only (container and LE slot values are not known
///   final: relocations are never applied to segment bytes).
/// - R5: the arch-width slot bytes are fully file-backed in one segment
///   (excludes truncated slots, BSS tails, and cross-segment spans; a
///   `Data` xref via `contains` is necessary but not sufficient here).
/// - R6: the little-endian slot value lies in executable file-backed bytes.
/// - R7: those bytes decode via `disasm_first`.
/// - R8: the target attributes to the site's function under the Pass-A
///   entry set (same-function only: no new entries, no callgraph edges).
///
/// Slot width is the arch pointer width (4 for x86-32, 8 for x86-64); other
/// arches have no approved shape and are rejected outright.
fn resolve_indirect_site(
    arch: Arch,
    format: BinaryFormat,
    space: &AddrSpace,
    decoded: &BTreeMap<u64, Decoded>,
    entries: &[u64],
    site: u64,
) -> Option<u64> {
    let found = decoded.get(&site)?;
    if found.insn.mnem != "jmp" {
        return None;
    }
    if !matches!(found.flow, Flow::Branch { target: None }) {
        return None;
    }
    if found.insn.branch_target.is_some() {
        return None;
    }
    let slot = found.insn.mem_target?;
    let width = indirect_slot_width(arch, format)?;
    let raw = space.file_bytes_at(slot, width)?;
    let target = match width {
        4 => u64::from(u32::from_le_bytes(raw.try_into().ok()?)),
        _ => u64::from_le_bytes(raw.try_into().ok()?),
    };
    let target_bytes = space.code_bytes(target)?;
    if !matches!(
        crate::disasm::disasm_first(arch, target_bytes, target),
        Ok(Some(_))
    ) {
        return None;
    }
    if entries.is_empty() {
        return None;
    }
    match (
        function_owner(entries, target),
        function_owner(entries, site),
    ) {
        (Some(t), Some(s)) if t == s => {}
        _ => return None,
    }
    Some(target)
}

/// Check one `UnresolvedIndirectJump` site against the guarded scaled-index
/// table pattern, returning its unique entry targets in ascending order.
///
/// All evidence is typed decoder facts, never operand text. Rejections:
/// - T1: `insn.mnem == "jmp"` with a `Branch { None }` lift (same gate as
///   the single-slot path: excludes calls and predicated forms).
/// - T2: `branch_target` is `None` (direct jumps never reach this set).
/// - T3: `table_base == Some(base)` (excludes the single-slot shapes, which
///   report `mem_target` instead, and strided scales, which report `None`).
/// - T4: raw mappings only (container slot values are not known final).
/// - T5: a direct conditional branch (`CBranch { Some }`, the index bound
///   check) within [`MAX_TABLE_GUARD_BACKTRACK`] decoded predecessors in
///   the site's function. Unguarded indexes are unbounded: unrecoverable.
/// - T6: the scan reads consecutive slots from `base` while every per-slot
///   check passes (same file-backed/executable/decodable/same-function
///   rules as the single-slot R5-R8, at the arch pointer width); the
///   first failure ends the table.
/// - T7: at least [`MIN_TABLE_ENTRIES_PER_SITE`] consecutive valid slots.
///   Singleton runs are stray pointers, not tables.
/// - T8: a run still valid at [`MAX_TABLE_ENTRIES_PER_SITE`] slots is
///   open-ended, not bounded: the whole site stays unresolved rather than
///   partially recovered (exact-or-reject).
///
/// Only x86 has an approved table shape (x86-32 scale 4, x86-64 scale 8);
/// other arches are rejected outright, as are ARM `tbb`/`tbh` (no typed
/// displacement) and single-entry fallbacks to the single-slot path.
fn resolve_table_site(
    arch: Arch,
    format: BinaryFormat,
    space: &AddrSpace,
    decoded: &BTreeMap<u64, Decoded>,
    entries: &[u64],
    site: u64,
) -> Option<TableResolution> {
    let found = decoded.get(&site)?;
    if found.insn.mnem != "jmp" {
        return None;
    }
    if !matches!(found.flow, Flow::Branch { target: None }) {
        return None;
    }
    if found.insn.branch_target.is_some() {
        return None;
    }
    let base = found.insn.table_base?;
    let width = indirect_slot_width(arch, format)?;
    if entries.is_empty() {
        return None;
    }
    let owner = function_owner(entries, site)?;
    if !table_guard_present(decoded, entries, site, owner) {
        return None;
    }
    let mut targets = BTreeSet::new();
    let mut slots = Vec::new();
    for i in 0..MAX_TABLE_ENTRIES_PER_SITE {
        let slot = base.wrapping_add((i as u64).wrapping_mul(width as u64));
        let Some(target) = table_slot_target(arch, space, entries, owner, slot, width) else {
            break;
        };
        slots.push(slot);
        targets.insert(target);
    }
    if slots.len() < MIN_TABLE_ENTRIES_PER_SITE {
        return None;
    }
    let probe = base.wrapping_add((MAX_TABLE_ENTRIES_PER_SITE as u64).wrapping_mul(width as u64));
    if table_slot_target(arch, space, entries, owner, probe, width).is_some() {
        return None;
    }
    Some(TableResolution {
        targets: targets.into_iter().collect(),
        slots,
    })
}

/// Unique entry targets plus scanned slot addresses of one table site.
struct TableResolution {
    /// Unique entry targets in ascending order.
    targets: Vec<u64>,
    /// Scanned slot addresses in table order (evidence for `Data` xrefs).
    slots: Vec<u64>,
}

/// Whether a direct conditional branch (the index bound check) precedes
/// `site` within [`MAX_TABLE_GUARD_BACKTRACK`] decoded predecessors in the
/// same function. Typed lift facts only: a `CBranch` with a direct target.
fn table_guard_present(
    decoded: &BTreeMap<u64, Decoded>,
    entries: &[u64],
    site: u64,
    owner: u64,
) -> bool {
    decoded
        .range(..site)
        .rev()
        .take(MAX_TABLE_GUARD_BACKTRACK)
        .take_while(|(va, _)| function_owner(entries, **va) == Some(owner))
        .any(|(_, d)| matches!(d.flow, Flow::CBranch { target: Some(_) }))
}

/// Validate one table slot: file-backed width bytes in a single segment,
/// a little-endian value in executable file-backed bytes that decodes and
/// attributes to the site's function. Mirrors the single-slot R5-R8 rules.
fn table_slot_target(
    arch: Arch,
    space: &AddrSpace,
    entries: &[u64],
    owner: u64,
    slot: u64,
    width: usize,
) -> Option<u64> {
    let raw = space.file_bytes_at(slot, width)?;
    let target = match width {
        4 => u64::from(u32::from_le_bytes(raw.try_into().ok()?)),
        _ => u64::from_le_bytes(raw.try_into().ok()?),
    };
    let target_bytes = space.code_bytes(target)?;
    if !matches!(
        crate::disasm::disasm_first(arch, target_bytes, target),
        Ok(Some(_))
    ) {
        return None;
    }
    if function_owner(entries, target) != Some(owner) {
        return None;
    }
    Some(target)
}

/// Resolve single-slot absolute indirect jumps and guarded scaled-index
/// tables over the walker's `UnresolvedIndirectJump` sites in ascending
/// address order.
///
/// Each site is checked once via [`resolve_indirect_site`], then via
/// [`resolve_table_site`]; a pass decodes each target's continuation with
/// the existing [`Walker::run`] (so case bodies decode normally) and
/// registers the targets for block splitting. Continuation decoding can
/// surface further indirect sites, which join the same ascending worklist.
/// Single-slot sites contribute at most one edge
/// ([`MAX_INFERRED_PER_SITE`], singleton by construction); table sites
/// contribute up to [`MAX_TABLE_ENTRIES_PER_SITE`] unique edges. Past
/// `max_edges` (normally [`MAX_INFERRED_EDGES`]) sites stay unresolved
/// with `truncated` set and each omission counted, never silently clipped.
///
/// Non-raw and non-x86 binaries return empty immediately via
/// [`indirect_slot_width`]: no site could resolve, so the diagnostic scan is
/// skipped entirely rather than visiting every site once per pass.
///
/// # Errors
/// [`Error::Limit`] when continuation decoding exceeds the analysis
/// instruction budget (hard budgets stay errors, as in [`Walker::run`]).
fn resolve_indirect_jumps(
    walk: &mut Walker,
    arch: Arch,
    format: BinaryFormat,
    space: &AddrSpace,
    entries: &[u64],
    max_edges: usize,
) -> Result<InferredJumps> {
    let mut pairs: Vec<(u64, u64)> = Vec::new();
    let mut slots: Vec<(u64, u64)> = Vec::new();
    if indirect_slot_width(arch, format).is_none() {
        return Ok(InferredJumps {
            pairs,
            slots,
            truncated: false,
            omitted: 0,
        });
    }
    let mut processed: BTreeSet<u64> = BTreeSet::new();
    // Ascending worklist (the old scan's `next()` pick was the smallest
    // unprocessed address): one initial pass over diagnostics, then only
    // the newly surfaced sites each continuation `run` reports.
    let mut pending: BTreeSet<u64> = walk
        .diagnostics
        .iter()
        .filter(|d| d.kind == DiagnosticKind::UnresolvedIndirectJump)
        .map(|d| d.addr)
        .collect();
    let mut truncated = false;
    let mut omitted: usize = 0;
    while let Some(site) = pending.pop_first() {
        // Each site contributes at most one single-slot edge, or one table
        // row set; the check returns at most one resolution per visit and
        // the processed set keeps sites single-visit.
        let inserted = processed.insert(site);
        debug_assert!(inserted);
        if let Some(target) =
            resolve_indirect_site(arch, format, space, &walk.decoded, entries, site)
        {
            if pairs.len() >= max_edges {
                truncated = true;
                omitted += 1;
                continue;
            }
            pairs.push((site, target));
            for fresh in walk.run(vec![target])? {
                if !processed.contains(&fresh) {
                    pending.insert(fresh);
                }
            }
            walk.jump_targets.insert(target);
        } else if let Some(table) =
            resolve_table_site(arch, format, space, &walk.decoded, entries, site)
        {
            let cost = table.targets.len();
            if pairs.len().saturating_add(cost) > max_edges {
                truncated = true;
                omitted += cost;
                continue;
            }
            for target in &table.targets {
                pairs.push((site, *target));
                walk.jump_targets.insert(*target);
            }
            for slot in &table.slots {
                slots.push((site, *slot));
            }
            for fresh in walk.run(table.targets)? {
                if !processed.contains(&fresh) {
                    pending.insert(fresh);
                }
            }
        }
    }
    // Unique by construction: single-slot sites resolve once, table
    // targets are a per-site set, and the two shapes own disjoint sites
    // (`mem_target` and `table_base` never coincide).
    debug_assert_eq!(pairs.iter().collect::<BTreeSet<_>>().len(), pairs.len());
    Ok(InferredJumps {
        pairs,
        slots,
        truncated,
        omitted,
    })
}

/// Index over string spans preserving the linear scan's first-match rule.
///
/// Holds `(start, exclusive end)` spans sorted ascending by start, with ends
/// computed by the caller via `wrapping_add` (as in [`analyze`]).
/// [`StringSpanIndex::lookup`] returns the start of the earliest span with
/// `start <= target < end`, using plain `u64` comparisons exactly like the
/// old linear scan. A naive last-start predecessor lookup misses nested spans
/// (an early wide span can contain a target past a later narrow span's end);
/// the prefix-maximum ends array recovers the earliest span with `end >
/// target`, and the starts upper bound enforces `start <= target`. Build is
/// `O(S)`, each query `O(log S)`.
#[derive(Debug, Clone, Default)]
pub struct StringSpanIndex {
    spans: Vec<(u64, u64)>,
    prefix_max: Vec<u64>,
}

impl StringSpanIndex {
    /// Build the index over `spans` sorted ascending by start.
    #[must_use]
    pub fn new(spans: Vec<(u64, u64)>) -> Self {
        let mut prefix_max = Vec::with_capacity(spans.len());
        let mut running: u64 = 0;
        for (_, e) in &spans {
            running = running.max(*e);
            prefix_max.push(running);
        }
        Self { spans, prefix_max }
    }

    /// Start of the earliest span containing `target`, if any.
    ///
    /// `None` when no span satisfies `start <= target < end`; empty and
    /// wrapped-empty (`end <= start` in plain `u64` order) spans never match,
    /// matching the old linear scan.
    #[must_use]
    pub fn lookup(&self, target: u64) -> Option<u64> {
        let cand = self.prefix_max.partition_point(|&m| m <= target);
        if cand >= self.spans.len() {
            return None;
        }
        let upto = self.spans.partition_point(|&(s, _)| s <= target);
        if cand < upto {
            let (s, e) = self.spans[cand];
            if target >= s && target < e {
                return Some(s);
            }
        }
        None
    }

    /// Number of indexed spans.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    /// Whether the index holds no spans.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }
}

/// Import slot map: slot VA to `imports` index for PE/ELF binaries.
///
/// Slots are the loader-resolved call pointers (PE IAT, ELF GOT; see
/// [`ImportRef::address`](crate::loader::ImportRef::address)). Mach-O
/// addresses are code stubs rather than slots, so they stay out: a data
/// reference can never legitimately target them.
#[must_use]
pub fn import_slots(bin: &LoadedBinary) -> BTreeMap<u64, usize> {
    if !matches!(bin.format, BinaryFormat::Pe | BinaryFormat::Elf) {
        return BTreeMap::new();
    }
    let mut map = BTreeMap::new();
    for (i, imp) in bin.imports.iter().enumerate() {
        if let Some(slot) = imp.address {
            map.entry(slot).or_insert(i);
        }
    }
    map
}

/// Import index serving one call site, if any.
///
/// Indirect sites match by slot (`mem_target`); direct sites match by
/// PLT-stub/thunk target (`branch_target` against `stubs`). The slot rule
/// runs first so a site carrying both resolves to the slot.
#[must_use]
pub fn import_index(
    slots: &BTreeMap<u64, usize>,
    stubs: &BTreeMap<u64, usize>,
    branch_target: Option<u64>,
    mem_target: Option<u64>,
) -> Option<usize> {
    if let Some(m) = mem_target
        && let Some(&i) = slots.get(&m)
    {
        return Some(i);
    }
    if let Some(t) = branch_target
        && let Some(&i) = stubs.get(&t)
    {
        return Some(i);
    }
    None
}

/// PLT-stub/import-thunk sites from decoded rows: `jmp [slot]` address
/// to `imports` index (x86 only; snapshot rebuilds run the same
/// predicate over re-decoded rows).
///
/// A bare `jmp` with no direct target whose slot resolves is a stub;
/// calls through slots are callers, not stubs. A CET `endbr32`/`endbr64`
/// immediately before the jump (`.plt.sec` entries) maps too, so direct
/// calls landing on the `endbr` resolve to the same import.
fn collect_stubs<'a>(
    rows: impl Iterator<Item = (u64, Flow, Option<u64>, &'a str, u8)>,
    slots: &BTreeMap<u64, usize>,
) -> BTreeMap<u64, usize> {
    let mut stubs = BTreeMap::new();
    let mut prev: Option<(u64, &'a str, u8)> = None;
    for (addr, flow, mem, mnem, size) in rows {
        if matches!(flow, Flow::Branch { target: None })
            && let Some(m) = mem
            && let Some(&i) = slots.get(&m)
        {
            stubs.insert(addr, i);
            if let Some((pa, pm, ps)) = prev
                && (pm == "endbr64" || pm == "endbr32")
                && pa.wrapping_add(ps as u64) == addr
            {
                stubs.insert(pa, i);
            }
        }
        prev = Some((addr, mnem, size));
    }
    stubs
}

/// Run recursive descent and build functions, CFGs, callgraph, and xrefs.
///
/// # Errors
/// [`Error::Limit`] when instruction, function, or seed caps are exceeded.
pub fn analyze(bin: &LoadedBinary) -> Result<Analysis> {
    let arch = bin.arch;
    let space = AddrSpace::new(bin);

    // Pass A: recursive descent over a plain VA worklist. Round one starts
    // from entry/exports (or the segment base); round two picks up prologue
    // hits in code round one never reached. Both rounds' seeds become
    // entries; incidental pattern matches inside reached code do not.
    let mut walk = Walker::new(arch, &space);
    let (seeds1, seed_diags) = authoritative_seeds(&space, bin);
    walk.diagnostics.extend(seed_diags);
    walk.run(seeds1.clone())?;
    let round1: BTreeSet<u64> = walk.decoded.keys().copied().collect();
    let seeds2 = prologue_seeds(arch, &space, &round1)?;
    walk.run(seeds2.clone())?;

    if walk.decoded.is_empty() {
        let diagnostics = Diagnostics::collect(walk.diagnostics.into_iter().collect(), false, 0);
        return Ok(Analysis {
            arch,
            functions: BTreeMap::new(),
            callgraph: DiGraphMap::new(),
            xrefs: Vec::new(),
            to_index: OnceLock::new(),
            import_stubs: BTreeMap::new(),
            strings: Vec::new(),
            diagnostics,
        });
    }

    // Function entries: both rounds' seeds that decoded, plus direct call
    // targets. Round-one hits are excluded by construction: `seeds2` only
    // holds prologue matches outside round-one code.
    let mut entries: BTreeSet<u64> = BTreeSet::new();
    for s in seeds1.iter().chain(seeds2.iter()) {
        if walk.decoded.contains_key(s) {
            entries.insert(*s);
        }
    }
    for t in &walk.call_targets {
        if walk.decoded.contains_key(t) {
            entries.insert(*t);
        }
    }
    if entries.is_empty()
        && let Some((&first, _)) = walk.decoded.iter().next()
    {
        entries.insert(first);
    }
    if entries.len() > MAX_FUNCTIONS {
        return Err(Error::Limit(format!("more than {MAX_FUNCTIONS} functions")));
    }
    // Discovery provenance: every seed path that reached an entry.
    // `seeds1` holds the entry point, exports, symbol-table addresses,
    // or the fallback base; `seeds2` holds prologue hits; `call_targets`
    // holds direct calls. A fallback base that is neither entry nor
    // export still counts as `Entry`: it seeded analysis as the entry
    // point.
    let seeds1_set: BTreeSet<u64> = seeds1.iter().copied().collect();
    let seeds2_set: BTreeSet<u64> = seeds2.iter().copied().collect();
    // Normalized like the seeds: an odd ARM export address and its masked
    // seed are the same function.
    let export_addrs: BTreeSet<u64> = bin
        .exports
        .iter()
        .filter_map(|e| e.address.map(|a| normalize_arm_seed(arch, a).0))
        .collect();
    let entry_norm = bin.entry.map(|e| normalize_arm_seed(arch, e).0);
    let symbol_addrs: BTreeSet<u64> = bin.symbols.iter().map(|s| s.address).collect();
    let mut reasons: BTreeMap<u64, BTreeSet<DiscoveryReason>> = BTreeMap::new();
    for e in &entries {
        let mut r = BTreeSet::new();
        if Some(*e) == entry_norm {
            r.insert(DiscoveryReason::Entry);
        }
        if export_addrs.contains(e) {
            r.insert(DiscoveryReason::Export);
        }
        if symbol_addrs.contains(e) {
            r.insert(DiscoveryReason::Symbol);
        }
        if walk.call_targets.contains(e) {
            r.insert(DiscoveryReason::DirectCall);
        }
        if seeds2_set.contains(e) {
            r.insert(DiscoveryReason::Prologue);
        }
        if r.is_empty() && seeds1_set.contains(e) {
            r.insert(DiscoveryReason::Entry);
        }
        if r.is_empty() {
            r.insert(DiscoveryReason::Entry);
        }
        reasons.insert(*e, r);
    }
    let entry_list: Vec<u64> = entries.iter().copied().collect();
    let owner = |va: u64| -> Option<u64> { function_owner(&entry_list, va) };

    // Pass A2: resolve single-slot absolute indirect jumps and guarded
    // scaled-index tables (raw x86 only). Entries are fixed above so the
    // resolvers can check same-function attribution without creating
    // entries; resolved targets decode next via the walker's continuation
    // and join block splitting below.
    let jumps = resolve_indirect_jumps(
        &mut walk,
        arch,
        bin.format,
        &space,
        &entry_list,
        MAX_INFERRED_EDGES,
    )?;
    let Walker {
        mut decoded,
        jump_targets,
        fallthroughs,
        diagnostics: mut diagnostic_set,
        ..
    } = walk;

    // Import call sites: the slot map comes from loader-resolved
    // addresses (PE IAT / ELF GOT); stub sites come from decoded
    // `jmp [slot]` shapes, CET `endbr` preludes included (see
    // `collect_stubs`). Calls through slots are callers, not stubs.
    let slots = import_slots(bin);
    let stubs: BTreeMap<u64, usize> = if matches!(arch, Arch::X86_64 | Arch::X86_32) {
        collect_stubs(
            decoded.iter().map(|(&va, d)| {
                (
                    va,
                    d.flow,
                    d.insn.mem_target,
                    d.insn.mnem.as_str(),
                    d.insn.size,
                )
            }),
            &slots,
        )
    } else {
        BTreeMap::new()
    };
    // Tag decoded rows with the import each site calls through.
    for d in decoded.values_mut() {
        if let Some(i) = import_index(&slots, &stubs, d.insn.branch_target, d.insn.mem_target)
            && let Some(imp) = bin.imports.get(i)
        {
            d.insn.import = Some(imp.name.clone());
        }
    }

    // Pass B: split decoded runs into blocks at seeds, targets, fallthroughs.
    let mut starts: BTreeSet<u64> = BTreeSet::new();
    starts.extend(entries.iter().copied());
    starts.extend(jump_targets.iter().copied());
    starts.extend(fallthroughs.iter().copied());
    let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();
    let mut cur_start: Option<u64> = None;
    let mut cur: Vec<Insn> = Vec::new();
    let flush =
        |start: &mut Option<u64>, cur: &mut Vec<Insn>, blocks: &mut BTreeMap<u64, BasicBlock>| {
            if let Some(s) = start.take()
                && !cur.is_empty()
            {
                blocks.insert(
                    s,
                    BasicBlock {
                        start: s,
                        insns: std::mem::take(cur),
                    },
                );
            }
        };
    for (&va, d) in &decoded {
        if starts.contains(&va) {
            flush(&mut cur_start, &mut cur, &mut blocks);
            cur_start = Some(va);
        } else if cur_start.is_none() {
            cur_start = Some(va);
        }
        cur.push(d.insn.clone());
        if d.flow.ends_block() {
            flush(&mut cur_start, &mut cur, &mut blocks);
        }
    }
    flush(&mut cur_start, &mut cur, &mut blocks);

    // Export names for entries, then symbol-table names, then import
    // addresses (Mach-O stubs; PE slots are data and never collide).
    // ELF stubs take `sym@plt` from the stub map below. Precedence per
    // address: export > symbol > import; annotation renames win over all
    // three at display time (see `Project::function_name`). Export
    // addresses normalize like seeds so an odd ARM export still names
    // its function.
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    for exp in &bin.exports {
        if let Some(addr) = exp.address {
            names
                .entry(normalize_arm_seed(arch, addr).0)
                .or_insert_with(|| exp.name.clone());
        }
    }
    for sym in &bin.symbols {
        names.entry(sym.address).or_insert_with(|| sym.name.clone());
    }
    for imp in &bin.imports {
        // ELF slots are data addresses that never collide with entries;
        // ELF stubs take `sym@plt` from the stub map below instead.
        if bin.format == BinaryFormat::Elf {
            continue;
        }
        if let Some(addr) = imp.address {
            names.entry(addr).or_insert_with(|| imp.name.clone());
        }
    }
    // PLT/import-thunk stubs: a `jmp [slot]` site that starts a function
    // serves that import. ELF stubs read `sym@plt`; PE thunks carry the
    // bare import name. `or_insert` keeps the export > symbol > import
    // precedence of the loops above.
    for (&site, &i) in &stubs {
        if !entries.contains(&site) {
            continue;
        }
        let Some(imp) = bin.imports.get(i) else {
            continue;
        };
        let name = match bin.format {
            BinaryFormat::Elf => format!("{}@plt", imp.name),
            _ => imp.name.clone(),
        };
        names.entry(site).or_insert(name);
    }

    // Pass C: assign blocks to functions, build CFGs and the callgraph.
    let mut functions: BTreeMap<u64, Function> = BTreeMap::new();
    for e in &entries {
        functions.insert(
            *e,
            Function {
                entry: *e,
                name: names.get(e).cloned(),
                blocks: BTreeMap::new(),
                cfg: DiGraphMap::new(),
                inferred: BTreeSet::new(),
                reasons: reasons.remove(e).unwrap_or_default(),
            },
        );
    }
    for (start, block) in blocks {
        let Some(o) = owner(start) else {
            continue;
        };
        if let Some(f) = functions.get_mut(&o) {
            f.cfg.add_node(start);
            f.blocks.insert(start, block);
        }
    }
    functions.retain(|_, f| !f.blocks.is_empty());

    // Inferred edges: attribute each resolved `(site, target)` to its
    // site/target blocks, recording the edge only when attribution confirms
    // the same function. Anything else (including a target whose block
    // landed elsewhere) rolls back to unresolved: no edge, no xref, and the
    // site keeps its diagnostic.
    let mut block_func: BTreeMap<u64, u64> = BTreeMap::new();
    for (entry, f) in &functions {
        for start in f.blocks.keys() {
            block_func.insert(*start, *entry);
        }
    }
    let mut resolved_sites: BTreeSet<u64> = BTreeSet::new();
    for (site, target) in &jumps.pairs {
        // Blocks partition decoded addresses across functions, so the site
        // sits in exactly one block; the target is a block start by
        // construction (it joined `jump_targets` before Pass B).
        let mut hit: Option<(u64, u64)> = None;
        for (entry, f) in &functions {
            if let Some((&start, b)) = f.blocks.range(..=*site).next_back()
                && *site < b.end()
            {
                hit = Some((*entry, start));
                break;
            }
        }
        match (hit, block_func.get(target)) {
            (Some((func, site_block)), Some(target_func)) if func == *target_func => {
                if let Some(f) = functions.get_mut(&func) {
                    f.inferred.insert((site_block, *target));
                    resolved_sites.insert(*site);
                }
            }
            _ => {}
        }
    }

    let mut callgraph = DiGraphMap::<u64, ()>::new();
    for e in functions.keys() {
        callgraph.add_node(*e);
    }
    // Block-end lookup for edge targets.
    let keys: Vec<u64> = functions.keys().copied().collect();
    let mut cfg_edges: Vec<(u64, u64, u64)> = Vec::new();
    let mut cg_edges: Vec<(u64, u64)> = Vec::new();
    for entry in keys {
        let Some(f) = functions.get(&entry) else {
            continue;
        };
        for (start, block) in &f.blocks {
            let Some(last) = block.insns.last() else {
                continue;
            };
            // Stored walker flow, never a fresh flow_of: Thumb instructions
            // inside an IT block decode without a condition suffix, so only
            // the walker's predicated flow keeps the fallthrough edge.
            let flow = decoded
                .get(&last.addr)
                .map(|d| d.flow)
                .unwrap_or_else(|| flow_of(arch, last));
            let end = block.end();
            match flow {
                Flow::Branch { target: Some(t) } => {
                    if f.blocks.contains_key(&t) {
                        cfg_edges.push((entry, *start, t));
                    } else if decoded.contains_key(&t)
                        && let Some(o) = owner(t)
                    {
                        cg_edges.push((entry, o));
                    }
                }
                Flow::Branch { target: None } => {}
                Flow::CBranch { target } => {
                    if let Some(t) = target
                        && f.blocks.contains_key(&t)
                    {
                        cfg_edges.push((entry, *start, t));
                    }
                    if f.blocks.contains_key(&end) {
                        cfg_edges.push((entry, *start, end));
                    }
                }
                Flow::Call { target } => {
                    if let Some(t) = target
                        && decoded.contains_key(&t)
                        && let Some(o) = owner(t)
                    {
                        cg_edges.push((entry, o));
                    }
                    if f.blocks.contains_key(&end) {
                        cfg_edges.push((entry, *start, end));
                    }
                }
                Flow::Ret => {}
                Flow::Seq => {
                    if f.blocks.contains_key(&end) {
                        cfg_edges.push((entry, *start, end));
                    }
                }
            }
        }
    }
    for (func, a, b) in cfg_edges {
        if let Some(f) = functions.get_mut(&func) {
            f.cfg.add_edge(a, b, ());
        }
    }
    for (a, b) in cg_edges {
        if functions.contains_key(&b) {
            callgraph.add_edge(a, b, ());
        }
    }

    // Pass D: xrefs. Code from direct branch/call targets, data from
    // PC-relative accesses and x86-32 absolute immediates/displacements
    // into a segment, string refs where data lands in a recovered string.
    // Inferred edges add one provenance-marked `InferredCode` xref per
    // resolved site (single-slot) or per unique entry target (tables);
    // the single-slot `Data` slot xref above is retained, and table sites
    // add one `Data` xref per scanned slot.
    let mut xrefs: BTreeSet<(u64, XrefKind, u64)> = BTreeSet::new();
    for (&va, d) in &decoded {
        let target = match d.flow {
            Flow::Branch { target } | Flow::CBranch { target } | Flow::Call { target } => target,
            _ => None,
        };
        if let Some(t) = target {
            xrefs.insert((va, XrefKind::Code, t));
        }
        if let Some(m) = d.insn.mem_target
            && space.contains(m)
        {
            xrefs.insert((va, XrefKind::Data, m));
        }
        // Import rows: indirect slot references and direct stub/thunk
        // targets both resolve to the import's slot address.
        if let Some(i) = import_index(&slots, &stubs, target, d.insn.mem_target)
            && let Some(slot) = bin.imports.get(i).and_then(|imp| imp.address)
        {
            xrefs.insert((va, XrefKind::Import, slot));
        }
    }
    // ARM64 `adrp` decodes to its 4K page base; the page offset rides in
    // the next instruction (`add`/`ldr`). Where an adjacent same-block
    // pair resolves, the second instruction references the final address
    // too; the page-base row above is retained as the strict fallback.
    for f in functions.values() {
        for block in f.blocks.values() {
            for pair in block.insns.windows(2) {
                if let Some(final_addr) = resolve_adrp_pair(&pair[0], &pair[1])
                    && space.contains(final_addr)
                {
                    xrefs.insert((pair[1].addr, XrefKind::Data, final_addr));
                }
            }
        }
    }
    for (site, target) in &jumps.pairs {
        if resolved_sites.contains(site) {
            xrefs.insert((*site, XrefKind::InferredCode, *target));
        }
    }
    for (site, slot) in &jumps.slots {
        if resolved_sites.contains(site) {
            xrefs.insert((*site, XrefKind::Data, *slot));
        }
    }
    let mut strings: Vec<StringHit> = Vec::new();
    for seg in &space.all {
        for mut h in strings::extract(
            &seg.data,
            strings::DEFAULT_MIN_LEN,
            strings::DEFAULT_MAX_HITS,
            Some(seg.vaddr),
        ) {
            let (section, executable) = locate_hit(&bin.sections, seg, h.vaddr);
            h.section = section;
            h.executable = executable;
            strings.push(h);
        }
    }
    strings.sort_by_key(|h| h.vaddr.unwrap_or(u64::MAX));
    let spans: Vec<(u64, u64)> = strings
        .iter()
        .filter_map(|h| {
            h.vaddr.map(|v| {
                let len = match h.encoding {
                    Encoding::Ascii => h.value.len() as u64,
                    Encoding::Utf16Le | Encoding::Utf16Be => h.value.len() as u64 * 2,
                };
                (v, v.wrapping_add(len))
            })
        })
        .collect();
    let span_index = StringSpanIndex::new(spans);
    let data_tos: Vec<(u64, u64)> = xrefs
        .iter()
        .filter(|(_, k, _)| *k == XrefKind::Data)
        .map(|(f, _, t)| (*f, *t))
        .collect();
    for (from, to) in data_tos {
        if let Some(s) = span_index.lookup(to) {
            xrefs.insert((from, XrefKind::String, s));
        }
    }
    let xrefs: Vec<Xref> = xrefs
        .into_iter()
        .map(|(from, kind, to)| Xref { from, to, kind })
        .collect();
    // Inferred rows count jointly against the `Code` budget so they cannot
    // evade the cap by relabeling; hard budgets stay [`Error::Limit`].
    let code_like = xrefs
        .iter()
        .filter(|x| matches!(x.kind, XrefKind::Code | XrefKind::InferredCode))
        .count();
    if code_like > MAX_XREFS_PER_KIND {
        return Err(Error::Limit(format!(
            "more than {MAX_XREFS_PER_KIND} {:?} xrefs",
            XrefKind::Code
        )));
    }
    for kind in [XrefKind::Data, XrefKind::String, XrefKind::Import] {
        if xrefs.iter().filter(|x| x.kind == kind).count() > MAX_XREFS_PER_KIND {
            return Err(Error::Limit(format!(
                "more than {MAX_XREFS_PER_KIND} {kind:?} xrefs"
            )));
        }
    }

    // Resolved sites leave the diagnostics set; failed and skipped sites
    // keep theirs.
    for site in &resolved_sites {
        diagnostic_set.remove(&Diagnostic {
            addr: *site,
            kind: DiagnosticKind::UnresolvedIndirectJump,
        });
    }
    let mut diagnostics = Diagnostics::collect(diagnostic_set.into_iter().collect(), false, 0);
    diagnostics.inferred_truncated = jumps.truncated;
    diagnostics.inferred_omitted = jumps.omitted;

    Ok(Analysis {
        arch,
        functions,
        callgraph,
        xrefs,
        to_index: OnceLock::new(),
        import_stubs: stubs,
        strings,
        diagnostics,
    })
}

/// Analyze a raw byte blob mapped at `base`, for tests and shellcode.
pub fn analyze_raw(bytes: &[u8], base: u64, arch: Arch, entry: Option<u64>) -> Result<Analysis> {
    let bin = load_raw(bytes, RawOptions { base, arch, entry })?;
    analyze(&bin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_of_maps_lift_ops() {
        let ret = Insn {
            addr: 0x1000,
            size: 1,
            bytes: vec![0xC3],
            mnem: "ret".to_string(),
            ops: Vec::new(),
            branch_target: None,
            mem_target: None,
            table_base: None,
            import: None,
            target_name: None,
            comment: None,
            string: None,
        };
        assert_eq!(flow_of(Arch::X86_64, &ret), Flow::Ret);
        let call = Insn {
            addr: 0x1000,
            size: 5,
            bytes: vec![0xE8, 0, 0, 0, 0],
            mnem: "call".to_string(),
            ops: vec!["0x1005".to_string()],
            branch_target: Some(0x1005),
            mem_target: None,
            table_base: None,
            import: None,
            target_name: None,
            comment: None,
            string: None,
        };
        assert_eq!(
            flow_of(Arch::X86_64, &call),
            Flow::Call {
                target: Some(0x1005)
            }
        );
    }

    #[test]
    fn pages_truncate_at_max_page() {
        let items: Vec<u64> = (0..10).collect();
        assert_eq!(page_slice(&items, 0, usize::MAX).len(), 10);
        assert!(page_slice(&items, 0, 3) == [0, 1, 2]);
        assert!(page_slice(&items, 20, 5).is_empty());
    }

    #[test]
    fn block_id_is_stable() {
        let b = BasicBlock {
            start: 0x2007,
            insns: Vec::new(),
        };
        assert_eq!(b.id(0x2000), "block@0x2000+0x2007");
    }

    /// Eager pre-fix oracle: collect every candidate, sort, dedup, filter,
    /// cap. For ARM this is verbatim the old behavior; for x86 it is the
    /// specified sorted-prefix contract (the old code stopped over-budget
    /// inputs in collection order instead of sorting).
    fn oracle_seeds(arch: Arch, space: &AddrSpace, reached: &BTreeSet<u64>) -> Result<Vec<u64>> {
        let mut out: Vec<u64> = Vec::new();
        for seg in &space.exec {
            if arch == Arch::Aarch64 {
                let mut off = 0usize;
                while off + 4 <= seg.data.len() {
                    let raw = seg.data.get(off..off + 4).expect("word in bounds");
                    let w = u32::from_le_bytes(raw.try_into().expect("word converts"));
                    if (w & 0xFFC0_7FFF) == 0xA980_7BFD {
                        out.push(seg.vaddr.wrapping_add(off as u64));
                    }
                    off += 4;
                }
                continue;
            }
            if arch == Arch::Arm32 {
                let mut off = 0usize;
                while off + 4 <= seg.data.len() {
                    let raw = seg.data.get(off..off + 4).expect("word in bounds");
                    let w = u32::from_le_bytes(raw.try_into().expect("word converts"));
                    if is_arm_push_lr(w) {
                        out.push(seg.vaddr.wrapping_add(off as u64));
                    }
                    off += 4;
                }
                continue;
            }
            if arch == Arch::Thumb {
                let mut off = 0usize;
                while off + 2 <= seg.data.len() {
                    let raw = seg.data.get(off..off + 2).expect("halfword in bounds");
                    let hw = u16::from_le_bytes(raw.try_into().expect("halfword converts"));
                    if (hw & 0xFF00) == 0xB500 && (hw & 0x0100) != 0 {
                        out.push(seg.vaddr.wrapping_add(off as u64));
                    } else if off + 4 <= seg.data.len() {
                        let raw = seg.data.get(off..off + 4).expect("word in bounds");
                        let w = u32::from_le_bytes(raw.try_into().expect("word converts"));
                        if is_arm_push_lr(w) {
                            out.push(seg.vaddr.wrapping_add(off as u64));
                        }
                    }
                    off += 2;
                }
                continue;
            }
            for pat in prologue_patterns(arch) {
                for (i, win) in seg.data.windows(pat.len()).enumerate() {
                    if win != *pat {
                        continue;
                    }
                    let mut va = seg.vaddr.wrapping_add(i as u64);
                    if i > 0 && seg.data[i - 1] == 0x55 {
                        va = va.wrapping_sub(1);
                    }
                    out.push(va);
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        let mut seeds: Vec<u64> = Vec::new();
        for va in out {
            if seeds.len() >= MAX_SEEDS {
                break;
            }
            if !reached.contains(&va) && decode_one(arch, space, va)?.is_some() {
                seeds.push(va);
            }
        }
        Ok(seeds)
    }

    fn seed_test_binary(arch: Arch, entry: Option<u64>, segs: Vec<(u64, Vec<u8>)>) -> LoadedBinary {
        LoadedBinary {
            format: crate::loader::BinaryFormat::Raw,
            arch,
            entry,
            segments: segs
                .into_iter()
                .map(|(vaddr, data)| Segment {
                    vaddr,
                    mem_size: data.len() as u64,
                    data,
                    readable: true,
                    writable: false,
                    executable: true,
                })
                .collect(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
        }
    }

    /// One match (`M`), decoder-rejected match (`U`), or junk (`J`) unit.
    fn seed_words(arch: Arch) -> (&'static [u8], &'static [u8], &'static [u8]) {
        match arch {
            Arch::Aarch64 => (
                &[0xFD, 0x7B, 0x80, 0xA9],
                &[0xFD, 0x7B, 0x80, 0xA9],
                &[0x1F, 0x20, 0x03, 0xD5],
            ),
            Arch::Arm32 => (
                &[0xF0, 0x40, 0x2D, 0xE9],
                &[0xF0, 0x40, 0x2D, 0xF9],
                &[0x1E, 0xFF, 0x2F, 0xE1],
            ),
            Arch::Thumb => (&[0xF0, 0xB5], &[0xF0, 0xB5], &[0x00, 0xBF]),
            Arch::X86_64 => (&[0x48, 0x89, 0xE5], &[0x48, 0x89, 0xE5], &[0x90]),
            Arch::X86_32 => (&[0x89, 0xE5], &[0x89, 0xE5], &[0x90]),
        }
    }

    /// Adversarial layout: out-of-order file order, an overlap with
    /// identical bytes (duplicate addresses), a wrapped segment, empty and
    /// short segments, and a zero-based segment.
    fn tricky_segments(arch: Arch) -> Vec<(u64, Vec<u8>)> {
        let (m, u, j) = seed_words(arch);
        let mut hi = Vec::new();
        for w in [m, j, m, u, j, m] {
            hi.extend_from_slice(w);
        }
        hi.push(0x00);
        if arch == Arch::Thumb {
            // 32-bit ARM-form word where the halfword is not a push; kept
            // halfword-aligned so the scan's word branch can hit it.
            hi.push(0x00);
            hi.extend_from_slice(&[0xF0, 0x40, 0x2D, 0xE9]);
        }
        if arch == Arch::X86_64 || arch == Arch::X86_32 {
            // Leading `push rbp`/`push ebp` steps the next match back a byte.
            hi.push(0x55);
            hi.extend_from_slice(m);
        }
        let mut lo = Vec::new();
        lo.extend_from_slice(j);
        lo.extend_from_slice(j);
        lo.extend_from_slice(&hi[..0x18.min(hi.len())]);
        let mut wrap = Vec::new();
        while wrap.len() + m.len() + j.len() <= 16 {
            wrap.extend_from_slice(m);
            wrap.extend_from_slice(j);
        }
        // End on a match so the wrapped-low tail holds a candidate.
        wrap.truncate(16 - m.len());
        wrap.extend_from_slice(m);
        let mut zero = Vec::new();
        for w in [m, j, m] {
            zero.extend_from_slice(w);
        }
        vec![
            (0x5000, hi),
            (0x4FF0, lo),
            (u64::MAX - 8, wrap),
            (0x6000, Vec::new()),
            (0x6100, vec![0x90]),
            (0, zero),
        ]
    }

    #[test]
    fn seed_streams_match_eager_oracle() {
        for arch in [
            Arch::Aarch64,
            Arch::Arm32,
            Arch::Thumb,
            Arch::X86_64,
            Arch::X86_32,
        ] {
            let bin = seed_test_binary(arch, None, tricky_segments(arch));
            let space = AddrSpace::new(&bin);
            let reached: BTreeSet<u64> = [0x5000, 0x5001, 0x5002, 0x5003, 0x4FF0, u64::MAX, 1]
                .into_iter()
                .collect();
            let got = prologue_seeds(arch, &space, &reached).expect("streaming seeds");
            let want = oracle_seeds(arch, &space, &reached).expect("oracle seeds");
            assert_eq!(got, want, "seed mismatch for {arch:?}");
            assert!(
                got.windows(2).all(|w| w[0] < w[1]),
                "seeds must be sorted and deduped for {arch:?}"
            );
        }
    }

    #[test]
    fn x86_wrap_edge_step_back_sorts_last() {
        // Pattern at the wrap point with a `0x55` step-back lands on
        // `u64::MAX`; it must sort after the high run, not first.
        let vaddr = u64::MAX - 4;
        let data = vec![
            0x48, 0x89, 0xE5, 0x90, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0xE5,
        ];
        let bin = seed_test_binary(Arch::X86_64, None, vec![(vaddr, data)]);
        let space = AddrSpace::new(&bin);
        let reached = BTreeSet::new();
        let got = prologue_seeds(Arch::X86_64, &space, &reached).expect("seeds");
        // `vaddr + 8` wraps to `3`, which is unmapped (`seg_at` uses plain
        // comparison), so it is offered first and rejected; the stashed
        // `u64::MAX` still sorts after the high run.
        assert_eq!(got, [vaddr, u64::MAX]);
        let want = oracle_seeds(Arch::X86_64, &space, &reached).expect("oracle");
        assert_eq!(got, want);
    }

    /// Drive Pass A plus entry computation over `bytes`, then resolve with
    /// an explicit edge budget. Mirrors [`analyze`] without block building.
    fn run_inferred_cap(
        bytes: &[u8],
        max_edges: usize,
    ) -> (Vec<(u64, u64)>, bool, usize, Vec<u64>) {
        let bin = load_raw(
            bytes,
            RawOptions {
                base: 0x1000,
                arch: Arch::X86_32,
                entry: Some(0x1000),
            },
        )
        .expect("raw loads");
        let space = AddrSpace::new(&bin);
        let mut walk = Walker::new(Arch::X86_32, &space);
        let seeds = authoritative_seeds(&space, &bin).0;
        walk.run(seeds.clone()).expect("round one walks");
        let round1: BTreeSet<u64> = walk.decoded.keys().copied().collect();
        let seeds2 = prologue_seeds(Arch::X86_32, &space, &round1).expect("prologue scans");
        walk.run(seeds2.clone()).expect("round two walks");
        let mut entries: BTreeSet<u64> = BTreeSet::new();
        for s in seeds.iter().chain(seeds2.iter()) {
            if walk.decoded.contains_key(s) {
                entries.insert(*s);
            }
        }
        let targets: Vec<u64> = walk.call_targets.iter().copied().collect();
        for t in targets {
            if walk.decoded.contains_key(&t) {
                entries.insert(t);
            }
        }
        let entry_list: Vec<u64> = entries.into_iter().collect();
        let jumps = resolve_indirect_jumps(
            &mut walk,
            Arch::X86_32,
            BinaryFormat::Raw,
            &space,
            &entry_list,
            max_edges,
        )
        .expect("resolution walks");
        (jumps.pairs, jumps.truncated, jumps.omitted, entry_list)
    }

    #[test]
    fn inferred_cap_reports_omissions_without_clipping() {
        // Two Pass-A-visible single-slot sites (x86-32, 27 bytes): the
        // entry calls 0x1010, each site jumps through its own slot at a
        // same-function ret.
        let bytes = vec![
            0xE8, 0x0B, 0x00, 0x00, 0x00, // 0x1000: call 0x1010
            0xFF, 0x25, 0x0B, 0x10, 0x00, 0x00, // 0x1005: jmp [0x100b]
            0x0F, 0x10, 0x00, 0x00, // 0x100b: dd 0x100f
            0xC3, // 0x100f: ret
            0xFF, 0x25, 0x16, 0x10, 0x00, 0x00, // 0x1010: jmp [0x1016]
            0x1A, 0x10, 0x00, 0x00, // 0x1016: dd 0x101a
            0xC3, // 0x101a: ret
        ];
        assert_eq!(bytes.len(), 27);
        // A budget of one resolves the first site and counts the skip
        // explicitly; the skipped site is left for the caller unresolved.
        let (pairs, truncated, omitted, entries) = run_inferred_cap(&bytes, 1);
        assert_eq!(entries, [0x1000, 0x1010]);
        assert_eq!(pairs, [(0x1005, 0x100F)]);
        assert!(truncated);
        assert_eq!(omitted, 1);
        // A full budget resolves both with clean accounting.
        let (pairs, truncated, omitted, _) = run_inferred_cap(&bytes, MAX_INFERRED_EDGES);
        assert_eq!(pairs, [(0x1005, 0x100F), (0x1010, 0x101A)]);
        assert!(!truncated);
        assert_eq!(omitted, 0);
    }

    #[test]
    fn table_cap_counts_unique_edges_against_shared_budget() {
        // One guarded x86-32 table site (base 0x1000): two slots, two
        // unique same-function ret targets, probe slot past the cap
        // window holding nop bytes (unmapped value, exact end).
        let mut bytes = vec![
            0x83, 0xF8, 0x01, // 0x1000: cmp eax,1
            0x73, 0x07, // 0x1003: jae 0x100c
            0xFF, 0x24, 0x85, 0x12, 0x10, 0x00, 0x00, // 0x1005: jmp [eax*4+0x1012]
            0xB8, 0x01, 0x00, 0x00, 0x00, // 0x100c: mov eax,1
            0xC3, // 0x1011: ret
            0x22, 0x10, 0x00, 0x00, // 0x1012: slot 0 -> 0x1022
            0x23, 0x10, 0x00, 0x00, // 0x1016: slot 1 -> 0x1023
        ];
        bytes.extend([0x90; 8]); // 0x101a: probe window (value unmapped)
        bytes.extend([0xC3, 0xC3]); // 0x1022/0x1023: bodies
        assert_eq!(bytes.len(), 36);
        // A budget below the unique-edge cost skips the whole site and
        // counts every edge that would have resolved, never a prefix.
        let (pairs, truncated, omitted, entries) = run_inferred_cap(&bytes, 1);
        assert_eq!(entries, [0x1000]);
        assert!(pairs.is_empty());
        assert!(truncated);
        assert_eq!(omitted, 2);
        // A full budget resolves both edges with clean accounting.
        let (pairs, truncated, omitted, _) = run_inferred_cap(&bytes, MAX_INFERRED_EDGES);
        assert_eq!(pairs, [(0x1005, 0x1022), (0x1005, 0x1023)]);
        assert!(!truncated);
        assert_eq!(omitted, 0);
    }

    #[test]
    fn seed_budget_truncates_accepted_prefix() {
        // 120k raw candidates with the first 12k reached: rejected rows must
        // not consume budget, so seeds are the next 100k accepted addresses.
        for arch in [
            Arch::Aarch64,
            Arch::Arm32,
            Arch::Thumb,
            Arch::X86_64,
            Arch::X86_32,
        ] {
            let (m, _, _) = seed_words(arch);
            let base: u64 = 0x1_0000;
            let period = m.len() as u64;
            let raw: usize = 120_000;
            let mut data = Vec::with_capacity(raw * m.len());
            for _ in 0..raw {
                data.extend_from_slice(m);
            }
            let bin = seed_test_binary(arch, None, vec![(base, data)]);
            let space = AddrSpace::new(&bin);
            let reached: BTreeSet<u64> = (0..12_000).map(|i| base + i * period).collect();
            let got = prologue_seeds(arch, &space, &reached).expect("streaming seeds");
            let want = oracle_seeds(arch, &space, &reached).expect("oracle seeds");
            assert_eq!(got.len(), MAX_SEEDS, "budget must fill for {arch:?}");
            assert_eq!(got, want, "truncated prefix mismatch for {arch:?}");
            assert_eq!(got[0], base + 12_000 * period);
            assert!(got.windows(2).all(|w| w[0] < w[1]));
        }
    }
}
