//! M4 analysis: function discovery, CFGs, callgraph, xrefs, queries.
//!
//! [`analyze`] runs recursive descent over [`LoadedBinary`]: starting from
//! the entry point and export addresses, it decodes one instruction at a time
//! (`decode_one()`), follows direct branches and calls, and falls back to a
//! prologue scan for functions unreachable from those seeds. Decoded code is
//! split into basic blocks, each function gets a CFG and the whole binary a
//! callgraph (both `petgraph` maps), and cross-references are split into
//! code, data, and string refs.
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

use std::collections::{BTreeMap, BTreeSet};

use petgraph::graphmap::DiGraphMap;
use serde::{Deserialize, Serialize};

use crate::disasm::{Arch, Disassembler, Insn};
use crate::error::{Error, Result};
use crate::ir::IrOp;
use crate::loader::strings::{self, Encoding, StringHit};
use crate::loader::{LoadedBinary, RawOptions, Section, Segment, load_raw};

/// Cap on decoded instructions per [`analyze`] call.
pub const MAX_TOTAL_INSNS: usize = 1_000_000;
/// Cap on discovered function entries per [`analyze`] call.
pub const MAX_FUNCTIONS: usize = 100_000;
/// Cap on cross-references of each kind per [`analyze`] call.
pub const MAX_XREFS_PER_KIND: usize = 1_000_000;
/// Cap on discovery seeds (entry/exports/prologues) per call.
pub const MAX_SEEDS: usize = 100_000;
/// Query pages longer than this are truncated.
pub const MAX_PAGE: usize = 1024;

/// What a cross-reference points through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum XrefKind {
    /// Branch/call target reference.
    Code,
    /// Data access reference (PC-relative slot or absolute pointer).
    Data,
    /// Reference into an extracted string.
    String,
}

/// One cross-reference: instruction at `from` refers to `to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Xref {
    /// Address of the referring instruction.
    pub from: u64,
    /// Referenced address (code target, data address, or string start).
    pub to: u64,
    /// How the reference is made.
    pub kind: XrefKind,
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
    /// Export/symbol name when one resolves to `entry`.
    pub name: Option<String>,
    /// Basic blocks keyed by start address.
    pub blocks: BTreeMap<u64, BasicBlock>,
    cfg: DiGraphMap<u64, ()>,
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

    /// All CFG edges as `(from_block, to_block)` pairs.
    #[must_use]
    pub fn edges(&self) -> Vec<(u64, u64)> {
        self.cfg.all_edges().map(|(a, b, _)| (a, b)).collect()
    }

    /// Rebuild a function from persisted rows (M5 redb round-trip).
    ///
    /// `edges` are `(from_block, to_block)` pairs within this function.
    #[must_use]
    pub fn from_parts(
        entry: u64,
        name: Option<String>,
        blocks: BTreeMap<u64, BasicBlock>,
        edges: &[(u64, u64)],
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
        Self {
            entry,
            name,
            blocks,
            cfg,
        }
    }
}

/// Whole-binary analysis result.
#[derive(Debug, Clone)]
pub struct Analysis {
    /// Disassembler target the binary was decoded as.
    pub arch: Arch,
    /// Discovered functions keyed by entry address.
    pub functions: BTreeMap<u64, Function>,
    callgraph: DiGraphMap<u64, ()>,
    /// Code, data, and string xrefs sorted by `(from, kind, to)`.
    pub xrefs: Vec<Xref>,
    /// Extracted strings sorted by address.
    pub strings: Vec<StringHit>,
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

    /// All callgraph edges as `(caller, callee)` pairs.
    #[must_use]
    pub fn call_edges(&self) -> Vec<(u64, u64)> {
        self.callgraph.all_edges().map(|(a, b, _)| (a, b)).collect()
    }

    /// Rebuild analysis from persisted rows (M5 redb round-trip).
    ///
    /// Drops call edges pointing at unknown functions, mirroring [`analyze`].
    #[must_use]
    pub fn from_parts(
        arch: Arch,
        functions: BTreeMap<u64, Function>,
        call_edges: &[(u64, u64)],
        xrefs: Vec<Xref>,
        strings: Vec<StringHit>,
    ) -> Self {
        let mut callgraph = DiGraphMap::<u64, ()>::new();
        for e in functions.keys() {
            callgraph.add_node(*e);
        }
        for &(a, b) in call_edges {
            if functions.contains_key(&a) && functions.contains_key(&b) {
                callgraph.add_edge(a, b, ());
            }
        }
        Self {
            arch,
            functions,
            callgraph,
            xrefs,
            strings,
        }
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// One block row for list views (instructions come via [`Analysis::block_insns`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        let rows: Vec<FunctionSummary> = self
            .functions
            .values()
            .map(|f| FunctionSummary {
                id: f.id(),
                entry: f.entry,
                name: f.name.clone(),
                blocks: f.blocks.len(),
                insns: f.insn_count(),
                calls: self.calls_of(f.entry),
            })
            .collect();
        page_slice(&rows, offset, limit)
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
        let rows: Vec<BlockSummary> = f
            .blocks
            .values()
            .map(|b| BlockSummary {
                id: b.id(func_entry),
                start: b.start,
                end: b.end(),
                insns: b.insns.len(),
                succs: f.successors(b.start),
            })
            .collect();
        Some(page_slice(&rows, offset, limit))
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
        let rows: Vec<Xref> = match kind {
            Some(k) => self.xrefs.iter().copied().filter(|x| x.kind == k).collect(),
            None => self.xrefs.clone(),
        };
        page_slice(&rows, offset, limit)
    }

    /// Xrefs pointing at `addr`.
    #[must_use]
    pub fn xrefs_to(&self, addr: u64) -> Vec<Xref> {
        self.xrefs
            .iter()
            .copied()
            .filter(|x| x.to == addr)
            .collect()
    }

    /// Xrefs originating at `addr`.
    #[must_use]
    pub fn xrefs_from(&self, addr: u64) -> Vec<Xref> {
        self.xrefs
            .iter()
            .copied()
            .filter(|x| x.from == addr)
            .collect()
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
        let show_code = filter.include_code || filter.section.is_some() || filter.pattern.is_some();
        let mut rows: Vec<StringHit> = Vec::new();
        for h in &self.strings {
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
            if let Some(pat) = &filter.pattern
                && !strings::matches_pattern(&h.value, pat)?
            {
                continue;
            }
            rows.push(h.clone());
        }
        Ok(page_slice(&rows, filter.start, filter.limit))
    }
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

fn classify(arch: Arch, insn: &Insn) -> Flow {
    match crate::ir::lift(arch, insn)
        .first()
        .map(|i| (i.op, i.target))
    {
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
/// undecodable bytes end that path, they are not an error. A trailing-garbage
/// window on x86 shrinks until the first instruction decodes, since later
/// bytes cannot change the first decode.
fn decode_one(arch: Arch, space: &AddrSpace, va: u64) -> Result<Option<Insn>> {
    let bytes = match space.code_bytes(va) {
        Some(b) if !b.is_empty() => b,
        _ => return Ok(None),
    };
    let dis = arch.disassembler();
    match arch {
        Arch::X86_64 | Arch::X86_32 => {
            let mut len = bytes.len().min(15);
            loop {
                match dis.disasm_range(&bytes[..len], va) {
                    Ok(mut v) if !v.is_empty() => return Ok(Some(v.remove(0))),
                    Ok(_) => return Ok(None),
                    Err(Error::Invalid(_)) if len > 1 => len -= 1,
                    Err(Error::Invalid(_)) => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
        }
        Arch::Aarch64 => {
            if bytes.len() < 4 {
                return Ok(None);
            }
            match dis.disasm_range(&bytes[..4], va) {
                Ok(mut v) if !v.is_empty() => Ok(Some(v.remove(0))),
                Ok(_) => Ok(None),
                Err(Error::Invalid(_)) => Ok(None),
                Err(e) => Err(e),
            }
        }
    }
}

struct Decoded {
    insn: Insn,
    flow: Flow,
}

/// Seed addresses from the entry point and exports resolving to executable
/// code. When neither exists (raw blobs, stripped objects), the first
/// executable byte seeds analysis so some function is always found.
fn authoritative_seeds(space: &AddrSpace, bin: &LoadedBinary) -> Vec<u64> {
    let mut seeds: Vec<u64> = Vec::new();
    if let Some(entry) = bin.entry
        && space.code_bytes(entry).is_some()
    {
        seeds.push(entry);
    }
    for exp in &bin.exports {
        if let Some(addr) = exp.address
            && seeds.len() < MAX_SEEDS
            && space.code_bytes(addr).is_some()
        {
            seeds.push(addr);
        }
    }
    if seeds.is_empty()
        && let Some(base) = space.first_exec_base()
    {
        seeds.push(base);
    }
    seeds.sort_unstable();
    seeds.dedup();
    seeds
}

/// Prologue-scan hits outside `reached` that decode. These seed the second
/// round and become entries; hits inside already-reached code stay plain code
/// so mid-function frame setups never split their function.
fn prologue_seeds(arch: Arch, space: &AddrSpace, reached: &BTreeSet<u64>) -> Result<Vec<u64>> {
    let mut seeds: Vec<u64> = Vec::new();
    for va in prologue_scan(arch, space) {
        if seeds.len() >= MAX_SEEDS {
            break;
        }
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
        Arch::Aarch64 => &[],
    }
}

/// Scan executable segments for function prologues. AArch64 matches
/// `stp x29, x30, [sp, #imm]!` words under a mask; x86 matches byte
/// patterns, stepping back over a leading `push rbp`/`push ebp`.
fn prologue_scan(arch: Arch, space: &AddrSpace) -> Vec<u64> {
    let mut out = Vec::new();
    for seg in &space.exec {
        if arch == Arch::Aarch64 {
            let mut off = 0usize;
            while off + 4 <= seg.data.len() {
                let w = u32::from_le_bytes(seg.data[off..off + 4].try_into().unwrap());
                if (w & 0xFFC0_7FFF) == 0xA980_7BFD {
                    out.push(seg.vaddr.wrapping_add(off as u64));
                }
                off += 4;
            }
            continue;
        }
        for pat in prologue_patterns(arch) {
            for (i, win) in seg.data.windows(pat.len()).enumerate() {
                if win != *pat {
                    continue;
                }
                let mut va = seg.vaddr.wrapping_add(i as u64);
                // `push rbp`/`push ebp` is 0x55 on both x86 targets.
                if i > 0 && seg.data[i - 1] == 0x55 {
                    va = va.wrapping_sub(1);
                }
                out.push(va);
                if out.len() >= MAX_SEEDS {
                    return out;
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Recursive-descent worklist state shared across seed rounds.
struct Walker<'a> {
    arch: Arch,
    space: &'a AddrSpace<'a>,
    decoded: BTreeMap<u64, Decoded>,
    jump_targets: BTreeSet<u64>,
    fallthroughs: BTreeSet<u64>,
    call_targets: BTreeSet<u64>,
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
        }
    }

    /// Decode from `seeds`, following direct branches, calls, and fallthrough.
    fn run(&mut self, seeds: Vec<u64>) -> Result<()> {
        let mut stack = seeds;
        while let Some(va) = stack.pop() {
            if self.decoded.contains_key(&va) {
                continue;
            }
            if self.decoded.len() >= MAX_TOTAL_INSNS {
                return Err(Error::Limit(format!(
                    "more than {MAX_TOTAL_INSNS} instructions"
                )));
            }
            let Some(insn) = decode_one(self.arch, self.space, va)? else {
                continue;
            };
            let flow = classify(self.arch, &insn);
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
        Ok(())
    }
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
    let seeds1 = authoritative_seeds(&space, bin);
    walk.run(seeds1.clone())?;
    let round1: BTreeSet<u64> = walk.decoded.keys().copied().collect();
    let seeds2 = prologue_seeds(arch, &space, &round1)?;
    walk.run(seeds2.clone())?;
    let Walker {
        decoded,
        jump_targets,
        fallthroughs,
        call_targets,
        ..
    } = walk;

    if decoded.is_empty() {
        return Ok(Analysis {
            arch,
            functions: BTreeMap::new(),
            callgraph: DiGraphMap::new(),
            xrefs: Vec::new(),
            strings: Vec::new(),
        });
    }

    // Function entries: both rounds' seeds that decoded, plus direct call
    // targets. Round-one hits are excluded by construction: `seeds2` only
    // holds prologue matches outside round-one code.
    let mut entries: BTreeSet<u64> = BTreeSet::new();
    for s in seeds1.iter().chain(seeds2.iter()) {
        if decoded.contains_key(s) {
            entries.insert(*s);
        }
    }
    for t in &call_targets {
        if decoded.contains_key(t) {
            entries.insert(*t);
        }
    }
    if entries.is_empty()
        && let Some((&first, _)) = decoded.iter().next()
    {
        entries.insert(first);
    }
    if entries.len() > MAX_FUNCTIONS {
        return Err(Error::Limit(format!("more than {MAX_FUNCTIONS} functions")));
    }
    let entry_list: Vec<u64> = entries.iter().copied().collect();
    let owner = |va: u64| -> u64 {
        match entry_list.iter().rfind(|e| **e <= va) {
            Some(e) => *e,
            None => entry_list[0],
        }
    };

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

    // Export names for entries.
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    for exp in &bin.exports {
        if let Some(addr) = exp.address {
            names.entry(addr).or_insert_with(|| exp.name.clone());
        }
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
            },
        );
    }
    for (start, block) in blocks {
        let o = owner(start);
        if let Some(f) = functions.get_mut(&o) {
            f.cfg.add_node(start);
            f.blocks.insert(start, block);
        }
    }
    functions.retain(|_, f| !f.blocks.is_empty());

    let mut callgraph = DiGraphMap::<u64, ()>::new();
    for e in functions.keys() {
        callgraph.add_node(*e);
    }
    // Block-end lookup for edge targets.
    let keys: Vec<u64> = functions.keys().copied().collect();
    let mut cfg_edges: Vec<(u64, u64, u64)> = Vec::new();
    let mut cg_edges: Vec<(u64, u64)> = Vec::new();
    for entry in keys {
        let f = &functions[&entry];
        for (start, block) in &f.blocks {
            let last = block.insns.last().expect("blocks hold at least one insn");
            let flow = classify(arch, last);
            let end = block.end();
            match flow {
                Flow::Branch { target: Some(t) } => {
                    if f.blocks.contains_key(&t) {
                        cfg_edges.push((entry, *start, t));
                    } else if decoded.contains_key(&t) {
                        cg_edges.push((entry, owner(t)));
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
                    {
                        cg_edges.push((entry, owner(t)));
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
        functions
            .get_mut(&func)
            .expect("function retained")
            .cfg
            .add_edge(a, b, ());
    }
    for (a, b) in cg_edges {
        if functions.contains_key(&b) {
            callgraph.add_edge(a, b, ());
        }
    }

    // Pass D: xrefs. Code from direct branch/call targets, data from
    // PC-relative accesses and x86-32 absolute immediates/displacements
    // into a segment, string refs where data lands in a recovered string.
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
    let data_tos: Vec<(u64, u64)> = xrefs
        .iter()
        .filter(|(_, k, _)| *k == XrefKind::Data)
        .map(|(f, _, t)| (*f, *t))
        .collect();
    for (from, to) in data_tos {
        for (s, e) in &spans {
            if to >= *s && to < *e {
                xrefs.insert((from, XrefKind::String, *s));
                break;
            }
        }
    }
    let xrefs: Vec<Xref> = xrefs
        .into_iter()
        .map(|(from, kind, to)| Xref { from, to, kind })
        .collect();
    for kind in [XrefKind::Code, XrefKind::Data, XrefKind::String] {
        if xrefs.iter().filter(|x| x.kind == kind).count() > MAX_XREFS_PER_KIND {
            return Err(Error::Limit(format!(
                "more than {MAX_XREFS_PER_KIND} {kind:?} xrefs"
            )));
        }
    }

    Ok(Analysis {
        arch,
        functions,
        callgraph,
        xrefs,
        strings,
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
    fn classify_maps_lift_ops() {
        let ret = Insn {
            addr: 0x1000,
            size: 1,
            bytes: vec![0xC3],
            mnem: "ret".to_string(),
            ops: Vec::new(),
            branch_target: None,
            mem_target: None,
        };
        assert_eq!(classify(Arch::X86_64, &ret), Flow::Ret);
        let call = Insn {
            addr: 0x1000,
            size: 5,
            bytes: vec![0xE8, 0, 0, 0, 0],
            mnem: "call".to_string(),
            ops: vec!["0x1005".to_string()],
            branch_target: Some(0x1005),
            mem_target: None,
        };
        assert_eq!(
            classify(Arch::X86_64, &call),
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
}
