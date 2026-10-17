//! Xref index queries: indexed paths return the same rows as linear scans,
//! and `to` lookups stay fast on large xref sets.
//!
//! The oracles below filter `a.xrefs` (storage order) directly, mirroring
//! the old collect-all-then-scan path; the naive slice reimplements the old
//! per-call `HashMap` predecessor map. Any divergence fails.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Instant;

use binscout::analysis::{Analysis, BasicBlock, Diagnostics, Function, Xref, XrefKind};
use binscout::disasm::{Arch, Insn};

const KINDS: [XrefKind; 5] = [
    XrefKind::Code,
    XrefKind::Data,
    XrefKind::String,
    XrefKind::Import,
    XrefKind::InferredCode,
];

fn test_insn(addr: u64) -> Insn {
    Insn {
        addr,
        size: 1,
        bytes: vec![0x90],
        mnem: "nop".to_string(),
        ops: Vec::new(),
        branch_target: None,
        mem_target: None,
        table_base: None,
        import: None,
    }
}

/// `n` xrefs in `(from, kind, to)` order with shared `from`s and shared
/// `to`s, so every query shape has hits.
fn build_xrefs(n: usize) -> Vec<Xref> {
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        let g = i / 3;
        v.push(Xref {
            from: 0x1000 + (g as u64) * 0x10,
            to: 0x8000 + ((i * 7919) % 97) as u64,
            kind: KINDS[i % KINDS.len()],
        });
    }
    v.sort_by_key(|x| (x.from, x.kind, x.to));
    v
}

fn build_analysis(xrefs: Vec<Xref>) -> Analysis {
    Analysis::from_parts(
        Arch::X86_64,
        BTreeMap::new(),
        &[],
        xrefs,
        Vec::new(),
        Diagnostics::empty(),
    )
}

fn oracle_matching(
    xrefs: &[Xref],
    to: Option<u64>,
    from: Option<u64>,
    kind: Option<XrefKind>,
) -> Vec<Xref> {
    xrefs
        .iter()
        .copied()
        .filter(|x| to.is_none_or(|t| x.to == t))
        .filter(|x| from.is_none_or(|f| x.from == f))
        .filter(|x| kind.is_none_or(|k| x.kind == k))
        .collect()
}

#[test]
fn to_from_match_linear_oracle() {
    let a = build_analysis(build_xrefs(5_000));
    let mut tos: Vec<u64> = a.xrefs.iter().map(|x| x.to).collect();
    tos.sort_unstable();
    tos.dedup();
    let mut froms: Vec<u64> = a.xrefs.iter().map(|x| x.from).collect();
    froms.sort_unstable();
    froms.dedup();
    assert!(tos.len() > 10 && froms.len() > 10);
    for t in tos {
        assert_eq!(
            a.xrefs_to(t),
            oracle_matching(&a.xrefs, Some(t), None, None),
            "xrefs_to {t:#x}"
        );
    }
    for f in froms {
        assert_eq!(
            a.xrefs_from(f),
            oracle_matching(&a.xrefs, None, Some(f), None),
            "xrefs_from {f:#x}"
        );
    }
    assert!(a.xrefs_to(0x1).is_empty());
    assert!(a.xrefs_from(0x1).is_empty());
}

#[test]
fn matching_page_matches_oracle_count_and_items() {
    let a = build_analysis(build_xrefs(2_000));
    // Cold: the `to` index is not built yet, so `to`-only filters scan.
    check_matching_page(&a);
    // Warm: `xrefs_to` builds the index; the same filters must agree.
    for t in [0x8000, 0x8001, 0xdead] {
        let _ = a.xrefs_to(t);
    }
    check_matching_page(&a);
}

fn check_matching_page(a: &Analysis) {
    let tos = [None, Some(0x8000), Some(0x8001), Some(0xdead)];
    let froms = [None, Some(0x1000), Some(0x1010), Some(0xdead)];
    let kinds = [None, Some(XrefKind::Code), Some(XrefKind::Import)];
    let offsets = [0, 1, 5, 96, 97, 5_000, usize::MAX];
    let limits = [0, 1, 7, 1024, 5000, usize::MAX];
    for &to in &tos {
        for &from in &froms {
            for kind in kinds {
                let full = oracle_matching(&a.xrefs, to, from, kind);
                for &off in &offsets {
                    for &lim in &limits {
                        let (total, items) = a.xrefs_matching_page(to, from, kind, off, lim);
                        let want: Vec<Xref> =
                            full.iter().skip(off).take(lim.min(1024)).copied().collect();
                        assert_eq!(total, full.len(), "total {to:?} {from:?} {kind:?}");
                        assert_eq!(
                            items, want,
                            "page {to:?} {from:?} {kind:?} off={off} lim={lim}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn from_parts_sorts_unsorted_xrefs() {
    let mut xrefs = build_xrefs(1_000);
    xrefs.reverse();
    assert!(
        !xrefs
            .windows(2)
            .all(|w| (w[0].from, w[0].kind, w[0].to) <= (w[1].from, w[1].kind, w[1].to))
    );
    let a = build_analysis(xrefs);
    assert!(
        a.xrefs
            .windows(2)
            .all(|w| (w[0].from, w[0].kind, w[0].to) <= (w[1].from, w[1].kind, w[1].to)),
        "from_parts must restore (from, kind, to) order"
    );
    let t = a.xrefs[a.xrefs.len() / 2].to;
    let f = a.xrefs[a.xrefs.len() / 2].from;
    assert_eq!(
        a.xrefs_to(t),
        oracle_matching(&a.xrefs, Some(t), None, None)
    );
    assert_eq!(
        a.xrefs_from(f),
        oracle_matching(&a.xrefs, None, Some(f), None)
    );
}

/// Old per-call predecessor map, rebuilt from the public rows exactly as
/// the pre-index `slice_to` did.
fn naive_slice(a: &Analysis, addr: u64, max_depth: usize) -> Vec<(u64, usize)> {
    let cap = max_depth.min(binscout::analysis::MAX_SLICE_DEPTH);
    if cap == 0 {
        return Vec::new();
    }
    let mut xref_preds: HashMap<u64, Vec<u64>> = HashMap::new();
    for x in &a.xrefs {
        xref_preds.entry(x.to).or_default().push(x.from);
    }
    let mut seen: HashSet<u64> = HashSet::from([addr]);
    let mut queue: VecDeque<(u64, usize)> = VecDeque::from([(addr, 0)]);
    let mut out: Vec<(u64, usize)> = Vec::new();
    while let Some((cur, depth)) = queue.pop_front() {
        if depth >= cap {
            continue;
        }
        let mut next: Vec<u64> = Vec::new();
        if let Some(v) = xref_preds.get(&cur) {
            next.extend(v.iter().copied());
        }
        next.extend(naive_insn_preds(a, cur));
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

fn naive_insn_preds(a: &Analysis, cur: u64) -> Vec<u64> {
    let Some(entry) = a.containing_function(cur) else {
        return Vec::new();
    };
    let Some(f) = a.functions.get(&entry) else {
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

/// Small LCG so the differential slice test needs no extra dependency.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 33
}

fn build_slice_analysis() -> Analysis {
    let mut functions = BTreeMap::new();
    let mut insn_addrs = Vec::new();
    for fi in 0..4u64 {
        let entry = 0x1000 + fi * 0x100;
        let mut blocks = BTreeMap::new();
        let mut edges = Vec::new();
        for bi in 0..3u64 {
            let start = entry + bi * 0x10;
            let insns = vec![test_insn(start), test_insn(start + 1)];
            insn_addrs.push(start);
            insn_addrs.push(start + 1);
            blocks.insert(start, BasicBlock { start, insns });
            if bi > 0 {
                edges.push((entry + (bi - 1) * 0x10, start));
            }
        }
        functions.insert(
            entry,
            Function::from_parts(entry, None, blocks, &edges, Vec::new(), &[]),
        );
    }
    insn_addrs.push(0x9000);
    insn_addrs.push(0x9008);
    let mut rng = 0x1234_5678_9abc_def0u64;
    let mut xrefs = Vec::new();
    for _ in 0..400 {
        let from = insn_addrs[(lcg(&mut rng) as usize) % insn_addrs.len()];
        let to = insn_addrs[(lcg(&mut rng) as usize) % insn_addrs.len()];
        xrefs.push(Xref {
            from,
            to,
            kind: KINDS[(lcg(&mut rng) as usize) % KINDS.len()],
        });
    }
    xrefs.sort_by_key(|x| (x.from, x.kind, x.to));
    xrefs.dedup_by_key(|x| (x.from, x.kind, x.to));
    Analysis::from_parts(
        Arch::X86_64,
        functions,
        &[],
        xrefs,
        Vec::new(),
        Diagnostics::empty(),
    )
}

#[test]
fn slice_matches_naive_hashmap_path() {
    let a = build_slice_analysis();
    let mut roots: Vec<u64> = a.xrefs.iter().map(|x| x.to).collect();
    roots.sort_unstable();
    roots.dedup();
    roots.push(0x4242);
    for &root in &roots {
        for depth in [0, 1, 2, 3, 5, 64, usize::MAX] {
            assert_eq!(
                a.slice_to(root, depth),
                naive_slice(&a, root, depth),
                "slice_to {root:#x} depth={depth}"
            );
        }
    }
}

/// Hand-run measurement for the xref index (not a CI timing gate, following
/// `tests/mcp_workflow_perf.rs`: no assertion depends on wall-clock speed).
/// Canonical run (release; debug works but is slower and not comparable):
///
/// ```sh
/// cargo test --release --test xref_index -- --ignored --nocapture
/// ```
///
/// Compares the old per-request cost (one linear scan) against the indexed
/// paths: cold `xrefs_to` (one-time build plus search), warm lookups, the
/// cold-scan `xrefs_matching_page` fallback, and `slice_to`. Functional
/// equivalence IS asserted (every measured result matches the linear
/// oracle); only the printed timings are informational.
#[ignore]
#[test]
fn perf_to_lookup_scales() {
    for n in [50_000usize, 500_000] {
        let a = build_analysis(build_xrefs(n));
        // Old cost: one linear scan per request.
        let t0 = Instant::now();
        let mut expect = 0usize;
        for i in 0..50 {
            expect += oracle_matching(&a.xrefs, Some(0x8000 + (i % 97) as u64), None, None).len();
        }
        let scan_d = t0.elapsed();
        // Indexed: first call builds, the rest search.
        let t0 = Instant::now();
        let mut hits = 0usize;
        for i in 0..50 {
            hits += a.xrefs_to(0x8000 + (i % 97) as u64).len();
        }
        let indexed_d = t0.elapsed();
        assert_eq!(hits, expect, "indexed rows must match the oracle");
        // Single-shot page path stays a scan while the index is cold.
        let b = build_analysis(build_xrefs(n));
        let t0 = Instant::now();
        let (total, page) = b.xrefs_matching_page(Some(0x8000), None, None, 0, 50);
        let page_d = t0.elapsed();
        let want = oracle_matching(&b.xrefs, Some(0x8000), None, None);
        assert_eq!(total, want.len());
        assert_eq!(page, want.iter().take(50).copied().collect::<Vec<_>>());
        // Slice over the same graph.
        let t0 = Instant::now();
        let rows = a.slice_to(0x8000, 3).len();
        let slice_d = t0.elapsed();
        assert_eq!(rows, naive_slice(&a, 0x8000, 3).len());
        eprintln!(
            "n={n}: scan x50={scan_d:?} indexed x50={indexed_d:?} cold page={page_d:?} slice={slice_d:?} rows={rows}"
        );
    }
}
