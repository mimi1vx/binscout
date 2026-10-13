//! Differential tests for [`binscout::analysis::StringSpanIndex`]: the
//! prefix-maximum string-span lookup must preserve the old linear scan's
//! first-overlap match, plus a comparison-count benchmark of many missed
//! refs against many spans.

mod common;

use std::collections::BTreeSet;
use std::time::Instant;

use binscout::analysis::{StringSpanIndex, XrefKind, analyze, analyze_raw};
use binscout::disasm::Arch;
use binscout::loader::strings::Encoding;

use common::builders;

/// Old linear scan: earliest `(start, end)` with `start <= target < end`.
fn linear(spans: &[(u64, u64)], target: u64) -> Option<u64> {
    spans
        .iter()
        .find(|&&(s, e)| target >= s && target < e)
        .map(|&(s, _)| s)
}

/// Sort `spans` stably by start (as `analyze` does) and assert the index
/// agrees with the linear oracle on every target.
fn check(spans: Vec<(u64, u64)>, targets: &[u64]) {
    let mut sorted = spans;
    sorted.sort_by_key(|&(s, _)| s);
    let index = StringSpanIndex::new(sorted.clone());
    for &t in targets {
        assert_eq!(
            index.lookup(t),
            linear(&sorted, t),
            "spans={sorted:?} target={t:#x}"
        );
    }
}

/// Assert agreement on every target in `0..end`.
fn check_dense(spans: Vec<(u64, u64)>, end: u64) {
    let targets: Vec<u64> = (0..end).collect();
    check(spans, &targets);
}

#[test]
fn misses_before_between_and_after() {
    check(vec![(10, 20), (30, 40)], &[0, 9, 20, 21, 29, 40, 41, 100]);
    check(vec![], &[0, 10, u64::MAX]);
    check_dense(vec![(10, 20), (30, 40)], 50);
}

#[test]
fn starts_match_and_ends_are_exclusive() {
    check(vec![(10, 20), (20, 30)], &[10, 11, 19, 20, 21, 29, 30, 31]);
    check_dense(vec![(10, 20), (20, 30)], 35);
}

#[test]
fn duplicate_starts_agree() {
    check(vec![(10, 20), (10, 30)], &[9, 10, 15, 19, 20, 25, 29, 30]);
    check(vec![(10, 20), (10, 20)], &[10, 15, 19, 20]);
    check_dense(vec![(10, 20), (10, 30)], 35);
}

#[test]
fn nested_span_contains_past_narrow_end() {
    // A naive last-start predecessor lookup reports a miss for 50 (last
    // start 10, end 11); the first match is the wide span at 0.
    check(vec![(0, 100), (10, 11)], &[0, 9, 10, 11, 12, 50, 99, 100]);
    check(vec![(0, 10), (5, 15)], &[0, 4, 5, 9, 10, 12, 14, 15]);
    check(
        vec![(0, 10), (5, 6), (7, 100)],
        &[0, 5, 6, 7, 9, 10, 50, 99, 100],
    );
    check_dense(vec![(0, 100), (10, 11)], 110);
    check_dense(vec![(0, 10), (5, 15)], 20);
}

#[test]
fn segment_overlap_keeps_first_match() {
    // Two segments' strings overlapping at 0x4004: targets inside both
    // resolve to the earlier span at 0x4000.
    check(
        vec![(0x4000, 0x4008), (0x4004, 0x400C)],
        &[
            0x3FFF, 0x4000, 0x4003, 0x4004, 0x4007, 0x4008, 0x400B, 0x400C,
        ],
    );
    let gap_targets: Vec<u64> = (0x3FFEu64..0x400E).collect();
    check(vec![(0x4000, 0x4008), (0x4004, 0x400C)], &gap_targets);
}

#[test]
fn wrapped_and_empty_spans_never_match() {
    let wrap_start = u64::MAX - 5;
    let wrap_end = wrap_start.wrapping_add(10);
    assert_eq!(wrap_end, 4);
    check(
        vec![(wrap_start, wrap_end)],
        &[wrap_start - 1, wrap_start, u64::MAX, 0, 2, 4, 5],
    );
    check(
        vec![(0, 100), (u64::MAX - 10, 5)],
        &[0, 2, 50, 99, 100, 200, u64::MAX - 10, u64::MAX - 1],
    );
    check(vec![(10, 10)], &[9, 10, 11]);
    check(vec![(0, 0)], &[0, 1]);
}

fn spans_of(a: &binscout::analysis::Analysis) -> Vec<(u64, u64)> {
    let mut spans: Vec<(u64, u64)> = a
        .strings
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
    spans.sort_by_key(|&(s, _)| s);
    spans
}

/// String xrefs recomputed with the linear oracle must equal the stored
/// ones, and the full xref vector must stay in `(from, kind, to)` order.
fn assert_xrefs_match_oracle(a: &binscout::analysis::Analysis) {
    let spans = spans_of(a);
    let index = StringSpanIndex::new(spans.clone());
    let mut expect: BTreeSet<(u64, XrefKind, u64)> = BTreeSet::new();
    for x in &a.xrefs {
        if x.kind == XrefKind::Data {
            assert_eq!(
                index.lookup(x.to),
                linear(&spans, x.to),
                "index/oracle diverge at data target {:#x}",
                x.to
            );
            if let Some(s) = linear(&spans, x.to) {
                expect.insert((x.from, XrefKind::String, s));
            }
        }
    }
    let actual: BTreeSet<(u64, XrefKind, u64)> = a
        .xrefs
        .iter()
        .filter(|x| x.kind == XrefKind::String)
        .map(|x| (x.from, x.kind, x.to))
        .collect();
    assert_eq!(actual, expect, "string xrefs must equal the oracle set");
    assert!(
        a.xrefs
            .windows(2)
            .all(|w| (w[0].from, w[0].kind, w[0].to) <= (w[1].from, w[1].kind, w[1].to)),
        "xrefs must stay in (from, kind, to) order"
    );
}

#[test]
fn xref_ordering_kinds_targets_match_oracle_on_fixtures() {
    let bytes = common::fixture_bytes(builders::BASIC_NAME);
    let bin = binscout::loader::load(&bytes).expect("synthetic PE32 must load");
    let a = analyze(&bin).expect("PE32 analyzes");
    assert_xrefs_match_oracle(&a);
    assert!(
        a.xrefs_page(Some(XrefKind::String), 0, 64).len() >= 2,
        "basic fixture keeps its two string refs"
    );

    // Raw blob: lea rdi,[rip+5] | ret | nop*4 | "test!\0".
    let mut b = vec![0x48, 0x8D, 0x3D, 0x05, 0x00, 0x00, 0x00, 0xC3];
    b.extend([0x90; 4]);
    b.extend(*b"test!\0");
    let r = analyze_raw(&b, 0x4000, Arch::X86_64, Some(0x4000)).expect("raw analyzes");
    assert_xrefs_match_oracle(&r);
}

#[test]
fn benchmark_many_missed_refs_against_many_spans() {
    const SPANS: usize = 2_000;
    const REFS: usize = 20_000;
    let spans: Vec<(u64, u64)> = (0..SPANS as u64).map(|i| (i * 100, i * 100 + 10)).collect();
    let targets: Vec<u64> = (0..REFS as u64)
        .map(|i| (i % SPANS as u64) * 100 + 50)
        .collect();

    let t0 = Instant::now();
    let linear_out: Vec<Option<u64>> = targets.iter().map(|&t| linear(&spans, t)).collect();
    let linear_ns = t0.elapsed();
    let linear_cmps = REFS * SPANS;

    let t1 = Instant::now();
    let index = StringSpanIndex::new(spans.clone());
    let build_ns = t1.elapsed();
    let t2 = Instant::now();
    let indexed_out: Vec<Option<u64>> = targets.iter().map(|&t| index.lookup(t)).collect();
    let query_ns = t2.elapsed();
    assert_eq!(indexed_out, linear_out, "indexed output must equal linear");
    assert!(
        indexed_out.iter().all(|o| o.is_none()),
        "gap targets must all miss"
    );

    // Comparison-count evidence with the same predicates as production:
    // rebuild the prefix-maximum array with the same `max` fold over the
    // same sorted spans, then count every predicate evaluation.
    let mut running: u64 = 0;
    let mut prefix_max = Vec::with_capacity(spans.len());
    for &(_, e) in &spans {
        running = running.max(e);
        prefix_max.push(running);
    }
    let mut indexed_cmps = 0usize;
    for &t in &targets {
        let cand = prefix_max.partition_point(|&m| {
            indexed_cmps += 1;
            m <= t
        });
        if cand < spans.len() {
            let upto = spans.partition_point(|&(s, _)| {
                indexed_cmps += 1;
                s <= t
            });
            if cand < upto {
                let (s, e) = spans[cand];
                indexed_cmps += 1;
                if t >= s {
                    indexed_cmps += 1;
                    assert!(t >= e, "gap target must fail the end check");
                }
            }
        }
    }
    eprintln!(
        "string-span bench: spans={SPANS} refs={REFS} linear_cmps={linear_cmps} \
         indexed_cmps={indexed_cmps} linear={linear_ns:?} build={build_ns:?} query={query_ns:?}"
    );
    assert!(
        indexed_cmps < linear_cmps / 10,
        "indexed comparisons ({indexed_cmps}) must be an order of magnitude below linear ({linear_cmps})"
    );
}
