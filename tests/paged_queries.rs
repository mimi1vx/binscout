//! Paged-query allocation bounds: differential equivalence plus page-sized
//! intermediates.
//!
//! The `Analysis` page helpers must return the identical bounded page as the
//! old collect-all-then-slice path while cloning only the selected page.
//! `strings_page_filtered` additionally preserves lazy pattern error
//! semantics (bad/overlong patterns error only when a row survives earlier
//! filters, even for zero-limit/beyond-end pages).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;

use binscout::analysis::{Analysis, MAX_PAGE, StringsFilter, Xref, XrefKind};
use binscout::disasm::{Arch, Insn};
use binscout::loader::strings::{Encoding, MAX_PATTERN_LEN, StringHit};

thread_local! {
    static THREAD_ALLOC_BYTES: Cell<usize> = const { Cell::new(0) };
    static THREAD_ALLOC_COUNT: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        THREAD_ALLOC_BYTES.with(|b| b.set(b.get().saturating_add(layout.size())));
        THREAD_ALLOC_COUNT.with(|c| c.set(c.get().saturating_add(1)));
        // SAFETY: delegates to the system allocator with the same layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: delegates to the system allocator with the same layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn reset_thread_allocs() {
    THREAD_ALLOC_BYTES.with(|b| b.set(0));
    THREAD_ALLOC_COUNT.with(|c| c.set(0));
}

fn thread_allocs() -> (usize, usize) {
    (
        THREAD_ALLOC_COUNT.with(|c| c.get()),
        THREAD_ALLOC_BYTES.with(|b| b.get()),
    )
}

fn oracle_slice<T: Clone>(items: &[T], offset: usize, limit: usize) -> Vec<T> {
    items
        .iter()
        .skip(offset)
        .take(limit.min(MAX_PAGE))
        .cloned()
        .collect()
}

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
        target_name: None,
        comment: None,
        string: None,
        operands: Vec::new(),
    }
}

fn build_functions(n: usize) -> BTreeMap<u64, binscout::analysis::Function> {
    let mut map = BTreeMap::new();
    for i in 0..n {
        let entry = 0x1000 + (i as u64) * 0x10;
        let mut blocks = BTreeMap::new();
        blocks.insert(
            entry,
            binscout::analysis::BasicBlock {
                start: entry,
                insns: vec![test_insn(entry)],
            },
        );
        let name = if i % 2 == 0 {
            Some(format!("fn-{i:05}"))
        } else {
            None
        };
        map.insert(
            entry,
            binscout::analysis::Function::from_parts(
                entry,
                name,
                blocks,
                &[],
                Vec::new(),
                &[],
                None,
            ),
        );
    }
    map
}

fn build_blocks_analysis(n_blocks: usize) -> Analysis {
    let entry = 0x2000;
    let mut blocks = BTreeMap::new();
    for i in 0..n_blocks {
        let start = entry + (i as u64) * 0x10;
        blocks.insert(
            start,
            binscout::analysis::BasicBlock {
                start,
                insns: vec![test_insn(start)],
            },
        );
    }
    let mut functions = BTreeMap::new();
    functions.insert(
        entry,
        binscout::analysis::Function::from_parts(
            entry,
            Some("many-blocks".to_string()),
            blocks,
            &[],
            Vec::new(),
            &[],
            None,
        ),
    );
    Analysis::from_parts(
        Arch::X86_64,
        functions,
        &[],
        Vec::new(),
        Vec::new(),
        binscout::analysis::Diagnostics::empty(),
    )
}

fn build_xrefs(n: usize) -> Vec<Xref> {
    (0..n)
        .map(|i| Xref {
            from: 0x1000 + (i as u64) * 4,
            to: 0x5000 + ((i % 7) as u64),
            kind: match i % 3 {
                0 => XrefKind::Code,
                1 => XrefKind::Data,
                _ => XrefKind::String,
            },
        })
        .collect()
}

fn build_strings(n: usize) -> Vec<StringHit> {
    (0..n)
        .map(|i| StringHit {
            offset: i * 32,
            vaddr: Some(0x4000 + (i as u64) * 32),
            encoding: Encoding::Ascii,
            value: format!("qmatch-{i:05}-abcdef"),
            section: Some(if i % 5 == 0 {
                ".text".to_string()
            } else {
                ".rdata".to_string()
            }),
            executable: i % 5 == 0,
        })
        .collect()
}

fn build_analysis(funcs: usize, xrefs: usize, strings: usize) -> Analysis {
    Analysis::from_parts(
        Arch::X86_64,
        build_functions(funcs),
        &[],
        build_xrefs(xrefs),
        build_strings(strings),
        binscout::analysis::Diagnostics::empty(),
    )
}

fn offsets(n: usize) -> Vec<usize> {
    vec![
        0,
        1,
        2,
        5,
        n.saturating_sub(1),
        n,
        n.saturating_add(5),
        usize::MAX - 1,
        usize::MAX,
    ]
}

fn limits() -> Vec<usize> {
    vec![0, 1, 2, 5, MAX_PAGE - 1, MAX_PAGE, MAX_PAGE + 1, usize::MAX]
}

#[test]
fn functions_page_matches_collect_all_oracle() {
    let n = 60;
    let a = build_analysis(n, 0, 0);
    // Oracle rows in storage (entry) order, as the old path built them.
    for &off in &offsets(n) {
        for &lim in &limits() {
            let full: Vec<_> = a
                .functions
                .values()
                .map(|f| binscout::analysis::FunctionSummary {
                    id: f.id(),
                    entry: f.entry,
                    name: f.name.clone(),
                    blocks: f.blocks.len(),
                    insns: f.insn_count(),
                    calls: a.calls_of(f.entry),
                    noreturn: f.noreturn,
                })
                .collect();
            let want = oracle_slice(&full, off, lim);
            let got = a.functions_page(off, lim);
            assert_eq!(got, want, "functions_page off={off} lim={lim}");
        }
    }
}

#[test]
fn blocks_page_matches_oracle_and_none_semantics() {
    let n = 60;
    let a = build_blocks_analysis(n);
    assert!(a.blocks_page(0x9999, 0, 10).is_none());
    for &off in &offsets(n) {
        for &lim in &limits() {
            let f = a.functions.get(&0x2000).expect("fixture func");
            let full: Vec<_> = f
                .blocks
                .values()
                .map(|b| binscout::analysis::BlockSummary {
                    id: b.id(0x2000),
                    start: b.start,
                    end: b.end(),
                    insns: b.insns.len(),
                    succs: f.successors(b.start),
                })
                .collect();
            let want = oracle_slice(&full, off, lim);
            let got = a.blocks_page(0x2000, off, lim).expect("known func is Some");
            assert_eq!(got, want, "blocks_page off={off} lim={lim}");
        }
    }
    // Known function, beyond-end page is Some(empty), not None.
    assert_eq!(
        a.blocks_page(0x2000, n + 100, 10)
            .expect("beyond end is Some"),
        Vec::new()
    );
}

#[test]
fn xrefs_page_matches_oracle_for_all_kinds() {
    let n = 90;
    let a = build_analysis(0, n, 0);
    let kinds = [
        None,
        Some(XrefKind::Code),
        Some(XrefKind::Data),
        Some(XrefKind::String),
    ];
    for kind in kinds {
        let full: Vec<Xref> = match kind {
            Some(k) => a.xrefs.iter().copied().filter(|x| x.kind == k).collect(),
            None => a.xrefs.clone(),
        };
        for &off in &offsets(full.len()) {
            for &lim in &limits() {
                let want = oracle_slice(&full, off, lim);
                let got = a.xrefs_page(kind, off, lim);
                assert_eq!(got, want, "xrefs_page {kind:?} off={off} lim={lim}");
            }
        }
    }
}

#[test]
fn empty_sets_page_empty() {
    let a = Analysis::from_parts(
        Arch::X86_64,
        BTreeMap::new(),
        &[],
        Vec::new(),
        Vec::new(),
        binscout::analysis::Diagnostics::empty(),
    );
    for &off in &[0, 1, usize::MAX] {
        for &lim in &[0, 1, MAX_PAGE + 1, usize::MAX] {
            assert!(a.functions_page(off, lim).is_empty());
            assert!(a.xrefs_page(None, off, lim).is_empty());
            assert!(a.xrefs_page(Some(XrefKind::Code), off, lim).is_empty());
            assert!(a.strings_page(off, lim).is_empty());
            let f = StringsFilter {
                start: off,
                limit: lim,
                ..StringsFilter::default()
            };
            assert!(
                a.strings_page_filtered(&f)
                    .expect("empty filters work")
                    .is_empty()
            );
        }
    }
    assert!(a.blocks_page(0x1000, 0, 10).is_none());
}

fn filtered_oracle(a: &Analysis, filter: &StringsFilter) -> Result<Vec<StringHit>, String> {
    let show_code = filter.include_code || filter.section.is_some() || filter.pattern.is_some();
    let mut matcher: Option<binscout::loader::strings::PatternMatcher<'_>> = None;
    let mut rows: Vec<StringHit> = Vec::new();
    for h in &a.strings {
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
                matcher = Some(
                    binscout::loader::strings::PatternMatcher::compile(pat)
                        .map_err(|e| format!("{e:?}"))?,
                );
            }
            if !matcher.as_ref().expect("compiled").is_match(&h.value) {
                continue;
            }
        }
        rows.push(h.clone());
    }
    Ok(oracle_slice(&rows, filter.start, filter.limit))
}

#[test]
fn filtered_strings_match_oracle_across_paging_and_filters() {
    let a = build_analysis(0, 0, 200);
    let patterns: Vec<Option<String>> = vec![
        None,
        Some(String::new()),
        Some("qmatch-".to_string()),
        Some("00001".to_string()),
        Some("QMATCH-".to_string()),
        Some("regex:qmatch-[0-9]+-abcdef".to_string()),
        Some("regex:^qmatch-00001-abcdef$".to_string()),
    ];
    let mut filters: Vec<StringsFilter> = Vec::new();
    for pattern in &patterns {
        for section in [
            None,
            Some(".rdata".to_string()),
            Some(".text".to_string()),
            Some(".nope".to_string()),
        ] {
            for min_len in [None, Some(1), Some(18), Some(10_000)] {
                for include_code in [false, true] {
                    filters.push(StringsFilter {
                        pattern: pattern.clone(),
                        section: section.clone(),
                        min_len,
                        include_code,
                        start: 0,
                        limit: 50,
                    });
                }
            }
        }
    }
    for base in filters {
        // all_matching-style paging sweep plus edge offsets/limits
        let total = a.strings.len();
        for &start in &offsets(total) {
            for &limit in &limits() {
                let f = StringsFilter {
                    start,
                    limit,
                    ..base.clone()
                };
                let want = filtered_oracle(&a, &f).expect("valid patterns must succeed");
                let got = a
                    .strings_page_filtered(&f)
                    .expect("valid patterns must succeed");
                assert_eq!(
                    got, want,
                    "filtered mismatch pattern={:?} section={:?} min_len={:?} code={} start={start} limit={limit}",
                    base.pattern, base.section, base.min_len, base.include_code,
                );
            }
        }
    }
}

#[test]
fn invalid_pattern_error_behavior_unchanged() {
    let a = build_analysis(0, 0, 200);
    let bad = "regex:([".to_string();
    let overlong = "y".repeat(MAX_PATTERN_LEN + 1);

    // Eligible hits: errors even for empty pages.
    for pat in [bad.clone(), overlong.clone()] {
        for f in [
            StringsFilter {
                pattern: Some(pat.clone()),
                ..StringsFilter::default()
            },
            StringsFilter {
                pattern: Some(pat.clone()),
                limit: 0,
                ..StringsFilter::default()
            },
            StringsFilter {
                pattern: Some(pat.clone()),
                start: 10_000,
                ..StringsFilter::default()
            },
            StringsFilter {
                pattern: Some(pat.clone()),
                start: usize::MAX,
                limit: usize::MAX,
                ..StringsFilter::default()
            },
        ] {
            assert!(
                a.strings_page_filtered(&f).is_err(),
                "eligible bad pattern must error: {f:?}"
            );
            assert!(
                filtered_oracle(&a, &f).is_err(),
                "oracle must agree on error: {f:?}"
            );
        }
    }

    // Fully prefiltered: no eligible rows, success empty even for bad patterns.
    for pat in [bad, overlong] {
        for f in [
            StringsFilter {
                pattern: Some(pat.clone()),
                section: Some(".nope".to_string()),
                ..StringsFilter::default()
            },
            StringsFilter {
                pattern: Some(pat.clone()),
                min_len: Some(10_000),
                ..StringsFilter::default()
            },
        ] {
            let got = a
                .strings_page_filtered(&f)
                .expect("prefiltered bad pattern must succeed");
            assert!(got.is_empty());
            assert!(filtered_oracle(&a, &f).expect("oracle agrees").is_empty());
        }
    }
}

#[test]
fn allocation_scales_with_page_not_matches_strings() {
    let n = 20_000;
    let a = build_analysis(0, 0, n);
    let base = StringsFilter {
        pattern: Some("qmatch-".to_string()),
        ..StringsFilter::default()
    };
    // Sanity: the population really is large.
    let full = a
        .strings_page_filtered(&StringsFilter {
            start: 0,
            limit: usize::MAX,
            ..base.clone()
        })
        .expect("full query works");
    assert_eq!(full.len(), MAX_PAGE.min(n));

    // Measure on freshly spawned threads: libtest reuses pool threads, so
    // same-thread thread-local counters could otherwise carry harness noise.
    let measure = |start: usize, limit: usize| -> (Vec<StringHit>, usize, usize) {
        std::thread::scope(|s| {
            s.spawn(|| {
                reset_thread_allocs();
                let page = a
                    .strings_page_filtered(&StringsFilter {
                        start,
                        limit,
                        ..base.clone()
                    })
                    .expect("paged query works");
                let (count, bytes) = thread_allocs();
                (page, count, bytes)
            })
            .join()
            .expect("worker joins")
        })
    };
    let (small, small_count, small_bytes) = measure(0, 10);
    assert_eq!(small.len(), 10);
    let (large, large_count, large_bytes) = measure(0, 500);
    assert_eq!(large.len(), 500);

    assert!(
        small_count <= 10 * 2 + 30,
        "small page must clone ~page rows, got {small_count} allocs for 20k matches"
    );
    assert!(
        small_bytes <= 32 * 1024,
        "small page must stay small, got {small_bytes} bytes for 20k matches"
    );
    assert!(
        large_count > small_count && large_bytes > small_bytes,
        "allocation must grow with page ({small_count}/{small_bytes}) vs ({large_count}/{large_bytes})"
    );
    assert!(
        large_count <= 500 * 2 + 60,
        "large page must still scale with page, got {large_count} allocs"
    );
    // Page contents are the dense prefix of the full match sequence.
    assert_eq!(&large[..10], &small[..]);
}

#[test]
fn allocation_scales_with_page_not_matches_functions() {
    let n = 5_000;
    let a = build_analysis(n, 0, 0);

    let measure = |offset: usize, limit: usize| {
        std::thread::scope(|s| {
            s.spawn(|| {
                reset_thread_allocs();
                let page = a.functions_page(offset, limit);
                let (count, bytes) = thread_allocs();
                (page, count, bytes)
            })
            .join()
            .expect("worker joins")
        })
    };
    let (small, small_count, small_bytes) = measure(0, 5);
    assert_eq!(small.len(), 5);
    let (large, large_count, large_bytes) = measure(0, 200);
    assert_eq!(large.len(), 200);

    assert!(
        small_count <= 5 * 4 + 10,
        "small function page must scale with page, got {small_count} allocs for {n} functions"
    );
    assert!(
        small_bytes <= 32 * 1024,
        "small function page must stay small, got {small_bytes} bytes"
    );
    assert!(
        large_count > small_count && large_bytes > small_bytes,
        "function allocation must grow with page ({small_count}/{small_bytes}) vs ({large_count}/{large_bytes})"
    );
    assert_eq!(&large[..5], &small[..]);
}

#[test]
fn allocation_scales_with_page_not_matches_xrefs() {
    let n = 100_000;
    let a = build_analysis(0, n, 0);

    let measure = |offset: usize, limit: usize| {
        std::thread::scope(|s| {
            s.spawn(|| {
                reset_thread_allocs();
                let page = a.xrefs_page(Some(XrefKind::Code), offset, limit);
                let (count, bytes) = thread_allocs();
                (page, count, bytes)
            })
            .join()
            .expect("worker joins")
        })
    };
    let (small, small_count, small_bytes) = measure(0, 5);
    assert_eq!(small.len(), 5);
    let (large, large_count, large_bytes) = measure(0, 500);
    assert_eq!(large.len(), 500);

    assert!(
        small_bytes <= 4 * 1024,
        "small xref page must not materialize all matches, got {small_bytes} bytes"
    );
    assert!(
        small_count <= 4,
        "small xref page must allocate ~page vec only, got {small_count} allocs"
    );
    assert!(
        large_bytes > small_bytes,
        "xref allocation must grow with page ({small_bytes}) vs ({large_bytes})"
    );
    assert!(
        large_count <= 10,
        "large xref page must allocate ~page vec only, got {large_count} allocs"
    );
    assert_eq!(&large[..5], &small[..]);
}
