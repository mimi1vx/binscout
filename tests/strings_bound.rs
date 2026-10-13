//! Bounded string extraction: differential equivalence plus allocation caps.
//!
//! Reference extraction mirrors the old allocate-all-then-sort path; the
//! tests below pin the new lazy merge to it across caps (including zero),
//! minimum lengths, both endians, odd offsets/lengths, EOF and
//! equal-offset ties, and verify dense short-run stress stays bounded.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use binscout::loader::strings::{Encoding, StringHit, extract};

use common::builders;

// ---------------------------------------------------------------------------
// Thread-local allocation counting (isolates this test binary's threads).
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Reference extraction: old allocate-all-then-sort behavior, verbatim.
// ---------------------------------------------------------------------------

fn ref_is_print(b: u8) -> bool {
    matches!(b, 0x20..=0x7E)
}

fn ref_va(base_va: Option<u64>, offset: usize) -> Option<u64> {
    base_va.map(|b| b.wrapping_add(offset as u64))
}

fn ref_unit_at(bytes: &[u8], i: usize, little: bool) -> Option<u8> {
    let pair = bytes.get(i..i + 2)?;
    let (c, z) = if little {
        (pair[0], pair[1])
    } else {
        (pair[1], pair[0])
    };
    (ref_is_print(c) && z == 0).then_some(c)
}

fn reference_extract(
    bytes: &[u8],
    min_len: usize,
    max_hits: usize,
    base_va: Option<u64>,
) -> Vec<StringHit> {
    let min = min_len.max(1);
    let mut hits = Vec::new();
    // ASCII.
    {
        let mut i = 0;
        while i < bytes.len() {
            if ref_is_print(bytes[i]) {
                let start = i;
                while i < bytes.len() && ref_is_print(bytes[i]) {
                    i += 1;
                }
                if i - start >= min {
                    hits.push(StringHit {
                        offset: start,
                        vaddr: ref_va(base_va, start),
                        encoding: Encoding::Ascii,
                        value: String::from_utf8_lossy(&bytes[start..i]).into_owned(),
                        section: None,
                        executable: false,
                    });
                }
            } else {
                i += 1;
            }
        }
    }
    // UTF-16 both endians.
    for little in [true, false] {
        let mut i = 0;
        while i + 1 < bytes.len() {
            if ref_unit_at(bytes, i, little).is_some() {
                let start = i;
                let mut value = String::new();
                while let Some(c) = ref_unit_at(bytes, i, little) {
                    value.push(c as char);
                    i += 2;
                }
                if value.len() >= min {
                    hits.push(StringHit {
                        offset: start,
                        vaddr: ref_va(base_va, start),
                        encoding: if little {
                            Encoding::Utf16Le
                        } else {
                            Encoding::Utf16Be
                        },
                        value,
                        section: None,
                        executable: false,
                    });
                }
            } else {
                i += 1;
            }
        }
    }
    hits.sort_by_key(|h| h.offset);
    hits.truncate(max_hits);
    hits
}

fn assert_equiv(bytes: &[u8], min_len: usize, max_hits: usize, base_va: Option<u64>) {
    let got = extract(bytes, min_len, max_hits, base_va);
    let want = reference_extract(bytes, min_len, max_hits, base_va);
    assert_eq!(
        got,
        want,
        "mismatch len={} min={min_len} cap={max_hits} va={base_va:?} bytes={bytes:02x?}",
        bytes.len()
    );
    assert!(
        got.windows(2).all(|w| w[0].offset <= w[1].offset),
        "output must stay offset-sorted"
    );
}

// ---------------------------------------------------------------------------
// Targeted edge cases.
// ---------------------------------------------------------------------------

#[test]
fn targeted_edges_match_reference() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x41],
        vec![0x00],
        vec![0x41, 0x00],
        vec![0x00, 0x41],
        vec![0xFF],
        // ASCII threshold boundaries.
        b"\x00ab\x00abc\x00abcd\x00".to_vec(),
        b"ABCD".to_vec(),
        // LE run exactly at EOF, odd tail, lone trailing byte.
        vec![0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00],
        vec![0x41, 0x00, 0x42, 0x00, 0x43],
        vec![0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44],
        vec![0xFF, 0x41, 0x00, 0x42, 0x00],
        // BE run at odd offset, EOF truncation.
        vec![0xFF, 0x00, 0x45, 0x00, 0x46, 0x00, 0x47, 0x00, 0x48, 0xFF],
        vec![0x00, 0x41, 0x00, 0x42, 0x00],
        vec![0x00, 0x41, 0x00, 0x42],
        vec![0x00, 0x41],
        // Equal-offset ASCII+LE tie with min 1: "A" + LE "ABCD".
        vec![0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00],
        // Odd-offset LE start and odd-length buffer.
        vec![0xFF, 0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00],
        vec![0xFF, 0xFF, 0x41, 0x00, 0x42, 0x00, 0xFF],
        // Rejected short UTF-16 runs still advance past the run.
        vec![
            0x41, 0x00, 0xFF, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00, 0x45, 0x00,
        ],
        // Mixed ASCII + both endians.
        b"\x00hello\x00\xFF".to_vec(),
    ];
    for bytes in &cases {
        for min_len in [0, 1, 2, 4, 5] {
            for max_hits in [0, 1, 2, 3, 100] {
                for base_va in [None, Some(0x1000)] {
                    assert_equiv(bytes, min_len, max_hits, base_va);
                }
            }
        }
    }
}

#[test]
fn tie_order_ascii_then_le() {
    // min 1 exposes the ASCII+LE tie at offset 0.
    let bytes = vec![0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00];
    let hits = extract(&bytes, 1, 100, None);
    let want = reference_extract(&bytes, 1, 100, None);
    assert_eq!(hits, want);
    assert!(hits.len() >= 2);
    assert_eq!(hits[0].offset, 0);
    assert_eq!(hits[1].offset, 0);
    assert_eq!(hits[0].encoding, Encoding::Ascii);
    assert_eq!(hits[1].encoding, Encoding::Utf16Le);
    // Capped prefix keeps the tie order.
    assert_eq!(extract(&bytes, 1, 1, None), want[..1]);
    assert_eq!(extract(&bytes, 1, 2, None), want[..2]);
}

#[test]
fn small_cap_keeps_earlier_utf16_over_later_ascii() {
    // LE hit at 0 must displace a later ASCII hit when capped.
    let mut bytes = vec![0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00, 0xFF, 0xFF];
    bytes.extend_from_slice(b"\x00hello\x00");
    let all = reference_extract(&bytes, 4, 100, None);
    assert!(all.len() >= 2);
    assert_eq!(all[0].encoding, Encoding::Utf16Le);
    assert_eq!(all[0].offset, 0);
    // Cap 1 must be the LE hit, not the first ASCII hit alone.
    assert_eq!(extract(&bytes, 4, 1, None), all[..1]);
    assert_eq!(extract(&bytes, 4, 2, None), all[..2]);
}

#[test]
fn exhaustive_tiny_buffers_match_reference() {
    let alphabet: [u8; 5] = [0x00, 0x41, 0x42, 0xFF, 0x20];
    let mut buf = Vec::new();
    fn walk(alphabet: &[u8; 5], buf: &mut Vec<u8>, depth: usize, max_depth: usize) {
        if depth == max_depth {
            for min_len in [1, 2, 4] {
                for max_hits in [0, 1, 2, 100] {
                    assert_equiv(buf, min_len, max_hits, None);
                    assert_equiv(buf, min_len, max_hits, Some(0x2000));
                }
            }
            return;
        }
        // Empty prefix is covered by the depth-0 call; recurse per byte.
        for b in alphabet {
            buf.push(*b);
            walk(alphabet, buf, depth + 1, max_depth);
            buf.pop();
        }
        if depth == 0 {
            // Also cover the empty buffer once.
            for min_len in [0, 1, 4] {
                assert_equiv(buf, min_len, 0, None);
                assert_equiv(buf, min_len, 5, Some(0x1000));
            }
        }
    }
    for len in 0..=3 {
        walk(&alphabet, &mut buf, 0, len);
    }
}

#[test]
fn fuzz_buffers_match_reference() {
    // Deterministic xorshift; biased alphabet yields dense runs.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let alphabet: [u8; 8] = [0x00, 0x41, 0x42, 0x43, 0x20, 0x7E, 0x7F, 0xFF];
    for _ in 0..1500 {
        let len = (next() % 33) as usize;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(alphabet[(next() % alphabet.len() as u64) as usize]);
        }
        let min_len = (next() % 6) as usize;
        let max_hits = match next() % 5 {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 5,
            _ => 100,
        } as usize;
        let base_va = if next() % 2 == 0 { None } else { Some(0x1000) };
        assert_equiv(&bytes, min_len, max_hits, base_va);
    }
}

#[test]
fn fixture_bytes_match_reference() {
    for name in builders::FIXTURE_NAMES {
        let bytes = common::fixture_bytes(name);
        for (min_len, max_hits) in [(4, 10_000), (1, 50), (6, 3), (4, 0)] {
            assert_equiv(&bytes, min_len, max_hits, None);
            assert_equiv(&bytes, min_len, max_hits, Some(0x400_000));
        }
    }
}

// ---------------------------------------------------------------------------
// Allocation bounds.
// ---------------------------------------------------------------------------

fn dense_ascii_repeats(repeats: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(repeats * 5);
    for _ in 0..repeats {
        out.extend_from_slice(b"AAAA\x00");
    }
    out
}

#[test]
fn zero_cap_allocates_nothing() {
    let bytes = dense_ascii_repeats(2000);
    reset_thread_allocs();
    let hits = extract(&bytes, 4, 0, None);
    let (count, bytes_alloc) = thread_allocs();
    assert!(hits.is_empty());
    assert_eq!(
        reference_extract(&bytes, 4, 0, None),
        hits,
        "zero cap must match reference"
    );
    assert_eq!(count, 0, "zero cap must not allocate, got {count} allocs");
    assert_eq!(
        bytes_alloc, 0,
        "zero cap must not allocate, got {bytes_alloc} bytes"
    );
}

#[test]
fn dense_stress_small_cap_bounds_owned_hits() {
    let bytes = dense_ascii_repeats(20_000);
    let cap = 10;
    // Reference sanity: dense input really does yield many candidates.
    let full = reference_extract(&bytes, 4, usize::MAX, None);
    assert!(
        full.len() >= 20_000,
        "dense fixture must yield many hits, got {}",
        full.len()
    );

    reset_thread_allocs();
    let hits = extract(&bytes, 4, cap, None);
    let (count, bytes_alloc) = thread_allocs();
    assert_eq!(hits, full[..cap]);
    assert_eq!(hits.len(), cap);
    // One String per retained hit plus a handful of Vec growth
    // reallocations; far below the 20k-hit reference population.
    assert!(
        count <= cap + 10,
        "bounded intermediates: {count} allocs for cap {cap}"
    );
    assert!(
        bytes_alloc <= 8 * 1024,
        "bounded intermediates: {bytes_alloc} bytes for cap {cap}"
    );

    // The old path allocates per candidate; confirm the test discriminates.
    reset_thread_allocs();
    let ref_hits = reference_extract(&bytes, 4, cap, None);
    let (ref_count, ref_bytes) = thread_allocs();
    assert_eq!(ref_hits, hits);
    assert!(
        ref_count > count,
        "reference should allocate more ({ref_count}) than bounded ({count})"
    );
    assert!(
        ref_bytes > bytes_alloc,
        "reference should allocate more bytes ({ref_bytes}) than bounded ({bytes_alloc})"
    );
}

#[test]
fn dense_utf16_stress_matches_and_stays_capped() {
    // Each 10-byte group is one LE "ABCD" candidate.
    let mut bytes = Vec::new();
    for _ in 0..3000 {
        bytes.extend_from_slice(&[0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x44, 0x00, 0xFF, 0xFF]);
    }
    for cap in [0, 1, 5] {
        assert_equiv(&bytes, 4, cap, None);
    }
    reset_thread_allocs();
    let hits = extract(&bytes, 4, 5, Some(0x5000));
    let (count, _) = thread_allocs();
    assert_eq!(hits, reference_extract(&bytes, 4, 5, Some(0x5000)));
    assert_eq!(hits.len(), 5);
    assert_eq!(hits[0].vaddr, Some(0x5000));
    assert!(
        count <= 5 + 10,
        "utf16 stress must stay bounded, got {count} allocs"
    );
}
