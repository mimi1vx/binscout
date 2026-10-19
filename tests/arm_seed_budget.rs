//! ARM seed-budget tests: bounded candidate collection must emit the same
//! sorted/deduped/filtered seed prefix as the old collect-all pass across
//! segment orders, overlaps, wrapped mappings, and over-cap inputs for every
//! ARM variant, with bounded memory under dense-prologue stress.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use binscout::Project;
use binscout::analysis::{Analysis, analyze};
use binscout::disasm::Arch;
use binscout::loader::{BinaryFormat, LoadedBinary, RawOptions, Segment, load_raw};

use common::{cleanup, temp_db, tmpdir, write_bin};

// SAFETY: the counters only observe; every call forwards to `System` with
// the original arguments and adjusts the live count on success.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let prev = LIVE.fetch_add(layout.size(), Ordering::SeqCst);
            PEAK.fetch_max(prev + layout.size(), Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !ptr.is_null() {
            if new_size >= layout.size() {
                let prev = LIVE.fetch_add(new_size - layout.size(), Ordering::SeqCst);
                PEAK.fetch_max(prev + new_size - layout.size(), Ordering::SeqCst);
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
            }
        }
        ptr
    }
}

/// Process-wide counting allocator: `LIVE` tracks live bytes, `PEAK` the
/// high-water mark. Only this test binary installs it, and every test holds
/// `MEASURE`, so peaks attribute to one test at a time.
struct CountingAlloc;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static MEASURE: Mutex<()> = Mutex::new(());

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::SeqCst), Ordering::SeqCst);
}

fn peak() -> usize {
    PEAK.load(Ordering::SeqCst)
}

fn lock_measure() -> std::sync::MutexGuard<'static, ()> {
    MEASURE.lock().unwrap_or_else(|e| e.into_inner())
}

fn exec_seg(vaddr: u64, data: Vec<u8>) -> Segment {
    Segment {
        vaddr,
        mem_size: data.len() as u64,
        data,
        readable: true,
        writable: false,
        executable: true,
    }
}

fn test_bin(arch: Arch, entry: Option<u64>, segs: Vec<Segment>) -> LoadedBinary {
    LoadedBinary {
        format: BinaryFormat::Raw,
        arch,
        entry,
        segments: segs,
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        symbols: Vec::new(),
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        relocatable: false,
        arm_hints: Default::default(),
    }
}

fn entries_of(a: &Analysis) -> Vec<u64> {
    a.functions.keys().copied().collect()
}

/// Per-variant terminator (`ret`), fallthrough (`seq`), and decodable
/// prologue match (`pro`) encodings.
struct ArmCase {
    arch: Arch,
    ret: &'static [u8],
    seq: &'static [u8],
    pro: &'static [u8],
}

fn arm_cases() -> [ArmCase; 3] {
    [
        ArmCase {
            arch: Arch::Aarch64,
            ret: &[0xC0, 0x03, 0x5F, 0xD6],
            seq: &[0x1F, 0x20, 0x03, 0xD5],
            pro: &[0xFD, 0x7B, 0x80, 0xA9],
        },
        ArmCase {
            arch: Arch::Arm32,
            ret: &[0x1E, 0xFF, 0x2F, 0xE1],
            seq: &[0x01, 0x00, 0xA0, 0xE1],
            pro: &[0xF0, 0x40, 0x2D, 0xE9],
        },
        ArmCase {
            arch: Arch::Thumb,
            ret: &[0x70, 0x47],
            seq: &[0x00, 0xBF],
            pro: &[0xF0, 0xB5],
        },
    ]
}

#[test]
fn seed_order_independent_of_segment_order() {
    let _guard = lock_measure();
    for case in arm_cases() {
        let mut hi = Vec::new();
        hi.extend_from_slice(case.pro);
        hi.extend_from_slice(case.seq);
        hi.extend_from_slice(case.pro);
        let lo = case.ret.to_vec();
        let unit = case.pro.len() as u64;
        let fwd = analyze(&test_bin(
            case.arch,
            None,
            vec![exec_seg(0x8000, hi.clone()), exec_seg(0x7000, lo.clone())],
        ))
        .expect("analyzes");
        let rev = analyze(&test_bin(
            case.arch,
            None,
            vec![exec_seg(0x7000, lo), exec_seg(0x8000, hi)],
        ))
        .expect("analyzes");
        let (mut f, mut r) = (entries_of(&fwd), entries_of(&rev));
        f.sort_unstable();
        r.sort_unstable();
        assert_eq!(f, r, "segment order must not matter for {:?}", case.arch);
        assert_eq!(
            f,
            [0x7000, 0x8000, 0x8000 + 2 * unit],
            "unexpected entries for {:?}",
            case.arch
        );
    }
}

#[test]
fn duplicate_prologue_across_segments_dedups() {
    let _guard = lock_measure();
    for case in arm_cases() {
        let unit = case.pro.len() as u64;
        let base = 0x9000u64;
        let shared = base + 2 * unit;
        let mut a = Vec::new();
        a.extend_from_slice(case.ret);
        a.extend_from_slice(case.seq);
        a.extend_from_slice(case.pro);
        // Same address, second segment: the shared prologue must seed exactly
        // one function whichever segment the bytes come from.
        for order in [false, true] {
            let segs = if order {
                vec![
                    exec_seg(shared, case.pro.to_vec()),
                    exec_seg(base, a.clone()),
                ]
            } else {
                vec![
                    exec_seg(base, a.clone()),
                    exec_seg(shared, case.pro.to_vec()),
                ]
            };
            let got = entries_of(&analyze(&test_bin(case.arch, None, segs)).expect("analyzes"));
            assert_eq!(got, [base, shared], "order {order} for {:?}", case.arch);
        }
    }
}

#[test]
fn reached_prologue_does_not_split_function() {
    let _guard = lock_measure();
    for case in arm_cases() {
        let unit = case.pro.len() as u64;
        let base = 0xA000u64;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(case.pro);
        bytes.extend_from_slice(case.seq);
        bytes.extend_from_slice(case.pro);
        bytes.extend_from_slice(case.ret);
        let a = analyze(&test_bin(
            case.arch,
            Some(base),
            vec![exec_seg(base, bytes)],
        ))
        .expect("analyzes");
        assert_eq!(entries_of(&a), [base], "no split for {:?}", case.arch);
        assert_eq!(
            a.containing_function(base + 2 * unit),
            Some(base),
            "mid-function prologue stays code for {:?}",
            case.arch
        );
    }
}

#[test]
fn wrapped_segment_candidates_sort_and_filter() {
    let _guard = lock_measure();
    // Segment straddling `u64::MAX`: wrapped-low candidates sort first but
    // are unmapped, so they are offered and rejected without consuming
    // budget; reached high candidates stay excluded.
    let base = u64::MAX - 8;
    for case in arm_cases() {
        let (bytes, want) = match case.arch {
            Arch::Aarch64 | Arch::Arm32 => {
                let mut b = Vec::new();
                b.extend_from_slice(case.pro);
                b.extend_from_slice(case.ret);
                b.extend_from_slice(case.pro);
                b.extend_from_slice(case.pro);
                (b, vec![base, u64::MAX])
            }
            Arch::Thumb => {
                let mut b = Vec::new();
                for w in [
                    case.pro, case.ret, case.pro, case.pro, case.ret, case.ret, case.pro, case.ret,
                ] {
                    b.extend_from_slice(w);
                }
                (b, vec![base, base + 4, base + 6])
            }
            _ => unreachable!("arm cases only"),
        };
        assert_eq!(bytes.len(), 16);
        let got = entries_of(
            &analyze(&test_bin(case.arch, None, vec![exec_seg(base, bytes)])).expect("analyzes"),
        );
        assert_eq!(got, want, "wrapped layout for {:?}", case.arch);
    }
}

#[test]
fn raw_open_path_matches_direct_analyze() {
    let _guard = lock_measure();
    let dir = tmpdir("arm-seed-raw");
    // Chains through both prologues: one function, no split.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0xF0, 0x40, 0x2D, 0xE9]);
    bytes.extend_from_slice(&[0x01, 0x00, 0xA0, 0xE1]);
    bytes.extend_from_slice(&[0xF0, 0x40, 0x2D, 0xE9]);
    bytes.extend_from_slice(&[0x1E, 0xFF, 0x2F, 0xE1]);
    let path = write_bin(&dir, "arm32.bin", &bytes);
    let db = temp_db(&dir, "arm32");
    let opts = RawOptions {
        base: 0xA000,
        arch: Arch::Arm32,
        entry: Some(0xA000),
    };
    let proj = Project::open_raw(&path, &db, opts).expect("raw opens");
    let direct = analyze(&load_raw(&bytes, opts).expect("raw loads")).expect("analyzes");
    assert_eq!(entries_of(proj.analysis()), entries_of(&direct));
    assert_eq!(entries_of(proj.analysis()), [0xA000]);
    cleanup(&dir);
}

#[test]
fn many_accepted_seeds_all_found() {
    let _guard = lock_measure();
    let base = 0xB000u64;
    let n = 2000usize;
    let mut bytes = vec![0x70, 0x47];
    for _ in 0..n {
        bytes.extend_from_slice(&[0xF0, 0xB5]);
    }
    let got = entries_of(
        &analyze(&test_bin(Arch::Thumb, None, vec![exec_seg(base, bytes)])).expect("analyzes"),
    );
    assert_eq!(got.len(), n + 1);
    assert_eq!(got[0], base);
    assert_eq!(got[n], base + 2 * n as u64);
    assert!(got.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn dense_undecodable_candidates_stay_bounded() {
    let _guard = lock_measure();
    // 2 MiB of never-condition `stmdb` words: every word matches the
    // prologue mask but none decodes, plus three decodable matches whose
    // seeds must survive. The old collect-all pass stored one `u64` per raw
    // candidate (~4 MiB here); the streaming merge stores only accepted
    // seeds plus one heap entry per segment.
    let base = 0xC000u64;
    let words = 524_288usize;
    let nv = 0xF92D40F0u32;
    let al = 0xE92D40F0u32;
    let mut data = Vec::with_capacity(words * 4);
    for i in 0..words {
        let v = if i == 100 || i == 200_000 || i == 500_000 {
            al
        } else {
            nv
        };
        data.extend_from_slice(&v.to_le_bytes());
    }
    let bin = test_bin(Arch::Arm32, None, vec![exec_seg(base, data)]);
    reset_peak();
    let got = entries_of(&analyze(&bin).expect("dense blob analyzes"));
    let live_peak = peak();
    assert_eq!(got, [base + 400, base + 800_000, base + 2_000_000]);
    assert!(
        live_peak < 4_000_000,
        "peak live {live_peak} exceeds bound; candidate storage must stay bounded"
    );
}
