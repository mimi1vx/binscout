//! Bounded function views: compact metadata, block pages, block-insn pages.
//!
//! A synthetic x86-64 function with 1201 blocks / 2701 instructions (past
//! the 1024-row page cap) must reconstruct exactly from successive pages,
//! edge pages must follow the protocol-1 page contract, compact metadata
//! must carry counts instead of unbounded arrays, and per-page allocation
//! must scale with the page rather than the function.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::path::Path;

use binscout::disasm::Arch;
use binscout::error::Error;
use binscout::loader::RawOptions;
use binscout::{Page, Project, WIRE_PROTOCOL};

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

const BASE: u64 = 0x1000;
const NOPS: usize = 1500;
const JMPS: usize = 1200;
/// One fat NOP block plus one single-`jmp` block per jump target.
const WANT_BLOCKS: usize = 1 + JMPS;
/// NOPs plus jumps plus the trailing `ret`.
const WANT_INSNS: usize = NOPS + JMPS + 1;
/// Instructions in the opening block: the NOP run absorbs the first jump
/// (it is not itself a jump target, fallthrough, or entry).
const FAT_INSNS: usize = NOPS + 1;

/// `nop` x 1500, then `jmp +0` x 1200 (each targeting the next), then `ret`.
///
/// The NOP run decodes as a single 1500-instruction block; every jump target
/// starts a new block, so the whole blob is one function with 1201 blocks.
/// No bytes match an x86 prologue pattern, so no spurious entries appear.
fn big_blob() -> Vec<u8> {
    let mut b = vec![0x90u8; NOPS];
    for _ in 0..JMPS {
        b.extend([0xEB, 0x00]);
    }
    b.push(0xC3);
    b
}

fn open_raw(dir: &Path, name: &str, bytes: &[u8], base: u64) -> Project {
    let bin = common::write_bin(dir, name, bytes);
    let db = common::temp_db(dir, name);
    Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base,
            arch: Arch::X86_64,
            entry: Some(base),
        },
    )
    .expect("synthetic blob must open")
}

fn open_big(dir: &Path, name: &str) -> Project {
    open_raw(dir, name, &big_blob(), BASE)
}

/// `func@0x1000` calls `func@0x1010` (same bytes as the analysis golden).
fn two_funcs() -> Vec<u8> {
    let mut b = vec![
        0x55, 0x48, 0x89, 0xE5, 0xE8, 0x07, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0x90, 0x90, 0x90, 0x90,
        0x90,
    ];
    b.extend([
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3,
    ]);
    b
}

fn is_not_found<T>(r: binscout::error::Result<T>) -> bool {
    matches!(r, Err(Error::NotFound(_)))
}

#[test]
fn large_function_reconstructs_exactly_from_pages() {
    let dir = common::tmpdir("func-pages-big");
    let p = open_big(&dir, "big.bin");

    let meta = p.func_meta(BASE).expect("big function metadata");
    assert_eq!(meta.blocks, WANT_BLOCKS);
    assert_eq!(meta.insns, WANT_INSNS);
    assert_eq!(meta.entry, BASE);
    assert_eq!(meta.calls, 0);

    // Successive block pages chain via next_offset to the exact total.
    let mut starts: Vec<u64> = Vec::new();
    let mut offset = 0usize;
    let mut pages = 0usize;
    loop {
        let page = p.func_blocks_page(BASE, offset, 100).expect("blocks page");
        assert_eq!(page.protocol, WIRE_PROTOCOL);
        assert_eq!(page.total, WANT_BLOCKS);
        assert_eq!(page.offset, offset);
        starts.extend(page.items.iter().map(|b| b.start));
        pages += 1;
        match page.next_offset {
            Some(next) => {
                assert_eq!(next, offset + 100);
                offset = next;
            }
            None => break,
        }
    }
    assert_eq!(pages, WANT_BLOCKS.div_ceil(100));
    let want: Vec<u64> = p.analysis().functions[&BASE]
        .blocks
        .keys()
        .copied()
        .collect();
    assert_eq!(starts, want, "block pages must rebuild the full order");
    assert!(
        starts.windows(2).all(|w| w[0] < w[1]),
        "no gaps or duplicates"
    );

    // Successive instruction pages rebuild the fat NOP block exactly.
    let mut addrs: Vec<u64> = Vec::new();
    let mut offset = 0usize;
    loop {
        let page = p
            .func_block_insns_page(BASE, BASE, offset, 256)
            .expect("insns page");
        assert_eq!(page.total, FAT_INSNS);
        addrs.extend(page.items.iter().map(|i| i.addr));
        match page.next_offset {
            Some(next) => offset = next,
            None => break,
        }
    }
    let want_insns: Vec<u64> = p.analysis().functions[&BASE].blocks[&BASE]
        .insns
        .iter()
        .map(|i| i.addr)
        .collect();
    assert_eq!(addrs, want_insns, "insn pages must rebuild the block");

    // Every decoded address is covered exactly once across all block pages.
    let mut covered: Vec<u64> = Vec::new();
    for start in &starts {
        let mut offset = 0usize;
        loop {
            let page = p
                .func_block_insns_page(BASE, *start, offset, 300)
                .expect("block insns page");
            covered.extend(page.items.iter().map(|i| i.addr));
            match page.next_offset {
                Some(next) => offset = next,
                None => break,
            }
        }
    }
    let mut sorted = covered.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(covered.len(), WANT_INSNS);
    assert_eq!(sorted.len(), WANT_INSNS, "no duplicate instructions");
    assert_eq!(sorted, want_insns_extended(&p));
    common::cleanup(&dir);
}

/// All decoded addresses of the big function in ascending order.
fn want_insns_extended(p: &Project) -> Vec<u64> {
    let mut out: Vec<u64> = p.analysis().functions[&BASE]
        .blocks
        .values()
        .flat_map(|b| b.insns.iter().map(|i| i.addr))
        .collect();
    out.sort_unstable();
    out
}

#[test]
fn page_contract_edges() {
    let dir = common::tmpdir("func-pages-edges");
    let p = open_big(&dir, "big.bin");

    // Zero limit: exact total, no rows, null next.
    let page = p.func_blocks_page(BASE, 0, 0).expect("zero-limit blocks");
    assert_eq!(page.total, WANT_BLOCKS);
    assert!(page.items.is_empty());
    assert_eq!((page.limit, page.next_offset, page.offset), (0, None, 0));
    let page = p
        .func_block_insns_page(BASE, BASE, 0, 0)
        .expect("zero-limit insns");
    assert_eq!(page.total, FAT_INSNS);
    assert!(page.items.is_empty());
    assert_eq!(page.next_offset, None);

    // Huge limits clip to the 1024-row cap and report the clipped limit.
    let page = p.func_blocks_page(BASE, 0, 5000).expect("clipped blocks");
    assert_eq!(page.limit, 1024);
    assert_eq!(page.items.len(), 1024);
    assert_eq!(page.next_offset, Some(1024));
    let page = p
        .func_block_insns_page(BASE, BASE, 0, usize::MAX)
        .expect("clipped insns");
    assert_eq!(page.limit, 1024);
    assert_eq!(page.items.len(), 1024);
    assert_eq!(page.next_offset, Some(1024));

    // Final partial page carries the tail and a null next.
    let page = p
        .func_blocks_page(BASE, WANT_BLOCKS - 1, 1024)
        .expect("final page");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.next_offset, None);
    let page = p
        .func_block_insns_page(BASE, BASE, FAT_INSNS - 1, 50)
        .expect("final insns");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.next_offset, None);

    // Offset past the end is an empty page with the exact total, not an error.
    let page = p
        .func_blocks_page(BASE, WANT_BLOCKS + 100, 50)
        .expect("past-end blocks");
    assert_eq!(page.total, WANT_BLOCKS);
    assert!(page.items.is_empty());
    assert_eq!(page.next_offset, None);
    assert_eq!(page.offset, WANT_BLOCKS + 100);
    let page = p
        .func_block_insns_page(BASE, BASE, usize::MAX, 50)
        .expect("past-end insns");
    assert_eq!(page.total, FAT_INSNS);
    assert!(page.items.is_empty());
    assert_eq!(page.next_offset, None);

    // Interior addresses resolve exactly like func_detail.
    let detail = p.func_detail(BASE + 7).expect("interior detail");
    assert_eq!(detail["entry"], BASE);
    assert_eq!(p.func_meta(BASE + 7).expect("interior meta").entry, BASE);
    let at_entry = p.func_blocks_page(BASE, 0, 5).expect("entry page");
    let inside = p.func_blocks_page(BASE + 7, 0, 5).expect("interior page");
    assert_eq!(at_entry.items, inside.items);

    // Unknown function: every view reports NotFound.
    let nowhere = 0xDEAD_BEEF;
    assert!(is_not_found(p.func_meta(nowhere)));
    assert!(is_not_found(p.func_blocks_page(nowhere, 0, 10)));
    assert!(is_not_found(p.func_block_insns_page(nowhere, BASE, 0, 10)));

    // Block interior (not a block start) of the same function: NotFound.
    assert!(is_not_found(p.func_block_insns_page(BASE, BASE + 1, 0, 10)));
    // Unmapped block address: NotFound.
    assert!(is_not_found(p.func_block_insns_page(BASE, nowhere, 0, 10)));
    common::cleanup(&dir);
}

#[test]
fn foreign_block_is_not_found() {
    let dir = common::tmpdir("func-pages-foreign");
    let p = open_raw(&dir, "two.bin", &two_funcs(), 0x1000);
    let caller = 0x1000;
    let callee = 0x1010;
    assert!(p.analysis().functions.contains_key(&caller));
    assert!(p.analysis().functions.contains_key(&callee));

    // Call counts, not target arrays.
    assert_eq!(p.func_meta(caller).expect("caller meta").calls, 1);
    assert_eq!(p.func_meta(callee).expect("callee meta").calls, 0);

    let callee_block = *p.analysis().functions[&callee]
        .blocks
        .keys()
        .next()
        .expect("callee has a block");
    let caller_block = *p.analysis().functions[&caller]
        .blocks
        .keys()
        .next()
        .expect("caller has a block");
    // Each block reads fine under its own function ...
    assert!(
        !p.func_block_insns_page(callee, callee_block, 0, 10)
            .expect("own block")
            .items
            .is_empty()
    );
    // ... but a block owned by another function is NotFound either way.
    assert!(is_not_found(p.func_block_insns_page(
        caller,
        callee_block,
        0,
        10
    )));
    assert!(is_not_found(p.func_block_insns_page(
        callee,
        caller_block,
        0,
        10
    )));
    common::cleanup(&dir);
}

#[test]
fn compact_meta_has_no_unbounded_arrays() {
    let dir = common::tmpdir("func-pages-meta");
    let mut p = open_big(&dir, "big.bin");

    let value = serde_json::to_value(p.func_meta(BASE).expect("meta")).expect("meta serializes");
    let obj = value.as_object().expect("meta is an object");
    let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "id",
            "entry",
            "entry_hex",
            "name",
            "blocks",
            "insns",
            "calls",
            "reasons",
            "inferred_edges"
        ]),
        "compact metadata carries counts plus the reason set only"
    );
    assert!(obj["blocks"].is_number());
    assert!(obj["insns"].is_number());
    assert!(obj["calls"].is_number());
    assert!(obj["inferred_edges"].is_number());
    assert_eq!(obj["entry_hex"], "0x1000");
    assert!(
        obj["reasons"].is_array(),
        "reasons is a bounded vocabulary set: {obj:?}"
    );

    // The envelope shape matches the protocol-1 contract.
    let envelope: serde_json::Value =
        serde_json::to_value(p.func_blocks_page(BASE, 0, 5).expect("page"))
            .expect("page serializes");
    let page_obj = envelope.as_object().expect("page is an object");
    let page_keys: BTreeSet<&str> = page_obj.keys().map(String::as_str).collect();
    assert_eq!(
        page_keys,
        BTreeSet::from([
            "protocol",
            "total",
            "offset",
            "limit",
            "next_offset",
            "items"
        ])
    );
    assert_eq!(envelope["protocol"], WIRE_PROTOCOL);
    assert_eq!(envelope["items"].as_array().expect("items array").len(), 5);

    // Renames resolve through the compact view, including interior queries.
    p.rename_function(BASE, "big").expect("rename works");
    assert_eq!(
        p.func_meta(BASE).expect("renamed meta").name.as_deref(),
        Some("big")
    );
    assert_eq!(
        p.func_meta(BASE + 3)
            .expect("interior renamed meta")
            .name
            .as_deref(),
        Some("big")
    );
    common::cleanup(&dir);
}

#[test]
fn pages_materialize_page_sized_rows() {
    let dir = common::tmpdir("func-pages-alloc");
    let p = open_big(&dir, "big.bin");
    assert_eq!(p.func_meta(BASE).expect("meta").blocks, WANT_BLOCKS);

    // Block pages: allocation grows with the page, never the function.
    let measure_blocks = |offset: usize, limit: usize| {
        std::thread::scope(|s| {
            s.spawn(|| {
                reset_thread_allocs();
                let items = p
                    .func_blocks_page(BASE, offset, limit)
                    .expect("blocks page")
                    .items;
                let (count, bytes) = thread_allocs();
                (items, count, bytes)
            })
            .join()
            .expect("worker joins")
        })
    };
    let (small, small_count, small_bytes) = measure_blocks(0, 5);
    assert_eq!(small.len(), 5);
    let (large, large_count, large_bytes) = measure_blocks(0, 500);
    assert_eq!(large.len(), 500);
    assert_eq!(&large[..5], &small[..]);
    assert!(
        small_count <= 5 * 4 + 30,
        "small block page must scale with the page, got {small_count} allocs for {WANT_BLOCKS} blocks"
    );
    assert!(
        small_bytes <= 32 * 1024,
        "small block page must stay small, got {small_bytes} bytes"
    );
    assert!(
        large_count > small_count && large_bytes > small_bytes,
        "block allocation must grow with page ({small_count}/{small_bytes}) vs ({large_count}/{large_bytes})"
    );
    assert!(
        large_count <= 500 * 4 + 60,
        "large block page must still scale with the page, got {large_count} allocs"
    );

    // Instruction pages on the 1500-instruction block: same scaling.
    let measure_insns = |offset: usize, limit: usize| {
        std::thread::scope(|s| {
            s.spawn(|| {
                reset_thread_allocs();
                let items = p
                    .func_block_insns_page(BASE, BASE, offset, limit)
                    .expect("insns page")
                    .items;
                let (count, bytes) = thread_allocs();
                (items, count, bytes)
            })
            .join()
            .expect("worker joins")
        })
    };
    let (small, small_count, small_bytes) = measure_insns(0, 5);
    assert_eq!(small.len(), 5);
    let (large, large_count, large_bytes) = measure_insns(0, 500);
    assert_eq!(large.len(), 500);
    assert_eq!(&large[..5], &small[..]);
    assert!(
        small_count <= 5 * 5 + 20,
        "small insn page must scale with the page, got {small_count} allocs for {FAT_INSNS} insns"
    );
    assert!(
        small_bytes <= 32 * 1024,
        "small insn page must stay small, got {small_bytes} bytes"
    );
    assert!(
        large_count > small_count && large_bytes > small_bytes,
        "insn allocation must grow with page ({small_count}/{small_bytes}) vs ({large_count}/{large_bytes})"
    );
    assert!(
        large_count <= 500 * 5 + 100,
        "large insn page must still scale with the page, got {large_count} allocs"
    );

    // Silence the unused-import warning path: Page is part of the signature.
    let _: Page<binscout::analysis::BlockSummary> =
        p.func_blocks_page(BASE, 0, 1).expect("typed page");
    common::cleanup(&dir);
}
