//! Compact-sidecar acceptance: a row-heavy mid-size input snapshots well
//! under 3x its binary size and round-trips every derived row kind.
//!
//! The reference blob is a deterministic raw x86-64 image (no external
//! fixture files): a heavy table of short printable strings plus
//! pointer-like `push imm32` references into it — the shape that made JSON
//! sidecars balloon (per-row objects with hex twins). Every function
//! carries a frame prologue the scanner seeds from.

mod common;

use binscout::Project;
use binscout::disasm::Arch;
use binscout::loader::RawOptions;

const BASE: u64 = 0x1000;
const FUNCTIONS: usize = 200;
const REFS_PER_FUNC: usize = 20;
const STRINGS: usize = 10000;

/// Reference blob: ~450 KiB raw x86-64 image shaped like the binaries that
/// made JSON sidecars balloon — many short strings plus pointer-like
/// references into them. Small rows maximize the per-row JSON overhead
/// (objects, hex twins) that the binary encoding drops, while strings cost
/// rows without costing re-decodes.
fn reference_blob() -> Vec<u8> {
    let mut code: Vec<u8> = Vec::new();
    // Offsets of `imm32` slots to patch with string addresses.
    let mut patches: Vec<(usize, usize)> = Vec::new();
    for i in 0..FUNCTIONS {
        code.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5]); // frame prologue
        code.extend_from_slice(&[0xB8]); // mov eax, imm32
        code.extend_from_slice(&(i as u32).to_le_bytes());
        // Data references: `push imm32`, patched to land on recovered
        // strings below (the same shape as the basic fixture's refs).
        for _ in 0..REFS_PER_FUNC {
            code.extend_from_slice(&[0x68]);
            patches.push((code.len(), (code.len() * 37) % STRINGS));
            code.extend_from_slice(&[0, 0, 0, 0]);
        }
        code.extend_from_slice(&[0x5D, 0xC3]); // leave; ret
    }
    let mut stroffs = Vec::with_capacity(STRINGS);
    for i in 0..STRINGS {
        stroffs.push(code.len());
        code.extend_from_slice(format!("reference-string-{i:05}-payload").as_bytes());
        code.push(0);
    }
    for (off, tgt) in patches {
        // Zero-extended VA, always below 4 GiB for this reference blob.
        let target = (BASE + stroffs[tgt] as u64) as u32;
        code[off..off + 4].copy_from_slice(&target.to_le_bytes());
    }
    code
}

fn raw_opts() -> RawOptions {
    RawOptions {
        base: BASE,
        arch: Arch::X86_64,
        entry: Some(BASE),
    }
}

#[test]
fn compact_sidecar_under_3x_and_round_trips() {
    let dir = common::tmpdir("sidecar-compact");
    let bytes = reference_blob();
    assert!(
        bytes.len() > 100 * 1024,
        "reference must dwarf the fixed sidecar overhead, got {}",
        bytes.len()
    );
    let bin = common::write_bin(&dir, "ref.bin", &bytes);
    let db = common::temp_db(&dir, "ref");

    let p = Project::open_raw(&bin, &db, raw_opts()).expect("open analyzes");
    assert!(p.analysis().functions.len() >= FUNCTIONS / 2);
    assert!(p.analysis().strings.len() >= STRINGS / 2);
    let before_summary = p.analysis().summary();
    let before_edges = p.analysis().call_edges();
    let before_xrefs = p.analysis().xrefs.clone();
    let before_strings = p.analysis().strings.clone();
    let entries: Vec<u64> = p.analysis().functions.keys().copied().collect();
    let before: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| p.func_detail(*e).expect("detail"))
        .collect();
    p.save().expect("save");

    let bin_size = std::fs::metadata(&bin).expect("binary").len();
    let db_size = std::fs::metadata(&db).expect("sidecar").len();
    assert!(
        db_size < bin_size * 3,
        "sidecar {db_size} must stay under 3x the binary {bin_size}"
    );
    drop(p);

    let q = Project::open_raw(&bin, &db, raw_opts()).expect("reopen hits cache");
    assert!(q.snapshot_fresh(), "reopen of unchanged bytes is a hit");
    assert_eq!(q.analysis().summary(), before_summary);
    assert_eq!(q.analysis().call_edges(), before_edges);
    assert_eq!(q.analysis().xrefs, before_xrefs);
    assert_eq!(q.analysis().strings, before_strings);
    for (entry, want) in entries.iter().zip(before.iter()) {
        let got = q.func_detail(*entry).expect("detail after reopen");
        assert_eq!(&got, want, "func {entry:#x} differs");
    }
    common::cleanup(&dir);
}
