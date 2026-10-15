//! Manual MCP investigation workflow benchmarks.
//!
//! Every test here is `#[ignore]`: these are hand-run measurements, not CI
//! timing gates, so no assertion depends on wall-clock speed. Canonical run
//! (release; debug works but is slower and not comparable):
//!
//! ```sh
//! cargo test --release --test mcp_workflow_perf -- --ignored --nocapture
//! ```
//!
//! Each test runs one warm-up rep (discarded), then `REPS` measured reps,
//! and prints a wall-time distribution plus response bytes. Scenario B/C
//! reuse one saved sidecar; scenario A writes fresh bytes per rep so no
//! sidecar exists. Functional outputs (the canonical workflow JSON) must
//! agree across scenarios; that equality IS asserted.
//!
//! No measurement hook was added to `src/`: stage costs are separated
//! externally (cold open ~= read+hash+analyze, saved reopen ~=
//! read+hash+sidecar+replay, repeated workflow ~= query+serialize only).
//! In-process peak RSS is not available without a new platform dependency,
//! so RSS is an external step (see `docs/book/src/performance.md`).

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use binscout::Project;
use binscout::analysis::StringsFilter;
use binscout::disasm::Arch;
use binscout::loader::RawOptions;

/// Warm-up reps (discarded); measured reps per scenario (≥5 per the plan).
const WARMUP: usize = 1;
const REPS: usize = 6;

/// Small fixture: synthetic PE32 container with functions, xrefs, strings.
const SMALL_NAME: &str = "pe32-basic.exe";
/// Large fixture: raw x86-64 blob, one 1201-block / 2701-insn function.
const LARGE_BASE: u64 = 0x1000;
const LARGE_NOPS: usize = 1500;
const LARGE_JMPS: usize = 1200;

fn large_blob() -> Vec<u8> {
    let mut b = vec![0x90u8; LARGE_NOPS];
    for _ in 0..LARGE_JMPS {
        b.extend([0xEB, 0x00]);
    }
    b.push(0xC3);
    b
}

fn raw_opts() -> RawOptions {
    RawOptions {
        base: LARGE_BASE,
        arch: Arch::X86_64,
        entry: Some(LARGE_BASE),
    }
}

struct StepOutput {
    canonical: serde_json::Value,
    bytes: usize,
    open_ms: f64,
    workflow_ms: f64,
}

/// One full agent investigation pass over an open project:
/// `project_info → functions → func → blocks → block_insns → xrefs → strings`.
/// Every response is serialized so `bytes` reflects wire cost; `canonical`
/// excludes host paths so fresh/cached outputs can be compared exactly.
fn run_workflow(p: &Project) -> (serde_json::Value, usize) {
    let info = serde_json::to_value(p.project_info()).expect("info serializes");
    let functions = serde_json::to_value(p.functions_resolved(0, 1024)).expect("functions");
    let entry = p
        .analysis()
        .functions
        .keys()
        .next()
        .copied()
        .expect("fixture has a function");
    let block = *p.analysis().functions[&entry]
        .blocks
        .keys()
        .next()
        .expect("function has a block");
    let meta = serde_json::to_value(p.func_meta(entry).expect("meta")).expect("meta");
    let blocks =
        serde_json::to_value(p.func_blocks_page(entry, 0, 1024).expect("blocks")).expect("blocks");
    let insns = serde_json::to_value(
        p.func_block_insns_page(entry, block, 0, 1024)
            .expect("insns"),
    )
    .expect("insns");
    let xrefs = serde_json::to_value(p.query_xrefs(None, None, None, 0, 1024)).expect("xrefs");
    let strings =
        serde_json::to_value(p.query_strings(&StringsFilter::default()).expect("strings"))
            .expect("strings");
    let counts = serde_json::json!({
        "functions": info["functions"], "blocks": info["blocks"],
        "insns": info["insns"], "xrefs": info["xrefs"], "strings": info["strings"],
    });
    let canonical = serde_json::json!({"counts": counts, "functions": functions, "meta": meta,
            "blocks": blocks, "insns": insns, "xrefs": xrefs, "strings": strings});
    let bytes = canonical.to_string().len();
    (canonical, bytes)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn describe(samples: &[f64]) -> (f64, f64, f64, f64) {
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    let min = s[0];
    let max = s[s.len() - 1];
    let mean = s.iter().sum::<f64>() / s.len() as f64;
    let median = if s.len().is_multiple_of(2) {
        (s[s.len() / 2 - 1] + s[s.len() / 2]) / 2.0
    } else {
        s[s.len() / 2]
    };
    (min, median, mean, max)
}

fn report(tag: &str, scenario: &str, outs: &[StepOutput]) {
    let opens: Vec<f64> = outs.iter().map(|o| o.open_ms).collect();
    let flows: Vec<f64> = outs.iter().map(|o| o.workflow_ms).collect();
    let totals: Vec<f64> = outs.iter().map(|o| o.open_ms + o.workflow_ms).collect();
    let (omin, omed, omean, omax) = describe(&opens);
    let (fmin, fmed, fmean, fmax) = describe(&flows);
    let (tmin, tmed, tmean, tmax) = describe(&totals);
    println!(
        "{tag} [{scenario}] n={} ({} warm-up discarded)",
        outs.len(),
        WARMUP
    );
    println!("  open_ms:     min {omin:.2}  median {omed:.2}  mean {omean:.2}  max {omax:.2}");
    println!("  workflow_ms: min {fmin:.2}  median {fmed:.2}  mean {fmean:.2}  max {fmax:.2}");
    println!("  total_ms:    min {tmin:.2}  median {tmed:.2}  mean {tmean:.2}  max {tmax:.2}");
    println!("  response_bytes: {}", outs[0].bytes);
}

/// Cold opens: fresh bytes + fresh (nonexistent) sidecar path per rep.
fn scenario_cold(
    dir: &Path,
    tag: &str,
    write: &dyn Fn(&Path, usize) -> (PathBuf, PathBuf),
    open: &dyn Fn(&Path, &Path) -> Project,
) -> Vec<StepOutput> {
    let mut outs = Vec::new();
    for i in 0..WARMUP + REPS {
        let (bin, db) = write(dir, i);
        let t = Instant::now();
        let p = open(&bin, &db);
        let open_d = t.elapsed();
        let t = Instant::now();
        let (canonical, bytes) = run_workflow(&p);
        let flow_d = t.elapsed();
        if i >= WARMUP {
            outs.push(StepOutput {
                canonical,
                bytes,
                open_ms: ms(open_d),
                workflow_ms: ms(flow_d),
            });
        }
    }
    let _ = tag;
    outs
}

/// Saved-sidecar opens: one analyzed project is saved, then each rep opens
/// the same binary+sidecar in a new `Project` (new-process shape).
fn scenario_saved(
    bin: &Path,
    db: &Path,
    open: &dyn Fn(&Path, &Path) -> Project,
) -> Vec<StepOutput> {
    let mut outs = Vec::new();
    for i in 0..WARMUP + REPS {
        let t = Instant::now();
        let p = open(bin, db);
        let open_d = t.elapsed();
        let t = Instant::now();
        let (canonical, bytes) = run_workflow(&p);
        let flow_d = t.elapsed();
        if i >= WARMUP {
            outs.push(StepOutput {
                canonical,
                bytes,
                open_ms: ms(open_d),
                workflow_ms: ms(flow_d),
            });
        }
    }
    outs
}

/// Repeated same-process queries: one open, `WARMUP + REPS` workflow passes.
fn scenario_repeated(p: &Project) -> Vec<StepOutput> {
    let mut outs = Vec::new();
    for i in 0..WARMUP + REPS {
        let t = Instant::now();
        let (canonical, bytes) = run_workflow(p);
        let flow_d = t.elapsed();
        if i >= WARMUP {
            outs.push(StepOutput {
                canonical,
                bytes,
                open_ms: 0.0,
                workflow_ms: ms(flow_d),
            });
        }
    }
    outs
}

fn check_agree(tag: &str, cold: &[StepOutput], saved: &[StepOutput], repeated: &[StepOutput]) {
    assert_eq!(cold.len(), REPS);
    assert_eq!(saved.len(), REPS);
    assert_eq!(repeated.len(), REPS);
    for (i, o) in cold.iter().chain(saved).chain(repeated).enumerate() {
        assert_eq!(
            o.canonical, cold[0].canonical,
            "{tag}: rep {i} functional output differs"
        );
        assert_eq!(
            o.bytes, cold[0].bytes,
            "{tag}: rep {i} response bytes differ"
        );
    }
}

fn fixture_counts(p: &Project) -> serde_json::Value {
    let info = p.project_info();
    let size = std::fs::metadata(p.path()).map(|m| m.len()).unwrap_or(0);
    serde_json::json!({
        "file_bytes": size, "functions": info.functions, "blocks": info.blocks,
        "insns": info.insns, "xrefs": info.xrefs, "strings": info.strings,
    })
}

#[ignore]
#[test]
fn perf_small_workflow() {
    let dir = common::tmpdir("perf-small");
    let write = |dir: &Path, i: usize| {
        let sub = dir.join(format!("rep{i}"));
        std::fs::create_dir_all(&sub).expect("subdir");
        let bin = common::write_fixture(&sub, SMALL_NAME);
        (bin.clone(), common::temp_db(&sub, "cold"))
    };
    let open = |bin: &Path, db: &Path| Project::open_with_db(bin, db).expect("small opens");
    let cold = scenario_cold(&dir, "small", &write, &open);
    println!("small fixture counts: {}", {
        let (bin, db) = write(&dir, 999);
        let p = open(&bin, &db);
        fixture_counts(&p)
    });

    let sdir = dir.join("saved");
    std::fs::create_dir_all(&sdir).expect("saved dir");
    let bin = common::write_fixture(&sdir, SMALL_NAME);
    let db = common::temp_db(&sdir, "saved");
    let p = Project::open_with_db(&bin, &db).expect("small opens");
    p.save().expect("save sidecar");
    drop(p);
    let saved = scenario_saved(&bin, &db, &open);

    let p = Project::open_with_db(&bin, &db).expect("small reopens");
    let repeated = scenario_repeated(&p);

    check_agree("small", &cold, &saved, &repeated);
    report("small", "cold/no-sidecar", &cold);
    report("small", "saved-sidecar/new-process", &saved);
    report("small", "repeated/same-process", &repeated);
    common::cleanup(&dir);
}

#[ignore]
#[test]
fn perf_large_workflow() {
    let dir = common::tmpdir("perf-large");
    let bytes = large_blob();
    let write = |dir: &Path, i: usize| {
        let sub = dir.join(format!("rep{i}"));
        std::fs::create_dir_all(&sub).expect("subdir");
        let bin = common::write_bin(&sub, "large.bin", &bytes);
        (bin.clone(), common::temp_db(&sub, "cold"))
    };
    let open = |bin: &Path, db: &Path| Project::open_raw(bin, db, raw_opts()).expect("large opens");
    let cold = scenario_cold(&dir, "large", &write, &open);
    println!("large fixture counts: {}", {
        let (bin, db) = write(&dir, 999);
        let p = open(&bin, &db);
        fixture_counts(&p)
    });

    let sdir = dir.join("saved");
    std::fs::create_dir_all(&sdir).expect("saved dir");
    let bin = common::write_bin(&sdir, "large.bin", &bytes);
    let db = common::temp_db(&sdir, "saved");
    let p = Project::open_raw(&bin, &db, raw_opts()).expect("large opens");
    p.save().expect("save sidecar");
    drop(p);
    let saved = scenario_saved(&bin, &db, &open);

    let p = Project::open_raw(&bin, &db, raw_opts()).expect("large reopens");
    let repeated = scenario_repeated(&p);

    check_agree("large", &cold, &saved, &repeated);
    report("large", "cold/no-sidecar", &cold);
    report("large", "saved-sidecar/new-process", &saved);
    report("large", "repeated/same-process", &repeated);
    common::cleanup(&dir);
}
