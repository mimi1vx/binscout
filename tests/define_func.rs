//! User-defined function seeds: `define-func` materializes unreachable
//! code as a `User`-reasoned function, `undefine-func` excludes it while
//! keeping the row, seeds survive reloads and export/import round-trips,
//! and seed modes are restricted to 32-bit ARM projects.

mod common;

use std::process::Command;

use serde_json::Value;

use binscout::analysis::{DiscoveryReason, SeedMode};
use binscout::disasm::Arch;
use binscout::loader::RawOptions;
use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

/// Raw x86-64 blob: `ret; nop; ret` at base 0. Only `0x0` seeds analysis
/// (the trailing `ret` is unreachable and matches no prologue pattern).
fn gap_blob(dir: &std::path::Path) -> std::path::PathBuf {
    write_bin(dir, "gap.bin", &[0xC3, 0x90, 0xC3])
}

fn open_gap(dir: &std::path::Path, name: &str) -> (binscout::Project, std::path::PathBuf) {
    let bin = gap_blob(dir);
    let db = temp_db(dir, name);
    let p = binscout::Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: 0,
            arch: Arch::X86_64,
            entry: None,
        },
    )
    .expect("gap blob must open");
    (p, bin)
}

fn reasons_of(p: &binscout::Project, entry: u64) -> Vec<DiscoveryReason> {
    p.analysis()
        .functions
        .get(&entry)
        .expect("function present")
        .reason_list()
}

/// Run the CLI; assert stdout is one valid JSON value.
fn run(args: &[&str]) -> (bool, Value) {
    let out = Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value)
}

#[test]
fn define_materializes_unreachable_code_with_user_reason() {
    let dir = tmpdir("define-basic");
    let (mut p, _) = open_gap(&dir, "a");
    assert!(
        !p.analysis().functions.contains_key(&0x2),
        "trailing ret is unreachable before define"
    );
    p.define_func(0x2, None).expect("define");
    assert!(
        p.analysis().functions.contains_key(&0x2),
        "define must materialize the function"
    );
    assert!(
        reasons_of(&p, 0x2).contains(&DiscoveryReason::User),
        "user seed carries the User reason"
    );
    // Persists immediately: reopen replays the seeded function.
    drop(p);
    let bin = gap_blob(&dir);
    let db = temp_db(&dir, "a");
    let q = binscout::Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: 0,
            arch: Arch::X86_64,
            entry: None,
        },
    )
    .expect("reopen");
    assert!(
        q.analysis().functions.contains_key(&0x2),
        "seeded function survives reload"
    );
    assert!(
        reasons_of(&q, 0x2).contains(&DiscoveryReason::User),
        "User reason survives reload"
    );
    // The new entry is a known function: renames resolve to it.
    let mut q = q;
    q.rename_function(0x2, "gap_tail")
        .expect("rename defined entry");
    assert_eq!(q.function_name(0x2).as_deref(), Some("gap_tail"));
    common::cleanup(&dir);
}

#[test]
fn undefine_excludes_seed_but_keeps_row() {
    let dir = tmpdir("undefine");
    let (mut p, _) = open_gap(&dir, "a");
    p.define_func(0x2, None).expect("define");
    p.undefine_func(0x2).expect("undefine");
    assert!(
        !p.analysis().functions.contains_key(&0x2),
        "undefined seed must not seed analysis"
    );
    let row = p.func_seeds().get(&0x2).expect("row kept as data");
    assert!(row.excluded, "undefine marks the row excluded");
    assert_eq!(
        p.seed_json(0x2),
        serde_json::json!({
            "addr": 0x2,
            "addr_hex": "0x2",
            "mode": null,
            "excluded": true,
        })
    );
    drop(p);
    let bin = gap_blob(&dir);
    let db = temp_db(&dir, "a");
    let q = binscout::Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: 0,
            arch: Arch::X86_64,
            entry: None,
        },
    )
    .expect("reopen");
    assert!(
        !q.analysis().functions.contains_key(&0x2),
        "exclusion survives reload"
    );
    assert!(
        q.func_seeds().get(&0x2).is_some_and(|s| s.excluded),
        "excluded row survives reload"
    );
    common::cleanup(&dir);
}

#[test]
fn comment_after_define_preserves_seed_and_function() {
    // Annotation fast path degrades to a full save when the seeds hash
    // changed; the rewrite must carry the seeds, not drop them.
    let dir = tmpdir("define-comment");
    let (mut p, _) = open_gap(&dir, "a");
    p.define_func(0x2, None).expect("define");
    drop(p);
    let bin = gap_blob(&dir);
    let db = temp_db(&dir, "a");
    let mut q = binscout::Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: 0,
            arch: Arch::X86_64,
            entry: None,
        },
    )
    .expect("reopen");
    q.set_comment(0x2, "tail").expect("comment");
    drop(q);
    let r = binscout::Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: 0,
            arch: Arch::X86_64,
            entry: None,
        },
    )
    .expect("reopen");
    assert!(
        r.analysis().functions.contains_key(&0x2),
        "function survives the annotation rewrite"
    );
    assert!(
        reasons_of(&r, 0x2).contains(&DiscoveryReason::User),
        "User reason survives the annotation rewrite"
    );
    assert_eq!(
        r.annotation(0x2).and_then(|a| a.comment.as_deref()),
        Some("tail")
    );
    common::cleanup(&dir);
}

#[test]
fn seed_mode_rejected_off_arm() {
    let dir = tmpdir("define-mode");
    let (mut p, _) = open_gap(&dir, "a");
    let err = p
        .define_func(0x2, Some(SeedMode::Thumb))
        .expect_err("thumb mode on x86_64 must fail");
    assert!(
        err.to_string().contains("32-bit ARM"),
        "mode error names the arch gate: {err}"
    );
    assert!(
        !p.analysis().functions.contains_key(&0x2),
        "failed define leaves analysis alone"
    );
    assert!(
        !p.func_seeds().contains_key(&0x2),
        "failed define leaves seeds alone"
    );
    common::cleanup(&dir);
}

#[test]
fn thumb_seed_decodes_thumb_in_arm32_project() {
    // `bx lr` is Thumb; as ARM32 the word does not decode, so the seed is
    // inert without a mode but materializes with `--mode thumb`.
    let dir = tmpdir("define-thumb");
    let bin = write_bin(&dir, "t.bin", &[0x70, 0x47]);
    let opts = RawOptions {
        base: 0x1000,
        arch: Arch::Arm32,
        entry: Some(0x1000),
    };
    let db = temp_db(&dir, "a");
    let mut p = binscout::Project::open_raw(&bin, &db, opts).expect("arm blob opens");
    assert!(
        p.analysis().functions.is_empty(),
        "bx lr does not decode as ARM32"
    );
    p.define_func(0x1000, None).expect("plain define stores");
    assert!(
        p.analysis().functions.is_empty(),
        "modeless seed still decodes as ARM32"
    );
    p.define_func(0x1000, Some(SeedMode::Thumb))
        .expect("thumb define");
    let f = p
        .analysis()
        .functions
        .get(&0x1000)
        .expect("thumb seed materializes");
    assert!(f.reason_list().contains(&DiscoveryReason::User));
    assert_eq!(f.decode_arch, Some(Arch::Thumb));
    drop(p);
    // Reload replays the mixed-mode snapshot bit-identically.
    let q = binscout::Project::open_raw(&bin, &db, opts).expect("reopen");
    let f = q
        .analysis()
        .functions
        .get(&0x1000)
        .expect("thumb function survives reload");
    assert!(f.reason_list().contains(&DiscoveryReason::User));
    assert_eq!(f.decode_arch, Some(Arch::Thumb));
    drop(q);
    // An odd Thumb-bit address canonicalizes to the even function entry.
    let db2 = temp_db(&dir, "b");
    let mut r = binscout::Project::open_raw(&bin, &db2, opts).expect("fresh open");
    r.define_func(0x1001, Some(SeedMode::Thumb))
        .expect("odd thumb seed");
    assert!(
        r.analysis().functions.contains_key(&0x1000),
        "odd seed canonicalizes to the even entry"
    );
    common::cleanup(&dir);
}

#[test]
fn export_import_round_trip_includes_seeds() {
    let dir = tmpdir("define-xfer");
    let (mut p, _) = open_gap(&dir, "a");
    p.define_func(0x2, None).expect("define");
    p.undefine_func(0x9).expect("undefine keeps row too");
    let doc = p.export_annotations().expect("export");
    let v: Value = serde_json::from_str(&doc).expect("export is JSON");
    let seeds = v["func_seeds"].as_array().expect("func_seeds array");
    assert_eq!(seeds.len(), 2, "both rows export: {seeds:?}");
    assert_eq!(seeds[0]["addr"], 0x2);
    assert_eq!(seeds[0]["excluded"], false);
    assert_eq!(seeds[1]["addr"], 0x9);
    assert_eq!(seeds[1]["excluded"], true);

    let bin = gap_blob(&dir);
    let db2 = temp_db(&dir, "b");
    let mut q = binscout::Project::open_raw(
        &bin,
        &db2,
        RawOptions {
            base: 0,
            arch: Arch::X86_64,
            entry: None,
        },
    )
    .expect("fresh open");
    let summary = q.import_annotations(&doc, false).expect("import");
    assert_eq!(summary.rows, 2);
    assert_eq!(summary.changed, 2);
    assert!(
        q.analysis().functions.contains_key(&0x2),
        "import re-analyzes with the seeds"
    );
    assert!(
        reasons_of(&q, 0x2).contains(&DiscoveryReason::User),
        "imported seed carries the User reason"
    );
    assert!(
        q.func_seeds().get(&0x9).is_some_and(|s| s.excluded),
        "imported exclusion persists"
    );
    drop(q);
    drop(p);
    let r = binscout::Project::open_raw(
        &bin,
        &db2,
        RawOptions {
            base: 0,
            arch: Arch::X86_64,
            entry: None,
        },
    )
    .expect("reopen");
    assert!(
        r.analysis().functions.contains_key(&0x2),
        "imported seed survives reload"
    );
    common::cleanup(&dir);
}

#[test]
fn stale_writer_reanalyzes_when_seeds_diverged() {
    // A defines a seed after B opened: B's rename must fall back to a full
    // save that re-analyzes with the merged seeds instead of persisting
    // B's stale seed-less analysis under the new seeds hash.
    let dir = tmpdir("define-race");
    let bin = gap_blob(&dir);
    let db = temp_db(&dir, "shared");
    let opts = RawOptions {
        base: 0,
        arch: Arch::X86_64,
        entry: None,
    };
    let probe = binscout::Project::open_raw(&bin, &db, opts).expect("open");
    probe.save().expect("bootstrap snapshot");
    drop(probe);

    let mut stale = binscout::Project::open_raw(&bin, &db, opts).expect("B opens");
    assert!(!stale.analysis().functions.contains_key(&0x2));
    {
        let mut other = binscout::Project::open_raw(&bin, &db, opts).expect("A opens");
        other.define_func(0x2, None).expect("A defines");
    }
    stale
        .rename_function(0x0, "entry")
        .expect("stale rename falls back");
    drop(stale);

    let r = binscout::Project::open_raw(&bin, &db, opts).expect("reopen");
    assert_eq!(r.function_name(0x0).as_deref(), Some("entry"));
    assert!(
        r.analysis().functions.contains_key(&0x2),
        "fallback re-analyzed with the merged seeds"
    );
    assert!(reasons_of(&r, 0x2).contains(&DiscoveryReason::User));
    assert!(r.func_seeds().contains_key(&0x2));
    common::cleanup(&dir);
}

#[test]
fn cli_define_undefine_round_trip() {
    let dir = tmpdir("define-cli");
    let bin = gap_blob(&dir);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "cli").display().to_string();

    let (ok, v) = run(&["--db", &db, "define-func", &bin_s, "0x2"]);
    assert!(ok, "{v}");
    assert_eq!(v["addr"], 0x2);
    assert_eq!(v["addr_hex"], "0x2");
    assert!(v["mode"].is_null(), "{v}");
    assert_eq!(v["excluded"], false);

    let (ok, v) = run(&["--db", &db, "func", &bin_s, "0x2"]);
    assert!(ok, "{v}");
    assert_eq!(v["entry"], 0x2);
    assert_eq!(v["reasons"], serde_json::json!(["user"]));

    let (ok, v) = run(&["--db", &db, "undefine-func", &bin_s, "0x2"]);
    assert!(ok, "{v}");
    assert_eq!(v["excluded"], true);

    let (ok, v) = run(&["--db", &db, "func", &bin_s, "0x2"]);
    assert!(!ok, "undefined function must be NotFound: {v}");
    assert!(v.get("error").is_some(), "{v}");

    // Bad mode spelling is a runtime JSON error, not a clap usage error.
    let (ok, v) = run(&["--db", &db, "define-func", &bin_s, "0x2", "--mode", "mips"]);
    assert!(!ok, "{v}");
    assert!(v.get("error").is_some(), "{v}");

    // Thumb mode on x86_64 is a runtime JSON error too.
    let (ok, v) = run(&["--db", &db, "define-func", &bin_s, "0x2", "--mode", "thumb"]);
    assert!(!ok, "{v}");
    assert!(
        v["error"]
            .as_str()
            .expect("error text")
            .contains("32-bit ARM"),
        "{v}"
    );
    cleanup(&dir);
}
