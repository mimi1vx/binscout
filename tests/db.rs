//! M5 persist tests: save/load round-trip, content-hash re-analysis with
//! surviving annotations, `project_info`, and the binary-is-never-written
//! guarantee. All file work stays under a unique temp dir; the analyzed
//! binaries are synthetic minimal ELFs built in memory.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use binscout::Project;
use binscout::error::Error;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "binscout-{}-{}-{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// Minimal 64-bit LE ELF: one `PT_LOAD` (`nop; nop; ret`) at `0x400000`.
fn minimal_elf() -> Vec<u8> {
    fn put16(v: &mut [u8], off: usize, x: u16) {
        v[off..off + 2].copy_from_slice(&x.to_le_bytes());
    }
    fn put32(v: &mut [u8], off: usize, x: u32) {
        v[off..off + 4].copy_from_slice(&x.to_le_bytes());
    }
    fn put64(v: &mut [u8], off: usize, x: u64) {
        v[off..off + 8].copy_from_slice(&x.to_le_bytes());
    }
    let mut f = vec![0u8; 0x78];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2;
    f[5] = 1;
    f[6] = 1;
    put16(&mut f, 16, 2);
    put16(&mut f, 18, 62);
    put32(&mut f, 20, 1);
    put64(&mut f, 24, 0x400000);
    put64(&mut f, 32, 64);
    put16(&mut f, 52, 64);
    put16(&mut f, 54, 56);
    put16(&mut f, 56, 1);
    let p = 64;
    put32(&mut f, p, 1);
    put32(&mut f, p + 4, 5);
    put64(&mut f, p + 8, 0x78);
    put64(&mut f, p + 16, 0x400000);
    put64(&mut f, p + 32, 3);
    put64(&mut f, p + 40, 3);
    put64(&mut f, p + 48, 0x1000);
    f.extend_from_slice(&[0x90, 0x90, 0xC3]);
    f
}

fn write_fixture(dir: &Path, name: &str, bytes: &[u8]) -> (PathBuf, PathBuf) {
    let bin = dir.join(name);
    let db = dir.join(format!("{name}.redb"));
    std::fs::write(&bin, bytes).expect("write fixture binary");
    (bin, db)
}

#[test]
fn save_load_round_trip_preserves_analysis_and_annotations() {
    let dir = tmpdir("roundtrip");
    let bytes = minimal_elf();
    let (bin, db) = write_fixture(&dir, "t.bin", &bytes);

    let mut p = Project::open_with_db(&bin, &db).expect("open analyzes");
    assert_eq!(p.analysis().summary().functions, 1);
    assert!(p.analysis().functions.contains_key(&0x400000));
    p.rename_function(0x400000, "main").expect("rename");
    p.set_comment(0x400000, "entry point").expect("comment");
    assert!(db.exists(), "annotation setters persist to the db file");
    let before = p.analysis().summary();
    let before_edges = p.analysis().call_edges();
    let before_xrefs = p.analysis().xrefs.len();

    drop(p);
    let q = Project::open_with_db(&bin, &db).expect("reopen loads snapshot");
    assert_eq!(q.analysis().summary(), before);
    assert_eq!(q.analysis().call_edges(), before_edges);
    assert_eq!(q.analysis().xrefs.len(), before_xrefs);
    assert_eq!(q.function_name(0x400000).as_deref(), Some("main"));
    assert_eq!(
        q.annotation(0x400000).map(|a| a.comment.as_deref()),
        Some(Some("entry point"))
    );
    assert_eq!(q.project_info().annotations, 1);

    assert_eq!(
        std::fs::read(&bin).expect("binary still readable"),
        bytes,
        "binary must be byte-identical after save/load"
    );
    cleanup(&dir);
}

#[test]
fn content_hash_change_reanalyzes_but_annotations_survive() {
    let dir = tmpdir("rehash");
    let bytes = minimal_elf();
    let (bin, db) = write_fixture(&dir, "r.bin", &bytes);

    let mut p = Project::open_with_db(&bin, &db).expect("open");
    let old_hash = p.content_hash();
    p.rename_function(0x400000, "main").expect("rename");
    p.set_comment(0x400001, "second nop").expect("comment");
    drop(p);

    // Ret -> nop at the trailing code byte: still valid, analysis differs.
    let mut patched = bytes.clone();
    let code_off = 0x78 + 2;
    assert_eq!(patched[code_off], 0xC3);
    patched[code_off] = 0x90;
    std::fs::write(&bin, &patched).expect("patch fixture");

    let q = Project::open_with_db(&bin, &db).expect("reopen re-analyzes");
    assert_ne!(q.content_hash(), old_hash);
    assert_eq!(q.function_name(0x400000).as_deref(), Some("main"));
    assert_eq!(
        q.annotation(0x400001).map(|a| a.comment.as_deref()),
        Some(Some("second nop")),
        "annotations survive re-analysis by address"
    );
    let entry_block = &q.analysis().functions[&0x400000]
        .blocks
        .values()
        .next()
        .expect("one block")
        .insns;
    assert_eq!(entry_block.len(), 3);
    assert_eq!(entry_block[2].mnem, "nop", "re-analysis sees patched bytes");
    cleanup(&dir);
}

#[test]
fn project_info_is_json_with_matching_counts() {
    let dir = tmpdir("info");
    let bytes = minimal_elf();
    let (bin, db) = write_fixture(&dir, "i.bin", &bytes);

    let p = Project::open_with_db(&bin, &db).expect("open");
    let info = p.project_info();
    let v = serde_json::to_value(&info).expect("project_info serializes");
    assert_eq!(v["arch"], "x86_64");
    assert_eq!(v["format"], "elf");
    assert_eq!(v["entry"], 0x400000);
    let s = p.analysis().summary();
    assert_eq!(info.functions, s.functions);
    assert_eq!(info.blocks, s.blocks);
    assert_eq!(info.insns, s.insns);
    assert_eq!(info.xrefs, s.xrefs);
    assert_eq!(info.strings, s.strings);
    assert_eq!(info.content_hash, p.content_hash());
    cleanup(&dir);
}

#[test]
fn rename_unknown_function_errors_and_clears() {
    let dir = tmpdir("rename");
    let bytes = minimal_elf();
    let (bin, db) = write_fixture(&dir, "n.bin", &bytes);

    let mut p = Project::open_with_db(&bin, &db).expect("open");
    let err = p.rename_function(0xdead, "nope").unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");

    p.rename_function(0x400000, "main").expect("rename");
    assert_eq!(p.function_name(0x400000).as_deref(), Some("main"));
    p.rename_function(0x400000, "").expect("clear");
    assert!(p.annotation(0x400000).is_none());
    assert_eq!(p.project_info().annotations, 0);
    // Empty comment clears the same way.
    p.set_comment(0x400000, "hi").expect("comment");
    p.set_comment(0x400000, "").expect("clear comment");
    assert!(p.annotation(0x400000).is_none());
    cleanup(&dir);
}

#[test]
fn save_only_writes_db_path() {
    let dir = tmpdir("dbonly");
    let bytes = minimal_elf();
    let (bin, db) = write_fixture(&dir, "d.bin", &bytes);
    let before_meta = std::fs::metadata(&bin).expect("meta");

    let mut p = Project::open_with_db(&bin, &db).expect("open");
    p.rename_function(0x400000, "main").expect("rename");
    p.set_comment(0x400001, "note").expect("comment");
    p.save().expect("explicit save");

    assert_ne!(p.db_path(), p.path(), "db and binary paths differ");
    assert_eq!(std::fs::read(&bin).expect("read"), bytes);
    let after_meta = std::fs::metadata(&bin).expect("meta");
    assert_eq!(
        before_meta.len(),
        after_meta.len(),
        "binary length untouched by db writes"
    );
    cleanup(&dir);
}
