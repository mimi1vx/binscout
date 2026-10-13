//! Stale-snapshot tests for `db::load_cached` and the metadata-first open.
//!
//! A sidecar written for one binary revision must not cost decoding
//! proportional to its discarded rows when a smaller revision opens against
//! it: only metadata and annotations are read on hash mismatch. Healthy
//! stale snapshots re-analyze to exactly the fresh golden analysis while
//! carrying annotations forward, and reads never save.

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use binscout::Project;
use binscout::db::{self, Annotation};
use redb::ReadableTable;

// Table handles for hand-crafted sidecars (mirror `binscout::db` layouts).
const META: redb::TableDefinition<&str, String> = redb::TableDefinition::new("meta");
const BINARIES: redb::TableDefinition<u64, String> = redb::TableDefinition::new("binaries");
const FUNCTIONS: redb::TableDefinition<u64, String> = redb::TableDefinition::new("functions");
const BLOCKS: redb::TableDefinition<String, String> = redb::TableDefinition::new("blocks");
const XREFS: redb::TableDefinition<String, String> = redb::TableDefinition::new("xrefs");
const STRINGS: redb::TableDefinition<u64, String> = redb::TableDefinition::new("strings");
const ANNOTATIONS: redb::TableDefinition<u64, String> = redb::TableDefinition::new("annotations");

/// Minimal 64-bit LE ELF: one `PT_LOAD` (`nop; nop; ret`) at `0x400000`.
fn small_elf() -> Vec<u8> {
    common::minimal_elf()
}

/// File offset of the trailing `ret` in [`small_elf`].
fn ret_off() -> usize {
    0x78 + 2
}

/// Patched copy of `bytes`: trailing `ret` becomes `nop` (valid, new hash).
fn patched(mut bytes: Vec<u8>) -> Vec<u8> {
    assert_eq!(bytes[ret_off()], 0xC3);
    bytes[ret_off()] = 0x90;
    bytes
}

/// Open `bin` with `db`, add a rename plus a comment (persists a full
/// snapshot on the fresh sidecar), and return the binary bytes.
fn bootstrap_with_annotations(bin: &Path, db: &Path) -> Vec<u8> {
    let mut p = Project::open_with_db(bin, db).expect("open");
    p.rename_function(0x400000, "main").expect("rename");
    p.set_comment(0x400001, "second nop").expect("comment");
    assert!(db.exists(), "setters persist the sidecar");
    std::fs::read(bin).expect("reread fixture")
}

/// Insert one undecodable row into a `u64`-keyed table under a fresh key.
fn poison_u64_row(db_path: &Path, table: redb::TableDefinition<u64, String>, key: u64) {
    let db = db::open_db(db_path).expect("open db");
    let wtxn = db.begin_write().expect("begin write");
    {
        let mut t = wtxn.open_table(table).expect("open table");
        t.insert(key, "{not valid json".to_string())
            .expect("poison row");
    }
    wtxn.commit().expect("commit");
}

/// Insert one undecodable row into a `String`-keyed table under a fresh key.
fn poison_str_row(db_path: &Path, table: redb::TableDefinition<String, String>, key: &str) {
    let db = db::open_db(db_path).expect("open db");
    let wtxn = db.begin_write().expect("begin write");
    {
        let mut t = wtxn.open_table(table).expect("open table");
        t.insert(key.to_string(), "{not valid json".to_string())
            .expect("poison row");
    }
    wtxn.commit().expect("commit");
}

/// Rewrite the stored `binaries` row 0 with `version`.
fn set_stored_version(db_path: &Path, version: u32) {
    let db = db::open_db(db_path).expect("open db");
    let wtxn = db.begin_write().expect("begin write");
    {
        let mut t = wtxn.open_table(BINARIES).expect("open binaries");
        let raw: String = t.get(0u64).expect("read").expect("row 0 exists").value();
        let mut v: serde_json::Value = serde_json::from_str(&raw).expect("meta is json");
        v["version"] = version.into();
        t.insert(0u64, v.to_string()).expect("rewrite meta");
    }
    wtxn.commit().expect("commit");
}

/// Fresh golden analysis of `bytes`: open from a scratch dir with no sidecar.
fn fresh_analysis(bytes: &[u8]) -> binscout::analysis::Analysis {
    let dir = common::tmpdir("stale-golden");
    let bin = common::write_bin(&dir, "golden.bin", bytes);
    let db = common::temp_db(&dir, "golden");
    let p = Project::open_with_db(&bin, &db).expect("golden open");
    assert!(!db.exists(), "golden open must not save");
    let analysis = p.analysis().clone();
    common::cleanup(&dir);
    analysis
}

fn assert_same_analysis(a: &binscout::analysis::Analysis, b: &binscout::analysis::Analysis) {
    assert_eq!(a.summary(), b.summary());
    assert_eq!(a.call_edges(), b.call_edges());
    assert_eq!(a.xrefs, b.xrefs);
    assert_eq!(a.strings, b.strings);
}

#[test]
fn hit_loads_cached_snapshot() {
    let dir = common::tmpdir("stale-hit");
    let bin = common::write_bin(&dir, "hit.bin", &small_elf());
    let db = common::temp_db(&dir, "hit");

    let mut p = Project::open_with_db(&bin, &db).expect("open");
    p.rename_function(0x400000, "main").expect("rename");
    let before = p.analysis().clone();
    let before_edges = p.analysis().call_edges();
    drop(p);

    let hash = db::content_hash(&std::fs::read(&bin).expect("read"));
    {
        let handle = db::open_db(&db).expect("open db");
        match db::load_cached(&handle, hash).expect("load_cached") {
            db::Snapshot::Hit(hit) => {
                assert_eq!(hit.meta.content_hash, hash);
                assert_same_analysis(&hit.analysis, &before);
                assert_eq!(hit.analysis.call_edges(), before_edges);
                assert_eq!(
                    hit.annotations
                        .get(&0x400000)
                        .and_then(|a| a.name.as_deref()),
                    Some("main")
                );
            }
            other => panic!("expected Hit, got {other:?}"),
        }
    }

    let q = Project::open_with_db(&bin, &db).expect("reopen");
    assert_same_analysis(q.analysis(), &before);
    assert_eq!(q.function_name(0x400000).as_deref(), Some("main"));
    common::cleanup(&dir);
}

#[test]
fn miss_on_fresh_db() {
    let dir = common::tmpdir("stale-miss");
    let db = common::temp_db(&dir, "fresh");
    let handle = db::open_db(&db).expect("create db");
    assert!(
        matches!(
            db::load_cached(&handle, 1234).expect("load_cached"),
            db::Snapshot::Miss
        ),
        "fresh sidecar has no snapshot"
    );
    assert!(
        db::load(&handle).expect("load").is_none(),
        "load agrees: no snapshot"
    );
    common::cleanup(&dir);
}

#[test]
fn meta_without_binaries_row_errors() {
    // META marker with an empty `binaries` table is metadata corruption: no
    // hash comparison is possible, so both readers error, never Miss/Stale.
    let dir = common::tmpdir("stale-nobin");
    let db = common::temp_db(&dir, "nobin");
    {
        let handle = db::open_db(&db).expect("create db");
        let wtxn = handle.begin_write().expect("begin write");
        {
            let mut t = wtxn.open_table(META).expect("open meta");
            t.insert("version", "1".to_string()).expect("mark version");
            // Create an empty `binaries` table: marker present, row 0 absent.
            let _ = wtxn.open_table(BINARIES).expect("create binaries");
        }
        wtxn.commit().expect("commit");
        let err = db::load_cached(&handle, 0).unwrap_err();
        assert!(
            err.to_string().contains("no binary row"),
            "unexpected: {err:?}"
        );
        let err = db::load(&handle).unwrap_err();
        assert!(
            err.to_string().contains("no binary row"),
            "load must agree: {err:?}"
        );
    }
    common::cleanup(&dir);
}

#[test]
fn missing_derived_tables_error_on_hit_but_stale_skips() {
    let dir = common::tmpdir("stale-missing-table");
    let bytes = small_elf();
    let bin = common::write_bin(&dir, "m.bin", &bytes);
    let db = common::temp_db(&dir, "m");

    let p = Project::open_with_db(&bin, &db).expect("open");
    p.save().expect("save full snapshot");
    drop(p);
    let old_hash = db::content_hash(&bytes);

    {
        let handle = db::open_db(&db).expect("open db");
        let wtxn = handle.begin_write().expect("begin write");
        wtxn.delete_table(FUNCTIONS).expect("drop functions");
        wtxn.commit().expect("commit");
    }

    // Matching hash: the snapshot is corrupt, still an error.
    {
        let handle = db::open_db(&db).expect("open db");
        let err = db::load_cached(&handle, old_hash).unwrap_err();
        assert!(
            err.to_string().contains("open functions"),
            "unexpected: {err:?}"
        );
    }

    // Mismatched hash: derived tables are never opened, open succeeds.
    let new_bytes = patched(bytes);
    std::fs::write(&bin, &new_bytes).expect("patch fixture");
    {
        let handle = db::open_db(&db).expect("open db");
        assert!(
            matches!(
                db::load_cached(&handle, db::content_hash(&new_bytes)).expect("load_cached"),
                db::Snapshot::Stale { .. }
            ),
            "missing derived tables must not fail the stale path"
        );
    }
    let q = Project::open_with_db(&bin, &db).expect("stale open succeeds");
    assert_same_analysis(q.analysis(), &fresh_analysis(&new_bytes));
    common::cleanup(&dir);
}

#[test]
fn version_mismatch_errors_on_hit_but_stale_carries_annotations() {
    let dir = common::tmpdir("stale-version");
    let bytes = small_elf();
    let bin = common::write_bin(&dir, "v.bin", &bytes);
    let db = common::temp_db(&dir, "v");

    bootstrap_with_annotations(&bin, &db);
    let old_hash = db::content_hash(&bytes);
    set_stored_version(&db, 999);

    // Matching hash with an unknown schema version: still an error, the
    // cached rows cannot be trusted for decoding.
    {
        let handle = db::open_db(&db).expect("open db");
        let err = db::load_cached(&handle, old_hash).unwrap_err();
        assert!(err.to_string().contains("version"), "unexpected: {err:?}");
    }

    // Mismatched hash: the version only gates analysis decoding, which the
    // stale path skips; annotations still carry over.
    let new_bytes = patched(bytes);
    std::fs::write(&bin, &new_bytes).expect("patch fixture");
    {
        let handle = db::open_db(&db).expect("open db");
        match db::load_cached(&handle, db::content_hash(&new_bytes)).expect("load_cached") {
            db::Snapshot::Stale { meta, annotations } => {
                assert_eq!(meta.version, 999);
                assert_eq!(
                    annotations.get(&0x400000).and_then(|a| a.name.as_deref()),
                    Some("main")
                );
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }
    let q = Project::open_with_db(&bin, &db).expect("stale open succeeds");
    assert_eq!(q.function_name(0x400000).as_deref(), Some("main"));
    assert_same_analysis(q.analysis(), &fresh_analysis(&new_bytes));
    common::cleanup(&dir);
}

#[test]
fn healthy_stale_carries_annotations_matches_fresh_and_never_saves() {
    let dir = common::tmpdir("stale-healthy");
    let bytes = small_elf();
    let bin = common::write_bin(&dir, "h.bin", &bytes);
    let db = common::temp_db(&dir, "h");

    bootstrap_with_annotations(&bin, &db);
    let old_hash = db::content_hash(&bytes);
    // Stored snapshot before the stale read (meta, analysis, annotations).
    let (stored_meta, stored_summary, stored_edges, stored_xrefs, stored_strings, stored_ann) = {
        let handle = db::open_db(&db).expect("open db");
        let stored = db::load(&handle).expect("load").expect("snapshot exists");
        (
            stored.meta,
            stored.analysis.summary(),
            stored.analysis.call_edges(),
            stored.analysis.xrefs,
            stored.analysis.strings,
            stored.annotations,
        )
    };
    assert_eq!(stored_meta.content_hash, old_hash);

    let new_bytes = patched(bytes);
    std::fs::write(&bin, &new_bytes).expect("patch fixture");

    let q = Project::open_with_db(&bin, &db).expect("stale open");
    assert_ne!(q.content_hash(), old_hash);
    assert_eq!(q.function_name(0x400000).as_deref(), Some("main"));
    assert_eq!(
        q.annotation(0x400001).and_then(|a| a.comment.as_deref()),
        Some("second nop"),
        "annotations survive re-analysis by address"
    );
    assert_same_analysis(q.analysis(), &fresh_analysis(&new_bytes));
    let entry_block = &q.analysis().functions[&0x400000]
        .blocks
        .values()
        .next()
        .expect("one block")
        .insns;
    assert_eq!(entry_block.len(), 3);
    assert_eq!(entry_block[2].mnem, "nop", "re-analysis sees patched bytes");

    // No read-path save: the sidecar still holds the old snapshot, with
    // the same analysis and annotations as before the stale read. (File
    // bytes may shift under `redb` open housekeeping; the stored snapshot
    // is what reads must leave alone.)
    {
        let handle = db::open_db(&db).expect("open db");
        let stored = db::load(&handle)
            .expect("load")
            .expect("old snapshot intact");
        assert_eq!(stored.meta, stored_meta);
        assert_eq!(stored.analysis.summary(), stored_summary);
        assert_eq!(stored.analysis.call_edges(), stored_edges);
        assert_eq!(stored.analysis.xrefs, stored_xrefs);
        assert_eq!(stored.analysis.strings, stored_strings);
        assert_eq!(stored.annotations, stored_ann);
    }
    common::cleanup(&dir);
}

#[test]
fn stale_corrupt_derived_rows_are_discarded() {
    let dir = common::tmpdir("stale-corrupt-derived");
    let bytes = small_elf();
    let bin = common::write_bin(&dir, "c.bin", &bytes);
    let db = common::temp_db(&dir, "c");

    bootstrap_with_annotations(&bin, &db);
    let old_hash = db::content_hash(&bytes);

    // Poison one row per derived table. A full decode must choke on these.
    poison_u64_row(&db, FUNCTIONS, u64::MAX);
    poison_str_row(&db, BLOCKS, "ff:ff");
    poison_str_row(&db, XREFS, "ff");
    poison_u64_row(&db, STRINGS, u64::MAX);
    {
        let handle = db::open_db(&db).expect("open db");
        let err = db::load(&handle).unwrap_err();
        assert!(
            err.to_string().contains("decode row"),
            "full load must still validate: {err:?}"
        );
        let err = db::load_cached(&handle, old_hash).unwrap_err();
        assert!(
            err.to_string().contains("decode row"),
            "hit path must still validate: {err:?}"
        );
    }

    // Stale open discards the poisoned rows and re-analyzes instead.
    let new_bytes = patched(bytes);
    std::fs::write(&bin, &new_bytes).expect("patch fixture");
    {
        let handle = db::open_db(&db).expect("open db");
        assert!(
            matches!(
                db::load_cached(&handle, db::content_hash(&new_bytes)).expect("load_cached"),
                db::Snapshot::Stale { .. }
            ),
            "stale path must skip corrupt derived rows"
        );
    }
    let q = Project::open_with_db(&bin, &db).expect("stale open succeeds");
    assert_eq!(q.function_name(0x400000).as_deref(), Some("main"));
    assert_eq!(
        q.annotation(0x400001).and_then(|a| a.comment.as_deref()),
        Some("second nop")
    );
    assert_same_analysis(q.analysis(), &fresh_analysis(&new_bytes));
    common::cleanup(&dir);
}

#[test]
fn stale_corrupt_annotations_still_error() {
    // Annotations carry over into the re-analysis, so a corrupt annotation
    // row errors even on the stale path: silently dropping user data would
    // be worse than refusing to open.
    let dir = common::tmpdir("stale-corrupt-ann");
    let bytes = small_elf();
    let bin = common::write_bin(&dir, "a.bin", &bytes);
    let db = common::temp_db(&dir, "a");

    bootstrap_with_annotations(&bin, &db);
    poison_u64_row(&db, ANNOTATIONS, u64::MAX);

    let new_bytes = patched(bytes);
    std::fs::write(&bin, &new_bytes).expect("patch fixture");
    {
        let handle = db::open_db(&db).expect("open db");
        let err = db::load_cached(&handle, db::content_hash(&new_bytes)).unwrap_err();
        assert!(
            err.to_string().contains("decode row"),
            "corrupt annotations must error: {err:?}"
        );
    }
    let err = Project::open_with_db(&bin, &db).unwrap_err();
    assert!(
        err.to_string().contains("decode row"),
        "stale open must surface corrupt annotations: {err:?}"
    );
    common::cleanup(&dir);
}

#[test]
fn stale_missing_annotations_table_reads_empty() {
    let dir = common::tmpdir("stale-no-ann-table");
    let bytes = small_elf();
    let bin = common::write_bin(&dir, "t.bin", &bytes);
    let db = common::temp_db(&dir, "t");

    let p = Project::open_with_db(&bin, &db).expect("open");
    p.save().expect("save full snapshot");
    drop(p);
    {
        let handle = db::open_db(&db).expect("open db");
        let wtxn = handle.begin_write().expect("begin write");
        wtxn.delete_table(ANNOTATIONS).expect("drop annotations");
        wtxn.commit().expect("commit");
    }

    let new_bytes = patched(bytes);
    std::fs::write(&bin, &new_bytes).expect("patch fixture");
    let q = Project::open_with_db(&bin, &db).expect("stale open succeeds");
    assert!(q.annotations().is_empty());
    assert_same_analysis(q.analysis(), &fresh_analysis(&new_bytes));
    common::cleanup(&dir);
}

#[test]
fn stale_snapshot_reads_one_coherent_sidecar_generation() {
    // Overwriting the sidecar with another binary's snapshot, then opening
    // the first binary, must yield that generation's metadata together with
    // its annotations — never a mix. One read transaction covers both.
    // (The `aaa` rename at `0x400000` legitimately carries over by address
    // into generation b, exactly like the concurrent-sidecar case: the
    // point is meta and annotations belong to the same generation.)
    let dir = common::tmpdir("stale-coherent");
    let bin_a = common::write_bin(&dir, "a.bin", &small_elf());
    let other = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let bin_b = dir.join("b.bin");
    std::fs::copy(&other, &bin_b).expect("copy");
    let _ = std::fs::remove_file(&other);
    let db = common::temp_db(&dir, "shared");

    let mut proj_a = Project::open_with_db(&bin_a, &db).expect("open a");
    proj_a.rename_function(0x400000, "aaa").expect("rename a");
    drop(proj_a);

    let entry_b = common::builders::BASIC_ENTRY_VA;
    let mut proj_b = Project::open_with_db(&bin_b, &db).expect("open b");
    proj_b.set_comment(entry_b, "bee").expect("comment b");
    proj_b.save().expect("overwrite sidecar with b");
    drop(proj_b);

    let hash_a = db::content_hash(&std::fs::read(&bin_a).expect("read a"));
    let hash_b = db::content_hash(&std::fs::read(&bin_b).expect("read b"));
    assert_ne!(hash_a, hash_b);
    let handle = db::open_db(&db).expect("open db");
    let expected = db::load(&handle)
        .expect("load")
        .expect("generation b snapshot");
    assert_eq!(expected.meta.content_hash, hash_b);
    match db::load_cached(&handle, hash_a).expect("load_cached") {
        db::Snapshot::Stale { meta, annotations } => {
            assert_eq!(meta, expected.meta, "stale meta is generation b");
            assert_eq!(
                annotations, expected.annotations,
                "stale annotations are generation b's"
            );
            assert_eq!(
                annotations.get(&entry_b).and_then(|a| a.comment.as_deref()),
                Some("bee")
            );
        }
        other => panic!("expected Stale, got {other:?}"),
    }
    common::cleanup(&dir);
}

#[test]
fn stale_open_ignores_large_derived_tables() {
    // Functional proof that discarded rows cost nothing to decode: twenty
    // thousand corrupt block rows plus a patched binary still open fast and
    // correct, because the stale path never touches the blocks table.
    let dir = common::tmpdir("stale-large");
    let bytes = small_elf();
    let bin = common::write_bin(&dir, "l.bin", &bytes);
    let db = common::temp_db(&dir, "l");

    bootstrap_with_annotations(&bin, &db);
    {
        let handle = db::open_db(&db).expect("open db");
        let wtxn = handle.begin_write().expect("begin write");
        {
            let mut t = wtxn.open_table(BLOCKS).expect("open blocks");
            for i in 0..20_000u32 {
                t.insert(format!("junk:{i:08x}"), "{not json".to_string())
                    .expect("junk row");
            }
        }
        wtxn.commit().expect("commit");
    }

    let new_bytes = patched(bytes);
    std::fs::write(&bin, &new_bytes).expect("patch fixture");
    let q = Project::open_with_db(&bin, &db).expect("stale open skips junk rows");
    assert_eq!(q.function_name(0x400000).as_deref(), Some("main"));
    assert_same_analysis(q.analysis(), &fresh_analysis(&new_bytes));
    common::cleanup(&dir);
}

#[test]
fn corrupt_unknown_arch_still_errors_on_hit_but_stale_skips() {
    // `arch`/`format` gate analysis decoding only: unchecked on stale.
    let dir = common::tmpdir("stale-arch");
    let bytes = small_elf();
    let bin = common::write_bin(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");

    bootstrap_with_annotations(&bin, &db);
    let old_hash = db::content_hash(&bytes);
    {
        let handle = db::open_db(&db).expect("open db");
        let wtxn = handle.begin_write().expect("begin write");
        {
            let mut t = wtxn.open_table(BINARIES).expect("open binaries");
            let raw: String = t.get(0u64).expect("read").expect("row 0 exists").value();
            let mut v: serde_json::Value = serde_json::from_str(&raw).expect("meta is json");
            v["arch"] = "mips".into();
            t.insert(0u64, v.to_string()).expect("rewrite meta");
        }
        wtxn.commit().expect("commit");
        let err = db::load_cached(&handle, old_hash).unwrap_err();
        assert!(
            err.to_string().contains("unknown arch"),
            "hit path must validate arch: {err:?}"
        );
    }

    let new_bytes = patched(bytes);
    std::fs::write(&bin, &new_bytes).expect("patch fixture");
    let q = Project::open_with_db(&bin, &db).expect("stale open skips arch check");
    assert_eq!(q.function_name(0x400000).as_deref(), Some("main"));
    assert_same_analysis(q.analysis(), &fresh_analysis(&new_bytes));
    common::cleanup(&dir);
}

#[test]
fn empty_annotations_are_skipped_but_kept_absent() {
    // Empty annotation rows never persist; the stale path mirrors that.
    let dir = common::tmpdir("stale-empty-ann");
    let bytes = small_elf();
    let bin = common::write_bin(&dir, "e.bin", &bytes);
    let db = common::temp_db(&dir, "e");

    bootstrap_with_annotations(&bin, &db);
    {
        let handle = db::open_db(&db).expect("open db");
        let wtxn = handle.begin_write().expect("begin write");
        {
            let mut t = wtxn.open_table(ANNOTATIONS).expect("open annotations");
            let empty = serde_json::to_string(&Annotation::default()).expect("encode");
            t.insert(0x9999u64, empty).expect("empty row");
        }
        wtxn.commit().expect("commit");
    }

    let new_bytes = patched(bytes);
    std::fs::write(&bin, &new_bytes).expect("patch fixture");
    let q = Project::open_with_db(&bin, &db).expect("stale open");
    assert!(!q.annotations().contains_key(&0x9999));
    assert_eq!(
        q.annotation(0x400000).and_then(|a| a.name.as_deref()),
        Some("main")
    );
    let ann_map: BTreeMap<u64, Annotation> = q.annotations().clone();
    assert_eq!(ann_map.len(), 2);
    common::cleanup(&dir);
}

#[cfg(unix)]
#[test]
fn read_opens_work_on_write_protected_sidecars() {
    // Read paths open the sidecar read-only: a `Hit` and a `Stale` open
    // both succeed on a write-protected file, where a writable open would
    // fail. Uses `std::os::unix` permissions; the file stays user-owned.
    use std::os::unix::fs::PermissionsExt;

    let dir = common::tmpdir("stale-readonly");
    let bytes = small_elf();
    let bin = common::write_bin(&dir, "ro.bin", &bytes);
    let db = common::temp_db(&dir, "ro");

    bootstrap_with_annotations(&bin, &db);
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o444))
        .expect("write-protect sidecar");

    // Matching hash: full cached snapshot from a read-only file.
    let p = Project::open_with_db(&bin, &db).expect("hit on read-only sidecar");
    assert_eq!(p.function_name(0x400000).as_deref(), Some("main"));

    // Mismatched hash: stale annotations without decoding, same file.
    let new_bytes = patched(bytes);
    std::fs::write(&bin, &new_bytes).expect("patch fixture");
    let q = Project::open_with_db(&bin, &db).expect("stale on read-only sidecar");
    assert_eq!(q.function_name(0x400000).as_deref(), Some("main"));
    assert_same_analysis(q.analysis(), &fresh_analysis(&new_bytes));

    // Restore writability so temp-dir cleanup cannot trip on the mode.
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644))
        .expect("restore sidecar mode");
    common::cleanup(&dir);
}
