//! Annotation fast-path tests: single-row writes match full-save logic.

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use binscout::Project;
use binscout::db::{self, Annotation, AnnotationSave};
use binscout::error::Error;

fn bootstrap(bin: &Path, db: &Path) -> Project {
    let p = Project::open_with_db(bin, db).expect("open");
    p.save().expect("bootstrap full save");
    Project::open_with_db(bin, db).expect("reopen bootstrapped")
}

fn dumped_annotations(bin: &Path, db: &Path) -> BTreeMap<u64, Annotation> {
    Project::open_with_db(bin, db)
        .expect("reopen")
        .annotations()
        .clone()
}

fn full_save_reference(
    ref_db: &Path,
    analysis: &binscout::analysis::Analysis,
    annotations: &BTreeMap<u64, Annotation>,
    meta_template: &db::BinaryMeta,
) -> db::Loaded {
    let db_handle = db::open_db(ref_db).expect("open ref db");
    db::save(&db_handle, meta_template, analysis, annotations).expect("ref full save");
    drop(db_handle);
    let db_handle = db::open_db(ref_db).expect("reopen ref db");
    db::load(&db_handle)
        .expect("load ref")
        .expect("ref has snapshot")
}

fn persisted_meta(bin: &Path, db: &Path) -> db::BinaryMeta {
    let handle = db::open_db(db).expect("open db");
    let loaded = db::load(&handle).expect("load").expect("snapshot exists");
    assert_eq!(
        std::fs::read(bin)
            .map(|b| db::content_hash(&b))
            .expect("hash"),
        loaded.meta.content_hash
    );
    loaded.meta
}

#[test]
fn fast_rename_matches_full_reference() {
    let dir = common::tmpdir("fast-rename");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "fast");
    let ref_db = common::temp_db(&dir, "ref");
    let entry = common::builders::BASIC_ENTRY_VA;
    let bytes_before = std::fs::read(&bin).expect("read bin");

    let mut p = bootstrap(&bin, &db);
    let before_summary = p.analysis().summary();
    let before_edges = p.analysis().call_edges();
    let meta = persisted_meta(&bin, &db);

    p.rename_function(entry, "fast_entry").expect("rename");
    assert_eq!(p.function_name(entry).as_deref(), Some("fast_entry"));

    drop(p);
    let q = Project::open_with_db(&bin, &db).expect("reopen");
    assert_eq!(q.analysis().summary(), before_summary);
    assert_eq!(q.analysis().call_edges(), before_edges);
    assert_eq!(q.function_name(entry).as_deref(), Some("fast_entry"));
    assert_eq!(
        q.annotation(entry).and_then(|a| a.name.as_deref()),
        Some("fast_entry")
    );

    let mut expected_ann = BTreeMap::new();
    expected_ann.insert(
        entry,
        Annotation {
            name: Some("fast_entry".to_string()),
            comment: None,
        },
    );
    let loaded_fast = {
        let h = db::open_db(&db).expect("open fast db");
        db::load(&h).expect("load fast").expect("snapshot")
    };
    let loaded_ref = full_save_reference(&ref_db, q.analysis(), &expected_ann, &meta);
    assert_eq!(
        loaded_fast.analysis.summary(),
        loaded_ref.analysis.summary()
    );
    assert_eq!(
        loaded_fast.analysis.call_edges(),
        loaded_ref.analysis.call_edges()
    );
    assert_eq!(loaded_fast.analysis.xrefs, loaded_ref.analysis.xrefs);
    assert_eq!(loaded_fast.analysis.strings, loaded_ref.analysis.strings);
    assert_eq!(loaded_fast.annotations, loaded_ref.annotations);
    assert_eq!(loaded_fast.meta, loaded_ref.meta);

    assert_eq!(std::fs::read(&bin).expect("reread"), bytes_before);
    common::cleanup(&dir);
}

#[test]
fn fast_comment_matches_full_reference() {
    let dir = common::tmpdir("fast-comment");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "fast");
    let ref_db = common::temp_db(&dir, "ref");
    let string_va = common::builders::BASIC_STRING_VA;
    let bytes_before = std::fs::read(&bin).expect("read bin");

    let mut p = bootstrap(&bin, &db);
    let before_summary = p.analysis().summary();
    let meta = persisted_meta(&bin, &db);

    p.set_comment(string_va, "string note").expect("comment");
    drop(p);
    let q = Project::open_with_db(&bin, &db).expect("reopen");
    assert_eq!(q.analysis().summary(), before_summary);
    assert_eq!(
        q.annotation(string_va).and_then(|a| a.comment.as_deref()),
        Some("string note")
    );

    let mut expected_ann = BTreeMap::new();
    expected_ann.insert(
        string_va,
        Annotation {
            name: None,
            comment: Some("string note".to_string()),
        },
    );
    let loaded_fast = {
        let h = db::open_db(&db).expect("open");
        db::load(&h).expect("load").expect("snapshot")
    };
    let loaded_ref = full_save_reference(&ref_db, q.analysis(), &expected_ann, &meta);
    assert_eq!(loaded_fast.annotations, loaded_ref.annotations);
    assert_eq!(
        loaded_fast.analysis.summary(),
        loaded_ref.analysis.summary()
    );
    assert_eq!(loaded_fast.meta, loaded_ref.meta);
    assert_eq!(std::fs::read(&bin).expect("reread"), bytes_before);
    common::cleanup(&dir);
}

#[test]
fn fast_clear_keeps_sibling_field_and_matches_full() {
    let dir = common::tmpdir("fast-clear");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "fast");
    let entry = common::builders::BASIC_ENTRY_VA;

    let mut p = bootstrap(&bin, &db);
    let before_summary = p.analysis().summary();
    p.rename_function(entry, "both").expect("rename");
    p.set_comment(entry, "keep me").expect("comment");
    assert_eq!(
        p.annotation(entry).and_then(|a| a.name.as_deref()),
        Some("both")
    );
    assert_eq!(
        p.annotation(entry).and_then(|a| a.comment.as_deref()),
        Some("keep me")
    );

    p.rename_function(entry, "").expect("clear rename");
    assert!(p.annotation(entry).is_some(), "comment keeps row alive");
    assert_eq!(
        p.annotation(entry).and_then(|a| a.comment.as_deref()),
        Some("keep me")
    );
    assert!(
        p.annotation(entry)
            .and_then(|a| a.name.as_deref())
            .is_none()
    );
    assert_eq!(
        p.function_name(entry).as_deref(),
        Some(common::builders::BASIC_EXPORT)
    );

    drop(p);
    let mut q = Project::open_with_db(&bin, &db).expect("reopen");
    assert_eq!(q.analysis().summary(), before_summary);
    assert_eq!(
        q.annotation(entry).and_then(|a| a.comment.as_deref()),
        Some("keep me")
    );
    assert!(
        q.annotation(entry)
            .and_then(|a| a.name.as_deref())
            .is_none()
    );

    q.set_comment(entry, "").expect("clear comment");
    assert!(q.annotation(entry).is_none());
    drop(q);
    let r = Project::open_with_db(&bin, &db).expect("reopen after clear");
    assert!(r.annotation(entry).is_none());
    assert_eq!(r.analysis().summary(), before_summary);
    assert_eq!(r.project_info().annotations, 0);
    common::cleanup(&dir);
}

#[test]
fn fresh_db_bootstraps_full_snapshot() {
    let dir = common::tmpdir("fast-fresh");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "fresh");
    let entry = common::builders::BASIC_ENTRY_VA;
    assert!(!db.exists());

    {
        let probe = Project::open_with_db(&bin, &db).expect("open fresh");
        let info = probe.project_info();
        let meta = db::BinaryMeta {
            version: db::SCHEMA_VERSION,
            binary_path: probe.path().display().to_string(),
            content_hash: probe.content_hash(),
            size: info.size,
            arch: info.arch.clone(),
            format: info.format.clone(),
            entry: info.entry,
            supported: true,
            reason: None,
        };
        let ann = Annotation {
            name: Some("probe".to_string()),
            comment: None,
        };
        // Probe holds no DB handle, so opening one here is exclusive-safe.
        let handle = db::open_db(&db).expect("create fresh db");
        let outcome = db::save_annotation(&handle, &meta, entry, Some(&ann)).expect("probe fresh");
        assert_eq!(outcome, AnnotationSave::NeedsFull);
    }
    let _ = std::fs::remove_file(&db);

    let mut p = Project::open_with_db(&bin, &db).expect("open fresh");
    let fresh_summary = p.analysis().summary();
    p.rename_function(entry, "first")
        .expect("first rename bootstraps");
    assert!(db.exists());
    drop(p);
    let q = Project::open_with_db(&bin, &db).expect("reopen");
    assert_eq!(q.analysis().summary(), fresh_summary);
    assert_eq!(q.function_name(entry).as_deref(), Some("first"));
    common::cleanup(&dir);
}

#[test]
fn changed_binary_forces_full_save_and_keeps_annotations() {
    let dir = common::tmpdir("fast-changed");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "changed");
    let entry = common::builders::BASIC_ENTRY_VA;
    let string_va = common::builders::BASIC_STRING_VA;

    let mut p = bootstrap(&bin, &db);
    p.rename_function(entry, "survivor").expect("rename");
    p.set_comment(string_va, "survives patch").expect("comment");
    let old_hash = p.content_hash();
    drop(p);

    let mut bytes = std::fs::read(&bin).expect("read");
    let patched_off = bytes
        .windows(2)
        .position(|w| w == [0x68, (string_va & 0xff) as u8])
        .expect("push of string va");
    bytes[patched_off] = 0x90;
    std::fs::write(&bin, &bytes).expect("patch");
    let new_hash = db::content_hash(&bytes);
    assert_ne!(old_hash, new_hash);

    let mut q = Project::open_with_db(&bin, &db).expect("reopen re-analyzes");
    assert_eq!(q.content_hash(), new_hash);
    assert_eq!(q.function_name(entry).as_deref(), Some("survivor"));
    let reanalyzed_summary = q.analysis().summary();

    q.set_comment(entry, "after patch")
        .expect("comment after patch");
    drop(q);
    let r = Project::open_with_db(&bin, &db).expect("reopen after full");
    assert_eq!(r.content_hash(), new_hash);
    assert_eq!(r.analysis().summary(), reanalyzed_summary);
    assert_eq!(r.function_name(entry).as_deref(), Some("survivor"));
    assert_eq!(
        r.annotation(string_va).and_then(|a| a.comment.as_deref()),
        Some("survives patch")
    );
    assert_eq!(
        r.annotation(entry).and_then(|a| a.comment.as_deref()),
        Some("after patch")
    );
    let handle = db::open_db(&db).expect("open");
    let loaded = db::load(&handle).expect("load").expect("snapshot");
    assert_eq!(loaded.meta.content_hash, new_hash);
    common::cleanup(&dir);
}

#[test]
fn unrelated_annotations_survive_fast_writes() {
    let dir = common::tmpdir("fast-unrelated");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "unrelated");
    let entry = common::builders::BASIC_ENTRY_VA;
    let string_va = common::builders::BASIC_STRING_VA;

    let mut p = bootstrap(&bin, &db);
    let before_summary = p.analysis().summary();
    p.rename_function(entry, "keep-a").expect("a");
    p.set_comment(string_va, "keep-b").expect("b");
    let data_va = common::builders::DATA_VA;
    p.set_comment(data_va, "third").expect("third");
    drop(p);

    let q = Project::open_with_db(&bin, &db).expect("reopen");
    assert_eq!(q.analysis().summary(), before_summary);
    assert_eq!(q.function_name(entry).as_deref(), Some("keep-a"));
    assert_eq!(
        q.annotation(string_va).and_then(|a| a.comment.as_deref()),
        Some("keep-b")
    );
    assert_eq!(
        q.annotation(data_va).and_then(|a| a.comment.as_deref()),
        Some("third")
    );
    assert_eq!(q.project_info().annotations, 3);

    let mut r = Project::open_with_db(&bin, &db).expect("reopen");
    r.set_comment(string_va, "keep-b2").expect("mutate b");
    drop(r);
    let s = Project::open_with_db(&bin, &db).expect("reopen");
    assert_eq!(s.function_name(entry).as_deref(), Some("keep-a"));
    assert_eq!(
        s.annotation(data_va).and_then(|a| a.comment.as_deref()),
        Some("third")
    );
    assert_eq!(
        s.annotation(string_va).and_then(|a| a.comment.as_deref()),
        Some("keep-b2")
    );
    assert_eq!(dumped_annotations(&bin, &db).len(), 3);
    common::cleanup(&dir);
}

#[test]
fn failed_rename_leaves_db_untouched() {
    let dir = common::tmpdir("fast-fail");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "fail");

    {
        let mut p = Project::open_with_db(&bin, &db).expect("open");
        let err = p.rename_function(0xdead, "nope").unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
        drop(p);
        assert!(!db.exists(), "failed rename must not create a sidecar");
    }

    let mut p = bootstrap(&bin, &db);
    let entry = common::builders::BASIC_ENTRY_VA;
    p.rename_function(entry, "real").expect("rename");
    let before = {
        let h = db::open_db(&db).expect("open");
        let l = db::load(&h).expect("load").expect("snapshot");
        (l.analysis.summary(), l.annotations.clone(), l.meta.clone())
    };
    let err = p.rename_function(0xdead_beef, "nope").unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    drop(p);
    let after = {
        let h = db::open_db(&db).expect("open");
        let l = db::load(&h).expect("load").expect("snapshot");
        (l.analysis.summary(), l.annotations.clone(), l.meta.clone())
    };
    assert_eq!(before, after);
    common::cleanup(&dir);
}

#[test]
fn analysis_tables_untouched_by_fast_path() {
    use redb::{ReadableDatabase, ReadableTable, TableDefinition};

    const META: TableDefinition<&str, String> = TableDefinition::new("meta");
    const BINARIES: TableDefinition<u64, String> = TableDefinition::new("binaries");
    const FUNCTIONS: TableDefinition<u64, String> = TableDefinition::new("functions");
    const BLOCKS: TableDefinition<String, String> = TableDefinition::new("blocks");
    const XREFS: TableDefinition<String, String> = TableDefinition::new("xrefs");
    const STRINGS: TableDefinition<u64, String> = TableDefinition::new("strings");
    const ANNOTATIONS: TableDefinition<u64, String> = TableDefinition::new("annotations");

    fn dump(path: &Path) -> BTreeMap<String, BTreeMap<String, String>> {
        let db = redb::Database::open(path).expect("open for dump");
        let rtxn = db.begin_read().expect("read txn");
        let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut meta_map = BTreeMap::new();
        for row in rtxn.open_table(META).expect("meta").iter().expect("iter") {
            let (k, v) = row.expect("row");
            meta_map.insert(k.value().to_string(), v.value());
        }
        out.insert("meta".to_string(), meta_map);
        let mut m = BTreeMap::new();
        for row in rtxn
            .open_table(BINARIES)
            .expect("bin")
            .iter()
            .expect("iter")
        {
            let (k, v) = row.expect("row");
            m.insert(k.value().to_string(), v.value());
        }
        out.insert("binaries".to_string(), m);
        let mut m = BTreeMap::new();
        for row in rtxn
            .open_table(FUNCTIONS)
            .expect("fn")
            .iter()
            .expect("iter")
        {
            let (k, v) = row.expect("row");
            m.insert(k.value().to_string(), v.value());
        }
        out.insert("functions".to_string(), m);
        let mut m = BTreeMap::new();
        for row in rtxn.open_table(BLOCKS).expect("bl").iter().expect("iter") {
            let (k, v) = row.expect("row");
            m.insert(k.value(), v.value());
        }
        out.insert("blocks".to_string(), m);
        let mut m = BTreeMap::new();
        for row in rtxn.open_table(XREFS).expect("xr").iter().expect("iter") {
            let (k, v) = row.expect("row");
            m.insert(k.value(), v.value());
        }
        out.insert("xrefs".to_string(), m);
        let mut m = BTreeMap::new();
        for row in rtxn.open_table(STRINGS).expect("st").iter().expect("iter") {
            let (k, v) = row.expect("row");
            m.insert(k.value().to_string(), v.value());
        }
        out.insert("strings".to_string(), m);
        let mut m = BTreeMap::new();
        for row in rtxn
            .open_table(ANNOTATIONS)
            .expect("an")
            .iter()
            .expect("iter")
        {
            let (k, v) = row.expect("row");
            m.insert(k.value().to_string(), v.value());
        }
        out.insert("annotations".to_string(), m);
        out
    }

    let dir = common::tmpdir("fast-untouched");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "untouched");
    let entry = common::builders::BASIC_ENTRY_VA;
    let string_va = common::builders::BASIC_STRING_VA;

    let mut p = bootstrap(&bin, &db);
    let before = dump(&db);

    p.rename_function(entry, "untouched").expect("rename");
    let after_rename = dump(&db);
    for t in [
        "meta",
        "binaries",
        "functions",
        "blocks",
        "xrefs",
        "strings",
    ] {
        assert_eq!(before[t], after_rename[t], "table {t} rewritten by rename");
    }
    assert_ne!(before["annotations"], after_rename["annotations"]);

    p.set_comment(string_va, "note").expect("comment");
    let after_comment = dump(&db);
    for t in [
        "meta",
        "binaries",
        "functions",
        "blocks",
        "xrefs",
        "strings",
    ] {
        assert_eq!(
            after_rename[t], after_comment[t],
            "table {t} rewritten by comment"
        );
    }

    p.set_comment(string_va, "").expect("clear");
    let after_clear = dump(&db);
    for t in [
        "meta",
        "binaries",
        "functions",
        "blocks",
        "xrefs",
        "strings",
    ] {
        assert_eq!(
            after_comment[t], after_clear[t],
            "table {t} rewritten by clear"
        );
    }
    assert_eq!(
        after_clear["annotations"],
        before["annotations"]
            .clone()
            .into_iter()
            .chain([(
                entry.to_string(),
                serde_json::to_string(&Annotation {
                    name: Some("untouched".to_string()),
                    comment: None,
                })
                .expect("encode"),
            )])
            .collect::<BTreeMap<_, _>>()
    );

    {
        let handle = db::open_db(&db).expect("open");
        let loaded = db::load(&handle).expect("load").expect("snapshot");
        let outcome =
            db::save_annotation(&handle, &loaded.meta, entry, loaded.annotations.get(&entry))
                .expect("probe fast");
        assert_eq!(outcome, AnnotationSave::Fast);
    }
    common::cleanup(&dir);
}

#[test]
fn concurrent_sidecar_change_falls_back_to_full() {
    let dir = common::tmpdir("fast-concurrent");
    let bin_a = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let tmp_b = common::write_fixture(&dir, common::builders::ORDINALS_NAME);
    let bin_b = dir.join("b.exe");
    std::fs::copy(&tmp_b, &bin_b).expect("copy");
    let _ = std::fs::remove_file(&tmp_b);
    let db = common::temp_db(&dir, "shared");

    let proj = Project::open_with_db(&bin_a, &db).expect("open a");
    proj.save().expect("bootstrap a");
    drop(proj);
    let mut proj_a = Project::open_with_db(&bin_a, &db).expect("reopen a");
    let entry_a = common::builders::BASIC_ENTRY_VA;

    {
        let proj_b = Project::open_with_db(&bin_b, &db).expect("open b");
        proj_b.save().expect("overwrite with b");
    }
    {
        let hash_b = db::content_hash(&std::fs::read(&bin_b).expect("read b"));
        let h = db::open_db(&db).expect("open");
        let loaded = db::load(&h).expect("load").expect("snapshot");
        assert_eq!(loaded.meta.content_hash, hash_b);
    }

    proj_a
        .rename_function(entry_a, "after-race")
        .expect("race rename");
    drop(proj_a);
    let reopened_a = Project::open_with_db(&bin_a, &db).expect("reopen a");
    assert_eq!(
        reopened_a.function_name(entry_a).as_deref(),
        Some("after-race")
    );
    let hash_a = db::content_hash(&std::fs::read(&bin_a).expect("read a"));
    assert_eq!(reopened_a.content_hash(), hash_a);
    {
        let h = db::open_db(&db).expect("open");
        let loaded = db::load(&h).expect("load").expect("snapshot");
        assert_eq!(loaded.meta.content_hash, hash_a);
    }
    assert_eq!(
        std::fs::read(&bin_a).expect("read a"),
        common::fixture_bytes(common::builders::BASIC_NAME)
    );
    common::cleanup(&dir);
}
