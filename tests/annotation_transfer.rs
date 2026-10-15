//! Annotation interchange tests: versioned export plus atomic import.
//!
//! Covers the §11 acceptance checks: export/import/reopen round-trips,
//! read-only export, identity/mapping mismatch, duplicates, oversized
//! documents and fields, unknown renames, final-row atomicity, idempotence,
//! default conflicts, overwrite/clear semantics, and unmapped comments.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use binscout::Project;
use binscout::annotations::MAX_TRANSFER_BYTES;
use binscout::db::{self, Annotation};
use binscout::disasm::Arch;
use binscout::error::Error;
use binscout::loader::RawOptions;

fn basic_pair(dir: &Path, db_name: &str) -> (PathBuf, PathBuf) {
    let bin = common::write_fixture(dir, common::builders::BASIC_NAME);
    let db = common::temp_db(dir, db_name);
    (bin, db)
}

fn entry_va() -> u64 {
    common::builders::BASIC_ENTRY_VA
}

fn string_va() -> u64 {
    common::builders::BASIC_STRING_VA
}

/// In-memory annotations plus sidecar bytes (`None` = no sidecar yet).
fn state_of(p: &Project, db: &Path) -> (BTreeMap<u64, Annotation>, Option<Vec<u8>>) {
    (p.annotations().clone(), std::fs::read(db).ok())
}

fn bootstrap_annotated(bin: &Path, db: &Path) -> Project {
    let mut p = Project::open_with_db(bin, db).expect("open");
    p.rename_function(entry_va(), "annotated_entry")
        .expect("rename");
    p.set_comment(string_va(), "string note").expect("comment");
    p
}

fn doc_value(doc: &str) -> serde_json::Value {
    serde_json::from_str(doc).expect("export is JSON")
}

#[test]
fn round_trip_export_import_reopen() {
    let dir = common::tmpdir("xfer-roundtrip");
    let (bin, db) = basic_pair(&dir, "a");
    let unmapped = 0xdead_beefu64;

    let p = {
        let mut p = bootstrap_annotated(&bin, &db);
        p.set_comment(unmapped, "far away").expect("comment");
        p
    };
    let doc = p.export_annotations().expect("export");
    assert!(doc.len() < MAX_TRANSFER_BYTES);
    let v = doc_value(&doc);
    assert_eq!(v["revision"], 1);
    assert_eq!(v["sha256"], p.content_sha256());
    assert_eq!(v["size"], p.size());
    assert_eq!(v["mapping"]["mode"], "auto");
    let rows = v["annotations"].as_array().expect("rows");
    assert_eq!(rows.len(), 3);
    let addrs: Vec<u64> = rows
        .iter()
        .map(|r| r["addr"].as_u64().expect("addr"))
        .collect();
    assert!(addrs.windows(2).all(|w| w[0] < w[1]), "rows sorted");
    assert!(addrs.contains(&unmapped));
    assert!(
        !doc.contains(&dir.display().to_string()),
        "no host paths in document"
    );

    let db2 = common::temp_db(&dir, "b");
    let mut q = Project::open_with_db(&bin, &db2).expect("open fresh");
    assert!(!db2.exists());
    let summary = q.import_annotations(&doc, false).expect("import");
    assert_eq!(summary.rows, 3);
    assert_eq!(summary.changed, 3);
    assert_eq!(q.annotations(), p.annotations());
    q.save().expect("save imported");
    drop(q);
    drop(p);

    let r = Project::open_with_db(&bin, &db2).expect("reopen");
    assert_eq!(
        r.function_name(entry_va()).as_deref(),
        Some("annotated_entry")
    );
    assert_eq!(
        r.annotation(string_va()).and_then(|a| a.comment.as_deref()),
        Some("string note")
    );
    assert_eq!(
        r.annotation(unmapped).and_then(|a| a.comment.as_deref()),
        Some("far away")
    );
    assert_eq!(
        std::fs::read(&bin).expect("reread"),
        common::fixture_bytes(common::builders::BASIC_NAME),
        "binary untouched"
    );
    common::cleanup(&dir);
}

#[test]
fn export_is_read_only() {
    let dir = common::tmpdir("xfer-readonly");
    let (bin, db) = basic_pair(&dir, "a");

    let p = Project::open_with_db(&bin, &db).expect("open");
    let _ = p.export_annotations().expect("export");
    assert!(!db.exists(), "export must not create a sidecar");
    drop(p);

    let p = bootstrap_annotated(&bin, &db);
    let before = std::fs::read(&db).expect("sidecar");
    let _ = p.export_annotations().expect("export");
    assert_eq!(std::fs::read(&db).expect("sidecar"), before);
    common::cleanup(&dir);
}

#[test]
fn empty_export_import_is_noop() {
    let dir = common::tmpdir("xfer-empty");
    let (bin, db) = basic_pair(&dir, "a");
    let p = Project::open_with_db(&bin, &db).expect("open");
    let doc = p.export_annotations().expect("export");
    assert_eq!(
        doc_value(&doc)["annotations"]
            .as_array()
            .expect("rows")
            .len(),
        0
    );
    drop(p);

    let db2 = common::temp_db(&dir, "b");
    let mut q = Project::open_with_db(&bin, &db2).expect("open fresh");
    let summary = q.import_annotations(&doc, false).expect("import");
    assert_eq!((summary.rows, summary.changed), (0, 0));
    assert!(!db2.exists(), "no-op import writes nothing");
    common::cleanup(&dir);
}

#[test]
fn identity_mismatch_leaves_everything() {
    let dir = common::tmpdir("xfer-identity");
    let (bin, db) = basic_pair(&dir, "a");
    let mut p = bootstrap_annotated(&bin, &db);
    let doc = p.export_annotations().expect("export");
    let before = state_of(&p, &db);

    let mut bad_sha = doc_value(&doc);
    bad_sha["sha256"] = "00".repeat(32).into();
    let err = p
        .import_annotations(&bad_sha.to_string(), false)
        .unwrap_err();
    assert!(matches!(err, Error::Storage(_)), "got {err:?}");

    let mut bad_size = doc_value(&doc);
    bad_size["size"] = (p.size() + 1).into();
    let err = p
        .import_annotations(&bad_size.to_string(), false)
        .unwrap_err();
    assert!(matches!(err, Error::Storage(_)), "got {err:?}");

    let mut malformed = doc_value(&doc);
    malformed["sha256"] = "not-a-digest".into();
    let err = p
        .import_annotations(&malformed.to_string(), false)
        .unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");

    assert_eq!(state_of(&p, &db), before);
    common::cleanup(&dir);
}

#[test]
fn mapping_mismatch_rejected_without_sidecar() {
    let dir = common::tmpdir("xfer-mapping");
    let (bin, db) = basic_pair(&dir, "a");
    let p = bootstrap_annotated(&bin, &db);
    let doc = p.export_annotations().expect("export");
    drop(p);

    let db_raw = common::temp_db(&dir, "raw");
    let mut q = Project::open_raw(
        &bin,
        &db_raw,
        RawOptions {
            base: 0,
            arch: Arch::X86_64,
            entry: None,
        },
    )
    .expect("raw open");
    assert!(q.annotations().is_empty());
    let err = q.import_annotations(&doc, false).unwrap_err();
    assert!(
        err.to_string().contains("mapping mismatch"),
        "unexpected: {err:?}"
    );
    assert!(q.annotations().is_empty());
    assert!(!db_raw.exists(), "failed import writes nothing");
    common::cleanup(&dir);
}

#[test]
fn duplicate_addresses_rejected() {
    let dir = common::tmpdir("xfer-dups");
    let (bin, db) = basic_pair(&dir, "a");
    let mut p = bootstrap_annotated(&bin, &db);
    let before = state_of(&p, &db);

    let mut v = doc_value(&p.export_annotations().expect("export"));
    let first = v["annotations"].as_array().expect("rows")[0].clone();
    v["annotations"].as_array_mut().expect("rows").push(first);
    let err = p.import_annotations(&v.to_string(), false).unwrap_err();
    assert!(err.to_string().contains("duplicate"), "unexpected: {err:?}");
    assert_eq!(state_of(&p, &db), before);
    common::cleanup(&dir);
}

#[test]
fn unsupported_revision_rejected() {
    let dir = common::tmpdir("xfer-rev");
    let (bin, db) = basic_pair(&dir, "a");
    let mut p = bootstrap_annotated(&bin, &db);
    let before = state_of(&p, &db);

    let mut v = doc_value(&p.export_annotations().expect("export"));
    v["revision"] = 999.into();
    let err = p.import_annotations(&v.to_string(), false).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
    assert_eq!(state_of(&p, &db), before);
    common::cleanup(&dir);
}

#[test]
fn oversized_or_garbled_input_rejected() {
    let dir = common::tmpdir("xfer-big-in");
    let (bin, db) = basic_pair(&dir, "a");
    let mut p = bootstrap_annotated(&bin, &db);
    let before = state_of(&p, &db);

    let huge = "x".repeat(MAX_TRANSFER_BYTES + 1);
    let err = p.import_annotations(&huge, false).unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
    let err = p.import_annotations("{not json", false).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
    assert_eq!(state_of(&p, &db), before);
    drop(p);

    let db2 = common::temp_db(&dir, "b");
    let mut q = Project::open_with_db(&bin, &db2).expect("open fresh");
    let err = q.import_annotations(&huge, false).unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
    assert!(!db2.exists(), "rejected input writes nothing");
    common::cleanup(&dir);
}

#[test]
fn oversized_fields_rejected() {
    let dir = common::tmpdir("xfer-big-field");
    let (bin, db) = basic_pair(&dir, "a");
    let mut p = bootstrap_annotated(&bin, &db);
    let before = state_of(&p, &db);
    let big = "y".repeat(db::MAX_ANNOTATION_BYTES + 1);

    let mut v = doc_value(&p.export_annotations().expect("export"));
    v["annotations"]
        .as_array_mut()
        .expect("rows")
        .push(serde_json::json!({"addr": 0x1234u64, "comment": big}));
    let err = p.import_annotations(&v.to_string(), false).unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");

    let mut v = doc_value(&p.export_annotations().expect("export"));
    for row in v["annotations"].as_array_mut().expect("rows") {
        if row["addr"].as_u64() == Some(entry_va()) {
            row["rename"] = big.clone().into();
        }
    }
    let err = p.import_annotations(&v.to_string(), false).unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");

    assert_eq!(state_of(&p, &db), before);
    common::cleanup(&dir);
}

#[test]
fn unknown_rename_rejected() {
    let dir = common::tmpdir("xfer-unknown");
    let (bin, db) = basic_pair(&dir, "a");
    let mut p = bootstrap_annotated(&bin, &db);
    let before = state_of(&p, &db);

    let mut v = doc_value(&p.export_annotations().expect("export"));
    v["annotations"]
        .as_array_mut()
        .expect("rows")
        .push(serde_json::json!({"addr": 0xdead_beefu64, "rename": "ghost"}));
    let err = p.import_annotations(&v.to_string(), false).unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    assert_eq!(state_of(&p, &db), before);
    drop(p);

    // Same failure on a fresh project creates no sidecar.
    let db2 = common::temp_db(&dir, "b");
    let mut q = Project::open_with_db(&bin, &db2).expect("open fresh");
    let err = q.import_annotations(&v.to_string(), false).unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    assert!(!db2.exists());
    common::cleanup(&dir);
}

#[test]
fn final_row_failure_leaves_db_and_memory_unchanged() {
    let dir = common::tmpdir("xfer-final-row");
    let (bin, db) = basic_pair(&dir, "a");
    let mut p = bootstrap_annotated(&bin, &db);
    let before = state_of(&p, &db);

    // Two valid new comments plus a failing last row: nothing may stick.
    let mut v = doc_value(&p.export_annotations().expect("export"));
    let rows = v["annotations"].as_array_mut().expect("rows");
    rows.push(serde_json::json!({"addr": 0x1111u64, "comment": "first"}));
    rows.push(serde_json::json!({"addr": 0x2222u64, "comment": "second"}));
    rows.push(serde_json::json!({"addr": 0xdead_beefu64, "rename": "ghost"}));
    for overwrite in [false, true] {
        let err = p.import_annotations(&v.to_string(), overwrite).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
        assert_eq!(state_of(&p, &db), before, "overwrite={overwrite}");
    }
    drop(p);
    let q = Project::open_with_db(&bin, &db).expect("reopen");
    assert_eq!(q.annotations(), &before.0);
    common::cleanup(&dir);
}

#[test]
fn reimport_is_idempotent_and_write_free() {
    let dir = common::tmpdir("xfer-idem");
    let (bin, db) = basic_pair(&dir, "a");
    let p = bootstrap_annotated(&bin, &db);
    let doc = p.export_annotations().expect("export");
    drop(p);

    let db2 = common::temp_db(&dir, "b");
    let mut q = Project::open_with_db(&bin, &db2).expect("open fresh");
    let first = q.import_annotations(&doc, false).expect("import");
    assert_eq!((first.rows, first.changed), (2, 2));
    let sidecar = std::fs::read(&db2).ok();
    let second = q.import_annotations(&doc, false).expect("reimport");
    assert_eq!((second.rows, second.changed), (2, 0));
    assert_eq!(std::fs::read(&db2).ok(), sidecar);
    drop(q);
    let r = Project::open_with_db(&bin, &db2).expect("reopen");
    assert_eq!(
        r.function_name(entry_va()).as_deref(),
        Some("annotated_entry")
    );
    common::cleanup(&dir);
}

#[test]
fn default_conflict_fails_overwrite_applies() {
    let dir = common::tmpdir("xfer-conflict");
    let (bin, db) = basic_pair(&dir, "a");
    let mut p = bootstrap_annotated(&bin, &db);
    let before = state_of(&p, &db);

    // Differing rename under default: conflict, nothing changes.
    let mut v = doc_value(&p.export_annotations().expect("export"));
    for row in v["annotations"].as_array_mut().expect("rows") {
        if row["addr"].as_u64() == Some(entry_va()) {
            row["rename"] = "other_name".into();
        }
    }
    let conflict = v.to_string();
    let err = p.import_annotations(&conflict, false).unwrap_err();
    assert!(err.to_string().contains("conflict"), "unexpected: {err:?}");
    assert_eq!(state_of(&p, &db), before);

    // Same document with overwrite: supplied rename wins, comment kept.
    let summary = p.import_annotations(&conflict, true).expect("overwrite");
    assert_eq!((summary.rows, summary.changed), (2, 1));
    assert_eq!(p.function_name(entry_va()).as_deref(), Some("other_name"));
    assert_eq!(
        p.annotation(entry_va()).and_then(|a| a.comment.as_deref()),
        None
    );
    assert_eq!(
        p.annotation(string_va()).and_then(|a| a.comment.as_deref()),
        Some("string note"),
        "untouched rows remain"
    );

    // Equal values stay idempotent under default.
    let doc = p.export_annotations().expect("export");
    let summary = p.import_annotations(&doc, false).expect("reimport");
    assert_eq!(summary.changed, 0);
    common::cleanup(&dir);
}

#[test]
fn overwrite_replaces_supplied_fields_only() {
    let dir = common::tmpdir("xfer-partial");
    let (bin, db) = basic_pair(&dir, "a");
    let mut p = Project::open_with_db(&bin, &db).expect("open");
    p.rename_function(entry_va(), "keep_me").expect("rename");
    p.set_comment(entry_va(), "keep comment").expect("comment");
    drop(p);

    // Default fill: a comment where none exists fills freely.
    let mut p = Project::open_with_db(&bin, &db).expect("reopen");
    let doc = p.export_annotations().expect("export");
    let mut v = doc_value(&doc);
    let rows = v["annotations"].as_array_mut().expect("rows");
    rows.push(serde_json::json!({"addr": string_va(), "comment": "fresh note"}));
    let summary = p.import_annotations(&v.to_string(), false).expect("fill");
    assert_eq!(summary.changed, 1);
    assert_eq!(p.function_name(entry_va()).as_deref(), Some("keep_me"));
    assert_eq!(
        p.annotation(string_va()).and_then(|a| a.comment.as_deref()),
        Some("fresh note")
    );

    // But a differing supplied comment under default conflicts.
    let mut v = doc_value(&p.export_annotations().expect("export"));
    let rows = v["annotations"].as_array_mut().expect("rows");
    rows.retain(|r| r["addr"].as_u64() != Some(entry_va()));
    rows.push(serde_json::json!({"addr": entry_va(), "comment": "other"}));
    let err = p.import_annotations(&v.to_string(), false).unwrap_err();
    assert!(err.to_string().contains("conflict"), "unexpected: {err:?}");

    // Overwrite with only rename supplied: existing comment survives.
    let mut v = doc_value(&p.export_annotations().expect("export"));
    let rows = v["annotations"].as_array_mut().expect("rows");
    rows.retain(|r| r["addr"].as_u64() != Some(entry_va()));
    rows.push(serde_json::json!({"addr": entry_va(), "rename": "changed"}));
    p.import_annotations(&v.to_string(), true)
        .expect("overwrite");
    assert_eq!(p.function_name(entry_va()).as_deref(), Some("changed"));
    assert!(
        p.annotation(entry_va())
            .and_then(|a| a.comment.as_deref())
            .is_some(),
        "omitted comment field stays"
    );
    common::cleanup(&dir);
}

#[test]
fn empty_string_clears_supplied_field() {
    let dir = common::tmpdir("xfer-clear");
    let (bin, db) = basic_pair(&dir, "a");
    let mut p = Project::open_with_db(&bin, &db).expect("open");
    p.rename_function(entry_va(), "to_clear").expect("rename");
    p.set_comment(entry_va(), "clear me").expect("comment");

    // Clear only the comment: rename survives, row stays alive.
    let mut v = doc_value(&p.export_annotations().expect("export"));
    let rows = v["annotations"].as_array_mut().expect("rows");
    rows.retain(|r| r["addr"].as_u64() != Some(entry_va()));
    rows.push(serde_json::json!({"addr": entry_va(), "comment": ""}));
    p.import_annotations(&v.to_string(), true).expect("clear");
    assert_eq!(p.function_name(entry_va()).as_deref(), Some("to_clear"));
    assert!(p.annotation(entry_va()).is_some());
    assert!(
        p.annotation(entry_va())
            .and_then(|a| a.comment.as_deref())
            .is_none()
    );

    // Clear the rename too: the row vanishes.
    let mut v = doc_value(&p.export_annotations().expect("export"));
    let rows = v["annotations"].as_array_mut().expect("rows");
    rows.retain(|r| r["addr"].as_u64() != Some(entry_va()));
    rows.push(serde_json::json!({"addr": entry_va(), "rename": ""}));
    p.import_annotations(&v.to_string(), true).expect("clear");
    assert!(p.annotation(entry_va()).is_none());

    // Clearing an absent field is a successful no-op.
    let summary = p.import_annotations(&v.to_string(), true).expect("noop");
    assert_eq!(summary.changed, 0);
    drop(p);
    let q = Project::open_with_db(&bin, &db).expect("reopen");
    assert!(q.annotation(entry_va()).is_none());
    common::cleanup(&dir);
}

#[test]
fn row_cap_enforced_before_any_write() {
    let dir = common::tmpdir("xfer-rowcap");
    let (bin, db) = basic_pair(&dir, "a");
    let mut p = bootstrap_annotated(&bin, &db);
    let before = state_of(&p, &db);

    let mut v = doc_value(&p.export_annotations().expect("export"));
    let rows = v["annotations"].as_array_mut().expect("rows");
    for i in 0..(db::MAX_SNAPSHOT_ANNOTATIONS + 1) {
        rows.push(serde_json::json!({"addr": 0x10000u64 + i as u64, "comment": "c"}));
    }
    let err = p.import_annotations(&v.to_string(), true).unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
    assert_eq!(state_of(&p, &db), before);
    common::cleanup(&dir);
}

#[test]
fn oversized_export_fails_explicitly() {
    let dir = common::tmpdir("xfer-big-out");
    let (bin, db) = basic_pair(&dir, "a");
    let p = Project::open_with_db(&bin, &db).expect("open");
    // Bulk-load annotations past the 16 MiB interchange cap in one snapshot
    // write: per-row setters cost hundreds of seconds here in debug builds.
    let filler = "x".repeat(db::MAX_ANNOTATION_BYTES);
    let mut annotations = BTreeMap::new();
    for i in 0..2150u64 {
        annotations.insert(
            0x10000 + i,
            Annotation {
                name: None,
                comment: Some(filler.clone()),
            },
        );
    }
    let info = p.project_info();
    let meta = db::BinaryMeta {
        version: db::SCHEMA_VERSION,
        binary_path: p.path().display().to_string(),
        content_hash: p.content_hash(),
        size: info.size,
        arch: info.arch.clone(),
        format: info.format.clone(),
        entry: info.entry,
        supported: true,
        reason: None,
        mapping: Some(p.mapping().clone()),
        analysis_rev: Some(db::ANALYSIS_REVISION),
        diagnostics_truncated: p.analysis().diagnostics.truncated,
        diagnostics_omitted: p.analysis().diagnostics.omitted,
        inferred_truncated: p.analysis().diagnostics.inferred_truncated,
        inferred_omitted: p.analysis().diagnostics.inferred_omitted,
    };
    let handle = db::open_db(&db).expect("create db");
    db::save(&handle, &meta, p.analysis(), &annotations).expect("bulk save");
    drop(handle);
    drop(p);

    let q = Project::open_with_db(&bin, &db).expect("reopen");
    assert_eq!(q.project_info().annotations, 2150);
    let err = q.export_annotations().unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
    assert!(err.to_string().contains("import cap"), "got {err:?}");
    common::cleanup(&dir);
}
