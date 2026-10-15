//! Raw-mapping cache identity: same bytes under different loader mappings
//! never share cached layouts, and populated sidecars under another mapping
//! require a separate DB.

mod common;

use std::path::Path;

use binscout::Project;
use binscout::db::{self, StoredMapping};
use binscout::disasm::Arch;
use binscout::loader::RawOptions;
use redb::ReadableTable;

const META: redb::TableDefinition<&str, String> = redb::TableDefinition::new("meta");
const BINARIES: redb::TableDefinition<u64, String> = redb::TableDefinition::new("binaries");

/// Three valid x86 bytes (`nop; nop; ret`) decoding in both x86 modes.
fn nop_ret() -> Vec<u8> {
    vec![0x90, 0x90, 0xC3]
}

fn opts(arch: Arch, base: u64, entry: Option<u64>) -> RawOptions {
    RawOptions { base, arch, entry }
}

fn mapping_of(o: RawOptions) -> StoredMapping {
    StoredMapping::for_request(Some(o))
}

fn write_raw(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    common::write_bin(dir, name, bytes)
}

/// Open `bin` with `o`, save a full snapshot, and return the content hash.
fn bootstrap_raw(bin: &Path, db: &Path, o: RawOptions) -> u64 {
    let p = Project::open_raw(bin, db, o).expect("raw open");
    p.save().expect("bootstrap save");
    p.content_hash()
}

fn cached_with(db: &Path, hash: u64, m: &StoredMapping) -> db::Snapshot {
    let handle = db::open_db(db).expect("open db");
    db::load_cached(&handle, hash, m).expect("load_cached")
}

fn assert_stale(snap: db::Snapshot) {
    assert!(
        matches!(snap, db::Snapshot::Stale { .. }),
        "expected Stale, got {snap:?}"
    );
}

#[test]
fn same_explicit_mapping_hits() {
    let dir = common::tmpdir("raw-same-hit");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");
    let o = opts(Arch::X86_64, 0x1000, None);

    let hash = bootstrap_raw(&bin, &db, o);
    match cached_with(&db, hash, &mapping_of(o)) {
        db::Snapshot::Hit(hit) => {
            assert_eq!(hit.meta.content_hash, hash);
            assert_eq!(hit.meta.mapping, Some(mapping_of(o)));
        }
        other => panic!("expected Hit, got {other:?}"),
    }
    let q = Project::open_raw(&bin, &db, o).expect("reopen hits");
    assert!(q.analysis().functions.contains_key(&0x1000));
    common::cleanup(&dir);
}

#[test]
fn arch_change_is_stale_not_hit() {
    let dir = common::tmpdir("raw-arch");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");
    let a = opts(Arch::X86_64, 0x1000, None);
    let b = opts(Arch::X86_32, 0x1000, None);

    let hash = bootstrap_raw(&bin, &db, a);
    assert_stale(cached_with(&db, hash, &mapping_of(b)));

    // Same bytes, no annotations: the other arch rebuilds instead of
    // reusing layouts, and records its own arch.
    let q = Project::open_raw(&bin, &db, b).expect("other arch rebuilds");
    assert_eq!(q.binary().arch, Arch::X86_32);
    assert!(q.analysis().functions.contains_key(&0x1000));
    common::cleanup(&dir);
}

#[test]
fn base_change_is_stale_not_hit() {
    let dir = common::tmpdir("raw-base");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");
    let a = opts(Arch::X86_64, 0x1000, None);
    let b = opts(Arch::X86_64, 0x2000, None);

    let hash = bootstrap_raw(&bin, &db, a);
    assert_stale(cached_with(&db, hash, &mapping_of(b)));

    let q = Project::open_raw(&bin, &db, b).expect("other base rebuilds");
    assert!(q.analysis().functions.contains_key(&0x2000));
    assert!(!q.analysis().functions.contains_key(&0x1000));
    common::cleanup(&dir);
}

#[test]
fn entry_change_is_stale_not_hit() {
    let dir = common::tmpdir("raw-entry");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");
    let a = opts(Arch::X86_64, 0x5000, None);
    let b = opts(Arch::X86_64, 0x5000, Some(0x5000));

    let hash = bootstrap_raw(&bin, &db, a);
    assert_stale(cached_with(&db, hash, &mapping_of(b)));
    common::cleanup(&dir);
}

#[test]
fn auto_and_explicit_never_alias() {
    let dir = common::tmpdir("raw-mode");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");

    // Auto open falls back to raw x86-64 at base 0 for these bytes.
    let auto = Project::open_with_db(&bin, &db).expect("auto open");
    assert_eq!(auto.binary().arch, Arch::X86_64);
    auto.save().expect("save auto snapshot");
    let hash = auto.content_hash();
    drop(auto);

    // The identical effective mapping requested explicitly still misses:
    // mode is part of the identity.
    let explicit = opts(Arch::X86_64, 0, None);
    assert_stale(cached_with(&db, hash, &mapping_of(explicit)));

    // And the reverse: an explicit snapshot never serves an auto open.
    let db2 = common::temp_db(&dir, "r2");
    bootstrap_raw(&bin, &db2, explicit);
    let handle = db::open_db(&db2).expect("open db");
    assert!(
        matches!(
            db::load_cached(&handle, hash, &StoredMapping::Auto).expect("load_cached"),
            db::Snapshot::Stale { .. }
        ),
        "auto open must not hit an explicit snapshot"
    );
    common::cleanup(&dir);
}

#[test]
fn same_mapping_stale_content_carries_annotations() {
    let dir = common::tmpdir("raw-stale-same");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");
    let o = opts(Arch::X86_64, 0x1000, None);

    let mut p = Project::open_raw(&bin, &db, o).expect("open");
    p.rename_function(0x1000, "entry").expect("rename");
    p.set_comment(0x1001, "second nop").expect("comment");
    let old_hash = p.content_hash();
    drop(p);

    let mut patched_bytes = bytes.clone();
    patched_bytes[2] = 0x90;
    std::fs::write(&bin, &patched_bytes).expect("patch fixture");
    let new_hash = db::content_hash(&patched_bytes);
    assert_ne!(old_hash, new_hash);

    let q = Project::open_raw(&bin, &db, o).expect("stale same-mapping open");
    assert_eq!(q.function_name(0x1000).as_deref(), Some("entry"));
    assert_eq!(
        q.annotation(0x1001).and_then(|a| a.comment.as_deref()),
        Some("second nop")
    );
    // No read-side save: the sidecar still holds the old snapshot.
    let handle = db::open_db(&db).expect("open db");
    let stored = db::load(&handle)
        .expect("load")
        .expect("old snapshot intact");
    assert_eq!(stored.meta.content_hash, old_hash);
    assert_eq!(stored.meta.mapping, Some(mapping_of(o)));
    common::cleanup(&dir);
}

#[test]
fn mapping_conflict_with_annotations_errors_without_writes() {
    let dir = common::tmpdir("raw-conflict");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");
    let a = opts(Arch::X86_64, 0x1000, None);
    let b = opts(Arch::X86_32, 0x1000, None);

    let mut p = Project::open_raw(&bin, &db, a).expect("open a");
    p.rename_function(0x1000, "entry-a").expect("rename");
    drop(p);
    let before = std::fs::read(&db).expect("sidecar bytes");

    let err = Project::open_raw(&bin, &db, b).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("separate --db"),
        "conflict must name a separate DB: {msg:?}"
    );
    assert!(
        msg.contains("annotation"),
        "conflict must mention annotations: {msg:?}"
    );
    assert_eq!(
        std::fs::read(&db).expect("reread sidecar"),
        before,
        "failed open must not write the sidecar"
    );
    // The stored snapshot is untouched: old mapping plus annotations.
    {
        let handle = db::open_db(&db).expect("open db");
        let stored = db::load(&handle)
            .expect("load")
            .expect("old snapshot intact");
        assert_eq!(stored.meta.mapping, Some(mapping_of(a)));
        assert_eq!(
            stored
                .annotations
                .get(&0x1000)
                .and_then(|x| x.name.as_deref()),
            Some("entry-a")
        );
    }

    // Writes under the conflicting mapping fail the same way.
    let q = Project::open_raw(&bin, &common::temp_db(&dir, "other"), b)
        .expect("conflicting mapping opens against a fresh DB");
    // Point it at the populated sidecar by saving: the overwrite guard fires.
    let hog = db::open_db(&db).expect("open db");
    let meta = db::BinaryMeta {
        version: db::SCHEMA_VERSION,
        binary_path: bin.display().to_string(),
        content_hash: q.content_hash(),
        size: bytes.len() as u64,
        arch: db::arch_name(q.binary().arch).to_string(),
        format: db::format_name(q.binary().format).to_string(),
        entry: q.binary().entry,
        supported: true,
        reason: None,
        mapping: Some(q.mapping().clone()),
        analysis_rev: Some(db::ANALYSIS_REVISION),
    };
    let err = db::save(&hog, &meta, q.analysis(), q.annotations()).unwrap_err();
    assert!(
        err.to_string().contains("separate --db"),
        "save must refuse cross-mapping overwrite: {err:?}"
    );
    common::cleanup(&dir);
}

#[test]
fn mapping_conflict_without_annotations_rebuilds() {
    let dir = common::tmpdir("raw-conflict-empty");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");
    let a = opts(Arch::X86_64, 0x1000, None);
    let b = opts(Arch::X86_64, 0x2000, None);

    bootstrap_raw(&bin, &db, a);
    let q = Project::open_raw(&bin, &db, b).expect("empty sidecar rebuilds");
    assert!(q.annotations().is_empty());
    assert!(q.analysis().functions.contains_key(&0x2000));
    common::cleanup(&dir);
}

/// Rewrite the sidecar as a pre-mapping (v2) snapshot: version 2 with no
/// mapping or revision fields.
fn downgrade_to_legacy_v2(db_path: &Path) {
    let db = db::open_db(db_path).expect("open db");
    let wtxn = db.begin_write().expect("begin write");
    {
        let mut meta = wtxn.open_table(META).expect("open meta");
        meta.insert("version", "2".to_string())
            .expect("downgrade meta");
    }
    {
        let mut t = wtxn.open_table(BINARIES).expect("open binaries");
        let raw: String = t.get(0u64).expect("read").expect("row 0").value();
        let mut v: serde_json::Value = serde_json::from_str(&raw).expect("meta json");
        v.as_object_mut().expect("meta object").remove("mapping");
        v.as_object_mut()
            .expect("meta object")
            .remove("analysis_rev");
        v["version"] = 2.into();
        t.insert(0u64, v.to_string()).expect("rewrite meta");
    }
    wtxn.commit().expect("commit");
}

#[test]
fn legacy_empty_rebuilds_not_trusted() {
    let dir = common::tmpdir("raw-legacy-empty");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");
    let o = opts(Arch::X86_64, 0x1000, None);

    bootstrap_raw(&bin, &db, o);
    downgrade_to_legacy_v2(&db);

    // Same bytes, same mapping, empty annotations: rebuilt, never a hit.
    let hash = db::content_hash(&bytes);
    assert_stale(cached_with(&db, hash, &mapping_of(o)));
    let q = Project::open_raw(&bin, &db, o).expect("legacy rebuilds");
    assert!(q.analysis().functions.contains_key(&0x1000));
    common::cleanup(&dir);
}

#[test]
fn legacy_annotated_requires_separate_db() {
    let dir = common::tmpdir("raw-legacy-ann");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");
    let o = opts(Arch::X86_64, 0x1000, None);

    let mut p = Project::open_raw(&bin, &db, o).expect("open");
    p.rename_function(0x1000, "legacy-name").expect("rename");
    drop(p);
    downgrade_to_legacy_v2(&db);
    let before = std::fs::read(&db).expect("sidecar bytes");

    // The mapping can no longer be established, so populated legacy
    // annotations are never trusted under any mapping.
    let hash = db::content_hash(&bytes);
    {
        let handle = db::open_db_read_only(&db).expect("open db");
        let err = db::load_cached(&handle, hash, &mapping_of(o)).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("separate --db") && msg.contains("legacy"),
            "legacy load_cached must require a separate DB, got: {msg:?}"
        );
    }
    let err = Project::open_raw(&bin, &db, o).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("separate --db") && msg.contains("legacy"),
        "legacy annotations must require a separate DB, got: {msg:?}"
    );
    assert_eq!(
        std::fs::read(&db).expect("reread"),
        before,
        "failed legacy open must not write"
    );
    common::cleanup(&dir);
}

#[test]
fn analysis_rev_mismatch_reanalyzes_same_mapping() {
    let dir = common::tmpdir("raw-rev");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");
    let o = opts(Arch::X86_64, 0x1000, None);

    let mut p = Project::open_raw(&bin, &db, o).expect("open");
    p.rename_function(0x1000, "entry").expect("rename");
    drop(p);
    let hash = db::content_hash(&bytes);

    {
        let dbh = db::open_db(&db).expect("open db");
        let wtxn = dbh.begin_write().expect("begin write");
        {
            let mut t = wtxn.open_table(BINARIES).expect("open binaries");
            let raw: String = t.get(0u64).expect("read").expect("row 0").value();
            let mut v: serde_json::Value = serde_json::from_str(&raw).expect("meta json");
            v["analysis_rev"] = 999.into();
            t.insert(0u64, v.to_string()).expect("rewrite rev");
        }
        wtxn.commit().expect("commit");
    }

    // Same mapping and bytes, stale revision: re-analyze, annotations survive.
    assert_stale(cached_with(&db, hash, &mapping_of(o)));
    let q = Project::open_raw(&bin, &db, o).expect("rev-mismatched open");
    assert_eq!(q.function_name(0x1000).as_deref(), Some("entry"));
    assert!(q.analysis().functions.contains_key(&0x1000));
    common::cleanup(&dir);
}

#[test]
fn reads_never_create_sidecars() {
    let dir = common::tmpdir("raw-no-save");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "fresh");
    let o = opts(Arch::X86_64, 0x1000, None);

    let p = Project::open_raw(&bin, &db, o).expect("fresh raw open");
    assert!(p.analysis().functions.contains_key(&0x1000));
    assert!(!db.exists(), "reads never create the sidecar");

    // A stale same-mapping open also leaves the sidecar alone.
    p.save().expect("save once");
    let mut patched_bytes = bytes.clone();
    patched_bytes[2] = 0x90;
    std::fs::write(&bin, &patched_bytes).expect("patch");
    let q = Project::open_raw(&bin, &db, o).expect("stale open");
    assert_eq!(q.content_hash(), db::content_hash(&patched_bytes));
    let handle = db::open_db(&db).expect("open db");
    let stored = db::load(&handle)
        .expect("load")
        .expect("old snapshot intact");
    assert_eq!(stored.meta.content_hash, db::content_hash(&bytes));
    common::cleanup(&dir);
}
