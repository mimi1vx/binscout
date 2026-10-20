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

/// Open `bin` with `o`, save a full snapshot, and return the content identity.
fn bootstrap_raw(bin: &Path, db: &Path, o: RawOptions) -> (u64, String, u64) {
    let p = Project::open_raw(bin, db, o).expect("raw open");
    p.save().expect("bootstrap save");
    (p.content_hash(), p.content_sha256().to_string(), p.size())
}

fn cached_with(db: &Path, hash: u64, sha256: &str, size: u64, m: &StoredMapping) -> db::Snapshot {
    let handle = db::open_db(db).expect("open db");
    db::load_cached(&handle, hash, sha256, size, m, &db::DebugId::default()).expect("load_cached")
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

    let (hash, sha256, size) = bootstrap_raw(&bin, &db, o);
    match cached_with(&db, hash, &sha256, size, &mapping_of(o)) {
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

    let (hash, sha256, size) = bootstrap_raw(&bin, &db, a);
    assert_stale(cached_with(&db, hash, &sha256, size, &mapping_of(b)));

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

    let (hash, sha256, size) = bootstrap_raw(&bin, &db, a);
    assert_stale(cached_with(&db, hash, &sha256, size, &mapping_of(b)));

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

    let (hash, sha256, size) = bootstrap_raw(&bin, &db, a);
    assert_stale(cached_with(&db, hash, &sha256, size, &mapping_of(b)));
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
    let sha256 = auto.content_sha256().to_string();
    let size = auto.size();
    drop(auto);

    // The identical effective mapping requested explicitly still misses:
    // mode is part of the identity.
    let explicit = opts(Arch::X86_64, 0, None);
    assert_stale(cached_with(&db, hash, &sha256, size, &mapping_of(explicit)));

    // And the reverse: an explicit snapshot never serves an auto open.
    let db2 = common::temp_db(&dir, "r2");
    bootstrap_raw(&bin, &db2, explicit);
    let handle = db::open_db(&db2).expect("open db");
    assert!(
        matches!(
            db::load_cached(
                &handle,
                hash,
                &sha256,
                size,
                &StoredMapping::Auto,
                &db::DebugId::default()
            )
            .expect("load_cached"),
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
        content_sha256: q.content_sha256().to_string(),
        size: bytes.len() as u64,
        arch: db::arch_name(q.binary().arch).to_string(),
        format: db::format_name(q.binary().format).to_string(),
        entry: q.binary().entry,
        supported: true,
        reason: None,
        mapping: Some(q.mapping().clone()),
        analysis_rev: Some(db::ANALYSIS_REVISION),
        diagnostics_truncated: q.analysis().diagnostics.truncated,
        diagnostics_omitted: q.analysis().diagnostics.omitted,
        inferred_truncated: q.analysis().diagnostics.inferred_truncated,
        inferred_omitted: q.analysis().diagnostics.inferred_omitted,
        debug: db::DebugId::default(),
        seeds_hash: 0,
    };
    let err = db::save(&hog, &meta, q.analysis(), q.annotations(), q.func_seeds()).unwrap_err();
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
    let sha256 = binscout::annotations::sha256_hex(&bytes);
    let size = bytes.len() as u64;
    assert_stale(cached_with(&db, hash, &sha256, size, &mapping_of(o)));
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
    let sha256 = binscout::annotations::sha256_hex(&bytes);
    let size = bytes.len() as u64;
    {
        let handle = db::open_db_read_only(&db).expect("open db");
        let err = db::load_cached(
            &handle,
            hash,
            &sha256,
            size,
            &mapping_of(o),
            &db::DebugId::default(),
        )
        .unwrap_err();
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
    let sha256 = binscout::annotations::sha256_hex(&bytes);
    let size = bytes.len() as u64;

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
    assert_stale(cached_with(&db, hash, &sha256, size, &mapping_of(o)));
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

/// Synthetic code per arch decoding to at least one function at its base.
fn arch_bytes(arch: Arch) -> Vec<u8> {
    match arch {
        Arch::X86_64 | Arch::X86_32 => vec![0x90, 0x90, 0xC3],
        // aarch64 `nop; ret`.
        Arch::Aarch64 => vec![0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6],
        // arm32 `mov r0, r1; bx lr`.
        Arch::Arm32 => vec![0x01, 0x00, 0xA0, 0xE1, 0x1E, 0xFF, 0x2F, 0xE1],
        // thumb `nop; bx lr`.
        Arch::Thumb => vec![0x00, 0xBF, 0x70, 0x47],
        // riscv `c.nop; ret` (jalr x0, 0(x1)).
        Arch::Riscv32 | Arch::Riscv64 => vec![0x01, 0x00, 0x67, 0x80, 0x00, 0x00],
        // ppc `nop` (ori r0, r0, 0); `blr`.
        Arch::Ppc32 | Arch::Ppc64 => vec![0x60, 0x00, 0x00, 0x00, 0x4E, 0x80, 0x00, 0x20],
    }
}

fn arch_base(arch: Arch) -> u64 {
    match arch {
        Arch::X86_64 => 0x1000,
        Arch::X86_32 => 0x2000,
        Arch::Aarch64 => 0x10000,
        Arch::Arm32 => 0x11000,
        Arch::Thumb => 0x20000,
        Arch::Riscv32 => 0x30000,
        Arch::Riscv64 => 0x31000,
        Arch::Ppc32 => 0x40000,
        Arch::Ppc64 => 0x41000,
    }
}

#[test]
fn explicit_raw_parity_across_arches() {
    for arch in [
        Arch::X86_64,
        Arch::X86_32,
        Arch::Aarch64,
        Arch::Arm32,
        Arch::Thumb,
        Arch::Riscv32,
        Arch::Riscv64,
        Arch::Ppc32,
        Arch::Ppc64,
    ] {
        let dir = common::tmpdir("raw-parity");
        let bytes = arch_bytes(arch);
        let base = arch_base(arch);
        let bin = write_raw(&dir, "r.bin", &bytes);
        let db = common::temp_db(&dir, "r");
        let o = opts(arch, base, None);

        let p = Project::open_raw(&bin, &db, o).expect("explicit raw open");
        assert_eq!(p.binary().arch, arch, "{arch:?}");
        assert!(
            p.analysis().functions.contains_key(&base),
            "{arch:?} must find a function at its base {base:#x}"
        );
        let info = p.project_info();
        assert_eq!(info.protocol, binscout::WIRE_PROTOCOL, "{arch:?}");
        assert_eq!(info.mode, "raw", "{arch:?}");
        assert_eq!(info.base, Some(base), "{arch:?}");
        assert_eq!(info.arch, db::arch_name(arch), "{arch:?}");
        assert_eq!(info.format, "raw", "{arch:?}");
        let stats = p.stats_json().expect("stats");
        assert_eq!(stats["mode"], "raw", "{arch:?}");
        assert_eq!(stats["base"], base, "{arch:?}");
        assert_eq!(stats["protocol"], binscout::WIRE_PROTOCOL, "{arch:?}");
        assert!(!db.exists(), "{arch:?} reads never create the sidecar");
        common::cleanup(&dir);
    }
}

#[test]
fn explicit_raw_entry_reports_and_seeds() {
    let dir = common::tmpdir("raw-entry-info");
    let bytes = nop_ret();
    let base = 0x4000;
    let bin = write_raw(&dir, "r.bin", &bytes);
    let db = common::temp_db(&dir, "r");
    let o = opts(Arch::X86_64, base, Some(base));

    let p = Project::open_raw(&bin, &db, o).expect("raw open with entry");
    assert_eq!(p.binary().entry, Some(base));
    let info = p.project_info();
    assert_eq!(info.mode, "raw");
    assert_eq!(info.base, Some(base));
    assert_eq!(info.entry, Some(base));
    assert!(p.analysis().functions.contains_key(&base));
    common::cleanup(&dir);
}

#[test]
fn shared_parser_rejects_misuse() {
    // Raw-only options without raw mode are errors.
    for (arch, base, entry) in [
        (Some("x86_64"), None, None),
        (None, Some("0x1000"), None),
        (None, None, Some("0x1000")),
    ] {
        let err = binscout::parse_raw_options(false, arch, base, entry).unwrap_err();
        assert!(
            err.to_string().contains("--raw"),
            "raw-only without --raw must name --raw: {err:?}"
        );
    }
    // Explicit mode requires arch and base.
    assert!(
        binscout::parse_raw_options(true, None, Some("0x1000"), None)
            .unwrap_err()
            .to_string()
            .contains("--arch")
    );
    assert!(
        binscout::parse_raw_options(true, Some("x86_64"), None, None)
            .unwrap_err()
            .to_string()
            .contains("--base")
    );
    // Unknown arch and bad addresses fail.
    assert!(
        binscout::parse_raw_options(true, Some("mips"), Some("0x1000"), None)
            .unwrap_err()
            .to_string()
            .contains("unknown arch")
    );
    assert!(binscout::parse_raw_options(true, Some("x86_64"), Some("zz"), None).is_err());
    // Well-formed explicit and auto parses succeed.
    assert!(
        binscout::parse_raw_options(true, Some("thumb"), Some("0x20000"), None)
            .expect("valid raw")
            .is_some()
    );
    assert!(
        binscout::parse_raw_options(false, None, None, None)
            .expect("valid auto")
            .is_none()
    );
}

#[test]
fn raw_mapping_validation_fails_without_fallback() {
    // Misaligned entries per mode.
    for (arch, base, entry) in [
        (Arch::Aarch64, 0x10000, 0x10001),
        (Arch::Arm32, 0x10000, 0x10002),
        (Arch::Thumb, 0x20000, 0x20001),
    ] {
        let bytes = arch_bytes(arch);
        let err = binscout::loader::load_raw(
            &bytes,
            RawOptions {
                base,
                arch,
                entry: Some(entry),
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("misaligned"),
            "{arch:?} misaligned entry must fail: {err:?}"
        );
    }
    // Out-of-range entry.
    let err = binscout::loader::load_raw(
        &nop_ret(),
        RawOptions {
            base: 0x1000,
            arch: Arch::X86_64,
            entry: Some(0x2000),
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("outside"),
        "out-of-range entry must fail: {err:?}"
    );
    // Base-plus-length overflow.
    let err = binscout::loader::load_raw(
        &nop_ret(),
        RawOptions {
            base: u64::MAX - 1,
            arch: Arch::X86_64,
            entry: None,
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("overflow"),
        "overflowing mapping must fail: {err:?}"
    );
    // Explicit opens surface the same errors instead of falling back.
    let dir = common::tmpdir("raw-no-fallback");
    let bin = write_raw(&dir, "r.bin", &arch_bytes(Arch::Aarch64));
    let db = common::temp_db(&dir, "r");
    let err = Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: 0x10000,
            arch: Arch::Aarch64,
            entry: Some(0x10001),
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("misaligned"),
        "explicit raw must error, never fall back: {err:?}"
    );
    assert!(!db.exists(), "failed explicit open must not write");
    common::cleanup(&dir);
}

#[test]
fn auto_mode_reports_auto_mapping() {
    // Unrecognized bytes keep the auto fallback; info reports auto/null.
    let dir = common::tmpdir("raw-auto-info");
    let bin = write_raw(&dir, "r.bin", &nop_ret());
    let db = common::temp_db(&dir, "r");
    let p = Project::open_with_db(&bin, &db).expect("auto open");
    let info = p.project_info();
    assert_eq!(info.mode, "auto");
    assert_eq!(info.base, None);
    assert_eq!(info.protocol, binscout::WIRE_PROTOCOL);

    // Containers without flags are unchanged: ELF stays auto/elf.
    let elf = common::write_bin(&dir, "t.elf", &common::minimal_elf());
    let elf_db = common::temp_db(&dir, "elf");
    let q = Project::open_with_db(&elf, &elf_db).expect("elf auto open");
    let info = q.project_info();
    assert_eq!(info.mode, "auto");
    assert_eq!(info.base, None);
    assert_eq!(info.format, "elf");
    assert_eq!(info.arch, "x86_64");
    common::cleanup(&dir);
}

#[test]
fn open_mapped_shares_parser_with_open_raw() {
    let dir = common::tmpdir("raw-open-mapped");
    let bytes = nop_ret();
    let bin = write_raw(&dir, "r.bin", &bytes);
    let parsed = binscout::parse_raw_options(true, Some("x86_64"), Some("0x1000"), None)
        .expect("parse")
        .expect("explicit");
    let db_a = common::temp_db(&dir, "a");
    let via_mapped = binscout::open_mapped(
        &bin,
        Some(&db_a),
        Some(parsed),
        None,
        &binscout::DebugOptions::default(),
    )
    .expect("open_mapped");
    let db_b = common::temp_db(&dir, "b");
    let via_raw = Project::open_raw(&bin, &db_b, parsed).expect("open_raw");
    let (m, r) = (via_mapped.project_info(), via_raw.project_info());
    assert_eq!(
        (m.mode, m.base, m.arch, m.format, m.entry, m.functions),
        (r.mode, r.base, r.arch, r.format, r.entry, r.functions),
        "shared opener must agree with open_raw"
    );
    common::cleanup(&dir);
}
