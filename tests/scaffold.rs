use std::path::Path;

mod common;

use common::builders;

#[test]
fn version_is_semver() {
    assert!(!binscout::version().is_empty());
}

#[test]
fn open_missing_returns_not_found() {
    let err = binscout::Project::open(Path::new("/nonexistent-binscout-fixture")).unwrap_err();
    assert!(matches!(err, binscout::error::Error::NotFound(_)));
}

#[test]
fn open_directory_returns_unsupported() {
    let err = binscout::Project::open(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap_err();
    assert!(matches!(err, binscout::error::Error::Unsupported(_)));
}

#[test]
fn open_raw_fixture_ok() {
    let p = binscout::Project::open(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/raw-x64.bin"
    )))
    .expect("raw fixture must open");
    assert!(p.path().is_file());
}

// --- F0 synthetic fixtures: builders-over-blobs, hermetic, deterministic ---

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Regenerate checked-in blobs: `FIXTURE_REGEN=1 cargo test --test scaffold`.
#[test]
fn fixture_regen() {
    if std::env::var("FIXTURE_REGEN").is_err() {
        return;
    }
    for (name, bytes) in builders::build_all() {
        std::fs::write(fixture_path(name), &bytes).expect("regen fixture blob");
    }
}

#[test]
fn fixture_builds_deterministically() {
    for (name, bytes) in builders::build_all() {
        assert!(!bytes.is_empty(), "{name} must build non-empty");
        assert_eq!(
            bytes,
            builders::build(name),
            "{name} must rebuild identically"
        );
    }
}

#[test]
fn fixture_blobs_byte_identical() {
    for (name, bytes) in builders::build_all() {
        let blob =
            std::fs::read(fixture_path(name)).unwrap_or_else(|_| panic!("missing blob {name}"));
        assert_eq!(blob, bytes, "{name} blob must equal builder output");
    }
}

#[test]
fn pe32_basic_loads_with_expected_shape() {
    use binscout::disasm::Arch;
    use binscout::loader::{BinaryFormat, load};

    let bytes = common::fixture_bytes(builders::BASIC_NAME);
    let bin = load(&bytes).expect("synthetic PE32 must load");
    assert_eq!(bin.format, BinaryFormat::Pe);
    assert_eq!(bin.arch, Arch::X86_32);
    assert_eq!(bin.entry, Some(builders::BASIC_ENTRY_VA));
    let names: Vec<&str> = bin.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, [".text", ".rdata", ".data"]);
    assert_eq!(bin.sections[0].vaddr, builders::TEXT_VA);
    assert_eq!(bin.sections[1].vaddr, builders::RDATA_VA);
    assert_eq!(bin.sections[2].vaddr, builders::DATA_VA);
    assert_eq!(
        bin.exports,
        [binscout::loader::ExportRef {
            name: builders::BASIC_EXPORT.to_string(),
            address: Some(builders::BASIC_ENTRY_VA),
            ordinal: None,
            demangled: None,
        }]
    );
    // Ground truth for X2/A4: the marker string sits at its VA and `.text`
    // holds exactly two LE32 occurrences (the two `push imm32`).
    let rdata = common::section_bytes(&bin, 1);
    let off = builders::BASIC_STRING_RDATA_OFF;
    assert_eq!(
        &rdata[off..off + builders::BASIC_STRING.len()],
        builders::BASIC_STRING.as_bytes()
    );
    let refs = common::le32_refs(
        common::section_bytes(&bin, 0),
        builders::TEXT_VA,
        builders::BASIC_STRING_VA,
    );
    assert_eq!(refs.len(), 2, "two push-imm32 refs expected: {refs:?}");
}

#[test]
fn pe32_basic_opens_end_to_end() {
    let dir = common::tmpdir("f0-basic");
    let p = common::open_test_project(&dir, builders::BASIC_NAME);
    let info = p.project_info();
    assert_eq!(info.format, "pe");
    assert_eq!(info.arch, "x86_32");
    assert_eq!(info.entry, Some(builders::BASIC_ENTRY_VA));
    assert!(info.supported, "supported formats report supported:true");
    assert!(info.reason.is_none());
    assert!(info.functions >= 1, "entry func must be found");
    assert!(
        p.analysis()
            .strings
            .iter()
            .any(|h| h.value == builders::BASIC_STRING),
        "marker string must be recovered"
    );
    common::cleanup(&dir);
}

#[test]
fn pe32_ordinals_loads_ordinal_and_mangled_imports() {
    use binscout::disasm::Arch;
    use binscout::loader::{BinaryFormat, load};

    let bytes = common::fixture_bytes(builders::ORDINALS_NAME);
    let bin = load(&bytes).expect("ordinals PE32 must load");
    assert_eq!(bin.format, BinaryFormat::Pe);
    assert_eq!(bin.arch, Arch::X86_32);
    assert_eq!(bin.entry, Some(builders::ORDINALS_ENTRY_VA));
    let names: Vec<String> = bin.imports.iter().map(|i| i.name.clone()).collect();
    assert!(names.contains(&"#1".to_string()), "ordinal #1: {names:?}");
    assert!(names.contains(&"#2".to_string()), "ordinal #2: {names:?}");
    assert!(
        names.contains(&builders::ORDINALS_MANGLED.to_string()),
        "mangled: {names:?}"
    );
    assert!(
        bin.imports
            .iter()
            .all(|i| i.library == builders::ORDINALS_DLL),
        "one library: {:?}",
        bin.imports
    );
}

#[test]
fn le_fixture_parses_as_le() {
    use binscout::loader::{BinaryFormat, le, load};

    let bytes = common::fixture_bytes(builders::LE_NAME);
    assert!(le::is_le(&bytes));
    let bin = load(&bytes).expect("LE must parse at loader level");
    assert_eq!(bin.format, BinaryFormat::Le);
}

#[test]
fn le_fixture_opens_and_analyzes_as_x86_32() {
    let dir = common::tmpdir("l1-le");
    let bin = common::write_fixture(&dir, builders::LE_NAME);
    let db = common::temp_db(&dir, "le");
    let p = binscout::Project::open_with_db(&bin, &db).expect("synthetic LE must open");
    assert_eq!(p.binary().format, binscout::loader::BinaryFormat::Le);
    assert_eq!(p.binary().arch, binscout::disasm::Arch::X86_32);
    assert_eq!(p.binary().entry, Some(0x10000));
    assert_eq!(p.binary().sections.len(), 1);
    assert!(
        !p.functions_resolved(0, 10).is_empty(),
        "LE code must yield functions"
    );
    common::cleanup(&dir);
}

#[test]
fn truncated_le_never_falls_back_to_raw() {
    use binscout::loader::le::is_le;

    let dir = common::tmpdir("l1-trunc");
    let mut bytes = common::fixture_bytes(builders::LE_NAME);
    // Keep MZ + e_lfanew + LE magic so the image is still recognized,
    // but truncate the header so the parse fails. The stub counts as
    // new-header so the guarded fast path still recognizes the prefix.
    bytes[0x18] = 0x40;
    bytes.truncate(0x44);
    assert!(is_le(&bytes), "truncated prefix must still read as LE");
    let bin = common::write_bin(&dir, "trunc-le.bin", &bytes);
    let db = common::temp_db(&dir, "trunc");
    let err = binscout::Project::open_with_db(&bin, &db).unwrap_err();
    assert!(
        matches!(err, binscout::error::Error::Invalid(_)),
        "recognized-but-truncated LE must stay invalid, never raw fallback: got {err:?}"
    );
    assert!(!db.exists(), "failed open must not create a sidecar");
    common::cleanup(&dir);
}

#[test]
fn unrecognized_bytes_still_fall_back_to_raw() {
    let dir = common::tmpdir("l1-raw");
    let p = common::open_test_project(&dir, builders::GARBAGE_NAME);
    assert_eq!(p.binary().format, binscout::loader::BinaryFormat::Raw);
    assert_eq!(p.binary().arch, binscout::disasm::Arch::X86_64);
    common::cleanup(&dir);
}

#[test]
fn garbage_fixture_has_noise_strings_and_decode_stop() {
    use binscout::disasm::{Arch, disasm_range};
    use binscout::error::Error;
    use binscout::loader::strings::extract;

    let bytes = common::fixture_bytes(builders::GARBAGE_NAME);
    let values: Vec<String> = extract(&bytes, 4, 100, None)
        .into_iter()
        .map(|h| h.value)
        .collect();
    assert!(values.contains(&builders::GARBAGE_STR1.to_string()));
    assert!(values.contains(&builders::GARBAGE_STR2.to_string()));
    // Full-range decode must stop at the invalid opcode (D2 turns this into
    // prefix + `error_at`); the valid prefix alone decodes.
    assert!(matches!(
        disasm_range(Arch::X86_64, &bytes, 0, 100).unwrap_err(),
        Error::Invalid(_)
    ));
    let stop = bytes.iter().position(|b| *b == 0xD6).expect("stop byte");
    assert!(
        !disasm_range(Arch::X86_64, &bytes[..stop], 0, 100)
            .expect("prefix decodes")
            .is_empty()
    );
}
