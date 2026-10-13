use std::path::Path;

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
