//! D3/A7 strings filters: pattern/min-len/section narrow the query, paging
//! renamed `offset`->`start`, and executable-memory noise is hidden unless
//! the query opts back in.

mod common;

use std::process::Command;

use serde_json::Value;

use binscout::analysis::StringsFilter;

use common::{binscout_bin, builders, cleanup, open_test_project, temp_db, tmpdir, write_fixture};

fn filter() -> StringsFilter {
    StringsFilter::default()
}

/// Run the CLI; returns exit success, parsed stdout JSON, and stderr text.
fn run_cli(args: &[&str]) -> (bool, Value, String) {
    let out = Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (
        out.status.success(),
        value,
        String::from_utf8(out.stderr).expect("stderr is utf-8"),
    )
}

fn values(rows: &[binscout::loader::strings::StringHit]) -> Vec<&str> {
    rows.iter().map(|h| h.value.as_str()).collect()
}

#[test]
fn default_page_shows_data_strings_without_executable_noise() {
    let dir = tmpdir("strings-default");
    let p = open_test_project(&dir, builders::BASIC_NAME);
    let rows = p.query_strings(&filter()).expect("default query works");
    let got = values(&rows);
    assert!(
        got.contains(&builders::BASIC_STRING),
        "marker must be visible by default: {got:?}"
    );
    assert!(
        got.contains(&builders::DATA_MARKER),
        "writable-section marker must be visible: {got:?}"
    );
    assert!(
        rows.iter().all(|h| !h.executable),
        "default page must hold zero executable rows: {rows:?}"
    );
    assert!(
        rows.iter().all(|h| h.section.is_some()),
        "container hits must be section-tagged: {rows:?}"
    );
    cleanup(&dir);
}

#[test]
fn marker_is_tagged_rdata_and_not_executable() {
    let dir = tmpdir("strings-tag");
    let p = open_test_project(&dir, builders::BASIC_NAME);
    let rows = p.query_strings(&filter()).expect("default query works");
    let marker = rows
        .iter()
        .find(|h| h.value == builders::BASIC_STRING)
        .expect("marker present");
    assert_eq!(marker.section.as_deref(), Some(".rdata"));
    assert!(!marker.executable);
    assert_eq!(
        marker.vaddr,
        Some(builders::BASIC_STRING_VA),
        "tagging must not move the address"
    );
    cleanup(&dir);
}

#[test]
fn pattern_save_with_min_len_finds_marker() {
    let dir = tmpdir("strings-pattern");
    let p = open_test_project(&dir, builders::BASIC_NAME);
    let rows = p
        .query_strings(&StringsFilter {
            pattern: Some("SAVE".to_string()),
            min_len: Some(6),
            ..filter()
        })
        .expect("pattern query works");
    assert_eq!(values(&rows), [builders::BASIC_STRING]);
    cleanup(&dir);
}

#[test]
fn min_len_counts_characters() {
    let dir = tmpdir("strings-minlen");
    let p = open_test_project(&dir, builders::BASIC_NAME);
    let n = builders::BASIC_STRING.chars().count();
    let at = p
        .query_strings(&StringsFilter {
            min_len: Some(n),
            ..filter()
        })
        .expect("threshold query works");
    assert!(values(&at).contains(&builders::BASIC_STRING));
    let over = p
        .query_strings(&StringsFilter {
            min_len: Some(n + 1),
            ..filter()
        })
        .expect("threshold query works");
    assert!(!values(&over).contains(&builders::BASIC_STRING));
    cleanup(&dir);
}

#[test]
fn section_filter_selects_exact_section() {
    let dir = tmpdir("strings-section");
    let p = open_test_project(&dir, builders::BASIC_NAME);
    let rdata = p
        .query_strings(&StringsFilter {
            section: Some(".rdata".to_string()),
            ..filter()
        })
        .expect("section query works");
    assert!(values(&rdata).contains(&builders::BASIC_STRING));
    assert!(rdata.iter().all(|h| h.section.as_deref() == Some(".rdata")));

    let text = p
        .query_strings(&StringsFilter {
            section: Some(".text".to_string()),
            ..filter()
        })
        .expect("section query works");
    assert!(text.is_empty(), "basic .text holds no runs: {text:?}");

    let missing = p
        .query_strings(&StringsFilter {
            section: Some(".nope".to_string()),
            ..filter()
        })
        .expect("section query works");
    assert!(missing.is_empty());
    cleanup(&dir);
}

#[test]
fn garbage_default_page_is_empty_but_searchable() {
    let dir = tmpdir("strings-garbage");
    let p = open_test_project(&dir, builders::GARBAGE_NAME);
    let def = p.query_strings(&filter()).expect("default query works");
    assert!(def.is_empty(), "byte-noise must hide by default: {def:?}");

    // A threshold alone does not opt back into executable memory.
    let gated = p
        .query_strings(&StringsFilter {
            min_len: Some(1),
            ..filter()
        })
        .expect("threshold query works");
    assert!(gated.is_empty());

    let code = p
        .query_strings(&StringsFilter {
            include_code: true,
            ..filter()
        })
        .expect("include_code query works");
    let got = values(&code);
    assert!(got.contains(&builders::GARBAGE_STR1), "{got:?}");
    assert!(got.contains(&builders::GARBAGE_STR2), "{got:?}");
    assert!(code.iter().all(|h| h.executable && h.section.is_none()));

    // An explicit pattern searches everything, including code noise.
    let found = p
        .query_strings(&StringsFilter {
            pattern: Some(builders::GARBAGE_STR1.to_string()),
            ..filter()
        })
        .expect("pattern query works");
    assert_eq!(values(&found), [builders::GARBAGE_STR1]);
    cleanup(&dir);
}

#[test]
fn regex_prefix_opts_in_and_bad_regex_errors() {
    let dir = tmpdir("strings-regex");
    let p = open_test_project(&dir, builders::BASIC_NAME);
    let rows = p
        .query_strings(&StringsFilter {
            pattern: Some("regex:SAVE.*invalid".to_string()),
            ..filter()
        })
        .expect("regex query works");
    assert_eq!(values(&rows), [builders::BASIC_STRING]);

    let err = p
        .query_strings(&StringsFilter {
            pattern: Some("regex:([".to_string()),
            ..filter()
        })
        .unwrap_err();
    assert!(
        matches!(err, binscout::error::Error::Invalid(_)),
        "bad regex must be Invalid, got {err:?}"
    );
    cleanup(&dir);
}

#[test]
fn paging_applies_after_filtering() {
    let dir = tmpdir("strings-paging");
    let p = open_test_project(&dir, builders::BASIC_NAME);
    let all = p.query_strings(&filter()).expect("default query works");
    assert!(all.len() >= 2, "need rows to page: {all:?}");
    let first = p
        .query_strings(&StringsFilter {
            start: 0,
            limit: 1,
            ..filter()
        })
        .expect("paged query works");
    let second = p
        .query_strings(&StringsFilter {
            start: 1,
            limit: 1,
            ..filter()
        })
        .expect("paged query works");
    assert_eq!(first, all[..1]);
    assert_eq!(second, all[1..2]);
    let past = p
        .query_strings(&StringsFilter {
            start: all.len() + 5,
            limit: 5,
            ..filter()
        })
        .expect("paged query works");
    assert!(past.is_empty());
    cleanup(&dir);
}

#[test]
fn tags_survive_sidecar_round_trip() {
    let dir = tmpdir("strings-roundtrip");
    let bin = write_fixture(&dir, builders::BASIC_NAME);
    let db = temp_db(&dir, "basic");
    let p = binscout::Project::open_with_db(&bin, &db).expect("fixture must open");
    p.save().expect("snapshot saves");
    let q = binscout::Project::open_with_db(&bin, &db).expect("snapshot must reopen");
    let rows = q.query_strings(&filter()).expect("default query works");
    let marker = rows
        .iter()
        .find(|h| h.value == builders::BASIC_STRING)
        .expect("marker survives reopen");
    assert_eq!(marker.section.as_deref(), Some(".rdata"));
    assert!(!marker.executable);
    cleanup(&dir);
}

#[test]
fn unfiltered_compat_view_still_sees_code_noise() {
    let dir = tmpdir("strings-compat");
    let p = open_test_project(&dir, builders::GARBAGE_NAME);
    let rows = p.analysis().strings_page(0, 100);
    assert_eq!(
        values(&rows),
        [builders::GARBAGE_STR1, builders::GARBAGE_STR2]
    );
    cleanup(&dir);
}

#[test]
fn cli_pattern_and_defaults_behave() {
    let dir = tmpdir("strings-cli");
    let basic = write_fixture(&dir, builders::BASIC_NAME);
    let basic_s = basic.display().to_string();
    let basic_db = temp_db(&dir, "basic").display().to_string();
    let garbage = write_fixture(&dir, builders::GARBAGE_NAME);
    let garbage_s = garbage.display().to_string();
    let garbage_db = temp_db(&dir, "garbage").display().to_string();

    let (ok, v, _) = run_cli(&[
        "--db",
        &basic_db,
        "strings",
        &basic_s,
        "--pattern",
        "SAVE",
        "--min-len",
        "6",
    ]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("array").len(), 1);
    assert_eq!(v[0]["value"], builders::BASIC_STRING);

    let (ok, v, _) = run_cli(&["--db", &garbage_db, "strings", &garbage_s]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("array").len(), 0);

    let (ok, v, _) = run_cli(&["--db", &garbage_db, "strings", &garbage_s, "--include-code"]);
    assert!(ok, "{v}");
    assert_eq!(v.as_array().expect("array").len(), 2);
    cleanup(&dir);
}

#[test]
fn cli_offset_alias_works_and_warns() {
    let dir = tmpdir("strings-alias");
    let bin = write_fixture(&dir, builders::BASIC_NAME);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "basic").display().to_string();

    let (ok, via_start, err_start) = run_cli(&[
        "--db", &db, "strings", &bin_s, "--start", "1", "--limit", "1",
    ]);
    assert!(ok, "{via_start}");
    assert!(
        !err_start.contains("deprecated"),
        "--start must not warn: {err_start:?}"
    );

    let (ok, via_offset, err_offset) = run_cli(&[
        "--db", &db, "strings", &bin_s, "--offset", "1", "--limit", "1",
    ]);
    assert!(ok, "{via_offset}");
    assert_eq!(via_offset, via_start, "alias must return the same page");
    assert!(
        err_offset.contains("--offset is deprecated, use --start"),
        "alias must warn on stderr: {err_offset:?}"
    );
    cleanup(&dir);
}

#[test]
fn cli_bad_regex_is_a_json_envelope() {
    let dir = tmpdir("strings-badre");
    let bin = write_fixture(&dir, builders::BASIC_NAME);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "basic").display().to_string();

    let (ok, v, _) = run_cli(&["--db", &db, "strings", &bin_s, "--pattern", "regex:(["]);
    assert!(!ok, "bad regex must fail, got {v}");
    assert!(v.get("error").is_some(), "{v}");
    cleanup(&dir);
}
