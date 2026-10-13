//! Lazy per-query pattern matcher: one compilation per query, zero when every
//! row is prefiltered; error, order, and paging behavior unchanged.
//!
//! The scale tests open a synthetic raw blob (unrecognized bytes fall back to
//! raw x86-64) holding thousands of `qmatch-NNNNN-abcdef` runs, so regex
//! queries evaluate thousands of eligible rows.

mod common;

use binscout::analysis::{MAX_PAGE, StringsFilter};
use binscout::loader::strings::{MAX_PATTERN_LEN, matches_pattern};

use common::{builders, cleanup, temp_db, tmpdir, write_bin, write_fixture};

/// Rows in the synthetic scale blob; thousands of eligible hits per query.
const ROWS: usize = 3000;

fn row(i: usize) -> String {
    format!("qmatch-{i:05}-abcdef")
}

fn many_rows_blob() -> Vec<u8> {
    let mut out = vec![0x00];
    for i in 0..ROWS {
        out.extend_from_slice(row(i).as_bytes());
        out.push(0x00);
    }
    out
}

fn open_many_rows(dir: &std::path::Path) -> binscout::Project {
    let bin = write_bin(dir, "many-rows.bin", &many_rows_blob());
    let db = temp_db(dir, "many-rows");
    binscout::Project::open_with_db(&bin, &db).expect("raw blob must open via fallback")
}

fn filter() -> StringsFilter {
    StringsFilter::default()
}

/// Collect every matching value, paging past the [`MAX_PAGE`] cap.
fn all_matching(p: &binscout::Project, base: &StringsFilter) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0;
    loop {
        let page = p
            .query_strings(&StringsFilter {
                start,
                limit: MAX_PAGE,
                ..base.clone()
            })
            .expect("query works");
        let done = page.len() < MAX_PAGE;
        out.extend(page.into_iter().map(|h| h.value));
        if done {
            return out;
        }
        start += MAX_PAGE;
    }
}

#[test]
fn scale_blob_holds_thousands_of_rows() {
    let dir = tmpdir("matcher-scale-shape");
    let p = open_many_rows(&dir);
    let all = all_matching(
        &p,
        &StringsFilter {
            pattern: Some(String::new()),
            ..filter()
        },
    );
    assert_eq!(all.len(), ROWS, "blob must yield one hit per row");
    assert_eq!(all[0], row(0));
    assert_eq!(all[ROWS - 1], row(ROWS - 1));
    cleanup(&dir);
}

#[test]
fn scale_regex_matches_all_and_agrees_with_per_row_loop() {
    let dir = tmpdir("matcher-scale-regex");
    let p = open_many_rows(&dir);
    let pattern = "regex:qmatch-[0-9]+-abcdef".to_string();
    let matched = all_matching(
        &p,
        &StringsFilter {
            pattern: Some(pattern.clone()),
            ..filter()
        },
    );
    assert_eq!(matched.len(), ROWS);
    // Old path (one `matches_pattern` call per row) must agree exactly,
    // in order: same compiled regex, same per-row predicate.
    let full = all_matching(
        &p,
        &StringsFilter {
            pattern: Some(String::new()),
            ..filter()
        },
    );
    let expected: Vec<String> = full
        .into_iter()
        .filter(|v| matches_pattern(v, &pattern).expect("valid regex"))
        .collect();
    assert_eq!(matched, expected);
    cleanup(&dir);
}

#[test]
fn scale_substring_modes_and_case_sensitivity() {
    let dir = tmpdir("matcher-scale-sub");
    let p = open_many_rows(&dir);
    let all = all_matching(
        &p,
        &StringsFilter {
            pattern: Some("qmatch-".to_string()),
            ..filter()
        },
    );
    assert_eq!(all.len(), ROWS);

    let one = p
        .query_strings(&StringsFilter {
            pattern: Some("00001".to_string()),
            ..filter()
        })
        .expect("substring query works");
    assert_eq!(
        one.iter().map(|h| h.value.as_str()).collect::<Vec<_>>(),
        [row(1).as_str()]
    );

    let lower = p
        .query_strings(&StringsFilter {
            pattern: Some("QMATCH-".to_string()),
            ..filter()
        })
        .expect("substring query works");
    assert!(lower.is_empty(), "substring stays case-sensitive");

    let anchored = all_matching(
        &p,
        &StringsFilter {
            pattern: Some("regex:^qmatch-00001-abcdef$".to_string()),
            ..filter()
        },
    );
    assert_eq!(anchored, [row(1)]);
    cleanup(&dir);
}

#[test]
fn bad_regex_errors_only_with_eligible_hits() {
    let dir = tmpdir("matcher-bad-regex");
    let p = open_many_rows(&dir);
    let bad = "regex:([".to_string();

    let err = p
        .query_strings(&StringsFilter {
            pattern: Some(bad.clone()),
            ..filter()
        })
        .unwrap_err();
    assert!(
        matches!(err, binscout::error::Error::Invalid(_)),
        "bad regex with eligible hits must be Invalid, got {err:?}"
    );

    // Every row prefiltered by section: zero compilations, success.
    let none = p
        .query_strings(&StringsFilter {
            pattern: Some(bad.clone()),
            section: Some(".nope".to_string()),
            ..filter()
        })
        .expect("prefiltered bad regex must succeed");
    assert!(none.is_empty());

    // Every row prefiltered by min_len: zero compilations, success.
    let short = p
        .query_strings(&StringsFilter {
            pattern: Some(bad.clone()),
            min_len: Some(10_000),
            ..filter()
        })
        .expect("prefiltered bad regex must succeed");
    assert!(short.is_empty());
    cleanup(&dir);
}

#[test]
fn overlong_pattern_errors_only_with_eligible_hits() {
    let dir = tmpdir("matcher-overlong");
    let p = open_many_rows(&dir);
    let overlong = "y".repeat(MAX_PATTERN_LEN + 1);

    let err = p
        .query_strings(&StringsFilter {
            pattern: Some(overlong.clone()),
            ..filter()
        })
        .unwrap_err();
    assert!(
        matches!(err, binscout::error::Error::Invalid(_)),
        "overlong pattern with eligible hits must be Invalid, got {err:?}"
    );

    let none = p
        .query_strings(&StringsFilter {
            pattern: Some(overlong),
            section: Some(".nope".to_string()),
            ..filter()
        })
        .expect("prefiltered overlong pattern must succeed");
    assert!(none.is_empty());
    cleanup(&dir);
}

#[test]
fn pattern_reaches_executable_rows_so_bad_regex_errors() {
    let dir = tmpdir("matcher-exec");
    let bin = write_fixture(&dir, builders::GARBAGE_NAME);
    let db = temp_db(&dir, "garbage");
    let p = binscout::Project::open_with_db(&bin, &db).expect("fixture must open");
    // Baseline: garbage rows are executable noise, hidden by default.
    let def = p.query_strings(&filter()).expect("default query works");
    assert!(def.is_empty(), "garbage must hide by default: {def:?}");

    // An explicit pattern opts back into executable memory, so the noise rows
    // are eligible: a bad pattern errors rather than succeeding empty.
    let err = p
        .query_strings(&StringsFilter {
            pattern: Some("regex:([".to_string()),
            ..filter()
        })
        .unwrap_err();
    assert!(
        matches!(err, binscout::error::Error::Invalid(_)),
        "bad regex over executable rows must be Invalid, got {err:?}"
    );
    cleanup(&dir);
}

#[test]
fn limit_zero_and_beyond_end_offset() {
    let dir = tmpdir("matcher-paging");
    let p = open_many_rows(&dir);
    let pattern = "regex:qmatch-[0-9]+".to_string();

    let zero = p
        .query_strings(&StringsFilter {
            pattern: Some(pattern.clone()),
            limit: 0,
            ..filter()
        })
        .expect("limit zero works");
    assert!(zero.is_empty());

    let past = p
        .query_strings(&StringsFilter {
            pattern: Some(pattern.clone()),
            start: ROWS + 100,
            ..filter()
        })
        .expect("beyond-end start works");
    assert!(past.is_empty());

    // Filtering runs before paging, so a bad pattern still errors even when
    // the page itself would be empty.
    for f in [
        StringsFilter {
            pattern: Some("regex:([".to_string()),
            limit: 0,
            ..filter()
        },
        StringsFilter {
            pattern: Some("regex:([".to_string()),
            start: ROWS + 100,
            ..filter()
        },
    ] {
        let err = p.query_strings(&f).unwrap_err();
        assert!(
            matches!(err, binscout::error::Error::Invalid(_)),
            "filter-before-page keeps the error observable, got {err:?}"
        );
    }
    cleanup(&dir);
}
