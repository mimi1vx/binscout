//! Type-hint comments: structured struct-layout/sizeof hints in the
//! comment channel.
//!
//! Covers the idea-10 acceptance checks: format/parse round-trips, plain
//! comments staying unhinted, corrupt hints erroring (never silent),
//! shape validation, free-text coexistence, and export/import carrying a
//! struct hint between projects while the rename-target contract holds.

mod common;

use std::process::Command;

use binscout::Project;
use binscout::annotations::{
    TYPE_HINT_PREFIX, TypeField, TypeHint, format_type_hint, parse_type_hint,
};
use binscout::db::MAX_ANNOTATION_BYTES;
use binscout::error::Error;

fn sample_hint() -> TypeHint {
    TypeHint {
        name: "Foo".to_string(),
        size: 24,
        fields: vec![
            TypeField {
                name: "a".to_string(),
                offset: 0,
                size: 8,
            },
            TypeField {
                name: "b".to_string(),
                offset: 8,
                size: 4,
            },
        ],
    }
}

#[test]
fn format_parse_round_trip() {
    let hint = sample_hint();
    let text = format_type_hint(&hint).expect("valid hint");
    assert!(text.starts_with(TYPE_HINT_PREFIX), "{text}");
    assert_eq!(parse_type_hint(&text).expect("parses"), Some(hint));
}

#[test]
fn plain_comments_are_not_hints() {
    assert_eq!(parse_type_hint("just a note").expect("plain"), None);
    assert_eq!(parse_type_hint("").expect("empty"), None);
    // Prefix-like text without the exact marker stays plain.
    assert_eq!(
        parse_type_hint("type-hint without colon {\"kind\":\"struct\"}").expect("plain"),
        None
    );
}

#[test]
fn corrupt_hints_error_instead_of_decoding_silently() {
    for bad in [
        "type-hint:{not json",
        "type-hint:{\"kind\":\"union\",\"name\":\"U\",\"size\":8}",
        "type-hint:{\"kind\":\"struct\",\"name\":\"\",\"size\":8}",
        "type-hint:{\"kind\":\"struct\",\"name\":\"S\",\"size\":0}",
        "type-hint:{\"kind\":\"struct\",\"name\":\"S\",\"size\":8,\
         \"fields\":[{\"name\":\"f\",\"offset\":4,\"size\":8}]}",
    ] {
        let err = parse_type_hint(bad).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)), "{bad}: got {err:?}");
    }
}

#[test]
fn shape_validation_rejects_bad_hints() {
    let overrun = TypeHint {
        name: "S".to_string(),
        size: 8,
        fields: vec![TypeField {
            name: "f".to_string(),
            offset: 4,
            size: 8,
        }],
    };
    let err = format_type_hint(&overrun).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");

    let overflow = TypeHint {
        name: "S".to_string(),
        size: u64::MAX,
        fields: vec![TypeField {
            name: "f".to_string(),
            offset: u64::MAX,
            size: 1,
        }],
    };
    let err = format_type_hint(&overflow).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");

    for bad in [
        TypeHint {
            name: String::new(),
            size: 8,
            fields: vec![],
        },
        TypeHint {
            name: "S".to_string(),
            size: 0,
            fields: vec![],
        },
        TypeHint {
            name: "S".to_string(),
            size: 8,
            fields: vec![TypeField {
                name: String::new(),
                offset: 0,
                size: 4,
            }],
        },
        TypeHint {
            name: "S".to_string(),
            size: 8,
            fields: vec![TypeField {
                name: "f".to_string(),
                offset: 0,
                size: 0,
            }],
        },
    ] {
        let err = format_type_hint(&bad).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
    }
}

#[test]
fn oversized_hints_hit_the_comment_cap() {
    let hint = TypeHint {
        name: "x".repeat(MAX_ANNOTATION_BYTES),
        size: 8,
        fields: vec![],
    };
    let err = format_type_hint(&hint).unwrap_err();
    assert!(matches!(err, Error::Limit(_)), "got {err:?}");
}

#[test]
fn overlapping_union_fields_are_allowed() {
    let hint = TypeHint {
        name: "U".to_string(),
        size: 8,
        fields: vec![
            TypeField {
                name: "as_u64".to_string(),
                offset: 0,
                size: 8,
            },
            TypeField {
                name: "as_bytes".to_string(),
                offset: 0,
                size: 8,
            },
        ],
    };
    let text = format_type_hint(&hint).expect("unions allowed");
    assert_eq!(parse_type_hint(&text).expect("parses"), Some(hint));
}

#[test]
fn trailing_free_text_coexists_with_the_hint() {
    let hint = sample_hint();
    let text = format!(
        "{}\nnoted by analyst",
        format_type_hint(&hint).expect("hint")
    );
    assert_eq!(parse_type_hint(&text).expect("parses"), Some(hint));
}

#[test]
fn hint_survives_export_import_round_trip() {
    let dir = common::tmpdir("typehint-roundtrip");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "a");
    let unmapped = 0xdead_beefu64;

    let hint = sample_hint();
    let mut p = Project::open_with_db(&bin, &db).expect("open");
    // Any-address contract: hints store away from any function or string.
    p.set_type_hint(unmapped, &hint).expect("set hint");
    p.set_comment(common::builders::BASIC_STRING_VA, "plain note")
        .expect("plain comment");
    assert_eq!(p.type_hint_at(unmapped).expect("read"), Some(hint.clone()));
    assert_eq!(
        p.type_hint_at(common::builders::BASIC_STRING_VA)
            .expect("read"),
        None,
        "plain comments stay unhinted"
    );
    let doc = p.export_annotations().expect("export");
    assert!(doc.contains(TYPE_HINT_PREFIX), "hint in document");
    drop(p);

    let db2 = common::temp_db(&dir, "b");
    let mut q = Project::open_with_db(&bin, &db2).expect("open fresh");
    let summary = q.import_annotations(&doc, false).expect("import");
    assert_eq!(summary.rows, 2);
    assert_eq!(summary.changed, 2);
    assert_eq!(q.type_hint_at(unmapped).expect("read"), Some(hint.clone()));
    drop(q);

    let r = Project::open_with_db(&bin, &db2).expect("reopen");
    assert_eq!(r.type_hint_at(unmapped).expect("read"), Some(hint.clone()));
    assert_eq!(
        r.annotation(unmapped)
            .and_then(|a| a.comment.as_deref())
            .expect("comment stored"),
        format_type_hint(&hint).expect("hint"),
    );

    // Rename-target contract untouched: unknown entries still fail.
    let mut s = Project::open_with_db(&bin, &db2).expect("reopen");
    let err = s.rename_function(0x1234_5678u64, "ghost").unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    common::cleanup(&dir);
}

#[test]
fn cli_carries_hints_through_comment_opaquely() {
    let dir = common::tmpdir("typehint-cli");
    let bin = common::write_fixture(&dir, common::builders::BASIC_NAME);
    let db = common::temp_db(&dir, "a");
    let hint_text = format_type_hint(&sample_hint()).expect("hint");

    let run = |args: &[&str]| {
        let out = Command::new(common::binscout_bin())
            .args(args)
            .output()
            .expect("spawn binscout");
        let text = String::from_utf8(out.stdout).expect("utf-8 stdout");
        let value: serde_json::Value =
            serde_json::from_str(text.trim_end()).expect("one JSON value");
        (out.status.success(), value)
    };
    let db_s = db.display().to_string();
    let bin_s = bin.display().to_string();

    let (ok, v) = run(&[
        "--db",
        &db_s,
        "annotate",
        &bin_s,
        "0xdeadbeef",
        "--comment",
        &hint_text,
    ]);
    assert!(ok, "{v}");
    assert_eq!(v["comment"], hint_text);

    let (ok, v) = run(&["--db", &db_s, "annotations-export", &bin_s]);
    assert!(ok, "{v}");
    let rows = v["annotations"].as_array().expect("rows");
    assert!(
        rows.iter().any(|r| r["comment"] == hint_text),
        "hint survives CLI export: {v}"
    );
    common::cleanup(&dir);
}
