mod common;

use binscout::analysis::{BasicBlock, StringsFilter, analyze_raw};
use binscout::disasm::Arch;

use common::{builders, cleanup, open_test_project, tmpdir};

#[test]
fn empty_block_reports_start_end_without_panic() {
    let empty = BasicBlock {
        start: 0x2000,
        insns: Vec::new(),
    };
    assert_eq!(empty.end(), 0x2000);
    assert_eq!(empty.id(0x2000), "block@0x2000+0x2000");
}

#[test]
fn degenerate_raw_blobs_analyze_ok() {
    for bytes in [vec![0xC3], vec![0x90], vec![0x90, 0x90, 0xC3]] {
        let a = analyze_raw(&bytes, 0x1000, Arch::X86_64, Some(0x1000))
            .expect("degenerate blob must analyze");
        assert!(!a.functions.is_empty());
        for (&entry, f) in &a.functions {
            assert!(!f.blocks.is_empty(), "no empty blocks for {entry:#x}");
            let rows = a.blocks_page(entry, 0, 16).expect("function exists");
            assert_eq!(rows.len(), f.blocks.len());
        }
    }
}

#[test]
fn pattern_filter_compiles_lazily_without_panic() {
    let mut bytes = b"hello-world-marker".to_vec();
    bytes.push(0x00);
    bytes.extend([0x90, 0x90, 0xC3]);
    let a =
        analyze_raw(&bytes, 0x1000, Arch::X86_64, Some(0x1013)).expect("marker blob must analyze");
    assert!(!a.strings.is_empty(), "blob must yield a string hit");
    let hit = a
        .strings_page_filtered(&StringsFilter {
            pattern: Some("hello-world".to_string()),
            ..StringsFilter::default()
        })
        .expect("substring query works");
    assert!(hit.iter().any(|h| h.value.contains("hello-world")));
    let regex = a
        .strings_page_filtered(&StringsFilter {
            pattern: Some("regex:hello-.*".to_string()),
            ..StringsFilter::default()
        })
        .expect("regex query works");
    assert!(regex.iter().any(|h| h.value.contains("hello-world")));
    let miss = a
        .strings_page_filtered(&StringsFilter {
            pattern: Some("zzz-no-such-string".to_string()),
            ..StringsFilter::default()
        })
        .expect("non-matching query works");
    assert!(miss.is_empty());
}

#[test]
fn project_open_and_pattern_query_survive_edge_cases() {
    let dir = tmpdir("analysis-robustness");
    let p = open_test_project(&dir, builders::BASIC_NAME);
    assert!(!p.analysis().functions.is_empty());
    let hit = p
        .query_strings(&StringsFilter {
            pattern: Some("SAVE".to_string()),
            ..StringsFilter::default()
        })
        .expect("fixture pattern query works");
    assert!(hit.iter().any(|h| h.value.contains("SAVE")));
    let miss = p
        .query_strings(&StringsFilter {
            pattern: Some("zzz-no-such-string".to_string()),
            ..StringsFilter::default()
        })
        .expect("non-matching query works");
    assert!(miss.is_empty());
    cleanup(&dir);
}
