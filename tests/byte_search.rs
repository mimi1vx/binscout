//! Bounded byte search: pattern grammar, filters, paging, gaps/BSS, and
//! agreement with a simple reference matcher over randomized buffers.

mod common;

use binscout::Project;
use binscout::disasm::Arch;
use binscout::error::Error;
use binscout::loader::RawOptions;

use common::builders::{BASIC_STRING_RDATA_OFF, BASIC_STRING_VA, TEXT_VA};

fn open_basic(dir: &std::path::Path) -> Project {
    common::open_test_project(dir, common::builders::BASIC_NAME)
}

fn open_raw(dir: &std::path::Path, name: &str, bytes: &[u8], base: u64) -> Project {
    let bin = common::write_bin(dir, name, bytes);
    let db = common::temp_db(dir, name);
    Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base,
            arch: Arch::X86_64,
            entry: None,
        },
    )
    .expect("raw open")
}

#[test]
fn literal_match_reports_va_file_off_section_len() {
    let dir = common::tmpdir("bs-literal");
    let p = open_basic(&dir);
    let page = p
        .search_bytes("55 89 e5", None, None, 0, 50)
        .expect("search");
    assert_eq!(page.protocol, binscout::WIRE_PROTOCOL);
    assert_eq!(page.total, 1);
    assert_eq!(page.offset, 0);
    assert_eq!(page.limit, 50);
    assert_eq!(page.next_offset, None);
    let m = &page.items[0];
    assert_eq!(m.addr, TEXT_VA);
    assert_eq!(m.file_off, Some(0x200));
    assert_eq!(m.section.as_deref(), Some(".text"));
    assert_eq!(m.len, 3);
    let v = serde_json::to_value(&page).expect("serializes");
    assert_eq!(v["items"][0]["addr_hex"], "0x401000");
    assert_eq!(v["items"][0]["len"], 3);
    common::cleanup(&dir);
}

#[test]
fn wildcard_and_repeat_matches() {
    let dir = common::tmpdir("bs-wild");
    let p = open_basic(&dir);
    let a = p
        .search_bytes("68 ?? ?? ?? ??", None, None, 0, 50)
        .expect("wild");
    assert_eq!(a.total, 2);
    assert_eq!(a.items[0].addr, TEXT_VA + 3);
    assert_eq!(a.items[0].file_off, Some(0x203));
    assert_eq!(a.items[1].addr, TEXT_VA + 8);
    assert_eq!(a.items[1].file_off, Some(0x208));
    let spaced = p
        .search_bytes("  68\t?? ??\n?? ??  ", None, None, 0, 50)
        .expect("whitespace");
    assert_eq!(spaced.items, a.items, "surrounding whitespace is ignored");
    let mixed = p
        .search_bytes("55 89 e5", None, None, 0, 50)
        .expect("lower");
    let mixed_upper = p
        .search_bytes("55 89 E5", None, None, 0, 50)
        .expect("upper");
    assert_eq!(mixed.items, mixed_upper.items, "hex is case-insensitive");
    assert_eq!(mixed.total, 1);
    common::cleanup(&dir);
}

#[test]
fn section_filter_narrows_and_unknown_errors() {
    let dir = common::tmpdir("bs-section");
    let p = open_basic(&dir);
    let all = p
        .search_bytes("53 41 56 45", None, None, 0, 50)
        .expect("unfiltered");
    assert_eq!(all.total, 1, "SAVE marker is unique in the fixture");
    let rdata = p
        .search_bytes("53 41 56 45", Some(".rdata"), None, 0, 50)
        .expect("rdata filter");
    assert_eq!(rdata.total, 1);
    assert_eq!(rdata.items[0].addr, BASIC_STRING_VA);
    assert_eq!(
        rdata.items[0].file_off,
        Some(0x400 + BASIC_STRING_RDATA_OFF as u64)
    );
    assert_eq!(rdata.items[0].section.as_deref(), Some(".rdata"));
    let text = p
        .search_bytes("53 41 56 45", Some(".text"), None, 0, 50)
        .expect("text filter");
    assert_eq!(text.total, 0);
    assert!(text.items.is_empty());
    assert_eq!(text.next_offset, None);
    let err = p
        .search_bytes("53 41 56 45", Some("nope"), None, 0, 50)
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    common::cleanup(&dir);
}

#[test]
fn section_filter_on_raw_errors() {
    let dir = common::tmpdir("bs-raw-section");
    let p = open_raw(&dir, "r.bin", &[0x90, 0x90, 0xC3], 0x1000);
    let err = p
        .search_bytes("90", Some(".text"), None, 0, 10)
        .unwrap_err();
    assert!(
        matches!(err, Error::NotFound(_)),
        "raw has no sections: {err:?}"
    );
    common::cleanup(&dir);
}

#[test]
fn range_filter_is_half_open() {
    let dir = common::tmpdir("bs-range");
    let p = open_basic(&dir);
    let inside = p
        .search_bytes("55 89 e5", None, Some((TEXT_VA, TEXT_VA + 3)), 0, 10)
        .expect("containing range");
    assert_eq!(inside.total, 1);
    let past_end = p
        .search_bytes("55 89 e5", None, Some((TEXT_VA, TEXT_VA + 2)), 0, 10)
        .expect("short range");
    assert_eq!(past_end.total, 0, "match ending past hi is excluded");
    let past_start = p
        .search_bytes("55 89 e5", None, Some((TEXT_VA + 1, TEXT_VA + 0x10)), 0, 10)
        .expect("late range");
    assert_eq!(past_start.total, 0);
    let swapped = p
        .search_bytes("55 89 e5", None, Some((TEXT_VA + 3, TEXT_VA)), 0, 10)
        .expect("swapped normalizes");
    assert_eq!(swapped.total, 1);
    let err = p
        .search_bytes("55 89 e5", None, Some((TEXT_VA, TEXT_VA)), 0, 10)
        .unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
    common::cleanup(&dir);
}

#[test]
fn raw_mapping_overlap_and_provenance() {
    let dir = common::tmpdir("bs-overlap");
    let bytes = [0x90, 0x90, 0x90, 0xC3, 0x90, 0x90];
    let p = open_raw(&dir, "r.bin", &bytes, 0x1000);
    let page = p.search_bytes("90 90", None, None, 0, 50).expect("search");
    assert_eq!(page.total, 3);
    let addrs: Vec<u64> = page.items.iter().map(|m| m.addr).collect();
    assert_eq!(
        addrs,
        [0x1000, 0x1001, 0x1004],
        "overlapping matches included"
    );
    let offs: Vec<Option<u64>> = page.items.iter().map(|m| m.file_off).collect();
    assert_eq!(
        offs,
        [Some(0), Some(1), Some(4)],
        "raw file_off is the blob offset"
    );
    assert!(page.items.iter().all(|m| m.section.is_none()));
    assert!(page.items.iter().all(|m| m.len == 2));
    common::cleanup(&dir);
}

#[test]
fn paging_envelope_offsets_and_zero_limit() {
    let dir = common::tmpdir("bs-pages");
    let bytes = [0x90, 0x90, 0x90, 0xC3, 0x90, 0x90];
    let p = open_raw(&dir, "r.bin", &bytes, 0x1000);
    let mid = p.search_bytes("90 90", None, None, 1, 1).expect("page");
    assert_eq!(mid.total, 3);
    assert_eq!(mid.offset, 1);
    assert_eq!(mid.limit, 1);
    assert_eq!(mid.next_offset, Some(2));
    assert_eq!(mid.items.len(), 1);
    assert_eq!(mid.items[0].addr, 0x1001);
    let past = p
        .search_bytes("90 90", None, None, 3, 10)
        .expect("past end");
    assert_eq!(past.total, 3);
    assert!(past.items.is_empty());
    assert_eq!(past.next_offset, None);
    let zero = p
        .search_bytes("90 90", None, None, 0, 0)
        .expect("zero limit");
    assert_eq!(zero.total, 3, "zero limit still reports the exact total");
    assert!(zero.items.is_empty());
    assert_eq!(zero.next_offset, None);
    let err = p.search_bytes("??", None, None, 0, 0).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "validation precedes paging: {err:?}"
    );
    common::cleanup(&dir);
}

#[test]
fn limit_clips_at_1024() {
    let dir = common::tmpdir("bs-clip");
    let p = open_raw(&dir, "r.bin", &[0x90; 1100], 0x2000);
    let page = p.search_bytes("90", None, None, 0, 5000).expect("clipped");
    assert_eq!(page.total, 1100);
    assert_eq!(page.limit, 1024);
    assert_eq!(page.next_offset, Some(1024));
    assert_eq!(page.items.len(), 1024);
    assert_eq!(page.items[0].addr, 0x2000);
    assert_eq!(page.items[1023].addr, 0x2000 + 1023);
    let tail = p.search_bytes("90", None, None, 1024, 5000).expect("tail");
    assert_eq!(tail.total, 1100);
    assert_eq!(tail.items.len(), 76);
    assert_eq!(tail.next_offset, None);
    common::cleanup(&dir);
}

#[test]
fn invalid_patterns_error() {
    let dir = common::tmpdir("bs-invalid");
    let p = open_basic(&dir);
    for bad in [
        "", "   ", "??", "?? ??", "5", "abc", "zz", "0x55", "5?", "555", "48 8B ?", "48,8B",
    ] {
        let err = p.search_bytes(bad, None, None, 0, 10).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)), "{bad:?} got {err:?}");
    }
    let over = vec!["ab"; 4097].join(" ");
    assert!(matches!(
        p.search_bytes(&over, None, None, 0, 10).unwrap_err(),
        Error::Invalid(_)
    ));
    let max = vec!["ab"; 4096].join(" ");
    let page = p
        .search_bytes(&max, None, None, 0, 10)
        .expect("cap accepted");
    assert_eq!(
        page.total, 0,
        "overlong pattern finds nothing in a tiny fixture"
    );
    common::cleanup(&dir);
}

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}
fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}
fn put64(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

/// 64-bit LE ELF with two `PT_LOAD`s: `seg1` at `0x400000` (file bytes
/// `seg1.len()`, in-memory `seg1_memsz`) and `seg2` at `0x401000`, leaving
/// a VA gap between them.
fn two_seg_elf(seg1: &[u8], seg1_memsz: u64, seg2: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 0xB0];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2;
    f[5] = 1;
    f[6] = 1;
    put16(&mut f, 16, 2);
    put16(&mut f, 18, 62);
    put32(&mut f, 20, 1);
    put64(&mut f, 24, 0x400000);
    put64(&mut f, 32, 64);
    put16(&mut f, 52, 64);
    put16(&mut f, 54, 56);
    put16(&mut f, 56, 2);
    put32(&mut f, 64, 1);
    put32(&mut f, 68, 5);
    put64(&mut f, 72, 0xB0);
    put64(&mut f, 80, 0x400000);
    put64(&mut f, 88, 0x400000);
    put64(&mut f, 96, seg1.len() as u64);
    put64(&mut f, 104, seg1_memsz);
    put64(&mut f, 112, 0x1000);
    let off2 = 0xB0 + seg1.len() as u64;
    put32(&mut f, 120, 1);
    put32(&mut f, 124, 6);
    put64(&mut f, 128, off2);
    put64(&mut f, 136, 0x401000);
    put64(&mut f, 144, 0x401000);
    put64(&mut f, 152, seg2.len() as u64);
    put64(&mut f, 160, seg2.len() as u64);
    put64(&mut f, 168, 0x1000);
    f.extend_from_slice(seg1);
    f.extend_from_slice(seg2);
    f
}

fn open_elf_bytes(dir: &std::path::Path, name: &str, bytes: &[u8]) -> Project {
    let bin = common::write_bin(dir, name, bytes);
    let db = common::temp_db(dir, name);
    Project::open_with_db(&bin, &db).expect("synthetic ELF opens")
}

#[test]
fn gap_never_bridged() {
    let dir = common::tmpdir("bs-gap");
    let elf = two_seg_elf(&[0xAA; 16], 16, &[0xBB; 16]);
    let p = open_elf_bytes(&dir, "gap.elf", &elf);
    let span = p.search_bytes("AA BB", None, None, 0, 50).expect("span");
    assert_eq!(span.total, 0, "matches never cross the inter-segment gap");
    let span4 = p
        .search_bytes("AA AA BB BB", None, None, 0, 50)
        .expect("span4");
    assert_eq!(span4.total, 0);
    let left = p.search_bytes("AA AA", None, None, 0, 50).expect("left");
    assert_eq!(left.total, 15);
    assert!(left.items.iter().all(|m| m.addr < 0x400010));
    assert!(left.items.iter().all(|m| m.section.is_none()));
    assert!(left.items.iter().all(|m| m.file_off.is_none()));
    let right = p.search_bytes("BB BB", None, None, 0, 50).expect("right");
    assert_eq!(right.total, 15);
    assert!(right.items.iter().all(|m| m.addr >= 0x401000));
    common::cleanup(&dir);
}

#[test]
fn bss_never_materialized() {
    let dir = common::tmpdir("bs-bss");
    let mut data = vec![0xAA; 8];
    data.extend_from_slice(&[0x00; 8]);
    let elf = two_seg_elf(&data, 16 + 0x100, &[0xCC; 8]);
    let p = open_elf_bytes(&dir, "bss.elf", &elf);
    let wide = p
        .search_bytes(&["00"; 12].join(" "), None, None, 0, 10)
        .expect("wide zeros");
    assert_eq!(
        wide.total, 0,
        "8 file zeros plus virtual BSS must not form a 12-zero match"
    );
    let exact = p
        .search_bytes(&["00"; 8].join(" "), None, None, 0, 10)
        .expect("exact zeros");
    assert_eq!(exact.total, 1);
    assert_eq!(exact.items[0].addr, 0x400008);
    let bss_only = p
        .search_bytes("AA", None, Some((0x400010, 0x400110)), 0, 10)
        .expect("bss range");
    assert_eq!(
        bss_only.total, 0,
        "pure-BSS range holds no searchable bytes"
    );
    common::cleanup(&dir);
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn parse_ref(pat: &str) -> Vec<Option<u8>> {
    pat.split_whitespace()
        .map(|t| {
            if t == "??" {
                None
            } else {
                Some(u8::from_str_radix(t, 16).expect("test pattern is valid"))
            }
        })
        .collect()
}

fn reference(bytes: &[u8], base: u64, pat: &[Option<u8>], range: Option<(u64, u64)>) -> Vec<u64> {
    let mut out = Vec::new();
    if bytes.len() < pat.len() {
        return out;
    }
    for i in 0..=bytes.len() - pat.len() {
        if pat
            .iter()
            .zip(&bytes[i..i + pat.len()])
            .all(|(p, b)| p.is_none_or(|x| x == *b))
        {
            let va = base + i as u64;
            if let Some((lo, hi)) = range
                && (va < lo || va + pat.len() as u64 > hi)
            {
                continue;
            }
            out.push(va);
        }
    }
    out
}

#[test]
fn random_buffers_agree_with_reference() {
    let dir = common::tmpdir("bs-fuzz");
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for iter in 0..200 {
        let len = 1 + rng.below(256) as usize;
        let base = [0u64, 0x1000, 0x400000][rng.below(3) as usize];
        let mut bytes = vec![0u8; len];
        for b in &mut bytes {
            *b = rng.below(256) as u8;
        }
        let plen = 1 + rng.below(8) as usize;
        let mut toks = Vec::new();
        for _ in 0..plen {
            if rng.below(2) == 0 {
                toks.push("??".to_string());
            } else {
                toks.push(format!("{:02x}", rng.below(256)));
            }
        }
        toks[0] = format!("{:02x}", rng.below(256));
        let pat_str = toks.join(" ");
        let pat = parse_ref(&pat_str);
        for _ in 0..3.min(len) {
            let at = rng.below(len as u64) as usize;
            for (j, t) in pat.iter().enumerate() {
                if let Some(x) = t
                    && at + j < len
                {
                    bytes[at + j] = *x;
                }
            }
        }
        let range = (rng.below(2) == 0).then(|| {
            let a = base + rng.below(len as u64 + 4);
            let b = base + rng.below(len as u64 + 4);
            (a.min(b), a.max(b).max(a.min(b) + 1))
        });
        let p = open_raw(&dir, &format!("f{iter}.bin"), &bytes, base);
        let page = p
            .search_bytes(&pat_str, None, range, 0, 10000)
            .expect("search");
        let want = reference(&bytes, base, &pat, range);
        assert_eq!(
            page.total,
            want.len(),
            "iter {iter} pat {pat_str:?} range {range:?}"
        );
        let got: Vec<u64> = page.items.iter().map(|m| m.addr).collect();
        assert_eq!(got, want, "iter {iter} addresses");
        for (m, w) in page.items.iter().zip(want.iter()) {
            assert_eq!(m.addr, *w);
            assert_eq!(m.file_off, Some(w - base));
            assert!(m.section.is_none());
            assert_eq!(m.len, pat.len());
        }
        if want.len() > 3 {
            let k = 1 + rng.below(want.len() as u64 - 1) as usize;
            let p1 = p.search_bytes(&pat_str, None, range, 0, k).expect("p1");
            let p2 = p.search_bytes(&pat_str, None, range, k, 10000).expect("p2");
            assert_eq!(p1.total, want.len());
            assert_eq!(p1.next_offset, Some(k));
            let mut both: Vec<u64> = p1.items.iter().chain(&p2.items).map(|m| m.addr).collect();
            assert_eq!(both.len(), want.len());
            assert!(both.iter().all(|a| want.contains(a)));
            both.sort_unstable();
            let mut sorted = want.clone();
            sorted.sort_unstable();
            assert_eq!(both, sorted);
        }
    }
    common::cleanup(&dir);
}

#[test]
fn search_never_writes() {
    let dir = common::tmpdir("bs-readonly");
    let bin = common::write_bin(&dir, "r.bin", &[0x90, 0x90, 0xC3]);
    let before = std::fs::read(&bin).expect("read binary");
    let db = common::temp_db(&dir, "fresh");
    let p = Project::open_with_db(&bin, &db).expect("open");
    let _ = p.search_bytes("90", None, None, 0, 10).expect("search");
    let _ = p.search_bytes("??", None, None, 0, 10).unwrap_err();
    let _ = p.search_bytes("90", Some("nope"), None, 0, 10).unwrap_err();
    assert!(!db.exists(), "searches never create the sidecar");
    assert_eq!(std::fs::read(&bin).expect("reread"), before);
    common::cleanup(&dir);
}
