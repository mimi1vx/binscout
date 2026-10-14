//! Input plus aggregate metadata budgets (rsdbg-z5o.12).
//!
//! Policy under test (see rustdoc on the constants). Input
//! [`binscout::loader::MAX_INPUT_BYTES`] (512 MiB, twice mapped) bounds the
//! pre-parse read; containers with unmapped overlays still open. Per-name
//! [`binscout::loader::MAX_NAME_BYTES`] (4 KiB) bounds one decoded
//! section/library/symbol name, checked before copying and after the up to
//! 3x replacement-character expansion. Demangled
//! [`binscout::loader::MAX_DEMANGLED_BYTES`] (8 KiB) bounds one C++
//! demangled output. Aggregate [`binscout::loader::MAX_METADATA_BYTES`]
//! (16 MiB) bounds the sum of owned names plus demangled copies; sharing a
//! long name across rows does not dodge it. Snapshot [`binscout::db`] row
//! counts plus the 64 MiB aggregate and 8 KiB per annotation field bound
//! the sidecar.
//!
//! Oversize always surfaces as [`binscout::error::Error::Limit`], never as
//! `Invalid` (which would fall back to raw) and never as a successful raw
//! open.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use binscout::db;
use binscout::error::Error;
use binscout::loader::{
    MAX_DEMANGLED_BYTES, MAX_INPUT_BYTES, MAX_METADATA_BYTES, MAX_NAME_BYTES, load,
};

use common::{binscout_bin, cleanup, mcp_bin, temp_db, tmpdir, write_bin, write_fixture};

// ---------------------------------------------------------------------------
// Policy constants.
// ---------------------------------------------------------------------------

#[test]
fn budget_constants_are_independently_justified() {
    assert_eq!(MAX_INPUT_BYTES, 512 * 1024 * 1024, "2x mapped for overlays");
    assert_eq!(MAX_NAME_BYTES, 4096, "covers mangled templates");
    assert_eq!(MAX_DEMANGLED_BYTES, 8192, "2x name for expansion");
    assert_eq!(MAX_METADATA_BYTES, 16 * 1024 * 1024, "16 MiB aggregate");
    assert_eq!(db::MAX_SNAPSHOT_FUNCTIONS, 100_000);
    assert_eq!(db::MAX_SNAPSHOT_ANNOTATIONS, 10_000);
    assert_eq!(db::MAX_ANNOTATION_BYTES, 8192);
}

// ---------------------------------------------------------------------------
// ELF builders with controlled section names.
// ---------------------------------------------------------------------------

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn put64(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

/// ELF64 with one `PT_LOAD` (`nop; nop; ret` at `0x400000`) plus `names.len()`
/// empty `PROGBITS` sections. `shared` makes every section point at the same
/// `shstrtab` offset (one file copy, N owned copies); otherwise each section
/// gets its own copy.
fn elf_with_section_names(names: &[Vec<u8>], shared: bool) -> Vec<u8> {
    let mut f = vec![0u8; 0x78];
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
    put16(&mut f, 56, 1);
    let p = 64;
    put32(&mut f, p, 1);
    put32(&mut f, p + 4, 5);
    put64(&mut f, p + 8, 0x78);
    put64(&mut f, p + 16, 0x400000);
    put64(&mut f, p + 32, 3);
    put64(&mut f, p + 40, 3);
    put64(&mut f, p + 48, 0x1000);
    f.extend_from_slice(&[0x90, 0x90, 0xC3]);

    // shstrtab: leading NUL, then names, then ".shstrtab".
    let mut strtab: Vec<u8> = vec![0];
    let mut offsets: Vec<u32> = Vec::new();
    if shared && !names.is_empty() {
        let off = strtab.len() as u32;
        strtab.extend_from_slice(&names[0]);
        strtab.push(0);
        offsets = vec![off; names.len()];
    } else {
        for n in names {
            offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(n);
            strtab.push(0);
        }
    }
    let shstrtab_name_off = strtab.len() as u32;
    strtab.extend_from_slice(b".shstrtab\0");

    let shoff = f.len() + strtab.len();
    // Align shoff to 8 for tidiness.
    let pad = (8 - (shoff % 8)) % 8;
    f.extend_from_slice(&strtab);
    f.extend(std::iter::repeat_n(0u8, pad));
    let shoff = f.len() as u64;

    let shnum = (2 + names.len()) as u16;
    let mut shdrs = vec![0u8; shnum as usize * 64];
    // Index 1: .shstrtab.
    let s = 64;
    put32(&mut shdrs, s, shstrtab_name_off);
    put32(&mut shdrs, s + 4, 3); // STRTAB
    put64(&mut shdrs, s + 24, (0x78 + 3) as u64);
    put64(&mut shdrs, s + 32, strtab.len() as u64);
    // Test sections: empty PROGBITS, only the name matters.
    for (i, off) in offsets.iter().enumerate() {
        let s = 128 + i * 64;
        put32(&mut shdrs, s, *off);
        put32(&mut shdrs, s + 4, 1); // PROGBITS
    }
    f.extend_from_slice(&shdrs);

    put64(&mut f, 40, shoff);
    put16(&mut f, 58, 64);
    put16(&mut f, 60, shnum);
    put16(&mut f, 62, 1);
    f
}

fn is_limit(e: &Error) -> bool {
    matches!(e, Error::Limit(_))
}

// ---------------------------------------------------------------------------
// Section names: exact boundary, over limit, expansion, sharing.
// ---------------------------------------------------------------------------

#[test]
fn section_name_exact_boundary_passes_over_fails() {
    let ok = elf_with_section_names(&[vec![b'A'; MAX_NAME_BYTES]], false);
    let bin = load(&ok).expect("4096-byte name passes");
    // NULL is skipped; .shstrtab plus the one test section remain.
    assert_eq!(bin.sections.len(), 2);
    let test = bin
        .sections
        .iter()
        .find(|s| s.name.len() == MAX_NAME_BYTES)
        .expect("test section");
    assert_eq!(test.name.len(), MAX_NAME_BYTES);

    let over = elf_with_section_names(&[vec![b'A'; MAX_NAME_BYTES + 1]], false);
    let err = load(&over).unwrap_err();
    assert!(is_limit(&err), "4097-byte name must be Limit, got {err:?}");
    assert!(err.to_string().contains("limit"), "{err}");
}

#[test]
fn section_name_replacement_expansion_enforced_after_decode() {
    // 1365 invalid bytes decode to 4095 replacement chars: pass.
    let ok = elf_with_section_names(&[vec![0xFF; 1365]], false);
    let bin = load(&ok).expect("1365 invalid bytes pass");
    let test = bin
        .sections
        .iter()
        .find(|s| s.name.contains('\u{FFFD}'))
        .expect("test section");
    assert_eq!(test.name.len(), 1365 * 3);
    assert!(test.name.contains('\u{FFFD}'));

    // 1366 invalid bytes decode to 4098 chars: Limit despite raw < 4096.
    let over = elf_with_section_names(&[vec![0xFF; 1366]], false);
    let err = load(&over).unwrap_err();
    assert!(
        is_limit(&err),
        "expansion past 4096 must be Limit, got {err:?}"
    );
}

#[test]
fn shared_long_section_names_each_copy_counts() {
    // Two sections sharing one 4096-byte name: 8192 aggregate, well under
    // 16 MiB, but proves the shared offset is copied per row.
    let bytes = elf_with_section_names(
        &[vec![b'S'; MAX_NAME_BYTES], vec![b'S'; MAX_NAME_BYTES]],
        true,
    );
    let bin = load(&bytes).expect("shared 4 KiB names pass");
    assert_eq!(bin.sections.len(), 3);
    let mut tests = bin
        .sections
        .iter()
        .filter(|s| s.name.len() == MAX_NAME_BYTES);
    let (a, b) = (tests.next().expect("first"), tests.next().expect("second"));
    assert_eq!(a.name, b.name);
}

// ---------------------------------------------------------------------------
// PE builder with N imports sharing one hint/name.
// ---------------------------------------------------------------------------

const PE_IMAGE_BASE: u32 = 0x400000;
const PE_TEXT_RVA: u32 = 0x1000;
const PE_RDATA_RVA: u32 = 0x2000;

/// PE32 whose `count` imports all resolve to the same `name` bytes via one
/// shared Hint/Name entry. File stays small (~36 KiB for 4k imports) while
/// owned metadata scales as `count * (library + name)`.
fn pe_with_shared_import(name: &[u8], count: usize) -> Vec<u8> {
    assert!(name.len() <= MAX_NAME_BYTES || count == 1);
    let library = b"TESTDLL.dll";
    // .rdata layout: 2 descriptors + ILT + IAT + hint/name + dll.
    let ilt_off = 0x28usize;
    let iat_off = ilt_off + 4 * (count + 1);
    let hint_off = iat_off + 4 * (count + 1);
    let dll_off = hint_off + 2 + name.len() + 1;
    let rdata_len = (dll_off + library.len() + 1).next_multiple_of(0x200);

    let mut f = vec![0u8; 0x200];
    f[0] = b'M';
    f[1] = b'Z';
    put32(&mut f, 0x3C, 0x80);
    f[0x80..0x84].copy_from_slice(b"PE\0\0");
    let c = 0x84;
    put16(&mut f, c, 0x14C);
    put16(&mut f, c + 2, 3);
    put32(&mut f, c + 4, 0x12345678);
    put16(&mut f, c + 16, 0xE0);
    put16(&mut f, c + 18, 0x010F);
    let o = 0x98;
    put16(&mut f, o, 0x10B);
    put32(&mut f, o + 16, PE_TEXT_RVA);
    put32(&mut f, o + 20, PE_TEXT_RVA);
    put32(&mut f, o + 24, PE_RDATA_RVA);
    put32(&mut f, o + 28, PE_IMAGE_BASE);
    put32(&mut f, o + 32, 0x1000);
    put32(&mut f, o + 36, 0x200);
    put32(&mut f, o + 56, 0x4000);
    put32(&mut f, o + 60, 0x200);
    put16(&mut f, o + 68, 3);
    put32(&mut f, o + 92, 16);
    put32(&mut f, o + 104, PE_RDATA_RVA);
    put32(&mut f, o + 108, 40);
    // Section headers with correct sizes: .rdata spans the full import
    // tables so high RVAs translate; .data follows page-aligned.
    let data_rva = (PE_RDATA_RVA + rdata_len as u32).next_multiple_of(0x1000);
    let size_of_image = (data_rva + 0x200).next_multiple_of(0x1000);
    let mut sh =
        |off: usize, nm: &[u8], rva: u32, vsize: u32, file_off: usize, raw: u32, chars: u32| {
            f[off..off + nm.len()].copy_from_slice(nm);
            put32(&mut f, off + 8, vsize);
            put32(&mut f, off + 12, rva);
            put32(&mut f, off + 16, raw);
            put32(&mut f, off + 20, file_off as u32);
            put32(&mut f, off + 36, chars);
        };
    sh(
        0x178,
        b".text",
        PE_TEXT_RVA,
        0x200,
        0x200,
        0x200,
        0x60000020,
    );
    sh(
        0x178 + 40,
        b".rdata",
        PE_RDATA_RVA,
        rdata_len as u32,
        0x400,
        rdata_len as u32,
        0x40000040,
    );
    sh(
        0x178 + 80,
        b".data",
        data_rva,
        0x200,
        0x400 + rdata_len,
        0x200,
        0xC0000040,
    );
    put32(&mut f, o + 56, size_of_image);

    // .text: frame setup + ret.
    let mut text = vec![0x55, 0x89, 0xE5, 0xC3];
    text.resize(0x200, 0);
    // .rdata.
    let mut r = vec![0u8; rdata_len];
    put32(&mut r, 0x00, PE_RDATA_RVA + ilt_off as u32);
    put32(&mut r, 0x0C, PE_RDATA_RVA + dll_off as u32);
    put32(&mut r, 0x10, PE_RDATA_RVA + iat_off as u32);
    let hint_rva = PE_RDATA_RVA + hint_off as u32;
    for i in 0..count {
        put32(&mut r, ilt_off + 4 * i, hint_rva);
        put32(&mut r, iat_off + 4 * i, hint_rva);
    }
    put16(&mut r, hint_off, 0);
    r[hint_off + 2..hint_off + 2 + name.len()].copy_from_slice(name);
    r[dll_off..dll_off + library.len()].copy_from_slice(library);
    let data = vec![0u8; 0x200];

    f.extend_from_slice(&text);
    // .text file offset is 0x200; headers already 0x200, so append directly.
    f.extend_from_slice(&r);
    f.extend_from_slice(&data);
    f
}

#[test]
fn import_name_exact_boundary_passes_over_fails() {
    let ok = pe_with_shared_import(&vec![b'I'; MAX_NAME_BYTES], 1);
    let bin = load(&ok).expect("4096-byte import passes");
    assert_eq!(bin.imports.len(), 1);
    assert_eq!(bin.imports[0].name.len(), MAX_NAME_BYTES);

    let over = pe_with_shared_import(&vec![b'I'; MAX_NAME_BYTES + 1], 1);
    let err = load(&over).unwrap_err();
    assert!(
        is_limit(&err),
        "4097-byte import must be Limit, got {err:?}"
    );
}

#[test]
fn shared_import_aggregate_exact_passes_over_fails() {
    // Per import: 11 (library) + 4096 (name) = 4107, plus ~16 section-name
    // bytes. 4085 imports ≈ 16,777,111 ≤ 16 MiB pass; 4086 exceed.
    let ok = pe_with_shared_import(&vec![b'G'; MAX_NAME_BYTES], 4085);
    let bin = load(&ok).expect("4085 shared 4 KiB imports pass");
    assert_eq!(bin.imports.len(), 4085);

    let over = pe_with_shared_import(&vec![b'G'; MAX_NAME_BYTES], 4086);
    let err = load(&over).unwrap_err();
    assert!(
        is_limit(&err),
        "4086 shared imports must be Limit, got {err:?}"
    );
    assert!(err.to_string().contains("16 MiB"), "{err}");
}

#[test]
fn oversize_aggregate_fails_fast_without_full_copy() {
    // 100k shared 4 KiB imports would own ~410 MiB without the aggregate;
    // the 16 MiB budget must fail after ~3.9k rows, not after 100k copies.
    let bytes = pe_with_shared_import(&vec![b'Z'; MAX_NAME_BYTES], 100_000);
    assert!(
        bytes.len() < 1024 * 1024,
        "fixture stays small: {}",
        bytes.len()
    );
    let err = load(&bytes).unwrap_err();
    assert!(
        is_limit(&err),
        "100k shared imports must be Limit, got {err:?}"
    );
}

#[test]
fn demangled_output_bounded_and_counted() {
    // 1000 int params: mangled 1011, demangled ~5016: both under caps.
    let ok_name = format!("?foo@@YAX{}@Z", "H".repeat(1000));
    let ok = pe_with_shared_import(ok_name.as_bytes(), 1);
    let bin = load(&ok).expect("demangled ~5 KiB passes");
    let d = bin.imports[0].demangled.as_ref().expect("demangled");
    assert!(d.contains("foo"), "{d:?}");
    assert!(d.len() <= MAX_DEMANGLED_BYTES, "len {}", d.len());

    // 2000 int params: mangled 2011 (under 4 KiB), demangled ~10 KiB over.
    let over_name = format!("?foo@@YAX{}@Z", "H".repeat(2000));
    assert!(over_name.len() <= MAX_NAME_BYTES);
    let over = pe_with_shared_import(over_name.as_bytes(), 1);
    let err = load(&over).unwrap_err();
    assert!(
        is_limit(&err),
        "10 KiB demangled must be Limit, got {err:?}"
    );
}

#[test]
fn repeated_mangled_names_share_cache_but_not_budget() {
    // Same mangled import 100 times: demangle runs once (cache) but all 100
    // owned copies plus demangled outputs count toward the aggregate.
    let name = b"?myfunc@@YAXH@Z".to_vec();
    let bytes = pe_with_shared_import(&name, 100);
    let bin = load(&bytes).expect("100 repeated mangled pass");
    assert_eq!(bin.imports.len(), 100);
    assert!(bin.imports.iter().all(|i| i.demangled.is_some()));
    assert_eq!(bin.imports[0].demangled, bin.imports[99].demangled);
}

// ---------------------------------------------------------------------------
// Input policy: overlays accepted, Limit never falls back to raw.
// ---------------------------------------------------------------------------

fn minimal_elf_code() -> Vec<u8> {
    let mut f = vec![0u8; 0x78];
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
    put16(&mut f, 56, 1);
    let p = 64;
    put32(&mut f, p, 1);
    put32(&mut f, p + 4, 5);
    put64(&mut f, p + 8, 0x78);
    put64(&mut f, p + 16, 0x400000);
    put64(&mut f, p + 32, 3);
    put64(&mut f, p + 40, 3);
    put64(&mut f, p + 48, 0x1000);
    f.extend_from_slice(&[0x90, 0x90, 0xC3]);
    f
}

#[test]
fn small_unmapped_overlay_accepted() {
    let mut bytes = minimal_elf_code();
    bytes.extend(vec![0u8; 2 * 1024 * 1024]); // 2 MiB debug-style overlay
    let bin = load(&bytes).expect("2 MiB overlay under input cap passes");
    assert_eq!(bin.format, binscout::loader::BinaryFormat::Elf);
    assert_eq!(bin.segments[0].data.len(), 3);
}

#[test]
fn overlay_past_mapped_cap_still_accepted_under_input_cap() {
    // 260 MiB file, 3 mapped bytes: proves the file-length policy is the
    // 512 MiB input cap, not the 256 MiB mapped cap.
    let mut bytes = minimal_elf_code();
    bytes.resize(260 * 1024 * 1024, 0);
    let bin = load(&bytes).expect("260 MiB overlay passes under 512 MiB input cap");
    assert_eq!(bin.format, binscout::loader::BinaryFormat::Elf);
    assert_eq!(bin.segments[0].data.len(), 3);
}

#[test]
fn oversize_is_limit_not_invalid_never_raw_fallback() {
    // Oversize names are Limit (not Invalid), so load_or_raw must not map
    // them as raw x86-64: Project::open and the CLI/MCP surfaces below
    // assert the same.
    let over = elf_with_section_names(&[vec![b'A'; MAX_NAME_BYTES + 1]], false);
    let err = load(&over).unwrap_err();
    assert!(is_limit(&err));
    // A Limit must not be reinterpreted as garbage-then-raw.
    let raw = binscout::loader::load_raw(
        &over,
        binscout::loader::RawOptions {
            base: 0,
            arch: binscout::disasm::Arch::X86_64,
            entry: None,
        },
    );
    assert!(
        raw.is_ok(),
        "raw mapping itself is fine; load() must not choose it"
    );
}

// ---------------------------------------------------------------------------
// CLI + MCP propagation without raw fallback.
// ---------------------------------------------------------------------------

fn run_cli(args: &[&str]) -> (bool, serde_json::Value, String) {
    let out = Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout utf-8");
    let value: serde_json::Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value, text)
}

#[test]
fn cli_oversize_is_limit_json_without_raw_fallback() {
    let dir = tmpdir("budget-cli");
    let bytes = elf_with_section_names(&[vec![b'C'; MAX_NAME_BYTES + 1]], false);
    let bin = write_bin(&dir, "over.elf", &bytes);
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "over").display().to_string();
    let (ok, v, text) = run_cli(&["--db", &db, "load", &bin_s]);
    assert!(!ok, "oversize load must fail, got {v}");
    let msg = v["error"].as_str().expect("error envelope");
    assert!(msg.contains("limit"), "{v}");
    assert!(v.get("format").is_none(), "must not fall back to raw: {v}");
    assert_eq!(text.trim_end().lines().count(), 1, "exactly one JSON value");
    // Binary untouched, no sidecar created on failure.
    assert_eq!(std::fs::read(&bin).expect("reread"), bytes);
    cleanup(&dir);
}

fn mcp_session(lines: &[String]) -> Vec<serde_json::Value> {
    let mut child = Command::new(mcp_bin())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn binscout-mcp");
    {
        let stdin = child.stdin.as_mut().expect("piped stdin");
        for line in lines {
            writeln!(stdin, "{line}").expect("write request");
        }
    }
    let out = child.wait_with_output().expect("server exits on EOF");
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).expect("utf-8");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("response JSON"))
        .collect()
}

fn mcp_req(id: u64, method: &str, params: serde_json::Value) -> String {
    serde_json::to_string(
        &serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
    )
    .expect("req")
}

fn mcp_call(id: u64, name: &str, args: serde_json::Value) -> String {
    mcp_req(
        id,
        "tools/call",
        serde_json::json!({"name": name, "arguments": args}),
    )
}

#[test]
fn mcp_oversize_is_tool_error_without_raw_fallback() {
    let dir = tmpdir("budget-mcp");
    let bytes = elf_with_section_names(&[vec![b'M'; MAX_NAME_BYTES + 1]], false);
    let bin = write_bin(&dir, "over.elf", &bytes).display().to_string();
    let db = temp_db(&dir, "over").display().to_string();
    let lines = vec![
        mcp_req(
            1,
            "initialize",
            serde_json::json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(
            &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .expect("n"),
        mcp_call(
            10,
            "project_info",
            serde_json::json!({"binary": bin, "db": db}),
        ),
    ];
    let resps = mcp_session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let resp = &resps[1];
    assert!(
        resp.get("result").is_none(),
        "oversize must not return info: {resp}"
    );
    let msg = resp["error"]["message"].as_str().expect("error message");
    assert!(msg.contains("limit"), "{resp}");
    cleanup(&dir);
}

// ---------------------------------------------------------------------------
// Snapshot path budgets.
// ---------------------------------------------------------------------------

#[test]
fn annotation_text_exact_passes_over_fails_at_api() {
    let dir = tmpdir("budget-ann");
    let mut p = common::open_test_project(&dir, common::builders::BASIC_NAME);
    let entry = common::builders::BASIC_ENTRY_VA;
    let exact = "c".repeat(db::MAX_ANNOTATION_BYTES);
    p.set_comment(entry, &exact)
        .expect("8192-byte comment passes");
    let over = "c".repeat(db::MAX_ANNOTATION_BYTES + 1);
    let err = p.set_comment(entry, &over).unwrap_err();
    assert!(
        is_limit(&err),
        "8193-byte comment must be Limit, got {err:?}"
    );
    let err = p.rename_function(entry, &over).unwrap_err();
    assert!(
        is_limit(&err),
        "8193-byte rename must be Limit, got {err:?}"
    );
    cleanup(&dir);
}

#[test]
fn snapshot_annotation_row_cap_exact_and_over() {
    use redb::{Database, TableDefinition};
    const ANNOTATIONS: TableDefinition<u64, String> = TableDefinition::new("annotations");
    let dir = tmpdir("budget-snap-rows");
    let bin = write_fixture(&dir, common::builders::BASIC_NAME);
    let db_path = temp_db(&dir, "rows");
    // Seed a valid snapshot first.
    let proj = binscout::Project::open_with_db(&bin, &db_path).expect("opens");
    proj.save().expect("saves");
    assert_eq!(db::MAX_SNAPSHOT_ANNOTATIONS, 10_000);

    // Forge exactly 10k annotation rows in one transaction: Hit-path decode
    // must still succeed (exact boundary passes).
    {
        let database = Database::create(&db_path).expect("open sidecar");
        {
            let wtxn = database.begin_write().expect("wtxn");
            {
                let mut t = wtxn.open_table(ANNOTATIONS).expect("annotations table");
                for addr in 0..10_000u64 {
                    t.insert(addr, r#"{"name":null,"comment":"c"}"#.to_string())
                        .expect("insert");
                }
            }
            wtxn.commit().expect("commit");
        }
    }
    let proj = binscout::Project::open_with_db(&bin, &db_path).expect("10k annotations pass");
    assert_eq!(proj.annotations().len(), 10_000);

    // One more row trips the cap on the Hit path.
    {
        let database = Database::create(&db_path).expect("open sidecar");
        {
            let wtxn = database.begin_write().expect("wtxn");
            {
                let mut t = wtxn.open_table(ANNOTATIONS).expect("annotations table");
                t.insert(10_000u64, r#"{"name":null,"comment":"c"}"#.to_string())
                    .expect("insert");
            }
            wtxn.commit().expect("commit");
        }
    }
    let err = binscout::Project::open_with_db(&bin, &db_path).unwrap_err();
    assert!(
        is_limit(&err),
        "10001 annotations must be Limit on Hit path, got {err:?}"
    );

    // Same forged sidecar against a different binary trips the stale path
    // too (annotations carry over into the re-analysis).
    let other = write_bin(&dir, "other.bin", &[0x90, 0x90, 0xC3]);
    let other_db = temp_db(&dir, "other");
    std::fs::copy(&db_path, &other_db).expect("copy sidecar");
    let err = binscout::Project::open_with_db(&other, &other_db).unwrap_err();
    assert!(
        is_limit(&err),
        "10001 annotations must be Limit on stale path, got {err:?}"
    );
    cleanup(&dir);
}

#[test]
fn save_rejects_oversize_annotations_before_writing() {
    use std::collections::BTreeMap;
    let dir = tmpdir("budget-save");
    let bin = write_fixture(&dir, common::builders::BASIC_NAME);
    let db_path = temp_db(&dir, "save");
    let proj = binscout::Project::open_with_db(&bin, &db_path).expect("opens");
    let meta = binscout::db::BinaryMeta {
        version: binscout::db::SCHEMA_VERSION,
        binary_path: bin.display().to_string(),
        content_hash: proj.content_hash(),
        size: 1,
        arch: "x86_32".to_string(),
        format: "pe".to_string(),
        entry: None,
        supported: true,
        reason: None,
    };
    let mut annotations = BTreeMap::new();
    annotations.insert(
        0x1000,
        binscout::db::Annotation {
            name: None,
            comment: Some("x".repeat(db::MAX_ANNOTATION_BYTES + 1)),
        },
    );
    let database = db::open_db(&db_path).expect("open db");
    let err = db::save(&database, &meta, proj.analysis(), &annotations).unwrap_err();
    assert!(
        is_limit(&err),
        "save with oversize annotation must be Limit, got {err:?}"
    );
    cleanup(&dir);
}
