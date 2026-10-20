//! em6.3: x86-64 non-PIE absolute imm32/disp32 data refs.
//!
//! A minimal two-segment ELF64 (`ET_EXEC`, base `0x400000`): `.text` (R+X)
//! references a `.rodata` (R-only) string three ways — `mov edi, imm32`
//! (`bf`), `mov edi, [abs32]` (SIB disp32), `lea edi, [abs32]` — and each
//! must recover a data xref plus a string xref. Unmapped small constants
//! stay xref-free via the analysis mapped check.

mod common;

use std::process::Command;

use binscout::analysis::XrefKind;
use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

const TEXT_VA: u64 = 0x400000;
const RODATA_VA: u64 = 0x402000;
const MARKER: &str = "NOPIE_HELLO_STR";

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn put64(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

/// Minimal non-PIE ELF64: `.text` at `TEXT_VA` references `RODATA_VA`
/// three ways; `.rodata` holds [`MARKER`] NUL-terminated.
fn nopie_elf() -> Vec<u8> {
    let str32 = RODATA_VA as u32;
    let mut text = Vec::new();
    text.push(0xBF); // mov edi, imm32
    text.extend_from_slice(&str32.to_le_bytes());
    text.extend_from_slice(&[0x8B, 0x3C, 0x25]); // mov edi, [abs32]
    text.extend_from_slice(&str32.to_le_bytes());
    text.extend_from_slice(&[0x8D, 0x3C, 0x25]); // lea edi, [abs32]
    text.extend_from_slice(&str32.to_le_bytes());
    text.push(0xC3); // ret
    assert_eq!(text.len(), 20);

    let mut rodata = MARKER.as_bytes().to_vec();
    rodata.push(0);

    let text_off = 64 + 2 * 56;
    let rodata_off = text_off + text.len();

    let mut f = vec![0u8; text_off];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2; // 64-bit
    f[5] = 1; // little-endian
    f[6] = 1; // version
    put16(&mut f, 16, 2); // ET_EXEC (non-PIE)
    put16(&mut f, 18, 62); // EM_X86_64
    put32(&mut f, 20, 1); // version
    put64(&mut f, 24, TEXT_VA); // entry
    put64(&mut f, 32, 64); // phoff
    put16(&mut f, 52, 64); // ehsize
    put16(&mut f, 54, 56); // phentsize
    put16(&mut f, 56, 2); // phnum

    let p = 64;
    put32(&mut f, p, 1); // PT_LOAD (.text)
    put32(&mut f, p + 4, 5); // R+X
    put64(&mut f, p + 8, text_off as u64);
    put64(&mut f, p + 16, TEXT_VA);
    put64(&mut f, p + 24, TEXT_VA);
    put64(&mut f, p + 32, text.len() as u64);
    put64(&mut f, p + 40, text.len() as u64);
    put64(&mut f, p + 48, 0x1000);

    let q = 64 + 56;
    put32(&mut f, q, 1); // PT_LOAD (.rodata)
    put32(&mut f, q + 4, 4); // R-only
    put64(&mut f, q + 8, rodata_off as u64);
    put64(&mut f, q + 16, RODATA_VA);
    put64(&mut f, q + 24, RODATA_VA);
    put64(&mut f, q + 32, rodata.len() as u64);
    put64(&mut f, q + 40, rodata.len() as u64);
    put64(&mut f, q + 48, 0x1000);

    f.extend_from_slice(&text);
    f.extend_from_slice(&rodata);
    f
}

#[test]
fn nopie_absolute_refs_recover_data_and_string_xrefs() {
    let dir = tmpdir("nopie-abs");
    let bytes = nopie_elf();
    let bin = write_bin(&dir, "nopie-x64.elf", &bytes);
    let db = temp_db(&dir, "nopie");
    let p = binscout::Project::open_with_db(&bin, &db).expect("non-PIE ELF must open");
    assert_eq!(p.binary().arch, binscout::disasm::Arch::X86_64);

    assert!(
        p.analysis()
            .strings
            .iter()
            .any(|h| h.value == MARKER && h.vaddr == Some(RODATA_VA)),
        "marker string must be recovered: {:?}",
        p.analysis().strings
    );

    let to: Vec<_> = p.analysis().xrefs_to(RODATA_VA);
    let data: Vec<_> = to.iter().filter(|x| x.kind == XrefKind::Data).collect();
    let strings: Vec<_> = to.iter().filter(|x| x.kind == XrefKind::String).collect();
    assert_eq!(data.len(), 3, "one data ref per absolute shape: {to:?}");
    assert_eq!(
        strings.len(),
        3,
        "one string ref per absolute shape: {to:?}"
    );
    let mut froms: Vec<u64> = data.iter().map(|x| x.from).collect();
    froms.sort_unstable();
    assert_eq!(froms, [TEXT_VA, TEXT_VA + 5, TEXT_VA + 12]);

    // Small unmapped constants never become xrefs: the mapped check in
    // Pass D filters them even though the decoder reports immediates.
    assert!(p.analysis().xrefs_to(0).is_empty());
    assert!(p.analysis().xrefs_to(1).is_empty());

    cleanup(&dir);
}

#[test]
fn nopie_absolute_refs_visible_via_cli() {
    let dir = tmpdir("nopie-cli");
    let bin = write_bin(&dir, "nopie-x64.elf", &nopie_elf());
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "cli").display().to_string();
    let to_hex = format!("{RODATA_VA:#x}");

    let out = Command::new(binscout_bin())
        .args(["--db", &db, "xrefs", &bin_s, "--to", &to_hex])
        .output()
        .expect("spawn binscout");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON value");
    assert_eq!(v["total"], 6, "{v}");
    let kinds: Vec<String> = v["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|x| x["kind"].as_str().expect("kind string").to_string())
        .collect();
    assert_eq!(
        kinds.iter().filter(|k| k.as_str() == "Data").count(),
        3,
        "{v}"
    );
    assert_eq!(
        kinds.iter().filter(|k| k.as_str() == "String").count(),
        3,
        "{v}"
    );

    cleanup(&dir);
}
