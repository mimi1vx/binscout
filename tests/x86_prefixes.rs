//! CET/MPX/HLE prefix words: iced-x86 folds `notrack`, `bnd`,
//! `xacquire` and `xrelease` into the formatted text, so the strip in
//! `split_asm` must remove them (possibly stacked) before the mnemonic is
//! read. Without the strip these decode as bogus `notrack`/`bnd` mnemonics
//! that lift to `Nop` and classify as fallthrough.

mod common;

use std::process::Command;

use binscout::Project;
use binscout::analysis::{DiagnosticKind, XrefKind, analyze_raw};
use binscout::disasm::{Arch, disasm_range};
use binscout::ir::{IrOp, lift};
use binscout::loader::RawOptions;

use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

fn x86(bytes: &[u8], va: u64) -> Vec<binscout::disasm::Insn> {
    disasm_range(Arch::X86_64, bytes, va, 100).expect("valid x86_64 must decode")
}

fn x64(bytes: &[u8], base: u64, entry: Option<u64>) -> binscout::analysis::Analysis {
    analyze_raw(bytes, base, Arch::X86_64, entry).expect("synthetic blob must analyze")
}

#[test]
fn cet_mpx_prefixes_expose_real_mnemonic() {
    // notrack jmp rax (CET indirect-branch landing).
    let v = x86(&[0x3E, 0xFF, 0xE0], 0x1000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "jmp");
    assert_eq!(v[0].ops, ["rax"]);
    // bnd jmp indirect (MPX PLT stub shape).
    let v = x86(&[0xF2, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00], 0x1000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "jmp");
    // bnd ret still returns, with no operands.
    let v = x86(&[0xF2, 0xC3], 0x1000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "ret");
    assert!(v[0].ops.is_empty());
    // bnd call rel32 keeps its branch target.
    let v = x86(&[0xF2, 0xE8, 0x00, 0x00, 0x00, 0x00], 0x1000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "call");
    assert_eq!(v[0].branch_target, Some(0x1006));
}

#[test]
fn stacked_prefixes_strip_fully() {
    // bnd + notrack stacked on one jump.
    let v = x86(&[0xF2, 0x3E, 0xFF, 0xE0], 0x1000);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].mnem, "jmp");
    assert_eq!(v[0].ops, ["rax"]);
    // HLE words stack with lock: xacquire/xrelease + lock add.
    for bytes in [&[0xF2, 0xF0, 0x01, 0x08][..], &[0xF3, 0xF0, 0x01, 0x08][..]] {
        let v = x86(bytes, 0x1000);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mnem, "add");
        assert_eq!(v[0].ops, ["[rax]", "ecx"]);
    }
}

#[test]
fn prefixed_branches_lift_without_warnings() {
    let insns = x86(&[0x3E, 0xFF, 0xE0], 0x1000);
    let v = lift(Arch::X86_64, &insns[0]);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].op, IrOp::Branch);
    assert_eq!(v[0].inputs, ["rax"]);
    assert_eq!(v[0].warning, None);
    let insns = x86(&[0xF2, 0xC3], 0x1000);
    let v = lift(Arch::X86_64, &insns[0]);
    assert_eq!(v[0].op, IrOp::Return);
    assert_eq!(v[0].warning, None);
    let insns = x86(&[0xF2, 0xE8, 0x00, 0x00, 0x00, 0x00], 0x1000);
    let v = lift(Arch::X86_64, &insns[0]);
    assert_eq!(v[0].op, IrOp::Call);
    assert_eq!(v[0].target, Some(0x1006));
    assert_eq!(v[0].warning, None);
}

#[test]
fn notrack_jmp_is_an_unresolved_indirect_jump() {
    let a = x64(&[0x3E, 0xFF, 0xE0], 0x1000, Some(0x1000));
    let sites: Vec<_> = a
        .diagnostics
        .records
        .iter()
        .map(|d| (d.addr, d.kind))
        .collect();
    assert_eq!(sites, [(0x1000, DiagnosticKind::UnresolvedIndirectJump)]);
    assert_eq!(a.functions[&0x1000].insn_count(), 1);
    assert!(a.functions[&0x1000].edges().is_empty());
    assert!(a.call_edges().is_empty());
}

#[test]
fn bnd_ret_ends_the_block() {
    // bnd ret followed by a nop: the nop is unreachable, so the function
    // holds one instruction in one successor-free block.
    let a = x64(&[0xF2, 0xC3, 0x90], 0x1000, Some(0x1000));
    assert!(a.diagnostics.records.is_empty());
    let f = &a.functions[&0x1000];
    assert_eq!(f.insn_count(), 1);
    assert_eq!(f.blocks.len(), 1);
    assert!(f.successors(0x1000).is_empty());
}

#[test]
fn bnd_call_gives_a_call_edge_and_xref() {
    // bnd call 0x1006; ret.
    let a = x64(
        &[0xF2, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3],
        0x1000,
        Some(0x1000),
    );
    assert_eq!(a.call_edges(), [(0x1000, 0x1006)]);
    assert_eq!(a.calls_of(0x1000), [0x1006]);
    assert!(
        a.xrefs_page(Some(XrefKind::Code), 0, 64)
            .iter()
            .any(|x| x.from == 0x1000 && x.to == 0x1006)
    );
}

#[test]
fn raw_open_sees_notrack_jmp_as_indirect() {
    let dir = tmpdir("prefix-raw");
    let bin = write_bin(&dir, "r.bin", &[0x3E, 0xFF, 0xE0]);
    let db = temp_db(&dir, "r");
    let p = Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: 0x1000,
            arch: Arch::X86_64,
            entry: Some(0x1000),
        },
    )
    .expect("raw open must analyze");
    assert_eq!(
        p.analysis()
            .diagnostics
            .records
            .iter()
            .map(|d| (d.addr, d.kind))
            .collect::<Vec<_>>(),
        [(0x1000, DiagnosticKind::UnresolvedIndirectJump)]
    );
    assert!(!db.exists(), "reads never create the sidecar");
    cleanup(&dir);
}

#[test]
fn cli_disasm_reports_jmp_for_notrack_bytes() {
    let dir = tmpdir("prefix-cli");
    let bin = write_bin(&dir, "r.bin", &[0x3E, 0xFF, 0xE0]);
    let db = temp_db(&dir, "r");
    let out = Command::new(binscout_bin())
        .args([
            "--raw",
            "--arch",
            "x86_64",
            "--base",
            "0x1000",
            "--entry",
            "0x1000",
            "--db",
            &db.display().to_string(),
            "disasm",
            &bin.display().to_string(),
            "0x1000",
            "3",
        ])
        .output()
        .expect("spawn binscout");
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let v: serde_json::Value =
        serde_json::from_str(text.trim_end()).expect("stdout must be one JSON value");
    assert_eq!(v["insns"][0]["mnem"], "jmp");
    assert_eq!(v["insns"][0]["ops"], serde_json::json!(["rax"]));
    assert!(!db.exists(), "reads never create the sidecar");
    cleanup(&dir);
}
