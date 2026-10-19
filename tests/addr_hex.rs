//! O1/A9: dual address encoding + MASM-suffix removal + IR warning lock-in.
//!
//! Every JSON address field pairs its integer with a canonical `0x`-hex
//! twin (`addr`/`addr_hex`, `entry`/`entry_hex`, `from`/`from_hex`, ...),
//! and operand text never carries MASM `h` suffixes (`402100h`).

mod common;

use serde_json::{Value, json};

use common::{builders, cleanup, open_test_project, tmpdir};

/// Address fields and their required hex twins (`null` matches `null`).
const PAIRS: [(&str, &str); 14] = [
    ("addr", "addr_hex"),
    ("from", "from_hex"),
    ("to", "to_hex"),
    ("entry", "entry_hex"),
    ("containing_entry", "containing_entry_hex"),
    ("query_addr", "query_addr_hex"),
    ("start", "start_hex"),
    ("end", "end_hex"),
    ("branch_target", "branch_target_hex"),
    ("mem_target", "mem_target_hex"),
    ("table_base", "table_base_hex"),
    ("target", "target_hex"),
    ("address", "address_hex"),
    ("vaddr", "vaddr_hex"),
];

fn expect_hex(int_val: &Value, hex_val: &Value, path: &str, out: &mut Vec<String>) {
    match (int_val, hex_val) {
        (Value::Number(n), Value::String(h)) => {
            let addr = n.as_u64().unwrap_or_else(|| panic!("{path} is not a u64"));
            let want = format!("{addr:#x}");
            if *h != want {
                out.push(format!("{path}: twin {h:?} != {want:?}"));
            }
        }
        (Value::Null, Value::Null) => {}
        _ => out.push(format!(
            "{path}: int/hex mismatch (int={int_val}, hex={hex_val})"
        )),
    }
}

/// Whether one whitespace-free word is a MASM-suffixed hex number.
fn is_masm_word(word: &str) -> bool {
    let b = word.as_bytes();
    b.len() >= 2
        && b[0].is_ascii_digit()
        && (b[b.len() - 1] == b'h' || b[b.len() - 1] == b'H')
        && b[..b.len() - 1].iter().all(|c| c.is_ascii_hexdigit())
}

fn check_text(s: &str, path: &str, out: &mut Vec<String>) {
    let mut word = String::new();
    let mut flush = |word: &mut String| {
        if is_masm_word(word) {
            out.push(format!("{path}: MASM suffix in {s:?}"));
        }
        word.clear();
    };
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
        } else {
            flush(&mut word);
        }
    }
    flush(&mut word);
}

fn walk(v: &Value, path: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (int_key, hex_key) in PAIRS {
                if let Some(int_val) = m.get(int_key) {
                    match m.get(hex_key) {
                        Some(hex_val) => {
                            expect_hex(int_val, hex_val, &format!("{path}.{int_key}"), out);
                        }
                        None => out.push(format!("{path}.{int_key}: missing {hex_key}")),
                    }
                }
            }
            for (k, val) in m {
                let child = format!("{path}.{k}");
                if (k == "ops" || k == "inputs" || k == "outputs")
                    && let Value::Array(ops) = val
                {
                    for (i, op) in ops.iter().enumerate() {
                        if let Value::String(s) = op {
                            check_text(s, &format!("{child}[{i}]"), out);
                        }
                    }
                } else {
                    walk(val, &child, out);
                }
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk(item, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

fn check_value(v: &Value, label: &str) {
    let mut problems = Vec::new();
    walk(v, label, &mut problems);
    assert!(
        problems.is_empty(),
        "{label} dual-encoding violations:\n{}",
        problems.join("\n")
    );
}

#[test]
fn addr_helpers_are_canonical() {
    assert_eq!(binscout::addr_hex(0x401000), "0x401000");
    assert_eq!(binscout::addr_hex(0), "0x0");
    assert_eq!(binscout::addr_hex(u64::MAX), "0xffffffffffffffff");
    assert_eq!(
        binscout::addr_pair(0x402100),
        (0x402100, "0x402100".to_string())
    );
    assert_eq!(binscout::opt_addr_pair(None), (None, None));
    assert_eq!(
        binscout::opt_addr_pair(Some(1)),
        (Some(1), Some("0x1".to_string()))
    );
}

#[test]
fn every_addr_has_matching_hex() {
    let dir = tmpdir("addr-hex");
    let p = open_test_project(&dir, builders::BASIC_NAME);
    let entry = builders::BASIC_ENTRY_VA;

    check_value(
        &Value::Array(p.functions_filtered(&Default::default(), 0, 50)),
        "functions",
    );
    check_value(&p.func_detail(entry).expect("func"), "func");
    check_value(
        &p.func_detail(entry + 1).expect("mid-function snap"),
        "func-mid",
    );
    check_value(&p.cfg_of(entry).expect("cfg"), "cfg");
    check_value(&p.structure_of(entry).expect("structure"), "structure");
    check_value(&p.pseudo_of(entry).expect("pseudo"), "pseudo");
    check_value(
        &p.func_detail(entry + 1).expect("mid-function snap"),
        "func-mid",
    );
    check_value(
        &serde_json::to_value(p.disasm_at(entry, 16).expect("disasm")).expect("json"),
        "disasm",
    );
    check_value(&p.ir_at(entry, 16).expect("ir"), "ir");
    check_value(
        &p.ir_coverage_at(binscout::disasm::Arch::X86_32, entry, 16)
            .expect("ir-coverage"),
        "ir-coverage",
    );
    check_value(
        &serde_json::to_value(p.query_xrefs(None, None, None, 0, 100)).expect("json"),
        "xrefs",
    );
    check_value(
        &serde_json::to_value(
            p.query_strings(&binscout::analysis::StringsFilter {
                include_code: true,
                limit: 100,
                ..Default::default()
            })
            .expect("strings"),
        )
        .expect("json"),
        "strings",
    );
    check_value(&p.sections_json(), "sections");
    check_value(&p.symbols_json(), "symbols");
    check_value(&p.annotation_json(entry), "annotate");
    check_value(
        &serde_json::to_value(p.project_info()).expect("json"),
        "project_info",
    );
    // Analysis-level summaries (same Serialize impls, direct API).
    check_value(
        &serde_json::to_value(p.analysis().functions_page(0, 10)).expect("json"),
        "functions_page",
    );
    check_value(
        &serde_json::to_value(p.analysis().blocks_page(entry, 0, 10).expect("blocks"))
            .expect("json"),
        "blocks_page",
    );

    // Garbage fixture covers `error_at` plus nullable string `vaddr`s.
    let g = open_test_project(&dir, builders::GARBAGE_NAME);
    let bytes = builders::build(builders::GARBAGE_NAME);
    check_value(
        &serde_json::to_value(g.disasm_at(0, bytes.len()).expect("partial")).expect("json"),
        "garbage-disasm",
    );
    check_value(&g.ir_at(0, bytes.len()).expect("ir"), "garbage-ir");
    cleanup(&dir);
}

#[test]
fn ops_have_no_masm_suffix() {
    let dir = tmpdir("masm-suffix");
    let p = open_test_project(&dir, builders::BASIC_NAME);
    let partial = p
        .disasm_at(builders::BASIC_ENTRY_VA, 8)
        .expect("entry prefix");
    // push ebp; mov ebp,esp; push 0x402100.
    assert_eq!(partial.insns.len(), 3);
    assert_eq!(partial.insns[2].ops, ["0x402100"]);
    assert_eq!(partial.insns[2].mem_target, Some(builders::BASIC_STRING_VA));
    let v = serde_json::to_value(&partial).expect("json");
    let mut problems = Vec::new();
    walk(&v, "disasm", &mut problems);
    assert!(problems.is_empty(), "{}", problems.join("\n"));

    // Regression shapes through the public decoder: leading-zero MASM
    // (`0052C2E0h`-style), `0F..h` immediates, branch prefixes, and
    // registers/keywords that must survive untouched.
    let x32 = binscout::disasm::Arch::X86_32;
    let one = |bytes: &[u8]| {
        binscout::disasm::disasm_range(x32, bytes, 0x401000, 8).expect("decodes")[0]
            .ops
            .clone()
    };
    assert_eq!(one(&[0xA1, 0x00, 0x30, 0x40, 0x00]), ["eax", "[0x403000]"]);
    let x64 = binscout::disasm::Arch::X86_64;
    let call = binscout::disasm::disasm_range(x64, &[0xE8, 0, 0, 0, 0], 0x2000, 8).expect("call");
    assert_eq!(call[0].ops, ["0x2005"]);
    let movff = binscout::disasm::disasm_range(x64, &[0xB8, 0xFF, 0xFF, 0xFF, 0xFF], 0x1000, 8)
        .expect("mov");
    assert_eq!(movff[0].ops, ["eax", "0xffffffff"]);
    let movah = binscout::disasm::disasm_range(x64, &[0x88, 0xE0], 0x1000, 8).expect("mov ah");
    assert_eq!(movah[0].ops, ["al", "ah"]);
    cleanup(&dir);
}

/// Golden disasm prefix: `push ebp; mov ebp,esp; push 0x402100` at the
/// basic fixture entry, byte-exact including dual encoding.
#[test]
fn golden_disasm_prefix() {
    let dir = tmpdir("golden-disasm");
    let p = open_test_project(&dir, builders::BASIC_NAME);
    let v = serde_json::to_value(p.disasm_at(builders::BASIC_ENTRY_VA, 8).expect("prefix"))
        .expect("json");
    let want = json!({
        "error_at": null,
        "insns": [
            {"addr": 4198400, "addr_hex": "0x401000", "size": 1, "bytes": [85],
             "mnem": "push", "ops": ["ebp"],
             "branch_target": null, "branch_target_hex": null,
             "mem_target": null, "mem_target_hex": null,
             "table_base": null, "table_base_hex": null, "thumb": false,
             "operands": [{"kind": "reg", "reg": "ebp", "bits": 32}]},
            {"addr": 4198401, "addr_hex": "0x401001", "size": 2, "bytes": [137, 229],
             "mnem": "mov", "ops": ["ebp", "esp"],
             "branch_target": null, "branch_target_hex": null,
             "mem_target": null, "mem_target_hex": null,
             "table_base": null, "table_base_hex": null, "thumb": false,
             "operands": [{"kind": "reg", "reg": "ebp", "bits": 32}, {"kind": "reg", "reg": "esp", "bits": 32}]},
            {"addr": 4198403, "addr_hex": "0x401003", "size": 5, "bytes": [104, 0, 33, 64, 0],
             "mnem": "push", "ops": ["0x402100"],
             "branch_target": null, "branch_target_hex": null,
             "mem_target": 4202752, "mem_target_hex": "0x402100",
             "table_base": null, "table_base_hex": null, "thumb": false,
             "operands": [{"kind": "imm", "value": 4202752, "bits": 32}],
             "string": "SAVE%d.GAM is invalid"},
        ],
    });
    assert_eq!(v, want);
    cleanup(&dir);
}

/// Pre-twin sidecar rows (no `*_hex` keys) still deserialize; the twins are
/// recomputed on serialize, never stored.
#[test]
fn legacy_rows_without_twins_still_decode() {
    let insn: binscout::disasm::Insn = serde_json::from_value(json!({
        "addr": 4096, "size": 1, "bytes": [144], "mnem": "nop", "ops": [],
        "branch_target": null, "mem_target": null,
    }))
    .expect("legacy insn");
    assert_eq!(
        serde_json::to_value(&insn).expect("json")["addr_hex"],
        "0x1000"
    );

    let err: binscout::disasm::PartialDisasm = serde_json::from_value(json!({
        "insns": [], "error_at": {"addr": 4, "message": "x86 invalid opcode at 0x4 (64-bit)"},
    }))
    .expect("legacy partial");
    assert_eq!(
        serde_json::to_value(&err).expect("json")["error_at"]["addr_hex"],
        "0x4"
    );

    let ir: binscout::ir::IrInsn = serde_json::from_value(json!({
        "addr": 8192, "op": "Return", "inputs": [], "outputs": [],
        "target": null, "warning": null,
    }))
    .expect("legacy ir");
    let v = serde_json::to_value(&ir).expect("json");
    assert_eq!(
        (v["addr"].as_u64(), v["addr_hex"].as_str()),
        (Some(8192), Some("0x2000"))
    );

    let xref: binscout::analysis::Xref = serde_json::from_value(json!({
        "from": 1, "to": 2, "kind": "Code",
    }))
    .expect("legacy xref");
    let v = serde_json::to_value(xref).expect("json");
    assert_eq!(
        (v["from_hex"].as_str(), v["to_hex"].as_str()),
        (Some("0x1"), Some("0x2"))
    );

    let summary: binscout::analysis::FunctionSummary = serde_json::from_value(json!({
        "id": "func@0x1000", "entry": 4096, "name": null,
        "blocks": 1, "insns": 3, "calls": [],
    }))
    .expect("legacy function summary");
    assert_eq!(
        serde_json::to_value(&summary).expect("json")["entry_hex"],
        "0x1000"
    );

    let block: binscout::analysis::BlockSummary = serde_json::from_value(json!({
        "id": "block@0x1000+0x1000", "start": 4096, "end": 4099,
        "insns": 3, "succs": [],
    }))
    .expect("legacy block summary");
    let v = serde_json::to_value(&block).expect("json");
    assert_eq!(
        (v["start_hex"].as_str(), v["end_hex"].as_str()),
        (Some("0x1000"), Some("0x1003"))
    );

    // Oldest string rows predate even `section`/`executable`.
    let hit: binscout::loader::strings::StringHit =
        serde_json::from_str(r#"{"offset":1,"vaddr":4096,"encoding":"Ascii","value":"hi"}"#)
            .expect("oldest string row");
    let v = serde_json::to_value(&hit).expect("json");
    assert_eq!(
        (v["vaddr"].as_u64(), v["vaddr_hex"].as_str()),
        (Some(4096), Some("0x1000"))
    );

    let file_hit: binscout::loader::strings::StringHit = serde_json::from_value(json!({
        "offset": 0, "vaddr": null, "encoding": "Ascii", "value": "hi!!",
        "section": null, "executable": false,
    }))
    .expect("file string row");
    let v = serde_json::to_value(&file_hit).expect("json");
    assert!(v["vaddr"].is_null() && v["vaddr_hex"].is_null());

    let export: binscout::loader::ExportRef = serde_json::from_value(json!({
        "name": "basic_entry", "address": 4198400,
    }))
    .expect("legacy export");
    assert_eq!(
        serde_json::to_value(&export).expect("json")["address_hex"],
        "0x401000"
    );

    let info: binscout::db::ProjectInfo = serde_json::from_value(json!({
        "binary": "b", "db_path": "d", "version": "0.1.0", "arch": "x86_32",
        "format": "pe", "entry": 4198400, "content_hash": 1, "size": 2,
        "supported": true, "reason": null, "functions": 1, "blocks": 1,
        "insns": 5, "xrefs": 4, "strings": 2, "annotations": 0,
    }))
    .expect("legacy project info");
    assert_eq!(
        serde_json::to_value(&info).expect("json")["entry_hex"],
        "0x401000"
    );
}

/// Unmapped mnemonics lift to `NOP` with a `warning` (never an error), and
/// every mapped mnemonic lifts clean.
#[test]
fn ir_warning_semantics_hold() {
    let x64 = binscout::disasm::Arch::X86_64;
    let lift_one = |bytes: &[u8]| {
        let insns = binscout::disasm::disasm_range(x64, bytes, 0x1000, 8).expect("decodes");
        binscout::ir::lift(x64, &insns[0])
    };
    // cpuid decodes but has no mapping: NOP + warning naming the mnemonic.
    let v = lift_one(&[0x0F, 0xA2]);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].op, binscout::ir::IrOp::Nop);
    assert_eq!(
        v[0].warning.as_deref(),
        Some("unlifted 'cpuid'; emitted NOP")
    );
    // Mapped mnemonics carry no warning.
    for bytes in [&[0x90][..], &[0xC3][..], &[0x48, 0x89, 0xD8][..]] {
        let v = lift_one(bytes);
        assert_eq!(v[0].warning, None);
    }
}

/// Arch-only coverage carries no `range` key; the ranged form pairs every
/// address with its hex twin and keeps the invalid-arch error typed.
#[test]
fn ir_coverage_range_shape_and_mismatch() {
    let dir = tmpdir("ir-coverage-shape");
    let p = open_test_project(&dir, builders::BASIC_NAME);
    let entry = builders::BASIC_ENTRY_VA;

    let arch_only = binscout::ir_coverage(binscout::disasm::Arch::X86_32);
    assert_eq!(arch_only["arch"], "x86_32");
    assert!(arch_only.get("range").is_none(), "{arch_only}");
    assert_eq!(
        arch_only["fallback"]["warning"],
        "unlifted '<mnem>'; emitted NOP"
    );

    let v = serde_json::to_value(
        p.ir_coverage_at(binscout::disasm::Arch::X86_32, entry, 16)
            .expect("range"),
    )
    .expect("json");
    check_value(&v, "ir-coverage");
    assert_eq!(v["arch"], "x86_32");
    let range = &v["range"];
    assert_eq!(
        (range["addr"].as_u64(), range["addr_hex"].as_str()),
        (Some(entry), Some(format!("{entry:#x}").as_str()))
    );
    assert_eq!(
        range["decoded"].as_u64().unwrap(),
        range["lifted"].as_u64().unwrap() + range["unlifted"].as_u64().unwrap()
    );

    let err = p
        .ir_coverage_at(binscout::disasm::Arch::Aarch64, entry, 16)
        .unwrap_err();
    assert!(
        matches!(err, binscout::error::Error::Invalid(_)),
        "arch mismatch is Invalid, got {err:?}"
    );
    cleanup(&dir);
}
