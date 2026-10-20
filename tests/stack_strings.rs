//! Stack-constructed strings (rsdbg-em6.18, M item): `mov [rsp/rbp+off],
//! imm` runs within one block reassemble with function and address.

mod common;

use std::process::Command;

use serde_json::Value;

use common::{cleanup, temp_db, tmpdir, write_bin};

/// x86-64 blob (raw fallback maps at base 0), one straight-line function:
/// `mov`-built "Hey!" (`[rsp+0..4]`), "test" (`[rsp+8..12]`), ignored
/// `[rax]`/register writes, a short `[rsp+0x20]` write, "abcd"
/// (`[rbp-0x10]`), then `ret`.
fn stack_blob() -> Vec<u8> {
    vec![
        0xC6, 0x44, 0x24, 0x00, 0x48, // 0x00: mov byte [rsp+0], 'H'
        0xC6, 0x44, 0x24, 0x01, 0x65, // 0x05: mov byte [rsp+1], 'e'
        0xC6, 0x44, 0x24, 0x02, 0x79, // 0x0A: mov byte [rsp+2], 'y'
        0xC6, 0x44, 0x24, 0x03, 0x21, // 0x0F: mov byte [rsp+3], '!'
        0xC7, 0x44, 0x24, 0x08, 0x74, 0x65, 0x73, 0x74, // 0x14: mov dword [rsp+8], "test"
        0xC6, 0x40, 0x10, 0x41, // 0x1C: mov byte [rax+0x10], 'A' (ignored)
        0xB8, 0x41, 0x00, 0x00, 0x00, // 0x20: mov eax, 'A' (ignored)
        0xC6, 0x44, 0x24, 0x20, 0x5A, // 0x25: short [rsp+0x20] write (ignored)
        0xC7, 0x45, 0xF0, 0x61, 0x62, 0x63, 0x64, // 0x2A: mov dword [rbp-0x10], "abcd"
        0xC3, // 0x32: ret
    ]
}

fn run_cli(args: &[&str]) -> (bool, Value) {
    let out = Command::new(common::binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value)
}

#[test]
fn mov_runs_reassemble_with_func_and_addr() {
    let dir = tmpdir("stackstr-rec");
    let bin = write_bin(&dir, "stack.bin", &stack_blob());
    let db = temp_db(&dir, "stack");
    let p = binscout::Project::open_with_db(&bin, &db).expect("blob must open");
    let rows = p.stack_strings();
    assert_eq!(
        rows.iter()
            .map(|r| (r.func, r.addr, r.value.as_str()))
            .collect::<Vec<_>>(),
        [(0, 0, "Hey!"), (0, 20, "test"), (0, 42, "abcd")],
        "runs report per base register with the lowest contributing address: {rows:?}"
    );
    // Address twins follow the protocol.
    let v = serde_json::to_value(&rows).expect("serializes");
    assert_eq!(v[0]["addr_hex"], "0x0");
    assert_eq!(v[0]["func_hex"], "0x0");
    assert_eq!(v[1]["addr_hex"], "0x14");
    assert!(v[0]["id"].as_str().expect("id").starts_with("stackstr@"));
    cleanup(&dir);
}

#[test]
fn cli_stack_strings_is_paged_envelope() {
    let dir = tmpdir("stackstr-cli");
    let bin = write_bin(&dir, "stack.bin", &stack_blob());
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "stack").display().to_string();
    let (ok, v) = run_cli(&["--db", &db, "stack-strings", &bin_s]);
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["total"], 3);
    let rows = v["items"].as_array().expect("items");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["value"], "Hey!");
    assert_eq!(rows[2]["value"], "abcd");
    cleanup(&dir);
}

#[test]
fn cli_stack_strings_paging_returns_first_row() {
    let dir = tmpdir("stackstr-page");
    let bin = write_bin(&dir, "stack.bin", &stack_blob());
    let bin_s = bin.display().to_string();
    let db = temp_db(&dir, "stack").display().to_string();
    let (ok, v) = run_cli(&["--db", &db, "stack-strings", &bin_s, "--limit", "1"]);
    assert!(ok, "{v}");
    assert_eq!(v["protocol"], 1);
    assert!(v["total"].as_u64().expect("total") >= 2);
    assert_eq!(v["items"].as_array().expect("items").len(), 1);
    assert_eq!(v["next_offset"], 1);
    cleanup(&dir);
}
