//! Approximate pseudo-C: lossy C-like lines per IR row plus CLI/MCP e2e.
//!
//! Covers data/control rendering on two fixtures (loop + branch), per-line
//! warning propagation from unmapped lifts, the top-level approximation
//! warning, snapping, read-only behavior, and CLI/MCP parity.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use binscout::disasm::Arch;
use binscout::ir::{IrInsn, IrOp};
use binscout::loader::RawOptions;
use binscout::pseudo::{PSEUDO_WARNING, render_function, render_one, render_rows};

use common::{binscout_bin, cleanup, mcp_bin, temp_db, tmpdir, write_bin};

const BASE: u64 = 0x1000;

/// Loop blob: xor eax,eax | inc eax | cmp eax,3 | jl +0x1002 | ret.
fn loop_blob() -> Vec<u8> {
    vec![
        0x31, 0xC0, // 0x1000: xor eax, eax
        0xFF, 0xC0, // 0x1002: inc eax
        0x83, 0xF8, 0x03, // 0x1004: cmp eax, 3
        0x7C, 0xF9, // 0x1007: jl 0x1002
        0xC3, // 0x1009: ret
    ]
}

/// Branch blob: xor eax,eax | cmp eax,1 | je +6 | mov eax,1 | ret |
/// mov eax,2 | ret.
fn branch_blob() -> Vec<u8> {
    vec![
        0x31, 0xC0, 0x83, 0xF8, 0x01, 0x74, 0x06, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xB8, 0x02,
        0x00, 0x00, 0x00, 0xC3,
    ]
}

fn row(addr: u64, op: IrOp, inputs: &[&str], outputs: &[&str], target: Option<u64>) -> IrInsn {
    IrInsn {
        addr,
        op,
        inputs: inputs.iter().map(|s| s.to_string()).collect(),
        outputs: outputs.iter().map(|s| s.to_string()).collect(),
        target,
        warning: None,
        effects: Default::default(),
    }
}

#[test]
fn data_ops_render_verbatim_operands() {
    assert_eq!(
        render_one(&row(0, IrOp::Copy, &["1"], &["eax"], None)).text,
        "eax = 1;"
    );
    assert_eq!(
        render_one(&row(0, IrOp::Load, &["[rbx]"], &["eax"], None)).text,
        "eax = LOAD([rbx]);"
    );
    assert_eq!(
        render_one(&row(0, IrOp::Store, &["eax"], &[], None)).text,
        "STORE(eax);"
    );
    assert_eq!(
        render_one(&row(0, IrOp::Add, &["ebx"], &["eax"], None)).text,
        "eax = ADD(ebx);"
    );
    assert_eq!(
        render_one(&row(0, IrOp::Cmp, &["eax", "3"], &[], None)).text,
        "CMP(eax, 3);"
    );
}

#[test]
fn control_ops_render_targets_and_keep_indirect_operands() {
    assert_eq!(
        render_one(&row(0, IrOp::Branch, &[], &[], Some(0x1000))).text,
        "goto 0x1000;"
    );
    assert_eq!(
        render_one(&row(0, IrOp::Branch, &["rax"], &[], None)).text,
        "goto *(rax);"
    );
    assert_eq!(
        render_one(&row(0, IrOp::CBranch, &["cond"], &[], Some(0x2000))).text,
        "if (cond) goto 0x2000;"
    );
    assert_eq!(
        render_one(&row(0, IrOp::Call, &[], &[], Some(0x3000))).text,
        "call 0x3000();"
    );
    assert_eq!(
        render_one(&row(0, IrOp::Return, &[], &[], None)).text,
        "return;"
    );
    assert_eq!(
        render_one(&row(0, IrOp::Nop, &[], &[], None)).text,
        "/* nop */;"
    );
}

#[test]
fn unmapped_rows_keep_warning_verbatim() {
    let lifted = binscout::ir::lift(
        Arch::X86_64,
        &binscout::disasm::Insn {
            addr: 0,
            size: 2,
            bytes: vec![0x0f, 0xa2],
            mnem: "cpuid".to_string(),
            ops: vec![],
            branch_target: None,
            mem_target: None,
            table_base: None,
            import: None,
        },
    );
    assert_eq!(lifted.len(), 1);
    let warning = lifted[0].warning.clone().expect("cpuid warns");
    let rendered = render_rows(&lifted);
    assert_eq!(rendered.warning, PSEUDO_WARNING);
    assert_eq!(rendered.lines.len(), 1);
    assert_eq!(rendered.lines[0].warning.as_deref(), Some(warning.as_str()));
    assert!(
        rendered.lines[0].text.contains(&warning),
        "line text carries the warning: {}",
        rendered.lines[0].text
    );
    assert!(rendered.text.contains(&warning));
}

#[test]
fn loop_fixture_renders_five_lines_with_warning() {
    let a = binscout::analysis::analyze_raw(&loop_blob(), BASE, Arch::X86_64, Some(BASE))
        .expect("loop analyzes");
    let func = a.functions.get(&BASE).expect("entry");
    let rendered = render_function(Arch::X86_64, func);
    assert_eq!(rendered.warning, PSEUDO_WARNING);
    let texts: Vec<&str> = rendered.lines.iter().map(|l| l.text.as_str()).collect();
    assert_eq!(
        texts,
        vec![
            "eax = XOR(eax);",
            "eax = ADD(eax);",
            "CMP(eax, 3);",
            "if (short 0x1002) goto 0x1002;",
            "return;",
        ]
    );
    assert!(rendered.lines.iter().all(|l| l.warning.is_none()));
    assert_eq!(rendered.lines[0].addr, BASE);
    assert!(
        rendered.text.contains("0x1000: eax = XOR(eax);"),
        "{}",
        rendered.text
    );
}

#[test]
fn branch_fixture_renders_both_sides() {
    let a = binscout::analysis::analyze_raw(&branch_blob(), 0x2000, Arch::X86_64, Some(0x2000))
        .expect("branch analyzes");
    let func = a.functions.get(&0x2000).expect("entry");
    let rendered = render_function(Arch::X86_64, func);
    assert_eq!(rendered.warning, PSEUDO_WARNING);
    let texts: Vec<&str> = rendered.lines.iter().map(|l| l.text.as_str()).collect();
    assert_eq!(
        texts,
        vec![
            "eax = XOR(eax);",
            "CMP(eax, 1);",
            "if (short 0x200d) goto 0x200d;",
            "eax = 1;",
            "return;",
            "eax = 2;",
            "return;",
        ]
    );
}

#[test]
fn adrp_add_pair_annotates_final_address() {
    // adrp x0, #0 at 0x4000 (page 0x4000); add x0, x0, #0x10; ret.
    let blob = vec![
        0x00, 0x00, 0x00, 0x90, // adrp x0, #0
        0x00, 0x40, 0x00, 0x91, // add x0, x0, #0x10
        0xC0, 0x03, 0x5F, 0xD6, // ret
    ];
    let base = 0x4000;
    let a = binscout::analysis::analyze_raw(&blob, base, Arch::Aarch64, Some(base))
        .expect("adrp pair analyzes");
    let func = a.functions.get(&base).expect("entry");
    let rendered = render_function(Arch::Aarch64, func);
    let add_line = rendered
        .lines
        .iter()
        .find(|l| l.addr == base + 4)
        .expect("add line");
    assert!(
        add_line.text.ends_with("// => 0x4010"),
        "add line carries the final address: {}",
        add_line.text
    );
    assert!(rendered.text.contains("// => 0x4010"), "{}", rendered.text);
    let adrp_line = rendered
        .lines
        .iter()
        .find(|l| l.addr == base)
        .expect("adrp line");
    assert!(
        !adrp_line.text.contains("// =>"),
        "adrp line itself is unannotated: {}",
        adrp_line.text
    );
}

#[test]
fn nonadjacent_adrp_pair_renders_without_annotation() {
    // Same pair with a nop between: adjacency is required, so no suffix.
    let blob = vec![
        0x00, 0x00, 0x00, 0x90, // adrp x0, #0
        0x1F, 0x20, 0x03, 0xD5, // nop
        0x00, 0x40, 0x00, 0x91, // add x0, x0, #0x10
        0xC0, 0x03, 0x5F, 0xD6, // ret
    ];
    let base = 0x4000;
    let a = binscout::analysis::analyze_raw(&blob, base, Arch::Aarch64, Some(base))
        .expect("split pair analyzes");
    let func = a.functions.get(&base).expect("entry");
    let rendered = render_function(Arch::Aarch64, func);
    assert!(
        !rendered.text.contains("// =>"),
        "unresolvable pairs render exactly as before: {}",
        rendered.text
    );
}

#[test]
fn project_snaps_and_stays_read_only() {
    let dir = tmpdir("pseudo-pages");
    let bin = write_bin(&dir, "loop.bin", &loop_blob());
    let db = temp_db(&dir, "loop");
    let p = binscout::Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: BASE,
            arch: Arch::X86_64,
            entry: Some(BASE),
        },
    )
    .expect("loop opens");

    let v = p.pseudo_of(BASE).expect("pseudo");
    assert_eq!(v["entry"], BASE);
    assert_eq!(v["entry_hex"], format!("{BASE:#x}"));
    assert_eq!(v["pseudo"]["warning"], PSEUDO_WARNING);
    assert_eq!(v["pseudo"]["lines"][0]["text"], "eax = XOR(eax);");
    assert_eq!(v["pseudo"]["lines"][0]["addr_hex"], format!("{BASE:#x}"));
    assert!(
        v["pseudo"]["text"]
            .as_str()
            .expect("text")
            .contains("return;"),
        "{v}"
    );

    let snapped = p.pseudo_of(BASE + 1).expect("snap");
    assert_eq!(snapped, v, "snap must equal the entry view");

    assert!(
        p.pseudo_of(0xdead).is_err(),
        "outside any function is NotFound"
    );
    assert!(!db.exists(), "reads never create the sidecar");
    cleanup(&dir);
}

/// Run the CLI; assert stdout is one valid JSON value.
fn run(args: &[&str]) -> (bool, Value) {
    let out = Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout utf-8");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value)
}

#[test]
fn cli_pseudo_envelope_and_errors() {
    let dir = tmpdir("cli-pseudo");
    let bin = write_bin(&dir, "loop.bin", &loop_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "loop").display().to_string();
    let d = db.as_str();
    let base = format!("{BASE:#x}");
    let raw = [
        "--raw", "--arch", "x86_64", "--base", &base, "--entry", &base,
    ];
    let with_raw = |extra: &[&str]| -> Vec<String> {
        let mut args = vec!["--db".to_string(), d.to_string()];
        args.extend(raw.iter().map(|s| s.to_string()));
        args.extend(extra.iter().map(|s| s.to_string()));
        args
    };

    let args = with_raw(&["pseudo", &bin, &format!("{BASE:#x}")]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&refs);
    assert!(ok, "{v}");
    assert_eq!(v["entry"], BASE);
    assert_eq!(v["pseudo"]["warning"], PSEUDO_WARNING);
    assert_eq!(v["pseudo"]["lines"][0]["text"], "eax = XOR(eax);");
    assert_eq!(v["pseudo"]["lines"][4]["text"], "return;");

    let args = with_raw(&["pseudo", &bin, &BASE.to_string()]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, n) = run(&refs);
    assert!(ok, "{n}");
    assert_eq!(v, n, "hex and decimal must agree");

    let args = with_raw(&["pseudo", &bin, "0xdead"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&refs);
    assert!(!ok && v.get("error").is_some(), "{v}");
    let args = with_raw(&["pseudo", &bin, "zz"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&refs);
    assert!(!ok && v.get("error").is_some(), "{v}");
    assert!(
        !std::path::Path::new(d).exists(),
        "pseudo reads never create the sidecar"
    );
    cleanup(&dir);
}

fn req(id: u64, method: &str, params: Value) -> String {
    serde_json::to_string(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .expect("request serializes")
}

fn call(id: u64, name: &str, args: Value) -> String {
    req(id, "tools/call", json!({"name": name, "arguments": args}))
}

fn session(lines: &[String]) -> Vec<Value> {
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
    let out = child.wait_with_output().expect("server exits on stdin EOF");
    assert!(out.status.success(), "server exit: {}", out.status);
    String::from_utf8(out.stdout)
        .expect("stdout utf-8")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("response line JSON"))
        .collect()
}

fn tool_text(resp: &Value) -> &str {
    let result = resp.get("result").expect("tool result");
    assert_ne!(result.get("isError"), Some(&Value::Bool(true)), "{resp}");
    result["content"][0]["text"].as_str().expect("text content")
}

fn tool_once(tool_id: u64, tool: &str, args: Value) -> Value {
    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(tool_id, tool, args),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let text = tool_text(&resps[1]).to_owned();
    serde_json::from_str(&text).expect("tool json")
}

#[test]
fn mcp_pseudo_parity_and_errors() {
    let dir = tmpdir("mcp-pseudo");
    let bin = write_bin(&dir, "loop.bin", &loop_blob())
        .display()
        .to_string();
    let db = temp_db(&dir, "loop").display().to_string();
    let base = format!("{BASE:#x}");
    let raw = json!({"arch": "x86_64", "base": base, "entry": base});

    let v = tool_once(
        10,
        "pseudo",
        json!({"binary": bin, "db": db, "raw": raw, "addr": format!("{BASE:#x}")}),
    );
    assert_eq!(v["entry"], BASE);
    assert_eq!(v["pseudo"]["warning"], PSEUDO_WARNING);
    assert_eq!(v["pseudo"]["lines"][0]["text"], "eax = XOR(eax);");

    let bbin = binscout_bin();
    let out = Command::new(bbin)
        .args([
            "--db",
            &db,
            "--raw",
            "--arch",
            "x86_64",
            "--base",
            &base,
            "--entry",
            &base,
            "pseudo",
            &bin,
            &format!("{BASE:#x}"),
        ])
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout utf-8");
    let from_cli: Value = serde_json::from_str(text.trim_end()).expect("cli json");
    assert_eq!(from_cli, v, "CLI and MCP must agree");

    let lines = vec![
        req(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .expect("n"),
        call(
            20,
            "pseudo",
            json!({"binary": bin, "db": db, "raw": raw, "addr": "0xdead"}),
        ),
        call(
            21,
            "pseudo",
            json!({"binary": bin, "db": db, "raw": raw, "addr": "zz"}),
        ),
    ];
    let resps = session(&lines);
    assert_eq!(resps.len(), 3, "{resps:?}");
    for resp in resps.iter().skip(1) {
        assert!(resp.get("error").is_some(), "must error: {resp:?}");
        assert!(resp.get("result").is_none());
    }
    assert!(
        !std::path::Path::new(&db).exists(),
        "pseudo queries never create the sidecar"
    );
    cleanup(&dir);
}
