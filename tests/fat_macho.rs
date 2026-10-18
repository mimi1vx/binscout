//! Fat Mach-O slice extraction + `StoredMapping` cache identity.
//!
//! Fixtures are built in-code (no binaries checked in): two thin Mach-O
//! slices (x86-64, arm64) packed into fat32/fat64 containers.

mod common;

use binscout::db::{self, StoredMapping};
use binscout::disasm::Arch;
use binscout::error::Error;
use binscout::loader::{BinaryFormat, load, load_with_slice};

const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
const CPU_TYPE_ARM64: u32 = 0x0100_000C;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;

fn put32le(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

fn put32be(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_be_bytes());
}

fn put64le(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_le_bytes());
}

fn put64be(v: &mut [u8], off: usize, x: u64) {
    v[off..off + 8].copy_from_slice(&x.to_be_bytes());
}

/// Minimal 64-bit Mach-O: one `__TEXT` segment + `__text` section holding
/// `code` (mirrors the `minimal_macho` harness in `tests/loader.rs`).
fn thin_macho(cputype: u32, cpusubtype: u32, code: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 32];
    put32le(&mut f, 0, 0xFEED_FACF);
    put32le(&mut f, 4, cputype);
    put32le(&mut f, 8, cpusubtype);
    put32le(&mut f, 12, 2); // MH_EXECUTE
    put32le(&mut f, 16, 1); // ncmds
    put32le(&mut f, 20, 152); // sizeofcmds
    let c = f.len();
    f.extend(vec![0u8; 72]);
    put32le(&mut f, c, 0x19); // LC_SEGMENT_64
    put32le(&mut f, c + 4, 152);
    f[c + 8..c + 14].copy_from_slice(b"__TEXT");
    put64le(&mut f, c + 24, 0x1000); // vmaddr
    put64le(&mut f, c + 32, code.len() as u64); // vmsize
    put64le(&mut f, c + 40, 0xB8); // fileoff
    put64le(&mut f, c + 48, code.len() as u64); // filesize
    put32le(&mut f, c + 56, 5); // maxprot
    put32le(&mut f, c + 60, 5); // initprot
    put32le(&mut f, c + 64, 1); // nsects
    let s = f.len();
    f.extend(vec![0u8; 80]);
    f[s..s + 6].copy_from_slice(b"__text");
    f[s + 16..s + 22].copy_from_slice(b"__TEXT");
    put64le(&mut f, s + 32, 0x1000); // addr
    put64le(&mut f, s + 40, code.len() as u64); // size
    put32le(&mut f, s + 48, 0xB8); // offset
    put32le(&mut f, s + 52, 2); // align
    put32le(&mut f, s + 64, 0x8000_0400); // pure instructions
    assert_eq!(f.len(), 0xB8, "headers must end at 0xB8");
    f.extend_from_slice(code);
    f
}

fn thin_x86_64() -> Vec<u8> {
    thin_macho(
        CPU_TYPE_X86_64,
        CPU_SUBTYPE_X86_64_ALL,
        &[0x90, 0x90, 0xC3, 0x90],
    )
}

fn thin_arm64() -> Vec<u8> {
    thin_macho(
        CPU_TYPE_ARM64,
        CPU_SUBTYPE_ARM64_ALL,
        &[0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6],
    )
}

/// Pack `(cputype, cpusubtype, slice)` entries into a fat32 container
/// (magic `0xCAFEBABE`, big-endian header).
fn fat32(slices: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut f = vec![0u8; 8 + 20 * slices.len()];
    f[0..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    put32be(&mut f, 4, slices.len() as u32);
    let mut off = f.len() as u32;
    for (i, (cputype, cpusubtype, bytes)) in slices.iter().enumerate() {
        let a = 8 + 20 * i;
        put32be(&mut f, a, *cputype);
        put32be(&mut f, a + 4, *cpusubtype);
        put32be(&mut f, a + 8, off);
        put32be(&mut f, a + 12, bytes.len() as u32);
        put32be(&mut f, a + 16, 12);
        off += bytes.len() as u32;
    }
    for (_, _, bytes) in slices {
        f.extend_from_slice(bytes);
    }
    f
}

/// Pack `(cputype, cpusubtype, slice)` entries into a fat64 container
/// (magic `0xCAFEBABF`, big-endian header).
fn fat64(slices: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut f = vec![0u8; 8 + 32 * slices.len()];
    f[0..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBF]);
    put32be(&mut f, 4, slices.len() as u32);
    let mut off = f.len() as u64;
    for (i, (cputype, cpusubtype, bytes)) in slices.iter().enumerate() {
        let a = 8 + 32 * i;
        put32be(&mut f, a, *cputype);
        put32be(&mut f, a + 4, *cpusubtype);
        put64be(&mut f, a + 8, off);
        put64be(&mut f, a + 16, bytes.len() as u64);
        put32be(&mut f, a + 24, 12);
        put32be(&mut f, a + 28, 0); // reserved
        off += bytes.len() as u64;
    }
    for (_, _, bytes) in slices {
        f.extend_from_slice(bytes);
    }
    f
}

fn two_slice_fat32() -> Vec<u8> {
    fat32(&[
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, thin_x86_64()),
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, thin_arm64()),
    ])
}

#[test]
fn fat_without_selection_errors_listing_archs() {
    let fat = two_slice_fat32();
    assert!(binscout::loader::is_recognized(&fat));
    let err = load(&fat).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "missing slice selection must be invalid, got {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("x86_64") && msg.contains("aarch64"),
        "error must list available archs: {msg:?}"
    );

    // Project-level: recognized-but-unselectable fat reports the error
    // instead of raw fallback, and writes no sidecar.
    let dir = common::tmpdir("fat-no-select");
    let bin = common::write_bin(&dir, "fat.bin", &fat);
    let db = common::temp_db(&dir, "fat");
    let err = binscout::Project::open_with_db(&bin, &db).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "fat without selection must stay invalid, never raw fallback: got {err:?}"
    );
    assert!(
        err.to_string().contains("x86_64"),
        "project error must list archs: {err:?}"
    );
    assert!(!db.exists(), "failed open must not create a sidecar");
    common::cleanup(&dir);
}

#[test]
fn fat_slice_selection_opens_each_arch() {
    let fat = two_slice_fat32();

    let x86 = load_with_slice(&fat, Some("x86_64")).expect("x86_64 slice must load");
    assert_eq!(x86.format, BinaryFormat::MachO);
    assert_eq!(x86.arch, Arch::X86_64);
    assert_eq!(x86.segments.len(), 1);
    assert_eq!(x86.segments[0].vaddr, 0x1000);
    assert_eq!(&x86.segments[0].data, &[0x90, 0x90, 0xC3, 0x90]);

    // Selector is case-insensitive.
    let x86_upper = load_with_slice(&fat, Some("X86_64")).expect("upper-case selector");
    assert_eq!(x86_upper, x86);

    // `lipo`-style alias resolves to the same slice.
    let arm_alias = load_with_slice(&fat, Some("arm64")).expect("arm64 alias");
    assert_eq!(arm_alias.arch, Arch::Aarch64);
    let arm = load_with_slice(&fat, Some("aarch64")).expect("aarch64 slice must load");
    assert_eq!(arm.format, BinaryFormat::MachO);
    assert_eq!(arm.arch, Arch::Aarch64);
    assert_eq!(arm, arm_alias);
    assert_eq!(arm.segments.len(), 1);
    assert_eq!(
        arm.segments[0].data,
        [0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6]
    );

    // Fat64 headers take the same selection path.
    let fat64 = fat64(&[
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, thin_x86_64()),
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, thin_arm64()),
    ]);
    let x86_64 = load_with_slice(&fat64, Some("x86_64")).expect("fat64 x86_64 slice");
    assert_eq!(x86_64.arch, Arch::X86_64);
    let arm64 = load_with_slice(&fat64, Some("arm64")).expect("fat64 arm64 slice");
    assert_eq!(arm64.arch, Arch::Aarch64);
    let err = load(&fat64).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)) && err.to_string().contains("aarch64"),
        "fat64 without selection must list archs: {err:?}"
    );
}

#[test]
fn fat_unknown_and_ambiguous_selections_error() {
    let fat = two_slice_fat32();
    let err = load_with_slice(&fat, Some("mips")).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "unknown arch must be invalid, got {err:?}"
    );
    assert!(
        err.to_string().contains("x86_64"),
        "unknown-arch error must list available: {err:?}"
    );

    let err = load_with_slice(&fat, Some("x86_32")).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "absent arch must be invalid, got {err:?}"
    );

    // Two slices sharing one arch make the selector ambiguous.
    let dup = fat32(&[
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, thin_x86_64()),
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, thin_x86_64()),
    ]);
    let err = load_with_slice(&dup, Some("x86_64")).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "duplicate arch must be invalid, got {err:?}"
    );
    assert!(
        err.to_string().contains("ambiguous"),
        "duplicate arch must report ambiguity: {err:?}"
    );
}

#[test]
fn fat_mapping_identity_is_per_slice() {
    // Selector normalization: case folds to one identity.
    assert_eq!(
        StoredMapping::for_fat_slice("X86_64"),
        StoredMapping::for_fat_slice("x86_64")
    );
    // Aliases canonicalize: either spelling shares one snapshot.
    assert_eq!(
        StoredMapping::for_fat_slice("arm64"),
        StoredMapping::for_fat_slice("aarch64")
    );
    assert_eq!(
        StoredMapping::for_fat_slice("ARM64"),
        StoredMapping::for_fat_slice("aarch64")
    );
    assert_eq!(
        StoredMapping::for_fat_slice("x86-64"),
        StoredMapping::for_fat_slice("x86_64")
    );
    assert_ne!(
        StoredMapping::for_fat_slice("x86_64"),
        StoredMapping::for_fat_slice("aarch64")
    );
    assert_ne!(StoredMapping::for_fat_slice("x86_64"), StoredMapping::Auto);
    assert!(
        StoredMapping::for_fat_slice("x86_64")
            .describe()
            .contains("x86_64"),
        "describe must name the slice"
    );
}

#[test]
fn fat_slice_alias_shares_annotations() {
    let dir = common::tmpdir("fat-alias");
    let bin = common::write_bin(&dir, "fat.bin", &two_slice_fat32());
    let db = common::temp_db(&dir, "fat");

    // Rename under the alias spelling, then persist.
    let mut proj =
        binscout::open_mapped(&bin, Some(&db), None, Some("arm64")).expect("arm64 slice must open");
    proj.rename_function(0x1000, "slice_main")
        .expect("rename under arm64");
    proj.save().expect("save slice snapshot");
    drop(proj);

    // The canonical spelling reopens the same snapshot: no mapping
    // mismatch, and the rename reads back.
    let again =
        binscout::open_mapped(&bin, Some(&db), None, Some("aarch64")).expect("aarch64 must reopen");
    assert_eq!(
        again.function_name(0x1000).as_deref(),
        Some("slice_main"),
        "alias spelling must share annotations with the canonical one"
    );
    assert_eq!(again.project_info().mode, "fat");
    common::cleanup(&dir);
}

#[test]
fn thin_input_rejects_fat_arch() {
    // Loader level: a thin Mach-O slice rejects any selection, even a
    // valid slice name or a casing of its own arch.
    let thin = thin_arm64();
    for sel in ["aarch64", "arm64", "AARCH64", "x86_64", "mips"] {
        let err = load_with_slice(&thin, Some(sel)).unwrap_err();
        assert!(
            matches!(err, Error::Invalid(_)),
            "thin + {sel} must be invalid, got {err:?}"
        );
    }
    // Thin ELF rejects selections too.
    for sel in ["x86_64", "mips"] {
        let err = load_with_slice(&common::minimal_elf(), Some(sel)).unwrap_err();
        assert!(
            matches!(err, Error::Invalid(_)),
            "thin ELF + {sel} must be invalid, got {err:?}"
        );
    }

    // Project level: thin binary + --fat-arch errors and writes no sidecar.
    let dir = common::tmpdir("thin-fat-arch");
    let bin = common::write_bin(&dir, "thin.bin", &thin);
    for sel in ["aarch64", "mips"] {
        let db = common::temp_db(&dir, sel);
        let err = binscout::open_mapped(&bin, Some(&db), None, Some(sel)).unwrap_err();
        assert!(
            matches!(err, Error::Invalid(_)),
            "thin open + {sel} must be invalid, got {err:?}"
        );
        assert!(!db.exists(), "failed open must not create a sidecar");
    }

    // Unrecognized bytes with a selection report the parse error instead
    // of silently falling back to raw.
    let raw = common::write_bin(&dir, "blob.bin", b"not a binary at all");
    let db = common::temp_db(&dir, "blob");
    let err = binscout::open_mapped(&raw, Some(&db), None, Some("aarch64")).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "blob + fat_arch must be invalid, got {err:?}"
    );
    assert!(!db.exists(), "failed open must not create a sidecar");

    // CLI level: one JSON error value, unsuccessful exit.
    let bin_s = bin.display().to_string();
    let db_s = common::temp_db(&dir, "cli").display().to_string();
    let (ok, v) = cli_run(&["--db", &db_s, "--fat-arch", "aarch64", "load", &bin_s]);
    assert!(!ok, "thin + --fat-arch must fail: {v}");
    assert!(
        v["error"].as_str().is_some_and(|m| m.contains("fat")),
        "error must name the fat-arch misuse: {v}"
    );
    common::cleanup(&dir);
}

/// Save a snapshot for one fat slice and return the container identity.
fn bootstrap_slice(
    dir: &std::path::Path,
    name: &str,
    fat: &[u8],
    selector: &str,
    annotations: std::collections::BTreeMap<u64, db::Annotation>,
) -> (std::path::PathBuf, u64, String) {
    let loaded = load_with_slice(fat, Some(selector)).expect("slice must load");
    let analysis = binscout::analysis::analyze(&loaded).expect("slice must analyze");
    let hash = db::content_hash(fat);
    let sha256 = binscout::annotations::sha256_hex(fat);
    let db_path = common::temp_db(dir, name);
    let handle = db::open_db(&db_path).expect("open db");
    let meta = db::BinaryMeta {
        version: db::SCHEMA_VERSION,
        binary_path: name.to_string(),
        content_hash: hash,
        content_sha256: sha256.clone(),
        size: fat.len() as u64,
        arch: db::arch_name(loaded.arch).to_string(),
        format: db::format_name(loaded.format).to_string(),
        entry: loaded.entry,
        supported: true,
        reason: None,
        mapping: Some(StoredMapping::for_fat_slice(selector)),
        analysis_rev: Some(db::ANALYSIS_REVISION),
        diagnostics_truncated: analysis.diagnostics.truncated,
        diagnostics_omitted: analysis.diagnostics.omitted,
        inferred_truncated: analysis.diagnostics.inferred_truncated,
        inferred_omitted: analysis.diagnostics.inferred_omitted,
        seeds_hash: 0,
    };
    db::save(
        &handle,
        &meta,
        &analysis,
        &annotations,
        &std::collections::BTreeMap::new(),
    )
    .expect("save slice snapshot");
    (db_path, hash, sha256)
}

#[test]
fn fat_open_mapped_threads_selection_end_to_end() {
    let dir = common::tmpdir("fat-open-mapped");
    let fat = two_slice_fat32();
    let bin = common::write_bin(&dir, "fat.bin", &fat);

    // Missing selection errors listing the available archs and writes no sidecar.
    let db = common::temp_db(&dir, "missing");
    let err = binscout::open_mapped(&bin, Some(&db), None, None).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, Error::Invalid(_)),
        "missing fat_arch must be invalid: {msg:?}"
    );
    assert!(
        msg.contains("x86_64") && msg.contains("aarch64"),
        "error must list available archs: {msg:?}"
    );
    assert!(!db.exists(), "failed open must not create a sidecar");

    // Unknown selections also list the available archs.
    let db = common::temp_db(&dir, "unknown");
    let err = binscout::open_mapped(&bin, Some(&db), None, Some("mips")).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "unknown arch: {err:?}");
    assert!(err.to_string().contains("x86_64"));

    // Each selection analyzes its slice and reports mode "fat".
    let db_x86 = common::temp_db(&dir, "x86");
    let x86 = binscout::open_mapped(&bin, Some(&db_x86), None, Some("x86_64"))
        .expect("x86_64 slice must open");
    let info = x86.project_info();
    assert_eq!(info.mode, "fat");
    assert_eq!(info.arch, "x86_64");
    assert_eq!(info.format, "macho");

    let db_arm = common::temp_db(&dir, "arm");
    let arm = binscout::open_mapped(&bin, Some(&db_arm), None, Some("arm64"))
        .expect("arm64 slice must open");
    let info = arm.project_info();
    assert_eq!(info.mode, "fat");
    assert_eq!(info.arch, "aarch64");

    // The saved slice snapshot reopens under the same selection.
    arm.save().expect("save slice snapshot");
    let again = binscout::open_mapped(&bin, Some(&db_arm), None, Some("arm64"))
        .expect("same slice must reopen");
    assert_eq!(again.project_info().mode, "fat");
    assert_eq!(again.binary().arch, Arch::Aarch64);

    // Explicit raw and fat selections are exclusive.
    let raw = binscout::loader::RawOptions {
        base: 0x1000,
        arch: Arch::X86_64,
        entry: None,
    };
    let db = common::temp_db(&dir, "both");
    let err = binscout::open_mapped(&bin, Some(&db), Some(raw), Some("x86_64")).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(_)),
        "raw plus fat_arch must be invalid: {err:?}"
    );

    // `Project::open_fat` agrees with `open_mapped`.
    let db = common::temp_db(&dir, "direct");
    let direct = binscout::Project::open_fat(&bin, &db, "x86_64").expect("open_fat");
    assert_eq!(direct.project_info().arch, "x86_64");
    assert_eq!(direct.project_info().mode, "fat");
    common::cleanup(&dir);
}

/// Run the CLI; assert stdout is one valid JSON value. Returns exit success
/// plus the parsed document.
fn cli_run(args: &[&str]) -> (bool, serde_json::Value) {
    let out = std::process::Command::new(common::binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: serde_json::Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value)
}

#[test]
fn cli_fat_arch_flag_selects_slice() {
    let dir = common::tmpdir("fat-cli-arch");
    let bin = common::write_bin(&dir, "fat.bin", &two_slice_fat32());
    let bin_s = bin.display().to_string();
    let db = common::temp_db(&dir, "fat").display().to_string();
    let d = db.as_str();

    // Without the flag the load errors listing the available archs.
    let (ok, v) = cli_run(&["--db", d, "load", &bin_s]);
    assert!(!ok, "missing --fat-arch must fail: {v}");
    let msg = v["error"].as_str().expect("error field");
    assert!(
        msg.contains("x86_64") && msg.contains("aarch64"),
        "error must list available archs: {msg:?}"
    );

    // With the flag the chosen slice loads and reports mode "fat".
    let (ok, v) = cli_run(&["--db", d, "--fat-arch", "arm64", "load", &bin_s]);
    assert!(ok, "{v}");
    assert_eq!(v["arch"], "aarch64");
    assert_eq!(v["format"], "macho");
    assert_eq!(v["mode"], "fat");

    // Reads under the same selection agree with the load counts.
    let (ok, f) = cli_run(&["--db", d, "--fat-arch", "arm64", "functions", &bin_s]);
    assert!(ok, "{f}");
    assert_eq!(
        f.as_array().expect("functions array").len() as u64,
        v["functions"].as_u64().expect("functions count"),
        "functions read must agree with load"
    );
    common::cleanup(&dir);
}

/// One MCP request line plus notification; returns response lines in order.
fn mcp_session(lines: &[String]) -> Vec<serde_json::Value> {
    use std::io::Write;
    let mut child = std::process::Command::new(common::mcp_bin())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
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
    let text = String::from_utf8(out.stdout).expect("stdout utf-8");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|_| panic!("response line must be JSON: {l:?}"))
        })
        .collect()
}

fn mcp_req(id: u64, method: &str, params: serde_json::Value) -> String {
    serde_json::to_string(
        &serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
    )
    .expect("request serializes")
}

fn mcp_call(id: u64, name: &str, args: serde_json::Value) -> String {
    mcp_req(
        id,
        "tools/call",
        serde_json::json!({"name": name, "arguments": args}),
    )
}

/// One slice-tool call in a fresh server process, returning the parsed JSON
/// text payload.
fn mcp_slice_once(tool_id: u64, args: serde_json::Value) -> serde_json::Value {
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
        mcp_call(tool_id, "slice", args),
    ];
    let resps = mcp_session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let by_id: std::collections::HashMap<u64, &serde_json::Value> = resps
        .iter()
        .map(|r| (r["id"].as_u64().expect("numeric id"), r))
        .collect();
    let result = by_id[&tool_id]
        .get("result")
        .unwrap_or_else(|| panic!("slice must return result: {:?}", by_id[&tool_id]));
    let text = result["content"][0]["text"].as_str().expect("text content");
    serde_json::from_str(text).expect("slice json")
}

#[test]
fn mcp_fat_arch_selects_slice() {
    let dir = common::tmpdir("fat-mcp-arch");
    let bin = common::write_bin(&dir, "fat.bin", &two_slice_fat32())
        .display()
        .to_string();
    let db = common::temp_db(&dir, "fat").display().to_string();

    // Without fat_arch the slice tool errors (missing selection lists archs).
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
            "slice",
            serde_json::json!({"binary": bin, "db": db, "addr": "0x1000"}),
        ),
    ];
    let resps = mcp_session(&lines);
    assert_eq!(resps.len(), 2, "{resps:?}");
    let err = resps[1].get("error").expect("missing fat_arch must error");
    let msg = err.to_string();
    assert!(
        msg.contains("x86_64"),
        "tool error must list available archs: {msg:?}"
    );
    assert!(resps[1].get("result").is_none());

    // With fat_arch the same slice root analyzes under the protocol envelope.
    let page = mcp_slice_once(
        11,
        serde_json::json!({"binary": bin, "db": db, "addr": "0x1000", "fat_arch": "arm64"}),
    );
    assert_eq!(page["protocol"], 1);
    assert!(page.get("total").is_some(), "slice page: {page:?}");
    assert!(page.get("items").is_some(), "slice page: {page:?}");
    common::cleanup(&dir);
}

#[test]
fn fat_slices_do_not_share_snapshots() {
    let dir = common::tmpdir("fat-slices");
    let fat = two_slice_fat32();

    let (db_path, hash, sha256) = bootstrap_slice(&dir, "x86", &fat, "x86_64", Default::default());
    let handle = db::open_db(&db_path).expect("open db");

    // Same slice replays; the other slice and auto rebuild instead.
    match db::load_cached(
        &handle,
        hash,
        &sha256,
        fat.len() as u64,
        &StoredMapping::for_fat_slice("x86_64"),
    )
    .expect("load_cached")
    {
        db::Snapshot::Hit(hit) => {
            assert_eq!(
                hit.meta.mapping,
                Some(StoredMapping::for_fat_slice("x86_64"))
            );
        }
        other => panic!("same slice must hit, got {other:?}"),
    }
    assert!(
        matches!(
            db::load_cached(
                &handle,
                hash,
                &sha256,
                fat.len() as u64,
                &StoredMapping::for_fat_slice("aarch64")
            )
            .expect("load_cached"),
            db::Snapshot::Stale { .. }
        ),
        "other slice must not hit"
    );
    assert!(
        matches!(
            db::load_cached(
                &handle,
                hash,
                &sha256,
                fat.len() as u64,
                &StoredMapping::Auto
            )
            .expect("load_cached"),
            db::Snapshot::Stale { .. }
        ),
        "auto must not hit a slice snapshot"
    );

    // A populated slice sidecar under the other slice errors with a
    // separate-DB message instead of reusing layouts or annotations.
    let (db_ann, hash_ann, sha256_ann) = bootstrap_slice(
        &dir,
        "ann",
        &fat,
        "x86_64",
        [(
            0x1000,
            db::Annotation {
                name: None,
                comment: Some("slice note".to_string()),
            },
        )]
        .into_iter()
        .collect(),
    );
    let hog = db::open_db(&db_ann).expect("open db");
    let err = db::load_cached(
        &hog,
        hash_ann,
        &sha256_ann,
        fat.len() as u64,
        &StoredMapping::for_fat_slice("aarch64"),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("separate --db"),
        "cross-slice annotations must require a separate DB: {err:?}"
    );
    common::cleanup(&dir);
}
