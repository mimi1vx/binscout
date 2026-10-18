//! User-supplied signatures: JSON corpus files, IDA `.pat` import,
//! `sig-gen` round-trips, and `--sigs` on `flirt-hints`.

mod common;

use std::process::Command;

use serde_json::Value;

use binscout::disasm::Arch;
use binscout::flirt::{
    SIGNATURE_FILE_VERSION, crc32_ieee, generate_for_function, load_signature_file,
    match_leading_runtime,
};
use binscout::loader::RawOptions;

use common::{binscout_bin, cleanup, temp_db, tmpdir, write_bin};

const BASE: u64 = 0x1000;

/// Blob: F@+0x0 (frame + call to G) + G@+0x20 (fixed 10-byte leaf,
/// `mov eax,1; ret` under a frame) + padding.
fn named_blob() -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    // F: push rbp; mov rbp,rsp; call G; ret.
    b.extend([0x55, 0x48, 0x89, 0xE5]);
    let rel = 0x20i32 - 0x09;
    b.extend([0xE8]);
    b.extend(rel.to_le_bytes());
    b.push(0xC3);
    b.extend(vec![0x90; 0x20 - b.len()]);
    // G: framed return-1 leaf, no address-like operands.
    b.extend([0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
    b.extend(vec![0x90; 0x60 - b.len()]);
    b
}

fn open_raw(dir: &std::path::Path, tag: &str) -> (std::path::PathBuf, binscout::Project) {
    let bin = write_bin(dir, &format!("{tag}.bin"), &named_blob());
    let db = temp_db(dir, tag);
    let p = binscout::Project::open_raw(
        &bin,
        &db,
        RawOptions {
            base: BASE,
            arch: Arch::X86_64,
            entry: Some(BASE),
        },
    )
    .expect("raw open");
    (bin, p)
}

fn write_sig_file(dir: &std::path::Path, name: &str, text: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("write sig file");
    path
}

#[test]
fn crc32_matches_known_vector() {
    assert_eq!(crc32_ieee(b"123456789"), 0xCBF43926);
}

#[test]
fn json_signatures_load_and_match() {
    let dir = tmpdir("sigs-load");
    let body = serde_json::json!({
        "version": 1,
        "signatures": [
            {"name": "wild_leaf", "arch": "x86_64", "bytes": "55 48 89 E5 ?? ?? ?? ?? ?? ??", "len": 10, "crc": 0},
        ],
    });
    let mut text = body.to_string();
    // Fix the crc: computed over pattern bytes with wildcards zeroed.
    let concrete = [0x55u8, 0x48, 0x89, 0xE5, 0, 0, 0, 0, 0, 0];
    let crc = crc32_ieee(&concrete);
    text = text.replace("\"crc\":0", &format!("\"crc\":{crc}"));
    let path = write_sig_file(&dir, "user.json", &text);

    let sigs = load_signature_file(&path).expect("valid sig file");
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].id, "wild_leaf");
    assert_eq!(sigs[0].arch, Some(Arch::X86_64));

    // Wildcard tail matches the G leaf; exact prefix still required.
    let hits = match_leading_runtime(
        Arch::X86_64,
        &[0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3],
        &sigs,
    );
    assert_eq!(hits.len(), 1);
    assert!(match_leading_runtime(Arch::X86_64, &[0x55, 0x48, 0x89, 0xE4], &sigs).is_empty());

    // Arch scoping: an explicit x86_64 sig never matches ARM-family modes.
    for arch in [Arch::Aarch64, Arch::Arm32, Arch::Thumb, Arch::X86_32] {
        assert!(
            match_leading_runtime(
                arch,
                &[0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3],
                &sigs,
            )
            .is_empty(),
            "{arch:?} must not match an x86_64 user signature"
        );
    }
    cleanup(&dir);
}

#[test]
fn archless_user_signature_matches_only_x86() {
    let dir = tmpdir("sigs-archless");
    let concrete = [0x90u8, 0xC3];
    let crc = crc32_ieee(&concrete);
    let text = serde_json::json!({
        "version": 1,
        "signatures": [
            {"name": "pad", "arch": null, "bytes": "90 C3", "len": 2, "crc": crc},
        ],
    })
    .to_string();
    let path = write_sig_file(&dir, "archless.json", &text);
    let sigs = load_signature_file(&path).expect("valid sig file");
    assert_eq!(sigs[0].arch, None);
    for arch in [Arch::X86_64, Arch::X86_32] {
        assert_eq!(match_leading_runtime(arch, &[0x90, 0xC3], &sigs).len(), 1);
    }
    for arch in [Arch::Aarch64, Arch::Arm32, Arch::Thumb] {
        assert!(
            match_leading_runtime(arch, &[0x90, 0xC3], &sigs).is_empty(),
            "{arch:?} must not match an arch-less user signature"
        );
    }
    cleanup(&dir);
}

#[test]
fn sig_file_validation_rejects_bad_rows() {
    let dir = tmpdir("sigs-invalid");
    let good = |bytes: &str, len: usize, crc: u32| -> serde_json::Value {
        serde_json::json!({"name": "s", "arch": "x86_64", "bytes": bytes, "len": len, "crc": crc})
    };
    let doc = |sigs: Vec<serde_json::Value>| -> String {
        serde_json::json!({"version": 1, "signatures": sigs}).to_string()
    };
    // crc disagreement.
    let path = write_sig_file(&dir, "bad-crc.json", &doc(vec![good("55 48", 2, 1)]));
    assert!(load_signature_file(&path).is_err());
    // len disagreement.
    let path = write_sig_file(&dir, "bad-len.json", &doc(vec![good("55 48", 3, 1)]));
    assert!(load_signature_file(&path).is_err());
    // Unknown arch.
    let mut row = good("55 48", 2, 0);
    row["arch"] = serde_json::Value::from("mips");
    row["crc"] = serde_json::Value::from(crc32_ieee(&[0x55, 0x48]));
    let path = write_sig_file(&dir, "bad-arch.json", &doc(vec![row]));
    assert!(load_signature_file(&path).is_err());
    // All-wildcard pattern (matches everything).
    let mut row = good("?? ??", 2, 0);
    row["crc"] = serde_json::Value::from(crc32_ieee(&[0, 0]));
    let path = write_sig_file(&dir, "wild.json", &doc(vec![row]));
    assert!(load_signature_file(&path).is_err());
    // Empty name.
    let mut row = good("55 48", 2, 0);
    row["name"] = serde_json::Value::from("");
    row["crc"] = serde_json::Value::from(crc32_ieee(&[0x55, 0x48]));
    let path = write_sig_file(&dir, "noname.json", &doc(vec![row]));
    assert!(load_signature_file(&path).is_err());
    // Unsupported version.
    let path = write_sig_file(
        &dir,
        "badver.json",
        &serde_json::json!({"version": 2, "signatures": []}).to_string(),
    );
    assert!(load_signature_file(&path).is_err());
    // Missing file.
    assert!(load_signature_file(&dir.join("nope.json")).is_err());
    cleanup(&dir);
}

#[test]
fn pat_import_head_and_name_only() {
    let dir = tmpdir("sigs-pat");
    // A 32-byte head needs a 32-byte function: 32 nops plus ret.
    let head = "90".repeat(32);
    let text = format!(
        "# comment line\n\
         ; another comment\n\
         {head} 00 0000 0021 :0000 nop_slide ^0005 some_ref\n\
         ---\n\
         554889E50000000000000000000000000000000000000000000000000000000000 00 0000 0001 :0000 ignored_after_terminator\n"
    );
    let path = write_sig_file(&dir, "corpus.pat", &text);
    let sigs = load_signature_file(&path).expect("pat import");
    assert_eq!(sigs.len(), 1, "terminator stops the import");
    assert_eq!(sigs[0].suggested_name, "nop_slide");
    assert_eq!(sigs[0].arch, None);
    let leading = vec![0x90; 32];
    let hits = match_leading_runtime(Arch::X86_64, &leading, &sigs);
    assert_eq!(hits.len(), 1);
    assert!(sigs[0].reason.contains(".pat import"));
    cleanup(&dir);
}

#[test]
fn sig_gen_masks_calls_and_round_trips() {
    let dir = tmpdir("sigs-gen");
    let (_bin, mut p) = open_raw(&dir, "gen");
    p.rename_function(BASE, "func_f").expect("rename F");
    p.rename_function(BASE + 0x20, "func_g").expect("rename G");

    let doc = p.generate_signatures();
    assert_eq!(doc.version, SIGNATURE_FILE_VERSION);
    assert_eq!(doc.signatures.len(), 2, "F and G only: {doc:?}");

    let f = doc
        .signatures
        .iter()
        .find(|s| s.name == "func_f")
        .expect("F row");
    assert_eq!(f.arch.as_deref(), Some("x86_64"));
    assert!(f.bytes.contains("??"), "call rel32 is masked: {}", f.bytes);
    assert!(
        f.bytes.starts_with("55 48 89 E5"),
        "frame prefix stays fixed"
    );
    let g = doc
        .signatures
        .iter()
        .find(|s| s.name == "func_g")
        .expect("G row");
    assert_eq!(g.bytes, "55 48 89 E5 B8 01 00 00 00 C3");
    assert_eq!(g.len, 10);

    // The emitted document loads back and matches with the same names.
    let path = dir.join("roundtrip.json");
    std::fs::write(&path, serde_json::to_string(&doc).expect("doc serializes")).expect("write doc");
    let extra = load_signature_file(&path).expect("round-trip loads");
    let page = p
        .query_flirt_hints_with(None, 0, 50, &extra)
        .expect("hints with user sigs");
    let names: Vec<&str> = page
        .items
        .iter()
        .map(|h| h.suggested_name.as_str())
        .collect();
    assert!(names.contains(&"func_f"), "{names:?}");
    assert!(names.contains(&"func_g"), "{names:?}");
    cleanup(&dir);
}

#[test]
fn generate_skips_unnamed_and_all_masked() {
    let dir = tmpdir("sigs-skip");
    let (_bin, p) = open_raw(&dir, "skip");
    // No renames: raw blobs carry no symbols, so nothing is named.
    assert!(p.generate_signatures().signatures.is_empty());
    // Direct unit check: a single masked instruction yields no signature.
    let a = binscout::analysis::analyze_raw(
        &[0xE8, 0x00, 0x00, 0x00, 0x00],
        BASE,
        Arch::X86_64,
        Some(BASE),
    )
    .expect("call blob analyzes");
    let func = a.functions.get(&BASE).expect("entry func");
    assert!(
        generate_for_function(Arch::X86_64, func, "calls_only", |_| true).is_none(),
        "all-masked shapes are skipped"
    );
    cleanup(&dir);
}

/// Run the CLI; assert stdout is one valid JSON value.
fn run(args: &[&str]) -> (bool, Value) {
    let out = Command::new(binscout_bin())
        .args(args)
        .output()
        .expect("spawn binscout");
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    let value: Value = serde_json::from_str(text.trim_end())
        .unwrap_or_else(|_| panic!("stdout must be one JSON value, got: {text:?}"));
    (out.status.success(), value)
}

#[test]
fn cli_sigs_and_sig_gen_json() {
    let dir = tmpdir("sigs-cli");
    let (bin, mut p) = open_raw(&dir, "cli");
    p.rename_function(BASE + 0x20, "leaf_g").expect("rename G");
    let (bin_s, db_s) = (
        bin.display().to_string(),
        temp_db(&dir, "cli").display().to_string(),
    );
    let raw = [
        "--raw", "--arch", "x86_64", "--base", "0x1000", "--entry", "0x1000",
    ];

    // sig-gen prints the JSON document.
    let mut gen_args: Vec<String> =
        vec!["--db".into(), db_s.clone(), "sig-gen".into(), bin_s.clone()];
    gen_args.extend(raw.iter().map(|s| s.to_string()));
    let args: Vec<&str> = gen_args.iter().map(String::as_str).collect();
    let (ok, v) = run(&args);
    assert!(ok, "{v}");
    assert_eq!(v["version"], 1);
    assert_eq!(v["signatures"].as_array().expect("rows").len(), 1);
    assert_eq!(v["signatures"][0]["name"], "leaf_g");

    // flirt-hints --sigs picks the generated row up as a hint.
    let sig_path = dir.join("gen.json");
    std::fs::write(&sig_path, v.to_string()).expect("write sigs");
    let mut hints: Vec<String> = vec![
        "--db".into(),
        db_s.clone(),
        "flirt-hints".into(),
        bin_s.clone(),
        "--sigs".into(),
        sig_path.display().to_string(),
    ];
    hints.extend(raw.iter().map(|s| s.to_string()));
    let args: Vec<&str> = hints.iter().map(String::as_str).collect();
    let (ok, v) = run(&args);
    assert!(ok, "{v}");
    let items = v["items"].as_array().expect("items");
    assert!(
        items.iter().any(|i| i["suggested_name"] == "leaf_g"),
        "user signature hints: {v}"
    );

    // A missing sig file is a runtime failure: one JSON error, exit 1.
    let mut bad: Vec<String> = vec![
        "--db".into(),
        db_s.clone(),
        "flirt-hints".into(),
        bin_s.clone(),
        "--sigs".into(),
        dir.join("nope.json").display().to_string(),
    ];
    bad.extend(raw.iter().map(|s| s.to_string()));
    let args: Vec<&str> = bad.iter().map(String::as_str).collect();
    let (ok, v) = run(&args);
    assert!(!ok, "missing sig file must fail");
    assert!(v.get("error").is_some(), "{v}");
    cleanup(&dir);
}

#[test]
fn cli_go_funcs_empty_on_non_go() {
    let dir = tmpdir("sigs-nongo");
    let (bin, _) = open_raw(&dir, "nongo");
    let (bin_s, db_s) = (
        bin.display().to_string(),
        temp_db(&dir, "nongo").display().to_string(),
    );
    let args = vec![
        "--db".to_string(),
        db_s,
        "go-funcs".to_string(),
        bin_s,
        "--raw".to_string(),
        "--arch".to_string(),
        "x86_64".to_string(),
        "--base".to_string(),
        "0x1000".to_string(),
        "--entry".to_string(),
        "0x1000".to_string(),
    ];
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, v) = run(&args);
    assert!(ok, "{v}");
    assert_eq!(v, Value::Array(vec![]), "non-Go blob recovers nothing");
    cleanup(&dir);
}
