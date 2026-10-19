//! YARA rule scanning via `yara-x` over mapped file bytes.
//!
//! Rules come from a user-supplied path and are never fetched from the
//! network. Each mapped segment's file-backed bytes are scanned separately
//! (like [`crate::search`]), so gaps, virtual BSS, and overlapping views
//! never bridge or double-report: hits deduplicate by
//! `(addr, rule, pattern)`. Every hit maps to its virtual address plus the
//! covering file-backed section and containing function (see
//! [`Project::scan_yara`](crate::Project::scan_yara)).
//!
//! The `yara` cargo feature (off by default) enables the real scanner with
//! `yara-x` default features disabled: plain string/hex/regex rules work,
//! `import` module rules are rejected at compile time. Without the feature
//! the query returns [`Error::Unsupported`]
//! and no `yara-x` code is linked.

use std::path::Path;

#[cfg(feature = "yara")]
use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::loader::LoadedBinary;

/// Cap on YARA rules-file bytes: read budget before parsing.
pub const MAX_YARA_RULES_BYTES: usize = 1 << 20;

/// Cap on total YARA hits collected before paging.
pub const MAX_YARA_HITS: usize = 100_000;

/// File offset of the byte at `va`, if file-backed.
///
/// Mirrors the [`Project::search_bytes`](crate::Project::search_bytes)
/// provenance: the covering file-backed section first, the raw-blob offset
/// for section-less raw mappings, else null.
pub(crate) fn file_off_of(va: u64, binary: &LoadedBinary) -> Option<u64> {
    for sec in &binary.sections {
        if sec.file_size == 0 || va < sec.vaddr {
            continue;
        }
        let d = va - sec.vaddr;
        if d < sec.file_size {
            return sec.file_off.checked_add(d);
        }
    }
    if binary.format == crate::loader::BinaryFormat::Raw {
        for seg in &binary.segments {
            if va < seg.vaddr {
                continue;
            }
            let d = va - seg.vaddr;
            if d < seg.data.len() as u64 {
                return Some(d);
            }
        }
    }
    None
}

/// Name of the file-backed section covering `va`, if any.
///
/// Mirrors the search provenance: virtual-only (BSS) and section-less
/// ranges report null.
pub(crate) fn section_of(va: u64, binary: &LoadedBinary) -> Option<String> {
    for sec in &binary.sections {
        if sec.file_size == 0 || va < sec.vaddr {
            continue;
        }
        let d = va - sec.vaddr;
        if d < sec.file_size {
            return Some(sec.name.clone());
        }
    }
    None
}

/// One YARA pattern occurrence with VA/file provenance.
///
/// JSON pairs `addr` with `addr_hex` and `func` with `func_hex`; the twins
/// are recomputed on serialize and ignored on deserialize. `file_off` is
/// the byte's file offset and `section` the covering file-backed section
/// name (null for zero-fill/BSS and section-less ranges, following
/// [`Project::search_bytes`](crate::Project::search_bytes)). `func` is the
/// entry of the containing function (null when in no function) and
/// `func_name` its rename-resolved display name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct YaraHit {
    /// Rule identifier (e.g. `ransom_note`).
    pub rule: String,
    /// Pattern identifier within the rule (e.g. `$a`).
    pub pattern: String,
    /// Virtual address of the first matched byte.
    pub addr: u64,
    /// File offset of the first matched byte, if known.
    pub file_off: Option<u64>,
    /// Covering section name, if any.
    pub section: Option<String>,
    /// Match length in bytes.
    pub len: usize,
    /// Entry of the function containing `addr`, if any.
    #[serde(default)]
    pub func: Option<u64>,
    /// Rename-resolved display name of that function, if any.
    #[serde(default)]
    pub func_name: Option<String>,
}

impl serde::Serialize for YaraHit {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("YaraHit", 9)?;
        st.serialize_field("rule", &self.rule)?;
        st.serialize_field("pattern", &self.pattern)?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("file_off", &self.file_off)?;
        st.serialize_field("section", &self.section)?;
        st.serialize_field("len", &self.len)?;
        st.serialize_field("func", &self.func)?;
        st.serialize_field("func_hex", &self.func.map(crate::addr_hex))?;
        st.serialize_field("func_name", &self.func_name)?;
        st.end()
    }
}

/// One compiled-rule pattern occurrence before enrichment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawYaraMatch {
    /// Rule identifier.
    pub rule: String,
    /// Pattern identifier within the rule.
    pub pattern: String,
    /// Virtual address of the first matched byte.
    pub addr: u64,
    /// Match length in bytes.
    pub len: usize,
}

/// Read a YARA rules file with a hard pre-parse budget.
///
/// Metadata rejects missing/non-file/oversize inputs before any read; the
/// post-read length re-check closes stat-then-read growth races. Rules are
/// never fetched from the network: only this explicit user path is read.
pub(crate) fn read_rules_file(path: &Path) -> Result<String> {
    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::NotFound(path.display().to_string()),
        _ => Error::Io(format!("stat {}: {e}", path.display())),
    })?;
    if !meta.is_file() {
        return Err(Error::Unsupported(format!(
            "not a file: {}",
            path.display()
        )));
    }
    if meta.len() > MAX_YARA_RULES_BYTES as u64 {
        return Err(Error::Limit(format!(
            "yara rules of {} bytes exceed the {MAX_YARA_RULES_BYTES}-byte cap",
            meta.len()
        )));
    }
    let bytes =
        std::fs::read(path).map_err(|e| Error::Io(format!("read {}: {e}", path.display())))?;
    if bytes.len() > MAX_YARA_RULES_BYTES {
        return Err(Error::Limit(format!(
            "yara rules of {} bytes exceed the {MAX_YARA_RULES_BYTES}-byte cap",
            bytes.len()
        )));
    }
    String::from_utf8(bytes).map_err(|e| Error::Invalid(format!("yara rules are not UTF-8: {e}")))
}

/// Compile `rules_text` and scan each mapped segment's file-backed bytes.
///
/// `rule` keeps one rule identifier ([`Error::NotFound`] when it matches no
/// compiled rule). Hits order by `(addr, rule, pattern)` after dedup so
/// overlapping segment views never double-report. Total hits past
/// [`MAX_YARA_HITS`] are [`Error::Limit`].
#[cfg(feature = "yara")]
pub(crate) fn collect_raw(
    binary: &LoadedBinary,
    rules_text: &str,
    rule: Option<&str>,
) -> Result<Vec<RawYaraMatch>> {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(rules_text)
        .map_err(|e| Error::Invalid(format!("yara compile: {e}")))?;
    let rules = compiler.build();
    if let Some(want) = rule
        && !rules.iter().any(|r| r.identifier() == want)
    {
        return Err(Error::NotFound(format!("unknown yara rule {want:?}")));
    }
    let mut seen: BTreeSet<(u64, String, String)> = BTreeSet::new();
    let mut out: Vec<RawYaraMatch> = Vec::new();
    for seg in &binary.segments {
        if seg.data.is_empty() {
            continue;
        }
        let mut scanner = yara_x::Scanner::new(&rules);
        let results = scanner.scan(&seg.data).map_err(|e| match e {
            yara_x::ScanError::Timeout => Error::Limit("yara scan timeout".to_string()),
            other => Error::Invalid(format!("yara scan: {other}")),
        })?;
        for matched in results.matching_rules() {
            let rule_id = matched.identifier().to_string();
            if rule.is_some_and(|want| want != rule_id) {
                continue;
            }
            for pat in matched.patterns() {
                let pat_id = pat.identifier().to_string();
                for m in pat.matches() {
                    let range = m.range();
                    let len = range.len();
                    if len == 0 {
                        continue;
                    }
                    let Some(addr) = seg.vaddr.checked_add(range.start as u64) else {
                        continue;
                    };
                    if out.len() >= MAX_YARA_HITS {
                        return Err(Error::Limit(format!(
                            "yara matches exceed the {MAX_YARA_HITS}-hit cap"
                        )));
                    }
                    if seen.insert((addr, rule_id.clone(), pat_id.clone())) {
                        out.push(RawYaraMatch {
                            rule: rule_id.clone(),
                            pattern: pat_id.clone(),
                            addr,
                            len,
                        });
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| {
        a.addr
            .cmp(&b.addr)
            .then_with(|| a.rule.cmp(&b.rule))
            .then_with(|| a.pattern.cmp(&b.pattern))
    });
    Ok(out)
}

/// Without the `yara` feature there is no scanner to run.
#[cfg(not(feature = "yara"))]
pub(crate) fn collect_raw(
    _binary: &LoadedBinary,
    _rules_text: &str,
    _rule: Option<&str>,
) -> Result<Vec<RawYaraMatch>> {
    Err(Error::Unsupported(
        "yara scanning requires the `yara` cargo feature (rebuild with --features yara)"
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_file_rejects_missing_dir_and_oversize_stat() {
        assert!(matches!(
            read_rules_file(Path::new("/nonexistent-yara-rules.yar")).unwrap_err(),
            Error::NotFound(_)
        ));
        assert!(matches!(
            read_rules_file(Path::new("/tmp")).unwrap_err(),
            Error::Unsupported(_)
        ));
    }

    #[test]
    fn rules_file_rejects_non_utf8() {
        let dir = std::env::temp_dir().join(format!(
            "binscout-yara-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("bad.yar");
        std::fs::write(&path, [0xffu8, 0xfe, 0x00]).expect("write");
        assert!(matches!(
            read_rules_file(&path).unwrap_err(),
            Error::Invalid(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(not(feature = "yara"))]
    fn collect_raw_without_feature_is_unsupported() {
        let bytes = vec![0x90u8; 16];
        let bin = crate::loader::load_raw(
            &bytes,
            crate::loader::RawOptions {
                base: 0x1000,
                arch: crate::disasm::Arch::X86_64,
                entry: None,
            },
        )
        .expect("raw loads");
        assert!(matches!(
            collect_raw(&bin, "rule t { condition: true }", None).unwrap_err(),
            Error::Unsupported(_)
        ));
    }
}
