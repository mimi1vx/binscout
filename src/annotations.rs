//! Versioned, identity-checked annotation interchange.
//!
//! [`AnnotationDocument`] is the portable form of a project's renames and
//! comments: a format [`ANNOTATION_FORMAT_REVISION`], the binary's SHA-256
//! plus size, the effective loader [`mapping`](crate::db::StoredMapping),
//! and the sorted non-empty annotation rows. Host paths and analysis
//! snapshots are never included, so a document moves analyst work without
//! leaking machine layout or disposable derived rows.
//!
//! [`build_document`] serializes a project snapshot to capped JSON and
//! [`parse_document`] plus [`validate_document`] check a candidate before
//! anything is written: identity, mapping, duplicates, row/text/storage
//! budgets, rename targets, and merge conflicts. Callers persist only the
//! returned per-address changes in one transaction and update memory only
//! after that commit succeeds, so a failing final row leaves the DB and the
//! in-memory annotations untouched.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::{self, Annotation, StoredMapping};
use crate::error::{Error, Result};

/// Format revision of [`AnnotationDocument`]; imports reject anything else.
pub const ANNOTATION_FORMAT_REVISION: u32 = 1;
/// Cap on serialized interchange documents in both directions (16 MiB).
///
/// Export fails explicitly past this instead of emitting a document the
/// importer cannot accept; import rejects larger inputs before parsing.
pub const MAX_TRANSFER_BYTES: usize = 16 * 1024 * 1024;

/// Lowercase hex SHA-256 of `bytes` (64 chars, no extra dependency).
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push(char::from_digit(u32::from(b >> 4), 16).expect("hex digit"));
        s.push(char::from_digit(u32::from(b & 0xf), 16).expect("hex digit"));
    }
    s
}

/// One portable annotation row: rename and/or comment at `addr`.
///
/// Missing/`null` fields are absent on import (existing values untouched);
/// an empty string clears the supplied field. Export emits only non-empty
/// fields of non-empty rows, sorted by address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnotationRow {
    /// Annotated address (rename rows must be known function entries).
    pub addr: u64,
    /// Function rename (`None` = absent, `Some("")` = clear).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rename: Option<String>,
    /// Free-text comment at any address (`None` = absent, `Some("")` = clear).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Portable annotation set for one binary under one loader mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnotationDocument {
    /// Format revision (see [`ANNOTATION_FORMAT_REVISION`]).
    pub revision: u32,
    /// Lowercase hex SHA-256 of the analyzed binary.
    pub sha256: String,
    /// Binary size in bytes.
    pub size: u64,
    /// Effective loader mapping the rows were taken over.
    pub mapping: StoredMapping,
    /// Non-empty rows, sorted by address.
    pub annotations: Vec<AnnotationRow>,
}

/// Import outcome: document rows seen and stored addresses changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportSummary {
    /// Rows in the imported document.
    pub rows: usize,
    /// Addresses whose stored annotation changed (upserts plus removals).
    pub changed: usize,
}

/// Serialize `annotations` to a capped interchange document.
///
/// Rows come out sorted by address (the map's order) with empty rows and
/// empty fields dropped. Pure read: no sidecar or binary is touched.
///
/// # Errors
/// [`Error::Limit`] when a field exceeds
/// [`MAX_ANNOTATION_BYTES`](crate::db::MAX_ANNOTATION_BYTES), when live rows
/// exceed [`MAX_SNAPSHOT_ANNOTATIONS`](crate::db::MAX_SNAPSHOT_ANNOTATIONS),
/// or when the serialized document exceeds [`MAX_TRANSFER_BYTES`]
/// (explicit failure, never truncation); [`Error::Storage`] on encoding
/// failure.
pub fn build_document(
    sha256: &str,
    size: u64,
    mapping: &StoredMapping,
    annotations: &BTreeMap<u64, Annotation>,
) -> Result<String> {
    let mut rows = Vec::new();
    for (&addr, ann) in annotations {
        if ann.is_empty() {
            continue;
        }
        let rename = ann.name.clone().filter(|s| !s.is_empty());
        let comment = ann.comment.clone().filter(|s| !s.is_empty());
        if rename.is_none() && comment.is_none() {
            continue;
        }
        if rows.len() >= db::MAX_SNAPSHOT_ANNOTATIONS {
            return Err(Error::Limit("annotation export exceeds cap".to_string()));
        }
        for (label, s) in [("rename", &rename), ("comment", &comment)] {
            if let Some(t) = s
                && t.len() > db::MAX_ANNOTATION_BYTES
            {
                return Err(Error::Limit(format!(
                    "annotation {label} of {} bytes exceeds {}",
                    t.len(),
                    db::MAX_ANNOTATION_BYTES
                )));
            }
        }
        rows.push(AnnotationRow {
            addr,
            rename,
            comment,
        });
    }
    let doc = AnnotationDocument {
        revision: ANNOTATION_FORMAT_REVISION,
        sha256: sha256.to_string(),
        size,
        mapping: mapping.clone(),
        annotations: rows,
    };
    let text = serde_json::to_string(&doc)
        .map_err(|e| Error::Storage(format!("encode annotation document: {e}")))?;
    if text.len() > MAX_TRANSFER_BYTES {
        return Err(Error::Limit(format!(
            "annotation export of {} bytes exceeds the {MAX_TRANSFER_BYTES}-byte import cap; split or clear annotations instead of truncating",
            text.len()
        )));
    }
    Ok(text)
}

/// Parse and size-check a candidate interchange document.
///
/// # Errors
/// [`Error::Limit`] when the input exceeds [`MAX_TRANSFER_BYTES`];
/// [`Error::Invalid`] when it is not a JSON annotation document.
pub fn parse_document(text: &str) -> Result<AnnotationDocument> {
    if text.len() > MAX_TRANSFER_BYTES {
        return Err(Error::Limit(format!(
            "annotation document of {} bytes exceeds the {MAX_TRANSFER_BYTES}-byte cap",
            text.len()
        )));
    }
    serde_json::from_str(text)
        .map_err(|e| Error::Invalid(format!("malformed annotation document: {e}")))
}

/// Whether `s` is a 64-char lowercase hex digest (malformed identity).
fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validate a parsed document against the open project and merge it over
/// `current`, returning the per-address changes to persist.
///
/// `None` values delete the stored row; only addresses whose stored state
/// changes are returned, so an idempotent re-import yields no writes. Pure:
/// `current` is never mutated, letting callers commit first and update
/// memory only on success.
///
/// Default (`overwrite == false`) fails on any supplied field that differs
/// from a present existing value; equal values are idempotent and absent
/// existing values fill freely. `overwrite == true` replaces supplied
/// fields only (absent fields untouched, empty strings clear). Rows outside
/// the document are never touched.
///
/// # Errors
/// [`Error::Invalid`] on unsupported revisions, malformed identity,
/// duplicate addresses, field-less rows, and default-mode conflicts;
/// [`Error::Storage`] on SHA-256/size/mapping mismatches;
/// [`Error::NotFound`] when a non-empty rename targets an unknown function
/// entry; [`Error::Limit`] past field/row budgets.
#[allow(clippy::too_many_arguments)]
pub fn validate_document(
    doc: &AnnotationDocument,
    expected_sha256: &str,
    expected_size: u64,
    expected_mapping: &StoredMapping,
    is_function: &dyn Fn(u64) -> bool,
    current: &BTreeMap<u64, Annotation>,
    overwrite: bool,
) -> Result<BTreeMap<u64, Option<Annotation>>> {
    if doc.revision != ANNOTATION_FORMAT_REVISION {
        return Err(Error::Invalid(format!(
            "unsupported annotation revision {} (expected {ANNOTATION_FORMAT_REVISION})",
            doc.revision
        )));
    }
    if !is_digest(&doc.sha256) {
        return Err(Error::Invalid(
            "malformed annotation identity: sha256 must be 64 hex chars".to_string(),
        ));
    }
    if doc.sha256 != expected_sha256 || doc.size != expected_size {
        return Err(Error::Storage(format!(
            "annotation identity mismatch: document is sha256 {} size {}, but project is sha256 {expected_sha256} size {expected_size}",
            doc.sha256, doc.size
        )));
    }
    if doc.mapping != *expected_mapping {
        return Err(Error::Storage(format!(
            "annotation mapping mismatch: document holds annotations under {}, but project uses {}; use the mapping the document was exported from (annotations are never remapped)",
            doc.mapping.describe(),
            expected_mapping.describe()
        )));
    }
    let mut seen = BTreeSet::new();
    for row in &doc.annotations {
        if !seen.insert(row.addr) {
            return Err(Error::Invalid(format!(
                "duplicate annotation address {:#x}",
                row.addr
            )));
        }
        if row.rename.is_none() && row.comment.is_none() {
            return Err(Error::Invalid(format!(
                "annotation row at {:#x} has neither rename nor comment",
                row.addr
            )));
        }
        for (label, s) in [("rename", &row.rename), ("comment", &row.comment)] {
            if let Some(t) = s
                && t.len() > db::MAX_ANNOTATION_BYTES
            {
                return Err(Error::Limit(format!(
                    "annotation {label} of {} bytes exceeds {}",
                    t.len(),
                    db::MAX_ANNOTATION_BYTES
                )));
            }
        }
        if let Some(name) = &row.rename
            && !name.is_empty()
            && !is_function(row.addr)
        {
            return Err(Error::NotFound(format!(
                "rename target {:#x} is not a known function",
                row.addr
            )));
        }
    }
    let mut changes: BTreeMap<u64, Option<Annotation>> = BTreeMap::new();
    let mut live_after: usize = current.values().filter(|a| !a.is_empty()).count();
    for row in &doc.annotations {
        let existing = current.get(&row.addr);
        let mut merged = existing.cloned().unwrap_or_default();
        for (label, supplied) in [("rename", &row.rename), ("comment", &row.comment)] {
            if let Some(v) = supplied {
                let new_val = (!v.is_empty()).then(|| v.clone());
                let old_val = if label == "rename" {
                    &merged.name
                } else {
                    &merged.comment
                };
                if !overwrite && old_val.is_some() && *old_val != new_val {
                    return Err(Error::Invalid(format!(
                        "annotation conflict at {:#x}: existing {label} differs (import with overwrite to replace supplied fields)",
                        row.addr
                    )));
                }
                if label == "rename" {
                    merged.name = new_val;
                } else {
                    merged.comment = new_val;
                }
            }
        }
        let next = (!merged.is_empty()).then_some(merged);
        if next.as_ref() != existing {
            match (&existing, &next) {
                (None, Some(_)) => live_after += 1,
                (Some(_), None) => live_after -= 1,
                _ => {}
            }
            if live_after > db::MAX_SNAPSHOT_ANNOTATIONS {
                return Err(Error::Limit("annotation import exceeds cap".to_string()));
            }
            changes.insert(row.addr, next);
        }
    }
    Ok(changes)
}

/// Apply validated `changes` to `annotations` (`None` deletes the row).
///
/// Call only after the backing transaction commits, so memory tracks the DB.
pub fn apply_changes(
    annotations: &mut BTreeMap<u64, Annotation>,
    changes: &BTreeMap<u64, Option<Annotation>>,
) {
    for (&addr, next) in changes {
        match next {
            Some(ann) => {
                annotations.insert(addr, ann.clone());
            }
            None => {
                annotations.remove(&addr);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_lowercase_hex() {
        let a = sha256_hex(b"abc");
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(a, sha256_hex(b"abc"));
        assert_ne!(a, sha256_hex(b"abd"));
    }
}
