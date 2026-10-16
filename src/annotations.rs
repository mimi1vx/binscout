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

/// Marker prefix of a structured type-hint comment (see [`TypeHint`]).
///
/// A comment starting with this prefix carries JSON struct-layout/sizeof
/// metadata after it; any other comment is plain free text. The hint stays
/// an ordinary comment everywhere else: it counts against the same 8 KiB
/// text cap, exports/imports as an opaque string through
/// [`build_document`]/[`validate_document`], and is never enforced against
/// the binary.
pub const TYPE_HINT_PREFIX: &str = "type-hint:";

/// Wire `kind` tag of [`TypeHint`] JSON; the only kind defined today.
const TYPE_HINT_STRUCT_KIND: &str = "struct";

/// One struct field of a [`TypeHint`]: byte `offset` and `size` within the
/// struct. Overlapping fields are allowed (unions); each field's end must
/// still lie within the struct size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeField {
    /// Field name (non-empty).
    pub name: String,
    /// Byte offset of the field within the struct.
    pub offset: u64,
    /// Field size in bytes (non-zero).
    pub size: u64,
}

/// Structured struct-layout/sizeof hint stored as a comment.
///
/// There is no type system: this is documentation for agents, formatted by
/// [`format_type_hint`] into the comment channel (`comment` accepts any
/// address, [`Project::set_type_hint`](crate::Project::set_type_hint))
/// and read back with [`parse_type_hint`]. Nothing validates the layout
/// against the binary; a wrong hint misleads exactly like a wrong
/// free-text comment.
///
/// # Example
///
/// ```
/// use binscout::annotations::{
///     TypeField, TypeHint, build_document, format_type_hint, parse_document,
///     parse_type_hint, sha256_hex, validate_document,
/// };
/// use binscout::db::{Annotation, StoredMapping};
/// use std::collections::BTreeMap;
///
/// let hint = TypeHint {
///     name: "Foo".to_string(),
///     size: 24,
///     fields: vec![
///         TypeField { name: "a".to_string(), offset: 0, size: 8 },
///         TypeField { name: "b".to_string(), offset: 8, size: 4 },
///     ],
/// };
/// let comment = format_type_hint(&hint).expect("valid hint");
/// assert_eq!(parse_type_hint(&comment).expect("parses"), Some(hint.clone()));
///
/// // The hint rides the comment channel through export/import unchanged.
/// let bytes = b"fake-binary";
/// let sha = sha256_hex(bytes);
/// let mut annotations = BTreeMap::new();
/// annotations.insert(
///     0x1000u64,
///     Annotation { name: None, comment: Some(comment.clone()) },
/// );
/// let text =
///     build_document(&sha, bytes.len() as u64, &StoredMapping::Auto, &annotations)
///         .expect("export");
/// let doc = parse_document(&text).expect("parse");
/// let changes = validate_document(
///     &doc,
///     &sha,
///     bytes.len() as u64,
///     &StoredMapping::Auto,
///     &|_| false,
///     &BTreeMap::new(),
///     false,
/// )
/// .expect("valid");
/// assert_eq!(changes.len(), 1);
/// let back = changes[&0x1000u64].clone().expect("row stored");
/// assert_eq!(
///     parse_type_hint(back.comment.as_deref().expect("comment")).expect("parses"),
///     Some(hint)
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeHint {
    /// Struct name (non-empty).
    pub name: String,
    /// `sizeof` the struct in bytes (non-zero).
    pub size: u64,
    /// Field layouts; may be empty for an opaque struct with known size.
    pub fields: Vec<TypeField>,
}

/// Wire form of [`TypeHint`]: the same shape plus the `kind` tag, so
/// future hint kinds fail closed on parse instead of misdecoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WireHint {
    kind: String,
    name: String,
    size: u64,
    #[serde(default)]
    fields: Vec<TypeField>,
}

impl From<&TypeHint> for WireHint {
    fn from(h: &TypeHint) -> Self {
        Self {
            kind: TYPE_HINT_STRUCT_KIND.to_string(),
            name: h.name.clone(),
            size: h.size,
            fields: h.fields.clone(),
        }
    }
}

/// Check a hint's shape: names, sizes, and field bounds.
///
/// Overlapping fields are allowed (unions); each field's checked end must
/// lie within the struct size. Shape only: never consults the binary.
///
/// # Errors
/// [`Error::Invalid`] on empty names, zero sizes, integer overflow, or a
/// field ending past the struct size.
fn check_hint_shape(hint: &TypeHint) -> Result<()> {
    if hint.name.trim().is_empty() {
        return Err(Error::Invalid(
            "type hint needs a non-empty struct name".to_string(),
        ));
    }
    if hint.size == 0 {
        return Err(Error::Invalid(
            "type hint needs a non-zero struct size".to_string(),
        ));
    }
    for f in &hint.fields {
        if f.name.trim().is_empty() {
            return Err(Error::Invalid(
                "type hint needs a non-empty field name".to_string(),
            ));
        }
        if f.size == 0 {
            return Err(Error::Invalid(format!(
                "type hint field {:?} needs a non-zero size",
                f.name
            )));
        }
        let end = f.offset.checked_add(f.size).ok_or_else(|| {
            Error::Invalid(format!(
                "type hint field {:?} offset {:#x} plus size {:#x} overflows",
                f.name, f.offset, f.size
            ))
        })?;
        if end > hint.size {
            return Err(Error::Invalid(format!(
                "type hint field {:?} ends at {end} past struct size {}",
                f.name, hint.size
            )));
        }
    }
    Ok(())
}

/// Format `hint` as a comment-channel string: [`TYPE_HINT_PREFIX`] plus
/// compact JSON (`{"kind":"struct","name":..,"size":..,"fields":[..]}`).
///
/// The result stores via
/// [`Project::set_comment`](crate::Project::set_comment) (or
/// [`Project::set_type_hint`](crate::Project::set_type_hint)) under the
/// same any-address, 8 KiB-cap rules as any comment.
///
/// # Errors
/// [`Error::Invalid`] on shape violations (see [`TypeHint`]);
/// [`Error::Limit`] when the formatted hint exceeds
/// [`MAX_ANNOTATION_BYTES`](crate::db::MAX_ANNOTATION_BYTES);
/// [`Error::Storage`] on encoding failure.
pub fn format_type_hint(hint: &TypeHint) -> Result<String> {
    check_hint_shape(hint)?;
    let wire = WireHint::from(hint);
    let json = serde_json::to_string(&wire)
        .map_err(|e| Error::Storage(format!("encode type hint: {e}")))?;
    let text = format!("{TYPE_HINT_PREFIX}{json}");
    if text.len() > db::MAX_ANNOTATION_BYTES {
        return Err(Error::Limit(format!(
            "type hint of {} bytes exceeds {}",
            text.len(),
            db::MAX_ANNOTATION_BYTES
        )));
    }
    Ok(text)
}

/// Parse a comment that may carry a [`TypeHint`].
///
/// `None` (no error) for ordinary comments without the
/// [`TYPE_HINT_PREFIX`]; trailing free text after the hint's first line
/// (e.g. `format` output plus `"\nnoted by …"`) is ignored, so a hint and
/// a human note coexist at one address.
///
/// # Errors
/// [`Error::Invalid`] when the prefix is present but the JSON or the
/// shape is bad (wrong `kind`, malformed JSON, failed [`TypeHint`]
/// validation): a corrupt hint errors instead of decoding silently.
pub fn parse_type_hint(comment: &str) -> Result<Option<TypeHint>> {
    let Some(rest) = comment.strip_prefix(TYPE_HINT_PREFIX) else {
        return Ok(None);
    };
    let first = rest.lines().next().unwrap_or("").trim();
    let wire: WireHint = serde_json::from_str(first)
        .map_err(|e| Error::Invalid(format!("malformed type hint: {e}")))?;
    if wire.kind != TYPE_HINT_STRUCT_KIND {
        return Err(Error::Invalid(format!(
            "unsupported type hint kind {:?} (expected {TYPE_HINT_STRUCT_KIND:?})",
            wire.kind
        )));
    }
    let hint = TypeHint {
        name: wire.name,
        size: wire.size,
        fields: wire.fields,
    };
    check_hint_shape(&hint)?;
    Ok(Some(hint))
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
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
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
