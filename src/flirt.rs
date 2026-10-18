//! FLIRT-like library-function identification hints (read-only).
//!
//! Matches each function's leading bytes against a small static table of
//! common CRT/compiler idioms and reports the hits as hints. Hints are
//! evidence only: they never rename functions or write comments, and the
//! suggested names must be applied explicitly through [`crate::Project::rename_function`]
//! when an analyst agrees with them.
//!
//! Matching rule: a signature matches when the function's leading bytes
//! (decoded instructions at and after the entry, in address order, up to
//! [`MAX_SIGNATURE_WINDOW`] bytes) start with the signature's exact bytes,
//! restricted to the signature's architecture when one is set. All matches
//! are reported, longest first, so a specific leaf (e.g. `frame_ret0`)
//! coexists with its generic prologue hint (`frame_rbp`).
//!
//! Initial corpus (deliberately small; exact leading-byte prefixes):
//!
//! | id | bytes | arch | suggested name | idiom |
//! |----|-------|------|----------------|-------|
//! | `frame_rbp` | `55 48 89 E5` | x86_64 | `frame_setup_rbp` | `push rbp; mov rbp, rsp` frame prologue |
//! | `frame_ebp` | `55 89 E5` | x86_32 | `frame_setup_ebp` | `push ebp; mov ebp, esp` frame prologue |
//! | `ret0_xor_eax` | `31 C0 C3` | any x86 | `ret_0` | `xor eax, eax; ret` zero-return stub |
//! | `frame_ret0` | `55 48 89 E5 31 C0 5D C3` | x86_64 | `frame_ret_0` | framed zero-return leaf |
//! | `frame_ret1` | `55 48 89 E5 B8 01 00 00 00 5D C3` | x86_64 | `frame_ret_1` | framed return-1 leaf |
//! | `pad_nop_ret` | `90 C3` | any x86 | `pad_ret_stub` | `nop; ret` padding stub |
//!
//! The corpus covers frame setup plus return-constant leaves and one padding
//! shape: the shapes a first pass over CRT-adjacent compiler output meets.
//! Byte-prefix matching cannot verify boundaries or intent, so every row
//! stays a hint with its `reason` attached.

use std::cmp::Reverse;

use serde::{Deserialize, Serialize};

use crate::analysis::{Analysis, Function};
use crate::disasm::Arch;

/// Leading bytes examined per function (decoded instructions at and after
/// the entry, in address order). Covers the longest corpus signature with
/// room for wider follow-up patterns.
pub const MAX_SIGNATURE_WINDOW: usize = 32;

/// One corpus entry: an exact leading-byte prefix plus its hint text.
///
/// `arch` scopes the match (`None` matches any x86 mode the [`crate::disasm::Insn`] bytes
/// decode under, i.e. [`Arch::is_x86`]); `suggested_name` is a hint only,
/// never applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    /// Stable id used in [`FlirtHint::signature`].
    pub id: &'static str,
    /// Suggested name, reported only (never written to annotations).
    pub suggested_name: &'static str,
    /// Architecture scope, or `None` for any x86 mode.
    pub arch: Option<Arch>,
    /// Exact leading-byte prefix that matches.
    pub bytes: &'static [u8],
    /// Why this shape is a library/compiler hint, not a verified identity.
    pub reason: &'static str,
}

/// The initial CRT/compiler-idiom corpus (see the module docs for the table).
pub static SIGNATURES: &[Signature] = &[
    Signature {
        id: "frame_rbp",
        suggested_name: "frame_setup_rbp",
        arch: Some(Arch::X86_64),
        bytes: &[0x55, 0x48, 0x89, 0xE5],
        reason: "push rbp; mov rbp,rsp frame prologue (compiler frame-setup idiom)",
    },
    Signature {
        id: "frame_ebp",
        suggested_name: "frame_setup_ebp",
        arch: Some(Arch::X86_32),
        bytes: &[0x55, 0x89, 0xE5],
        reason: "push ebp; mov ebp,esp frame prologue (compiler frame-setup idiom)",
    },
    Signature {
        id: "ret0_xor_eax",
        suggested_name: "ret_0",
        arch: None,
        bytes: &[0x31, 0xC0, 0xC3],
        reason: "xor eax,eax; ret zero-return stub (compiler/CRT return-constant idiom)",
    },
    Signature {
        id: "frame_ret0",
        suggested_name: "frame_ret_0",
        arch: Some(Arch::X86_64),
        bytes: &[0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3],
        reason: "framed zero-return leaf (push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret)",
    },
    Signature {
        id: "frame_ret1",
        suggested_name: "frame_ret_1",
        arch: Some(Arch::X86_64),
        bytes: &[
            0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3,
        ],
        reason: "framed return-1 leaf (mov eax,1 under a frame)",
    },
    Signature {
        id: "pad_nop_ret",
        suggested_name: "pad_ret_stub",
        arch: None,
        bytes: &[0x90, 0xC3],
        reason: "nop; ret padding stub (alignment/padding idiom)",
    },
];

/// One library hint: a corpus signature matched at a function entry.
///
/// JSON pairs `entry` with `entry_hex` (`entry_hex` is recomputed on
/// serialize and ignored on deserialize).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FlirtHint {
    /// Function entry address the signature matched at.
    pub entry: u64,
    /// Corpus id (see [`SIGNATURES`]).
    pub signature: String,
    /// Suggested name (hint only, never applied automatically).
    pub suggested_name: String,
    /// Why this shape is a hint, not a verified identity.
    pub reason: String,
}

impl Serialize for FlirtHint {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("FlirtHint", 6)?;
        st.serialize_field("id", &format!("func@{:#x}", self.entry))?;
        st.serialize_field("entry", &self.entry)?;
        st.serialize_field("entry_hex", &crate::addr_hex(self.entry))?;
        st.serialize_field("signature", &self.signature)?;
        st.serialize_field("suggested_name", &self.suggested_name)?;
        st.serialize_field("reason", &self.reason)?;
        st.end()
    }
}

/// Leading bytes of `func`: decoded instruction bytes at and after the entry
/// in address order, capped at [`MAX_SIGNATURE_WINDOW`].
///
/// Blocks iterate in start order (already address order), stopping once the
/// window fills so large functions never decode past the signature prefix.
#[must_use]
pub fn leading_bytes(func: &Function) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_SIGNATURE_WINDOW);
    for insn in func
        .blocks
        .range(func.entry..)
        .flat_map(|(_, b)| b.insns.iter())
        .filter(|i| i.addr >= func.entry)
    {
        if out.len() >= MAX_SIGNATURE_WINDOW {
            break;
        }
        let take = (MAX_SIGNATURE_WINDOW - out.len()).min(insn.bytes.len());
        out.extend_from_slice(&insn.bytes[..take]);
    }
    out
}

/// Corpus signatures matching `leading` under `arch`, longest first.
#[must_use]
pub fn match_leading(arch: Arch, leading: &[u8]) -> Vec<&'static Signature> {
    let mut hits: Vec<&'static Signature> = SIGNATURES
        .iter()
        .filter(|s| match s.arch {
            Some(a) => a == arch,
            None => arch.is_x86(),
        })
        .filter(|s| leading.starts_with(s.bytes))
        .collect();
    hits.sort_by_key(|s| Reverse(s.bytes.len()));
    hits
}

/// Hints for one function: every corpus match at its entry, longest first.
///
/// Read-only over decoded bytes; never touches annotations.
#[must_use]
pub fn hints_for_function(arch: Arch, func: &Function) -> Vec<FlirtHint> {
    let leading = leading_bytes(func);
    match_leading(arch, &leading)
        .into_iter()
        .map(|s| FlirtHint {
            entry: func.entry,
            signature: s.id.to_string(),
            suggested_name: s.suggested_name.to_string(),
            reason: s.reason.to_string(),
        })
        .collect()
}

/// Hints for every function in `analysis`, ordered by entry.
///
/// Read-only; the binary and the sidecar are never written.
#[must_use]
pub fn hints_for_analysis(analysis: &Analysis) -> Vec<FlirtHint> {
    analysis
        .functions
        .values()
        .flat_map(|f| hints_for_function(analysis.arch, f))
        .collect()
}
