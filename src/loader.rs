//! M1 loader: binary format readers mapped to shared [`Segment`]s.
//!
//! ELF/PE/Mach-O/COFF go through the `object` crate (parent epic
//! `rsdbg-m1-loader-0tp`); the LE branch is a custom pure-Rust reader in
//! [`le`] because `object` has no Linear Executable support. Raw blobs
//! (firmware, shellcode, `--base` dumps) map via [`load_raw`]. Printable
//! runs live in [`strings`].

pub mod debuginfo;
pub mod le;
pub mod strings;

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use object::{FileKind, Object, ObjectSection, ObjectSegment, ObjectSymbol};

use crate::disasm::Arch;
use crate::error::{Error, Result};
use crate::loader::le::{LeImage, LeTarget};

/// Cap on segments per binary.
pub const MAX_SEGMENTS: usize = 256;
/// Cap on sections per binary.
pub const MAX_SECTIONS: usize = 2048;
/// Cap on materialized segment bytes and, separately, file-backed section
/// bytes named by the table (zero-fill/`bss` tails stay virtual).
pub const MAX_MAPPED_BYTES: u64 = 256 * 1024 * 1024;
/// Cap on imports per binary.
pub const MAX_IMPORTS: usize = 100_000;
/// Cap on exports per binary.
pub const MAX_EXPORTS: usize = 100_000;
/// Cap on defined text symbols (locals and globals) per binary.
///
/// Matches [`MAX_IMPORTS`]/[`MAX_EXPORTS`]: 100k short names fit the
/// [`MAX_METADATA_BYTES`] budget with headroom, and the per-symbol work
/// is one binary search over the executable ranges plus one budgeted
/// name copy.
pub const MAX_SYMBOLS: usize = 100_000;
/// Cap on total input bytes read before parsing (all formats).
///
/// Twice [`MAX_MAPPED_BYTES`] so containers with large unmapped
/// overlays/debug data still open while pre-parse allocation stays bounded.
pub const MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;
/// Cap on one decoded symbol/section/library name in bytes.
///
/// 4 KiB covers mangled C++/Rust template expansions while keeping a
/// single name allocation trivial.
pub const MAX_NAME_BYTES: usize = 4096;
/// Cap on one demangled C++ name in bytes.
///
/// Demanglers expand templates, so the output budget is twice the input
/// name budget while still bounding each owned copy.
pub const MAX_DEMANGLED_BYTES: usize = 8192;
/// Cap on aggregate owned name/demangled bytes per binary.
///
/// 16 MiB holds 100k typical (~160 B) names with headroom yet rejects
/// 100k repeated 4 KiB names (~400 MiB) well before OOM.
pub const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
/// Cap on PE `.pdata` function ranges per binary.
///
/// Matches [`MAX_SYMBOLS`]: one range per non-leaf function, bounded like
/// any other table-derived seed source.
pub const MAX_PDATA_FUNCS: usize = 100_000;
/// Cap on PE TLS callback addresses per binary.
///
/// Callbacks are a null-terminated pointer array; real images carry a
/// handful, so this cap only bounds hostile tables.
pub const MAX_TLS_CALLBACKS: usize = 4096;
/// Cap on ELF init/fini addresses per binary.
///
/// Covers `.init_array`/`.fini_array`/`.ctors` entries plus `DT_INIT`,
/// `DT_FINI`, and `DT_INIT_ARRAY`/`DT_FINI_ARRAY` slots.
pub const MAX_INIT_FUNCS: usize = 100_000;
/// Cap on Mach-O `LC_FUNCTION_STARTS` addresses per binary.
///
/// Matches [`MAX_SYMBOLS`]: one start per function, bounded like any
/// other table-derived seed source.
pub const MAX_FUNC_STARTS: usize = 100_000;
/// Base virtual address for synthetic relocatable layouts.
///
/// Relocatable objects (ELF `ET_REL`, COFF `.obj`) link at address 0, so
/// every section overlaps. The loader lays mapped sections out from here
/// instead, leaving the null page unmapped like a linked image.
pub const RELOC_BASE: u64 = 0x10000;
/// Alignment between synthetic relocatable sections.
///
/// Sections lay out in file order, each start rounded up to this boundary
/// (or its own stricter alignment), so no two mapped ranges overlap.
pub const RELOC_ALIGN: u64 = 16;
/// Cap on applied relocations per relocatable object.
///
/// Matches [`MAX_IMPORTS`]: one relocation row is at most one import or
/// one patched site, bounded like any other table-derived source.
pub const MAX_RELOCS: usize = 100_000;

/// One loaded object: a contiguous virtual range with its file bytes.
///
/// `data` holds the file-backed prefix of the range (zero-padded per page by
/// the LE reader); `mem_size` is the full in-memory size, which may exceed
/// `data.len()` when the tail is zero-fill or `bss`-like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Flat virtual address of the first byte.
    pub vaddr: u64,
    /// In-memory size of the object.
    pub mem_size: u64,
    /// File-backed bytes starting at `vaddr`.
    pub data: Vec<u8>,
    /// Object is readable.
    pub readable: bool,
    /// Object is writable.
    pub writable: bool,
    /// Object is executable.
    pub executable: bool,
}

impl Segment {
    /// Architecture the segment's code targets (LE is x86-only for now).
    #[must_use]
    pub fn arch(&self) -> Arch {
        Arch::X86_32
    }

    /// Length of the file-backed prefix.
    #[must_use]
    pub fn file_size(&self) -> usize {
        self.data.len()
    }
}

/// Detected container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    /// ELF (Unix).
    Elf,
    /// PE (Windows).
    Pe,
    /// Mach-O (macOS).
    MachO,
    /// COFF relocatable object (e.g. Windows `.obj`): sections lay out at
    /// synthetic non-overlapping addresses from [`RELOC_BASE`] (aligned to
    /// [`RELOC_ALIGN`] in file order), entry is `None`, and imports are
    /// synthesized from undefined symbols referenced by relocations in
    /// executable sections (each carrying a synthetic stub `address`).
    Coff,
    /// Linear Executable (DOS4GW), analyzed as [`Arch::X86_32`].
    Le,
    /// Flat bytes with caller-supplied architecture and base.
    Raw,
}

/// One named section mapping over the [`Segment`] byte store.
///
/// Sections carry no owned bytes: `file_off` plus `file_size` name the
/// file-backed prefix at `vaddr` (`file_size` is `0` for `bss`-like
/// sections whose `size` is purely virtual, and may trail `size` when the
/// tail is zero-fill). Byte reads resolve through segments by VA, so a
/// container holds the input once instead of twice.
#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    /// Section name (`objN` for LE objects, which have no names).
    pub name: String,
    /// Flat virtual address of the first byte.
    pub vaddr: u64,
    /// In-memory size.
    pub size: u64,
    /// File offset of the raw data (`0` when the section has no on-disk
    /// range, e.g. `bss`, or the container has no section table).
    pub file_off: u64,
    /// File-backed byte count starting at `vaddr`.
    pub file_size: u64,
    /// Shannon entropy of the file-backed bytes, in bits per byte (0-8).
    pub entropy: f64,
    /// Section is readable.
    pub readable: bool,
    /// Section is writable.
    pub writable: bool,
    /// Section is executable.
    pub executable: bool,
}

impl Section {
    /// Shannon entropy of the file-backed bytes, in bits per byte (0–8).
    ///
    /// Stored at load time from the file-backed prefix; empty
    /// (virtual-only, e.g. `bss`) sections report `0.0`. Values near
    /// 8 mark dense or encrypted/packed bytes; values under ~6 are typical
    /// of code and tables. First-minute triage compares this against ~7.2
    /// when judging whether a section is packed.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        self.entropy
    }
}

/// Shannon entropy of `data` in bits per byte (0–8); empty input is `0.0`.
#[must_use]
pub fn section_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for b in data {
        counts[usize::from(*b)] += 1;
    }
    let total = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// One imported symbol: `library!name`, where `name` is `#ordinal` for
/// ordinal-only imports and `@0xoff` for LE name-table references.
///
/// Ordinal-only imports carry `ordinal: Some(n)` plus `unresolved: true`
/// because the providing DLL's export names are not visible from the
/// importing image; named imports carry `ordinal: None` and
/// `unresolved: false`. C++ names (MSVC `?...` and Itanium `_Z...`)
/// additionally carry `demangled: Some(...)` when the demangler succeeds.
/// Resolved imports carry the pointer they are called through in
/// `address`: the `__stubs`/`__auth_stubs` entry on Mach-O, the IAT slot
/// on PE, the GOT slot named by `.rela.plt`/`.rel.plt` `R_*_JUMP_SLOT`
/// relocations on ELF, or the synthetic stub past the last section on
/// relocatable objects (ELF `.o`, COFF `.obj`). Unresolved imports carry
/// `address: None`. JSON
/// pairs `address` with `address_hex` (`null` on both sides for
/// address-less imports).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ImportRef {
    /// Providing module (`""` when the format names none).
    pub library: String,
    /// Symbol name, `#ordinal`, or `@0xoff`.
    pub name: String,
    /// Ordinal number for ordinal-only imports (`None` for named imports).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    /// True when the import has no name to resolve (ordinal-only).
    #[serde(default)]
    pub unresolved: bool,
    /// Demangled C++ name, when `name` is a recognized mangling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    /// `__stubs`/`__auth_stubs` entry address on Mach-O, IAT slot on PE,
    /// GOT slot on ELF, synthetic stub on relocatable objects (`None` for
    /// unmapped imports; see `load`).
    #[serde(default)]
    pub address: Option<u64>,
}

impl Serialize for ImportRef {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut len = 5;
        if self.ordinal.is_some() {
            len += 1;
        }
        if self.demangled.is_some() {
            len += 1;
        }
        let mut st = serializer.serialize_struct("ImportRef", len)?;
        st.serialize_field("library", &self.library)?;
        st.serialize_field("name", &self.name)?;
        if self.ordinal.is_some() {
            st.serialize_field("ordinal", &self.ordinal)?;
        } else {
            st.skip_field("ordinal")?;
        }
        st.serialize_field("unresolved", &self.unresolved)?;
        if self.demangled.is_some() {
            st.serialize_field("demangled", &self.demangled)?;
        } else {
            st.skip_field("demangled")?;
        }
        st.serialize_field("address", &self.address)?;
        st.serialize_field("address_hex", &self.address.map(crate::addr_hex))?;
        st.end()
    }
}

/// Identity key for LE import dedupe: the [`ImportRef`] fields compared by
/// [`convert_le`]'s membership index, so index hits equal `Vec::contains`
/// hits, including distinct module indices decoding to one `library` and
/// real names colliding with the `mod#N` fallback.
type LeImportKey = (String, String, Option<u32>, bool, Option<String>);

/// One exported symbol.
///
/// Ordinal-only exports carry `ordinal: Some(n)` with `name` as `#n`;
/// named exports carry `ordinal: None`. C++ names additionally carry
/// `demangled: Some(...)` when the demangler succeeds. JSON pairs `address`
/// with `address_hex` (`null` on both sides for address-less exports).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExportRef {
    /// Symbol name (LE: decimal ordinal).
    pub name: String,
    /// Export address (`None` for re-exports, TLS, and resolver stubs).
    pub address: Option<u64>,
    /// Ordinal number for ordinal-only exports (`None` for named exports).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    /// Demangled C++ name, when `name` is a recognized mangling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
}

impl Serialize for ExportRef {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut len = 3;
        if self.ordinal.is_some() {
            len += 1;
        }
        if self.demangled.is_some() {
            len += 1;
        }
        let mut st = serializer.serialize_struct("ExportRef", len)?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("address", &self.address)?;
        st.serialize_field("address_hex", &self.address.map(crate::addr_hex))?;
        if self.ordinal.is_some() {
            st.serialize_field("ordinal", &self.ordinal)?;
        } else {
            st.skip_field("ordinal")?;
        }
        if self.demangled.is_some() {
            st.serialize_field("demangled", &self.demangled)?;
        } else {
            st.skip_field("demangled")?;
        }
        st.end()
    }
}

/// One defined code symbol from the object symbol table.
///
/// Unlike [`ExportRef`], this covers locals: static functions, section-
/// relative labels, and any other `SymbolKind::Text` definition in an
/// executable section, whether or not it is exported. C++ names carry
/// `demangled: Some(...)` when the demangler succeeds. JSON pairs
/// `address` with `address_hex`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SymbolRef {
    /// Symbol name as recorded in the table.
    pub name: String,
    /// Canonical code address (Thumb bit cleared on ARM, see
    /// [`canonical_code_addr`]).
    pub address: u64,
    /// Demangled C++ name, when `name` is a recognized mangling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
}

impl Serialize for SymbolRef {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut len = 3;
        if self.demangled.is_some() {
            len += 1;
        }
        let mut st = serializer.serialize_struct("SymbolRef", len)?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("address", &self.address)?;
        st.serialize_field("address_hex", &crate::addr_hex(self.address))?;
        if self.demangled.is_some() {
            st.serialize_field("demangled", &self.demangled)?;
        } else {
            st.skip_field("demangled")?;
        }
        st.end()
    }
}

/// ARM/Thumb decode hints for 32-bit ARM containers.
///
/// ARM ELF images mix ARM and Thumb code in one executable segment. The
/// mode is recorded per address: `$a`/`$t` mapping symbols mark ARM/Thumb
/// regions, and `STT_FUNC` symbols carry the Thumb bit (bit 0) for Thumb
/// functions. These hints let analysis seed each address in its own mode
/// instead of decoding everything as ARM.
///
/// Empty on other architectures and on raw/LE/relocatable mappings (which
/// have no mapping tables). All addresses are canonical (Thumb bit
/// cleared, see [`canonical_code_addr`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArmHints {
    /// Thumb-mode code ranges from `$t` mapping symbols, as
    /// `(start, end)` with `start < end`, in table order.
    pub thumb_ranges: Vec<(u64, u64)>,
    /// ARM-mode code ranges from `$a` mapping symbols, same shape.
    pub arm_ranges: Vec<(u64, u64)>,
    /// Canonical Thumb-function addresses (`STT_FUNC` with bit 0 set).
    pub thumb_seeds: Vec<u64>,
}

/// A parsed binary ready for disassembly and analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedBinary {
    /// Container format.
    pub format: BinaryFormat,
    /// Target architecture for disassembly.
    pub arch: Arch,
    /// Entry-point virtual address (`None` for libraries/objects).
    pub entry: Option<u64>,
    /// Loadable segments in file order.
    pub segments: Vec<Segment>,
    /// Sections in file order (empty for raw blobs, which have no table).
    pub sections: Vec<Section>,
    /// Imported symbols in table order.
    pub imports: Vec<ImportRef>,
    /// Exported symbols in table order.
    pub exports: Vec<ExportRef>,
    /// Defined code symbols in table order, deduplicated by address.
    ///
    /// Empty for raw blobs and LE images, which have no symbol tables.
    pub symbols: Vec<SymbolRef>,
    /// PE `.pdata` function ranges as `(start_va, end_va)` in table order.
    ///
    /// Exact starts and ends for every non-leaf function on 64-bit Windows
    /// (`RUNTIME_FUNCTION` records); empty on other formats. Capped at
    /// [`MAX_PDATA_FUNCS`].
    pub pdata_funcs: Vec<(u64, u64)>,
    /// PE TLS callback addresses in callback-array order.
    ///
    /// `IMAGE_TLS_DIRECTORY.AddressOfCallBacks` null-terminated array;
    /// empty when absent (most binaries) or on other formats. Capped at
    /// [`MAX_TLS_CALLBACKS`].
    pub tls_callbacks: Vec<u64>,
    /// ELF init/fini addresses in discovery order.
    ///
    /// `.init_array`/`.fini_array`/`.ctors`/`.dtors` entries plus `DT_INIT`,
    /// `DT_FINI`, and `DT_INIT_ARRAY`/`DT_FINI_ARRAY` slots; empty on
    /// other formats. Capped at [`MAX_INIT_FUNCS`].
    pub init_funcs: Vec<u64>,
    /// Mach-O `LC_FUNCTION_STARTS` addresses in table order.
    ///
    /// Exact starts decoded from ULEB deltas off the `__TEXT` base; empty
    /// on other formats. Capped at [`MAX_FUNC_STARTS`].
    pub func_starts: Vec<u64>,
    /// Debug-info functions: DWARF `DW_TAG_subprogram` rows (embedded or
    /// `--debug-file`) and `--pdb` public/procedure rows.
    ///
    /// Exact starts with optional ends and names; empty without debug info
    /// (raw blobs, LE images, and relocatable objects never carry rows).
    /// Capped at [`debuginfo::MAX_DEBUG_FUNCS`].
    pub debug_funcs: Vec<debuginfo::DebugFunc>,
    /// Whether this binary is a relocatable object with a synthetic layout.
    ///
    /// True for COFF `.obj` and ELF `ET_REL`: sections lay out at
    /// non-overlapping synthetic addresses from [`RELOC_BASE`] (see
    /// [`RELOC_ALIGN`]), relocations are applied to the mapped bytes, and
    /// undefined symbols referenced from executable code become imports
    /// with synthetic stub addresses. Linked images report `false`.
    pub relocatable: bool,
    /// 32-bit ARM decode hints (mapping symbols, Thumb-bit functions).
    ///
    /// Empty on other architectures and on raw/LE/relocatable mappings,
    /// which have no mapping tables.
    pub arm_hints: ArmHints,
}

/// Options for [`load_raw`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawOptions {
    /// Virtual address of the first byte.
    pub base: u64,
    /// Architecture to disassemble as.
    pub arch: Arch,
    /// Entry-point address, if known.
    pub entry: Option<u64>,
}

/// True when `bytes` carry a recognized container magic (LE included),
/// whether or not the full parse succeeds.
///
/// [`crate::Project`] falls back to raw only below this line:
/// recognized-but-malformed containers report their parse error instead
/// of silently opening as raw x86-64.
#[must_use]
pub fn is_recognized(bytes: &[u8]) -> bool {
    le::is_le(bytes) || FileKind::parse(bytes).is_ok()
}

/// Parse any supported binary: LE via [`le`], ELF/PE/Mach-O/COFF via `object`.
///
/// Input longer than [`MAX_INPUT_BYTES`] is rejected before sniffing so a
/// huge blob cannot allocate before table caps run; oversize returns
/// [`Error::Limit`] (never [`Error::Invalid`]) so
/// [`crate::load_or_raw`](crate::Project) does not fall back to raw.
///
/// Fat (universal) Mach-O containers need a slice selection; without one
/// this errors listing the available slice archs (see [`load_with_slice`]).
///
/// # Errors
/// [`Error::Invalid`] on empty or unrecognized input, [`Error::Unsupported`]
/// on recognized formats this loader does not handle (Wasm, archives, …)
/// or architectures without a disassembler, [`Error::Limit`] when input,
/// table, byte, name, demangled, or aggregate metadata caps are exceeded.
pub fn load(bytes: &[u8]) -> Result<LoadedBinary> {
    load_with_slice(bytes, None)
}

/// Parse any supported binary, selecting a fat Mach-O slice by arch name.
///
/// For thin containers `fat_arch` must be `None`: supplying a selection
/// for thin (non-fat) input errors with [`Error::Invalid`] instead of
/// silently ignoring the flag, so a misspelled workflow fails loudly
/// rather than opening under an unintended mapping. For fat input the slice
/// is required — a missing, unknown, or ambiguous selection errors with
/// [`Error::Invalid`] listing the available slice archs, so the failure
/// names what to retry with instead of surfacing an `object` parse error.
/// The selected slice bytes re-enter the `load_object` Mach-O path, so thin and
/// sliced opens share every table cap and mapping rule.
///
/// `fat_arch` accepts the canonical loader arch names case-insensitively
/// (`x86_64`, `x86_32`, `aarch64`, `arm32`) plus the common `lipo` aliases
/// (`x86-64`, `i386`/`x86`, `arm64`, `arm`). This is the internal hook the
/// CLI `--fat-arch` / MCP `fat_arch` plumbing wires to: pass the flag value
/// through unchanged.
///
/// # Errors
/// Same as [`load`], plus [`Error::Invalid`] when a selection is supplied
/// for thin input, when fat input has no usable selection (missing,
/// unknown, or ambiguous), or when the selected slice range is unreadable.
pub fn load_with_slice(bytes: &[u8], fat_arch: Option<&str>) -> Result<LoadedBinary> {
    load_with_debug(bytes, fat_arch, &debuginfo::DebugInputs::none())
}

/// [`load_with_slice`] with explicit debug inputs.
///
/// Embedded DWARF parses automatically; `debug.external` (a `--debug-file`
/// object) and `debug.pdb` (a `--pdb` file, PE only) attach their function
/// rows. LE images accept an external DWARF object but reject `--pdb`.
///
/// # Errors
/// Same as [`load_with_slice`], plus [`Error::Invalid`] when `--pdb`
/// names a non-PE binary or fails to parse, or when `--debug-file`
/// parses but carries no DWARF sections.
pub fn load_with_debug(
    bytes: &[u8],
    fat_arch: Option<&str>,
    debug: &debuginfo::DebugInputs,
) -> Result<LoadedBinary> {
    if bytes.is_empty() {
        return Err(Error::Invalid("empty input".to_string()));
    }
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(Error::Limit("input exceeds 512 MiB".to_string()));
    }
    if le::is_le(bytes) {
        if fat_arch.is_some() {
            return Err(Error::Invalid(
                "--fat-arch selects a fat Mach-O slice, but the input is not a fat container"
                    .to_string(),
            ));
        }
        let mut bin = convert_le(le::parse_le(bytes)?);
        if let Some(pdb) = &debug.pdb {
            return Err(Error::Invalid(format!(
                "{}: PDB input needs a PE binary, got LE",
                pdb.label
            )));
        }
        if let Some(ext) = &debug.external {
            let mut meta_bytes: u64 = 0;
            let funcs = debuginfo::dwarf_funcs(&ext.bytes, &ext.label, bin.arch, &mut meta_bytes)?;
            bin.debug_funcs = filter_debug_funcs(funcs, &bin.sections, &bin.segments);
        }
        return Ok(bin);
    }
    let kind = FileKind::parse(bytes).map_err(|e| {
        if fat_arch.is_some() {
            Error::Invalid(format!("--fat-arch requires a fat Mach-O container: {e}"))
        } else {
            Error::Invalid(format!("unrecognized binary format: {e}"))
        }
    })?;
    if !matches!(kind, FileKind::MachOFat32 | FileKind::MachOFat64) && fat_arch.is_some() {
        return Err(Error::Invalid(
            "--fat-arch selects a fat Mach-O slice, but the input is not a fat container"
                .to_string(),
        ));
    }
    match kind {
        FileKind::Elf32 | FileKind::Elf64 => load_object(bytes, BinaryFormat::Elf, debug),
        FileKind::Pe32 | FileKind::Pe64 => load_object(bytes, BinaryFormat::Pe, debug),
        FileKind::MachO32 | FileKind::MachO64 => load_object(bytes, BinaryFormat::MachO, debug),
        FileKind::MachOFat32 | FileKind::MachOFat64 => load_fat_slice(bytes, kind, fat_arch, debug),
        FileKind::Coff => load_object(bytes, BinaryFormat::Coff, debug),
        other => Err(Error::Unsupported(format!("file kind {other:?}"))),
    }
}

/// Keep executable-range starts, deduplicated and capped, for opens whose
/// container parse does not run [`debuginfo::collect_debug_funcs`] (LE with
/// an external DWARF object; raw blobs via the same rule in `lib.rs`).
#[must_use]
pub fn filter_debug_funcs(
    funcs: Vec<debuginfo::DebugFunc>,
    sections: &[Section],
    segments: &[Segment],
) -> Vec<debuginfo::DebugFunc> {
    debuginfo::finalize(funcs, sections, segments)
}

/// Merged executable address ranges over sections (segments when no
/// executable section exists).
///
/// Shared by symbol collection and debug-info filtering so both agree on
/// what "executable" means: section ranges win when present, segments are
/// the fallback for section-less layouts, and overlaps merge so a binary
/// search (or linear scan) cannot miss a hit hiding behind a neighbor.
fn merged_exec_ranges(sections: &[Section], segments: &[Segment]) -> Vec<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for s in sections {
        if s.executable && s.size > 0 {
            ranges.push((s.vaddr, s.vaddr.saturating_add(s.size)));
        }
    }
    if ranges.is_empty() {
        for s in segments {
            if s.executable && s.mem_size > 0 {
                ranges.push((s.vaddr, s.vaddr.saturating_add(s.mem_size)));
            }
        }
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        if let Some((_, last_hi)) = merged.last_mut()
            && lo <= *last_hi
        {
            *last_hi = (*last_hi).max(hi);
            continue;
        }
        merged.push((lo, hi));
    }
    merged
}

/// Canonical raw arch name for diagnostics (`x86_64`, `x86_32`, `aarch64`,
/// `arm32`, `thumb`, `riscv32`, `riscv64`).
#[must_use]
pub fn raw_arch_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "x86_64",
        Arch::X86_32 => "x86_32",
        Arch::Aarch64 => "aarch64",
        Arch::Arm32 => "arm32",
        Arch::Thumb => "thumb",
        Arch::Riscv32 => "riscv32",
        Arch::Riscv64 => "riscv64",
    }
}

/// Required entry alignment in bytes for a raw [`Arch`].
///
/// x86 targets decode from any byte; AArch64/ARM32 need 4-byte words;
/// Thumb and RISC-V need 2-byte halfwords (their 4-byte forms still
/// require 4-byte alignment, enforced by the decoder, not the entry).
/// Bases accept any alignment: only the entry must satisfy the mode.
#[must_use]
pub fn raw_entry_alignment(arch: Arch) -> u64 {
    match arch {
        Arch::X86_64 | Arch::X86_32 => 1,
        Arch::Aarch64 | Arch::Arm32 => 4,
        Arch::Thumb | Arch::Riscv32 | Arch::Riscv64 => 2,
    }
}

/// Map a raw blob to a single `RWX` segment at `opts.base`.
///
/// Permissions are unknown for raw input; the segment is marked `RWX` as the
/// neutral stand-in. Sections/imports/exports/symbols are empty: raw has
/// no tables.
///
/// # Errors
/// [`Error::Invalid`] on empty input, base-plus-length overflow, an entry
/// outside the mapped range, or a mode-misaligned entry;
/// [`Error::Limit`] when the blob exceeds [`MAX_MAPPED_BYTES`].
pub fn load_raw(bytes: &[u8], opts: RawOptions) -> Result<LoadedBinary> {
    load_raw_vec(bytes.to_vec(), opts)
}

/// [`load_raw`] taking ownership of the input: the segment reuses the
/// caller's allocation instead of copying it, so a raw open holds the input
/// once. Open paths prefer this; the borrowing form stays for callers that
/// only hold a slice.
///
/// # Errors
/// Same as [`load_raw`].
pub fn load_raw_vec(bytes: Vec<u8>, opts: RawOptions) -> Result<LoadedBinary> {
    if bytes.is_empty() {
        return Err(Error::Invalid("empty raw input".to_string()));
    }
    if bytes.len() as u64 > MAX_MAPPED_BYTES {
        return Err(Error::Limit("raw blob exceeds 256 MiB".to_string()));
    }
    let len = bytes.len() as u64;
    let end = opts.base.checked_add(len).ok_or_else(|| {
        Error::Invalid(format!(
            "raw base {:#x} with length {len} overflows address space",
            opts.base
        ))
    })?;
    if let Some(entry) = opts.entry {
        if entry < opts.base || entry >= end {
            return Err(Error::Invalid(format!(
                "raw entry {entry:#x} outside mapped range {:#x}..{end:#x}",
                opts.base
            )));
        }
        let align = raw_entry_alignment(opts.arch);
        if entry % align != 0 {
            return Err(Error::Invalid(format!(
                "raw entry {entry:#x} misaligned for {} (needs {align}-byte alignment)",
                raw_arch_name(opts.arch)
            )));
        }
    }
    Ok(LoadedBinary {
        format: BinaryFormat::Raw,
        arch: opts.arch,
        entry: opts.entry,
        segments: vec![Segment {
            vaddr: opts.base,
            mem_size: len,
            data: bytes,
            readable: true,
            writable: true,
            executable: true,
        }],
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        symbols: Vec::new(),
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        debug_funcs: Vec::new(),
        relocatable: false,
        arm_hints: ArmHints::default(),
    })
}

/// Map an `object` architecture to a disassembler target.
///
/// 32-bit ARM containers default to ARM mode; Thumb regions decode through
/// [`Arch::Thumb`] seeds derived from [`ArmHints`] (mapping symbols and
/// Thumb-bit function addresses), direct `blx` targets, and explicit
/// `define-func --mode` seeds.
///
/// # Errors
/// [`Error::Unsupported`] for any architecture without a disassembler.
pub fn arch_from_object(arch: object::Architecture) -> Result<Arch> {
    use object::Architecture as A;
    match arch {
        A::X86_64 | A::X86_64_X32 => Ok(Arch::X86_64),
        A::I386 => Ok(Arch::X86_32),
        A::Aarch64 | A::Aarch64_Ilp32 => Ok(Arch::Aarch64),
        A::Arm => Ok(Arch::Arm32),
        A::Riscv32 => Ok(Arch::Riscv32),
        A::Riscv64 => Ok(Arch::Riscv64),
        other => Err(Error::Unsupported(format!("architecture {other:?}"))),
    }
}

/// Canonical code address for `addr` under `arch`.
///
/// 32-bit ARM containers link Thumb functions with bit 0 set; the
/// address the decoder (and every seed/name/table row) uses clears it.
/// Every other architecture passes through unchanged. Apply at the
/// producer (loader tables), never at each consumer, so seeds, names,
/// and `symbols` output agree on one address per function.
#[must_use]
pub fn canonical_code_addr(arch: Arch, addr: u64) -> u64 {
    match arch {
        Arch::Arm32 => addr & !1,
        _ => addr,
    }
}

/// True when `bytes` hold an ELF relocatable object (`ET_REL`).
///
/// Reads only the ELF ident plus `e_type`, honoring the file's own byte
/// order; anything shorter, non-ELF, or with an unknown encoding is not
/// relocatable (linked ELF images report `false` here and keep the
/// segment mapping).
#[must_use]
fn is_elf_relocatable(bytes: &[u8]) -> bool {
    if bytes.len() < 18 || bytes[0..4] != [0x7F, b'E', b'L', b'F'] {
        return false;
    }
    match bytes[5] {
        1 => u16::from_le_bytes([bytes[16], bytes[17]]) == 1,
        2 => u16::from_be_bytes([bytes[16], bytes[17]]) == 1,
        _ => false,
    }
}

/// Round `v` up to `align` (a power of two; `0` means no alignment).
fn align_up(v: u64, align: u64) -> Option<u64> {
    if align <= 1 {
        return Some(v);
    }
    let mask = align.wrapping_sub(1);
    if align & mask != 0 {
        return None;
    }
    v.checked_add(mask).map(|a| a & !mask)
}

/// Whether a section kind maps into the synthetic relocatable layout.
///
/// Loadable code/data (including zero-fill `bss`) map; debug, metadata,
/// linker, and note sections stay out, exactly like a linker discarding
/// non-`ALLOC` sections.
fn is_reloc_mapped_kind(kind: object::SectionKind) -> bool {
    use object::SectionKind as K;
    matches!(
        kind,
        K::Text
            | K::Data
            | K::ReadOnlyData
            | K::ReadOnlyString
            | K::UninitializedData
            | K::Tls
            | K::UninitializedTls
            | K::TlsVariables
    )
}

/// Load a relocatable object (ELF `ET_REL` or COFF `.obj`) at synthetic
/// addresses with relocations applied and externals as imports.
///
/// Sections that map (see [`is_reloc_mapped_kind`]) lay out in file order
/// from [`RELOC_BASE`], each start rounded up to its own alignment or
/// [`RELOC_ALIGN`]. Defined `Text` symbols remap through their section's
/// base and seed analysis like linked-image symbols; relocations in
/// executable sections patch the mapped bytes (`Relative`/`PltRelative`
/// as `target + addend - place`, `Absolute` as `target + addend`), and
/// undefined symbols referenced from executable code become imports with
/// synthetic stub addresses past the last section (direct calls to them
/// resolve through the same stub map as Mach-O imports in analysis).
/// Anything unhandled (unknown kinds, unreadable symbols, out-of-range
/// places) is skipped, never guessed.
///
/// # Errors
/// [`Error::Limit`] when sections, symbols, imports, relocations, mapped
/// bytes, or metadata exceed their caps.
fn load_relocatable<'a>(
    file: &object::File<'a, &'a [u8]>,
    format: BinaryFormat,
    arch: Arch,
    meta_bytes: &mut u64,
    demangle_cache: &mut HashMap<String, Option<String>>,
) -> Result<LoadedBinary> {
    use object::RelocationKind as K;
    let le = file.endianness() == object::Endianness::Little;
    // Sections in file order with their synthetic bases.
    struct Mapped {
        name: String,
        base: u64,
        size: u64,
        file_off: u64,
        data: Vec<u8>,
        readable: bool,
        writable: bool,
        executable: bool,
    }
    let mut mapped: Vec<Mapped> = Vec::new();
    let mut by_index: HashMap<object::SectionIndex, usize> = HashMap::new();
    let mut cursor = RELOC_BASE;
    let mut smapped: u64 = 0;
    for sec in file.sections() {
        if !is_reloc_mapped_kind(sec.kind()) {
            continue;
        }
        let size = sec.size();
        if size == 0 {
            continue;
        }
        if mapped.len() >= MAX_SECTIONS {
            return Err(Error::Limit("sections exceed cap".to_string()));
        }
        let align = sec.align().max(RELOC_ALIGN);
        let Some(base) = align_up(cursor, align) else {
            return Err(Error::Limit("relocatable layout overflow".to_string()));
        };
        let Some(next) = base.checked_add(size) else {
            return Err(Error::Limit("relocatable layout overflow".to_string()));
        };
        let data = match sec.data() {
            Ok(d) => d,
            Err(_) if is_bss(sec.kind()) => &[],
            Err(e) => return Err(Error::Invalid(format!("bad section data: {e}"))),
        };
        smapped = smapped
            .checked_add(data.len() as u64)
            .filter(|m| *m <= MAX_MAPPED_BYTES)
            .ok_or_else(|| Error::Limit("section bytes exceed 256 MiB".to_string()))?;
        let name = match sec.name_bytes() {
            Ok(b) => decode_owned_name(b, meta_bytes)?,
            Err(_) => {
                account_meta(meta_bytes, "<invalid>".len())?;
                "<invalid>".to_string()
            }
        };
        let (readable, writable, executable) = section_perms(sec.kind());
        let (file_off, _) = sec.file_range().unwrap_or((0, 0));
        by_index.insert(sec.index(), mapped.len());
        cursor = next;
        mapped.push(Mapped {
            name,
            base,
            size,
            file_off,
            data: data.to_vec(),
            readable,
            writable,
            executable,
        });
    }
    // Defined text symbols remapped through their section's base.
    let mut ranges: Vec<(u64, u64)> = mapped
        .iter()
        .filter(|m| m.executable && m.size > 0)
        .map(|m| (m.base, m.base.saturating_add(m.size)))
        .collect();
    ranges.sort_unstable();
    let in_exec = |addr: u64| -> bool { ranges.iter().any(|(lo, hi)| addr >= *lo && addr < *hi) };
    let mut symbols: Vec<SymbolRef> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    for sym in file.symbols() {
        if sym.kind() != object::SymbolKind::Text {
            continue;
        }
        let object::SymbolSection::Section(idx) = sym.section() else {
            continue;
        };
        let Some(&pos) = by_index.get(&idx) else {
            continue;
        };
        let m = &mapped[pos];
        if !m.executable {
            continue;
        }
        let raw = sym.address();
        let off = if arch == Arch::Arm32 { raw & !1 } else { raw };
        if off >= m.size {
            continue;
        }
        let Some(addr) = m.base.checked_add(off) else {
            continue;
        };
        let addr = canonical_code_addr(arch, addr);
        if !in_exec(addr) {
            continue;
        }
        let raw_name = match sym.name_bytes() {
            Ok(b) if !b.is_empty() => decode_owned_name(b, meta_bytes)?,
            _ => continue,
        };
        if !seen.insert(addr) {
            continue;
        }
        if symbols.len() >= MAX_SYMBOLS {
            return Err(Error::Limit("symbols exceed cap".to_string()));
        }
        let demangled = demangle_bounded(&raw_name, meta_bytes, demangle_cache)?;
        symbols.push(SymbolRef {
            name: raw_name,
            address: addr,
            demangled,
        });
    }
    // Relocations in executable sections: patch sites, externals as imports.
    struct Patch {
        seg: usize,
        off: usize,
        size: u8,
        value: i64,
    }
    let mut patches: Vec<Patch> = Vec::new();
    let mut imports: Vec<ImportRef> = Vec::new();
    let mut import_pos: HashMap<String, usize> = HashMap::new();
    // Stub cursor past the last section.
    let mut stub_cursor = cursor;
    let mut relocs = 0usize;
    // Map section index to its position in `mapped` for relocation lookup.
    for sec in file.sections() {
        let Some(&pos) = by_index.get(&sec.index()) else {
            continue;
        };
        if !mapped[pos].executable {
            continue;
        }
        let base = mapped[pos].base;
        for (offset, rel) in sec.relocations() {
            if relocs >= MAX_RELOCS {
                return Err(Error::Limit("relocations exceed cap".to_string()));
            }
            relocs += 1;
            let kind = rel.kind();
            if !matches!(kind, K::Relative | K::PltRelative | K::Absolute) {
                continue;
            }
            if rel.size() != 32 && rel.size() != 64 {
                continue;
            }
            let Some(place) = base.checked_add(offset) else {
                continue;
            };
            // Resolve the target to a synthetic address or an import.
            enum Target {
                Addr(u64),
                Import(usize),
            }
            let target: Target = match rel.target() {
                object::RelocationTarget::Symbol(sym_idx) => {
                    let Ok(sym) = file.symbol_by_index(sym_idx) else {
                        continue;
                    };
                    match sym.section() {
                        object::SymbolSection::Section(idx) => {
                            let Some(&tpos) = by_index.get(&idx) else {
                                continue;
                            };
                            let tbase = mapped[tpos].base;
                            let tsize = mapped[tpos].size;
                            let raw = sym.address();
                            let off = if arch == Arch::Arm32 { raw & !1 } else { raw };
                            if off >= tsize {
                                continue;
                            }
                            let Some(addr) = tbase.checked_add(off) else {
                                continue;
                            };
                            Target::Addr(canonical_code_addr(arch, addr))
                        }
                        object::SymbolSection::Undefined
                        | object::SymbolSection::Unknown
                        | object::SymbolSection::None
                        | object::SymbolSection::Common => {
                            let raw = match sym.name_bytes() {
                                Ok(b) if !b.is_empty() => decode_owned_name(b, meta_bytes)?,
                                _ => continue,
                            };
                            if let Some(&i) = import_pos.get(&raw) {
                                Target::Import(i)
                            } else {
                                if imports.len() >= MAX_IMPORTS {
                                    return Err(Error::Limit("imports exceed cap".to_string()));
                                }
                                let Some(stub) = align_up(stub_cursor, RELOC_ALIGN) else {
                                    return Err(Error::Limit(
                                        "relocatable layout overflow".to_string(),
                                    ));
                                };
                                let Some(next) = stub.checked_add(RELOC_ALIGN) else {
                                    return Err(Error::Limit(
                                        "relocatable layout overflow".to_string(),
                                    ));
                                };
                                stub_cursor = next;
                                let demangled = demangle_bounded(&raw, meta_bytes, demangle_cache)?;
                                let idx = imports.len();
                                import_pos.insert(raw.clone(), idx);
                                imports.push(ImportRef {
                                    library: String::new(),
                                    name: raw,
                                    ordinal: None,
                                    unresolved: false,
                                    demangled,
                                    address: Some(stub),
                                });
                                Target::Import(idx)
                            }
                        }
                        object::SymbolSection::Absolute => continue,
                        _ => continue,
                    }
                }
                object::RelocationTarget::Section(idx) => {
                    let Some(&tpos) = by_index.get(&idx) else {
                        continue;
                    };
                    let tbase = mapped[tpos].base;
                    let total = rel.addend();
                    let Ok(off) = u64::try_from(total) else {
                        continue;
                    };
                    if off >= mapped[tpos].size {
                        continue;
                    }
                    let Some(addr) = tbase.checked_add(off) else {
                        continue;
                    };
                    Target::Addr(addr)
                }
                object::RelocationTarget::Absolute => continue,
                _ => continue,
            };
            let target_va = match target {
                Target::Addr(a) => a,
                Target::Import(i) => match imports.get(i).and_then(|r| r.address) {
                    Some(a) => a,
                    None => continue,
                },
            };
            // Segment holding the place must be the section's own bytes.
            let seg = pos;
            let m = &mapped[seg];
            let Ok(doff) = usize::try_from(place.wrapping_sub(m.base)) else {
                continue;
            };
            let size = rel.size();
            let bytes_needed = if size == 32 { 4usize } else { 8usize };
            if doff
                .checked_add(bytes_needed)
                .is_none_or(|e| e > m.data.len())
            {
                continue;
            }
            let mut implicit: i64 = 0;
            if rel.has_implicit_addend() {
                let raw = &m.data[doff..doff + bytes_needed];
                implicit = if bytes_needed == 4 {
                    let w: [u8; 4] = raw.try_into().unwrap_or([0; 4]);
                    i64::from(if le {
                        i32::from_le_bytes(w)
                    } else {
                        i32::from_be_bytes(w)
                    })
                } else {
                    let w: [u8; 8] = raw.try_into().unwrap_or([0; 8]);
                    if le {
                        i64::from_le_bytes(w)
                    } else {
                        i64::from_be_bytes(w)
                    }
                };
            }
            let value = match kind {
                K::Relative | K::PltRelative => {
                    match (target_va as i64)
                        .checked_add(rel.addend())
                        .and_then(|v| v.checked_add(implicit))
                        .and_then(|v| v.checked_sub(place as i64))
                    {
                        Some(v) => v,
                        None => continue,
                    }
                }
                _ => match (target_va as i64)
                    .checked_add(rel.addend())
                    .and_then(|v| v.checked_add(implicit))
                {
                    Some(v) => v,
                    None => continue,
                },
            };
            patches.push(Patch {
                seg,
                off: doff,
                size,
                value,
            });
        }
    }
    // Apply patches to the owned segment bytes.
    let mut segments: Vec<Segment> = Vec::new();
    let mut sections: Vec<Section> = Vec::new();
    for (i, m) in mapped.into_iter().enumerate() {
        let mut data = m.data;
        for p in patches.iter().filter(|p| p.seg == i) {
            if p.size == 32 {
                let w = (p.value as i32).to_le_bytes();
                // Relocatable test objects are little-endian; big-endian
                // images encode through the same branch with swapped bytes.
                if le {
                    data[p.off..p.off + 4].copy_from_slice(&w);
                } else {
                    let w = (p.value as i32).to_be_bytes();
                    data[p.off..p.off + 4].copy_from_slice(&w);
                }
            } else if p.off + 8 <= data.len() {
                let w = if le {
                    (p.value).to_le_bytes()
                } else {
                    (p.value).to_be_bytes()
                };
                data[p.off..p.off + 8].copy_from_slice(&w);
            }
        }
        let entropy = section_entropy(&data);
        let file_size = data.len() as u64;
        sections.push(Section {
            name: m.name,
            vaddr: m.base,
            size: m.size,
            file_off: m.file_off,
            file_size,
            entropy,
            readable: m.readable,
            writable: m.writable,
            executable: m.executable,
        });
        segments.push(Segment {
            vaddr: m.base,
            mem_size: m.size,
            data,
            readable: m.readable,
            writable: m.writable,
            executable: m.executable,
        });
    }
    Ok(LoadedBinary {
        format,
        arch,
        entry: None,
        segments,
        sections,
        imports,
        exports: Vec::new(),
        symbols,
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        debug_funcs: Vec::new(),
        relocatable: true,
        arm_hints: ArmHints::default(),
    })
}

fn load_object(
    bytes: &[u8],
    format: BinaryFormat,
    debug: &debuginfo::DebugInputs,
) -> Result<LoadedBinary> {
    let file =
        object::File::parse(bytes).map_err(|e| Error::Invalid(format!("object parse: {e}")))?;
    let arch = arch_from_object(file.architecture())?;
    // Owned-name budget shared by sections/imports/exports below; counted
    // before each copy so repeated long names fail fast instead of OOMing.
    let mut meta_bytes: u64 = 0;
    let mut demangle_cache: HashMap<String, Option<String>> = HashMap::new();
    if format == BinaryFormat::Coff || (format == BinaryFormat::Elf && is_elf_relocatable(bytes)) {
        return load_relocatable(&file, format, arch, &mut meta_bytes, &mut demangle_cache);
    }

    let mut mapped: u64 = 0;
    let mut segments = Vec::new();
    for seg in file.segments() {
        if segments.len() >= MAX_SEGMENTS {
            return Err(Error::Limit("segments exceed cap".to_string()));
        }
        let data = seg
            .data()
            .map_err(|e| Error::Invalid(format!("bad segment data: {e}")))?;
        mapped = mapped
            .checked_add(data.len() as u64)
            .filter(|m| *m <= MAX_MAPPED_BYTES)
            .ok_or_else(|| Error::Limit("segment bytes exceed 256 MiB".to_string()))?;
        let perms = seg.permissions();
        segments.push(Segment {
            vaddr: seg.address(),
            mem_size: seg.size(),
            data: data.to_vec(),
            readable: perms.readable(),
            writable: perms.writable(),
            executable: perms.executable(),
        });
    }

    let mut smapped: u64 = 0;
    let mut sections = Vec::new();
    for sec in file.sections() {
        if sections.len() >= MAX_SECTIONS {
            return Err(Error::Limit("sections exceed cap".to_string()));
        }
        let name = match sec.name_bytes() {
            Ok(b) => decode_owned_name(b, &mut meta_bytes)?,
            Err(_) => {
                account_meta(&mut meta_bytes, "<invalid>".len())?;
                "<invalid>".to_string()
            }
        };
        let data = match sec.data() {
            Ok(d) => d,
            Err(_) if sec.size() == 0 || is_bss(sec.kind()) => &[],
            Err(e) => return Err(Error::Invalid(format!("bad section data: {e}"))),
        };
        smapped = smapped
            .checked_add(data.len() as u64)
            .filter(|m| *m <= MAX_MAPPED_BYTES)
            .ok_or_else(|| Error::Limit("section bytes exceed 256 MiB".to_string()))?;
        let (readable, writable, executable) = section_perms(sec.kind());
        let (file_off, _) = sec.file_range().unwrap_or((0, 0));
        sections.push(Section {
            name,
            vaddr: sec.address(),
            size: sec.size(),
            file_off,
            file_size: data.len() as u64,
            entropy: section_entropy(data),
            readable,
            writable,
            executable,
        });
    }

    let entry = match file.entry() {
        0 => None,
        e => Some(macho_entry_va(&file, bytes, format, e)),
    };

    let mut imports = Vec::new();
    for imp in file
        .imports()
        .map_err(|e| Error::Invalid(format!("bad import table: {e}")))?
    {
        let imp = imp.map_err(|e| Error::Invalid(format!("bad import: {e}")))?;
        if imports.len() >= MAX_IMPORTS {
            return Err(Error::Limit("imports exceed cap".to_string()));
        }
        imports.push(import_from_object(
            imp.library(),
            imp.name(),
            &mut meta_bytes,
            &mut demangle_cache,
        )?);
    }

    if format == BinaryFormat::MachO {
        if let Some(stubs) = macho_stub_addresses(bytes, &imports) {
            for (imp, addr) in imports.iter_mut().zip(stubs) {
                imp.address = Some(addr);
            }
        } else if let Some(stubs) = macho_chained_stub_addresses(bytes, &imports) {
            for (imp, addr) in imports.iter_mut().zip(stubs) {
                if let Some(addr) = addr {
                    imp.address = Some(addr);
                }
            }
        }
    }

    if format == BinaryFormat::Pe
        && let Some(slots) = pe_iat_slots(bytes, imports.len())
    {
        for (imp, slot) in imports.iter_mut().zip(slots) {
            imp.address = Some(slot);
        }
    }

    if format == BinaryFormat::Elf {
        elf_got_slots(&file, bytes, arch, &mut imports);
    }

    let mut exports = Vec::new();
    for exp in file
        .exports()
        .map_err(|e| Error::Invalid(format!("bad export table: {e}")))?
    {
        let exp = exp.map_err(|e| Error::Invalid(format!("bad export: {e}")))?;
        if exports.len() >= MAX_EXPORTS {
            return Err(Error::Limit("exports exceed cap".to_string()));
        }
        exports.push(export_from_object(
            exp.name(),
            match exp.target() {
                object::ExportTarget::Address { address } => Some(address),
                _ => None,
            },
            &mut meta_bytes,
            &mut demangle_cache,
        )?);
    }

    let symbols = collect_symbols(
        &file,
        arch,
        &sections,
        &segments,
        &mut meta_bytes,
        &mut demangle_cache,
    )?;

    let arm_hints = collect_arm_hints(&file, arch, &sections, &segments)?;

    let (pdata_funcs, tls_callbacks, init_funcs, func_starts) = match format {
        BinaryFormat::Pe => (
            pe_pdata_ranges(bytes, &segments),
            pe_tls_callbacks(bytes, &segments),
            Vec::new(),
            Vec::new(),
        ),
        BinaryFormat::Elf => (
            Vec::new(),
            Vec::new(),
            elf_init_funcs(bytes, &segments, &sections),
            Vec::new(),
        ),
        BinaryFormat::MachO => (
            Vec::new(),
            Vec::new(),
            Vec::new(),
            macho_function_starts(bytes),
        ),
        _ => (Vec::new(), Vec::new(), Vec::new(), Vec::new()),
    };

    let debug_funcs = debuginfo::collect_debug_funcs(
        &file,
        bytes,
        format,
        arch,
        &sections,
        &segments,
        debug,
        &mut meta_bytes,
    )?;

    Ok(LoadedBinary {
        format,
        arch,
        entry,
        segments,
        sections,
        imports,
        exports,
        symbols,
        pdata_funcs,
        tls_callbacks,
        init_funcs,
        func_starts,
        debug_funcs,
        relocatable: false,
        arm_hints,
    })
}

/// Map a Mach-O `LC_MAIN` file-offset entry to its VA.
///
/// `object` 0.40 `entry()` returns `LC_MAIN.entryoff` raw, but the spec
/// defines it as a file (`__TEXT`) offset, so real `LC_MAIN` binaries would
/// seed a bogus entry. Translate through the segment map; anything else
/// (other formats, `LC_UNIXTHREAD` images with no `LC_MAIN`, unmapped
/// offsets) keeps the reported value.
fn macho_entry_va(file: &object::File<'_>, bytes: &[u8], format: BinaryFormat, raw: u64) -> u64 {
    if format != BinaryFormat::MachO {
        return raw;
    }
    let Some(entryoff) = macho_lc_main_entryoff(bytes) else {
        return raw;
    };
    for seg in file.segments() {
        let (off, size) = seg.file_range();
        if size > 0
            && entryoff >= off
            && entryoff - off < size
            && let Some(va) = seg.address().checked_add(entryoff - off)
        {
            return va;
        }
    }
    raw
}

/// `LC_MAIN.entryoff` from thin Mach-O `bytes`, or `None` when absent or
/// truncated.
///
/// Bounds-checked walk mirroring [`macho_has_chained_fixups`]: hostile
/// `ncmds` cannot loop, and anything unreadable vetoes (the caller keeps
/// the reported entry value).
fn macho_lc_main_entryoff(bytes: &[u8]) -> Option<u64> {
    const LC_MAIN: u32 = 0x8000_0028;
    const MAX_COMMANDS: u32 = 4096;
    if bytes.len() < 32 {
        return None;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let header: usize = match magic {
        0xFEED_FACE => 28,
        0xFEED_FACF => 32,
        _ => return None,
    };
    let ncmds = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    if ncmds > MAX_COMMANDS {
        return None;
    }
    let mut off = header;
    for _ in 0..ncmds {
        if off.saturating_add(8) > bytes.len() {
            return None;
        }
        let cmd = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        let cmdsize = u32::from_le_bytes([
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]);
        if cmdsize < 8 {
            return None;
        }
        if cmd == LC_MAIN {
            if off.saturating_add(24) > bytes.len() {
                return None;
            }
            return Some(u64::from_le_bytes(
                bytes[off + 8..off + 16].try_into().ok()?,
            ));
        }
        off = off.saturating_add(cmdsize as usize);
        if off > bytes.len() {
            return None;
        }
    }
    None
}

/// Derive Mach-O stub entry addresses in import order, or `None` on any doubt.
///
/// Each `__stubs`/`__auth_stubs` entry resolves through its section's
/// `reserved1` (the starting index into the `LC_DYSYMTAB` indirect symbol
/// table) plus the entry position: indirect entry → symtab index → symbol
/// name, matched against the import of the same name. Positional pairing
/// would misattribute whenever symtab order differs from indirect-table
/// order (the symtab import path reports undefined symbols in symtab
/// order), so every stub must name-match exactly one still-unmapped import.
/// Every other guard vetoes the whole mapping rather than guessing: thin
/// little-endian Mach-O magic, no `LC_DYLD_CHAINED_FIXUPS` (chained fixups
/// reorder binds away from stub order), at least one stub section of type
/// `S_SYMBOL_STUBS` in a `__TEXT*` segment with a nonzero `reserved2`
/// stride dividing its size, checked entry arithmetic, total entries
/// exactly equal to the import count, and a bounds-checked symtab/indirect
/// table behind every lookup. Real binaries routinely fail the count guard:
/// `/bin/ls` (arm64e) carries 84 `__auth_stubs` for 90 chained-fixup
/// imports, and its x86_64 slice 84 `__stubs` for 91 `LC_DYLD_INFO` imports
/// (stub-less data binds have no entry).
fn macho_stub_addresses(bytes: &[u8], imports: &[ImportRef]) -> Option<Vec<u64>> {
    const LC_SEGMENT: u32 = 0x1;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x2;
    const LC_DYSYMTAB: u32 = 0xB;
    // Section type mask (`SECTION_TYPE`) and `S_SYMBOL_STUBS` per mach-o/loader.h.
    const SECTION_TYPE: u32 = 0xff;
    const S_SYMBOL_STUBS: u32 = 0x8;
    const MAX_COMMANDS: u32 = 4096;
    if imports.is_empty() || imports.len() > MAX_IMPORTS {
        return None;
    }
    if !is_thin_le_macho(bytes) {
        return None;
    }
    if macho_has_chained_fixups(bytes) != Some(false) {
        return None;
    }
    let is64 = bytes
        .get(0..4)
        .is_some_and(|m| m == 0xFEED_FACFu32.to_le_bytes());
    let get32 = |off: usize| -> Option<u32> {
        let b: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
        Some(u32::from_le_bytes(b))
    };
    let get64 = |off: usize| -> Option<u64> {
        let b: [u8; 8] = bytes.get(off..off + 8)?.try_into().ok()?;
        Some(u64::from_le_bytes(b))
    };
    let ncmds = get32(16)?;
    if ncmds > MAX_COMMANDS {
        return None;
    }
    // Stub sections first: symbol/indirect tables may come later in command
    // order, so collect (base address, entry count, indirect start, stride)
    // here and resolve names after the walk.
    let mut sections: Vec<(u64, u64, u32, u64)> = Vec::new();
    let mut total: u64 = 0;
    let mut symtab: Option<(usize, usize, usize, usize)> = None;
    let mut indirect: Option<(usize, usize)> = None;
    let mut off = if is64 { 32usize } else { 28usize };
    for _ in 0..ncmds {
        let base = off;
        let cmd = get32(base)?;
        let cmdsize = get32(base + 4)? as usize;
        if cmdsize < 8 || base.checked_add(cmdsize)? > bytes.len() {
            return None;
        }
        match cmd {
            LC_SYMTAB => {
                if symtab.is_some() {
                    return None;
                }
                symtab = Some((
                    get32(base + 8)? as usize,
                    get32(base + 12)? as usize,
                    get32(base + 16)? as usize,
                    get32(base + 20)? as usize,
                ));
            }
            LC_DYSYMTAB => {
                if indirect.is_some() {
                    return None;
                }
                indirect = Some((get32(base + 56)? as usize, get32(base + 60)? as usize));
            }
            LC_SEGMENT | LC_SEGMENT_64 => {
                if (cmd == LC_SEGMENT_64) != is64 {
                    return None;
                }
                let (nsects, sect_off, sect_len) = if is64 {
                    (get32(base + 64)? as usize, base + 72, 80usize)
                } else {
                    (get32(base + 48)? as usize, base + 56, 68usize)
                };
                if nsects.checked_mul(sect_len)?.checked_add(sect_off - base)? > cmdsize {
                    return None;
                }
                for s in 0..nsects {
                    let sec = sect_off + s * sect_len;
                    let name_end = bytes
                        .get(sec..sec + 16)?
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(16);
                    let name = bytes.get(sec..sec + name_end)?;
                    if name != b"__stubs" && name != b"__auth_stubs" {
                        continue;
                    }
                    if !bytes.get(sec + 16..sec + 32)?.starts_with(b"__TEXT") {
                        return None;
                    }
                    let (addr, size) = if is64 {
                        (get64(sec + 32)?, get64(sec + 40)?)
                    } else {
                        (u64::from(get32(sec + 32)?), u64::from(get32(sec + 36)?))
                    };
                    let flags_off = if is64 { sec + 64 } else { sec + 56 };
                    let flags = get32(flags_off)?;
                    let reserved1 = get32(flags_off + 4)?;
                    let stride = get32(flags_off + 8)?;
                    if flags & SECTION_TYPE != S_SYMBOL_STUBS || stride == 0 {
                        return None;
                    }
                    let stride = u64::from(stride);
                    if size == 0 || size % stride != 0 {
                        return None;
                    }
                    let count = size / stride;
                    total = total.checked_add(count)?;
                    if total > imports.len() as u64 {
                        return None;
                    }
                    sections.push((addr, count, reserved1, stride));
                }
            }
            _ => {}
        }
        off = base + cmdsize;
    }
    if total != imports.len() as u64 {
        return None;
    }
    let (symoff, nsyms, stroff, strsize) = symtab?;
    let (indirectoff, nindirect) = indirect?;
    let nlist = if is64 { 16usize } else { 12usize };
    if nsyms.checked_mul(nlist)?.checked_add(symoff)? > bytes.len()
        || strsize.checked_add(stroff)? > bytes.len()
        || nindirect.checked_mul(4)?.checked_add(indirectoff)? > bytes.len()
    {
        return None;
    }
    let str_end = stroff + strsize;
    // Queue of import positions per name: each stub takes the first
    // still-unmapped import of its resolved name.
    let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, imp) in imports.iter().enumerate() {
        by_name.entry(imp.name.as_str()).or_default().push(i);
    }
    for positions in by_name.values_mut() {
        positions.reverse();
    }
    let mut addrs: Vec<u64> = vec![0; imports.len()];
    let mut mapped = 0usize;
    for (base_addr, count, reserved1, stride) in sections {
        for i in 0..count {
            let table_idx = (u64::from(reserved1)).checked_add(i)? as usize;
            if table_idx >= nindirect {
                return None;
            }
            let sym = get32(indirectoff + table_idx * 4)? as usize;
            if sym >= nsyms {
                return None;
            }
            let strx = get32(symoff + sym * nlist)? as usize;
            if strx >= strsize {
                return None;
            }
            let name_len = bytes
                .get(stroff + strx..str_end)?
                .iter()
                .position(|&b| b == 0)?;
            let raw = bytes.get(stroff + strx..stroff + strx + name_len)?;
            // Same lossy decode the import names went through, so the
            // comparison cannot disagree on non-UTF-8 bytes.
            let want = String::from_utf8_lossy(raw).into_owned();
            let addr = base_addr.checked_add(i.checked_mul(stride)?)?;
            let imp = by_name.get_mut(want.as_str()).and_then(Vec::pop)?;
            addrs[imp] = addr;
            mapped += 1;
        }
    }
    if mapped != imports.len() {
        return None;
    }
    Some(addrs)
}

/// Stub decode shapes for [`macho_chained_stub_addresses`].
#[derive(Clone, Copy)]
enum ChainedStubArch {
    Aarch64,
    X86_64,
    X86_32,
}

/// Derive Mach-O stub entry addresses through `LC_DYLD_CHAINED_FIXUPS`
/// binds, or `None` on any doubt.
///
/// Modern arm64/x86_64 macOS images (macOS 12+) bind through chained fixups
/// instead of the `LC_DYSYMTAB` indirect table, so [`macho_stub_addresses`]
/// vetoes them. This path recovers the same `import.address` stub mapping
/// without the indirect table:
/// 1. Walk the load commands for the chained-fixups payload offset/size,
///    the segments (`vmaddr`/`fileoff`/`filesize`, in command order), and
///    the `__stubs`/`__auth_stubs` sections (same name/segment/type guards
///    as the classic path, but a non-conforming section is skipped rather
///    than vetoing the whole mapping).
/// 2. Parse the payload with the `object` crate's chained-fixups walker and
///    collect every bind fixup as slot VA (`vmaddr + chain offset`) to
///    import-table ordinal. All pointer formats the walker supports resolve
///    here (`DYLD_CHAINED_PTR_64`, `_64_OFFSET`, `_32`, and the `ARM64E*`
///    family); authenticated binds map by ordinal like plain ones — pointer
///    signing is never verified, only read. Rebase fixups are ignored.
/// 3. Translate ordinals to `imports` positions by replaying the table in
///    order while skipping `BIND_SPECIAL_DYLIB_SELF` entries, exactly as
///    `object`'s own import iterator does; a surviving count mismatch
///    vetoes the mapping.
/// 4. Decode each stub entry's first instructions to the GOT slot it loads
///    (arm64 `adrp` + 64-bit `ldr`, x86-64 `jmp [rip+disp]`, x86-32 absolute
///    `jmp [addr]`; see [`chained_stub_slot`]) and assign the entry address
///    to that slot's import.
///
/// Mapping is per-stub best-effort: entries that fail to decode, load an
/// unbound slot, or point outside the import table leave their import at
/// `None` (data-only binds with no stub, the real-`/bin/ls` shape, stay
/// `None` rather than vetoing the mapped ones). Two whole-mapping vetoes
/// remain: zero mapped stubs, and two stubs resolving to one import
/// (ambiguous, never guessed).
///
/// Out of scope: 32-bit ARM stubs (no chained-fixups ARM32/Thumb shape is
/// decoded — old 32-bit images still use the indirect table), stubs whose
/// slot load is not the entry's first instruction pair, and ObjC fixups
/// (which are rebases, not binds).
fn macho_chained_stub_addresses(bytes: &[u8], imports: &[ImportRef]) -> Option<Vec<Option<u64>>> {
    use object::read::macho::{DyldChainedFixups, Fixup};
    const LC_SEGMENT: u32 = 0x1;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
    const SECTION_TYPE: u32 = 0xff;
    const S_SYMBOL_STUBS: u32 = 0x8;
    const MAX_COMMANDS: u32 = 4096;
    // `object` cputypes for the stub shapes decoded below.
    const CPU_TYPE_I386: u32 = 7;
    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    const CPU_TYPE_ARM64: u32 = 0x0100_000C;
    if imports.is_empty() || imports.len() > MAX_IMPORTS {
        return None;
    }
    if !is_thin_le_macho(bytes) {
        return None;
    }
    if macho_has_chained_fixups(bytes) != Some(true) {
        return None;
    }
    let is64 = bytes
        .get(0..4)
        .is_some_and(|m| m == 0xFEED_FACFu32.to_le_bytes());
    let stub_arch = match bytes.get(4..8) {
        Some(m) if m == CPU_TYPE_ARM64.to_le_bytes() => ChainedStubArch::Aarch64,
        Some(m) if m == CPU_TYPE_X86_64.to_le_bytes() => ChainedStubArch::X86_64,
        Some(m) if m == CPU_TYPE_I386.to_le_bytes() => ChainedStubArch::X86_32,
        _ => return None,
    };
    let get32 = |off: usize| -> Option<u32> {
        let b: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
        Some(u32::from_le_bytes(b))
    };
    let get64 = |off: usize| -> Option<u64> {
        let b: [u8; 8] = bytes.get(off..off + 8)?.try_into().ok()?;
        Some(u64::from_le_bytes(b))
    };
    let ncmds = get32(16)?;
    if ncmds > MAX_COMMANDS {
        return None;
    }
    // Segments in command order (the chain walk indexes them positionally),
    // stub sections, and the fixups payload range.
    let mut segments: Vec<(u64, usize, usize)> = Vec::new();
    let mut sections: Vec<(u64, u64, u64)> = Vec::new();
    let mut chained: Option<(usize, usize)> = None;
    let mut off = if is64 { 32usize } else { 28usize };
    for _ in 0..ncmds {
        let base = off;
        let cmd = get32(base)?;
        let cmdsize = get32(base + 4)? as usize;
        if cmdsize < 8 || base.checked_add(cmdsize)? > bytes.len() {
            return None;
        }
        match cmd {
            LC_DYLD_CHAINED_FIXUPS => {
                if chained.is_some() {
                    return None;
                }
                chained = Some((get32(base + 8)? as usize, get32(base + 12)? as usize));
            }
            LC_SEGMENT | LC_SEGMENT_64 => {
                if (cmd == LC_SEGMENT_64) != is64 {
                    return None;
                }
                let (vmaddr, fileoff, filesize, nsects, sect_off, sect_len) = if is64 {
                    (
                        get64(base + 24)?,
                        get32(base + 40)? as usize,
                        get32(base + 48)? as usize,
                        get32(base + 64)? as usize,
                        base + 72,
                        80usize,
                    )
                } else {
                    (
                        u64::from(get32(base + 24)?),
                        get32(base + 32)? as usize,
                        get32(base + 36)? as usize,
                        get32(base + 48)? as usize,
                        base + 56,
                        68usize,
                    )
                };
                if nsects.checked_mul(sect_len)?.checked_add(sect_off - base)? > cmdsize {
                    return None;
                }
                let seg_name_end = bytes
                    .get(base + 8..base + 24)?
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(16);
                let seg_name = bytes.get(base + 8..base + 8 + seg_name_end)?;
                segments.push((vmaddr, fileoff, filesize));
                for s in 0..nsects {
                    let sec = sect_off + s * sect_len;
                    let name_end = bytes
                        .get(sec..sec + 16)?
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(16);
                    let name = bytes.get(sec..sec + name_end)?;
                    if name != b"__stubs" && name != b"__auth_stubs" {
                        continue;
                    }
                    if !seg_name.starts_with(b"__TEXT") {
                        continue;
                    }
                    let (addr, size) = if is64 {
                        (get64(sec + 32)?, get64(sec + 40)?)
                    } else {
                        (u64::from(get32(sec + 32)?), u64::from(get32(sec + 36)?))
                    };
                    let flags_off = if is64 { sec + 64 } else { sec + 56 };
                    let flags = get32(flags_off)?;
                    let stride = get32(flags_off + 8)?;
                    if flags & SECTION_TYPE != S_SYMBOL_STUBS || stride == 0 {
                        continue;
                    }
                    let stride = u64::from(stride);
                    if size == 0 || size % stride != 0 {
                        continue;
                    }
                    let min_insn: u64 = match stub_arch {
                        ChainedStubArch::Aarch64 => 8,
                        ChainedStubArch::X86_64 | ChainedStubArch::X86_32 => 6,
                    };
                    if stride < min_insn {
                        continue;
                    }
                    sections.push((addr, size / stride, stride));
                }
            }
            _ => {}
        }
        off = base + cmdsize;
    }
    let (dataoff, datasize) = chained?;
    let payload = bytes.get(dataoff..dataoff.checked_add(datasize)?)?;
    let endian = object::LittleEndian;
    let fixups = DyldChainedFixups::parse(endian, payload).ok()?;
    // Ordinal to `imports` position: replay the table in order, skipping
    // self-dylib entries exactly as `object`'s import iterator does.
    let mut ordinal_to_import: Vec<Option<usize>> = Vec::new();
    let mut next_import = 0usize;
    let mut table = fixups.imports(endian).ok()?;
    loop {
        match table.next() {
            Err(_) => return None,
            Ok(None) => break,
            Ok(Some(entry)) => {
                if entry.dylib == object::macho::BIND_SPECIAL_DYLIB_SELF {
                    ordinal_to_import.push(None);
                } else {
                    ordinal_to_import.push(Some(next_import));
                    next_import += 1;
                }
            }
        }
    }
    if next_import != imports.len() {
        return None;
    }
    // Slot VA to import-table ordinal over every segment's chains. A dead
    // chain tail keeps the binds already walked (each is exact on its own);
    // only the bind count is capped.
    let mut slot_ordinal: HashMap<u64, u32> = HashMap::new();
    let text_base = segments.first().map(|s| s.0).unwrap_or(0);
    let mut seg_starts = fixups.segments(endian).ok()?;
    loop {
        let seg = match seg_starts.next() {
            Err(_) | Ok(None) => break,
            Ok(Some(seg)) => seg,
        };
        let Some(&(vmaddr, fileoff, filesize)) = segments.get(seg.index() as usize) else {
            continue;
        };
        let Some(seg_data) = bytes.get(fileoff..fileoff.checked_add(filesize)?) else {
            continue;
        };
        let mut chain = seg.fixups(endian, text_base, seg_data);
        while let Ok(Some((chain_off, fix))) = chain.next() {
            let Fixup::Bind(bind) = fix else { continue };
            if slot_ordinal.len() >= MAX_IMPORTS {
                return None;
            }
            slot_ordinal
                .entry(vmaddr.wrapping_add(chain_off))
                .or_insert(bind.ordinal);
        }
    }
    if slot_ordinal.is_empty() {
        return None;
    }
    let file_bytes_at = |va: u64, len: usize| -> Option<&[u8]> {
        for &(vmaddr, fileoff, filesize) in &segments {
            let end = vmaddr.checked_add(filesize as u64)?;
            if va >= vmaddr && va.checked_add(len as u64)? <= end {
                let start = fileoff.checked_add((va - vmaddr) as usize)?;
                return bytes.get(start..start.checked_add(len)?);
            }
        }
        None
    };
    let mut addrs: Vec<Option<u64>> = vec![None; imports.len()];
    let mut mapped = 0usize;
    for (base_addr, count, stride) in sections {
        for i in 0..count {
            let va = base_addr.checked_add(i.checked_mul(stride)?)?;
            let need = match stub_arch {
                ChainedStubArch::Aarch64 => 8,
                ChainedStubArch::X86_64 | ChainedStubArch::X86_32 => 6,
            };
            let Some(code) = file_bytes_at(va, need) else {
                continue;
            };
            let Some(slot) = chained_stub_slot(code, stub_arch, va) else {
                continue;
            };
            let Some(&ordinal) = slot_ordinal.get(&slot) else {
                continue;
            };
            let Some(&imp) = ordinal_to_import
                .get(ordinal as usize)
                .and_then(|o| o.as_ref())
            else {
                continue;
            };
            if addrs[imp].is_some() {
                return None;
            }
            addrs[imp] = Some(va);
            mapped += 1;
        }
    }
    if mapped == 0 { None } else { Some(addrs) }
}

/// GOT slot a chained-fixups stub entry loads, if its first instructions
/// match one known shape.
///
/// arm64 entries start with `adrp Rd, page` plus a 64-bit unsigned-offset
/// `ldr` off the same register (the classic `__stubs` 12-byte and the
/// authenticated `__auth_stubs` `adrp`/`ldr`/`braa` entries share this
/// prefix; the trailing branch is never inspected, so PAC branches need no
/// special handling). x86-64 entries are `jmp [rip+disp32]`; x86-32 entries
/// are absolute `jmp [addr32]`. Anything else (including 32-bit `ldr` forms,
/// pre-indexed loads, and multi-instruction page math) is `None`.
fn chained_stub_slot(code: &[u8], arch: ChainedStubArch, va: u64) -> Option<u64> {
    match arch {
        ChainedStubArch::Aarch64 => {
            let w0 = u32::from_le_bytes(code.get(0..4)?.try_into().ok()?);
            let w1 = u32::from_le_bytes(code.get(4..8)?.try_into().ok()?);
            if w0 & 0x9F00_0000 != 0x9000_0000 {
                return None;
            }
            if w1 & 0xFFC0_0000 != 0xF940_0000 {
                return None;
            }
            if (w1 >> 5) & 31 != w0 & 31 {
                return None;
            }
            let imm12 = u64::from((w1 >> 10) & 0xFFF);
            let off21 = ((w0 >> 5) & 0x7_FFFF) << 2 | ((w0 >> 29) & 3);
            let signed = ((off21 << 11) as i32 >> 11) as i64;
            let page = (va & !0xFFF).wrapping_add((signed << 12) as u64);
            Some(page.wrapping_add(imm12 * 8))
        }
        ChainedStubArch::X86_64 => {
            if code.get(0..2) != Some(&[0xFF, 0x25][..]) {
                return None;
            }
            let disp = i32::from_le_bytes(code.get(2..6)?.try_into().ok()?) as i64;
            Some(va.wrapping_add(6).wrapping_add(disp as u64))
        }
        ChainedStubArch::X86_32 => {
            if code.get(0..2) != Some(&[0xFF, 0x25][..]) {
                return None;
            }
            Some(u64::from(u32::from_le_bytes(
                code.get(2..6)?.try_into().ok()?,
            )))
        }
    }
}

/// IAT slot virtual addresses in import order, or `None` on any doubt.
///
/// Walks the regular import descriptors (`FirstThunk` tables) counting one
/// slot per thunk; the count must equal `import_count` exactly, otherwise
/// nothing maps rather than misattributing a slot (delay-load imports,
/// which the generic import walk reports after the regular ones, trip
/// this guard). Slot math is checked against the image base.
fn pe_iat_slots(bytes: &[u8], import_count: usize) -> Option<Vec<u64>> {
    use object::read::pe::{PeFile32, PeFile64};
    if import_count == 0 || import_count > MAX_IMPORTS {
        return None;
    }
    match FileKind::parse(bytes) {
        Ok(FileKind::Pe32) => PeFile32::parse(bytes)
            .ok()
            .and_then(|pe| pe_slots(&pe, import_count, 4)),
        Ok(FileKind::Pe64) => PeFile64::parse(bytes)
            .ok()
            .and_then(|pe| pe_slots(&pe, import_count, 8)),
        _ => None,
    }
}

fn pe_slots<Pe>(
    pe: &object::read::pe::PeFile<'_, Pe>,
    import_count: usize,
    stride: u64,
) -> Option<Vec<u64>>
where
    Pe: object::read::pe::ImageNtHeaders,
{
    use object::LittleEndian as LE;
    let table = pe.import_table().ok()??;
    let base = pe.relative_address_base();
    let mut descs = table.descriptors().ok()?;
    let mut slots = Vec::new();
    while let Some(desc) = descs.next().ok()? {
        let first_thunk = desc.first_thunk.get(LE);
        let mut thunks = table.thunks(first_thunk).ok()?;
        let mut idx: u64 = 0;
        while thunks.next::<Pe>().ok()?.is_some() {
            if slots.len() >= MAX_IMPORTS {
                return None;
            }
            let rva = u64::from(first_thunk).checked_add(idx.checked_mul(stride)?)?;
            slots.push(base.checked_add(rva)?);
            idx += 1;
        }
    }
    if slots.len() != import_count {
        return None;
    }
    Some(slots)
}

/// Assign GOT slot addresses to ELF imports from `R_*_JUMP_SLOT` relocs.
///
/// Parses `.rela.plt`/`.rel.plt` entries directly (`object` maps these
/// types to `RelocationKind::Unknown`, so the unified relocation view
/// cannot see them): each entry's `r_offset` is already the slot's
/// virtual address, and its symbol resolves through the dynamic symbol
/// table to an import matched by name. Unknown types, unreadable
/// sections, and nameless imports are skipped, never guessed; the first
/// slot wins on repeats.
fn elf_got_slots<'a>(
    file: &object::File<'a, &'a [u8]>,
    bytes: &[u8],
    arch: Arch,
    imports: &mut [ImportRef],
) {
    if imports.is_empty() {
        return;
    }
    let jump_slot: u32 = match arch {
        Arch::X86_64 | Arch::X86_32 => 7,
        Arch::Arm32 | Arch::Thumb => 22,
        Arch::Aarch64 => 1026,
        Arch::Riscv32 | Arch::Riscv64 => 5,
    };
    let is64 = bytes.get(4).is_some_and(|&c| c == 2);
    let le = file.endianness() == object::Endianness::Little;
    // Index-aligned with `r_info` symbol numbers: the dynamic-symbol
    // iterator starts past the null symbol, so index 0 stays empty here.
    let mut dynsyms: Vec<Vec<u8>> = vec![Vec::new()];
    dynsyms.extend(
        file.dynamic_symbols()
            .map(|s| s.name_bytes().unwrap_or_default().to_vec()),
    );
    if dynsyms.len() < 2 {
        return;
    }
    let mut assigned = 0usize;
    for sec in file.sections() {
        if assigned >= imports.len() || assigned >= MAX_IMPORTS {
            break;
        }
        let is_rela = match sec.name() {
            Ok(".rela.plt") => true,
            Ok(".rel.plt") => false,
            _ => continue,
        };
        let data = match sec.data() {
            Ok(d) => d,
            Err(_) => continue,
        };
        let entry = if is64 {
            if is_rela { 24 } else { 16 }
        } else if is_rela {
            12
        } else {
            8
        };
        if data.is_empty() || data.len() % entry != 0 {
            continue;
        }
        let get32 = |off: usize| -> Option<u32> {
            let b: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
            Some(if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            })
        };
        let get64 = |off: usize| -> Option<u64> {
            let b: [u8; 8] = data.get(off..off + 8)?.try_into().ok()?;
            Some(if le {
                u64::from_le_bytes(b)
            } else {
                u64::from_be_bytes(b)
            })
        };
        let mut off = 0;
        while off + entry <= data.len() {
            if assigned >= MAX_IMPORTS {
                break;
            }
            let (slot, sym, rtype) = if is64 {
                let (Some(r_offset), Some(r_info)) = (get64(off), get64(off + 8)) else {
                    break;
                };
                (r_offset, (r_info >> 32) as usize, r_info as u32)
            } else {
                let (Some(r_offset), Some(r_info)) = (get32(off), get32(off + 4)) else {
                    break;
                };
                (u64::from(r_offset), (r_info >> 8) as usize, r_info & 0xff)
            };
            off += entry;
            if rtype != jump_slot || slot == 0 {
                continue;
            }
            let sym_name = match dynsyms.get(sym) {
                Some(n) if !n.is_empty() => n,
                _ => continue,
            };
            let want = String::from_utf8_lossy(sym_name);
            if let Some(imp) = imports
                .iter_mut()
                .find(|i| i.address.is_none() && i.name.as_str() == want.as_ref())
            {
                imp.address = Some(slot);
                assigned += 1;
            }
        }
    }
}

/// File-backed bytes at `va` within a single segment, if any.
///
/// Discovery tables (`.pdata`, TLS directories, init arrays) live in one
/// section, so cross-segment spans and BSS tails report `None` rather than
/// synthesizing bytes.
fn segment_bytes_at(segments: &[Segment], va: u64, len: usize) -> Option<&[u8]> {
    for seg in segments {
        let Some(off) = va.checked_sub(seg.vaddr) else {
            continue;
        };
        let Ok(off) = usize::try_from(off) else {
            continue;
        };
        let Some(end) = off.checked_add(len) else {
            continue;
        };
        if end <= seg.data.len() {
            return seg.data.get(off..end);
        }
    }
    None
}

/// PE `.pdata` function ranges as `(start_va, end_va)` in table order.
///
/// 64-bit Windows only (`RUNTIME_FUNCTION` records); 32-bit PEs and other
/// formats yield nothing. Reads the exception directory via `object` for
/// the image base and table bounds, then each 12-byte record through the
/// segment store. Malformed, truncated, or unmapped records are skipped,
/// never guessed; output stops at [`MAX_PDATA_FUNCS`].
fn pe_pdata_ranges(bytes: &[u8], segments: &[Segment]) -> Vec<(u64, u64)> {
    use object::read::pe::PeFile64;
    use object::{LittleEndian as LE, pe as pe_const};
    let mut out: Vec<(u64, u64)> = Vec::new();
    let (base, dir_rva, dir_size) = match FileKind::parse(bytes) {
        Ok(FileKind::Pe64) => {
            let Ok(pe) = PeFile64::parse(bytes) else {
                return out;
            };
            let base = pe.relative_address_base();
            let Some(d) = pe.data_directory(pe_const::IMAGE_DIRECTORY_ENTRY_EXCEPTION) else {
                return out;
            };
            (base, d.virtual_address.get(LE), d.size.get(LE))
        }
        Ok(FileKind::Pe32) => return out,
        _ => return out,
    };
    if dir_rva == 0 || dir_size < 12 {
        return out;
    }
    let count = (dir_size as usize / 12).min(MAX_PDATA_FUNCS);
    for i in 0..count {
        let Some(rec_va) = base
            .checked_add(u64::from(dir_rva))
            .and_then(|b| b.checked_add((i as u64).checked_mul(12)?))
        else {
            break;
        };
        let Some(rec) = segment_bytes_at(segments, rec_va, 12) else {
            continue;
        };
        let begin = u32::from_le_bytes(rec[0..4].try_into().unwrap_or([0; 4]));
        let end = u32::from_le_bytes(rec[4..8].try_into().unwrap_or([0; 4]));
        if begin == 0 || end <= begin {
            continue;
        }
        let (Some(start), Some(stop)) = (
            base.checked_add(u64::from(begin)),
            base.checked_add(u64::from(end)),
        ) else {
            continue;
        };
        out.push((start, stop));
        if out.len() >= MAX_PDATA_FUNCS {
            break;
        }
    }
    out
}

/// PE TLS callback addresses in callback-array order.
///
/// Reads the TLS directory via `object` for the `AddressOfCallBacks` VA,
/// then the null-terminated pointer array through the segment store.
/// 32-bit images use 4-byte slots, 64-bit 8-byte slots. Unmapped or
/// truncated arrays stop the scan; output stops at [`MAX_TLS_CALLBACKS`].
fn pe_tls_callbacks(bytes: &[u8], segments: &[Segment]) -> Vec<u64> {
    use object::read::pe::{PeFile32, PeFile64};
    use object::{LittleEndian as LE, pe as pe_const};
    let mut out: Vec<u64> = Vec::new();
    enum Kind {
        P32,
        P64,
    }
    let kind = match FileKind::parse(bytes) {
        Ok(FileKind::Pe32) => Kind::P32,
        Ok(FileKind::Pe64) => Kind::P64,
        _ => return out,
    };
    let (ptr, dir_va, dir_len) = match kind {
        Kind::P64 => {
            let Ok(pe) = PeFile64::parse(bytes) else {
                return out;
            };
            let base = pe.relative_address_base();
            let Some(d) = pe.data_directory(pe_const::IMAGE_DIRECTORY_ENTRY_TLS) else {
                return out;
            };
            let (rva, size) = (d.virtual_address.get(LE), d.size.get(LE));
            if rva == 0 || size < 40 {
                return out;
            }
            let Some(va) = base.checked_add(u64::from(rva)) else {
                return out;
            };
            (8usize, va, size as usize)
        }
        Kind::P32 => {
            let Ok(pe) = PeFile32::parse(bytes) else {
                return out;
            };
            let base = pe.relative_address_base();
            let Some(d) = pe.data_directory(pe_const::IMAGE_DIRECTORY_ENTRY_TLS) else {
                return out;
            };
            let (rva, size) = (d.virtual_address.get(LE), d.size.get(LE));
            if rva == 0 || size < 24 {
                return out;
            }
            let Some(va) = base.checked_add(u64::from(rva)) else {
                return out;
            };
            (4usize, va, size as usize)
        }
    };
    let dir_len = dir_len.min(64);
    let Some(dir) = segment_bytes_at(segments, dir_va, dir_len) else {
        return out;
    };
    let callbacks: u64 = match ptr {
        8 => {
            if dir.len() < 32 {
                return out;
            }
            u64::from_le_bytes(dir[24..32].try_into().unwrap_or([0; 8]))
        }
        _ => {
            if dir.len() < 16 {
                return out;
            }
            u64::from(u32::from_le_bytes(dir[12..16].try_into().unwrap_or([0; 4])))
        }
    };
    if callbacks == 0 {
        return out;
    }
    let mut cur = callbacks;
    for _ in 0..MAX_TLS_CALLBACKS {
        let Some(slot) = segment_bytes_at(segments, cur, ptr) else {
            break;
        };
        let target: u64 = if ptr == 8 {
            u64::from_le_bytes(slot.try_into().unwrap_or([0; 8]))
        } else {
            u64::from(u32::from_le_bytes(slot.try_into().unwrap_or([0; 4])))
        };
        if target == 0 {
            break;
        }
        out.push(target);
        let Some(next) = cur.checked_add(ptr as u64) else {
            break;
        };
        cur = next;
    }
    out
}

/// ELF init/fini addresses in discovery order.
///
/// Section entries (`.init_array`, `.fini_array`, `.ctors`, `.dtors`) plus
/// dynamic tags (`DT_INIT`, `DT_FINI`, `DT_INIT_ARRAY`/`DT_FINI_ARRAY` with
/// their sizes). Values are pointer-sized file bytes decoded with the ELF
/// endianness; zeroes are skipped. Total output stops at
/// [`MAX_INIT_FUNCS`].
fn elf_init_funcs(bytes: &[u8], segments: &[Segment], sections: &[Section]) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    if bytes.get(..4) != Some(b"\x7fELF".as_slice()) || bytes.len() < 64 {
        return out;
    }
    let (is64, le) = match (bytes.get(4), bytes.get(5)) {
        (Some(1), Some(1)) => (false, true),
        (Some(1), Some(2)) => (false, false),
        (Some(2), Some(1)) => (true, true),
        (Some(2), Some(2)) => (true, false),
        _ => return out,
    };
    let ptr = if is64 { 8usize } else { 4usize };
    let u16at = |off: usize| -> Option<u16> {
        let w: [u8; 2] = bytes.get(off..off + 2)?.try_into().ok()?;
        Some(if le {
            u16::from_le_bytes(w)
        } else {
            u16::from_be_bytes(w)
        })
    };
    let u32at = |off: usize| -> Option<u32> {
        let w: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
        Some(if le {
            u32::from_le_bytes(w)
        } else {
            u32::from_be_bytes(w)
        })
    };
    let u64at = |off: usize| -> Option<u64> {
        if is64 {
            let w: [u8; 8] = bytes.get(off..off + 8)?.try_into().ok()?;
            Some(if le {
                u64::from_le_bytes(w)
            } else {
                u64::from_be_bytes(w)
            })
        } else {
            Some(u64::from(u32at(off)?))
        }
    };
    let read_ptr_at = |va: u64| -> Option<u64> {
        let raw = segment_bytes_at(segments, va, ptr)?;
        if ptr == 8 {
            let w: [u8; 8] = raw.try_into().ok()?;
            Some(if le {
                u64::from_le_bytes(w)
            } else {
                u64::from_be_bytes(w)
            })
        } else {
            let w: [u8; 4] = raw.try_into().ok()?;
            Some(u64::from(if le {
                u32::from_le_bytes(w)
            } else {
                u32::from_be_bytes(w)
            }))
        }
    };
    let push = |va: u64, out: &mut Vec<u64>| {
        if va != 0 && out.len() < MAX_INIT_FUNCS {
            out.push(va);
        }
    };
    for sec in sections {
        if !matches!(
            sec.name.as_str(),
            ".init_array" | ".fini_array" | ".ctors" | ".dtors"
        ) {
            continue;
        }
        let mut off = 0u64;
        while off.saturating_add(ptr as u64) <= sec.file_size {
            if out.len() >= MAX_INIT_FUNCS {
                return out;
            }
            let Some(va) = sec.vaddr.checked_add(off) else {
                break;
            };
            match read_ptr_at(va) {
                Some(v) if v != 0 => out.push(v),
                None => break,
                _ => {}
            }
            off += ptr as u64;
        }
    }
    let (phoff, phentsize, phnum) = if is64 {
        match (u64at(32), u16at(54), u16at(56)) {
            (Some(a), Some(b), Some(c)) => (a, b as usize, c as usize),
            _ => return out,
        }
    } else {
        match (u32at(28), u16at(42), u16at(44)) {
            (Some(a), Some(b), Some(c)) => (u64::from(a), b as usize, c as usize),
            _ => return out,
        }
    };
    let phsize = if is64 { 56 } else { 32 };
    if phentsize < phsize || phnum > 256 {
        return out;
    }
    let mut dyn_off: Option<(u64, u64)> = None;
    for i in 0..phnum {
        let Some(ph_base) = phoff.checked_add((i * phentsize) as u64) else {
            return out;
        };
        let base = ph_base as usize;
        if base.saturating_add(phentsize) > bytes.len() {
            return out;
        }
        let (t, off, filesz) = if is64 {
            let (Some(t), Some(off), Some(filesz)) =
                (u32at(base), u64at(base + 8), u64at(base + 32))
            else {
                return out;
            };
            (t, off, filesz)
        } else {
            let (Some(t), Some(off), Some(filesz)) =
                (u32at(base), u32at(base + 4), u32at(base + 16))
            else {
                return out;
            };
            (t, u64::from(off), u64::from(filesz))
        };
        if t == 2 {
            dyn_off = Some((off, filesz));
            break;
        }
    }
    let Some((doff, dsize)) = dyn_off else {
        return out;
    };
    let entry = if is64 { 16 } else { 8 };
    if dsize > 1024 * 1024 || (doff as usize) > bytes.len() {
        return out;
    }
    let count = (dsize as usize / entry).min(1024);
    let mut init: Option<u64> = None;
    let mut fini: Option<u64> = None;
    let mut init_array: Option<(u64, u64)> = None;
    let mut fini_array: Option<(u64, u64)> = None;
    let mut init_sz: u64 = 0;
    let mut fini_sz: u64 = 0;
    let mut init_va: u64 = 0;
    let mut fini_va: u64 = 0;
    for i in 0..count {
        let Some(base) = (doff as usize).checked_add(i * entry) else {
            break;
        };
        if base.saturating_add(entry) > bytes.len() {
            break;
        }
        let (tag, val) = if is64 {
            let (Some(t), Some(v)) = (bytes.get(base..base + 8), bytes.get(base + 8..base + 16))
            else {
                break;
            };
            let (Ok(t), Ok(v)) = (<[u8; 8]>::try_from(t), <[u8; 8]>::try_from(v)) else {
                break;
            };
            let tt = if le {
                i64::from_le_bytes(t)
            } else {
                i64::from_be_bytes(t)
            };
            let vv = if le {
                u64::from_le_bytes(v)
            } else {
                u64::from_be_bytes(v)
            };
            (tt, vv)
        } else {
            let (Some(t), Some(v)) = (u32at(base), u32at(base + 4)) else {
                break;
            };
            (i64::from(t), u64::from(v))
        };
        match tag {
            0 => break,
            12 => init = Some(val),
            13 => fini = Some(val),
            25 => init_va = val,
            27 => init_sz = val,
            26 => fini_va = val,
            28 => fini_sz = val,
            _ => {}
        }
    }
    if init_va != 0 {
        init_array = Some((init_va, init_sz));
    }
    if fini_va != 0 {
        fini_array = Some((fini_va, fini_sz));
    }
    if let Some(v) = init {
        push(v, &mut out);
    }
    if let Some(v) = fini {
        push(v, &mut out);
    }
    for (va, sz) in [init_array, fini_array].into_iter().flatten() {
        let mut n = (sz as usize / ptr).min(MAX_INIT_FUNCS.saturating_sub(out.len()));
        let mut cur = va;
        while n > 0 {
            if out.len() >= MAX_INIT_FUNCS {
                return out;
            }
            match read_ptr_at(cur) {
                Some(v) if v != 0 => out.push(v),
                None => break,
                _ => {}
            }
            cur = match cur.checked_add(ptr as u64) {
                Some(c) => c,
                None => break,
            };
            n -= 1;
        }
    }
    out
}

/// Mach-O `LC_FUNCTION_STARTS` addresses in table order.
///
/// Decodes ULEB deltas off the `__TEXT` base; anything doubtful (non-thin
/// image, truncated commands, unreadable payload, overflow) yields the
/// prefix so far. Output stops at [`MAX_FUNC_STARTS`].
fn macho_function_starts(bytes: &[u8]) -> Vec<u64> {
    const LC_SEGMENT: u32 = 0x1;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_FUNCTION_STARTS: u32 = 0x26;
    const MAX_COMMANDS: u32 = 4096;
    let mut out: Vec<u64> = Vec::new();
    if bytes.len() < 32 || !is_thin_le_macho(bytes) {
        return out;
    }
    let is64 = bytes[0..4] == 0xFEED_FACFu32.to_le_bytes();
    let get32 = |off: usize| -> Option<u32> {
        let b: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
        Some(u32::from_le_bytes(b))
    };
    let get64 = |off: usize| -> Option<u64> {
        let b: [u8; 8] = bytes.get(off..off + 8)?.try_into().ok()?;
        Some(u64::from_le_bytes(b))
    };
    let Some(ncmds) = get32(16) else {
        return out;
    };
    if ncmds > MAX_COMMANDS {
        return out;
    }
    let mut off = if is64 { 32usize } else { 28usize };
    let mut text_base: Option<u64> = None;
    let mut first_seg: Option<u64> = None;
    let mut payloads: Vec<(usize, usize)> = Vec::new();
    for _ in 0..ncmds {
        let base = off;
        let Some(cmd) = get32(base) else {
            return out;
        };
        let Some(cmdsize_u32) = get32(base + 4) else {
            return out;
        };
        let cmdsize = cmdsize_u32 as usize;
        if cmdsize < 8 || base.checked_add(cmdsize).is_none_or(|e| e > bytes.len()) {
            return out;
        }
        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 => {
                if (cmd == LC_SEGMENT_64) != is64 {
                    return out;
                }
                let (Some(vmaddr), seg_off) = (
                    if is64 {
                        get64(base + 24)
                    } else {
                        get32(base + 24).map(u64::from)
                    },
                    base + 8,
                ) else {
                    return out;
                };
                if first_seg.is_none() {
                    first_seg = Some(vmaddr);
                }
                let Some(seg_name) = bytes.get(seg_off..seg_off + 16) else {
                    return out;
                };
                let name_len = seg_name.iter().position(|&b| b == 0).unwrap_or(16);
                let Some(name) = bytes.get(seg_off..seg_off + name_len) else {
                    return out;
                };
                if name == b"__TEXT" && text_base.is_none() {
                    text_base = Some(vmaddr);
                }
            }
            LC_FUNCTION_STARTS => {
                let (Some(dataoff_u32), Some(datasize_u32)) = (get32(base + 8), get32(base + 12))
                else {
                    return out;
                };
                let (dataoff, datasize) = (dataoff_u32 as usize, datasize_u32 as usize);
                let Some(end) = dataoff.checked_add(datasize) else {
                    return out;
                };
                if end > bytes.len() {
                    return out;
                }
                payloads.push((dataoff, datasize));
            }
            _ => {}
        }
        off = base + cmdsize;
    }
    let Some(mut addr) = text_base.or(first_seg) else {
        return out;
    };
    for (dataoff, datasize) in payloads {
        let end = dataoff + datasize;
        let mut pos = dataoff;
        while pos < end {
            if out.len() >= MAX_FUNC_STARTS {
                return out;
            }
            let mut result: u64 = 0;
            let mut shift: u32 = 0;
            let mut done = false;
            for _ in 0..10 {
                if pos >= end {
                    return out;
                }
                let b = bytes[pos];
                pos += 1;
                let low = u64::from(b & 0x7F);
                if shift >= 64 && low != 0 {
                    return out;
                }
                result |= low.checked_shl(shift).unwrap_or(0);
                if b & 0x80 == 0 {
                    done = true;
                    break;
                }
                shift += 7;
            }
            if !done {
                return out;
            }
            if result == 0 {
                break;
            }
            let Some(next) = addr.checked_add(result) else {
                return out;
            };
            addr = next;
            out.push(addr);
        }
    }
    out
}

/// True for thin little-endian Mach-O images (32- or 64-bit).
///
/// Fat container bytes and big-endian images are not stub-mapped; fat
/// slices re-enter this path as thin images, so they map normally.
fn is_thin_le_macho(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    magic == 0xFEED_FACE || magic == 0xFEED_FACF
}

/// Whether thin Mach-O `bytes` carry `LC_DYLD_CHAINED_FIXUPS`.
///
/// `None` on bad magic or any truncation (unknown means "veto the mapping",
/// never "assume classic binds"). The walk is bound-checked and capped well
/// past real command counts, so hostile `ncmds` cannot loop: exceeding the
/// cap is also `None`.
fn macho_has_chained_fixups(bytes: &[u8]) -> Option<bool> {
    const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
    const MAX_COMMANDS: u32 = 4096;
    if bytes.len() < 32 {
        return None;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let header: usize = match magic {
        0xFEED_FACE => 28,
        0xFEED_FACF => 32,
        _ => return None,
    };
    let ncmds = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    if ncmds > MAX_COMMANDS {
        return None;
    }
    let mut off = header;
    for _ in 0..ncmds {
        if off.saturating_add(8) > bytes.len() {
            return None;
        }
        let cmd = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        let cmdsize = u32::from_le_bytes([
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]);
        if cmd == LC_DYLD_CHAINED_FIXUPS {
            return Some(true);
        }
        if cmdsize < 8 {
            return None;
        }
        off = off.saturating_add(cmdsize as usize);
        if off > bytes.len() {
            return None;
        }
    }
    Some(false)
}

/// Canonical slice name for a fat entry's `object` architecture.
///
/// `None` when the entry targets no disassembler; such slices still appear
/// in the available-arch listing under their `object` debug name.
/// Canonical names match [`raw_arch_name`].
fn canonical_fat_name(arch: object::Architecture) -> Option<&'static str> {
    use object::Architecture as A;
    match arch {
        A::X86_64 | A::X86_64_X32 => Some("x86_64"),
        A::I386 => Some("x86_32"),
        A::Aarch64 | A::Aarch64_Ilp32 => Some("aarch64"),
        A::Arm => Some("arm32"),
        A::Riscv32 => Some("riscv32"),
        A::Riscv64 => Some("riscv64"),
        _ => None,
    }
}

/// Normalize a user-supplied slice selector to a canonical arch name.
///
/// Accepts the canonical names plus `lipo`-style aliases; anything else
/// is unknown (never guessed to a slice).
pub fn normalize_fat_selector(s: &str) -> Option<&'static str> {
    match s.to_lowercase().as_str() {
        "x86_64" | "x86-64" => Some("x86_64"),
        "x86_32" | "i386" | "x86" => Some("x86_32"),
        "aarch64" | "arm64" => Some("aarch64"),
        "arm32" | "arm" => Some("arm32"),
        "riscv32" => Some("riscv32"),
        "riscv64" => Some("riscv64"),
        _ => None,
    }
}

/// Display label for one fat entry: canonical name, else `object` debug.
fn fat_label(arch: object::Architecture) -> String {
    match canonical_fat_name(arch) {
        Some(name) => name.to_string(),
        None => format!("{arch:?}"),
    }
}

/// One fat entry: `object` architecture plus its byte range in the container.
fn fat_table<Fat>(
    fat: &object::read::macho::MachOFatFile<'_, Fat>,
) -> Vec<(object::Architecture, u64, u64)>
where
    Fat: object::read::macho::FatArch,
{
    fat.arches()
        .iter()
        .map(|a| {
            let (offset, size) = a.file_range();
            (a.architecture(), offset, size)
        })
        .collect()
}

/// Extract the selected slice from a fat Mach-O container and load it.
///
/// Parses the fat header with `object::read::macho` (`MachOFatFile32` for
/// `MachOFat32`, `MachOFatFile64` for `MachOFat64`), resolves `fat_arch`
/// against the entry architectures, and loads the selected slice bytes via
/// [`load_object`] as Mach-O. Only the selected slice is copied; the rest
/// of the container is never parsed.
fn load_fat_slice(
    bytes: &[u8],
    kind: FileKind,
    fat_arch: Option<&str>,
    debug: &debuginfo::DebugInputs,
) -> Result<LoadedBinary> {
    use object::read::macho::{MachOFatFile32, MachOFatFile64};
    let table: Vec<(object::Architecture, u64, u64)> = match kind {
        FileKind::MachOFat32 => {
            let fat = MachOFatFile32::parse(bytes)
                .map_err(|e| Error::Invalid(format!("bad fat Mach-O header: {e}")))?;
            fat_table(&fat)
        }
        FileKind::MachOFat64 => {
            let fat = MachOFatFile64::parse(bytes)
                .map_err(|e| Error::Invalid(format!("bad fat Mach-O header: {e}")))?;
            fat_table(&fat)
        }
        _ => return Err(Error::Invalid("not a fat Mach-O container".to_string())),
    };
    if table.is_empty() {
        return Err(Error::Invalid(
            "fat Mach-O container holds no slices".to_string(),
        ));
    }
    let available: Vec<String> = table.iter().map(|(a, _, _)| fat_label(*a)).collect();
    let Some(want) = fat_arch else {
        let plural = if table.len() == 1 { "" } else { "s" };
        return Err(Error::Invalid(format!(
            "fat Mach-O container with {} slice{plural} requires a slice selection (available: {})",
            table.len(),
            available.join(", "),
        )));
    };
    let Some(canonical) = normalize_fat_selector(want) else {
        return Err(Error::Invalid(format!(
            "unknown fat slice arch {want:?} (available: {})",
            available.join(", "),
        )));
    };
    let hits: Vec<usize> = table
        .iter()
        .enumerate()
        .filter(|(_, (a, _, _))| canonical_fat_name(*a) == Some(canonical))
        .map(|(i, _)| i)
        .collect();
    let idx = match hits.len() {
        0 => {
            return Err(Error::Invalid(format!(
                "fat Mach-O container has no {canonical} slice (available: {})",
                available.join(", "),
            )));
        }
        1 => hits[0],
        n => {
            return Err(Error::Invalid(format!(
                "ambiguous fat slice arch {want:?}: matches {n} slices (available: {})",
                available.join(", "),
            )));
        }
    };
    let (_, offset, size) = table[idx];
    let start = usize::try_from(offset)
        .ok()
        .and_then(|o| {
            usize::try_from(size)
                .ok()
                .and_then(|s| o.checked_add(s).map(|e| (o, e)))
        })
        .and_then(|(s, e)| bytes.get(s..e))
        .ok_or_else(|| Error::Invalid(format!("bad fat slice range {offset:#x}+{size:#x}")))?;
    load_object(start, BinaryFormat::MachO, debug)
}

/// Add `len` owned metadata bytes to the aggregate budget.
///
/// Checked so hostile counts cannot wrap the accumulator past the cap.
fn account_meta(meta: &mut u64, len: usize) -> Result<()> {
    *meta = meta
        .checked_add(len as u64)
        .filter(|m| *m <= MAX_METADATA_BYTES)
        .ok_or_else(|| Error::Limit("owned metadata exceeds 16 MiB".to_string()))?;
    Ok(())
}

/// Decode borrowed name bytes to an owned budgeted `String`.
///
/// The raw length is checked before copying and the decoded length after,
/// since one invalid byte expands to a 3-byte replacement character.
fn decode_owned_name(raw: &[u8], meta: &mut u64) -> Result<String> {
    if raw.len() > MAX_NAME_BYTES {
        return Err(Error::Limit(format!(
            "name of {} bytes exceeds {MAX_NAME_BYTES}",
            raw.len()
        )));
    }
    let owned = String::from_utf8_lossy(raw).into_owned();
    if owned.len() > MAX_NAME_BYTES {
        return Err(Error::Limit(format!(
            "decoded name of {} bytes exceeds {MAX_NAME_BYTES}",
            owned.len()
        )));
    }
    account_meta(meta, owned.len())?;
    Ok(owned)
}

/// Demangle with per-output and aggregate budgets, memoizing repeats.
///
/// The cache only saves CPU on repeated names; every owned copy still
/// counts toward the aggregate, so sharing a long name cannot dodge it.
fn demangle_bounded(
    raw: &str,
    meta: &mut u64,
    cache: &mut HashMap<String, Option<String>>,
) -> Result<Option<String>> {
    if let Some(hit) = cache.get(raw) {
        if let Some(d) = hit {
            account_meta(meta, d.len())?;
        }
        return Ok(hit.clone());
    }
    let demangled = demangle_cpp(raw);
    if let Some(d) = &demangled {
        if d.len() > MAX_DEMANGLED_BYTES {
            return Err(Error::Limit(format!(
                "demangled name of {} bytes exceeds {MAX_DEMANGLED_BYTES}",
                d.len()
            )));
        }
        account_meta(meta, d.len())?;
    }
    // Bound the memo itself: distinct hostile names cannot grow it past a
    // few thousand entries; beyond that demangle per row (still budgeted).
    if cache.len() < 4096 {
        cache.insert(raw.to_string(), demangled.clone());
    }
    Ok(demangled)
}

/// Map a parsed LE image to [`LoadedBinary`].
///
/// Imports dedupe fixup targets (`Internal`/`Entry` fixups carry no import);
/// name-table imports keep their table offset as `@0xoff` because [`LeImage`]
/// retains decoded names without offsets. Exports resolve entry bundles to
/// flat addresses, skipping bundles whose object index is out of range.
/// Sections mirror objects as `objN` file-size metadata over each
/// segment's bytes.
/// `symbols` is empty: LE images carry no symbol table.
/// LE owned names are budgeted at [`le::parse_le`] time (shared 16 MiB
/// aggregate); this mapping only clones that bounded set plus small
/// generated names (`objN`, `#n`, `@0x…`, `mod#N`, each under a dozen bytes
/// and count-capped), so its output stays bounded without a second check.
#[must_use]
pub fn convert_le(img: LeImage) -> LoadedBinary {
    let LeImage {
        objects,
        segments,
        entry,
        fixups,
        entries,
        import_modules,
        ..
    } = img;
    let mut imports = Vec::new();
    // Identity index over the resolved import fields. `Vec::contains` made
    // U uniques cost U*(U-1)/2 comparisons; the default-hasher `HashSet`
    // keeps membership O(1) without trusting hostile names to a fixed seed.
    // (`demangled` is always `None` here; it rides along so the key stays
    // a faithful image of the equality predicate.)
    let mut seen: HashSet<LeImportKey> = HashSet::with_capacity(fixups.len().min(MAX_IMPORTS));
    for fix in &fixups {
        let imp = match &fix.target {
            LeTarget::Internal { .. } | LeTarget::Entry { .. } => continue,
            LeTarget::ImportOrdinal { module, ordinal } => ImportRef {
                library: le_module(&import_modules, *module),
                name: format!("#{ordinal}"),
                ordinal: Some(*ordinal),
                unresolved: true,
                demangled: None,
                address: None,
            },
            LeTarget::ImportName {
                module,
                name_offset,
            } => ImportRef {
                library: le_module(&import_modules, *module),
                name: format!("@{name_offset:#x}"),
                ordinal: None,
                unresolved: false,
                demangled: None,
                address: None,
            },
        };
        let key: LeImportKey = (
            imp.library.clone(),
            imp.name.clone(),
            imp.ordinal,
            imp.unresolved,
            imp.demangled.clone(),
        );
        if seen.insert(key) {
            imports.push(imp);
        }
        if imports.len() >= MAX_IMPORTS {
            break;
        }
    }
    let mut exports = Vec::new();
    for e in &entries {
        if exports.len() >= MAX_EXPORTS {
            break;
        }
        let Some(obj) = e
            .object
            .checked_sub(1)
            .and_then(|i| objects.get(i as usize))
        else {
            continue;
        };
        exports.push(ExportRef {
            name: e.ordinal.to_string(),
            address: Some(obj.reloc_base as u64 + e.offset as u64),
            ordinal: Some(e.ordinal),
            demangled: None,
        });
    }
    let sections = objects
        .iter()
        .zip(segments.iter())
        .map(|(o, s)| Section {
            name: format!("obj{}", o.index),
            vaddr: o.reloc_base as u64,
            size: o.virtual_size as u64,
            file_off: 0,
            file_size: s.data.len() as u64,
            entropy: section_entropy(&s.data),
            readable: o.readable,
            writable: o.writable,
            executable: o.executable,
        })
        .collect();
    LoadedBinary {
        format: BinaryFormat::Le,
        arch: Arch::X86_32,
        entry,
        segments,
        sections,
        imports,
        exports,
        symbols: Vec::new(),
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        debug_funcs: Vec::new(),
        relocatable: false,
        arm_hints: ArmHints::default(),
    }
}

fn le_module(modules: &[String], module: u32) -> String {
    module
        .checked_sub(1)
        .and_then(|i| modules.get(i as usize))
        .cloned()
        .unwrap_or_else(|| format!("mod#{module}"))
}

fn import_from_object(
    library: &[u8],
    name: object::NameOrOrdinal<&[u8]>,
    meta: &mut u64,
    cache: &mut HashMap<String, Option<String>>,
) -> Result<ImportRef> {
    let library = decode_owned_name(library, meta)?;
    match name {
        object::NameOrOrdinal::Ordinal(o) => {
            let name = format!("#{o}");
            account_meta(meta, name.len())?;
            Ok(ImportRef {
                library,
                name,
                ordinal: Some(u32::from(o)),
                unresolved: true,
                demangled: None,
                address: None,
            })
        }
        object::NameOrOrdinal::Name(b) => {
            let raw = decode_owned_name(b, meta)?;
            let demangled = demangle_bounded(&raw, meta, cache)?;
            Ok(ImportRef {
                library,
                name: raw,
                ordinal: None,
                unresolved: false,
                demangled,
                address: None,
            })
        }
    }
}

fn export_from_object(
    name: object::NameOrOrdinal<&[u8]>,
    address: Option<u64>,
    meta: &mut u64,
    cache: &mut HashMap<String, Option<String>>,
) -> Result<ExportRef> {
    match name {
        object::NameOrOrdinal::Ordinal(o) => {
            let name = format!("#{o}");
            account_meta(meta, name.len())?;
            Ok(ExportRef {
                name,
                address,
                ordinal: Some(u32::from(o)),
                demangled: None,
            })
        }
        object::NameOrOrdinal::Name(b) => {
            let raw = decode_owned_name(b, meta)?;
            let demangled = demangle_bounded(&raw, meta, cache)?;
            Ok(ExportRef {
                name: raw,
                address,
                ordinal: None,
                demangled,
            })
        }
    }
}

/// Collect 32-bit ARM decode hints (see [`ArmHints`]).
///
/// Reads `$a`/`$t` mapping symbols (plus `$d` data boundaries) and
/// Thumb-bit `STT_FUNC` symbols from the regular and dynamic tables.
/// Anything else (other architectures, relocatable objects, unreadable
/// symbols, out-of-range mappings) yields empty hints, never an error —
/// except hostile table sizes, which fail with [`Error::Limit`] like the
/// other table collectors.
///
/// Mapping ranges extend from each marker to the next marker (any kind),
/// clamped to the containing executable range; `$d` markers only bound
/// their neighbors. A bare `$t` start with no executable cover is
/// dropped. Names match exactly or with a dotted suffix (`$t.0`).
fn collect_arm_hints<'a>(
    file: &object::File<'a, &'a [u8]>,
    arch: Arch,
    sections: &[Section],
    segments: &[Segment],
) -> Result<ArmHints> {
    let mut hints = ArmHints::default();
    if arch != Arch::Arm32 {
        return Ok(hints);
    }
    let ranges = merged_exec_ranges(sections, segments);
    let in_exec = |addr: u64| -> bool {
        ranges
            .binary_search_by(|(lo, hi)| {
                if addr < *lo {
                    std::cmp::Ordering::Greater
                } else if addr >= *hi {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    };
    let exec_end = |addr: u64| -> Option<u64> {
        ranges
            .iter()
            .find(|(lo, hi)| *lo <= addr && addr < *hi)
            .map(|(_, hi)| *hi)
    };
    // (address, mode): `Some(true)` is `$t`, `Some(false)` is `$a`,
    // `None` is a `$d` boundary (bounds neighbors, no range of its own).
    let mut starts: Vec<(u64, Option<bool>)> = Vec::new();
    // Chaining is lazy: dynamic rows only decode when the regular table
    // is exhausted, mirroring [`collect_symbols`].
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if !matches!(sym.section(), object::SymbolSection::Section(_)) {
            continue;
        }
        let Ok(name) = sym.name_bytes() else {
            continue;
        };
        if name == b"$a" || name.starts_with(b"$a.") {
            if starts.len() >= MAX_SYMBOLS {
                return Err(Error::Limit("symbols exceed cap".to_string()));
            }
            starts.push((sym.address(), Some(false)));
        } else if name == b"$t" || name.starts_with(b"$t.") {
            if starts.len() >= MAX_SYMBOLS {
                return Err(Error::Limit("symbols exceed cap".to_string()));
            }
            starts.push((sym.address(), Some(true)));
        } else if name == b"$d" || name.starts_with(b"$d.") {
            if starts.len() >= MAX_SYMBOLS {
                return Err(Error::Limit("symbols exceed cap".to_string()));
            }
            starts.push((sym.address(), None));
        } else if sym.kind() == object::SymbolKind::Text
            && arch == Arch::Arm32
            && sym.address() & 1 == 1
        {
            let addr = canonical_code_addr(arch, sym.address());
            if in_exec(addr) {
                if hints.thumb_seeds.len() >= MAX_SYMBOLS {
                    return Err(Error::Limit("symbols exceed cap".to_string()));
                }
                hints.thumb_seeds.push(addr);
            }
        }
    }
    starts.sort_unstable();
    starts.dedup_by_key(|(addr, _)| *addr);
    for (i, (addr, mode)) in starts.iter().enumerate() {
        let Some(mode) = mode else {
            continue;
        };
        let next = starts.get(i + 1).map(|(a, _)| *a).unwrap_or(u64::MAX);
        let Some(hi) = exec_end(*addr) else {
            continue;
        };
        let end = next.min(hi);
        if end <= *addr {
            continue;
        }
        if hints.thumb_ranges.len() + hints.arm_ranges.len() >= MAX_SYMBOLS {
            return Err(Error::Limit("symbols exceed cap".to_string()));
        }
        if *mode {
            hints.thumb_ranges.push((*addr, end));
        } else {
            hints.arm_ranges.push((*addr, end));
        }
    }
    hints.thumb_seeds.sort_unstable();
    hints.thumb_seeds.dedup();
    Ok(hints)
}
/// Collect defined code symbols from the regular and dynamic tables.
///
/// Keeps `SymbolKind::Text` definitions sectioned in executable memory
/// (locals included: statics, non-exported globals), canonicalized via
/// [`canonical_code_addr`] and deduplicated by address with the first
/// table row winning. Names and demangled copies count against the
/// shared metadata budget; unique rows are capped at [`MAX_SYMBOLS`].
///
/// The executable-range check runs over the loader's own mapped
/// sections (segments as fallback) so `Text`-kind rows pointing at
/// data never seed or name functions.
fn collect_symbols<'a>(
    file: &object::File<'a, &'a [u8]>,
    arch: Arch,
    sections: &[Section],
    segments: &[Segment],
    meta: &mut u64,
    cache: &mut HashMap<String, Option<String>>,
) -> Result<Vec<SymbolRef>> {
    let ranges = merged_exec_ranges(sections, segments);
    let in_exec = |addr: u64| -> bool {
        ranges
            .binary_search_by(|(lo, hi)| {
                if addr < *lo {
                    std::cmp::Ordering::Greater
                } else if addr >= *hi {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    };

    let mut out: Vec<SymbolRef> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    // Chaining is lazy: dynamic rows only decode when the regular table
    // is exhausted, and every row below is filtered before any copy.
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if sym.kind() != object::SymbolKind::Text {
            continue;
        }
        if !matches!(sym.section(), object::SymbolSection::Section(_)) {
            continue;
        }
        let address = canonical_code_addr(arch, sym.address());
        if !in_exec(address) {
            continue;
        }
        let raw = match sym.name_bytes() {
            Ok(b) if !b.is_empty() => decode_owned_name(b, meta)?,
            _ => continue,
        };
        if !seen.insert(address) {
            continue;
        }
        if out.len() >= MAX_SYMBOLS {
            return Err(Error::Limit("symbols exceed cap".to_string()));
        }
        let demangled = demangle_bounded(&raw, meta, cache)?;
        out.push(SymbolRef {
            name: raw,
            address,
            demangled,
        });
    }
    Ok(out)
}

/// Demangle a C++ symbol to a human-readable form.
///
/// Tries MSVC undecoration (`?...`, `.?AV...@@`) via `msvc-demangler`
/// then Itanium (`_Z...`, including one leading-underscore Mach-O form)
/// via `cpp_demangle`. Returns `None` for plain C names, ordinal
/// placeholders (`#n`), LE offsets (`@0x...`), and failed decodes.
/// Both demanglers are dependency-light MIT crates with no transitive
/// dependencies (no `cargo-deny` exception needed).
#[must_use]
pub fn demangle_cpp(name: &str) -> Option<String> {
    if name.is_empty() || name.starts_with('#') || name.starts_with('@') {
        return None;
    }
    if let Ok(d) = msvc_demangler::demangle(name, msvc_demangler::DemangleFlags::llvm())
        && !d.is_empty()
        && d != name
    {
        return Some(d);
    }
    if name.contains("_Z") {
        let mut candidates = [name, ""];
        let stripped = name.strip_prefix('_').unwrap_or(name);
        if stripped != name {
            candidates[1] = stripped;
        }
        for cand in candidates.into_iter().filter(|c| !c.is_empty()) {
            if let Ok(sym) = cpp_demangle::Symbol::new(cand.as_bytes())
                && let Ok(d) = sym.demangle()
                && !d.is_empty()
                && d != name
            {
                return Some(d);
            }
        }
    }
    None
}

fn is_bss(kind: object::SectionKind) -> bool {
    kind.is_bss()
}

fn section_perms(kind: object::SectionKind) -> (bool, bool, bool) {
    use object::SectionKind as K;
    match kind {
        K::Text => (true, false, true),
        K::Data | K::Tls | K::UninitializedData | K::UninitializedTls => (true, true, false),
        _ => (true, false, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::le::{LeEntry, LeFixup, LeObject};

    #[test]
    fn arch_mapping_covers_supported_targets() {
        use object::Architecture as A;
        assert_eq!(arch_from_object(A::X86_64).unwrap(), Arch::X86_64);
        assert_eq!(arch_from_object(A::I386).unwrap(), Arch::X86_32);
        assert_eq!(arch_from_object(A::Aarch64).unwrap(), Arch::Aarch64);
        assert_eq!(arch_from_object(A::Arm).unwrap(), Arch::Arm32);
        assert_eq!(arch_from_object(A::Riscv32).unwrap(), Arch::Riscv32);
        assert_eq!(arch_from_object(A::Riscv64).unwrap(), Arch::Riscv64);
        assert!(matches!(
            arch_from_object(A::Mips).unwrap_err(),
            Error::Unsupported(_)
        ));
    }

    #[test]
    fn le_conversion_maps_entry_tables_and_sections() {
        let img = LeImage {
            page_size: 0x1000,
            cpu: 2,
            os: 3,
            module_flags: 0,
            objects: vec![LeObject {
                index: 1,
                virtual_size: 0x1000,
                reloc_base: 0x10000,
                flags: 0x2005,
                readable: true,
                writable: false,
                executable: true,
            }],
            segments: vec![Segment {
                vaddr: 0x10000,
                mem_size: 0x1000,
                data: vec![0x90, 0x90, 0xC3],
                readable: true,
                writable: false,
                executable: true,
            }],
            entry: Some(0x10000),
            fixups: vec![LeFixup {
                page: 1,
                sources: vec![0],
                target: LeTarget::ImportOrdinal {
                    module: 1,
                    ordinal: 7,
                },
                additive: None,
            }],
            entries: vec![LeEntry {
                ordinal: 1,
                object: 1,
                offset: 0,
                exported: true,
            }],
            import_modules: vec!["KERNEL".to_string()],
            import_procs: vec!["ExitProcess".to_string()],
        };
        let bin = convert_le(img);
        assert_eq!(bin.format, BinaryFormat::Le);
        assert_eq!(bin.arch, Arch::X86_32);
        assert_eq!(bin.entry, Some(0x10000));
        assert_eq!(
            bin.imports,
            [ImportRef {
                library: "KERNEL".to_string(),
                name: "#7".to_string(),
                ordinal: Some(7),
                unresolved: true,
                demangled: None,
                address: None,
            }]
        );
        assert_eq!(
            bin.exports,
            [ExportRef {
                name: "1".to_string(),
                address: Some(0x10000),
                ordinal: Some(1),
                demangled: None,
            }]
        );
        assert_eq!(bin.sections.len(), 1);
        assert_eq!(bin.sections[0].name, "obj1");
        assert_eq!(bin.sections[0].file_size, 3);
    }

    #[test]
    fn chained_stub_slot_decodes_known_shapes() {
        // arm64: adrp x16, 0x11000 from 0x10008 (page imm 1), then
        // ldr x16, [x16, #8].
        let arm = [0x10u8, 0x00, 0x00, 0xB0, 0x10, 0x06, 0x40, 0xF9];
        assert_eq!(
            chained_stub_slot(&arm, ChainedStubArch::Aarch64, 0x10008),
            Some(0x11008)
        );
        // x86-64: jmp [rip+0xFF2] lands on 0x11000.
        let x64 = [0xFFu8, 0x25, 0xF2, 0x0F, 0x00, 0x00];
        assert_eq!(
            chained_stub_slot(&x64, ChainedStubArch::X86_64, 0x10008),
            Some(0x11000)
        );
        // x86-32: absolute jmp [0x11000].
        let x32 = [0xFFu8, 0x25, 0x00, 0x10, 0x01, 0x00];
        assert_eq!(
            chained_stub_slot(&x32, ChainedStubArch::X86_32, 0),
            Some(0x11000)
        );
        // Rejections: non-adrp first word, 32-bit ldr, base-register
        // mismatch (ldr x16, [x17]), truncated input.
        let ret = [0xC0u8, 0x03, 0x5F, 0xD6, 0x10, 0x02, 0x40, 0xF9];
        assert_eq!(
            chained_stub_slot(&ret, ChainedStubArch::Aarch64, 0x10008),
            None
        );
        let ldr32 = [0x10u8, 0x00, 0x00, 0xB0, 0x10, 0x02, 0x40, 0xB9];
        assert_eq!(
            chained_stub_slot(&ldr32, ChainedStubArch::Aarch64, 0x10008),
            None
        );
        let mismatch = [0x10u8, 0x00, 0x00, 0xB0, 0x30, 0x02, 0x40, 0xF9];
        assert_eq!(
            chained_stub_slot(&mismatch, ChainedStubArch::Aarch64, 0x10008),
            None
        );
        assert_eq!(
            chained_stub_slot(&[0xFF, 0x25], ChainedStubArch::X86_64, 0),
            None
        );
    }

    #[test]
    fn chained_fixups_scan_vetoes_only_on_evidence() {
        fn header(ncmds: u32, cmds: &[u8]) -> Vec<u8> {
            let mut f = vec![0u8; 32];
            f[0..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
            f[16..20].copy_from_slice(&ncmds.to_le_bytes());
            f.extend_from_slice(cmds);
            f
        }
        fn cmd(id: u32, size: u32) -> Vec<u8> {
            let mut c = vec![0u8; size as usize];
            c[0..4].copy_from_slice(&id.to_le_bytes());
            c[4..8].copy_from_slice(&size.to_le_bytes());
            c
        }
        let plain = header(1, &cmd(0x19, 72));
        assert_eq!(macho_has_chained_fixups(&plain), Some(false));
        // ncmds says 2 but only 1 present above; rebuild honestly:
        let chained = header(2, &[cmd(0x19, 72), cmd(0x8000_0034, 16)].concat());
        assert_eq!(macho_has_chained_fixups(&chained), Some(true));
        assert_eq!(macho_has_chained_fixups(&[]), None);
        assert_eq!(macho_has_chained_fixups(b"garbage........"), None);
        // Truncated command claims more than the bytes hold.
        assert_eq!(macho_has_chained_fixups(&header(4, &cmd(0x19, 72))), None);
        // Fat magic is not a thin image: unknown, so veto.
        let mut fat = plain.clone();
        fat[0..4].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
        assert_eq!(macho_has_chained_fixups(&fat), None);
    }

    #[test]
    fn load_rejects_empty_input() {
        assert!(matches!(load(&[]).unwrap_err(), Error::Invalid(_)));
        assert!(matches!(
            load_raw(
                &[],
                RawOptions {
                    base: 0,
                    arch: Arch::X86_64,
                    entry: None
                }
            )
            .unwrap_err(),
            Error::Invalid(_)
        ));
    }

    #[test]
    fn load_rejects_garbage() {
        assert!(matches!(
            load(b"this is not a binary at all..........").unwrap_err(),
            Error::Invalid(_)
        ));
    }

    #[test]
    fn demangle_cpp_handles_msvc_itanium_and_plain() {
        let msvc = demangle_cpp("?myfunc@@YAXH@Z").expect("MSVC demangles");
        assert!(msvc.contains("myfunc"), "got {msvc:?}");
        let itanium = demangle_cpp("_ZN5space3fooEibc").expect("Itanium demangles");
        assert_eq!(itanium, "space::foo(int, bool, char)");
        assert_eq!(demangle_cpp("plain_c_func"), None);
        assert_eq!(demangle_cpp("#1"), None);
        assert_eq!(demangle_cpp("@0x10"), None);
    }
}
