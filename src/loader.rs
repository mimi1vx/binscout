//! M1 loader: binary format readers mapped to shared [`Segment`]s.
//!
//! ELF/PE/Mach-O/COFF go through the `object` crate (parent epic
//! `rsdbg-m1-loader-0tp`); the LE branch is a custom pure-Rust reader in
//! [`le`] because `object` has no Linear Executable support. Raw blobs
//! (firmware, shellcode, `--base` dumps) map via [`load_raw`]. Printable
//! runs live in [`strings`].

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
    /// COFF relocatable object (e.g. Windows `.obj`): sections map at
    /// their link-time addresses (usually zero), entry is `None`, and
    /// imports/exports are empty (`object` exposes no COFF import/export
    /// tables yet).
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Section is readable.
    pub readable: bool,
    /// Section is writable.
    pub writable: bool,
    /// Section is executable.
    pub executable: bool,
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
/// relocations on ELF. Unresolved imports carry `address: None`. JSON
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
    /// GOT slot on ELF (`None` for unmapped imports; see `load`).
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

/// A parsed binary ready for disassembly and analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        return Ok(convert_le(le::parse_le(bytes)?));
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
        FileKind::Elf32 | FileKind::Elf64 => load_object(bytes, BinaryFormat::Elf),
        FileKind::Pe32 | FileKind::Pe64 => load_object(bytes, BinaryFormat::Pe),
        FileKind::MachO32 | FileKind::MachO64 => load_object(bytes, BinaryFormat::MachO),
        FileKind::MachOFat32 | FileKind::MachOFat64 => load_fat_slice(bytes, kind, fat_arch),
        FileKind::Coff => load_object(bytes, BinaryFormat::Coff),
        other => Err(Error::Unsupported(format!("file kind {other:?}"))),
    }
}

/// Canonical raw arch name for diagnostics (`x86_64`, `x86_32`, `aarch64`,
/// `arm32`, `thumb`).
#[must_use]
pub fn raw_arch_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "x86_64",
        Arch::X86_32 => "x86_32",
        Arch::Aarch64 => "aarch64",
        Arch::Arm32 => "arm32",
        Arch::Thumb => "thumb",
    }
}

/// Required entry alignment in bytes for a raw [`Arch`].
///
/// x86 targets decode from any byte; AArch64/ARM32 need 4-byte words and
/// Thumb needs 2-byte halfwords. Bases accept any alignment: only the entry
/// must satisfy the mode.
#[must_use]
pub fn raw_entry_alignment(arch: Arch) -> u64 {
    match arch {
        Arch::X86_64 | Arch::X86_32 => 1,
        Arch::Aarch64 | Arch::Arm32 => 4,
        Arch::Thumb => 2,
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
    })
}

/// Map an `object` architecture to a disassembler target.
///
/// 32-bit ARM containers default to ARM mode; Thumb regions decode through
/// [`Arch::Thumb`] raw mappings.
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

fn load_object(bytes: &[u8], format: BinaryFormat) -> Result<LoadedBinary> {
    let file =
        object::File::parse(bytes).map_err(|e| Error::Invalid(format!("object parse: {e}")))?;
    let arch = arch_from_object(file.architecture())?;
    // Owned-name budget shared by sections/imports/exports below; counted
    // before each copy so repeated long names fail fast instead of OOMing.
    let mut meta_bytes: u64 = 0;
    let mut demangle_cache: HashMap<String, Option<String>> = HashMap::new();

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

    Ok(LoadedBinary {
        format,
        arch,
        entry,
        segments,
        sections,
        imports,
        exports,
        symbols,
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
fn load_fat_slice(bytes: &[u8], kind: FileKind, fat_arch: Option<&str>) -> Result<LoadedBinary> {
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
    load_object(start, BinaryFormat::MachO)
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
    // Merge overlaps so the binary search below cannot miss a hit
    // hiding behind a neighboring range in a hostile section table.
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
    let ranges = merged;
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
