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

use object::{FileKind, Object, ObjectSection, ObjectSegment};

use crate::disasm::Arch;
use crate::error::{Error, Result};
use crate::loader::le::{LeImage, LeTarget};

/// Cap on segments per binary.
pub const MAX_SEGMENTS: usize = 256;
/// Cap on sections per binary.
pub const MAX_SECTIONS: usize = 2048;
/// Cap on materialized segment bytes and, separately, section bytes
/// (zero-fill/`bss` tails stay virtual).
pub const MAX_MAPPED_BYTES: u64 = 256 * 1024 * 1024;
/// Cap on imports per binary.
pub const MAX_IMPORTS: usize = 100_000;
/// Cap on exports per binary.
pub const MAX_EXPORTS: usize = 100_000;
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

/// One named section with its file bytes (`data` may be empty for `bss`-like
/// sections whose `size` is purely virtual).
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
    /// File-backed bytes starting at `vaddr`.
    pub data: Vec<u8>,
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
/// Mach-O imports resolved to a `__stubs`/`__auth_stubs` entry carry its
/// address; every other import carries `address: None`. JSON pairs
/// `address` with `address_hex` (`null` on both sides for address-less
/// imports).
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
    /// `__stubs`/`__auth_stubs` entry address (`None` for non-Mach-O and
    /// unmapped Mach-O imports; see `load` stub mapping).
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
/// Identical to [`load`] for thin containers: `fat_arch` is ignored unless
/// the input is a fat (universal) Mach-O container. For fat input the slice
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
/// Same as [`load`], plus [`Error::Invalid`] when fat input has no usable
/// selection (missing, unknown, or ambiguous) or the selected slice range
/// is unreadable.
pub fn load_with_slice(bytes: &[u8], fat_arch: Option<&str>) -> Result<LoadedBinary> {
    if bytes.is_empty() {
        return Err(Error::Invalid("empty input".to_string()));
    }
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(Error::Limit("input exceeds 512 MiB".to_string()));
    }
    if le::is_le(bytes) {
        return Ok(convert_le(le::parse_le(bytes)?));
    }
    let kind = FileKind::parse(bytes)
        .map_err(|e| Error::Invalid(format!("unrecognized binary format: {e}")))?;
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
/// neutral stand-in. Sections/imports/exports are empty: raw has no tables.
///
/// # Errors
/// [`Error::Invalid`] on empty input, base-plus-length overflow, an entry
/// outside the mapped range, or a mode-misaligned entry;
/// [`Error::Limit`] when the blob exceeds [`MAX_MAPPED_BYTES`].
pub fn load_raw(bytes: &[u8], opts: RawOptions) -> Result<LoadedBinary> {
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
            mem_size: bytes.len() as u64,
            data: bytes.to_vec(),
            readable: true,
            writable: true,
            executable: true,
        }],
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
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
            data: data.to_vec(),
            readable,
            writable,
            executable,
        });
    }

    let entry = match file.entry() {
        0 => None,
        e => Some(e),
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

    if format == BinaryFormat::MachO
        && let Some(stubs) = macho_stub_addresses(&file, bytes, imports.len())
    {
        for (imp, addr) in imports.iter_mut().zip(stubs) {
            imp.address = Some(addr);
        }
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

    Ok(LoadedBinary {
        format,
        arch,
        entry,
        segments,
        sections,
        imports,
        exports,
    })
}

/// Derive Mach-O stub entry addresses in import order, or `None` on any doubt.
///
/// Pairs the i-th `__stubs`/`__auth_stubs` entry (section-table order) with
/// the i-th import (`object` bind order). Every guard must hold, otherwise
/// nothing maps rather than misattributing an address to the wrong import:
/// thin little-endian Mach-O magic, no `LC_DYLD_CHAINED_FIXUPS` (chained
/// fixups reorder binds away from stub order), at least one stub section of
/// type `S_SYMBOL_STUBS` in a `__TEXT*` segment with a nonzero `reserved2`
/// stride dividing its size, checked entry arithmetic, and total entries
/// exactly equal to `import_count`. Real binaries routinely fail the last
/// two guards: `/bin/ls` (arm64e) carries 84 `__auth_stubs` for 90
/// chained-fixup imports, and its x86_64 slice 84 `__stubs` for 91
/// `LC_DYLD_INFO` imports (stub-less data binds have no entry).
fn macho_stub_addresses<'a>(
    file: &object::File<'a, &'a [u8]>,
    bytes: &'a [u8],
    import_count: usize,
) -> Option<Vec<u64>> {
    use object::{Object, ObjectSection};
    if import_count == 0 || import_count > MAX_IMPORTS {
        return None;
    }
    if !is_thin_le_macho(bytes) {
        return None;
    }
    if macho_has_chained_fixups(bytes) != Some(false) {
        return None;
    }
    let mut addrs = Vec::new();
    let mut stubbed = false;
    for sec in file.sections() {
        if !matches!(sec.name(), Ok("__stubs" | "__auth_stubs")) {
            continue;
        }
        let in_text = sec
            .segment_name()
            .ok()
            .flatten()
            .is_some_and(|s| s.starts_with("__TEXT"));
        let stride = match sec.flags() {
            object::SectionFlags::MachO { flags, reserved2 }
                if flags.typ() == object::macho::S_SYMBOL_STUBS && reserved2 != 0 =>
            {
                u64::from(reserved2)
            }
            _ => return None,
        };
        if !in_text {
            return None;
        }
        let size = sec.size();
        if size == 0 || size % stride != 0 {
            return None;
        }
        let base = sec.address();
        for i in 0..size / stride {
            addrs.push(base.checked_add(i.checked_mul(stride)?)?);
            if addrs.len() > import_count {
                return None;
            }
        }
        stubbed = true;
    }
    if !stubbed || addrs.len() != import_count {
        return None;
    }
    Some(addrs)
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
fn normalize_fat_selector(s: &str) -> Option<&'static str> {
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
/// Sections mirror objects as `objN` sharing each segment's bytes.
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
            data: s.data.clone(),
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
        assert_eq!(bin.sections[0].data, [0x90, 0x90, 0xC3]);
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
