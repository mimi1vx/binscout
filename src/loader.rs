//! M1 loader: binary format readers mapped to shared [`Segment`]s.
//!
//! ELF/PE/Mach-O go through the `object` crate (parent epic
//! `rsdbg-m1-loader-0tp`); the LE branch is a custom pure-Rust reader in
//! [`le`] because `object` has no Linear Executable support. Raw blobs
//! (firmware, shellcode, `--base` dumps) map via [`load_raw`]. Printable
//! runs live in [`strings`].

pub mod le;
pub mod strings;

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
    /// Linear Executable (DOS4GW).
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportRef {
    /// Providing module (`""` when the format names none).
    pub library: String,
    /// Symbol name, `#ordinal`, or `@0xoff`.
    pub name: String,
}

/// One exported symbol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRef {
    /// Symbol name (LE: decimal ordinal).
    pub name: String,
    /// Export address (`None` for re-exports, TLS, and resolver stubs).
    pub address: Option<u64>,
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

/// Parse any supported binary: LE via [`le`], ELF/PE/Mach-O via `object`.
///
/// # Errors
/// [`Error::Invalid`] on empty or unrecognized input, [`Error::Unsupported`]
/// on recognized formats this loader does not handle (Wasm, archives, …)
/// or architectures without a disassembler, [`Error::Limit`] when table or
/// byte caps are exceeded.
pub fn load(bytes: &[u8]) -> Result<LoadedBinary> {
    if bytes.is_empty() {
        return Err(Error::Invalid("empty input".to_string()));
    }
    if le::is_le(bytes) {
        return Ok(convert_le(le::parse_le(bytes)?));
    }
    let kind = FileKind::parse(bytes)
        .map_err(|e| Error::Invalid(format!("unrecognized binary format: {e}")))?;
    match kind {
        FileKind::Elf32 | FileKind::Elf64 => load_object(bytes, BinaryFormat::Elf),
        FileKind::Pe32 | FileKind::Pe64 => load_object(bytes, BinaryFormat::Pe),
        FileKind::MachO32 | FileKind::MachO64 | FileKind::MachOFat32 | FileKind::MachOFat64 => {
            load_object(bytes, BinaryFormat::MachO)
        }
        other => Err(Error::Unsupported(format!("file kind {other:?}"))),
    }
}

/// Map a raw blob to a single `RWX` segment at `opts.base`.
///
/// Permissions are unknown for raw input; the segment is marked `RWX` as the
/// neutral stand-in. Sections/imports/exports are empty: raw has no tables.
///
/// # Errors
/// [`Error::Invalid`] on empty input, [`Error::Limit`] when the blob exceeds
/// [`MAX_MAPPED_BYTES`].
pub fn load_raw(bytes: &[u8], opts: RawOptions) -> Result<LoadedBinary> {
    if bytes.is_empty() {
        return Err(Error::Invalid("empty raw input".to_string()));
    }
    if bytes.len() as u64 > MAX_MAPPED_BYTES {
        return Err(Error::Limit("raw blob exceeds 256 MiB".to_string()));
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
/// # Errors
/// [`Error::Unsupported`] for 32-bit ARM (deferred to `rsdbg-0bw`) and any
/// other architecture without a disassembler.
pub fn arch_from_object(arch: object::Architecture) -> Result<Arch> {
    use object::Architecture as A;
    match arch {
        A::X86_64 | A::X86_64_X32 => Ok(Arch::X86_64),
        A::I386 => Ok(Arch::X86_32),
        A::Aarch64 | A::Aarch64_Ilp32 => Ok(Arch::Aarch64),
        A::Arm => Err(Error::Unsupported(
            "armv7/thumb deferred to rsdbg-0bw".to_string(),
        )),
        other => Err(Error::Unsupported(format!("architecture {other:?}"))),
    }
}

fn load_object(bytes: &[u8], format: BinaryFormat) -> Result<LoadedBinary> {
    let file =
        object::File::parse(bytes).map_err(|e| Error::Invalid(format!("object parse: {e}")))?;
    let arch = arch_from_object(file.architecture())?;

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
        let name = sec
            .name_bytes()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_else(|_| "<invalid>".to_string());
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
        sections.push(Section {
            name,
            vaddr: sec.address(),
            size: sec.size(),
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
        imports.push(ImportRef {
            library: String::from_utf8_lossy(imp.library()).into_owned(),
            name: name_or_ordinal(imp.name()),
        });
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
        exports.push(ExportRef {
            name: name_or_ordinal(exp.name()),
            address: match exp.target() {
                object::ExportTarget::Address { address } => Some(address),
                _ => None,
            },
        });
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

/// Map a parsed LE image to [`LoadedBinary`].
///
/// Imports dedupe fixup targets (`Internal`/`Entry` fixups carry no import);
/// name-table imports keep their table offset as `@0xoff` because [`LeImage`]
/// retains decoded names without offsets. Exports resolve entry bundles to
/// flat addresses, skipping bundles whose object index is out of range.
/// Sections mirror objects as `objN` sharing each segment's bytes.
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
    for fix in &fixups {
        let (library, name) = match &fix.target {
            LeTarget::Internal { .. } | LeTarget::Entry { .. } => continue,
            LeTarget::ImportOrdinal { module, ordinal } => {
                (le_module(&import_modules, *module), format!("#{ordinal}"))
            }
            LeTarget::ImportName {
                module,
                name_offset,
            } => (
                le_module(&import_modules, *module),
                format!("@{name_offset:#x}"),
            ),
        };
        let imp = ImportRef { library, name };
        if !imports.contains(&imp) {
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
        let Some(obj) = objects.get(e.object as usize - 1) else {
            continue;
        };
        exports.push(ExportRef {
            name: e.ordinal.to_string(),
            address: Some(obj.reloc_base as u64 + e.offset as u64),
        });
    }
    let sections = objects
        .iter()
        .zip(segments.iter())
        .map(|(o, s)| Section {
            name: format!("obj{}", o.index),
            vaddr: o.reloc_base as u64,
            size: o.virtual_size as u64,
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
    modules
        .get(module as usize - 1)
        .cloned()
        .unwrap_or_else(|| format!("mod#{module}"))
}

fn name_or_ordinal(name: object::NameOrOrdinal<&[u8]>) -> String {
    match name {
        object::NameOrOrdinal::Name(b) => String::from_utf8_lossy(b).into_owned(),
        object::NameOrOrdinal::Ordinal(o) => format!("#{o}"),
    }
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
        assert!(matches!(
            arch_from_object(A::Arm).unwrap_err(),
            Error::Unsupported(_)
        ));
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
            }]
        );
        assert_eq!(
            bin.exports,
            [ExportRef {
                name: "1".to_string(),
                address: Some(0x10000),
            }]
        );
        assert_eq!(bin.sections.len(), 1);
        assert_eq!(bin.sections[0].name, "obj1");
        assert_eq!(bin.sections[0].data, [0x90, 0x90, 0xC3]);
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
}
