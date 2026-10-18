//! On-demand header metadata (`headers` command / MCP tool).
//!
//! [`headers_of`] parses the raw container bytes on demand and returns one
//! JSON value with triage staples plus file hashes: PE timestamps,
//! mitigations, Rich data, imphash, Authenticode/PDB/version resources,
//! delay-load imports and export forwarders; ELF interpreter, needed
//! libraries, RUNPATH/RPATH, RELRO/NX/PIE, build-id and stripped state;
//! Mach-O load commands, dylibs, min-OS/SDK, code signature, entitlements
//! and UUID; plus `sha256` (the project's content identity) and `md5` for
//! VirusTotal-style lookups. Nothing is persisted: the sidecar is never
//! touched, and unparseable inputs degrade to `null` fields rather than
//! errors. String outputs clip to [`MAX_HEADER_STR`] characters and every
//! list carries a cap, so hostile headers cannot blow up the document.
//!
//! MD5 here is a fingerprint (imphash, Rich hash, VT lookups), never a
//! security control; it is implemented inline (RFC 1321) so no new
//! dependency enters the supply chain (`digest 0.10` via `md-5` would
//! duplicate the `digest 0.11` already in the graph and trip the
//! `[bans] multiple-versions` gate). `tlsh`/`ssdeep` stay out for the same
//! reason: new deps need a `deny.toml` review first.

use crate::loader::{BinaryFormat, ImportRef, LoadedBinary};

/// Per-string clip in characters: long paths and dylib names stay bounded.
pub const MAX_HEADER_STR: usize = 256;
/// Cap on reported ELF `DT_NEEDED` entries.
pub const MAX_NEEDED: usize = 128;
/// Cap on reported Mach-O dylibs.
pub const MAX_DYLIBS: usize = 128;
/// Cap on reported Mach-O load commands.
pub const MAX_COMMANDS: usize = 256;
/// Cap on reported Rich header entries.
pub const MAX_RICH_ENTRIES: usize = 256;
/// Cap on reported delay-load libraries.
pub const MAX_DELAY_LIBS: usize = 64;
/// Cap on reported functions per delay-load library.
pub const MAX_DELAY_FUNCS: usize = 512;
/// Cap on reported export forwarders.
pub const MAX_FORWARDERS: usize = 128;
/// Cap on scanned debug-directory entries.
const MAX_DEBUG_ENTRIES: usize = 64;
/// Cap on scanned resource-directory entries per level.
const MAX_RESOURCE_ENTRIES: usize = 512;
/// Cap on bytes read for one version-info blob.
const MAX_VERSION_BLOB: usize = 16384;
/// Cap on code-signature blob index entries when hunting entitlements.
const MAX_SIG_BLOBS: usize = 64;

/// Lowercase hex MD5 of `data` (RFC 1321; fingerprint use only, see above).
fn md5_hex(data: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    let (mut a0, mut b0, mut c0, mut d0): (u32, u32, u32, u32) =
        (0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476);
    for chunk in msg.as_chunks::<64>().0 {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes(chunk[4 * i..4 * i + 4].try_into().expect("chunked"));
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..16 => ((b & c) | ((!b) & d), i),
                16..32 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..48 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(sum.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = String::with_capacity(32);
    for w in [a0, b0, c0, d0] {
        for b in w.to_le_bytes() {
            out.push(char::from_digit(u32::from(b >> 4), 16).expect("hex digit"));
            out.push(char::from_digit(u32::from(b & 0x0f), 16).expect("hex digit"));
        }
    }
    out
}

/// Classic imphash over the loader's import table: lowercase
/// `library.name` pairs in table order, comma-joined, MD5-hashed.
///
/// Ordinal-only imports render as `library.N` (the loader's `#N` without
/// the `#`), matching the `library.ordinal` convention. Returns `None`
/// when there are no imports (nothing to hash).
///
/// # Example
///
/// ```
/// use binscout::headers::imphash;
/// use binscout::loader::ImportRef;
/// let imports = vec![ImportRef {
///     library: "KERNEL32.dll".to_string(),
///     name: "CreateFileA".to_string(),
///     ordinal: None,
///     unresolved: false,
///     demangled: None,
///     address: None,
/// }];
/// assert_eq!(
///     imphash(&imports).as_deref(),
///     Some("a5cac3dbd4f004df82abbe238d4eaf06")
/// );
/// ```
#[must_use]
pub fn imphash(imports: &[ImportRef]) -> Option<String> {
    if imports.is_empty() {
        return None;
    }
    let mut canonical = String::new();
    for (i, imp) in imports.iter().enumerate() {
        if i > 0 {
            canonical.push(',');
        }
        let name = imp.name.strip_prefix('#').unwrap_or(&imp.name);
        canonical.push_str(&format!(
            "{}.{}",
            imp.library.to_lowercase(),
            name.to_lowercase()
        ));
    }
    Some(md5_hex(canonical.as_bytes()))
}

/// Clip to [`MAX_HEADER_STR`] characters (never splits a boundary: counts
/// in `char`s, not bytes).
fn clip(s: &str) -> String {
    if s.chars().count() > MAX_HEADER_STR {
        s.chars().take(MAX_HEADER_STR).collect()
    } else {
        s.to_string()
    }
}

/// Lossy-decode `bytes` and clip to [`MAX_HEADER_STR`] characters.
fn lossy(bytes: &[u8]) -> String {
    clip(&String::from_utf8_lossy(bytes))
}

fn le16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .and_then(|w| w.try_into().ok())
        .map(u16::from_le_bytes)
}

fn le32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .and_then(|w| w.try_into().ok())
        .map(u32::from_le_bytes)
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .and_then(|w| w.try_into().ok())
        .map(u32::from_be_bytes)
}

/// NUL-terminated byte string at `off`, at most `max` bytes (exclusive of
/// the NUL); `None` when out of bounds or unterminated within `max`.
fn cstr_at(bytes: &[u8], off: usize, max: usize) -> Option<&[u8]> {
    let tail = bytes.get(off..)?;
    let end = tail.iter().take(max + 1).position(|&c| c == 0)?;
    if end > max {
        return None;
    }
    Some(&tail[..end])
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(*b >> 4), 16).expect("hex digit"));
        out.push(char::from_digit(u32::from(*b & 0x0f), 16).expect("hex digit"));
    }
    out
}

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` from 16 bytes.
fn guid_dashed(b: &[u8; 16]) -> String {
    let h = hex(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Map a PE RVA to file bytes through the loader's section table.
///
/// Sections carry flat virtual addresses (`IMAGE_BASE + RVA` on PE), so
/// the section RVA is `vaddr - image_base`. Returns exactly `len` covering
/// bytes, or `None` when unmapped or past the file-backed prefix
/// (zero-fill tails hold no parseable headers). A VA-shaped table
/// (`vaddr == RVA`) resolves on a second pass, so forged-but-parseable
/// layouts still resolve.
///
/// For NUL-terminated strings and blobs of unknown length use
/// [`pe_rva_tail`], which returns the bounded tail instead.
/// Exactly `len` file-backed bytes at `va` within one segment, if any.
fn seg_bytes(segments: &[crate::loader::Segment], va: u64, len: usize) -> Option<&[u8]> {
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

/// File-backed tail at `va` within one segment, if any.
fn seg_tail(segments: &[crate::loader::Segment], va: u64) -> Option<&[u8]> {
    for seg in segments {
        let Some(off) = va.checked_sub(seg.vaddr) else {
            continue;
        };
        let Ok(off) = usize::try_from(off) else {
            continue;
        };
        if let Some(tail) = seg.data.get(off..)
            && !tail.is_empty()
        {
            return Some(tail);
        }
    }
    None
}

/// Map a PE RVA to exactly `len` file bytes through the section map.
///
/// Same two-pass base probe as before (`vaddr == image_base + rva` first,
/// then a VA-shaped table); the section only bounds the range, the bytes
/// come from the segment store, so sections stay metadata-only.
fn pe_rva(bin: &LoadedBinary, image_base: u64, rva: u32, len: usize) -> Option<&[u8]> {
    let rva = u64::from(rva);
    for base in [image_base, 0] {
        for sec in &bin.sections {
            let Some(start) = sec.vaddr.checked_sub(base) else {
                continue;
            };
            if rva < start {
                continue;
            }
            let off = rva - start;
            if off.saturating_add(len as u64) > sec.file_size {
                continue;
            }
            let Some(va) = sec.vaddr.checked_add(off) else {
                continue;
            };
            if let Some(s) = seg_bytes(&bin.segments, va, len)
                && s.len() == len
            {
                return Some(s);
            }
        }
    }
    None
}

/// Map a PE RVA to at most `maxlen` file bytes from the RVA offset.
///
/// Same section map as [`pe_rva`], but for strings and blobs whose exact
/// length is unknown upfront: callers bound the tail with [`cstr_at`] or an
/// explicit length check instead of requiring the full span file-backed.
fn pe_rva_tail(bin: &LoadedBinary, image_base: u64, rva: u32, maxlen: usize) -> Option<&[u8]> {
    let rva = u64::from(rva);
    for base in [image_base, 0] {
        for sec in &bin.sections {
            let Some(start) = sec.vaddr.checked_sub(base) else {
                continue;
            };
            if rva < start {
                continue;
            }
            let off = rva - start;
            if off >= sec.file_size {
                continue;
            }
            let Some(va) = sec.vaddr.checked_add(off) else {
                continue;
            };
            if let Some(s) = seg_tail(&bin.segments, va)
                && !s.is_empty()
            {
                return Some(&s[..s.len().min(maxlen)]);
            }
        }
    }
    None
}

/// PE subsystem number to short name.
fn subsystem_name(sub: u16) -> &'static str {
    match sub {
        0 => "UNKNOWN",
        1 => "NATIVE",
        2 => "WINDOWS_GUI",
        3 => "WINDOWS_CUI",
        5 => "OS2_CUI",
        7 => "POSIX_CUI",
        8 => "NATIVE_WINDOWS",
        9 => "WINDOWS_CE_GUI",
        10 => "EFI_APPLICATION",
        11 => "EFI_BOOT_SERVICE_DRIVER",
        12 => "EFI_RUNTIME_DRIVER",
        13 => "EFI_ROM",
        14 => "XBOX",
        16 => "WINDOWS_BOOT_APPLICATION",
        17 => "XBOX_CODE_CATALOG",
        _ => "UNKNOWN",
    }
}

/// Parse the export directory for forwarder entries (`name -> target`).
///
/// A function RVA landing inside the export directory itself is a
/// forwarder string, not code. Returns at most [`MAX_FORWARDERS`] rows.
fn pe_forwarders(
    bin: &LoadedBinary,
    image_base: u64,
    dir_rva: u32,
    dir_size: u32,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let Some(dir) = pe_rva(bin, image_base, dir_rva, 40) else {
        return out;
    };
    let num_names = le32(dir, 24).unwrap_or(0).min(4096);
    let (Some(addr_funcs), Some(addr_names), Some(addr_ord)) =
        (le32(dir, 28), le32(dir, 32), le32(dir, 36))
    else {
        return out;
    };
    for i in 0..num_names {
        if out.len() >= MAX_FORWARDERS {
            break;
        }
        let (Some(nr_off), Some(or_off)) =
            (addr_names.checked_add(4 * i), addr_ord.checked_add(2 * i))
        else {
            continue;
        };
        let (Some(name_rva), Some(ord_idx)) = (
            pe_rva(bin, image_base, nr_off, 4).and_then(|s| le32(s, 0)),
            pe_rva(bin, image_base, or_off, 2).and_then(|s| le16(s, 0)),
        ) else {
            continue;
        };
        let Some(fr_off) = addr_funcs.checked_add(4 * u32::from(ord_idx)) else {
            continue;
        };
        let Some(func_rva) = pe_rva(bin, image_base, fr_off, 4).and_then(|s| le32(s, 0)) else {
            continue;
        };
        if func_rva < dir_rva || func_rva.wrapping_sub(dir_rva) >= dir_size {
            continue;
        }
        let (Some(name), Some(fwd)) = (
            pe_rva_tail(bin, image_base, name_rva, MAX_HEADER_STR + 1)
                .and_then(|s| cstr_at(s, 0, MAX_HEADER_STR))
                .map(lossy),
            pe_rva_tail(bin, image_base, func_rva, MAX_HEADER_STR + 1)
                .and_then(|s| cstr_at(s, 0, MAX_HEADER_STR))
                .map(lossy),
        ) else {
            continue;
        };
        out.push(serde_json::json!({"name": name, "forward": fwd}));
    }
    out
}

/// Parse the CodeView RSDS record behind debug-directory entry `i`.
fn pe_pdb(bin: &LoadedBinary, image_base: u64, entry: &[u8]) -> Option<serde_json::Value> {
    if entry.len() < 28 || le32(entry, 12).unwrap_or(0) != 2 {
        return None;
    }
    let size = le32(entry, 16).unwrap_or(0).min(4096) as usize;
    let rva = le32(entry, 20).unwrap_or(0);
    if size < 25 {
        return None;
    }
    let raw = pe_rva_tail(bin, image_base, rva, size)?;
    if raw.len() < 25 {
        return None;
    }
    if raw.get(..4) != Some(b"RSDS".as_slice()) {
        return None;
    }
    let guid: &[u8; 16] = raw.get(4..20)?.try_into().ok()?;
    let age = le32(raw, 20)?;
    let path = cstr_at(raw, 24, MAX_HEADER_STR).map(lossy)?;
    Some(serde_json::json!({
        "path": path,
        "guid": guid_dashed(guid),
        "age": age,
    }))
}

/// Hunt an `RT_VERSION` resource for `VS_FIXEDFILEINFO`'s file version.
///
/// Walks three resource-directory levels (type 16 -> name/id -> language)
/// and parses the fixed info behind the first data entry. Returns
/// `(present, version)`: `present` is true when the version resource
/// exists even if the fixed info fails to parse.
fn pe_version_info(bin: &LoadedBinary, image_base: u64, dir_rva: u32) -> (bool, Option<String>) {
    let dir_at = |rva: u32| pe_rva(bin, image_base, rva, 16);
    let entry_at = |rva: u32, idx: u32| {
        pe_rva(bin, image_base, rva, 16 + 8 * (idx as usize + 1))
            .and_then(|d| d.get(16 + 8 * idx as usize..16 + 8 * idx as usize + 8))
    };
    let Some(dir) = dir_at(dir_rva) else {
        return (false, None);
    };
    let named = le16(dir, 12).unwrap_or(0) as u32;
    let ids = le16(dir, 14).unwrap_or(0) as u32;
    let total = named.saturating_add(ids).min(MAX_RESOURCE_ENTRIES as u32);
    let mut type_off = None;
    for i in 0..total {
        let Some(e) = entry_at(dir_rva, i) else {
            continue;
        };
        if le32(e, 0).unwrap_or(0) == 16 {
            type_off = Some(le32(e, 4).unwrap_or(0));
            break;
        }
    }
    let Some(type_off) = type_off else {
        return (false, None);
    };
    if type_off & 0x8000_0000 == 0 {
        return (true, None);
    }
    let sub_rva = dir_rva.wrapping_add(type_off & 0x7fff_ffff);
    let Some(sub) = dir_at(sub_rva) else {
        return (true, None);
    };
    let sub_total = (le16(sub, 12).unwrap_or(0) as u32)
        .saturating_add(le16(sub, 14).unwrap_or(0) as u32)
        .min(MAX_RESOURCE_ENTRIES as u32)
        .max(1);
    let Some(e0) = entry_at(sub_rva, 0).filter(|_| sub_total >= 1) else {
        return (true, None);
    };
    let lang_off = le32(e0, 4).unwrap_or(0);
    // Subdirectory offsets are relative to the resource base, like every
    // other level: a data offset (high bit clear) already is one.
    let lang_rva = if lang_off & 0x8000_0000 != 0 {
        let lang_dir = dir_rva.wrapping_add(lang_off & 0x7fff_ffff);
        let Some(le0) = entry_at(lang_dir, 0) else {
            return (true, None);
        };
        let data_off = le32(le0, 4).unwrap_or(0);
        if data_off & 0x8000_0000 != 0 {
            return (true, None);
        }
        dir_rva.wrapping_add(data_off)
    } else {
        dir_rva.wrapping_add(lang_off)
    };
    let Some(de) = pe_rva(bin, image_base, lang_rva, 16) else {
        return (true, None);
    };
    let data_rva = le32(de, 0).unwrap_or(0);
    let data_size = le32(de, 4).unwrap_or(0).min(MAX_VERSION_BLOB as u32) as usize;
    let Some(blob) = pe_rva_tail(bin, image_base, data_rva, data_size.min(256)) else {
        return (true, None);
    };
    // `VS_VERSION_INFO`: wLength, wValueLength, wType, UTF-16 key, pad to
    // 32 bits, then `VS_FIXEDFILEINFO`.
    const KEY: &[u8] = b"V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0\0\0";
    if blob.len() < 6 + KEY.len() || &blob[6..6 + KEY.len()] != KEY {
        return (true, None);
    }
    let mut fixed = 6 + KEY.len();
    fixed += (4 - fixed % 4) % 4;
    let Some(f) = blob.get(fixed..fixed + 52) else {
        return (true, None);
    };
    let get = |o: usize| u32::from_le_bytes(f[o..o + 4].try_into().expect("sliced"));
    if get(0) != 0xFEEF_04BD {
        return (true, None);
    }
    let (ms, ls) = (get(10 * 4 - 32), get(11 * 4 - 32));
    let version = format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff);
    (true, Some(version))
}

/// Delay-load imports via `object`: library plus bounded function names.
fn pe_delay_load(bytes: &[u8]) -> Vec<serde_json::Value> {
    use object::read::pe::{PeFile32, PeFile64};
    fn libs<Pe>(pe: &object::read::pe::PeFile<'_, Pe>) -> Vec<serde_json::Value>
    where
        Pe: object::read::pe::ImageNtHeaders,
    {
        use object::LittleEndian as LE;
        let mut out = Vec::new();
        let Ok(Some(table)) = pe.delay_load_import_table() else {
            return out;
        };
        let Ok(mut descs) = table.descriptors() else {
            return out;
        };
        while let Ok(Some(d)) = descs.next() {
            if out.len() >= MAX_DELAY_LIBS {
                break;
            }
            let library = table
                .name(d.dll_name_rva.get(LE))
                .map(lossy)
                .unwrap_or_else(|_| "<invalid>".to_string());
            let mut functions = Vec::new();
            if let Ok(mut thunks) = table.thunks(d.import_name_table_rva.get(LE)) {
                while let Ok(Some(t)) = thunks.next::<Pe>() {
                    if functions.len() >= MAX_DELAY_FUNCS {
                        break;
                    }
                    match table.import::<Pe>(t) {
                        Ok(object::read::pe::Import::Ordinal(o)) => {
                            functions.push(serde_json::Value::String(format!("#{o}")));
                        }
                        Ok(object::read::pe::Import::Name(_, n)) => {
                            functions.push(serde_json::Value::String(lossy(n)));
                        }
                        Err(_) => {}
                    }
                }
            }
            let count = functions.len();
            out.push(serde_json::json!({
                "library": library,
                "functions": functions,
                "count": count,
            }));
        }
        out
    }
    match object::FileKind::parse(bytes) {
        Ok(object::FileKind::Pe32) => PeFile32::parse(bytes)
            .map(|pe| libs(&pe))
            .unwrap_or_default(),
        Ok(object::FileKind::Pe64) => PeFile64::parse(bytes)
            .map(|pe| libs(&pe))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Parsed PE header fields shared by the 32- and 64-bit branches below:
///
/// timestamp, subsystem, DLL characteristics, image base, the
/// export/security/debug/resource data directories, and the Rich header.
type PeFieldSet<'a> = (
    u32,
    u16,
    u16,
    u64,
    Option<(u32, u32)>,
    Option<(u32, u32)>,
    Option<(u32, u32)>,
    Option<(u32, u32)>,
    Option<object::read::pe::RichHeaderInfo<'a>>,
);

/// Full PE triage object, or `null` when the bytes are not a PE.
fn pe_headers(bytes: &[u8], loaded: &LoadedBinary) -> Option<serde_json::Value> {
    use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile32, PeFile64};
    use object::{FileKind, LittleEndian as LE};
    enum Pe<'a> {
        P32(PeFile32<'a>),
        P64(PeFile64<'a>),
    }
    let pe = match FileKind::parse(bytes) {
        Ok(FileKind::Pe32) => PeFile32::parse(bytes).ok().map(Pe::P32),
        Ok(FileKind::Pe64) => PeFile64::parse(bytes).ok().map(Pe::P64),
        _ => None,
    }?;
    // Borrow the parsed headers once per variant.
    macro_rules! fields {
        ($p:expr) => {{
            let fh = $p.nt_headers().file_header();
            let oh = $p.nt_headers().optional_header();
            (
                fh.time_date_stamp.get(LE),
                oh.subsystem().0,
                oh.dll_characteristics().0,
                oh.image_base(),
                $p.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_EXPORT as usize)
                    .map(|d| (d.virtual_address.get(LE), d.size.get(LE))),
                $p.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_SECURITY as usize)
                    .map(|d| (d.virtual_address.get(LE), d.size.get(LE))),
                $p.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_DEBUG as usize)
                    .map(|d| (d.virtual_address.get(LE), d.size.get(LE))),
                $p.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE as usize)
                    .map(|d| (d.virtual_address.get(LE), d.size.get(LE))),
                $p.rich_header_info(),
            )
        }};
    }
    let (
        timestamp,
        subsystem,
        dll,
        image_base,
        export_dir,
        security_dir,
        debug_dir,
        resource_dir,
        rich,
    ): PeFieldSet<'_> = match &pe {
        Pe::P32(p) => fields!(p),
        Pe::P64(p) => fields!(p),
    };
    let rich_json = match rich {
        None => serde_json::json!({"present": false}),
        Some(info) => {
            let mut entries = Vec::new();
            let mut raw = Vec::new();
            for e in info.unmasked_entries().take(MAX_RICH_ENTRIES + 1) {
                if entries.len() >= MAX_RICH_ENTRIES {
                    break;
                }
                raw.extend_from_slice(&e.comp_id.to_le_bytes());
                raw.extend_from_slice(&e.count.to_le_bytes());
                entries.push(serde_json::json!({"comp_id": e.comp_id, "count": e.count}));
            }
            serde_json::json!({
                "present": true,
                "entries": entries,
                "md5": md5_hex(&raw),
            })
        }
    };
    let (auth_present, auth_size) = match security_dir {
        Some((_, s)) if s != 0 => (true, s),
        _ => (false, 0),
    };
    let pdb = debug_dir.and_then(|(rva, size)| {
        let count = (size / 28).min(MAX_DEBUG_ENTRIES as u32);
        (0..count).find_map(|i| {
            pe_rva(loaded, image_base, rva + 28 * i, 28).and_then(|e| pe_pdb(loaded, image_base, e))
        })
    });
    let (ver_present, ver_version) = resource_dir
        .map(|(rva, _)| pe_version_info(loaded, image_base, rva))
        .unwrap_or((false, None));
    let forwarders = export_dir
        .map(|(rva, size)| pe_forwarders(loaded, image_base, rva, size))
        .unwrap_or_default();
    Some(serde_json::json!({
        "timestamp": timestamp,
        "subsystem": subsystem,
        "subsystem_name": subsystem_name(subsystem),
        "dll_characteristics": dll,
        "aslr": dll & 0x0040 != 0,
        "dep": dll & 0x0100 != 0,
        "cfg": dll & 0x4000 != 0,
        "high_entropy_va": dll & 0x0020 != 0,
        "rich": rich_json,
        "imphash": imphash(&loaded.imports),
        "authenticode": {"present": auth_present, "size": auth_size},
        "pdb": pdb,
        "version_info": {"present": ver_present, "file_version": ver_version},
        "delay_load": pe_delay_load(bytes),
        "export_forwarders": forwarders,
    }))
}

/// ELF triage object, or `None` when the bytes are not an ELF.
fn elf_headers(bytes: &[u8]) -> Option<serde_json::Value> {
    if bytes.get(..4) != Some(b"\x7fELF".as_slice()) {
        return None;
    }
    let class64 = match bytes.get(4) {
        Some(1) => false,
        Some(2) => true,
        _ => return None,
    };
    let le = match bytes.get(5) {
        Some(1) => true,
        Some(2) => false,
        _ => return None,
    };
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
        if class64 {
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
    let e_type = u16at(16)?;
    let (phoff, phentsize, phnum, shoff, shentsize, shnum, shstrndx) = if class64 {
        (
            u64at(32)?,
            u16at(54)? as usize,
            u16at(56)? as usize,
            u64at(40)?,
            u16at(58)? as usize,
            u16at(60)? as usize,
            u16at(62)? as usize,
        )
    } else {
        (
            u64::from(u32at(28)?),
            u16at(42)? as usize,
            u16at(44)? as usize,
            u64::from(u32at(32)?),
            u16at(46)? as usize,
            u16at(48)? as usize,
            u16at(50)? as usize,
        )
    };
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const PT_NOTE: u32 = 4;
    const PT_GNU_RELRO: u32 = 0x6474_e552;
    const PT_GNU_STACK: u32 = 0x6474_e551;
    let phsize = if class64 { 56 } else { 32 };
    if phentsize < phsize || phnum > 256 {
        return None;
    }
    // (p_type, p_flags, p_offset, p_vaddr, p_filesz)
    let mut loads: Vec<(u64, u64, u64)> = Vec::new();
    let mut interp: Option<String> = None;
    let mut dynamic: Option<(u64, u64)> = None;
    let mut notes: Vec<(u64, u64)> = Vec::new();
    let mut relro = false;
    let mut stack: Option<u32> = None;
    for i in 0..phnum {
        let base = phoff.checked_add((i * phentsize) as u64)? as usize;
        if base.checked_add(phentsize)? > bytes.len() {
            return None;
        }
        let (t, flags, off, va, filesz) = if class64 {
            (
                u32at(base)?,
                u32at(base + 4)?,
                u64at(base + 8)?,
                u64at(base + 16)?,
                u64at(base + 32)?,
            )
        } else {
            (
                u32at(base)?,
                u32at(base + 24)?,
                u64::from(u32at(base + 4)?),
                u64::from(u32at(base + 8)?),
                u64::from(u32at(base + 16)?),
            )
        };
        match t {
            PT_LOAD => loads.push((va, off, filesz)),
            PT_INTERP => {
                let end = off.checked_add(filesz)? as usize;
                if filesz as usize > MAX_HEADER_STR + 1 || end > bytes.len() {
                    continue;
                }
                interp = cstr_at(bytes, off as usize, MAX_HEADER_STR).map(lossy);
            }
            PT_DYNAMIC => dynamic = Some((off, filesz)),
            PT_NOTE => notes.push((off, filesz)),
            PT_GNU_RELRO => relro = true,
            PT_GNU_STACK => stack = Some(flags),
            _ => {}
        }
    }
    let va_to_off = |va: u64| -> Option<usize> {
        loads.iter().find_map(|&(v, o, s)| {
            if va >= v && va.checked_sub(v)?.checked_add(1)? <= s {
                o.checked_add(va - v).and_then(|f| usize::try_from(f).ok())
            } else {
                None
            }
        })
    };
    // Dynamic tags.
    let mut needed: Vec<String> = Vec::new();
    let mut strtab: Option<(u64, u64)> = None;
    let mut runpath: Option<String> = None;
    let mut rpath: Option<String> = None;
    let mut bind_now = false;
    if let Some((doff, dsize)) = dynamic {
        let entry = if class64 { 16 } else { 8 };
        if dsize <= 16 * 1024 * 1024 && doff as usize <= bytes.len() {
            let count = (dsize as usize / entry).min(1024);
            let mut needed_offs = Vec::new();
            let mut runpath_off = None;
            let mut rpath_off = None;
            for i in 0..count {
                let base = doff as usize + i * entry;
                if base + entry > bytes.len() {
                    break;
                }
                let (tag, val) = if class64 {
                    let t = bytes.get(base..base + 8)?;
                    let v = bytes.get(base + 8..base + 16)?;
                    let tt = if le {
                        i64::from_le_bytes(t.try_into().ok()?)
                    } else {
                        i64::from_be_bytes(t.try_into().ok()?)
                    };
                    let vv = if le {
                        u64::from_le_bytes(v.try_into().ok()?)
                    } else {
                        u64::from_be_bytes(v.try_into().ok()?)
                    };
                    (tt, vv)
                } else {
                    (i64::from(u32at(base)?), u64::from(u32at(base + 4)?))
                };
                match tag {
                    0 => break,
                    1 => needed_offs.push(val),
                    5 => {
                        strtab = Some((val, strtab.map(|s| s.1).unwrap_or(0)));
                    }
                    10 => {
                        strtab = Some((strtab.map(|s| s.0).unwrap_or(0), val));
                    }
                    15 => rpath_off = Some(val),
                    29 => runpath_off = Some(val),
                    30 => bind_now |= val & 0x8 != 0,
                    0x6fff_fffb => bind_now |= val & 0x1 != 0,
                    _ => {}
                }
            }
            if let Some((sva, ssz)) = strtab
                && ssz <= 4 * 1024 * 1024
                && let Some(soff) = va_to_off(sva)
            {
                let strtab_end = soff.checked_add(ssz as usize)?;
                for o in needed_offs {
                    if needed.len() >= MAX_NEEDED {
                        break;
                    }
                    let at = soff.checked_add(o as usize)?;
                    if at >= strtab_end || at >= bytes.len() {
                        continue;
                    }
                    if let Some(s) = cstr_at(bytes, at, MAX_HEADER_STR) {
                        needed.push(lossy(s));
                    }
                }
                let pick = |o: u64| -> Option<String> {
                    let at = soff.checked_add(o as usize)?;
                    if at >= strtab_end || at >= bytes.len() {
                        return None;
                    }
                    cstr_at(bytes, at, MAX_HEADER_STR).map(lossy)
                };
                runpath = runpath_off.and_then(pick);
                rpath = rpath_off.and_then(pick);
            }
        }
    }
    // Build-ID from PT_NOTE segments (`GNU\0`, type 3).
    let mut build_id: Option<String> = None;
    for (off, size) in notes {
        if build_id.is_some() || size > 1024 * 1024 {
            continue;
        }
        let mut at = off as usize;
        let end = at.checked_add(size as usize).filter(|&e| e <= bytes.len());
        let Some(end) = end else { continue };
        while at + 12 <= end {
            let (Some(ns), Some(ds), Some(ty)) = (u32at(at), u32at(at + 4), u32at(at + 8)) else {
                break;
            };
            if ns > 1024 || ds > 1024 * 1024 {
                break;
            }
            let name_at = at + 12;
            let name_end = name_at + ns.next_multiple_of(4) as usize;
            let desc_end = name_end + ds as usize;
            if desc_end > end {
                break;
            }
            if ns == 4 && ty == 3 && bytes.get(name_at..name_at + 4) == Some(b"GNU\0".as_slice()) {
                build_id = Some(hex(&bytes[name_end..desc_end.min(name_end + 64)]));
                break;
            }
            at = desc_end;
        }
    }
    // Stripped: no `.symtab` section.
    let mut stripped = true;
    if shoff != 0 && shnum != 0 && shnum <= 4096 && shentsize >= if class64 { 64 } else { 40 } {
        let shsize = if class64 { 64 } else { 40 };
        let shstr = shstrndx < shnum;
        let strtab_sec = if shstr {
            let base = shoff as usize + shstrndx * shentsize;
            let (off, size) = if class64 {
                (u64at(base + 24)? as usize, u64at(base + 32)? as usize)
            } else {
                (u32at(base + 16)? as usize, u32at(base + 20)? as usize)
            };
            bytes.get(off..off + size.min(1024 * 1024))
        } else {
            None
        };
        if let Some(strsec) = strtab_sec {
            for i in 0..shnum {
                let base = shoff as usize + i * shentsize;
                if base + shsize > bytes.len() {
                    break;
                }
                let name_off = u32at(base)? as usize;
                if name_off < strsec.len()
                    && let Some(n) = cstr_at(strsec, name_off, 32)
                    && n == b".symtab"
                {
                    stripped = false;
                    break;
                }
            }
        }
    }
    let relro_state = if relro {
        if bind_now { "full" } else { "partial" }
    } else {
        "none"
    };
    Some(serde_json::json!({
        "interp": interp,
        "needed": needed,
        "runpath": runpath,
        "rpath": rpath,
        "relro": relro_state,
        "nx": stack.is_some_and(|f| f & 1 == 0),
        "pie": e_type == 3 && interp.is_some(),
        "build_id": build_id,
        "stripped": stripped,
    }))
}

/// Mach-O load-command number to name.
fn macho_command_name(cmd: u32) -> String {
    const REQ: u32 = 0x8000_0000;
    match cmd {
        0x1 => "LC_SEGMENT".to_string(),
        0x2 => "LC_SYMTAB".to_string(),
        0x3 => "LC_SYMSEG".to_string(),
        0x4 => "LC_THREAD".to_string(),
        0x5 => "LC_UNIXTHREAD".to_string(),
        0x6 => "LC_LOADFVMLIB".to_string(),
        0x7 => "LC_IDFVMLIB".to_string(),
        0x8 => "LC_IDENT".to_string(),
        0x9 => "LC_FVMFILE".to_string(),
        0xa => "LC_PREPAGE".to_string(),
        0xb => "LC_DYSYMTAB".to_string(),
        0xc => "LC_LOAD_DYLIB".to_string(),
        0xd => "LC_ID_DYLIB".to_string(),
        0xe => "LC_LOAD_DYLINKER".to_string(),
        0xf => "LC_ID_DYLINKER".to_string(),
        0x10 => "LC_PREBOUND_DYLIB".to_string(),
        0x11 => "LC_ROUTINES".to_string(),
        0x12 => "LC_SUB_FRAMEWORK".to_string(),
        0x13 => "LC_SUB_UMBRELLA".to_string(),
        0x14 => "LC_SUB_CLIENT".to_string(),
        0x15 => "LC_SUB_LIBRARY".to_string(),
        0x16 => "LC_TWOLEVEL_HINTS".to_string(),
        0x17 => "LC_PREBIND_CKSUM".to_string(),
        0x18 => "LC_LOAD_WEAK_DYLIB".to_string(),
        0x19 => "LC_SEGMENT_64".to_string(),
        0x1a => "LC_ROUTINES_64".to_string(),
        0x1b => "LC_UUID".to_string(),
        0x1c => "LC_RPATH".to_string(),
        0x1d => "LC_CODE_SIGNATURE".to_string(),
        0x1e => "LC_SEGMENT_SPLIT_INFO".to_string(),
        0x1f => "LC_REEXPORT_DYLIB".to_string(),
        0x20 => "LC_DYLIB_CODE_SIGN_DRS".to_string(),
        0x21 => "LC_ENCRYPTION_INFO".to_string(),
        0x22 => "LC_DYLD_INFO".to_string(),
        0x24 => "LC_VERSION_MIN_MACOSX".to_string(),
        0x25 => "LC_VERSION_MIN_IPHONEOS".to_string(),
        0x26 => "LC_FUNCTION_STARTS".to_string(),
        0x27 => "LC_DYLD_ENVIRONMENT".to_string(),
        0x29 => "LC_DATA_IN_CODE".to_string(),
        0x2a => "LC_SOURCE_VERSION".to_string(),
        0x2b => "LC_DYLIB_CODE_SIGN_DRS".to_string(),
        0x2c => "LC_ENCRYPTION_INFO_64".to_string(),
        0x2d => "LC_LINKER_OPTION".to_string(),
        0x2e => "LC_LINKER_OPTIMIZATION_HINT".to_string(),
        0x2f => "LC_VERSION_MIN_TVOS".to_string(),
        0x30 => "LC_VERSION_MIN_WATCHOS".to_string(),
        0x31 => "LC_NOTE".to_string(),
        0x32 => "LC_BUILD_VERSION".to_string(),
        c if c == 0x22 | REQ => "LC_DYLD_INFO_ONLY".to_string(),
        c if c == 0x23 | REQ => "LC_LOAD_UPWARD_DYLIB".to_string(),
        c if c == 0x28 | REQ => "LC_MAIN".to_string(),
        c if c == 0x33 | REQ => "LC_DYLD_EXPORTS_TRIE".to_string(),
        c if c == 0x34 | REQ => "LC_DYLD_CHAINED_FIXUPS".to_string(),
        c if c == 0x35 | REQ => "LC_FILESET_ENTRY".to_string(),
        _ => format!("UNKNOWN({cmd:#x})"),
    }
}

fn macho_platform_name(p: u32) -> String {
    match p {
        1 => "macos".to_string(),
        2 => "ios".to_string(),
        3 => "tvos".to_string(),
        4 => "watchos".to_string(),
        5 => "bridgeos".to_string(),
        6 => "macCatalyst".to_string(),
        7 => "iossimulator".to_string(),
        8 => "tvossimulator".to_string(),
        9 => "watchossimulator".to_string(),
        10 => "driverkit".to_string(),
        _ => format!("platform{p}"),
    }
}

fn macho_version(v: u32) -> String {
    let (maj, min, patch) = (v >> 16, (v >> 8) & 0xff, v & 0xff);
    if patch == 0 {
        format!("{maj}.{min}")
    } else {
        format!("{maj}.{min}.{patch}")
    }
}

/// Map a fat-slice CPU type to the disassembler arch.
fn fat_arch_matches(cputype: u32, arch: crate::disasm::Arch) -> bool {
    use crate::disasm::Arch as A;
    matches!(
        (cputype, arch),
        (0x0100_0007, A::X86_64) | (7, A::X86_32) | (0x0100_000c, A::Aarch64) | (12, A::Arm32)
    )
}

/// Select the fat slice matching `arch`, or `None` on any doubt.
fn fat_slice_for(bytes: &[u8], arch: crate::disasm::Arch) -> Option<&[u8]> {
    let wide = bytes.get(..4) == Some([0xCA, 0xFE, 0xBA, 0xBF].as_slice());
    if !wide && bytes.get(..4) != Some([0xCA, 0xFE, 0xBA, 0xBE].as_slice()) {
        return None;
    }
    let be64 = |off: usize| -> Option<u64> {
        let (hi, lo) = (be32(bytes, off)?, be32(bytes, off + 4)?);
        Some((u64::from(hi) << 32) | u64::from(lo))
    };
    let n = be32(bytes, 4)? as usize;
    if n == 0 || n > 256 {
        return None;
    }
    let entry = if wide { 32 } else { 20 };
    for i in 0..n {
        let base = 8 + i * entry;
        if base + entry > bytes.len() {
            return None;
        }
        let cputype = be32(bytes, base)?;
        if !fat_arch_matches(cputype, arch) {
            continue;
        }
        let (off, size) = if wide {
            (be64(base + 8)?, be64(base + 16)?)
        } else {
            (
                u64::from(be32(bytes, base + 8)?),
                u64::from(be32(bytes, base + 12)?),
            )
        };
        let end = off.checked_add(size)?;
        if size == 0 || size > crate::loader::MAX_INPUT_BYTES {
            return None;
        }
        return bytes
            .get(off as usize..end as usize)
            .filter(|s| !s.is_empty());
    }
    None
}

/// Mach-O triage object, or `None` when the bytes hold no thin image.
fn macho_headers(bytes: &[u8], arch: crate::disasm::Arch) -> Option<serde_json::Value> {
    // A fat container under a slice open still carries the container bytes:
    // select the slice matching the loaded arch first.
    let thin: &[u8] = fat_slice_for(bytes, arch).unwrap_or(bytes);
    let (is64, le) = match thin.get(..4) {
        Some([0xCE, 0xFA, 0xED, 0xFE]) => (false, true),
        Some([0xCF, 0xFA, 0xED, 0xFE]) => (true, true),
        Some([0xFE, 0xED, 0xFA, 0xCE]) => (false, false),
        Some([0xFE, 0xED, 0xFA, 0xCF]) => (true, false),
        _ => return None,
    };
    let u32at = |off: usize| -> Option<u32> {
        let w: [u8; 4] = thin.get(off..off + 4)?.try_into().ok()?;
        Some(if le {
            u32::from_le_bytes(w)
        } else {
            u32::from_be_bytes(w)
        })
    };
    let ncmds = u32at(16)? as usize;
    if ncmds > 4096 {
        return None;
    }
    let mut at = if is64 { 32 } else { 28 };
    let mut commands = Vec::new();
    let mut dylibs = Vec::new();
    let mut uuid = None;
    let mut min_os = None;
    let mut sdk = None;
    let mut platform = None;
    let mut codesig = None;
    for _ in 0..ncmds {
        if at + 8 > thin.len() {
            return None;
        }
        let (cmd, size) = (u32at(at)?, u32at(at + 4)? as usize);
        if size < 8 || at.checked_add(size)? > thin.len() || commands.len() >= MAX_COMMANDS {
            return None;
        }
        commands.push(macho_command_name(cmd));
        match cmd {
            0x0c | 0x18 | 0x1f | 0x20 | 0x8000_0023 => {
                if dylibs.len() < MAX_DYLIBS
                    && let Some(off) = u32at(at + 8)
                    && (off as usize) < size
                    && let Some(name) = cstr_at(
                        thin,
                        at + off as usize,
                        MAX_HEADER_STR.min(size - off as usize),
                    )
                {
                    dylibs.push(serde_json::Value::String(lossy(name)));
                }
            }
            0x1b => {
                if let Some(id) = thin.get(at + 8..at + 24) {
                    let h = hex(id);
                    uuid = Some(format!(
                        "{}-{}-{}-{}-{}",
                        &h[0..8],
                        &h[8..12],
                        &h[12..16],
                        &h[16..20],
                        &h[20..32]
                    ));
                }
            }
            0x32 => {
                if let (Some(p), Some(m), Some(s)) = (u32at(at + 8), u32at(at + 12), u32at(at + 16))
                {
                    platform = Some(macho_platform_name(p));
                    min_os = Some(macho_version(m));
                    sdk = Some(macho_version(s));
                }
            }
            0x24 | 0x25 | 0x2f | 0x30 => {
                if platform.is_none()
                    && let (Some(m), Some(s)) = (u32at(at + 8), u32at(at + 12))
                {
                    platform = Some(
                        match cmd {
                            0x24 => "macos",
                            0x25 => "ios",
                            0x2f => "tvos",
                            _ => "watchos",
                        }
                        .to_string(),
                    );
                    min_os = Some(macho_version(m));
                    sdk = Some(macho_version(s));
                }
            }
            0x1d => {
                if let (Some(o), Some(s)) = (u32at(at + 8), u32at(at + 12)) {
                    codesig = Some((o as usize, s as usize));
                }
            }
            _ => {}
        }
        at += size;
    }
    let (sig_present, sig_size) = match codesig {
        Some((_, s)) if s != 0 => (true, s),
        _ => (false, 0),
    };
    // Entitlements: `CSMAGIC_EMBEDDED_SIGNATURE` superblob, slot 5.
    // Layout: magic, length, count, then `count` (type, offset) index
    // entries; blob offsets are relative to the superblob start.
    let mut entitlements = serde_json::json!({"present": false, "size": 0});
    if let Some((off, _)) = codesig
        && thin.get(off..off + 12).is_some()
        && be32(thin, off) == Some(0xfade_0cc0)
        && let Some(count) = be32(thin, off + 8)
        && count as usize <= MAX_SIG_BLOBS
    {
        for i in 0..count {
            let base = off + 12 + 8 * i as usize;
            if base + 8 > thin.len() {
                break;
            }
            let (Some(ty), Some(bo)) = (be32(thin, base), be32(thin, base + 4)) else {
                break;
            };
            if ty != 5 {
                continue;
            }
            let blob = off + bo as usize;
            if thin.get(blob..blob + 8).is_some()
                && be32(thin, blob) == Some(0xfade_7171)
                && let Some(len) = be32(thin, blob + 4)
                && len >= 8
            {
                entitlements = serde_json::json!({"present": true, "size": len});
            }
            break;
        }
    }
    Some(serde_json::json!({
        "commands": commands,
        "dylibs": dylibs,
        "platform": platform,
        "min_os": min_os,
        "sdk": sdk,
        "code_signature": {"present": sig_present, "size": sig_size},
        "entitlements": entitlements,
        "uuid": uuid,
    }))
}

/// Detect the container format of `bytes` for the `format` field.
///
/// Falls back to the loader's format when the bytes carry no recognized
/// magic (explicit-raw opens of arbitrary blobs).
fn detect_format(bytes: &[u8], loaded: &LoadedBinary) -> &'static str {
    if crate::loader::le::is_le(bytes) {
        return "le";
    }
    match object::FileKind::parse(bytes) {
        Ok(object::FileKind::Elf32) | Ok(object::FileKind::Elf64) => "elf",
        Ok(object::FileKind::Pe32) | Ok(object::FileKind::Pe64) => "pe",
        Ok(object::FileKind::MachO32)
        | Ok(object::FileKind::MachO64)
        | Ok(object::FileKind::MachOFat32)
        | Ok(object::FileKind::MachOFat64) => "macho",
        Ok(object::FileKind::Coff) => "coff",
        _ => match loaded.format {
            BinaryFormat::Elf => "elf",
            BinaryFormat::Pe => "pe",
            BinaryFormat::MachO => "macho",
            BinaryFormat::Coff => "coff",
            BinaryFormat::Le => "le",
            BinaryFormat::Raw => "raw",
        },
    }
}

/// On-demand header metadata plus file hashes as one JSON value.
///
/// Parses `bytes` (the analyzed file's contents) with `loaded` supplying
/// the section map and import table; `sha256` is the project's content
/// identity. Format-specific objects are `null` for other formats; unknown
/// fields degrade to `null`/empty rather than erroring. Reads nothing
/// beyond `bytes` and writes nothing anywhere.
///
/// JSON shape (`protocol` follows [`crate::WIRE_PROTOCOL`]; additive-only,
/// so the wire revision is unchanged):
///
/// ```json
/// {"format": "pe", "size": 0, "sha256": "…", "md5": "…",
///  "pe": {"timestamp": 0, "subsystem": 3, "subsystem_name": "WINDOWS_CUI",
///   "dll_characteristics": 0, "aslr": false, "dep": false,
///   "cfg": false, "high_entropy_va": false,
///   "rich": {"present": false}, "imphash": null,
///   "authenticode": {"present": false, "size": 0}, "pdb": null,
///   "version_info": {"present": false, "file_version": null},
///   "delay_load": [], "export_forwarders": []},
///  "elf": null, "macho": null}
/// ```
#[must_use]
pub fn headers_of(bytes: &[u8], loaded: &LoadedBinary, sha256: &str) -> serde_json::Value {
    let format = detect_format(bytes, loaded);
    let (pe, elf, macho) = match format {
        "pe" => (pe_headers(bytes, loaded), None, None),
        "elf" => (None, elf_headers(bytes), None),
        "macho" => (None, None, macho_headers(bytes, loaded.arch)),
        _ => (None, None, None),
    };
    serde_json::json!({
        "protocol": crate::WIRE_PROTOCOL,
        "format": format,
        "size": bytes.len() as u64,
        "sha256": sha256,
        "md5": md5_hex(bytes),
        "pe": pe,
        "elf": elf,
        "macho": macho,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_vectors_match_rfc1321() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(b"message digest"),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            md5_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            md5_hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
        assert_eq!(
            md5_hex(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn imphash_is_empty_aware_and_ordinal_stripped() {
        assert_eq!(imphash(&[]), None);
        let named = ImportRef {
            library: "KERNEL32.dll".to_string(),
            name: "CreateFileA".to_string(),
            ordinal: None,
            unresolved: false,
            demangled: None,
            address: None,
        };
        let ordinal = ImportRef {
            library: "TESTDLL.dll".to_string(),
            name: "#1".to_string(),
            ordinal: Some(1),
            unresolved: true,
            demangled: None,
            address: None,
        };
        let h = imphash(&[named, ordinal]).expect("hash");
        assert_eq!(h.len(), 32);
        assert_eq!(h, md5_hex(b"kernel32.dll.createfilea,testdll.dll.1"));
    }

    #[test]
    fn subsystem_names_cover_common_values() {
        assert_eq!(subsystem_name(2), "WINDOWS_GUI");
        assert_eq!(subsystem_name(3), "WINDOWS_CUI");
        assert_eq!(subsystem_name(99), "UNKNOWN");
    }

    #[test]
    fn elf_rejects_non_elf() {
        let loaded = LoadedBinary {
            format: BinaryFormat::Raw,
            arch: crate::disasm::Arch::X86_64,
            entry: None,
            segments: Vec::new(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            pdata_funcs: Vec::new(),
            tls_callbacks: Vec::new(),
            init_funcs: Vec::new(),
            func_starts: Vec::new(),
        };
        assert_eq!(elf_headers(b"MZ garbage"), None);
        let v = headers_of(b"nope", &loaded, "00");
        assert_eq!(v["format"], "raw");
        assert!(v["pe"].is_null() && v["elf"].is_null() && v["macho"].is_null());
        assert_eq!(v["md5"].as_str().expect("md5").len(), 32);
    }

    #[test]
    fn macho_rejects_non_macho() {
        assert_eq!(macho_headers(b"nope", crate::disasm::Arch::X86_64), None);
    }

    /// One file-backed section at `rva` under `image_base`, with its bytes
    /// in a covering segment like the loader maps PE sections.
    fn bin_at(image_base: u64, rva: u32, data: Vec<u8>) -> LoadedBinary {
        let vaddr = image_base + u64::from(rva);
        let file_size = data.len() as u64;
        LoadedBinary {
            format: BinaryFormat::Pe,
            arch: crate::disasm::Arch::X86_32,
            entry: None,
            segments: vec![crate::loader::Segment {
                vaddr,
                mem_size: file_size,
                data,
                readable: true,
                writable: false,
                executable: false,
            }],
            sections: vec![crate::loader::Section {
                name: ".rsrc".to_string(),
                vaddr,
                size: file_size,
                file_off: 0,
                file_size,
                readable: true,
                writable: false,
                executable: false,
            }],
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            pdata_funcs: Vec::new(),
            tls_callbacks: Vec::new(),
            init_funcs: Vec::new(),
            func_starts: Vec::new(),
        }
    }

    #[test]
    fn pe_version_info_reads_file_version() {
        const BASE: u64 = 0x400_000;
        const RVA: u32 = 0x2000;
        let mut r = vec![0u8; 256];
        let put16 = |r: &mut [u8], off: usize, x: u16| {
            r[off..off + 2].copy_from_slice(&x.to_le_bytes());
        };
        let put32 = |r: &mut [u8], off: usize, x: u32| {
            r[off..off + 4].copy_from_slice(&x.to_le_bytes());
        };
        // Level 0: one ID entry, type 16 -> subdir at 24.
        put16(&mut r, 14, 1);
        put32(&mut r, 16, 16);
        put32(&mut r, 20, 0x8000_0000 | 24);
        // Level 1: one ID entry, name 1 -> language dir at 48.
        put16(&mut r, 24 + 14, 1);
        put32(&mut r, 40, 1);
        put32(&mut r, 44, 0x8000_0000 | 48);
        // Level 2: one language entry -> data entry at 72.
        put16(&mut r, 48 + 14, 1);
        put32(&mut r, 64, 0x409);
        put32(&mut r, 68, 72);
        // Data entry: blob at RVA+128.
        put32(&mut r, 72, RVA + 128);
        put32(&mut r, 76, 96);
        // VS_VERSION_INFO with file version 1.2.3.4.
        let key: Vec<u8> = "VS_VERSION_INFO\0"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        put16(&mut r, 128, 96);
        put16(&mut r, 130, 52);
        put16(&mut r, 132, 1);
        r[134..134 + key.len()].copy_from_slice(&key);
        let fixed = 134 + key.len() + (4 - (134 + key.len()) % 4) % 4;
        put32(&mut r, fixed, 0xFEEF_04BD);
        put32(&mut r, fixed + 8, (1 << 16) | 2);
        put32(&mut r, fixed + 12, (3 << 16) | 4);
        let bin = bin_at(BASE, RVA, r);
        let (present, version) = pe_version_info(&bin, BASE, RVA);
        assert!(present);
        assert_eq!(version.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn pe_pdb_reads_codeview() {
        const BASE: u64 = 0x400_000;
        let mut blob = Vec::new();
        blob.extend_from_slice(b"RSDS");
        blob.extend_from_slice(&(0..16u8).collect::<Vec<u8>>());
        blob.extend_from_slice(&7u32.to_le_bytes());
        blob.extend_from_slice(b"C:\\b\\x.pdb\0");
        let mut entry = vec![0u8; 28];
        entry[12..16].copy_from_slice(&2u32.to_le_bytes());
        entry[16..20].copy_from_slice(&(blob.len() as u32).to_le_bytes());
        entry[20..24].copy_from_slice(&0x3000u32.to_le_bytes());
        let mut data = vec![0u8; 0x100];
        data[..blob.len()].copy_from_slice(&blob);
        let bin = bin_at(BASE, 0x3000, data);
        let pdb = pe_pdb(&bin, BASE, &entry).expect("pdb");
        assert_eq!(pdb["path"], "C:\\b\\x.pdb");
        assert_eq!(pdb["guid"], "00010203-0405-0607-0809-0a0b0c0d0e0f");
        assert_eq!(pdb["age"], 7);
    }

    #[test]
    fn pe_forwarders_resolve_inside_dir() {
        const BASE: u64 = 0x400_000;
        const DIR: u32 = 0x3000;
        let mut s = vec![0u8; 0x200];
        let put32 = |s: &mut [u8], off: usize, x: u32| {
            s[off..off + 4].copy_from_slice(&x.to_le_bytes());
        };
        put32(&mut s, 20, 1); // NumberOfFunctions
        put32(&mut s, 24, 1); // NumberOfNames
        put32(&mut s, 28, DIR + 0x100); // AddressOfFunctions
        put32(&mut s, 32, DIR + 0x110); // AddressOfNames
        put32(&mut s, 36, DIR + 0x120); // AddressOfNameOrdinals
        put32(&mut s, 0x100, DIR + 100); // func[0] lands inside the dir
        put32(&mut s, 0x110, DIR + 0x130); // names[0]
        s[0x120..0x122].copy_from_slice(&0u16.to_le_bytes());
        s[100..100 + 14].copy_from_slice(b"otherdll.func\0");
        s[0x130..0x130 + 9].copy_from_slice(b"myexport\0");
        let bin = bin_at(BASE, DIR, s);
        let out = pe_forwarders(&bin, BASE, DIR, 200);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["name"], "myexport");
        assert_eq!(out[0]["forward"], "otherdll.func");
    }
}
