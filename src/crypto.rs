//! First-minute crypto triage: static constant scan over mapped bytes.
//!
//! Each [`CryptoConst`] is a leading slice of a well-known cipher/hash
//! table, scanned with [`crate::search`] exactly like `search-bytes` (same
//! segment walk, same gap/BSS rules, same 256 MiB per-pattern budget). Rows
//! carry the constant `name` plus the match provenance, so an analyst sees
//! *which* primitive a binary embeds (AES tables, SHA-256 round constants,
//! `expand 32-byte k`, ...) at a glance.
//!
//! The table is deliberately small: leading 16-byte prefixes (four
//! little-endian words where the table is word-oriented) instead of full
//! multi-kilobyte tables. A 16-byte prefix is distinctive enough for triage
//! while keeping scan cost at one `search-bytes` pass per entry. Both
//! little- and big-endian word orders get their own row under one `name`
//! because table dumps appear in either order depending on how the code
//! stores them.
//!
//! | name | bytes | source |
//! |------|-------|--------|
//! | `aes-sbox` | `63 7c ... ab 76` | FIPS-197 §5.1.1 forward S-box, leading 16 bytes |
//! | `aes-inv-sbox` | `52 09 ... d7 fb` | FIPS-197 §5.3.2 inverse S-box, leading 16 bytes |
//! | `aes-t0` | LE/BE of `c66363a5 f87c7c84 ee7777ad f97b7b8d` | forward T-table Te0, leading 4 words (other rotations are the same words rotated) |
//! | `sha256-k` | LE/BE of `428a2f98 71374491 b5c0fbcf e9b5dba5` | FIPS 180-4 SHA-256 round constants K, leading 4 words |
//! | `sha1-k` | LE/BE of `5a827999 6ed9eba1 8f1bbcdc ca62c1d6` | FIPS 180-4 SHA-1 round constants K (all four) |
//! | `md5-t` | LE/BE of `d76aa478 e8c7b756 242070db c1bdceee` | RFC 1321 MD5 sine table T, leading 4 words |
//! | `crc32-table` | LE/BE of `77073096 ee0e612c 990951ba 076dc419` | IEEE 802.3 CRC-32 table (poly `0xEDB88320`), words 1–4 (word 0 is zero) |
//! | `chacha-sigma` | `65 78 ... 20 6b` | ASCII `expand 32-byte k` (ChaCha/Salsa sigma constant) |
//! | `blowfish-p` | LE/BE of `243f6a88 85a308d3 13198a2e 03707344` | Blowfish P-array (hex of pi), leading 4 words |
//! | `tea-delta` | LE/BE of `9e3779b9` | TEA/XTEA delta (short: indicative only, confirm with xrefs) |
//!
//! RC4 has no row on purpose: its KSA builds the identity permutation at
//! runtime, so there is no static data constant to match. TEA's 4-byte
//! delta is the weakest row; its `xrefs_count` decides whether code
//! actually uses the hit.

use crate::error::{Error, Result};
use crate::loader::LoadedBinary;
use crate::search::{ByteMatch, BytePattern};

/// One static crypto constant: a leading table slice as hex tokens.
///
/// `pattern` is parsed by [`BytePattern::parse`] (whitespace-separated hex
/// bytes, no wildcards); `note` names the source table so reports stay
/// auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoConst {
    /// Stable hit name shared by the LE/BE rows of one table.
    pub name: &'static str,
    /// Hex tokens for [`BytePattern::parse`].
    pub pattern: &'static str,
    /// Source table and slice, for analyst notes.
    pub note: &'static str,
}

/// The static triage table (see the module docs for sources).
///
/// Endian-neutral rows (S-boxes, sigma) appear once; word tables appear
/// twice (LE and BE) under one `name`.
pub static CRYPTO_CONSTS: &[CryptoConst] = &[
    CryptoConst {
        name: "aes-sbox",
        pattern: "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76",
        note: "FIPS-197 forward S-box, leading 16 bytes",
    },
    CryptoConst {
        name: "aes-inv-sbox",
        pattern: "52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb",
        note: "FIPS-197 inverse S-box, leading 16 bytes",
    },
    CryptoConst {
        name: "aes-t0",
        pattern: "a5 63 63 c6 84 7c 7c f8 ad 77 77 ee 8d 7b 7b f9",
        note: "forward T-table Te0, leading 4 words, little-endian",
    },
    CryptoConst {
        name: "aes-t0",
        pattern: "c6 63 63 a5 f8 7c 7c 84 ee 77 77 ad f9 7b 7b 8d",
        note: "forward T-table Te0, leading 4 words, big-endian",
    },
    CryptoConst {
        name: "sha256-k",
        pattern: "98 2f 8a 42 91 44 37 71 cf fb c0 b5 a5 db b5 e9",
        note: "SHA-256 round constants K, leading 4 words, little-endian",
    },
    CryptoConst {
        name: "sha256-k",
        pattern: "42 8a 2f 98 71 37 44 91 b5 c0 fb cf e9 b5 db a5",
        note: "SHA-256 round constants K, leading 4 words, big-endian",
    },
    CryptoConst {
        name: "sha1-k",
        pattern: "99 79 82 5a a1 eb d9 6e dc bc 1b 8f d6 c1 62 ca",
        note: "SHA-1 round constants K, little-endian",
    },
    CryptoConst {
        name: "sha1-k",
        pattern: "5a 82 79 99 6e d9 eb a1 8f 1b bc dc ca 62 c1 d6",
        note: "SHA-1 round constants K, big-endian",
    },
    CryptoConst {
        name: "md5-t",
        pattern: "78 a4 6a d7 56 b7 c7 e8 db 70 20 24 ee ce bd c1",
        note: "MD5 sine table T, leading 4 words, little-endian",
    },
    CryptoConst {
        name: "md5-t",
        pattern: "d7 6a a4 78 e8 c7 b7 56 24 20 70 db c1 bd ce ee",
        note: "MD5 sine table T, leading 4 words, big-endian",
    },
    CryptoConst {
        name: "crc32-table",
        pattern: "96 30 07 77 2c 61 0e ee ba 51 09 99 19 c4 6d 07",
        note: "CRC-32 table words 1-4, little-endian",
    },
    CryptoConst {
        name: "crc32-table",
        pattern: "77 07 30 96 ee 0e 61 2c 99 09 51 ba 07 6d c4 19",
        note: "CRC-32 table words 1-4, big-endian",
    },
    CryptoConst {
        name: "chacha-sigma",
        pattern: "65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b",
        note: "ASCII expand 32-byte k (ChaCha/Salsa sigma)",
    },
    CryptoConst {
        name: "blowfish-p",
        pattern: "88 6a 3f 24 d3 08 a3 85 2e 8a 19 13 44 73 70 03",
        note: "Blowfish P-array, leading 4 words, little-endian",
    },
    CryptoConst {
        name: "blowfish-p",
        pattern: "24 3f 6a 88 85 a3 08 d3 13 19 8a 2e 03 70 73 44",
        note: "Blowfish P-array, leading 4 words, big-endian",
    },
    CryptoConst {
        name: "tea-delta",
        pattern: "b9 79 37 9e",
        note: "TEA delta 0x9e3779b9, little-endian (indicative only)",
    },
    CryptoConst {
        name: "tea-delta",
        pattern: "9e 37 79 b9",
        note: "TEA delta 0x9e3779b9, big-endian (indicative only)",
    },
];

/// One crypto-constant hit: the table name plus match provenance.
///
/// `xrefs_count` is filled in by [`crate::Project::crypto_scan`] (all xref
/// kinds to `addr`); `0` means nothing in the analysis references the
/// constant, which downgrades short rows like `tea-delta`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct CryptoHit {
    /// Virtual address of the first matched byte.
    pub addr: u64,
    /// Table name (e.g. `aes-sbox`).
    pub name: String,
    /// File offset of the first matched byte, if known.
    pub file_off: Option<u64>,
    /// Covering section name, if any.
    pub section: Option<String>,
    /// Match length in bytes (the table-prefix length).
    pub len: usize,
    /// Xrefs to `addr` (any kind) in the cached analysis.
    pub xrefs_count: usize,
}

impl serde::Serialize for CryptoHit {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("CryptoHit", 7)?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("file_off", &self.file_off)?;
        st.serialize_field("section", &self.section)?;
        st.serialize_field("len", &self.len)?;
        st.serialize_field("xrefs_count", &self.xrefs_count)?;
        st.end()
    }
}

/// Scan `binary` for every table entry, returning `(name, match)` pairs.
///
/// `name` keeps one constant (`Error::NotFound` when it names no entry);
/// `section` keeps matches fully inside a file-backed section of that exact
/// name. Pairs order by `(addr, name)`. Each entry runs one bounded
/// [`crate::search`] pass, so the worst-case scan budget is
/// `CRYPTO_CONSTS.len()` times the per-request budget; table prefixes are
/// at least 4 distinctive bytes, so hit counts stay small on real inputs.
///
/// # Errors
/// Unknown `name`/`section`, plus the [`crate::search`] scan budget.
pub(crate) fn scan(
    binary: &LoadedBinary,
    name: Option<&str>,
    section: Option<&str>,
) -> Result<Vec<(String, ByteMatch)>> {
    if let Some(n) = name
        && !CRYPTO_CONSTS.iter().any(|c| c.name == n)
    {
        return Err(Error::NotFound(format!("unknown crypto constant {n:?}")));
    }
    let mut out = Vec::new();
    for c in CRYPTO_CONSTS {
        if name.is_some_and(|n| c.name != n) {
            continue;
        }
        let pattern = BytePattern::parse(c.pattern).map_err(|e| Error::Invalid(e.to_string()))?;
        let (_, items) = crate::search::run(binary, &pattern, section, None, 0, usize::MAX)?;
        out.extend(items.into_iter().map(|m| (c.name.to_string(), m)));
    }
    out.sort_by(|a, b| a.1.addr.cmp(&b.1.addr).then_with(|| a.0.cmp(&b.0)));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::Arch;
    use crate::loader::{BinaryFormat, RawOptions, Section, Segment, load_raw};

    fn raw_bin(bytes: &[u8]) -> LoadedBinary {
        load_raw(
            bytes,
            RawOptions {
                base: 0x1000,
                arch: Arch::X86_64,
                entry: None,
            },
        )
        .expect("raw fixture loads")
    }

    #[test]
    fn table_patterns_parse_and_have_literals() {
        for c in CRYPTO_CONSTS {
            let p = BytePattern::parse(c.pattern)
                .unwrap_or_else(|e| panic!("static pattern {:?} parses: {e}", c.name));
            assert!(p.len() >= 4, "{:?} is at least a word", c.name);
            assert!(
                p.bytes().iter().all(Option::is_some),
                "{:?} has no wildcards",
                c.name
            );
        }
        assert!(
            CRYPTO_CONSTS.iter().any(|c| c.name == "aes-sbox"),
            "table keeps the AES row"
        );
    }

    #[test]
    fn scan_finds_embedded_prefixes_by_name() {
        let mut bytes = vec![0x90u8; 64];
        bytes[8..24].copy_from_slice(&[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ]);
        bytes[32..48].copy_from_slice(b"expand 32-byte k");
        let bin = raw_bin(&bytes);
        let hits = scan(&bin, None, None).expect("scan");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0], ("aes-sbox".to_string(), hits[0].1.clone()));
        assert_eq!(hits[0].1.addr, 0x1008);
        assert_eq!(hits[1].1.addr, 0x1020);
        assert_eq!(hits[1].0, "chacha-sigma");
        let only = scan(&bin, Some("aes-sbox"), None).expect("named scan");
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].1.addr, 0x1008);
        assert!(matches!(
            scan(&bin, Some("nope"), None).unwrap_err(),
            Error::NotFound(_)
        ));
        assert!(matches!(
            scan(&bin, None, Some("nope")).unwrap_err(),
            Error::NotFound(_)
        ));
    }

    #[test]
    fn scan_section_filter_attributes_hits() {
        let mut data = vec![0x63, 0x7c, 0x77, 0x7b];
        data.extend_from_slice(b"expand 32-byte k");
        let bin = LoadedBinary {
            format: BinaryFormat::Elf,
            arch: Arch::X86_64,
            entry: None,
            segments: vec![Segment {
                vaddr: 0x400000,
                mem_size: data.len() as u64,
                data: data.clone(),
                readable: true,
                writable: false,
                executable: true,
            }],
            sections: vec![Section {
                name: ".rodata".to_string(),
                vaddr: 0x400000,
                size: data.len() as u64,
                file_off: 0,
                file_size: data.len() as u64,
                entropy: crate::loader::section_entropy(&data),
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
            debug_funcs: Vec::new(),
            relocatable: false,
        };
        let hits = scan(&bin, None, Some(".rodata")).expect("section scan");
        assert_eq!(hits.len(), 1, "only the sigma matches: {hits:?}");
        assert_eq!(hits[0].0, "chacha-sigma");
        assert_eq!(hits[0].1.addr, 0x400004);
        assert_eq!(hits[0].1.section.as_deref(), Some(".rodata"));
        let none = scan(&bin, Some("tea-delta"), Some(".rodata")).expect("empty page");
        assert!(none.is_empty(), "4-byte sbox head is not the TEA delta");
        let err = scan(&bin, None, Some(".missing")).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }
}
