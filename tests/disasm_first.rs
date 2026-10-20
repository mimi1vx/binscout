mod common;

use binscout::disasm::{
    Arch, DEFAULT_MAX_INSNS, Insn, disasm_first, disasm_range, disasm_range_partial,
};
use binscout::error::Error;

fn arch_tag(arch: Arch) -> u64 {
    match arch {
        Arch::X86_64 => 1,
        Arch::X86_32 => 2,
        Arch::Aarch64 => 3,
        Arch::Arm32 => 4,
        Arch::Thumb => 5,
        Arch::Riscv32 => 6,
        Arch::Riscv64 => 7,
        Arch::Mips32 => 8,
        Arch::Ppc32 => 9,
        Arch::Ppc64 => 10,
    }
}

const ARCHES: [Arch; 10] = [
    Arch::X86_64,
    Arch::X86_32,
    Arch::Aarch64,
    Arch::Arm32,
    Arch::Thumb,
    Arch::Riscv32,
    Arch::Riscv64,
    Arch::Mips32,
    Arch::Ppc32,
    Arch::Ppc64,
];

/// Pre-fix oracle: the exact shrinking-window algorithm `decode_one` used
/// before the first-instruction decoder, reimplemented over the public
/// range API. Returns `None` where the old code ended the path.
fn oracle_first(arch: Arch, bytes: &[u8], va: u64) -> Option<Insn> {
    if bytes.is_empty() {
        return None;
    }
    match arch {
        Arch::X86_64 | Arch::X86_32 => {
            let mut len = bytes.len().min(15);
            loop {
                match disasm_range(arch, &bytes[..len], va, DEFAULT_MAX_INSNS) {
                    Ok(mut v) if !v.is_empty() => return Some(v.remove(0)),
                    Ok(_) => return None,
                    Err(Error::Invalid(_)) if len > 1 => len -= 1,
                    Err(Error::Invalid(_)) => return None,
                    Err(e) => panic!("oracle hit unexpected error: {e:?}"),
                }
            }
        }
        Arch::Aarch64 | Arch::Arm32 => {
            if bytes.len() < 4 {
                return None;
            }
            match disasm_range(arch, &bytes[..4], va, DEFAULT_MAX_INSNS) {
                Ok(mut v) if !v.is_empty() => Some(v.remove(0)),
                Ok(_) => None,
                Err(Error::Invalid(_)) => None,
                Err(e) => panic!("oracle hit unexpected error: {e:?}"),
            }
        }
        // PowerPC mirrors the fixed-width shape: one big-endian word or
        // nothing; short tails and illegal words end the path.
        Arch::Ppc32 | Arch::Ppc64 => {
            if bytes.len() < 4 {
                return None;
            }
            match disasm_range(arch, &bytes[..4], va, DEFAULT_MAX_INSNS) {
                Ok(mut v) if !v.is_empty() => Some(v.remove(0)),
                Ok(_) => None,
                Err(Error::Invalid(_)) => None,
                Err(e) => panic!("oracle hit unexpected error: {e:?}"),
            }
        }
        Arch::Thumb => {
            if bytes.len() >= 4 {
                match disasm_range(arch, &bytes[..4], va, DEFAULT_MAX_INSNS) {
                    Ok(mut v) if !v.is_empty() => return Some(v.remove(0)),
                    Ok(_) => return None,
                    Err(Error::Invalid(_)) => {}
                    Err(e) => panic!("oracle hit unexpected error: {e:?}"),
                }
            }
            if bytes.len() >= 2 {
                match disasm_range(arch, &bytes[..2], va, DEFAULT_MAX_INSNS) {
                    Ok(mut v) if !v.is_empty() => Some(v.remove(0)),
                    Ok(_) => None,
                    Err(Error::Invalid(_)) => None,
                    Err(e) => panic!("oracle hit unexpected error: {e:?}"),
                }
            } else {
                None
            }
        }
        Arch::Riscv32 | Arch::Riscv64 => {
            // New arch, no legacy window behavior: the oracle mirrors the
            // strict contract (length from the low two bits, truncated
            // words fail) over the public range API.
            let wide = bytes[0] & 0x03 == 0x03;
            let need = if wide { 4 } else { 2 };
            if bytes.len() < need {
                return None;
            }
            match disasm_range(arch, &bytes[..need], va, DEFAULT_MAX_INSNS) {
                Ok(mut v) if !v.is_empty() => Some(v.remove(0)),
                Ok(_) => None,
                Err(Error::Invalid(_)) => None,
                Err(e) => panic!("oracle hit unexpected error: {e:?}"),
            }
        }
        Arch::Mips32 => {
            // Fixed 4-byte words: the oracle mirrors the strict contract
            // (truncated words fail) over the public range API.
            if bytes.len() < 4 {
                return None;
            }
            match disasm_range(arch, &bytes[..4], va, DEFAULT_MAX_INSNS) {
                Ok(mut v) if !v.is_empty() => Some(v.remove(0)),
                Ok(_) => None,
                Err(Error::Invalid(_)) => None,
                Err(e) => panic!("oracle hit unexpected error: {e:?}"),
            }
        }
    }
}

/// New decoder mapped to the `decode_one` contract (`Invalid` ends the path).
fn new_first(arch: Arch, bytes: &[u8], va: u64) -> Option<Insn> {
    match disasm_first(arch, bytes, va) {
        Ok(v) => v,
        Err(Error::Invalid(_)) => None,
        Err(e) => panic!("disasm_first hit unexpected error: {e:?}"),
    }
}

fn assert_agree(arch: Arch, bytes: &[u8], va: u64) {
    let old = std::panic::catch_unwind(|| oracle_first(arch, bytes, va));
    let new = std::panic::catch_unwind(|| new_first(arch, bytes, va));
    match (old, new) {
        (Ok(old), Ok(new)) => assert_eq!(
            new,
            old,
            "first-instruction mismatch for {arch:?} window {} at {va:#x}",
            Hex(bytes),
        ),
        // Hostile words report Invalid, never abort: any escaping panic is
        // a containment failure (see arm32_decoder_panic_words_are_invalid).
        _ => panic!(
            "decoder panicked for {arch:?} window {} at {va:#x}",
            Hex(bytes),
        ),
    }
}

/// Lowercase hex rendering for failure messages.
struct Hex<'a>(&'a [u8]);
impl std::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[test]
fn empty_input_reports_none_on_all_arches() {
    for arch in ARCHES {
        assert_eq!(
            disasm_first(arch, &[], 0x1000).expect("empty is not an error"),
            None
        );
        assert_agree(arch, &[], 0x1000);
    }
}

#[test]
fn invalid_first_opcode_agrees_on_all_arches() {
    // 0x06 is invalid in 64-bit, valid `push` in 32-bit: bitness must survive.
    assert_agree(Arch::X86_64, &[0x06], 0x1000);
    assert_eq!(new_first(Arch::X86_64, &[0x06], 0x1000), None);
    assert_agree(Arch::X86_32, &[0x06], 0x1000);
    assert_eq!(
        new_first(Arch::X86_32, &[0x06], 0x1000)
            .expect("must decode")
            .mnem,
        "push"
    );
    // Truncated multi-byte opcodes (64-bit: lone REX/prefix is invalid).
    for win in [&[0xE8][..], &[0xE8, 0x01][..], &[0x48][..], &[0x66][..]] {
        assert_agree(Arch::X86_64, win, 0x1000);
        assert_eq!(
            new_first(Arch::X86_64, win, 0x1000),
            None,
            "truncated {win:02x?}"
        );
    }
    // 32-bit: truncated calls/prefixes fail, but 0x48 is valid `dec eax`.
    for win in [&[0xE8][..], &[0xE8, 0x01][..], &[0x66][..]] {
        assert_agree(Arch::X86_32, win, 0x1000);
        assert_eq!(
            new_first(Arch::X86_32, win, 0x1000),
            None,
            "truncated {win:02x?}"
        );
    }
    assert_agree(Arch::X86_32, &[0x48], 0x1000);
    assert_eq!(
        new_first(Arch::X86_32, &[0x48], 0x1000)
            .expect("dec decodes")
            .mnem,
        "dec"
    );
    // Fixed-width garbage and short tails.
    assert_agree(Arch::Aarch64, &[0xff, 0xff, 0xff, 0xff], 0x4000);
    assert_eq!(
        new_first(Arch::Aarch64, &[0xff, 0xff, 0xff, 0xff], 0x4000),
        None
    );
    assert_agree(Arch::Aarch64, &[0x1f, 0x20], 0x4000);
    assert_eq!(new_first(Arch::Aarch64, &[0x1f, 0x20], 0x4000), None);
    assert_agree(Arch::Arm32, &[0xff, 0xff, 0xff, 0xff], 0x10000);
    assert_eq!(
        new_first(Arch::Arm32, &[0xff, 0xff, 0xff, 0xff], 0x10000),
        None
    );
    assert_agree(Arch::Arm32, &[0x01, 0x00], 0x10000);
    assert_eq!(new_first(Arch::Arm32, &[0x01, 0x00], 0x10000), None);
    // PowerPC: opcode-0 word is illegal, short tails decode nothing.
    // (`0xff..` decodes as a valid extended floating-point form, so the
    // illegal probe uses the empty primary opcode instead.)
    assert_agree(Arch::Ppc32, &[0x00, 0x00, 0x00, 0x00], 0x10000);
    assert_eq!(
        new_first(Arch::Ppc32, &[0x00, 0x00, 0x00, 0x00], 0x10000),
        None
    );
    assert_agree(Arch::Ppc64, &[0x00, 0x00, 0x00, 0x00], 0x10000);
    assert_eq!(
        new_first(Arch::Ppc64, &[0x00, 0x00, 0x00, 0x00], 0x10000),
        None
    );
    assert_agree(Arch::Ppc32, &[0x48, 0x00, 0x01], 0x10000);
    assert_eq!(new_first(Arch::Ppc32, &[0x48, 0x00, 0x01], 0x10000), None);
    // Lone first halfword of a 32-bit Thumb instruction.
    assert_agree(Arch::Thumb, &[0x00, 0xf0], 0x20000);
    assert_eq!(new_first(Arch::Thumb, &[0x00, 0xf0], 0x20000), None);
    assert_agree(Arch::Thumb, &[0x00], 0x20000);
    assert_eq!(new_first(Arch::Thumb, &[0x00], 0x20000), None);
}

#[test]
fn arm32_decoder_panic_words_are_invalid() {
    // yaxpeax-arm 0.5.0 panics inside `decode` on STRD with Rt == 15
    // (`Reg::from_u8(16)`); the panic is contained as Invalid at every
    // entry point instead of aborting the process.
    let hostile = [0xF9, 0xF0, 0x00, 0x00];
    assert!(matches!(
        disasm_first(Arch::Arm32, &hostile, 0x1000),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        disasm_range(Arch::Arm32, &hostile, 0x1000, DEFAULT_MAX_INSNS),
        Err(Error::Invalid(_))
    ));
    let partial = disasm_range_partial(Arch::Arm32, &hostile, 0x1000, DEFAULT_MAX_INSNS)
        .expect("partial keeps the prefix");
    assert!(partial.insns.is_empty());
    assert!(partial.error_at.is_some());
    // Byte-swapped control errors identically in kind, without the panic path.
    let swapped = [0x00, 0x00, 0xF0, 0xF9];
    assert!(matches!(
        disasm_first(Arch::Arm32, &swapped, 0x1000),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        disasm_range(Arch::Arm32, &swapped, 0x1000, DEFAULT_MAX_INSNS),
        Err(Error::Invalid(_))
    ));
    // A valid prefix before the hostile word is kept; the hostile word ends
    // the range exactly like any other undecodable word.
    let mut prefixed = vec![0x01, 0x00, 0xA0, 0xE1];
    prefixed.extend(hostile);
    assert!(matches!(
        disasm_range(Arch::Arm32, &prefixed, 0x10000, DEFAULT_MAX_INSNS),
        Err(Error::Invalid(_))
    ));
    let partial = disasm_range_partial(Arch::Arm32, &prefixed, 0x10000, DEFAULT_MAX_INSNS)
        .expect("partial keeps the prefix");
    assert_eq!(partial.insns.len(), 1);
    assert_eq!(partial.insns[0].mnem, "mov");
    assert!(partial.error_at.is_some());
    // Deterministic fuzz corpus over ARM32/Thumb words: no escaping panics.
    // An escaping panic fails the test (no catch_unwind by design).
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..20_000 {
        let word = (rng.next() & 0xffff_ffff) as u32;
        let bytes = word.to_le_bytes();
        for arch in [Arch::Arm32, Arch::Thumb] {
            let _ = disasm_first(arch, &bytes, 0x1000);
            let _ = disasm_range(arch, &bytes, 0x1000, DEFAULT_MAX_INSNS);
            disasm_range_partial(arch, &bytes, 0x1000, DEFAULT_MAX_INSNS)
                .expect("partial never errors on undecodable bytes");
        }
    }
    // Structured Rt == 15 sample (the STRD/LDRD panic shape) across the
    // condition/flag space, plus a Thumb halfword sample.
    for top in 0..=0xFFu32 {
        for flags in 0..=0x1Fu32 {
            let bytes = ((top << 24) | (flags << 20) | (0xF << 12) | 0xF9).to_le_bytes();
            for arch in [Arch::Arm32, Arch::Thumb] {
                let _ = disasm_first(arch, &bytes, 0x1000);
                let _ = disasm_range(arch, &bytes, 0x1000, DEFAULT_MAX_INSNS);
            }
        }
    }
    for hw in (0..=0xFFFFu32).step_by(64) {
        let bytes = (hw as u16).to_le_bytes();
        let _ = disasm_first(Arch::Thumb, &bytes, 0x20000);
        let _ = disasm_range(Arch::Thumb, &bytes, 0x20000, DEFAULT_MAX_INSNS);
    }
}

#[test]
fn valid_first_with_invalid_tail_keeps_first() {
    // nop with garbage tail: the tail cannot alter the first decode.
    let insn = new_first(Arch::X86_64, &[0x90, 0x06], 0x1000).expect("nop decodes");
    assert_eq!((insn.mnem.as_str(), insn.size), ("nop", 1));
    assert_eq!(insn.bytes, [0x90]);
    assert_agree(Arch::X86_64, &[0x90, 0x06], 0x1000);
    // Longer first instruction with a garbage tail.
    assert_agree(Arch::X86_64, &[0x48, 0x89, 0xd8, 0x06, 0x90], 0x1000);
    assert_eq!(
        new_first(Arch::X86_64, &[0x48, 0x89, 0xd8, 0x06], 0x1000)
            .expect("must decode")
            .mnem,
        "mov"
    );
    // 10-byte movabs with trailing garbage: shrink window must land on it.
    let mut win = vec![0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8];
    win.extend([0x06, 0x06, 0x06, 0x06, 0x06]);
    assert_agree(Arch::X86_64, &win, 0x1000);
    assert_eq!(
        new_first(Arch::X86_64, &win, 0x1000)
            .expect("must decode")
            .size,
        10
    );
    // Fixed-width first words with garbage tails.
    assert_agree(
        Arch::Aarch64,
        &[0x1f, 0x20, 0x03, 0xd5, 0xff, 0xff, 0xff, 0xff],
        0x4000,
    );
    assert_eq!(
        new_first(Arch::Aarch64, &[0x1f, 0x20, 0x03, 0xd5, 0xff], 0x4000)
            .expect("must decode")
            .mnem,
        "nop"
    );
    assert_agree(
        Arch::Arm32,
        &[0x01, 0x00, 0xa0, 0xe1, 0xff, 0xff, 0xff, 0xff],
        0x10000,
    );
    assert_eq!(
        new_first(Arch::Arm32, &[0x01, 0x00, 0xa0, 0xe1, 0xff], 0x10000)
            .expect("must decode")
            .mnem,
        "mov"
    );
    // Thumb nop followed by a truncated 32-bit prefix: falls back to the
    // lone halfword, exactly like the old 4-then-2 window retry.
    assert_agree(Arch::Thumb, &[0x00, 0xbf, 0x00, 0xf0], 0x20000);
    assert_eq!(
        new_first(Arch::Thumb, &[0x00, 0xbf, 0x00, 0xf0], 0x20000)
            .expect("must decode")
            .mnem,
        "nop"
    );
}

#[test]
fn prefixes_agree_with_and_without_tails() {
    let heads: &[&[u8]] = &[
        &[0x66, 0x90],                                     // operand-size prefix + nop
        &[0x67, 0x90],                                     // address-size prefix + nop
        &[0x40],                                           // REX prefix alone (truncated)
        &[0x48, 0x89, 0xd8],                               // REX.W mov
        &[0xf3, 0x90],                                     // pause/nop with rep prefix
        &[0x66, 0xf3, 0x90],                               // stacked prefixes
        &[0x2e, 0x48, 0x8d, 0x3d, 0x05, 0x00, 0x00, 0x00], // cs prefix + lea
    ];
    let tails: &[&[u8]] = &[
        &[],
        &[0x06],
        &[0x90, 0x90, 0x90],
        &[0x06, 0x06, 0x06, 0x06, 0x06],
    ];
    for arch in [Arch::X86_64, Arch::X86_32] {
        for head in heads {
            for tail in tails {
                let mut win = head.to_vec();
                win.extend(*tail);
                assert_agree(arch, &win, 0x1000);
            }
        }
    }
}

#[test]
fn branch_and_mem_targets_agree() {
    // call rel32 carries an addr-derived branch target; lea carries mem_target.
    assert_agree(Arch::X86_64, &[0xe8, 0, 0, 0, 0, 0x06], 0x2000);
    let call = new_first(Arch::X86_64, &[0xe8, 0, 0, 0, 0, 0x06], 0x2000).expect("call decodes");
    assert_eq!(call.branch_target, Some(0x2005));
    assert_agree(
        Arch::X86_64,
        &[0x48, 0x8d, 0x3d, 0x05, 0x00, 0x00, 0x00, 0x06],
        0x4000,
    );
    let lea = new_first(
        Arch::X86_64,
        &[0x48, 0x8d, 0x3d, 0x05, 0x00, 0x00, 0x00],
        0x4000,
    )
    .expect("lea decodes");
    assert_eq!(lea.mem_target, Some(0x400c));
    // x86-32 absolute push-imm32 mem target survives a garbage tail.
    assert_agree(
        Arch::X86_32,
        &[0x68, 0x00, 0x21, 0x40, 0x00, 0x06],
        0x401003,
    );
    assert_eq!(
        new_first(
            Arch::X86_32,
            &[0x68, 0x00, 0x21, 0x40, 0x00, 0x06],
            0x401003
        )
        .expect("must decode")
        .mem_target,
        Some(0x402100)
    );
    // AArch64 bl / adr targets.
    assert_agree(Arch::Aarch64, &[0x04, 0, 0, 0x94, 0xff], 0x4000);
    assert_eq!(
        new_first(Arch::Aarch64, &[0x04, 0, 0, 0x94, 0xff], 0x4000)
            .expect("must decode")
            .branch_target,
        Some(0x4010)
    );
}

/// Xorshift64: deterministic generated windows, no harness randomness.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

#[test]
fn generated_windows_agree_on_all_arches() {
    // Byte pool biased toward real opcode bytes, prefixes, and garbage.
    const POOL: &[u8] = &[
        0x00, 0x06, 0x1f, 0x20, 0x2e, 0x40, 0x48, 0x55, 0x66, 0x67, 0x68, 0x89, 0x8d, 0x90, 0xb8,
        0xc3, 0xd5, 0xd6, 0xe5, 0xe8, 0xf0, 0xf3, 0xff,
    ];
    let vas = [0x1000u64, 0x0, 0xffff_ffff_ffff_f000];
    for arch in ARCHES {
        let mut rng = Rng(0x1234_5678_9abc_def1 ^ arch_tag(arch));
        for _ in 0..1200 {
            let len = (rng.next() % 25) as usize;
            let mut win = Vec::with_capacity(len);
            for _ in 0..len {
                let pick = rng.next();
                let b = if pick & 1 == 0 {
                    (pick >> 33) as u8
                } else {
                    POOL[(pick >> 33) as usize % POOL.len()]
                };
                win.push(b);
            }
            let va = vas[(rng.next() as usize) % vas.len()];
            assert_agree(arch, &win, va);
        }
    }
}

#[test]
fn appending_tails_never_changes_valid_first() {
    let heads: &[(Arch, &[u8], u64)] = &[
        (Arch::X86_64, &[0x90], 0x1000),
        (Arch::X86_64, &[0x48, 0x89, 0xe5], 0x1000),
        (Arch::X86_32, &[0x55, 0x89, 0xe5], 0x1000),
        (Arch::Aarch64, &[0x1f, 0x20, 0x03, 0xd5], 0x4000),
        (Arch::Arm32, &[0x01, 0x00, 0xa0, 0xe1], 0x10000),
        (Arch::Thumb, &[0x00, 0xbf], 0x20000),
        (Arch::Thumb, &[0x00, 0xf0, 0x00, 0xf8], 0x20000),
    ];
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for (arch, head, va) in heads {
        let base = new_first(*arch, head, *va).expect("head must decode");
        for _ in 0..32 {
            let tail_len = (rng.next() % 17) as usize;
            let mut win = head.to_vec();
            for _ in 0..tail_len {
                win.push((rng.next() >> 17) as u8);
            }
            let with_tail = new_first(*arch, &win, *va).expect("valid head stays valid");
            assert_eq!(with_tail, base, "tail changed the first decode: {win:02x?}");
            assert_agree(*arch, &win, *va);
        }
    }
}

#[test]
fn every_fixture_offset_agrees() {
    let names: Vec<&str> = common::builders::FIXTURE_NAMES.to_vec();
    let raw_x64 = include_bytes!("fixtures/raw-x64.bin");
    for name in names {
        let bytes = common::fixture_bytes(name);
        assert!(!bytes.is_empty(), "{name} fixture must be non-empty");
        for arch in ARCHES {
            for (off, _) in bytes.iter().enumerate() {
                assert_agree(arch, &bytes[off..], 0x400000 + off as u64);
            }
        }
    }
    // Checked-in raw blob and minimal ELF code bytes too.
    let elf = common::minimal_elf();
    for extra in [raw_x64.as_slice(), elf.as_slice()] {
        for arch in ARCHES {
            for off in 0..extra.len() {
                assert_agree(arch, &extra[off..], 0x400000 + off as u64);
            }
        }
    }
}

#[test]
fn dense_nop_blob_analyzes_with_exact_counts() {
    // 4096 single-byte NOPs: every address decodes, so the old window
    // decoder formatted ~15 instructions per step; the first-instruction
    // decoder formats exactly one.
    let blob = vec![0x90u8; 4096];
    let a = binscout::analysis::analyze_raw(&blob, 0x1000, Arch::X86_64, Some(0x1000))
        .expect("nop sled analyzes");
    let s = a.summary();
    assert_eq!(s.insns, 4096);
    assert_eq!(s.functions, 1);
    let f = &a.functions[&0x1000];
    assert_eq!(f.insn_count(), 4096);
    assert_eq!(f.blocks.len(), 1);
}
