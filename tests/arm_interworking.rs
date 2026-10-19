//! rsdbg-em6.13: ARM/Thumb interworking inside ELF + `movw`/`movt`
//! pair resolution.
//!
//! - Thumb-bit entry seeds decode as Thumb (never ARM garbage).
//! - `$t`/`$a` mapping symbols switch the decode mode per region.
//! - Direct `blx` targets decode in the other state.
//! - `bx reg` after an adjacent `movw`/`movt` pair resolves its constant
//!   and switches to bit-0-selected state.
//! - `movw rX,#lo; movt rX,#hi` yields a data/string xref to the combined
//!   address, with IR/pseudo annotation like the `adrp` path.
//! - ARM literal-pool loads (`ldr rX, [pc, #imm]`) reference the pool word
//!   plus the pointer stored there.

use binscout::analysis::{analyze, DiscoveryReason, XrefKind};
use binscout::disasm::Arch;
use binscout::ir::lift_range;
use binscout::loader::{load, ArmHints, BinaryFormat, LoadedBinary, Segment};
use binscout::pseudo::render_function;

fn text_seg(vaddr: u64, code: Vec<u8>) -> Segment {
    Segment {
        vaddr,
        mem_size: code.len() as u64,
        data: code,
        readable: true,
        writable: false,
        executable: true,
    }
}

fn data_seg(vaddr: u64, size: usize, at: usize, bytes: &[u8]) -> Segment {
    let mut data = vec![0u8; size];
    data[at..at + bytes.len()].copy_from_slice(bytes);
    Segment {
        vaddr,
        mem_size: data.len() as u64,
        data,
        readable: true,
        writable: true,
        executable: false,
    }
}

fn arm_bin(entry: Option<u64>, segments: Vec<Segment>) -> LoadedBinary {
    LoadedBinary {
        format: BinaryFormat::Elf,
        arch: Arch::Arm32,
        entry,
        segments,
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
    }
}

fn has_xref(a: &binscout::analysis::Analysis, from: u64, kind: XrefKind, to: u64) -> bool {
    a.xrefs
        .iter()
        .any(|x| x.from == from && x.kind == kind && x.to == to)
}

#[test]
fn thumb_bit_entry_seed_decodes_as_thumb() {
    // Thumb `movs r0, #1; bx lr` at 0x8000, Thumb-bit entry.
    let bin = arm_bin(
        Some(0x8001),
        vec![text_seg(0x8000, vec![0x01, 0x20, 0x70, 0x47])],
    );
    let a = analyze(&bin).expect("synthetic arm elf must analyze");
    let f = a.functions.get(&0x8000).expect("entry function");
    assert_eq!(f.decode_arch, Some(Arch::Thumb));
    assert_eq!(f.reason_list(), [DiscoveryReason::Entry]);
    let insns: Vec<_> = f.blocks.values().flat_map(|b| &b.insns).collect();
    assert_eq!(
        insns.iter().map(|i| i.mnem.as_str()).collect::<Vec<_>>(),
        ["movs", "bx"]
    );
    assert!(insns.iter().all(|i| i.thumb));
    assert!(
        !a.functions.contains_key(&0x8001),
        "no function at the odd Thumb-bit address"
    );
}

#[test]
fn blx_target_switches_mode() {
    // No mapping hints: only the `blx` state switch can decode 0x8012 as
    // Thumb. 0x8000: `b 0x8008`; 0x8004: skipped `bx lr`; 0x8008: `blx`
    // (FB000000 targets 0x8012); 0x800C: `bx lr`. 0x8012: Thumb leaf.
    let code = vec![
        0x00, 0x00, 0x00, 0xEA, // b 0x8008
        0x1E, 0xFF, 0x2F, 0xE1, // bx lr (skipped)
        0x00, 0x00, 0x00, 0xFB, // blx -> 0x8012
        0x1E, 0xFF, 0x2F, 0xE1, // bx lr
        0x00, 0x00, // padding to 0x8012
        0x01, 0x20, // movs r0, #1 (Thumb)
        0x70, 0x47, // bx lr (Thumb)
    ];
    assert_eq!(code.len(), 0x16);
    let bin = arm_bin(Some(0x8000), vec![text_seg(0x8000, code)]);
    let a = analyze(&bin).expect("synthetic arm elf must analyze");
    let callee = a.functions.get(&0x8012).expect("blx target function");
    assert_eq!(callee.decode_arch, Some(Arch::Thumb));
    assert_eq!(
        callee
            .blocks
            .values()
            .flat_map(|b| &b.insns)
            .next()
            .expect("insn")
            .mnem,
        "movs"
    );
    assert!(
        has_xref(&a, 0x8008, XrefKind::Code, 0x8012),
        "blx edge reaches the Thumb target"
    );
    assert!(
        a.calls_of(0x8000).contains(&0x8012),
        "callgraph crosses the mode switch"
    );
}

#[test]
fn bx_reg_after_movw_movt_switches_mode() {
    // `movw r4, #0x8011; movt r4, #0; bx r4` materializes Thumb address
    // 0x8010 (bit 0 set): the branch decodes there as Thumb.
    let code = vec![
        0x11, 0x40, 0x08, 0xE3, // movw r4, #0x8011
        0x00, 0x40, 0x40, 0xE3, // movt r4, #0x0
        0x14, 0xFF, 0x2F, 0xE1, // bx r4
        0x00, 0x00, 0x00, 0x00, // padding to 0x8010
        0x01, 0x20, // movs r0, #1 (Thumb)
        0x70, 0x47, // bx lr (Thumb)
    ];
    let bin = arm_bin(Some(0x8000), vec![text_seg(0x8000, code)]);
    let a = analyze(&bin).expect("synthetic arm elf must analyze");
    let callee = a.functions.get(&0x8010).expect("bx target function");
    assert_eq!(callee.decode_arch, Some(Arch::Thumb));
    assert!(
        has_xref(&a, 0x8008, XrefKind::Code, 0x8010),
        "resolved bx edge reaches the Thumb target"
    );
    assert!(
        !a.diagnostics.records.iter().any(|d| d.addr == 0x8008
            && d.kind == binscout::analysis::DiagnosticKind::UnresolvedIndirectJump),
        "resolved bx keeps no indirect-jump diagnostic"
    );
}

#[test]
fn movw_movt_pair_yields_xref_ir_and_pseudo() {
    // `movw r2, #0x1234; movt r2, #0x5678; bx lr` materializes 0x56781234,
    // which holds "pool-string" in the data segment.
    let text = vec![
        0x34, 0x22, 0x01, 0xE3, // movw r2, #0x1234
        0x78, 0x26, 0x45, 0xE3, // movt r2, #0x5678
        0x1E, 0xFF, 0x2F, 0xE1, // bx lr
    ];
    let data = data_seg(0x5678_0000, 0x2000, 0x1234, b"pool-string\0");
    let bin = arm_bin(Some(0x8000), vec![text_seg(0x8000, text), data]);
    let a = analyze(&bin).expect("synthetic arm elf must analyze");
    assert!(
        has_xref(&a, 0x8004, XrefKind::Data, 0x5678_1234),
        "movt row references the combined address"
    );
    assert!(
        has_xref(&a, 0x8004, XrefKind::String, 0x5678_1234),
        "combined address inside a string yields a string ref"
    );
    let f = a.functions.get(&0x8000).expect("function");
    let owned: Vec<binscout::disasm::Insn> =
        f.blocks.values().flat_map(|b| b.insns.clone()).collect();
    let rows = lift_range(Arch::Arm32, &owned);
    assert_eq!(rows.len(), owned.len());
    assert_eq!(
        rows[1].target,
        Some(0x5678_1234),
        "second pair row lifts with the resolved address"
    );
    let render = render_function(Arch::Arm32, f);
    assert!(
        render.text.contains("// => 0x56781234"),
        "pseudo annotates the pair address, got:\n{}",
        render.text
    );
}

#[test]
fn literal_pool_ldr_yields_pool_and_value_refs() {
    // `ldr r1, [pc, #0]; bx lr` with pool word 0x9000 at 0x8008, pointing
    // at "pool-value" in the data segment.
    let mut text = vec![
        0x00, 0x10, 0x9F, 0xE5, // ldr r1, [pc, #0] (-> 0x8008)
        0x1E, 0xFF, 0x2F, 0xE1, // bx lr
    ];
    text.extend_from_slice(&0x9000u32.to_le_bytes()); // pool word
    let data = data_seg(0x9000, 0x1000, 0, b"pool-value\0");
    let bin = arm_bin(Some(0x8000), vec![text_seg(0x8000, text), data]);
    let a = analyze(&bin).expect("synthetic arm elf must analyze");
    assert!(
        has_xref(&a, 0x8000, XrefKind::Data, 0x8008),
        "ldr references its pool word"
    );
    assert!(
        has_xref(&a, 0x8000, XrefKind::Data, 0x9000),
        "ldr references the pointer stored in the pool word"
    );
    assert!(
        has_xref(&a, 0x8000, XrefKind::String, 0x9000),
        "pool value inside a string yields a string ref"
    );
}

// --- ELF32 fixture with $a/$t mapping symbols and a Thumb-bit function ---

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_le_bytes());
}

/// Minimal 32-bit ARM ELF: one RX `PT_LOAD` at 0x8000 mixing ARM and Thumb
/// code, with mapping symbols and a Thumb-bit `STT_FUNC` symbol.
///
/// Layout: 0x8000 ARM leaf (`mov r0, r1; bx lr`), 0x8008 ARM caller
/// (`bl 0x8000`; `blx` to 0x8014; `bx lr`), 0x8014 Thumb leaf
/// (`movs r0, #1; bx lr`). Entry is the Thumb leaf with bit 0 set.
fn arm_mixed_elf() -> Vec<u8> {
    let text: Vec<u8> = vec![
        0x01, 0x00, 0xA0, 0xE1, // 0x8000: mov r0, r1
        0x1E, 0xFF, 0x2F, 0xE1, // 0x8004: bx lr
        0xFC, 0xFF, 0xFF, 0xEB, // 0x8008: bl 0x8000
        0x00, 0x00, 0x00, 0xFA, // 0x800C: blx -> 0x8014
        0x1E, 0xFF, 0x2F, 0xE1, // 0x8010: bx lr
        0x01, 0x20, // 0x8014: movs r0, #1 (Thumb)
        0x70, 0x47, // 0x8016: bx lr (Thumb)
        0x02, 0x20, // 0x8018: movs r0, #2 (Thumb, mapping seed only)
        0x70, 0x47, // 0x801A: bx lr (Thumb)
        0x00, 0x00, // 0x801C: padding
    ];
    assert_eq!(text.len(), 0x1E);
    // strtab: offsets 1:$a 4:arm_leaf 13:$t 16:thumb_fn 25:arm_fn.
    let strtab = b"\0$a\0arm_leaf\0$t\0thumb_fn\0arm_fn\0";
    assert_eq!(strtab.len(), 32);
    // shstrtab: offsets 1:.text 7:.symtab 15:.strtab 23:.shstrtab.
    let shstrtab = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
    assert_eq!(shstrtab.len(), 33);

    let text_off = 52 + 32;
    let symtab_off = text_off + text.len();
    let strtab_off = symtab_off + 7 * 16;
    let shstrtab_off = strtab_off + strtab.len();
    let shoff = shstrtab_off + shstrtab.len();

    let mut f = vec![0u8; shoff + 5 * 40];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 1; // 32-bit
    f[5] = 1; // little-endian
    f[6] = 1; // version
    put16(&mut f, 16, 2); // EXEC
    put16(&mut f, 18, 40); // EM_ARM
    put32(&mut f, 20, 1);
    put32(&mut f, 24, 0x8015); // entry: Thumb leaf with bit 0 set
    put32(&mut f, 28, 52); // phoff
    put32(&mut f, 32, shoff as u32); // shoff
    put32(&mut f, 36, 0); // flags
    put16(&mut f, 40, 52); // ehsize
    put16(&mut f, 42, 32); // phentsize
    put16(&mut f, 44, 1); // phnum
    put16(&mut f, 46, 40); // shentsize
    put16(&mut f, 48, 5); // shnum
    put16(&mut f, 50, 4); // shstrndx
                          // Program header: one RX load.
    let p = 52;
    put32(&mut f, p, 1); // PT_LOAD
    put32(&mut f, p + 4, text_off as u32); // offset
    put32(&mut f, p + 8, 0x8000); // vaddr
    put32(&mut f, p + 12, 0x8000); // paddr
    put32(&mut f, p + 16, text.len() as u32); // filesz
    put32(&mut f, p + 20, text.len() as u32); // memsz
    put32(&mut f, p + 24, 5); // R+X
    put32(&mut f, p + 28, 0x1000); // align
    f[text_off..text_off + text.len()].copy_from_slice(&text);
    // Symbol table: null, $a, $t, arm_fn, thumb_fn (bit set), arm_leaf.
    let mut sym = |idx: usize, name: u32, value: u32, info: u8| {
        let o = symtab_off + idx * 16;
        put32(&mut f, o, name);
        put32(&mut f, o + 4, value);
        put32(&mut f, o + 8, 0); // size
        f[o + 12] = info;
        f[o + 13] = 0;
        put16(&mut f, o + 14, 1); // .text
    };
    sym(1, 1, 0x8000, 0x00); // $a: LOCAL NOTYPE
    sym(2, 13, 0x8014, 0x00); // $t: LOCAL NOTYPE
    sym(6, 13, 0x8018, 0x00); // $t: second Thumb region
    sym(3, 25, 0x8008, 0x12); // arm_fn: GLOBAL FUNC
    sym(4, 16, 0x8015, 0x12); // thumb_fn: GLOBAL FUNC, Thumb bit
    sym(5, 4, 0x8000, 0x12); // arm_leaf: GLOBAL FUNC
    f[strtab_off..strtab_off + strtab.len()].copy_from_slice(strtab);
    f[shstrtab_off..shstrtab_off + shstrtab.len()].copy_from_slice(shstrtab);
    // Section headers: null, .text, .symtab, .strtab, .shstrtab.
    let mut sec = |idx: usize,
                   name: u32,
                   ty: u32,
                   flags: u32,
                   addr: u32,
                   off: usize,
                   size: usize,
                   link: u32,
                   info: u32,
                   align: u32,
                   entsize: u32| {
        let o = shoff + idx * 40;
        put32(&mut f, o, name);
        put32(&mut f, o + 4, ty);
        put32(&mut f, o + 8, flags);
        put32(&mut f, o + 12, addr);
        put32(&mut f, o + 16, off as u32);
        put32(&mut f, o + 20, size as u32);
        put32(&mut f, o + 24, link);
        put32(&mut f, o + 28, info);
        put32(&mut f, o + 32, align);
        put32(&mut f, o + 36, entsize);
    };
    sec(1, 1, 1, 0x6, 0x8000, text_off, text.len(), 0, 0, 4, 0);
    sec(2, 7, 2, 0, 0, symtab_off, 7 * 16, 3, 3, 4, 16);
    sec(3, 15, 3, 0, 0, strtab_off, strtab.len(), 0, 0, 1, 0);
    sec(4, 23, 3, 0, 0, shstrtab_off, shstrtab.len(), 0, 0, 1, 0);
    f
}

#[test]
fn mapping_symbols_switch_mode() {
    let bytes = arm_mixed_elf();
    let bin = load(&bytes).expect("synthetic arm elf must load");
    assert_eq!(bin.arch, Arch::Arm32);
    assert_eq!(
        bin.arm_hints.thumb_ranges,
        [(0x8014, 0x8018), (0x8018, 0x801E)]
    );
    assert_eq!(bin.arm_hints.arm_ranges, [(0x8000, 0x8014)]);
    assert_eq!(bin.arm_hints.thumb_seeds, [0x8014]);

    let a = analyze(&bin).expect("synthetic arm elf must analyze");
    // ARM leaf: mapping seed (Entry) plus the direct-call edge (DirectCall).
    let leaf = a.functions.get(&0x8000).expect("arm leaf");
    assert_eq!(leaf.decode_arch, None);
    assert_eq!(
        leaf.reason_list(),
        [DiscoveryReason::Symbol, DiscoveryReason::DirectCall]
    );
    // ARM caller: symbol seed.
    let caller = a.functions.get(&0x8008).expect("arm caller");
    assert_eq!(caller.decode_arch, None);
    assert_eq!(caller.reason_list(), [DiscoveryReason::Symbol]);
    // Thumb leaf: Thumb-bit entry, Thumb-bit function symbol, blx target.
    let thumb = a.functions.get(&0x8014).expect("thumb leaf");
    assert_eq!(thumb.decode_arch, Some(Arch::Thumb));
    assert_eq!(
        thumb.reason_list(),
        [
            DiscoveryReason::Entry,
            DiscoveryReason::Symbol,
            DiscoveryReason::DirectCall
        ]
    );
    let mnems: Vec<_> = thumb
        .blocks
        .values()
        .flat_map(|b| &b.insns)
        .map(|i| i.mnem.as_str())
        .collect();
    assert_eq!(mnems, ["movs", "bx"]);
    assert!(
        thumb
            .blocks
            .values()
            .flat_map(|b| &b.insns)
            .all(|i| i.thumb),
        "every Thumb row records its mode"
    );
    assert!(has_xref(&a, 0x8008, XrefKind::Code, 0x8000));
    assert!(has_xref(&a, 0x800C, XrefKind::Code, 0x8014));
    assert!(a.calls_of(0x8008).contains(&0x8014));
    // Mapping-only region: no symbol, no branch, unreachable from entry —
    // its function exists purely through the `$t` range-start seed.
    let only = a.functions.get(&0x8018).expect("mapping-seeded region");
    assert_eq!(only.decode_arch, Some(Arch::Thumb));
    assert_eq!(only.reason_list(), [DiscoveryReason::Entry]);
    let mnems: Vec<_> = only
        .blocks
        .values()
        .flat_map(|b| &b.insns)
        .map(|i| i.mnem.as_str())
        .collect();
    assert_eq!(mnems, ["movs", "bx"]);
}
