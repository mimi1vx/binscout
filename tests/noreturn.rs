//! Noreturn calls: `exit`/`abort`-style imports cut the fall-through CFG
//! edge, flag the function row, and propagate to callers.
//!
//! Handbuilt `LoadedBinary` fixtures exercise the ELF (direct PLT call),
//! PE (indirect IAT call), and raw (loop-callee propagation) shapes; a
//! real ELF container covers loader-to-analysis import resolution plus
//! snapshot-reopen parity.

mod common;

use binscout::analysis::{DiagnosticKind, analyze, analyze_raw};
use binscout::disasm::Arch;
use binscout::loader::{BinaryFormat, ImportRef, LoadedBinary, Segment, load};
use binscout::{FunctionFilter, Project};

use common::{cleanup, temp_db, tmpdir, write_bin};

const CODE_VA: u64 = 0x400000;
const SLOT_VA: u64 = 0x401000;

/// Handbuilt executable+slot image: `code` runs at `CODE_VA`, one
/// writable slot at `SLOT_VA` serves the single named import.
fn image_with_import(format: BinaryFormat, name: &str, code: Vec<u8>) -> LoadedBinary {
    LoadedBinary {
        format,
        arch: Arch::X86_64,
        entry: Some(CODE_VA),
        segments: vec![
            Segment {
                vaddr: CODE_VA,
                mem_size: code.len() as u64,
                data: code,
                readable: true,
                writable: false,
                executable: true,
            },
            Segment {
                vaddr: SLOT_VA,
                mem_size: 8,
                data: vec![0u8; 8],
                readable: true,
                writable: true,
                executable: false,
            },
        ],
        sections: Vec::new(),
        imports: vec![ImportRef {
            library: String::new(),
            name: name.to_string(),
            ordinal: None,
            unresolved: false,
            demangled: None,
            address: Some(SLOT_VA),
        }],
        exports: Vec::new(),
        symbols: Vec::new(),
        pdata_funcs: Vec::new(),
        tls_callbacks: Vec::new(),
        init_funcs: Vec::new(),
        func_starts: Vec::new(),
        debug_funcs: Vec::new(),
        relocatable: false,
        arm_hints: Default::default(),
    }
}

fn rel_call(from: u64, to: u64) -> Vec<u8> {
    let mut v = vec![0xE8];
    v.extend_from_slice(&(to.wrapping_sub(from + 5) as u32).to_le_bytes());
    v
}

fn jmp_slot(slot: u64, at: u64) -> Vec<u8> {
    let mut v = vec![0xFF, 0x25];
    v.extend_from_slice(&(slot.wrapping_sub(at + 6) as u32).to_le_bytes());
    v
}

fn cut_sites(a: &binscout::analysis::Analysis) -> Vec<u64> {
    let mut v: Vec<u64> = a
        .diagnostics
        .records
        .iter()
        .filter(|d| d.kind == DiagnosticKind::NoreturnCut)
        .map(|d| d.addr)
        .collect();
    v.sort_unstable();
    v
}

/// Direct `call exit@plt` followed by zero padding: the padding block is
/// gone, the edge is cut, and both functions flag noreturn.
#[test]
fn direct_noreturn_call_cuts_fallthrough_and_flags() {
    let stub = CODE_VA + 5 + 32;
    let mut code = rel_call(CODE_VA, stub);
    code.extend_from_slice(&[0u8; 32]);
    code.extend_from_slice(&jmp_slot(SLOT_VA, stub));
    let bin = image_with_import(BinaryFormat::Elf, "exit", code);

    let a = analyze(&bin).expect("noreturn image analyzes");
    let entry = a.functions.get(&CODE_VA).expect("entry is a function");
    assert_eq!(entry.blocks.len(), 1, "padding block pruned");
    assert!(entry.noreturn);
    assert_eq!(entry.successors(CODE_VA), Vec::<u64>::new());
    assert_eq!(a.calls_of(CODE_VA), vec![stub]);

    let plt = a.functions.get(&stub).expect("stub is a function");
    assert_eq!(plt.name.as_deref(), Some("exit@plt"));
    assert!(plt.noreturn);
    assert_eq!(cut_sites(&a), vec![CODE_VA]);
}

/// `main` calls `die`, `die` calls `abort@plt`: the cut propagates one
/// level, pruning `die`'s `ret` and `main`'s tail.
#[test]
fn noreturn_propagates_to_callers() {
    let die = CODE_VA + 7;
    let stub = die + 6;
    let mut code = rel_call(CODE_VA, die);
    code.push(0x90);
    code.push(0xC3);
    code.extend_from_slice(&rel_call(die, stub));
    code.push(0xC3);
    code.extend_from_slice(&jmp_slot(SLOT_VA, stub));
    let bin = image_with_import(BinaryFormat::Elf, "abort", code);

    let a = analyze(&bin).expect("propagation image analyzes");
    let main = a.functions.get(&CODE_VA).expect("main is a function");
    assert_eq!(main.blocks.len(), 1, "main tail pruned");
    assert!(main.noreturn);
    let die_f = a.functions.get(&die).expect("die is a function");
    assert_eq!(die_f.blocks.len(), 1, "die ret pruned");
    assert!(die_f.noreturn);
    assert_eq!(a.calls_of(CODE_VA), vec![die]);
    assert_eq!(a.calls_of(die), vec![stub]);
    assert_eq!(cut_sites(&a), vec![CODE_VA, die]);
}

/// A call to a returning import keeps its fall-through: no cut, no flag.
#[test]
fn returning_import_keeps_fallthrough() {
    let stub = CODE_VA + 6;
    let mut code = rel_call(CODE_VA, stub);
    code.push(0xC3);
    code.extend_from_slice(&jmp_slot(SLOT_VA, stub));
    let bin = image_with_import(BinaryFormat::Elf, "foo", code);

    let a = analyze(&bin).expect("returning image analyzes");
    let entry = a.functions.get(&CODE_VA).expect("entry is a function");
    assert_eq!(entry.blocks.len(), 2);
    assert!(!entry.noreturn);
    assert_eq!(entry.successors(CODE_VA), vec![CODE_VA + 5]);
    let plt = a.functions.get(&stub).expect("stub is a function");
    assert!(!plt.noreturn);
    assert!(cut_sites(&a).is_empty());
}

/// Indirect `call [slot]` to a noreturn PE import cuts too, while the
/// unresolved-call diagnostic stays (the target is still unknown).
#[test]
fn indirect_noreturn_call_cuts_and_keeps_diagnostic() {
    let mut code = vec![0xFF, 0x15];
    code.extend_from_slice(&(SLOT_VA.wrapping_sub(CODE_VA + 6) as u32).to_le_bytes());
    code.extend_from_slice(&[0u8; 16]);
    code.push(0xC3);
    let bin = image_with_import(BinaryFormat::Pe, "ExitProcess", code);

    let a = analyze(&bin).expect("PE image analyzes");
    let entry = a.functions.get(&CODE_VA).expect("entry is a function");
    assert_eq!(entry.blocks.len(), 1, "padding block pruned");
    assert!(entry.noreturn);
    assert_eq!(cut_sites(&a), vec![CODE_VA]);
    assert!(
        a.diagnostics
            .records
            .iter()
            .any(|d| d.addr == CODE_VA && d.kind == DiagnosticKind::UnresolvedIndirectCall)
    );
}

/// No imports needed: a call to a self-looping function cuts, since the
/// callee has no return-reachable exit.
#[test]
fn call_to_loop_is_noreturn() {
    let spin = 0x1006u64;
    let mut bytes = vec![0xE8];
    bytes.extend_from_slice(&((spin - 0x1000 - 5) as u32).to_le_bytes());
    bytes.push(0xC3);
    bytes.extend_from_slice(&[0xEB, 0xFE]);
    let a = analyze_raw(&bytes, 0x1000, Arch::X86_64, Some(0x1000)).expect("raw analyzes");

    let spin_f = a.functions.get(&spin).expect("spin is a function");
    assert!(spin_f.noreturn);
    let main = a.functions.get(&0x1000).expect("main is a function");
    assert_eq!(main.blocks.len(), 1);
    assert!(main.noreturn);
    assert_eq!(cut_sites(&a), vec![0x1000]);
}

const ELF_TEXT_VA: u64 = 0x4000B0;
const ELF_GOT: u64 = 0x401000;
const ELF_PAD: usize = 16;

/// Real ELF64 container: the entry calls an `exit` PLT stub (resolved via
/// `.rela.plt` `JUMP_SLOT`), followed by zero padding. Mirrors the
/// `import_xrefs` fixture with a noreturn name and padding after the call.
fn elf64_with_noreturn_plt() -> Vec<u8> {
    fn put16(v: &mut [u8], off: usize, x: u16) {
        v[off..off + 2].copy_from_slice(&x.to_le_bytes());
    }
    fn put32(v: &mut [u8], off: usize, x: u32) {
        v[off..off + 4].copy_from_slice(&x.to_le_bytes());
    }
    fn put64(v: &mut [u8], off: usize, x: u64) {
        v[off..off + 8].copy_from_slice(&x.to_le_bytes());
    }
    let stub_va = ELF_TEXT_VA + 5 + ELF_PAD as u64;
    let text_len = 5 + ELF_PAD + 6;
    let got_off = 0xD0usize;
    let mut f = vec![0u8; 0xB0];
    f[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    f[4] = 2;
    f[5] = 1;
    f[6] = 1;
    put16(&mut f, 16, 2);
    put16(&mut f, 18, 62);
    put32(&mut f, 20, 1);
    put64(&mut f, 24, ELF_TEXT_VA);
    put64(&mut f, 32, 64);
    put16(&mut f, 52, 64);
    put16(&mut f, 54, 56);
    put16(&mut f, 56, 2);
    put16(&mut f, 58, 64);
    let p = 64;
    put32(&mut f, p, 1);
    put32(&mut f, p + 4, 5);
    put64(&mut f, p + 8, 0);
    put64(&mut f, p + 16, 0x400000);
    put64(&mut f, p + 32, got_off as u64);
    put64(&mut f, p + 40, got_off as u64);
    put64(&mut f, p + 48, 0x1000);
    let p = 64 + 56;
    put32(&mut f, p, 1);
    put32(&mut f, p + 4, 6);
    put64(&mut f, p + 8, got_off as u64);
    put64(&mut f, p + 16, ELF_GOT);
    put64(&mut f, p + 32, 8);
    put64(&mut f, p + 40, 8);
    put64(&mut f, p + 48, 8);
    // Caller: call stub, then padding (no ret: `exit` never returns).
    f.extend_from_slice(&[0xE8]);
    f.extend_from_slice(&((stub_va - ELF_TEXT_VA - 5) as u32).to_le_bytes());
    f.extend_from_slice(&[0u8; ELF_PAD]);
    let disp = (ELF_GOT.wrapping_sub(stub_va + 6)) as u32;
    f.extend_from_slice(&[0xFF, 0x25]);
    f.extend_from_slice(&disp.to_le_bytes());
    while f.len() < got_off {
        f.push(0);
    }
    assert_eq!(f.len(), got_off);
    f.extend_from_slice(&[0u8; 8]);
    let rela_off = f.len();
    let mut rela = Vec::new();
    rela.extend_from_slice(&ELF_GOT.to_le_bytes());
    rela.extend_from_slice(&((1u64 << 32) | 7).to_le_bytes());
    rela.extend_from_slice(&0u64.to_le_bytes());
    f.extend_from_slice(&rela);
    let dynsym_off = f.len();
    f.extend_from_slice(&[0u8; 24]);
    let mut sym = vec![0u8; 24];
    put32(&mut sym, 0, 1);
    sym[4] = 0x12;
    f.extend_from_slice(&sym);
    let dynstr_off = f.len();
    f.extend_from_slice(b"\0exit\0");
    let shstr_off = f.len();
    let shstr = b"\0.text\0.rela.plt\0.dynsym\0.dynstr\0.shstrtab\0";
    f.extend_from_slice(shstr);
    while !f.len().is_multiple_of(8) {
        f.push(0);
    }
    let shoff = f.len();
    let mut sh = |name: u32,
                  ty: u32,
                  flags: u64,
                  addr: u64,
                  off: u64,
                  size: u64,
                  link: u32,
                  info: u32,
                  align: u64,
                  entsize: u64| {
        let mut h = vec![0u8; 64];
        put32(&mut h, 0, name);
        put32(&mut h, 4, ty);
        put64(&mut h, 8, flags);
        put64(&mut h, 16, addr);
        put64(&mut h, 24, off);
        put64(&mut h, 32, size);
        put32(&mut h, 40, link);
        put32(&mut h, 44, info);
        put64(&mut h, 48, align);
        put64(&mut h, 56, entsize);
        f.extend_from_slice(&h);
    };
    sh(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    sh(1, 1, 6, ELF_TEXT_VA, 0xB0, text_len as u64, 0, 0, 1, 0);
    sh(7, 4, 0, 0, rela_off as u64, 24, 3, 0, 8, 24);
    sh(17, 11, 0, 0, dynsym_off as u64, 48, 4, 1, 8, 24);
    sh(25, 3, 0, 0, dynstr_off as u64, 6, 0, 0, 1, 0);
    sh(
        33,
        3,
        0,
        0,
        shstr_off as u64,
        shstr.len() as u64,
        0,
        0,
        1,
        0,
    );
    put64(&mut f, 40, shoff as u64);
    put16(&mut f, 60, 6);
    put16(&mut f, 62, 5);
    f
}

/// End to end over a real container: import resolution, cut, flags, and
/// identical rows on snapshot reopen (the rebuild fixpoint).
#[test]
fn elf_container_noreturn_cut_and_cached_reopen() {
    let bytes = elf64_with_noreturn_plt();
    let stub_va = ELF_TEXT_VA + 5 + ELF_PAD as u64;
    let bin = load(&bytes).expect("synthetic ELF64 must load");
    assert_eq!(bin.imports.len(), 1);
    assert_eq!(bin.imports[0].name, "exit");
    assert_eq!(bin.imports[0].address, Some(ELF_GOT));

    let a = analyze(&bin).expect("synthetic ELF64 must analyze");
    let entry = a.functions.get(&ELF_TEXT_VA).expect("entry is a function");
    assert_eq!(entry.blocks.len(), 1, "padding block pruned");
    assert!(entry.noreturn);
    assert_eq!(
        a.functions
            .get(&stub_va)
            .expect("stub is a function")
            .name
            .as_deref(),
        Some("exit@plt")
    );
    assert!(a.functions.get(&stub_va).expect("stub").noreturn);
    assert_eq!(cut_sites(&a), vec![ELF_TEXT_VA]);

    let dir = tmpdir("noreturn-container");
    let bin_path = write_bin(&dir, "exit.elf", &bytes);
    let db = temp_db(&dir, "exit");
    let rows_of = |db: &std::path::Path| {
        let p = Project::open_with_db(&bin_path, db).expect("project must open");
        let rows = p.functions_filtered(&FunctionFilter::default(), 0, 50);
        let diags = p
            .query_diagnostics(Some(DiagnosticKind::NoreturnCut), None, 0, 50)
            .expect("diagnostics query works");
        (rows, diags.total)
    };
    let (fresh_rows, fresh_diags) = rows_of(&db);
    assert_eq!(fresh_rows.len(), 2);
    assert!(fresh_rows.iter().all(|r| r["noreturn"] == true));
    assert_eq!(fresh_diags, 1);
    // Second open replays the snapshot: rows and diagnostics agree.
    let (cached_rows, cached_diags) = rows_of(&db);
    assert_eq!(cached_rows, fresh_rows);
    assert_eq!(cached_diags, fresh_diags);
    cleanup(&dir);
}
