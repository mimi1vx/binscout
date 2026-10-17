//! M3 IR: minimal P-code-inspired lift over [`Insn`].
//!
//! One machine instruction lifts to one [`IrInsn`]. The `Vec` return reserves
//! multi-op expansion (e.g. `push` as adjust-plus-store); M3 always emits a
//! single element. Operands reuse the disassembler's strings verbatim and
//! `target` carries direct branch/call destinations from
//! [`Insn::branch_target`]. Flag and stack-pointer effects are scoped:
//! integer add/sub/cmp record [`IrEffects::sets_flags`] and x86
//! push/pop/call/operand-free-ret record [`IrEffects::sp_delta`];
//! everything else reports none (see [`IrEffects`] for the bounds).
//!
//! [`IrOp::Phi`] is never emitted by these lifters; M4 synthesizes it at CFG
//! merges. Unknown mnemonics become [`IrOp::Nop`] with `warning` set instead
//! of failing, so analysis can proceed over partial lifts.
//!
//! # ISA coverage
//!
//! `lift_x86` covers both 32- and 64-bit x86 (same mnemonic table; only the
//! decoder differs). The `rep`/`repe`/`repne`/`lock` prefixes are stripped by
//! the disassembler, so prefixed string/atomic operations lift as their core
//! mnemonic (`rep movsb` lifts as `movsb`):
//!
//! - `COPY`: `mov`, `movsx`, `movsxd`, `movzx`, `movabs`, `movbe`, `xchg`,
//!   `leave`, `enter`, `cbw`/`cwde`/`cdqe`/`cdq`/`cqo`, `bswap`, all 16
//!   `cmovcc`/`setcc` forms, `movs`/`movsb`/`movsw`/`movsd`/`movsq`, scalar
//!   and packed SSE/AVX moves (`movss`, `movaps`, `movups`, `movdqa`,
//!   `vmovaps`, ...), shuffles and unpacks (`shufps`, `pshufb`, `unpcklps`,
//!   `vshufps`, ...), inserts/extracts/broadcasts/converts (`pinsrw`,
//!   `vextractps`, `vbroadcastss`, `vpmovsxbw`, ...), `bextr`/`pdep`/`pext`,
//!   x87 `fld1`/`fabs`/`fxch`/`fcmovcc`/`fnstsw`, `rdtsc`/`rdtscp`/`rdpmc`,
//!   `rdrand`/`rdseed`, `xgetbv`.
//! - `LOAD`: `pop`, `popa`, `popad`, `popf`/`popfd`/`popfq`, `lods*`,
//!   `xlat`, `in`/`ins*`, `movntdqa`, x87 `fld`/`fild`/`fbld`/`fldenv`/
//!   `fldcw`, `frstor`/`fxrstor`/`xrstor` (x87 stack/control effects
//!   unmodeled).
//! - `STORE`: `push`, `pusha`, `pushad`, `pushf`/`pushfd`/`pushfq`,
//!   `stos*`, `out`/`outs*`, nontemporal `movnt*`/`vmovnt*`, x87
//!   `fst`/`fstp`/`fist*`/`fbstp`/`fnstcw`/`fnstenv`/`fnsave`/`fxsave`/
//!   `xsave`.
//! - `ADD`: `add`, `adc`, `adcx`, `adox`, `lea` (address math, not a load),
//!   `inc`, x87 `fadd`/`faddp`/`fiadd`, packed `addps`/`addpd`/`addss`/
//!   `addsd`/`paddb`-`paddq`/`haddps`/`phaddw` plus `v`-prefixed AVX forms.
//!   `SUB`: `sub`, `sbb`, `dec`, `neg`, x87 `fsub`/`fsubp`/`fsubr`/
//!   `fisub`/`fisubr`, packed `subps`/`psubb`-`psubq`/`hsubps`/`phsubw` plus
//!   AVX, `psadbw`/`mpsadbw` (+`v` forms). `MUL`: `mul`, `imul`, `mulx`,
//!   x87 `fmul`/`fmulp`/`fimul`, packed `mulps`/`pmullw`/`pmulld`/
//!   `pmuludq`/`pmulhw`/`pmaddwd` plus AVX, and 48 FMA `vfmadd*`/`vfmsub*`/
//!   `vfnmadd*`/`vfnmsub*` forms. `DIV`: `div`, `idiv`, x87
//!   `fdiv`/`fdivp`/`fdivr`/`fidiv`/`fidivr`, packed `divps` plus AVX.
//!   `AND`: `and`, `pand`/`vpand`, `pandn`/`vpandn`, `andps`/`andpd`/
//!   `vandps`/`vandpd`, `andn`, `blsi`/`blsr`/`bzhi`. `OR`: `or`,
//!   `por`/`vpor`, `orps`/`orpd`/`vorps`/`vorpd`. `XOR`: `xor`, `pxor`/
//!   `vpxor`, `not`, `xorps`/`xorpd`/`vxorps`/`vxorpd`, `blsmsk`, AES
//!   (`aesenc`, `aesenclast`, `aesdec`, `aesdeclast`, `aeskeygenassist`,
//!   `aesimc`), `pclmulqdq` (all four imm-folded spellings), SHA
//!   (`sha1msg1`, `sha1msg2`, `sha1nexte`, `sha1rnds4`, `sha256rnds2`,
//!   `sha256msg1`, `sha256msg2`), `crc32` (crypto folded to XOR).
//!   `SHL`: `shl`, `sal`, `shld`, `shlx`, `psllw`/`pslld`/`psllq`/
//!   `pslldq` plus AVX. `SHR`: `shr`, `sar`, plus rotates `rol`, `ror`,
//!   `rcl`, `rcr` (approximated as shifts; exact bit motion is out of
//!   scope), `shrd`, `sarx`/`shrx`/`rorx`, `psrlw`/`psrld`/`psrlq`/
//!   `psrldq`, `psraw`/`psrad` plus AVX, `palignr`/`vpalignr`.
//! - `CMP`: `cmp`, `test`, string `cmps*`/`scas*`, `comiss`/`comisd`/
//!   `ucomiss`/`ucomisd` (+`v` forms), `vtestps`/`vtestpd`/`vptest`,
//!   imm-folded `cmp<cc>ps`/`pd`/`ss`/`sd` and `vcmp<cc>*` pseudo-ops
//!   (`cmpeqps`, `vcmpltps`, ...), x87 `fcom`/`fcomp`/`fcompp`/`fucom*`/
//!   `fcomi*`/`fucomi*`/`ftst`/`fxam`/`ficom`/`ficomp`, `pcmpeqb`-`pcmpgtq`
//!   (+`v` forms), `pcmpestri`/`pcmpistri` (+`m` forms), `phminposuw`/
//!   `vphminposuw`.
//! - `BRANCH`: direct `jmp` (indirect keeps operands, no target).
//!   `CBRANCH`: all `jcc` forms plus `jcxz`/`jecxz`/`jrcxz` and
//!   `loop`/`loope`/`loopne`. `CALL`: `call`, `syscall`, `sysenter`, `int`,
//!   `int3`. `RETURN`: `ret`, `retn`, `retf`, `iret`, `iretd`, `iretq`,
//!   `sysret`, `sysexit`.
//! - `NOP`: `nop`, `pause`, `hlt`, `fwait`, `endbr32`, `endbr64`, fences
//!   (`mfence`, `lfence`, `sfence`), `clflush`/`clflushopt`/`clwb`, `emms`,
//!   `femms`, `prefetch*`, flag-only `clc`/`stc`/`cmc`/`cld`/`std`/`cli`/
//!   `sti`/`clac`/`stac`/`lahf`/`sahf`, `monitor`/`mwait`, `vzeroupper`/
//!   `vzeroall`, x87 `fnop`/`ffree`/`fdecstp`/`fincstp`/`fnclex`/`fninit`.
//!   Still unmapped by design: `cpuid`, `popcnt`/`tzcnt`/`lzcnt`/`bsf`/
//!   `bsr` (bit counts/scans), `cmpxchg`/`xadd` (conditional/atomic RMW),
//!   `ud2`, x87 transcendentals.
//!
//! `lift_aarch64` covers A64 mnemonics as printed by the disassembler (which
//! folds common aliases: `movz`/`movn`/`orr`-with-zero print as `mov`,
//! `orn`/`not` print as `mvn`, `adds`-with-zero-dest prints as `cmn`,
//! `sbc`-with-zero prints as `ngc`, `madd`-with-zero prints as `mul`,
//! `csinc`-with-zero prints as `cset`, `ubfm`/`sbfm`/`bfm` always print as
//! `lsl`/`lsr`/`asr`/`sxtb`/`ubfx`/`bfi`/..., `lslv`/`lsrv`/`asrv`/`rorv`
//! print as `lsl`/`lsr`/`asr`/`ror`, and `dmb`/`dsb` carry their option in
//! the operands, not the mnemonic):
//!
//! - `COPY`: `mov`, `movz`, `movn`, `movk`, `mvn`, `movi`, `dup`, `smov`,
//!   `umov`, `adr`, `adrp`, `ext`, `tbl`, `tbx`, `uzp1`/`uzp2`, `trn1`/
//!   `trn2`, `zip1`/`zip2`, `rev`/`rev16`/`rev32`/`rev64`, `rbit`,
//!   `csel`/`csinc`/`csinv`/`csneg` (plus `cinc`/`cset`/`cinv`/`csetm`/
//!   `cneg` spellings), `fcsel`, `uxtb`/`uxth`/`sxtb`/`sxth`/`sxtw`,
//!   `ubfx`/`sbfx`/`ubfiz`/`sbfiz`/`bfc`/`bfi`/`bfxil`, `extr`, `clz`,
//!   `cls`, `cnt`, `abs`, `sqabs`, narrowing `xtn`/`xtn2`/`sqxtn`/
//!   `sqxtn2`/`sqxtun`/`sqxtun2`/`uqxtn`/`uqxtn2`, FP `fmov`/`fabs`,
//!   `scvtf`/`ucvtf`, `fcvt`/`fcvtl`/`fcvtn`/`fcvtxn`/`fcvtns`/`fcvtnu`/
//!   `fcvtps`/`fcvtpu`/`fcvtms`/`fcvtmu`/`fcvtas`/`fcvtau`/`fcvtzs`/
//!   `fcvtzu`/`fjcvtzs`/`bfcvt`, `frint*`, min/max selects (`fmax`/`fmin`/
//!   `fmaxnm`/`fminnm`/`smax`/`smin`/`umax`/`umin` and `p`/`v` forms),
//!   `frecpe`/`frecps`/`frecpx`/`frsqrte`/`frsqrts`, atomic swaps
//!   (`swp*`, store half unmodeled), atomic max/min (`ldsmax*`/
//!   `ldsmin*`/`ldumax*`/`ldumin*`, store half unmodeled).
//! - `LOAD`: `ldr`, `ldp`, `ldpsw`, `ldur`, `ldrb`, `ldrh`, `ldrsb`,
//!   `ldrsh`, `ldrsw`, unscaled `ldurb`-`ldursw`, unprivileged
//!   `ldtr`-`ldtrsw`, acquire/exclusive `ldar*`/`ldaxr*`/`ldxr*`/`ldlar*`/
//!   `ldapr*`/`ldapur*`, `ldnp`, SIMD `ld1`-`ld4`/`ld1r`-`ld4r`,
//!   pointer-authenticated `ldraa`/`ldrab`. `STORE`: `str`, `stp`, `stur`,
//!   `strb`, `strh`, unscaled `sturb`/`sturh`, unprivileged `sttr*`,
//!   release/exclusive `stlr*`/`stxr*`/`stllr*`/`stlur*`, `stnp`, SIMD
//!   `st1`-`st4`, store-only atomics (`stadd*`, `stclr*`, `stset*`,
//!   `steor*`, `stsmax*`, `stsmin*`, `stumax*`, `stumin*`; read-modify-write
//!   folded to STORE, ALU part unmodeled).
//! - `ADD`: `add`, `adds`, `adc`, `adcs`, FP `fadd`/`faddp`, `fcadd`, `addv`, `saddlv`/`uaddlv`, `saddlp`/`sadalp`/
//!   `uaddlp`/`uadalp`, `addp`, long `saddl`/`saddw`/`uaddl`/`uaddw` (+`2`),
//!   halving `shadd`/`uhadd`/`srhadd`/`urhadd`, saturating `sqadd`/
//!   `uqadd`/`suqadd`/`usqadd`, `saba`/`uaba`, narrowing `addhn`/
//!   `raddhn` (+`2`), atomic `ldadd*`. `SUB`: `sub`, `subs`, `sbc`,
//!   `sbcs`, `neg`, `negs`, `ngc`, `ngcs`, `fsub`, `fneg`, `sqneg`,
//!   `fabd`, long `ssubl`/`ssubw`/`usubl`/`usubw` (+`2`), halving
//!   `shsub`/`uhsub`, saturating `sqsub`/`uqsub`, `sabd`/`uabd`,
//!   narrowing `subhn`/`rsubhn` (+`2`), `sabdl`/`uabdl` (+`2`), `subp`/
//!   `subps`. `MUL`: `mul`, `madd`, `msub`, `mneg`, `mla`, `mls`,
//!   `smaddl`/`smsubl`/`umaddl`/`umsubl`, `smnegl`/`umnegl`, `smull`,
//!   `smulh`, `umull`, `umulh` (+`2`/`l2` long forms, `smlal`/`smlsl`/
//!   `umlsl` families), FP `fmul`/`fmulx`, `fmla`/`fmls`/`fmlal`/`fmlsl`/
//!   `fcmla` (+`2`), `fmadd`/`fmsub`/`fnmadd`/`fnmsub`/`fnmul`,
//!   polynomial `pmul`/`pmull`/`pmull2`, dot products `sdot`/`udot`,
//!   saturating `sqdmulh`/`sqrdmulh`/`sqdmull`/`sqdmlal`/`sqdmlsl`/
//!   `sqrdmlah`/`sqrdmlsh` (+`2`). `DIV`: `sdiv`, `udiv`, `fdiv`.
//!   `AND`: `and`, `ands`, `bic`, `bics`, atomic `ldclr*`. `OR`: `orr`,
//!   `orn`, bitwise selects `bsl`/`bit`/`bif`, atomic `ldset*`. `XOR`:
//!   `eor`, `eon`, `mvni`, `eor3`, `bcax`, `rax1`, `xar`, AES
//!   (`aese`/`aesd`/`aesmc`/`aesimc`), SHA-1/SHA-2/SHA-512
//!   (`sha1c`/`sha1h`/`sha1m`/`sha1p`/`sha1su0`/`sha1su1`/`sha256h`/
//!   `sha256h2`/`sha256su0`/`sha256su1`/`sha512h`/`sha512h2`/`sha512su0`/
//!   `sha512su1`), SM3/SM4 (`sm3tt1a`-`sm3ss1`, `sm4e`/`sm4ekey`), CRC
//!   (`crc32b`/`crc32h`/`crc32w`/`crc32x` and `cb`/`ch`/`cw`/`cx`),
//!   atomic `ldeor*` (crypto folded to XOR). `SHL`: `lsl`, `lslv`, `shl`,
//!   `sshl`/`ushl`/`srshl`/`urshl`/`sqrshl`/`uqrshl`, saturating
//!   `sqshl`/`uqshl`/`sqshlu`, `sli`, long `shll`/`sshll`/`ushll` (+`2`).
//!   `SHR`: `lsr`, `lsrv`, `asr`, `asrv`, `ror`, `rorv`, `ushr`/`sshr`/
//!   `urshr`/`srshr`, accumulate `usra`/`ssra`/`ursra`/`srsra`, `sri`,
//!   narrowing `shrn`/`rshrn`/`sqshrn`/`sqrshrn`/`sqshrun`/`sqrshrun`/
//!   `uqshrn`/`uqrshrn` (+`2`).
//! - `CMP`: `cmp`, `cmn`, `tst`, `ccmn`, `ccmp`, `cmtst`, FP `fcmp`/
//!   `fcmpe`/`fccmp`/`fccmpe`, vector `cmeq`/`cmgt`/`cmge`/`cmle`/
//!   `cmlt`/`cmhi`/`cmhs`/`cmtst`, FP `fcmeq`/`fcmge`/`fcmgt`/`fcmle`/
//!   `fcmlt`/`facge`/`facgt`, compare-and-swap `cas*` (conditional store
//!   unmodeled). `BRANCH`: direct `b`, indirect `br`/`braa`/`brab`/
//!   `braaz`/`brabz` (indirect keeps operands).
//!   `CBRANCH`: `cbz`, `cbnz`, `tbz`, `tbnz`, `b.<cond>`, `bc.<cond>`.
//!   `CALL`: direct `bl`, indirect `blr`/`blraa`/`blrab`/`blraaz`/
//!   `blrabz` (indirect keeps operands) plus `svc`,
//!   `hvc`, `smc`. `RETURN`: `ret`, `eret`, `retaa`/`retab`/
//!   `eretaa`/`eretab`. `NOP`: `nop`, `hint`,
//!   `dmb`, `dsb`, `isb`, `brk`, `hlt`, barriers `sb`/`ssbb`/`pssbb`,
//!   `clrex`, waits/events `wfe`/`wfi`/`sev`/`sevl`/`yield`,
//!   `esb`/`csdb`/`psb`/`tsb`, prefetches `prfm`/`prfum`, `sys`/`sysl`,
//!   flag sets `rmif`/`setf8`/`setf16`, `dcps1`-`dcps3`/`drps`. Still
//!   unmapped by design: `mrs`/`msr` (system registers), `udf`, remaining
//!   pointer authentication (sign/auth/strip, `retaasppc`-family), MTE tags.
//!
//! `lift_arm32` covers ARMv7/ARM32 and Thumb mnemonics as printed by the
//! disassembler (one `.w`/`.n` width suffix, one condition suffix, and one
//! flag `s` stripped first; the decoder has no VFP/NEON or media
//! instructions, so those stay unmapped rather than mislifting):
//!
//! - `COPY`: `mov`, `movw`, `movt`, `mvn`, `adr`, `swp`, `swpb`, `clz`,
//!   `rev`, `rev16`, `revsh`, `sxth`, `sxtb`, `uxth`, `uxtb`. `LOAD`:
//!   `ldr`, `ldrb`, `ldrh`, `ldrsb`, `ldrsh`, `ldrd`, `ldm` (plus `ldmia`/
//!   `ldmdb`/`ldmda`), unprivileged `ldrt`/`ldrbt`/`ldrht`/`ldrsbt`/
//!   `ldrsht`, exclusives `ldrex`/`ldrexb`/`ldrexh`/`ldrexd`
//!   (`pop`/`ldm*` naming `pc` lifts to `RETURN`, or `CBRANCH` when
//!   conditioned). `STORE`: `str`, `strb`, `strh`, `strd`, `stm` (plus
//!   `stmia`/`stmdb`/`stmda`), unprivileged `strt`/`strbt`/`strht`,
//!   exclusives `strex`/`strexb`/`strexh`/`strexd`, `push`.
//! - `ADD`: `add`, `adc`, saturating `qadd`, `qdadd`, `qadd16`, `qadd8`,
//!   `uqadd16`, `uqadd8`. `SUB`: `sub`, `sbc`, `rsb`, `rsc`, saturating
//!   `qsub`, `qdsub`, `qsub16`, `qsub8`, `uqsub16`, `uqsub8`. `MUL`:
//!   `mul`, `mla`, `umaal`, `mls`, halfword `smlabb`/`smlabt`/`smlatb`/
//!   `smlatt`, `smlawb`/`smlawt`, `smulbb`/`smulbt`/`smultb`/`smultt`,
//!   `smlalbb`/`smlalbt`/`smlaltb`/`smlaltt`. `DIV`: `sdiv`, `udiv`
//!   (Thumb only; ARM-mode divide is outside the decoder). `AND`: `and`,
//!   `bic`. `OR`: `orr`, `orn`. `XOR`: `eor`. `SHL`: `lsl`. `SHR`:
//!   `lsr`, `asr`, `ror`, `rrx`.
//! - `CMP`: `cmp`, `cmn`, `tst`, `teq`. `BRANCH`: plain `b`/`bx` (indirect
//!   keeps operands), `tbb`/`tbh`. `CBRANCH`: conditioned `b`/`bx`,
//!   `cbz`/`cbnz`. `CALL`: direct `bl`/`blx` (indirect keeps operands) plus
//!   `svc`, `hvc`, `smc`. `RETURN`: `pop`/`ldm*` with `pc`, plain `bx lr`.
//!   `NOP`: `nop`, `dmb`, `dsb`, `isb`, `bkpt`, `it`, `hint`, `wfe`/
//!   `wfi`/`sev`/`yield`, `cpsid`/`cpsie`, `setend`, `dbg` (mostly Thumb;
//!   ARM-mode hints/barriers are outside the decoder).
//!
//! # Warning semantics
//!
//! Lifting never fails: a mnemonic outside all tables (e.g. x86 `cpuid`,
//! ARM `mrs`) lifts to [`IrOp::Nop`] with `warning` set to
//! `"unlifted '<mnem>'; emitted NOP"`. `warning` is `None` for every mapped
//! mnemonic, so `warning.is_some()` exactly marks approximate coverage.
//! Downstream passes treat unlifted instructions as fall-through (`Seq`),
//! never as control flow.
//!
//! JSON pairs `addr` with `addr_hex` and `target` with `target_hex`
//! (see [`crate::addr_hex`]).
use serde::{Deserialize, Serialize};

use crate::disasm::{Arch, Insn, resolve_adrp_pair};

/// Minimal P-code-inspired operation set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IrOp {
    /// Register-to-register or memory-to-register copy.
    Copy,
    /// Memory read.
    Load,
    /// Memory write.
    Store,
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
    /// Division.
    Div,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Logical left shift.
    Shl,
    /// Logical right shift.
    Shr,
    /// Comparison (integer forms record flag writes; see [`IrEffects`]).
    Cmp,
    /// Unconditional direct branch.
    Branch,
    /// Conditional direct branch.
    CBranch,
    /// Direct call.
    Call,
    /// Function return.
    Return,
    /// Merge value, synthesized at CFG joins (never lifted).
    Phi,
    /// Unmapped or effect-free operation.
    Nop,
}

impl IrOp {
    /// Uppercase opcode name (`COPY`, `LOAD`, ...).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Copy => "COPY",
            Self::Load => "LOAD",
            Self::Store => "STORE",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Div => "DIV",
            Self::And => "AND",
            Self::Or => "OR",
            Self::Xor => "XOR",
            Self::Shl => "SHL",
            Self::Shr => "SHR",
            Self::Cmp => "CMP",
            Self::Branch => "BRANCH",
            Self::CBranch => "CBRANCH",
            Self::Call => "CALL",
            Self::Return => "RETURN",
            Self::Phi => "PHI",
            Self::Nop => "NOP",
        }
    }

    /// Whether this op transfers control.
    #[must_use]
    pub fn is_control(self) -> bool {
        matches!(
            self,
            Self::Branch | Self::CBranch | Self::Call | Self::Return
        )
    }
}

/// Scoped per-instruction flag/stack effects over [`IrInsn`].
///
/// The [`IrOp`] set stays unchanged: effects ride along as data so existing
/// consumers keep working. Only the first scope is modeled:
/// [`IrEffects::sets_flags`] for integer add/sub/cmp and
/// [`IrEffects::sp_delta`] for x86 push/pop/call/operand-free-ret.
///
/// Still unmodeled: FP/SIMD/vector ALU flag writes (`fadd`, `addps`,
/// `paddb`, ... report no flags although they lift as `Add`), `lea`
/// (address math, never flags), x87 FPU-condition writers (`fcom`,
/// `ftst`, `fxam`, `ficom`, packed mask writers like `pcmpeqb`, and the
/// imm-folded `cmp<cc>`/`vcmp<cc>` pseudo-ops, which target the FPU status
/// word or a mask register instead of EFLAGS/NZCV), flag reads
/// (`adc`/`sbb`/`rsc` carry-in, `cmovcc`/`setcc` conditions), preserved
/// bits (`inc`/`dec` keep CF yet report `sets_flags`), ARM saturating `Q`
/// effects (`qadd`/`qsub`), `ret` with an immediate (extra argument pop),
/// far/privileged returns (`retf`, `iret*`) and traps
/// (`syscall`/`sysenter`/`int`, `svc`/`hvc`/`smc`), ARM multi-register
/// push/pop (the delta needs register-list decoding, so they report
/// `None`), AArch64 `bl`/`blr`/`ret` (link-register moves, no SP effect),
/// and calling-convention frame effects (`enter`/`leave`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IrEffects {
    /// Whether the instruction writes condition flags in the common
    /// integer case: x86 EFLAGS or ARM NZCV.
    ///
    /// True only for the curated integer writers (x86 `add`/`adc`/`sub`/
    /// `sbb`/`inc`/`dec`/`neg`/`cmp`/`test`/`bt`, string compares, and the
    /// EFLAGS-writing FP compares `comiss*`/`vtest*`/`vptest`/`fcomi*`;
    /// AArch64 `adds`/`adcs`/`subs`/`sbcs`/`negs`/`ngcs` and
    /// `cmp`/`cmn`/`tst`/`ccmp`/`ccmn`/`cmtst`/`fcmp*`; ARM32/Thumb
    /// compares and `s`-suffixed add/sub). Every other mnemonic reports
    /// false, including FP/SIMD ALU forms that lift as `Add`/`Sub`/`Cmp`.
    pub sets_flags: bool,
    /// Signed stack-pointer delta in bytes (`None` means no effect or an
    /// unmodeled one).
    ///
    /// Only x86 reports values: `push`/`pop`/`pushf*`/`popf*` move one
    /// slot (-/+8 on x86-64, -/+4 on x86-32), `pusha`/`popa` move 16 and
    /// `pushad`/`popad` 32, `call` pushes one return slot, and
    /// operand-free `ret`/`retn` pop one. Assigned by [`lift`], which owns
    /// the arch context: [`lift_x86`] is mode-agnostic by design (one
    /// table for both x86 modes), so its direct rows carry flags only.
    pub sp_delta: Option<i64>,
}

/// One lifted IR operation.
///
/// JSON pairs `addr` with `addr_hex` and `target` with `target_hex`
/// (see [`crate::addr_hex`]); old rows without the twins still
/// deserialize. Rows written before effects existed (no `effects` key)
/// also still deserialize, defaulting to no modeled effects.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct IrInsn {
    /// Address of the source machine instruction.
    pub addr: u64,
    /// Lifted operation.
    pub op: IrOp,
    /// Input operands (disassembler strings).
    pub inputs: Vec<String>,
    /// Output operands (disassembler strings).
    pub outputs: Vec<String>,
    /// Absolute target for direct branches/calls, if any.
    pub target: Option<u64>,
    /// Set when the mnemonic had no mapping and `op` fell back to [`IrOp::Nop`].
    pub warning: Option<String>,
    /// Scoped flag/stack effects (see [`IrEffects`]).
    ///
    /// Defaults to no modeled effects so pre-effect rows still decode.
    #[serde(default)]
    pub effects: IrEffects,
}

impl Serialize for IrInsn {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("IrInsn", 8)?;
        st.serialize_field("addr", &self.addr)?;
        st.serialize_field("addr_hex", &crate::addr_hex(self.addr))?;
        st.serialize_field("op", &self.op)?;
        st.serialize_field("inputs", &self.inputs)?;
        st.serialize_field("outputs", &self.outputs)?;
        st.serialize_field("target", &self.target)?;
        st.serialize_field("target_hex", &self.target.map(crate::addr_hex))?;
        st.serialize_field("warning", &self.warning)?;
        st.serialize_field("effects", &self.effects)?;
        st.end()
    }
}

/// Lift one instruction for its architecture.
///
/// Flag effects come from the per-arch lifters; stack-slot magnitudes need
/// the mode, so `sp_delta` is assigned here where the arch is known
/// (see [`IrEffects::sp_delta`]).
#[must_use]
pub fn lift(arch: Arch, insn: &Insn) -> Vec<IrInsn> {
    let mut rows = match arch {
        Arch::X86_64 | Arch::X86_32 => lift_x86(insn),
        Arch::Aarch64 => lift_aarch64(insn),
        Arch::Arm32 | Arch::Thumb => lift_arm32(insn),
    };
    if let [row] = rows.as_mut_slice()
        && row.warning.is_none()
    {
        row.effects.sp_delta = sp_delta_for(arch, insn);
    }
    rows
}

/// Lift a decoded range, preserving order.
///
/// AArch64 pairs thread the immediate predecessor so an `adrp`+`add`/`ldr`
/// second row carries its resolved address (see
/// [`lift_aarch64_with_prev`]); every other arch lifts each instruction
/// independently.
#[must_use]
pub fn lift_range(arch: Arch, insns: &[Insn]) -> Vec<IrInsn> {
    if arch != Arch::Aarch64 {
        return insns.iter().flat_map(|i| lift(arch, i)).collect();
    }
    let mut out = Vec::new();
    for (idx, insn) in insns.iter().enumerate() {
        let prev = idx.checked_sub(1).and_then(|p| insns.get(p));
        let mut rows = lift_aarch64_with_prev(insn, prev);
        if let [row] = rows.as_mut_slice()
            && row.warning.is_none()
        {
            row.effects.sp_delta = sp_delta_for(arch, insn);
        }
        out.extend(rows);
    }
    out
}

/// Control-flow effect of one instruction, without lifting.
///
/// Returns the control operation plus its direct target for branches,
/// calls, and returns, or `None` when the instruction falls through
/// (lifts to anything but [`IrOp::Branch`]/[`IrOp::CBranch`]/
/// [`IrOp::Call`]/[`IrOp::Return`], including unmapped mnemonics).
/// Same outcome as `lift(arch, insn).first()` restricted to the control
/// ops, with no allocation: only the small control-flow tables are
/// consulted, never the full data-movement/ALU tables, and no operand
/// strings are cloned. Hot walker paths call this instead of [`lift`].
#[must_use]
pub fn control_op(arch: Arch, insn: &Insn) -> Option<(IrOp, Option<u64>)> {
    match arch {
        Arch::X86_64 | Arch::X86_32 => {
            let mnem = insn.mnem.as_str();
            if mnem == "jmp" {
                Some((IrOp::Branch, insn.branch_target))
            } else if is_x86_jcc(mnem) {
                Some((IrOp::CBranch, insn.branch_target))
            } else if is_x86_call(mnem) {
                Some((IrOp::Call, insn.branch_target))
            } else if is_x86_return(mnem) {
                Some((IrOp::Return, None))
            } else {
                None
            }
        }
        Arch::Aarch64 => {
            let mnem = insn.mnem.as_str();
            if matches!(mnem, "b" | "br" | "braa" | "brab" | "braaz" | "brabz") {
                Some((IrOp::Branch, insn.branch_target))
            } else if is_arm_cbranch(mnem) {
                Some((IrOp::CBranch, insn.branch_target))
            } else if matches!(mnem, "bl" | "blr" | "blraa" | "blrab" | "blraaz" | "blrabz") {
                Some((IrOp::Call, insn.branch_target))
            } else if is_arm_call(mnem) {
                Some((IrOp::Call, None))
            } else if is_arm_return(mnem) {
                Some((IrOp::Return, None))
            } else {
                None
            }
        }
        Arch::Arm32 | Arch::Thumb => {
            let (base, cond) = split_arm_mnem(&insn.mnem);
            // Same guards and outcomes as `lift_arm32`'s `pc`-write rule.
            if !is_arm32_store(base)
                && !is_arm32_branch(base)
                && !is_arm32_ldm(base)
                && arm32_dest_is_pc(insn)
            {
                if base == "mov" && !cond {
                    return Some((IrOp::Return, None));
                } else if cond {
                    return Some((IrOp::CBranch, None));
                } else {
                    return Some((IrOp::Branch, insn.branch_target));
                }
            }
            if is_arm32_ldm(base) && ops_contain_pc(insn) {
                if cond {
                    return Some((IrOp::CBranch, None));
                } else {
                    return Some((IrOp::Return, None));
                }
            }
            match base {
                "b" if cond => Some((IrOp::CBranch, insn.branch_target)),
                "b" => Some((IrOp::Branch, insn.branch_target)),
                "bl" | "blx" => Some((IrOp::Call, insn.branch_target)),
                "bx" if !cond && insn.ops.as_slice() == ["lr"] => Some((IrOp::Return, None)),
                "bx" if cond => Some((IrOp::CBranch, None)),
                "bx" => Some((IrOp::Branch, insn.branch_target)),
                "cbz" | "cbnz" => Some((IrOp::CBranch, insn.branch_target)),
                "tbb" | "tbh" => Some((IrOp::Branch, None)),
                _ if is_arm32_call(base) => Some((IrOp::Call, None)),
                _ => None,
            }
        }
    }
}

/// Whether `mnem` has a lift mapping for `arch`.
///
/// Anything else lifts to fallback [`IrOp::Nop`] with a warning instead of
/// failing, so `!is_mapped(..)` exactly predicts `warning.is_some()` on the
/// lifted row. ARM32/Thumb reduce the mnemonic through suffix stripping
/// first, so conditioned/suffixed forms (`addeq`, `bl.w`) count as mapped.
#[must_use]
pub fn is_mapped(arch: Arch, mnem: &str) -> bool {
    match arch {
        Arch::X86_64 | Arch::X86_32 => {
            is_x86_copy(mnem)
                || is_x86_load(mnem)
                || is_x86_store(mnem)
                || is_x86_alu(mnem, IrOp::Add)
                || is_x86_alu(mnem, IrOp::Sub)
                || is_x86_alu(mnem, IrOp::Mul)
                || is_x86_alu(mnem, IrOp::Div)
                || is_x86_alu(mnem, IrOp::And)
                || is_x86_alu(mnem, IrOp::Or)
                || is_x86_alu(mnem, IrOp::Xor)
                || is_x86_alu(mnem, IrOp::Shl)
                || is_x86_alu(mnem, IrOp::Shr)
                || is_x86_cmp(mnem)
                || mnem == "jmp"
                || is_x86_jcc(mnem)
                || is_x86_call(mnem)
                || is_x86_return(mnem)
                || is_x86_nop(mnem)
        }
        Arch::Aarch64 => {
            is_arm_copy(mnem)
                || is_arm_load(mnem)
                || is_arm_store(mnem)
                || is_arm_alu(mnem, IrOp::Add)
                || is_arm_alu(mnem, IrOp::Sub)
                || is_arm_alu(mnem, IrOp::Mul)
                || is_arm_alu(mnem, IrOp::Div)
                || is_arm_alu(mnem, IrOp::And)
                || is_arm_alu(mnem, IrOp::Or)
                || is_arm_alu(mnem, IrOp::Xor)
                || is_arm_alu(mnem, IrOp::Shl)
                || is_arm_alu(mnem, IrOp::Shr)
                || ARM_CMP.contains(&mnem)
                || matches!(
                    mnem,
                    "b" | "br"
                        | "braa"
                        | "brab"
                        | "braaz"
                        | "brabz"
                        | "bl"
                        | "blr"
                        | "blraa"
                        | "blrab"
                        | "blraaz"
                        | "blrabz"
                )
                || is_arm_cbranch(mnem)
                || is_arm_call(mnem)
                || is_arm_return(mnem)
                || is_arm_nop(mnem)
        }
        Arch::Arm32 | Arch::Thumb => arm_base_mnem(split_arm_mnem(mnem).0),
    }
}

/// How completely one [`IrOp`] family is lifted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageStatus {
    /// Every listed member lifts; notes may still bound the semantics.
    Implemented,
    /// Listed members lift, but known effects are approximated or dropped.
    Partial,
    /// Never produced by the lifters (only [`IrOp::Phi`]).
    Unmapped,
}

/// One lifted family's machine-readable coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyCoverage {
    /// Lifted operation.
    pub op: IrOp,
    /// Whether the family is fully, partially, or never lifted.
    pub status: CoverageStatus,
    /// Liftable mnemonics (ARM32/Thumb: base forms before suffix stripping).
    pub mnemonics: Vec<String>,
    /// Non-literal members (e.g. AArch64 `b.<cond>`).
    pub patterns: Vec<String>,
    /// Bounds that keep `implemented` from meaning semantically complete.
    pub note: Option<String>,
}

/// The unknown-mnemonic rule: unmapped input stays [`IrOp::Nop`] with a
/// warning, distinguishable from a genuine `NOP`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackCoverage {
    /// Always [`IrOp::Nop`].
    pub op: IrOp,
    /// Always [`CoverageStatus::Unmapped`].
    pub status: CoverageStatus,
    /// Warning template (`<mnem>` is the unmapped mnemonic).
    pub warning: String,
    /// How to tell fallback NOP from a genuine one.
    pub distinguish: String,
}

/// Machine-readable lift coverage for one architecture: the [`coverage`]
/// query's row shape.
///
/// This is the machine-readable form of the ISA tables in the module docs,
/// built from the same slices the dispatch predicates consult, so it cannot
/// drift from the lifters. `implemented` never means semantically complete:
/// see `limitations` plus each family's `status`/`note`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// Architecture name (`x86_64`, `x86_32`, `aarch64`, `arm32`, `thumb`).
    pub arch: String,
    /// Per-operation families in [`IrOp`] declaration order.
    pub families: Vec<FamilyCoverage>,
    /// Engine-wide bounds (operand strings, flags, stack effects, no SSA).
    pub limitations: Vec<String>,
    /// The unknown-mnemonic rule.
    pub fallback: FallbackCoverage,
    /// Arch-wide mnemonic reading rule, if any (ARM32/Thumb suffixes).
    pub arch_note: Option<String>,
}

/// Engine-wide lift limitations shared by every architecture.
pub const COVERAGE_LIMITATIONS: &[&str] = &[
    "operands reuse the disassembler's strings verbatim; no operand decoding beyond that",
    "flag effects are scoped: integer add/sub/cmp record sets_flags (x86 EFLAGS writers, ARM NZCV writers); FP/SIMD/vector forms, lea, x87 FPU-condition writers, flag reads (adc/sbb carry-in), and preserved bits (inc/dec keep CF) are unmodeled",
    "stack effects are scoped: x86 push/pop/call and operand-free ret record sp_delta in bytes (pusha/popad as multi-slot constants); ret-with-immediate, far/privileged returns, traps, ARM multi-register push/pop, and calling-convention frame effects are unmodeled",
    "no SSA/PHI production: Phi is never emitted by lifters; it is synthesized at CFG merges",
    "implemented families are not semantically complete: listed mnemonics lift without warning, but the bounds above still apply",
];

fn fam(
    op: IrOp,
    status: CoverageStatus,
    mnemonics: &[&str],
    patterns: &[&str],
    note: Option<&str>,
) -> FamilyCoverage {
    FamilyCoverage {
        op,
        status,
        mnemonics: mnemonics.iter().map(|s| (*s).to_string()).collect(),
        patterns: patterns.iter().map(|s| (*s).to_string()).collect(),
        note: note.map(str::to_string),
    }
}

/// Genuine-vs-fallback NOP note shared by every architecture.
const NOP_NOTE: &str = "genuine effect-free mnemonics lift with no warning; unmapped mnemonics also lift to NOP but carry a warning";

fn phi_family() -> FamilyCoverage {
    fam(
        IrOp::Phi,
        CoverageStatus::Unmapped,
        &[],
        &[],
        Some("never emitted by lifters; synthesized at CFG merges"),
    )
}

fn x86_families() -> Vec<FamilyCoverage> {
    use CoverageStatus::{Implemented, Partial};
    vec![
        fam(
            IrOp::Copy,
            Implemented,
            X86_COPY,
            &[],
            Some(
                "xchg swaps both operands; leave/enter copy the frame pointer; cmovcc/setcc conditions, SIMD lanes/shuffles, and x87 stack effects unmodeled",
            ),
        ),
        fam(
            IrOp::Load,
            Implemented,
            X86_LOAD,
            &[],
            Some(
                "pop lifts as LOAD; single-slot pop/popf record sp_delta, popa/popad as multi-slot constants; x87 control/state loads approximated as LOAD",
            ),
        ),
        fam(
            IrOp::Store,
            Implemented,
            X86_STORE,
            &[],
            Some(
                "push lifts as STORE; single-slot push/pushf record sp_delta, pusha/pushad as multi-slot constants; x87 control/state stores approximated as STORE",
            ),
        ),
        fam(
            IrOp::Add,
            Implemented,
            X86_ADD,
            &[],
            Some(
                "lea lifts as address math, not a load; only integer add/adc/inc record sets_flags, FP/SIMD forms report none",
            ),
        ),
        fam(
            IrOp::Sub,
            Implemented,
            X86_SUB,
            &[],
            Some(
                "only integer sub/sbb/dec/neg record sets_flags; FP/SIMD forms report none; carry-in reads unmodeled",
            ),
        ),
        fam(IrOp::Mul, Implemented, X86_MUL, &[], None),
        fam(IrOp::Div, Implemented, X86_DIV, &[], None),
        fam(IrOp::And, Implemented, X86_AND, &[], None),
        fam(IrOp::Or, Implemented, X86_OR, &[], None),
        fam(
            IrOp::Xor,
            Partial,
            X86_XOR,
            &[],
            Some(
                "not folds bitwise complement to XOR; AES/SHA/carryless-multiply rounds and crc32 folded to XOR, exact transforms unmodeled",
            ),
        ),
        fam(IrOp::Shl, Implemented, X86_SHL, &[], None),
        fam(
            IrOp::Shr,
            Partial,
            X86_SHR,
            &[],
            Some(
                "rol/ror/rcl/rcr/shlx/shrx/sarx/rorx approximated as shifts; exact bit motion out of scope",
            ),
        ),
        fam(
            IrOp::Cmp,
            Partial,
            X86_CMP,
            X86_CMP_PATTERNS,
            Some(
                "integer/EFLAGS compares (cmp/test/bt/cmps/scas, comiss/vtest/fcomi families) record sets_flags; x87-condition and mask writers report none; imm-folded cmp<cc>/vcmp<cc> pseudo-ops match by pattern",
            ),
        ),
        fam(
            IrOp::Branch,
            Implemented,
            &["jmp"],
            &[],
            Some("indirect forms keep operands without target"),
        ),
        fam(IrOp::CBranch, Implemented, X86_JCC, &[], None),
        fam(
            IrOp::Call,
            Implemented,
            X86_CALL,
            &[],
            Some(
                "indirect calls keep operands without target; call records sp_delta, traps (syscall/int/...) report none",
            ),
        ),
        fam(
            IrOp::Return,
            Implemented,
            X86_RETURN,
            &[],
            Some(
                "operand-free ret/retn record sp_delta; ret-with-immediate and far/privileged returns report none",
            ),
        ),
        phi_family(),
        fam(IrOp::Nop, Implemented, X86_NOP, &[], Some(NOP_NOTE)),
    ]
}

fn aarch64_families() -> Vec<FamilyCoverage> {
    use CoverageStatus::{Implemented, Partial};
    vec![
        fam(
            IrOp::Copy,
            Implemented,
            ARM_COPY,
            &[],
            Some(
                "conditional selects, min/max selects, saturating narrowing, and crypto-adjacent permutations approximated as COPY",
            ),
        ),
        fam(
            IrOp::Load,
            Implemented,
            ARM_LOAD,
            &[],
            Some("acquire/exclusive/pair/SIMD loads carry no ordering effects"),
        ),
        fam(
            IrOp::Store,
            Implemented,
            ARM_STORE,
            &[],
            Some(
                "release/exclusive/pair/SIMD stores carry no ordering effects; store-only atomics fold the ALU part away",
            ),
        ),
        fam(
            IrOp::Add,
            Implemented,
            ARM_ADD,
            &[],
            Some("only adds/adcs record sets_flags; FP/SIMD/atomic forms report none"),
        ),
        fam(
            IrOp::Sub,
            Implemented,
            ARM_SUB,
            &[],
            Some("only subs/sbcs/negs/ngcs record sets_flags; FP/SIMD forms report none"),
        ),
        fam(IrOp::Mul, Implemented, ARM_MUL, &[], None),
        fam(IrOp::Div, Implemented, ARM_DIV, &[], None),
        fam(IrOp::And, Implemented, ARM_AND, &[], None),
        fam(IrOp::Or, Implemented, ARM_OR, &[], None),
        fam(
            IrOp::Xor,
            Partial,
            ARM_XOR,
            &[],
            Some(
                "AES/SHA/SM3/SM4 rounds, CRC, and atomic xor folded to XOR; exact transforms unmodeled",
            ),
        ),
        fam(IrOp::Shl, Implemented, ARM_SHL, &[], None),
        fam(
            IrOp::Shr,
            Partial,
            ARM_SHR,
            &[],
            Some("ror/rorv are rotates, approximated as shifts; narrowing shifts drop lanes"),
        ),
        fam(
            IrOp::Cmp,
            Partial,
            ARM_CMP,
            &[],
            Some(
                "integer/FP compares record sets_flags; vector compares and compare-and-swap report none; compare-and-swap drops the conditional store",
            ),
        ),
        fam(
            IrOp::Branch,
            Implemented,
            &["b", "br", "braa", "brab", "braaz", "brabz"],
            &[],
            Some("indirect forms keep operands without target"),
        ),
        fam(
            IrOp::CBranch,
            Implemented,
            ARM_CBRANCH,
            ARM_CBRANCH_PATTERNS,
            None,
        ),
        fam(
            IrOp::Call,
            Implemented,
            &[
                "bl", "blr", "blraa", "blrab", "blraaz", "blrabz", "svc", "hvc", "smc",
            ],
            &[],
            Some("indirect bl/blr keep operands without target"),
        ),
        fam(IrOp::Return, Implemented, ARM_RETURN, &[], None),
        phi_family(),
        fam(IrOp::Nop, Implemented, ARM_NOP, &[], Some(NOP_NOTE)),
    ]
}

fn arm32_families() -> Vec<FamilyCoverage> {
    use CoverageStatus::{Implemented, Partial};
    vec![
        fam(IrOp::Copy, Implemented, ARM32_COPY, &[], None),
        fam(
            IrOp::Load,
            Implemented,
            ARM32_LOAD,
            &[],
            Some(
                "pop/ldm/ldmia/ldmdb/ldmda naming pc lift as RETURN (CBRANCH when predicated), not LOAD; exclusives carry no ordering effects; push/pop-equivalent stack deltas need register-list decoding, reported as none",
            ),
        ),
        fam(
            IrOp::Store,
            Implemented,
            ARM32_STORE,
            &[],
            Some("push lifts as STORE; stack deltas need register-list decoding, reported as none"),
        ),
        fam(
            IrOp::Add,
            Implemented,
            ARM32_ADD,
            &[],
            Some("s-suffixed forms record sets_flags; saturating Q-flag effects unmodeled"),
        ),
        fam(
            IrOp::Sub,
            Implemented,
            ARM32_SUB,
            &[],
            Some("s-suffixed forms record sets_flags; carry-in reads (sbc/rsc) unmodeled"),
        ),
        fam(IrOp::Mul, Implemented, ARM32_MUL, &[], None),
        fam(IrOp::Div, Implemented, ARM32_DIV, &[], None),
        fam(IrOp::And, Implemented, ARM32_AND, &[], None),
        fam(IrOp::Or, Implemented, ARM32_OR, &[], None),
        fam(IrOp::Xor, Implemented, ARM32_XOR, &[], None),
        fam(IrOp::Shl, Implemented, ARM32_SHL, &[], None),
        fam(
            IrOp::Shr,
            Partial,
            ARM32_SHR,
            &[],
            Some("ror/rrx are rotates, approximated as shifts"),
        ),
        fam(
            IrOp::Cmp,
            Partial,
            ARM32_CMP,
            &[],
            Some("cmp/cmn/tst/teq and s-suffixed add/sub record sets_flags"),
        ),
        fam(
            IrOp::Branch,
            Implemented,
            &["b", "bx", "tbb", "tbh"],
            &[],
            Some("condition-suffixed b/bx lift as CBRANCH; bx lr lifts as RETURN"),
        ),
        fam(
            IrOp::CBranch,
            Implemented,
            &["cbz", "cbnz"],
            &[],
            Some("plus condition-suffixed b/bx and predicated pop/ldm naming pc"),
        ),
        fam(
            IrOp::Call,
            Implemented,
            &["bl", "blx", "svc", "hvc", "smc"],
            &[],
            Some("indirect bl/blx keep operands without target"),
        ),
        fam(
            IrOp::Return,
            Implemented,
            &[],
            &[],
            Some(
                "operand-dependent: bx lr and pop/ldm naming pc (predicated forms lift as CBRANCH)",
            ),
        ),
        phi_family(),
        fam(IrOp::Nop, Implemented, ARM32_NOP, &[], Some(NOP_NOTE)),
    ]
}

/// Machine-readable lift coverage for `arch`, without opening a binary.
///
/// Families publish the same mnemonic slices the dispatch predicates
/// consult, so advertised coverage cannot drift from actual lifts; unknown
/// mnemonics stay fallback [`IrOp::Nop`] with a warning per
/// [`unlifted`](self#warning-semantics) semantics.
#[must_use]
pub fn coverage(arch: Arch) -> Coverage {
    let (families, arch_note) = match arch {
        Arch::X86_64 | Arch::X86_32 => (x86_families(), None),
        Arch::Aarch64 => (aarch64_families(), None),
        Arch::Arm32 | Arch::Thumb => (
            arm32_families(),
            Some(
                "mnemonics are base forms: one .w/.n width suffix, one condition suffix, and one flag s are stripped before lookup; a stripped condition turns plain b into CBRANCH",
            ),
        ),
    };
    Coverage {
        arch: crate::db::arch_name(arch).to_string(),
        families,
        limitations: COVERAGE_LIMITATIONS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        fallback: FallbackCoverage {
            op: IrOp::Nop,
            status: CoverageStatus::Unmapped,
            warning: "unlifted '<mnem>'; emitted NOP".to_string(),
            distinguish:
                "warning.is_some() marks fallback NOP; genuine NOP mnemonics lift with warning None"
                    .to_string(),
        },
        arch_note: arch_note.map(str::to_string),
    }
}

/// Lift one x86 (32- or 64-bit) instruction.
///
/// Mode-agnostic by design (one table for both modes): flag effects are
/// complete here, but slot-sized `sp_delta` values are assigned by
/// [`lift`], which owns the arch context.
#[must_use]
pub fn lift_x86(insn: &Insn) -> Vec<IrInsn> {
    let mnem = insn.mnem.as_str();
    // Read-modify-write with a single operand reads as well as writes.
    let alu_out_in = |insn: &Insn| -> (Vec<String>, Vec<String>) {
        match insn.ops.as_slice() {
            [] => (Vec::new(), Vec::new()),
            [dst] => (vec![dst.clone()], vec![dst.clone()]),
            [dst, rest @ ..] => (vec![dst.clone()], rest.to_vec()),
        }
    };
    let (op, inputs, outputs, target) = match mnem {
        s if is_x86_copy(s) => {
            let (outputs, inputs) = match insn.ops.as_slice() {
                [] => (Vec::new(), Vec::new()),
                // xchg swaps both operands.
                [a, b] if s == "xchg" => (vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]),
                [single] => (vec![single.clone()], Vec::new()),
                [dst, rest @ ..] => (vec![dst.clone()], rest.to_vec()),
            };
            (IrOp::Copy, inputs, outputs, None)
        }
        s if is_x86_load(s) => (IrOp::Load, Vec::new(), insn.ops.clone(), None),
        s if is_x86_store(s) => (IrOp::Store, insn.ops.clone(), Vec::new(), None),
        s if is_x86_alu(s, IrOp::Add) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Add, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Sub) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Sub, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Mul) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Mul, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Div) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Div, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::And) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::And, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Or) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Or, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Xor) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Xor, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Shl) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Shl, inputs, outputs, None)
        }
        s if is_x86_alu(s, IrOp::Shr) => {
            let (outputs, inputs) = alu_out_in(insn);
            (IrOp::Shr, inputs, outputs, None)
        }
        s if is_x86_cmp(s) => (IrOp::Cmp, insn.ops.clone(), Vec::new(), None),
        "jmp" => direct_or_indirect(insn, IrOp::Branch),
        s if is_x86_jcc(s) => (
            IrOp::CBranch,
            insn.ops.clone(),
            Vec::new(),
            insn.branch_target,
        ),
        s if is_x86_call(s) => direct_or_indirect(insn, IrOp::Call),
        s if is_x86_return(s) => (IrOp::Return, Vec::new(), Vec::new(), None),
        s if is_x86_nop(s) => (IrOp::Nop, Vec::new(), Vec::new(), None),
        _ => return unlifted(insn),
    };
    let sets_flags = matches!(op, IrOp::Add | IrOp::Sub | IrOp::Cmp) && x86_sets_flags(mnem);
    vec![IrInsn {
        addr: insn.addr,
        op,
        inputs,
        outputs,
        target,
        warning: None,
        effects: IrEffects {
            sets_flags,
            sp_delta: None,
        },
    }]
}

/// Lift one AArch64 instruction.
#[must_use]
pub fn lift_aarch64(insn: &Insn) -> Vec<IrInsn> {
    lift_aarch64_with_prev(insn, None)
}

/// Lift one AArch64 instruction with its immediate predecessor, if any.
///
/// When `prev` ends where `insn` begins and the two form an
/// adrp+add/ldr pair resolving to a final address, the second row's
/// `target` carries that address; otherwise the row is identical to
/// [`lift_aarch64`]. Nonadjacent or unresolvable pairs keep current
/// behavior exactly.
#[must_use]
pub fn lift_aarch64_with_prev(insn: &Insn, prev: Option<&Insn>) -> Vec<IrInsn> {
    let mnem = insn.mnem.as_str();
    let (op, inputs, outputs, mut target) = match mnem {
        s if is_arm_copy(s) => first_out_rest_in(insn, IrOp::Copy),
        s if is_arm_load(s) => first_out_rest_in(insn, IrOp::Load),
        s if is_arm_store(s) => (IrOp::Store, insn.ops.clone(), Vec::new(), None),
        s if is_arm_alu(s, IrOp::Add) => first_out_rest_in(insn, IrOp::Add),
        s if is_arm_alu(s, IrOp::Sub) => first_out_rest_in(insn, IrOp::Sub),
        s if is_arm_alu(s, IrOp::Mul) => first_out_rest_in(insn, IrOp::Mul),
        s if is_arm_alu(s, IrOp::Div) => first_out_rest_in(insn, IrOp::Div),
        s if is_arm_alu(s, IrOp::And) => first_out_rest_in(insn, IrOp::And),
        s if is_arm_alu(s, IrOp::Or) => first_out_rest_in(insn, IrOp::Or),
        s if is_arm_alu(s, IrOp::Xor) => first_out_rest_in(insn, IrOp::Xor),
        s if is_arm_alu(s, IrOp::Shl) => first_out_rest_in(insn, IrOp::Shl),
        s if is_arm_alu(s, IrOp::Shr) => first_out_rest_in(insn, IrOp::Shr),
        s if ARM_CMP.contains(&s) => (IrOp::Cmp, insn.ops.clone(), Vec::new(), None),
        "b" | "br" | "braa" | "brab" | "braaz" | "brabz" => direct_or_indirect(insn, IrOp::Branch),
        s if is_arm_cbranch(s) => (
            IrOp::CBranch,
            insn.ops.clone(),
            Vec::new(),
            insn.branch_target,
        ),
        "bl" | "blr" | "blraa" | "blrab" | "blraaz" | "blrabz" => {
            direct_or_indirect(insn, IrOp::Call)
        }
        s if is_arm_call(s) => (IrOp::Call, insn.ops.clone(), Vec::new(), None),
        s if is_arm_return(s) => (IrOp::Return, Vec::new(), Vec::new(), None),
        s if is_arm_nop(s) => (IrOp::Nop, Vec::new(), Vec::new(), None),
        _ => return unlifted(insn),
    };
    if target.is_none()
        && let Some(first) = prev
        && first.addr.wrapping_add(u64::from(first.size)) == insn.addr
        && let Some(resolved) = resolve_adrp_pair(first, insn)
    {
        target = Some(resolved);
    }
    let sets_flags = matches!(op, IrOp::Add | IrOp::Sub | IrOp::Cmp) && arm_sets_flags(mnem);
    vec![IrInsn {
        addr: insn.addr,
        op,
        inputs,
        outputs,
        target,
        warning: None,
        effects: IrEffects {
            sets_flags,
            sp_delta: None,
        },
    }]
}

fn first_out_rest_in(insn: &Insn, op: IrOp) -> (IrOp, Vec<String>, Vec<String>, Option<u64>) {
    match insn.ops.as_slice() {
        [] => (op, Vec::new(), Vec::new(), None),
        [dst, rest @ ..] => (op, rest.to_vec(), vec![dst.clone()], None),
    }
}

/// Input/output split for an ARM32 load.
///
/// Single loads (`ldr` family) write the first operand and read the rest.
/// Load-multiples (`ldm` family, `pop`) read the base register and write
/// the listed registers; a write-back `!` base is read and written.
fn arm32_load_parts(base: &str, insn: &Insn) -> (Vec<String>, Vec<String>) {
    if !is_arm32_ldm(base) {
        return match insn.ops.as_slice() {
            [] => (Vec::new(), Vec::new()),
            [dst, rest @ ..] => (rest.to_vec(), vec![dst.clone()]),
        };
    }
    match insn.ops.as_slice() {
        [] => (Vec::new(), Vec::new()),
        [single] => match arm32_reglist(single) {
            Some(regs) => (Vec::new(), regs),
            None => (Vec::new(), vec![single.clone()]),
        },
        [first, rest @ ..] => {
            let (base_reg, writeback) = arm32_strip_bang(first);
            let mut outputs = Vec::new();
            for op in rest {
                match arm32_reglist(op) {
                    Some(regs) => outputs.extend(regs),
                    None => outputs.push(op.clone()),
                }
            }
            if writeback && !outputs.iter().any(|o| o == base_reg) {
                outputs.push(base_reg.to_string());
            }
            (vec![base_reg.to_string()], outputs)
        }
    }
}

/// Input/output split for an ARM32 store, mirroring [`arm32_load_parts`].
///
/// Single stores (`str` family) read every operand (stored value plus
/// address). Store-multiples (`stm` family, `push`) read the base register
/// and the listed registers; a write-back `!` base is also written.
fn arm32_store_parts(base: &str, insn: &Insn) -> (Vec<String>, Vec<String>) {
    if !is_arm32_stm(base) {
        return (insn.ops.clone(), Vec::new());
    }
    match insn.ops.as_slice() {
        [] => (Vec::new(), Vec::new()),
        [single] => match arm32_reglist(single) {
            Some(regs) => (regs, Vec::new()),
            None => (vec![single.clone()], Vec::new()),
        },
        [first, rest @ ..] => {
            let (base_reg, writeback) = arm32_strip_bang(first);
            let mut inputs = vec![base_reg.to_string()];
            for op in rest {
                match arm32_reglist(op) {
                    Some(regs) => inputs.extend(regs),
                    None => inputs.push(op.clone()),
                }
            }
            let outputs = if writeback {
                vec![base_reg.to_string()]
            } else {
                Vec::new()
            };
            (inputs, outputs)
        }
    }
}

/// Expand a `{r1, r2}` register-list operand into its registers.
///
/// Returns `None` when `op` is not a single brace-enclosed list, so
/// callers can fall back to treating the operand verbatim.
fn arm32_reglist(op: &str) -> Option<Vec<String>> {
    let inner = op.strip_prefix('{')?.strip_suffix('}')?;
    let regs: Vec<String> = inner
        .split(',')
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();
    if regs.is_empty() { None } else { Some(regs) }
}

/// Split a write-back `!` base (`r0!` into `("r0", true)`).
fn arm32_strip_bang(op: &str) -> (&str, bool) {
    op.strip_suffix('!')
        .map_or((op, false), |base| (base, true))
}

/// Lift one ARM32/Thumb instruction.
///
/// ARMv7 Display bakes the condition code and flag suffix into the mnemonic
/// (`addeq`, `adds`, `bl.w`), so `split_arm_mnem` reduces it to the base
/// first; a stripped condition turns a plain `b` into a conditional branch
/// and keeps predicated returns on the fallthrough path.
#[must_use]
pub fn lift_arm32(insn: &Insn) -> Vec<IrInsn> {
    let (base, cond) = split_arm_mnem(&insn.mnem);
    let (op, inputs, outputs, target) = match base {
        // Any write to `pc` is control flow, not data movement. An
        // unconditional `mov pc, lr` returns; everything else with a `pc`
        // destination (`ldr pc, ...` veneers, `add pc, ...` table dispatch,
        // predicated `mov pc, ...`) is an indirect branch. Load-multiples
        // keep their own `pc`-in-list rule below (`pop {pc}` reads the whole
        // list from `ops`, not `ops[0]`), and the branch/call arms never take
        // this path (their first operand is not a destination).
        s if !is_arm32_store(s)
            && !is_arm32_branch(s)
            && !is_arm32_ldm(s)
            && arm32_dest_is_pc(insn) =>
        {
            if s == "mov" && !cond {
                (IrOp::Return, Vec::new(), Vec::new(), None)
            } else if cond {
                (IrOp::CBranch, insn.ops.clone(), Vec::new(), None)
            } else {
                direct_or_indirect(insn, IrOp::Branch)
            }
        }
        s if is_arm32_copy(s) => first_out_rest_in(insn, IrOp::Copy),
        s if is_arm32_load(s) => {
            if is_arm32_ldm(s) && ops_contain_pc(insn) {
                if cond {
                    (IrOp::CBranch, insn.ops.clone(), Vec::new(), None)
                } else {
                    (IrOp::Return, Vec::new(), Vec::new(), None)
                }
            } else {
                let (inputs, outputs) = arm32_load_parts(s, insn);
                (IrOp::Load, inputs, outputs, None)
            }
        }
        s if is_arm32_store(s) => {
            let (inputs, outputs) = arm32_store_parts(s, insn);
            (IrOp::Store, inputs, outputs, None)
        }
        s if is_arm32_alu(s, IrOp::Add) => first_out_rest_in(insn, IrOp::Add),
        s if is_arm32_alu(s, IrOp::Sub) => first_out_rest_in(insn, IrOp::Sub),
        s if is_arm32_alu(s, IrOp::Mul) => first_out_rest_in(insn, IrOp::Mul),
        s if is_arm32_alu(s, IrOp::Div) => first_out_rest_in(insn, IrOp::Div),
        s if is_arm32_alu(s, IrOp::And) => first_out_rest_in(insn, IrOp::And),
        s if is_arm32_alu(s, IrOp::Or) => first_out_rest_in(insn, IrOp::Or),
        s if is_arm32_alu(s, IrOp::Xor) => first_out_rest_in(insn, IrOp::Xor),
        s if is_arm32_alu(s, IrOp::Shl) => first_out_rest_in(insn, IrOp::Shl),
        s if is_arm32_alu(s, IrOp::Shr) => first_out_rest_in(insn, IrOp::Shr),
        s if ARM32_CMP.contains(&s) => (IrOp::Cmp, insn.ops.clone(), Vec::new(), None),
        "b" if cond => (
            IrOp::CBranch,
            insn.ops.clone(),
            Vec::new(),
            insn.branch_target,
        ),
        "b" => direct_or_indirect(insn, IrOp::Branch),
        "bl" | "blx" => direct_or_indirect(insn, IrOp::Call),
        "bx" if !cond && insn.ops.as_slice() == ["lr"] => {
            (IrOp::Return, Vec::new(), Vec::new(), None)
        }
        "bx" if cond => (IrOp::CBranch, insn.ops.clone(), Vec::new(), None),
        "bx" => direct_or_indirect(insn, IrOp::Branch),
        "cbz" | "cbnz" => (
            IrOp::CBranch,
            insn.ops.clone(),
            Vec::new(),
            insn.branch_target,
        ),
        "tbb" | "tbh" => (IrOp::Branch, insn.ops.clone(), Vec::new(), None),
        s if is_arm32_call(s) => (IrOp::Call, insn.ops.clone(), Vec::new(), None),
        s if is_arm32_nop(s) => (IrOp::Nop, Vec::new(), Vec::new(), None),
        _ => return unlifted(insn),
    };
    let sets_flags =
        matches!(op, IrOp::Add | IrOp::Sub | IrOp::Cmp) && arm32_sets_flags(base, &insn.mnem);
    vec![IrInsn {
        addr: insn.addr,
        op,
        inputs,
        outputs,
        target,
        warning: None,
        effects: IrEffects {
            sets_flags,
            sp_delta: None,
        },
    }]
}

/// Reduce an ARMv7 mnemonic to its base plus whether it carries a condition
/// code. Strips one `.w`/`.n` width suffix, then one condition suffix
/// (`eq`..`le`, only when the remainder is a known base so `teq`/`bics`
/// survive), then one flag `s` (same guard, so `mrs`/`svc` survive).
fn split_arm_mnem(mnem: &str) -> (&str, bool) {
    let base = mnem
        .strip_suffix(".w")
        .or_else(|| mnem.strip_suffix(".n"))
        .unwrap_or(mnem);
    if base.len() > 2 {
        let (prefix, suffix) = base.split_at(base.len() - 2);
        if ARM_CONDS.contains(&suffix) && arm_base_mnem(prefix) {
            return (prefix, true);
        }
    }
    if let Some(prefix) = base.strip_suffix('s')
        && arm_base_mnem(prefix)
    {
        return (prefix, false);
    }
    (base, false)
}

/// Condition suffixes of [`split_arm_mnem`], matching the decoder's
/// `ConditionCode` names (`hs`/`lo`, never the `cs`/`cc` aliases).
const ARM_CONDS: [&str; 14] = [
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
];

/// Whether `s` is a base mnemonic of [`lift_arm32`]: the load/store/copy
/// tables, any ALU table, the compare table, or the control/nop words
/// matched inline by the lifter.
fn arm_base_mnem(s: &str) -> bool {
    is_arm32_copy(s)
        || is_arm32_load(s)
        || is_arm32_store(s)
        || is_arm32_alu(s, IrOp::Add)
        || is_arm32_alu(s, IrOp::Sub)
        || is_arm32_alu(s, IrOp::Mul)
        || is_arm32_alu(s, IrOp::Div)
        || is_arm32_alu(s, IrOp::And)
        || is_arm32_alu(s, IrOp::Or)
        || is_arm32_alu(s, IrOp::Xor)
        || is_arm32_alu(s, IrOp::Shl)
        || is_arm32_alu(s, IrOp::Shr)
        || ARM32_CMP.contains(&s)
        || is_arm32_nop(s)
        || matches!(
            s,
            "b" | "bl" | "blx" | "bx" | "cbz" | "cbnz" | "tbb" | "tbh" | "svc" | "hvc" | "smc"
        )
}

/// Whether any operand names `pc` (return-via-`pop`/`ldm` check).
fn ops_contain_pc(insn: &Insn) -> bool {
    insn.ops
        .iter()
        .any(|o| o.split(|c: char| !c.is_alphanumeric()).any(|w| w == "pc"))
}

/// Whether the first operand names `pc` as the written destination.
///
/// Operands split on commas, so `ldr pc, [pc, #-4]` arrives with `ops[0]`
/// exactly `pc`; the match is on the first alphanumeric word for stray
/// writeback/bracket punctuation. Only the destination position counts: a
/// `pc` base in a later operand (`ldr r0, [pc, #4]`) is a literal load.
fn arm32_dest_is_pc(insn: &Insn) -> bool {
    insn.ops.first().is_some_and(|o| {
        o.split(|c: char| !c.is_alphanumeric())
            .find(|w| !w.is_empty())
            == Some("pc")
    })
}

/// Direct branch/call keeps only `target`; indirect keeps the operands.
fn direct_or_indirect(insn: &Insn, op: IrOp) -> (IrOp, Vec<String>, Vec<String>, Option<u64>) {
    match insn.branch_target {
        Some(t) => (op, Vec::new(), Vec::new(), Some(t)),
        None => (op, insn.ops.clone(), Vec::new(), None),
    }
}

fn unlifted(insn: &Insn) -> Vec<IrInsn> {
    vec![IrInsn {
        addr: insn.addr,
        op: IrOp::Nop,
        inputs: Vec::new(),
        outputs: Vec::new(),
        target: None,
        warning: Some(format!("unlifted '{}'; emitted NOP", insn.mnem)),
        effects: IrEffects::default(),
    }]
}

/// Whether x86 `mnem` writes EFLAGS in the common integer case.
///
/// Call only with a mnemonic that already lifted as Add/Sub/Cmp: plain
/// integer `add`/`adc`/`adcx`/`adox`/`inc`, `sub`/`sbb`/`dec`/`neg`,
/// integer and string compares and tests, `bt`, and the EFLAGS-writing FP
/// compares (`comiss*`, `ucomiss*`, `vtestps`/`vtestpd`, `vptest`,
/// `fcomi*`). `lea`, x87 FPU-condition writers, packed mask writers, and
/// the imm-folded `cmp<cc>`/`vcmp<cc>` pseudo-ops report false.
fn x86_sets_flags(mnem: &str) -> bool {
    matches!(
        mnem,
        "add"
            | "adc"
            | "adcx"
            | "adox"
            | "inc"
            | "sub"
            | "sbb"
            | "dec"
            | "neg"
            | "cmp"
            | "test"
            | "bt"
            | "cmps"
            | "cmpsb"
            | "cmpsw"
            | "cmpsd"
            | "cmpsq"
            | "scas"
            | "scasb"
            | "scasw"
            | "scasd"
            | "scasq"
            | "comiss"
            | "comisd"
            | "ucomiss"
            | "ucomisd"
            | "vcomiss"
            | "vcomisd"
            | "vucomiss"
            | "vucomisd"
            | "vtestps"
            | "vtestpd"
            | "vptest"
            | "fcomi"
            | "fcomip"
            | "fucomi"
            | "fucomip"
    )
}

/// Whether an AArch64 `mnem` writes NZCV in the common integer case.
///
/// Call only with a mnemonic that already lifted as Add/Sub/Cmp: the
/// `s`-suffixed integer forms (`adds`, `adcs`, `subs`, `sbcs`, `negs`,
/// `ngcs`) and the scalar compares (`cmp`, `cmn`, `tst`, `ccmp`,
/// `ccmn`, `cmtst`, `fcmp`, `fcmpe`, `fccmp`, `fccmpe`). Plain
/// `add`/`sub`, FP/SIMD ALU, vector compares, and compare-and-swap
/// report false.
fn arm_sets_flags(mnem: &str) -> bool {
    matches!(
        mnem,
        "adds"
            | "adcs"
            | "subs"
            | "sbcs"
            | "negs"
            | "ngcs"
            | "cmp"
            | "cmn"
            | "tst"
            | "ccmp"
            | "ccmn"
            | "cmtst"
            | "fcmp"
            | "fcmpe"
            | "fccmp"
            | "fccmpe"
    )
}

/// Whether an ARM32/Thumb `base`+full-mnemonic pair writes NZCV: any
/// compare base (`cmp`/`cmn`/`tst`/`teq`), or an add/sub base with the
/// flag `s` suffix (`adds`, `subs.w`, ...).
///
/// Mirrors [`split_arm_mnem`]: one `.w`/`.n` width suffix and one guarded
/// condition suffix peel first, then the trailing `s` must leave exactly
/// `base`, so `svc`/`mrs`/`teq` keep their own meaning.
fn arm32_sets_flags(base: &str, full: &str) -> bool {
    if ARM32_CMP.contains(&base) {
        return true;
    }
    if !(is_arm32_alu(base, IrOp::Add) || is_arm32_alu(base, IrOp::Sub)) {
        return false;
    }
    let w = full
        .strip_suffix(".w")
        .or_else(|| full.strip_suffix(".n"))
        .unwrap_or(full);
    let core = if w.len() > 2 {
        let (prefix, suffix) = w.split_at(w.len() - 2);
        if ARM_CONDS.contains(&suffix) && arm_base_mnem(prefix) {
            prefix
        } else {
            w
        }
    } else {
        w
    };
    core.strip_suffix('s').is_some_and(|p| p == base)
}

/// Signed stack-pointer delta in bytes for `arch`+`insn`, if the effect is
/// a single known slot move.
///
/// x86 only: `push`/`pop`/`pushf*`/`popf*` move one slot (-/+8 on x86-64,
/// -/+4 on x86-32), `pusha`/`popa` move 16 and `pushad`/`popad` 32,
/// `call` pushes one return slot, and operand-free `ret`/`retn` pop one.
/// Everything else reports `None`: `ret` with an immediate (extra
/// argument pop), far/privileged returns, traps, and all ARM mnemonics
/// (multi-register push/pop need register-list decoding; `bl`/`ret` are
/// link-register moves with no SP effect).
fn sp_delta_for(arch: Arch, insn: &Insn) -> Option<i64> {
    if !matches!(arch, Arch::X86_64 | Arch::X86_32) {
        return None;
    }
    let slot: i64 = if arch == Arch::X86_64 { 8 } else { 4 };
    match insn.mnem.as_str() {
        "push" | "pushf" | "pushfd" | "pushfq" => Some(-slot),
        "pop" | "popf" | "popfd" | "popfq" => Some(slot),
        "pusha" => Some(-16),
        "popa" => Some(16),
        "pushad" => Some(-32),
        "popad" => Some(32),
        "call" => Some(-slot),
        "ret" | "retn" if insn.ops.is_empty() => Some(slot),
        _ => None,
    }
}

fn is_x86_copy(s: &str) -> bool {
    X86_COPY.contains(&s)
}

fn is_x86_load(s: &str) -> bool {
    X86_LOAD.contains(&s)
}

fn is_x86_store(s: &str) -> bool {
    X86_STORE.contains(&s)
}

fn is_x86_alu(s: &str, op: IrOp) -> bool {
    match op {
        IrOp::Add => X86_ADD.contains(&s),
        IrOp::Sub => X86_SUB.contains(&s),
        IrOp::Mul => X86_MUL.contains(&s),
        IrOp::Div => X86_DIV.contains(&s),
        IrOp::And => X86_AND.contains(&s),
        IrOp::Or => X86_OR.contains(&s),
        IrOp::Xor => X86_XOR.contains(&s),
        // Rotates approximate to shifts; exact bit motion is out of scope for M3.
        IrOp::Shl => X86_SHL.contains(&s),
        IrOp::Shr => X86_SHR.contains(&s),
        _ => false,
    }
}

/// Shared dispatch/coverage tables: the `is_x86_*` predicates consult these,
/// and [`coverage`] publishes the same slices, so the machine-readable
/// report cannot drift from the lifters.
const X86_COPY: &[&str] = &[
    "mov",
    "movsx",
    "movsxd",
    "movzx",
    "movabs",
    "movbe",
    "xchg",
    "leave",
    "enter",
    "cbw",
    "cwde",
    "cdqe",
    "cdq",
    "cqo",
    "bswap",
    "cmovo",
    "cmovno",
    "cmovb",
    "cmovae",
    "cmove",
    "cmovne",
    "cmovbe",
    "cmova",
    "cmovs",
    "cmovns",
    "cmovp",
    "cmovnp",
    "cmovl",
    "cmovge",
    "cmovle",
    "cmovg",
    "seto",
    "setno",
    "setb",
    "setae",
    "sete",
    "setne",
    "setbe",
    "seta",
    "sets",
    "setns",
    "setp",
    "setnp",
    "setl",
    "setge",
    "setle",
    "setg",
    "movs",
    "movsb",
    "movsw",
    "movsd",
    "movsq",
    "movss",
    "movaps",
    "movups",
    "movapd",
    "movupd",
    "movdqa",
    "movdqu",
    "movd",
    "movq",
    "movlps",
    "movlpd",
    "movhps",
    "movhpd",
    "movlhps",
    "movhlps",
    "movmskps",
    "movmskpd",
    "lddqu",
    "shufps",
    "shufpd",
    "pshufb",
    "pshufd",
    "pshufhw",
    "pshuflw",
    "unpcklps",
    "unpcklpd",
    "unpckhps",
    "unpckhpd",
    "punpcklbw",
    "punpcklwd",
    "punpckldq",
    "punpcklqdq",
    "punpckhbw",
    "punpckhwd",
    "punpckhdq",
    "punpckhqdq",
    "pinsrw",
    "pextrw",
    "bextr",
    "pdep",
    "pext",
    "vmovaps",
    "vmovups",
    "vmovapd",
    "vmovupd",
    "vmovdqa",
    "vmovdqu",
    "vmovss",
    "vmovsd",
    "vmovd",
    "vmovq",
    "vmovlps",
    "vmovlpd",
    "vmovhps",
    "vmovhpd",
    "vshufps",
    "vshufpd",
    "vpshufb",
    "vpshufd",
    "vpshufhw",
    "vpshuflw",
    "vunpcklps",
    "vunpcklpd",
    "vunpckhps",
    "vunpckhpd",
    "vpunpcklbw",
    "vpunpcklwd",
    "vpunpckldq",
    "vpunpcklqdq",
    "vpunpckhbw",
    "vpunpckhwd",
    "vpunpckhdq",
    "vpunpckhqdq",
    "vpermps",
    "vpermd",
    "vpermq",
    "vpermilps",
    "vpermilpd",
    "vperm2f128",
    "vinsertps",
    "vextractps",
    "vinsertf128",
    "vextractf128",
    "vpinsrb",
    "vpinsrw",
    "vpinsrd",
    "vpinsrq",
    "vpextrb",
    "vpextrw",
    "vpextrd",
    "vpextrq",
    "vbroadcastss",
    "vbroadcastsd",
    "vpbroadcastb",
    "vpbroadcastw",
    "vpbroadcastd",
    "vpbroadcastq",
    "vpmovsxbw",
    "vpmovsxbd",
    "vpmovsxbq",
    "vpmovsxwd",
    "vpmovsxwq",
    "vpmovsxdq",
    "vpmovzxbw",
    "vpmovzxbd",
    "vpmovzxbq",
    "vpmovzxwd",
    "vpmovzxwq",
    "vpmovzxdq",
    "vpsignb",
    "vpsignw",
    "vpsignd",
    "psignb",
    "psignw",
    "psignd",
    "fld1",
    "fldl2t",
    "fldl2e",
    "fldpi",
    "fldlg2",
    "fldln2",
    "fldz",
    "fabs",
    "fsqrt",
    "fxch",
    "frndint",
    "fnstsw",
    "fcmovb",
    "fcmove",
    "fcmovbe",
    "fcmovu",
    "fcmovnb",
    "fcmovne",
    "fcmovnbe",
    "fcmovnu",
    "rdtsc",
    "rdtscp",
    "rdpmc",
    "rdrand",
    "rdseed",
    "xgetbv",
];
const X86_LOAD: &[&str] = &[
    "pop", "popa", "popad", "popf", "popfd", "popfq", "lods", "lodsb", "lodsw", "lodsd", "lodsq",
    "xlat", "in", "insb", "insw", "insd", "movntdqa", "fld", "fild", "fbld", "fldenv", "fldcw",
    "frstor", "fxrstor", "xrstor",
];
const X86_STORE: &[&str] = &[
    "push", "pusha", "pushad", "pushf", "pushfd", "pushfq", "stos", "stosb", "stosw", "stosd",
    "stosq", "out", "outsb", "outsw", "outsd", "movntps", "movntpd", "movntdq", "movnti",
    "vmovntps", "vmovntpd", "vmovntdq", "fst", "fstp", "fist", "fistp", "fisttp", "fbstp",
    "fnstcw", "fnstenv", "fnsave", "fxsave", "xsave",
];
const X86_ADD: &[&str] = &[
    "add", "adc", "adcx", "adox", "lea", "inc", "fadd", "faddp", "fiadd", "addps", "addpd",
    "addss", "addsd", "vaddps", "vaddpd", "vaddss", "vaddsd", "paddb", "paddw", "paddd", "paddq",
    "vpaddb", "vpaddw", "vpaddd", "vpaddq", "haddps", "haddpd", "vhaddps", "vhaddpd", "phaddw",
    "phaddd",
];
const X86_SUB: &[&str] = &[
    "sub", "sbb", "dec", "neg", "fchs", "fsub", "fsubp", "fsubr", "fisub", "fisubr", "subps",
    "subpd", "subss", "subsd", "vsubps", "vsubpd", "vsubss", "vsubsd", "psubb", "psubw", "psubd",
    "psubq", "vpsubb", "vpsubw", "vpsubd", "vpsubq", "hsubps", "hsubpd", "vhsubps", "vhsubpd",
    "phsubw", "phsubd", "psadbw", "mpsadbw", "vpsadbw", "vmpsadbw",
];
const X86_MUL: &[&str] = &[
    "mul",
    "imul",
    "mulx",
    "fmul",
    "fmulp",
    "fimul",
    "mulps",
    "mulpd",
    "mulss",
    "mulsd",
    "vmulps",
    "vmulpd",
    "vmulss",
    "vmulsd",
    "pmullw",
    "pmulld",
    "vpmullw",
    "vpmulld",
    "pmuldq",
    "vpmuldq",
    "pmuludq",
    "vpmuludq",
    "pmulhw",
    "pmulhuw",
    "vpmulhw",
    "vpmulhuw",
    "pmaddwd",
    "vpmaddwd",
    "vfmadd132ps",
    "vfmadd132pd",
    "vfmadd132ss",
    "vfmadd132sd",
    "vfmadd213ps",
    "vfmadd213pd",
    "vfmadd213ss",
    "vfmadd213sd",
    "vfmadd231ps",
    "vfmadd231pd",
    "vfmadd231ss",
    "vfmadd231sd",
    "vfmsub132ps",
    "vfmsub132pd",
    "vfmsub132ss",
    "vfmsub132sd",
    "vfmsub213ps",
    "vfmsub213pd",
    "vfmsub213ss",
    "vfmsub213sd",
    "vfmsub231ps",
    "vfmsub231pd",
    "vfmsub231ss",
    "vfmsub231sd",
    "vfnmadd132ps",
    "vfnmadd132pd",
    "vfnmadd132ss",
    "vfnmadd132sd",
    "vfnmadd213ps",
    "vfnmadd213pd",
    "vfnmadd213ss",
    "vfnmadd213sd",
    "vfnmadd231ps",
    "vfnmadd231pd",
    "vfnmadd231ss",
    "vfnmadd231sd",
    "vfnmsub132ps",
    "vfnmsub132pd",
    "vfnmsub132ss",
    "vfnmsub132sd",
    "vfnmsub213ps",
    "vfnmsub213pd",
    "vfnmsub213ss",
    "vfnmsub213sd",
    "vfnmsub231ps",
    "vfnmsub231pd",
    "vfnmsub231ss",
    "vfnmsub231sd",
];
const X86_DIV: &[&str] = &[
    "div", "idiv", "fdiv", "fdivp", "fdivr", "fidiv", "fidivr", "divps", "divpd", "divss", "divsd",
    "vdivps", "vdivpd", "vdivss", "vdivsd",
];
const X86_AND: &[&str] = &[
    "and", "pand", "vpand", "pandn", "vpandn", "andps", "andpd", "vandps", "vandpd", "andn",
    "blsi", "blsr", "bzhi", "btr",
];
const X86_OR: &[&str] = &["or", "por", "vpor", "orps", "orpd", "vorps", "vorpd", "bts"];
const X86_XOR: &[&str] = &[
    "xor",
    "pxor",
    "vpxor",
    "not",
    "xorps",
    "xorpd",
    "vxorps",
    "vxorpd",
    "blsmsk",
    "btc",
    "aesenc",
    "aesenclast",
    "aesdec",
    "aesdeclast",
    "aeskeygenassist",
    "aesimc",
    "pclmullqlqdq",
    "pclmulhqlqdq",
    "pclmullqhqdq",
    "pclmulhqhqdq",
    "sha1nexte",
    "sha1msg1",
    "sha1msg2",
    "sha1rnds4",
    "sha256rnds2",
    "sha256msg1",
    "sha256msg2",
    "crc32",
];
const X86_SHL: &[&str] = &[
    "shl", "sal", "shld", "shlx", "psllw", "pslld", "psllq", "pslldq", "vpsllw", "vpslld",
    "vpsllq", "vpslldq",
];
const X86_SHR: &[&str] = &[
    "shr", "sar", "rol", "ror", "rcl", "rcr", "shrd", "shrx", "sarx", "rorx", "psrlw", "psrld",
    "psrlq", "psrldq", "vpsrlw", "vpsrld", "vpsrlq", "vpsrldq", "psraw", "psrad", "vpsraw",
    "vpsrad", "palignr", "vpalignr",
];
const X86_CMP: &[&str] = &[
    "cmp",
    "test",
    "bt",
    "cmps",
    "cmpsb",
    "cmpsw",
    "cmpsd",
    "cmpsq",
    "scas",
    "scasb",
    "scasw",
    "scasd",
    "scasq",
    "comiss",
    "comisd",
    "ucomiss",
    "ucomisd",
    "vcomiss",
    "vcomisd",
    "vucomiss",
    "vucomisd",
    "vtestps",
    "vtestpd",
    "vptest",
    "fcom",
    "fcomp",
    "fcompp",
    "fucom",
    "fucomp",
    "fucompp",
    "fcomi",
    "fcomip",
    "fucomi",
    "fucomip",
    "ftst",
    "fxam",
    "ficom",
    "ficomp",
    "pcmpeqb",
    "pcmpeqw",
    "pcmpeqd",
    "pcmpeqq",
    "vpcmpeqb",
    "vpcmpeqw",
    "vpcmpeqd",
    "vpcmpeqq",
    "pcmpgtb",
    "pcmpgtw",
    "pcmpgtd",
    "pcmpgtq",
    "vpcmpgtb",
    "vpcmpgtw",
    "vpcmpgtd",
    "vpcmpgtq",
    "pcmpestri",
    "pcmpestrm",
    "pcmpistri",
    "pcmpistrm",
    "phminposuw",
    "vphminposuw",
];
/// Imm-folded x86 compare pseudo-ops: iced-x86 folds the immediate predicate
/// into the mnemonic (`cmpeqps`, `vcmpltps`, ...), so these publish as
/// patterns with the same `<cond>` placeholder style as AArch64 `b.<cond>`.
const X86_CMP_PATTERNS: &[&str] = &[
    "cmp<cond>ps",
    "cmp<cond>pd",
    "cmp<cond>ss",
    "cmp<cond>sd",
    "vcmp<cond>ps",
    "vcmp<cond>pd",
    "vcmp<cond>ss",
    "vcmp<cond>sd",
];
const X86_JCC: &[&str] = &[
    "jo", "jno", "jb", "jnae", "jc", "jnb", "jae", "jnc", "je", "jz", "jne", "jnz", "jbe", "jna",
    "jnbe", "ja", "js", "jns", "jp", "jpe", "jnp", "jpo", "jl", "jnge", "jnl", "jge", "jle", "jng",
    "jnle", "jg", "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne",
];
const X86_CALL: &[&str] = &["call", "syscall", "sysenter", "int", "int3"];
const X86_RETURN: &[&str] = &[
    "ret", "retn", "retf", "iret", "iretd", "iretq", "sysret", "sysexit",
];
const X86_NOP: &[&str] = &[
    "nop",
    "pause",
    "hlt",
    "fwait",
    "endbr32",
    "endbr64",
    "mfence",
    "lfence",
    "sfence",
    "clflush",
    "clflushopt",
    "clwb",
    "emms",
    "femms",
    "prefetchnta",
    "prefetcht0",
    "prefetcht1",
    "prefetcht2",
    "prefetchw",
    "clc",
    "stc",
    "cmc",
    "cld",
    "std",
    "cli",
    "sti",
    "clac",
    "stac",
    "lahf",
    "sahf",
    "monitor",
    "mwait",
    "vzeroupper",
    "vzeroall",
    "fnop",
    "ffree",
    "fdecstp",
    "fincstp",
    "fnclex",
    "fninit",
];

const ARM_COPY: &[&str] = &[
    "mov",
    "movz",
    "movn",
    "movk",
    "adr",
    "adrp",
    "mvn",
    "movi",
    "dup",
    "smov",
    "umov",
    "ext",
    "tbl",
    "tbx",
    "uzp1",
    "uzp2",
    "trn1",
    "trn2",
    "zip1",
    "zip2",
    "rev",
    "rev16",
    "rev32",
    "rev64",
    "rbit",
    "csel",
    "csinc",
    "csinv",
    "csneg",
    "cinc",
    "cset",
    "cinv",
    "csetm",
    "cneg",
    "fcsel",
    "uxtb",
    "uxth",
    "sxtb",
    "sxth",
    "sxtw",
    "ubfx",
    "sbfx",
    "ubfiz",
    "sbfiz",
    "bfc",
    "bfi",
    "bfxil",
    "extr",
    "clz",
    "cls",
    "cnt",
    "abs",
    "sqabs",
    "xtn",
    "xtn2",
    "sqxtn",
    "sqxtn2",
    "sqxtun",
    "sqxtun2",
    "uqxtn",
    "uqxtn2",
    "fmov",
    "fabs",
    "scvtf",
    "ucvtf",
    "fcvt",
    "fcvtl",
    "fcvtl2",
    "fcvtn",
    "fcvtn2",
    "fcvtxn",
    "fcvtxn2",
    "fcvtns",
    "fcvtnu",
    "fcvtps",
    "fcvtpu",
    "fcvtms",
    "fcvtmu",
    "fcvtas",
    "fcvtau",
    "fcvtzs",
    "fcvtzu",
    "fjcvtzs",
    "bfcvt",
    "frintn",
    "frintp",
    "frintm",
    "frintz",
    "frinta",
    "frintx",
    "frinti",
    "frint32x",
    "frint32z",
    "frint64x",
    "frint64z",
    "fmax",
    "fmin",
    "fmaxnm",
    "fminnm",
    "fmaxp",
    "fmaxnmp",
    "fminp",
    "fminnmp",
    "fmaxv",
    "fmaxnmv",
    "fminv",
    "fminnmv",
    "smax",
    "smin",
    "umax",
    "umin",
    "smaxp",
    "sminp",
    "umaxp",
    "uminp",
    "smaxv",
    "sminv",
    "umaxv",
    "uminv",
    "frecpe",
    "frecps",
    "frecpx",
    "frsqrte",
    "frsqrts",
    "swp",
    "swpl",
    "swpa",
    "swpal",
    "swpb",
    "swplb",
    "swpab",
    "swpalb",
    "swph",
    "swplh",
    "swpah",
    "swpalh",
    "ldsmax",
    "ldsmaxl",
    "ldsmaxa",
    "ldsmaxal",
    "ldsmaxh",
    "ldsmaxlh",
    "ldsmaxah",
    "ldsmaxalh",
    "ldsmaxb",
    "ldsmaxlb",
    "ldsmaxab",
    "ldsmaxalb",
    "ldsmin",
    "ldsminl",
    "ldsmina",
    "ldsminal",
    "ldsminh",
    "ldsminlh",
    "ldsminah",
    "ldsminalh",
    "ldsminb",
    "ldsminlb",
    "ldsminab",
    "ldsminalb",
    "ldumax",
    "ldumaxl",
    "ldumaxa",
    "ldumaxal",
    "ldumaxh",
    "ldumaxlh",
    "ldumaxah",
    "ldumaxalh",
    "ldumaxb",
    "ldumaxlb",
    "ldumaxab",
    "ldumaxalb",
    "ldumin",
    "lduminl",
    "ldumina",
    "lduminal",
    "lduminh",
    "lduminlh",
    "lduminah",
    "lduminalh",
    "lduminb",
    "lduminlb",
    "lduminab",
    "lduminalb",
];
const ARM_LOAD: &[&str] = &[
    "ldr", "ldp", "ldpsw", "ldur", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldurb", "ldurh",
    "ldursb", "ldursh", "ldursw", "ldtr", "ldtrb", "ldtrh", "ldtrsb", "ldtrsh", "ldtrsw", "ldar",
    "ldarb", "ldarh", "ldaxr", "ldaxrb", "ldaxrh", "ldaxp", "ldxr", "ldxrb", "ldxrh", "ldxp",
    "ldlar", "ldlarb", "ldlarh", "ldapr", "ldaprh", "ldaprb", "ldapur", "ldapurb", "ldapurh",
    "ldapursb", "ldapursh", "ldapursw", "ldnp", "ld1", "ld2", "ld3", "ld4", "ld1r", "ld2r", "ld3r",
    "ld4r", "ldraa", "ldrab",
];
const ARM_STORE: &[&str] = &[
    "str", "stp", "stur", "strb", "strh", "sturb", "sturh", "sttr", "sttrb", "sttrh", "stlr",
    "stlrb", "stlrh", "stxr", "stxrb", "stxrh", "stxp", "stlxr", "stlxrb", "stlxrh", "stllr",
    "stllrb", "stllrh", "stlur", "stlurb", "stlurh", "stnp", "st1", "st2", "st3", "st4", "stadd",
    "staddl", "staddh", "staddlh", "staddb", "staddlb", "stclr", "stclrl", "stclrh", "stclrlh",
    "stclrb", "stclrlb", "stset", "stsetl", "stseth", "stsetlh", "stsetb", "stsetlb", "steor",
    "steorl", "steorh", "steorlh", "steorb", "steorlb", "stsmax", "stsmaxl", "stsmaxh", "stsmaxlh",
    "stsmaxb", "stsmaxlb", "stsmin", "stsminl", "stsminh", "stsminlh", "stsminb", "stsminlb",
    "stumax", "stumaxl", "stumaxh", "stumaxlh", "stumaxb", "stumaxlb", "stumin", "stuminl",
    "stuminh", "stuminlh", "stuminb", "stuminlb",
];
const ARM_ADD: &[&str] = &[
    "add", "adds", "adc", "adcs", "fadd", "faddp", "fcadd", "addv", "saddlv", "uaddlv", "saddlp",
    "sadalp", "uaddlp", "uadalp", "addp", "saddl", "saddl2", "uaddl", "uaddl2", "saddw", "saddw2",
    "uaddw", "uaddw2", "shadd", "uhadd", "srhadd", "urhadd", "sqadd", "uqadd", "suqadd", "usqadd",
    "saba", "uaba", "sabal", "sabal2", "uabal", "uabal2", "addhn", "addhn2", "raddhn", "raddhn2",
    "ldadd", "ldaddl", "ldadda", "ldaddal", "ldaddh", "ldaddlh", "ldaddah", "ldaddalh", "ldaddb",
    "ldaddlb", "ldaddab", "ldaddalb",
];
const ARM_SUB: &[&str] = &[
    "sub", "subs", "sbc", "sbcs", "neg", "negs", "ngc", "ngcs", "fsub", "fneg", "sqneg", "fabd",
    "ssubl", "ssubl2", "usubl", "usubl2", "ssubw", "ssubw2", "usubw", "usubw2", "shsub", "uhsub",
    "sqsub", "uqsub", "sabd", "uabd", "subhn", "subhn2", "rsubhn", "rsubhn2", "sabdl", "sabdl2",
    "uabdl", "uabdl2", "subp", "subps",
];
const ARM_MUL: &[&str] = &[
    "mul", "madd", "msub", "mneg", "mla", "mls", "smaddl", "smsubl", "umaddl", "umsubl", "smnegl",
    "umnegl", "smull", "smulh", "umull", "umulh", "smull2", "umull2", "umlal", "umlal2", "smlal",
    "smlal2", "smlsl", "smlsl2", "umlsl", "umlsl2", "sqdmulh", "sqrdmulh", "sqdmull", "sqdmull2",
    "sqdmlal", "sqdmlal2", "sqdmlsl", "sqdmlsl2", "sqrdmlah", "sqrdmlsh", "fmul", "fmulx", "fmla",
    "fmls", "fmlal", "fmlal2", "fmlsl", "fmlsl2", "fcmla", "fmadd", "fmsub", "fnmadd", "fnmsub",
    "fnmul", "pmul", "pmull", "pmull2", "sdot", "udot",
];
const ARM_DIV: &[&str] = &["sdiv", "udiv", "fdiv"];
const ARM_AND: &[&str] = &[
    "and", "ands", "bic", "bics", "ldclr", "ldclrl", "ldclra", "ldclral", "ldclrh", "ldclrlh",
    "ldclrah", "ldclralh", "ldclrb", "ldclrlb", "ldclrab", "ldclralb",
];
const ARM_OR: &[&str] = &[
    "orr", "orn", "bsl", "bit", "bif", "ldset", "ldsetl", "ldseta", "ldsetal", "ldseth", "ldsetlh",
    "ldsetah", "ldsetalh", "ldsetb", "ldsetlb", "ldsetab", "ldsetalb",
];
const ARM_XOR: &[&str] = &[
    "eor",
    "eon",
    "mvni",
    "eor3",
    "bcax",
    "rax1",
    "xar",
    "aese",
    "aesd",
    "aesmc",
    "aesimc",
    "sha1c",
    "sha1h",
    "sha1m",
    "sha1p",
    "sha1su0",
    "sha1su1",
    "sha256h",
    "sha256h2",
    "sha256su0",
    "sha256su1",
    "sha512h",
    "sha512h2",
    "sha512su0",
    "sha512su1",
    "sm3tt1a",
    "sm3tt1b",
    "sm3tt2a",
    "sm3tt2b",
    "sm3partw1",
    "sm3partw2",
    "sm3ss1",
    "sm4e",
    "sm4ekey",
    "crc32b",
    "crc32h",
    "crc32w",
    "crc32x",
    "crc32cb",
    "crc32ch",
    "crc32cw",
    "crc32cx",
    "ldeor",
    "ldeorl",
    "ldeora",
    "ldeoral",
    "ldeorh",
    "ldeorlh",
    "ldeorah",
    "ldeoralh",
    "ldeorb",
    "ldeorlb",
    "ldeorab",
    "ldeoralb",
];
const ARM_SHL: &[&str] = &[
    "lsl", "lslv", "shl", "sshl", "ushl", "srshl", "urshl", "sqrshl", "uqrshl", "sqshl", "uqshl",
    "sqshlu", "sli", "shll", "shll2", "sshll", "sshll2", "ushll", "ushll2",
];
const ARM_SHR: &[&str] = &[
    "lsr",
    "lsrv",
    "asr",
    "asrv",
    "ror",
    "rorv",
    "ushr",
    "sshr",
    "urshr",
    "srshr",
    "usra",
    "ssra",
    "ursra",
    "srsra",
    "sri",
    "shrn",
    "shrn2",
    "rshrn",
    "rshrn2",
    "sqshrn",
    "sqshrn2",
    "sqrshrn",
    "sqrshrn2",
    "sqshrun",
    "sqshrun2",
    "sqrshrun",
    "sqrshrun2",
    "uqshrn",
    "uqshrn2",
    "uqrshrn",
    "uqrshrn2",
];
const ARM_CMP: &[&str] = &[
    "cmp", "cmn", "tst", "ccmn", "ccmp", "cmtst", "fcmp", "fcmpe", "fccmp", "fccmpe", "cmeq",
    "cmgt", "cmge", "cmle", "cmlt", "cmhi", "cmhs", "fcmeq", "fcmge", "fcmgt", "fcmle", "fcmlt",
    "facge", "facgt", "cas", "casl", "casa", "casal", "casb", "caslb", "casab", "casalb", "cash",
    "caslh", "casah", "casalh", "casp", "caspl", "caspa", "caspal",
];
const ARM_CBRANCH: &[&str] = &["cbz", "cbnz", "tbz", "tbnz"];
/// Non-literal AArch64 members: `b.<cond>` / `bc.<cond>` match the
/// [`is_arm_cbranch`] prefix rule, so they publish as patterns, not mnemonics.
const ARM_CBRANCH_PATTERNS: &[&str] = &["b.<cond>", "bc.<cond>"];
const ARM_CALL: &[&str] = &["svc", "hvc", "smc"];
const ARM_RETURN: &[&str] = &["ret", "eret", "retaa", "retab", "eretaa", "eretab"];
const ARM_NOP: &[&str] = &[
    "nop", "hint", "dmb", "dsb", "isb", "brk", "hlt", "sb", "ssbb", "pssbb", "clrex", "wfe", "wfi",
    "sev", "sevl", "yield", "esb", "csdb", "psb", "tsb", "prfm", "prfum", "sys", "sysl", "rmif",
    "setf8", "setf16", "dcps1", "dcps2", "dcps3", "drps",
];

const ARM32_COPY: &[&str] = &[
    "mov", "movw", "movt", "mvn", "adr", "swp", "swpb", "clz", "rev", "rev16", "revsh", "rbit",
    "sxth", "sxtb", "uxth", "uxtb",
];
const ARM32_LOAD: &[&str] = &[
    "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrd", "ldm", "ldmia", "ldmdb", "ldmda", "pop",
    "ldrt", "ldrbt", "ldrht", "ldrsbt", "ldrsht", "ldrex", "ldrexb", "ldrexh", "ldrexd",
];
const ARM32_STORE: &[&str] = &[
    "str", "strb", "strh", "strd", "stm", "stmia", "stmdb", "stmda", "push", "strt", "strbt",
    "strht", "strex", "strexb", "strexh", "strexd",
];
const ARM32_ADD: &[&str] = &[
    "add", "adc", "qadd", "qdadd", "qadd16", "qadd8", "uqadd16", "uqadd8",
];
const ARM32_SUB: &[&str] = &[
    "sub", "sbc", "rsb", "rsc", "qsub", "qdsub", "qsub16", "qsub8", "uqsub16", "uqsub8",
];
const ARM32_MUL: &[&str] = &[
    "mul", "mla", "umaal", "mls", "smlabb", "smlabt", "smlatb", "smlatt", "smlawb", "smlawt",
    "smulbb", "smulbt", "smultb", "smultt", "smlalbb", "smlalbt", "smlaltb", "smlaltt",
];
const ARM32_DIV: &[&str] = &["sdiv", "udiv"];
const ARM32_AND: &[&str] = &["and", "bic"];
const ARM32_OR: &[&str] = &["orr", "orn"];
const ARM32_XOR: &[&str] = &["eor"];
const ARM32_SHL: &[&str] = &["lsl"];
const ARM32_SHR: &[&str] = &["lsr", "asr", "ror", "rrx"];
const ARM32_CMP: &[&str] = &["cmp", "cmn", "tst", "teq"];
const ARM32_CALL: &[&str] = &["svc", "hvc", "smc"];
const ARM32_NOP: &[&str] = &[
    "nop", "dmb", "dsb", "isb", "bkpt", "it", "hint", "wfe", "wfi", "sev", "yield", "cpsid",
    "cpsie", "setend", "dbg",
];

fn is_x86_jcc(s: &str) -> bool {
    X86_JCC.contains(&s)
}

/// Whether `s` is an x86 compare: the literal table plus iced-x86's
/// imm-folded pseudo-ops (`cmpeqps`, `vcmpltps`, ...), which never print in
/// their generic `cmpps`/`vcmpps` form. The `cmp`/`vcmp` prefix with a lane
/// width suffix only ever matches compares; `cmpxchg` and the string
/// `cmps*` forms do not end in a width and stay literal-only.
fn is_x86_cmp(s: &str) -> bool {
    if X86_CMP.contains(&s) {
        return true;
    }
    let t = s.strip_prefix('v').unwrap_or(s);
    t.starts_with("cmp") && ["ps", "pd", "ss", "sd"].iter().any(|w| t.ends_with(w))
}

fn is_x86_call(s: &str) -> bool {
    X86_CALL.contains(&s)
}

fn is_x86_return(s: &str) -> bool {
    X86_RETURN.contains(&s)
}

fn is_x86_nop(s: &str) -> bool {
    X86_NOP.contains(&s)
}

fn is_arm_copy(s: &str) -> bool {
    ARM_COPY.contains(&s)
}

fn is_arm_load(s: &str) -> bool {
    ARM_LOAD.contains(&s)
}

fn is_arm_store(s: &str) -> bool {
    ARM_STORE.contains(&s)
}

fn is_arm_alu(s: &str, op: IrOp) -> bool {
    match op {
        IrOp::Add => ARM_ADD.contains(&s),
        IrOp::Sub => ARM_SUB.contains(&s),
        IrOp::Mul => ARM_MUL.contains(&s),
        IrOp::Div => ARM_DIV.contains(&s),
        IrOp::And => ARM_AND.contains(&s),
        IrOp::Or => ARM_OR.contains(&s),
        IrOp::Xor => ARM_XOR.contains(&s),
        IrOp::Shl => ARM_SHL.contains(&s),
        IrOp::Shr => ARM_SHR.contains(&s),
        _ => false,
    }
}

fn is_arm_cbranch(s: &str) -> bool {
    ARM_CBRANCH.contains(&s) || s.starts_with("b.") || s.starts_with("bc.")
}

fn is_arm_call(s: &str) -> bool {
    ARM_CALL.contains(&s)
}

fn is_arm_return(s: &str) -> bool {
    ARM_RETURN.contains(&s)
}

fn is_arm_nop(s: &str) -> bool {
    ARM_NOP.contains(&s)
}

fn is_arm32_copy(s: &str) -> bool {
    ARM32_COPY.contains(&s)
}

fn is_arm32_load(s: &str) -> bool {
    ARM32_LOAD.contains(&s)
}

fn is_arm32_store(s: &str) -> bool {
    ARM32_STORE.contains(&s)
}

fn is_arm32_alu(s: &str, op: IrOp) -> bool {
    match op {
        IrOp::Add => ARM32_ADD.contains(&s),
        IrOp::Sub => ARM32_SUB.contains(&s),
        IrOp::Mul => ARM32_MUL.contains(&s),
        IrOp::Div => ARM32_DIV.contains(&s),
        IrOp::And => ARM32_AND.contains(&s),
        IrOp::Or => ARM32_OR.contains(&s),
        IrOp::Xor => ARM32_XOR.contains(&s),
        IrOp::Shl => ARM32_SHL.contains(&s),
        IrOp::Shr => ARM32_SHR.contains(&s),
        _ => false,
    }
}

fn is_arm32_call(s: &str) -> bool {
    ARM32_CALL.contains(&s)
}

/// Whether `s` is an ARM32 branch mnemonic handled by [`lift_arm32`]'s
/// explicit control-flow arms (never a `pc`-writing data instruction).
fn is_arm32_branch(s: &str) -> bool {
    matches!(
        s,
        "b" | "bl" | "blx" | "bx" | "cbz" | "cbnz" | "tbb" | "tbh"
    ) || is_arm32_call(s)
}

/// Whether `s` is a load-multiple covered by the `pop`/`ldm`-with-`pc`
/// return rule (`ldm` and its `ia`/`db`/`da` addressing-mode spellings).
fn is_arm32_ldm(s: &str) -> bool {
    s == "pop" || s == "ldm" || s == "ldmia" || s == "ldmdb" || s == "ldmda"
}

/// Whether `s` is a store-multiple covered by the register-list store
/// rule (`stm` and its `ia`/`db`/`da` addressing-mode spellings, plus
/// the `push` alias for `stmdb sp!`).
fn is_arm32_stm(s: &str) -> bool {
    s == "push" || s == "stm" || s == "stmia" || s == "stmdb" || s == "stmda"
}

fn is_arm32_nop(s: &str) -> bool {
    ARM32_NOP.contains(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(mnem: &str, ops: &[&str]) -> Insn {
        Insn {
            addr: 0x1000,
            size: 1,
            bytes: vec![0x90],
            mnem: mnem.to_string(),
            ops: ops.iter().map(|s| (*s).to_string()).collect(),
            branch_target: None,
            mem_target: None,
            table_base: None,
            import: None,
        }
    }

    #[test]
    fn op_names_are_uppercase() {
        assert_eq!(IrOp::Copy.name(), "COPY");
        assert_eq!(IrOp::CBranch.name(), "CBRANCH");
        assert_eq!(IrOp::Nop.name(), "NOP");
        assert!(IrOp::Call.is_control());
        assert!(!IrOp::Add.is_control());
    }

    #[test]
    fn x86_mov_is_copy() {
        let v = lift_x86(&insn("mov", &["rax", "rbx"]));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].op, IrOp::Copy);
        assert_eq!(v[0].outputs, ["rax"]);
        assert_eq!(v[0].inputs, ["rbx"]);
        assert_eq!(v[0].warning, None);
    }

    #[test]
    fn x86_jcc_is_cbranch() {
        let mut i = insn("je", &["short 0x1002"]);
        i.branch_target = Some(0x1002);
        let v = lift_x86(&i);
        assert_eq!(v[0].op, IrOp::CBranch);
        assert_eq!(v[0].target, Some(0x1002));
    }

    #[test]
    fn x86_unknown_is_nop_with_warning() {
        let v = lift_x86(&insn("cpuid", &[]));
        assert_eq!(v[0].op, IrOp::Nop);
        assert!(v[0].warning.is_some());
    }

    #[test]
    fn arm_b_eq_is_cbranch() {
        let mut i = insn("b.eq", &["$+0x8"]);
        i.branch_target = Some(0x4008);
        let v = lift_aarch64(&i);
        assert_eq!(v[0].op, IrOp::CBranch);
        assert_eq!(v[0].target, Some(0x4008));
    }

    #[test]
    fn arm_unknown_is_nop_with_warning() {
        let v = lift_aarch64(&insn("mrs", &["x0", "tpidr_el0"]));
        assert_eq!(v[0].op, IrOp::Nop);
        assert!(v[0].warning.is_some());
    }

    #[test]
    fn arm_adrp_add_pair_second_row_carries_final_address() {
        let mut first = insn("adrp", &["x0", "#0x0"]);
        first.addr = 0x4000;
        first.size = 4;
        first.mem_target = Some(0x4000);
        let mut second = insn("add", &["x0", "x0", "#0x10"]);
        second.addr = 0x4004;
        second.size = 4;
        let v = lift_aarch64_with_prev(&second, Some(&first));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].op, IrOp::Add);
        assert_eq!(v[0].target, Some(0x4010));
        // Single lift keeps current behavior exactly.
        let v = lift_aarch64(&second);
        assert_eq!(v[0].target, None);
        // Nonadjacent pairs never resolve.
        let mut gapped = second.clone();
        gapped.addr = 0x4008;
        let v = lift_aarch64_with_prev(&gapped, Some(&first));
        assert_eq!(v[0].target, None);
    }

    #[test]
    fn lift_never_emits_phi() {
        for m in ["mov", "add", "jmp", "call", "ret", "nop", "cpuid"] {
            for ir in lift_x86(&insn(m, &[])) {
                assert_ne!(ir.op, IrOp::Phi, "mnem {m}");
            }
        }
        for m in ["ldr", "add", "b", "blr", "ret", "nop", "mrs"] {
            for ir in lift_aarch64(&insn(m, &[])) {
                assert_ne!(ir.op, IrOp::Phi, "mnem {m}");
            }
        }
        for m in [
            "mov", "movs", "addeq", "b", "beq", "bl", "bl.w", "blx", "bx", "cbz", "svc", "push",
            "pop", "nop",
        ] {
            for ir in lift_arm32(&insn(m, &[])) {
                assert_ne!(ir.op, IrOp::Phi, "mnem {m}");
            }
        }
    }

    #[test]
    fn arm32_mnem_suffixes_reduce_to_base() {
        assert_eq!(split_arm_mnem("bl.w"), ("bl", false));
        assert_eq!(split_arm_mnem("beq.w"), ("b", true));
        assert_eq!(split_arm_mnem("addeq"), ("add", true));
        assert_eq!(split_arm_mnem("adds"), ("add", false));
        assert_eq!(split_arm_mnem("movs"), ("mov", false));
        // Guarded strips: teq keeps its own base, mrs/svc keep the `s`.
        assert_eq!(split_arm_mnem("teq"), ("teq", false));
        assert_eq!(split_arm_mnem("mrs"), ("mrs", false));
        assert_eq!(split_arm_mnem("svc"), ("svc", false));
        assert_eq!(split_arm_mnem("bls"), ("b", true));
    }

    #[test]
    fn arm32_bx_lr_is_return_but_predicated_is_cbranch() {
        let mut i = insn("bx", &["lr"]);
        assert_eq!(lift_arm32(&i)[0].op, IrOp::Return);
        i = insn("bxeq", &["lr"]);
        let v = lift_arm32(&i);
        assert_eq!(v[0].op, IrOp::CBranch);
        assert_eq!(v[0].target, None);
        // Indirect bx without lr is a plain indirect branch.
        let i = insn("bx", &["r3"]);
        let v = lift_arm32(&i);
        assert_eq!(v[0].op, IrOp::Branch);
        assert_eq!(v[0].target, None);
    }

    #[test]
    fn arm32_pop_pc_is_return() {
        let i = insn("pop", &["{r4, pc}"]);
        assert_eq!(lift_arm32(&i)[0].op, IrOp::Return);
        let i = insn("pop", &["{r4, r5}"]);
        assert_eq!(lift_arm32(&i)[0].op, IrOp::Load);
        let i = insn("push", &["{r4, lr}"]);
        assert_eq!(lift_arm32(&i)[0].op, IrOp::Store);
    }

    #[test]
    fn arm32_cond_branch_is_cbranch() {
        let mut i = insn("beq", &["$+0x8"]);
        i.branch_target = Some(0x1008);
        let v = lift_arm32(&i);
        assert_eq!(v[0].op, IrOp::CBranch);
        assert_eq!(v[0].target, Some(0x1008));
        let i = insn("cbz", &["r0", "$+0x4"]);
        let v = lift_arm32(&i);
        assert_eq!(v[0].op, IrOp::CBranch);
    }

    #[test]
    fn arm32_unknown_is_nop_with_warning() {
        let v = lift_arm32(&insn("mrs", &["r0", "cpsr"]));
        assert_eq!(v[0].op, IrOp::Nop);
        assert!(v[0].warning.is_some());
    }
}
