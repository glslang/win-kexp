//! A64's operands, registers, effect and privilege, decoded from the encoding.
//!
//! [`super::flow`] answers where control goes; this answers what an instruction *is*. The two are
//! separate functions over the same word because they are separate claims — flow landed first,
//! with no operand reader behind it, and [`crate::dbgeng::InstructionSet::operands_are_read`] was
//! `false` here for as long as that was true.
//!
//! # What "decoded" means here, and where the line is
//!
//! A64's general-purpose architecture is decoded in full: the four top-level groups that hold it —
//! data-processing immediate, branches and system, loads and stores, data-processing register —
//! are shaped operand by operand, with the aliases a compiler emits resolved (`cmp` out of `subs`,
//! `mov` out of `orr`, `lsr` out of `ubfm`) because an alias changes the operand *list* and not
//! just the spelling. Of the extensions on top of it, these are read: the atomics and
//! compare-and-swaps, pointer authentication, memory tagging, the acquiring unscaled loads, `crc32`,
//! FlagM, HBC's `bc.cond`, CSSC's minimum and maximum in both their forms, and MOPS' copies and
//! sets.
//!
//! **That paragraph used to be a claim and is now a measurement.** Seven review rounds on
//! dbgscope#171 each found one or two families it was wrong about — `subps`, the tagging accesses,
//! the acquiring loads, `cpyfp` — because nobody could check it: a corpus finds only what a target
//! contains, and no Windows ARM64 image contains any of those.
//! `examples/undecoded_families.rs` checks it instead, by decoding every 32-bit word twice, once
//! here and once with tables generated from the architecture, and listing what the second knows and
//! the first does not. What that leaves, of 3,762 definitions with a general-purpose operand:
//!
//! | left unread | what it is |
//! |---|---|
//! | 112 | SVE, SVE2 and SME — declined, and the section below says why all-or-nothing |
//! | 174 | named extensions past Armv8.2: `THE` and `D128` (64), `LSUI` (34), `LSE128` (12), MOPS' guarded forms (12), CMPBR (24), and `LS64`, `CPA`, `POE2`, `RCPC3`, `LSCP`, `GCS`, `TME`, `WFXT` (28 between them) |
//! | 23 | a definition whose *canonical* encoding is not a legal instruction, so this refuses it correctly: a register-offset load with `option` zero, an `mrs` with bit 20 clear, a fixed-point `fcvtzs` with no fraction bits, a `umov` naming no element size |
//!
//! Nothing in the base architecture is left. The extensions are one command away from being
//! re-counted, which is the point: the next one to be added is a row that moves rather than a round
//! of review.
//!
//! # What is over-accepted, which is the other direction and is deliberate
//!
//! That table counts encodings this decoder does not read. The opposite question — encodings it
//! reads that the architecture does not allocate — was measured once the review rounds kept
//! reaching it, by decoding all 4,294,967,296 words twice and keeping every one this shapes and
//! the generated table refuses. **86 mnemonics, 88,276,608 words, 2.1% of the encoding space**,
//! re-measured after the last of the fixes below -- three of them moved it.
//!
//! What is left is one kind of thing: a *reserved field nobody constrained*. The exclusive and
//! atomic family ignores the `Rs`/`Rt2` values the architecture fixes at `11111`, `crc32` does not
//! check that `sf` matches its variant, `smulh` ignores `Ra`, and the vector-structure forms
//! ignore the bit that must be zero without a post-index. **No real image contains any of them** —
//! the corpus is unmoved by every fix in this space — so what it costs is that `decode_range`
//! walking data reports a plausible instruction where [`Operand::Undecoded`] is the honest answer.
//!
//! It is left open on purpose. Closing it means a fixed-field check in most of the functions here,
//! which is a large change whose own risk is demonstrated in this file's history: two of the four
//! bugs the sizeless-access audit found were *introduced* by tightening a neighbouring guard. The
//! measurement is the deliverable, and `examples/undecoded_families.rs` prints this listing beside
//! the one above — the same sweep, the other direction — so this paragraph is a number to re-run
//! rather than a claim to trust.
//!
//! The Advanced SIMD, scalar floating-point, SVE and SME spaces are **not** shaped, and an
//! instruction in them comes back as a single [`Operand::Undecoded`] naming the space —
//! `advanced-simd`, `floating-point`, `sve`, `unallocated`, `reserved`. (The last of those covers
//! the part of the Reserved space that is *not* `udf #imm16`, that one member being decoded.) That
//! variant exists because this is
//! the first decoder here that reads most of an instruction set rather than all of it, and the
//! distinction had nowhere to live: an *empty* operand list means "this instruction takes none",
//! the same thing it means on x64, so saying "nothing was read" needed a shape of its own rather
//! than a convention about what an [`Operand::Other`] contained. Three review rounds on
//! dbgscope#171 each found a caller that would have read the convention wrongly.
//!
//! # The exception, and where it stops
//!
//! Advanced SIMD and scalar floating-point have one: **every encoding in those two that reaches a
//! general-purpose register or the flags is decoded**, and the list is short enough to give in
//! full — the floating-point conversions in both directions, `fmov` between the register files
//! including its upper-lane form, `umov`/`smov`/`ins`/`dup`, `fcmp`/`fccmp` and `fjcvtzs` for the
//! flags, and the base-register writeback of a vector load or store. Everything left in those two
//! spaces reaches vector registers only, so a caller following a value through a routine — which
//! is following a general-purpose one — loses nothing to it.
//!
//! **SVE and SME have no such exception, and that is a real gap rather than a claim.** `incb x0`
//! increments a general-purpose register by the vector length and `whilelt p0.s,x3,x4` reads two,
//! and both come back as `Operand::Undecoded("sve")` with empty access lists — so a consumer that
//! read those lists as "touches nothing" would keep a value `incb` had changed. Raised on
//! dbgscope#171.
//!
//! It is left that way deliberately, because **a partial decode of that space would be worse than
//! none**. The marker is what tells a caller nothing was read; shaping the counting instructions
//! would remove it from exactly those encodings while leaving the gather loads, the predicate
//! counts and `ctermeq`'s flags unshaped — handing back an access list that looks complete and is
//! not, in place of one that says outright that it is empty. The way to close this is to enumerate
//! the SVE encodings that reach a general-purpose register or the flags and shape all of them at
//! once, the way the two spaces above were; until then the honest answer is the one the marker
//! already gives. Measured on the 26100 ARM64 kernel's `.text` and `PAGE`, the whole SVE space is
//! 1,085 words of which the engine declines to render 958 — so a Windows kernel image barely
//! reaches it, which is why the gap has cost nothing so far and is **not** the reason it is
//! acceptable. The reason is the paragraph above.
//!
//! # What that line costs, measured rather than estimated
//!
//! `examples/decode_against_rendering.rs` decodes every word of an image's executable sections and
//! cross-checks each one against the engine's own rendering of the same four bytes, on the
//! reasoning that a hand-picked fixture is chosen from the shapes its author already knew about.
//! Run over the 26100 ARM64 kernel's `nt` — 2,621,440 instructions across sixteen executable
//! sections, of which the engine rendered 2,513,920 and the rest are pages a minidump does not
//! carry — it takes 51 seconds and reports:
//!
//! * **11,875 unread, 0.501%** of what the engine could render: 11,501 Advanced SIMD, 216 SVE, 157
//!   scalar floating-point, and one encoding no class allocates — a fixed-point conversion asking
//!   for more fraction bits than a 32-bit destination has, which the engine renders and the
//!   architecture does not define. Nothing the four general-purpose groups *do* allocate comes
//!   back unread.
//! * **0** instructions with [`crate::dbgeng::Flow::Unknown`], and **0** disagreements between
//!   this decode and [`crate::dbgeng::DebugEngine::decode_range`]'s over 2,508,800 comparisons.
//! * **0** wrong resolved addresses out of 94,166 — which is what pins `adrp`'s page truncation
//!   and the fact that A64 measures a displacement from the instruction rather than from its end.
//! * **48,116** operand spellings out of 2,896,755 that differ from the rendering, and **22**
//!   registers the rendering names under a spelling this decode did not produce — one question
//!   from both sides rather than two. No category of either is this decoder's: 48,094 are
//!   `tbz`/`tbnz`, where `b5` clear names a `W` register and this engine names an `X` throughout;
//!   20 are a literal `ldrsw`, whose destination the engine prints `W` and the architecture `X`;
//!   one is `xzr`, an operand here and deliberately not a read; and one is register 31 in a
//!   *shifted*-register `subs`, which the engine prints `sp` and the encoding calls the zero
//!   register.
//! * **192** mnemonics out of 2,370,233, each the debugger's preferred spelling rather than the
//!   architecture's — `movi` for a `mov` of a wide bitmask, `mov` for the 57 `umov`s that have a
//!   `MOV` alias, `hint #0x16` for `clrbhb`, `lsl w9,w9,#0` for a `ubfm` whose preferred alias is
//!   `lsr #0`, and `b` for a `b.al` inside a data word.
//!
//! The counts that are not zero above are floors rather than defects, and the run prints what each
//! one was so the two can be told apart. Seven defects were found this way while the decoder was
//! written, among them a `ccmp` whose fixed bit was read the wrong way round — which rejected
//! every one of the 3,009 in the image — and a no-allocate pair load decoded out of an `opc` that
//! form does not allocate, which only a sweep past `.text` reaches.
//!
//! **What a sweep of a Windows kernel cannot find is what a Windows kernel does not contain**, and
//! that is most of what review caught on dbgscope#171: a `brab` spelled backwards, because this
//! image signs with `pacibsp` and returns with a plain `ret`; `subps`, `ldg` and `ldapur`, because
//! nothing here is built for memory tagging. A corpus is a net under the shapes a target uses, and
//! the fixtures beside it are for the ones it does not.
//!
//! **Nothing here panics on any input**, which is worth answering exhaustively rather than by
//! sample: this runs inside a debugger worker, and a word it is handed may be data, a truncated
//! read or a hostile image. All 4,294,967,296 encodings were decoded with the dev profile's
//! overflow checks on, at addresses spread across the whole 64-bit space so that the
//! relative-branch and page arithmetic wraps as well. Seventy-two seconds, no panic.
//!
//! # How much a memory operand says it touches
//!
//! [`MemoryOperand::size`] is the width of the access, and a caller bounding a read or a write has
//! only this. So **every access whose width is encoded reports it**, including the two families
//! where the width is arithmetic rather than a field: a load/store pair reports both registers,
//! and a vector-structure access reports the registers named times the width each transfers —
//! which for a replicating `ld1r` is the *one element it reads*, not the sixteen bytes it writes.
//!
//! Four positions report nothing, and each is a different reason rather than an omission:
//!
//! | reports no size | why |
//! |---|---|
//! | `adr`, `adrp` | no access happens. The operand carries the `address` it computes and nothing reads it — [`Effect::LoadAddress`] is the tell |
//! | `prfm`, `prfum` | the architecture defines no transfer width. `size` in the encoding scales the *offset*, and a range derived from it would be one that does not exist; what is touched is a cache line, which is an implementation's business |
//! | the MOPS copies and fills | the amount moved is a **register's value** at run time, not an encoded field. This is the largest memory effect the architecture has and its size is genuinely not a decode-time fact |
//! | `ldgm`, `stgm`, `stzgm` | the whole-granule tag forms reach as many granules as `GMID_EL1.BS` says, which is again a run-time fact. Their neighbours are *not* in this row: `stg` and `ldg` are one granule and `st2g`/`stz2g` are two, and all four say so |
//!
//! **That list is a measurement rather than a reading of the code**, which is the only reason it is
//! worth stating: every one of the 4,294,967,296 encodings is decoded and every memory operand's
//! size checked, and what comes back is those four and nothing else. Two tests pin the rows, and
//! neither can pin the *closure* — the sweep is what does that, and it lives beside the ones in
//! `examples/`.
//!
//! **Asking the question found three decoding bugs before it found a missing row**, all of them
//! encodings shaped here that the architecture does not allocate, and all of them invisible to
//! both the corpus and the family enumeration: a post-indexed and a pre-indexed `prfm`, an
//! unprivileged prefetch slot decoded as `sttr`, a vector `ldtr`/`sttr`, and — in the other
//! direction — every `ldg` with a nonzero displacement refused as unallocated. A sizeless access
//! turned out to be a good smell for an encoding nobody had constrained, which is the gap the
//! family enumeration explicitly could not reach: it finds a family nobody decoded, not a field
//! nobody checked.
//!
//! # Where register 31 is the stack pointer, in full
//!
//! A64 spells the stack pointer and the zero register with the same five bits, and which one a 31
//! means is decided **per operand position** rather than per instruction. Getting it wrong is not a
//! mislabelled operand: the zero register is dropped from the access lists by design, so an `irg
//! sp,sp` read as `irg xzr,xzr` comes back touching nothing at all.
//!
//! This produced a review finding on dbgscope#171 in two consecutive rounds, the second of them
//! against an audit done from recollection. So here is the list, derived rather than remembered,
//! and `test_register_thirty_one_is_the_stack_pointer_in_exactly_these_positions` pins every row
//! of it against a real encoding:
//!
//! | form | positions where 31 is `sp` |
//! |---|---|
//! | any addressing mode | the base, `Rn` |
//! | `add`/`sub` immediate and extended-register | `Rn`; `Rd` too where it sets no flags |
//! | `and`/`orr`/`eor` immediate | `Rd` — but not `ands`, which is why `tst` exists |
//! | `addg`/`subg` | `Rd`, `Rn` |
//! | `irg` | `Rd`, `Rn` |
//! | `gmi` | `Rn` |
//! | `subp`/`subps` | `Rn`, `Rm` |
//! | `pacga` | `Rm` |
//! | `pacia` and the rest of its family | `Rn`, the modifier |
//! | `braa`/`brab`/`blraa`/`blrab` | `op4`, the modifier |
//! | `stg`/`stzg`/`st2g`/`stz2g` | `Rt` *and* `Rn` |
//! | `ldg`/`ldgm`/`stgm`/`stzgm` | `Rn` only |
//!
//! Everywhere else — the shifted-register arithmetic, the bitfields, the moves, the conditionals,
//! the multiplies, every transfer register that is not a tag store's — a 31 is the zero register.
//!
//! # Two shapes a caller coming from x64 will read wrongly
//!
//! **A store names its source first.** `str x8,[x9]` is `[Register(x8), Memory(…)]`, where x64's
//! `mov [rcx],rax` is `[Memory(…), Register(rax)]`. [`Operand`]s are in the order printed, which
//! is the contract, so `operands[0]` is not the destination on this architecture.
//! [`crate::dbgeng::Instruction::writes`] is the field that answers what changed, and it is right
//! on both.
//!
//! **A modifier the operand list cannot carry demotes the effect.** A64 folds a shift or an
//! extension into an arithmetic operand — `add x8,x9,x10,lsl #3`, `cmp x19,w0,sxtw` — and
//! [`Operand`] has no shape for one. Reporting `[x8, x9, x10, Immediate(3)]` with
//! [`Effect::Add`] would invite a consumer to compute `x9 + 3`, so the modifier is named as an
//! [`Operand::Other`] *and* the effect drops to [`Effect::Other`]: the consumer learns nothing
//! rather than something false. A shift of zero carries no modifier and keeps its effect, which is
//! the form a compiler emits for ordinary arithmetic.
//!
//! A shifted *immediate* is the opposite case and is folded into its value rather than named,
//! because a value is a thing [`Operand::Immediate`] can hold: `sub w0,w0,#0x222,lsl #12` carries
//! `0x222000`, which is the number the processor subtracts and the one dbgscope#170 was filed
//! about. A post-indexed addressing mode's amount is named, having nowhere to be folded into —
//! see [`post_index_amount`].

use crate::dbgeng::{
    Condition, Decoded, Effect, MemoryOperand, Operand, Privilege, RegisterOperand,
};

/// One instruction's decoded shape, built up by the arms below.
///
/// Separate from [`Decoded`] only so the flow is added once, at the end, by the one caller that
/// has the address — every arm here would otherwise carry a field it has nothing to say about.
struct Out {
    mnemonic: String,
    operands: Vec<Operand>,
    effect: Effect,
    condition: Option<Condition>,
    writes_flags: bool,
    privilege: Option<Privilege>,
    writes: Vec<RegisterOperand>,
    reads: Vec<RegisterOperand>,
}

impl Out {
    fn new(mnemonic: &str) -> Self {
        Self {
            mnemonic: mnemonic.to_string(),
            operands: Vec::new(),
            effect: Effect::Other,
            condition: None,
            writes_flags: false,
            privilege: None,
            writes: Vec::new(),
            reads: Vec::new(),
        }
    }

    /// A word in a space this does not shape, which says so in a shape a caller cannot read past:
    /// [`Operand::Undecoded`] naming the space, as the whole operand list.
    ///
    /// The mnemonic is left empty so [`crate::dbgeng::split_instruction`] falls back to the
    /// rendering's first token, which is the engine's own and is worth more than nothing.
    fn undecoded(space: &str) -> Self {
        let mut out = Self::new("");
        out.operands.push(Operand::Undecoded(space.to_string()));
        out
    }

    fn effect(mut self, effect: Effect) -> Self {
        self.effect = effect;
        self
    }

    fn flags(mut self) -> Self {
        self.writes_flags = true;
        self
    }

    fn cond(mut self, condition: Option<Condition>) -> Self {
        self.condition = condition;
        self
    }

    /// Needs privilege to execute, and reaches `family` with it. There is no way to say the first
    /// without the second, which is what keeps [`Decoded::privileged`] and
    /// [`Decoded::privilege`] from disagreeing.
    fn privileged(mut self, family: Privilege) -> Self {
        self.privilege = Some(family);
        self
    }

    /// A register operand the instruction **writes** — the destination of the form.
    fn out_reg(mut self, register: RegisterOperand) -> Self {
        self.record_write(&register);
        self.operands.push(Operand::Register(register));
        self
    }

    /// A register operand the instruction **reads**.
    fn in_reg(mut self, register: RegisterOperand) -> Self {
        self.record_read(&register);
        self.operands.push(Operand::Register(register));
        self
    }

    /// A register operand the instruction reads *and* writes — `movk`'s destination, which keeps
    /// the halves it does not replace, `bfi`'s, and the compare value of a `cas`.
    fn inout_reg(mut self, register: RegisterOperand) -> Self {
        self.record_read(&register);
        self.record_write(&register);
        self.operands.push(Operand::Register(register));
        self
    }

    /// A register the instruction writes without naming it — `bl`'s link register, the base of a
    /// writeback addressing mode.
    fn writes_only(mut self, register: RegisterOperand) -> Self {
        self.record_write(&register);
        self
    }

    /// A register the instruction reads without naming it.
    fn reads_only(mut self, register: RegisterOperand) -> Self {
        self.record_read(&register);
        self
    }

    fn imm(mut self, value: u64) -> Self {
        self.operands.push(Operand::Immediate(value));
        self
    }

    fn target(mut self, address: u64) -> Self {
        self.operands.push(Operand::Target(address));
        self
    }

    fn other(mut self, text: String) -> Self {
        self.operands.push(Operand::Other(text));
        self
    }

    /// A memory operand, whose base and index registers are reads of their own — the contract
    /// [`crate::dbgeng::Instruction::reads`] states, and the reason a `cmp` against a loaded value
    /// reports the address registers without claiming the comparison is about them.
    fn mem(mut self, memory: MemoryOperand) -> Self {
        if let Some(base) = &memory.base {
            self.record_read(base);
        }
        if let Some(index) = &memory.index {
            self.record_read(index);
        }
        self.operands.push(Operand::Memory(memory));
        self
    }

    /// **A write is recorded at the whole register**, which is the contract
    /// [`crate::dbgeng::Instruction::writes`] states and is true of A64 for the same reason it is
    /// true of x64: a 32-bit write zeroes the upper half, so `mov w8,#1` leaves nothing of `x8`
    /// behind and a consumer asking which register stopped holding what it did wants `x8`. The
    /// vector file behaves the same way — a `Q`-clear Advanced SIMD operation and a scalar
    /// floating-point one both zero the lanes above what they wrote — so a vector write is
    /// recorded as the whole `v` register. [`Self::operands`] still carries the spelling the
    /// instruction was written with, those being different questions.
    ///
    /// **The zero register is not recorded.** `xzr` holds no state — a write to it is discarded
    /// and a read of it is the constant zero — so listing it would put a register in that list
    /// that nothing can be tracking. It is still an *operand* wherever the encoding names one and
    /// no alias hides it.
    fn record_write(&mut self, register: &RegisterOperand) {
        if register.full != ZERO_REGISTER {
            self.writes.push(whole(register));
        }
    }

    fn record_read(&mut self, register: &RegisterOperand) {
        if register.full != ZERO_REGISTER {
            self.reads.push(register.clone());
        }
    }
}

/// The 64-bit spelling of the zero register, which is the one value [`Out::record_write`] drops.
const ZERO_REGISTER: &str = "xzr";

/// The whole of the register a narrow spelling is part of. A `v` prefix is the vector file, whose
/// registers are sixteen bytes; everything else here is general-purpose and eight.
fn whole(register: &RegisterOperand) -> RegisterOperand {
    RegisterOperand {
        name: register.full.clone(),
        full: register.full.clone(),
        width: match register.full.starts_with('v') {
            true => 16,
            false => 8,
        },
    }
}

/// `width` bits of `word` starting at `lo`.
const fn field(word: u32, lo: u32, width: u32) -> u32 {
    (word >> lo) & (u32::MAX >> (32 - width))
}

/// A value carried in `bits` of a wider word, read as the signed number it is.
const fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    ((value << shift) as i32 >> shift) as i64
}

/// A general-purpose register, by the name the engine prints for it.
///
/// **The spellings are the debugger's and not the architecture's**, because
/// [`RegisterOperand::name`] has always been "as the engine prints it" and a consumer reading a
/// rendering beside a field should see one register named one way. Measured against the 26100
/// ARM64 kernel's own listing, WinDbg prints `x16`/`x17`/`x18` as `xip0`, `xip1` and `xpr` — the
/// two intra-procedure-call scratch registers and Windows' reserved platform register — and
/// `x29`/`x30` as `fp` and `lr`. The 32-bit views follow: `wip0`, `wpr`, `wfp`, `wlr`.
///
/// `sp` says which of the two meanings register 31 has in this position, the encoding giving it no
/// other tell: the stack pointer in an addressing mode or an `add`'s destination, the zero
/// register nearly everywhere else.
fn gpr(number: u32, wide: bool, sp: bool) -> RegisterOperand {
    RegisterOperand {
        name: gpr_name(number, wide, sp),
        full: gpr_name(number, true, sp),
        width: if wide { 8 } else { 4 },
    }
}

fn gpr_name(number: u32, wide: bool, sp: bool) -> String {
    match (number, sp) {
        (31, true) => if wide { "sp" } else { "wsp" }.to_string(),
        (31, false) => if wide { "xzr" } else { "wzr" }.to_string(),
        (16, _) => if wide { "xip0" } else { "wip0" }.to_string(),
        (17, _) => if wide { "xip1" } else { "wip1" }.to_string(),
        (18, _) => if wide { "xpr" } else { "wpr" }.to_string(),
        (29, _) => if wide { "fp" } else { "wfp" }.to_string(),
        (30, _) => if wide { "lr" } else { "wlr" }.to_string(),
        (n, _) => format!("{}{n}", if wide { 'x' } else { 'w' }),
    }
}

/// The link register, which `bl`, `blr` and the pointer-authentication hints write without naming.
fn link_register() -> RegisterOperand {
    gpr(30, true, false)
}

/// The stack pointer.
fn stack_pointer() -> RegisterOperand {
    gpr(31, true, true)
}

/// A SIMD or floating-point register, at the width this instruction names it by.
///
/// The scalar spellings are the width's own letter — `b`, `h`, `s`, `d`, `q` for one, two, four,
/// eight and sixteen bytes — and [`RegisterOperand::full`] is the `v` form, so a caller matching on
/// it sees one register across the widths exactly as it does for `w8` inside `x8`.
fn vreg(number: u32, bytes: u32) -> RegisterOperand {
    let letter = match bytes {
        1 => 'b',
        2 => 'h',
        4 => 's',
        8 => 'd',
        _ => 'q',
    };
    RegisterOperand {
        name: format!("{letter}{number}"),
        full: format!("v{number}"),
        width: bytes,
    }
}

/// The whole of a vector register, as a form that names no element width sees it.
fn vreg_whole(number: u32) -> RegisterOperand {
    RegisterOperand {
        name: format!("v{number}"),
        full: format!("v{number}"),
        width: 16,
    }
}

/// What a four-bit condition field requires of the flags.
///
/// `None` for `al` and `nv`, which A64 gives the meaning "always": there is no condition there to
/// report, and [`super::flow`] already reports such a branch as unconditional.
fn condition(code: u32) -> Option<Condition> {
    Some(match code {
        0b0000 => Condition::Equal,
        0b0001 => Condition::NotEqual,
        // `cs`/`hs` and `cc`/`lo` are the carry flag, which on A64 as on x86 is the unsigned
        // comparison: `hs` is "higher or same", and spelling it `UnsignedAboveOrEqual` is the
        // whole reason this type is not a mnemonic.
        0b0010 => Condition::UnsignedAboveOrEqual,
        0b0011 => Condition::UnsignedBelow,
        0b0100 => Condition::Negative,
        0b0101 => Condition::NotNegative,
        0b0110 => Condition::Overflow,
        0b0111 => Condition::NotOverflow,
        0b1000 => Condition::UnsignedAbove,
        0b1001 => Condition::UnsignedBelowOrEqual,
        0b1010 => Condition::SignedGreaterOrEqual,
        0b1011 => Condition::SignedLess,
        0b1100 => Condition::SignedGreater,
        0b1101 => Condition::SignedLessOrEqual,
        // `al` and `nv`.
        _ => return None,
    })
}

/// The condition's spelling, which A64 joins to the mnemonic rather than to an operand.
fn condition_suffix(code: u32) -> &'static str {
    match code {
        0b0000 => "eq",
        0b0001 => "ne",
        0b0010 => "hs",
        0b0011 => "lo",
        0b0100 => "mi",
        0b0101 => "pl",
        0b0110 => "vs",
        0b0111 => "vc",
        0b1000 => "hi",
        0b1001 => "ls",
        0b1010 => "ge",
        0b1011 => "lt",
        0b1100 => "gt",
        0b1101 => "le",
        0b1110 => "al",
        _ => "nv",
    }
}

/// The condition with its sense inverted, which is what a conditional-select alias reads: `cset`
/// writes one when the condition holds and is encoded as `csinc` on the *inverse*.
fn invert(code: u32) -> u32 {
    code ^ 1
}

/// A64's logical bitmask immediate, from `N:immr:imms`.
///
/// This is `DecodeBitMasks` out of the architecture, and it is here rather than approximated
/// because the field is not a number: `and x10,x2,#0xF` and `and xpr,xpr,#-0x1000` are the same
/// six bits of `imms` read at two element widths. `None` is the encoding's own answer for the
/// combinations it does not allocate, which are UNDEFINED rather than zero.
fn bitmask_immediate(n: u32, immr: u32, imms: u32, wide: bool) -> Option<u64> {
    let datasize = if wide { 64 } else { 32 };
    // `len` is the position of the highest set bit of `N:NOT(imms)`, which is what picks the
    // element width — 64 down to 2 bits — and 0 would leave a one-bit element, which is not
    // allocated. `N` set with a 32-bit operation is not allocated either.
    let combined = (n << 6) | ((!imms) & 0x3f);
    let len = 31 - combined.leading_zeros() as i32;
    if len < 1 || (!wide && n == 1) {
        return None;
    }
    let esize = 1u32 << len;
    let levels = esize - 1;
    let s = imms & levels;
    let r = immr & levels;
    // `imms` all-ones within the element would ask for an element of every bit set, which the
    // encoding reserves.
    if s == levels {
        return None;
    }
    let mut element: u64 = if s + 1 >= 64 {
        u64::MAX
    } else {
        (1u64 << (s + 1)) - 1
    };
    // Rotate right by `r` within the element, then replicate the element up to the data size.
    if r != 0 {
        element = ((element >> r) | (element << (esize - r))) & mask_of(esize);
    }
    let mut value = 0u64;
    let mut at = 0;
    while at < datasize {
        value |= element << at;
        at += esize;
    }
    Some(value & mask_of(datasize))
}

/// The low `bits` of a `u64`, as a mask. `bits` is 64 at most, which `1 << 64` would not survive.
const fn mask_of(bits: u32) -> u64 {
    match bits >= 64 {
        true => u64::MAX,
        false => (1u64 << bits) - 1,
    }
}

/// One A64 word, decoded into everything but its flow.
///
/// `address` is here for the two forms that fold it into an operand — a PC-relative address
/// computation and a literal load — and for nothing else; A64 measures both from the instruction
/// itself rather than from its end, so there is no instruction length in the arithmetic.
///
/// The dispatch is A64's own top-level table, four bits at 28, and it is a `match` rather than a
/// chain of masks because that table is exhaustive: every word is in exactly one of these groups,
/// and the groups this does not decode are named rather than defaulted.
pub(crate) fn decode(word: u32, address: u64) -> Decoded {
    let out = match field(word, 25, 4) {
        // The Reserved space, whose one allocated member is `udf #imm16` -- everything above its
        // immediate being zero. Inter-function padding is a zero word and is therefore a `udf #0`,
        // which is why `super::flow` stops on it.
        //
        // **Naming it costs nothing and saying nothing was misleading**, because
        // [`super::flow`] already reads this space and stops there: reporting
        // [`Operand::Undecoded`] claimed the word had not been read when its meaning was the one
        // thing about it that was certain. The rest of the space is reserved and *is* unread.
        // Raised on dbgscope#171, where the standalone `decode_instruction` made it visible --
        // there being no rendering to borrow a mnemonic from.
        0b0000 => match word & 0xffff_0000 {
            0 => Out::new("udf").imm((word & 0xffff) as u64),
            _ => Out::undecoded("reserved"),
        },
        // SME, SVE, and the space between them. Vector state, and nothing in them writes a
        // general-purpose register that a Windows kernel image has been seen to use — measured on
        // the 26100 ARM64 `nt`, where the whole of the three is 1,800 words of which 1,673 are
        // padding the engine renders `???`.
        0b0001 | 0b0011 => Out::undecoded("unallocated"),
        0b0010 => Out::undecoded("sve"),
        0b1000 | 0b1001 => data_processing_immediate(word, address),
        0b1010 | 0b1011 => branch_exception_system(word, address),
        op0 if op0 & 0b0101 == 0b0100 => loads_and_stores(word, address),
        op0 if op0 & 0b0111 == 0b0101 => data_processing_register(word),
        // `x111`: Advanced SIMD and scalar floating-point.
        _ => simd_and_floating_point(word),
    };
    Decoded {
        mnemonic: out.mnemonic,
        operands: out.operands,
        flow: super::flow(word, address),
        privileged: out.privilege.is_some(),
        privilege: out.privilege,
        effect: out.effect,
        condition: out.condition,
        writes_flags: out.writes_flags,
        writes: out.writes,
        reads: out.reads,
        // Fixed-width, which is the whole of A64's answer to the question.
        length: Some(super::INSTRUCTION_BYTES),
    }
}

// ---------------------------------------------------------------------------------------------
// Data processing -- immediate
// ---------------------------------------------------------------------------------------------

fn data_processing_immediate(word: u32, address: u64) -> Out {
    match field(word, 23, 3) {
        0b000 | 0b001 => pc_relative(word, address),
        0b010 => add_subtract_immediate(word),
        0b011 => add_subtract_immediate_tags(word),
        0b100 => logical_immediate(word),
        0b101 => move_wide_immediate(word),
        0b110 => bitfield(word),
        _ => extract(word),
    }
}

/// `adr` and `adrp`, which compute an address and read no memory — x64's `lea`, and reported the
/// way that one is: a [`MemoryOperand`] whose [`MemoryOperand::address`] is the answer, with
/// [`Effect::LoadAddress`] beside it. Nothing at run time contributes to either, which is the
/// condition that field exists for.
///
/// `adrp` is a *page* address: the 21-bit displacement is in 4 KiB units and the instruction's own
/// address is truncated to its page before the addition, which is the step a reading that took the
/// whole address would get wrong by up to 4,095.
fn pc_relative(word: u32, address: u64) -> Out {
    let immediate = (field(word, 5, 19) << 2) | field(word, 29, 2);
    let page = word & 0x8000_0000 != 0;
    let target = match page {
        true => (address & !0xfff).wrapping_add((sign_extend(immediate, 21) * 4096) as u64),
        false => address.wrapping_add(sign_extend(immediate, 21) as u64),
    };
    Out::new(if page { "adrp" } else { "adr" })
        .out_reg(gpr(field(word, 0, 5), true, false))
        .mem(MemoryOperand {
            address: Some(target),
            ..MemoryOperand::default()
        })
        .effect(Effect::LoadAddress)
}

/// `add`/`adds`/`sub`/`subs` against a twelve-bit immediate, optionally shifted left by twelve.
///
/// **The shift is folded into the value**, which is the one thing issue #170 named outright: the
/// compare chain a compiler emits for a control-code switch is `sub wN,wM,#0x222,lsl #12` against
/// a literal, and an `Operand::Immediate` holding `0x222` describes a different comparison from
/// the one the processor makes. `lsl #12` is not a modifier the operand list cannot carry, unlike
/// a shifted *register* — it is an immediate, and this is its value.
fn add_subtract_immediate(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    let subtract = word & 0x4000_0000 != 0;
    let sets_flags = word & 0x2000_0000 != 0;
    let shift = field(word, 22, 2);
    // Only `00` and `01` are allocated; the other two are UNDEFINED rather than a wider shift.
    if shift > 1 {
        return Out::undecoded("unallocated");
    }
    let value = (field(word, 10, 12) as u64) << (shift * 12);
    let (rd, rn) = (field(word, 0, 5), field(word, 5, 5));
    // The destination is the stack pointer's spelling only where it cannot set flags: `adds`/`subs`
    // write the zero register when `Rd` is 31, which is exactly what makes `cmp` and `cmn` aliases
    // of them.
    let destination = gpr(rd, wide, !sets_flags);
    let source = gpr(rn, wide, true);
    match (sets_flags, subtract, rd, value) {
        // `cmp Rn,#imm` -- `subs` discarding its result.
        (true, true, 31, _) => Out::new("cmp")
            .in_reg(source)
            .imm(value)
            .effect(Effect::Compare)
            .flags(),
        // `cmn Rn,#imm` is **not** [`Effect::Compare`]. It compares against the negation, and a
        // consumer reading it as a compare against `imm` reads the test backwards -- the same
        // trap `ja` against `jg` is on the other architecture.
        (true, false, 31, _) => Out::new("cmn").in_reg(source).imm(value).flags(),
        // `mov Rd,Rn` between a stack pointer and a register, which is how a frame pointer is
        // established: `add` with a zero immediate where either end is register 31.
        (false, false, _, 0) if shift == 0 && (rd == 31 || rn == 31) => Out::new("mov")
            .out_reg(destination)
            .in_reg(source)
            .effect(Effect::Move),
        _ => {
            let out = Out::new(match (subtract, sets_flags) {
                (false, false) => "add",
                (false, true) => "adds",
                (true, false) => "sub",
                (true, true) => "subs",
            })
            .out_reg(destination)
            .in_reg(source)
            .imm(value)
            .effect(match subtract {
                true => Effect::Subtract,
                false => Effect::Add,
            });
            match sets_flags {
                true => out.flags(),
                false => out,
            }
        }
    }
}

/// `addg`/`subg`, which adjust a pointer's address and its tag together. Decoded for its registers
/// rather than for its arithmetic: the tag is not a value a caller here follows.
fn add_subtract_immediate_tags(word: u32) -> Out {
    // **This slot holds two families, and the bit that separates them is the one an earlier
    // version rejected on.** With bit 22 set it is CSSC's minimum and maximum against an eight-bit
    // literal, whose register forms this already decoded two classes away -- so half a family was
    // read and half was not. Found by enumerating a generated instruction table against this
    // decoder rather than by review; see `examples/undecoded_families.rs`.
    if word & 0x0040_0000 != 0 {
        let wide = word & 0x8000_0000 != 0;
        if word & 0x6000_0000 != 0 {
            return Out::undecoded("unallocated");
        }
        let (mnemonic, signed) = match field(word, 18, 2) {
            0b00 => ("smax", true),
            0b01 => ("umax", false),
            0b10 => ("smin", true),
            _ => ("umin", false),
        };
        let literal = field(word, 10, 8);
        return Out::new(mnemonic)
            .out_reg(gpr(field(word, 0, 5), wide, false))
            .in_reg(gpr(field(word, 5, 5), wide, false))
            .imm(match signed {
                true => sign_extend(literal, 8) as u64,
                false => literal as u64,
            });
    }
    // The tagged add and subtract, which are 64-bit only.
    if word & 0x8000_0000 == 0 {
        return Out::undecoded("unallocated");
    }
    Out::new(match word & 0x4000_0000 == 0 {
        true => "addg",
        false => "subg",
    })
    .out_reg(gpr(field(word, 0, 5), true, true))
    .in_reg(gpr(field(word, 5, 5), true, true))
    .imm((field(word, 16, 6) as u64) * 16)
    .imm(field(word, 10, 4) as u64)
}

/// `and`/`orr`/`eor`/`ands` against a bitmask immediate, with `mov` and `tst` resolved out of them.
fn logical_immediate(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    let opc = field(word, 29, 2);
    let Some(value) = bitmask_immediate(
        field(word, 22, 1),
        field(word, 16, 6),
        field(word, 10, 6),
        wide,
    ) else {
        return Out::undecoded("unallocated");
    };
    let (rd, rn) = (field(word, 0, 5), field(word, 5, 5));
    let source = gpr(rn, wide, false);
    // **Built once, because the aliases below share it.** `and`, `orr` and `eor` may write the
    // stack pointer and `ands` may not, which is what makes `tst` its alias -- and the `mov` arm
    // constructing its own destination is how that rule was stated twice and got wrong once:
    // `mov sp,#imm` reported writing nothing at all, the zero register being dropped by design.
    // Raised on dbgscope#171.
    let destination = gpr(rd, wide, opc != 0b11);
    match (opc, rd, rn) {
        // `mov Rd,#imm` -- `orr` from the zero register, which is how a constant too wide for a
        // `movz` but regular enough for a bitmask reaches a register in one instruction.
        (0b01, _, 31) => Out::new("mov")
            .out_reg(destination)
            .imm(value)
            .effect(Effect::Move),
        // `tst Rn,#imm` -- `ands` discarding its result.
        (0b11, 31, _) => Out::new("tst")
            .in_reg(source)
            .imm(value)
            .effect(Effect::Test)
            .flags(),
        _ => {
            let out = Out::new(match opc {
                0b00 => "and",
                0b01 => "orr",
                0b10 => "eor",
                _ => "ands",
            })
            .out_reg(destination)
            .in_reg(source)
            .imm(value)
            .effect(match opc {
                0b00 | 0b11 => Effect::BitAnd,
                0b01 => Effect::BitOr,
                _ => Effect::BitXor,
            });
            match opc == 0b11 {
                true => out.flags(),
                false => out,
            }
        }
    }
}

/// `movz`/`movn`/`movk`, the three halves of building a 64-bit constant.
///
/// `movz` and `movn` are reported as `mov` against the value they produce, which is what the
/// engine prints and what the instruction does: `movn` writes the bitwise complement of its
/// shifted immediate, so a caller reading the field would have the wrong number and the wrong
/// sign. `movk` keeps its own name because it is not a copy — it replaces one sixteen-bit half and
/// leaves the rest, which makes its destination a **read** as well as a write, and that is the
/// fact a value-tracking pass needs from it.
///
/// **All three report the immediate already shifted**, so a pair that builds a constant reports
/// the two halves of it rather than the same sixteen bits twice. Measured on
/// `mountmgr!MountMgrDeviceControl` in the ARM64 kernel dump, where a control code is built by
/// exactly that pair: `mov w8,#0xC004` then `movk w8,#0x6D,lsl #0x10`, whose operands are
/// `0xc004` and `0x6d0000` and whose union is the `0x6dc004` the routine goes on to compare
/// against.
fn move_wide_immediate(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    let opc = field(word, 29, 2);
    let shift = field(word, 21, 2) * 16;
    // `hw` above one is a 64-bit-only encoding, and `opc` 01 is unallocated.
    if opc == 0b01 || (!wide && shift >= 32) {
        return Out::undecoded("unallocated");
    }
    let immediate = (field(word, 5, 16) as u64) << shift;
    let destination = gpr(field(word, 0, 5), wide, false);
    match opc {
        0b00 => Out::new("mov")
            .out_reg(destination)
            .imm(!immediate & mask_of(if wide { 64 } else { 32 }))
            .effect(Effect::Move),
        0b10 => Out::new("mov")
            .out_reg(destination)
            .imm(immediate)
            .effect(Effect::Move),
        _ => Out::new("movk").inout_reg(destination).imm(immediate),
    }
}

/// `sbfm`/`bfm`/`ubfm`, and the twelve aliases that are how they are ever written.
///
/// The aliases are not a spelling here. `lsr x0,x0,#16` and `ubfx x0,x0,#16,#8` are the same three
/// encoded fields read two ways, and they have **different operand lists** — three operands
/// against four — so a consumer that matched the base form would be reading a shift amount out of
/// a field position. Resolving them is what makes [`Effect::ShiftRight`] answerable at all.
fn bitfield(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    let opc = field(word, 29, 2);
    // `N` tracks `sf`, and a mismatch is unallocated.
    if field(word, 22, 1) != u32::from(wide) || opc == 0b11 {
        return Out::undecoded("unallocated");
    }
    let (immr, imms) = (field(word, 16, 6), field(word, 10, 6));
    let datasize = if wide { 64 } else { 32 };
    if immr >= datasize || imms >= datasize {
        return Out::undecoded("unallocated");
    }
    let destination = gpr(field(word, 0, 5), wide, false);
    let source = gpr(field(word, 5, 5), wide, false);
    // The extending aliases read a *narrow* source: `sxtb x0,w0` names `w0` whatever `sf` says,
    // the byte being taken from the low end either way.
    //
    // **Only the word-width ones carry a move effect**, and the difference is whether an operand's
    // width says how much was extended. `uxtw x0,w0` extends exactly the four bytes `w0` names, so
    // a consumer propagating the value is right; `uxtb x0,w0` extends *one* byte of a register
    // named as four, and the narrowness is in the mnemonic where no operand expresses it -- so
    // [`Effect::Move`] there would invite a copy that is only correct when the value happens to
    // fit in a byte. It is the same reason `bic` is not [`Effect::BitAnd`]: the operands do not
    // carry the whole operation. Review on dbgscope#171 raised the mnemonic; this is what was
    // underneath it.
    //
    // The mnemonics themselves stay as the engine spells them, `uxtb x0,w1` for a 64-bit `ubfm`
    // included, which the architecture's alias table reserves for the 32-bit form and calls
    // `ubfx`. That is the same deviation the `uxtw` arm below records, and with the effect no
    // longer claiming more than the operands do it costs a spelling rather than a reading.
    let narrow_source = gpr(field(word, 5, 5), false, false);
    match opc {
        // SBFM.
        0b00 => match (immr, imms) {
            (0, 7) => Out::new("sxtb").out_reg(destination).in_reg(narrow_source),
            (0, 15) => Out::new("sxth").out_reg(destination).in_reg(narrow_source),
            (0, 31) if wide => Out::new("sxtw")
                .out_reg(destination)
                .in_reg(narrow_source)
                .effect(Effect::MoveSigned),
            (_, _) if imms == datasize - 1 => Out::new("asr")
                .out_reg(destination)
                .in_reg(source)
                .imm(immr as u64)
                .effect(Effect::ShiftRight),
            (_, _) if imms < immr => Out::new("sbfiz")
                .out_reg(destination)
                .in_reg(source)
                .imm(((datasize - immr) % datasize) as u64)
                .imm((imms + 1) as u64),
            _ => Out::new("sbfx")
                .out_reg(destination)
                .in_reg(source)
                .imm(immr as u64)
                .imm((imms - immr + 1) as u64),
        },
        // BFM, whose destination keeps the bits it does not replace and is therefore a read.
        0b01 => match (imms < immr, field(word, 5, 5)) {
            (true, 31) => Out::new("bfc")
                .inout_reg(destination)
                .imm(((datasize - immr) % datasize) as u64)
                .imm((imms + 1) as u64),
            (true, _) => Out::new("bfi")
                .inout_reg(destination)
                .in_reg(source)
                .imm(((datasize - immr) % datasize) as u64)
                .imm((imms + 1) as u64),
            (false, _) => Out::new("bfxil")
                .inout_reg(destination)
                .in_reg(source)
                .imm(immr as u64)
                .imm((imms - immr + 1) as u64),
        },
        // UBFM.
        _ => match (immr, imms) {
            (0, 7) => Out::new("uxtb").out_reg(destination).in_reg(narrow_source),
            (0, 15) => Out::new("uxth").out_reg(destination).in_reg(narrow_source),
            // A 64-bit extract of the low thirty-two bits is a zero-extending copy, and the
            // engine names it `uxtw`. That is **not** one of the architecture's aliases — ARM
            // leaves it as `ubfx`, there being a `mov Wd,Wn` that does the same — and it is
            // taken here anyway, because the alternative is [`Effect::Other`] over a four-operand
            // bitfield extraction for what is the commonest widening copy in the image.
            (0, 31) if wide => Out::new("uxtw")
                .out_reg(destination)
                .in_reg(narrow_source)
                .effect(Effect::Move),
            (_, _) if imms == datasize - 1 => Out::new("lsr")
                .out_reg(destination)
                .in_reg(source)
                .imm(immr as u64)
                .effect(Effect::ShiftRight),
            (_, _) if imms + 1 == immr => Out::new("lsl")
                .out_reg(destination)
                .in_reg(source)
                .imm((datasize - immr) as u64)
                .effect(Effect::ShiftLeft),
            (_, _) if imms < immr => Out::new("ubfiz")
                .out_reg(destination)
                .in_reg(source)
                .imm(((datasize - immr) % datasize) as u64)
                .imm((imms + 1) as u64),
            _ => Out::new("ubfx")
                .out_reg(destination)
                .in_reg(source)
                .imm(immr as u64)
                .imm((imms - immr + 1) as u64),
        },
    }
}

/// `extr`, and the `ror` it is written as when both source registers are the same.
fn extract(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    let imms = field(word, 10, 6);
    if field(word, 29, 2) != 0
        || field(word, 21, 1) != 0
        || field(word, 22, 1) != u32::from(wide)
        || (!wide && imms >= 32)
    {
        return Out::undecoded("unallocated");
    }
    let (rn, rm) = (field(word, 5, 5), field(word, 16, 5));
    let out = Out::new(if rn == rm { "ror" } else { "extr" })
        .out_reg(gpr(field(word, 0, 5), wide, false))
        .in_reg(gpr(rn, wide, false));
    match rn == rm {
        true => out.imm(imms as u64),
        false => out.in_reg(gpr(rm, wide, false)).imm(imms as u64),
    }
}

// ---------------------------------------------------------------------------------------------
// Branches, exception generating and system instructions
// ---------------------------------------------------------------------------------------------

fn branch_exception_system(word: u32, address: u64) -> Out {
    let (op0, op1) = (field(word, 29, 3), field(word, 22, 4));
    match (op0, op1) {
        // `b.cond` and FEAT_HBC's `bc.cond`, which differ in whether the branch is a hint to the
        // predictor and not in anything this reports.
        (0b010, op1) if op1 & 0b1000 == 0 => conditional_branch(word, address),
        (0b110, op1) if op1 & 0b1100 == 0 => exception(word),
        (0b110, 0b0100) => system(word),
        (0b110, op1) if op1 & 0b1000 != 0 => branch_register(word),
        (op0, _) if op0 & 0b011 == 0 => branch_immediate(word, address),
        (op0, op1) if op0 & 0b011 == 0b001 && op1 & 0b1000 == 0 => {
            compare_and_branch(word, address)
        }
        (op0, _) if op0 & 0b011 == 0b001 => test_and_branch(word, address),
        _ => Out::undecoded("unallocated"),
    }
}

fn conditional_branch(word: u32, address: u64) -> Out {
    if field(word, 24, 1) != 0 {
        return Out::undecoded("unallocated");
    }
    let code = field(word, 0, 4);
    // `o0` picks FEAT_HBC's `bc.cond`, a conditional branch the processor is told not to speculate
    // past. [`super::flow`] does not read it, both forms having the same two edges; the mnemonic
    // does, because they are different instructions. The engine on this bench refuses the encoding
    // outright rather than rendering it as a `b.cond`, which is the clearest evidence of that.
    let stem = match field(word, 4, 1) {
        0 => "b",
        _ => "bc",
    };
    Out::new(&format!("{stem}.{}", condition_suffix(code)))
        .target(super::relative(address, field(word, 5, 19), 19))
        .cond(condition(code))
}

/// `b` and `bl`. The link register is written by `bl` and named by neither, which is the case
/// [`Out::writes_only`] exists for — a caller tracking a value in `lr` across a call is tracking
/// something the call destroyed.
fn branch_immediate(word: u32, address: u64) -> Out {
    let link = word & 0x8000_0000 != 0;
    let out = Out::new(if link { "bl" } else { "b" }).target(super::relative(
        address,
        field(word, 0, 26),
        26,
    ));
    match link {
        true => out.writes_only(link_register()),
        false => out,
    }
}

fn compare_and_branch(word: u32, address: u64) -> Out {
    Out::new(match field(word, 24, 1) {
        0 => "cbz",
        _ => "cbnz",
    })
    .in_reg(gpr(field(word, 0, 5), word & 0x8000_0000 != 0, false))
    .target(super::relative(address, field(word, 5, 19), 19))
}

/// `tbz`/`tbnz`. The bit number is split across the word, its top bit sitting where `sf` does
/// everywhere else.
///
/// **`b5` is a width selector as well as the bit number's top bit**, and an earlier draft of this
/// argued it could not be both. It is: the architecture names a `W` register when it is clear and
/// an `X` when it is set, and those agree with each other, a bit number of 32 or more needing a
/// 64-bit operand to be in.
///
/// **The engine disagrees and is the outlier.** Measured over the 26100 ARM64 kernel's 23,448 of
/// these, it names an `X` register in every single one, `b5` set or clear -- where the
/// architecture's syntax and a second disassembler both name `W` for the clear half. The encoding
/// is what this decodes, so the encoding wins, and [`RegisterOperand::full`] is `x8` either way,
/// which is what keeps the two spellings one register for anything matching on it.
/// Raised on dbgscope#171.
fn test_and_branch(word: u32, address: u64) -> Out {
    let bit = (field(word, 31, 1) << 5) | field(word, 19, 5);
    Out::new(match field(word, 24, 1) {
        0 => "tbz",
        _ => "tbnz",
    })
    .in_reg(gpr(field(word, 0, 5), bit >= 32, false))
    .imm(bit as u64)
    .target(super::relative(address, field(word, 5, 14), 14))
}

/// `br`, `blr`, `ret`, `eret` and `drps`, with the pointer-authentication forms of the first three.
fn branch_register(word: u32) -> Out {
    let (op2, op3, op4) = (field(word, 16, 5), field(word, 10, 6), field(word, 0, 5));
    if op2 != 0b11111 {
        return Out::undecoded("unallocated");
    }
    // `op3` carries the authentication: none, `a`-key or `b`-key. A form that names a second
    // register (`braa`) has `op4` as that register; a form that does not requires it to be zero,
    // or `11111` for the returns.
    //
    // **The key is the letter after the `a`, not in place of it.** The family is `braa`/`brab`,
    // `retaa`/`retab` — a fixed `a` for the instruction and then the key — so a mnemonic built as
    // `br` + key + `a` spells every b-key form backwards, and no Windows ARM64 image measured here
    // contains one to notice it by. Raised on dbgscope#171.
    let key = match op3 {
        0b000000 => "",
        0b000010 => "a",
        0b000011 => "b",
        _ => return Out::undecoded("unallocated"),
    };
    let rn = field(word, 5, 5);
    // **A form that does not use a field is one the architecture fixes**, and the paragraph above
    // has said so since it was written while nothing enforced it: `0xd61f0001` decoded as `br x0`,
    // and an authenticated return with a stray `Rn` reported reads of the link register and the
    // stack pointer that the word does not name. That matters where `decode_range` walks data or a
    // malformed image, which is the case the marker exists for -- a consumer sees a complete
    // branch instead of [`Operand::Undecoded`], and a walker follows it. Raised on dbgscope#171
    // and settled by differencing this whole space against the generated table rather than by
    // deriving eleven forms from memory.
    //
    // `op4` is a register only in the modifier forms; otherwise it is zero without authentication
    // and `11111` with it, that being where the key's own `Zm` would sit.
    let op4_fixed = match key.is_empty() {
        true => 0b00000,
        false => 0b11111,
    };
    // **And a modifier form exists only with a key.** `braa`/`brab` and `blraa`/`blrab` are the
    // whole of the `opc` bit-three space; there is no plain `br` that takes a second register, so
    // `0xd71f0000` is not a `br x0` reading `x0` as a modifier -- it is not an instruction. Spelled
    // by the `("", _)` arm below, which answers for the key and not for the form.
    let modifier_form = field(word, 21, 4) & 0b1000 != 0;
    if modifier_form && key.is_empty() {
        return Out::undecoded("unallocated");
    }
    match field(word, 21, 4) {
        // `br`/`braaz`/`brabz`, then `braa`/`brab`, which name a modifier register.
        opc @ (0b0000 | 0b1000) => {
            let modifier = opc == 0b1000;
            if !modifier && op4 != op4_fixed {
                return Out::undecoded("unallocated");
            }
            let out = Out::new(&match (key, modifier) {
                ("", _) => "br".to_string(),
                (key, false) => format!("bra{key}z"),
                (key, true) => format!("bra{key}"),
            })
            .in_reg(gpr(rn, true, false));
            match modifier {
                true => out.in_reg(gpr(op4, true, true)),
                false => out,
            }
        }
        opc @ (0b0001 | 0b1001) => {
            let modifier = opc == 0b1001;
            if !modifier && op4 != op4_fixed {
                return Out::undecoded("unallocated");
            }
            let out = Out::new(&match (key, modifier) {
                ("", _) => "blr".to_string(),
                (key, false) => format!("blra{key}z"),
                (key, true) => format!("blra{key}"),
            })
            .in_reg(gpr(rn, true, false));
            let out = match modifier {
                true => out.in_reg(gpr(op4, true, true)),
                false => out,
            };
            out.writes_only(link_register())
        }
        // `ret`, whose operand is omitted where it is the link register -- which is every `ret` a
        // compiler emits, and is why the engine prints the mnemonic alone.
        0b0010 => {
            if op4 != op4_fixed || (!key.is_empty() && rn != 0b11111) {
                return Out::undecoded("unallocated");
            }
            let out = Out::new(&match key {
                "" => "ret".to_string(),
                key => format!("reta{key}"),
            });
            match (key, rn) {
                ("", 30) => out.reads_only(link_register()),
                ("", _) => out.in_reg(gpr(rn, true, false)),
                // `retaa`/`retab` authenticate the link register against the stack pointer and
                // name neither.
                _ => out.reads_only(link_register()).reads_only(stack_pointer()),
            }
        }
        // `eret` and `drps` return from an exception and from debug state. Both are EL1 and above.
        0b0100 => {
            if rn != 0b11111 || op4 != op4_fixed {
                return Out::undecoded("unallocated");
            }
            let out = Out::new(&match key {
                "" => "eret".to_string(),
                key => format!("ereta{key}"),
            })
            .privileged(Privilege::Other);
            // `eretaa`/`eretab` authenticate the saved exception return address against the stack
            // pointer, exactly as `retaa` does the link register, and name it no more than that
            // one does. Raised on dbgscope#171: the `ret` arm above recorded the modifier and this
            // did not.
            match key.is_empty() {
                true => out,
                false => out.reads_only(stack_pointer()),
            }
        }
        0b0101 if key.is_empty() && rn == 0b11111 && op4 == 0 => {
            Out::new("drps").privileged(Privilege::Other)
        }
        _ => Out::undecoded("unallocated"),
    }
}

/// The exception-generating class. Only the system-call family returns to the following word, and
/// [`super::flow`] is where that distinction lives; here the question is which of them needs
/// privilege to execute at all.
fn exception(word: u32) -> Out {
    if field(word, 2, 3) != 0 {
        return Out::undecoded("unallocated");
    }
    let immediate = field(word, 5, 16) as u64;
    let (opc, ll) = (field(word, 21, 3), field(word, 0, 2));
    match (opc, ll) {
        (0b000, 0b01) => Out::new("svc").imm(immediate),
        (0b000, 0b10) => Out::new("hvc")
            .imm(immediate)
            .privileged(Privilege::Virtualization),
        (0b000, 0b11) => Out::new("smc")
            .imm(immediate)
            .privileged(Privilege::Virtualization),
        (0b001, 0b00) => Out::new("brk").imm(immediate),
        // **`hlt` is not privileged here, though the x86 instruction of that name is.** A64's is a
        // debug trap -- it enters Debug state where halting is allowed and is UNDEFINED where it
        // is not -- rather than an operation gated on the exception level, and it sits beside
        // `brk` rather than beside `eret`.
        (0b010, 0b00) => Out::new("hlt").imm(immediate),
        (0b011, 0b00) => Out::new("tcancel").imm(immediate),
        (0b101, level @ 0b01..=0b11) => Out::new(&format!("dcps{level}"))
            .imm(immediate)
            .privileged(Privilege::Other),
        _ => Out::undecoded("unallocated"),
    }
}

/// The system class: hints, barriers, `msr`, `mrs` and the `sys` family.
///
/// # Privilege is read off `op1`, not off a register's name
///
/// A64 puts the minimum exception level of a system register or operation in the encoding's `op1`
/// field, and `011` is the one value that names EL0. So "does this need privilege" is a field read
/// rather than a table of register names — which is the same argument the x64 side makes for
/// taking `privileged` from the decoder instead of a mnemonic list, and it matters more here: a
/// name table for AArch64's system registers is hundreds of rows long and grows with every
/// architecture revision, and the row nobody adds is the one a driver touches.
///
/// **The interrupt-mask fields are the exception, and they are one deliberately.** `msr daifset`
/// and `msr daifclr` encode `op1` as `011`, and they are still EL1 operations — EL0 may write them
/// only where `SCTLR_EL1.UMA` allows it, which is a run-time fact rather than an encoded one. They
/// are also the exact counterpart of the `cli`/`sti` that the x64 side counts as privileged for
/// the same reason. So the rule is `op1` plus those two, and nothing else is carved out.
fn system(word: u32) -> Out {
    let load = field(word, 21, 1) != 0;
    let (op0, op1) = (field(word, 19, 2), field(word, 16, 3));
    let (crn, crm, op2) = (field(word, 12, 4), field(word, 8, 4), field(word, 5, 3));
    let rt = field(word, 0, 5);
    match (op0, load) {
        // `op0` zero is the hint, barrier and PSTATE space, all of which are writes. A read there
        // is unallocated, and falling through to the arm below would name a system register out of
        // an `op0` no system register has.
        (0b00, true) => Out::undecoded("unallocated"),
        (0b00, false) => match crn {
            0b0010 if op1 == 0b011 && rt == 0b11111 => hint((crm << 3) | op2),
            0b0011 => barrier(crm, op2),
            0b0100 if rt == 0b11111 => pstate(op1, crm, op2),
            _ => Out::undecoded("unallocated"),
        },
        // `sys` and `sysl` -- and `at`, `dc`, `ic` and `tlbi`, which are how the useful members of
        // the family are written. [`maintenance`] says which of the four an encoding is, if any,
        // and the family comes with the name, so the two cannot disagree.
        (0b01, _) => {
            let (mnemonic, family) = match maintenance(load, crn, crm, op1, op2) {
                Some(named) => named,
                None if load => ("sysl", Privilege::Other),
                None => ("sys", Privilege::Other),
            };
            let out = Out::new(mnemonic);
            let out = match load {
                true => out.out_reg(gpr(rt, true, false)),
                false => out,
            };
            let out = out
                .imm(op1 as u64)
                .other(format!("C{crn}"))
                .other(format!("C{crm}"))
                .imm(op2 as u64);
            let out = match (load, rt) {
                (false, 0b11111) => out,
                (false, _) => out.in_reg(gpr(rt, true, false)),
                (true, _) => out,
            };
            // **A system operation is privileged whatever its `op1` says**, because the
            // architecture has no unconditionally-EL0 member of this family: every encoding under
            // `op1` three is reached only through a privileged enable bit. `SCTLR_EL1.UCI` gates
            // the by-address cache maintenance -- `dc cvau`, `dc civac`, `dc cvac`, `dc cvap`,
            // `dc cvadp` and `ic ivau` -- `SCTLR_EL1.DZE` gates `dc zva` and the MTE zeroing forms
            // beside it, and `GCSCRE0_EL1` gates the guarded-stack pushes. The rest of the family
            // is EL1 and above by `op1` alone.
            //
            // So this reads *nothing*, where it used to read `op1` and carve `DAIF` back out one
            // encoding at a time. That carve-out is still right for a system **register**
            // ([`interrupt_mask`], below) -- most of EL0's registers really are EL0's, and `NZCV`
            // sits one `op2` away from `DAIF` -- but for an operation the exception is the whole
            // set, and a rule with no exceptions is the one that stops generating them. Raised on
            // dbgscope#171, whose reviewer reached `dc cvau` by the same argument that reached
            // `DAIF` two rounds earlier; the third time it would have been `dc zva`.
            out.privileged(family)
        }
        // `msr`/`mrs` against a named system register. `op0` is 2 or 3 and is part of the name.
        (_, load) => {
            let name = format!("s{op0}_{op1}_c{crn}_c{crm}_{op2}");
            let out = match load {
                true => Out::new("mrs").out_reg(gpr(rt, true, false)).other(name),
                false => Out::new("msr").other(name).in_reg(gpr(rt, true, false)),
            };
            // Writing `NZCV` is the one system-register access that sets the flags a conditional
            // branch reads, and a restore of a saved context does exactly that.
            let out = match (load, op0, op1, crn, crm, op2) {
                (false, 0b11, 0b011, 0b0100, 0b0010, 0b000) => out.flags(),
                _ => out,
            };
            // **`DAIF` reached as a register is the same gate as `daifset` reached as a field**,
            // and only the second of the two was carved out. `SCTLR_EL1.UMA` traps EL0 accesses to
            // it in *both* directions, so a `mrs x8,DAIF` is as privileged as the `msr daifset` a
            // few lines above -- and there are 241 of them in this bench's kernel, which a hazard
            // scan was seeing none of. Raised on dbgscope#171; the `NZCV` beside it, one `op2`
            // away, really is EL0's to read and write.
            // Which family, from the same five fields: the two interrupt masks by encoding, the
            // IMPLEMENTATION DEFINED space by `CRn`, and every other system register a control
            // register -- A64 having no control-register file apart from these.
            let family = if interrupt_mask(op0, op1, crn, crm, op2)
                || all_interrupts_mask(op0, op1, crn, crm, op2)
            {
                Privilege::InterruptFlag
            } else if implementation_defined(op0, crn) {
                Privilege::ModelSpecificRegister
            } else {
                Privilege::ControlRegister
            };
            match privileged_level(op1) || interrupt_mask(op0, op1, crn, crm, op2) {
                true => out.privileged(family),
                false => out,
            }
        }
    }
}

/// Whether a system *register* encoding's `op1` names an exception level above EL0.
///
/// **Registers only.** The system *operation* family reads no `op1` at all, every member of it
/// needing privilege one way or another -- see the arm that builds `sys`/`dc`/`ic`/`tlbi`.
const fn privileged_level(op1: u32) -> bool {
    op1 != 0b011
}

/// Whether a system *register* encoding is `DAIF`, the interrupt masks.
///
/// The one *register* under EL0's `op1` that EL0 may not reach freely: `SCTLR_EL1.UMA` gates it,
/// which is a run-time fact the encoding does not carry, so it is named here as its
/// processor-state counterpart is named in [`pstate`]. The two together are the whole of the
/// register carve-out, and they are the same instruction reached two ways.
///
/// **A system operation needs no such list**, though it was nearly given one: the same argument
/// that reaches `DAIF` reaches `dc cvau` under `SCTLR_EL1.UCI` and `dc zva` under
/// `SCTLR_EL1.DZE`, and there the exception turned out to be the entire family. So that arm reads
/// nothing rather than carrying a second table this one's shape would have suggested.
const fn interrupt_mask(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> bool {
    op0 == 0b11 && op1 == 0b011 && crn == 0b0100 && crm == 0b0010 && op2 == 0b001
}

/// Whether a system *register* encoding is `ALLINT`, FEAT_NMI's mask over every interrupt,
/// superpriority ones included.
///
/// **Only the family asks**, where [`interrupt_mask`] is asked by privilege too: `ALLINT`'s `op1`
/// is EL1's, so the general rule already makes it privileged. What this adds is which family -- it
/// masks interrupts as `DAIF` does, and [`pstate`] reaches it as a field as it reaches `daifset`.
const fn all_interrupts_mask(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> bool {
    op0 == 0b11 && op1 == 0b000 && crn == 0b0100 && crm == 0b0011 && op2 == 0b000
}

/// Whether a system *register* encoding is in the IMPLEMENTATION DEFINED space -- `op0` 3 with
/// `CRn` 11 or 15 -- which the architecture sets aside for registers a particular implementation
/// defines: A64's model-specific registers. None of the 1,118 registers `disarm64`'s generated
/// table names is there, which is the check that this space holds nothing architected.
const fn implementation_defined(op0: u32, crn: u32) -> bool {
    op0 == 0b11 && matches!(crn, 0b1011 | 0b1111)
}

/// The cache, TLB or address-translation operation a system-operation encoding is, if it is one:
/// the name it is written with, and the family that comes with it. `None` is a generic `sys` or
/// `sysl`.
///
/// **The cell says which of the four and a mask says whether this word is one.** `CRn` and `CRm`
/// decide what an encoding would be -- `CRn` 7 holds the cache and address-translation cells, 8 is
/// `tlbi`, and 9 is `tlbi` again in its `nXS` forms -- but only some `op1`/`op2` pairs in a cell are
/// allocated, and the rest are generic `sys` words, UNDEFINED where they execute. Naming the whole
/// cell called those `dc` or `tlbi` and put them in the maintenance family: 85 of the 1,024
/// `op1`/`CRm`/`op2` combinations in `CRn` 8 are `tlbi` operations, and on the 26100 ARM64 kernel
/// one `sysl` word in `CRn` 9 came out `tlbi` that way. Raised on dbgscope#192.
///
/// So each cell carries a 64-bit mask over `(op1 << 3) | op2`, one bit per allocated operation,
/// generated by disassembling every word of `CRn` 7, 8 and 9 with LLVM (Apple clang 21,
/// `--mattr=+all`) and keeping the pairs it names as one of the four. `CRn` 9's masks came out
/// identical to `CRn` 8's, which is what lets the two share arms. That is twenty numbers rather
/// than a table of operation names, because what is reported is the cell's name and not the
/// operation's -- `dc`, not `dc civac` -- and the engine's rendering already carries the rest.
///
/// **A pair missing from a mask fails safe**: an operation newer than that disassembler reads as
/// `sys` and [`Privilege::Other`], which costs a name and not a finding, where the cell rule failed
/// the other way and named a family for words that are in none. All four are `sys` forms, so a
/// `sysl` is never one of them. And `CRn` 7 is not `dc` wholesale even by cell: `CRm` 3 there is
/// the prediction-restriction family, `CRm` 7 the guarded-control-stack operations, which stay
/// `sys` and [`Privilege::Other`] -- as `at` is, since it asks for a translation and maintains
/// nothing.
fn maintenance(
    load: bool,
    crn: u32,
    crm: u32,
    op1: u32,
    op2: u32,
) -> Option<(&'static str, Privilege)> {
    if load {
        return None;
    }
    let (mnemonic, family, allocated): (_, _, u64) = match (crn, crm) {
        (0b0111, 0b0001) => ("ic", Privilege::CacheOrTlb, 0x0000_0000_0000_0001),
        (0b0111, 0b0100) => ("dc", Privilege::CacheOrTlb, 0x0000_0000_ba00_0000),
        (0b0111, 0b0101) => ("ic", Privilege::CacheOrTlb, 0x0000_0000_0200_0001),
        (0b0111, 0b0110) => ("dc", Privilege::CacheOrTlb, 0x0000_0000_0000_007e),
        (0b0111, 0b1000) => ("at", Privilege::Other, 0x0003_00f3_0000_000f),
        (0b0111, 0b1001) => ("at", Privilege::Other, 0x0004_0004_0000_0007),
        (0b0111, 0b1010) => ("dc", Privilege::CacheOrTlb, 0x0000_0000_2a00_0054),
        (0b0111, 0b1011) => ("dc", Privilege::CacheOrTlb, 0x0000_0000_8300_0000),
        (0b0111, 0b1100) => ("dc", Privilege::CacheOrTlb, 0x0000_0000_2a00_0000),
        (0b0111, 0b1101) => ("dc", Privilege::CacheOrTlb, 0x0000_0000_2a00_0000),
        (0b0111, 0b1110) => ("dc", Privilege::CacheOrTlb, 0x0022_0081_2a00_0054),
        (0b0111, 0b1111) => ("dc", Privilege::CacheOrTlb, 0x0000_0000_8100_0022),
        (0b1000 | 0b1001, 0b0000) => ("tlbi", Privilege::CacheOrTlb, 0x0000_0066_0000_0000),
        (0b1000 | 0b1001, 0b0001) => ("tlbi", Privilege::CacheOrTlb, 0x0033_0073_0000_00af),
        (0b1000 | 0b1001, 0b0010) => ("tlbi", Privilege::CacheOrTlb, 0x0022_0026_0000_00aa),
        (0b1000 | 0b1001, 0b0011) => ("tlbi", Privilege::CacheOrTlb, 0x0023_0073_0000_00af),
        (0b1000 | 0b1001, 0b0100) => ("tlbi", Privilege::CacheOrTlb, 0x0088_00ff_0000_0000),
        (0b1000 | 0b1001, 0b0101) => ("tlbi", Privilege::CacheOrTlb, 0x0022_0026_0000_00aa),
        (0b1000 | 0b1001, 0b0110) => ("tlbi", Privilege::CacheOrTlb, 0x0022_0026_0000_00aa),
        (0b1000 | 0b1001, 0b0111) => ("tlbi", Privilege::CacheOrTlb, 0x0033_0073_0000_00af),
        _ => return None,
    };
    ((allocated >> ((op1 << 3) | op2)) & 1 == 1).then_some((mnemonic, family))
}

/// The `hint` space, by the seven bits of `CRm:op2`.
///
/// **The pointer-authentication hints write a register and name none**, which is the reason this
/// is a table at all rather than a mnemonic: `pacibsp` signs the link register against the stack
/// pointer, and it is the second instruction of nearly every function in a Windows ARM64 image
/// (11,716 of them in this kernel's `.text`). A caller tracking a value in `lr` across a prologue
/// has to know it changed.
fn hint(number: u32) -> Out {
    // The four that sign or authenticate `x17` against `x16`, and the eight that do it to the
    // link register. `24..=31` are `pac`/`aut` with the `z` forms using the zero register as the
    // modifier and the `sp` forms using the stack pointer.
    let named = |name: &str| Out::new(name);
    match number {
        0 => named("nop"),
        1 => named("yield"),
        2 => named("wfe"),
        3 => named("wfi"),
        4 => named("sev"),
        5 => named("sevl"),
        6 => named("dgh"),
        7 => named("xpaclri")
            .writes_only(link_register())
            .reads_only(link_register()),
        8 | 10 | 12 | 14 => {
            let name = match number {
                8 => "pacia1716",
                10 => "pacib1716",
                12 => "autia1716",
                _ => "autib1716",
            };
            named(name)
                .writes_only(gpr(17, true, false))
                .reads_only(gpr(17, true, false))
                .reads_only(gpr(16, true, false))
        }
        16 => named("esb"),
        17 => named("psb").other("csync".to_string()),
        18 => named("tsb").other("csync".to_string()),
        19 => named("gcsb").other("dsync".to_string()),
        20 => named("csdb"),
        22 => named("clrbhb"),
        24..=31 => {
            let name = match number {
                24 => "paciaz",
                25 => "paciasp",
                26 => "pacibz",
                27 => "pacibsp",
                28 => "autiaz",
                29 => "autiasp",
                30 => "autibz",
                _ => "autibsp",
            };
            let out = named(name)
                .writes_only(link_register())
                .reads_only(link_register());
            match number % 2 {
                1 => out.reads_only(stack_pointer()),
                _ => out,
            }
        }
        32 => named("bti"),
        34 => named("bti").other("c".to_string()),
        36 => named("bti").other("j".to_string()),
        38 => named("bti").other("jc".to_string()),
        // A hint this build does not name is still a hint: it changes no register and no flag, so
        // the number is the whole of what there is to report.
        other => named("hint").imm(other as u64),
    }
}

/// `dsb`, `dmb`, `isb`, `sb` and `clrex`. The shareability domain and access types are a
/// four-bit field with a name, which is an operand kind [`Operand`] has no shape for -- so it is
/// named rather than reduced to the number, [`Operand::Other`] being exactly that case.
fn barrier(crm: u32, op2: u32) -> Out {
    let domain = match crm {
        0b0001 => "oshld",
        0b0010 => "oshst",
        0b0011 => "osh",
        0b0101 => "nshld",
        0b0110 => "nshst",
        0b0111 => "nsh",
        0b1001 => "ishld",
        0b1010 => "ishst",
        0b1011 => "ish",
        0b1101 => "ld",
        0b1110 => "st",
        0b1111 => "sy",
        _ => "",
    };
    let named = |name: &str| match domain.is_empty() {
        true => Out::new(name).imm(crm as u64),
        false => Out::new(name).other(domain.to_string()),
    };
    match op2 {
        0b010 => Out::new("clrex").imm(crm as u64),
        // **`dsb` has two aliases that are whole instructions**, and they are the architecture's
        // preferred spelling rather than a nicety: `ssbb` and `pssbb` are the speculative-store-
        // bypass barriers, and a caller matching mnemonics for a speculation mitigation cannot
        // find them under `dsb #0`. They also take no operand, which is this decoder's stated test
        // for resolving an alias -- it changes the operand *list* and not only the spelling.
        // Raised on dbgscope#171. The engine renders neither, having no instance of either in the
        // image this was measured against, so nothing in the corpus check speaks to it.
        0b100 => match crm {
            0b0000 => Out::new("ssbb"),
            0b0100 => Out::new("pssbb"),
            _ => named("dsb"),
        },
        0b101 => named("dmb"),
        // **`isb`'s `CRm` is an option field, not a shareability domain**, and sharing the table
        // above with `dsb`/`dmb` gave it that domain's names: `d50337df` is `isb #7` and was
        // reported as `isb nsh`, a domain `isb` has no concept of. `sy` is the one option the
        // architecture defines and is kept, because it is that option's own name and is what the
        // engine renders (`d5033fdf  isb sy`) -- the architecture's preferred spelling omits it,
        // which is a spelling question rather than one about what the field says. Raised on
        // dbgscope#171.
        0b110 => match crm {
            0b1111 => Out::new("isb").other("sy".to_string()),
            _ => Out::new("isb").imm(crm as u64),
        },
        0b111 => Out::new("sb"),
        _ => Out::undecoded("unallocated"),
    }
}

/// `msr <pstatefield>, #imm`: the immediate form, which reaches a processor-state bit rather than
/// a system register. The field's name comes from `op1:op2` and the value is `CRm`.
fn pstate(op1: u32, crm: u32, op2: u32) -> Out {
    let field_name = match (op1, op2) {
        (0b000, 0b000) => "cfinv",
        (0b000, 0b001) => "xaflag",
        (0b000, 0b010) => "axflag",
        (0b000, 0b011) => "uao",
        (0b000, 0b100) => "pan",
        (0b000, 0b101) => "spsel",
        (0b001, 0b000) => "allint",
        (0b011, 0b001) => "ssbs",
        (0b011, 0b010) => "dit",
        (0b011, 0b100) => "tco",
        (0b011, 0b110) => "daifset",
        (0b011, 0b111) => "daifclr",
        _ => return Out::undecoded("unallocated"),
    };
    // **The three FlagM members are instructions rather than fields**, written `cfinv` with no
    // operands at all rather than `msr cfinv,#0` -- which the engine confirms, rendering `cfinv`
    // for `d500401f`. They rewrite the condition flags themselves, and their `CRm` is reserved
    // rather than an immediate. Raised on dbgscope#171.
    if matches!((op1, op2), (0b000, 0b000..=0b010)) {
        return match crm {
            0 => Out::new(field_name).flags(),
            _ => Out::undecoded("unallocated"),
        };
    }
    let out = Out::new("msr")
        .other(field_name.to_string())
        .imm(crm as u64);
    // **`op1` decides this everywhere else and cannot decide it here**, because the immediate form
    // addresses a processor-state *field* rather than a system register, and `op1` zero holds two
    // kinds of them: `uao`, `pan` and `spsel`, which are EL1, and the three FlagM instructions
    // above, which reach `NZCV` and nothing else. EL0 may already write the whole of `NZCV` with
    // `msr nzcv`, so inverting a carry flag is not a privileged act — and reporting it as one puts
    // a compiler's own flag manipulation in a driver hazard report. Raised on dbgscope#171.
    //
    // The other carve-out runs the opposite way: `daifset` and `daifclr` encode EL0's `op1` and
    // are EL1 all the same, EL0 reaching them only where `SCTLR_EL1.UMA` allows it.
    let privileged = match (op1, op2) {
        (0b000, 0b000..=0b010) => false,
        (0b011, 0b110 | 0b111) => true,
        (op1, _) => privileged_level(op1),
    };
    // **A field is the register it is a field of**, so the family is the one that register's own
    // encoding gets: `daifset`, `daifclr` and `allint` mask interrupts, and `pan`, `uao` and
    // `spsel` are system registers like any other.
    let family = match (op1, op2) {
        (0b011, 0b110 | 0b111) | (0b001, 0b000) => Privilege::InterruptFlag,
        _ => Privilege::ControlRegister,
    };
    match privileged {
        true => out.privileged(family),
        false => out,
    }
}

// ---------------------------------------------------------------------------------------------
// Loads and stores
// ---------------------------------------------------------------------------------------------

/// What one load or store moves, as its `size`, `opc` and `V` fields say.
struct Access {
    /// The mnemonic's stem, before the addressing mode's own prefix.
    stem: &'static str,
    /// The suffix that names the width and the signedness -- `b`, `sh`, `sw`.
    suffix: &'static str,
    /// How wide the transfer register is named, in bytes.
    register: u32,
    /// How many bytes the memory operand covers.
    bytes: u32,
    /// Whether the transfer register is written (a load) rather than read (a store).
    load: bool,
    /// A prefetch, whose `Rt` field is an operation rather than a register.
    prefetch: bool,
    /// The transfer register is in the vector file.
    vector: bool,
}

/// The `size`/`opc` table the single-register load and store forms share, whatever addressing mode
/// they are written with. `None` is an unallocated combination.
fn access_of(size: u32, opc: u32, vector: bool) -> Option<Access> {
    if vector {
        // `opc<1>:size` is the access width, which is how a 128-bit `ldr q0` is encoded with
        // `size` zero; `opc<0>` is the direction.
        let scale = ((opc & 0b10) << 1) | size;
        if scale > 4 {
            return None;
        }
        return Some(Access {
            stem: if opc & 1 == 1 { "ldr" } else { "str" },
            suffix: "",
            register: 1 << scale,
            bytes: 1 << scale,
            load: opc & 1 == 1,
            prefetch: false,
            vector: true,
        });
    }
    let bytes = 1 << size;
    let (stem, suffix, register, load, prefetch) = match (size, opc) {
        (0..=2, 0b00) => ("str", ["b", "h", ""][size as usize], 4, false, false),
        (0..=2, 0b01) => ("ldr", ["b", "h", ""][size as usize], 4, true, false),
        // The sign-extending loads, whose `opc<0>` picks the destination width: `10` extends into
        // a 64-bit register and `11` into a 32-bit one, which is why the wider encoding is the
        // lower number.
        (0..=1, 0b10) => ("ldr", ["sb", "sh"][size as usize], 8, true, false),
        (0..=1, 0b11) => ("ldr", ["sb", "sh"][size as usize], 4, true, false),
        (2, 0b10) => ("ldr", "sw", 8, true, false),
        (3, 0b00) => ("str", "", 8, false, false),
        (3, 0b01) => ("ldr", "", 8, true, false),
        (3, 0b10) => ("prfm", "", 8, false, true),
        _ => return None,
    };
    Some(Access {
        stem,
        suffix,
        register,
        bytes,
        load,
        prefetch,
        vector: false,
    })
}

/// A prefetch's `Rt` field, which is a three-part operation name rather than a register:
/// what to prefetch, which cache level, and whether the line is expected to be reused.
fn prefetch_operation(rt: u32) -> String {
    let kind = match field(rt, 3, 2) {
        0b00 => "PLD",
        0b01 => "PLI",
        0b10 => "PST",
        _ => return format!("#{rt}"),
    };
    let level = match field(rt, 1, 2) {
        0b00 => "L1",
        0b01 => "L2",
        0b10 => "L3",
        _ => return format!("#{rt}"),
    };
    let policy = match rt & 1 {
        0 => "KEEP",
        _ => "STRM",
    };
    format!("{kind}{level}{policy}")
}

/// The transfer register of a load or store, in whichever file the form names.
fn transfer(number: u32, access: &Access) -> RegisterOperand {
    match access.vector {
        true => vreg(number, access.register),
        false => gpr(number, access.register == 8, false),
    }
}

/// The operand and register bookkeeping every single-register form shares: the transfer register
/// on the side the direction puts it, then the memory operand.
fn transfer_operands(out: Out, rt: u32, access: &Access, memory: MemoryOperand) -> Out {
    let out = match (access.prefetch, access.load) {
        (true, _) => out.other(prefetch_operation(rt)),
        (false, true) => out.out_reg(transfer(rt, access)),
        (false, false) => out.in_reg(transfer(rt, access)),
    };
    // **A prefetch has no transfer width.** Its `size` field scales the offset -- which is why
    // [`Access::bytes`] is eight for one and has to be -- but nothing eight bytes wide is moved,
    // and a consumer bounding an instruction's memory effect from this would be told a range the
    // architecture does not define. What a prefetch touches is a cache line, whose size is an
    // implementation's business. Raised on dbgscope#171.
    let memory = match access.prefetch {
        true => MemoryOperand {
            size: None,
            ..memory
        },
        false => memory,
    };
    out.mem(memory)
        .effect(match (access.prefetch, access.suffix) {
            (true, _) => Effect::Other,
            // A sign-extending load means something different about the value afterwards, which is
            // exactly the distinction `MoveSigned` was split out for.
            (false, "sb" | "sh" | "sw") => Effect::MoveSigned,
            (false, _) => Effect::Move,
        })
}

fn loads_and_stores(word: u32, address: u64) -> Out {
    match word & 0x3f00_0000 {
        0x0800_0000 => return load_store_exclusive(word),
        0x0c00_0000 | 0x0d00_0000 => return vector_structures(word),
        _ => {}
    }
    if word & 0x3b00_0000 == 0x1800_0000 {
        return load_literal(word, address);
    }
    // The memory-copy and memory-set family, which occupies two top-level slots and is told from
    // its neighbours in them by `sz` being zero and `op4` being `01`.
    if matches!(word & 0x3f00_0000, 0x1900_0000 | 0x1d00_0000)
        && field(word, 30, 2) == 0
        && field(word, 21, 1) == 0
        && field(word, 10, 2) == 0b01
    {
        return memory_operations(word);
    }
    if word & 0x3f00_0000 == 0x1900_0000 {
        return match field(word, 21, 1) {
            0 => unscaled_acquire(word),
            _ => memory_tags(word),
        };
    }
    match word & 0x3800_0000 {
        0x2800_0000 => load_store_pair(word),
        0x3800_0000 => load_store_register(word),
        _ => Out::undecoded("unallocated"),
    }
}

/// `ldapur`/`stlur` and their narrowing forms: an ordinary unscaled load or store that also orders.
///
/// The `size`/`opc` table is the one every other single-register form reads, which is the whole
/// reason this is fifteen lines: what the encoding changes is the ordering the access carries and
/// the name it is written under, and neither is a different operand shape. The one hole in the
/// shared table is the prefetch, which this space does not allocate.
fn unscaled_acquire(word: u32) -> Out {
    let (size, opc) = (field(word, 30, 2), field(word, 22, 2));
    let Some(access) = access_of(size, opc, false).filter(|access| !access.prefetch) else {
        return Out::undecoded("unallocated");
    };
    if field(word, 10, 2) != 0 {
        return Out::undecoded("unallocated");
    }
    let mnemonic = format!(
        "{}{}",
        if access.load { "ldapur" } else { "stlur" },
        access.suffix
    );
    let memory = MemoryOperand {
        size: Some(access.bytes),
        base: Some(gpr(field(word, 5, 5), true, true)),
        scale: 1,
        displacement: sign_extend(field(word, 12, 9), 9),
        ..MemoryOperand::default()
    };
    transfer_operands(Out::new(&mnemonic), field(word, 0, 5), &access, memory)
}

/// `cpy` and `set`: the memory-copy and memory-set instructions, which a compiler emits in place
/// of a `memcpy` or `memset` call.
///
/// **All three registers are read and written**, which is the fact worth having: each instruction
/// is one third of a copy -- a prologue, a main body and an epilogue, run in sequence -- and each
/// leaves the pointers and the remaining count advanced for the next. A consumer that did not know
/// that would carry three stale values across an inlined `memcpy`.
///
/// The naming is systematic rather than a table, which is the only reason it is here in full:
/// `op1` picks the stage, and `op2` picks the memory attributes as two independent halves, one for
/// the read side and one for the write. Derived from a generated instruction table rather than
/// recalled -- see `examples/undecoded_families.rs`, which is what found this family after review
/// raised it on dbgscope#171.
fn memory_operations(word: u32) -> Out {
    // The two slots differ by one bit: `cpyf`/`set` ignore the tags, `cpy`/`setg` do not.
    let tagged = field(word, 26, 1) != 0;
    let (op1, op2) = (field(word, 22, 2), field(word, 12, 4));
    let (other, rn, rd) = (field(word, 16, 5), field(word, 5, 5), field(word, 0, 5));
    let stage = ["p", "m", "e"];
    // **A bracketed operand is a memory reference here as it is everywhere else in this decoder**,
    // which is what a consumer enumerating an instruction's memory effects looks for -- and these
    // instructions are the whole of a copy or a fill, so reporting none would be the wrong answer
    // about the largest memory effect the architecture has. The **size is unknown**: how much is
    // moved is the count register's value rather than an encoded width. The pointer registers stay
    // in the access lists, a memory operand's base being a read and its writeback a write.
    // Raised on dbgscope#171.
    let through = |number: u32| MemoryOperand {
        base: Some(gpr(number, true, false)),
        scale: 1,
        ..MemoryOperand::default()
    };
    if op1 == 0b11 {
        // A set names a destination, a count and the byte to write; only the byte is not updated.
        let Some(which) = stage.get((op2 >> 2) as usize) else {
            return Out::undecoded("unallocated");
        };
        let suffix = ["", "t", "n", "tn"][(op2 & 0b11) as usize];
        let out = Out::new(&format!(
            "set{}{which}{suffix}",
            if tagged { "g" } else { "" }
        ))
        .mem(through(rd))
        .writes_only(gpr(rd, true, false))
        .inout_reg(gpr(rn, true, false))
        .in_reg(gpr(other, true, false));
        return match *which == "p" {
            true => out.flags(),
            false => out,
        };
    }
    // A copy names a destination, a source and a count, and advances all three.
    let which = stage[op1 as usize];
    let read = ["", "wt", "rt", "t"][(op2 & 0b11) as usize];
    let write = ["", "wn", "rn", "n"][(op2 >> 2) as usize];
    let out = Out::new(&format!(
        "cpy{}{which}{read}{write}",
        if tagged { "" } else { "f" }
    ))
    .mem(through(rd))
    .writes_only(gpr(rd, true, false))
    .mem(through(other))
    .writes_only(gpr(other, true, false))
    .inout_reg(gpr(rn, true, false));
    // **The prologue writes the flags the other two stages run on**, which is the protocol the
    // three of them share: it chooses a direction and an option and leaves them in `NZCV` for the
    // main body and the epilogue to read. So a caller asking what set the flags after a copy has
    // to stop at the prologue rather than walk past it to an earlier compare.
    //
    // That the main and epilogue *read* them is a fact this type has no field for, as it has none
    // for `ccmp`'s or `fccmp`'s reads. Raised on dbgscope#171.
    match op1 == 0b00 {
        true => out.flags(),
        false => out,
    }
}

/// The memory-tagging accesses: `stg` and its relatives, `ldg`, and the whole-granule forms.
///
/// **`ldg` reads the register it writes**, which is the one thing in this family a first-operand
/// rule gets wrong: the tag it loads is *inserted into* `Xt`'s existing value rather than replacing
/// it, so the address already in that register survives the load.
///
/// The displacement is in tag granules of sixteen bytes, and [`Effect::Other`] throughout: what
/// these move is an allocation tag, which is not a value any consumer here follows.
fn memory_tags(word: u32) -> Out {
    // 64-bit only; the `size` field is fixed at `11` for every member.
    if field(word, 30, 2) != 0b11 {
        return Out::undecoded("unallocated");
    }
    let (opc, index) = (field(word, 22, 2), field(word, 10, 2));
    let (rn, rt) = (field(word, 5, 5), field(word, 0, 5));
    let displacement = sign_extend(field(word, 12, 9), 9) * 16;
    // `op2` zero is where the whole-granule forms live -- **but `ldg` lives there too**, and it is
    // an ordinary tagged access with a displacement rather than one of them. So `op2` picks the
    // *spelling* below and is not the question "is this a whole-granule form"; `opc` settles that,
    // and the flag is taken from the mnemonic afterwards so the two cannot drift apart.
    //
    // Reading `op2` alone as "whole granule" took `ldg`'s displacement away twice over: the guard
    // further down refused every `ldg` with a nonzero one as unallocated -- the generated table
    // has `ldg x0,[x1,#240]` -- and the size arm reported no width for the one form that survived,
    // though `ldg` reads the tag of a single sixteen-byte granule like the stores beside it. Found
    // by the sizeless-access audit in the module header rather than by review.
    let at_index_zero = index == 0b00;
    let mnemonic = match (opc, at_index_zero) {
        (0b00, true) => "stzgm",
        (0b00, false) => "stg",
        (0b01, true) => "ldg",
        (0b01, false) => "stzg",
        (0b10, true) => "stgm",
        (0b10, false) => "st2g",
        (0b11, true) => "ldgm",
        _ => "stz2g",
    };
    let granule = matches!(mnemonic, "stzgm" | "stgm" | "ldgm");
    if granule && displacement != 0 {
        return Out::undecoded("unallocated");
    }
    let loads = matches!(mnemonic, "ldg" | "ldgm");
    // **The tagging stores name an `|SP` transfer register**, unlike every other store in the
    // architecture: `stg sp,[sp]` tags the stack frame a prologue just made, which is the whole
    // point of the instruction. The loads and the granule-group forms do not.
    let tagged = gpr(rt, true, !loads && !granule);
    let out = Out::new(mnemonic);
    let out = match (loads, mnemonic) {
        // `ldg` combines the tag with what `Xt` already holds; `ldgm` replaces it.
        (true, "ldg") => out.inout_reg(tagged),
        (true, _) => out.out_reg(tagged),
        (false, _) => out.in_reg(tagged),
    };
    let out = out.mem(MemoryOperand {
        // **`st2g` and `stz2g` reach two granules**, which is what the `2` in them is, so a caller
        // reading this to bound an affected range misses half of a `stz2g`'s zeroing without it.
        // The granule-group forms reach a number of granules `GMID_EL1.BS` decides, which is a
        // run-time fact rather than an encoded one, so they claim no size at all.
        size: match (granule, mnemonic) {
            (true, _) => None,
            (_, "st2g" | "stz2g") => Some(32),
            _ => Some(16),
        },
        base: Some(gpr(rn, true, true)),
        scale: 1,
        // A post-indexed access happens at the base, as everywhere else here.
        displacement: match index {
            0b01 => 0,
            _ => displacement,
        },
        ..MemoryOperand::default()
    });
    let out = match index {
        0b01 => out.other(post_index_amount(displacement)),
        _ => out,
    };
    match index {
        0b01 | 0b11 => out.writes_only(gpr(rn, true, true)),
        _ => out,
    }
}

/// `ldr Xt,<label>`, whose address the encoding pins outright. Reported the way x64's
/// `[rip+disp]` is: a memory operand carrying the address it resolves to, since nothing at run
/// time contributes to it.
///
/// **The displacement is measured from the instruction, not from its end.** A64 has no
/// instruction length in this arithmetic, which is the one place a reader carrying an x86 habit
/// would be four bytes out.
fn load_literal(word: u32, address: u64) -> Out {
    let vector = field(word, 26, 1) != 0;
    let opc = field(word, 30, 2);
    let displacement = sign_extend(field(word, 5, 19), 19) * 4;
    let target = address.wrapping_add(displacement as u64);
    let rt = field(word, 0, 5);
    let (out, bytes) = match (vector, opc) {
        (false, 0b00) => (Out::new("ldr").out_reg(gpr(rt, false, false)), 4),
        (false, 0b01) => (Out::new("ldr").out_reg(gpr(rt, true, false)), 8),
        (false, 0b10) => (Out::new("ldrsw").out_reg(gpr(rt, true, false)), 4),
        // The literal prefetch, whose width is unknown for the reason `transfer_operands` gives.
        (false, _) => (Out::new("prfm").other(prefetch_operation(rt)), 0),
        (true, 0b00) => (Out::new("ldr").out_reg(vreg(rt, 4)), 4),
        (true, 0b01) => (Out::new("ldr").out_reg(vreg(rt, 8)), 8),
        (true, 0b10) => (Out::new("ldr").out_reg(vreg(rt, 16)), 16),
        (true, _) => return Out::undecoded("unallocated"),
    };
    let effect = match opc {
        0b10 if !vector => Effect::MoveSigned,
        0b11 if !vector => Effect::Other,
        _ => Effect::Move,
    };
    out.mem(MemoryOperand {
        size: (bytes != 0).then_some(bytes),
        displacement,
        address: Some(target),
        ..MemoryOperand::default()
    })
    .effect(effect)
}

/// `ldp`/`stp` and their no-allocate and sign-extending relatives.
///
/// [`Effect::Other`] throughout, deliberately: a pair moves two registers, and every effect this
/// type has is about one. A consumer learns what changed from
/// [`crate::dbgeng::Instruction::writes`], which names both.
fn load_store_pair(word: u32) -> Out {
    let vector = field(word, 26, 1) != 0;
    let opc = field(word, 30, 2);
    let index = field(word, 23, 3);
    let load = field(word, 22, 1) != 0;
    let (rt, rt2, rn) = (field(word, 0, 5), field(word, 10, 5), field(word, 5, 5));
    // `opc` is the element width, and `01` means two different things: a sign-extending pair load
    // on the general-purpose side, and a doubleword pair on the vector one.
    let (scale, register, signed) = match (vector, opc, load) {
        (false, 0b00, _) => (2, 4, false),
        // `opc` 01 is `ldpsw` and `stgp`, and **neither has a no-allocate form** -- so on the
        // general-purpose side the combination is unallocated rather than a 64-bit `ldnp`. Found
        // by sweeping a whole image rather than its `.text`: the words that reach it are data the
        // engine renders `???`, and reading them as a pair load invents two register writes.
        (false, 0b01, _) if index == 0b000 => return Out::undecoded("unallocated"),
        (false, 0b01, true) => (2, 8, true),
        // `stgp`, which stores a pair and a tag. Decoded for its registers like `addg` above.
        (false, 0b01, false) => (4, 8, false),
        (false, 0b10, _) => (3, 8, false),
        (true, 0b00, _) => (2, 4, false),
        (true, 0b01, _) => (3, 8, false),
        (true, 0b10, _) => (4, 16, false),
        _ => return Out::undecoded("unallocated"),
    };
    let displacement = sign_extend(field(word, 15, 7), 7) * (1 << scale);
    let mnemonic = match (index, signed, load, vector, opc) {
        (0b000, _, true, _, _) => "ldnp",
        (0b000, _, false, _, _) => "stnp",
        (_, true, _, _, _) => "ldpsw",
        (_, _, false, false, 0b01) => "stgp",
        (_, _, true, _, _) => "ldp",
        (_, _, false, _, _) => "stp",
    };
    let one = |number: u32| match vector {
        true => vreg(number, register),
        false => gpr(number, register == 8, false),
    };
    let out = Out::new(mnemonic);
    let out = match load {
        true => out.out_reg(one(rt)).out_reg(one(rt2)),
        false => out.in_reg(one(rt)).in_reg(one(rt2)),
    };
    // A post-indexed access happens at the base and *then* moves it, so reporting the
    // displacement on the memory operand would name an address the instruction never forms.
    let out = out.mem(MemoryOperand {
        size: Some(if signed { 8 } else { register * 2 }),
        base: Some(gpr(rn, true, true)),
        scale: 1,
        displacement: match index {
            0b001 => 0,
            _ => displacement,
        },
        ..MemoryOperand::default()
    });
    let out = match index {
        0b001 => out.other(post_index_amount(displacement)),
        _ => out,
    };
    match index {
        0b001 | 0b011 => out.writes_only(gpr(rn, true, true)),
        _ => out,
    }
}

/// The single-register load and store forms, which share one `size`/`opc` table and differ only in
/// how the address is written.
fn load_store_register(word: u32) -> Out {
    let vector = field(word, 26, 1) != 0;
    let (size, opc) = (field(word, 30, 2), field(word, 22, 2));
    let (rn, rt) = (field(word, 5, 5), field(word, 0, 5));
    // The unsigned-offset form is the common one and is the only member of `op2 = 01`.
    if field(word, 24, 2) == 0b01 {
        let Some(access) = access_of(size, opc, vector) else {
            return Out::undecoded("unallocated");
        };
        let scale = access.bytes.trailing_zeros();
        let memory = MemoryOperand {
            size: Some(access.bytes),
            base: Some(gpr(rn, true, true)),
            scale: 1,
            displacement: ((field(word, 10, 12) as i64) << scale),
            ..MemoryOperand::default()
        };
        let mnemonic = format!("{}{}", access.stem, access.suffix);
        return transfer_operands(Out::new(&mnemonic), rt, &access, memory);
    }
    match (field(word, 21, 1), field(word, 10, 2)) {
        // Atomics, and `ldapr` beside them: `Rs` is a value going in, `Rt` the old value coming
        // out, and both are general-purpose.
        (1, 0b00) if !vector => atomic_memory_operation(word),
        // The register-offset form. **The extension's signedness is not carried**: a
        // [`MemoryOperand`] has an index and a scale and no shape for `sxtw`, so the index is
        // reported at the width the option names and the operand claims no address -- which it
        // could not anyway, a register contributing to it.
        (1, 0b10) => {
            let Some(access) = access_of(size, opc, vector) else {
                return Out::undecoded("unallocated");
            };
            let option = field(word, 13, 3);
            if option & 0b010 == 0 {
                return Out::undecoded("unallocated");
            }
            // **Measured, because review read this arm as swallowing FEAT_RPRFM's range
            // prefetches.** `f8a659fe` was offered as one; the engine renders it
            // `prfm #0x1E,[x15,w6 uxtw #3]`, which is what this produces field for field -- the
            // same operation number, base, index width and scale. So that example is an ordinary
            // prefetch and not evidence of an overlap. Whether some *other* word in this space is
            // a range prefetch is not answerable on a bench whose engine renders none, and
            // carving one out of a wrong example would refuse valid prefetches, so nothing is
            // carved out here. Reopen it with a target that renders an `rprfm`.
            let shift = match field(word, 12, 1) {
                1 => access.bytes.trailing_zeros(),
                _ => 0,
            };
            let memory = MemoryOperand {
                size: Some(access.bytes),
                base: Some(gpr(rn, true, true)),
                index: Some(gpr(field(word, 16, 5), option & 1 == 1, false)),
                scale: 1 << shift,
                ..MemoryOperand::default()
            };
            let mnemonic = format!("{}{}", access.stem, access.suffix);
            transfer_operands(Out::new(&mnemonic), rt, &access, memory)
        }
        // `ldraa`/`ldrab`: a load whose base is authenticated, with a ten-bit scaled displacement
        // split across the word. `op4` is `W:1`, so **both** `01` and `11` are this form -- reading
        // only the second loses every one of them that does not write its base back.
        (1, mode) if mode & 1 == 1 => {
            // **`opc` is not an opcode in this form**, which is what made the guard that used to
            // stand here reject half of these: bit 23 is the key and bit 22 is the top bit of the
            // displacement, so requiring bit 22 clear refused every `ldraa` with a negative
            // offset. The form is constrained by `size` and `V` and by nothing else.
            // Raised on dbgscope#171.
            if vector || size != 0b11 {
                return Out::undecoded("unallocated");
            }
            let displacement = sign_extend((field(word, 22, 1) << 9) | field(word, 12, 9), 10) * 8;
            let out = Out::new(match field(word, 23, 1) {
                0 => "ldraa",
                _ => "ldrab",
            })
            .out_reg(gpr(rt, true, false))
            .mem(MemoryOperand {
                size: Some(8),
                base: Some(gpr(rn, true, true)),
                scale: 1,
                displacement,
                ..MemoryOperand::default()
            })
            .effect(Effect::Move);
            match mode & 0b10 {
                0b10 => out.writes_only(gpr(rn, true, true)),
                _ => out,
            }
        }
        // The `imm9` forms: unscaled, post-indexed, unprivileged and pre-indexed.
        (0, mode) => {
            let Some(access) = access_of(size, opc, vector) else {
                return Out::undecoded("unallocated");
            };
            // **The `size`/`opc`/`V` table is shared across all four addressing modes, and two of
            // its rows are not allocated in all four.** `access_of` answers for the shape of the
            // transfer and has no `mode` to consult, so the two exceptions are made here.
            //
            // A **prefetch** exists only unscaled, as `prfum`: there is no post-indexed,
            // pre-indexed or unprivileged one, and the two writeback modes could not have one --
            // a prefetch has no transfer register, so a `prfm x0,[x1],#8` would be an encoding
            // whose only effect is its own writeback. And the **unprivileged** mode has no vector
            // form at all; `ldtr`/`sttr` are general-purpose only.
            //
            // Unguarded, each decoded as something that does not exist: the writeback modes as a
            // `prfm` the architecture does not define, the unprivileged prefetch slot as `sttr` --
            // an allocated mnemonic wearing a prefetch's semantics, reporting no transfer width
            // and `Effect::Other` for a store, with its `Rt` rendered as a prefetch operation --
            // and the vector rows as `sttr b0,[x0]` and `ldtr b0,[x0]`. Found by the audits in the
            // module header rather than by review, and each confirmed against the generated table
            // (`examples/undecoded_families.rs`), which leaves all of them unallocated.
            if (access.prefetch && mode != 0b00) || (mode == 0b10 && vector) {
                return Out::undecoded("unallocated");
            }
            let displacement = sign_extend(field(word, 12, 9), 9);
            let stem = match (mode, access.prefetch, access.stem) {
                (0b00, true, _) => "prfum".to_string(),
                // `ldur`, not `ldrur`: the unscaled forms replace the `r` rather than follow it.
                (0b00, _, stem) => format!("{}ur", &stem[..stem.len() - 1]),
                (0b10, _, "ldr") => "ldtr".to_string(),
                (0b10, _, _) => "sttr".to_string(),
                (_, _, stem) => stem.to_string(),
            };
            let memory = MemoryOperand {
                size: Some(access.bytes),
                base: Some(gpr(rn, true, true)),
                scale: 1,
                // As for a pair: a post-indexed access happens at the base itself.
                displacement: match mode {
                    0b01 => 0,
                    _ => displacement,
                },
                ..MemoryOperand::default()
            };
            let mnemonic = format!("{stem}{}", access.suffix);
            let out = transfer_operands(Out::new(&mnemonic), rt, &access, memory);
            let out = match mode {
                0b01 => out.other(post_index_amount(displacement)),
                _ => out,
            };
            match mode {
                0b01 | 0b11 => out.writes_only(gpr(rn, true, true)),
                _ => out,
            }
        }
        // `(1, 0b00)` with `V` set, which is the atomics' slot in the vector half and allocates
        // nothing.
        _ => Out::undecoded("unallocated"),
    }
}

/// The atomic read-modify-write family, `swp` and `ldapr`.
///
/// `Rs` is the operand going in and `Rt` the value that was there, which is the shape a caller has
/// to have right: `ldadd x8,x8,[x9]` names `x8` twice and the two are a read and a write.
fn atomic_memory_operation(word: u32) -> Out {
    let size = field(word, 30, 2);
    let (acquire, release) = (field(word, 23, 1), field(word, 22, 1));
    let (rs, rn, rt) = (field(word, 16, 5), field(word, 5, 5), field(word, 0, 5));
    let (o3, opc) = (field(word, 15, 1), field(word, 12, 3));
    let wide = size == 0b11;
    let width = match size {
        0b00 => "b",
        0b01 => "h",
        _ => "",
    };
    let ordering = match (acquire, release) {
        (0, 0) => "",
        (0, _) => "l",
        (_, 0) => "a",
        _ => "al",
    };
    let bytes = 1 << size;
    let memory = MemoryOperand {
        size: Some(bytes),
        base: Some(gpr(rn, true, true)),
        scale: 1,
        ..MemoryOperand::default()
    };
    // `ldapr` shares the encoding and is not an arithmetic operation: it loads, acquiring.
    if o3 == 1 && opc == 0b100 && rs == 0b11111 && acquire == 1 && release == 0 {
        return Out::new(&format!("ldapr{width}"))
            .out_reg(gpr(rt, wide, false))
            .mem(memory)
            .effect(Effect::Move);
    }
    let operation = match (o3, opc) {
        (0, 0b000) => "ldadd",
        (0, 0b001) => "ldclr",
        (0, 0b010) => "ldeor",
        (0, 0b011) => "ldset",
        (0, 0b100) => "ldsmax",
        (0, 0b101) => "ldsmin",
        (0, 0b110) => "ldumax",
        (0, 0b111) => "ldumin",
        (_, 0b000) => "swp",
        _ => return Out::undecoded("unallocated"),
    };
    // Discarding the old value is a `st<op>` rather than a `ld<op>`, and the encoding says so by
    // naming the zero register -- but only where nothing was being acquired, since an acquire with
    // no destination would have nothing to order against.
    if rt == 0b11111 && acquire == 0 && operation != "swp" {
        let stem = operation.replace("ld", "st");
        return Out::new(&format!("{stem}{ordering}{width}"))
            .in_reg(gpr(rs, wide, false))
            .mem(memory);
    }
    Out::new(&format!("{operation}{ordering}{width}"))
        .in_reg(gpr(rs, wide, false))
        .out_reg(gpr(rt, wide, false))
        .mem(memory)
}

/// The exclusive and compare-and-swap family.
///
/// Four shapes share one encoding, and which one it is comes from `o2` and `o1` rather than from
/// the mnemonic: an exclusive store writes a *status* register that neither of its other operands
/// is, and a compare-and-swap's first operand is read and written both -- the expected value goes
/// in and what was actually there comes back.
fn load_store_exclusive(word: u32) -> Out {
    let size = field(word, 30, 2);
    let (o2, load, o1, o0) = (
        field(word, 23, 1),
        field(word, 22, 1) != 0,
        field(word, 21, 1),
        field(word, 15, 1),
    );
    let (rs, rt2, rn, rt) = (
        field(word, 16, 5),
        field(word, 10, 5),
        field(word, 5, 5),
        field(word, 0, 5),
    );
    let width = match size {
        0b00 => "b",
        0b01 => "h",
        _ => "",
    };
    let wide = size == 0b11;
    let bytes = 1u32 << size;
    let memory = |bytes: u32| MemoryOperand {
        size: Some(bytes),
        base: Some(gpr(rn, true, true)),
        scale: 1,
        ..MemoryOperand::default()
    };
    match (o2, o1) {
        // `ldxr`/`stxr` and their acquiring and releasing forms.
        (0, 0) => match load {
            true => Out::new(&format!("ld{}xr{width}", if o0 == 1 { "a" } else { "" }))
                .out_reg(gpr(rt, wide, false))
                .mem(memory(bytes))
                .effect(Effect::Move),
            false => Out::new(&format!("st{}xr{width}", if o0 == 1 { "l" } else { "" }))
                .out_reg(gpr(rs, false, false))
                .in_reg(gpr(rt, wide, false))
                .mem(memory(bytes)),
        },
        // `ldxp`/`stxp` on the 64-bit side of the encoding, `casp` on the 32-bit one.
        (0, 1) if size & 0b10 != 0 => match load {
            true => Out::new(&format!("ld{}xp", if o0 == 1 { "a" } else { "" }))
                .out_reg(gpr(rt, wide, false))
                .out_reg(gpr(rt2, wide, false))
                .mem(memory(bytes * 2)),
            false => Out::new(&format!("st{}xp", if o0 == 1 { "l" } else { "" }))
                .out_reg(gpr(rs, false, false))
                .in_reg(gpr(rt, wide, false))
                .in_reg(gpr(rt2, wide, false))
                .mem(memory(bytes * 2)),
        },
        (0, _) => {
            // **A pair names its even half and the architecture supplies the odd one**, so an odd
            // `Rs` or `Rt` is CONSTRAINED UNPREDICTABLE -- not an encoding whose second register is
            // the first again, which is what `rs | 1` produced: `0x482b7c0c` came back as
            // `casp x11,x11,x12,x13,[x0]`, with `x11` listed as both halves of one pair. The
            // generated table renders that second register `<undefined>`, which is the same fact
            // said another way. Refusing is the honest answer for a word whose behaviour the
            // architecture does not pin: [`Operand::Undecoded`] means nothing was read, and here
            // there is nothing to read. Raised on dbgscope#171.
            if rs & 1 != 0 || rt & 1 != 0 {
                return Out::undecoded("unallocated");
            }
            let pair_wide = size & 1 != 0;
            let element = if pair_wide { 8 } else { 4 };
            Out::new(&format!(
                "casp{}{}",
                if load { "a" } else { "" },
                if o0 == 1 { "l" } else { "" }
            ))
            .inout_reg(gpr(rs, pair_wide, false))
            .inout_reg(gpr(rs | 1, pair_wide, false))
            .in_reg(gpr(rt, pair_wide, false))
            .in_reg(gpr(rt | 1, pair_wide, false))
            .mem(memory(element * 2))
        }
        // `ldar`/`stlr`, and the `ldlar`/`stllr` beside them that order without acquiring.
        (_, 0) => match load {
            true => Out::new(&format!("ld{}r{width}", if o0 == 1 { "a" } else { "la" }))
                .out_reg(gpr(rt, wide, false))
                .mem(memory(bytes))
                .effect(Effect::Move),
            false => Out::new(&format!("st{}r{width}", if o0 == 1 { "l" } else { "ll" }))
                .in_reg(gpr(rt, wide, false))
                .mem(memory(bytes))
                .effect(Effect::Move),
        },
        // `cas`: `Rs` carries the comparand in and the old value out.
        _ => Out::new(&format!(
            "cas{}{}{width}",
            if load { "a" } else { "" },
            if o0 == 1 { "l" } else { "" }
        ))
        .inout_reg(gpr(rs, wide, false))
        .in_reg(gpr(rt, wide, false))
        .mem(memory(bytes)),
    }
}

/// How many bytes one register's share of a structure transfer moves.
///
/// The whole-register forms move the register: eight bytes or sixteen, as `Q` says. A
/// single-structure form moves one *element*, whose width the opcode's top two bits give directly
/// except where they say `10`, which is a single-precision element unless `size`'s low bit makes
/// it a double. The replicate forms take the width from `size` alone, an element of every lane
/// being the same width as one.
///
/// Checked against the engine's own rendering of the amount it prints: `ld1 {v0.8b},[x1],#8`,
/// `ld1 {v0.16b,v1.16b,v2.16b,v3.16b},[x1],#0x40`, `ld2 {v0.b,v1.b}[0],[x1],#2` and
/// `st1 {v0.s}[0],[x1],#4`.
fn structure_element(word: u32, single: bool, replicate: &str) -> i64 {
    if !single {
        return 8 << field(word, 30, 1);
    }
    if !replicate.is_empty() {
        return 1 << field(word, 10, 2);
    }
    match field(word, 14, 2) {
        0b00 => 1,
        0b01 => 2,
        _ => 4 << field(word, 10, 1),
    }
}

/// Advanced SIMD's structure loads and stores.
///
/// The register *list* is an operand kind [`Operand`] has no shape for -- `{v0.16b, v1.16b}` is
/// neither a register nor a memory reference -- so it is named. What is decoded here is the part a
/// caller following general-purpose values needs: the base register, and whether the addressing
/// mode wrote it back.
fn vector_structures(word: u32) -> Out {
    let post_index = field(word, 23, 1) != 0;
    // **Without a post-index there is no `Rm`, and the field it would occupy is reserved.** An
    // extension may carve an instruction out of that reserved space and one has: RCPC3's `ldap1`
    // and `stl1` are these encodings with a nonzero `Rm`, and reading the field as "absent" rather
    // than "must be zero" shaped them as ordinary `ld1`/`st1` and lost their ordering. This
    // decodes no RCPC3, so they are refused by name rather than mis-shaped.
    // Raised on dbgscope#171.
    if !post_index && field(word, 16, 5) != 0 {
        return Out::undecoded("unallocated");
    }
    let load = field(word, 22, 1) != 0;
    let single = word & 0x3f00_0000 == 0x0d00_0000;
    let rn = field(word, 5, 5);
    let (count, stem) = match (single, field(word, 12, 4)) {
        (false, 0b0000) => (4, "4"),
        (false, 0b0010) => (4, "1"),
        (false, 0b0100) => (3, "3"),
        (false, 0b0110) => (3, "1"),
        (false, 0b0111) => (1, "1"),
        (false, 0b1000) => (2, "2"),
        (false, 0b1010) => (2, "1"),
        (false, _) => return Out::undecoded("unallocated"),
        // The single-structure forms name one element of one to four registers, and how many is
        // `opcode<0>:R` — two bits eight apart, which is why a count taken from either alone
        // reports a `ld4` as a `ld1` or a `ld2`. The top two bits of the opcode pick the
        // *replicate* forms, which load one element into every lane and are written `ld1r`.
        (true, _) => (((field(word, 13, 1) << 1) | field(word, 21, 1)) + 1, ""),
    };
    let replicate = match single && field(word, 14, 2) == 0b11 {
        true => "r",
        false => "",
    };
    let mnemonic = match (load, stem) {
        (true, "") => format!("ld{count}{replicate}"),
        (false, "") => format!("st{count}{replicate}"),
        (true, stem) => format!("ld{stem}"),
        (false, stem) => format!("st{stem}"),
    };
    let first = field(word, 0, 5);
    let mut out = Out::new(&mnemonic).other(format!(
        "{{{}}}",
        (0..count)
            .map(|step| format!("v{}", (first + step) % 32))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    // **A load that fills one lane reads the register it fills**, the other lanes surviving it —
    // the same fact that makes `ins` a read of its destination. The whole-register forms and the
    // replicate forms do not: those write every lane there is.
    let merges = load && single && replicate.is_empty();
    for step in 0..count {
        let register = vreg_whole((first + step) % 32);
        if merges || !load {
            out = out.reads_only(register.clone());
        }
        if load {
            out = out.writes_only(register);
        }
    }
    // **The width is encoded here and was already being computed**, for the post-index amount
    // below: how many registers are named, times how wide each transfer is. Reporting it on the
    // memory operand as well is what lets a caller bound the read or the write, which for this
    // family is the one thing the register list does not tell them. Raised on dbgscope#171.
    let transferred = (count as i64) * structure_element(word, single, replicate);
    let out = out.mem(MemoryOperand {
        size: Some(transferred as u32),
        base: Some(gpr(rn, true, true)),
        scale: 1,
        ..MemoryOperand::default()
    });
    // **The post-index register is not part of the address**, which is the whole point of a
    // post-index: the access happens at the base and the register is what moves it afterwards.
    // Reporting it as [`MemoryOperand::index`] describes an access at `base + index` that the
    // instruction never makes — so it is a read of its own, as the engine prints it, and the
    // memory operand keeps only the base. Raised on dbgscope#171.
    //
    // `11111` there is the immediate form instead, whose amount is the transfer's own size:
    // implied by how many registers are named and how wide each transfer is, rather than encoded.
    // It is computed rather than left out, because the base still moves by it and a caller with
    // only the writeback knows *that* and not *how far*. Raised on dbgscope#171.
    let rm = field(word, 16, 5);
    let out = match (post_index, rm) {
        (true, 0b11111) => out.other(post_index_amount(transferred)),
        (true, rm) => out.in_reg(gpr(rm, true, false)),
        (false, _) => out,
    };
    match post_index {
        true => out.writes_only(gpr(rn, true, true)),
        false => out,
    }
}

// ---------------------------------------------------------------------------------------------
// Data processing -- register
// ---------------------------------------------------------------------------------------------

fn data_processing_register(word: u32) -> Out {
    let op2 = field(word, 21, 4);
    if field(word, 28, 1) == 0 {
        return match (op2 & 0b1000, op2 & 1) {
            (0, _) => logical_shifted_register(word),
            (_, 0) => add_subtract_shifted_register(word),
            (_, _) => add_subtract_extended_register(word),
        };
    }
    match op2 {
        0b0000 => match field(word, 10, 6) {
            0b000000 => add_subtract_with_carry(word),
            // `rmif`, `setf8` and `setf16`, which write the flags from a value rather than from a
            // comparison. Reported for the flags they set and the register they read.
            op3 if op3 & 0b011111 == 0b000001 => Out::new("rmif")
                .in_reg(gpr(field(word, 5, 5), true, false))
                .imm(field(word, 15, 6) as u64)
                .imm(field(word, 0, 4) as u64)
                .flags(),
            op3 if op3 & 0b001111 == 0b000010 => Out::new(match field(word, 14, 1) {
                0 => "setf8",
                _ => "setf16",
            })
            .in_reg(gpr(field(word, 5, 5), false, false))
            .flags(),
            _ => Out::undecoded("unallocated"),
        },
        0b0010 => conditional_compare(word),
        0b0100 => conditional_select(word),
        0b0110 => match field(word, 30, 1) {
            0 => data_processing_two_source(word),
            _ => data_processing_one_source(word),
        },
        op2 if op2 & 0b1000 != 0 => data_processing_three_source(word),
        _ => Out::undecoded("unallocated"),
    }
}

/// The shift folded into an arithmetic or logical operand, as a name.
///
/// `None` where the amount is zero, which makes the operand a plain register whatever the shift
/// type says -- and that is the form a compiler emits for ordinary arithmetic, so the common case
/// keeps its [`Effect`].
fn shift_modifier(kind: u32, amount: u32) -> Option<String> {
    if amount == 0 {
        return None;
    }
    let name = match kind {
        0b00 => "lsl",
        0b01 => "lsr",
        0b10 => "asr",
        _ => "ror",
    };
    Some(format!("{name} #{amount:#x}"))
}

/// `and`/`bic`/`orr`/`orn`/`eor`/`eon`/`ands`/`bics`, with `mov`, `mvn` and `tst` resolved out.
fn logical_shifted_register(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    let opc = field(word, 29, 2);
    let negated = field(word, 21, 1) != 0;
    let amount = field(word, 10, 6);
    if !wide && amount >= 32 {
        return Out::undecoded("unallocated");
    }
    let modifier = shift_modifier(field(word, 22, 2), amount);
    let (rd, rn, rm) = (field(word, 0, 5), field(word, 5, 5), field(word, 16, 5));
    let (destination, left, right) = (
        gpr(rd, wide, false),
        gpr(rn, wide, false),
        gpr(rm, wide, false),
    );
    // `mov Rd,Rm` is `orr` from the zero register with nothing shifted -- the commonest
    // instruction in the image, and invisible to anything reading the base mnemonic.
    //
    // **A zero amount is not enough: the shift type has to be `lsl`.** A `lsr #0` is the same
    // no-op arithmetically, which is why [`shift_modifier`] reports no modifier for it and why the
    // effect below is sound either way -- but it is not the alias, and both the engine and a
    // generated table spell it `orr x0,xzr,x1,lsr #0`. Raised on dbgscope#171.
    if opc == 0b01 && !negated && rn == 31 && field(word, 22, 2) == 0b00 && modifier.is_none() {
        return Out::new("mov")
            .out_reg(destination)
            .in_reg(right)
            .effect(Effect::Move);
    }
    if opc == 0b01 && negated && rn == 31 {
        return finish_modifier(
            Out::new("mvn").out_reg(destination).in_reg(right),
            modifier,
            Effect::Other,
        );
    }
    if opc == 0b11 && !negated && rd == 31 {
        return finish_modifier(
            Out::new("tst").in_reg(left).in_reg(right),
            modifier,
            Effect::Test,
        )
        .flags();
    }
    let mnemonic = match (opc, negated) {
        (0b00, false) => "and",
        (0b00, true) => "bic",
        (0b01, false) => "orr",
        (0b01, true) => "orn",
        (0b10, false) => "eor",
        (0b10, true) => "eon",
        (_, false) => "ands",
        (_, true) => "bics",
    };
    // The complementing forms are **not** their base operation's effect: `bic` is an `and` against
    // an inverted operand, and a consumer computing the mask from the operand would get its
    // complement.
    let effect = match (opc, negated) {
        (_, true) => Effect::Other,
        (0b00 | 0b11, _) => Effect::BitAnd,
        (0b01, _) => Effect::BitOr,
        _ => Effect::BitXor,
    };
    let out = finish_modifier(
        Out::new(mnemonic)
            .out_reg(destination)
            .in_reg(left)
            .in_reg(right),
        modifier,
        effect,
    );
    match opc == 0b11 {
        true => out.flags(),
        false => out,
    }
}

/// The amount a post-indexed addressing mode moves its base by, as the engine spells it.
///
/// **A post-indexed access has nowhere else to put this.** The access happens at the base, so the
/// displacement on the [`MemoryOperand`] is zero and has to be — reporting the amount there would
/// name an address the instruction never forms — and the base being in
/// [`crate::dbgeng::Instruction::writes`] says only *that* it moved. A pre-indexed form needs none
/// of this: its displacement is the amount, and the two are the same number.
fn post_index_amount(displacement: i64) -> String {
    match displacement < 0 {
        true => format!("#-{:#x}", -displacement),
        false => format!("#{displacement:#x}"),
    }
}

/// Attaches a modifier if there is one, and gives the effect only if there is not.
fn finish_modifier(out: Out, modifier: Option<String>, effect: Effect) -> Out {
    match modifier {
        Some(text) => out.other(text),
        None => out.effect(effect),
    }
}

/// `add`/`adds`/`sub`/`subs` between two registers, with `cmp`, `cmn` and `neg` resolved out.
fn add_subtract_shifted_register(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    let subtract = word & 0x4000_0000 != 0;
    let sets_flags = word & 0x2000_0000 != 0;
    let shift = field(word, 22, 2);
    let amount = field(word, 10, 6);
    if shift == 0b11 || (!wide && amount >= 32) {
        return Out::undecoded("unallocated");
    }
    let modifier = shift_modifier(shift, amount);
    let (rd, rn) = (field(word, 0, 5), field(word, 5, 5));
    let (destination, left, right) = (
        gpr(rd, wide, false),
        gpr(rn, wide, false),
        gpr(field(word, 16, 5), wide, false),
    );
    let out = match (sets_flags, subtract, rd, rn) {
        (true, true, 31, _) => finish_modifier(
            Out::new("cmp").in_reg(left).in_reg(right),
            modifier,
            Effect::Compare,
        ),
        // `cmn`, again not a [`Effect::Compare`]: it tests against the negation.
        (true, false, 31, _) => finish_modifier(
            Out::new("cmn").in_reg(left).in_reg(right),
            modifier,
            Effect::Other,
        ),
        (_, true, _, 31) => finish_modifier(
            Out::new(if sets_flags { "negs" } else { "neg" })
                .out_reg(destination)
                .in_reg(right),
            modifier,
            Effect::Other,
        ),
        _ => finish_modifier(
            Out::new(match (subtract, sets_flags) {
                (false, false) => "add",
                (false, true) => "adds",
                (true, false) => "sub",
                (true, true) => "subs",
            })
            .out_reg(destination)
            .in_reg(left)
            .in_reg(right),
            modifier,
            match subtract {
                true => Effect::Subtract,
                false => Effect::Add,
            },
        ),
    };
    match sets_flags {
        true => out.flags(),
        false => out,
    }
}

/// `add`/`sub` with an extended second operand -- the form that mixes widths, and the only one
/// that may name the stack pointer as a source.
///
/// **An extension is a modifier except where the operand's own width already says it.** `uxtw` on
/// a `w` register and `uxtx` on an `x` one are zero-extensions to the operation's width, which is
/// what naming the register at its width already conveys — so `add x0,x8,w9,uxtw` keeps
/// [`Effect::Add`] and `add w0,w0,w3,uxth` does not, the second taking two bytes of a four-byte
/// register.
fn add_subtract_extended_register(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    let subtract = word & 0x4000_0000 != 0;
    let sets_flags = word & 0x2000_0000 != 0;
    let amount = field(word, 10, 3);
    if field(word, 22, 2) != 0 || amount > 4 {
        return Out::undecoded("unallocated");
    }
    let option = field(word, 13, 3);
    let (rd, rn) = (field(word, 0, 5), field(word, 5, 5));
    let destination = gpr(rd, wide, !sets_flags);
    let left = gpr(rn, wide, true);
    // **An extended source is `X` only where the operation is 64-bit.** `add w0,w1,w2,uxtx`
    // names a `W` register: nothing above bit 31 of it survives a 32-bit add, so there is nothing
    // wider to name. A round-one finding said so and was declined on a misreading of the width
    // table; the engine and a second decoder both render `w`, and they are right.
    // Raised again on dbgscope#171.
    let right = gpr(field(word, 16, 5), wide && option & 0b011 == 0b011, false);
    let plain = amount == 0 && matches!(option, 0b010 | 0b011);
    let modifier = match plain {
        true => None,
        false => Some(format!(
            "{} #{amount:#x}",
            [
                "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"
            ][option as usize]
        )),
    };
    let out = match (sets_flags, subtract, rd) {
        (true, true, 31) => finish_modifier(
            Out::new("cmp").in_reg(left).in_reg(right),
            modifier,
            Effect::Compare,
        ),
        (true, false, 31) => finish_modifier(
            Out::new("cmn").in_reg(left).in_reg(right),
            modifier,
            Effect::Other,
        ),
        _ => finish_modifier(
            Out::new(match (subtract, sets_flags) {
                (false, false) => "add",
                (false, true) => "adds",
                (true, false) => "sub",
                (true, true) => "subs",
            })
            .out_reg(destination)
            .in_reg(left)
            .in_reg(right),
            modifier,
            match subtract {
                true => Effect::Subtract,
                false => Effect::Add,
            },
        ),
    };
    match sets_flags {
        true => out.flags(),
        false => out,
    }
}

/// `adc`/`adcs`/`sbc`/`sbcs`, and the `ngc` that is `sbc` from the zero register.
fn add_subtract_with_carry(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    let subtract = word & 0x4000_0000 != 0;
    let sets_flags = word & 0x2000_0000 != 0;
    let rn = field(word, 5, 5);
    let destination = gpr(field(word, 0, 5), wide, false);
    let right = gpr(field(word, 16, 5), wide, false);
    let out = match (subtract, rn) {
        (true, 31) => Out::new(if sets_flags { "ngcs" } else { "ngc" })
            .out_reg(destination)
            .in_reg(right),
        _ => Out::new(match (subtract, sets_flags) {
            (false, false) => "adc",
            (false, true) => "adcs",
            (true, false) => "sbc",
            (true, true) => "sbcs",
        })
        .out_reg(destination)
        .in_reg(gpr(rn, wide, false))
        .in_reg(right)
        .effect(match subtract {
            true => Effect::Subtract,
            false => Effect::Add,
        }),
    };
    match sets_flags {
        true => out.flags(),
        false => out,
    }
}

/// `ccmp`/`ccmn`, against a register or a five-bit immediate.
///
/// [`Effect::Other`], not [`Effect::Compare`]: what this leaves in the flags is the comparison
/// **or** the literal `nzcv` the encoding carries, depending on a condition, and a consumer reading
/// it as a comparison would take the first of those for both.
fn conditional_compare(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    let sets_flags = word & 0x2000_0000 != 0;
    if !sets_flags || field(word, 10, 1) != 0 || field(word, 4, 1) != 0 {
        return Out::undecoded("unallocated");
    }
    let code = field(word, 12, 4);
    let immediate = field(word, 11, 1) != 0;
    let out = Out::new(match word & 0x4000_0000 == 0 {
        true => "ccmn",
        false => "ccmp",
    })
    .in_reg(gpr(field(word, 5, 5), wide, false));
    let out = match immediate {
        true => out.imm(field(word, 16, 5) as u64),
        false => out.in_reg(gpr(field(word, 16, 5), wide, false)),
    };
    out.imm(field(word, 0, 4) as u64)
        .cond(condition(code))
        .flags()
}

/// `csel`/`csinc`/`csinv`/`csneg` and the five aliases compilers reach for -- `cset`, `csetm`,
/// `cinc`, `cinv`, `cneg`.
///
/// The aliases invert the condition: `cset Rd,eq` is `csinc Rd,xzr,xzr,ne`, so reporting the
/// encoded field would answer the opposite question about the flags.
fn conditional_select(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    let op = field(word, 30, 1);
    let op2 = field(word, 10, 2);
    if field(word, 29, 1) != 0 || op2 & 0b10 != 0 {
        return Out::undecoded("unallocated");
    }
    let code = field(word, 12, 4);
    let (rd, rn, rm) = (field(word, 0, 5), field(word, 5, 5), field(word, 16, 5));
    let destination = gpr(rd, wide, false);
    let aliasable = code & 0b1110 != 0b1110;
    let (base, alias_nullary, alias_unary) = match (op, op2) {
        (0, 0) => ("csel", "", ""),
        (0, _) => ("csinc", "cset", "cinc"),
        (_, 0) => ("csinv", "csetm", "cinv"),
        (_, _) => ("csneg", "", "cneg"),
    };
    if aliasable && !alias_nullary.is_empty() && rn == 31 && rm == 31 {
        return Out::new(alias_nullary)
            .out_reg(destination)
            .cond(condition(invert(code)));
    }
    if aliasable && !alias_unary.is_empty() && rn == rm {
        return Out::new(alias_unary)
            .out_reg(destination)
            .in_reg(gpr(rn, wide, false))
            .cond(condition(invert(code)));
    }
    Out::new(base)
        .out_reg(destination)
        .in_reg(gpr(rn, wide, false))
        .in_reg(gpr(rm, wide, false))
        .cond(condition(code))
}

/// The two-source operations: division, the variable shifts, CRC and the pointer-tagging pair.
fn data_processing_two_source(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    // **`subps` is the one allocated encoding here with `S` set**, and a blanket rejection of that
    // bit -- which is right for every other class in this space -- took its registers and its
    // flags with it. Raised on dbgscope#171; the guards in the neighbouring classes were audited
    // in the same pass and reject only field values the architecture does not allocate.
    let sets_flags = word & 0x2000_0000 != 0;
    if sets_flags && !(wide && field(word, 10, 6) == 0b000000) {
        return Out::undecoded("unallocated");
    }
    // The variable shifts are written by their alias everywhere: `lsl x0,x1,x2` is `lslv`.
    let (mnemonic, effect) = match field(word, 10, 6) {
        0b000010 => ("udiv", Effect::Other),
        0b000011 => ("sdiv", Effect::Other),
        0b001000 => ("lsl", Effect::ShiftLeft),
        0b001001 => ("lsr", Effect::ShiftRight),
        0b001010 => ("asr", Effect::ShiftRight),
        0b001011 => ("ror", Effect::Other),
        0b000000 => ("subp", Effect::Other),
        0b000100 => ("irg", Effect::Other),
        0b000101 => ("gmi", Effect::Other),
        0b001100 => ("pacga", Effect::Other),
        0b010000 => ("crc32b", Effect::Other),
        0b010001 => ("crc32h", Effect::Other),
        0b010010 => ("crc32w", Effect::Other),
        0b010011 => ("crc32x", Effect::Other),
        0b010100 => ("crc32cb", Effect::Other),
        0b010101 => ("crc32ch", Effect::Other),
        0b010110 => ("crc32cw", Effect::Other),
        0b010111 => ("crc32cx", Effect::Other),
        0b011000 => ("smax", Effect::Other),
        0b011001 => ("umax", Effect::Other),
        0b011010 => ("smin", Effect::Other),
        0b011011 => ("umin", Effect::Other),
        _ => return Out::undecoded("unallocated"),
    };
    // **Which positions read register 31 as the stack pointer is per instruction here**, and this
    // class is the only one in the data-processing space where it is not "none of them": the four
    // pointer-arithmetic instructions the memory-tagging extension adds take `|SP` operands, and
    // reading them as the zero register drops the access entirely -- `irg sp,sp` reported no
    // registers at all. Raised on dbgscope#171, alongside the same mistake in `memory_tags`; the
    // other twenty-two sites in this module that read a 31 were audited in the same pass.
    let (destination, left, right) = (
        gpr(field(word, 0, 5), wide, matches!(mnemonic, "irg")),
        gpr(
            field(word, 5, 5),
            wide,
            matches!(mnemonic, "irg" | "gmi" | "subp"),
        ),
        gpr(
            field(word, 16, 5),
            wide,
            matches!(mnemonic, "subp" | "pacga"),
        ),
    );
    // The CRC accumulators take a 32-bit accumulator and a source whose width the mnemonic names,
    // which is the one place in this class where the two operands are not the same width.
    let crc = mnemonic.starts_with("crc32");
    if sets_flags {
        // `subps` shares `subp`'s shape, both of its sources included.
        return Out::new("subps")
            .out_reg(gpr(field(word, 0, 5), wide, false))
            .in_reg(gpr(field(word, 5, 5), wide, true))
            .in_reg(gpr(field(word, 16, 5), wide, true))
            .flags();
    }
    let out = Out::new(mnemonic);
    match crc {
        true => out
            .out_reg(gpr(field(word, 0, 5), false, false))
            .in_reg(gpr(field(word, 5, 5), false, false))
            .in_reg(gpr(field(word, 16, 5), mnemonic.ends_with('x'), false)),
        false => out
            .out_reg(destination)
            .in_reg(left)
            .in_reg(right)
            .effect(effect),
    }
}

/// The one-source operations: bit and byte reversal, counting, and the pointer-authentication
/// family that signs a register in place.
fn data_processing_one_source(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    if word & 0x2000_0000 != 0 {
        return Out::undecoded("unallocated");
    }
    let (rd, rn) = (field(word, 0, 5), field(word, 5, 5));
    let opcode = field(word, 10, 6);
    match field(word, 16, 5) {
        0b00000 => {
            let mnemonic = match (opcode, wide) {
                (0b000000, _) => "rbit",
                (0b000001, _) => "rev16",
                (0b000010, false) => "rev",
                (0b000010, true) => "rev32",
                (0b000011, true) => "rev",
                (0b000100, _) => "clz",
                (0b000101, _) => "cls",
                (0b000110, _) => "ctz",
                (0b000111, _) => "cnt",
                (0b001000, _) => "abs",
                _ => return Out::undecoded("unallocated"),
            };
            Out::new(mnemonic)
                .out_reg(gpr(rd, wide, false))
                .in_reg(gpr(rn, wide, false))
        }
        // `pacia`/`autia` and friends: 64-bit only, and the destination is the pointer being
        // signed -- so it is read as well as written, which a first-operand rule would miss.
        0b00001 if wide => {
            let mnemonic = match opcode {
                0b000000 => "pacia",
                0b000001 => "pacib",
                0b000010 => "pacda",
                0b000011 => "pacdb",
                0b000100 => "autia",
                0b000101 => "autib",
                0b000110 => "autda",
                0b000111 => "autdb",
                0b001000 => "paciza",
                0b001001 => "pacizb",
                0b001010 => "pacdza",
                0b001011 => "pacdzb",
                0b001100 => "autiza",
                0b001101 => "autizb",
                0b001110 => "autdza",
                0b001111 => "autdzb",
                0b010000 => "xpaci",
                0b010001 => "xpacd",
                _ => return Out::undecoded("unallocated"),
            };
            let out = Out::new(mnemonic).inout_reg(gpr(rd, true, false));
            // The `z` and `xpac` forms take no modifier and require the zero register there.
            match opcode >= 0b001000 {
                true => out,
                false => out.in_reg(gpr(rn, true, true)),
            }
        }
        _ => Out::undecoded("unallocated"),
    }
}

/// The three-source multiplies, with `mul`, `mneg`, `smull`, `umull` and their negating forms
/// resolved out of the accumulating encodings they are written as.
fn data_processing_three_source(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    if word & 0x6000_0000 != 0 {
        return Out::undecoded("unallocated");
    }
    let subtract = field(word, 15, 1) != 0;
    let (rd, rn, rm, ra) = (
        field(word, 0, 5),
        field(word, 5, 5),
        field(word, 16, 5),
        field(word, 10, 5),
    );
    // `op31` says whether the multiply is widening, and which sign it widens with.
    let (widening, signed, high) = match field(word, 21, 3) {
        0b000 => (false, false, false),
        0b001 => (true, true, false),
        0b010 if !subtract => (true, true, true),
        0b101 => (true, false, false),
        0b110 if !subtract => (true, false, true),
        _ => return Out::undecoded("unallocated"),
    };
    if (widening || high) && !wide {
        return Out::undecoded("unallocated");
    }
    if high {
        return Out::new(if signed { "smulh" } else { "umulh" })
            .out_reg(gpr(rd, true, false))
            .in_reg(gpr(rn, true, false))
            .in_reg(gpr(rm, true, false));
    }
    // A widening multiply names 32-bit sources and a 64-bit destination and accumulator.
    let (destination, accumulator) = (gpr(rd, wide, false), gpr(ra, wide, false));
    let source = |number: u32| gpr(number, wide && !widening, false);
    let stem = match (widening, signed) {
        (false, _) => "",
        (true, true) => "s",
        (true, false) => "u",
    };
    // The zero register as the accumulator is what makes a multiply-accumulate a plain multiply.
    if ra == 31 {
        let mnemonic = match (widening, subtract) {
            (false, false) => "mul".to_string(),
            (false, true) => "mneg".to_string(),
            (true, false) => format!("{stem}mull"),
            (true, true) => format!("{stem}mnegl"),
        };
        return Out::new(&mnemonic)
            .out_reg(destination)
            .in_reg(source(rn))
            .in_reg(source(rm));
    }
    let mnemonic = match (widening, subtract) {
        (false, false) => "madd".to_string(),
        (false, true) => "msub".to_string(),
        (true, false) => format!("{stem}maddl"),
        (true, true) => format!("{stem}msubl"),
    };
    Out::new(&mnemonic)
        .out_reg(destination)
        .in_reg(source(rn))
        .in_reg(source(rm))
        .in_reg(accumulator)
}

// ---------------------------------------------------------------------------------------------
// Advanced SIMD and scalar floating-point
// ---------------------------------------------------------------------------------------------

/// The vector and floating-point space, decoded exactly as far as the boundary with the rest of
/// the machine.
///
/// Four things in here are a general-purpose register's or the flags' business, and each of them
/// would be a wrong answer if it were left unread rather than merely unshaped:
///
/// * the conversions and `fmov` forms that move a value **between the register files** — `fmov
///   w3,s2` and `umov x8,v17.d[1]` write a general-purpose register, and a value-tracking pass
///   that did not see it would go on believing what used to be there;
/// * `ins` and `dup` in the other direction, which read one;
/// * `fcmp` and `fccmp`, which write the flags a `b.eq` after them reads — the one case where
///   answering `writes_flags` wrongly sends a consumer looking for the compare that set them past
///   this instruction and back to an integer one that did not;
/// * a vector load or store's base-register writeback, which [`vector_structures`] handles.
///
/// What is left writes vector registers and reads vector registers, and is named rather than
/// shaped.
fn simd_and_floating_point(word: u32) -> Out {
    // The copy class, which is where `umov`, `smov`, `ins` and `dup` cross between the files.
    if word & 0xbfe0_8400 == 0x0e00_0400 {
        return vector_copy(word);
    }
    // The scalar floating-point classes all sit under `x0x11110`, and `op1` at bit 21 separates
    // the fixed-point conversions from everything else.
    if word & 0x5f00_0000 == 0x1e00_0000 {
        if field(word, 21, 1) == 0 {
            return float_fixed_conversion(word);
        }
        let op3 = field(word, 10, 6);
        if op3 == 0b000000 {
            return float_integer_conversion(word);
        }
        if op3 & 0b001111 == 0b001000 && field(word, 14, 2) == 0 {
            return float_compare(word);
        }
        if op3 & 0b000011 == 0b000001 {
            return float_conditional_compare(word);
        }
        return Out::undecoded("floating-point");
    }
    match word & 0x5e00_0000 == 0x1e00_0000 {
        true => Out::undecoded("floating-point"),
        false => Out::undecoded("advanced-simd"),
    }
}

/// How a floating-point `type` field names its register: single, double or half.
fn float_width(kind: u32) -> Option<u32> {
    match kind {
        0b00 => Some(4),
        0b01 => Some(8),
        0b11 => Some(2),
        _ => None,
    }
}

/// `fcvt*`, `scvtf`, `ucvtf` and `fmov` between the two register files.
///
/// **Which file the destination is in comes from `opcode` alone**: `010`, `011` and `111` write
/// the vector register and read the general-purpose one, and every other allocated value goes the
/// other way. That is one field rather than a list of eighteen mnemonics, and it is the answer the
/// rest of this function is arranged around.
fn float_integer_conversion(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    if word & 0x2000_0000 != 0 {
        return Out::undecoded("unallocated");
    }
    let kind = field(word, 22, 2);
    let (rmode, opcode) = (field(word, 19, 2), field(word, 16, 3));
    let (rd, rn) = (field(word, 0, 5), field(word, 5, 5));
    // The one form that names half of a 128-bit register rather than a scalar one: `fmov` to and
    // from `Vn.D[1]`, which is `type` `10` and exists only at 64 bits.
    if kind == 0b10 {
        if rmode != 0b01 || !wide || !matches!(opcode, 0b110 | 0b111) {
            return Out::undecoded("unallocated");
        }
        // The lane is an operand kind [`Operand`] has no shape for, so it is named -- and the
        // register behind that name is still reached, which is a separate question and the one
        // the access lists answer. Writing `Vd.D[1]` leaves the low half standing, so that
        // direction **reads** the register it writes, exactly as `ins` does. Raised on
        // dbgscope#171, where both halves were missing.
        return match opcode {
            // Into a general-purpose register, which ends up holding exactly the lane: a copy.
            0b110 => Out::new("fmov")
                .out_reg(gpr(rd, true, false))
                .other(format!("v{rn}.d[1]"))
                .reads_only(vreg_whole(rn))
                .effect(Effect::Move),
            // And out of one into half a vector register, which is **not** a copy: what the
            // destination holds afterwards is the source beside the low lane it kept.
            _ => Out::new("fmov")
                .other(format!("v{rd}.d[1]"))
                .in_reg(gpr(rn, true, false))
                .writes_only(vreg_whole(rd))
                .reads_only(vreg_whole(rd)),
        };
    }
    let Some(bytes) = float_width(kind) else {
        return Out::undecoded("unallocated");
    };
    let mnemonic = match (rmode, opcode) {
        (0b00, 0b000) => "fcvtns",
        (0b00, 0b001) => "fcvtnu",
        (0b00, 0b010) => "scvtf",
        (0b00, 0b011) => "ucvtf",
        (0b00, 0b100) => "fcvtas",
        (0b00, 0b101) => "fcvtau",
        (0b00, 0b110 | 0b111) => "fmov",
        (0b01, 0b000) => "fcvtps",
        (0b01, 0b001) => "fcvtpu",
        (0b10, 0b000) => "fcvtms",
        (0b10, 0b001) => "fcvtmu",
        (0b11, 0b000) => "fcvtzs",
        (0b11, 0b001) => "fcvtzu",
        (0b11, 0b110) if kind == 0b01 && !wide => "fjcvtzs",
        _ => return Out::undecoded("unallocated"),
    };
    let out = match matches!(opcode, 0b010 | 0b011 | 0b111) {
        true => Out::new(mnemonic)
            .out_reg(vreg(rd, bytes))
            .in_reg(gpr(rn, wide, false)),
        false => Out::new(mnemonic)
            .out_reg(gpr(rd, wide, false))
            .in_reg(vreg(rn, bytes)),
    };
    // **`fmov` is the one member of this class that copies rather than converts**, and it is the
    // distinction the effect exists to draw: a consumer propagating values across a routine can
    // follow `fmov x0,d1` and must not follow `fcvtzs x0,d1`, which is the same two registers and
    // a different number. Raised on dbgscope#171. The upper-lane forms are handled above, where
    // only one direction is a whole copy.
    let out = match mnemonic == "fmov" {
        true => out.effect(Effect::Move),
        false => out,
    };
    // **`fjcvtzs` is the one conversion that also writes the flags**, reporting in `Z` whether the
    // conversion was exact -- which is the Javascript semantics it exists for, and which a caller
    // asking "what set the flags this branch reads" has to see. Found by enumerating this space
    // after dbgscope#171 raised two other holes in it.
    match mnemonic == "fjcvtzs" {
        true => out.flags(),
        false => out,
    }
}

/// The fixed-point half of the same conversions, whose extra operand is how many fraction bits the
/// integer side carries.
fn float_fixed_conversion(word: u32) -> Out {
    let wide = word & 0x8000_0000 != 0;
    if word & 0x2000_0000 != 0 {
        return Out::undecoded("unallocated");
    }
    let Some(bytes) = float_width(field(word, 22, 2)) else {
        return Out::undecoded("unallocated");
    };
    let scale = field(word, 10, 6);
    // A 32-bit operation may not name more fraction bits than it has.
    if !wide && scale < 32 {
        return Out::undecoded("unallocated");
    }
    let mnemonic = match (field(word, 19, 2), field(word, 16, 3)) {
        (0b00, 0b010) => "scvtf",
        (0b00, 0b011) => "ucvtf",
        (0b11, 0b000) => "fcvtzs",
        (0b11, 0b001) => "fcvtzu",
        _ => return Out::undecoded("unallocated"),
    };
    let (rd, rn) = (field(word, 0, 5), field(word, 5, 5));
    let fraction = (64 - scale) as u64;
    match mnemonic.starts_with("fcvt") {
        true => Out::new(mnemonic)
            .out_reg(gpr(rd, wide, false))
            .in_reg(vreg(rn, bytes))
            .imm(fraction),
        false => Out::new(mnemonic)
            .out_reg(vreg(rd, bytes))
            .in_reg(gpr(rn, wide, false))
            .imm(fraction),
    }
}

/// `fcmp`/`fcmpe`, which write the flags a following `b.cond` reads.
fn float_compare(word: u32) -> Out {
    if word & 0xa000_0000 != 0 {
        return Out::undecoded("unallocated");
    }
    let Some(bytes) = float_width(field(word, 22, 2)) else {
        return Out::undecoded("unallocated");
    };
    let opcode2 = field(word, 0, 5);
    if opcode2 & 0b00111 != 0 {
        return Out::undecoded("unallocated");
    }
    let against_zero = opcode2 & 0b01000 != 0;
    let out = Out::new(match opcode2 & 0b10000 {
        0 => "fcmp",
        _ => "fcmpe",
    })
    .in_reg(vreg(field(word, 5, 5), bytes));
    let out = match against_zero {
        true => out.other("#0.0".to_string()),
        false => out.in_reg(vreg(field(word, 16, 5), bytes)),
    };
    out.flags()
}

/// `fccmp`/`fccmpe`. As with the integer `ccmp`, the flags afterwards are the comparison or the
/// literal the encoding carries, so there is no [`Effect::Compare`] to claim here either.
fn float_conditional_compare(word: u32) -> Out {
    if word & 0xa000_0000 != 0 {
        return Out::undecoded("unallocated");
    }
    let Some(bytes) = float_width(field(word, 22, 2)) else {
        return Out::undecoded("unallocated");
    };
    Out::new(match field(word, 4, 1) {
        0 => "fccmp",
        _ => "fccmpe",
    })
    .in_reg(vreg(field(word, 5, 5), bytes))
    .in_reg(vreg(field(word, 16, 5), bytes))
    .imm(field(word, 0, 4) as u64)
    .cond(condition(field(word, 12, 4)))
    .flags()
}

/// `dup`, `ins`, `smov` and `umov` -- the four ways a value crosses between a vector register's
/// lanes and a general-purpose register.
///
/// The lane is an operand kind [`Operand`] has no shape for (`v17.d[1]` is a register *and* an
/// index), so it is named; the general-purpose side is a register and is reported as one, which is
/// the half that matters to a caller following a value.
fn vector_copy(word: u32) -> Out {
    let q = field(word, 30, 1) != 0;
    let imm5 = field(word, 16, 5);
    // The lowest set bit of `imm5` picks the element width, and what is above it is the index.
    let (element, index) = match imm5.trailing_zeros() {
        0 => ('b', imm5 >> 1),
        1 => ('h', imm5 >> 2),
        2 => ('s', imm5 >> 3),
        3 => ('d', imm5 >> 4),
        _ => return Out::undecoded("unallocated"),
    };
    let (rd, rn) = (field(word, 0, 5), field(word, 5, 5));
    let lane = |number: u32| format!("v{number}.{element}[{index}]");
    match field(word, 11, 4) {
        // `dup Vd.<T>,Vn.<Ts>[index]`: vector to vector, and here only for its mnemonic.
        0b0000 => Out::new("dup")
            .other(format!("v{rd}"))
            .other(lane(rn))
            .writes_only(vreg_whole(rd))
            .reads_only(vreg_whole(rn)),
        // `dup Vd.<T>,Rn`: a general-purpose register read into every lane.
        0b0001 => Out::new("dup")
            .other(format!("v{rd}"))
            .in_reg(gpr(rn, element == 'd', false))
            .writes_only(vreg_whole(rd)),
        // `ins Vd.<Ts>[index],Rn`: one lane written, the rest kept -- so the vector register is
        // read as well as written.
        0b0011 => Out::new("ins")
            .other(lane(rd))
            .in_reg(gpr(rn, element == 'd', false))
            .writes_only(vreg_whole(rd))
            .reads_only(vreg_whole(rd)),
        // **Both are copies out of a lane and neither was saying so.** `umov` zero-extends and
        // `smov` sign-extends, which is the same pair of effects `uxtb` and `sxtb` carry on the
        // general-purpose side and the same distinction `Effect::MoveSigned` exists to draw: what
        // the value means afterwards. Raised on dbgscope#171.
        0b0101 => Out::new("smov")
            .out_reg(gpr(rd, q, false))
            .other(lane(rn))
            .reads_only(vreg_whole(rn))
            .effect(Effect::MoveSigned),
        0b0111 => Out::new("umov")
            .out_reg(gpr(rd, element == 'd', false))
            .other(lane(rn))
            .reads_only(vreg_whole(rn))
            .effect(Effect::Move),
        _ => Out::undecoded("advanced-simd"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbgeng::Flow;

    /// Every word below was rendered by the engine on the 26100 ARM64 kernel dump in
    /// `windbg-mcp`'s `docs/samples`, and the rendering is quoted beside it. That is the point:
    /// the expectations are the debugger's own reading of the same four bytes rather than this
    /// decoder's arithmetic done twice.
    ///
    /// The whole of that image's `.text` and `PAGE` — 1,233,502 words, of which the engine
    /// rendered 1,189,047 — was run through this decoder against those renderings while it was
    /// written. What that found, and what it left, is in the module header.
    const ANYWHERE: u64 = 0x1000;

    fn shapes(word: u32) -> Decoded {
        decode(word, ANYWHERE)
    }

    fn spellings(registers: &[RegisterOperand]) -> Vec<&str> {
        registers.iter().map(|r| r.name.as_str()).collect()
    }

    fn register(name: &str, full: &str, width: u32) -> Operand {
        Operand::Register(RegisterOperand {
            name: name.to_string(),
            full: full.to_string(),
            width,
        })
    }

    /// The shift on an add/subtract immediate is **part of the value**, and issue #170 named this
    /// one outright: the compare chain a compiler emits for a control-code switch is a `sub`
    /// against a shifted literal, and an operand holding the unshifted field describes a different
    /// comparison from the one the processor makes.
    #[test]
    fn test_a_shifted_immediate_is_folded_into_the_value_it_means() {
        // `71576343  subs w3,w26,#0x5D8,lsl #0xC`.
        let subs = shapes(0x7157_6343);
        assert_eq!(subs.mnemonic, "subs");
        assert_eq!(subs.operands[2], Operand::Immediate(0x5d8 << 12));
        assert_eq!(subs.effect, Effect::Subtract);
        assert!(subs.writes_flags);
        // `7140053f  cmp w9,#1,lsl #0xC` -- the same folding through the `cmp` alias.
        let cmp = shapes(0x7140_053f);
        assert_eq!(cmp.mnemonic, "cmp");
        assert_eq!(cmp.operands[1], Operand::Immediate(0x1000));
        // An unshifted one is not multiplied by anything.
        // `f10010df  cmp x6,#4`.
        assert_eq!(shapes(0xf100_10df).operands[1], Operand::Immediate(4));
    }

    /// `cmp` writes no register and `cmn` is not a comparison against the immediate it names.
    ///
    /// Both are aliases of an arithmetic instruction discarding its result into the zero register,
    /// and they part company in what a consumer may conclude: `cmp Rn,#4` is true of `Rn == 4`,
    /// while `cmn Rn,#4` is true of `Rn == -4`. Reporting the second as [`Effect::Compare`] reads
    /// the test backwards, which is the same defect as reading `ja` for `jg`.
    #[test]
    fn test_a_compare_writes_nothing_and_a_compare_negative_is_not_one() {
        let cmp = shapes(0xf100_10df);
        assert_eq!(cmp.operands.len(), 2);
        assert_eq!(cmp.effect, Effect::Compare);
        assert!(cmp.writes.is_empty(), "{cmp:?}");
        assert!(cmp.writes_flags);
        // `3100067f  cmn w19,#1`.
        let cmn = shapes(0x3100_067f);
        assert_eq!(cmn.mnemonic, "cmn");
        assert_eq!(cmn.effect, Effect::Other);
        assert!(cmn.writes_flags);
        assert!(cmn.writes.is_empty(), "{cmn:?}");
    }

    /// A logical immediate is a bitmask description and not a number, and the same six bits of
    /// `imms` mean different masks at different element widths.
    #[test]
    fn test_a_bitmask_immediate_is_decoded_rather_than_read() {
        // `9274ce52  and xpr,xpr,#-0x1000`.
        assert_eq!(
            shapes(0x9274_ce52).operands[2],
            Operand::Immediate(0xffff_ffff_ffff_f000)
        );
        // `b2407fe4  mov x4,#0xFFFFFFFF` -- `orr` from the zero register, which is the alias.
        let wide = shapes(0xb240_7fe4);
        assert_eq!(wide.mnemonic, "mov");
        assert_eq!(wide.effect, Effect::Move);
        assert_eq!(wide.operands[1], Operand::Immediate(0xffff_ffff));
        // `b20003e8`, which the engine renders `movi x8,#0x100000001`: `N` is **zero** here, so
        // the element is 32 bits and the mask replicates. Reading it at 64 would give 1.
        assert_eq!(
            shapes(0xb200_03e8).operands[1],
            Operand::Immediate(0x1_0000_0001)
        );
        // `f25a005f  tst x2,#0x4000000000`.
        let tst = shapes(0xf25a_005f);
        assert_eq!(tst.mnemonic, "tst");
        assert_eq!(tst.effect, Effect::Test);
        assert_eq!(tst.operands[1], Operand::Immediate(0x40_0000_0000));
        assert!(tst.writes.is_empty(), "{tst:?}");
    }

    /// A move-wide reports the value it leaves in the register, which for `movn` is the
    /// complement of the field and for `movk` is only part of what ends up there — so `movk`
    /// **reads** its destination.
    #[test]
    fn test_a_move_wide_reports_the_value_it_writes() {
        // `d2800016  mov x22,#0`.
        assert_eq!(shapes(0xd280_0016).operands[1], Operand::Immediate(0));
        // `1281383a  mov w26,#-0x9C2` -- a `movn`, whose field is `0x9C1`.
        let negative = shapes(0x1281_383a);
        assert_eq!(negative.mnemonic, "mov");
        assert_eq!(negative.operands[1], Operand::Immediate(0xffff_f63e));
        // `f2b80000  movk x0,#0xC000,lsl #0x10`.
        let keep = shapes(0xf2b8_0000);
        assert_eq!(keep.mnemonic, "movk");
        assert_eq!(keep.operands[1], Operand::Immediate(0xc000_0000));
        assert_eq!(spellings(&keep.writes), ["x0"]);
        assert_eq!(
            spellings(&keep.reads),
            ["x0"],
            "a `movk` keeps the other halves"
        );
        assert_eq!(keep.effect, Effect::Other, "it is a merge, not a copy");
    }

    /// A bitfield alias changes the **operand list**, which is why they are resolved rather than
    /// left as the base form: `lsr x0,x0,#16` and `ubfx x0,x0,#16,#8` are the same three encoded
    /// fields read two ways, and a consumer matching `ubfm` would take a shift amount out of a
    /// field position.
    #[test]
    fn test_a_bitfield_alias_changes_the_operand_list() {
        // `53107c00  lsr w0,w0,#0x10`.
        let lsr = shapes(0x5310_7c00);
        assert_eq!(lsr.mnemonic, "lsr");
        assert_eq!(lsr.effect, Effect::ShiftRight);
        assert_eq!(lsr.operands[2], Operand::Immediate(0x10));
        // `d378dfde  lsl lr,lr,#8`.
        let lsl = shapes(0xd378_dfde);
        assert_eq!(lsl.mnemonic, "lsl");
        assert_eq!(lsl.effect, Effect::ShiftLeft);
        assert_eq!(lsl.operands[2], Operand::Immediate(8));
        // `9343fdad  asr x13,x13,#3`.
        assert_eq!(shapes(0x9343_fdad).mnemonic, "asr");
        // `53065509  ubfx w9,w8,#6,#0x10` -- four operands, and no effect to claim.
        let ubfx = shapes(0x5306_5509);
        assert_eq!(ubfx.mnemonic, "ubfx");
        assert_eq!(ubfx.operands[2], Operand::Immediate(6));
        assert_eq!(ubfx.operands[3], Operand::Immediate(0x10));
        assert_eq!(ubfx.effect, Effect::Other);
        // The extending aliases, which read a narrow register whatever `sf` says.
        // `53001d00  uxtb w0,w8` and `93407c59  sxtw x25,w2`.
        let uxtb = shapes(0x5300_1d00);
        assert_eq!(uxtb.mnemonic, "uxtb");
        // **Not a move**: it extends one byte of a register named as four, and no operand's width
        // says so, exactly as `bic`'s mask is not in its operands. The word-width pair is, their
        // source naming precisely what they extend.
        assert_eq!(uxtb.effect, Effect::Other);
        assert_eq!(shapes(0xd340_1c20).effect, Effect::Other, "and at 64 bits");
        assert_eq!(shapes(0x5300_3c00).effect, Effect::Other, "uxth");
        let sxtw = shapes(0x9340_7c59);
        assert_eq!(sxtw.mnemonic, "sxtw");
        assert_eq!(sxtw.effect, Effect::MoveSigned);
        assert_eq!(shapes(0xd340_7c08).effect, Effect::Move, "uxtw");
        assert_eq!(sxtw.operands[1], register("w2", "x2", 4));
        // `b374cd28  bfi x8,x9,#0xC,#0x34` -- an insert keeps the bits it does not replace, so
        // the destination is a read too.
        let bfi = shapes(0xb374_cd28);
        assert_eq!(bfi.mnemonic, "bfi");
        assert_eq!(spellings(&bfi.reads), ["x8", "x9"]);
        assert_eq!(spellings(&bfi.writes), ["x8"]);
    }

    /// `adrp` is a **page** address: the instruction's own address is truncated to its page before
    /// the displacement is added, and taking the whole address instead is wrong by up to 4,095.
    #[test]
    fn test_a_page_address_truncates_the_instruction_s_own() {
        // `fffff802e9e5d5b4  90005928  adrp x8,nt!PopSIdle+0x40 (fffff802ea981000)`.
        let adrp = decode(0x9000_5928, 0xfffff802_e9e5d5b4);
        assert_eq!(adrp.mnemonic, "adrp");
        assert_eq!(adrp.effect, Effect::LoadAddress);
        assert_eq!(
            adrp.operands[1],
            Operand::Memory(MemoryOperand {
                address: Some(0xfffff802_ea981000),
                ..MemoryOperand::default()
            })
        );
        // `fffff802e9e000c0  10ffffe1  adr x1,nt!HalpStartupStub+0xc (fffff802e9e000cc)` -- an
        // `adr` measures from the whole address and from the instruction rather than its end.
        let adr = decode(0x10ff_ffe1, 0xfffff802_e9e000d0);
        assert_eq!(adr.mnemonic, "adr");
        assert_eq!(
            adr.operands[1],
            Operand::Memory(MemoryOperand {
                address: Some(0xfffff802_e9e000cc),
                ..MemoryOperand::default()
            })
        );
    }

    /// A call writes the link register and names it in neither direction.
    #[test]
    fn test_a_call_writes_the_link_register_without_naming_it() {
        // `fffff802e9e5df70  97fffcc4  bl nt!KeBugCheck2 (fffff802e9e5d280)`.
        let call = decode(0x97ff_fcc4, 0xfffff802_e9e5df70);
        assert_eq!(call.mnemonic, "bl");
        assert_eq!(call.operands, [Operand::Target(0xfffff802_e9e5d280)]);
        assert_eq!(spellings(&call.writes), ["lr"]);
        // `d63f01e0  blr x15`.
        let indirect = shapes(0xd63f_01e0);
        assert_eq!(indirect.mnemonic, "blr");
        assert_eq!(spellings(&indirect.reads), ["x15"]);
        assert_eq!(spellings(&indirect.writes), ["lr"]);
        // `d65f03c0  ret` -- the engine prints no operand where it is the link register, and
        // neither does this.
        let ret = shapes(0xd65f_03c0);
        assert_eq!(ret.mnemonic, "ret");
        assert!(ret.operands.is_empty(), "{ret:?}");
        assert_eq!(spellings(&ret.reads), ["lr"]);
        // `b` writes nothing.
        assert!(shapes(0x1400_0004).writes.is_empty());
    }

    /// The condition is a field rather than a mnemonic, and the signedness comes with it.
    #[test]
    fn test_a_conditional_instruction_carries_the_condition_as_a_field() {
        // `fffff802ea69dc1c  540002c1  bne nt!KiSystemStartup+0xb4`.
        let branch = decode(0x5400_02c1, 0xfffff802_ea69dc1c);
        assert_eq!(branch.mnemonic, "b.ne");
        assert_eq!(branch.condition, Some(Condition::NotEqual));
        assert_eq!(branch.flow, Flow::Branch(Some(0xfffff802_ea69dc74)));
        // `540002c3`, which the engine renders `blo`: the carry flag, which is the **unsigned**
        // comparison and is the distinction a mnemonic match loses.
        assert_eq!(
            shapes(0x5400_02c3).condition,
            Some(Condition::UnsignedBelow)
        );
        // `5400028c`, rendered `bgt`.
        assert_eq!(
            shapes(0x5400_028c).condition,
            Some(Condition::SignedGreater)
        );
        // An always-condition has none to report, and `super::flow` calls it a jump.
        let always = shapes(0x5400_002e);
        assert_eq!(always.condition, None);
        assert_eq!(always.flow, Flow::Jmp(Some(0x1004)));
    }

    /// A conditional select is encoded on the **inverse** of the condition it is written with, so
    /// reporting the encoded field answers the opposite question about the flags.
    #[test]
    fn test_a_conditional_select_alias_inverts_its_condition() {
        // `9a9f37e0`, which the engine renders `cseths x0`: `csinc x0,xzr,xzr,lo`.
        let set = shapes(0x9a9f_37e0);
        assert_eq!(set.mnemonic, "cset");
        assert_eq!(set.condition, Some(Condition::UnsignedAboveOrEqual));
        assert_eq!(set.operands, [register("x0", "x0", 8)]);
        // `9a8724e7`, rendered `cinclo x7,x7`.
        let increment = shapes(0x9a87_24e7);
        assert_eq!(increment.mnemonic, "cinc");
        assert_eq!(increment.condition, Some(Condition::UnsignedBelow));
        // `9a891108`, rendered `cselne x8,x8,x9` -- a plain select keeps the encoded condition.
        let select = shapes(0x9a89_1108);
        assert_eq!(select.mnemonic, "csel");
        assert_eq!(select.condition, Some(Condition::NotEqual));
        assert_eq!(select.operands.len(), 3);
    }

    /// A conditional compare leaves either the comparison **or** the literal `nzcv` it carries in
    /// the flags, depending on a condition, so there is no comparison for a consumer to read.
    #[test]
    fn test_a_conditional_compare_is_not_a_compare() {
        // `fa4a1284`, rendered `ccmpne x20,x10,#4`.
        let ccmp = shapes(0xfa4a_1284);
        assert_eq!(ccmp.mnemonic, "ccmp");
        assert_eq!(ccmp.effect, Effect::Other);
        assert_eq!(ccmp.condition, Some(Condition::NotEqual));
        assert!(ccmp.writes_flags);
        assert_eq!(spellings(&ccmp.reads), ["x20", "x10"]);
        assert_eq!(ccmp.operands[2], Operand::Immediate(4));
        // `7a400984`, rendered `ccmpeq w12,#0,#4` -- the immediate form.
        let immediate = shapes(0x7a40_0984);
        assert_eq!(immediate.operands[1], Operand::Immediate(0));
        assert_eq!(immediate.condition, Some(Condition::Equal));
    }

    /// A load's immediate is scaled by the access width, which is the field this would be most
    /// quietly wrong about: `0x87` at eight bytes is `0x438`, and unscaled it is a different
    /// structure member.
    #[test]
    fn test_a_load_scales_its_displacement_by_the_access_width() {
        // `f9421e93  ldr x19,[x20,#0x438]`.
        let wide = shapes(0xf942_1e93);
        assert_eq!(wide.mnemonic, "ldr");
        assert_eq!(wide.effect, Effect::Move);
        assert_eq!(
            wide.operands[1],
            Operand::Memory(MemoryOperand {
                size: Some(8),
                base: Some(RegisterOperand {
                    name: "x20".into(),
                    full: "x20".into(),
                    width: 8
                }),
                scale: 1,
                displacement: 0x438,
                ..MemoryOperand::default()
            })
        );
        // `79400423  ldrh w3,[x1,#2]` -- two bytes, so the same field means something else.
        let half = shapes(0x7940_0423);
        assert_eq!(half.mnemonic, "ldrh");
        let Operand::Memory(memory) = &half.operands[1] else {
            panic!("{half:?}");
        };
        assert_eq!((memory.size, memory.displacement), (Some(2), 2));
        // `b9868d02  ldrsw x2,[x8,#0x68C]` -- a sign-extending load means something different
        // about the value afterwards.
        assert_eq!(shapes(0xb986_8d02).effect, Effect::MoveSigned);
    }

    /// A post-indexed access happens **at the base**, and a pre-indexed one at the displacement;
    /// both move the base afterwards, and that is a write the operand list has no shape for.
    #[test]
    fn test_an_indexed_access_reports_the_address_it_forms_and_the_base_it_moves() {
        // `b8404423  ldr w3,[x1],#4`.
        let post = shapes(0xb840_4423);
        let Operand::Memory(memory) = &post.operands[1] else {
            panic!("{post:?}");
        };
        assert_eq!(memory.displacement, 0, "the access is at the base itself");
        assert_eq!(spellings(&post.writes), ["x3", "x1"]);
        assert_eq!(
            post.operands[2],
            Operand::Other("#0x4".to_string()),
            "the amount has nowhere else to go: {post:?}"
        );
        // `f8408d09  ldr x9,[x8,#8]!`.
        let pre = shapes(0xf840_8d09);
        let Operand::Memory(memory) = &pre.operands[1] else {
            panic!("{pre:?}");
        };
        assert_eq!(memory.displacement, 8);
        assert_eq!(spellings(&pre.writes), ["x9", "x8"]);
        assert_eq!(pre.operands.len(), 2, "a pre-index needs no name: {pre:?}");
        // `f8403028  ldur x8,[x1,#3]` -- unscaled, and named `ldur` rather than `ldrur`.
        let unscaled = shapes(0xf840_3028);
        assert_eq!(unscaled.mnemonic, "ldur");
        assert!(unscaled.writes.len() == 1, "no writeback: {unscaled:?}");
        // `385f02c8  ldurb w8,[x22,#-0x10]` -- the suffix follows the `ur`, and the displacement
        // is signed.
        let byte = shapes(0x385f_02c8);
        assert_eq!(byte.mnemonic, "ldurb");
        let Operand::Memory(memory) = &byte.operands[1] else {
            panic!("{byte:?}");
        };
        assert_eq!(memory.displacement, -0x10);
    }

    /// **A store names its source first**, which is the shape an x64 habit reads backwards.
    #[test]
    fn test_a_store_names_its_source_first_and_writes_no_register() {
        // `f9000fe8  str x8,[sp,#0x18]`.
        let store = shapes(0xf900_0fe8);
        assert_eq!(store.mnemonic, "str");
        assert_eq!(store.operands[0], register("x8", "x8", 8));
        assert!(matches!(store.operands[1], Operand::Memory(_)));
        assert!(store.writes.is_empty(), "{store:?}");
        assert_eq!(spellings(&store.reads), ["x8", "sp"]);
    }

    /// A pair moves two registers, so there is no single effect to claim and both ends are in the
    /// register lists.
    #[test]
    fn test_a_pair_reaches_two_registers_and_its_base() {
        // `a9bf7bfd  stp fp,lr,[sp,#-0x10]!`, which is the first instruction of most functions in
        // the image. The engine renders the displacement `-0x10` and it is `-0x20` in the
        // seven-bit field's own units, which is what the scaling is for.
        let push = shapes(0xa9bf_7bfd);
        assert_eq!(push.mnemonic, "stp");
        assert_eq!(push.effect, Effect::Other);
        assert_eq!(spellings(&push.reads), ["fp", "lr", "sp"]);
        assert_eq!(
            spellings(&push.writes),
            ["sp"],
            "the writeback, and nothing else"
        );
        let Operand::Memory(memory) = &push.operands[2] else {
            panic!("{push:?}");
        };
        assert_eq!((memory.size, memory.displacement), (Some(16), -0x10));
        // `a9427bfd  ldp fp,lr,[sp,#0x20]`.
        let pop = shapes(0xa942_7bfd);
        assert_eq!(pop.mnemonic, "ldp");
        assert_eq!(spellings(&pop.writes), ["fp", "lr"]);
        // `a8c353f3  ldp x19,x20,[sp],#0x30` -- the post-indexed epilogue, whose amount is named.
        let unwind = shapes(0xa8c3_53f3);
        assert_eq!(spellings(&unwind.writes), ["x19", "x20", "sp"]);
        assert_eq!(unwind.operands[3], Operand::Other("#0x30".to_string()));
        // `f81f84df  str xzr,[x6],#-8` -- and a negative one keeps its sign.
        assert_eq!(
            shapes(0xf81f_84df).operands[2],
            Operand::Other("#-0x8".to_string())
        );
        // `694d5050  ldpsw xip0,x20,[x2,#0x68]` -- sign-extending, and a four-byte scale against
        // eight-byte registers.
        let signed = shapes(0x694d_5050);
        assert_eq!(signed.mnemonic, "ldpsw");
        assert_eq!(spellings(&signed.writes), ["xip0", "x20"]);
    }

    /// A literal load's address is in the encoding, measured from the instruction rather than from
    /// its end -- the one place a reader carrying an x86 habit is four bytes out.
    #[test]
    fn test_a_literal_load_resolves_its_own_address() {
        // `fffff802e9e001dc  580001e5  ldr x5,nt!HalpStubVmTarget+0x34 (fffff802e9e00218)`.
        let literal = decode(0x5800_01e5, 0xfffff802_e9e001dc);
        assert_eq!(literal.mnemonic, "ldr");
        let Operand::Memory(memory) = &literal.operands[1] else {
            panic!("{literal:?}");
        };
        assert_eq!(memory.address, Some(0xfffff802_e9e00218));
        assert_eq!(memory.base, None, "nothing at run time contributes to it");
        assert_eq!(memory.size, Some(8));
    }

    /// The atomic and exclusive families put a register on each side of the access, and which is
    /// which is not the operand order: `ldadd x8,x8,[x9]` names one register twice and the two are
    /// a read and a write, and an exclusive store writes a *status* register neither of its other
    /// operands is.
    #[test]
    fn test_the_atomic_family_separates_what_goes_in_from_what_comes_out() {
        // `f8280128  ldadd x8,x8,[x9]`.
        let add = shapes(0xf828_0128);
        assert_eq!(add.mnemonic, "ldadd");
        assert_eq!(spellings(&add.reads), ["x8", "x9"]);
        assert_eq!(spellings(&add.writes), ["x8"]);
        // `c8e8ff20  casal x8,x0,[x25]` -- the comparand goes in and the old value comes back.
        let swap = shapes(0xc8e8_ff20);
        assert_eq!(swap.mnemonic, "casal");
        assert_eq!(spellings(&swap.reads), ["x8", "x0", "x25"]);
        assert_eq!(spellings(&swap.writes), ["x8"]);
        // `c8117d49  stxr wip1,x9,[x10]` -- `wip1` is the status, `x9` the value stored.
        let exclusive = shapes(0xc811_7d49);
        assert_eq!(exclusive.mnemonic, "stxr");
        assert_eq!(spellings(&exclusive.writes), ["xip1"]);
        assert_eq!(spellings(&exclusive.reads), ["x9", "x10"]);
        // `b8bfc129  ldapr w9,[x9]`, which shares the encoding and is an ordinary load.
        let acquire = shapes(0xb8bf_c129);
        assert_eq!(acquire.mnemonic, "ldapr");
        assert_eq!(acquire.effect, Effect::Move);
        // `88a87c02  cas w8,w2,[x0]` -- the unordered form, at 32 bits.
        assert_eq!(shapes(0x88a8_7c02).mnemonic, "cas");
        // `482a7c0c  casp x10,x11,x12,x13,[x0]` -- four registers, and the pair is consecutive.
        let pair = shapes(0x482a_7c0c);
        assert_eq!(pair.mnemonic, "casp");
        assert_eq!(spellings(&pair.writes), ["x10", "x11"]);
    }

    /// A shift folded into a register operand **demotes the effect**, because the operand list has
    /// no shape for one and a consumer reading `[x8, x9, x4, Immediate(56)]` as an `orr` would
    /// compute against 56 rather than against `x4 << 56`.
    #[test]
    fn test_a_modifier_the_operand_list_cannot_carry_demotes_the_effect() {
        // `aa04e3de  orr lr,lr,x4,lsl #0x38`.
        let shifted = shapes(0xaa04_e3de);
        assert_eq!(shifted.mnemonic, "orr");
        assert_eq!(shifted.effect, Effect::Other);
        assert_eq!(shifted.operands[3], Operand::Other("lsl #0x38".to_string()));
        // `aa050085  orr x5,x4,x5` -- shift zero, so no modifier and the effect survives.
        let plain = shapes(0xaa05_0085);
        assert_eq!(plain.effect, Effect::BitOr);
        assert_eq!(plain.operands.len(), 3);
        // **The `mov` alias needs `lsl` and not merely a zero amount.** `aa0103e0` is
        // `mov x0,x1`; `aa4103e0` is the same registers shifted `lsr #0`, which is the same no-op
        // arithmetically and is not the alias -- the engine and a generated table both spell it
        // `orr x0,xzr,x1,lsr #0`.
        assert_eq!(shapes(0xaa01_03e0).mnemonic, "mov");
        let not_a_move = shapes(0xaa41_03e0);
        assert_eq!(not_a_move.mnemonic, "orr");
        assert_eq!(not_a_move.effect, Effect::BitOr);
        assert_eq!(not_a_move.operands.len(), 3);
        // `eb47311f  cmp x8,x7,lsr #0xC` -- a compare with a modifier is not one either.
        let compare = shapes(0xeb47_311f);
        assert_eq!(compare.mnemonic, "cmp");
        assert_eq!(compare.effect, Effect::Other);
        assert!(compare.writes_flags);
        // `8a0600e7  and x7,x7,x6`.
        assert_eq!(shapes(0x8a06_00e7).effect, Effect::BitAnd);
        // `8a220021  bic x1,x1,x2` -- an `and` against an inverted operand is **not** a
        // [`Effect::BitAnd`]: a consumer taking the mask from the operand would have its
        // complement.
        let clear = shapes(0x8a22_0021);
        assert_eq!(clear.mnemonic, "bic");
        assert_eq!(clear.effect, Effect::Other);
    }

    /// An extension the operand's own width already conveys is not a modifier, and one that takes
    /// part of a register is.
    #[test]
    fn test_an_extension_the_register_width_already_says_is_not_a_modifier() {
        // `8b294100  add x0,x8,w9,uxtw #0` -- a 32-bit register zero-extended into 64-bit
        // arithmetic, which is what naming `w9` says.
        let widened = shapes(0x8b29_4100);
        assert_eq!(widened.effect, Effect::Add);
        assert_eq!(widened.operands[2], register("w9", "x9", 4));
        assert_eq!(widened.operands.len(), 3);
        // `cb2363ff  sub sp,sp,x3` -- `uxtx #0`, which the engine prints as nothing at all.
        let stack = shapes(0xcb23_63ff);
        assert_eq!(stack.effect, Effect::Subtract);
        assert_eq!(stack.operands[0], register("sp", "sp", 8));
        // `0b232000  add w0,w0,w3,uxth #0` -- two bytes of a four-byte register, which is a
        // modifier.
        let narrowed = shapes(0x0b23_2000);
        assert_eq!(narrowed.effect, Effect::Other);
        assert_eq!(
            narrowed.operands[3],
            Operand::Other("uxth #0x0".to_string())
        );
        // `eb20c27f  cmp x19,w0,sxtw #0` -- signed, so not a plain register either.
        assert_eq!(shapes(0xeb20_c27f).effect, Effect::Other);
        // **An extended source is `X` only where the operation is**, nothing above bit 31 of it
        // surviving a 32-bit add. `0b226020  add w0,w1,w2,uxtx` against `8b226020`, the same
        // encoding at 64 bits.
        assert_eq!(shapes(0x0b22_6020).operands[2], register("w2", "x2", 4));
        assert_eq!(shapes(0x8b22_6020).operands[2], register("x2", "x2", 8));
    }

    /// A multiply that accumulates the zero register is a plain multiply, and its operand list is
    /// one shorter for it.
    #[test]
    fn test_a_multiply_accumulating_nothing_is_written_as_one() {
        // `9b097d08  mul x8,x8,x9`.
        let multiply = shapes(0x9b09_7d08);
        assert_eq!(multiply.mnemonic, "mul");
        assert_eq!(multiply.operands.len(), 3);
        // `9b0b3108  madd x8,x8,x11,x12`.
        let accumulate = shapes(0x9b0b_3108);
        assert_eq!(accumulate.mnemonic, "madd");
        assert_eq!(accumulate.operands.len(), 4);
        // `9ba97d49  umull x9,w10,w9` -- a widening multiply names 32-bit sources.
        let widening = shapes(0x9ba9_7d49);
        assert_eq!(widening.mnemonic, "umull");
        assert_eq!(widening.operands[1], register("w10", "x10", 4));
        assert_eq!(widening.operands[0], register("x9", "x9", 8));
        // `9bc77ccc  umulh x12,x6,x7`.
        assert_eq!(shapes(0x9bc7_7ccc).mnemonic, "umulh");
        // `9ac10928  udiv x8,x9,x1` and `9ac524c6  lsr x6,x6,x5`, the two-source class.
        assert_eq!(shapes(0x9ac1_0928).mnemonic, "udiv");
        let variable = shapes(0x9ac5_24c6);
        assert_eq!(variable.mnemonic, "lsr");
        assert_eq!(variable.effect, Effect::ShiftRight);
        // `5ac01108  clz w8,w8` and `dac00d09  rev x9,x8`, the one-source class.
        assert_eq!(shapes(0x5ac0_1108).mnemonic, "clz");
        assert_eq!(shapes(0xdac0_0d09).mnemonic, "rev");
    }

    /// A system register is named from its own encoding rather than from a table, and privilege
    /// comes from the `op1` field beside it.
    #[test]
    fn test_a_system_register_is_named_and_gated_by_its_encoding() {
        // `d5182025  msr TTBR1_EL1,x5` -- `S3_0_C2_C0_1`, and `op1` zero is EL1.
        let write = shapes(0xd518_2025);
        assert_eq!(write.mnemonic, "msr");
        assert_eq!(
            write.operands[0],
            Operand::Other("s3_0_c2_c0_1".to_string())
        );
        assert_eq!(spellings(&write.reads), ["x5"]);
        assert!(write.privileged);
        // `d53be04d  mrs x13,CNTVCT_EL0` -- `op1` three, which is the one value naming EL0, so
        // reading the virtual counter is not privileged and reporting it as such would put every
        // user-mode timing loop in a hazard report.
        let counter = shapes(0xd53b_e04d);
        assert_eq!(counter.mnemonic, "mrs");
        assert_eq!(
            counter.operands[1],
            Operand::Other("s3_3_c14_c0_2".to_string())
        );
        assert!(!counter.privileged);
        assert_eq!(spellings(&counter.writes), ["x13"]);
        // `d53b4208  mrs x8,NZCV` reads the flags and does not write them; `d51b4402  msr FPCR,x2`
        // is EL0-writable.
        assert!(!shapes(0xd53b_4208).privileged);
        assert!(!shapes(0xd51b_4402).privileged);
        // Writing `NZCV` is the one system-register access that sets the flags a branch reads.
        // `d51b4208  msr NZCV,x8`.
        let flags = shapes(0xd51b_4208);
        assert_eq!(flags.mnemonic, "msr");
        assert!(flags.writes_flags, "{flags:?}");
    }

    /// The interrupt masks encode `op1` as EL0's value and are still privileged, which is the one
    /// carve-out in the rule above -- and the direct counterpart of the `cli`/`sti` that x64
    /// counts as privileged for exactly the same reason.
    ///
    /// **They are one register reached two ways**, as a processor-state field and as a system
    /// register, and only the first was carved out until review found the second: `SCTLR_EL1.UMA`
    /// traps EL0 accesses to `DAIF` in both directions, and this bench's kernel makes 241 of them.
    /// Raised on dbgscope#171.
    #[test]
    fn test_the_interrupt_mask_is_privileged_though_its_field_names_el0() {
        // `d50341df  msr daifset,#1` and `d50342ff  msr daifclr,#2`.
        let mask = shapes(0xd503_41df);
        assert_eq!(mask.mnemonic, "msr");
        assert_eq!(mask.operands[0], Operand::Other("daifset".to_string()));
        assert_eq!(mask.operands[1], Operand::Immediate(1));
        assert!(mask.privileged);
        assert!(shapes(0xd503_42ff).privileged);
        // `d50040bf  msr spsel,#0` -- `op1` zero, so the general rule catches it.
        assert!(shapes(0xd500_40bf).privileged);
        // The same masks as a system register: `d51b4220  msr DAIF,x0` and `d53b4221  mrs x1,DAIF`,
        // both gated and both under EL0's `op1`.
        assert!(shapes(0xd51b_4220).privileged, "msr DAIF");
        assert!(shapes(0xd53b_4221).privileged, "mrs DAIF");
        // `NZCV` is one `op2` away and really is EL0's, in both directions -- which is what makes
        // this a carve-out for a register rather than for the `CRm` it sits in.
        assert!(!shapes(0xd53b_4208).privileged, "mrs NZCV");
        let restore = shapes(0xd51b_4208);
        assert!(!restore.privileged, "msr NZCV");
        assert!(
            restore.writes_flags,
            "and it is the one that sets the flags"
        );
    }

    /// The cache, TLB and address-translation operations are named from the register space they
    /// reach, where that space allocates them, and the operation's own name is left to the
    /// rendering rather than to a table of a hundred rows.
    #[test]
    fn test_the_maintenance_operations_are_named_from_their_register_space() {
        // `d508871f  tlbi VMALLE1`.
        let tlb = shapes(0xd508_871f);
        assert_eq!(tlb.mnemonic, "tlbi");
        assert!(tlb.privileged);
        // `d50b7a29  dc CVAC,x9` -- `op1` three, which **is not EL0's to execute** however much
        // the field suggests it. This assertion read `!clean.privileged` and its comment said "EL0
        // may do it", and EL0 may do it only where `SCTLR_EL1.UCI` says so. There is no
        // unconditionally-EL0 system operation, which is why the arm reads no `op1` at all now.
        let clean = shapes(0xd50b_7a29);
        assert_eq!(clean.mnemonic, "dc");
        assert!(clean.privileged);
        assert_eq!(spellings(&clean.reads), ["x9"]);
        // The rest of the gated set, which the same reasoning reaches and one round at a time
        // would not have: `d50b7b20  dc CVAU,x0` and `d50b7521  ic IVAU,x1` under `SCTLR_EL1.UCI`,
        // and `d50b7420  dc ZVA,x0` under `SCTLR_EL1.DZE`.
        for word in [0xd50b_7b20_u32, 0xd50b_7521, 0xd50b_7420] {
            assert!(shapes(word).privileged, "{word:#010x}");
        }
        // **And the barriers and hints beside them are untouched**, being a different `op0`:
        // `d5033fdf  isb` and `d503201f  nop` really are EL0's.
        assert!(!shapes(0xd503_3fdf).privileged);
        assert!(!shapes(0xd503_201f).privileged);
        // `d508751f  ic IALLU` and `d5087855  at S1E0R,x21`.
        assert_eq!(shapes(0xd508_751f).mnemonic, "ic");
        assert!(shapes(0xd508_751f).privileged);
        assert_eq!(shapes(0xd508_7855).mnemonic, "at");
        // `d50b7388`, which the engine itself renders `sys #3,C7,C3,#4,x8`: `CRn` 7 is not `dc`
        // wholesale, and reading it as one names an operation that is not in that space.
        let generic = shapes(0xd50b_7388);
        assert_eq!(generic.mnemonic, "sys");
        assert_eq!(
            generic.operands[..4],
            [
                Operand::Immediate(3),
                Operand::Other("C7".to_string()),
                Operand::Other("C3".to_string()),
                Operand::Immediate(4),
            ]
        );
    }

    /// Which family a privileged instruction reaches is read off the same fields its privilege
    /// is, and it is `Some` exactly when the instruction is privileged: the builder cannot say one
    /// without the other.
    ///
    /// A system register is a control register unless its encoding says otherwise -- the two
    /// interrupt masks by their full encoding, and the IMPLEMENTATION DEFINED space by `CRn` --
    /// and a processor-state field is the register it is a field of. A system *operation* is
    /// cache or TLB maintenance where its `CRn`/`CRm` name one, and [`Privilege::Other`] where
    /// they name `at` or nothing.
    #[test]
    fn test_a_privileged_instruction_says_which_family_it_reaches() {
        use Privilege::*;
        for (word, text, family) in [
            (0xd518_2025_u32, "msr TTBR1_EL1,x5", Some(ControlRegister)),
            // `op0` two is the debug registers, which are this family's other half on x86 too.
            (0xd510_0240, "msr MDSCR_EL1,x0", Some(ControlRegister)),
            (0xd51b_4220, "msr DAIF,x0", Some(InterruptFlag)),
            (0xd53b_4221, "mrs x1,DAIF", Some(InterruptFlag)),
            (0xd538_4300, "mrs x0,ALLINT", Some(InterruptFlag)),
            (
                0xd538_f200,
                "mrs x0,S3_0_C15_C2_0",
                Some(ModelSpecificRegister),
            ),
            (
                0xd53f_b000,
                "mrs x0,S3_7_C11_C0_0",
                Some(ModelSpecificRegister),
            ),
            // `op1` three is EL0's in the IMPLEMENTATION DEFINED space as everywhere else, so this
            // one needs no privilege and has no family -- the space does not make it a finding.
            (0xd53b_f000, "mrs x0,S3_3_C15_C0_0", None),
            (0xd53b_e04d, "mrs x13,CNTVCT_EL0", None),
            (0xd53b_4208, "mrs x8,NZCV", None),
            (0xd503_41df, "msr daifset,#1", Some(InterruptFlag)),
            (0xd503_42ff, "msr daifclr,#2", Some(InterruptFlag)),
            (0xd501_411f, "msr allint,#1", Some(InterruptFlag)),
            (0xd500_419f, "msr pan,#1", Some(ControlRegister)),
            (0xd500_40bf, "msr spsel,#0", Some(ControlRegister)),
            (0xd508_871f, "tlbi VMALLE1", Some(CacheOrTlb)),
            (0xd508_931f, "tlbi VMALLE1ISnXS", Some(CacheOrTlb)),
            (0xd50b_7e20, "dc CIVAC,x0", Some(CacheOrTlb)),
            (0xd50b_7420, "dc ZVA,x0", Some(CacheOrTlb)),
            (0xd50b_7f01, "dc CIVAOC,x1", Some(CacheOrTlb)),
            (0xd508_751f, "ic IALLU", Some(CacheOrTlb)),
            (0xd508_7855, "at S1E0R,x21", Some(Other)),
            (0xd508_7901, "at S1E1RP,x1", Some(Other)),
            (0xd50b_7388, "sys #3,C7,C3,#4,x8", Some(Other)),
            // Unallocated pairs inside a maintenance cell, which are generic `sys` words and so
            // in no maintenance family: the two dbgscope#192's review named, and the `sysl` the
            // 26100 ARM64 kernel holds in `tlbi`'s `nXS` cell.
            (0xd508_7f00, "sys #0,C7,C15,#0,x0", Some(Other)),
            (0xd508_9000, "sys #0,C9,C0,#0,x0", Some(Other)),
            (0xd52e_954d, "sysl x13,#6,C9,C5,#2", Some(Other)),
            // A `sysl` whose fields *are* an allocated pair -- `tlbi vmalle1`'s -- which is the
            // case only the `load` guard decides: the kernel's word above is unallocated in both
            // forms, so the mask refuses it with or without one.
            (0xd528_8701, "sysl x1,#0,C8,C7,#0", Some(Other)),
            (0xd400_0002, "hvc #0", Some(Virtualization)),
            (0xd400_0003, "smc #0", Some(Virtualization)),
            (0xd400_0001, "svc #0", None),
            (0xd69f_03e0, "eret", Some(Other)),
            (0xd4a0_0001, "dcps1", Some(Other)),
            (0xd503_201f, "nop", None),
        ] {
            let one = shapes(word);
            assert_eq!(one.privilege, family, "`{text}` {word:#010x}: {one:?}");
            assert_eq!(one.privileged, family.is_some(), "`{text}`: {one:?}");
        }
        // The three cells the name match used to miss, whose family comes out of the same arm:
        // `CRn` 9 is `tlbi`'s `nXS` forms, `CRm` 9 is `at`, and `CRm` 15 is `dc`. LLVM disassembles
        // all three that way.
        assert_eq!(shapes(0xd508_931f).mnemonic, "tlbi");
        assert_eq!(shapes(0xd508_7901).mnemonic, "at");
        assert_eq!(shapes(0xd50b_7f01).mnemonic, "dc");
        // And the words beside them that the cells do not allocate keep the generic spelling.
        assert_eq!(shapes(0xd508_7f00).mnemonic, "sys");
        assert_eq!(shapes(0xd508_9000).mnemonic, "sys");
        assert_eq!(shapes(0xd52e_954d).mnemonic, "sysl");
        assert_eq!(shapes(0xd528_8701).mnemonic, "sysl");
    }

    /// Every system-operation encoding in `CRn` 7 to 9, by the name it decodes to: how many, and the
    /// sum of their words. 230 are one of the four maintenance operations and the other 2,842 are
    /// generic `sys`, and both figures per name are what LLVM's disassembly of the same 3,072
    /// encodings gives -- computed from that output, not from [`maintenance`]'s masks, so a bit
    /// added to, lost from or moved within any mask fails here.
    #[test]
    fn test_only_allocated_maintenance_encodings_are_named() {
        let mut named: std::collections::BTreeMap<String, (u32, u64)> = Default::default();
        for crn in 0b0111..=0b1001_u32 {
            for crm in 0..16_u32 {
                for op1 in 0..8_u32 {
                    for op2 in 0..8_u32 {
                        let word =
                            0xd508_001f | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5);
                        let entry = named.entry(shapes(word).mnemonic).or_default();
                        entry.0 += 1;
                        entry.1 += u64::from(word);
                    }
                }
            }
        }
        assert_eq!(
            named,
            std::collections::BTreeMap::from([
                ("at".to_string(), (17, 60_762_751_919)),
                ("dc".to_string(), (40, 142_969_748_920)),
                ("ic".to_string(), (3, 10_722_499_453)),
                ("sys".to_string(), (2_842, 10_158_271_623_430)),
                ("tlbi".to_string(), (170, 607_632_041_494)),
            ])
        );
    }

    /// A pointer-authentication hint writes the link register and names nothing at all, which is
    /// the reason the hint space is a table rather than a mnemonic: `pacibsp` is the second
    /// instruction of nearly every function in this image.
    #[test]
    fn test_a_pointer_authentication_hint_writes_the_link_register() {
        // `d503237f  pacibsp` and `d50323ff  autibsp`.
        let sign = shapes(0xd503_237f);
        assert_eq!(sign.mnemonic, "pacibsp");
        assert!(sign.operands.is_empty(), "{sign:?}");
        assert_eq!(spellings(&sign.writes), ["lr"]);
        assert_eq!(spellings(&sign.reads), ["lr", "sp"]);
        assert_eq!(shapes(0xd503_23ff).mnemonic, "autibsp");
        // `d50320ff  xpaclri` -- the link register again, and no stack pointer.
        let strip = shapes(0xd503_20ff);
        assert_eq!(strip.mnemonic, "xpaclri");
        assert_eq!(spellings(&strip.reads), ["lr"]);
        // `d503211f  pacia1716` reaches `x17` and `x16` instead.
        let scratch = shapes(0xd503_211f);
        assert_eq!(scratch.mnemonic, "pacia1716");
        assert_eq!(spellings(&scratch.writes), ["xip1"]);
        assert_eq!(spellings(&scratch.reads), ["xip1", "xip0"]);
        // `d503201f  nop` and `d503203f  yield` touch nothing.
        assert_eq!(shapes(0xd503_201f).mnemonic, "nop");
        assert!(shapes(0xd503_203f).writes.is_empty());
    }

    /// A barrier's domain is a named operand kind, which is what [`Operand::Other`] is for.
    #[test]
    fn test_a_barrier_names_its_domain() {
        // `d5033abf  dmb ishst`, `d5033f9f  dsb sy`, `d5033fdf  isb sy`.
        let barrier = shapes(0xd503_3abf);
        assert_eq!(barrier.mnemonic, "dmb");
        assert_eq!(barrier.operands, [Operand::Other("ishst".to_string())]);
        assert!(!barrier.privileged, "a barrier needs no privilege");
        assert_eq!(shapes(0xd503_3f9f).mnemonic, "dsb");
        assert_eq!(shapes(0xd503_3fdf).mnemonic, "isb");
    }

    /// The vector space is decoded exactly as far as the boundary with the rest of the machine:
    /// what writes a general-purpose register or the flags is read, and the rest names itself.
    #[test]
    fn test_the_vector_boundary_is_decoded_and_the_rest_names_itself() {
        // `1e260043  fmov w3,s2` -- a general-purpose register a value-tracking pass must see
        // change.
        let from_float = shapes(0x1e26_0043);
        assert_eq!(from_float.mnemonic, "fmov");
        assert_eq!(spellings(&from_float.writes), ["x3"]);
        assert_eq!(spellings(&from_float.reads), ["s2"]);
        // `4e183e28  umov x8,v17.d[1]` -- the lane is named, the register is not.
        let extract = shapes(0x4e18_3e28);
        assert_eq!(extract.mnemonic, "umov");
        assert_eq!(spellings(&extract.writes), ["x8"]);
        assert_eq!(extract.operands[1], Operand::Other("v17.d[1]".to_string()));
        // `4e081d10  ins v16.d[0],x8` -- the other direction, and an insert keeps the lanes it
        // does not write.
        let insert = shapes(0x4e08_1d10);
        assert_eq!(insert.mnemonic, "ins");
        assert_eq!(spellings(&insert.reads), ["x8", "v16"]);
        assert_eq!(spellings(&insert.writes), ["v16"]);
        // `1e212000  fcmp s0,s1` -- **the flags**, which is the case where leaving this unread
        // sends a consumer looking for the compare a `b.eq` reads past this instruction and back
        // to an integer one that did not set them.
        let compare = shapes(0x1e21_2000);
        assert_eq!(compare.mnemonic, "fcmp");
        assert!(compare.writes_flags);
        // `6f00e402  movi v2.2d,#0` -- vector state only, and it says which space it came from.
        let vector = shapes(0x6f00_e402);
        assert_eq!(
            vector.operands,
            [Operand::Undecoded("advanced-simd".to_string())]
        );
        assert!(
            vector.mnemonic.is_empty(),
            "the rendering's token is better"
        );
        assert!(vector.writes.is_empty());
        // `a5e0a01f  ld1d {z31.d},p0/z,[x0]`, and a reserved word from the same image.
        assert_eq!(
            shapes(0xa5e0_a01f).operands,
            [Operand::Undecoded("sve".to_string())]
        );
        // **Not the zero word**, which this line used to use and which is `udf #0` -- as the
        // comment above it said while the assertion beneath said otherwise. The reserved *space*
        // is still unread and is what belongs here;
        // `test_the_reserved_spaces_one_allocated_member_is_decoded` has both halves.
        assert_eq!(
            shapes(0x8000_0005).operands,
            [Operand::Undecoded("reserved".to_string())]
        );
    }

    /// A write is recorded at the **whole** register and the zero register is not recorded at all.
    ///
    /// Both are about the one question [`crate::dbgeng::Instruction::writes`] answers -- which
    /// register stopped holding what it did. A 32-bit write zeroes the upper half, so `mov w22,#0`
    /// leaves nothing of `x22`; a write to `xzr` is discarded, so nothing changed.
    #[test]
    fn test_a_write_reaches_the_whole_register_and_the_zero_register_holds_nothing() {
        // `d2800016  mov x22,#0` and `52800016  mov w22,#0`.
        let wide = shapes(0xd280_0016);
        let narrow = shapes(0x5280_0016);
        assert_eq!(spellings(&wide.writes), ["x22"]);
        assert_eq!(spellings(&narrow.writes), ["x22"]);
        assert_eq!(narrow.writes[0].width, 8);
        assert_eq!(
            narrow.operands[0],
            register("w22", "x22", 4),
            "the operand keeps the spelling it was written with"
        );
        // `ea1f018c  ands x12,x12,xzr` -- the zero register is an operand and is not a read.
        let masked = shapes(0xea1f_018c);
        assert_eq!(masked.operands[2], register("xzr", "xzr", 8));
        assert_eq!(spellings(&masked.reads), ["x12"]);
        // `79005fff  strh wzr,[sp,#0x2E]` -- nor is it a source worth recording.
        let store = shapes(0x7900_5fff);
        assert_eq!(spellings(&store.reads), ["sp"]);
        assert!(store.writes.is_empty());
    }

    /// The register spellings are the debugger's, which is what lets a rendering and a field name
    /// one register one way.
    #[test]
    fn test_the_register_spellings_are_the_engine_s() {
        // `f9452610  ldr xip0,[xip0,#0xA48]` -- `x16`, which WinDbg prints as an
        // intra-procedure-call scratch register.
        let scratch = shapes(0xf945_2610);
        assert_eq!(scratch.operands[0], register("xip0", "xip0", 8));
        // `d518d092  msr TPIDR_EL1,xpr` -- `x18`, Windows' reserved platform register.
        assert_eq!(shapes(0xd518_d092).operands[1], register("xpr", "xpr", 8));
        // `31706e50  adds wip0,wpr,#0xC1B,lsl #0xC` -- the 32-bit views of both.
        let narrow = shapes(0x3170_6e50);
        assert_eq!(narrow.operands[0], register("wip0", "xip0", 4));
        assert_eq!(narrow.operands[1], register("wpr", "xpr", 4));
        // `910003fd  mov fp,sp` -- the frame pointer and the stack pointer, and an `add` of zero
        // between them is the `mov` the engine prints.
        let frame = shapes(0x9100_03fd);
        assert_eq!(frame.mnemonic, "mov");
        assert_eq!(frame.effect, Effect::Move);
        assert_eq!(frame.operands[0], register("fp", "fp", 8));
        assert_eq!(frame.operands[1], register("sp", "sp", 8));
    }

    /// `tbz`'s `b5` is the bit number's top bit **and** the operand's width, and those agree: a
    /// bit at 32 or above needs a 64-bit register to be in.
    ///
    /// An earlier round argued it could not be both and named the register at 64 bits throughout,
    /// on the strength of this engine printing `x` for all 23,448 of them. The engine is the
    /// outlier -- the architecture's syntax and a second disassembler both name `w` for the clear
    /// half -- and the encoding is what this decodes. Raised on dbgscope#171.
    #[test]
    fn test_a_test_and_branch_takes_its_width_from_the_bit_number() {
        // `fffff802e9ef919c  36800208  tbz x8,#0x10,nt!PsSessionGetWin32Callouts+0x4c` -- `b5`
        // clear, so the architecture names a `w` register where this engine prints an `x`. The
        // two are one register, which [`RegisterOperand::full`] is what says.
        let low = decode(0x3680_0208, 0xfffff802_e9ef919c);
        assert_eq!(low.mnemonic, "tbz");
        assert_eq!(low.operands[0], register("w8", "x8", 4));
        assert_eq!(low.operands[1], Operand::Immediate(16));
        assert_eq!(low.flow, Flow::Branch(Some(0xfffff802_e9ef91dc)));
        // `b6f80148  tbz x8,#0x3F,...` -- `b5` set, so the bit number is above 31 and so is the
        // operand's width. The two halves of that field agree, which is why one bit can be both.
        let high = shapes(0xb6f8_0148);
        assert_eq!(high.operands[0], register("x8", "x8", 8));
        assert_eq!(high.operands[1], Operand::Immediate(0x3f));
        // `fffff802ea3773f0  b4000293  cbz x19,nt!EtwpDestructIptData+0x68`.
        let compare = decode(0xb400_0293, 0xfffff802_ea3773f0);
        assert_eq!(compare.mnemonic, "cbz");
        assert_eq!(compare.operands[0], register("x19", "x19", 8));
        assert_eq!(spellings(&compare.reads), ["x19"]);
        // `3500128` at 32 bits names a `w` register, `sf` there being a width and not a bit.
        // `fffff802ea69dc80  35000128  cbnz w8,nt!KiSystemStartup+0xe4`.
        assert_eq!(
            decode(0x3500_0128, 0xfffff802_ea69dc80).operands[0],
            register("w8", "x8", 4)
        );
    }

    /// An encoding the architecture does not allocate is not shaped, and says so rather than
    /// coming back as an instruction with no operands.
    #[test]
    fn test_an_unallocated_encoding_names_itself() {
        // A logical immediate whose `imms` is all ones within its element, which the encoding
        // reserves.
        assert_eq!(
            shapes(0x1200_fc00).operands,
            [Operand::Undecoded("unallocated".to_string())]
        );
        // A move-wide with `opc` 01, which is unallocated, and a 32-bit one whose `hw` asks for
        // a shift of 32 -- the field is two bits and only the 64-bit forms may use both.
        assert_eq!(
            shapes(0x3280_0000).operands,
            [Operand::Undecoded("unallocated".to_string())]
        );
        assert_eq!(
            shapes(0x52c0_0000).operands,
            [Operand::Undecoded("unallocated".to_string())]
        );
    }

    /// An authenticated branch spells its key **after** the `a`, and the `b`-key forms are the
    /// half a corpus of Windows kernel code cannot check: it signs with `pacibsp` and returns with
    /// a plain `ret`, so not one `brab` or `retab` occurs in the image this decoder was measured
    /// on. Raised on dbgscope#171.
    #[test]
    fn test_an_authenticated_branch_spells_its_key_after_the_a() {
        // `d71f0843  braa x2,x3` and `d71f0c43  brab x2,x3` -- the modifier register is a read of
        // its own, being what the pointer is authenticated against.
        let a_key = shapes(0xd71f_0843);
        assert_eq!(a_key.mnemonic, "braa");
        assert_eq!(spellings(&a_key.reads), ["x2", "x3"]);
        let b_key = shapes(0xd71f_0c43);
        assert_eq!(b_key.mnemonic, "brab", "not `brba`: {b_key:?}");
        assert_eq!(b_key.flow, Flow::Jmp(None));
        // The zero-modifier forms, which take no second register -- and therefore fix `op4` at
        // `11111` rather than leaving it free. **This line used to read `0xd61f_0840`**, which is
        // not an encoding: it was accepted only because nothing checked the field, and the
        // generated table calls it unallocated. `test_an_addressing_mode_constrains_which_
        // transfers_it_allows` is where that now fails.
        assert_eq!(shapes(0xd61f_085f).mnemonic, "braaz");
        assert_eq!(shapes(0xd61f_0c5f).mnemonic, "brabz");
        // And the same through the three other opcodes in the class.
        let call = shapes(0xd73f_0c43);
        assert_eq!(call.mnemonic, "blrab");
        assert_eq!(spellings(&call.writes), ["lr"]);
        assert_eq!(shapes(0xd63f_085f).mnemonic, "blraaz");
        assert_eq!(shapes(0xd65f_0bff).mnemonic, "retaa");
        assert_eq!(shapes(0xd65f_0fff).mnemonic, "retab");
        assert_eq!(shapes(0xd69f_0fff).mnemonic, "eretab");
        assert!(shapes(0xd69f_0fff).privileged);
        // An authenticated exception return reads the stack pointer it authenticates against,
        // exactly as `retaa` does, and a plain `eret` reads nothing.
        assert_eq!(spellings(&shapes(0xd69f_0bff).reads), ["sp"]);
        assert!(shapes(0xd69f_03e0).reads.is_empty());
    }

    /// `op1` decides privilege everywhere but the processor-state fields, where zero holds both
    /// exception levels: `uao`, `pan` and `spsel` are EL1, and the three FlagM instructions beside
    /// them reach `NZCV` and nothing else.
    ///
    /// Reporting the second three as privileged puts a compiler's own flag manipulation in a
    /// driver hazard report, which is the field's whole consumer. Raised on dbgscope#171.
    #[test]
    fn test_the_flag_manipulation_fields_are_not_privileged() {
        // `d500401f  cfinv`, `d500403f  xaflag`, `d500405f  axflag` -- standalone instructions
        // rather than fields, which the engine confirms by rendering `cfinv` for the first.
        for (word, mnemonic) in [
            (0xd500_401f_u32, "cfinv"),
            (0xd500_403f, "xaflag"),
            (0xd500_405f, "axflag"),
        ] {
            let flags = shapes(word);
            assert_eq!(flags.mnemonic, mnemonic);
            assert!(
                flags.operands.is_empty(),
                "{mnemonic} takes none: {flags:?}"
            );
            assert!(!flags.privileged, "{word:#010x} is EL0: {flags:?}");
            assert!(flags.writes_flags, "{word:#010x}: {flags:?}");
        }
        // Their `CRm` is reserved rather than an immediate: `d5004c1f` is not a `cfinv`.
        assert_eq!(
            shapes(0xd500_4c1f).operands,
            [Operand::Undecoded("unallocated".to_string())]
        );
        // Their neighbours under the same `op1` are EL1, and so are the interrupt masks under the
        // `op1` that otherwise names EL0.
        for (word, field) in [
            (0xd500_407f_u32, "uao"),
            (0xd500_409f, "pan"),
            (0xd500_40bf, "spsel"),
            (0xd503_41df, "daifset"),
            (0xd503_42ff, "daifclr"),
        ] {
            let one = shapes(word);
            assert_eq!(one.operands[0], Operand::Other(field.to_string()));
            assert!(one.privileged, "{field} is EL1: {one:?}");
        }
        // And the EL0 fields under `op1` three stay unprivileged: `d503403f  msr dit,#1` is
        // `op1` 011, `op2` 010.
        assert!(!shapes(0xd503_405f).privileged);
    }

    /// A vector structure access's post-index register is **not part of the address**: the access
    /// happens at the base and the register is what moves it afterwards, so reporting it as the
    /// memory operand's index describes an address the instruction never forms.
    ///
    /// And a load that fills one lane reads the register it fills, the other lanes surviving it —
    /// which the replicate forms, writing every lane, do not. Both raised on or found beside
    /// dbgscope#171.
    #[test]
    fn test_a_vector_structure_access_keeps_its_post_index_register_out_of_the_address() {
        // `4dcaefb2  ld3r {v18.2d,v19.2d,v20.2d},[fp], x10`.
        let replicate = shapes(0x4dca_efb2);
        assert_eq!(replicate.mnemonic, "ld3r");
        let Operand::Memory(memory) = &replicate.operands[1] else {
            panic!("{replicate:?}");
        };
        assert_eq!(memory.index, None, "the access is at the base alone");
        assert_eq!(memory.base.as_deref(), Some("fp"));
        assert_eq!(replicate.operands[2], register("x10", "x10", 8));
        assert_eq!(spellings(&replicate.writes), ["v18", "v19", "v20", "fp"]);
        assert_eq!(spellings(&replicate.reads), ["fp", "x10"]);
        // `0dff0020  ld2 {v0.b,v1.b}[0],[x1],#2` -- one lane each, so both registers survive in
        // part and are reads as well as writes.
        let lanes = shapes(0x0dff_0020);
        assert_eq!(lanes.mnemonic, "ld2");
        assert_eq!(spellings(&lanes.writes), ["v0", "v1", "x1"]);
        assert_eq!(spellings(&lanes.reads), ["v0", "v1", "x1"]);
        // `4d40c110  ld1r {v16.16b},[x8]` -- every lane written, and no writeback.
        let whole = shapes(0x4d40_c110);
        assert_eq!(whole.mnemonic, "ld1r");
        assert_eq!(spellings(&whole.writes), ["v16"]);
        assert_eq!(spellings(&whole.reads), ["x8"]);
        // **Without a post-index the `Rm` field is reserved**, and an extension has been carved
        // out of it: `0d018774` and `0d418774` are RCPC3's `stl1` and `ldap1`, which this does not
        // decode. Reading the field as absent shaped them as ordinary `st1`/`ld1` and lost the
        // ordering that is the whole point of them.
        for word in [0x0d01_8774_u32, 0x0d41_8774] {
            assert_eq!(
                shapes(word).operands,
                [Operand::Undecoded("unallocated".to_string())],
                "{word:#010x}"
            );
        }
        // The legacy forms have it zero, which is why every one above still decodes.
        assert_eq!(shapes(0x0d00_2140).mnemonic, "st3");
        // **An immediate post-index still moves the base, and by how much is computable** from how
        // many registers are named and how wide each transfer is. Every amount below is the one
        // the engine prints for the same word.
        let amount = |word: u32| match shapes(word).operands.last() {
            Some(Operand::Other(text)) => text.clone(),
            other => panic!("{word:#010x}: {other:?}"),
        };
        assert_eq!(amount(0x0dff_0020), "#0x2", "ld2 of one byte each");
        assert_eq!(
            amount(0x0cdf_7020),
            "#0x8",
            "ld1 of one eight-byte register"
        );
        assert_eq!(
            amount(0x4cdf_2020),
            "#0x40",
            "ld1 of four sixteen-byte registers"
        );
        assert_eq!(
            amount(0x0d9f_8020),
            "#0x4",
            "st1 of one single-precision lane"
        );
    }

    /// **The width of a vector-structure access is the one thing its register list does not say**,
    /// and this decoder was computing it for the post-index amount above while reporting `None` on
    /// the memory operand beside it. A caller bounding a read or a write therefore lost the range
    /// for precisely the family whose transfer size cannot be inferred from the mnemonic.
    ///
    /// Every word below is one the engine rendered in the 26100 kernel, and the post-indexed ones
    /// pin the arithmetic against the amount the engine itself prints. Raised on dbgscope#171.
    #[test]
    fn test_a_vector_structure_access_reports_how_much_it_transfers() {
        let transferred = |word: u32| {
            let shaped = shapes(word);
            let memory = shaped.operands.iter().find_map(|operand| match operand {
                Operand::Memory(memory) => Some(memory.clone()),
                _ => None,
            });
            memory
                .unwrap_or_else(|| panic!("{word:#010x}: {shaped:?}"))
                .size
        };
        // Multiple structures: registers named, times the bytes each holds.
        // `4c402020  ld1 {v0.16b,v1.16b,v2.16b,v3.16b},[x1]`.
        assert_eq!(transferred(0x4c40_2020), Some(64));
        // `0c407020  ld1 {v0.8b},[x1]` -- a half-width register is half the transfer.
        assert_eq!(transferred(0x0c40_7020), Some(8));
        // `4c40a020  ld1 {v0.16b,v1.16b},[x1]`.
        assert_eq!(transferred(0x4c40_a020), Some(32));
        // A single structure moves one element per register, whatever the registers hold.
        // `0dff0020  ld2 {v0.b,v1.b}[0],[x1],#2`, whose own post-index amount is 2.
        assert_eq!(transferred(0x0dff_0020), Some(2));
        // `4d207972  st4 {v18.h,v19.h,v20.h,v21.h}[7],[x11]` -- four halfwords.
        assert_eq!(transferred(0x4d20_7972), Some(8));
        // **The replicate forms are the case that separates the transfer from the registers**, and
        // a size read off the register list would get exactly these wrong: `4d40c110
        // ld1r {v16.16b},[x8]` fills all sixteen bytes of `v16` from **one** byte of memory.
        assert_eq!(transferred(0x4d40_c110), Some(1));
        assert_eq!(spellings(&shapes(0x4d40_c110).writes), ["v16"]);
        // `4dcaefb2  ld3r {v18.2d,v19.2d,v20.2d},[fp], x10` -- three doublewords read, 48 bytes
        // written.
        assert_eq!(transferred(0x4dca_efb2), Some(24));
    }

    /// The three positions that report no access width, pinned against the ones that do.
    ///
    /// The module header states this as a closed list, and a closed list is only worth stating if
    /// something fails when it stops being true. Each row is a different reason rather than an
    /// omission, and two of the three were review findings on dbgscope#171 — the third would have
    /// been, which is why the audit was done in one pass rather than waited out.
    #[test]
    fn test_an_access_reports_its_width_unless_it_genuinely_has_none() {
        let width = |word: u32| {
            let shaped = shapes(word);
            let sizes: Vec<_> = shaped
                .operands
                .iter()
                .filter_map(|operand| match operand {
                    Operand::Memory(memory) => Some(memory.size),
                    _ => None,
                })
                .collect();
            assert!(!sizes.is_empty(), "{word:#010x}: {shaped:?}");
            sizes
        };
        // `f000187e  adrp lr,nt!...` -- an address is computed and nothing reads it.
        assert_eq!(width(0xf000_187e), [None]);
        assert_eq!(shapes(0xf000_187e).effect, Effect::LoadAddress);
        // `f9800021  prfm PLDL1STRM,[x1]` -- the encoding's `size` scales the offset and no
        // architectural width is moved.
        assert_eq!(width(0xf980_0021), [None]);
        // `19410440  cpyfm` -- both pointers are memory operands and the amount is `Xn`'s value.
        assert_eq!(width(0x1941_0440), [None, None]);
        // `d9a00000  stgm` -- as many granules as `GMID_EL1.BS` says.
        assert_eq!(width(0xd9a0_0000), [None]);
        // **Its neighbours are not in that row**, which is the distinction the flag behind it used
        // to lose: `d9600020  ldg x0,[x1]` reads one granule and `d9a00020`'s `st2g` reaches two.
        assert_eq!(width(0xd960_0020), [Some(16)]);
        assert_eq!(shapes(0xd960_0020).mnemonic, "ldg");
        assert_eq!(width(0xd9e0_0420), [Some(32)]);
        assert_eq!(shapes(0xd9e0_0420).mnemonic, "stz2g");
        // And the widths that *are* encoded, including the two that are arithmetic rather than a
        // field. `a9427bfd  ldp fp,lr,[sp,#0x20]` moves two eight-byte registers...
        assert_eq!(width(0xa942_7bfd), [Some(16)]);
        // ...and `4c40a020  ld1 {v0.16b,v1.16b},[x1]` moves two sixteen-byte ones.
        assert_eq!(width(0x4c40_a020), [Some(32)]);
        // A plain load is the ordinary case the other two are measured against.
        assert_eq!(width(0xf940_0021), [Some(8)]);
    }

    /// The barrier options, where one shared table was answering for three different fields.
    ///
    /// `isb`'s `CRm` is an option and not a shareability domain, so `d50337df` -- `isb #7` -- was
    /// being spelled `isb nsh` with a name from `dsb`'s table. And `dsb`'s own `CRm` zero and four
    /// are whole instructions rather than numbered forms. Raised on dbgscope#171.
    #[test]
    fn test_a_barrier_option_is_read_from_its_own_field() {
        // `d5033fdf  isb sy` -- the one option the architecture defines, and the engine's own
        // spelling of it.
        let sync = shapes(0xd503_3fdf);
        assert_eq!(sync.mnemonic, "isb");
        assert_eq!(sync.operands, [Operand::Other("sy".to_string())]);
        // **Every other value is a number, not a domain.** This is the assertion that fails
        // against the shared table.
        let numbered = shapes(0xd503_37df);
        assert_eq!(numbered.mnemonic, "isb");
        assert_eq!(numbered.operands, [Operand::Immediate(7)]);
        // The speculative-store-bypass barriers, which take no operand at all.
        for (word, mnemonic) in [(0xd503_309f_u32, "ssbb"), (0xd503_349f, "pssbb")] {
            let barrier = shapes(word);
            assert_eq!(barrier.mnemonic, mnemonic, "{word:#010x}");
            assert!(barrier.operands.is_empty(), "{barrier:?}");
        }
        // **And the domains `dsb` and `dmb` really do take are untouched**, which is what says the
        // split was a split rather than a deletion: `d5033f9f  dsb sy` and `d5033bbf  dmb ish`.
        assert_eq!(shapes(0xd503_3f9f).mnemonic, "dsb");
        assert_eq!(
            shapes(0xd503_3f9f).operands,
            [Operand::Other("sy".to_string())]
        );
        assert_eq!(
            shapes(0xd503_3bbf).operands,
            [Operand::Other("ish".to_string())]
        );
    }

    /// A register pair names its even half, and an odd one is not a pair of a register with itself.
    ///
    /// `casp` supplies the second register of each pair by adding one, which `rs | 1` does only
    /// where `rs` is even -- `0x482b7c0c` came back as `casp x11,x11,x12,x13,[x0]`. The generated
    /// table renders that operand `<undefined>`, the architecture making an odd field CONSTRAINED
    /// UNPREDICTABLE, so there is nothing to read and [`Operand::Undecoded`] says exactly that.
    /// Raised on dbgscope#171.
    #[test]
    fn test_a_compare_and_swap_pair_refuses_an_odd_register() {
        // `482a7c0c  casp x10,x11,x12,x13,[x0]` -- both fields even, and the successors supplied.
        let pair = shapes(0x482a_7c0c);
        assert_eq!(pair.mnemonic, "casp");
        assert_eq!(spellings(&pair.writes), ["x10", "x11"]);
        assert_eq!(spellings(&pair.reads), ["x10", "x11", "x12", "x13", "x0"]);
        // **Both fields, not just the first.** An odd `Rs` and an odd `Rt` are separate encodings
        // and a check of one would pass the other.
        for word in [0x482b_7c0c_u32, 0x482a_7c0d] {
            assert_eq!(
                shapes(word).operands,
                [Operand::Undecoded("unallocated".to_string())],
                "{word:#010x}"
            );
        }
    }

    /// A register-branch form fixes every field it does not use, and nothing enforced it.
    ///
    /// The comment in [`branch_register`] has stated this rule since it was written, which is the
    /// same shape as the `udf` finding two rounds earlier: the prose knew and the code did not.
    /// `0xd61f0001` came back as `br x0`, and an authenticated return with a stray `Rn` reported
    /// reads of the link register and the stack pointer that its word does not name -- both of
    /// them complete answers where [`Operand::Undecoded`] is the honest one, which matters when
    /// `decode_range` walks data. Raised on dbgscope#171, and every expectation below is the
    /// generated table's own reading of the same word.
    #[test]
    fn test_a_branch_form_fixes_the_fields_it_does_not_use() {
        let unallocated = |word: u32| {
            assert_eq!(
                shapes(word).operands,
                [Operand::Undecoded("unallocated".to_string())],
                "{word:#010x}"
            );
        };
        // `br`/`blr`/`ret` fix `op4` at zero and leave `Rn` free.
        assert_eq!(shapes(0xd61f_0000).mnemonic, "br");
        unallocated(0xd61f_0001);
        // The zero-modifier authenticated forms fix it at `11111` instead -- the opposite value,
        // so a single check of "is it zero" would have passed half of these and failed the rest.
        assert_eq!(shapes(0xd61f_085f).mnemonic, "braaz");
        unallocated(0xd61f_0840);
        // `retaa` names neither register, so both are fixed.
        assert_eq!(shapes(0xd65f_0bff).mnemonic, "retaa");
        unallocated(0xd65f_0801);
        // `eret` names nothing at all, and its `Rn` is fixed even in the plain form.
        assert_eq!(shapes(0xd69f_03e0).mnemonic, "eret");
        unallocated(0xd69f_0000);
        // `drps` has **no** authenticated form, which the key match alone let through: `op3` two
        // spelled it `drps` rather than refusing it.
        assert_eq!(shapes(0xd6bf_03e0).mnemonic, "drps");
        unallocated(0xd6bf_0be0);
        // **And the modifier forms still take a register there**, which is the half that says
        // these guards are narrow: `d71f0843  braa x2,x3`.
        let modifier = shapes(0xd71f_0843);
        assert_eq!(modifier.mnemonic, "braa");
        assert_eq!(spellings(&modifier.reads), ["x2", "x3"]);
        // **A modifier form with no key is not a `br`**, though the arm that spells these answers
        // for the key and would have called it one while still reading `op4` as a register.
        // `0xd71f0000` was `br x0` reading `x0` twice; there is no unauthenticated form here.
        unallocated(0xd71f_0000);
        unallocated(0xd73f_0000);
    }

    /// The encodings the access-width audit found shaped here and unallocated in the architecture,
    /// plus the one it found refused here and allocated there.
    ///
    /// All four are the same root: a table keyed on the *shape of the transfer* consulted from a
    /// context that also constrains which shapes exist. `access_of` has no addressing mode and
    /// `memory_tags` read `op2` as though it answered a question it does not. Each was settled
    /// against the generated table rather than a recalled one, this branch having already been
    /// wrong once from memory about an ARM table.
    #[test]
    fn test_an_addressing_mode_constrains_which_transfers_it_allows() {
        let unallocated = |word: u32| {
            assert_eq!(
                shapes(word).operands,
                [Operand::Undecoded("unallocated".to_string())],
                "{word:#010x}"
            );
        };
        // A prefetch exists only unscaled. `f8800000` is `prfum` and is kept; the post-indexed,
        // pre-indexed and unprivileged rows of the same slot are not encodings.
        assert_eq!(shapes(0xf880_0000).mnemonic, "prfum");
        unallocated(0xf880_0400);
        unallocated(0xf880_0800);
        unallocated(0xf880_0c00);
        // The unprivileged mode is general-purpose only, so the vector rows go too -- these were
        // `sttr b0,[x0]` and `ldtr b0,[x0]`.
        unallocated(0x3c00_0800);
        unallocated(0x3c40_0800);
        // **And the neighbours each of those sat beside still decode**, which is the half that
        // says the guards are narrow rather than merely quiet.
        assert_eq!(shapes(0x3c00_0000).mnemonic, "stur");
        assert_eq!(shapes(0xf800_0800).mnemonic, "sttr");
        assert_eq!(shapes(0xf840_0800).mnemonic, "ldtr");
        assert_eq!(shapes(0xb880_0800).mnemonic, "ldtrsw");
        // The other direction: `ldg` takes a displacement, and every nonzero one was refused.
        // `d960f020  ldg x0,[x1,#240]` -- the generated table's own rendering.
        for word in [0xd960_0020_u32, 0xd960_1020, 0xd960_f020] {
            assert_eq!(shapes(word).mnemonic, "ldg", "{word:#010x}");
        }
        let Operand::Memory(memory) = &shapes(0xd960_f020).operands[1] else {
            panic!("{:?}", shapes(0xd960_f020));
        };
        assert_eq!(memory.displacement, 240);
        // The whole-granule forms beside it genuinely take none, and that guard is unchanged.
        assert_eq!(shapes(0xd9a0_0020).mnemonic, "stgm");
        unallocated(0xd9a0_1020);
    }

    /// The **Reserved** top-level space has one allocated member, `udf #imm16`, and reporting it as
    /// unread claimed this decoder had not read a word whose meaning was the one certain thing
    /// about it -- [`super::flow`] already stops on it. The engine renders the whole space `???`,
    /// so nothing in the corpus check could have caught this; it took the standalone
    /// `decode_instruction`, where there is no rendering to borrow a mnemonic from, to make it
    /// visible. Raised on dbgscope#171.
    #[test]
    fn test_the_reserved_spaces_one_allocated_member_is_decoded() {
        let trap = shapes(0x0000_1234);
        assert_eq!(trap.mnemonic, "udf");
        assert_eq!(trap.operands, [Operand::Immediate(0x1234)]);
        assert_eq!(trap.flow, Flow::Trap);
        // Inter-function padding, which is 25,157 words of that kernel's `.text` and `PAGE`.
        let padding = shapes(0x0000_0000);
        assert_eq!(padding.mnemonic, "udf");
        assert_eq!(padding.operands, [Operand::Immediate(0)]);
        // **And the rest of the space stays unread**, which is the half that keeps the claim
        // honest: `udf` is `0x0000_0000` through `0x0000_ffff` and nothing above it. `80000005`
        // is a real word from the same image -- data the engine also rendered `???`.
        let reserved = shapes(0x8000_0005);
        assert_eq!(reserved.mnemonic, "");
        assert_eq!(
            reserved.operands,
            [Operand::Undecoded("reserved".to_string())]
        );
        // Either way the space traps, and that was already true before it was named.
        assert_eq!(reserved.flow, Flow::Trap);
    }

    /// The two halves of the vector boundary a name on an operand hides: an upper-lane `fmov`
    /// still reaches the register its lane belongs to, and `fjcvtzs` is the one conversion that
    /// reports on itself in the flags.
    ///
    /// Both are the case where leaving a field unread is worse than leaving an operand unshaped:
    /// a consumer asking what set the flags a `b.eq` reads, or what a `fmov` left changed, gets a
    /// wrong answer rather than no answer. Raised on and found beside dbgscope#171.
    #[test]
    fn test_the_upper_lane_moves_and_the_javascript_conversion_reach_what_they_name() {
        // `9eae0020  fmov x0,v1.d[1]`.
        let out_of = shapes(0x9eae_0020);
        assert_eq!(out_of.mnemonic, "fmov");
        assert_eq!(spellings(&out_of.writes), ["x0"]);
        assert_eq!(spellings(&out_of.reads), ["v1"]);
        // `9eaf0062  fmov v2.d[1],x3` -- the low half survives, so the destination is a read too.
        let into = shapes(0x9eaf_0062);
        assert_eq!(spellings(&into.writes), ["v2"]);
        assert_eq!(spellings(&into.reads), ["x3", "v2"]);
        // `1e7e0000  fjcvtzs w0,d0`.
        let javascript = shapes(0x1e7e_0000);
        assert_eq!(javascript.mnemonic, "fjcvtzs");
        assert!(javascript.writes_flags, "{javascript:?}");
        assert_eq!(spellings(&javascript.writes), ["x0"]);
        // The conversions beside it do not touch the flags.
        assert!(!shapes(0x1e18_0000).writes_flags, "fcvtzs");
    }

    /// The memory-tagging and unscaled-acquire families, which sat behind one decline until a
    /// second review round landed on the same seam as the first. Raised on dbgscope#171.
    ///
    /// **`ldg` reads the register it writes**, which is the member of the family a first-operand
    /// rule gets wrong: the tag it loads is inserted into what `Xt` already holds rather than
    /// replacing it, so the address in that register survives the load.
    #[test]
    fn test_the_tagging_and_acquiring_accesses_are_shaped() {
        // `d9600128  ldg x8,[x9]`.
        let tag = shapes(0xd960_0128);
        assert_eq!(tag.mnemonic, "ldg");
        assert_eq!(spellings(&tag.writes), ["x8"]);
        assert_eq!(
            spellings(&tag.reads),
            ["x8", "x9"],
            "the address survives: {tag:?}"
        );
        // `d9201462  stg x2,[x3],#16` -- post-indexed, so the access is at the base and the amount
        // is named, and the granule scale is sixteen rather than one.
        let store = shapes(0xd920_1462);
        assert_eq!(store.mnemonic, "stg");
        assert_eq!(store.operands[2], Operand::Other("#0x10".to_string()));
        assert_eq!(spellings(&store.writes), ["x3"]);
        assert_eq!(spellings(&store.reads), ["x2", "x3"]);
        let Operand::Memory(memory) = &store.operands[1] else {
            panic!("{store:?}");
        };
        assert_eq!(memory.displacement, 0);
        // `d9a00128  stgm x8,[x9]` -- a whole-granule form, which takes no index mode.
        assert_eq!(shapes(0xd9a0_0128).mnemonic, "stgm");
        // `199b7088  ldapursb x8,[x4,#-0x49]` -- the acquiring half reads the same `size`/`opc`
        // table as every other single-register form, and only the name and the ordering change.
        let acquire = shapes(0x199b_7088);
        assert_eq!(acquire.mnemonic, "ldapursb");
        assert_eq!(acquire.effect, Effect::MoveSigned);
        let Operand::Memory(memory) = &acquire.operands[1] else {
            panic!("{acquire:?}");
        };
        assert_eq!(memory.displacement, -0x49);
        // `d9404020  ldapur x0,[x1,#4]`, and the store beside it.
        assert_eq!(shapes(0xd940_4020).mnemonic, "ldapur");
        assert_eq!(shapes(0xd900_4020).mnemonic, "stlur");
        // The prefetch slot the shared table has is not allocated here.
        assert_eq!(
            shapes(0xd980_4020).operands,
            [Operand::Undecoded("unallocated".to_string())]
        );
    }

    /// `subps` is the one allocated encoding in the two-source class with the flag-setting bit, and
    /// a blanket rejection of that bit took its registers and its flags with it. Raised on
    /// dbgscope#171; the neighbouring classes' guards were audited in the same pass.
    #[test]
    fn test_the_flag_setting_pointer_subtraction_is_not_rejected_with_its_class() {
        // `bac50083  subps x3,x4,x5`.
        let subps = shapes(0xbac5_0083);
        assert_eq!(subps.mnemonic, "subps");
        assert!(subps.writes_flags, "{subps:?}");
        assert_eq!(spellings(&subps.writes), ["x3"]);
        assert_eq!(spellings(&subps.reads), ["x4", "x5"]);
        // `9ac50083  subp x3,x4,x5` -- the same opcode without the bit, which sets no flags.
        let subp = shapes(0x9ac5_0083);
        assert_eq!(subp.mnemonic, "subp");
        assert!(!subp.writes_flags);
        // Every other opcode in the class **is** unallocated with that bit, and a 32-bit `subps`
        // is too: the form is 64-bit only.
        assert_eq!(
            shapes(0xbac5_0883).operands,
            [Operand::Undecoded("unallocated".to_string())]
        );
        assert_eq!(
            shapes(0x3ac5_0083).operands,
            [Operand::Undecoded("unallocated".to_string())]
        );
    }

    /// An instruction this does not read says so in a shape of its own, which is what separates it
    /// from an operand kind that merely has no shape.
    ///
    /// The two used to be one [`Operand::Other`] told apart by its contents, and three review
    /// rounds on dbgscope#171 each found a caller that would not have. A consumer matching this
    /// variant needs to know no architecture and no space name.
    #[test]
    fn test_an_unread_instruction_is_a_different_shape_from_an_unshaped_operand() {
        // `6f00e402  movi v2.2d,#0` -- read by nothing here, so every field beside it is a
        // default: no registers, no effect, no privilege.
        let unread = shapes(0x6f00_e402);
        assert_eq!(
            unread.operands,
            [Operand::Undecoded("advanced-simd".to_string())]
        );
        assert!(unread.writes.is_empty() && unread.reads.is_empty());
        assert!(!unread.privileged && !unread.writes_flags);
        assert_eq!(unread.effect, Effect::Other);
        // `d5033abf  dmb ishst` -- fully read, and the domain is the one thing with no shape.
        let shaped = shapes(0xd503_3abf);
        assert_eq!(shaped.mnemonic, "dmb");
        assert_eq!(shaped.operands, [Operand::Other("ishst".to_string())]);
        assert!(
            !shaped
                .operands
                .iter()
                .any(|operand| matches!(operand, Operand::Undecoded(_))),
            "a named operand kind is not an unread instruction: {shaped:?}"
        );
    }

    /// Which positions read register 31 as the stack pointer is per instruction, and the
    /// memory-tagging additions are the only ones outside the addressing modes that do.
    ///
    /// Reading them as the zero register does not merely mislabel an operand: [`Out::record_write`]
    /// drops the zero register, so `irg sp,sp` came back touching nothing at all. Raised on
    /// dbgscope#171; the module's other twenty-two sites that read a 31 were audited beside it and
    /// one more was wrong, the transfer register of a tag store.
    #[test]
    fn test_the_pointer_arithmetic_reads_register_thirty_one_as_the_stack_pointer() {
        // `9adf13ff  irg sp,sp` -- both ends of it.
        let tag = shapes(0x9adf_13ff);
        assert_eq!(tag.mnemonic, "irg");
        assert_eq!(spellings(&tag.writes), ["sp"], "{tag:?}");
        assert_eq!(spellings(&tag.reads), ["sp"], "{tag:?}");
        // `9ac203e0  subp x0,sp,x2` and the flag-setting form beside it: both sources are
        // stack-pointer capable and the destination is not.
        for (word, flags) in [(0x9ac2_03e0_u32, false), (0xbac2_03e0, true)] {
            let one = shapes(word);
            assert_eq!(spellings(&one.writes), ["x0"], "{one:?}");
            assert_eq!(spellings(&one.reads), ["sp", "x2"], "{one:?}");
            assert_eq!(one.writes_flags, flags, "{one:?}");
        }
        // `irg`'s third operand is **not** stack-pointer capable, so a 31 there is the zero
        // register and is dropped: `9adf1000  irg x0,x0`.
        let ordinary = shapes(0x9adf_1000);
        assert_eq!(spellings(&ordinary.writes), ["x0"]);
        assert_eq!(spellings(&ordinary.reads), ["x0"]);
        // And the class's other members read a 31 as the zero register throughout:
        // `9adf0800  udiv x0,x0,xzr`.
        let divide = shapes(0x9adf_0800);
        assert_eq!(divide.mnemonic, "udiv");
        assert_eq!(spellings(&divide.reads), ["x0"], "{divide:?}");
        // The other site the audit found: a tag store's transfer register, which a prologue uses
        // to tag the frame it just made. `d9200bff  stg sp,[sp]` -- the offset form, `op2` zero
        // being the granule-group one.
        let frame = shapes(0xd920_0bff);
        assert_eq!(frame.mnemonic, "stg");
        assert_eq!(spellings(&frame.reads), ["sp", "sp"], "{frame:?}");
        // A tag *load*'s is an ordinary register: `d96003ff  ldg xzr,[sp]`.
        assert_eq!(spellings(&shapes(0xd960_03ff).reads), ["sp"]);
    }

    /// `st2g` and `stz2g` reach two granules, which is what the `2` in them is.
    ///
    /// A caller reading [`MemoryOperand::size`] to bound an affected range misses half of a
    /// `stz2g`'s zeroing without it. The granule-group forms reach a number of granules
    /// `GMID_EL1.BS` decides, which is a run-time fact and not an encoded one, so they claim no
    /// size rather than a plausible wrong one. Raised on dbgscope#171.
    #[test]
    fn test_a_two_granule_tag_store_reports_both_granules() {
        let size = |word: u32| {
            let one = shapes(word);
            let Operand::Memory(memory) = &one.operands[1] else {
                panic!("{one:?}");
            };
            (one.mnemonic.clone(), memory.size)
        };
        // `d9e00862  stz2g x2,[x3]` and `d9200862  stg x2,[x3]`.
        assert_eq!(size(0xd9e0_0862), ("stz2g".to_string(), Some(32)));
        assert_eq!(size(0xd920_0862), ("stg".to_string(), Some(16)));
        // `d9a00128  stgm x8,[x9]` -- a group whose size the encoding does not carry.
        assert_eq!(size(0xd9a0_0128), ("stgm".to_string(), None));
    }

    /// `fmov` copies where everything else in its class converts, and the effect is the field that
    /// distinguishes them.
    ///
    /// `fmov x0,d1` and `fcvtzs x0,d1` name the same two registers and leave different numbers, so
    /// a consumer propagating values must follow one and not the other. Raised on dbgscope#171.
    #[test]
    fn test_a_cross_register_file_move_is_a_move_and_a_conversion_is_not() {
        // `9e660020  fmov x0,d1`, `1e260043  fmov w3,s2`, `9e670020  fmov d0,x1`.
        for word in [0x9e66_0020_u32, 0x1e26_0043, 0x9e67_0020] {
            let one = shapes(word);
            assert_eq!(one.mnemonic, "fmov");
            assert_eq!(one.effect, Effect::Move, "{word:#010x}: {one:?}");
        }
        // `1e380000  fcvtzs w0,s0` -- the same shape, a different number.
        let convert = shapes(0x1e38_0000);
        assert_eq!(convert.mnemonic, "fcvtzs");
        assert_eq!(convert.effect, Effect::Other);
        // The upper-lane forms part company: into a general-purpose register the whole value
        // arrives, and out of one only half of the destination is replaced.
        assert_eq!(shapes(0x9eae_0020).effect, Effect::Move);
        assert_eq!(
            shapes(0x9eaf_0062).effect,
            Effect::Other,
            "what it holds afterwards is the source beside the lane it kept"
        );
    }

    /// Every position in this decoder where register 31 is the stack pointer, and three where it
    /// is not.
    ///
    /// **This test is the audit.** The question produced a review finding on dbgscope#171 in two
    /// consecutive rounds — the second against an audit done by recalling the list rather than
    /// deriving it, which is how `pacga`'s modifier survived it — so the list now lives in the
    /// module header and every row of it is pinned here. A form added without its `|SP` positions
    /// fails this rather than waiting for a round five.
    #[test]
    fn test_register_thirty_one_is_the_stack_pointer_in_exactly_these_positions() {
        let touched = |word: u32| {
            let one = shapes(word);
            let mut names: Vec<String> = one
                .reads
                .iter()
                .chain(one.writes.iter())
                .map(|register| register.name.clone())
                .collect();
            names.sort();
            names.dedup();
            (one.mnemonic.clone(), names)
        };
        // Each row: the encoding, what it is, and that `sp` is among what it touches.
        for (word, what) in [
            (0xf940_03ff_u32, "ldr xzr,[sp] — any addressing mode's base"),
            (0x9100_03ff, "mov sp,sp — add immediate, both ends"),
            (
                0xb100_03ff,
                "cmn sp,#0 — add immediate's source when it sets flags",
            ),
            (0x8b3f_63ff, "add sp,sp,xzr — the extended-register form"),
            (
                0x9240_03ff,
                "and sp,xzr,#1 — a logical immediate's destination",
            ),
            (
                0xb266_97ff,
                "mov sp,#-0x4000000 — and the same through its `mov` alias",
            ),
            (0x9180_03ff, "addg sp,sp,#0,#0"),
            (0x9adf_13ff, "irg sp,sp"),
            (0x9ac1_17e0, "gmi x0,sp,x1"),
            (0x9ac2_03e0, "subp x0,sp,x2 — the left source"),
            (0x9adf_0020, "subp x0,x1,sp — and the right one"),
            (0x9adf_3020, "pacga x0,x1,sp — the modifier"),
            (0xdac1_03e0, "pacia x0,sp — the modifier again"),
            (0xd71f_083f, "braa x1,sp — and once more"),
            (0xd920_0bff, "stg sp,[sp] — a tag store's transfer register"),
            (0xd960_03ff, "ldg xzr,[sp] — but not a tag load's"),
        ] {
            let (mnemonic, names) = touched(word);
            assert!(
                names.iter().any(|name| name == "sp"),
                "{word:#010x} `{what}`: {mnemonic} touched {names:?}"
            );
        }
        // And three where a 31 is the zero register, so nothing is recorded at all.
        for (word, what) in [
            (
                0xeb1f_03ff_u32,
                "cmp xzr,xzr — the shifted-register arithmetic",
            ),
            (
                0xf240_03ff,
                "tst xzr,#1 — `ands`, which is why the alias exists",
            ),
            (0xaa1f_03ff, "mov xzr,xzr — a logical shifted register"),
        ] {
            let (mnemonic, names) = touched(word);
            assert!(
                names.is_empty(),
                "{word:#010x} `{what}`: {mnemonic} touched {names:?}"
            );
        }
    }

    /// `bc.cond` is a different instruction from `b.cond`, not a spelling of it.
    ///
    /// The bit that picks it is one [`super::flow`] deliberately does not read, both forms having
    /// the same two edges — and the mnemonic must, because a caller matching one is not asking
    /// about the other. The engine on this bench refuses the encoding outright rather than
    /// rendering it as a `b.cond`, which is what settled it. Raised on dbgscope#171.
    #[test]
    fn test_a_consistency_hinted_branch_keeps_its_own_mnemonic() {
        // `54000000  beq .` and `54000010`, the same branch with `o0` set.
        let ordinary = decode(0x5400_0000, 0x1000);
        assert_eq!(ordinary.mnemonic, "b.eq");
        let hinted = decode(0x5400_0010, 0x1000);
        assert_eq!(hinted.mnemonic, "bc.eq");
        // Everything else about them is the same, which is why the flow does not read the bit.
        assert_eq!(hinted.condition, ordinary.condition);
        assert_eq!(hinted.flow, ordinary.flow);
        assert_eq!(hinted.operands, ordinary.operands);
    }

    /// `ldraa`/`ldrab` are constrained by `size` and `V` and by nothing else, and the field a
    /// guard here used to treat as an opcode is the top bit of the displacement.
    ///
    /// **The corpus caught this in round one and it was explained away**, which is the more useful
    /// half of the story: `f8fcfcf6` showed up as an unallocated encoding the engine rendered
    /// `ldrab`, and a hand check of its bits said the fixed bit was wrong. The hand check was
    /// wrong. Raised again on dbgscope#171, and the encoding below is that same word.
    #[test]
    fn test_an_authenticated_load_is_constrained_by_its_size_and_nothing_else() {
        // `f86c24a2  ldraa x2,[x5,#-0x13E]` as the engine renders it -- a **negative**
        // displacement, which is the half a guard on bit 22 refused.
        let negative = shapes(0xf86c_24a2);
        assert_eq!(negative.mnemonic, "ldraa");
        assert_eq!(spellings(&negative.writes), ["x2"]);
        let Operand::Memory(memory) = &negative.operands[1] else {
            panic!("{negative:?}");
        };
        // Scaled by eight, which is the architecture's answer; the engine prints the raw field,
        // and that divergence is one of the residues the whole-image sweep reports.
        assert_eq!(memory.displacement, -318 * 8);
        // The same instruction with the bit clear, which used to be the only half that decoded.
        let positive = shapes(0xf82c_24a2);
        assert_eq!(positive.mnemonic, "ldraa");
        // `f8fcfcf6  ldrab x22,[x7,#-0x31]!` -- the b-key, writing its base back.
        let key = shapes(0xf8fc_fcf6);
        assert_eq!(key.mnemonic, "ldrab");
        assert_eq!(spellings(&key.writes), ["x22", "x7"]);
        assert_eq!(spellings(&key.reads), ["x7"]);
        // And the base is stack-pointer capable, as every addressing mode's is.
        assert_eq!(spellings(&shapes(0xf82b_9fff).writes), ["sp"]);
    }

    /// `cpy` and `set`, whose three registers are all read and all written -- the fact a consumer
    /// carrying values across an inlined `memcpy` needs, and the family review raised on
    /// dbgscope#171 after a corpus of a million kernel instructions could not: Windows does not
    /// build for Armv8.8.
    ///
    /// Every mnemonic below is the one a generated instruction table gives for the same word, the
    /// naming being systematic enough to derive rather than tabulate.
    #[test]
    fn test_a_memory_copy_advances_all_three_of_its_registers() {
        // `19010440  cpyfp [x0]!, [x1]!, x2!`.
        let prologue = shapes(0x1901_0440);
        assert_eq!(prologue.mnemonic, "cpyfp");
        assert_eq!(spellings(&prologue.reads), ["x0", "x1", "x2"]);
        assert_eq!(spellings(&prologue.writes), ["x0", "x1", "x2"]);
        // The two bracketed operands are memory references and the count is not, which is what a
        // consumer looking for this instruction's memory effect finds. Their size is unknown: how
        // much is moved is what the count register holds.
        let Operand::Memory(destination) = &prologue.operands[0] else {
            panic!("{prologue:?}");
        };
        assert_eq!(destination.base.as_deref(), Some("x0"));
        assert_eq!(destination.size, None);
        assert!(matches!(prologue.operands[1], Operand::Memory(_)));
        assert_eq!(prologue.operands[2], register("x2", "x2", 8));
        // The stage is `op1` and the memory attributes are `op2`, as two independent halves.
        assert_eq!(shapes(0x1941_0440).mnemonic, "cpyfm");
        assert_eq!(shapes(0x1981_0440).mnemonic, "cpyfe");
        assert_eq!(shapes(0x1900_5440).mnemonic, "cpyfpwtwn");
        assert_eq!(shapes(0x1900_f400).mnemonic, "cpyfptn");
        // The second slot is the tag-preserving copy.
        assert_eq!(shapes(0x1d01_0440).mnemonic, "cpyp");
        // `19c20420  setp [x0]!, x1!, x2` -- a set advances two and reads the third, that being
        // the byte it writes rather than a pointer.
        let set = shapes(0x19c2_0420);
        assert_eq!(set.mnemonic, "setp");
        assert!(matches!(set.operands[0], Operand::Memory(_)));
        assert_eq!(set.operands[2], register("x2", "x2", 8));
        assert_eq!(spellings(&set.writes), ["x0", "x1"]);
        assert_eq!(spellings(&set.reads), ["x0", "x1", "x2"]);
        assert_eq!(shapes(0x19c0_b400).mnemonic, "setetn");
        assert_eq!(shapes(0x1dc0_0400).mnemonic, "setgp");
        // `op2` above eleven allocates no stage for a set.
        assert_eq!(
            shapes(0x19c0_c400).operands,
            [Operand::Undecoded("unallocated".to_string())]
        );
        // **The prologue writes the flags the other two stages run on**, and only the prologue:
        // the three share a protocol through `NZCV`, so a caller asking what set the flags after a
        // copy stops at `cpyfp` rather than walking past it.
        assert!(shapes(0x1901_0440).writes_flags, "cpyfp");
        assert!(shapes(0x19c2_0420).writes_flags, "setp");
        assert!(!shapes(0x1941_0440).writes_flags, "cpyfm");
        assert!(!shapes(0x1981_0440).writes_flags, "cpyfe");
        assert!(!shapes(0x19c2_4420).writes_flags, "setm");
    }

    /// CSSC's minimum and maximum against a literal, which share the tagged add's slot and were
    /// half a family: the register forms two classes away were already read.
    ///
    /// Found by enumerating a generated table against this decoder rather than by review, which is
    /// the check `examples/undecoded_families.rs` exists to be.
    #[test]
    fn test_the_literal_minimum_and_maximum_share_the_tagged_add_s_slot() {
        // `11c00000  smax w0,w0,#0` and the three beside it, which `opc` picks.
        for (word, mnemonic) in [
            (0x11c0_0000_u32, "smax"),
            (0x11c4_0000, "umax"),
            (0x11c8_0000, "smin"),
            (0x11cc_0000, "umin"),
        ] {
            let one = shapes(word);
            assert_eq!(one.mnemonic, mnemonic);
            assert_eq!(spellings(&one.writes), ["x0"]);
        }
        // The signed pair read their literal as signed and the unsigned pair do not, which is the
        // only thing separating `smax w0,w0,#-1` from `umax w0,w0,#255`.
        assert_eq!(shapes(0x11c3_fc00).operands[2], Operand::Immediate(!0));
        assert_eq!(shapes(0x11c7_fc00).operands[2], Operand::Immediate(0xff));
        // And the tagged add still has the slot with that bit clear: `918003ff  addg sp,sp,#0,#0`.
        let tagged = shapes(0x9180_03ff);
        assert_eq!(tagged.mnemonic, "addg");
        assert_eq!(spellings(&tagged.writes), ["sp"]);
    }

    /// `umov` and `smov` copy a lane into a general-purpose register, zero-extending and
    /// sign-extending respectively -- the same pair of effects `uxtb` and `sxtb` carry, and the
    /// distinction [`Effect::MoveSigned`] exists to draw. Raised on dbgscope#171.
    #[test]
    fn test_a_lane_extraction_is_a_move_and_says_which_kind() {
        // `0e053c20  umov w0,v1.b[2]` and `0e0e2ce6  smov w6,v7.h[3]`.
        let zero = shapes(0x0e05_3c20);
        assert_eq!(zero.mnemonic, "umov");
        assert_eq!(zero.effect, Effect::Move);
        assert_eq!(spellings(&zero.writes), ["x0"]);
        let signed = shapes(0x0e0e_2ce6);
        assert_eq!(signed.mnemonic, "smov");
        assert_eq!(signed.effect, Effect::MoveSigned);
        // The other two members of the class are not copies: `ins` fills one lane and leaves the
        // rest, and `dup` broadcasts into every one.
        assert_eq!(shapes(0x4e08_1d10).effect, Effect::Other);
        assert_eq!(shapes(0x4e04_0c60).effect, Effect::Other);
    }

    /// A prefetch's `size` field scales its offset and is not a transfer width, so it claims none.
    ///
    /// Eight bytes was the plausible wrong answer: the field is the one a 64-bit load uses and the
    /// scaling really is by eight, but nothing that wide moves. What a prefetch touches is a cache
    /// line, whose size the implementation decides. Raised on dbgscope#171.
    #[test]
    fn test_a_prefetch_claims_no_transfer_width() {
        let size = |word: u32| {
            let one = shapes(word);
            let Operand::Memory(memory) = &one.operands[1] else {
                panic!("{one:?}");
            };
            (one.mnemonic.clone(), memory.size, memory.displacement)
        };
        // `f9800130  prfm PSTL1KEEP,[x9]` and `f9801021  prfm PLDL1STRM,[x1,#0x20]` -- the offset
        // is still scaled by eight, which is what the field is for.
        assert_eq!(size(0xf980_0130), ("prfm".to_string(), None, 0));
        assert_eq!(size(0xf980_1021), ("prfm".to_string(), None, 0x20));
        // `f880c040  prfum PLDL1KEEP,[x2,#0xC]` and the literal form.
        assert_eq!(size(0xf880_c040), ("prfum".to_string(), None, 0xc));
        assert_eq!(size(0xd807_aa98).1, None);
        // An ordinary load of the same width still reports one: `f9400021  ldr x1,[x1]`.
        assert_eq!(size(0xf940_0021), ("ldr".to_string(), Some(8), 0));
    }

    /// The flow comes from [`super::flow`] unchanged, so one word has one answer whichever field
    /// is read.
    #[test]
    fn test_the_flow_is_the_one_the_flow_decoder_gives() {
        for word in [
            0x97ff_fcc4_u32,
            0xd63f_01e0,
            0xd65f_03c0,
            0xd43e_0000,
            0x5400_02c1,
            0x0000_0000,
            0x6f00_e402,
        ] {
            assert_eq!(
                decode(word, ANYWHERE).flow,
                super::super::flow(word, ANYWHERE),
                "{word:#010x}"
            );
        }
    }
}
