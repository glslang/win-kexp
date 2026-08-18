use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;
use windows::Win32::Foundation::{E_INVALIDARG, E_NOINTERFACE, S_FALSE, S_OK};
use windows::core::{HRESULT, IUnknown, Interface, PCSTR, PCWSTR, PWSTR};

// Import the necessary Windows Debug Engine interfaces
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_ANY_ID, DEBUG_ATTACH_KERNEL_CONNECTION, DEBUG_ATTACH_LOCAL_KERNEL, DEBUG_BREAKPOINT_CODE,
    DEBUG_BREAKPOINT_DATA, DEBUG_BREAKPOINT_DEFERRED, DEBUG_BREAKPOINT_ENABLED,
    DEBUG_BREAKPOINT_ONE_SHOT, DEBUG_CLASS_KERNEL, DEBUG_ENGOPT_INITIAL_BREAK,
    DEBUG_EVENT_BREAKPOINT, DEBUG_EXECUTE_ECHO, DEBUG_INTERRUPT_ACTIVE, DEBUG_KERNEL_SMALL_DUMP,
    DEBUG_MODNAME_SYMBOL_FILE, DEBUG_MODULE_PARAMETERS, DEBUG_MODULE_USER_MODE,
    DEBUG_OUTCTL_THIS_CLIENT, DEBUG_OUTPUT_NORMAL, DEBUG_REGISTER_DESCRIPTION,
    DEBUG_REGISTER_SUB_REGISTER, DEBUG_STACK_FRAME, DEBUG_STATUS_GO, DEBUG_STATUS_NO_DEBUGGEE,
    DEBUG_SYMTYPE_CODEVIEW, DEBUG_SYMTYPE_COFF, DEBUG_SYMTYPE_DEFERRED, DEBUG_SYMTYPE_DIA,
    DEBUG_SYMTYPE_EXPORT, DEBUG_SYMTYPE_NONE, DEBUG_SYMTYPE_PDB, DEBUG_SYMTYPE_SYM, DEBUG_VALUE,
    DEBUG_VALUE_FLOAT32, DEBUG_VALUE_FLOAT64, DEBUG_VALUE_FLOAT80, DEBUG_VALUE_FLOAT82,
    DEBUG_VALUE_FLOAT128, DEBUG_VALUE_INT8, DEBUG_VALUE_INT16, DEBUG_VALUE_INT32,
    DEBUG_VALUE_INT64, DEBUG_VALUE_VECTOR64, DEBUG_VALUE_VECTOR128, IDebugBreakpoint,
    IDebugBreakpoint2, IDebugClient6, IDebugControl4, IDebugDataSpaces4,
    IDebugEventContextCallbacks, IDebugOutputCallbacks, IDebugRegisters, IDebugSymbols3,
    IDebugSystemObjects,
};

/// Callback type for breakpoint events that receives the breakpoint, context, and flags
pub type BreakpointCallback =
    Box<dyn Fn(&IDebugBreakpoint2, *const std::ffi::c_void, u32) -> windows::core::Result<()>>;

#[derive(Debug, Error)]
pub enum DbgEngError {
    #[error("Failed to initialize COM: {0}")]
    ComInitFailed(#[from] windows::core::Error),

    #[error("Failed to create debug client: {0}")]
    CreateClientFailed(windows::core::Error),

    #[error("Failed to get debug control: {0}")]
    GetControlFailed(windows::core::Error),

    #[error("Failed to get debug symbols: {0}")]
    GetSymbolsFailed(windows::core::Error),

    #[error("Failed to attach to kernel: {0}")]
    AttachFailed(windows::core::Error),

    #[error("Debug command failed: {0}")]
    CommandFailed(windows::core::Error),

    #[error("Symbol path operation failed: {0}")]
    SymbolPathFailed(windows::core::Error),

    #[error("Breakpoint failed: {0}")]
    BreakpointFailed(windows::core::Error),

    #[error("Invalid command string (contains interior NUL)")]
    InvalidCommand,

    #[error(
        "No active debuggee — attach to a target, launch a process, or open a dump/trace first"
    )]
    NoDebuggee,

    #[error(
        "kernel target did not break in within the attach timeout — is it reachable and in debug mode?"
    )]
    KernelBreakTimeout,

    #[error("Operation failed: {0}")]
    OperationFailed(windows::core::Error),

    #[error("{operation} failed: {source}")]
    Context {
        operation: String,
        #[source]
        source: windows::core::Error,
    },

    #[error("short virtual read at {address:#x}: requested {requested} bytes, read {actual}")]
    ShortRead {
        address: u64,
        requested: usize,
        actual: usize,
    },

    #[error("requested debugger buffer is too large: {0} bytes")]
    BufferTooLarge(usize),

    #[error("debugger text contains an interior NUL")]
    InvalidOutput,

    #[error("this scope was read from a target the engine no longer holds")]
    ScopeFromAnotherTarget,
}

/// Fallback length of `_EPROCESS::ImageFileName` when the field's own size cannot be read.
///
/// 15 bytes on every Windows version this can attach to. Only reached when symbols answer the
/// field's *offset* but not its type, which should not happen — it is here so that a partial
/// symbol answer produces a slightly short name rather than no name at all.
const EPROCESS_IMAGE_NAME_LEN: u32 = 15;

/// Buffer to ask a module's names into when the engine reports no size for them, which is what
/// an *unloaded* module's parameters carry. Big enough for a full image path.
const MODULE_NAME_FALLBACK: usize = 260;

/// `DEBUG_MODULE_PARAMETERS::Flags`: this module has unloaded. Zero — `DEBUG_MODULE_LOADED` — is
/// the other state, so the flag is what separates the two halves of the engine's module list.
const DEBUG_MODULE_UNLOADED: u32 = 0x0000_0001;

/// `CreateProcess` flag: debug only the launched process, not its children.
const DEBUG_ONLY_THIS_PROCESS: u32 = 0x0000_0002;
/// `CreateProcess` flag: give the launched target its own console. Without this a
/// console target inherits the host's stdout — fatal when the host's stdout is an
/// MCP/JSON-RPC channel, as the target's prints corrupt the stream.
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
/// `AttachProcess` default attach flags.
const DEBUG_ATTACH_DEFAULT: u32 = 0x0000_0000;
/// `EndSession` flag used on teardown: detach passively without resuming.
const DEBUG_END_PASSIVE: u32 = 0x0000_0000;
/// `EndSession` flag: actively detach — the engine talks to the target to resume it
/// before disconnecting, so a live kernel is left running instead of frozen at a break.
const DEBUG_END_ACTIVE_DETACH: u32 = 0x0000_0002;
/// How long to wait for a freshly launched/attached target to reach its initial
/// break before giving up (ms).
const LIVE_WAIT_MS: u32 = 30_000;
/// `WaitForEvent` timeout for a *live kernel* target. DbgEng requires INFINITE here —
/// a finite timeout on a live kernel connection returns `E_NOTIMPL` (the engine never
/// drives the connection). See [`DebugEngine::is_live_kernel`].
const WAIT_INFINITE: u32 = u32::MAX;
/// Upper bound (ms) on a live-kernel break-in wait. The wait itself must be INFINITE
/// (a finite `WaitForEvent` returns `E_NOTIMPL` on a live kernel), so a watchdog forces
/// it to return after this long. Generous, to allow a KDNET resync (~25s observed).
///
/// **Bounds less than it appears to.** The watchdog works by `SetInterrupt`, which only
/// reaches a target that has *connected*, so this caps a connected-but-unresponsive target
/// and nothing else. One that never dials in — powered off, wrong key, not booted with
/// `bcdedit /debug on` — blocks past this bound indefinitely (measured: >300s, killed).
/// See [`DebugEngine::attach_kernel`].
const KERNEL_ATTACH_WAIT_MS: u32 = 60_000;

/// Buffer sizes offered to `GetScope` for a scope's register context, smallest first.
///
/// The engine rejects a buffer below the target's `CONTEXT` size and accepts anything at or
/// above it (measured — see [`DebugEngine::scope`]), so the first size accepted is the smallest
/// here that fits, and the first three are the `CONTEXT` sizes of the architectures dbgeng
/// debugs: x86 (716), ARM64 (912), x64 (1232). The doubling tail is for a target whose context
/// is larger than any of them — a size this crate has not seen, and would otherwise refuse to
/// read a scope for at all.
const SCOPE_CONTEXT_SIZES: &[u32] = &[716, 912, 1232, 2048, 4096, 8192, 16384, 32768, 65536];

/// Ctrl+Breaks one engine from another thread.
///
/// `SetInterrupt` is the one DbgEng call documented as safe from any thread — the rest of the
/// engine is single-thread-affine — which is the whole reason this can exist without a second
/// threading model. It is also the only call this makes.
///
/// Two kinds of caller, and the engine cannot tell them apart: the watchdogs below, which raise
/// an interrupt when a deadline passes, and a **host that has decided to stop waiting** — an
/// operator abandoning a runaway `s` search, say. The second is why this is public. Everything
/// about *which* operation an interrupt is meant for belongs to that host: this addresses an
/// engine, so whatever it is running now is what stops.
pub struct InterruptHandle {
    /// An owned reference, not a borrowed pointer. A handle is public now, so it can outlive the
    /// `DebugEngine` it came from — and a raw pointer would then be a dangling one at exactly the
    /// moment a host reaches for it. The refcount costs nothing and makes the lifetime a fact
    /// rather than a convention.
    control: IDebugControl4,
    /// Set whenever this handle raises an interrupt, and cleared by the command that finds it.
    ///
    /// Shared with the engine so [`DebugEngine::execute_command_bounded`] can tell an aborted
    /// `Execute` from a failed one *without* being the thread that asked. Without it an interrupt
    /// on request is indistinguishable from a command error, and the output captured up to the
    /// break is discarded with it — which is most of what an interrupted search is worth.
    raised: Arc<AtomicBool>,
}
// SAFETY: `control` is only ever handed to SetInterrupt, the one cross-thread-safe DbgEng call.
// The other cross-thread touch is the `Release` on drop, which rests on the same assumption
// [`DebugEngine`]'s own `Send`/`Sync` below already make about these interfaces; a handle held for
// the life of a process (the intended use) never reaches it at all.
unsafe impl Send for InterruptHandle {}
// SAFETY: as above — sharing a handle only shares the ability to make that one call.
unsafe impl Sync for InterruptHandle {}

impl InterruptHandle {
    /// Asks the engine this came from to break out of whatever it is running.
    ///
    /// Returns as soon as the request is lodged, not when the engine acts on it: a long command
    /// polls for the flag exactly as it does for a human's Ctrl+Break, so the operation ends at
    /// its next poll and its own caller is who observes that. Two limits carry over from the
    /// engine, both of them properties of `SetInterrupt` rather than of this: a command that never
    /// polls is not reached, and neither is a live-kernel wait whose target has not yet connected
    /// (see [`DebugEngine::wait_for_event_bounded`]).
    pub fn interrupt(&self) -> Result<(), DbgEngError> {
        // Stored *before* the call, so the flag can never become visible later than the break it
        // explains — a bounded command reads it after `Execute` returns, and one that read `false`
        // there would report the abort it caused as a debugger error.
        self.raised.store(true, Ordering::SeqCst);
        unsafe { self.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE) }.map_err(|source| {
            DbgEngError::Context {
                operation: "requesting a debugger interrupt".into(),
                source,
            }
        })
    }
}

/// Encodes a `&str` as a NUL-terminated UTF-16 buffer for the `*Wide` DbgEng APIs.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Where execution stopped after a [`DebugEngine::run_to_address`] request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunToOutcome {
    /// The target reached the requested address.
    Hit,
    /// The target stopped at a different address (another breakpoint or an exception)
    /// before reaching the requested one.
    StoppedElsewhere { stopped_at: u64 },
    /// The target did not stop within the timeout — the address was not reached with the
    /// current input/state.
    Timeout,
}

/// Result of [`DebugEngine::run_to_address`]: the structured [`RunToOutcome`] plus the
/// debugger text captured across the run (the stop banner, for context/logging).
#[derive(Debug, Clone)]
pub struct RunToResult {
    pub outcome: RunToOutcome,
    pub output: String,
}

/// Why a command stopped before it finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interruption {
    /// The watchdog's deadline passed and it Ctrl+Broke the engine. Nobody outside this crate can
    /// see that happen, so a caller rendering for a human should say so — and say what to do about
    /// it, which is to scope the command and retry.
    Deadline { after_ms: u32 },
    /// A host asked, through an [`InterruptHandle`]. Distinct from a deadline because the advice
    /// is different and mostly unnecessary: that caller knows, having asked.
    OnRequest,
}

/// What a command produced, and whether it finished — the same shape as [`RunToResult`], and for
/// the same reason.
///
/// A `String` alone cannot answer "did this run?", and an interrupted command is exactly the case
/// where the text looks like an answer and is not: a search cut short prints the hits it had
/// reached and nothing to say there were more. Encoding it as an `Err` is no better — it discards
/// the output, which is the whole reason to interrupt rather than end the session.
#[derive(Debug, Clone)]
pub struct CommandRun {
    pub output: String,
    /// `None` when the command ran to completion.
    pub cut_short: Option<Interruption>,
}

impl CommandRun {
    /// The output, for a caller that has already dealt with [`Self::cut_short`] — or one running a
    /// command it knows cannot be interrupted.
    pub fn into_output(self) -> String {
        self.output
    }
}

/// `DEBUG_INVALID_OFFSET` from `dbgeng.h`: the engine's "there is no address here".
///
/// Spelled out because the `windows` crate does not generate it, and the value matters — a
/// breakpoint reporting it is one that has not resolved, which is not the same as one at zero.
const DEBUG_INVALID_OFFSET: u64 = u64::MAX;

/// What one register holds, decoded from the engine's tagged union.
///
/// `DEBUG_VALUE` is a union plus a `Type` discriminant, and reading the wrong arm is not a
/// compile error or even a runtime one — it is a plausible-looking number. So the tag is read
/// once, here, and each arm keeps a shape it can hold losslessly: the wide floats and the vector
/// registers stay as bytes rather than being squeezed into an `f64` that cannot represent them.
#[derive(Debug, Clone, PartialEq)]
pub enum RegisterValue {
    /// An integer register, zero-extended to 64 bits from whatever width the engine reported.
    Int(u64),
    /// A floating-point register narrow enough to be exact in an `f64` (`f32`/`f64`).
    Float(f64),
    /// An x87 (80/82/128-bit) or vector (`xmm`/`ymm`) register, in the engine's byte order.
    /// Kept raw because there is no scalar to narrow it to without losing part of it.
    Bytes(Vec<u8>),
    /// The engine holds no value for this register in this target — a minidump without
    /// floating-point state reads this way — or reported a type this build does not decode.
    Unavailable,
}

impl RegisterValue {
    /// Decodes one `DEBUG_VALUE` by its own tag.
    fn decode(value: &DEBUG_VALUE) -> Self {
        // SAFETY: every read below is of the arm `value.Type` names, which is the contract
        // `DEBUG_VALUE` is defined by, and the engine fills the whole struct. An unrecognised
        // tag reads no arm at all.
        unsafe {
            match value.Type {
                DEBUG_VALUE_INT8 => Self::Int(u64::from(value.Anonymous.I8)),
                DEBUG_VALUE_INT16 => Self::Int(u64::from(value.Anonymous.I16)),
                DEBUG_VALUE_INT32 => Self::Int(u64::from(value.Anonymous.I32)),
                DEBUG_VALUE_INT64 => Self::Int(value.Anonymous.Anonymous.I64),
                DEBUG_VALUE_FLOAT32 => Self::Float(f64::from(value.Anonymous.F32)),
                DEBUG_VALUE_FLOAT64 => Self::Float(value.Anonymous.F64),
                DEBUG_VALUE_FLOAT80 => Self::Bytes(value.Anonymous.F80Bytes.to_vec()),
                DEBUG_VALUE_FLOAT82 => Self::Bytes(value.Anonymous.F82Bytes.to_vec()),
                DEBUG_VALUE_FLOAT128 => Self::Bytes(value.Anonymous.F128Bytes.to_vec()),
                DEBUG_VALUE_VECTOR64 => Self::Bytes(value.Anonymous.VI8[..8].to_vec()),
                DEBUG_VALUE_VECTOR128 => Self::Bytes(value.Anonymous.VI8.to_vec()),
                _ => Self::Unavailable,
            }
        }
    }
}

/// One register of the target's context, as [`DebugEngine::register_values`] reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct Register {
    /// The engine's own name for it, lowercase (`rax`, `xmm0`, `cs`, `efl`).
    pub name: String,
    pub value: RegisterValue,
    /// Whether this register is a *view* of another rather than storage of its own — `eax`
    /// within `rax`, `al` within `ax`. Reported rather than filtered because which of the two a
    /// caller wants depends entirely on what they are doing.
    pub subregister: bool,
}

/// How much symbol information the engine has for a module — the `lm` "symbols" column.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// No symbols at all.
    #[default]
    None,
    /// Symbols have not been loaded yet; the engine will fetch them when something needs them.
    /// The most consequential value here, because it is *not* a statement that symbols are
    /// missing — a `deferred` module usually resolves fine on first use.
    Deferred,
    Coff,
    CodeView,
    Pdb,
    /// Names taken from the image's export table: enough for `module!Export`, nothing more.
    Export,
    Sym,
    Dia,
    /// A symbol type this build does not name, kept as the engine's own code rather than
    /// flattened into `None` — which would read as "no symbols" for something that has them.
    Other(u32),
}

impl SymbolKind {
    fn from_engine(code: u32) -> Self {
        match code {
            DEBUG_SYMTYPE_NONE => Self::None,
            DEBUG_SYMTYPE_COFF => Self::Coff,
            DEBUG_SYMTYPE_CODEVIEW => Self::CodeView,
            DEBUG_SYMTYPE_PDB => Self::Pdb,
            DEBUG_SYMTYPE_EXPORT => Self::Export,
            DEBUG_SYMTYPE_DEFERRED => Self::Deferred,
            DEBUG_SYMTYPE_SYM => Self::Sym,
            DEBUG_SYMTYPE_DIA => Self::Dia,
            other => Self::Other(other),
        }
    }

    /// Whether this symbol provider exposes private type information suitable for allocator
    /// layout resolution.
    pub fn has_type_info(self) -> bool {
        matches!(self, Self::Pdb | Self::Dia)
    }
}

/// One module, as [`DebugEngine::modules`] and [`DebugEngine::unloaded_modules`] report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    pub base: u64,
    pub size: u32,
    /// The name symbols are qualified by — the `nt` in `nt!KeBugCheckEx`.
    ///
    /// **Empty for an unloaded module**, which is not a truncation bug but the fact: there is no
    /// module left to qualify a symbol with. `lm` prints [`Self::image_name`] in its name column
    /// for those rows, and so should anything rendering them.
    pub name: String,
    /// The image's own name (`ntkrnlmp.exe`).
    ///
    /// The one name an *unloaded* module still has, and the kernel stores it truncated — twelve
    /// characters, so `WpdUpFltr.sys` comes back as `WpdUpFltr.sy`. `lm` shows the same truncation
    /// because it is reading the same list.
    pub image_name: String,
    /// The path the engine loaded the image from, where it has one.
    pub loaded_image_name: String,
    pub timestamp: u32,
    pub checksum: u32,
    pub symbols: SymbolKind,
    /// Whether this is a user-mode module. On a kernel target both kinds can be present.
    pub user_mode: bool,
    /// Whether this module has **unloaded**: the engine's own `DEBUG_MODULE_UNLOADED` flag, not
    /// an inference from which call produced it.
    ///
    /// Carried on the value so a `Module` that has been passed around still knows which half of
    /// the engine's list it came from — the distinction decides whether `base` is where the image
    /// *is* or where it *was*.
    pub unloaded: bool,
}

/// Stable identity and symbol provenance for one loaded image.
///
/// The PE tuple is what DbgEng and symbol servers use to distinguish builds; the base is
/// included because resolved globals are addresses in this particular target. `symbol_file`
/// is the exact file DbgEng selected for the module, rather than a path inferred from the
/// configured symbol search path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ModuleIdentity {
    pub name: String,
    pub image_name: String,
    pub loaded_image_name: String,
    pub symbol_file: String,
    pub symbols: SymbolKind,
    pub base: u64,
    pub size: u32,
    pub timestamp: u32,
    pub checksum: u32,
}

impl Module {
    /// One past the last byte of the image — the end of the `start end` pair `lm` prints.
    pub fn end(&self) -> u64 {
        self.base.saturating_add(u64::from(self.size))
    }
}

/// The kernel image a target is running: where it is loaded, and which build it is.
///
/// Hashable and comparable so it can key a cache of anything derived from the kernel's types
/// and globals — which is why the build fields travel with the base rather than beside it. See
/// [`DebugEngine::kernel_image`] for what each field is and why these three.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct KernelImage {
    /// Where `nt` is loaded. Globals resolved against it are addresses, so this is part of the
    /// identity of anything resolved, not merely of the lookup that found it.
    pub base: u64,
    pub size: u32,
    pub timestamp: u32,
    pub checksum: u32,
}

/// The bug check a target stopped on, as [`DebugEngine::bug_check`] reports it.
///
/// The engine's own five values and nothing else: what each parameter *means* is per-code lore
/// that lives in `!analyze`'s tables, not in the engine, so it is not invented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BugCheck {
    /// The bug check code — `0x9f` for `DRIVER_POWER_STATE_FAILURE`.
    pub code: u32,
    /// The four parameters, in the order the bug check screen and `!analyze` print them as
    /// `Arg1`..`Arg4`.
    pub parameters: [u64; 4],
}

/// One frame of a stack walk, as [`DebugEngine::stack_frames`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackFrame {
    /// Its position in the walk: 0 is the innermost frame, where the target is stopped.
    pub index: u32,
    /// The instruction this frame is executing at — the address a symbol or `module+RVA` is
    /// resolved from.
    pub instruction_offset: u64,
    pub return_offset: u64,
    pub frame_offset: u64,
    pub stack_offset: u64,
    /// `module!Symbol` as the engine resolves [`Self::instruction_offset`], or `None` when
    /// nothing resolves — the normal case for a driver with no PDB.
    pub symbol: Option<String>,
    /// How far past [`Self::symbol`] the instruction is; zero when there is no symbol.
    pub displacement: u64,
}

/// One disassembled instruction, as [`DebugEngine::disassemble`] reports it.
///
/// The engine has no structured disassembly — `IDebugControl::Disassemble` renders one line of
/// text and says where the next instruction starts — so this is that line split at its two column
/// boundaries, with the address taken from the walk rather than parsed back out of it. A line the
/// split does not recognise keeps everything after the address in [`Self::text`] and leaves
/// [`Self::bytes`] empty, rather than guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// Where the instruction is. **Not** parsed from the rendered line: it is the offset this
    /// walk asked about, which is the previous instruction's end.
    pub address: u64,
    /// The encoding, as the engine prints it — `48895c2408`. Empty when the line carried no byte
    /// column, which is not a shape any current engine produces for a readable address.
    pub bytes: String,
    /// The mnemonic and its operands — `mov qword ptr [rsp+8],rbx` — with the engine's column
    /// padding collapsed to single spaces, since the columns it was aligning are separate fields
    /// here. Operand symbols are the engine's own (`call nt!KeBugCheckEx (fffff803`...)`).
    pub text: String,
}

/// The engine's current **scope**: which instruction, which frame, and the register context
/// those are read through — what `.frame`, `.cxr`, `.ecxr` and `.trap` set, and what `dt`, `dv`,
/// `k` and every register read are answered against.
///
/// Held in order to be handed back. A scope is a position in someone else's session, and its
/// fields are the engine's own bookkeeping — a [`DEBUG_STACK_FRAME`] it walked, and an opaque
/// context blob whose layout is the target's `CONTEXT` — so this is a token to return through
/// [`DebugEngine::set_scope`] rather than a record to edit. [`DebugEngine::scope_guard`] is the
/// usual way to use one.
///
/// Compares by value, so "the scope did not move" is a thing a caller can assert.
#[derive(Clone, PartialEq)]
pub struct Scope {
    instruction: u64,
    frame: DEBUG_STACK_FRAME,
    /// The target's register context, verbatim. Empty when the scope carries none — see
    /// [`DebugEngine::scope`].
    context: Vec<u8>,
    /// Which target this was read from, so a restore cannot land on a later one. See
    /// [`DebugEngine::target_identity`].
    target: u64,
}

impl Scope {
    /// The instruction the scope is on — frame 0's program counter, unless a frame or a
    /// register context was selected, in which case it is that one's.
    pub fn instruction_offset(&self) -> u64 {
        self.instruction
    }

    /// The frame the scope names, as the engine walked it.
    pub fn frame(&self) -> &DEBUG_STACK_FRAME {
        &self.frame
    }

    /// Whether the scope carries a register context.
    ///
    /// `false` is a legitimate scope rather than a failed read: a target with no thread context
    /// to offer still has a position, and restoring a scope that never had a context must not —
    /// and does not — fail.
    pub fn has_context(&self) -> bool {
        !self.context.is_empty()
    }
}

impl std::fmt::Debug for Scope {
    /// Summarizes the context rather than printing it: the blob is a kilobyte of register
    /// state whose bytes mean nothing outside the engine, and a derived `Debug` puts all of
    /// it in every log line and assertion message that mentions a scope.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scope")
            .field("instruction", &format_args!("{:#x}", self.instruction))
            .field("frame", &self.frame.FrameNumber)
            .field(
                "frame_offset",
                &format_args!("{:#x}", self.frame.FrameOffset),
            )
            .field("context", &format_args!("{} bytes", self.context.len()))
            .field("target", &self.target)
            .finish()
    }
}

/// What kind of event a breakpoint watches for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointKind {
    /// Execution reaching an address (`bp`).
    Code,
    /// Access to a range of memory (`ba`).
    Data,
    /// A type this build does not name, kept as the engine's own code.
    Other(u32),
}

impl BreakpointKind {
    fn from_engine(code: u32) -> Self {
        match code {
            DEBUG_BREAKPOINT_CODE => Self::Code,
            DEBUG_BREAKPOINT_DATA => Self::Data,
            other => Self::Other(other),
        }
    }
}

/// One breakpoint the engine holds, as [`DebugEngine::breakpoints`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakpointInfo {
    /// The id the debugger prints and `bc`/`bd`/`be` take.
    pub id: u32,
    pub kind: BreakpointKind,
    /// Where it will fire, or `None` while it is [deferred](Self::deferred) — its module is not
    /// loaded, so it has no address yet. Never zero for "unknown".
    pub address: Option<u64>,
    /// The expression the engine is still holding this breakpoint as — in practice a deferred
    /// one (`hevd!Trigger+0x40` for a driver that has not loaded). A breakpoint that resolved
    /// when it was set keeps its [address](Self::address) instead and the engine no longer holds
    /// the text, so `None` here is the normal case for a live breakpoint, not a gap.
    pub expression: Option<String>,
    /// The command string the debugger runs each time it fires, where it has one.
    pub command: Option<String>,
    /// The thread it is restricted to, or `None` for any thread.
    pub thread: Option<u32>,
    pub enabled: bool,
    /// Waiting for its module to load, and therefore not yet resolved to an address.
    pub deferred: bool,
    /// Removes itself the first time it fires.
    pub one_shot: bool,
    /// How many times it must be reached before it stops the target (1 = every time).
    pub pass_count: u32,
    /// How many of those passes are still to go.
    pub passes_remaining: u32,
}

/// Reads a string out of one of DbgEng's two-call string getters.
///
/// They all take the same shape — a buffer, its length, and an out-parameter for the size the
/// engine wanted — and they all truncate silently when the buffer is short. So the size is asked
/// for first with no buffer at all, and the read that follows is exactly big enough; a name that
/// grew between the two calls (it cannot here — nothing is running) would still be NUL-terminated
/// rather than clipped mid-way.
fn read_engine_string(
    mut get: impl FnMut(Option<&mut [u8]>, Option<*mut u32>) -> windows::core::Result<()>,
) -> windows::core::Result<String> {
    let mut needed = 0u32;
    get(None, Some(&mut needed))?;
    if needed <= 1 {
        return Ok(String::new());
    }
    let mut buffer = vec![0u8; needed as usize];
    get(Some(&mut buffer), None)?;
    Ok(nul_terminated(&buffer))
}

/// Splits one rendered disassembly line into its byte and mnemonic columns.
///
/// The line is `<address> <bytes> <mnemonic and operands>`, whitespace-separated, and the address
/// is discarded because the walk already knows it — reading it back would make the record depend
/// on a rendering it does not otherwise trust. Anything the shape does not fit keeps its whole
/// remainder as text, so an engine that renders differently loses a column rather than an
/// instruction.
fn split_instruction(address: u64, line: &str) -> Instruction {
    let mut columns = line.trim().splitn(3, char::is_whitespace);
    let (_address, bytes, rest) = (columns.next(), columns.next(), columns.next());
    match (bytes, rest) {
        (Some(bytes), Some(rest)) => Instruction {
            address,
            bytes: bytes.to_string(),
            text: collapse_spaces(rest),
        },
        // One column past the address, or none: keep it whole rather than calling it an encoding.
        (Some(only), None) => Instruction {
            address,
            bytes: String::new(),
            text: collapse_spaces(only),
        },
        _ => Instruction {
            address,
            bytes: String::new(),
            text: collapse_spaces(line),
        },
    }
}

/// Runs of whitespace as one space. The engine pads its columns to align them in a listing, and
/// the alignment means nothing once the columns are separate fields.
fn collapse_spaces(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The text up to the first NUL in an engine-filled buffer.
fn nul_terminated(buffer: &[u8]) -> String {
    let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

/// Hands out a fresh identity for every engine, and again whenever one releases its
/// target. Caches that ask "is this still the same target?" cannot use the kernel base
/// alone — two dumps from one boot share it — and dbgeng holds one debuggee session per
/// process, so per-engine identity plus a bump on release covers every case.
static NEXT_TARGET_IDENTITY: AtomicU64 = AtomicU64::new(1);

fn next_target_identity() -> u64 {
    NEXT_TARGET_IDENTITY.fetch_add(1, Ordering::Relaxed)
}

/// The identity currently in force for each debug client, so one **outlives the wrapper it was
/// issued to**.
///
/// A borrowed engine is built afresh around the same `IDebugClient6` for every extension
/// command, so its identity has to be stable across those wrappers or each command misses every
/// cache. Deriving it from the client pointer did that, and lost each wrapper's lifecycle with
/// the wrapper: an `end_session` bumped a field on a value dropped moments later, so the next
/// wrapper restored the original pointer-derived identity and could be served a snapshot
/// gathered from the target before it. The identity lives here instead, where the bump survives.
///
/// An entry is only ever cache warmth. Forgetting one costs a re-resolve and a re-walk, never a
/// stale answer, since a fresh identity matches nothing — which is why this can simply drop
/// everything when it grows rather than needing an eviction policy to reason about.
///
/// **What it does not fix**: a client the *host* released, with another allocated at the same
/// address, inherits the first one's identity. Every client this code creates itself reissues
/// instead — see [`DebugEngine::new`] and [`DebugEngine::create_from_windbg_client`] — so what
/// is left is the case we cannot observe. That was equally true of the pointer-derived scheme
/// this replaces, and closing it needs an identity read from the debuggee rather than from the
/// client holding it.
fn client_identities() -> &'static Mutex<HashMap<usize, u64>> {
    static IDENTITIES: OnceLock<Mutex<HashMap<usize, u64>>> = OnceLock::new();
    IDENTITIES.get_or_init(Mutex::default)
}

/// How many clients' identities to remember before dropping the lot; see [`client_identities`]
/// for why dropping them is safe. Sized well past the handful of clients any real host holds —
/// the extension reuses exactly one — so reaching it means something is creating clients in a
/// loop, and that is the case worth bounding.
const MAX_REMEMBERED_CLIENTS: usize = 64;

fn client_key(client: &IDebugClient6) -> usize {
    client.as_raw() as usize
}

/// The registry, recovered if a thread panicked while holding it.
///
/// Poisoning carries nothing here: the map holds `u64` and no invariant a panic could leave
/// half-applied. Propagating it would, though — `from_client_interface` is infallible, so one
/// unrelated panic would turn every later wrap into a second one. Same recovery as
/// [`DebugEngine::release_deferred_inputs`].
fn locked_identities() -> MutexGuard<'static, HashMap<usize, u64>> {
    client_identities()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The identity in force for `client`, issuing one if this is the first wrapper to ask.
fn identity_of(client: &IDebugClient6) -> u64 {
    identity_for(client_key(client))
}

/// Issues a fresh identity for `client` and records it, so nothing cached against the target it
/// is letting go of can be handed to a later wrapper around the same client.
fn reissue_identity(client: &IDebugClient6) -> u64 {
    reissue_for(client_key(client))
}

/// The two above, over the key rather than the COM pointer it comes from — which is all the
/// registry deals in, and all a test of it needs.
fn identity_for(key: usize) -> u64 {
    let mut identities = locked_identities();
    // Only a client we have never seen can push the map over its cap, and only then is
    // anything dropped. Clearing before the lookup would take the identity of the very client
    // being asked about — a live one, mid-session — and hand it a new one, which is a cache
    // thrown away for the caller that arrived rather than for the ones that left.
    if !identities.contains_key(&key) && identities.len() >= MAX_REMEMBERED_CLIENTS {
        identities.clear();
    }
    *identities.entry(key).or_insert_with(next_target_identity)
}

fn reissue_for(key: usize) -> u64 {
    let identity = next_target_identity();
    locked_identities().insert(key, identity);
    identity
}

pub struct DebugEngine {
    client: IDebugClient6,
    control: IDebugControl4,
    dataspaces: IDebugDataSpaces4,
    symbols: IDebugSymbols3,
    /// Whether this engine opened its own session (via `DebugCreate`) and is thus
    /// responsible for ending it on `Drop`. False when wrapping a borrowed WinDbg
    /// client, so going out of scope can't stop the host's active session.
    owns_session: bool,
    /// Input buffers handed to DbgEng by a *deferred* call — `CreateProcessWide`, which
    /// spawns at the next `WaitForEvent` and reads the command line then, and the kernel
    /// connection string, whose link is likewise established during the wait.
    ///
    /// They live here, not in [`PendingTarget`], because the engine is what DbgEng reads
    /// them on behalf of and the guard's lifetime is the caller's to end. A guard that
    /// owned them would be a use-after-free the moment it was dropped without waiting — and
    /// the alternative, waiting from `Drop`, can block without bound on a kernel attach
    /// whose link is still coming up (`SetInterrupt` cannot cancel that wait; see
    /// [`DebugEngine::wait_for_event_bounded`]). Owning them here costs one small
    /// allocation per open, released when the session ends.
    ///
    /// **Why not release each entry as soon as its `wait()` succeeds?** It looks safe — the
    /// spawn has happened, the link is up — but that is an inference about DbgEng's
    /// internals, not a documented guarantee, and `.restart` re-launches a process from the
    /// original command line. If the engine kept the caller's pointer for that, an early
    /// release would be a use-after-free, which is the one bug this field exists to prevent.
    /// End of session is the only release point that needs no such inference. The cost is a
    /// per-open allocation retained until then, and — for a *borrowed* client, which never
    /// reaches `end_session` — retained for good. Verifying on hardware that DbgEng does not
    /// re-read the buffer (drive `.restart` after a `launch_process`) is what would make a
    /// tighter release safe.
    deferred_inputs: Mutex<Vec<TargetInput>>,
    /// Whether an interrupt has been raised on this engine and not yet accounted for. Shared with
    /// every [`InterruptHandle`] this engine hands out; see there for what it buys.
    interrupt_raised: Arc<AtomicBool>,
}

impl Default for DebugEngine {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl Sync for DebugEngine {}
unsafe impl Send for DebugEngine {}

impl DebugEngine {
    /// Creates a new instance of the Debug Engine client
    pub fn new() -> Self {
        // Create the debug client
        let client: IDebugClient6 =
            unsafe { windows::Win32::System::Diagnostics::Debug::Extensions::DebugCreate() }
                .expect("[-] Failed to create debug client");

        // We opened this session, so we own its teardown.
        let mut engine = Self::from_client_interface(client);
        engine.owns_session = true;
        // A client this new cannot be one anything holds a cached view of — whatever address
        // it landed on. Reissuing rather than adopting whatever `identity_of` found there is
        // what makes a recycled pointer harmless for the case we control.
        reissue_identity(&engine.client);
        engine
    }

    pub fn from_windbg_client(client: &IUnknown) -> Self {
        let client: IDebugClient6 = client.cast().expect("[-] Failed to cast debug client");
        Self::from_client_interface(client)
    }

    /// Fallible counterpart used by native extension callbacks.  Extension entry
    /// points must translate bad client interfaces to HRESULTs instead of panicking.
    pub fn try_from_windbg_client(client: &IUnknown) -> Result<Self, DbgEngError> {
        let client: IDebugClient6 = client.cast().map_err(|source| DbgEngError::Context {
            operation: "querying IDebugClient6".into(),
            source,
        })?;
        Self::try_from_client_interface(client)
    }

    pub fn create_from_windbg_client(client: &IUnknown) -> Self {
        let client: IDebugClient6 = client.cast().expect("[-] Failed to cast debug client");
        let new_client = unsafe {
            client
                .CreateClient()
                .expect("[-] Failed to create debug client")
        }
        .cast::<IDebugClient6>()
        .expect("[-] Failed to cast debug client");
        // `CreateClient` hands back a client this code just made, so — exactly as in `new` — it
        // cannot be one anything holds a cached view of, whatever address it landed on.
        // Adopting what `identity_of` found there would inherit a released client's identity
        // the moment the allocator reused its address.
        let engine = Self::from_client_interface(new_client);
        reissue_identity(&engine.client);
        engine
    }

    pub fn from_client_interface(client: IDebugClient6) -> Self {
        let control: IDebugControl4 = client
            .cast::<IDebugControl4>()
            .expect("[-] Failed to get debug control interface");

        let dataspaces: IDebugDataSpaces4 = client
            .cast::<IDebugDataSpaces4>()
            .expect("[-] Failed to get debug data spaces interface");

        let symbols: IDebugSymbols3 = client
            .cast::<IDebugSymbols3>()
            .expect("[-] Failed to get debug symbols interface");

        Self {
            client,
            control,
            dataspaces,
            symbols,
            // Default to "borrowed": constructors that wrap an existing WinDbg client
            // go through here, and only `new()` (which calls `DebugCreate`) sets this.
            owns_session: false,
            deferred_inputs: Mutex::new(Vec::new()),
            interrupt_raised: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn try_from_client_interface(client: IDebugClient6) -> Result<Self, DbgEngError> {
        let control = client
            .cast::<IDebugControl4>()
            .map_err(|source| DbgEngError::Context {
                operation: "querying IDebugControl4".into(),
                source,
            })?;
        let dataspaces =
            client
                .cast::<IDebugDataSpaces4>()
                .map_err(|source| DbgEngError::Context {
                    operation: "querying IDebugDataSpaces4".into(),
                    source,
                })?;
        let symbols = client
            .cast::<IDebugSymbols3>()
            .map_err(|source| DbgEngError::Context {
                operation: "querying IDebugSymbols3".into(),
                source,
            })?;
        Ok(Self {
            client,
            control,
            dataspaces,
            symbols,
            owns_session: false,
            deferred_inputs: Mutex::new(Vec::new()),
            interrupt_raised: Arc::new(AtomicBool::new(false)),
        })
    }

    /// A handle another thread can use to Ctrl+Break whatever this engine is running.
    ///
    /// The engine stays confined to its own thread; this is the one thing about it that may be
    /// touched from outside, and only because `SetInterrupt` is documented as safe there. See
    /// [`InterruptHandle`].
    pub fn interrupt_handle(&self) -> InterruptHandle {
        InterruptHandle {
            control: self.control.clone(),
            raised: Arc::clone(&self.interrupt_raised),
        }
    }

    /// A value that identifies the target this engine currently holds.
    ///
    /// Changes when the engine is replaced *or* when it releases its target, so a cache
    /// keyed on it cannot serve data gathered from a previous target. The kernel base is
    /// not sufficient on its own: two dumps from the same boot share it.
    ///
    /// Read from the registry keyed on this engine's *client* — see [`client_identities`] —
    /// rather than from a copy taken when this wrapper was built. Two things follow, and both
    /// are the point:
    ///
    /// - a host that rebuilds its engine around one client, as a WinDbg extension does per
    ///   command, keeps its caches across the rebuild *and* cannot lose a release an earlier
    ///   wrapper performed;
    /// - two wrappers coexisting around one client agree. A copy in each would not: an
    ///   `end_session` through one would move that one and the registry, leaving the other
    ///   answering with an identity whose target is gone, and a cache keyed on it would be
    ///   served for whatever was opened next.
    ///
    /// A client whose entry was dropped to keep the registry bounded is issued a later
    /// identity here, never an earlier one. That costs a re-walk, and — in the one case that
    /// compares two reads, [`Self::set_scope`] — a restore refused rather than a restore onto
    /// the wrong target. Both are the safe direction.
    pub fn target_identity(&self) -> u64 {
        identity_of(&self.client)
    }

    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>, DbgEngError> {
        let size_u32 = u32::try_from(size).map_err(|_| DbgEngError::BufferTooLarge(size))?;
        let mut buffer = vec![0; size];
        let mut read = 0u32;
        unsafe {
            self.dataspaces.ReadVirtual(
                address,
                buffer.as_mut_ptr().cast(),
                size_u32,
                Some(&mut read),
            )
        }
        .map_err(|source| DbgEngError::Context {
            operation: format!("reading {size} bytes of virtual memory at {address:#x}"),
            source,
        })?;
        if read as usize != size {
            return Err(DbgEngError::ShortRead {
                address,
                requested: size,
                actual: read as usize,
            });
        }

        Ok(buffer)
    }

    pub fn kernel_base(&self) -> Result<u64, DbgEngError> {
        let name = CString::new("nt").unwrap();
        let mut base = 0u64;
        unsafe {
            self.symbols.GetModuleByModuleName(
                PCSTR::from_raw(name.as_ptr().cast()),
                0,
                None,
                Some(&mut base),
            )
        }
        .map_err(|source| DbgEngError::Context {
            operation: "discovering the nt kernel base".into(),
            source,
        })?;
        Ok(base)
    }

    /// Where `nt` is loaded **and which build it is**.
    ///
    /// The base alone does not identify a kernel. Two targets from different Windows builds can
    /// load `nt` at the same address — the debugger says nothing about the change — so anything
    /// caching type offsets or globals against a base can serve one build's layout for another
    /// and mis-decode every structure it reads, confidently. That is what this exists for; see
    /// [`Self::kernel_base`] when only the address is wanted.
    ///
    /// `TimeDateStamp` and `SizeOfImage` are the identity a symbol server keys the *binary* on
    /// — the `65F579991450000` in a downloaded `ntkrnlmp.exe` path is exactly this pair — so
    /// they change with the build by construction. `CheckSum` comes along because it is in the
    /// same read and narrows it further.
    ///
    /// One caveat worth knowing: a target whose headers the engine could not read reports these
    /// as zero, and two such builds at one base are indistinguishable again. That is the state
    /// this replaced, not a regression from it.
    pub fn kernel_image(&self) -> Result<KernelImage, DbgEngError> {
        let base = self.kernel_base()?;
        let mut params = DEBUG_MODULE_PARAMETERS::default();
        // Looked up by base rather than by index: `GetModuleByModuleName` hands back an
        // address, and asking for the parameters of *that* module is one call, where finding
        // its index first would be two and could race a module list that changed between them.
        unsafe {
            self.symbols
                .GetModuleParameters(1, Some(&base), 0, &mut params)
        }
        .map_err(|source| DbgEngError::Context {
            operation: format!("reading the parameters of the kernel image at {base:#x}"),
            source,
        })?;
        Ok(KernelImage {
            base,
            size: params.Size,
            timestamp: params.TimeDateStamp,
            checksum: params.Checksum,
        })
    }

    pub fn symbol_offset(&self, name: &str) -> Result<u64, DbgEngError> {
        let name = CString::new(name).map_err(|_| DbgEngError::InvalidCommand)?;
        unsafe {
            self.symbols
                .GetOffsetByName(PCSTR::from_raw(name.as_ptr().cast()))
        }
        .map_err(|source| DbgEngError::Context {
            operation: format!("resolving symbol {}", name.to_string_lossy()),
            source,
        })
    }

    pub fn type_id(&self, module: u64, name: &str) -> Result<u32, DbgEngError> {
        let name = CString::new(name).map_err(|_| DbgEngError::InvalidCommand)?;
        unsafe {
            self.symbols
                .GetTypeId(module, PCSTR::from_raw(name.as_ptr().cast()))
        }
        .map_err(|source| DbgEngError::Context {
            operation: format!("resolving type {}", name.to_string_lossy()),
            source,
        })
    }

    pub fn type_size(&self, module: u64, type_id: u32) -> Result<u32, DbgEngError> {
        unsafe { self.symbols.GetTypeSize(module, type_id) }.map_err(|source| {
            DbgEngError::Context {
                operation: format!("resolving size of type id {type_id}"),
                source,
            }
        })
    }

    pub fn field_offset(&self, module: u64, type_id: u32, field: &str) -> Result<u32, DbgEngError> {
        let field = CString::new(field).map_err(|_| DbgEngError::InvalidCommand)?;
        unsafe {
            self.symbols
                .GetFieldOffset(module, type_id, PCSTR::from_raw(field.as_ptr().cast()))
        }
        .map_err(|source| DbgEngError::Context {
            operation: format!("resolving field {}", field.to_string_lossy()),
            source,
        })
    }

    /// Resolve a field's PDB type id and byte offset in one DbgEng call.
    pub fn field_type_and_offset(
        &self,
        module: u64,
        type_id: u32,
        field: &str,
    ) -> Result<(u32, u32), DbgEngError> {
        let field = CString::new(field).map_err(|_| DbgEngError::InvalidCommand)?;
        let mut field_type = 0u32;
        let mut offset = 0u32;
        unsafe {
            self.symbols.GetFieldTypeAndOffset(
                module,
                type_id,
                PCSTR::from_raw(field.as_ptr().cast()),
                Some(&mut field_type),
                Some(&mut offset),
            )
        }
        .map_err(|source| DbgEngError::Context {
            operation: format!(
                "resolving type and offset of field {}",
                field.to_string_lossy()
            ),
            source,
        })?;
        Ok((field_type, offset))
    }

    /// Enumerate the named fields DbgEng exposes for a PDB type.
    ///
    /// DbgEng has no field-count getter. Its documented enumeration contract is consecutive
    /// indices ending at the first failed `GetFieldName`, so a corrupt provider cannot turn
    /// this into an unbounded loop.
    pub fn field_names(&self, module: u64, type_id: u32) -> Vec<String> {
        const MAX_FIELDS: u32 = 4096;
        let mut fields = Vec::new();
        for index in 0..MAX_FIELDS {
            let name = read_engine_string(|buffer, size| unsafe {
                self.symbols
                    .GetFieldName(module, type_id, index, buffer, size)
            });
            match name {
                Ok(name) if !name.is_empty() => fields.push(name),
                Ok(_) | Err(_) => break,
            }
        }
        fields
    }

    /// The PEB of DbgEng's current process.
    pub fn current_process_peb(&self) -> Result<u64, DbgEngError> {
        let objects: IDebugSystemObjects =
            self.client.cast().map_err(|source| DbgEngError::Context {
                operation: "obtaining the system-objects interface".into(),
                source,
            })?;
        unsafe { objects.GetCurrentProcessPeb() }.map_err(|source| DbgEngError::Context {
            operation: "reading the current process PEB".into(),
            source,
        })
    }

    /// The operating-system process id of DbgEng's current process.
    pub fn current_process_system_id(&self) -> Result<u32, DbgEngError> {
        let objects: IDebugSystemObjects =
            self.client.cast().map_err(|source| DbgEngError::Context {
                operation: "obtaining the system-objects interface".into(),
                source,
            })?;
        unsafe { objects.GetCurrentProcessSystemId() }.map_err(|source| DbgEngError::Context {
            operation: "reading the current process id".into(),
            source,
        })
    }

    pub fn valid_virtual_region(
        &self,
        base: u64,
        size: usize,
    ) -> Result<(u64, usize), DbgEngError> {
        let size_u32 = u32::try_from(size).map_err(|_| DbgEngError::BufferTooLarge(size))?;
        let mut valid_base = 0;
        let mut valid_size = 0;
        unsafe {
            self.dataspaces
                .GetValidRegionVirtual(base, size_u32, &mut valid_base, &mut valid_size)
        }
        .map_err(|source| DbgEngError::Context {
            operation: format!("querying valid virtual region at {base:#x}"),
            source,
        })?;
        Ok((valid_base, valid_size as usize))
    }

    pub fn interrupted(&self) -> Result<bool, DbgEngError> {
        // The generated windows wrapper calls HRESULT::ok(), which deliberately
        // maps both S_OK and S_FALSE to Ok(()). GetInterrupt uses that distinction:
        // S_OK means Ctrl+C was requested and S_FALSE means it was not.
        let result = unsafe {
            (Interface::vtable(&self.control).GetInterrupt)(Interface::as_raw(&self.control))
        };
        match result {
            S_OK => Ok(true),
            S_FALSE => Ok(false),
            result => Err(DbgEngError::Context {
                operation: "polling debugger interrupt".into(),
                source: windows::core::Error::from_hresult(HRESULT(result.0)),
            }),
        }
    }

    fn output_inner(&self, text: &str, dml: bool) -> Result<(), DbgEngError> {
        // DbgEng's output parameter is printf-style. Doubling percent signs makes
        // user-controlled tags and diagnostics data rather than format directives.
        let escaped = text.replace('%', "%%");
        let message = CString::new(escaped).map_err(|_| DbgEngError::InvalidOutput)?;
        let outctl = if dml {
            DEBUG_OUTCTL_THIS_CLIENT | 0x20
        } else {
            DEBUG_OUTCTL_THIS_CLIENT
        };
        unsafe {
            self.control.ControlledOutput(
                outctl,
                DEBUG_OUTPUT_NORMAL,
                PCSTR::from_raw(message.as_ptr().cast()),
            )
        }
        .map_err(|source| DbgEngError::Context {
            operation: "writing debugger output".into(),
            source,
        })
    }

    pub fn output(&self, text: &str) -> Result<(), DbgEngError> {
        self.output_inner(text, false)
    }

    pub fn output_dml(&self, text: &str) -> Result<(), DbgEngError> {
        self.output_inner(text, true)
    }

    pub fn execution_status(&self) -> Result<u32, DbgEngError> {
        unsafe { self.control.GetExecutionStatus() }.map_err(|source| DbgEngError::Context {
            operation: "querying target execution status".into(),
            source,
        })
    }

    pub fn processor_type(&self) -> Result<u32, DbgEngError> {
        unsafe { self.control.GetActualProcessorType() }.map_err(|source| DbgEngError::Context {
            operation: "querying target processor type".into(),
            source,
        })
    }

    pub fn is_kernel_target(&self) -> Result<bool, DbgEngError> {
        let mut class = 0;
        let mut qualifier = 0;
        unsafe { self.control.GetDebuggeeType(&mut class, &mut qualifier) }.map_err(|source| {
            DbgEngError::Context {
                operation: "querying target type".into(),
                source,
            }
        })?;
        Ok(class == DEBUG_CLASS_KERNEL)
    }

    /// Asks the engine to break in as soon as a freshly attached target initializes
    /// (the equivalent of kd's `-b`), so a kernel attach stops the target at the
    /// connection's first event instead of letting it run free.
    fn request_initial_break(&self) -> Result<(), DbgEngError> {
        unsafe { self.control.AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK) }
            .map_err(DbgEngError::OperationFailed)
    }

    /// Disarms the initial-break option once the target has stopped, so subsequent
    /// `go`/step run to real breakpoints instead of immediately re-breaking. Best-effort.
    fn clear_initial_break(&self) {
        unsafe {
            let _ = self.control.RemoveEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
        }
    }

    /// Breaking into a live kernel via INITIAL_BREAK leaves *one further* break-in
    /// pending: the next resume re-breaks immediately at `nt!DbgBreakPointWithStatus`
    /// (the "CTRL+C/CTRL+BREAK" artifact) before the target makes progress. Consume it
    /// here — resume once and let it re-break — so the target is left cleanly halted and
    /// the caller's first real `go`/step runs to an actual breakpoint. Best-effort.
    fn absorb_initial_break_artifact(&self) {
        // The spurious re-break fires immediately on resume; a short bound keeps this
        // from hanging if (unexpectedly) it doesn't.
        let _ = self.execute_and_wait("g", 5_000);
    }

    /// Whether the current target is a *live* kernel connection (net/1394/serial/local/
    /// EXDI/IDNA) as opposed to a kernel dump or a user-mode target. A live kernel
    /// requires an INFINITE `WaitForEvent` timeout; a finite one returns `E_NOTIMPL`.
    fn is_live_kernel(&self) -> bool {
        let mut class = 0u32;
        let mut qualifier = 0u32;
        if unsafe { self.control.GetDebuggeeType(&mut class, &mut qualifier) }.is_err() {
            return false;
        }
        // Dump qualifiers are >= DEBUG_KERNEL_SMALL_DUMP; live connections are below it.
        class == DEBUG_CLASS_KERNEL && qualifier < DEBUG_KERNEL_SMALL_DUMP
    }

    /// Attaches to the local kernel and breaks in.
    ///
    /// Returns an error rather than panicking when the attach fails (e.g. the host
    /// was not booted with local kernel debugging enabled), so callers driving the
    /// engine on a worker thread can surface a clean message instead of unwinding.
    ///
    /// Fuses the attach with the break-in wait, so a failure cannot say which half
    /// failed. Use [`Self::attach_local_kernel_begin`] when that matters.
    pub fn attach_local_kernel(&self) -> Result<(), DbgEngError> {
        self.attach_local_kernel_begin()?.wait()
    }

    /// [`Self::attach_local_kernel`] up to — and not including — the break-in wait.
    ///
    /// An `Ok` means the engine has claimed the local kernel as its target, so attaching
    /// again is no longer a clean retry. See [`PendingTarget`].
    pub fn attach_local_kernel_begin(&self) -> Result<PendingTarget<'_>, DbgEngError> {
        self.request_initial_break()?;
        unsafe {
            self.client
                .AttachKernel(DEBUG_ATTACH_LOCAL_KERNEL, None)
                .map_err(DbgEngError::AttachFailed)?;
        }
        // A live kernel needs an INFINITE WaitForEvent (a finite timeout returns
        // E_NOTIMPL); INITIAL_BREAK makes it stop at the first event. `wait()` bounds it
        // so an unresponsive target can't hang the engine thread forever.
        Ok(PendingTarget::new(self, WaitKind::KernelBreakIn))
    }

    /// Attaches to a kernel over a connection string (e.g. `net:port=50000,key=...`)
    /// and breaks in.
    ///
    /// Returns an error rather than panicking when the connection string is invalid or
    /// the attach fails (e.g. the transport/port is already owned by another debugger).
    ///
    /// # Blocks indefinitely if the target never connects
    ///
    /// **This call has no effective upper bound.** If the guest does not dial in — powered
    /// off, unreachable, wrong key, or (most commonly) not booted with `bcdedit /debug on` —
    /// it blocks in the transport like `kd` does, and the `KERNEL_ATTACH_WAIT_MS` watchdog
    /// cannot cancel it: `SetInterrupt` only reaches a wait whose target has *connected*.
    /// Measured at over 300s against a 60s bound before the run was killed.
    ///
    /// [`DbgEngError::KernelBreakTimeout`] therefore covers only a target that connects and
    /// *then* fails to break in — not the far more common case of one that never connects.
    ///
    /// Callers that must stay responsive (a server, an MCP endpoint) need a **separate process
    /// they can kill**. Moving the call to a worker thread and abandoning it is not a recovery:
    /// detaching a `JoinHandle` frees nothing, so the thread, its stack, this `DebugEngine`, its
    /// COM objects and the claimed transport endpoint all live on, still blocked, for the life
    /// of the process. Retrying then leaks another set and can find the endpoint still held.
    /// Nothing can interrupt the wait from outside, so the only way to reclaim the resources is
    /// to exit the process holding them.
    ///
    /// Fuses the attach with the break-in wait, so a failure cannot say which half
    /// failed. Use [`Self::attach_kernel_begin`] when that matters.
    pub fn attach_kernel(&self, connection_string: &str) -> Result<(), DbgEngError> {
        self.attach_kernel_begin(connection_string)?.wait()
    }

    /// [`Self::attach_kernel`] up to — and not including — the break-in wait.
    ///
    /// An `Ok` means the engine has taken the connection, so dialing again is no longer a
    /// clean retry — it re-dials a link that may already be up. See [`PendingTarget`].
    pub fn attach_kernel_begin(
        &self,
        connection_string: &str,
    ) -> Result<PendingTarget<'_>, DbgEngError> {
        let connection =
            CString::new(connection_string).map_err(|_| DbgEngError::InvalidCommand)?;

        self.request_initial_break()?;
        unsafe {
            self.client
                .AttachKernel(
                    DEBUG_ATTACH_KERNEL_CONNECTION,
                    PCSTR::from_raw(connection.as_ptr() as *const u8),
                )
                .map_err(DbgEngError::AttachFailed)?;
        }
        // Live kernel: INFINITE wait is mandatory (finite → E_NOTIMPL). INITIAL_BREAK
        // above makes the engine stop once the KDNET link establishes, and `wait()` bounds
        // it so an unreachable target can't hang the engine thread forever. The connection
        // string rides along because that link is only established during the wait.
        self.retain_deferred_input(TargetInput::Ansi(connection));
        Ok(PendingTarget::new(self, WaitKind::KernelBreakIn))
    }

    /// Shared tail of the kernel attach paths: wait (bounded) for the INITIAL_BREAK stop,
    /// clear the option, and absorb the one spurious re-break it leaves. Returns
    /// [`DbgEngError::KernelBreakTimeout`] if the target never broke in within the bound,
    /// rather than reporting a false success.
    ///
    /// That covers a target that *connects* and then fails to break in — wedged, or spinning
    /// somewhere the break-in cannot be serviced. A target that never connects at all does not
    /// reach this error: the watchdog cannot interrupt a dial that has not established its
    /// link, so the wait blocks instead — see [`Self::wait_for_event_bounded`]. Note that a
    /// guest not booted with `bcdedit /debug on` is the *second* case, not the first: it never
    /// dials, so it hangs rather than timing out.
    fn wait_for_kernel_break_in(&self) -> Result<(), DbgEngError> {
        let (waited, timed_out) = self.wait_for_event_bounded(KERNEL_ATTACH_WAIT_MS);
        self.clear_initial_break();
        waited.map_err(DbgEngError::CommandFailed)?;
        // If the watchdog forced the wait to return, the target never reached its
        // INITIAL_BREAK on its own within the bound — the stop (if any) is a forced
        // Ctrl+Break, not the clean break-in. Report a timeout and skip the absorb (there
        // is no INITIAL_BREAK artifact to consume). Also treat a wait that returned with
        // no debuggee as a timeout, defensively.
        let status =
            unsafe { self.control.GetExecutionStatus() }.map_err(DbgEngError::CommandFailed)?;
        if timed_out || status == DEBUG_STATUS_NO_DEBUGGEE {
            return Err(DbgEngError::KernelBreakTimeout);
        }
        self.absorb_initial_break_artifact();
        Ok(())
    }

    /// Sets (replaces) the symbol search path.
    pub fn set_symbol_path(&self, symbol_path: &str) -> Result<(), DbgEngError> {
        let path = CString::new(symbol_path).map_err(|_| DbgEngError::InvalidCommand)?;
        unsafe {
            self.symbols
                .SetSymbolPath(PCSTR::from_raw(path.as_ptr() as *const u8))
                .map_err(DbgEngError::SymbolPathFailed)
        }
    }

    /// Appends a directory (or `srv*` spec) to the symbol search path, preserving the
    /// existing entries (e.g. the OS symbol server). Goes through the DbgEng API, so
    /// unlike the `.sympath+` command it takes only a path and cannot swallow trailing
    /// `;`-separated commands.
    pub fn append_symbol_path(&self, symbol_path: &str) -> Result<(), DbgEngError> {
        let path = CString::new(symbol_path).map_err(|_| DbgEngError::InvalidCommand)?;
        unsafe {
            self.symbols
                .AppendSymbolPath(PCSTR::from_raw(path.as_ptr() as *const u8))
                .map_err(DbgEngError::SymbolPathFailed)
        }
    }

    /// Executes a debug command and returns its full textual output.
    pub fn execute_command(&self, command: &str) -> Result<String, DbgEngError> {
        // DbgEng reads a NUL-terminated C string; a `&str` is not NUL-terminated,
        // so build a `CString` and keep it alive for the duration of `Execute`.
        let cmd_c = CString::new(command).map_err(|_| DbgEngError::InvalidCommand)?;
        let cmd = PCSTR::from_raw(cmd_c.as_ptr() as *const u8);

        // Buffer accumulates output across the many Output() callbacks DbgEng emits
        // (one per chunk/line) — it must append, not overwrite.
        let mut output_buffer = Vec::<u8>::with_capacity(4096);
        let output_callbacks = OutputCallbacks::new(&mut output_buffer);
        let output_interface: IDebugOutputCallbacks = output_callbacks.into();

        // Set the output callbacks
        unsafe {
            self.client
                .SetOutputCallbacks(Some(&output_interface))
                .map_err(DbgEngError::CommandFailed)?;
        }

        // Execute the command
        let result = unsafe {
            self.control
                .Execute(DEBUG_OUTCTL_THIS_CLIENT, cmd, DEBUG_EXECUTE_ECHO)
        };

        // Always detach the callbacks before `output_interface`/`output_buffer` drop.
        unsafe {
            let _ = self.client.SetOutputCallbacks(None);
        }

        result.map_err(DbgEngError::CommandFailed)?;

        Ok(String::from_utf8_lossy(&output_buffer).to_string())
    }

    /// Like [`Self::execute_command`], but **bounded**: a watchdog thread `SetInterrupt`s the
    /// engine after `timeout_ms` so a runaway command — most importantly a broad `s` memory
    /// search — aborts and frees the single engine thread instead of pinning it (every later
    /// call would otherwise block behind it). `SetInterrupt` is the one DbgEng call documented
    /// as safe from another thread (see [`InterruptHandle`]); a long command polls for it
    /// exactly as WinDbg's Ctrl+Break does.
    ///
    /// Returns [`CommandRun`]: whatever output was captured, **and** whether the command finished.
    /// A break — the watchdog's or a host's, through an [`InterruptHandle`] — is reported in
    /// `cut_short` rather than as an error, because the output up to it is the point; the `Execute`
    /// error it provokes is not surfaced. `timeout_ms == 0` disables the watchdog (equivalent to
    /// [`Self::execute_command`], plus the reporting).
    ///
    /// **Both facts, or neither is usable.** Returning the text alone makes an aborted command
    /// indistinguishable from one that ran, so every caller downstream has to be told through some
    /// side channel — and each place that is forgotten reports a break as a fact about the target.
    /// Returning the error alone throws the output away, which on an interrupted search is all
    /// there was. Callers that want the note a human reads should render it from `cut_short`; it
    /// deliberately does not go into the text, since prose in a return value is a fact the next
    /// caller has to string-match for.
    pub fn execute_command_bounded(
        &self,
        command: &str,
        timeout_ms: u32,
    ) -> Result<CommandRun, DbgEngError> {
        let cmd_c = CString::new(command).map_err(|_| DbgEngError::InvalidCommand)?;
        let cmd = PCSTR::from_raw(cmd_c.as_ptr() as *const u8);

        // Whatever was raised before this command belongs to the last one. A request that arrives
        // from here on is about what runs below; one left standing from an earlier operation would
        // otherwise make the *next* command swallow a genuine error as though it had been aborted.
        self.interrupt_raised.store(false, Ordering::SeqCst);

        let mut output_buffer = Vec::<u8>::with_capacity(4096);
        let output_callbacks = OutputCallbacks::new(&mut output_buffer);
        let output_interface: IDebugOutputCallbacks = output_callbacks.into();
        unsafe {
            self.client
                .SetOutputCallbacks(Some(&output_interface))
                .map_err(DbgEngError::CommandFailed)?;
        }

        // Arm a watchdog that Ctrl+Breaks the engine after `timeout_ms` so a long `Execute`
        // returns instead of hanging the engine thread. Mirrors `wait_for_event_bounded`.
        let done = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        let watchdog = (timeout_ms > 0).then(|| {
            let done_watch = Arc::clone(&done);
            let fired_watch = Arc::clone(&fired);
            let handle = self.interrupt_handle();
            let deadline = Duration::from_millis(timeout_ms as u64);
            thread::spawn(move || {
                let handle = handle; // move the whole (Send) handle, not just the raw field
                let start = Instant::now();
                loop {
                    if done_watch.load(Ordering::SeqCst) {
                        return;
                    }
                    if start.elapsed() >= deadline {
                        // Repeat in case a busy command swallows one interrupt.
                        let _ = handle.interrupt();
                        fired_watch.store(true, Ordering::SeqCst);
                    }
                    thread::sleep(Duration::from_millis(200));
                }
            })
        });

        let result = unsafe {
            self.control
                .Execute(DEBUG_OUTCTL_THIS_CLIENT, cmd, DEBUG_EXECUTE_ECHO)
        };

        done.store(true, Ordering::SeqCst);
        if let Some(w) = watchdog {
            let _ = w.join();
        }

        // Always detach the callbacks before `output_interface`/`output_buffer` drop.
        unsafe {
            let _ = self.client.SetOutputCallbacks(None);
        }

        let by_watchdog = fired.load(Ordering::SeqCst);
        // Either origin aborts the command the same way, so both take the recovery below; only the
        // note is the watchdog's alone. Swapped rather than read, so a request that arrived while
        // this command ran is accounted for here and cannot be charged to the next one.
        let interrupted = by_watchdog | self.interrupt_raised.swap(false, Ordering::SeqCst);
        if interrupted {
            // The watchdog may have raised `SetInterrupt` right as `Execute` finished (or fired
            // once more before we joined it), leaving a Ctrl+Break pending with no command
            // running. Consume it via `GetInterrupt`, which does clear the pending flag.
            //
            // Retained as insurance, not as a fix for an observed bug. Measured against dbgeng
            // 10.0.26100.1 on a user-mode target (see the `#[ignore]`d tests below, which are
            // the record): `GetInterrupt` clears the flag, and the flag is a flag rather than a
            // counter — three `SetInterrupt`s still take one poll to clear. But a pending
            // interrupt did *not* abort a following command in any case tried, short or long:
            // a `version` produced byte-identical output drained and undrained, and a 38s
            // interrupt-polling `.for` ran to completion either way (37.94s vs 37.91s). The
            // engine appears to reset the request when `Execute` begins a command, which is
            // also how WinDbg behaves — a Ctrl+Break pressed while idle does not kill the next
            // command you type.
            //
            // So this is a no-op on the engine it was measured against. It costs one call on an
            // already-exceptional path, the behaviour is undocumented by Microsoft and may vary
            // by engine version, and the live-kernel path was not measured — which is why it
            // stays rather than being deleted on the strength of one environment.
            let _ = self.interrupted();
        }
        // A watchdog-forced interrupt makes `Execute` fail (or return partial output); that is
        // expected, so only propagate a genuine (non-interrupted) error.
        if !interrupted {
            result.map_err(DbgEngError::CommandFailed)?;
        }

        Ok(CommandRun {
            output: String::from_utf8_lossy(&output_buffer).to_string(),
            // Which origin, not merely that one happened: the advice differs. A deadline says
            // "scope it and retry", a request says "you asked" — and only the caller that renders
            // for a human needs either.
            cut_short: match (by_watchdog, interrupted) {
                (true, _) => Some(Interruption::Deadline {
                    after_ms: timeout_ms,
                }),
                (false, true) => Some(Interruption::OnRequest),
                (false, false) => None,
            },
        })
    }

    /// Waits for the target to break
    pub fn wait_for_event(&self, timeout_ms: u32) -> Result<(), DbgEngError> {
        let result = unsafe { self.control.WaitForEvent(0, timeout_ms) };

        if result.is_err() {
            return Err(DbgEngError::CommandFailed(result.err().unwrap()));
        }

        Ok(())
    }

    /// `WaitForEvent` with the INFINITE timeout a live kernel requires, but **bounded**:
    /// after `timeout_ms` a watchdog thread Ctrl+Breaks the target via `SetInterrupt`
    /// (the one DbgEng call safe from another thread) so the wait returns instead of
    /// hanging the single engine thread forever — e.g. a `go`/step that never hits a
    /// breakpoint, or an attach whose target is reachable but won't break in.
    ///
    /// Returns the raw `WaitForEvent` result **and** a `bool` that is `true` when the
    /// watchdog had to force the return — in that case the stop is a forced Ctrl+Break,
    /// not the event the caller was waiting for, so callers must not treat it as a normal
    /// completion (e.g. an attach should report a timeout rather than a clean break-in).
    ///
    /// Limitation: `SetInterrupt` can only unblock a wait once the target is *connected*.
    /// A wait still establishing the KDNET link (e.g. an unreachable target) cannot be
    /// cancelled this way and will block like `kd` itself does on a dead connection.
    /// Measured (`cargo run --example kdtest -- --timeout-probe`, in-box dbgeng on Windows 11
    /// 26200): dialing a port nothing answers on returned from `AttachKernel` in ~8ms and was
    /// still blocked in this wait when killed at 300s — five times `timeout_ms`, no return.
    /// So the `bool` below can only ever be `true` for a target that connected; an
    /// unreachable one hangs instead of timing out.
    fn wait_for_event_bounded(&self, timeout_ms: u32) -> (windows::core::Result<()>, bool) {
        let done = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        let done_watch = Arc::clone(&done);
        let fired_watch = Arc::clone(&fired);
        let handle = self.interrupt_handle();
        let deadline = Duration::from_millis(timeout_ms as u64);
        let watchdog = thread::spawn(move || {
            let handle = handle; // capture the whole (Send) handle, not just the raw field
            let start = Instant::now();
            loop {
                if done_watch.load(Ordering::SeqCst) {
                    return;
                }
                if start.elapsed() >= deadline {
                    // Ctrl+Break a connected target so the engine thread's WaitForEvent
                    // returns with a stop. Repeat in case a busy target ignores one.
                    let _ = handle.interrupt();
                    fired_watch.store(true, Ordering::SeqCst);
                }
                thread::sleep(Duration::from_millis(300));
            }
        });
        let result = unsafe { self.control.WaitForEvent(0, WAIT_INFINITE) };
        done.store(true, Ordering::SeqCst);
        let _ = watchdog.join();
        (result, fired.load(Ordering::SeqCst))
    }

    /// Issues an execution-control command (`g`, `t`, `p`, `g-`, `t-`, `p-`, …) and
    /// drives it to the next stop.
    ///
    /// Unlike [`Self::execute_command`], commands that *resume* the target only set the
    /// engine running when `Execute` returns — the target doesn't actually move until
    /// `WaitForEvent` pumps it. This captures output across both the command and the
    /// resulting execution (so e.g. a "Breakpoint N hit" message is included), which is
    /// what makes go/step (and TTD forward/reverse navigation) actually advance.
    ///
    /// Reports [`Interruption::OnRequest`] in `cut_short` when a host asked for the break, so a
    /// caller can tell "the target stopped" from "somebody stopped it". A **deadline**-forced break
    /// is deliberately not reported: for go/step the watchdog's bound is an ordinary outcome — the
    /// target simply had not stopped yet — and callers already treat it as one.
    pub fn execute_and_wait(
        &self,
        command: &str,
        timeout_ms: u32,
    ) -> Result<CommandRun, DbgEngError> {
        // Whatever was raised before this belongs to the last operation; see
        // `execute_command_bounded`, which clears it for the same reason.
        self.interrupt_raised.store(false, Ordering::SeqCst);
        // Driving execution control (`g`/`t`/`p`/…) into an engine with no live
        // debuggee can push DbgEng into an access violation — a structured exception
        // that Rust's `catch_unwind` cannot trap, which tears down the whole process.
        // Refuse up front when there is nothing to run, returning a clean error.
        let status =
            unsafe { self.control.GetExecutionStatus() }.map_err(DbgEngError::CommandFailed)?;
        if status == DEBUG_STATUS_NO_DEBUGGEE {
            return Err(DbgEngError::NoDebuggee);
        }

        // A live kernel target requires an INFINITE WaitForEvent timeout; a finite one
        // returns E_NOTIMPL, so go/step would never advance. We instead wait INFINITE but
        // bound it with a watchdog (below), so `timeout_ms` still caps the wait without
        // hanging the engine thread. Dumps/TTD/user-mode use the timeout directly.
        let live_kernel = self.is_live_kernel();

        let cmd_c = CString::new(command).map_err(|_| DbgEngError::InvalidCommand)?;
        let cmd = PCSTR::from_raw(cmd_c.as_ptr() as *const u8);

        let mut output_buffer = Vec::<u8>::with_capacity(4096);
        let output_callbacks = OutputCallbacks::new(&mut output_buffer);
        let output_interface: IDebugOutputCallbacks = output_callbacks.into();

        unsafe {
            self.client
                .SetOutputCallbacks(Some(&output_interface))
                .map_err(DbgEngError::CommandFailed)?;
        }

        // Initiate execution, then pump events until the target stops again.
        let exec = unsafe {
            self.control
                .Execute(DEBUG_OUTCTL_THIS_CLIENT, cmd, DEBUG_EXECUTE_ECHO)
        };
        let waited = if exec.is_ok() {
            if live_kernel {
                // A forced break at the bound is a fine outcome for go/step (the target
                // simply hadn't stopped yet), so ignore the watchdog-fired flag here.
                self.wait_for_event_bounded(timeout_ms).0
            } else {
                unsafe { self.control.WaitForEvent(0, timeout_ms) }
            }
        } else {
            Ok(())
        };

        unsafe {
            let _ = self.client.SetOutputCallbacks(None);
        }

        // A break the *host* asked for makes both of these fail, exactly as it does in
        // `execute_command_bounded` — and for the same reason the output must survive it, since a
        // `go` stopped on request has still moved the target and the caller needs to see where to.
        let on_request = self.interrupt_raised.swap(false, Ordering::SeqCst);
        if on_request {
            // As there: consume anything the engine did not, so the next operation starts clean.
            let _ = self.interrupted();
        } else {
            exec.map_err(DbgEngError::CommandFailed)?;
            waited.map_err(DbgEngError::CommandFailed)?;
        }

        Ok(CommandRun {
            output: String::from_utf8_lossy(&output_buffer).to_string(),
            cut_short: on_request.then_some(Interruption::OnRequest),
        })
    }

    /// Runs the target until it reaches `address` and reports a **structured** stop reason
    /// instead of raw text. A [`RunToOutcome::Hit`] confirms empirically that the current
    /// input/state actually drives execution to that block.
    ///
    /// Uses an explicitly managed breakpoint ([`ScopedBreakpoint`]) plus a plain `g`, so the
    /// breakpoint is removed on *every* exit path — hit, stopped elsewhere, timed out, or
    /// errored. The caller's own breakpoints are untouched.
    ///
    /// Every target type uses one wait: `WaitForEvent(INFINITE)` bounded by the same watchdog
    /// as [`Self::execute_and_wait`], so `timeout_ms` caps it and a target that never reaches
    /// `address` is left broken in rather than running.
    ///
    /// A *finite* `WaitForEvent` is not usable here even where DbgEng accepts one. It returns
    /// `S_FALSE` with the target still running and the engine holding no current
    /// process/thread, and nothing recovers from that — a subsequent `SetInterrupt` plus
    /// `WaitForEvent` never delivers a break, because the engine is no longer pumping events.
    /// Commands needing a current process (`bl` among them) fail from then on.
    ///
    /// Classification is by the actual stop, not the watchdog: a hit at `address` landing in
    /// the same window the deadline passes still reports [`RunToOutcome::Hit`]; only a break
    /// *elsewhere* is [`RunToOutcome::StoppedElsewhere`], and a target that had to be forced
    /// to a halt is [`RunToOutcome::Timeout`].
    ///
    /// `timeout_ms == 0` means an *immediate* timeout — the watchdog's deadline has already
    /// passed on its first check, so it interrupts at once and the result is a
    /// [`RunToOutcome::Timeout`] with the target barely resumed. Note this is the opposite of
    /// [`Self::execute_command_bounded`], where `0` disables the watchdog entirely. The
    /// asymmetry is deliberate: there, an unbounded command is a documented escape hatch
    /// (plain `execute_command`), whereas here "no bound" would mean waiting forever for a
    /// target that may never reach `address`, hanging the single engine thread — the exact
    /// outcome the watchdog exists to prevent.
    pub fn run_to_address(
        &self,
        address: u64,
        timeout_ms: u32,
    ) -> Result<RunToResult, DbgEngError> {
        // Refuse when there's nothing to run (driving `g` with no debuggee can fault
        // DbgEng in a way `catch_unwind` can't trap — see `execute_and_wait`).
        let status =
            unsafe { self.control.GetExecutionStatus() }.map_err(DbgEngError::CommandFailed)?;
        if status == DEBUG_STATUS_NO_DEBUGGEE {
            return Err(DbgEngError::NoDebuggee);
        }
        // An explicitly managed breakpoint, not `g <addr>`. WinDbg's one-shot form auto-clears
        // only when *hit* and hands back no handle, so every other exit — stopped elsewhere,
        // timed out, errored — left it armed with no way to remove it, and a later unrelated
        // `g` passing `address` could stop there spuriously. This guard removes it on every
        // path, including the `?` returns below.
        let _breakpoint = ScopedBreakpoint::at(self, address)?;

        let cmd_c = CString::new("g").map_err(|_| DbgEngError::InvalidCommand)?;
        let cmd = PCSTR::from_raw(cmd_c.as_ptr() as *const u8);

        let mut output_buffer = Vec::<u8>::with_capacity(4096);
        let output_callbacks = OutputCallbacks::new(&mut output_buffer);
        let output_interface: IDebugOutputCallbacks = output_callbacks.into();
        unsafe {
            self.client
                .SetOutputCallbacks(Some(&output_interface))
                .map_err(DbgEngError::CommandFailed)?;
        }

        let exec = unsafe {
            self.control
                .Execute(DEBUG_OUTCTL_THIS_CLIENT, cmd, DEBUG_EXECUTE_ECHO)
        };
        // One wait for every target type: `WaitForEvent(INFINITE)` bounded by a watchdog that
        // Ctrl+Breaks at `timeout_ms`. A *finite* wait cannot be used here even where DbgEng
        // allows one — it returns S_FALSE with the target still running and the engine holding
        // no current process/thread, and no interrupt afterwards recovers it, because the
        // engine is no longer pumping events. `expired` is then simply "the watchdog fired".
        let (waited, expired) = if exec.is_ok() {
            let (waited, forced) = self.wait_for_event_bounded(timeout_ms);
            // A forced return is reported as `Ok`, so only a genuine failure propagates.
            let waited = if forced {
                Ok(())
            } else {
                waited.map_err(DbgEngError::CommandFailed)
            };
            (waited, forced)
        } else {
            (Ok(()), false)
        };

        unsafe {
            let _ = self.client.SetOutputCallbacks(None);
        }
        exec.map_err(DbgEngError::CommandFailed)?;
        waited?;

        let output = String::from_utf8_lossy(&output_buffer).to_string();

        if expired {
            // The watchdog has already broken the target in, so the caller is not left with a
            // running one. A hit landing in the same window as the deadline is still a hit, so
            // consult the instruction pointer before concluding otherwise — leniently, since a
            // failed read here means "no clean stop to report", which is the timeout.
            if self.instruction_pointer().ok() == Some(address) {
                return Ok(RunToResult {
                    outcome: RunToOutcome::Hit,
                    output,
                });
            }
            return Ok(RunToResult {
                outcome: RunToOutcome::Timeout,
                output,
            });
        }

        // The target stopped on its own.
        let rip = self.instruction_pointer()?;
        let outcome = if rip == address {
            RunToOutcome::Hit
        } else {
            RunToOutcome::StoppedElsewhere { stopped_at: rip }
        };
        Ok(RunToResult { outcome, output })
    }

    pub fn create_debug_event_context_callbacks(
        callback: Option<BreakpointCallback>,
    ) -> IDebugEventContextCallbacks {
        let callbacks = DebugEventContextCallbacks::new(callback);
        callbacks.into()
    }

    pub fn set_breakpoint_event_callbacks(&self, event_callbacks: IDebugEventContextCallbacks) {
        unsafe {
            self.client
                .SetEventContextCallbacks(Some(&event_callbacks))
                .expect("[-] Failed to set event callbacks");
        };
    }

    pub fn log(&self, message: &str) {
        let message = CString::new(message).expect("Failed to create CString");
        let message = PCSTR::from_raw(message.as_ptr() as *const u8);
        unsafe { self.control.Output(DEBUG_OUTPUT_NORMAL, message) }
            .expect("[-] Failed to log message");
    }

    /// Reloads symbols. `args` mirrors `.reload` arguments — e.g. "/f HEVD.sys" to
    /// force-load one module's symbols, or "" to reload all deferred modules.
    pub fn reload_symbols(&self, args: &str) -> Result<(), DbgEngError> {
        let args = CString::new(args).map_err(|_| DbgEngError::InvalidCommand)?;
        unsafe {
            self.symbols
                .Reload(PCSTR::from_raw(args.as_ptr() as *const u8))
                .map_err(DbgEngError::OperationFailed)
        }
    }

    /// Returns the current register set as formatted text (`r`).
    pub fn registers(&self) -> Result<String, DbgEngError> {
        self.execute_command("r")
    }

    /// Reads the engine's current [`Scope`], so it can be put back later.
    ///
    /// **What this is for.** Commands move the scope, and some move it as a side effect of
    /// answering an unrelated question. Measured against dbgeng `10.0.29547.1002` on four
    /// targets — a `0x13A` kernel bug check, a `0xD1` driver fault, a `0x9F` power-state
    /// watchdog, and a user-mode access violation: `!analyze -v` ends with the scope at the
    /// target's *default*, so a session that had frame 3 selected is on frame 0 afterwards, and
    /// one that had `.ecxr`'s context selected has lost it. Nothing was written to the debuggee
    /// — but two identical stack reads either side of the analysis describe different things,
    /// which is the same problem for a host that has to report which of its calls mutate state.
    /// Saving the scope first and restoring it after makes the analysis observably
    /// scope-neutral.
    ///
    /// The current thread and process are *not* part of a scope, and do not need restoring
    /// alongside one — for a better reason than "the analysis leaves them alone". It does move
    /// them: on the `0x9F`, where the thread `!analyze` blames is not the one the dump opens on,
    /// its output says `Implicit thread is now ffffe284fe4dd040` partway through. It puts them
    /// back before it returns, which the scope is precisely what it does *not* do.
    ///
    /// **Sizing the context blob.** `GetScope` neither reports nor negotiates the size of the
    /// context it wants: it rejects a buffer smaller than the target's `CONTEXT` with
    /// `E_INVALIDARG` and accepts any buffer at or above it, filling the front. (Measured on an
    /// x64 target, kernel and user-mode alike: 1231 bytes rejected, 1232 — the x64 `CONTEXT` —
    /// accepted, as is 4096.) So the ask walks [`SCOPE_CONTEXT_SIZES`] upward and keeps the
    /// first size the engine accepts, which is the smallest of them that covers the target's
    /// context. `sizeof(CONTEXT)` for *this* process would be the wrong number: the target's
    /// architecture is the engine's business, not the host's.
    ///
    /// **A scope with no register context is legitimate**, so if the engine will not answer the
    /// context form but will answer the contextless one (`GetScope` with no buffer, which is its
    /// own documented form), that is the scope — [`Scope::has_context`] says which happened, and
    /// [`Self::set_scope`] restores either.
    ///
    /// An engine with no target answers `E_UNEXPECTED` to both forms (measured: before any open,
    /// after `end_session`, and on a dump named but never waited for), and that comes back as an
    /// error rather than as an empty scope.
    pub fn scope(&self) -> Result<Scope, DbgEngError> {
        let mut refusal = None;
        for &size in SCOPE_CONTEXT_SIZES {
            let mut instruction = 0u64;
            let mut frame = DEBUG_STACK_FRAME::default();
            let mut context = vec![0u8; size as usize];
            match unsafe {
                self.symbols.GetScope(
                    Some(&mut instruction),
                    Some(&mut frame),
                    Some(context.as_mut_ptr().cast()),
                    size,
                )
            } {
                Ok(()) => {
                    return Ok(Scope {
                        instruction,
                        frame,
                        context,
                        target: self.target_identity(),
                    });
                }
                // "That buffer is too small for this target's context" — try the next size up.
                Err(why) if why.code() == E_INVALIDARG => refusal = Some(why),
                // Anything else is the engine declining to produce a context at all, which is
                // not the same as declining to produce a scope.
                Err(why) => {
                    refusal = Some(why);
                    break;
                }
            }
        }
        self.contextless_scope(refusal)
    }

    /// The scope with no register context — the fallback of [`Self::scope`], and the shape a
    /// target that has no thread context answers with. `refusal` is why the context form did
    /// not work, reported if this form fails too.
    fn contextless_scope(
        &self,
        refusal: Option<windows::core::Error>,
    ) -> Result<Scope, DbgEngError> {
        let mut instruction = 0u64;
        let mut frame = DEBUG_STACK_FRAME::default();
        unsafe {
            self.symbols
                .GetScope(Some(&mut instruction), Some(&mut frame), None, 0)
        }
        .map_err(|source| DbgEngError::Context {
            operation: "reading the debugger's scope".into(),
            // The context read is the one that was actually wanted, so its failure is the
            // one worth reporting when neither form works.
            source: refusal.unwrap_or(source),
        })?;
        Ok(Scope {
            instruction,
            frame,
            context: Vec::new(),
            target: self.target_identity(),
        })
    }

    /// Puts a [`Scope`] back — `.cxr`'s mechanism, with the engine's own bytes.
    ///
    /// Refused if the engine no longer holds the target the scope was read from: the frame and
    /// context describe *that* target's stack, and applying them to a later one would point the
    /// session at an address that means nothing there. This is the case a long-lived
    /// [`ScopeGuard`] hits when whatever it wrapped replaced the target underneath it.
    ///
    /// **What that check does and does not cover.** [`Self::target_identity`] is a per-engine
    /// generation, bumped when this engine is created and when `end_session` releases its
    /// target — so it catches the destructive case, a session ended and another opened, where
    /// the saved addresses are meaningless. It says nothing about *movement inside* one
    /// session, and there are two such cases:
    ///
    /// - **A different process or thread is current.** A scope is engine-global, not per-thread,
    ///   so a scope captured while one process was current is restored as-is while another is —
    ///   which is what `.cxr` does deliberately, and is wrong only if the caller did not mean it.
    ///   A guard wrapping one command is not exposed to this by a command that moves the thread
    ///   and moves it back, which is what `!analyze -v` was measured doing (see [`Self::scope`]):
    ///   what matters at the restore is where the thread ended up, not where it went.
    /// - **A borrowed WinDbg client whose host switched targets.** The identity is held per
    ///   client and reissued when an `end_session` goes through *this* engine, so a change
    ///   WinDbg makes on its own — opening another dump under an extension — does not move it.
    ///
    /// In both, the caller is the only one who can know, and a guard held across such a change
    /// restores a scope its target no longer means.
    pub fn set_scope(&self, scope: &Scope) -> Result<(), DbgEngError> {
        if scope.target != self.target_identity() {
            return Err(DbgEngError::ScopeFromAnotherTarget);
        }
        unsafe {
            self.symbols.SetScope(
                scope.instruction,
                Some(&scope.frame),
                // A scope that carried no context is restored as one: passing a buffer the
                // engine never gave us would be inventing register state.
                if scope.context.is_empty() {
                    None
                } else {
                    Some(scope.context.as_ptr().cast())
                },
                scope.context.len() as u32,
            )
        }
        .map_err(|source| DbgEngError::Context {
            operation: "restoring the debugger's scope".into(),
            source,
        })
    }

    /// Reads the current [`Scope`] and hands back a guard that restores it when dropped.
    ///
    /// The shape to wrap a scope-moving command in, because it puts the scope back on *every*
    /// path out — an early return, an error, a panic unwinding through the caller — which is
    /// exactly where a hand-written restore is forgotten:
    ///
    /// ```no_run
    /// # use win_kexp::dbgeng::DebugEngine;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let engine = DebugEngine::new();
    /// let analysis = {
    ///     let _scope = engine.scope_guard()?;
    ///     engine.execute_command("!analyze -v")?
    /// }; // the scope `!analyze` moved is back here
    /// # let _ = analysis;
    /// # Ok(())
    /// # }
    /// ```
    pub fn scope_guard(&self) -> Result<ScopeGuard<'_>, DbgEngError> {
        Ok(ScopeGuard {
            engine: self,
            saved: self.scope()?,
        })
    }

    /// The current register set as **values**, read through `IDebugRegisters`.
    ///
    /// The same registers [`Self::registers`] prints, minus the printing. `r` renders a target's
    /// context as a paragraph — `rax=0000000000000000 rbx=…`, the flags as mnemonics, the current
    /// instruction disassembled on the end — and a host that needs `rsp` as a number has to find
    /// it in there. That parse is the thing this exists to delete: the widths, the grouping and
    /// the flag spelling are all presentation, and they differ by processor, by target kind and by
    /// engine build.
    ///
    /// Every register the engine knows is returned, subregisters included (`eax` as well as
    /// `rax`), because which of those a caller wants depends on what they are doing —
    /// [`Register::subregister`] is how they narrow it.
    ///
    /// A register the engine cannot produce a value for is reported as
    /// [`RegisterValue::Unavailable`] rather than failing the call: a minidump carrying no
    /// floating-point state answers exactly that way for `st0`–`st7`, and losing the general
    /// registers over it would be absurd. An `Err` here means the *set* could not be read at all.
    pub fn register_values(&self) -> Result<Vec<Register>, DbgEngError> {
        let registers: IDebugRegisters =
            self.client.cast().map_err(|source| DbgEngError::Context {
                operation: "obtaining the register interface".into(),
                source,
            })?;
        let count =
            unsafe { registers.GetNumberRegisters() }.map_err(|source| DbgEngError::Context {
                operation: "counting the target's registers".into(),
                source,
            })?;
        let mut out = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut description = DEBUG_REGISTER_DESCRIPTION::default();
            let name = read_engine_string(|buffer, size| unsafe {
                registers.GetDescription(index, buffer, size, Some(&mut description))
            })
            .map_err(|source| DbgEngError::Context {
                operation: format!("describing register {index}"),
                source,
            })?;
            // Read one at a time rather than through `GetValues`, which fetches the whole bank in
            // one call: a bank read fails as a unit, and the failures worth surviving here are
            // per-register (the absent x87/vector state of a minidump). One call per register buys
            // the granularity that makes `Unavailable` an answer instead of an error.
            let mut value = DEBUG_VALUE::default();
            let value = match unsafe { registers.GetValue(index, &mut value) } {
                Ok(()) => RegisterValue::decode(&value),
                Err(_) => RegisterValue::Unavailable,
            };
            out.push(Register {
                name,
                value,
                subregister: description.Flags & DEBUG_REGISTER_SUB_REGISTER != 0,
            });
        }
        Ok(out)
    }

    /// The current instruction pointer, read typed via `IDebugRegisters` (no text parse).
    ///
    /// Public because "where is the target stopped?" is the question every host asks after
    /// resuming one, and the alternatives are all text: `r` to be parsed, or `? @$ip` to be read
    /// back out of `Evaluate expression:`.
    pub fn instruction_pointer(&self) -> Result<u64, DbgEngError> {
        let registers: IDebugRegisters =
            self.client.cast().map_err(|source| DbgEngError::Context {
                operation: "obtaining the register interface".into(),
                source,
            })?;
        unsafe { registers.GetInstructionOffset() }.map_err(|source| DbgEngError::Context {
            operation: "reading the instruction pointer".into(),
            source,
        })
    }

    /// The loaded modules, read through `IDebugSymbols3` — what `lm` renders above its
    /// `Unloaded modules:` line, as data.
    ///
    /// Ordered as the engine holds them (by load order), and **loaded modules only**. The tail of
    /// modules that have since unloaded is [`Self::unloaded_modules`]: a different question about
    /// a different kind of thing, and one `lm` does print, so a host rendering that text beside
    /// these values needs both to describe the same listing.
    ///
    /// [`Module::symbols`] is the column hosts most often reach into `lm` for — "does this
    /// module have real symbols, or is it deferred / export-only?" — and it is a value here
    /// rather than a parenthesised word.
    pub fn modules(&self) -> Result<Vec<Module>, DbgEngError> {
        let (loaded, _) = self.module_counts()?;
        self.module_range(0, loaded)
    }

    /// Locate a loaded module by the name used to qualify its symbols.
    pub fn module(&self, name: &str) -> Result<Module, DbgEngError> {
        let name = CString::new(name).map_err(|_| DbgEngError::InvalidCommand)?;
        let mut index = 0u32;
        let mut base = 0u64;
        unsafe {
            self.symbols.GetModuleByModuleName(
                PCSTR::from_raw(name.as_ptr().cast()),
                0,
                Some(&mut index),
                Some(&mut base),
            )
        }
        .map_err(|source| DbgEngError::Context {
            operation: format!("locating module {}", name.to_string_lossy()),
            source,
        })?;
        let mut params = DEBUG_MODULE_PARAMETERS::default();
        unsafe {
            self.symbols
                .GetModuleParameters(1, Some(&base), 0, &mut params)
        }
        .map_err(|source| DbgEngError::Context {
            operation: format!("reading parameters of module at {base:#x}"),
            source,
        })?;
        Ok(self.named_module(index, &params))
    }

    /// The exact PDB or symbol file DbgEng selected for `module_base`.
    pub fn module_symbol_file(&self, module_base: u64) -> Result<String, DbgEngError> {
        read_engine_string(|buffer, size| unsafe {
            self.symbols.GetModuleNameString(
                DEBUG_MODNAME_SYMBOL_FILE,
                DEBUG_ANY_ID,
                module_base,
                buffer,
                size,
            )
        })
        .map_err(|source| DbgEngError::Context {
            operation: format!("reading the symbol file for module at {module_base:#x}"),
            source,
        })
    }

    /// Image and symbol identity for a loaded module.
    pub fn module_identity(&self, name: &str) -> Result<ModuleIdentity, DbgEngError> {
        let module = self.module(name)?;
        let symbol_file = self.module_symbol_file(module.base)?;
        Ok(ModuleIdentity {
            name: module.name,
            image_name: module.image_name,
            loaded_image_name: module.loaded_image_name,
            symbol_file,
            symbols: module.symbols,
            base: module.base,
            size: module.size,
            timestamp: module.timestamp,
            checksum: module.checksum,
        })
    }

    /// The modules that have **unloaded**, which the engine keeps a bounded tail of and `lm`
    /// prints under `Unloaded modules:`.
    ///
    /// A different question from [`Self::modules`], and worth asking: a stack frame or a pool
    /// pointer into a driver that is no longer there resolves to no loaded module at all, and
    /// this tail is what names it. `!analyze` reads the same list.
    ///
    /// **Read through the same index space**, because that is how the engine exposes it:
    /// `GetNumberModules` returns the two counts, and the unloaded ones are
    /// [indexed after the loaded ones][counts] — indices `Loaded..Loaded + Unloaded`. So this is
    /// `GetModuleParameters` over that range, not a second enumeration.
    ///
    /// **Empty is an ordinary answer.** Windows does not track unloaded modules everywhere — for
    /// user-mode targets only since Server 2003, per the same page — and a target that tracks
    /// them has simply not unloaded anything yet. Neither is a failure, so both are `Ok(vec![])`.
    ///
    /// The fields that describe an image (`base`, `size`, the names) are the ones that were true
    /// when it was loaded; `symbols` says what the engine holds for it now, which is usually
    /// nothing.
    ///
    /// [counts]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugsymbols-getnumbermodules
    pub fn unloaded_modules(&self) -> Result<Vec<Module>, DbgEngError> {
        let (loaded, unloaded) = self.module_counts()?;
        self.module_range(loaded, unloaded)
    }

    /// How many modules the engine holds: `(loaded, unloaded)`.
    fn module_counts(&self) -> Result<(u32, u32), DbgEngError> {
        let mut loaded = 0u32;
        let mut unloaded = 0u32;
        unsafe { self.symbols.GetNumberModules(&mut loaded, &mut unloaded) }.map_err(|source| {
            DbgEngError::Context {
                operation: "counting the target's modules".into(),
                source,
            }
        })?;
        Ok((loaded, unloaded))
    }

    /// `count` modules starting at `start` in the engine's own index space.
    fn module_range(&self, start: u32, count: u32) -> Result<Vec<Module>, DbgEngError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        // One call for the whole range: the parameters are the engine's own bookkeeping and
        // cannot fail per-module the way a register read can.
        let mut params = vec![DEBUG_MODULE_PARAMETERS::default(); count as usize];
        unsafe {
            self.symbols
                .GetModuleParameters(count, None, start, params.as_mut_ptr())
        }
        .map_err(|source| DbgEngError::Context {
            operation: "reading module parameters".into(),
            source,
        })?;

        let mut out = Vec::with_capacity(count as usize);
        for (offset, params) in params.iter().enumerate() {
            out.push(self.named_module(start + offset as u32, params));
        }
        Ok(out)
    }

    /// The module holding `address`, or `None` if the address is in no loaded module.
    ///
    /// `None` is the ordinary answer, not a failure: a stack frame can point into a driver that
    /// was unloaded before the dump was written, or into pool. So the engine's "no module here"
    /// is reported as an absent module rather than as an error, and only a call that actually
    /// broke comes back as one.
    ///
    /// Asked of the engine (`GetModuleByOffset`) rather than answered by scanning
    /// [`Self::modules`], because these are not the same question: the engine's own containment
    /// test is what `module!Symbol` is resolved with, and a scan would additionally have to
    /// decide what to do about the modules whose ranges overlap. It is also much less work when
    /// the caller has a handful of addresses rather than a need for the whole table.
    pub fn module_at(&self, address: u64) -> Result<Option<Module>, DbgEngError> {
        let mut index = 0u32;
        match unsafe {
            self.symbols
                .GetModuleByOffset(address, 0, Some(&mut index), None)
        } {
            Ok(()) => {}
            // "No module holds this offset" — the answer this reports as `None`.
            //
            // Two codes, because the engine is not the only implementation and the documentation
            // names neither. `E_INVALIDARG` is what a real dbgeng 10.x answers, measured against a
            // kernel dump for a pool address, an unmapped kernel address and a null one — the
            // offset *is* the parameter it is calling incorrect. `E_NOINTERFACE` is what Wine's
            // dbgeng and the neighbouring `IDebugSymbols` lookups answer for not-found, so it is
            // accepted too rather than turned into an error on a host that answers that way.
            Err(why) if matches!(why.code(), E_INVALIDARG | E_NOINTERFACE) => return Ok(None),
            // Anything else is the lookup itself failing — no debuggee, a target that has gone
            // away — and reporting that as "the address is in no module" would turn a broken
            // engine into a stack frame attributed to nothing, which reads like a finding.
            Err(source) => {
                return Err(DbgEngError::Context {
                    operation: format!("locating the module holding {address:#x}"),
                    source,
                });
            }
        }
        let mut params = DEBUG_MODULE_PARAMETERS::default();
        // `Count = 1, Start = index`: the parameters for that one module.
        unsafe {
            self.symbols
                .GetModuleParameters(1, None, index, &mut params)
        }
        .map_err(|source| DbgEngError::Context {
            operation: format!("reading the parameters of the module at {address:#x}"),
            source,
        })?;
        Ok(Some(self.named_module(index, &params)))
    }

    /// Fills in a [`Module`]'s names from the engine, given parameters already read for it.
    ///
    /// Infallible by design: the parameters carry everything structural (base, size, symbol
    /// state), so a module whose *names* cannot be read is still a module, reported with empty
    /// name fields rather than dropped from the table or turned into an error.
    fn named_module(&self, index: u32, params: &DEBUG_MODULE_PARAMETERS) -> Module {
        let mut name = String::new();
        let mut image_name = String::new();
        let mut loaded_image_name = String::new();
        // Names come back in a single call with three buffers, each optional. Sized from the
        // parameters above rather than from a guess, because a loaded-image name is a full
        // path and truncating it silently would be worse than not reporting it.
        // A size of **zero** is not "no name": an unloaded module's parameters carry no sizes at
        // all, and the engine still has the (truncated) name `lm` prints for it under
        // `Unloaded modules:`. Measured on a kernel dump — every unloaded entry reports
        // `ModuleNameSize == 0` — where sizing from it produced fifty nameless modules. So a
        // reported size is believed and an absent one falls back to a path-sized buffer.
        let sized = |reported: u32| {
            vec![
                0u8;
                if reported == 0 {
                    MODULE_NAME_FALLBACK
                } else {
                    reported as usize
                }
            ]
        };
        let mut name_buffer = sized(params.ModuleNameSize);
        let mut image_buffer = sized(params.ImageNameSize);
        let mut loaded_buffer = sized(params.LoadedImageNameSize);
        let named = unsafe {
            self.symbols.GetModuleNames(
                index,
                0,
                Some(&mut image_buffer),
                None,
                Some(&mut name_buffer),
                None,
                Some(&mut loaded_buffer),
                None,
            )
        };
        if named.is_ok() {
            name = nul_terminated(&name_buffer);
            image_name = nul_terminated(&image_buffer);
            loaded_image_name = nul_terminated(&loaded_buffer);
        }
        Module {
            base: params.Base,
            size: params.Size,
            name,
            image_name,
            loaded_image_name,
            timestamp: params.TimeDateStamp,
            checksum: params.Checksum,
            symbols: SymbolKind::from_engine(params.SymbolType),
            user_mode: params.Flags & DEBUG_MODULE_USER_MODE != 0,
            unloaded: params.Flags & DEBUG_MODULE_UNLOADED != 0,
        }
    }

    /// The bug check this target stopped on, or `None` if it did not stop on one.
    ///
    /// `None` covers the two ordinary cases together — a live kernel simply broken into, and a
    /// kernel dump that is not a crash dump — because the engine reports both the same way: code
    /// zero, which is not a bug check code. Distinguishing them is a question about the *target*,
    /// not about this call.
    ///
    /// Fails on a user-mode target, where the engine has no bug check data to read at all. That
    /// is deliberately an error rather than `None`: "this process did not bug check" is not a
    /// fact about a process, and a caller that treats it as one is asking the wrong tool.
    pub fn bug_check(&self) -> Result<Option<BugCheck>, DbgEngError> {
        let mut code = 0u32;
        let mut parameters = [0u64; 4];
        let [arg1, arg2, arg3, arg4] = &mut parameters;
        unsafe {
            self.control
                .ReadBugCheckData(&mut code, arg1, arg2, arg3, arg4)
        }
        .map_err(|source| DbgEngError::Context {
            operation: "reading the target's bug check data".into(),
            source,
        })?;
        if code == 0 {
            return Ok(None);
        }
        Ok(Some(BugCheck { code, parameters }))
    }

    /// The current thread's stack, read through `IDebugControl` — what `k` renders, as data.
    ///
    /// Walked from the current context (`GetStackTrace` with zero offsets), so on a crash dump
    /// this is the stack of the thread the dump was written for, and on a live target the stack
    /// of whatever the engine is stopped in.
    ///
    /// Each frame carries the symbol the engine resolves its instruction pointer to, split into
    /// the `module!Symbol` name and the displacement past it. Both are `None`/zero rather than
    /// invented when nothing resolves — a driver with no PDB is exactly the case a caller needs
    /// to detect, so that it can fall back to `module+RVA` from [`Self::module_at`].
    ///
    /// `max_frames` bounds the walk. Zero frames is a legitimate ask and returns an empty stack
    /// without touching the engine.
    pub fn stack_frames(&self, max_frames: usize) -> Result<Vec<StackFrame>, DbgEngError> {
        if max_frames == 0 {
            return Ok(Vec::new());
        }
        let mut raw = vec![DEBUG_STACK_FRAME::default(); max_frames];
        let mut filled = 0u32;
        // Zero for all three offsets means "walk from the current register context", which is
        // what `k` does. Supplying them explicitly is for walking a stack that is not the
        // current one, which is a different question than this answers.
        unsafe {
            self.control
                .GetStackTrace(0, 0, 0, &mut raw, Some(&mut filled))
        }
        .map_err(|source| DbgEngError::Context {
            operation: "walking the current thread's stack".into(),
            source,
        })?;
        // Clamped to the buffer as well as to what the engine says it filled: `filled` is the
        // engine's own count, and trusting it past the allocation would be a trust decision this
        // does not need to make.
        raw.truncate((filled as usize).min(max_frames));
        Ok(raw
            .iter()
            .enumerate()
            .map(|(index, frame)| {
                let (symbol, displacement) = self.symbol_at(frame.InstructionOffset);
                StackFrame {
                    index: index as u32,
                    instruction_offset: frame.InstructionOffset,
                    return_offset: frame.ReturnOffset,
                    frame_offset: frame.FrameOffset,
                    stack_offset: frame.StackOffset,
                    symbol,
                    displacement,
                }
            })
            .collect())
    }

    /// Disassembles `count` instructions from `address` — what `u` renders, as data.
    ///
    /// Walks forward the way the engine does: each instruction's end is the next one's start, so
    /// every address here is the engine's own arithmetic rather than a length this code guessed.
    /// `count` bounds the walk; zero is a legitimate ask and returns nothing without touching the
    /// engine.
    ///
    /// **A short answer is a fact about the target, not an error.** Disassembly runs forward into
    /// whatever follows, and what follows the end of a function may be unmapped, unreadable, or
    /// not code at all. So a walk that cannot render its *first* instruction fails — there is
    /// nothing to report and the caller asked about that address specifically — while one that
    /// stops later returns what it has. A caller that needs to know compares the length it got
    /// with the length it asked for, exactly as [`Self::stack_frames`] expects.
    ///
    /// Flags are zero: the same rendering `u` produces by default, without the effective-address
    /// annotation, which is a fact about the *current register context* rather than about the
    /// instruction and would make two identical calls differ.
    pub fn disassemble(&self, address: u64, count: usize) -> Result<Vec<Instruction>, DbgEngError> {
        let mut out = Vec::with_capacity(count.min(64));
        let mut at = address;
        for _ in 0..count {
            let mut next = 0u64;
            let line = read_engine_string(|buffer, size| unsafe {
                self.control.Disassemble(at, 0, buffer, size, &mut next)
            });
            let line = match line {
                Ok(line) if !line.trim().is_empty() => line,
                // The first one failing is the caller's own question going unanswered; a later one
                // is the end of what can be read, and the instructions before it are still good.
                Ok(_) | Err(_) if !out.is_empty() => break,
                Ok(_) => {
                    return Err(DbgEngError::Context {
                        operation: format!("disassembling {at:#x}"),
                        source: S_FALSE.into(),
                    });
                }
                Err(source) => {
                    return Err(DbgEngError::Context {
                        operation: format!("disassembling {at:#x}"),
                        source,
                    });
                }
            };
            out.push(split_instruction(at, &line));
            // An engine that does not advance would spin here forever rendering one instruction.
            if next <= at {
                break;
            }
            at = next;
        }
        Ok(out)
    }

    /// The `module!Symbol` an address resolves to and how far past it the address is.
    ///
    /// Infallible: an address that resolves to nothing is the normal case for a module without
    /// symbols, and reporting it as a failure would make every unsymbolised frame fail a stack
    /// walk that is otherwise perfectly good.
    fn symbol_at(&self, address: u64) -> (Option<String>, u64) {
        let mut displacement = 0u64;
        let name = read_engine_string(|buffer, size| unsafe {
            self.symbols
                .GetNameByOffset(address, buffer, size, Some(&mut displacement))
        });
        match name {
            Ok(name) if !name.is_empty() => (Some(name), displacement),
            _ => (None, 0),
        }
    }

    /// The image name of the process the engine's context is currently in — what a bug check
    /// screen and `!analyze` call `PROCESS_NAME`.
    ///
    /// **Two different reads, because "the current process" means two different things.** On a
    /// user-mode target it is the debuggee, and the engine names it directly. On a kernel target
    /// `GetCurrentProcessExecutableName` answers with the *kernel image* — `ntkrnlmp.exe`, for
    /// every process there has ever been — which is not an answer, so the name is read out of the
    /// current `_EPROCESS` instead.
    ///
    /// The kernel path therefore needs symbols for `nt`. Without them it fails rather than
    /// falling back to the executable name: `ntkrnlmp.exe` presented as the crashing process is
    /// worse than no answer, because it looks like one.
    ///
    /// # Which field, and why it is not the obvious one
    ///
    /// `_EPROCESS::ImageFileName` is the obvious one and it is **15 bytes**, so it silently
    /// truncates: `mm_exploit_v5.exe` reads back as `mm_exploit_v5.`, which looks like a name and
    /// is not one. Measured against a real crash dump, where `!analyze` printed the full name
    /// beside this function's truncated one.
    ///
    /// So the audit name is preferred — `SeAuditProcessCreationInfo.ImageFileName`, an
    /// `OBJECT_NAME_INFORMATION` holding the full NT path, of which the leaf is taken. It is what
    /// `!analyze` reports. `ImageFileName` remains the fallback for a target whose audit name is
    /// not there to read (it is a pointer, and a partial dump need not have captured what it
    /// points at), because a truncated name beats no name.
    pub fn current_process_name(&self) -> Result<String, DbgEngError> {
        let system: IDebugSystemObjects =
            self.client.cast().map_err(|source| DbgEngError::Context {
                operation: "querying IDebugSystemObjects".into(),
                source,
            })?;
        if !self.is_kernel_target()? {
            return read_engine_string(|buffer, size| unsafe {
                system.GetCurrentProcessExecutableName(buffer, size)
            })
            .map_err(|source| DbgEngError::Context {
                operation: "reading the current process's image name".into(),
                source,
            });
        }
        // On a kernel target the "process data offset" is the current `_EPROCESS`.
        let process = unsafe { system.GetCurrentProcessDataOffset() }.map_err(|source| {
            DbgEngError::Context {
                operation: "locating the current process's EPROCESS".into(),
                source,
            }
        })?;
        let nt = self.kernel_base()?;
        let eprocess = self.type_id(nt, "_EPROCESS")?;
        if let Some(full) = self.audit_image_name(nt, eprocess, process) {
            return Ok(full);
        }
        let offset = self.field_offset(nt, eprocess, "ImageFileName")?;
        // `ImageFileName` is a fixed-size array, NUL-*padded* rather than NUL-terminated: a name
        // that fills it has no terminator at all, which is why the length is read from the type
        // and the result cut at the first NUL rather than parsed as a C string.
        let size = self
            .field_size(nt, eprocess, "ImageFileName")
            .unwrap_or(EPROCESS_IMAGE_NAME_LEN) as usize;
        let raw = self.read_memory(process.saturating_add(u64::from(offset)), size)?;
        Ok(nul_terminated(&raw))
    }

    /// The leaf of `SeAuditProcessCreationInfo.ImageFileName`, the full NT path of a process's
    /// image — `mm_exploit_v5.exe` where `_EPROCESS::ImageFileName` has only `mm_exploit_v5.`.
    ///
    /// Best-effort throughout, returning `None` rather than an error at every step: this is the
    /// *better* of two answers and the caller has the other one. It is several dereferences deep,
    /// and each of them is a page a partial crash dump is entitled not to have captured.
    ///
    /// The field's offset is resolved from symbols, because that is what moves between builds. The
    /// two structures it leads through are not read through symbols: `OBJECT_NAME_INFORMATION`
    /// begins with its `UNICODE_STRING`, and a `UNICODE_STRING` on x64 is `{u16 Length, u16
    /// MaximumLength, u32 pad, u64 Buffer}`. That is ABI, not a build detail.
    fn audit_image_name(&self, nt: u64, eprocess: u32, process: u64) -> Option<String> {
        let offset = self
            .field_offset(nt, eprocess, "SeAuditProcessCreationInfo")
            .ok()?;
        // The structure's single member is the `OBJECT_NAME_INFORMATION*`, so its address is the
        // structure's own.
        let name_info = u64::from_le_bytes(
            self.read_memory(process.checked_add(u64::from(offset))?, 8)
                .ok()?
                .try_into()
                .ok()?,
        );
        if name_info == 0 {
            return None;
        }
        let unicode_string = self.read_memory(name_info, 16).ok()?;
        let length = u16::from_le_bytes(unicode_string[0..2].try_into().ok()?) as usize;
        let buffer = u64::from_le_bytes(unicode_string[8..16].try_into().ok()?);
        // A zero-length or absurd name is not an answer. The bound is generous — an NT path can be
        // long — and exists only so a wild `Length` cannot ask for a huge read.
        if buffer == 0 || length == 0 || length > 2 * 1024 {
            return None;
        }
        let raw = self.read_memory(buffer, length).ok()?;
        let wide: Vec<u16> = raw
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let path = String::from_utf16_lossy(&wide);
        // The leaf, as `!analyze` prints it: the path is
        // `\Device\HarddiskVolume3\Users\Admin\mm_exploit_v5.exe`.
        let leaf = path.rsplit(['\\', '/']).next().unwrap_or(&path).trim();
        (!leaf.is_empty()).then(|| leaf.to_string())
    }

    /// The size of one field of a type, for a field whose length is part of its meaning.
    ///
    /// Best-effort — `None` rather than an error — because every caller has something sensible to
    /// do without it, and a type this build cannot measure is not a reason to fail a read whose
    /// offset resolved fine.
    fn field_size(&self, module: u64, type_id: u32, field: &str) -> Option<u32> {
        let name = CString::new(field).ok()?;
        let mut field_type = 0u32;
        let mut offset = 0u32;
        unsafe {
            self.symbols.GetFieldTypeAndOffset(
                module,
                type_id,
                PCSTR::from_raw(name.as_ptr().cast()),
                Some(&mut field_type),
                Some(&mut offset),
            )
        }
        .ok()?;
        self.type_size(module, field_type).ok()
    }

    /// Every breakpoint the engine holds, read through `IDebugControl` — what `bl` renders, as
    /// data.
    ///
    /// The distinction `bl` makes with a `u`/`e` letter and a blank address column is a typed one
    /// here: a deferred breakpoint has [`BreakpointInfo::address`] `None`, because its module is
    /// not loaded and it therefore *has* no address yet. Reporting that as zero would invent a
    /// breakpoint on the null page.
    pub fn breakpoints(&self) -> Result<Vec<BreakpointInfo>, DbgEngError> {
        let count = unsafe { self.control.GetNumberBreakpoints() }.map_err(|source| {
            DbgEngError::Context {
                operation: "counting breakpoints".into(),
                source,
            }
        })?;
        let mut out = Vec::with_capacity(count as usize);
        for index in 0..count {
            let breakpoint =
                unsafe { self.control.GetBreakpointByIndex(index) }.map_err(|source| {
                    DbgEngError::Context {
                        operation: format!("reading breakpoint at index {index}"),
                        source,
                    }
                })?;
            // Never released, exactly as in [`Breakpoint`]: DbgEng owns breakpoint objects and
            // hands out borrowed interfaces, so letting the generated wrapper `Release()` one is
            // a call on an object this code does not own. There is nothing to leak — the engine
            // frees them with the session.
            let breakpoint = std::mem::ManuallyDrop::new(breakpoint);
            let id = unsafe { breakpoint.GetId() }.map_err(|source| DbgEngError::Context {
                operation: format!("reading the id of breakpoint {index}"),
                source,
            })?;
            let mut kind = 0u32;
            let mut _processor = 0u32;
            let kind = match unsafe { breakpoint.GetType(&mut kind, &mut _processor) } {
                Ok(()) => BreakpointKind::from_engine(kind),
                Err(_) => BreakpointKind::Other(DEBUG_ANY_ID),
            };
            let flags = unsafe { breakpoint.GetFlags() }.unwrap_or(0);
            // A deferred breakpoint answers `GetOffset` with an error, and one whose expression
            // resolved to nothing answers with `DEBUG_INVALID_OFFSET`. Both mean "no address
            // yet", and neither means address zero.
            let address = match unsafe { breakpoint.GetOffset() } {
                Ok(offset) if offset != DEBUG_INVALID_OFFSET => Some(offset),
                _ => None,
            };
            let expression = read_engine_string(|buffer, size| unsafe {
                breakpoint.GetOffsetExpression(buffer, size)
            })
            .ok()
            .filter(|text| !text.is_empty());
            let command =
                read_engine_string(|buffer, size| unsafe { breakpoint.GetCommand(buffer, size) })
                    .ok()
                    .filter(|text| !text.is_empty());
            let thread = unsafe { breakpoint.GetMatchThreadId() }
                .ok()
                .filter(|id| *id != DEBUG_ANY_ID);
            out.push(BreakpointInfo {
                id,
                kind,
                address,
                expression,
                command,
                thread,
                enabled: flags & DEBUG_BREAKPOINT_ENABLED != 0,
                deferred: flags & DEBUG_BREAKPOINT_DEFERRED != 0,
                one_shot: flags & DEBUG_BREAKPOINT_ONE_SHOT != 0,
                pass_count: unsafe { breakpoint.GetPassCount() }.unwrap_or(0),
                passes_remaining: unsafe { breakpoint.GetCurrentPassCount() }.unwrap_or(0),
            });
        }
        Ok(out)
    }

    /// Ensures the engine breaks at the initial (loader) breakpoint. A bare
    /// `DebugCreate` host defaults this event filter to "ignore", so a freshly
    /// launched/attached target would run free and the engine would never establish a
    /// current process/thread (register/stack commands then fail with `0x80040205`).
    fn enable_initial_break(&self) -> Result<(), DbgEngError> {
        self.execute_command("sxe ibp").map(|_| ())
    }

    /// Launches a new user-mode process under the debugger and waits for it to stop at
    /// its initial breakpoint, leaving a current process/thread ready to inspect.
    ///
    /// Fuses the launch with the initial-break wait, so a failure cannot say which half
    /// failed. Use [`Self::launch_process_begin`] when that matters.
    pub fn launch_process(&self, command_line: &str) -> Result<(), DbgEngError> {
        self.launch_process_begin(command_line)?.wait()
    }

    /// [`Self::launch_process`] up to — and not including — the initial-break wait.
    ///
    /// An `Ok` means the session is committed even though the process has not started yet:
    /// `CreateProcessWide` is deferred, so the spawn happens inside the wait, and from the
    /// caller's side a retry would spawn a second process. See [`PendingTarget`].
    pub fn launch_process_begin(
        &self,
        command_line: &str,
    ) -> Result<PendingTarget<'_>, DbgEngError> {
        self.enable_initial_break()?;
        let mut wide = to_wide(command_line);
        unsafe {
            self.client.CreateProcessWide(
                0,
                PWSTR::from_raw(wide.as_mut_ptr()),
                DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
            )
        }
        .map_err(DbgEngError::OperationFailed)?;

        // `CreateProcessWide` is deferred: the engine doesn't actually spawn the process
        // until the next `WaitForEvent`, and it reads the command-line buffer (`wide`) at
        // that point — so `wide` moves into the guard, which owns it until the wait
        // returns. With the initial-breakpoint filter enabled above, that wait stops at
        // the loader breakpoint.
        self.retain_deferred_input(TargetInput::Wide(wide));
        Ok(PendingTarget::new(self, WaitKind::Live))
    }

    /// Attaches to an existing user-mode process by PID and waits for the break-in,
    /// leaving a current process/thread ready to inspect.
    ///
    /// Fuses the attach with the break-in wait, so a failure cannot say which half failed.
    /// Use [`Self::attach_process_begin`] when that matters.
    pub fn attach_process(&self, pid: u32) -> Result<(), DbgEngError> {
        self.attach_process_begin(pid)?.wait()
    }

    /// [`Self::attach_process`] up to — and not including — the break-in wait.
    ///
    /// An `Ok` means the debugger is attached to `pid`, so attaching again is no longer a
    /// clean retry — it attaches to the same process twice. See [`PendingTarget`].
    pub fn attach_process_begin(&self, pid: u32) -> Result<PendingTarget<'_>, DbgEngError> {
        self.enable_initial_break()?;
        unsafe { self.client.AttachProcess(0, pid, DEBUG_ATTACH_DEFAULT) }
            .map_err(DbgEngError::OperationFailed)?;
        // The attach completes during `WaitForEvent`, which breaks the target in.
        Ok(PendingTarget::new(self, WaitKind::Live))
    }

    /// Opens a crash dump (`.dmp`) or a Time Travel Debugging trace (`.run`).
    /// Call [`Self::wait_for_event`] afterward to finish loading the target.
    pub fn open_dump(&self, path: &str) -> Result<(), DbgEngError> {
        let wide = to_wide(path);
        unsafe {
            self.client
                .OpenDumpFileWide(PCWSTR::from_raw(wide.as_ptr()), 0)
        }
        .map_err(DbgEngError::OperationFailed)
    }

    /// Opens a TTD trace (`.run`); alias for [`Self::open_dump`].
    pub fn open_trace(&self, path: &str) -> Result<(), DbgEngError> {
        self.open_dump(path)
    }

    /// Parks an input buffer for the life of the session, so DbgEng can still read it when
    /// it completes a deferred spawn or dial. See [`DebugEngine::deferred_inputs`].
    fn retain_deferred_input(&self, input: TargetInput) {
        self.deferred_inputs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(input);
    }

    /// Releases the parked input buffers. Only sound once the session is over: until then
    /// the engine may still owe a deferred spawn or dial that reads them.
    fn release_deferred_inputs(&self) {
        self.deferred_inputs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Ends the current debug session without destroying the client, so it can be
    /// reused for another target.
    pub fn end_session(&self) -> Result<(), DbgEngError> {
        // The target is going away, so anything cached against it must not be reused for
        // whatever this engine holds next — nor by any other wrapper around this same client,
        // which is why the identity is recorded against the client rather than in this engine.
        reissue_identity(&self.client);
        // A live kernel left halted (at a break) and detached *passively* stays FROZEN —
        // one CPU halted, the rest spinning — because a passive detach never tells the
        // target to run. Resume it and actively detach instead, leaving it running.
        let ended = if self.is_live_kernel() {
            self.resume_and_detach_live_kernel()
        } else {
            unsafe { self.client.EndSession(DEBUG_END_PASSIVE) }
                .map_err(DbgEngError::OperationFailed)
        };
        // Released only once the session is *confirmed* torn down: an outstanding deferred
        // spawn or dial dies with it, so nothing can read these buffers afterwards. A failed
        // teardown may leave the session live and still owing that read, so the buffers stay
        // — retaining a few bytes for the life of the engine beats a use-after-free.
        if ended.is_ok() {
            self.release_deferred_inputs();
        }
        ended
    }

    /// Detaches from a live kernel leaving it **running**, not frozen at the last break.
    /// Clears breakpoints (restoring their patched `int3` bytes), sets the target to run,
    /// then does an *active* detach — which, unlike a passive one, communicates with the
    /// target to resume it before disconnecting.
    fn resume_and_detach_live_kernel(&self) -> Result<(), DbgEngError> {
        let _ = self.execute_command("bc *");
        unsafe {
            let _ = self.control.SetExecutionStatus(DEBUG_STATUS_GO);
            self.client.EndSession(DEBUG_END_ACTIVE_DETACH)
        }
        .map_err(DbgEngError::OperationFailed)
    }
}

impl Drop for DebugEngine {
    fn drop(&mut self) {
        // Only tear down sessions we opened ourselves. Wrapping a borrowed WinDbg
        // client must not end the host's active session when the wrapper drops.
        if !self.owns_session {
            // That session outlives this wrapper, so it may still complete a deferred spawn
            // or dial and read the parked input buffers — and nothing will ever tell us when
            // that is over. Leak them rather than free memory the host's engine still holds a
            // pointer to; `end_session` is the only place a release can be justified, and a
            // borrowed client never reaches it. Costs nothing unless a `*_begin` opener was
            // actually used on a borrowed client.
            std::mem::forget(std::mem::take(
                &mut *self
                    .deferred_inputs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()),
            ));
            return;
        }
        // Don't leave a live kernel frozen at a break if we're torn down without an
        // explicit end_session (e.g. the process exits): resume + actively detach.
        if self.is_live_kernel() {
            let _ = self.resume_and_detach_live_kernel();
            return;
        }
        // Best-effort teardown; ignore errors (e.g. when no session is active).
        unsafe {
            let _ = self.client.EndSession(DEBUG_END_PASSIVE);
        }
    }
}

/// Which initial-break wait completes a [`PendingTarget`].
#[derive(Clone, Copy)]
enum WaitKind {
    /// User-mode launch/attach: a finite `WaitForEvent`.
    Live,
    /// Kernel attach: the bounded INFINITE wait plus its INITIAL_BREAK bookkeeping.
    KernelBreakIn,
}

/// Input buffers DbgEng may still read *after* the target-creating call has returned,
/// held so the pointers handed to the engine stay valid across the seam.
///
/// `CreateProcessWide` is the documented case: the spawn is deferred until the next
/// `WaitForEvent`, and the engine reads the command line at that point. A kernel
/// connection string gets the same treatment, because the link it describes is likewise
/// only established during the wait — before the split its buffer stayed alive by accident
/// of scope, and freeing it early here would be a silent regression. Never read by this
/// crate; held only to own the allocation.
//
// The payloads are deliberately never read, so rustc reports them as dead and offers to
// replace them with `()`. Taking that suggestion would free the buffers at the end of the
// opener and hand DbgEng a dangling pointer during the wait — the exact bug this guards.
#[allow(dead_code)]
enum TargetInput {
    Wide(Vec<u16>),
    Ansi(CString),
}

/// A debug target that has been created or claimed, but not yet waited for.
///
/// Separates the two halves the openers otherwise fuse: the side effect that creates or
/// claims a target (`CreateProcessWide` / `AttachProcess` / `AttachKernel`) and the wait
/// for the resulting initial break. Fused, one `Err` covers both "nothing happened, the
/// slate is clean" and "the target exists and only the wait failed" — which need opposite
/// recovery, since re-running the first is correct and re-running the second spawns a
/// second process, attaches twice, or re-dials a live KD link.
///
/// Holding one of these means the side effect *succeeded*. A caller that tracks sessions
/// can commit that bookkeeping here, before a wait that may still fail or time out:
///
/// ```no_run
/// # use win_kexp::dbgeng::DebugEngine;
/// # fn commit(_: &str) {}
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let engine = DebugEngine::new();
/// let pending = engine.launch_process_begin("notepad.exe")?;
/// commit("session-1"); // the target is ours from here, even if the wait below fails
/// pending.wait()?;
/// # Ok(())
/// # }
/// ```
///
/// The type is what makes the ordering unforgeable: the guard cannot exist unless the side
/// effect returned `Ok`.
///
/// **Dropping the guard without calling [`wait`](Self::wait) is safe and cancels nothing.**
/// The engine has already been told to spawn or connect, and it completes that at the next
/// `WaitForEvent` from any source — `execute_and_wait` and `run_to_address` included —
/// reading the input buffers then. Those buffers live in the [`DebugEngine`] precisely so
/// this is sound whether or not the guard is waited on; dropping merely forfeits the
/// initial-break wait, leaving the target to materialize later.
///
/// There is deliberately no `Drop` impl. Driving the wait from one could hang without bound
/// on a kernel attach whose link is still coming up (`SetInterrupt` cannot cancel that wait),
/// and clearing that attach's `DEBUG_ENGOPT_INITIAL_BREAK` would half-cancel a request that
/// is still pending — the target would connect and keep *running* instead of stopping, which
/// is the one thing the attach asked for.
///
/// The cost, for an abandoned **kernel** guard only: `DEBUG_ENGOPT_INITIAL_BREAK` stays armed
/// for the session, since only [`Self::wait`] clears it. The pending attach still breaks in
/// as asked, but a later `go`/step can immediately re-break until something clears the
/// option. Abandoning a kernel attach is a poor way to change your mind; prefer `wait()` and
/// then `end_session`.
#[must_use = "the target was created but never waited for; call `wait()` to reach the initial break"]
pub struct PendingTarget<'a> {
    engine: &'a DebugEngine,
    kind: WaitKind,
}

impl<'a> PendingTarget<'a> {
    fn new(engine: &'a DebugEngine, kind: WaitKind) -> Self {
        Self { engine, kind }
    }

    /// Waits for the target's initial break, completing the open.
    ///
    /// For a kernel attach this can block **without bound** when the target never connects;
    /// see [`DebugEngine::attach_kernel`]. User-mode waits are bounded by `LIVE_WAIT_MS`.
    pub fn wait(self) -> Result<(), DbgEngError> {
        match self.kind {
            WaitKind::Live => self.engine.wait_for_event(LIVE_WAIT_MS),
            WaitKind::KernelBreakIn => self.engine.wait_for_kernel_break_in(),
        }
    }
}

/// Holds the [`Scope`] the engine was in, and puts it back when dropped.
///
/// From [`DebugEngine::scope_guard`]. The guard borrows the engine, so it cannot outlive it;
/// what it cannot promise is that the engine still holds the same *target* at drop time, and a
/// scope from a released target is refused rather than applied — see [`DebugEngine::set_scope`].
///
/// `Drop` cannot report anything, so a caller who needs to know the restore worked calls
/// [`Self::restore`] and reads the result; the drop afterwards then restores the same scope
/// again, which is a no-op the engine accepts.
#[must_use = "the scope is restored when this is dropped, so dropping it immediately restores nothing later"]
pub struct ScopeGuard<'a> {
    engine: &'a DebugEngine,
    saved: Scope,
}

impl ScopeGuard<'_> {
    /// The scope that will be restored — the engine's position when the guard was taken.
    pub fn saved(&self) -> &Scope {
        &self.saved
    }

    /// Restores the saved scope now, reporting whether it worked.
    pub fn restore(&self) -> Result<(), DbgEngError> {
        self.engine.set_scope(&self.saved)
    }
}

impl Drop for ScopeGuard<'_> {
    fn drop(&mut self) {
        // Best-effort: a failure here has nowhere to go, and this runs on unwind paths where
        // panicking would abort the process. A target that has gone away is the ordinary
        // failure, and it is refused inside `set_scope` rather than applied to its successor.
        let _ = self.engine.set_scope(&self.saved);
    }
}

// Output callbacks implementation to capture command output
#[windows::core::implement(
    windows::Win32::System::Diagnostics::Debug::Extensions::IDebugOutputCallbacks
)]
#[derive(Debug)]
pub struct OutputCallbacks {
    buffer: *mut Vec<u8>,
}

impl OutputCallbacks {
    fn new(buffer: &mut Vec<u8>) -> Self {
        Self {
            buffer: buffer as *mut Vec<u8>,
        }
    }
}

#[allow(non_snake_case)]
impl windows::Win32::System::Diagnostics::Debug::Extensions::IDebugOutputCallbacks_Impl
    for OutputCallbacks_Impl
{
    fn Output(&self, _mask: u32, text: &PCSTR) -> windows::core::Result<()> {
        // `self` (the generated `_Impl` wrapper) derefs to the inner `OutputCallbacks`,
        // so access the field directly. The previous `self as *const OutputCallbacks`
        // cast reinterpreted the COM wrapper's header as our struct (UB) — it read a
        // vtable pointer as `buffer` and corrupted memory.
        if text.is_null() {
            return Ok(());
        }
        let c_str = unsafe { std::ffi::CStr::from_ptr(text.0 as *const i8) };
        if let Ok(str_slice) = c_str.to_str() {
            // Append: DbgEng calls Output() once per chunk, so clearing here would
            // discard everything but the final chunk.
            unsafe {
                (*self.buffer).extend_from_slice(str_slice.as_bytes());
            }
        }
        Ok(())
    }
}

/// A breakpoint owned by a single operation and removed when that operation ends —
/// on success, on an early `?`, and on an unwind alike.
///
/// [`DebugEngine::run_to_address`] previously drove execution with WinDbg's one-shot
/// `g <addr>`, which DbgEng clears only when the breakpoint is *hit* and for which it hands
/// back no handle. Every other outcome therefore left it armed and unremovable, and a later
/// unrelated `g` passing `address` could stop there spuriously. Owning the handle is what
/// makes cleanup possible at all.
///
/// Distinct from [`Breakpoint`], which is a caller-managed handle with explicit
/// `enable`/`disable`/`remove` and no `Drop`.
struct ScopedBreakpoint<'a> {
    control: &'a IDebugControl4,
    breakpoint: std::mem::ManuallyDrop<IDebugBreakpoint2>,
}

impl<'a> ScopedBreakpoint<'a> {
    /// Adds an enabled code breakpoint at `address`.
    fn at(engine: &'a DebugEngine, address: u64) -> Result<Self, DbgEngError> {
        let breakpoint = unsafe {
            engine
                .control
                .AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID)
        }
        .map_err(DbgEngError::BreakpointFailed)?;
        // Wrapped before it is configured, so a failure below still removes it rather than
        // leaking a half-built breakpoint into the session.
        let scoped = Self {
            control: &engine.control,
            breakpoint: std::mem::ManuallyDrop::new(breakpoint),
        };
        unsafe {
            scoped
                .breakpoint
                .SetOffset(address)
                .map_err(DbgEngError::BreakpointFailed)?;
            scoped
                .breakpoint
                .AddFlags(DEBUG_BREAKPOINT_ENABLED)
                .map_err(DbgEngError::BreakpointFailed)?;
        }
        Ok(scoped)
    }
}

impl Drop for ScopedBreakpoint<'_> {
    fn drop(&mut self) {
        // Best-effort: a failure here has nowhere to go, and this runs on unwind paths where
        // panicking would abort the process.
        unsafe {
            let _ = self.control.RemoveBreakpoint2(&*self.breakpoint);
        }
        // `breakpoint` is deliberately not dropped. DbgEng owns breakpoint objects and
        // `RemoveBreakpoint2` destroys this one, so letting the generated wrapper `Release()`
        // it afterwards dereferences freed memory — observed as an access violation that took
        // down the host process, not as an error return. `ManuallyDrop` is what stops that.
    }
}

pub struct Breakpoint<'a> {
    control: &'a IDebugControl4,
    /// Never released by this wrapper: DbgEng owns breakpoint objects, and [`Self::remove`]
    /// destroys this one, so a `Release()` afterwards would be a use-after-free. See
    /// [`ScopedBreakpoint`], where the same hazard showed up as a host-process crash.
    breakpoint: std::mem::ManuallyDrop<IDebugBreakpoint>,
}

impl<'a> Breakpoint<'a> {
    pub fn new(engine: &'a DebugEngine) -> Result<Self, DbgEngError> {
        let breakpoint = unsafe {
            engine
                .control
                .AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID)
        };

        if breakpoint.is_err() {
            return Err(DbgEngError::BreakpointFailed(breakpoint.err().unwrap()));
        }

        Ok(Self {
            breakpoint: std::mem::ManuallyDrop::new(breakpoint.unwrap()),
            control: &engine.control,
        })
    }

    pub fn set_offset_expression(&self, expression: &str) -> Result<(), DbgEngError> {
        // Mirror execute_command: return an error on malformed input rather than panic.
        let expr = CString::new(expression).map_err(|_| DbgEngError::InvalidCommand)?;

        unsafe {
            self.breakpoint
                .SetOffsetExpression(PCSTR::from_raw(expr.as_ptr() as *const u8))
                .map_err(DbgEngError::BreakpointFailed)?;
        }
        Ok(())
    }

    pub fn enable(&self) {
        unsafe {
            self.breakpoint
                .AddFlags(DEBUG_BREAKPOINT_ENABLED)
                .expect("[-] Failed to set breakpoint offset");
        }
    }

    pub fn disable(&self) {
        unsafe {
            self.breakpoint
                .RemoveFlags(DEBUG_BREAKPOINT_ENABLED)
                .expect("[-] Failed to remove breakpoint offset");
        }
    }

    pub fn remove(&self) {
        unsafe {
            self.control
                .RemoveBreakpoint(&*self.breakpoint)
                .expect("[-] Failed to remove breakpoint");
        }
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::System::Diagnostics::Debug::Extensions::{
        DEBUG_VALUE_0, DEBUG_VALUE_INVALID, DEBUG_VALUE_TYPES,
    };

    use super::*;

    /// The engine renders one instruction as three columns. The split has to survive both
    /// architectures' padding, and it must take the address from the walk rather than from the
    /// line — the point of the record is that it is not a re-parse of a rendering.
    #[test]
    fn test_an_instruction_splits_into_its_encoding_and_its_mnemonic() {
        let x64 = split_instruction(
            0xfffff803_89201234,
            "fffff803`89201234 48895c2408      mov     qword ptr [rsp+8],rbx\n",
        );
        assert_eq!(x64.address, 0xfffff803_89201234);
        assert_eq!(x64.bytes, "48895c2408");
        assert_eq!(x64.text, "mov qword ptr [rsp+8],rbx");

        let arm64 = split_instruction(
            0xfffff803_89201234,
            "fffff803`89201234 a9bf7bfd     stp         fp,lr,[sp,#-0x10]!\n",
        );
        assert_eq!(arm64.bytes, "a9bf7bfd");
        assert_eq!(arm64.text, "stp fp,lr,[sp,#-0x10]!");
    }

    /// The address is the walk's, not the line's. Asserted against a line that disagrees, because
    /// agreeing lines cannot tell the two sources apart.
    #[test]
    fn test_an_instructions_address_comes_from_the_walk_not_the_rendering() {
        let one = split_instruction(0x1000, "deadbeef`deadbeef 90    nop");
        assert_eq!(one.address, 0x1000);
        assert_eq!(one.text, "nop");
    }

    /// An engine that renders a shape this does not know loses a column, never an instruction:
    /// the remainder is kept as text and nothing is presented as an encoding that is not one.
    #[test]
    fn test_an_unrecognised_line_keeps_its_text_rather_than_inventing_an_encoding() {
        let two_columns = split_instruction(0x1000, "fffff803`89201234 ????");
        assert!(two_columns.bytes.is_empty(), "{two_columns:?}");
        assert_eq!(two_columns.text, "????");

        let one_column = split_instruction(0x1000, "???");
        assert!(one_column.bytes.is_empty(), "{one_column:?}");
        assert_eq!(one_column.text, "???");
    }

    /// glslang/win-kexp#82: a borrowed engine's lifecycle used to die with the wrapper.
    ///
    /// The identity was the client pointer, so it was stable across the per-command wrappers an
    /// extension builds — which is what it was for — while an `end_session` bumped a field on a
    /// value dropped moments later. Rebuild the wrapper around the same client and the original
    /// pointer-derived identity came back, matching cache entries gathered from the target it
    /// had just let go of.
    ///
    /// One test rather than four: the registry is process-global, so separate tests could clear
    /// each other's entries through the cap below.
    #[test]
    fn test_a_clients_identity_outlives_the_wrapper_it_was_issued_to() {
        // Keys no real client pointer can collide with: an `IDebugClient6` is a heap
        // allocation, and these sit far below any address one lands at.
        let (client, other) = (0x11, 0x22);

        let first = identity_for(client);
        assert_eq!(
            identity_for(client),
            first,
            "a rebuilt wrapper keeps its caches"
        );
        assert_ne!(identity_for(other), first, "two clients are two targets");

        // The case that was lost: the wrapper that ends the session is gone by the time the
        // next one asks, so the bump has to be recorded against the client, not in the wrapper.
        let after_release = reissue_for(client);
        assert_ne!(after_release, first);
        assert_eq!(identity_for(client), after_release);

        // Forgetting an entry is safe by construction, and this is the claim that makes it so:
        // identities come from a counter that never repeats, so a dropped entry costs a re-walk
        // and can never resurrect a previous target's.
        for filler in 0..MAX_REMEMBERED_CLIENTS {
            identity_for(0x1000 + filler);
        }
        assert!(locked_identities().len() <= MAX_REMEMBERED_CLIENTS);
        assert!(
            identity_for(client) >= after_release,
            "a forgotten client is issued a later identity, never an earlier one"
        );

        // A client already known does not make room, because it does not need any. Clearing
        // before the lookup would take the identity of the very client being asked about — a
        // live one, mid-session — so the cap has to be reached with it present to see that.
        let mut identities = locked_identities();
        identities.clear();
        identities.insert(client, after_release);
        for filler in 1..MAX_REMEMBERED_CLIENTS {
            identities.insert(0x2000 + filler, next_target_identity());
        }
        assert_eq!(identities.len(), MAX_REMEMBERED_CLIENTS);
        drop(identities);
        assert_eq!(
            identity_for(client),
            after_release,
            "a client at the cap keeps the caches it is in the middle of using"
        );
        assert_eq!(locked_identities().len(), MAX_REMEMBERED_CLIENTS);

        // A client it has never seen is what makes room, and pays for it with everything.
        identity_for(0xbeef);
        assert!(locked_identities().len() < MAX_REMEMBERED_CLIENTS);
    }

    /// A `DEBUG_VALUE` carrying a value in the arm `type_code` names.
    fn tagged(type_code: u32, fill: impl FnOnce(&mut DEBUG_VALUE_0)) -> DEBUG_VALUE {
        let mut anonymous = DEBUG_VALUE_0::default();
        fill(&mut anonymous);
        DEBUG_VALUE {
            Anonymous: anonymous,
            TailOfRawBytes: 0,
            Type: type_code,
        }
    }

    /// The tag decides which arm is read, and nothing else does.
    ///
    /// Worth a test precisely because getting it wrong is invisible: every arm of the union
    /// occupies the same bytes, so a 32-bit register read as `I64` yields a number that looks
    /// like an answer. Each case below stores one arm and asserts the *other* interpretations do
    /// not leak into the result.
    #[test]
    fn a_register_value_is_read_by_the_arm_its_tag_names() {
        let int32 = tagged(DEBUG_VALUE_INT32, |v| v.I32 = 0xdead_beef);
        assert_eq!(
            RegisterValue::decode(&int32),
            RegisterValue::Int(0xdead_beef)
        );

        // The 64-bit arm of a value whose low half is the same bytes: read as I32 this would
        // silently drop the high half, which is the failure mode on every kernel pointer.
        let int64 = tagged(DEBUG_VALUE_INT64, |v| {
            v.Anonymous.I64 = 0xffff_8000_dead_beef
        });
        assert_eq!(
            RegisterValue::decode(&int64),
            RegisterValue::Int(0xffff_8000_dead_beef)
        );

        let byte = tagged(DEBUG_VALUE_INT8, |v| v.I8 = 0xff);
        assert_eq!(RegisterValue::decode(&byte), RegisterValue::Int(0xff));

        let float = tagged(DEBUG_VALUE_FLOAT64, |v| v.F64 = 1.5);
        assert_eq!(RegisterValue::decode(&float), RegisterValue::Float(1.5));
    }

    /// A vector register keeps all of its bytes, and an x87 one keeps its ten.
    ///
    /// The alternative — narrowing them to a scalar — is the one decoding choice that cannot be
    /// undone by the caller, so the width is pinned here.
    #[test]
    fn a_wide_register_keeps_every_byte() {
        let mut bytes = [0u8; 16];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let vector = tagged(DEBUG_VALUE_VECTOR128, |v| v.VI8 = bytes);
        assert_eq!(
            RegisterValue::decode(&vector),
            RegisterValue::Bytes(bytes.to_vec())
        );

        let half = tagged(DEBUG_VALUE_VECTOR64, |v| v.VI8 = bytes);
        assert_eq!(
            RegisterValue::decode(&half),
            RegisterValue::Bytes(bytes[..8].to_vec())
        );

        let x87 = tagged(DEBUG_VALUE_FLOAT80, |v| v.F80Bytes = [7u8; 10]);
        assert_eq!(
            RegisterValue::decode(&x87),
            RegisterValue::Bytes(vec![7u8; 10])
        );
    }

    /// A type this build does not decode is reported as having no value, never as a number.
    #[test]
    fn an_undecodable_register_is_unavailable_rather_than_zero() {
        let unknown = tagged(DEBUG_VALUE_TYPES + 1, |v| {
            v.Anonymous.I64 = 0xdead_beef_dead_beef
        });
        assert_eq!(RegisterValue::decode(&unknown), RegisterValue::Unavailable);

        let invalid = tagged(DEBUG_VALUE_INVALID, |v| v.Anonymous.I64 = 1);
        assert_eq!(RegisterValue::decode(&invalid), RegisterValue::Unavailable);
    }

    /// A symbol type this build does not name keeps the engine's code instead of collapsing
    /// into `None` — which a caller would read as "this module has no symbols".
    #[test]
    fn an_unknown_symbol_type_is_not_reported_as_having_no_symbols() {
        assert_eq!(SymbolKind::from_engine(DEBUG_SYMTYPE_PDB), SymbolKind::Pdb);
        assert_eq!(
            SymbolKind::from_engine(DEBUG_SYMTYPE_DEFERRED),
            SymbolKind::Deferred
        );
        assert_eq!(
            SymbolKind::from_engine(DEBUG_SYMTYPE_NONE),
            SymbolKind::None
        );
        assert_eq!(SymbolKind::from_engine(4242), SymbolKind::Other(4242));
        assert!(SymbolKind::Pdb.has_type_info());
        assert!(SymbolKind::Dia.has_type_info());
        assert!(!SymbolKind::Export.has_type_info());
        assert!(!SymbolKind::Deferred.has_type_info());
    }

    #[test]
    fn a_breakpoint_type_keeps_an_unknown_code() {
        assert_eq!(
            BreakpointKind::from_engine(DEBUG_BREAKPOINT_CODE),
            BreakpointKind::Code
        );
        assert_eq!(
            BreakpointKind::from_engine(DEBUG_BREAKPOINT_DATA),
            BreakpointKind::Data
        );
        assert_eq!(BreakpointKind::from_engine(9), BreakpointKind::Other(9));
    }

    /// Engine buffers are fixed-size and NUL-terminated, so the tail past the NUL is whatever
    /// was there before — never part of the name.
    #[test]
    fn a_name_stops_at_the_nul_the_engine_wrote() {
        assert_eq!(nul_terminated(b"nt\0junkjunk"), "nt");
        assert_eq!(nul_terminated(b"\0"), "");
        assert_eq!(nul_terminated(b"no terminator"), "no terminator");
    }

    #[cfg(not(miri))]
    #[test]
    fn test_create_debug_engine() {
        // Serialized like every other engine test: this one's `Drop` ends the process-wide
        // debuggee session, which is not this process's to end while another test holds one.
        let _debuggee = one_debuggee();
        // Create new debug engine instance
        let _ = DebugEngine::new();

        println!("Debug engine created successfully");

        // DebugEngine's Drop impl will handle cleanup and detach
    }

    /// The half of glslang/win-kexp#82 that a registry alone does not close, and the reason the
    /// identity is not a field: two wrappers can be live around one client at once.
    ///
    /// With a copy in each, an `end_session` through one moves that one and the registry and
    /// leaves the other answering with an identity whose target is gone — so a snapshot or
    /// layout cached against it is served for whatever is opened next, which is the same stale
    /// read the issue was about arriving through a second wrapper instead of a later one.
    #[cfg(not(miri))]
    #[test]
    fn test_every_live_wrapper_sees_a_release_through_any_of_them() {
        // Serialized like every other engine test: this one's `Drop` ends the process-wide
        // debuggee session.
        let _debuggee = one_debuggee();
        let owner = DebugEngine::new();
        // A second wrapper around the *same* client, which is what an extension builds per
        // command. `clone` bumps the COM refcount and keeps the pointer, so both agree.
        let borrowed = DebugEngine::from_client_interface(owner.client.clone());
        let before = owner.target_identity();
        assert_eq!(borrowed.target_identity(), before);

        // There is no target to end, so the call itself fails. The identity moves before it
        // tries, which is the half this is about.
        let _ = owner.end_session();
        assert_ne!(
            owner.target_identity(),
            before,
            "a release moves the identity"
        );
        assert_eq!(
            borrowed.target_identity(),
            owner.target_identity(),
            "a wrapper that did not perform the release still has to observe it"
        );
    }

    /// Reads a debugger pseudo-register (`$t0`, …) as a number, via `? <expr>` — whose output
    /// is `Evaluate expression: <decimal> = <hex>`. `None` when no value came back.
    ///
    /// Fallible rather than panicking, because a read that fails is one of the outcomes these
    /// tests are here to observe: on an engine where a stale interrupt aborts the next
    /// command, this read can *be* that next command. Panicking would crash out of the
    /// measurement instead of recording it.
    #[cfg(not(miri))]
    fn read_pseudo_register_opt(e: &DebugEngine, expr: &str) -> Option<u64> {
        eval_expression(e, &format!("@{expr}"))
    }

    /// Evaluates a debugger expression — a symbol, an address, a pseudo-register — via
    /// `? <expr>`, whose output is `Evaluate expression: <decimal> = <hex>`. `None` when no
    /// value came back, for the same reason as [`read_pseudo_register_opt`].
    #[cfg(not(miri))]
    fn eval_expression(e: &DebugEngine, expr: &str) -> Option<u64> {
        let out = e.execute_command(&format!("? {expr}")).ok()?;
        let tail = out.split("Evaluate expression: ").nth(1)?;
        let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    }

    /// Breakpoints the engine currently holds, as `bl` lines. `None` when `bl` itself failed —
    /// which must not be read as "no breakpoints", since that is the answer these tests want.
    #[cfg(not(miri))]
    fn breakpoints(e: &DebugEngine) -> Option<Vec<String>> {
        let out = e.execute_command("bl").ok()?;
        Some(
            out.lines()
                .map(str::trim)
                // `DEBUG_EXECUTE_ECHO` puts the command itself in the buffer first.
                .filter(|line| !line.is_empty() && *line != "bl")
                .map(str::to_string)
                .collect(),
        )
    }

    /// [`read_pseudo_register_opt`] for call sites where a failed read means the test's own
    /// setup is broken rather than an observation — reading `$t0` after a command that is
    /// asserted to have run, for instance.
    #[cfg(not(miri))]
    fn read_pseudo_register(e: &DebugEngine, expr: &str) -> u64 {
        read_pseudo_register_opt(e, expr)
            .unwrap_or_else(|| panic!("could not read {expr} from the engine"))
    }

    /// Runs a command and reports whether it actually *took effect*, by having it stamp a
    /// sentinel into `$t1` and reading it back.
    ///
    /// Substring-matching the captured output cannot answer this. `execute_command` passes
    /// `DEBUG_EXECUTE_ECHO`, so DbgEng echoes the command text into the output buffer before
    /// running it, and [`OutputCallbacks`] appends every chunk unfiltered — a check like
    /// `output.contains("version")` therefore matches the echo alone and passes even when the
    /// command was aborted immediately after being echoed, which is precisely the failure
    /// these tests exist to catch.
    ///
    /// Every step is fallible and none of them panic. The clear below is itself a command, so
    /// on an engine where a stale interrupt does abort the next one, *this* is the command it
    /// aborts — panicking there would take out the measurement the caller is in the middle of,
    /// and the undrained case could never report the very behaviour it exists to report. A
    /// probe that cannot run at all is caught instead by the caller's baseline assertion,
    /// taken before anything is staged.
    #[cfg(not(miri))]
    fn command_took_effect(e: &DebugEngine, sentinel: u64) -> bool {
        // Clear first, so a value left by an earlier probe cannot pass for a fresh one.
        if e.execute_command("r $t1 = 0").is_err() || read_pseudo_register_opt(e, "$t1") != Some(0)
        {
            return false;
        }
        if e.execute_command(&format!("r $t1 = 0x{sentinel:x}"))
            .is_err()
        {
            return false;
        }
        read_pseudo_register_opt(e, "$t1") == Some(sentinel)
    }

    // The `#[ignore]`d tests below each drive a real debuggee, and MUST be run with
    // `--test-threads=1`. dbgeng.dll holds one debuggee session per *process*, so two of them
    // running concurrently in the same test binary fight over the same session and fail in
    // ways that look like engine bugs. Individually they pass under the default harness; as a
    // group they do not.
    //
    // They are ignored rather than gated on an env var because CI has no target to give them
    // on any platform, so there is no configuration in which they would run there.

    /// A reachable address: `run_to_address` reports [`RunToOutcome::Hit`] and leaves no
    /// breakpoint behind.
    ///
    /// Ignored: needs a live target; see the note above these tests.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 test_run_to_address_hit`
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs a live debuggee; run manually with --ignored"]
    fn test_run_to_address_hit_removes_its_breakpoint() {
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");
        assert_eq!(
            breakpoints(&e).expect("bl failed"),
            Vec::<String>::new(),
            "the target should start with no breakpoints"
        );

        // `cmd.exe` opens files as it starts up, so this is reached.
        let addr = eval_expression(&e, "ntdll!NtCreateFile").expect("could not resolve symbol");
        let res = e
            .run_to_address(addr, 20_000)
            .expect("run_to_address errored");
        assert_eq!(res.outcome, RunToOutcome::Hit, "output: {}", res.output);

        // Not vacuous: an `Ok` outcome means the breakpoint was successfully added, so an
        // empty `bl` here can only mean it was removed again. `breakpoints` returns None
        // rather than an empty list if `bl` itself fails.
        assert_eq!(
            breakpoints(&e).expect("bl failed"),
            Vec::<String>::new(),
            "run_to_address left its breakpoint armed after a hit"
        );
        let _ = e.end_session();
    }

    /// An address the target never reaches: `run_to_address` reports
    /// [`RunToOutcome::Timeout`], leaves no breakpoint behind, and leaves the engine usable.
    ///
    /// The last part is the regression that motivated the rewrite. Detecting the timeout from
    /// `GetExecutionStatus` did not work — an expired wait reports `DEBUG_STATUS_BREAK`, not
    /// `DEBUG_STATUS_GO`, and the engine has dropped the current process/thread by then — so
    /// this case used to fall through to a register read that failed with `0x8000FFFF`,
    /// returning a "Catastrophic failure" error and no usable session.
    ///
    /// Ignored: needs a live target; see the note above these tests.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 test_run_to_address_timeout`
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs a live debuggee; run manually with --ignored"]
    fn test_run_to_address_timeout_removes_its_breakpoint() {
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");

        // Nothing in this target calls it.
        let addr = eval_expression(&e, "ntdll!NtShutdownSystem").expect("could not resolve symbol");
        let res = e
            .run_to_address(addr, 2_000)
            .expect("run_to_address errored");
        assert_eq!(res.outcome, RunToOutcome::Timeout, "output: {}", res.output);

        assert_eq!(
            breakpoints(&e).expect("bl failed"),
            Vec::<String>::new(),
            "run_to_address left its breakpoint armed after a timeout — a later `g` passing              that address would stop there spuriously"
        );
        assert!(
            command_took_effect(&e, 0x63),
            "the engine is unusable after a timeout — the target was left running, or the              current process/thread was never restored"
        );
        let _ = e.end_session();
    }

    /// Probes whether `GetInterrupt` *consumes* a pending `SetInterrupt`, which
    /// [`DebugEngine::execute_command_bounded`]'s stale-interrupt drain assumes. DbgEng
    /// documents `GetInterrupt` as a check (S_OK requested / S_FALSE not); whether it also
    /// clears is not documented, so it is measured rather than assumed.
    ///
    /// Ignored: needs a live target, which CI has no way to provide. See the note above these
    /// tests on why they must not run in parallel.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 test_get_interrupt`
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs a live debuggee; run manually with --ignored"]
    fn test_get_interrupt_drain_semantics() {
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c exit").expect("launch failed");

        // Asserted, not just printed: this test is the record the production drain rests on,
        // so an engine that stopped clearing — or started counting — has to fail here rather
        // than quietly print a different vector on a manual run.
        const DRAINS_ON_FIRST_POLL: [bool; 5] = [true, false, false, false, false];

        // One request in.
        unsafe { e.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE) }.expect("SetInterrupt failed");
        let polls: Vec<bool> = (0..5).map(|_| e.interrupted().unwrap()).collect();
        println!("after 1x SetInterrupt, five GetInterrupt polls: {polls:?}");
        assert_eq!(
            polls, DRAINS_ON_FIRST_POLL,
            "GetInterrupt no longer clears the pending request on this engine"
        );

        // Several requests in, since the watchdog re-fires every 200ms while past its
        // deadline: does one poll clear them all, or one each?
        for _ in 0..3 {
            unsafe { e.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE) }.expect("SetInterrupt failed");
        }
        let polls: Vec<bool> = (0..5).map(|_| e.interrupted().unwrap()).collect();
        println!("after 3x SetInterrupt, five GetInterrupt polls: {polls:?}");
        assert_eq!(
            polls, DRAINS_ON_FIRST_POLL,
            "repeated SetInterrupt now accumulates; one drain no longer suffices"
        );

        let _ = e.end_session();
    }

    /// Forces the exact race the drain targets, which ordinary timing almost never hits: a
    /// `SetInterrupt` landing *after* `Execute` has returned, leaving a Ctrl+Break pending
    /// with no command running.
    ///
    /// Named for what it measures, not for a result: on the engine tested a stale interrupt
    /// does **not** abort the next command, short or long, so only the drained case is
    /// asserted. The undrained case prints its observation rather than asserting one, because
    /// pinning it down would encode "stale interrupts are harmless" as a requirement — the
    /// opposite of what this test exists to keep watching.
    ///
    /// Ignored: needs a live target; see the note above these tests.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 test_stale_interrupt`
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs a live debuggee; run manually with --ignored"]
    fn test_stale_interrupt_effect_on_the_next_command() {
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c exit").expect("launch failed");

        // Baseline: the probe reports a healthy engine before anything is staged.
        assert!(
            command_took_effect(&e, 0xBA5E),
            "baseline command did not take effect; the probe is broken, not the engine"
        );

        // Undrained: stage the race, then run a command.
        unsafe { e.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE) }.expect("SetInterrupt failed");
        let undrained = command_took_effect(&e, 0xA11);
        println!("undrained next command took effect: {undrained}");

        // Drained: stage the same race, consume it, then run the same command.
        //
        // The drain's return value is asserted, not discarded. `Execute` resets the request
        // itself, so if the staged interrupt never registered — or `GetInterrupt` errored —
        // the `version` below would still succeed and this case would pass while draining
        // nothing. The assertion is what makes it the *drained* case rather than a second
        // undrained one, and it has to stand on its own here: this test is documented as
        // runnable by name, without `test_get_interrupt_drain_semantics` to catch it first.
        unsafe { e.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE) }.expect("SetInterrupt failed");
        assert!(
            e.interrupted().expect("GetInterrupt failed"),
            "staged interrupt was not pending — nothing was drained, so the case below is not \
             the drained one it claims to be"
        );
        let drained = command_took_effect(&e, 0xB22);
        println!("drained   next command took effect: {drained}");

        // A short command like `version` may simply never poll for the interrupt. The case
        // that matters is a *long* next command, which does — if a stale Ctrl+Break aborts
        // that, the drain is load-bearing; if not, it is a no-op.
        // Whether it *finished* is read from `$t0`, not inferred from the clock.
        const LONG_ITERS: u64 = 0x4_0000;
        let long = format!(".for (r $t0 = 0; @$t0 < 0x{LONG_ITERS:x}; r $t0 = @$t0 + 1) {{ }}");

        // Seed `$t0` with a value the loop cannot produce before *each* run. The loop's own
        // `r $t0 = 0` initializer is part of the command, so an abort landing before it leaves
        // `$t0` holding `LONG_ITERS` from the previous run — which would read as "completed"
        // and report the immediate abort, the very case this probe exists to catch, as "did
        // NOT abort". Seeding makes "never started" its own observable value.
        const UNSTARTED: u64 = 0xDEAD_BEEF;
        let seed = format!("r $t0 = 0x{UNSTARTED:x}");

        e.execute_command(&seed).expect("seeding $t0 failed");
        let clean_start = Instant::now();
        e.execute_command(&long).expect("long command failed");
        let clean = clean_start.elapsed();
        let clean_t0 = read_pseudo_register(&e, "$t0");
        assert_eq!(
            clean_t0, LONG_ITERS,
            "the uninterrupted run did not complete — the probe is broken, not the engine"
        );

        e.execute_command(&seed).expect("seeding $t0 failed");
        unsafe { e.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE) }.expect("SetInterrupt failed");
        let stale_start = Instant::now();
        let stale = e.execute_command(&long);
        let stale_elapsed = stale_start.elapsed();
        let stale_t0 = read_pseudo_register_opt(&e, "$t0");
        let stale_result = if stale.is_ok() { "Ok" } else { "Err" };
        println!("long command, clean:           {clean:?} (t0={clean_t0} of {LONG_ITERS})");
        println!(
            "long command, stale interrupt: {stale_elapsed:?} (t0={stale_t0:?} of {LONG_ITERS}, {stale_result})"
        );
        println!(
            "  -> stale interrupt {} the long command",
            match stale_t0 {
                None => "gave no readable $t0 after",
                Some(UNSTARTED) => "ABORTED, before the loop even started,",
                Some(t0) if t0 < LONG_ITERS => "ABORTED mid-loop",
                _ => "did NOT abort",
            }
        );
        let _ = e.interrupted();

        // Only the drained case is asserted; the undrained ones are the measurement.
        assert!(
            drained,
            "draining should leave the next command fully usable"
        );

        let _ = e.end_session();
    }

    /// The behaviour the drain exists to protect, end to end: after a bounded command is
    /// cut short by its watchdog, the *next* command must run normally rather than being
    /// aborted by a Ctrl+Break left pending behind it.
    ///
    /// Ignored: needs a live target; see the note above these tests.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 test_next_command`
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs a live debuggee; run manually with --ignored"]
    fn test_next_command_survives_a_bounded_timeout() {
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c exit").expect("launch failed");

        // A deliberately runaway command. Note a broad `s` search does *not* work here: it
        // skips unmapped ranges, so even `L?0x7fffffffff` returns almost immediately. A tight
        // `.for` in the expression evaluator is genuinely CPU-bound and interruptible, and it
        // leaves its progress behind in `$t0` — which is what proves the interruption below.
        const ITERATIONS: u64 = 0x100_0000;
        const TIMEOUT_MS: u32 = 1_500;
        let started = Instant::now();
        let out = e
            .execute_command_bounded(
                &format!(".for (r $t0 = 0; @$t0 < 0x{ITERATIONS:x}; r $t0 = @$t0 + 1) {{ }}"),
                TIMEOUT_MS,
            )
            .expect("bounded command should return, not error");
        let elapsed = started.elapsed();

        // Proof of interruption is the loop counter, not the clock and not the diagnostic
        // note. The note is appended whenever the watchdog *attempted* `SetInterrupt`, so an
        // interrupt the engine ignored still produces it. A wall-clock bound is no better: it
        // has to be picked for this host, and on a faster machine or a cheaper `.for` the loop
        // could finish naturally inside the bound, passing both checks while the watchdog did
        // nothing. `$t0` is host-independent — short of `ITERATIONS`, the loop did not finish.
        let t0 = read_pseudo_register(&e, "$t0");
        println!("bounded command returned after {elapsed:?}, $t0 = {t0} of {ITERATIONS}");
        assert!(t0 > 0, "loop never started; $t0 = {t0}");
        assert!(
            t0 < ITERATIONS,
            "loop ran to completion ($t0 = {t0}) — the watchdog did not cut it short, so the \
             rest of this test would prove nothing"
        );
        assert_eq!(
            out.cut_short,
            Some(Interruption::Deadline {
                after_ms: TIMEOUT_MS
            }),
            "a loop that stopped short has to say a deadline stopped it"
        );

        // The command under test. If a stale interrupt survived, this aborts instead — so the
        // check has to be that it *took effect*, not that its text came back. `Execute` echoes
        // the command into the output buffer before running it, which makes any substring
        // check against the command name pass on the echo alone.
        assert!(
            command_took_effect(&e, 0x5A5E),
            "next command did not take effect — a stale interrupt aborted it"
        );

        let _ = e.end_session();
    }

    /// The same command, cut short by an [`InterruptHandle`] instead of by a deadline: the
    /// partial output comes back as `Ok`, without the watchdog's note, and the engine is left
    /// usable.
    ///
    /// The `Ok` is the whole point of the shared flag. `SetInterrupt` makes `Execute` fail, so
    /// without it an abort on request is a `CommandFailed` — the caller loses every line the
    /// command had already produced, which on an interrupted search is the only thing it was
    /// ever going to get. The absent note is the other half: a watchdog explains itself because
    /// nobody saw the deadline pass, whereas this caller is the one who asked.
    ///
    /// Ignored: needs a live target; see the note above these tests.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 test_command_interrupted_on_request`
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs a live debuggee; run manually with --ignored"]
    fn test_command_interrupted_on_request_keeps_its_output() {
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c exit").expect("launch failed");

        // As in the watchdog test above: a genuinely CPU-bound `.for` that polls for the
        // interrupt and leaves its progress in `$t0`, which is what proves it was cut short.
        const ITERATIONS: u64 = 0x100_0000;
        let long = format!(".for (r $t0 = 0; @$t0 < 0x{ITERATIONS:x}; r $t0 = @$t0 + 1) {{ }}");

        // Raised from another thread while the command runs — the arrangement the handle exists
        // for. A delay rather than a handshake because there is nothing to hand shake with: the
        // engine thread is inside `Execute` and the only observable it publishes is the loop
        // counter this test reads afterwards.
        let handle = e.interrupt_handle();
        let asker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(1_500));
            handle.interrupt().expect("SetInterrupt failed");
        });

        // No watchdog of its own (`0`), so anything that stops this command came from the thread
        // above and the result cannot be credited to the deadline path by accident.
        let out = e
            .execute_command_bounded(&long, 0)
            .expect("an interrupted command must return its partial output, not an error");
        asker.join().expect("the interrupting thread panicked");

        let t0 = read_pseudo_register(&e, "$t0");
        println!("command interrupted on request, $t0 = {t0} of {ITERATIONS}");
        assert!(t0 > 0, "loop never started; $t0 = {t0}");
        assert!(
            t0 < ITERATIONS,
            "loop ran to completion ($t0 = {t0}) — the interrupt never reached it, so the rest \
             of this test would prove nothing"
        );
        assert_eq!(
            out.cut_short,
            Some(Interruption::OnRequest),
            "the break came from the handle, not from a deadline — and which it was is what a \
             caller renders its advice from"
        );

        // And the next command is unaffected, which is what the drain is for.
        assert!(
            command_took_effect(&e, 0x1234),
            "next command did not take effect — the requested interrupt was left pending"
        );

        let _ = e.end_session();
    }

    /// Serializes the tests that build a [`DebugEngine`].
    ///
    /// dbgeng holds **one debuggee session per process** and `DebugEngine::drop` ends it, so
    /// two engine tests sharing a test binary either lose the race to open a target — the
    /// launch fails with `0x80004005` — or end each other's session on the way out.
    ///
    /// Nothing under `cargo nextest run`, which gives every test its own process and is what CI
    /// and this repo's instructions use. Load-bearing under plain `cargo test`, which the
    /// coverage workflow runs. (The `#[ignore]`d tests above have the same requirement, met the
    /// other way: they are documented as needing `--test-threads=1`.)
    #[cfg(not(miri))]
    static ONE_DEBUGGEE: Mutex<()> = Mutex::new(());

    #[cfg(not(miri))]
    fn one_debuggee() -> std::sync::MutexGuard<'static, ()> {
        // A test that panics while holding this poisons it. The next test still needs the
        // lock, and its own assertion is a better failure message than a poison error.
        ONE_DEBUGGEE.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Puts the session somewhere other than its default scope, and says what did it.
    ///
    /// `None` means nothing moved — which the scope tests below must treat as a failure rather
    /// than a pass, since a scope that never moved is restored by doing nothing at all.
    #[cfg(not(miri))]
    fn move_the_scope(e: &DebugEngine) -> Option<&'static str> {
        let before = e.scope().ok()?;
        for command in [".frame 1", ".frame 2", ".ecxr"] {
            let _ = e.execute_command(command);
            if e.scope().ok()? != before {
                return Some(command);
            }
        }
        None
    }

    #[test]
    #[cfg(not(miri))]
    fn a_scope_needs_a_target_to_be_read_from() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        // Measured: `GetScope` answers `E_UNEXPECTED` with no target, for every buffer size
        // including none at all. So there is no scope to report as empty — only an error.
        let err = e
            .scope()
            .expect_err("an engine holding no target reported a scope");
        println!("scope() with no target: {err}");
    }

    #[test]
    #[cfg(not(miri))]
    fn a_saved_scope_is_the_one_restored() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c exit").expect("launch failed");

        let moved_by = move_the_scope(&e).expect("nothing moved the scope; the rest is vacuous");
        let saved = e.scope().expect("scope() failed");
        println!("scope moved by `{moved_by}`: {saved:?}");
        // The context is what makes this more than a frame number, and its buffer is sized by
        // walking `SCOPE_CONTEXT_SIZES`. A live target on any architecture the CI runs (x64 and
        // ARM64) must find its size in there.
        assert!(
            saved.has_context(),
            "no size in SCOPE_CONTEXT_SIZES covered this target's CONTEXT"
        );

        // Move again, so the restore has something to undo.
        e.execute_command(".frame 0").expect(".frame 0 failed");
        assert_ne!(
            e.scope().expect("scope() failed"),
            saved,
            "the second move did not move anything"
        );

        e.set_scope(&saved).expect("set_scope failed");
        assert_eq!(
            e.scope().expect("scope() failed"),
            saved,
            "the scope that came back is not the one that was saved"
        );
        let _ = e.end_session();
    }

    #[test]
    #[cfg(not(miri))]
    fn a_guard_restores_the_scope_even_when_the_caller_panics() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c exit").expect("launch failed");
        move_the_scope(&e).expect("nothing moved the scope; the rest is vacuous");
        let before = e.scope().expect("scope() failed");

        // The path a hand-written save/restore pair misses. `AssertUnwindSafe` because the
        // engine is deliberately shared across the boundary: whether it was left consistent is
        // the thing under test.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = e.scope_guard().expect("scope_guard() failed");
            e.execute_command(".frame 0").expect(".frame 0 failed");
            panic!("the guarded call gave up");
        }))
        .is_err();
        assert!(panicked, "the closure was supposed to panic");

        assert_eq!(
            e.scope().expect("scope() failed"),
            before,
            "the guard did not restore the scope while unwinding"
        );
        let _ = e.end_session();
    }

    #[test]
    #[cfg(not(miri))]
    fn a_scope_is_not_restored_onto_a_later_target() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c exit").expect("launch failed");
        let stale = e.scope().expect("scope() failed");
        let _ = e.end_session();

        // A second target in the same engine: the frame and context in `stale` describe a stack
        // that no longer exists, and pointing this session at it would be worse than refusing.
        e.launch_process("cmd.exe /c exit")
            .expect("second launch failed");
        let err = e
            .set_scope(&stale)
            .expect_err("a scope from the previous target was applied to this one");
        assert!(
            matches!(err, DbgEngError::ScopeFromAnotherTarget),
            "wrong error for a stale scope: {err}"
        );

        // The refusal is about *that* scope, not about the engine: this target's own still works.
        let fresh = e.scope().expect("scope() failed");
        e.set_scope(&fresh)
            .expect("set_scope failed on a fresh scope");
        let _ = e.end_session();
    }
}

#[windows::core::implement(
    windows::Win32::System::Diagnostics::Debug::Extensions::IDebugEventContextCallbacks
)]
pub struct DebugEventContextCallbacks {
    callback: Option<BreakpointCallback>,
}

impl DebugEventContextCallbacks {
    pub fn new(callback: Option<BreakpointCallback>) -> Self {
        Self { callback }
    }
}

#[allow(non_snake_case)]
impl windows::Win32::System::Diagnostics::Debug::Extensions::IDebugEventContextCallbacks_Impl
    for DebugEventContextCallbacks_Impl
{
    fn GetInterestMask(&self) -> windows::core::Result<u32> {
        Ok(DEBUG_EVENT_BREAKPOINT)
    }

    fn Breakpoint(
        &self,
        bp: windows::core::Ref<'_, IDebugBreakpoint2>,
        _context: *const std::ffi::c_void,
        _flags: u32,
    ) -> windows::core::Result<()> {
        if let Some(callback) = &self.callback {
            let _ = callback(bp.as_ref().unwrap(), _context, _flags);
        }
        Ok(())
    }

    fn Exception(
        &self,
        _exception: *const windows::Win32::System::Diagnostics::Debug::EXCEPTION_RECORD64,
        _first_chance: u32,
        _context: *const std::ffi::c_void,
        _flags: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn CreateThread(
        &self,
        _handle: u64,
        _data_offset: u64,
        _start_offset: u64,
        _context: *const std::ffi::c_void,
        _flags: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn ExitThread(
        &self,
        _exit_code: u32,
        _context: *const std::ffi::c_void,
        _flags: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn CreateProcessA(
        &self,
        _image_file_handle: u64,
        _handle: u64,
        _base_offset: u64,
        _module_size: u32,
        _module_name: &PCWSTR,
        _image_name: &PCWSTR,
        _checksum: u32,
        _timestamp: u32,
        _initial_thread_handle: u64,
        _thread_data_offset: u64,
        _start_offset: u64,
        _context: *const std::ffi::c_void,
        _flags: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn ExitProcess(
        &self,
        _exit_code: u32,
        _context: *const std::ffi::c_void,
        _flags: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn LoadModule(
        &self,
        _image_file_handle: u64,
        _base_offset: u64,
        _module_size: u32,
        _module_name: &PCWSTR,
        _image_name: &PCWSTR,
        _checksum: u32,
        _timestamp: u32,
        _context: *const std::ffi::c_void,
        _flags: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn UnloadModule(
        &self,
        _image_base_name: &PCWSTR,
        _base_offset: u64,
        _context: *const std::ffi::c_void,
        _flags: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn SystemError(
        &self,
        _error: u32,
        _level: u32,
        _context: *const std::ffi::c_void,
        _flags: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn SessionStatus(&self, _status: u32) -> windows::core::Result<()> {
        Ok(())
    }

    fn ChangeDebuggeeState(
        &self,
        _flags: u32,
        _argument: u64,
        _context: *const std::ffi::c_void,
        _flags2: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn ChangeEngineState(
        &self,
        _flags: u32,
        _argument: u64,
        _context: *const std::ffi::c_void,
        _flags2: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn ChangeSymbolState(&self, _flags: u32, _argument: u64) -> windows::core::Result<()> {
        Ok(())
    }
}
