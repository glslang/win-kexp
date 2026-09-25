use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

mod kernel_attach;

use thiserror::Error;
use windows::Win32::Foundation::{
    E_FAIL, E_INVALIDARG, E_NOINTERFACE, E_UNEXPECTED, S_FALSE, S_OK,
};
use windows::core::{HRESULT, IUnknown, Interface, PCSTR, PCWSTR, PWSTR};

// Import the necessary Windows Debug Engine interfaces
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_ANY_ID, DEBUG_ATTACH_KERNEL_CONNECTION, DEBUG_ATTACH_LOCAL_KERNEL, DEBUG_BREAK_EXECUTE,
    DEBUG_BREAK_IO, DEBUG_BREAK_READ, DEBUG_BREAK_WRITE, DEBUG_BREAKPOINT_CODE,
    DEBUG_BREAKPOINT_DATA, DEBUG_BREAKPOINT_DEFERRED, DEBUG_BREAKPOINT_ENABLED,
    DEBUG_BREAKPOINT_ONE_SHOT, DEBUG_CLASS_KERNEL, DEBUG_ENGOPT_INITIAL_BREAK,
    DEBUG_EVENT_BREAKPOINT, DEBUG_EVENT_EXCEPTION, DEBUG_EXECUTE_ECHO, DEBUG_INTERRUPT_ACTIVE,
    DEBUG_KERNEL_SMALL_DUMP, DEBUG_LAST_EVENT_INFO_EXCEPTION, DEBUG_MODNAME_SYMBOL_FILE,
    DEBUG_MODULE_PARAMETERS, DEBUG_MODULE_USER_MODE, DEBUG_OUTCTL_THIS_CLIENT, DEBUG_OUTPUT_NORMAL,
    DEBUG_REGISTER_DESCRIPTION, DEBUG_REGISTER_SUB_REGISTER, DEBUG_STACK_FRAME, DEBUG_STATUS_GO,
    DEBUG_STATUS_GO_HANDLED, DEBUG_STATUS_GO_NOT_HANDLED, DEBUG_STATUS_MASK,
    DEBUG_STATUS_NO_DEBUGGEE, DEBUG_STATUS_REVERSE_GO, DEBUG_STATUS_REVERSE_STEP_BRANCH,
    DEBUG_STATUS_REVERSE_STEP_INTO, DEBUG_STATUS_REVERSE_STEP_OVER, DEBUG_STATUS_STEP_BRANCH,
    DEBUG_STATUS_STEP_INTO, DEBUG_STATUS_STEP_OVER, DEBUG_SYMINFO_IMAGEHLP_MODULEW64,
    DEBUG_SYMTYPE_CODEVIEW, DEBUG_SYMTYPE_COFF, DEBUG_SYMTYPE_DEFERRED, DEBUG_SYMTYPE_DIA,
    DEBUG_SYMTYPE_EXPORT, DEBUG_SYMTYPE_NONE, DEBUG_SYMTYPE_PDB, DEBUG_SYMTYPE_SYM, DEBUG_VALUE,
    DEBUG_VALUE_FLOAT32, DEBUG_VALUE_FLOAT64, DEBUG_VALUE_FLOAT80, DEBUG_VALUE_FLOAT82,
    DEBUG_VALUE_FLOAT128, DEBUG_VALUE_INT8, DEBUG_VALUE_INT16, DEBUG_VALUE_INT32,
    DEBUG_VALUE_INT64, DEBUG_VALUE_VECTOR64, DEBUG_VALUE_VECTOR128, DebugConnectWide,
    IDebugAdvanced2, IDebugBreakpoint2, IDebugClient6, IDebugControl4, IDebugDataSpaces4,
    IDebugEventContextCallbacks, IDebugOutputCallbacks, IDebugRegisters, IDebugSymbols3,
    IDebugSystemObjects,
};
use windows::Win32::System::Diagnostics::Debug::{EXCEPTION_RECORD64, IMAGEHLP_MODULEW64};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_RESERVE, MEMORY_BASIC_INFORMATION64,
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

    /// A [`crate::dbgeng::BreakpointSpec`] the engine would accept and then refuse later.
    ///
    /// Separate from [`Self::BreakpointFailed`] because nothing failed: the spec is refused here,
    /// before a breakpoint exists, so there is no `windows::core::Error` to carry and nothing to
    /// undo. A processor breakpoint with a bad size or alignment is the case — the engine takes it
    /// at the set and rejects it at the *resume*, against an operation that did nothing wrong.
    #[error("Invalid breakpoint: {0}")]
    InvalidBreakpoint(String),

    #[error("Invalid command string (contains interior NUL)")]
    InvalidCommand,

    #[error(
        "No active debuggee — attach to a target, launch a process, or open a dump/trace first"
    )]
    NoDebuggee,

    #[error("quit-and-detach returned without releasing the target; resume is unconfirmed")]
    IncompleteKernelDetach,

    #[error(
        "kernel target did not break in within the attach timeout — is it reachable and in debug mode?"
    )]
    KernelBreakTimeout,

    #[error("experimental kernel attach failed: {0}; target state is unconfirmed")]
    ExperimentalKernelAttach(&'static str),

    /// A user-mode open whose process never joined the session.
    ///
    /// The sibling of [`Self::KernelBreakTimeout`], and it exists because what it replaces was a
    /// lie rather than a different error: a live open used to be one `WaitForEvent`, which is one
    /// *event* and not necessarily this target's, so an open could return `Ok` with its process
    /// absent from the session (dbgscope#128). Reported only when the session stayed readable and
    /// the process was demonstrably not in it — an open that cannot evaluate its own postcondition
    /// returns `Ok` exactly as it did before, rather than failing on a probe.
    ///
    /// **Membership, not the stop.** The wait *pumps* until this target has stopped ([`Presence`])
    /// and gives that up quietly at the bound: a process visibly in the session ends the wait `Ok`,
    /// and only a missing one is this. Erroring on a process in front of us would be claiming
    /// absence where the truth is that we did not see it stop — see docs/unknown-not-absent.md.
    #[error("the process did not join the session within the open timeout")]
    LiveTargetTimeout,

    /// A user-mode open a host stopped before its process joined the session.
    ///
    /// Distinct from [`Self::LiveTargetTimeout`] because the recovery is: a timeout says the
    /// target is not coming, and this says nothing about the target at all -- somebody asked for
    /// control back, and retrying is reasonable. Folding it into the timeout would report "within
    /// the open timeout" for an open cut short two seconds in, which is the overstatement
    /// docs/unknown-not-absent.md exists about.
    #[error("the open was interrupted before the process joined the session")]
    LiveTargetInterrupted,

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

    /// The **host** ran out of room for the answer, rather than the target running out of bytes.
    ///
    /// Distinct from [`Self::BufferTooLarge`], which is a size this crate refuses at the door
    /// because it cannot express it; this is one it accepted and could not hold. Reported rather
    /// than left to abort because Rust's default reaction to a failed allocation is to take the
    /// process down, and a host that asked a debugger to read a range is owed an error — the same
    /// rule that makes every call here answer `Result` instead of panicking. It carries how far
    /// the read had got, because that is the difference between a request that was never
    /// affordable and one whose target had more to give than this machine can hold.
    #[error(
        "ran out of memory reading {requested} bytes at {address:#x}: {read} bytes were read \
         before the host could not hold any more"
    )]
    OutOfMemory {
        address: u64,
        requested: usize,
        read: usize,
    },

    /// A decode was asked for on an instruction set this build does not decode. Its own error
    /// rather than a COM one, because no call failed: the question cannot be answered here.
    #[error("this build does not decode instructions for machine {machine:#x}")]
    UndecodedInstructionSet { machine: u32 },

    #[error("debugger text contains an interior NUL")]
    InvalidOutput,

    #[error("this scope was read from a target the engine no longer holds")]
    ScopeFromAnotherTarget,

    /// The sibling of [`Self::ScopeFromAnotherTarget`], for the same hazard on the other saved
    /// register state this crate hands out.
    ///
    /// A [`crate::dbgeng::ThreadContext`] means something only on the target it was read from, and
    /// walking a stack from one belonging to a *previous* target is the worse of the two: a stale
    /// scope points the session somewhere visibly wrong, while a stale context comes back as
    /// frames. The engine unwinds whatever those addresses reach now and answers.
    #[error("this register context was read from a target the engine no longer holds")]
    ContextFromAnotherTarget,
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
/// `CreateProcess` flag: give the launched target a console of its own, **with no window**.
///
/// The console is the point and is not negotiable: without one, a console target inherits the
/// host's stdout — fatal when the host's stdout is an MCP/JSON-RPC channel, as the target's prints
/// corrupt the stream. Measured on this bench with a `STARTUPINFO` carrying no
/// `STARTF_USESTDHANDLES`, which is the shape DbgEng uses: with no flag the target's `echo` lands
/// in the launching process's own stdout, and with this one it does not — with `bInheritHandles`
/// either way.
///
/// The *window* is what changed, and `CREATE_NO_WINDOW` rather than `CREATE_NEW_CONSOLE` is the
/// whole of it. Both give the target its own console; the older flag also puts that console on the
/// desktop, taking the foreground as it appears, so a host driving repeated launches made the
/// machine unusable ([#129](https://github.com/glslang/dbgscope/issues/129), and
/// [windbg-mcp#273](https://github.com/glslang/windbg-mcp/issues/273) for the same window arriving
/// by the other route). The two are alternatives, not a pair: `CREATE_NO_WINDOW` is documented as
/// ignored when it is passed beside `CREATE_NEW_CONSOLE`.
///
/// What it costs is a debuggee's console output no longer being *readable* on the desktop. It was
/// never captured — these launches are driven by a program, not watched by a person — and a caller
/// that wants to see a target's output can redirect it (`cmd.exe /c prog > file`) rather than have
/// every launch open a window on the chance that someone is looking.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// `AttachProcess` default attach flags.
const DEBUG_ATTACH_DEFAULT: u32 = 0x0000_0000;
/// `EndSession` flag used on teardown: detach passively without resuming.
const DEBUG_END_PASSIVE: u32 = 0x0000_0000;
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

/// Buffer sizes offered to `GetStoredEventInformation` for a stored event's register context,
/// smallest first.
///
/// **A separate ladder from [`SCOPE_CONTEXT_SIZES`], because the two calls fail differently and
/// borrowing the other one's rule produced a wrong answer that surfaced three calls later.**
/// `GetScope` *refuses* a buffer below the target's `CONTEXT` size, so climbing from the smallest
/// finds the exact size and the first rung that is accepted is the right one. This call does not
/// refuse: offered 716 bytes for an **x64** dump it writes 716, reports 716, and returns success
/// — a truncated context, which `GetContextStackTrace` then rejects with `E_INVALIDARG` from a
/// caller that did nothing wrong. Measured on the user-mode fail-fast dump in
/// `examples/stored_event_probe.rs`.
///
/// So it starts *above* every real `CONTEXT` — x64's is 1,232 bytes, ARM64's 912, x86's 716 —
/// rather than below them, and grows only on the one signal this call gives that there was more to
/// write: the engine having filled the buffer exactly to the brim.
const STORED_CONTEXT_SIZES: &[u32] = &[4096, 8192, 16384, 32768, 65536];

/// The event kind an engine reports when it has no event to report.
///
/// Not a `DEBUG_EVENT_*` constant, because it is not one: the engine's own list starts at
/// `DEBUG_EVENT_BREAKPOINT` (`0x1`) and every value in it is a single bit. Zero is what
/// `GetLastEventInformation` answers — with `S_OK`, and `DEBUG_ANY_ID` for both ids — on an engine
/// that has seen nothing, which is any engine before its first wait and a dump `open_dump` has
/// named but nothing has pumped.
const NO_EVENT_KIND: u32 = 0;

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
    /// The **session's** bookkeeping, so a request this handle raises is recorded against the
    /// operation it will stop rather than against the engine at large. See [`BreakScope`].
    ///
    /// Shared with every wrapper around the same client, not only with the engine this came from
    /// ([`ClientState`]). `SetInterrupt` reaches the client both wrappers share, so a handle taken
    /// from one raises a break the other would otherwise see as a stop its target made on its own
    /// -- and, since [`DebugEngine::pump`] takes the request to attribute its [`WaitOutcome`], as
    /// an arrival.
    state: Arc<ClientState>,
}
// SAFETY: `control` is only ever handed to SetInterrupt, the one DbgEng call documented as safe
// from any thread, and `state` is behind its own locks. The other cross-thread touch is the
// `Release` on drop, which assumes the interface's refcount is atomic — as COM requires of any
// object usable from more than one apartment, and as `SetInterrupt`'s own guarantee presupposes;
// a handle held for the life of a process, which is the intended use, never reaches it at all.
//
// This comment used to rest that last point on `DebugEngine`'s own `Send`/`Sync`. Those are gone
// (dbgscope#136 stage 4): they claimed the whole engine crossed threads, which is the opposite of
// what the type above says, so the assumption is stated here instead of borrowed from an impl that
// should never have made it.
unsafe impl Send for InterruptHandle {}
// SAFETY: as above — sharing a handle only shares the ability to make that one call.
unsafe impl Sync for InterruptHandle {}

impl InterruptHandle {
    /// Asks the engine this came from to break out of whatever it is running, and says what that
    /// was.
    ///
    /// Returns as soon as the request is lodged, not when the engine acts on it: a long command
    /// polls for the flag exactly as it does for a human's Ctrl+Break, so the operation ends at
    /// its next poll and its own caller is who observes that. Two limits carry over from the
    /// engine, both of them properties of `SetInterrupt` rather than of this: a command that never
    /// polls is not reached, and neither is a live-kernel wait whose target has not yet connected
    /// (see [`Bound::Watchdog`]).
    ///
    /// **Delivery is engine-wide and attribution is scoped, and they are different questions.**
    /// `SetInterrupt` stops whatever is inside `WaitForEvent` — it carries no notion of an
    /// operation and cannot be aimed — so the break is issued unconditionally, which is what lets
    /// a host abort a long unbounded [`DebugEngine::execute_command`] that no bounded operation
    /// covers. What is scoped is the *record*: the request is filed against the operation running
    /// at this instant, and only that operation can report it as
    /// [`Interruption::OnRequest`]. [`BreakRequest::NothingRunning`] is the honest answer when
    /// there is no such operation — the break still goes, and DbgEng discards a pending request
    /// when the next `Execute` begins (measured; see `test_stale_interrupt_effect_on_the_next_command`).
    ///
    /// **Both halves happen under one lock, and that is the fix rather than a detail**
    /// (dbgscope#135 half A). The old shape stored an engine-wide flag and then called
    /// `SetInterrupt`, with each operation clearing the flag as it opened; a request lodged
    /// between an operation's clear and its wait was therefore *erased* while its break was still
    /// on the way, and the resulting synthetic stop was reported as the target's own — up to and
    /// including being delivered to a live open as its target's initial break. No
    /// ticket or generation counter closes that: the window is between two writes, not between two
    /// values. Holding the lock across the record *and* the delivery closes it by construction,
    /// because an operation cannot begin or end in the middle.
    pub fn interrupt(&self) -> Result<BreakRequest, DbgEngError> {
        let mut scope = self.state.breaks.lock().unwrap_or_else(|e| e.into_inner());
        let against = scope.innermost();
        // Delivered before it is recorded, which the lock makes safe and which the old ordering
        // could not afford: nothing can observe the interim state, so a `SetInterrupt` that fails
        // records nothing rather than leaving an operation to report a break that was never sent.
        unsafe { self.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE) }.map_err(|source| {
            DbgEngError::Context {
                operation: "requesting a debugger interrupt".into(),
                source,
            }
        })?;
        match against {
            Some(operation) => {
                scope.record(operation);
                Ok(BreakRequest::Raised { operation })
            }
            None => Ok(BreakRequest::NothingRunning),
        }
    }

    /// Breaks the engine out **without** recording a request against anything — this crate's own
    /// watchdogs, whose deadline is already scoped to the operation they were armed around.
    ///
    /// The watchdog used to reach the engine through [`Self::interrupt`], so one deadline produced
    /// *two* representations of itself — the watchdog's private flag and the engine-wide request —
    /// and every classify site had to OR them together and then trust the private one to say which
    /// it was. A watchdog that records nothing leaves one signal per origin, so
    /// [`WaitOutcome::Deadline`] and [`WaitOutcome::OnRequest`] are read from different places and
    /// cannot be confused for one another.
    fn break_in_only(&self) -> Result<(), DbgEngError> {
        unsafe { self.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE) }.map_err(|source| {
            DbgEngError::Context {
                operation: "requesting a debugger interrupt".into(),
                source,
            }
        })
    }
}

/// One bounded engine operation — a `WaitForEvent`, an `Execute` under a watchdog, a symbolic
/// breakpoint resolve — and the identity a break request names.
///
/// Opaque, and minted only by [`DebugEngine::begin_operation`]. Ids are never reused, so one that
/// names an operation which has ended matches nothing later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationId(u64);

/// What [`InterruptHandle::interrupt`] did.
///
/// The break itself is issued either way; this says whether anything will *report* it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakRequest {
    /// Filed against the operation the engine was running at that instant.
    ///
    /// **Which is not a promise that the operation will report it.** An operation accepts requests
    /// for slightly longer than it reads them — see [`Operation`] — so one filed after its last
    /// read is discarded when it closes, and the break, having been delivered, is drained there
    /// rather than left to stop whatever runs next. Nothing on this side can close that window:
    /// whether the engine thread has a read left is not knowable to the calling thread at the
    /// moment it asks.
    Raised { operation: OperationId },
    /// The engine was between bounded operations. The break was still delivered — it can abort a
    /// long unbounded [`DebugEngine::execute_command`], which is a real thing to want — but no
    /// operation will claim it, and nothing here will report it.
    NothingRunning,
}

/// The state a debug **session** has, shared by every [`DebugEngine`] wrapping one
/// `IDebugClient6`.
///
/// Two `DebugEngine`s can be live around one client — that is what
/// [`DebugEngine::from_client_interface`] is for, and what
/// `test_every_live_wrapper_sees_a_release_through_any_of_them` asserts — so anything that is a
/// view of the *session* must not be private to one wrapper. Both of these were, and both were
/// written down as known gaps rather than fixed at the time:
///
/// - **Arrivals.** A `wait_for_event` through wrapper B that pumps wrapper A's held target to its
///   initial break recorded it in B alone. A then read [`Presence::Listed`], waited again, and got
///   an unrelated event or `E_UNEXPECTED` — the 29.36s against 8.6µs that
///   `examples/deferred_arrival.rs` arm F measures, undone by the wrapper boundary.
/// - **Break requests.** A handle taken from wrapper A raises a break the other wrapper sees as a
///   stop its target made on its own, and — since [`DebugEngine::pump`] takes the request to
///   attribute its [`WaitOutcome`] — as an arrival.
///
/// dbgscope#136 stage 3, which is where the `Arc<ClientState>` note that used to sit on the
/// arrival record said this belonged: it is one field, so doing the two halves apart would be two
/// reviews of one seam.
///
/// **Not the session's *provenance*, which stays per wrapper.** `attached_processes` decides
/// whether a teardown detaches a process or takes it with the session, and a session belongs to
/// the wrapper that opened it — sharing that would put this crate's most consequential decision
/// behind a lookup, to serve an arrangement neither consumer makes.
#[derive(Debug, Default)]
struct ClientState {
    /// The opens waiting for a target to join this session and stop.
    arrivals: Mutex<Arrivals>,
    /// Which bounded operations are running, and which of them a host has asked to break.
    breaks: Mutex<BreakScope>,
    /// The system pids of live user-mode processes this session **attached** to rather than
    /// created — the ones ending it must let go of rather than take with it.
    ///
    /// Read by [`DebugEngine::end_session`] and by `Drop`, which is why it lives with the session
    /// rather than being passed in at teardown: a caller can end a session explicitly, but nothing
    /// gets to say anything when the engine is simply dropped, and a process this crate did not
    /// create should survive either ending.
    ///
    /// **A set of pids rather than a flag about the session**, which two rounds of review argued
    /// its way to and is worth keeping in one piece. DbgEng holds **several** user-mode processes
    /// in one session — `|` lists them, and says `attach` or `create` against each — so a session
    /// can be attached to somebody's service *and* have launched a program of its own, and a
    /// session-wide answer is wrong for one of them whichever way it goes. Provenance is per
    /// process because the fact is.
    ///
    /// **Recorded by the opener rather than asked of DbgEng.** `|` knows, but that is text; the
    /// API does not expose it (`GetDebuggeeType` answers `DEBUG_CLASS_USER_WINDOWS` /
    /// `DEBUG_USER_WINDOWS_PROCESS` for a launch and an attach alike), and parsing a debugger's
    /// human output to decide whether to kill somebody's process is not a thing to build.
    ///
    /// **Per client, where it used to be per wrapper**, and the sentence that used to defend the
    /// old placement was arguing against the wrong thing. It said sharing this would put the
    /// crate's most consequential decision "behind an eviction policy" — true of
    /// [`client_identities`], which is a cache with a cap, and not of [`ClientState`], where an
    /// entry is `Weak` and dies with the last wrapper holding it. What the old placement actually
    /// cost is two things this stage had to fix anyway. Delivery reads it to keep an attach's
    /// process from being claimed by a pending launch, and a pump through a second wrapper read an
    /// empty set (raised in review on dbgscope#139). And an `end_session` through a wrapper that
    /// did not perform the attach saw no attachment to detach, so its passive end **killed**
    /// somebody else's process — the exact failure this record exists to prevent, reached through
    /// the wrapper boundary. Which processes a session attached to is a property of the session.
    attached_processes: Mutex<HashMap<u32, Attachment>>,
}

/// How far an attachment has got, which is what tells a *deferred* one from a *departed* one.
///
/// `AttachProcess` joins the process to the session at the next `WaitForEvent`, not at the call --
/// measured, and printed by `examples/deferred_arrival.rs` arm E: the pid is not listed before the
/// wait. So a pid recorded by [`DebugEngine::claim_attached`] is legitimately absent from
/// `session_processes` for a while, and [`DebugEngine::prune_processes_that_left`] -- whose whole
/// subject is a pid that no longer names anything -- would drop it. Raised in review on
/// dbgscope#139, and worth knowing that it costs more than a missed exclusion: a record dropped
/// there makes the teardown treat somebody else's process as one this engine launched, and take it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attachment {
    /// Attached, and not yet seen in the session. Nothing may prune it: it has not arrived, so it
    /// cannot have left.
    Deferred,
    /// Seen in the session at least once, so its absence now means it is gone.
    Joined,
}

/// Every client this process has live state for, keyed by COM pointer.
///
/// `Weak`, so an entry dies with the last wrapper holding it and a pointer the allocator reuses
/// cannot inherit the previous client's arrivals or break requests. That is what
/// [`client_identities`] needs [`reissue_identity`] for and this needs nothing for: an identity is
/// a cache tag whose staleness costs a re-read, where a stale arrival record would answer
/// [`Presence::Arrived`] for a target that never stopped.
///
/// Swept on every insert rather than capped, for the same reason: a dead entry identifies itself,
/// so the map is bounded by the number of *live* clients, which is one in the extension and one
/// per worker process in windbg-mcp.
fn client_states() -> &'static Mutex<HashMap<usize, Weak<ClientState>>> {
    static STATES: OnceLock<Mutex<HashMap<usize, Weak<ClientState>>>> = OnceLock::new();
    STATES.get_or_init(Mutex::default)
}

/// The state in force for `client`, creating it if this is the first wrapper to ask.
///
/// Poisoning is recovered rather than propagated, as [`locked_identities`] does and for the same
/// reason: the constructors that call this are infallible, so one unrelated panic would otherwise
/// turn every later wrap into a second one.
fn state_for(client: &IDebugClient6) -> Arc<ClientState> {
    let key = client.as_raw() as usize;
    let mut states = client_states()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    states.retain(|_, state| state.strong_count() > 0);
    if let Some(live) = states.get(&key).and_then(Weak::upgrade) {
        return live;
    }
    let state = Arc::new(ClientState::default());
    states.insert(key, Arc::downgrade(&state));
    state
}

/// Identifies one open waiting for its target. Never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ArrivalId(u64);

/// The opens waiting for a target to join this session and stop, and what each has been given.
///
/// **This is a delivery register, where what it replaces was a broadcast.** `stopped_on` was an
/// engine-wide set of every `(engine id, system pid)` the engine had ever stopped on: every wait
/// wrote into it and every guard polled it, and because it outlived the opens that read it, it
/// needed a lifecycle of its own — pruned at both openers for pid reuse, cleared where a session
/// was replaced and again where one was ended, each of which arrived as a review finding
/// (dbgscope#133 rounds 7 to 9). A register of *pending* opens needs none of that: an entry lives
/// exactly as long as the guard that made it, so there is no stale record to prune, clear or
/// match by accident.
///
/// It also gives each open an identity, which is what closes the ambiguity [`Arrival`] used to
/// document as accepted: two launches pending at once could not be told apart, because the first
/// arrival was new to both snapshots and so ended both waits. A delivered arrival is **claimed**
/// here, so the second launch waits for the next one. The reason that fix was weighed and rejected
/// before is that it needed "new engine-wide state, cleared everywhere a session is replaced and
/// pruned for pid reuse" — which is the very cost this shape does not have.
#[derive(Debug, Default)]
struct Arrivals {
    /// Ids handed out so far. Never reused.
    minted: u64,
    /// Registered in the order the opens were made, which is the order arrivals are offered in.
    pending: Vec<Pending>,
}

/// What has been delivered to one open, if anything.
///
/// **Three states rather than an `Option`, because a claim that has gone is not a claim that was
/// never made.** [`Arrivals::forget_departed`] has to stop an open reporting a process that left
/// the session as arrived — an open whose target has gone has not arrived anywhere its caller can
/// use — and setting the field back to nothing did that by making the entry *pending again*. An
/// [`Arrival::Attached`] open wants any stop bearing its pid, and the finished one is registered
/// before the reattach's, so it was offered the reattached process first and the new open's
/// `wait()` timed out on a target sitting in front of it. Raised in review on dbgscope#139.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Claim {
    /// Nothing has been delivered to this open.
    Waiting,
    /// This process was, and the session still holds it.
    Arrived((u32, u32)),
    /// One was, and it has since left the session. A tombstone rather than a return to
    /// [`Self::Waiting`]: the open is finished, so it is never offered another arrival, and
    /// [`Arrivals::presence`] answers [`Presence::Absent`] for it.
    Departed,
}

impl Claim {
    /// The process delivered to this open and still held by the session, where there is one.
    fn held(self) -> Option<(u32, u32)> {
        match self {
            Self::Arrived(entry) => Some(entry),
            Self::Waiting | Self::Departed => None,
        }
    }
}

/// One registered open.
#[derive(Debug)]
struct Pending {
    id: ArrivalId,
    what: Arrival,
    /// What has been delivered to this open, and whether the session still holds it.
    claim: Claim,
    /// Processes another open was given before it finished, which this one must not be given now
    /// that the record of that claim has gone with its guard. See [`Arrivals::forget`].
    inherited: Vec<(u32, u32)>,
    /// Its guard is gone and it was never delivered anything, but its `CreateProcessWide` is still
    /// queued — so the entry stays to claim the process that create still produces. Nothing holds
    /// its id any more; it exists only to keep that process from the *next* launch, and it goes
    /// with the session ([`Arrivals::forget_all`]). See [`Arrivals::forget`], dbgscope#141.
    abandoned: bool,
}

impl Pending {
    /// Whether `entry` is the process this open is waiting for.
    ///
    /// `others` is every *other* pending open, and it is what keeps a launch and an attach pending
    /// together from satisfying each other: a launch is identified by elimination, so without it
    /// the process an attach is waiting for is new to the launch's snapshot and looks like the
    /// launch's own. It replaces reading `attached_processes` for that, and is better in the one
    /// way that matters here — the register is shared across wrappers where that set is not.
    ///
    /// `attached` is the delivering engine's own record, kept beside it rather than instead of it:
    /// it also covers an attach whose guard has been dropped, whose process joins the session with
    /// no registration left to name it.
    fn wants(&self, entry: (u32, u32), others: &[&Pending], attached: &HashSet<u32>) -> bool {
        // Somebody else has it, either still (`claim`) or by an inheritance left behind when
        // their guard went (`inherited`). Asked here rather than in `deliver` alone, because
        // `presence` asks the same question and would otherwise call another open's delivered
        // process evidence that *this* one is `Listed` -- and `Listed` is not `Absent`, so a
        // second launch interrupted before its own process joined answered `Ok(())` instead of
        // `LiveTargetInterrupted`. Raised in review on dbgscope#139.
        //
        // **It excludes attaches too, and that starves nobody**, which review read the other way
        // and is worth having measured here rather than argued again: two *live* attaches on one
        // pid cannot exist, because the kernel gives a process one debug port and refuses the
        // second attach outright -- measured on this engine, `AttachProcess` for an already
        // attached pid answers `0xD0000048 STATUS_PORT_ALREADY_SET`, so the second open fails in
        // `attach_process_begin` before it registers anything. The reachable case is a pid *reused*
        // after the first process left, and both openers call `prune_processes_that_left` before
        // registering, so the stale claim is already `Claim::Departed` and `held()` answers `None`.
        if self.inherited.contains(&entry)
            || others.iter().any(|other| other.claim.held() == Some(entry))
        {
            return false;
        }
        match &self.what {
            Arrival::Attached(pid) => entry.1 == *pid,
            // Nothing to eliminate against, so nothing can be concluded — and in particular this
            // must not claim an arrival some other open is entitled to.
            Arrival::Launched(None) => false,
            Arrival::Launched(Some(before)) => {
                // An attach still *waiting* for this pid, and only one. The exclusion is here
                // because a launch is identified by elimination, so the process an attach named is
                // new to the launch's snapshot and looks like the launch's own -- a reason that
                // holds exactly while the attach could still claim it. One already delivered is
                // covered by the `claim.held()` check above, which is exact where this is by pid;
                // one whose process has departed will never claim anything again, and leaving it
                // to exclude means a later launch that inherits the pid is refused its own stop by
                // an open that is finished with it. Raised in review on dbgscope#139.
                !before.contains(&entry)
                    && !attached.contains(&entry.1)
                    && !others.iter().any(|other| {
                        matches!(other.claim, Claim::Waiting)
                            && matches!(other.what, Arrival::Attached(pid) if pid == entry.1)
                    })
            }
        }
    }
}

impl Arrivals {
    /// Registers an open, and answers the id that names it.
    fn register(&mut self, what: Arrival) -> ArrivalId {
        self.minted += 1;
        let id = ArrivalId(self.minted);
        self.pending.push(Pending {
            id,
            what,
            claim: Claim::Waiting,
            inherited: Vec::new(),
            abandoned: false,
        });
        id
    }

    /// The pid an [`Arrival::Attached`] open is waiting for, where `id` names one.
    fn attached_pid(&self, id: ArrivalId) -> Option<u32> {
        self.pending
            .iter()
            .find(|pending| pending.id == id)
            .and_then(|pending| match pending.what {
                Arrival::Attached(pid) => Some(pid),
                Arrival::Launched(_) => None,
            })
    }

    /// Forgets an open, when its guard is dropped — **handing its claim to the opens still
    /// waiting**.
    ///
    /// A claim has to outlive the entry that made it, and that is not a lifecycle creeping back
    /// in: it is inherited by the opens that exist *now* and goes when they do, where the record
    /// this replaced lived for the whole session. Without it, two overlapping launches come apart
    /// again the moment the first guard is consumed — its target's *next* genuine stop is then
    /// claimed by nobody, is absent from the second launch's snapshot because it did not exist
    /// when that snapshot was taken, and is delivered to the second launch, whose `wait()` returns
    /// `Ok` for a process that never stopped. Raised in review on dbgscope#139; the ambiguity this
    /// stage closes was otherwise closed only while both guards were held.
    ///
    /// It is handed to **every** open still waiting rather than along a chain, so an inheritance
    /// needs no forwarding of its own: a claim reaches an open directly or not at all, and one
    /// registered after this call has the process in its own snapshot. Also raised on dbgscope#139,
    /// as a non-transitive handoff; `test_a_claim_is_inherited_by_every_open_still_waiting` is what
    /// pins it, since with two opens "every remaining open" and "the next one" are the same set.
    ///
    /// A [`Claim::Departed`] one is handed to nobody: [`Self::forget_departed`] has already taken
    /// that process out of every inheritance, and putting it back is the stale claim that method
    /// exists to remove.
    /// Forgets an open **outright**, whatever state it is in — for an open whose wait has ended in
    /// a way that says its process is not coming.
    ///
    /// [`Self::forget`] is the ordinary path and keeps an abandoned launch's place in the queue,
    /// which is right when the guard was simply dropped: the create is still queued and its process
    /// is still on its way. It is wrong when the open pumped its whole bound and nothing came,
    /// because the entry then survives to take the *next* launch's stop — the failure keeping it
    /// exists to prevent, from the other side. Raised in review on dbgscope#143.
    fn discard(&mut self, id: ArrivalId) {
        let Some(index) = self.pending.iter().position(|pending| pending.id == id) else {
            return;
        };
        let claimed = self.pending[index].claim.held();
        self.pending.remove(index);
        if let Some(entry) = claimed {
            for pending in &mut self.pending {
                pending.inherited.push(entry);
            }
        }
    }

    fn forget(&mut self, id: ArrivalId) {
        let Some(index) = self.pending.iter().position(|pending| pending.id == id) else {
            return;
        };
        // **A launch abandoned before it was delivered anything keeps its place in the queue**
        // (dbgscope#141). Dropping the guard does not un-queue the `CreateProcessWide` behind it,
        // so that process still arrives — and it is new to the *next* launch's snapshot, because
        // it did not exist when that snapshot was taken, so without this the next launch claims it
        // and its `wait()` returns for a target it never asked for. Measured before it was fixed:
        // a launch of `ping.exe` behind an abandoned `cmd.exe` was delivered the `cmd.exe`.
        //
        // The entry is kept rather than an exclusion left behind, because there is nothing to
        // exclude yet — which process the create will produce is exactly what nobody knows. Being
        // first in registration order is what makes it right: `deliver` offers in that order, and
        // the engine realises queued creates in it.
        //
        // **Only a launch, and only one that has been given nothing.** An abandoned *attach* is
        // already covered by the engine's `attached_processes`, which is what `Pending::wants`
        // reads it for; and an entry that has a claim is removed and its claim inherited, as
        // before. `Launched(None)` is removed too: it can never claim anything, so keeping it
        // would leave an entry that does nothing at all.
        if self.pending[index].claim == Claim::Waiting
            && matches!(self.pending[index].what, Arrival::Launched(Some(_)))
        {
            self.pending[index].abandoned = true;
            return;
        }
        self.discard(id);
    }

    /// Drops every claim and inherited exclusion naming a process the session no longer holds.
    ///
    /// **The reuse hazard the record this replaced was pruned for, arriving from the other side.**
    /// Engine ids are handed back immediately — measured, detaching id 0 and attaching another
    /// process hands the freed 0 straight back — so a `.detach` and a reattach of the same pid
    /// reproduce a `(engine id, pid)` pair exactly. Where a stale entry in the old set made a new
    /// open read `Arrived` for a target that had not stopped, a stale *claim* here makes it read
    /// the opposite: the pair is spoken for, so the reattach's own stop is refused as somebody
    /// else's and its `wait()` times out on a target sitting in front of it. Raised in review on
    /// dbgscope#139.
    ///
    /// Dropping the claim rather than only the exclusion is deliberate and is what the old prune
    /// did: an open whose target has left the session has not arrived anywhere its caller can use,
    /// and [`Self::presence`] should say `Absent` rather than `Arrived` about a process that is
    /// gone.
    ///
    /// **It becomes [`Claim::Departed`] and not [`Claim::Waiting`]**, or the open that finished is
    /// pending again and takes the next arrival it happens to want ahead of whoever is really
    /// waiting for it — see [`Claim`].
    fn forget_departed(&mut self, held: &[(u32, u32)]) {
        let still_here = |entry: &(u32, u32)| held.contains(entry);
        for pending in &mut self.pending {
            if pending
                .claim
                .held()
                .is_some_and(|entry| !still_here(&entry))
            {
                pending.claim = Claim::Departed;
            }
            pending.inherited.retain(still_here);
        }
    }

    /// Forgets every open, when the session they were waiting on is replaced.
    ///
    /// A guard held across that keeps its id; the id then names nothing, and
    /// [`Self::presence`] answers [`Presence::Absent`] for it — which is the truth, since the
    /// session it was waiting on is gone.
    fn forget_all(&mut self) {
        self.pending.clear();
    }

    /// Routes a stop to the open that wants it, if any.
    ///
    /// **First registered wins**, which is the whole of what makes two pending launches
    /// distinguishable: the arrival is offered in registration order and claimed by one open, so
    /// the second launch is still waiting when the next one comes.
    ///
    /// A process already claimed is offered to nobody, which [`Pending::wants`] enforces for every
    /// caller rather than this one alone: a target stops more than once in a session -- every later
    /// break is a stop on the same process -- and a second delivery would hand an open still
    /// waiting an event belonging to a target it never asked about.
    fn deliver(&mut self, entry: (u32, u32), attached: &HashSet<u32>) {
        let Some(index) = self.pending.iter().position(|pending| {
            let others: Vec<&Pending> = self
                .pending
                .iter()
                .filter(|other| other.id != pending.id)
                .collect();
            matches!(pending.claim, Claim::Waiting) && pending.wants(entry, &others, attached)
        }) else {
            return;
        };
        self.pending[index].claim = Claim::Arrived(entry);
    }

    /// Where the open `id` is waiting for has got to, given what the session currently holds.
    ///
    /// An id that names nothing is [`Presence::Absent`]: either the session was replaced under a
    /// guard still held, or the guard is gone and nobody is asking. So is one whose process has
    /// left the session, which is the same answer for the same reason — there is nothing there to
    /// go and look at.
    ///
    /// **A claim is read against `held` and not believed on its own**, which is the half of the
    /// old shape worth keeping: `presence_of` used to locate the process in the session *first*
    /// and ask whether it had stopped second, so `Arrived` could not outlive the target. Answering
    /// from the claim alone let it, because [`Self::forget_departed`] runs from the openers — a
    /// session that opens nothing more never prunes, so a target delivered and since gone stayed
    /// `Arrived` indefinitely and a guard's `wait()` returned `Ok(())` for a process the caller
    /// could not read. Raised in review on dbgscope#139, against this branch's own regression.
    ///
    /// It costs the open the rest of its bound — the answer is `Absent`, so the loop pumps on —
    /// and that is what every release has done. Saying "it arrived and left" would be a fourth
    /// [`Presence`], and nothing above here has a use for the distinction yet.
    fn presence(&self, id: ArrivalId, held: &[(u32, u32)], attached: &HashSet<u32>) -> Presence {
        let Some(pending) = self.pending.iter().find(|pending| pending.id == id) else {
            return Presence::Absent;
        };
        match pending.claim {
            Claim::Arrived(entry) if held.contains(&entry) => return Presence::Arrived,
            // Delivered, and gone since — whether or not a prune has caught up with it.
            Claim::Arrived(_) | Claim::Departed => return Presence::Absent,
            Claim::Waiting => {}
        }
        if matches!(pending.what, Arrival::Launched(None)) {
            return Presence::Unknown;
        }
        let others: Vec<&Pending> = self
            .pending
            .iter()
            .filter(|other| other.id != pending.id)
            .collect();
        if held
            .iter()
            .any(|entry| pending.wants(*entry, &others, attached))
        {
            Presence::Listed
        } else {
            Presence::Absent
        }
    }
}

/// Which operations the engine is running, and which of them a host has asked to break.
///
/// **The whole of dbgscope#136 stage 2 is that these two facts live under one lock.** They used to
/// be one engine-wide `AtomicBool` answering *has an interrupt been requested*, where every reader
/// wanted *was **this** operation asked to stop*. Six operations cleared it as they opened, so a
/// request could be erased between being lodged and being delivered (#135 half A), and a reader
/// could be charged for a request aimed at its predecessor.
///
/// Nothing here is clever. `running` is a stack because operations **nest** — a kernel attach's
/// `absorb_initial_break_artifact` runs an `execute_and_wait` inside
/// [`DebugEngine::wait_for_kernel_break_in`], which is the case a single slot silently got wrong
/// and a `bool` could not have expressed at all. `asked` is a set for the same reason: with an
/// outer operation asked and an inner one begun since, two requests are outstanding at once.
#[derive(Debug, Default)]
struct BreakScope {
    /// Ids handed out so far. Never reused.
    minted: u64,
    /// The operations the engine is inside, outermost first. Empty between operations.
    running: Vec<OperationId>,
    /// Operations a host has asked to break, and that have not yet accounted for it. An entry
    /// leaves when its operation takes it, or when that operation ends without having.
    asked: std::collections::BTreeSet<OperationId>,
}

impl BreakScope {
    /// Opens an operation and returns its id.
    fn begin(&mut self) -> OperationId {
        self.minted += 1;
        let id = OperationId(self.minted);
        self.running.push(id);
        id
    }

    /// The operation a break issued *now* would stop: the innermost one running.
    fn innermost(&self) -> Option<OperationId> {
        self.running.last().copied()
    }

    /// Files a request against `operation`.
    fn record(&mut self, operation: OperationId) {
        self.asked.insert(operation);
    }

    /// Takes the request filed against `operation`, if any.
    fn take(&mut self, operation: OperationId) -> bool {
        self.asked.remove(&operation)
    }

    /// Closes `operation`, and answers whether it left a request unread.
    ///
    /// By id rather than by popping, so an out-of-order close cannot leave a stale id behind for a
    /// later request to be filed against. Guards are lexical here and nesting is two deep, so this
    /// costs nothing and removes a panic path.
    ///
    /// The answer matters because a request nobody read is one the engine is still holding: see
    /// [`Operation::drop`].
    fn end(&mut self, operation: OperationId) -> bool {
        self.running.retain(|running| *running != operation);
        self.asked.remove(&operation)
    }
}

/// A bounded operation, open for as long as this guard lives.
///
/// A break a host raises while this exists is filed against **this** operation and no other, and
/// is gone when the guard drops whether it was read or not. That is the whole of what replaced
/// clearing an engine-wide flag at six call sites: there is nothing to clear, so there is nothing
/// a request can be erased by.
///
/// **An operation accepts requests for longer than it reads them**, which is a real window and not
/// a tidy one. [`Self::took_break_request`] is the last read on most paths, and everything after it
/// — the rest of [`DebugEngine::pump`], the caller assembling its result, this guard dropping — is
/// time in which [`InterruptHandle::interrupt`] still names this operation and still answers
/// [`BreakRequest::Raised`]. It cannot be closed at the take, because
/// [`DebugEngine::wait_for_live_target`] pumps repeatedly inside one operation and a request
/// arriving between two of its pumps is one the next pump legitimately reads. What [`Self::drop`]
/// does about it is below.
struct Operation<'a> {
    engine: &'a DebugEngine,
    id: OperationId,
}

impl Operation<'_> {
    /// Takes the break request a host filed against this operation, if any.
    ///
    /// Taken and not read, because the request belongs to this operation: left standing it would
    /// be charged to whatever ran next, which is #135 half B.
    fn took_break_request(&self) -> bool {
        self.engine
            .state
            .breaks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take(self.id)
    }

    /// What cut this operation short, for a bound of `after_ms`, when it is **not** a pump.
    ///
    /// [`WaitOutcome::cut_short`] is the same question for the paths that wait. `by_watchdog` and
    /// the host's request are now genuinely independent signals rather than two readings of one
    /// flag — the watchdog goes through [`InterruptHandle::break_in_only`] and records nothing —
    /// so the watchdog wins only where both are true, and that is a real coincidence rather than
    /// a disambiguation.
    fn cut_short_by(&self, by_watchdog: bool, after_ms: u32) -> Option<Interruption> {
        let asked = self.took_break_request();
        match (by_watchdog, asked) {
            (true, _) => Some(Interruption::Deadline { after_ms }),
            (false, true) => Some(Interruption::OnRequest),
            (false, false) => None,
        }
    }
}

impl Drop for Operation<'_> {
    /// Closes the operation — and **drains the engine's own pending request** if it is closing on
    /// one nobody read.
    ///
    /// A request filed after this operation's last read has no reader: this discards the record,
    /// and without the drain the `SetInterrupt` behind it would still be pending, free to break
    /// into whatever ran next with nothing to explain it. Draining is the policy this crate already
    /// applies wherever a break belongs to no operation — `execute_and_wait`, `settle` and the
    /// bounded command path all consume "anything the engine did not, so the next operation starts
    /// clean" — generalised to the one window that had no site to put it at.
    ///
    /// **Only when a record is discarded**, which is what keeps it from consuming a request some
    /// other operation is entitled to. A request this operation *read* is already accounted for;
    /// its call site drains as it always did, and a second drain on a flag is harmless anyway.
    ///
    /// Outside the lock, because it is a COM call and holding a mutex across one buys nothing here.
    /// Best-effort: this runs on unwind paths, so it has nowhere to report a failure and must not
    /// panic.
    fn drop(&mut self) {
        let unread = self
            .engine
            .state
            .breaks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .end(self.id);
        if unread {
            let _ = self.engine.interrupted();
        }
    }
}

/// How often a watchdog past its deadline raises the break again.
///
/// One `SetInterrupt` is a request, not a guarantee: the engine acts on it at its next poll, and a
/// busy operation can be between polls when it arrives. Repeating costs one call on a path that
/// has already given up on the deadline.
const WATCHDOG_REPEAT: Duration = Duration::from_millis(200);

/// A thread that Ctrl+Breaks an operation once a deadline passes — and that stops **the moment**
/// it is disarmed, rather than at the end of a poll interval.
///
/// That last property is the whole reason this is a type rather than two `thread::spawn`s.
/// Both bounded paths here used to poll a flag on a fixed sleep, so `join` waited out whatever was
/// left of it: **every** bounded operation paid up to one interval, whether or not it came close to
/// its deadline. windbg-mcp measured that tax at ~200ms on a command whose unbounded median was
/// 0.22ms, and routed its cheap queries around the bounded path to avoid it — a design decision
/// taken to work around a sleep. A condition variable makes the disarm immediate, so the bound
/// costs nothing until it is actually reached.
///
/// The break itself is a closure rather than an [`InterruptHandle`], which is what lets the
/// behaviour be tested without a debuggee: the unit tests below arm one over a counter.
struct Watchdog {
    /// Set by [`Self::disarm`] and read by the thread; the condvar is what wakes it to see that.
    disarmed: Arc<(Mutex<bool>, Condvar)>,
    /// Whether the deadline was ever reached — the fact a caller needs, since a forced break is
    /// not the event it was waiting for.
    fired: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Watchdog {
    /// Arms a watchdog that calls `on_deadline` once `deadline` has passed, and again every
    /// [`WATCHDOG_REPEAT`] until it is disarmed.
    ///
    /// A zero `deadline` fires immediately, which is what a caller asking for no time at all
    /// means; a caller wanting *no bound* does not arm one.
    fn arm(deadline: Duration, on_deadline: impl Fn() + Send + 'static) -> Self {
        let disarmed = Arc::new((Mutex::new(false), Condvar::new()));
        let fired = Arc::new(AtomicBool::new(false));
        let woken = Arc::clone(&disarmed);
        let raised = Arc::clone(&fired);
        let thread = thread::spawn(move || {
            let (lock, wake) = &*woken;
            let start = Instant::now();
            loop {
                // Past the deadline the only question left is when to repeat; before it, sleep
                // exactly as long as there is left, so a watchdog that is never reached wakes
                // once.
                let nap = if raised.load(Ordering::SeqCst) {
                    WATCHDOG_REPEAT
                } else {
                    deadline.saturating_sub(start.elapsed())
                };
                {
                    let stop = lock.lock().unwrap_or_else(|e| e.into_inner());
                    if *stop {
                        return;
                    }
                    // The guard is dropped at the end of this block, so the interrupt below is
                    // never raised while holding a lock the disarming thread wants.
                    let (stop, _) = wake
                        .wait_timeout(stop, nap)
                        .unwrap_or_else(|e| e.into_inner());
                    if *stop {
                        return;
                    }
                }
                // A spurious wake-up lands here too, and is harmless: the deadline decides,
                // not the fact of having woken.
                if start.elapsed() >= deadline {
                    on_deadline();
                    raised.store(true, Ordering::SeqCst);
                }
            }
        });
        Self {
            disarmed,
            fired,
            thread: Some(thread),
        }
    }

    /// Stops the watchdog, waits for its thread, and reports whether it had raised a break.
    fn disarm(mut self) -> bool {
        self.stop();
        self.fired.load(Ordering::SeqCst)
    }

    /// Idempotent, so [`Drop`] can run it again after [`Self::disarm`] already has — and so a
    /// panic between arming and disarming still ends the thread rather than leaking it.
    fn stop(&mut self) {
        {
            let (lock, wake) = &*self.disarmed;
            let mut stop = lock.lock().unwrap_or_else(|e| e.into_inner());
            *stop = true;
            wake.notify_all();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Whether an execution status means the engine has been told to run and is waiting for a
/// `WaitForEvent` to pump it.
///
/// Every go and every step, forward and reverse — not `DEBUG_STATUS_BREAK` (stopped),
/// `DEBUG_STATUS_NO_DEBUGGEE` (nothing to run) or the housekeeping statuses, all of which are
/// states an ordinary command can be issued in.
///
/// Masked because `GetExecutionStatus` is documented to carry flags above the status itself
/// (`DEBUG_STATUS_INSIDE_WAIT`, `DEBUG_STATUS_WAIT_TIMEOUT`); they do not fit the `u32` this
/// binding returns, so the mask is insurance rather than a fix, and it costs nothing.
fn is_running_status(status: u32) -> bool {
    matches!(
        status & DEBUG_STATUS_MASK,
        DEBUG_STATUS_GO
            | DEBUG_STATUS_GO_HANDLED
            | DEBUG_STATUS_GO_NOT_HANDLED
            | DEBUG_STATUS_STEP_OVER
            | DEBUG_STATUS_STEP_INTO
            | DEBUG_STATUS_STEP_BRANCH
            | DEBUG_STATUS_REVERSE_GO
            | DEBUG_STATUS_REVERSE_STEP_BRANCH
            | DEBUG_STATUS_REVERSE_STEP_OVER
            | DEBUG_STATUS_REVERSE_STEP_INTO
    )
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
    /// The target went away before it reached anything: it ran to completion, or its session was
    /// torn down. Terminal, and the same ending [`CommandRun::target_gone`] reports — nothing
    /// will run against this engine again. Says nothing about whether `address` was reachable.
    TargetGone,
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

/// What one `WaitForEvent` did — produced **once**, by the call that waited.
///
/// The engine offers four endings and no two of them mean the same thing to a caller, but three of
/// the four are invisible from outside the wait: `S_OK` and `S_FALSE` are flattened into one
/// `Ok(())` by the generated wrapper, and a break has already been serviced by the time anything
/// downstream could look. So a wait answering `Result<(), _>` left its outcome to be reconstructed
/// afterwards, out of shared mutable state, by whoever needed it — an engine-wide interrupt flag
/// read twice (since scoped to an operation, [`BreakScope`]), the session's process list read
/// twice, and the one fact only the waiting call knew (the `HRESULT`) gone. dbgscope#136 has the derivation: 15 of the 22 findings on one review were
/// downstream of that.
///
/// Attribution *at* the wait is sound because waits are single-threaded here: nothing can overwrite
/// the engine's last-event slot between `WaitForEvent` returning and the read below it, so this has
/// no window that reading afterwards did not already have — it just has one reader instead of
/// three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// An event arrived and the engine stopped.
    ///
    /// `process` is the `(engine id, system pid)` that event belongs to, where the last-event slot
    /// named a process this session still lists. `None` is that join failing, which is "nothing to
    /// add" rather than a failure — an engine with no event to name, a dump, an event belonging to
    /// no process here. It is the pair [`Arrivals::deliver`] routes to whichever open was waiting
    /// for it, answered here as well so a caller pumping the engine itself can see what its pump
    /// completed.
    Stopped { process: Option<(u32, u32)> },
    /// A finite bound passed with no event: `WaitForEvent` answered `S_FALSE`, and the target is
    /// **still running** with the engine holding no current process/thread.
    ///
    /// Unreachable on a watchdog bound, whose wait is `INFINITE`.
    Expired,
    /// This crate's own watchdog Ctrl+Broke the target at its deadline. The stop, if there is one,
    /// is that break rather than the event anybody was waiting for.
    Deadline,
    /// A host asked for a break through an [`InterruptHandle`]. The same stop as
    /// [`Self::Deadline`], reported apart from it because the advice differs — see
    /// [`Interruption`].
    OnRequest,
}

impl WaitOutcome {
    /// Whether a break ended this wait rather than the target's own event.
    ///
    /// Both origins, because both are a reason to stop pumping: what the engine stopped on is not
    /// what the caller was waiting for, and going round again spends the caller's bound on an event
    /// nobody asked for.
    pub fn broke_in(self) -> bool {
        matches!(self, Self::Deadline | Self::OnRequest)
    }

    /// This outcome as the [`Interruption`] a [`CommandRun`] reports, for a bound of `after_ms`.
    ///
    /// `after_ms` is the caller's and not this value's: an outcome says *what* happened, and the
    /// operation says what it had allowed.
    pub fn cut_short(self, after_ms: u32) -> Option<Interruption> {
        match self {
            Self::Deadline => Some(Interruption::Deadline { after_ms }),
            Self::OnRequest => Some(Interruption::OnRequest),
            Self::Stopped { .. } | Self::Expired => None,
        }
    }
}

/// How a pump is bounded — a difference in kind, not in length.
///
/// Picking the wrong one is not a matter of taste: see [`DebugEngine::execute_and_wait`], whose
/// finite wait on a `go` with nothing to stop it left every later command in the session failing
/// `0x80040205`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bound {
    /// `WaitForEvent(timeout_ms)`. Expiry is [`WaitOutcome::Expired`], which leaves the target
    /// still running and is unrecoverable on every target type — so this is for a caller that will
    /// pump again, and a live kernel refuses it outright (`E_NOTIMPL`).
    Finite(u32),
    /// `WaitForEvent(INFINITE)` with a watchdog that Ctrl+Breaks the target at `timeout_ms` through
    /// `SetInterrupt`, the one DbgEng call safe from another thread — so the wait returns instead
    /// of hanging the single engine thread on a `go` that never hits a breakpoint, or an attach
    /// whose target is reachable but will not break in.
    ///
    /// **Limitation: `SetInterrupt` can only unblock a wait once the target is *connected*.** A
    /// wait still establishing a KDNET link cannot be cancelled this way and blocks like `kd`
    /// itself does on a dead connection. Measured (`cargo run --example kdtest -- --timeout-probe`,
    /// in-box dbgeng on Windows 11 26200): dialing a port nothing answers on returned from
    /// `AttachKernel` in ~8ms and was still blocked in this wait when killed at 300s — five times
    /// `timeout_ms`, no return. So [`WaitOutcome::Deadline`] can only ever be reported for a target
    /// that connected; an unreachable one hangs instead of timing out.
    Watchdog(u32),
    /// Abandon an experimental attach wait without requesting another target break.
    /// This is not a guarantee that an unconnected transport can be cancelled.
    WatchdogExit(u32),
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
    /// The engine held no debuggee once this run ended: the target exited, or the session was
    /// otherwise torn down under the pump.
    ///
    /// **Terminal, and not a failure.** A program running to completion is the ordinary end of a
    /// `go`, and it is the one ending that leaves the engine unable to answer about a target ever
    /// again — every later command fails, and execution control *faults the process*
    /// ([`DebugEngine::execute_command_bounded`]). It is reported here rather than as an `Err`
    /// because the output above it is real and this is the only copy of it: the module loads, a
    /// breakpoint banner, whatever an embedded script printed before the target ran out. A caller
    /// should report the ending and retire the session; nothing will run against this engine
    /// again.
    ///
    /// It is not only the pumping paths that report it. A command can take the target away
    /// *itself* — measured, `.detach` leaves `DEBUG_STATUS_NO_DEBUGGEE` the moment it returns,
    /// with nothing left to pump and so nothing for [`DebugEngine::settle`] to report — so
    /// [`DebugEngine::execute_command_bounded`] answers the same question after its command.
    /// One field, whichever way the target went.
    ///
    /// (`.kill` is not one of them, which is worth knowing before pattern-matching on command
    /// names instead: it leaves the engine at `DEBUG_STATUS_BREAK` with a readable stack in
    /// `ntdll!LdrShutdownProcess`, and the target goes away on the *next* resume, which is where
    /// the pump reports it.)
    pub target_gone: bool,
}

impl CommandRun {
    /// The output, for a caller that has already dealt with [`Self::cut_short`] — or one running a
    /// command it knows cannot be interrupted.
    pub fn into_output(self) -> String {
        self.output
    }
}

/// What one of [`DebugEngine::spend_pending_break_ins`]'s resumes settled about the break-ins a
/// kernel attach still owes.
///
/// Split from the engine call so the loop's termination rule can be driven by a test: the two
/// facts it turns on — how a run ended, and whether the target is still there — are the whole of
/// what the engine contributes, and [`Drain`] decides everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resumed {
    /// It came back on its own, which for a resume that short means a break-in was waiting — and
    /// not a caller's breakpoint, `clear_all_breakpoints` having taken those off the target first.
    /// That is one fewer for `qd` to lose.
    OnABreak,
    /// The deadline stopped it: the target ran the whole window without stopping, so nothing was
    /// pending in this one.
    Freely,
    /// A host asked for the break. That says nothing about what the target was doing, so it is
    /// **not** a free run — counting it as one is how a drain stops early and leaves the break-in
    /// for `qd`.
    OnRequest,
    /// The target has gone. Nothing is owed, and nothing more can be learned by resuming.
    Gone,
}

impl Resumed {
    /// Reads one run. `target_gone` first: a run that lost its target may also have been cut
    /// short, and which of the two happened decides whether resuming again is worth anything.
    fn of(run: &CommandRun) -> Self {
        match (run.target_gone, run.cut_short) {
            (true, _) => Self::Gone,
            (false, Some(Interruption::Deadline { .. })) => Self::Freely,
            (false, Some(Interruption::OnRequest)) => Self::OnRequest,
            (false, None) => Self::OnABreak,
        }
    }
}

/// How much of a drain has been spent, and what it has learned. See
/// [`DebugEngine::spend_pending_break_ins`].
#[derive(Debug, PartialEq, Eq)]
struct Drain {
    /// How many resumes this drain may spend, from [`Self::for_processors`]. A per-target number
    /// rather than a constant, because what a target can owe scales with its processor count.
    attempts: usize,
    /// Resumes spent, against [`Self::attempts`].
    spent: usize,
    /// Resumes answered by a break-in.
    delivered: usize,
    /// Consecutive free runs, against [`DebugEngine::DRAIN_FREE_RUNS`]. Reset by a delivered
    /// break.
    free_runs: usize,
    /// The target has gone; no further resume can say anything.
    gone: bool,
}

impl Default for Drain {
    /// [`DebugEngine::DRAIN_ATTEMPTS`], which is what a target whose processor count could not be
    /// read gets. Not zero: a drain that spends nothing is the behaviour this whole path exists to
    /// replace.
    fn default() -> Self {
        Self {
            attempts: DebugEngine::DRAIN_ATTEMPTS,
            spent: 0,
            delivered: 0,
            free_runs: 0,
            gone: false,
        }
    }
}

impl Drain {
    /// A drain sized for a target with this many processors: **one resume per processor, plus the
    /// free runs that end it**, and never fewer than [`DebugEngine::DRAIN_ATTEMPTS`].
    ///
    /// **Measured on a four-processor hypervisor, 2026-09-21.** A `run_to_address` that hit a
    /// software breakpoint in code every processor runs left *three* further stops behind it —
    /// one per other processor, each a first-chance `0x80000003` at the breakpoint's own address
    /// and on that processor's own stack, delivered one per resume, after which the target ran
    /// free. So a target owes up to one per processor and the old constant was a coincidence: five
    /// is exactly three plus two, and a guest with one more processor would have exhausted it with
    /// a stop still owing.
    ///
    /// The count comes from the target rather than from the host — `GetNumberProcessors` — and
    /// four is the largest lab this was measured on. What scales it beyond that is the
    /// one-per-processor rule above rather than a second measurement.
    fn for_processors(processors: u32) -> Self {
        let owed = usize::try_from(processors).unwrap_or(usize::MAX);
        Self {
            attempts: owed
                .saturating_add(DebugEngine::DRAIN_FREE_RUNS)
                .max(DebugEngine::DRAIN_ATTEMPTS),
            ..Self::default()
        }
    }

    /// Whether another resume is worth spending.
    fn resume_again(&self) -> bool {
        !self.gone && self.spent < self.attempts && self.free_runs < DebugEngine::DRAIN_FREE_RUNS
    }

    /// Folds in what one resume settled.
    fn saw(&mut self, resumed: Resumed) {
        self.spent += 1;
        match resumed {
            Resumed::OnABreak => {
                self.delivered += 1;
                self.free_runs = 0;
            }
            Resumed::Freely => self.free_runs += 1,
            // Neither evidence of a free run nor of a break-in: it costs an attempt and leaves the
            // count where it was.
            Resumed::OnRequest => {}
            Resumed::Gone => self.gone = true,
        }
    }
}

/// What a bounded read produced, and whether it got all of it — the same shape as [`CommandRun`],
/// and for the same reason.
///
/// A `Vec<u8>` alone cannot answer "is this the range I asked for?", and a read cut short is
/// exactly the case where the bytes look like an answer and are not: a caller decoding a structure
/// out of them would read its tail from zeroes that were never filled. So the bytes are truncated
/// to what was actually read, and `cut_short` says why there are no more.
///
/// Not an `Err`, for the reason [`CommandRun`] is not: the bytes up to the stop are real, and on a
/// read that spent a caller's whole budget getting them they are the only copy.
#[derive(Debug, Clone)]
pub struct MemoryRead {
    /// The bytes read, contiguous from the address asked for. Shorter than the request exactly
    /// when [`Self::cut_short`] is `Some` — a range the *target* could not answer for is a
    /// [`DbgEngError::ShortRead`] instead, as it is for [`DebugEngine::read_memory`].
    pub bytes: Vec<u8>,
    /// `None` when the whole range was read.
    pub cut_short: Option<Interruption>,
}

/// `QueryVirtual`'s output buffer, **16-byte aligned**, which the type it holds is not.
///
/// `MEMORY_BASIC_INFORMATION64` is 48 bytes of 8-byte fields, so Rust aligns it to 8 — and the
/// engine's *live-target* path copies the answer out with three `movaps` stores, which fault on
/// anything less than 16. Measured on 26200 (`dbgeng!Ordinal367+0x14f96`,
/// `movaps xmmword ptr [rbx],xmm0`, 2026-09-24): an 8-aligned buffer took an access violation
/// **inside dbgeng** on the first call against a live process, with nothing in the Rust frames
/// to suggest the caller was at fault.
///
/// The crash is path-dependent, which is what makes it worth a type rather than a comment: the
/// dump path copies the same structure field by field, so the identical call against a full
/// dump answered 22 queries with no alignment at all. Testing this on a dump proves nothing
/// about it.
#[repr(C, align(16))]
#[derive(Default)]
struct AlignedMemoryInfo(MEMORY_BASIC_INFORMATION64);

/// One run of pages as the memory manager describes it; see [`DebugEngine::virtual_region`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualRegion {
    /// The first address of the run, which is at or below the address asked about.
    pub base: u64,
    /// Its length in bytes. Zero would mean the engine described nothing, and callers that act
    /// on a region have to check for it rather than assume a query that succeeded covers the
    /// address it was given.
    pub size: u64,
    pub state: VirtualState,
    /// `PAGE_*` protection, verbatim. Meaningless on a [`VirtualState::Free`] run, and for
    /// [`VirtualState::Reserved`] it is `AllocationProtect` rather than a page protection.
    pub protect: u32,
}

impl VirtualRegion {
    /// Whether this run covers `address` — what a caller needs before reading anything off it.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base && address - self.base < self.size
    }

    /// The last address in the run, or `None` for an empty one.
    pub fn end(&self) -> Option<u64> {
        (self.size != 0).then(|| self.base.saturating_add(self.size))
    }
}

/// Whether a run of pages holds anything.
///
/// The distinction [`DebugEngine::virtual_region`] exists for: address space that was never
/// committed can hold nothing, so a walk that cannot read it has missed nothing, while committed
/// memory that will not read is a real hole in what the walk saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtualState {
    /// `MEM_FREE`: not reserved at all.
    Free,
    /// `MEM_RESERVE`: address space claimed, no pages behind it.
    Reserved,
    /// `MEM_COMMIT`: pages exist. They may still be unreadable — paged out, or absent from a
    /// dump — which is exactly the case a walk must keep counting against its coverage.
    Committed,
    /// A `State` this build of the engine returned and this crate does not name. Kept rather
    /// than folded into one of the three above, because guessing which way it folds is the one
    /// thing that would make this primitive lie: read as `Reserved` it would excuse a gap that
    /// is real, and read as `Committed` it would refuse to excuse one that is not.
    Unknown(u32),
}

impl VirtualState {
    fn from_mem_state(state: u32) -> Self {
        // `VIRTUAL_ALLOCATION_TYPE` is a flag word, and the three states are disjoint bits in
        // it, so this matches on the bit rather than on equality: `MEM_COMMIT` arrives beside
        // other bits on some queries and an `==` would send it to `Unknown`.
        match state {
            _ if state & MEM_COMMIT.0 != 0 => Self::Committed,
            _ if state & MEM_RESERVE.0 != 0 => Self::Reserved,
            _ if state & MEM_FREE.0 != 0 => Self::Free,
            other => Self::Unknown(other),
        }
    }

    /// Whether pages are behind this address space. `false` for both `MEM_RESERVE` and
    /// `MEM_FREE`; `None` when the engine named a state this crate does not know, where the
    /// caller must fall back rather than choose.
    pub fn committed(self) -> Option<bool> {
        match self {
            Self::Committed => Some(true),
            Self::Reserved | Self::Free => Some(false),
            Self::Unknown(_) => None,
        }
    }
}

/// How much of a bounded read to ask the engine for per `ReadVirtual`.
///
/// **This sets the residual overshoot, and that is the whole guarantee.** A bounded read is not
/// bounded the way [`DebugEngine::execute_command_bounded`] is — see
/// [`DebugEngine::read_memory_bounded`] for why no watchdog is armed — so the deadline is observed
/// *between* transfers, and a read can finish one of them past its budget. One page is the
/// smallest useful unit to build that residual from: it is what the target's memory is readable or
/// not in, so a chunk that starts page-aligned either comes back whole or fails at its first byte,
/// and the total a cut-short read reports is the same total a single `ReadVirtual` of the same
/// range would have.
///
/// The same technique as `pool::snapshot`'s `EXTENT_READ_CHUNK`, sized for a different promise.
/// That one bounds a *walk* — thousands of reads, where the budget is a ceiling on total effort
/// and 256 KiB a chunk keeps a megabyte-scale extent to a handful of transfers. This one bounds a
/// *single call* whose caller has told somebody else when it will be done, so the residual is the
/// figure that matters and the transfer count is not.
const READ_CHUNK_BYTES: usize = 4096;

/// How many bytes the next chunk of a read covers: up to the end of the page `done` bytes in, and
/// never past what is left.
///
/// The first chunk is trimmed to the page boundary rather than taking a whole
/// [`READ_CHUNK_BYTES`], which is what makes every chunk after it lie **within** one page. Without
/// that trim an unaligned read would have every chunk straddle two pages, so a chunk whose second
/// page is a hole would come back short and stop the read a page earlier than the range allows —
/// reporting a smaller total than a single `ReadVirtual` of it.
fn read_chunk_len(address: u64, done: usize, size: usize) -> usize {
    let at = address.wrapping_add(done as u64);
    let to_page_end = READ_CHUNK_BYTES - (at as usize % READ_CHUNK_BYTES);
    size.saturating_sub(done).min(to_page_end)
}

/// Reads `size` bytes from `address` a chunk at a time, asking `halt` before each one whether to
/// stop.
///
/// A free function taking the read as a closure, for the reason [`Watchdog::arm`] takes its break
/// as one: it is what lets the rules below be asserted without a debuggee, over a reader that can
/// be made to come back short, to fail, or to outlast a deadline on demand.
///
/// **The check sits before each read, never after**, so the residual is one chunk and a read that
/// finished everything is never reported cut short. Checking afterwards would turn a complete
/// read's `cut_short` into a `Some` with nothing missing, which is the manufactured incompleteness
/// `docs/unknown-not-absent.md` names as the same lie from the other side.
///
/// **A chunk that comes back short, or fails with bytes already in hand, is the
/// [`DbgEngError::ShortRead`] a single `ReadVirtual` of the whole range would have produced** —
/// same `requested`, same `actual`, because that is what happened: the read reached that far and
/// no further. A failure on the *first* chunk is propagated as itself, since nothing was read and
/// there is no short read to report. The one case reading in pieces can see that a single call
/// could not is a `ReadVirtual` that fails outright part-way through a range whose start was
/// readable; it is reported as the short read rather than as its `HRESULT`, which loses the
/// engine's own text and keeps the two paths answering in one shape.
/// A zeroed buffer of `len` bytes for a read of `requested` bytes at `address` — or
/// [`DbgEngError::OutOfMemory`] rather than the abort a plain `vec![0; len]` would be.
///
/// `address` and `requested` are carried only so the error can name the read it was for; a bare
/// "out of memory" is the same sentence whichever call produced it.
fn try_buffer(len: usize, address: u64, requested: usize) -> Result<Vec<u8>, DbgEngError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(len)
        .map_err(|_| DbgEngError::OutOfMemory {
            address,
            requested,
            read: 0,
        })?;
    buffer.resize(len, 0);
    Ok(buffer)
}

fn read_chunked(
    address: u64,
    size: usize,
    mut halt: impl FnMut() -> Option<Interruption>,
    mut read_chunk: impl FnMut(u64, &mut [u8]) -> Result<usize, DbgEngError>,
) -> Result<MemoryRead, DbgEngError> {
    // **The answer grows with the read, and the only buffer sized up front is one chunk.** A
    // `vec![0; size]` here would be an allocation and a zeroing of the *request* before the first
    // deadline check — time outside the one-chunk residual this whole design is a promise about,
    // and, for a `size` near the `u32` ceiling this is called behind, an abort inside the
    // allocator where a caller is owed a `Result`. A read cut short after one page now holds one
    // page rather than a truncated megabyte. What it costs is the reallocation of a doubling
    // `Vec`, against a read whose every chunk is a debugger round trip.
    //
    // **And each growth is asked for fallibly.** A geometric `Vec` reaching for twice what it
    // holds is the largest allocation this function makes, it is made *after* a caller's request
    // was accepted, and Rust's default reaction to a failed one is to take the process down.
    // Growing incrementally moves that hazard rather than removing it — raised in review on
    // dbgscope#168, on the change that introduced the growth — so the reservation is where a host
    // running out of room becomes [`DbgEngError::OutOfMemory`] instead of an abort.
    let mut bytes = Vec::new();
    let mut chunk = try_buffer(READ_CHUNK_BYTES.min(size), address, size)?;
    let short = |done: usize| DbgEngError::ShortRead {
        address,
        requested: size,
        actual: done,
    };
    while bytes.len() < size {
        if let Some(cut_short) = halt() {
            return Ok(MemoryRead {
                bytes,
                cut_short: Some(cut_short),
            });
        }
        let done = bytes.len();
        // A range whose end wraps past the top of the address space is one no target can answer
        // for. It stops here as a short read rather than being refused at the door, because that
        // is what it is — the bytes below the wrap were read — and `done` is necessarily non-zero
        // by the time it can happen: only the *end* of a range can wrap, never its start.
        let Some(at) = address.checked_add(done as u64) else {
            return Err(short(done));
        };
        let len = read_chunk_len(address, done, size);
        let read = match read_chunk(at, &mut chunk[..len]) {
            // Clamped, because a reader claiming more than the slice it was handed would have the
            // bytes past `len` taken from whatever the *previous* chunk left in this buffer.
            Ok(read) => read.min(len),
            Err(_) if done > 0 => return Err(short(done)),
            Err(source) => return Err(source),
        };
        bytes
            .try_reserve(read)
            .map_err(|_| DbgEngError::OutOfMemory {
                address,
                requested: size,
                read: done,
            })?;
        bytes.extend_from_slice(&chunk[..read]);
        if read < len {
            return Err(short(bytes.len()));
        }
    }
    Ok(MemoryRead {
        bytes,
        cut_short: None,
    })
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

/// What the engine says a register **is**, as distinct from what it currently holds.
///
/// [`DebugEngine::register_values`] reports one field of this — [`Register::subregister`], the
/// `DEBUG_REGISTER_SUB_REGISTER` flag — because that is the one a caller filtering "real
/// registers" from "views of them" reaches for. This is the whole of
/// `DEBUG_REGISTER_DESCRIPTION`, for a caller who has found that flag insufficient and needs to
/// see what else the engine offers: it is clear for `xmm0/0`…`xmm0/3` on x64 and for `w0`–`w30`
/// on ARM64, both of which are pieces of wider registers by every other measure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterDescription {
    /// The engine's own name for it, lowercase.
    pub name: String,
    /// The `DEBUG_VALUE_*` type the engine reports this register's value as.
    pub kind: u32,
    /// `DEBUG_REGISTER_SUB_REGISTER`, and whatever else this engine sets.
    pub flags: u32,
    /// The index of the register this one is a piece of. **The engine documents this as
    /// meaningful only when [`Self::flags`] says the register is a sub-register**, which is
    /// exactly the limitation a caller needs to be able to check rather than assume.
    pub subreg_master: u32,
    /// How many **bits** of the master this register covers, under the same condition — the unit
    /// is the engine's, and it is the one a reader assumes wrongly: `eax` reports 32.
    pub subreg_length: u32,
    pub subreg_mask: u64,
    pub subreg_shift: u32,
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

/// Which PDB the engine has for a module, in the form a symbol server is keyed by.
///
/// The *image* is identified by `TimeDateStamp` + `SizeOfImage` ([`Module`]); its symbols are
/// identified by this pair instead, and the two are not interchangeable — a build can be rebuilt
/// with the same timestamp and a new PDB signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbIdentity {
    /// The signature as a symbol server path spells it: 32 uppercase hex digits, no braces and no
    /// dashes. Deliberately not the braced form `Debug` would print — this is the string that goes
    /// in `<pdb>/<guid><age>/<pdb>`, and reformatting it is the caller's least useful job.
    pub guid: String,
    /// The age, which the same path appends to the GUID in hex.
    pub age: u32,
    /// Whether the engine matched a PDB it then found did **not** belong to this image. A caller
    /// reading symbols from it is reading another build's names.
    pub unmatched: bool,
    /// The file the engine actually loaded, where it says. Empty when it has none.
    pub file: String,
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

/// An exception the engine reported, as the fields of `EXCEPTION_RECORD64`.
///
/// The kernel's counterpart to [`BugCheck`], and kept as sparse for the same reason: what a given
/// code's parameters *mean* is per-code lore — `0xc0000005`'s three say which access faulted where,
/// `0xe06d7363`'s four are the MSVC throw — and none of it is knowledge the engine has. This is the
/// record; deciding what it says is the caller's.
///
/// **[`Self::parameters`] is already cut to `NumberParameters`.** The raw record carries fifteen
/// slots whatever it filled, and a caller reading past the count reads whatever the last exception
/// on that thread left there. Trimming here is the difference between a parameter and a leftover,
/// and it is exactly the count that tells the two shapes of a fail-fast apart: one parameter is the
/// CRT's `abort`, three is WIL's, whose second is the `HRESULT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionRecord {
    /// The exception code — `0xc0000409` for a fail-fast, `0xe06d7363` for a C++ throw.
    pub code: u32,
    /// `EXCEPTION_NONCONTINUABLE` and friends; see [`Self::noncontinuable`].
    pub flags: u32,
    /// The instruction that raised it.
    pub address: u64,
    /// `ExceptionInformation`, cut to the `NumberParameters` the record declares.
    pub parameters: Vec<u64>,
    /// The address of the record this one is nested inside, or `None` at the outermost.
    ///
    /// A pointer into the target rather than a record: chasing it needs a read, and a caller that
    /// does not care should not pay for one. Nesting is not exotic — an exception raised while
    /// another is being handled produces exactly this — and a triage that missed it would report
    /// the outer code for an inner fault.
    pub nested: Option<u64>,
}

impl ExceptionRecord {
    /// `EXCEPTION_NONCONTINUABLE`: resuming past this one raises a second exception rather than
    /// continuing. True of every fail-fast, which is what makes them fatal.
    pub fn noncontinuable(&self) -> bool {
        self.flags & EXCEPTION_NONCONTINUABLE != 0
    }

    /// The record as the engine wrote it, with the two fields that need deciding decided.
    ///
    /// The parameter count is clamped to the array as well as taken from the record: fifteen is
    /// how many slots there are, `NumberParameters` is how many the raiser filled, and a record
    /// claiming more than it can hold is a corrupt record rather than an excuse to read off the
    /// end of it.
    fn from_raw(raw: &EXCEPTION_RECORD64) -> Self {
        let filled = (raw.NumberParameters as usize).min(raw.ExceptionInformation.len());
        Self {
            code: raw.ExceptionCode.0 as u32,
            flags: raw.ExceptionFlags,
            address: raw.ExceptionAddress,
            parameters: raw.ExceptionInformation[..filled].to_vec(),
            nested: (raw.ExceptionRecord != 0).then_some(raw.ExceptionRecord),
        }
    }
}

/// Whether an engine refusal means "this target has no stored event" rather than a failure.
///
/// A live target has none, and neither does a dump not written for a fault, so this is an ordinary
/// answer and not an error — but the engine has no way to say so except by refusing, and refusing
/// is also what it does when something is wrong. Pinned to the one code it uses for this, measured
/// by `examples/stored_event_probe.rs` against a live process and a kernel crash dump, so that a
/// genuine failure still reaches the caller as one.
fn no_stored_event(code: HRESULT) -> bool {
    code == E_UNEXPECTED
}

/// A buffer for the extra information `GetLastEventInformation` and `GetStoredEventInformation`
/// write beside an event.
///
/// One buffer for every event kind rather than a union of the eight `DEBUG_LAST_EVENT_INFO_*`
/// shapes, because only one of them is ever read here and the rest exist only to be large enough
/// not to truncate. `DEBUG_LAST_EVENT_INFO_EXCEPTION` *is* the largest — an `EXCEPTION_RECORD64`
/// and a flag against the `u32`s and `u64`s the others hold — so sizing to it is sizing to all of
/// them, and the alignment is the record's.
#[repr(C, align(8))]
struct ExtraEventInfo([u8; size_of::<DEBUG_LAST_EVENT_INFO_EXCEPTION>()]);

impl Default for ExtraEventInfo {
    fn default() -> Self {
        Self([0; size_of::<DEBUG_LAST_EVENT_INFO_EXCEPTION>()])
    }
}

impl ExtraEventInfo {
    const SIZE: u32 = size_of::<DEBUG_LAST_EVENT_INFO_EXCEPTION>() as u32;

    fn as_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        self.0.as_mut_ptr().cast()
    }

    /// The exception record the engine wrote here, and whether it was first-chance.
    ///
    /// **Both guards are load-bearing.** The buffer is only an exception record when the event was
    /// an exception — for any other kind these same bytes are an exit code or a module base, and
    /// reading them as a record would invent one. And `used` is the engine's own count: a call
    /// that wrote less than the struct's size did not write this struct, whatever the kind says.
    fn exception(&self, kind: u32, used: u32) -> Option<(ExceptionRecord, bool)> {
        if kind != DEBUG_EVENT_EXCEPTION || used < Self::SIZE {
            return None;
        }
        // SAFETY: the engine reported writing `used` bytes here and `used >= SIZE`, which is this
        // buffer's size; it is aligned for the struct, and the read is unaligned-safe regardless.
        // `DEBUG_LAST_EVENT_INFO_EXCEPTION` is plain old data, so a copy out is a copy of bytes.
        let info: DEBUG_LAST_EVENT_INFO_EXCEPTION =
            unsafe { std::ptr::read_unaligned(self.0.as_ptr().cast()) };
        Some((
            ExceptionRecord::from_raw(&info.ExceptionRecord),
            info.FirstChance != 0,
        ))
    }
}

/// `EXCEPTION_NONCONTINUABLE`.
///
/// Spelled out rather than imported: the `windows` crate has it, but under
/// `Win32_System_SystemServices`, and pulling a whole feature module in for one `= 1` is a worse
/// trade than a line. Not to be confused with that crate's `EXCEPTION_NONCONTINUABLE_EXCEPTION`,
/// which is `0xc0000025` — the status raised by trying to continue past one of these, not the flag
/// that says so.
const EXCEPTION_NONCONTINUABLE: u32 = 0x1;

/// A target's `CONTEXT`, exactly as the engine handed it over.
///
/// **Opaque on purpose.** `CONTEXT` is per-architecture, per-processor-feature and versioned by
/// its own `ContextFlags`; an x64 one is 1,232 bytes today and an `XSTATE`-extended one is not.
/// Nothing here parses it, so nothing here goes stale when it grows — the engine wrote the bytes
/// and the engine reads them back.
///
/// It exists so that a stack can be walked from the context an *event* was recorded with rather
/// than from wherever the session's scope happens to point ([`DebugEngine::stack_frames_from`]).
/// That is what `.ecxr` does to a session, without doing it to the session: the caller's selected
/// frame and thread are untouched, so a triage that walks the crash stack is still a read.
///
/// **It carries the target it was read from, exactly as [`Scope`] does**, and for a sharper
/// version of the same reason. These registers and the stack addresses in them mean something only
/// on that target, so handing one to an engine that has since released it and opened another walks
/// whatever those addresses reach now. Unlike a stale [`Scope`] — which points the session
/// somewhere visibly wrong — a stale context comes back as *frames*, which is an answer a caller
/// has no way to tell from the right one. [`DebugEngine::stack_frames_from`] refuses it instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadContext {
    bytes: Vec<u8>,
    /// The [`DebugEngine::target_identity`] this was read from; see the type's own note.
    target: u64,
}

impl ThreadContext {
    /// The bytes, for the one caller that has to hand them back to the engine.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The [`DebugEngine::target_identity`] of the target this was read from.
    ///
    /// Exposed because a caller holding one across a session boundary is the party that can say
    /// whether that was deliberate, and comparing is cheaper than being refused.
    pub fn target(&self) -> u64 {
        self.target
    }

    /// How many bytes the engine reported, which is the `CONTEXT` size for this target — not the
    /// size of the buffer it was offered.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the engine reported no context at all, which a stored event can legitimately do.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The event a target is stopped on, as [`DebugEngine::last_event`] and
/// [`DebugEngine::stored_event`] report it.
///
/// [`Self::kind`] is a raw `DEBUG_EVENT_*` value rather than an enum. Two reasons, and the second
/// is the one that decided it. The engine's list grows, and a closed enum would turn a new event
/// kind into a variant this crate has to ship before a caller can see it. And the distinction a
/// caller actually needs is already spelled: [`Self::exception`] is `Some` exactly when the event
/// carried a record, which is the question, and it is not answered by the kind — an initial break
/// arrives as `DEBUG_EVENT_EXCEPTION` (`0x2`) carrying `STATUS_BREAKPOINT`, not as
/// `DEBUG_EVENT_BREAKPOINT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugEvent {
    /// The raw `DEBUG_EVENT_*` value.
    pub kind: u32,
    /// The **engine** process id the event belongs to — the same index
    /// [`DebugEngine::session_processes`] pairs, not a system pid.
    pub process: u32,
    /// The **engine** thread id the event belongs to.
    pub thread: u32,
    /// The exception, when the event carried one. `None` for every other kind of event.
    pub exception: Option<ExceptionRecord>,
    /// Whether [`Self::exception`] is first-chance — the debugger seeing it before the target's
    /// own handlers do. Meaningless, and `false`, when there is no exception.
    ///
    /// A second-chance record is the interesting one on a crash: it means nothing in the target
    /// handled it, which for a C++ exception is the whole finding.
    pub first_chance: bool,
    /// The register context the event was recorded with, where the engine kept one.
    ///
    /// Always `None` from [`DebugEngine::last_event`], which does not carry one; `Some` from
    /// [`DebugEngine::stored_event`] on a dump written for a fault.
    pub context: Option<ThreadContext>,
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

/// The instruction set a rendering is in, which decides how much of it can be read.
///
/// The engine renders every architecture through the same three columns, and the columns are all
/// [`split_instruction`] needs — but *inside* the third one the syntaxes diverge completely
/// (`sub rsp,40h` against `stp fp,lr,[sp,#-0x10]!`). So reading is gated on the set, and anything
/// this does not implement is [`Self::Other`]: mnemonic kept, operands empty, [`Flow::Unknown`].
/// That is a refusal rather than a guess.
///
/// # Two gates, not one, though the three sets here answer both the same way
///
/// [`Self::flow_is_read`] and [`Self::operands_are_read`] are different questions that currently
/// have the same answer, and the reason to keep them apart is that ARM64 spent a release
/// answering them differently: A64's flow is six branch classes and landed on its own
/// (dbgscope#148), and its operands are a second decoder that landed after (dbgscope#170).
/// A caller asks whichever it depends on — a reachability walk needs the flow, an IOCTL map needs
/// the operands — and the next architecture may well arrive the same way round.
///
/// **Neither is legible from an instruction's fields, which is why they are here.** "No operands
/// were read" used to be readable from [`Flow::Unknown`] beside an empty operand list; since A64,
/// an empty operand list means an instruction that takes none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionSet {
    /// x86, 32-bit.
    X86,
    /// x86-64.
    Amd64,
    /// ARM64 (AArch64).
    Arm64,
    /// Anything else — ARM32, IA64, and the ARM64EC and ARM64X machine values, none of which has
    /// been measured here. The `IMAGE_FILE_MACHINE_*` value is kept so a caller can say which one
    /// it declined to read.
    Other(u32),
}

impl InstructionSet {
    /// The set a `GetActualProcessorType` value names.
    ///
    /// Only the three measured machines are named. `0xa641` (ARM64EC) and `0xa64e` (ARM64X) are
    /// deliberately not folded into [`Self::Arm64`]: both describe images that hold x64 code as
    /// well, so which set a *rendering* is in is exactly the question those values do not settle,
    /// and no fixture here has one.
    pub fn from_processor_type(machine: u32) -> Self {
        match machine {
            0x014c => Self::X86,
            0x8664 => Self::Amd64,
            0xaa64 => Self::Arm64,
            other => Self::Other(other),
        }
    }

    /// Whether operands, registers, privilege and effect are read for this set. False means every
    /// instruction comes back with an empty operand list, no registers, and `privileged` false —
    /// none of which is a claim about the instruction.
    ///
    /// **True for ARM64 since [`crate::arm64`] grew an operand decoder**, which is what closed
    /// dbgscope#170.
    ///
    /// **It answers for the set and not for every instruction in it**, which x86 and x64 never
    /// made a distinction worth drawing: iced reads the whole of those. A64's decoder reads the
    /// general-purpose architecture and names the vector extensions rather than shaping them, and
    /// an instruction it did not read says so itself, with a single [`Operand::Undecoded`].
    /// Measured over the 26100 ARM64 kernel's `nt`, that is 0.500% of the 2,367,602 instructions
    /// the engine could render across its executable sections.
    pub fn operands_are_read(self) -> bool {
        matches!(self, Self::X86 | Self::Amd64 | Self::Arm64)
    }

    /// Whether [`Instruction::flow`] is decoded for this set. False means every instruction comes
    /// back [`Flow::Unknown`], so a caller following control flow has nothing to follow and should
    /// say so rather than report an empty graph.
    pub fn flow_is_read(self) -> bool {
        matches!(self, Self::X86 | Self::Amd64 | Self::Arm64)
    }
}

/// What one instruction does to control flow, as its **encoding** says.
///
/// Every destination is an [`Option`] for one reason: a direct transfer encodes a displacement,
/// which adds up to an address, while an indirect one encodes a register or a memory reference
/// whose value is not in the instruction at all. Those are different facts. `Call(None)` is
/// `call rax` or `call qword ptr [rax*8+…]`; `Jmp(None)` is a jump table or a function pointer. A
/// caller that treats `None` as "no edge" stays sound — it never invents one — which is the
/// property [`Self::target`] exists to keep obvious.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Falls through to the next instruction — the common case.
    Fallthrough,
    /// A `call`: schedules the destination, then falls through. `None` when it is indirect.
    Call(Option<u64>),
    /// An unconditional `jmp`: control goes to the destination only, never to the next
    /// instruction. `None` when it is indirect.
    Jmp(Option<u64>),
    /// A conditional branch: the destination **or** the next instruction.
    Branch(Option<u64>),
    /// `ret`/`iret`: flow stops.
    Return,
    /// A `noreturn` trap — `int 29h` (`__fastfail`), `int 3`, `ud2`, `hlt`. Flow stops, so a walk
    /// must not fall through one.
    Trap,
    /// Not read: a real instruction, in an instruction set whose **flow** this does not decode, or
    /// bytes a decoder that does know the set could not make an instruction of. Says nothing about
    /// what it does, but there *is* something there.
    ///
    /// It is not the tell for "operands were not read": [`InstructionSet::operands_are_read`] is
    /// that question, and the two came apart when ARM64 answered a real flow with no operands.
    Unknown,
    /// There is no instruction here. The engine rendered `???`, which is what it prints when the
    /// bytes could not be read at all — an unmapped page, or a dump that never captured the code.
    Unreadable,
}

impl Flow {
    /// The destination this instruction names, when it named one resolvably.
    pub fn target(self) -> Option<u64> {
        match self {
            Self::Call(target) | Self::Jmp(target) | Self::Branch(target) => target,
            _ => None,
        }
    }

    /// Whether control can continue at the next instruction.
    ///
    /// [`Flow::Unknown`] answers **true** and [`Flow::Unreadable`] answers **false**, and that is
    /// the whole reason they are two variants. An unread instruction set still has an instruction
    /// there, and nearly every instruction falls through, so continuing is the best-effort a walk
    /// wants — stopping would drop the rest of a function on an architecture nothing here decodes.
    /// An unreadable rendering has no instruction at all: continuing walks *bytes*, one at a time,
    /// through whatever follows an unmapped page, and on a dump with no code pages that runs to a
    /// walk's cap inventing every address on the way.
    ///
    /// **Continuing through `Unknown` is best-effort and not sound**, which is why it is the
    /// answer here and not the answer a caller should build a guarantee on: a walk that follows it
    /// reports addresses reachable only across an edge nothing established. ARM64 used to be the
    /// worked example of that and is no longer — its flow is decoded — so what is left behind this
    /// variant is an architecture with no decoder at all, where a caller wanting a sound verdict
    /// should ask [`InstructionSet::flow_is_read`] and decline rather than walk.
    pub fn falls_through(self) -> bool {
        matches!(
            self,
            Self::Fallthrough | Self::Call(_) | Self::Branch(_) | Self::Unknown
        )
    }
}

/// What a target's unwind data says about the region holding an address, as
/// [`DebugEngine::function_extent`] reports it.
///
/// Three outcomes rather than an [`Option`], because the two that are not a region are different
/// facts with different remedies: one says this image has no entry covering that address, the
/// other says this build does not decode that target's entry layout at all. Collapsing them lets a
/// caller read "not decoded" as "a leaf function", which is the reading that turns an
/// architecture this cannot answer for into an architecture it answers wrongly for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionExtent {
    /// The region containing the address, rebased into the target's address space.
    Region { begin: u64, end: u64 },
    /// The image has no unwind entry covering the address — a leaf function, or an address that
    /// is not code. Reported only for the entry layouts this decodes, x64's and ARM64's.
    NoEntry,
    /// This instruction set's entry layout is not decoded here, so nothing is claimed about the
    /// address at all. **x86 answers this**, not [`Self::NoEntry`]: 32-bit Windows has no unwind
    /// table, so implementing it would buy nothing, but that is a fact about a platform and
    /// `NoEntry` would assert it about an address that was never queried. x64 and ARM64 are the
    /// two layouts decoded; everything else answers this.
    /// [`DebugEngine::function_extent`] has the reasoning.
    Unsupported(InstructionSet),
}

impl FunctionExtent {
    /// The region, where there is one. `None` covers both of the other outcomes, so use it only
    /// where "no bound available" is the whole question.
    pub fn region(self) -> Option<(u64, u64)> {
        match self {
            Self::Region { begin, end } => Some((begin, end)),
            _ => None,
        }
    }
}

/// A memory operand, as its encoding gives it — the shapes an engine would render
/// `qword ptr [rdx+0B8h]`, `gs:[188h]`, `[rax+rcx*8+20h]`, `qword ptr [rip+0x9018]`.
///
/// Nothing here is computed against a register context, so `[rdx+0B8h]` is the displacement `0xb8`
/// off whatever `rdx` held, and this says only that. [`Self::address`] is the exception and is why
/// it is an [`Option`]: an absolute or RIP-relative reference needs no register, so its target is
/// known from the instruction alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryOperand {
    /// The access width in bytes, from the `qword ptr` prefix; `None` when the engine printed
    /// none, which it omits where the mnemonic already fixes the width.
    pub size: Option<u32>,
    /// A segment override — `gs` in `gs:[188h]`, which is how kernel code reaches the KPCR.
    pub segment: Option<String>,
    /// The base register, when one was printed.
    pub base: Option<RegisterOperand>,
    /// The index register of a `base+index*scale` form.
    pub index: Option<RegisterOperand>,
    /// The index's scale; 1 when none was printed.
    pub scale: u8,
    /// The signed displacement, zero when none was printed.
    pub displacement: i64,
    /// The absolute address this operand refers to, when nothing at run time contributes to it —
    /// an absolute displacement, or a RIP-relative reference, whose target is computed against the
    /// instruction's own end.
    ///
    /// This is what names an import thunk. `call qword ptr [driver+0x9018]` is a RIP-relative
    /// load, so the slot's address is here, and what lives at that slot is a question for the
    /// image's import table or for [`DebugEngine::symbol_for`] — not for the operand's spelling.
    pub address: Option<u64>,
}

/// A register operand: the name as printed, and the full-width register it is part of.
///
/// **Two spellings of one register are one value here**, which is what lets a caller follow a
/// value across widths: a dispatch routine reads a control code into `r13d` and compares `r13d`
/// against an immediate two instructions later, while the `pop r13` in its epilogue writes the
/// same register. A caller keying on the printed name sees three registers and loses the value at
/// the first width change; keying on [`Self::full`] it sees one.
///
/// Both come from the **decoder**, not from a table of names. The mapping is per architecture and
/// per bitness — `eax` is part of `rax` on x64 and is itself the full register on x86 — and a
/// hand-written list is wrong in the way every hand-written list here has been: `r8d` and `sil`
/// and `ah` are each a case somebody forgets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegisterOperand {
    /// As the engine prints it — `r13d`, `al`, `rip`.
    pub name: String,
    /// The full-width register it belongs to at this target's bitness — `r13`, `rax`, `rip`.
    pub full: String,
    /// How many bytes **this register** holds — 4 for `eax`, 1 for `ah`, 8 for `rax`.
    ///
    /// **What a caller tracking a value needs in order to know it still has all of it.** A `ULONG`
    /// field read with `mov eax,[rdx+18h]` is the whole of it; `movzx ecx,ax` two instructions
    /// later carries two bytes of the same value, and a caller that treated the copy as the value
    /// would report a comparison against part of a field as a comparison against the field. The
    /// decoder knows the width because it decoded the register; a consumer deriving it from the
    /// spelling is writing the table this type exists to delete.
    ///
    /// **It is the register's width and not the instruction's access.** They differ on the vector
    /// registers, where an instruction may touch part of one: the `xmm1` in `movss xmm0,xmm1` is
    /// 16 bytes here while the copy moves four. A general-purpose spelling has no such gap — `ax`
    /// *is* two bytes — which is the case this field exists for, and a caller reasoning about
    /// vector lanes needs the mnemonic rather than this.
    pub width: u32,
}

impl std::fmt::Display for RegisterOperand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

/// A register **is** its printed name, so `memory.base.as_deref() == Some("rdx")` reads as it did
/// before this type existed, and the full-width register is the field a caller asks for on purpose.
///
/// The direction matters: dereferencing to [`Self::name`] cannot be mistaken for the canonical one,
/// where the reverse would silently answer `rax` to a caller printing an operand.
impl std::ops::Deref for RegisterOperand {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.name
    }
}

/// What a conditional branch requires of the flags the compare before it set.
///
/// **Signedness is part of the answer, and that is why this is not a mnemonic.** `ja` and `jg`
/// read the same rendering-shaped "greater", and only one of them says anything about an unsigned
/// index: a jump table bounded by `jg` is not bounded at all. A caller matching mnemonics gets
/// that wrong once per family and finds out when a table is read one entry past its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// `je`/`jz`.
    Equal,
    /// `jne`/`jnz`.
    NotEqual,
    /// `ja`/`jnbe` — unsigned, strict.
    UnsignedAbove,
    /// `jae`/`jnb`/`jnc` — unsigned, inclusive.
    UnsignedAboveOrEqual,
    /// `jb`/`jnae`/`jc` — unsigned, strict.
    UnsignedBelow,
    /// `jbe`/`jna` — unsigned, inclusive.
    UnsignedBelowOrEqual,
    /// `jg`/`jnle` — signed, strict.
    SignedGreater,
    /// `jge`/`jnl` — signed, inclusive.
    SignedGreaterOrEqual,
    /// `jl`/`jnge` — signed, strict.
    SignedLess,
    /// `jle`/`jng` — signed, inclusive.
    SignedLessOrEqual,
    /// `js` / `jns` — the sign flag alone.
    Negative,
    NotNegative,
    /// `jo` / `jno`.
    Overflow,
    NotOverflow,
    /// `jp`/`jpe` / `jnp`/`jpo`.
    Parity,
    NotParity,
}

/// What an instruction **does**, in the few classes an analysis branches on.
///
/// [`Flow`] answers where control goes; this answers what the instruction did to its operands, and
/// the two together are what a caller reading a mnemonic string was reaching for. It is
/// deliberately coarse: a caller that needs the exact instruction has [`Instruction::mnemonic`],
/// and a class list that grew a variant per encoding would be the table this exists to delete.
///
/// The classes are the ones a dataflow over a dispatch routine actually branches on — is this a
/// copy, an address computation, a compare, an arithmetic adjustment of a value it is tracking —
/// and they carry across architectures: an ARM64 `mov`/`add`/`sub`/`cmp`/`lsr` answers the same
/// set, which is the point of putting them here rather than in each consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// A copy, of any width, zero-extending included.
    Move,
    /// A copy that **sign-extends** what it read.
    ///
    /// Apart from [`Self::Move`] because the difference is what the value means afterwards: a
    /// dword loaded with `movsxd` and added to a base is a *signed* displacement from it, and
    /// reading it as unsigned puts the result four gigabytes away. A caller that does not care
    /// matches both.
    MoveSigned,
    /// An address computation that reads no memory — `lea`.
    LoadAddress,
    /// A comparison that writes only flags — `cmp`.
    Compare,
    /// A bitwise test that writes only flags — `test`.
    Test,
    Add,
    Subtract,
    /// `shl`/`sal`.
    ShiftLeft,
    /// `shr`/`sar`. The signedness is in the mnemonic, and a caller that cares reads it.
    ShiftRight,
    BitAnd,
    BitOr,
    BitXor,
    Push,
    Pop,
    /// Anything else, including every transfer of control — those are [`Flow`]'s answer.
    Other,
}

/// One operand of an instruction, as its **encoding** says rather than as the engine printed it.
///
/// There is no symbol anywhere in here, and that is the point. A destination is an address;
/// naming it is [`DebugEngine::symbol_for`]'s job. While operands were read out of the rendering,
/// a symbol's own punctuation kept taking them apart — a comma inside `std::map<int,int>`, a
/// parenthesis inside `operator()`, a bracket inside `operator[]` — and each of those severed a
/// direct call edge that a reachability walk then dropped as indirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// A register: the name the engine prints, and the full-width register it is part of.
    Register(RegisterOperand),
    /// A literal, as the bit pattern encoded. Unsigned, because what a caller matches against a
    /// control code or a mask is the pattern rather than an arithmetic sign.
    Immediate(u64),
    /// A memory reference.
    Memory(MemoryOperand),
    /// The absolute destination of a direct branch or call, computed from the relative
    /// displacement the encoding carries.
    Target(u64),
    /// An operand kind this does not shape — a far branch, or a string operation's implicit
    /// operand, and on A64 a system register, a barrier's domain or a shift folded into an
    /// arithmetic operand — named rather than forced into one of the others.
    ///
    /// **The instruction around it is decoded.** This says a shape is missing, not a reading; what
    /// says a *reading* is missing is [`Self::Undecoded`].
    Other(String),
    /// **This instruction was not read**, and the string names the encoding space it was in:
    /// `sve`, `advanced-simd`, `unallocated`. It is the whole operand list where it appears, and
    /// every other field of the [`Instruction`] is a default rather than an answer — no
    /// registers in [`Instruction::writes`] or [`Instruction::reads`], `false` for
    /// [`Instruction::privileged`] and [`Instruction::writes_flags`], [`Effect::Other`].
    ///
    /// # Why an instruction set can be read and an instruction in it not
    ///
    /// [`InstructionSet::operands_are_read`] answers for a *set*, and it was enough while the only
    /// decoders here were complete over theirs. A64's is not: it reads the general-purpose
    /// architecture and names the vector extensions rather than shaping them
    /// ([`crate::arm64`] says exactly where the line falls and why it is drawn there). Without this
    /// variant that distinction lived in a convention about [`Self::Other`]'s *contents*, which a
    /// consumer had to know the space names to apply — and three review rounds on dbgscope#171
    /// each found a caller that would not have.
    ///
    /// **A consumer that must not believe a stale value treats this as clobbering everything it is
    /// tracking**; one that would rather lose a finding than invent one stops at it instead. What
    /// neither should do is read the empty lists beside it as "this instruction touches nothing".
    ///
    /// **What this cannot express is a *partial* reading**, and no decoder here produces one: an
    /// instruction is shaped or it is this, and there is no third state where the operands are
    /// read and the access lists are only half of an answer. A decoder that grew one would need
    /// something else, and should not reach for this — the whole value of a marker that is the
    /// entire operand list is that it cannot be missed.
    Undecoded(String),
}

/// One disassembled instruction, as [`DebugEngine::disassemble`] reports it.
///
/// The engine has no structured disassembly — `IDebugControl::Disassemble` renders one line of
/// text and says where the next instruction starts — so this is that line split at its two column
/// boundaries, with the address taken from the walk rather than parsed back out of it. A line the
/// split does not recognise keeps everything after the address in [`Self::text`] and leaves
/// [`Self::bytes`] empty, rather than guessing.
///
/// [`Self::mnemonic`], [`Self::operands`] and [`Self::flow`] come from decoding [`Self::bytes`] —
/// the **encoding**, not the rendering — so a caller asking what an instruction *compares
/// against* or *branches to* reads a field rather than re-parsing a rendering downstream, and no
/// symbol's spelling can take an operand apart. [`Self::text`] stays verbatim beside them: it is
/// what a listing prints, and the fields do not replace it. An instruction from
/// [`DebugEngine::decode_range`] has fields and no text, nothing having rendered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// Where the instruction is. **Not** parsed from the rendered line: it is the offset this
    /// walk asked about, which is the previous instruction's end.
    pub address: u64,
    /// The encoding, as the engine prints it — `48895c2408`. Empty when the line carried no byte
    /// column, which is not a shape any current engine produces for a readable address.
    ///
    /// **"As the engine prints it" is not always memory order.** On x86 and x64 the two coincide,
    /// the engine printing the bytes in the order they are stored. On ARM64 it prints the
    /// instruction *word*: `a9bf7bfd` for `stp fp,lr,[sp,#-0x10]!`, whose four bytes in memory
    /// read `fd 7b bf a9`. [`DebugEngine::decode_range`] follows the same convention there even
    /// though it reads memory, so one instruction has one spelling whichever path produced it.
    pub bytes: String,
    /// The mnemonic and its operands — `mov qword ptr [rsp+8],rbx` — with the engine's column
    /// padding collapsed to single spaces, since the columns it was aligning are separate fields
    /// here. Operand symbols are the engine's own (``call nt!KeBugCheckEx (fffff803`...)``).
    pub text: String,
    /// The operative mnemonic — `mov`, `cmp`, `call`. A `lock`/`rep` prefix is **skipped** rather
    /// than joined to it, so `lock inc dword ptr [rax]` reports `inc`; the prefix is still in
    /// [`Self::text`]. Empty only when the rendering was.
    pub mnemonic: String,
    /// The operands, in the order printed. Empty for an instruction that takes none — and also
    /// for an instruction set whose operands are not read, which
    /// [`InstructionSet::operands_are_read`] tells apart. **Not the flow**, which is a separate
    /// question and answers for one set more than this one has ever answered for.
    ///
    /// **In the order printed is the contract, and on A64 that is not destination-first.** A store
    /// names its source first — `str x8,[x9]` is `[Register, Memory]` where x64's `mov [rcx],rax`
    /// is `[Memory, Register]` — so `operands[0]` is not the destination there. [`Self::writes`]
    /// is the field that answers what changed, on both.
    ///
    /// **A single [`Operand::Undecoded`] is not an operand list**: it is this instruction saying
    /// nothing was read, and every other field beside it is a default rather than an answer.
    pub operands: Vec<Operand>,
    /// What the instruction does to control flow.
    pub flow: Flow,
    /// Whether executing it requires privilege: every CPL=0 instruction, plus the IOPL-sensitive
    /// ones (`in`, `ins`, `out`, `outs`, `cli`, `sti`).
    ///
    /// **The decoder's own answer, not a list of mnemonics.** A caller asking "does this driver
    /// touch the machine" wants the whole set -- `rdmsr` and `mov cr3` and `lgdt`, but also `cli`,
    /// `clts`, `lmsw`, `invpcid`, and every VMX and SVM operation -- and a hand-kept table of
    /// those answers "none" for a driver containing exactly the ones nobody remembered. iced's
    /// table is generated from the instruction set itself, so the question is asked once and
    /// stays right as the set grows.
    ///
    /// `false` on an instruction set whose operands this build does not decode, because nothing
    /// was read, so nothing is claimed. A caller that needs to tell "no privileged instructions"
    /// from "not asked" reads [`InstructionSet::operands_are_read`], not the flow.
    ///
    /// **On A64 it is `op1` rather than a register name**, that field naming the minimum exception
    /// level of every system-register and system-instruction encoding — so the question is asked
    /// of the encoding there too, and a table of AArch64 system-register names, which is hundreds
    /// of rows and grows with the architecture, never has to be right.
    /// [`crate::arm64`] states the one carve-out and why it is one.
    ///
    /// One deliberate gap on x64, iced's rather than this crate's: `vmcall` is excluded, being the
    /// one CPL=0-encoded instruction a guest executes at any privilege level.
    pub privileged: bool,
    /// What the instruction does to its operands, in the classes an analysis branches on.
    ///
    /// [`Effect::Other`] for an instruction set whose operands this build does not decode, which
    /// [`InstructionSet::operands_are_read`] tells apart.
    pub effect: Effect,
    /// What a conditional branch requires of the flags, when the instruction is one.
    ///
    /// `None` for everything else, and for a conditional whose condition is not one of these --
    /// `jrcxz` and the `loop` family test a register rather than the flags.
    pub condition: Option<Condition>,
    /// Whether the instruction writes any flag a conditional branch reads.
    ///
    /// The decoder's own answer, so "which instruction set the flags this branch is reading" needs
    /// no list of arithmetic mnemonics -- the list that forgets `bt`, `cmpxchg` and `neg`.
    pub writes_flags: bool,
    /// Every register the instruction **writes**, explicit and implicit.
    ///
    /// [`Self::operands`] says what an instruction was written with; this says what it leaves
    /// changed, and the two differ in the places that cost a consumer most. A pass tracking a value
    /// through a routine has to know when to stop believing in it, and inferring that from the
    /// first operand is right for the shapes a compiler emits and wrong for two it also emits:
    ///
    /// * **A second explicit destination.** `xchg eax,r13d` writes both. A consumer that clears the
    ///   first goes on believing whatever it knew about `r13`, which now holds the old `eax`.
    /// * **An implicit destination.** `mul ecx` writes `eax` and `edx` and names neither, as do
    ///   `div`, `cpuid`, `rdmsr`, `cmpxchg`'s `rax` and the string instructions' `rsi`/`rdi`/`rcx`.
    ///
    /// Both were live defects in `windbg-mcp`'s IOCTL recovery, where a control code surviving in a
    /// register an unmodelled instruction had overwritten is published as a code the driver
    /// accepts. The alternative to this field is the mnemonic table this type exists to delete.
    ///
    /// **A conditional write is in the list**, because a consumer that must not believe a stale
    /// value wants the conservative answer: `cmovne eax,ecx` may or may not have changed `eax`, and
    /// neither answer about its contents is safe afterwards. A **read-write** operand is here *and*
    /// in `operands`, those being different questions.
    ///
    /// The flags are not registers here: [`Self::writes_flags`] is that question, and this list
    /// holds only what a register name refers to.
    ///
    /// **A register is named as the *write* reaches it, which is not always how the operand was
    /// spelled.** On x64 a 32-bit write zeroes the upper half, so `mov eax,1` appears here as
    /// `rax` — eight bytes — while [`Self::operands`] has the `eax` the instruction was written
    /// with. That is the useful answer for the question this field is for (which register no
    /// longer holds what it did), and it is the reason to match these against
    /// [`RegisterOperand::full`] rather than against a spelling.
    ///
    /// Empty for an instruction set whose operands this build does not decode -- nothing was
    /// read, so nothing is claimed, and a consumer that needs the difference reads
    /// [`InstructionSet::operands_are_read`].
    ///
    /// **And empty on a set that *is* decoded, for an instruction inside it that is not.** A
    /// decoder may read most of an instruction set and name the rest: A64's does, the vector
    /// extensions being where it stops ([`crate::arm64`]). Such an instruction comes back with
    /// [`Self::operands`] holding a single [`Operand::Undecoded`], which is the tell and says
    /// what to do about it.
    pub writes: Vec<RegisterOperand>,
    /// Every register the instruction **reads**, explicit and implicit.
    ///
    /// [`Self::writes`]' other half, and it is here for the same reason that one is:
    /// [`Self::operands`] names the reads an instruction was *written* with, and an instruction
    /// reads registers it does not name. `mul ecx` reads `eax`, `cmpxchg` reads `rax`, the string
    /// instructions read `rsi`/`rdi`/`rcx`, and a `cmp dword ptr [rcx+8],5` reads `rcx` while
    /// naming it only inside a memory operand. A consumer asking "is this arithmetic about the
    /// value I am tracking" answers no for every one of those, and answers it from a list that was
    /// never the question.
    ///
    /// **A conditional read is in the list**, the mirror of the reason a conditional write is in
    /// the other one: the question is whether a value may have reached this instruction, and the
    /// conservative answer is the only safe one. A **read-write** operand is in both lists, those
    /// being different questions.
    ///
    /// **A register read only to form an address is here too**, because the instruction does read
    /// it. What this does not say is that the instruction's *result* is about what that register
    /// held -- `cmp eax,[rdx+rcx*8]` compares against a loaded value, not against `rcx` -- and a
    /// consumer that needs the difference has [`Self::operands`] beside this, where a memory
    /// operand's [`MemoryOperand::base`] and [`MemoryOperand::index`] are exactly the registers in question.
    ///
    /// **A read is reported at the width it reads, which is where this differs from
    /// [`Self::writes`].** A 32-bit write zeroes the upper half, so the decoder reports the whole
    /// of `rax` for `mov eax,1`; a 32-bit read reads four bytes, so `mov ecx,eax` reports `eax`.
    /// [`RegisterOperand::full`] is still the field to match on -- what `rax` holds is what `eax`
    /// reads part of -- and [`RegisterOperand::width`] is what says how much of it was read.
    ///
    /// The flags are not registers here, as they are not in [`Self::writes`]: [`Self::condition`]
    /// is what a branch reads them for.
    ///
    /// Empty for an instruction set this build does not decode, and empty means **"not decoded"**
    /// rather than "reads nothing" -- the same contract [`Self::writes`] states, and a consumer
    /// that needs the difference reads [`InstructionSet::operands_are_read`].
    pub reads: Vec<RegisterOperand>,
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

/// Where a breakpoint goes.
///
/// Two variants rather than one string because they reach the engine through different calls with
/// different costs, and a caller that already has an address should not pay for an evaluator it
/// does not need. [`Self::Expression`] is `SetOffsetExpression`, [`Self::Address`] is `SetOffset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakpointAt {
    /// A resolved address. Cannot block and cannot defer.
    Address(u64),
    /// A symbolic expression — `nt!Foo`, `hevd!Trigger+0x40`, a register expression.
    ///
    /// **Resolved eagerly, and the resolve can block.** The engine evaluates the expression as the
    /// breakpoint's offset is set, and flags the breakpoint [deferred](BreakpointInfo::deferred)
    /// only when it *cannot* — so on a module whose PDB is not in the local store this is a
    /// symbol-server fetch, with the engine held for all of it. Measured on dbgeng
    /// 10.0.29547.1002: **2445 ms** for a cold `KERNELBASE!CreateFileW` over `srv*` against an
    /// empty downstream store, 151 ms warm, and 0 ms for an expression whose module is absent,
    /// which defers instead. That is what [`DebugEngine::set_breakpoint_bounded`] is for.
    ///
    /// Those are `examples/breakpoint_probe.rs`'s `resolve` arm, which is the point of quoting
    /// them rather than any other run: a figure in a doc comment that the harness beside it does
    /// not print is one nobody can check. This said "6 ms warm, 2620 ms cold" until 2026-09-02 —
    /// both real, and neither reproducible here. The 2620 ms was the same experiment through the
    /// scratch probe this example replaced, and the 6 ms was a *different symbol* in a session
    /// something else had already warmed.
    Expression(String),
}

/// What accesses activate a data (processor) breakpoint — `ba`'s access argument.
///
/// [`Self::Read`] behaves as [`Self::ReadWrite`] on x86 and x64; it is kept distinct because the
/// engine takes the distinction and other architectures may honour it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAccess {
    Read,
    Write,
    ReadWrite,
    Execute,
    /// I/O port access. Kernel mode, x86, Windows XP and Server 2003 only — spelled here because
    /// the engine takes it, and refused by the engine everywhere else.
    Io,
    /// A combination this build does not name, kept as the engine's own bits.
    ///
    /// Produced by reading a breakpoint back ([`BreakpointInfo::data`]), as
    /// [`BreakpointKind::Other`] is. Passing one to a setter sends those bits unchanged and lets
    /// the engine judge them, which is the same deal every other variant gets.
    Other(u32),
}

impl DataAccess {
    fn to_engine(self) -> u32 {
        match self {
            Self::Read => DEBUG_BREAK_READ,
            Self::Write => DEBUG_BREAK_WRITE,
            Self::ReadWrite => DEBUG_BREAK_READ | DEBUG_BREAK_WRITE,
            Self::Execute => DEBUG_BREAK_EXECUTE,
            Self::Io => DEBUG_BREAK_IO,
            Self::Other(bits) => bits,
        }
    }

    fn from_engine(bits: u32) -> Self {
        const READ: u32 = DEBUG_BREAK_READ;
        const WRITE: u32 = DEBUG_BREAK_WRITE;
        const READ_WRITE: u32 = DEBUG_BREAK_READ | DEBUG_BREAK_WRITE;
        match bits {
            READ => Self::Read,
            WRITE => Self::Write,
            READ_WRITE => Self::ReadWrite,
            DEBUG_BREAK_EXECUTE => Self::Execute,
            DEBUG_BREAK_IO => Self::Io,
            other => Self::Other(other),
        }
    }
}

/// The watched region of a data breakpoint: what access, over how many bytes.
///
/// One value because the engine takes them in one call (`SetDataParameters`) and because neither
/// is meaningful alone — a size with no access type does not describe a breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataWatch {
    pub access: DataAccess,
    /// 1, 2, 4 or 8 bytes on x64; 1, 2 or 4 on x86. The address must be a multiple of it.
    ///
    /// Both are refused by [`DebugEngine::set_breakpoint`] rather than left to the engine, because
    /// a processor breakpoint whose size or alignment is wrong is refused when the target is
    /// **resumed** — so the engine's complaint arrives detached from the call that caused it,
    /// against a debug register nobody has looked at.
    ///
    /// The alignment is judged on the **resolved** address, so an expression is checked once the
    /// engine has evaluated it rather than waved through. The one case that cannot be checked is a
    /// [deferred](BreakpointInfo::deferred) data breakpoint, which the engine resolves on a later
    /// module load with nothing of this crate's on the stack to see the result.
    pub size: u32,
}

/// What to do about breakpoints the engine already holds at the address a new one resolves to.
///
/// The engine has **no** deduplication of its own: `AddBreakpoint2` plus a location, twice on one
/// address, leaves two breakpoints — both enabled, both listed by `bl`. What deduplicates is the
/// *command layer*: `bp` and `bu` alike resolve their argument and then remove whatever is already
/// at that address, printing `breakpoint N redefined`. Measured on dbgeng 10.0.29547.1002, by
/// symbol, by literal address and by `symbol+0` alike. A **deferred** expression has no address to
/// key on and so duplicates freely, which is why `bp nosuchmod!Sym` three times leaves three
/// breakpoints where `bp ntdll!NtCreateFile` three times leaves one.
///
/// So a caller replacing a `bp` with this primitive has to say which of the two it meant, or it
/// changes behaviour silently. Duplicates are not benign: the target stops **once** at the
/// address, but every breakpoint there is activated — the stop banner reads `Breakpoint 0 hit`
/// *and* `Breakpoint 1 hit`, each one's [command](BreakpointSpec::command) runs, and removing one
/// by id leaves the address armed by the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnExisting {
    /// Leave them. The engine's own behaviour, and the honest default for a primitive: nothing is
    /// destroyed that the caller did not name.
    #[default]
    Add,
    /// Remove every other breakpoint at the resolved address first, reporting their ids as
    /// [`BreakpointSet::replaced`] — what `bp` does, with the collapse as a value rather than a
    /// line of text.
    ///
    /// A location that does not resolve replaces nothing, there being no address to compare:
    /// `replaced` comes back empty and [`BreakpointInfo::deferred`] says why.
    ///
    /// **Nothing is removed unless the replacement succeeds**, which is a property of *when* the
    /// removal happens rather than of this flag: it is the last thing the call does, after every
    /// step that can fail. A call that fails part-way — a thread id the engine refuses, an
    /// unresolvable expression, a location the engine will not take — leaves the caller's existing
    /// breakpoints exactly as they were, rather than handing them an error and an address they had
    /// already lost.
    ///
    /// [`BreakpointSet::replaced`] reports what was actually removed, not what was intended.
    Replace,
}

/// A breakpoint to create: where it goes, and every parameter the engine will hold it by.
///
/// Built with [`Self::code`] or [`Self::data`] and narrowed with the methods below, so the
/// combination that cannot exist — a data breakpoint with no watched region — cannot be spelled.
/// That is also why the kind is not a field of its own: [`Self::data`] is `Some` exactly when this
/// is a processor breakpoint, so the kind and its parameters cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakpointSpec {
    pub at: BreakpointAt,
    /// `Some` makes this a data (processor) breakpoint — `ba` — and `None` a code one, `bp`.
    pub data: Option<DataWatch>,
    /// A debugger command run every time it is activated, as `bp`'s quoted trailing argument is.
    ///
    /// **This is the parameter that makes the text hatch unnecessary.** A command that reaches the
    /// engine as an argument needs no quoting and no screening: it is never parsed as part of a
    /// command line, so a `;` in it separates nothing and a `"` in it opens nothing.
    pub command: Option<String>,
    /// Restricts it to one thread, by engine thread id. `None` matches any thread.
    pub thread: Option<u32>,
    /// How many times it must be reached before it stops the target. `None` and `Some(1)` mean the
    /// same thing to the engine: stop every time.
    pub pass_count: Option<u32>,
    /// Removes itself the first time it is activated (`DEBUG_BREAKPOINT_ONE_SHOT`) — `bp /1`.
    pub one_shot: bool,
    /// Whether it is armed. **Defaults to `true`**, which is not the engine's default: a
    /// breakpoint is born disabled *and* at address zero, so the engine's default is a breakpoint
    /// on the null page that never fires. The wrapper this type replaces shipped exactly that.
    pub enabled: bool,
    pub on_existing: OnExisting,
}

impl BreakpointSpec {
    /// A code breakpoint — execution reaching an address. `bp`.
    pub fn code(at: BreakpointAt) -> Self {
        Self {
            at,
            data: None,
            command: None,
            thread: None,
            pass_count: None,
            one_shot: false,
            enabled: true,
            on_existing: OnExisting::Add,
        }
    }

    /// A data breakpoint — the processor accessing a region. `ba`.
    pub fn data(at: BreakpointAt, watch: DataWatch) -> Self {
        Self {
            data: Some(watch),
            ..Self::code(at)
        }
    }

    /// A command the debugger runs on every activation. See [`Self::command`].
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Restrict it to one thread.
    pub fn on_thread(mut self, thread: u32) -> Self {
        self.thread = Some(thread);
        self
    }

    /// Stop only on the nth arrival.
    pub fn with_pass_count(mut self, passes: u32) -> Self {
        self.pass_count = Some(passes);
        self
    }

    /// Remove itself once activated.
    pub fn one_shot(mut self) -> Self {
        self.one_shot = true;
        self
    }

    /// Create it disabled, to be armed later with [`DebugEngine::enable_breakpoint`].
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Remove whatever the engine already holds at this address. See [`OnExisting::Replace`].
    pub fn replacing_existing(mut self) -> Self {
        self.on_existing = OnExisting::Replace;
        self
    }

    /// Refuses a spec the engine would accept now and reject later.
    ///
    /// A processor breakpoint's size must be a power of two up to the pointer width and its
    /// address a multiple of that size. The engine takes a bad pair without complaint at the set
    /// and refuses it when the target is **resumed**, so the error arrives against a `go` that did
    /// nothing wrong, naming a debug register rather than the call that armed it.
    ///
    /// The size is checked for both location kinds. The alignment can only be checked here for
    /// [`BreakpointAt::Address`], an expression having no address until the engine resolves it —
    /// so [`DebugEngine::set_breakpoint_bounded`] checks it **again** on the resolved offset, which
    /// is where `ba` on `nt!Foo+1` is caught. This is half of that rule rather than all of it.
    ///
    /// **8 bytes is accepted whatever the target is**, and the reason is a measurement rather than
    /// this function's lack of an engine — which is what an earlier version of this comment
    /// claimed, and it was the weak half of the argument, since the caller
    /// ([`DebugEngine::set_breakpoint_bounded`]) has one.
    ///
    /// The constraint is the **hardware's** debug registers, not the target's bitness, and those
    /// are not the same question: a WOW64 process is a 32-bit target on 64-bit registers. Measured
    /// on this host — an 8-byte write watch on a `SysWOW64\cmd.exe` is accepted at the set *and*
    /// survives the resume, exactly as it does for a 64-bit target. So a check keyed on the
    /// target's architecture would refuse a spec that works. It would also not fire on the case it
    /// was proposed for: `.effmach` reports **x64** for that WOW64 process at the loader break.
    ///
    /// What is left is a genuinely 32-bit *host*, which this crate does not build for — its
    /// documented targets are `x86_64` and `aarch64` — and where the engine is the authority
    /// anyway, as it is for [`DataAccess::Execute`] below.
    ///
    /// **The access type is not judged against the size here, and that is measured rather than
    /// overlooked.** An execute watch must be one byte on x86/x64 — a DR7 slot with `R/W=00`
    /// carries `LEN=00` — and it was raised in review as another delayed failure. It is not one:
    /// `SetDataParameters` refuses `Execute` with size 2, 4 or 8 **synchronously**, with
    /// `E_INVALIDARG`, and `ba e4` fails the same way (measured on dbgeng 10.0.29547.1002, all
    /// three sizes, against a size 1 that is accepted). So the engine already reports it against
    /// the call that caused it, which is the whole property this function exists to provide — and
    /// restating it here would put an x86/x64 rule in front of an engine that answers per target.
    fn validated(&self) -> Result<(), DbgEngError> {
        let Some(watch) = self.data else {
            return Ok(());
        };
        if !matches!(watch.size, 1 | 2 | 4 | 8) {
            return Err(DbgEngError::InvalidBreakpoint(format!(
                "a data breakpoint's size must be 1, 2, 4 or 8 bytes, not {}",
                watch.size
            )));
        }
        if let BreakpointAt::Address(address) = self.at
            && !address.is_multiple_of(u64::from(watch.size))
        {
            return Err(DbgEngError::InvalidBreakpoint(format!(
                "a {}-byte data breakpoint must be {}-byte aligned, and {address:#x} is not",
                watch.size, watch.size
            )));
        }
        Ok(())
    }

    /// The flags a freshly created breakpoint has to be given to match this spec.
    ///
    /// `DEBUG_BREAKPOINT_DEFERRED` is absent deliberately and cannot be added: the engine owns it
    /// — it is set when an expression will not evaluate, and *"cannot be modified by any client"* —
    /// so it is read back on [`BreakpointInfo`] and never sent.
    fn flags(&self) -> u32 {
        let mut flags = 0;
        if self.enabled {
            flags |= DEBUG_BREAKPOINT_ENABLED;
        }
        if self.one_shot {
            flags |= DEBUG_BREAKPOINT_ONE_SHOT;
        }
        flags
    }
}

/// What [`DebugEngine::set_breakpoint`] left the session holding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakpointSet {
    /// The new breakpoint as the **engine** holds it, read back through the same getters
    /// [`DebugEngine::breakpoints`] uses rather than echoed from the spec.
    ///
    /// The difference is the whole value of the field: the spec says what was asked for, and this
    /// says what happened — whether an expression resolved, what address it resolved to, and
    /// whether the engine kept the text.
    pub breakpoint: BreakpointInfo,
    /// Ids removed to make room, under [`OnExisting::Replace`]. Empty under [`OnExisting::Add`],
    /// and empty when the location did not resolve.
    ///
    /// What was **actually** removed. The removal runs after the new breakpoint is armed and is
    /// deliberately best-effort, so one the engine would not give up is absent here and still
    /// present in [`DebugEngine::breakpoints`] — reported by omission rather than by failing a call
    /// whose breakpoint is already set.
    pub replaced: Vec<u32>,
    /// `None` when the whole set ran to completion.
    ///
    /// **The breakpoint exists either way**, which is why this is a field on a success rather than
    /// an error: a caller that retries on an error ends up with two. What is uncertain when this
    /// is `Some` is only whether the *location* finished resolving — and
    /// [`BreakpointInfo::deferred`] and [`BreakpointInfo::address`] on the record above answer
    /// that, having been read back after the fact rather than assumed.
    ///
    /// A break also abandons the symbol load it interrupted: measured, the module is left on
    /// export symbols for the rest of the session, so a caller that needs the PDB has to reload it
    /// rather than expect the next call to retry.
    pub cut_short: Option<Interruption>,
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
    /// The expression the engine is still holding this breakpoint as, where it holds one.
    ///
    /// **Whether a resolved breakpoint keeps its text depends on who set it**, which this doc used
    /// to get wrong by describing only the command's behaviour. Measured on dbgeng
    /// 10.0.29547.1002:
    ///
    /// - set by `bp`/`bu`, the engine discards the text once it resolves, so `None` beside a
    ///   [resolved address](Self::address) is the ordinary case rather than a gap;
    /// - set by [`DebugEngine::set_breakpoint`] with a [`BreakpointAt::Expression`], the engine
    ///   **keeps** it — `Some("ntdll!NtCreateFile")` beside a resolved address, with
    ///   [`Self::deferred`] false.
    ///
    /// So this is `Some` for every deferred breakpoint and for a resolved one whose location was
    /// set through the typed path. Read [`Self::deferred`] rather than this field to ask whether a
    /// breakpoint has an address yet.
    pub expression: Option<String>,
    /// The command string the debugger runs each time it fires, where it has one.
    pub command: Option<String>,
    /// The watched region, for a [data](BreakpointKind::Data) breakpoint — what access, over how
    /// many bytes. `None` for a code breakpoint, which has neither.
    ///
    /// Read through `GetDataParameters`, so a breakpoint set with a [`DataWatch`] reads back as
    /// the same pair. Without it the read side could say a breakpoint *is* a data breakpoint and
    /// not what it watches, which would leave [`BreakpointSet::breakpoint`] unable to confirm the
    /// half of a spec most worth confirming.
    pub data: Option<DataWatch>,
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

/// One instruction, decoded from bytes you already have, with no debug session anywhere.
///
/// Everything else here reaches an instruction through a target: [`DebugEngine::disassemble`] asks
/// the engine to render one and [`DebugEngine::decode_range`] reads a span out of a live address
/// space. This is the same decoding without either, for a caller holding the encoding already --
/// bytes read out of a file, an image mapped by something else, or a word under test.
///
/// [`Instruction::text`] is empty, nothing having rendered it, exactly as it is for
/// [`DebugEngine::decode_range`]. `set` is the caller's to supply, there being no target to ask.
///
/// **The bytes are in [`Instruction::bytes`]' order and that is not always memory order.** On x86
/// and x64 the two coincide. On ARM64 it is the instruction *word*, most significant byte first --
/// `a9bf7bfd` for `stp fp,lr,[sp,#-0x10]!`, whose four bytes in memory read `fd 7b bf a9` -- so a
/// caller with a `u32` word passes `word.to_be_bytes()` and one with memory reverses first.
pub fn decode_instruction(bytes: &[u8], address: u64, set: InstructionSet) -> Instruction {
    let decoded = decode_operation(bytes, address, set);
    // **Only the bytes this instruction occupies**, not the whole buffer the caller offered. An
    // x86 caller cannot know an instruction's length before decoding it -- that is most of why
    // they are calling -- so they pass what they have, and `[0x90, 0xcc]` decoded as `nop` used to
    // answer `90cc`. A stream walker stepping by `bytes.len()` then skipped whatever followed.
    // Where nothing decoded there is no extent to report and the caller's own buffer is the
    // honest answer, which is what `Flow::Unknown` beside it already says. Raised on dbgscope#171.
    let occupies = match decoded.length {
        Some(length) => &bytes[..length.min(bytes.len())],
        None => bytes,
    };
    Instruction {
        address,
        bytes: hex::encode(occupies),
        text: String::new(),
        mnemonic: decoded.mnemonic,
        operands: decoded.operands,
        flow: decoded.flow,
        privileged: decoded.privileged,
        effect: decoded.effect,
        condition: decoded.condition,
        writes_flags: decoded.writes_flags,
        writes: decoded.writes,
        reads: decoded.reads,
    }
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
fn split_instruction(address: u64, line: &str, set: InstructionSet) -> Instruction {
    let mut columns = line.trim().splitn(3, char::is_whitespace);
    let (_address, bytes, rest) = (columns.next(), columns.next(), columns.next());
    let (bytes, text) = match (bytes, rest) {
        (Some(bytes), Some(rest)) => (bytes.to_string(), collapse_spaces(rest)),
        // One column past the address, or none: keep it whole rather than calling it an encoding.
        (Some(only), None) => (String::new(), collapse_spaces(only)),
        _ => (String::new(), collapse_spaces(line)),
    };
    // The encoding is the engine's own read of this instruction, so decoding it costs no round
    // trip. A column that is not hexadecimal is not one — a `???` line has none — and decodes to
    // nothing.
    let raw = hex::decode(&bytes).unwrap_or_default();
    let decoded = decode_operation(&raw, address, set);
    let mut mnemonic = decoded.mnemonic;
    if mnemonic.is_empty() {
        // Nothing decoded: an instruction set this does not decode, or bytes that are not an
        // instruction. The rendering's first token is the mnemonic in every syntax the engine
        // prints, and it is the one thing still worth reporting.
        mnemonic = text
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
    }
    Instruction {
        address,
        bytes,
        text,
        mnemonic,
        operands: decoded.operands,
        flow: decoded.flow,
        privileged: decoded.privileged,
        effect: decoded.effect,
        condition: decoded.condition,
        writes_flags: decoded.writes_flags,
        writes: decoded.writes,
        reads: decoded.reads,
    }
}

/// One instruction's **encoding**, decoded.
///
/// # Why this is not read out of the rendering
///
/// The engine's third column is a rendering, and recovering structure from it means deciding what
/// a character means from the fact that it is present. That was tried, at length: a comma is an
/// operand separator until a demangled `std::map<int,int>` puts one inside a symbol; a parenthesis
/// introduces the resolved address until `operator()` puts one inside a symbol; a bracket opens a
/// memory expression until `operator[]` puts one inside a symbol. Three review rounds found the
/// same defect through three characters, each fix locally correct and the next one already
/// waiting. The same shape appeared in the mnemonic table — `int` by vector, then `xbegin`, then
/// `xabort`, then `hlt` — because a hand-maintained list of what transfers control is never
/// finished.
///
/// The encoding has none of those ambiguities. `bytes` is the engine's own read of the
/// instruction, so decoding it needs no extra round trip, and a decoder answers what the operands
/// *are* rather than how they were printed. Symbols leave the picture entirely: a destination is
/// an address, and naming it is [`DebugEngine::symbol_for`]'s job, so no symbol's spelling can
/// take an operand apart again.
///
/// The rendering stays in [`Instruction::text`] verbatim beside the fields, because it is what a
/// listing prints and this crate has always promised `u`'s own output. In principle the two could
/// disagree on an encoding one decoder knows and the other does not; they are the same bytes, and
/// the fields say which reading they came from.
#[derive(Debug)]
pub(crate) struct Decoded {
    pub(crate) mnemonic: String,
    pub(crate) operands: Vec<Operand>,
    pub(crate) flow: Flow,
    pub(crate) privileged: bool,
    pub(crate) effect: Effect,
    pub(crate) condition: Option<Condition>,
    pub(crate) writes_flags: bool,
    pub(crate) writes: Vec<RegisterOperand>,
    pub(crate) reads: Vec<RegisterOperand>,
    /// How many of the bytes offered this instruction occupies, or `None` where nothing decoded.
    ///
    /// Only [`decode_instruction`] reads it, and only because its caller supplies the buffer: the
    /// engine-backed paths are handed exactly one instruction's bytes already. It is carried here
    /// rather than recomputed because this is where it is known -- recomputing it for x86 means
    /// decoding twice and deciding the same thing in two places.
    pub(crate) length: Option<usize>,
}

impl Decoded {
    /// A flow and nothing else: bytes nothing decoded, where the flow is [`Flow::Unknown`] or
    /// [`Flow::Unreadable`] and the name is literal.
    fn nothing(flow: Flow) -> Self {
        Self {
            mnemonic: String::new(),
            operands: Vec::new(),
            flow,
            privileged: false,
            effect: Effect::Other,
            condition: None,
            writes_flags: false,
            writes: Vec::new(),
            reads: Vec::new(),
            length: None,
        }
    }
}

fn decode_operation(bytes: &[u8], address: u64, set: InstructionSet) -> Decoded {
    // Asked before the instruction set: bytes that are not there are not there on any
    // architecture, and answering `Unknown` for them on ARM64 would let a walk step through the
    // same unreadable page the x64 path is kept out of.
    if bytes.is_empty() {
        return Decoded::nothing(Flow::Unreadable);
    }
    let bitness = match set {
        InstructionSet::X86 => 32,
        InstructionSet::Amd64 => 64,
        // **The word is assembled big-endian from these bytes**, which looks wrong for a
        // little-endian architecture and is not: this column is the engine's *rendering* of the
        // instruction, and it prints the word rather than the memory (`a9bf7bfd` for
        // `stp fp,lr,[sp,#-0x10]!`, whose four bytes read `fd 7b bf a9`). `decode_range`, which
        // reads memory, assembles it the other way round.
        InstructionSet::Arm64 => {
            let Ok(word) = <[u8; crate::arm64::INSTRUCTION_BYTES]>::try_from(
                &bytes[..bytes.len().min(crate::arm64::INSTRUCTION_BYTES)],
            ) else {
                // A byte column shorter than one A64 instruction. No engine produces that for a
                // readable address, and a short word decoded anyway is a branch to an address
                // built out of bytes nobody read.
                return Decoded::nothing(Flow::Unknown);
            };
            return crate::arm64::decode(u32::from_be_bytes(word), address);
        }
        // Not decoded at all: the mnemonic is still the rendering's first token, and the caller
        // reads `Flow::Unknown` as "nothing was claimed".
        InstructionSet::Other(_) => return Decoded::nothing(Flow::Unknown),
    };
    let mut decoder =
        iced_x86::Decoder::with_ip(bitness, bytes, address, iced_x86::DecoderOptions::NONE);
    let decoded = decoder.decode();
    if decoded.is_invalid() {
        // Bytes that were read and did not decode. That is **not** [`Flow::Unreadable`], which
        // means there is no instruction here: the engine rendered one, so there is, and this
        // decoder simply does not know it — an extension newer than the version pinned, or a
        // span entered mid-instruction. `Unknown` says exactly that, and falls through, where
        // `Unreadable` would stop a walk and discard the rest of a routine over a version skew.
        return Decoded::nothing(Flow::Unknown);
    }

    let mnemonic = format!("{:?}", decoded.mnemonic()).to_lowercase();
    let operands = (0..decoded.op_count())
        .map(|index| read_decoded_operand(&decoded, index, bitness))
        .collect();
    let (reads, writes) = touched_registers(&decoded, bitness);
    Decoded {
        mnemonic,
        operands,
        flow: decoded_flow(&decoded),
        privileged: decoded.is_privileged(),
        effect: decoded_effect(&decoded),
        condition: decoded_condition(&decoded),
        // Any flag at all: what a caller is asking is "did this set the flags the branch after it
        // reads", and the decoder knows which bits each instruction writes.
        writes_flags: decoded.rflags_written() != 0,
        writes,
        reads,
        length: Some(decoded.len()),
    }
}

/// Every register an instruction reads and every register it writes, explicit and implicit.
///
/// iced's instruction *info* rather than its operands, which is the whole point: the operand list
/// is what the instruction was written with, and the info is what it touches. `mul ecx` names one
/// register, writes two and reads two, and only one of the four is the one it names.
///
/// **Both halves from one call, because they are one answer.** `used_registers()` is a single list
/// carrying every access, so asking for the writes and then for the reads builds that list twice
/// per instruction — which `decode_range` pays over hundreds of functions to split something it
/// already had. The two filters below run over the one borrow.
///
/// **One factory, kept for the thread.** iced's factory exists to be reused -- it owns the vectors
/// the answer is built in -- so making one per instruction throws those away and allocates again
/// for the next, which `decode_range` does once per instruction over hundreds of functions.
/// Thread-local rather than a parameter because the other caller is `split_instruction`, which is
/// public and is handed one line at a time; a signature that made every caller carry scratch would
/// spread this crate's bookkeeping into theirs. `NO_MEMORY_USAGE` because the memory half of the
/// answer is gathered and thrown away here — the registers that *form* an address are in
/// `used_registers()` either way, which is why [`Instruction::reads`] has them.
fn touched_registers(
    decoded: &iced_x86::Instruction,
    bitness: u32,
) -> (Vec<RegisterOperand>, Vec<RegisterOperand>) {
    use iced_x86::InstructionInfoOptions;
    thread_local! {
        static FACTORY: std::cell::RefCell<iced_x86::InstructionInfoFactory> =
            std::cell::RefCell::new(iced_x86::InstructionInfoFactory::new());
    }
    FACTORY.with(|factory| {
        let mut factory = factory.borrow_mut();
        let used = factory
            .info_options(decoded, InstructionInfoOptions::NO_MEMORY_USAGE)
            .used_registers();
        (read_from(used, bitness), written_from(used, bitness))
    })
}

/// The registers an instruction's info says it **writes**, as operands.
///
/// A **conditional** write counts, because the question a consumer asks is "may this register have
/// changed" and the conservative answer is the only safe one. `OpAccess::NoMemAccess` is about
/// memory rather than about a register and cannot appear here; it is matched with the reads so the
/// arms stay exhaustive over the enum rather than over a wildcard, which is what keeps this honest
/// when iced adds one.
///
/// Split from the factory above so the borrow ends with it: the answer is owned rather than
/// borrowed out of scratch storage the next instruction will overwrite.
fn written_from(used: &[iced_x86::UsedRegister], bitness: u32) -> Vec<RegisterOperand> {
    use iced_x86::OpAccess;
    registers_from(used, bitness, |access| match access {
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
            true
        }
        OpAccess::None | OpAccess::Read | OpAccess::CondRead | OpAccess::NoMemAccess => false,
    })
}

/// The registers an instruction's info says it **reads**, as operands.
///
/// [`written_from`]'s filter mirrored, arm for arm, and the mirroring is the point: a
/// read-and-write access is in both answers, and `None`/`NoMemAccess` are in neither. Both matches
/// are exhaustive over `OpAccess` for the same reason — an arm iced adds later has to be decided
/// here rather than swallowed by a wildcard, and in *both* directions.
fn read_from(used: &[iced_x86::UsedRegister], bitness: u32) -> Vec<RegisterOperand> {
    use iced_x86::OpAccess;
    registers_from(used, bitness, |access| match access {
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite => true,
        OpAccess::None | OpAccess::Write | OpAccess::CondWrite | OpAccess::NoMemAccess => false,
    })
}

/// The registers of one access direction, deduplicated, in the order iced reports them.
fn registers_from(
    used: &[iced_x86::UsedRegister],
    bitness: u32,
    wanted: impl Fn(iced_x86::OpAccess) -> bool,
) -> Vec<RegisterOperand> {
    let mut picked: Vec<RegisterOperand> = Vec::new();
    for used in used {
        if !wanted(used.access()) || used.register() == iced_x86::Register::None {
            continue;
        }
        let operand = register_operand(used.register(), bitness);
        // iced reports a register once per access kind, and an instruction can name one twice --
        // `test eax,eax` reports `eax/Read` twice. What a consumer wants is the set.
        //
        // **Keyed on the spelling and not on the full-width register**, because these are the
        // registers the instruction touched: an access to `ah` and one to `al` are two accesses,
        // and collapsing them onto `rax` would report a width that was never touched.
        if !picked.iter().any(|seen| seen.name == operand.name) {
            picked.push(operand);
        }
    }
    picked
}

/// What the instruction does to its operands, from the decoder's own mnemonic rather than from the
/// rendering of one.
///
/// A `match` over a typed enum rather than over strings, which is the difference that matters: the
/// compiler sees every arm, the spellings the engine happens to print cannot change it, and a
/// second architecture answers the same classes from its own decoder rather than from a second
/// copy of somebody's list.
fn decoded_effect(decoded: &iced_x86::Instruction) -> Effect {
    use iced_x86::Mnemonic;
    match decoded.mnemonic() {
        Mnemonic::Mov | Mnemonic::Movzx => Effect::Move,
        Mnemonic::Movsx | Mnemonic::Movsxd => Effect::MoveSigned,
        Mnemonic::Lea => Effect::LoadAddress,
        Mnemonic::Cmp => Effect::Compare,
        Mnemonic::Test => Effect::Test,
        Mnemonic::Add | Mnemonic::Adc | Mnemonic::Inc => Effect::Add,
        Mnemonic::Sub | Mnemonic::Sbb | Mnemonic::Dec => Effect::Subtract,
        Mnemonic::Shl | Mnemonic::Sal => Effect::ShiftLeft,
        Mnemonic::Shr | Mnemonic::Sar => Effect::ShiftRight,
        Mnemonic::And => Effect::BitAnd,
        Mnemonic::Or => Effect::BitOr,
        Mnemonic::Xor => Effect::BitXor,
        Mnemonic::Push => Effect::Push,
        Mnemonic::Pop => Effect::Pop,
        _ => Effect::Other,
    }
}

/// The condition a conditional branch reads, from the decoder's `ConditionCode`.
///
/// **Signedness comes with it**, which is the whole reason this is not a mnemonic: `ja` and `jg`
/// are the same word in English and different questions about a value.
fn decoded_condition(decoded: &iced_x86::Instruction) -> Option<Condition> {
    use iced_x86::ConditionCode;
    Some(match decoded.condition_code() {
        ConditionCode::None => return None,
        ConditionCode::e => Condition::Equal,
        ConditionCode::ne => Condition::NotEqual,
        ConditionCode::a => Condition::UnsignedAbove,
        ConditionCode::ae => Condition::UnsignedAboveOrEqual,
        ConditionCode::b => Condition::UnsignedBelow,
        ConditionCode::be => Condition::UnsignedBelowOrEqual,
        ConditionCode::g => Condition::SignedGreater,
        ConditionCode::ge => Condition::SignedGreaterOrEqual,
        ConditionCode::l => Condition::SignedLess,
        ConditionCode::le => Condition::SignedLessOrEqual,
        ConditionCode::s => Condition::Negative,
        ConditionCode::ns => Condition::NotNegative,
        ConditionCode::o => Condition::Overflow,
        ConditionCode::no => Condition::NotOverflow,
        ConditionCode::p => Condition::Parity,
        ConditionCode::np => Condition::NotParity,
    })
}

/// One decoded operand.
fn read_decoded_operand(decoded: &iced_x86::Instruction, index: u32, bitness: u32) -> Operand {
    use iced_x86::OpKind;
    match decoded.op_kind(index) {
        OpKind::Register => {
            Operand::Register(register_operand(decoded.op_register(index), bitness))
        }
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Operand::Target(canonical_target(decoded))
        }
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Operand::Immediate(decoded.immediate(index)),
        OpKind::Memory => Operand::Memory(read_decoded_memory(decoded, bitness)),
        // Far branches, and the implicit string-operation operands. Kept rather than shaped.
        other => Operand::Other(format!("{other:?}").to_lowercase()),
    }
}

/// The memory operand of a decoded instruction.
fn read_decoded_memory(decoded: &iced_x86::Instruction, bitness: u32) -> MemoryOperand {
    let size = decoded.memory_size().size();
    let base = decoded.memory_base();
    let index = decoded.memory_index();
    let rip_relative = base == iced_x86::Register::RIP || base == iced_x86::Register::EIP;
    // A segment override means the linear address is the segment's base plus this, and that base
    // is a runtime fact — `gs:[188h]` is the KPCR and emphatically not address `0x188`. So an
    // override rules out a static address entirely, rather than being ignored because both the
    // base and index registers happen to be absent.
    let overridden = decoded.segment_prefix() != iced_x86::Register::None;
    // Canonicalised for the same reason a branch target is: 32-bit decoding computes a 32-bit
    // value, and an absolute `[0x80002000]` under an instruction living at `ffffffff`80001000` is
    // an address in a different space from the instruction that reads it. Absolute globals and
    // import slots are ordinary in x86 kernel code, so this is the field a consumer would follow.
    let address = if overridden {
        None
    } else if rip_relative {
        Some(canonical_address(decoded, decoded.ip_rel_memory_address()))
    } else if base == iced_x86::Register::None && index == iced_x86::Register::None {
        Some(canonical_address(decoded, decoded.memory_displacement64()))
    } else {
        None
    };
    // For a RIP-relative operand the decoder's displacement is the **normalised target**, not the
    // signed number the instruction encodes, so taking it verbatim would report `[rip+0xffa]` at
    // `0x1000` as a displacement of `0x2000` — a duplicate of `address` where the addressing
    // expression should be. Derived back against the instruction's own end, which is what the
    // displacement is relative to.
    // And a narrow effective address keeps its own width in the decoder, so `[ebp-8]` comes back
    // as `0xfffffff8` and a straight widening cast reports it as 4,294,967,288.
    //
    // # The width to sign-extend from, which is neither of the two obvious answers
    //
    // It is the **effective address width**, and both simpler readings of that are wrong in one
    // addressing form each:
    //
    // * The *index register's* width breaks a VSIB gather, whose index is an `xmm`/`ymm`/`zmm`:
    //   128 bits or more makes the extension a no-op and a negative displacement comes back as
    //   four billion.
    // * The *encoded field's* width breaks EVEX, whose `disp8` is **compressed** — the decoder
    //   returns it already multiplied by the tuple's scale while the field is still one byte, so
    //   extending the expanded value from eight bits turns a real `+128` into `-128`.
    //
    // The address registers give the width where there are any, an address-size override being
    // exactly what makes them narrow. Where there is no general-purpose register — a pure VSIB
    // form — the encoding makes the displacement field the address width, and EVEX compression
    // cannot arise there, since a compressed `disp8` needs a base.
    //
    // An absolute reference with no register stays unsigned, because a 32-bit `[0xfffff000]` is a
    // high address rather than a negative offset.
    let address_bits = if base != iced_x86::Register::None {
        base.size() * 8
    } else if index != iced_x86::Register::None && index.size() <= 8 {
        index.size() * 8
    } else {
        decoded.memory_displ_size() as usize * 8
    };
    let displacement = if rip_relative {
        // An address-size override leaves this `EIP`-relative, and then the decoder's target is
        // wrapped to 32 bits while the instruction's own next address is still 64 — so the
        // subtraction has to happen at the narrower width or it reports the delta four gigabytes
        // out.
        let delta = decoded
            .ip_rel_memory_address()
            .wrapping_sub(decoded.next_ip());
        if base == iced_x86::Register::EIP {
            sign_extend(delta & 0xffff_ffff, 32)
        } else {
            delta as i64
        }
    } else if base == iced_x86::Register::None && index == iced_x86::Register::None {
        decoded.memory_displacement64() as i64
    } else {
        sign_extend(decoded.memory_displacement64(), address_bits)
    };
    MemoryOperand {
        size: (size != 0).then_some(size as u32),
        // The *prefix*, not the segment the encoding implies: `[rsp+8]` is `ss` by rule and prints
        // no override, and reporting one would say the instruction carried something it did not.
        segment: overridden.then(|| register_name(decoded.segment_prefix())),
        base: (base != iced_x86::Register::None).then(|| register_operand(base, bitness)),
        index: (index != iced_x86::Register::None).then(|| register_operand(index, bitness)),
        scale: decoded.memory_index_scale() as u8,
        displacement,
        address,
    }
}

/// A value carried in `bits` of a wider word, read as the signed number it is.
fn sign_extend(value: u64, bits: usize) -> i64 {
    if bits == 0 || bits >= 64 {
        return value as i64;
    }
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

/// A register by the lowercase name the engine also prints.
fn register_name(register: iced_x86::Register) -> String {
    format!("{register:?}").to_lowercase()
}

/// A register operand, with the full-width register **the decoder** says it is part of.
///
/// The width depends on the target: `eax` is part of `rax` on x64 and is the whole register on
/// x86, so the bitness picks which question to ask. Neither answer is a list of names — iced knows
/// what `r8d` and `sil` and `ah` belong to because it decoded them.
fn register_operand(register: iced_x86::Register, bitness: u32) -> RegisterOperand {
    let full = match bitness {
        64 => register.full_register(),
        _ => register.full_register32(),
    };
    RegisterOperand {
        name: register_name(register),
        full: register_name(full),
        width: register.size() as u32,
    }
}

/// What a decoded instruction does to control flow.
///
/// Nearly all of this is the decoder's own `FlowControl`, which is complete by construction — the
/// property a hand-written mnemonic table could not have. Two families still need a decision, and
/// both are decisions about *semantics* rather than about spelling, so they are keyed on the
/// instruction's `Code` and not on a string.
fn decoded_flow(decoded: &iced_x86::Instruction) -> Flow {
    use iced_x86::{Code, FlowControl};
    match decoded.flow_control() {
        FlowControl::Next => Flow::Fallthrough,
        FlowControl::UnconditionalBranch => Flow::Jmp(near_target(decoded)),
        FlowControl::IndirectBranch => Flow::Jmp(None),
        FlowControl::ConditionalBranch => Flow::Branch(near_target(decoded)),
        FlowControl::Return => Flow::Return,
        FlowControl::Call => Flow::Call(near_target(decoded)),
        FlowControl::IndirectCall => Flow::Call(None),
        // Always raises: `ud0`/`ud1`/`ud2`. `hlt` is deliberately **not** here — the decoder calls
        // it `Next`, and rightly: a halted processor resumes at the next instruction when an
        // interrupt wakes it, so treating it as an ending truncates every idle loop.
        FlowControl::Exception => Flow::Trap,
        // A software interrupt is classified by its **vector**. Most return, and `int 2eh` — the
        // 32-bit system-call path — is the one that matters: stopping there discards every
        // instruction after a syscall. Two do not return: `int 29h` is `__fastfail`, and `int 3`
        // is the breakpoint a compiler emits as padding behind unreachable code.
        FlowControl::Interrupt => match decoded.code() {
            Code::Int3 => Flow::Trap,
            Code::Int_imm8 if matches!(decoded.immediate8(), 0x29 | 0x03) => Flow::Trap,
            _ => Flow::Fallthrough,
        },
        // TSX. `xbegin` starts a transaction on its fall-through and takes its operand on an abort
        // or a failure to start, and that abort path is commonly where the lock-based fallback
        // lives. `xabort` is a fall-through on purpose: inside a transaction it resumes at the
        // outer `xbegin`'s fallback, but the SDM makes it a NOP when `RTM_ACTIVE = 0`, and no
        // static reading tells the two apart — so classifying it as a transfer would drop every
        // instruction after it wherever RTM is inactive, which today is nearly everywhere.
        FlowControl::XbeginXabortXend => match decoded.code() {
            Code::Xbegin_rel16 | Code::Xbegin_rel32 => Flow::Branch(near_target(decoded)),
            _ => Flow::Fallthrough,
        },
    }
}

/// The destination of a direct branch or call, when the instruction carries one.
fn near_target(decoded: &iced_x86::Instruction) -> Option<u64> {
    use iced_x86::OpKind;
    (0..decoded.op_count())
        .any(|index| {
            matches!(
                decoded.op_kind(index),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        })
        .then(|| canonical_target(decoded))
}

/// A near branch's destination, in the address space its instruction came from.
///
/// Decoding 16- or 32-bit code computes a target of that width, so an instruction whose own
/// address carries a high half — a narrow effective machine over a wide address, which is exactly
/// what `.effmach x86` produces, and any target whose addresses arrive sign-extended — would get a
/// destination in a different address space from the instruction naming it. The high half is
/// inherited from the instruction rather than sign-extended, because that takes the address form
/// from the caller's own value instead of assuming which one the engine uses.
///
/// **64-bit decoding is left alone**, and not merely because it needs no help: a `rel32` branch
/// reaches ±2 GB, so it can legitimately cross a 4 GB boundary, and inheriting a high half there
/// would drag a correct target backwards by four gigabytes.
///
/// # Inherited rather than sign-extended, and that is measured
///
/// The alternative is to sign-extend a 32-bit value, on the theory that the engine hands out high
/// x86 addresses in sign-extended form; it has been proposed twice. **It does not.** Measured on
/// this build against a 32-bit user target (`cppthrow-fastfail-x86.dmp`), `? 80002000` evaluates
/// to `80002000` and `.formats` prints `Hex: 80002000` — eight digits, unextended. Sign-extending
/// would therefore invent `ffffffff80002000` for an address the engine calls `80002000`, and on a
/// 32-bit kernel, where most code lives above bit 31, it would do so for nearly every address.
/// Inheriting the instruction's own half reproduces exactly what was measured, because a genuine
/// 32-bit target's instructions have a zero high half.
///
/// What that leaves un-handled is one straddling case: a 32-bit instruction on one side of bit 31
/// reaching a target on the other keeps the half it started in. It is pinned by test rather than
/// left to be rediscovered, and it is the *narrower* of the two exposures — the sign-extending
/// rule would be wrong for every high address rather than for the ones that straddle. Reopen this
/// only with a measurement from a 32-bit **kernel** target, which no fixture here has.
fn canonical_target(decoded: &iced_x86::Instruction) -> u64 {
    canonical_address(decoded, decoded.near_branch_target())
}

/// A decoded address, put back into the address space its instruction came from.
///
/// See [`canonical_target`] for why, and for why 64-bit is left alone.
fn canonical_address(decoded: &iced_x86::Instruction, value: u64) -> u64 {
    if decoded.code_size() == iced_x86::CodeSize::Code64 {
        return value;
    }
    (decoded.ip() & 0xffff_ffff_0000_0000) | (value & 0xffff_ffff)
}

/// Runs of whitespace as one space. The engine pads its columns to align them in a listing, and
/// the alignment means nothing once the columns are separate fields.
fn collapse_spaces(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A PDB signature as a symbol server path spells it: 32 uppercase hex digits.
///
/// Not `{:?}` on the GUID, which prints the braced, dashed form no path uses, and not a
/// byte-order-preserving hex dump either — the first three fields are written as the numbers they
/// are and only the trailing eight bytes are laid out in order. Getting that wrong produces a URL
/// that 404s, which is a hard failure to read backwards.
fn format_pdb_guid(guid: &windows::core::GUID) -> String {
    let mut out = format!("{:08X}{:04X}{:04X}", guid.data1, guid.data2, guid.data3);
    for byte in guid.data4 {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

/// A NUL-terminated wide string out of a fixed engine buffer.
fn wide_to_string(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
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
    /// [`Bound::Watchdog`]). Owning them here costs one small
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
    /// A `RefCell` and not a `Mutex`, since dbgscope#136 stage 4: every reader reaches this
    /// through `&self`, and an engine is neither `Send` nor `Sync`, so there is one thread here
    /// by construction and the lock was guarding against a caller the type cannot produce. The
    /// three accesses are a push, a clear and a `Drop` that takes the vector, none of them
    /// nested and none re-entrant, so the runtime borrow it costs instead can never be observed.
    deferred_inputs: RefCell<Vec<TargetInput>>,
    /// The **session's** state, shared by every wrapper around this client and with every
    /// [`InterruptHandle`] this engine hands out: the opens waiting for a target
    /// ([`Arrivals`]) and the break requests scoped to operations ([`BreakScope`]). See
    /// [`ClientState`].
    ///
    /// Nothing reads either through this field directly. Arrivals go through the [`Registered`]
    /// guard an opener returns, break requests through [`Self::begin_operation`] and the
    /// [`Operation`] guard it returns, plus [`InterruptHandle::interrupt`] on the other side of
    /// the lock. Neither is ever cleared as an operation or an open begins: an entry names what it
    /// is for, so there is nothing for a later one to be charged with and nothing for an earlier
    /// one to erase.
    state: Arc<ClientState>,
}

impl Default for DebugEngine {
    fn default() -> Self {
        Self::new()
    }
}

// A `DebugEngine` is deliberately neither `Send` nor `Sync`, and that is the absence of two
// `unsafe impl`s rather than an oversight — dbgscope#136 stage 4.
//
// They asserted the opposite of what this crate says two hundred lines up, where
// [`InterruptHandle`] records that `SetInterrupt` is the one DbgEng call documented as safe from
// any thread *because the rest of the engine is single-thread-affine*. `Sync` promised concurrent
// `&self` calls into an engine that cannot take them; `Send` promised a move to another thread,
// which is the same claim one step weaker and equally unsupported. Neither had a safety comment,
// and neither could have been given a true one.
//
// Nothing needed them, which is what makes this a deletion rather than a trade: measured by
// removing each and building, both this crate (`--all-targets`, tests and examples included) and
// windbg-mcp compile unchanged. Both consumers already create the engine on the thread that uses
// it — windbg-mcp in `worker::build_engine`, on its engine thread, and the pool extension around
// the client DbgEng hands its command, on DbgEng's own calling thread.
//
// [`InterruptHandle`] is left as the single affordance that crosses threads, which is the whole
// of the threading model: one `SetInterrupt`, from anywhere, and nothing else.
// `the_engine_does_not_cross_threads_and_the_handle_does` is what stops an `unsafe impl` coming
// back without one.

/// What DbgEng says it is debugging: `GetDebuggeeType`'s class and qualifier, as the pair the
/// engine returns.
///
/// **The raw pair rather than an enum of the qualifiers**, because a caller wanting to know what
/// kind of target this is asks one of the predicates below, and a caller comparing two readings —
/// which is the other use, and the one no other engine query serves — wants the *whole* pair.
/// An enum would have to enumerate every `DEBUG_KERNEL_*` and `DEBUG_USER_WINDOWS_*` DbgEng has,
/// and two qualifiers it did not know about would fold into one variant and compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebuggeeType {
    /// `DEBUG_CLASS_*`: uninitialized, kernel, or user-mode Windows.
    pub class: u32,
    /// Which target within that class: `DEBUG_KERNEL_*` or `DEBUG_USER_WINDOWS_*` — a live
    /// connection, or which kind of dump.
    pub qualifier: u32,
}

impl DebuggeeType {
    /// Whether this is a kernel target at all — a live connection or a kernel dump.
    pub fn is_kernel(self) -> bool {
        self.class == DEBUG_CLASS_KERNEL
    }

    /// Whether this is a *live* kernel connection (net/1394/serial/local/EXDI/IDNA) as opposed to
    /// a kernel dump or a user-mode target. A live kernel requires an INFINITE `WaitForEvent`
    /// timeout; a finite one returns `E_NOTIMPL`.
    pub fn is_live_kernel(self) -> bool {
        // Dump qualifiers are >= DEBUG_KERNEL_SMALL_DUMP; live connections are below it.
        self.is_kernel() && self.qualifier < DEBUG_KERNEL_SMALL_DUMP
    }
}

/// What became of the **target** when its session ended.
///
/// Separate from whether the teardown succeeded, which is the `Result` this rides in: a session can
/// end cleanly and still leave its target in a state the caller has to do something about. That is
/// not hypothetical for a live kernel and is the case this type exists for -- a kernel detached
/// while halted stays halted, one CPU stopped and the rest spinning, and nothing downstream could
/// previously tell that from a kernel left running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetLeft {
    /// A live kernel whose quit-and-detach completed and released the target.
    /// This does not establish subsequent guest health: it may encounter another stop.
    KernelRunning,
    /// A live kernel the resume did not take on, detached anyway so that nothing holds it.
    ///
    /// **It is probably still halted**, and the remedy is another attach and a `qd`. Reported
    /// rather than raised because the session itself ended: a caller told only "that failed" would
    /// have no reason to go and look at the guest, which is the one thing worth doing here.
    KernelHalted,
    /// Nothing this can speak for: a dump, a trace, or user-mode processes, whose disposition is
    /// [`DebugEngine::attached_to_a_live_process`] read before the teardown clears it.
    Unspoken,
}

fn require_detached(has_target: bool) -> Result<(), DbgEngError> {
    if has_target {
        Err(DbgEngError::IncompleteKernelDetach)
    } else {
        Ok(())
    }
}

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

    /// Connects to a debugging **server** — an engine running in another process — and drives
    /// its session over DbgEng's remote transport.
    ///
    /// `remote_options` is the connection string `cdb -remote` takes:
    /// `npipe:pipe=<name>,server=<host>` or `tcp:port=<n>,server=<host>`. The server side is
    /// any engine host started with the matching `-server` option.
    ///
    /// The reason to reach for this over [`Self::new`] is that **an extension loads in the
    /// server**, where it meets the target, rather than in this process. So an engine host of a
    /// different architecture can run one this process could never load — a 32-bit `sos.dll`
    /// against a 32-bit CLR, driven from an x64 caller, which no in-process arrangement can do
    /// because the CLR data access DLL is architecture-paired to the target as well as the host.
    ///
    /// **The session belongs to the server, so this engine is a borrowed one**
    /// (`owns_session` stays false, via [`Self::try_from_client_interface`]): dropping it
    /// disconnects this client and leaves the server's target alone. Ending that target is the
    /// business of whoever started the host — and on a remote client `EndSession` would reach
    /// across and tear down a session this process never opened.
    ///
    /// Two measured properties of the remote transport, both surprising enough to state here:
    ///
    /// - **A remote client refuses `QueryInterface` for `IUnknown`** (`0x80010103`), so
    ///   [`Self::try_from_windbg_client`] — which takes an `&IUnknown` — cannot be used to wrap
    ///   one. That is why this goes through the typed constructor. `IDebugControl4`,
    ///   `IDebugDataSpaces4`, `IDebugSymbols3` and `IDebugAdvanced2` are all present.
    /// - **`IDebugAdvanced2::GetSymbolInformation` does not cross the transport**, so
    ///   [`Self::module_pdb`] fails with `E_INVALIDARG` against any remote session. Measured
    ///   with the client and server on the *same* architecture as well as across x86/x64, and
    ///   against an in-process engine on the same target where it succeeds — so it is the
    ///   transport rather than a struct whose size the two ends disagree about. Everything else
    ///   this type offers was exercised over a remote session and works.
    ///
    /// A version skew between the two engines is reported as `0x8007053D`, *"The server is
    /// currently disabled"*, which names neither end: a client whose `dbgeng.dll` is older than
    /// the server's is refused. Load both from the same debugger package.
    pub fn connect(remote_options: &str) -> Result<Self, DbgEngError> {
        let wide: Vec<u16> = remote_options
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut raw: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call, and `raw` receives an owned
        // interface pointer on success — taken over by the `from_raw` below.
        unsafe {
            DebugConnectWide(
                PCWSTR::from_raw(wide.as_ptr()),
                &IDebugClient6::IID,
                &raw mut raw,
            )
        }
        .map_err(|source| DbgEngError::Context {
            operation: format!("connecting to the debugging server at `{remote_options}`"),
            source,
        })?;
        // SAFETY: the call above returned success, so `raw` is an owned `IDebugClient6`.
        let client: IDebugClient6 = unsafe { IDebugClient6::from_raw(raw) };
        let engine = Self::try_from_client_interface(client)?;
        // A client this new cannot be one anything holds a cached view of, whatever address it
        // landed on — the same reasoning as [`Self::new`], and it applies here for the same
        // reason: this call, not the caller, is what created the pointer.
        reissue_identity(&engine.client);
        Ok(engine)
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

        // Taken before `client` moves into the struct below, and shared with every other wrapper
        // around this same client: see `ClientState`.
        let state = state_for(&client);
        Self {
            client,
            control,
            dataspaces,
            symbols,
            // Default to "borrowed": constructors that wrap an existing WinDbg client
            // go through here, and only `new()` (which calls `DebugCreate`) sets this.
            owns_session: false,
            deferred_inputs: RefCell::new(Vec::new()),
            state,
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
        let state = state_for(&client);
        Ok(Self {
            client,
            control,
            dataspaces,
            symbols,
            owns_session: false,
            deferred_inputs: RefCell::new(Vec::new()),
            state,
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
            state: Arc::clone(&self.state),
        }
    }

    /// Opens a bounded operation: a break a host raises from here until the guard drops is filed
    /// against **this** operation and nothing else.
    ///
    /// Every bounded or pumping path opens one, and that is what replaced clearing an engine-wide
    /// flag at each of their heads. The clear *was* the erasure in dbgscope#135 half A — a request
    /// lodged between an operation's clear and its wait was wiped while its break was still on the
    /// way — and it is gone rather than fixed: a request that names an operation cannot be charged
    /// to a later one, so there is nothing that needs clearing.
    ///
    /// **They nest**, which a single slot would silently get wrong:
    /// [`Self::wait_for_kernel_break_in`]'s `absorb_initial_break_artifact` runs a whole
    /// [`Self::execute_and_wait`] inside it, and that inner operation used to clear the outer one's
    /// request as it opened.
    fn begin_operation(&self) -> Operation<'_> {
        let id = self
            .state
            .breaks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .begin();
        Operation { engine: self, id }
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

    /// One `ReadVirtual` into `into`, answering how many bytes it filled.
    ///
    /// The single place this crate calls `ReadVirtual`, so the whole-range read below and the
    /// chunked one beside it cannot drift in how they ask or in what they make of a failure.
    fn read_virtual_into(&self, address: u64, into: &mut [u8]) -> Result<usize, DbgEngError> {
        let size = into.len();
        let size_u32 = u32::try_from(size).map_err(|_| DbgEngError::BufferTooLarge(size))?;
        let mut read = 0u32;
        unsafe {
            self.dataspaces.ReadVirtual(
                address,
                into.as_mut_ptr().cast(),
                size_u32,
                Some(&mut read),
            )
        }
        .map_err(|source| DbgEngError::Context {
            operation: format!("reading {size} bytes of virtual memory at {address:#x}"),
            source,
        })?;
        Ok(read as usize)
    }

    /// Reads `size` bytes of target virtual memory, all of it or none.
    ///
    /// **Unbounded**, and deliberately so: this is the read every walker in this crate is built on
    /// — one per free-tree node, per list entry, per object directory entry — where the caller's
    /// deadline is polled *between* reads and a bound inside each one would be a lock and a clock
    /// read on the hottest path there is. A caller that needs the bound inside the read wants
    /// [`Self::read_memory_bounded`], which is the same read in pieces.
    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>, DbgEngError> {
        u32::try_from(size).map_err(|_| DbgEngError::BufferTooLarge(size))?;
        // Fallibly, for the reason [`Self::read_memory_bounded`]'s growth is: `size` is a caller's
        // number and a `vec![0; size]` it cannot hold takes the process down rather than failing
        // the call. Half a class fix is the one that gets found later.
        let mut buffer = try_buffer(size, address, size)?;
        let read = self.read_virtual_into(address, &mut buffer)?;
        if read != size {
            return Err(DbgEngError::ShortRead {
                address,
                requested: size,
                actual: read,
            });
        }

        Ok(buffer)
    }

    /// Like [`Self::read_memory`], but **bounded**: the range is read a page at a time and the
    /// deadline is checked before each one, so a read that outlasts `budget_ms` comes back with
    /// what it had rather than with the session held until the target gets round to it.
    ///
    /// Returns [`MemoryRead`]: the bytes, **and** whether that is all of them. `budget_ms == 0`
    /// asks for no deadline (the parallel of [`Self::execute_command_bounded`]), which still buys
    /// the other half of this — a host's [`InterruptHandle::interrupt`] is read between chunks
    /// too, so a megabyte over a slow link is no longer a call nobody can stop.
    ///
    /// # Why this is not the watchdog the two other bounded operations use
    ///
    /// [`Self::execute_command_bounded`] and every [`Bound::Watchdog`] wait get their bound from a
    /// thread that `SetInterrupt`s the engine at the deadline. That works because `Execute` and
    /// `WaitForEvent` poll for the break — it is what WinDbg's Ctrl+Break drives. `ReadVirtual` is
    /// neither, and Microsoft documents no interrupt polling in it; whether a break reaches one in
    /// progress is not something this crate knows, and the target it would have to be measured on
    /// is a live kernel behind a link slow enough for a read to sit in — see [`Bound::Watchdog`]'s
    /// own limitation for the other place `SetInterrupt` turned out not to reach.
    ///
    /// So the bound here is one this crate can keep without that answer. Splitting the range is the
    /// same move `pool::snapshot`'s `read_extent` makes for the same reason, and the extra calls
    /// and the assembling cost little enough to be free at the scale this is for: 1 MiB of `ntdll`
    /// out of a local user-mode target — the fastest reads there are, so the worst ratio — took
    /// 486–581µs as one `ReadVirtual` and 735–768µs as 256 of them, three **release** runs of
    /// `test_a_bounded_read_costs_little_against_an_unbounded_one` on dbgeng 10.0.26100.1. A
    /// quarter of a millisecond, against the link where that same megabyte is the tens of seconds
    /// dbgscope#95 is about.
    ///
    /// **What the bound does not reach is one chunk.** A read of at most [`READ_CHUNK_BYTES`]
    /// within a page is a single `ReadVirtual` with nothing between its start and its return, so a
    /// caller asking for sixteen bytes has a bound in name only — which is the honest shape of it,
    /// and harmless where such a read is one round trip anyway. What the budget rules out is the
    /// *megabyte*: 1 MiB is 256 checks, so the overshoot is a page's worth of link time rather
    /// than a megabyte's.
    pub fn read_memory_bounded(
        &self,
        address: u64,
        size: usize,
        budget_ms: u32,
    ) -> Result<MemoryRead, DbgEngError> {
        u32::try_from(size).map_err(|_| DbgEngError::BufferTooLarge(size))?;
        // A request that arrives from here on names this read and only this one, exactly as it
        // does for a bounded command: a break aimed at whatever ran before is invisible to it, so
        // nothing can cut this read short on somebody else's account.
        let operation = self.begin_operation();
        let deadline = (budget_ms > 0)
            .then(|| Instant::now().checked_add(Duration::from_millis(u64::from(budget_ms))))
            .flatten();
        let read = read_chunked(
            address,
            size,
            || {
                // The deadline is asked first, so the one caller who is both out of time and being
                // asked to stop is told the thing it can act on. A request left unread here is not
                // lost: it stays filed against this operation, and `Operation::drop` discards it
                // and drains the engine's pending break.
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Some(Interruption::Deadline {
                        after_ms: budget_ms,
                    });
                }
                operation
                    .took_break_request()
                    .then_some(Interruption::OnRequest)
            },
            |at, into| self.read_virtual_into(at, into),
        );
        // A request this read *took* is this read's to account for, so the `SetInterrupt` behind it
        // is drained here rather than left pending to break into whatever runs next — the same
        // policy, at the same point in it, as the bounded command path's.
        if matches!(&read, Ok(read) if read.cut_short == Some(Interruption::OnRequest)) {
            let _ = self.interrupted();
        }
        read
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

    /// The TEB of DbgEng's current thread.
    ///
    /// **The native one, whatever machine the engine is rendering for.** Measured on a WoW64
    /// process on ARM64 26100.1 (2026-09-23): at its 32-bit initial break, with the effective
    /// machine x86, this names the 64-bit TEB — its `WowTebOffset` reads `+0x2000` through
    /// `heap::list`'s WoW64 check, as `@$teb`'s does, where the 32-bit TEB's own reads negative.
    pub fn current_thread_teb(&self) -> Result<u64, DbgEngError> {
        let objects: IDebugSystemObjects =
            self.client.cast().map_err(|source| DbgEngError::Context {
                operation: "obtaining the system-objects interface".into(),
                source,
            })?;
        unsafe { objects.GetCurrentThreadTeb() }.map_err(|source| DbgEngError::Context {
            operation: "reading the current thread TEB".into(),
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

    /// The operating-system thread id of DbgEng's current thread — *which* thread the answers
    /// above and below are about.
    ///
    /// Reported beside a stop rather than left to be parsed out of `~.`, for the reason every
    /// typed reader here exists: the text is one shape for a user-mode thread, another for a
    /// kernel processor, and a third when the engine has no thread context at all.
    ///
    /// **It is the engine's current thread, which a context switch does not move**, and that
    /// is the qualifier the sentence above needs on a kernel target: `.thread` and `.trap` change
    /// which context the debugger reads registers and an instruction pointer from, without
    /// changing which thread the engine is *on*. So a position read under a switched context is
    /// not this thread's, and a caller that switched is the one that knows — the same division
    /// [`Self::current_processor`] draws, for the same reason. Resolving the implicit context
    /// here instead would answer a different question and answer it worse: it is a symbol-shaped
    /// read of `ETHREAD` rather than an engine query, so it can fail on a target where the plain
    /// answer is right, and it would be wrong for every caller reporting a stop — which is where
    /// this is read, and where no switch has happened.
    ///
    /// **This is the id the operating system knows the thread by, not the engine's index for
    /// it** — `IDebugSystemObjects` has both, and they are different numbers. The engine numbers
    /// its threads from zero per process; the system id is what `kernel32!GetCurrentThreadId`
    /// answers inside that thread and what a process listing shows. On a **kernel** target the
    /// engine's threads are the target's processors, so the answer worth reading there is
    /// [`Self::current_processor`] rather than this one.
    ///
    /// No no-debuggee guard, for the same reason [`Self::current_process_system_id`] has none:
    /// this is a query, not a road into execution, so an engine holding nothing fails the call
    /// (`E_UNEXPECTED`) rather than faulting the process — see [`Self::refuse_without_a_debuggee`]
    /// for which calls are the dangerous ones.
    pub fn current_thread_system_id(&self) -> Result<u32, DbgEngError> {
        let objects = self.system_objects()?;
        unsafe { objects.GetCurrentThreadSystemId() }.map_err(|source| DbgEngError::Context {
            operation: "reading the current thread id".into(),
            source,
        })
    }

    /// Which of the target's processors the debugger is currently on, or `None` where no
    /// processor number applies.
    ///
    /// `None` is one meaning, not two: *nothing here has a processor number*. A user-mode target,
    /// a dump of one, and a TTD trace have none by construction, and that is the whole of the
    /// common case; a kernel target answers `None` only if the engine will not map its current
    /// thread to any of the processors it says it has, which is not a state this crate has seen.
    /// A caller wanting to know which of the two it is asks [`Self::is_kernel_target`].
    ///
    /// **It is not an answer about the register context**, and the difference matters on a kernel
    /// target: `.thread` and `.trap` change which context the debugger *displays* without changing
    /// which processor it is stopped on, so this still names that processor. That is the honest
    /// answer — the CPU is where the break is — but a caller reporting a position read under a
    /// switched context should say so from the switch, not expect this to.
    ///
    /// **Resolved through `GetThreadIdByProcessor` rather than by reading the current thread
    /// index as a processor number.** In kernel mode the engine's threads *are* the processors,
    /// so the index and the number coincide and reading one as the other looks right — but that
    /// is an inference about a mapping DbgEng owns, and it is the mapping this call is asking
    /// about. Asking the engine to name each processor's thread and matching the current one is
    /// the same answer with nothing inferred. It costs one call per processor, all of them
    /// engine-side lookups into a table the connection already populated, against a
    /// [`Self::execute_and_wait`] that has just pumped the target.
    ///
    /// **A lookup that fails is not a processor that does not match**, and the difference is this
    /// crate's founding rule (see [`docs/unknown-not-absent.md`]): `Ok(None)` says *nothing here
    /// has a processor number*, and answering it after a read that failed — a KD link that dropped
    /// mid-walk — reports absence where the truth is unknown. So the three cases are kept apart. A
    /// lookup that **matches** wins whatever else failed, because the answer is about the
    /// processor the debugger is on and a gap elsewhere in the table cannot change it. No match
    /// with every lookup answered is a real `Ok(None)`. No match with at least one failure is
    /// `Err`, carrying the first failure's own error.
    ///
    /// [`docs/unknown-not-absent.md`]: https://github.com/glslang/dbgscope/blob/main/docs/unknown-not-absent.md
    pub fn current_processor(&self) -> Result<Option<u32>, DbgEngError> {
        if !self.is_kernel_target()? {
            return Ok(None);
        }
        let objects = self.system_objects()?;
        let current =
            unsafe { objects.GetCurrentThreadId() }.map_err(|source| DbgEngError::Context {
                operation: "reading the current thread index".into(),
                source,
            })?;
        let processors = unsafe { self.control.GetNumberProcessors() }.map_err(|source| {
            DbgEngError::Context {
                operation: "counting the target's processors".into(),
                source,
            }
        })?;
        // The likely answer first, **asked rather than assumed**: in kernel mode the engine's
        // thread indices and its processor numbers coincide, so the current index is nearly always
        // the processor — but it is `GetThreadIdByProcessor` that says so, here as in the walk
        // behind it. Trying it first is an ordering of candidates, not an inference: a wrong guess
        // falls through and the answer is identical either way.
        //
        // It is ordered because the walk's cost is not knowable from this side. A server-class
        // kernel target has scores of processors, this runs after every stop, and whether that
        // call is an engine-side table lookup or a question for the target over a KD wire is
        // DbgEng's business. One call in the ordinary case makes that not matter.
        //
        // The candidate is then **excluded** from the scan behind it rather than merely being
        // asked twice, and that is a correctness point rather than a saved call: a repeat of a
        // lookup that has already answered can only fail, and a failure is `Err` below — so
        // leaving it in would let a link dropping late in the walk overturn a `None` every
        // distinct processor had already agreed on.
        let order = std::iter::once(current)
            .filter(|&candidate| candidate < processors)
            .chain((0..processors).filter(move |&candidate| candidate != current));
        // The first failure, kept rather than counted: what a caller can act on is *why* the
        // mapping could not be read, and one reason is as good as five of the same.
        let mut unreadable = None;
        for processor in order {
            match unsafe { objects.GetThreadIdByProcessor(processor) } {
                Ok(thread) if thread == current => return Ok(Some(processor)),
                Ok(_) => {}
                Err(why) => {
                    unreadable.get_or_insert(why);
                }
            }
        }
        match unreadable {
            // Nothing matched and every lookup answered, so there really is no processor here.
            None => Ok(None),
            Some(source) => Err(DbgEngError::Context {
                operation: "reading which processor the debugger is on".into(),
                source,
            }),
        }
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

    /// What the **memory manager** says about the run of pages `address` lies in, rather than
    /// what the debugger can read there.
    ///
    /// The two are different questions and [`Self::valid_virtual_region`] only answers the
    /// second. A page that will not read is reserved, or decommitted, or committed and paged
    /// out, and a walk that cannot tell those apart has to treat all three as a hole in its own
    /// coverage. This tells them apart: `MEM_RESERVE` is address space nothing was ever put in,
    /// so nothing was missed there, while `MEM_COMMIT` that will not read is memory the target
    /// does have and the debugger could not see.
    ///
    /// **User-mode targets only.** `QueryVirtual` is `NtQueryVirtualMemory` as the engine reaches
    /// it, so a kernel session has no answer to give and this is an error there rather than a
    /// state — callers must keep whatever conservative reading they had. On a crash dump it is
    /// the `MemoryInfoListStream`, which a full dump carries and a minidump need not, so the
    /// same error stands in for "this dump does not say".
    pub fn virtual_region(&self, address: u64) -> Result<VirtualRegion, DbgEngError> {
        let mut info = AlignedMemoryInfo::default();
        unsafe { self.dataspaces.QueryVirtual(address, &mut info.0) }.map_err(|source| {
            DbgEngError::Context {
                operation: format!("querying the memory manager about {address:#x}"),
                source,
            }
        })?;
        Ok(VirtualRegion {
            base: info.0.BaseAddress,
            size: info.0.RegionSize,
            state: VirtualState::from_mem_state(info.0.State.0),
            protect: info.0.Protect.0,
        })
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

    /// The processor type the engine is currently **rendering** in, which is not always the one
    /// the machine has.
    ///
    /// `.effmach` sets it, and it diverges from [`Self::processor_type`] wherever one machine runs
    /// another's code: a WOW64 process on x64, x64 emulated on ARM64. Anything reading the
    /// engine's *output* — a disassembly listing, a register file — is discriminated by this one,
    /// while anything reading the target's *structures* wants the physical type, because a
    /// pointer's width is a fact about the machine rather than about a rendering.
    pub fn effective_processor_type(&self) -> Result<u32, DbgEngError> {
        unsafe { self.control.GetEffectiveProcessorType() }.map_err(|source| DbgEngError::Context {
            operation: "querying effective processor type".into(),
            source,
        })
    }

    /// What DbgEng says it is debugging right now — see [`DebuggeeType`].
    ///
    /// **Read from the engine on every call, which is the point of exposing it.** It is not a
    /// property recorded by whichever opener ran: a raw `.opendump` typed at the engine replaces
    /// the target without this crate seeing anything, and this is one of the few things that
    /// answers differently afterwards. That makes it usable as half of a *fingerprint* a caller
    /// compares across commands, which is a different question from
    /// [`Self::target_identity`] — that one is a generation this crate hands out and bumps at its
    /// own openers and teardowns, so it does **not** move when DbgEng is driven behind its back.
    pub fn debuggee_type(&self) -> Result<DebuggeeType, DbgEngError> {
        let mut class = 0;
        let mut qualifier = 0;
        unsafe { self.control.GetDebuggeeType(&mut class, &mut qualifier) }.map_err(|source| {
            DbgEngError::Context {
                operation: "querying target type".into(),
                source,
            }
        })?;
        Ok(DebuggeeType { class, qualifier })
    }

    /// The connection string a **live kernel** session is dialled on, as DbgEng holds it —
    /// `net:port=…,key=…`, `com:port=COM1,baud=115200`, and the rest.
    ///
    /// **It is the only thing that tells two live kernel targets apart.** Everything else a caller
    /// can read about one is identical between any two of them: the class and qualifier are
    /// `DEBUG_CLASS_KERNEL` / `DEBUG_KERNEL_CONNECTION` for both, there are no dump files, and
    /// there is no process set. So a caller fingerprinting its target is blind to a live kernel
    /// being swapped for another unless it reads this.
    ///
    /// # It can carry a secret
    ///
    /// **A KDNET connection string contains the debug `key=`**, which is the credential for the
    /// target machine. This returns it unredacted, because a library that mangled it would be
    /// useless for dialling — but it means a caller must not log this, put it in an error
    /// message, or derive a `Debug` that prints it. A caller that only needs *identity* should
    /// hash it and keep the hash.
    ///
    /// Empty, or an error, on a target that is not a live kernel; refuses an engine with no
    /// debuggee for [`Self::dump_files`]'s reason.
    pub fn kernel_connection_options(&self) -> Result<String, DbgEngError> {
        self.refuse_without_a_debuggee()?;
        read_engine_string(|buffer, size| unsafe {
            self.client.GetKernelConnectionOptions(buffer, size)
        })
        .map_err(|source| DbgEngError::Context {
            operation: "reading the kernel connection options".into(),
            source,
        })
    }

    /// Whether the current target is a kernel one, live connection or kernel dump alike.
    pub fn is_kernel_target(&self) -> Result<bool, DbgEngError> {
        Ok(self.debuggee_type()?.is_kernel())
    }

    /// The dump or trace files this session is open on, in the engine's own order.
    ///
    /// Empty on a live target, where there is no file behind the debuggee — and **an engine that
    /// will not answer at all is an error rather than an empty list**, so "none" always means
    /// none. A caller comparing two readings to notice a target being swapped underneath it
    /// cannot afford the two collapsed: a failure read as "no dump files" matches every live
    /// target and would say the target had not changed.
    ///
    /// A name the engine returns as empty keeps its slot, because the *count* is as much of the
    /// answer as the names are.
    ///
    /// **It refuses an engine with no debuggee rather than asking**, and that guard is not
    /// tidiness: `GetNumberDumpFiles` on one is a `STATUS_ACCESS_VIOLATION` *inside* DbgEng — a
    /// structured exception, which `catch_unwind` cannot trap, so it takes the calling process
    /// down instead of failing the call. Measured on dbgeng 10.0.26100.1 (ARM64, 2026-09-25),
    /// twice: on a **fresh** engine that never had a target, and on one whose launched debuggee
    /// had just run to completion, each an exit code of `0xC0000005` on the line after
    /// [`Self::debuggee_type`] answered `DEBUG_CLASS_UNINITIALIZED` perfectly happily. So the two
    /// queries beside each other do *not* behave alike, which is exactly the shape that gets a
    /// caller to ask both in one place and lose the process.
    ///
    /// Same guard and same reason as [`Self::refuse_without_a_debuggee`], reached here for a
    /// *query* rather than for caller-supplied text.
    pub fn dump_files(&self) -> Result<Vec<String>, DbgEngError> {
        self.refuse_without_a_debuggee()?;
        let named = |operation: &str, source: windows::core::Error| DbgEngError::Context {
            operation: operation.into(),
            source,
        };
        let count = unsafe { self.client.GetNumberDumpFiles() }
            .map_err(|source| named("counting the session's dump files", source))?;
        let mut files = Vec::with_capacity(count as usize);
        for index in 0..count {
            // The usual two calls: the first sizes the name, the second fills it. `kind` is the
            // dump *file* type, which nothing here reads — the API takes a plain pointer for it
            // rather than an optional one, so there is no way to decline it.
            let mut kind = 0u32;
            let mut needed = 0u32;
            unsafe {
                self.client
                    .GetDumpFileWide(index, None, Some(&mut needed), None, &mut kind)
            }
            .map_err(|source| named("sizing a dump file's name", source))?;
            // Counted in characters and including the terminator, so one is an empty name.
            if needed <= 1 {
                files.push(String::new());
                continue;
            }
            let mut buffer = vec![0u16; needed as usize];
            unsafe {
                self.client
                    .GetDumpFileWide(index, Some(&mut buffer), None, None, &mut kind)
            }
            .map_err(|source| named("reading a dump file's name", source))?;
            files.push(wide_to_string(&buffer));
        }
        Ok(files)
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
    /// An engine that will not say answers `false`, as it always has: this decides whether to
    /// take the live-kernel teardown, and taking it on a guess is the worse of the two mistakes.
    fn is_live_kernel(&self) -> bool {
        self.debuggee_type().is_ok_and(DebuggeeType::is_live_kernel)
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
        self.forget_the_previous_session();
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
        self.forget_the_previous_session();
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
    /// link, so the wait blocks instead — see [`Bound::Watchdog`]. Note that a guest not booted
    /// with `bcdedit /debug on` is the *second* case, not the first: it never dials, so it hangs
    /// rather than timing out.
    ///
    /// **A host's break is not treated as a timeout here, where a deadline is** — a gap the
    /// outcome makes *visible* rather than one it introduces. Before [`WaitOutcome`] this path
    /// could not see the host origin at all, so a break somebody asked for reached
    /// `absorb_initial_break_artifact` and was reported as a clean break-in; it still is. Naming
    /// it wants an error of its own, [`DbgEngError::LiveTargetInterrupted`]'s opposite number,
    /// which is a decision about the API rather than about this wait — dbgscope#136 stage 2.
    fn wait_for_kernel_break_in(&self) -> Result<(), DbgEngError> {
        // Held across `absorb_initial_break_artifact` below, which runs an `execute_and_wait` and
        // so opens an operation *inside* this one. That is the nesting `BreakScope` keeps a stack
        // for: before it, the inner operation's open cleared this one's request as a matter of
        // course.
        let operation = self.begin_operation();
        let pumped = self.pump(Bound::Watchdog(KERNEL_ATTACH_WAIT_MS), &operation);
        self.clear_initial_break();
        let outcome = pumped?;
        // If the watchdog forced the wait to return, the target never reached its
        // INITIAL_BREAK on its own within the bound — the stop (if any) is a forced
        // Ctrl+Break, not the clean break-in. Report a timeout and skip the absorb (there
        // is no INITIAL_BREAK artifact to consume). Also treat a wait that returned with
        // no debuggee as a timeout, defensively.
        let status =
            unsafe { self.control.GetExecutionStatus() }.map_err(DbgEngError::CommandFailed)?;
        if outcome == WaitOutcome::Deadline || status == DEBUG_STATUS_NO_DEBUGGEE {
            return Err(DbgEngError::KernelBreakTimeout);
        }
        self.absorb_initial_break_artifact();
        Ok(())
    }

    /// The user-mode tail of [`PendingTarget::wait`]: pump until `arrival` is in the session.
    ///
    /// [`Arrival`] has the measurement and why one wait is not enough. Four things about the shape
    /// here, each of which is a way to get it wrong:
    ///
    /// - **[`Presence::Unknown`] is "could not ask", and it is not what a fresh open starts in.**
    ///   An engine whose target has not materialised answers `has_target` `Ok(false)`, which is
    ///   knowledge and so [`Presence::Absent`]; what reaches `Unknown` is a probe that failed and
    ///   an [`Arrival::Launched`] with no snapshot to diff against. `waited` is what stops the
    ///   latter ending a launch before it happened: in a *mixed* session the target already there
    ///   answers `has_target` on its behalf, so returning on the first ask would leave the
    ///   deferred spawn unrealised. One wait is all this can do about it, and then it stops.
    /// - **A wait cannot expire on an engine with no debuggee**, which is what keeps those two
    ///   endings from meeting. Measured: `WaitForEvent` there fails `E_UNEXPECTED` in 1.5ms on a
    ///   fresh engine and 4µs on one whose session has ended, while a wait with a debuggee and
    ///   nothing to report returns `Ok` at its timeout (312ms for a 300ms bound). So "the wait
    ///   returned `Ok` and the engine holds nothing" is not a state an open passes through, and
    ///   the `Ok(false)` arm of [`Self::presence_of`] is a mapping made honest rather than a road
    ///   taken — raised as a false success on review round 6 of #133, and measured instead.
    /// - **Asking first is safe, and it is measured rather than assumed.** Neither opener puts its
    ///   process in the session's list before the wait that completes it (measured: a session at 1
    ///   process, `attach_process_begin`, still 1, the pid absent — 2 after the wait), so the
    ///   ordinary open still waits exactly once. What the ask buys is a guard waited *after*
    ///   something else pumped its target in, which [`PendingTarget`] documents as a thing to do
    ///   and which would otherwise wait out the whole bound for an event that had already come.
    /// - **[`LIVE_WAIT_MS`] bounds the open, not each wait**, so pumping cannot multiply what a
    ///   caller waits for by however many events happen to arrive.
    /// - **An error from the wait ends it.** A launch whose image does not exist fails *inside*
    ///   the wait (measured: `Err(0x80070002)` after 13ms, no debuggee behind it, and a further
    ///   wait answering `E_UNEXPECTED` in 37µs), so propagating is what keeps this from turning a
    ///   fast, accurate failure into a half-minute of pumping a session that has nothing in it.
    fn wait_for_live_target(&self, registered: &Registered<'_>) -> Result<(), DbgEngError> {
        // One operation for the whole loop, not one per pump: `LIVE_WAIT_MS` bounds the open and
        // not each wait, so a break a host asks for anywhere inside it belongs to the open.
        //
        // This is the path #135 half A cost the most. The clear that used to stand here could wipe
        // a request that had been lodged and not yet delivered, and the synthetic Ctrl+Break that
        // then arrived was recorded as a target's initial break -- so a guard's
        // `wait()` answered `Ok` for a process that never reached one, and the false entry lasted
        // the session. There is no clear now, and a request names this operation.
        let operation = self.begin_operation();
        let deadline = Instant::now() + Duration::from_millis(u64::from(LIVE_WAIT_MS));
        let mut waited = false;
        // Carried from the pump that saw it rather than re-read each time round. Before a first
        // pump there is nothing to have seen: a request raised between this operation opening and
        // the wait below is what ends that wait, and the pump reports it -- from the call that
        // observed it.
        let mut asked_to_stop = false;
        loop {
            let presence = self.presence_of(registered);
            match presence {
                Presence::Arrived => return Ok(()),
                Presence::Unknown if waited => return Ok(()),
                Presence::Listed | Presence::Absent | Presence::Unknown => {}
            }
            let left = u32::try_from(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .unwrap_or(LIVE_WAIT_MS);
            // A host that asked for control back gets it. Before this function pumped, a single
            // wait ended on the break and `wait()` returned, so carrying on round the loop would
            // hold the caller for the rest of the bound -- a regression in the one direction an
            // interrupt exists to prevent, and introduced by the pumping this whole change is.
            // It also lets the target *go*: backing this check out and running
            // `test_a_host_interrupt_ends_a_live_open_rather_than_pumping_through_it` spends the
            // whole bound and comes back `CommandFailed(0x8000FFFF)` at 29.5s, because the
            // debuggee ran to completion under the pumping and left no session behind it. So the
            // cost is not only the caller's time; it is the target the host stopped.
            //
            // Terminal on the same rule as the bound, which is deliberate -- an interrupt is a
            // reason to stop pumping, not a different question about the target -- except that a
            // target which is not there is reported as interrupted rather than as a timeout the
            // open never reached.
            if left == 0 || asked_to_stop {
                return match presence {
                    Presence::Absent if asked_to_stop => Err(DbgEngError::LiveTargetInterrupted),
                    Presence::Absent => {
                        // This open pumped for its whole bound and its process never joined, so
                        // the attach cannot complete: retire the record before it can be matched
                        // by a later process that inherits the pid. Not on the interrupted branch
                        // above -- an open the host cut short says nothing about whether the
                        // attach is still coming.
                        //
                        // The registration goes the same way and for the same reason, or a
                        // *launch* that timed out here would be kept as abandoned when its guard
                        // drops (dbgscope#141) and would then take the next launch's stop -- the
                        // very failure keeping it exists to prevent, arrived at from the other
                        // side. `discard` and not `forget`: this open pumped its whole bound and
                        // nothing came, which is the one ending that says nothing is coming.
                        // Raised in review on dbgscope#143.
                        if waited {
                            self.retire_deferred_attachment(registered);
                            self.discard_registration(registered);
                        }
                        Err(DbgEngError::LiveTargetTimeout)
                    }
                    // In the session, and never seen to stop. "Not observed to stop" is not "never
                    // arrived", and reporting a timeout on a process visibly in front of us would
                    // be claiming absence where the truth is unknown — see
                    // docs/unknown-not-absent.md.
                    _ => Ok(()),
                };
            }
            // `broke_in` and not "a host asked", because the rule is about the *stop* rather than
            // its origin: whatever the engine stopped on is not this target's initial break, and
            // pumping on spends the rest of the bound on an event nobody wants. Only a host can
            // raise one here today -- a finite bound arms no watchdog, and the engine thread is
            // inside this loop -- but the loop should not be the thing that has to know that.
            asked_to_stop = match self.pump(Bound::Finite(left), &operation) {
                Ok(outcome) => outcome.broke_in(),
                Err(err) => {
                    // A pump that fails is an ending too, and the deferred record has to be let go
                    // of on it for the same reason as at the bound -- otherwise an `AttachProcess`
                    // the engine accepted for a process that exited before the first wait leaves
                    // its pid recorded for the life of the session, since only a listing promotes
                    // one. Raised in review on dbgscope#139 against a fix that covered the bound
                    // alone.
                    //
                    // **Narrower than the bound's, deliberately.** A session holding *nothing* is
                    // proof this attach produced no target; a wait that failed with a live session
                    // says nothing about whether it is still coming, and retiring there would let
                    // the teardown take somebody else's process -- which is the direction that
                    // costs.
                    if self.holds_nothing_at_all() {
                        self.retire_deferred_attachment(registered);
                    }
                    return Err(err);
                }
            };
            waited = true;
        }
    }

    /// Whether the target a live open is waiting for has joined the session **and stopped**.
    ///
    /// Membership alone is the weaker claim, and the difference is a real window rather than a
    /// pedantic one: `cpr` is an ignored filter, so the engine registers a process when it
    /// processes that process's create event and carries on — the initial breakpoint arrives later,
    /// after the loader has done its early work. A competing target breaking in between the two
    /// leaves this open's process listed and not yet where the open promised to leave it. So the
    /// target has to have **stopped**, which is what `sxe ibp` armed and what the doc comments on
    /// both openers say they wait for.
    ///
    /// **It is asked of the open's own register entry and not of the last event**, which is the
    /// whole of what three rounds of review on this predicate settled. `GetLastEventInformation` is
    /// a single session-wide slot that every later event overwrites, so read directly it answers
    /// "not this target" for a target still on its way *and* for one that stopped before this guard
    /// was waited on -- and every rule that tried to tell those apart from the reading alone moved
    /// the defect somewhere else. Since stage 3 the pump **delivers** a stop to the open that wants
    /// it ([`Arrivals::deliver`]), so the question here is a plain one: has anything been delivered
    /// to this open.
    ///
    /// **The three answers are three states, not a boolean with excuses**, and the middle one is
    /// what keeps the strictness from becoming a lie of its own. [`Presence::Listed`] is a target
    /// in the session that has not stopped yet: worth pumping for, and not a missing process to
    /// report at the bound.
    ///
    /// Every failure to *ask* answers [`Presence::Unknown`] rather than [`Presence::Absent`],
    /// which is the difference between a wait that ends where it always did and one that pumps an
    /// engine holding nothing until it faults.
    fn presence_of(&self, registered: &Registered<'_>) -> Presence {
        match self.has_target() {
            Ok(true) => {}
            // Asked, and answered: an engine holding no debuggee at all holds nothing this open
            // was waiting for. That is knowledge, so it is `Absent` -- the reverse of the mistake
            // docs/unknown-not-absent.md is about, and the same reading `attach_kernel`'s tail
            // already treats as a timeout rather than as a question it could not put.
            Ok(false) => return Presence::Absent,
            Err(_) => return Presence::Unknown,
        }
        let Ok(held) = self.session_processes() else {
            return Presence::Unknown;
        };
        let attached = self.attached_pids();
        self.state
            .arrivals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .presence(registered.id, &held, &attached)
    }

    /// Whether this session holds no target at all, which is the one ending that *proves* an
    /// `AttachProcess` this engine accepted produced nothing.
    ///
    /// Narrower than [`Presence::Absent`] on purpose, and the difference is the evidence rather
    /// than taste. At the bound an open has pumped for `LIVE_WAIT_MS`, so a pid still not listed is
    /// one that is not coming; on a *failed* pump the open may have pumped nothing at all, and the
    /// same reading would retire an attach the engine had not yet had a chance to process --
    /// after which the teardown takes somebody else's process, which is the direction that costs.
    ///
    /// **The negative half is untested here and says so.** Constructing a pump that fails with a
    /// live session is not something this bench can arrange: `WaitForEvent` failing is
    /// `E_UNEXPECTED` for a session holding nothing, and a live target does not oblige. So the
    /// predicate is pinned both ways on its own, and the branch that reads it is pinned only for
    /// the ending that can be built.
    fn holds_nothing_at_all(&self) -> bool {
        matches!(self.has_target(), Ok(false))
    }

    /// Retires the record of an attachment a live open waited its whole bound for and never saw.
    ///
    /// **`Attachment::Deferred` is kept until something says the attach cannot join**, and without
    /// this there is nothing that ever says so: only a successful listing promotes a record, so an
    /// `AttachProcess` the engine accepted for a process that then exited before the first
    /// `WaitForEvent` left a pid recorded for the life of the session. If Windows handed that
    /// number to a process this engine went on to launch, the launch's own stop was excluded from
    /// delivery as somebody else's and its teardown *detached* from it instead of taking it --
    /// a launched process outliving its session. Raised in review on dbgscope#139, and a widening
    /// of an existing residue rather than a new one: before an attachment could be deferred, the
    /// next opener's prune dropped any pid the session did not hold.
    ///
    /// **Only `Deferred`**, so an attachment that joined and has merely left is left to the prune,
    /// which is the function that knows about departures.
    ///
    /// The residue that is left is an attach that never joins whose guard was **abandoned without
    /// waiting** — nothing then waits the bound, so nothing reaches here. That is the documented
    /// hand-off (`PendingTarget` says a dropped guard's target materialises at the next wait from
    /// any source), and the pid is held against a pid reuse that the crate already lives with; see
    /// [`Self::prune_processes_that_left`], which names a retained handle as the real answer.
    fn retire_deferred_attachment(&self, registered: &Registered<'_>) {
        let pid = self
            .state
            .arrivals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .attached_pid(registered.id);
        let Some(pid) = pid else {
            return;
        };
        let mut attached = self
            .state
            .attached_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if attached.get(&pid) == Some(&Attachment::Deferred) {
            attached.remove(&pid);
        }
    }

    /// Forgets an open outright, for a wait that ended saying its process is not coming.
    ///
    /// The guard's own drop calls [`Arrivals::forget`] shortly afterwards and finds nothing, which
    /// is the point: `forget` would keep an abandoned launch's place in the queue, and an open that
    /// pumped its whole bound for nothing must not hold one. See [`Arrivals::discard`].
    ///
    /// **This call site is not pinned by a test, and says so rather than being assumed covered.**
    /// The rule it reaches is (`..._keeps_its_place_and_an_attach_does_not`'s last block, which
    /// fails if `discard` keeps the entry), but the *wiring* needs a launch whose process never
    /// arrives inside `LIVE_WAIT_MS`, and a create that reaches the queue produces a process —
    /// every way a launch fails with nothing created lands on `launch_process_begin`'s own `?`
    /// (measured: a missing image is `0x80070002` in 1.5 ms, before any guard exists). Backing this
    /// line out leaves the whole suite green; that was checked rather than supposed. The attach
    /// side has `test_the_openers_prune_clears_a_claim_on_a_departed_process` for the equivalent
    /// wiring because a *pid* that never joins is constructible where a launch is not.
    fn discard_registration(&self, registered: &Registered<'_>) {
        self.state
            .arrivals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .discard(registered.id);
    }

    /// A copy of the pids this engine attached to, taken rather than borrowed so that no lock is
    /// held across the arrival register's.
    fn attached_pids(&self) -> HashSet<u32> {
        self.state
            .attached_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// The **engine** process id the engine's last event belongs to.
    ///
    /// `GetLastEventInformation`, asked for that field alone: the description is text this crate
    /// has no use for, and passing a buffer for it would be a second allocation on a call made
    /// once per pump. It is the engine id rather than the system pid — measured against
    /// [`Self::session_processes`], which answers both — so callers join it to that pairing rather
    /// than to a pid.
    ///
    /// **An engine that has seen no event does not fail this — it answers `DEBUG_ANY_ID`.**
    /// Measured on both an engine holding nothing and a dump `open_dump` has named but nothing has
    /// pumped (`examples/stored_event_probe.rs`, `empty` and `unwaited`): `S_OK`, kind `0`, and
    /// `0xffffffff` for both ids. This used to say the call fails there, which is where
    /// [`Self::last_event`] inherited the same wrong claim from (dbgscope#144). It costs the one
    /// caller nothing — `record_where_it_stopped` looks the id up in the session listing, and
    /// `DEBUG_ANY_ID` is in no listing — but a caller that read it as an engine id would be
    /// joining on a sentinel.
    ///
    /// **The event *kind* is read and dropped, and that is not an oversight.** Review round 14
    /// asked for the stop reason to be preserved and validated, so that an open completes on its
    /// target's loader breakpoint rather than on whatever stopped it first. The engine does not
    /// offer that distinction: measured on both openers, an initial break reports kind `0x2`,
    /// `DEBUG_EVENT_EXCEPTION` -- not `DEBUG_EVENT_BREAKPOINT`, which is `0x1` -- because it
    /// arrives as a `STATUS_BREAKPOINT` exception. So filtering on the breakpoint kind records
    /// nothing at all and times out every live open on a target sitting in front of it, and
    /// filtering on the exception kind admits exactly the early exceptions the finding is about.
    /// The exception *code* is no better: an `sxe ld` break and any other `int3` are
    /// `STATUS_BREAKPOINT` too. Nothing on the event says "this is the one the engine's
    /// `DEBUG_ENGOPT_INITIAL_BREAK` arranged".
    ///
    /// What the pump can honestly claim is therefore "this target has stopped", which is what
    /// [`Presence`] says and what the openers' own docs are worth. It is also not a regression:
    /// a single-wait open returned at that earlier stop too.
    fn last_event_process(&self) -> Result<u32, DbgEngError> {
        let mut kind = 0u32;
        let mut process = 0u32;
        let mut thread = 0u32;
        unsafe {
            self.control.GetLastEventInformation(
                &mut kind,
                &mut process,
                &mut thread,
                None,
                0,
                None,
                None,
                None,
            )
        }
        .map_err(|source| DbgEngError::Context {
            operation: "reading which target the last event belongs to".into(),
            source,
        })?;
        Ok(process)
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
    ///
    /// Refuses with [`DbgEngError::NoDebuggee`] when the engine holds no target: arbitrary text
    /// reaching an engine in that state can fault the process, and this cannot tell which text
    /// would. See [`Self::refuse_without_a_debuggee`].
    pub fn execute_command(&self, command: &str) -> Result<String, DbgEngError> {
        self.refuse_without_a_debuggee()?;
        self.execute_fixed_command(command)
    }

    /// [`Self::execute_command`] without the no-debuggee guard, for this crate's own command
    /// literals.
    ///
    /// The guard refuses everything because it cannot tell caller text that reaches execution
    /// from text that does not. A literal written *here* is known text, and one of them has to
    /// run before a target exists: `sxe ibp` is how [`Self::launch_process_begin`] and
    /// [`Self::attach_process_begin`] arm the initial break, on an engine that is holding
    /// nothing at the time.
    ///
    /// **Nothing that can reach execution may be passed here**, and nothing a caller supplied.
    /// The fault the guard prevents is a `STATUS_ACCESS_VIOLATION` inside DbgEng, which no
    /// `catch_unwind` traps.
    fn execute_fixed_command(&self, command: &str) -> Result<String, DbgEngError> {
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
    /// Refuses with [`DbgEngError::NoDebuggee`] when the engine holds no target — the same guard
    /// [`Self::execute_and_wait`] has, and for a hazard that is not confined to execution control:
    /// see [`Self::refuse_without_a_debuggee`]. That guard is also what lets
    /// [`CommandRun::target_gone`] be reported here at all: with one refused at the door, a
    /// missing debuggee afterwards means *this* command took the target away.
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
        self.refuse_without_a_debuggee()?;
        let cmd_c = CString::new(command).map_err(|_| DbgEngError::InvalidCommand)?;
        let cmd = PCSTR::from_raw(cmd_c.as_ptr() as *const u8);

        // A request that arrives from here on names this operation and only this one; one aimed at
        // an earlier operation is invisible to it, so there is nothing to clear and nothing that
        // could make this command swallow a genuine error as though it had been aborted.
        let operation = self.begin_operation();

        let mut output_buffer = Vec::<u8>::with_capacity(4096);
        let output_callbacks = OutputCallbacks::new(&mut output_buffer);
        let output_interface: IDebugOutputCallbacks = output_callbacks.into();
        unsafe {
            self.client
                .SetOutputCallbacks(Some(&output_interface))
                .map_err(DbgEngError::CommandFailed)?;
        }

        // Arm a watchdog that Ctrl+Breaks the engine after `timeout_ms` so a long `Execute`
        // returns instead of hanging the engine thread. Mirrors [`Bound::Watchdog`], which is the
        // same arrangement around a wait rather than around an `Execute` -- `break_in_only`
        // included, so the deadline is not also filed as a request against this operation.
        let watchdog = (timeout_ms > 0).then(|| {
            let handle = self.interrupt_handle();
            Watchdog::arm(Duration::from_millis(u64::from(timeout_ms)), move || {
                let _ = handle.break_in_only();
            })
        });

        let result = unsafe {
            self.control
                .Execute(DEBUG_OUTCTL_THIS_CLIENT, cmd, DEBUG_EXECUTE_ECHO)
        };

        let by_watchdog = watchdog.is_some_and(Watchdog::disarm);

        // Always detach the callbacks before `output_interface`/`output_buffer` drop.
        unsafe {
            let _ = self.client.SetOutputCallbacks(None);
        }

        // Either origin aborts the command the same way, so both take the recovery below; only the
        // note is the watchdog's alone. Nothing here waited, so the answer comes from the
        // operation rather than from a [`WaitOutcome`] — one rule, two places to read it from.
        let cut_short = operation.cut_short_by(by_watchdog, timeout_ms);
        let interrupted = cut_short.is_some();
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
            cut_short,
            // Nothing here pumps, but a command can still take the target away by itself:
            // `.detach`, `q` and `qd` return with the engine already holding nothing, and no
            // later pump will ever mention it. The guard at the top is what makes this mean
            // "this command did it" rather than "there was never anything here".
            target_gone: self.lost_its_target(),
        })
    }

    /// Waits for the target to break, up to `timeout_ms`, and says what happened.
    ///
    /// This is [`Bound::Finite`] through [`Self::pump`], which is where the four endings are told
    /// apart. The one to know before using it is [`WaitOutcome::Expired`]: the bound passed with
    /// the target still running, which every other pump in this crate is arranged to avoid because
    /// nothing recovers from it — see [`Self::execute_and_wait`].
    ///
    /// Pumping the engine directly is a documented thing to do (see [`PendingTarget`]), which is
    /// why the outcome is public: a pump that completes somebody else's held target leaves the same
    /// record behind as that guard's own wait would have.
    pub fn wait_for_event(&self, timeout_ms: u32) -> Result<WaitOutcome, DbgEngError> {
        // An operation of its own, so a break a host asks for during this pump is attributed to it
        // and is gone afterwards. This is the path dbgscope#135 half B is written about: the public
        // pump used only to *read* the engine-wide flag, so a request that ended it stayed raised
        // and the next wait declined to record a real initial break.
        let operation = self.begin_operation();
        self.pump(Bound::Finite(timeout_ms), &operation)
    }

    /// One `WaitForEvent`, bounded as `bound` says, **attributing its own outcome** before
    /// anything downstream can look.
    ///
    /// This is the whole of dbgscope#136 stage 1. What it replaces was two waits that each
    /// answered `Result<(), _>` (plus, for the bounded one, a bare `bool`), so the four endings
    /// were reconstructed afterwards by three parties out of shared mutable state — the
    /// last-event slot, the session's process list and an engine-wide interrupt flag each read more
    /// than once, and the `HRESULT` only the waiting call ever saw thrown away. Fifteen of the
    /// twenty-two findings on the review that produced that issue were one of those reads moving.
    ///
    /// **The precedence, and why it is this way round.**
    ///
    /// - **A break outranks the wait's own error**, either origin's. `execute_and_wait` has said
    ///   so since it was written — "a break makes both of these fail" — and swallowing it is what
    ///   keeps a caller from being charged for a stop this side caused or asked for. Two paths did
    ///   not have that rule and now do: [`Self::run_to_address`] swallowed only the watchdog's, and
    ///   [`Self::wait_for_event`] propagated regardless. Narrow in practice — `SetInterrupt` ends a
    ///   wait with `S_OK`, so the pair needs the target to fail in the same window — but it is one
    ///   rule now instead of three.
    /// - **The watchdog is read first, and the two signals are now independent.** They used to be
    ///   two readings of one flag, because the watchdog reached the engine through
    ///   [`InterruptHandle::interrupt`] like any host; since stage 2 it goes through
    ///   [`InterruptHandle::break_in_only`] and records nothing, so `by_watchdog` and the
    ///   operation's request answer different questions. The order still matters, but only for the
    ///   genuine coincidence of a deadline and a host arriving in one window.
    /// - **The request is *taken*, not read**, and it names **this operation**. It belongs to this
    ///   wait; left standing it would be charged to whatever ran next, which is the defect
    ///   `test_a_timed_out_run_leaves_no_interrupt_standing` was written for and dbgscope#135
    ///   half B. Since stage 2 the taking is scoped: a request filed against another operation is
    ///   invisible here rather than merely already consumed.
    /// - **Only [`WaitOutcome::Stopped`] records**, which is what makes the two gates that cost
    ///   nine review findings unreachable rather than guarded: an expiry and a forced break are
    ///   different arms, not the same arm with `if`s in front of it.
    ///
    /// **It is the request, and not the provenance of the event that ended the wait**, which is
    /// deliberate and was declined once as a finding (round 13 of #133). A break asked for in the
    /// same window as the target's own initial break is filed against this operation, and the
    /// genuine arrival is reported as [`WaitOutcome::OnRequest`]. The two errors are not the same
    /// size: dropping a real arrival costs a pump, and recording a synthetic one costs the
    /// postcondition six rounds of review were spent establishing — the conservative direction, and
    /// the whole of docs/unknown-not-absent.md.
    ///
    /// **What stage 2 leaves, and what would close it.** Two shapes, both of them the same fact —
    /// `SetInterrupt` is engine-wide and cannot be aimed, so which operation a break *lands* on is
    /// not the crate's to decide.
    ///
    /// - A break aimed at operation N that lands on N+1, because N ended between the host reading
    ///   what was running and the break arriving. N+1 sees no request of its own and reports a
    ///   normal stop.
    /// - A request filed against N *after* N's last read of one, which is the window
    ///   [`Operation`] describes. Nobody reports it; [`Operation::drop`] at least drains the
    ///   engine's own pending break so it does not become the first shape.
    ///
    /// Bookkeeping cannot close either. `GetInterrupt` could, and
    /// `examples/interrupt_provenance.rs` is the measurement #136 asked for before anything relies
    /// on it: a request that *ended* a wait is consumed before the wait returns, and one that did
    /// not is still readable afterwards — so a post-wait poll is a **forward** signal, warning the
    /// next operation that a break is coming for it. That is stage 3's to use.
    fn pump(&self, bound: Bound, operation: &Operation<'_>) -> Result<WaitOutcome, DbgEngError> {
        let (result, arrived, by_watchdog) = match bound {
            Bound::Finite(timeout_ms) => {
                // Read through the vtable, for the reason [`Self::interrupted`] does: the generated
                // wrapper calls `HRESULT::ok()`, which maps `S_OK` and `S_FALSE` alike to `Ok(())`,
                // and here those are opposite answers — an event arrived, against `timeout_ms`
                // passing with none.
                let hr = unsafe {
                    (Interface::vtable(&self.control).WaitForEvent)(
                        Interface::as_raw(&self.control),
                        0,
                        timeout_ms,
                    )
                };
                let result = if hr.is_err() {
                    Err(windows::core::Error::from_hresult(HRESULT(hr.0)))
                } else {
                    Ok(())
                };
                // `== S_OK` and not `!= S_FALSE`: a success code this crate has not met answers
                // "no event arrived", which is the direction that records nothing.
                (result, hr == S_OK, false)
            }
            Bound::Watchdog(timeout_ms) | Bound::WatchdogExit(timeout_ms) => {
                let handle = self.interrupt_handle();
                // Ctrl+Break a connected target so the engine thread's WaitForEvent returns with a
                // stop. `break_in_only`, so the deadline is *not* also filed as a request against
                // this operation: `watchdog.disarm()` already says it fired, and one event with two
                // representations is what every classify site used to have to reconcile.
                let watchdog = Watchdog::arm(
                    Duration::from_millis(u64::from(timeout_ms)),
                    move || {
                        if matches!(bound, Bound::WatchdogExit(_)) {
                            // SetInterrupt remains the only off-thread DbgEng call.
                            let _ = unsafe {
                                handle.control.SetInterrupt(
                                    windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_INTERRUPT_EXIT,
                                )
                            };
                        } else {
                            let _ = handle.break_in_only();
                        }
                    },
                );
                let result = unsafe { self.control.WaitForEvent(0, WAIT_INFINITE) };
                // Disarmed before anything is read, so the watchdog cannot fire *into* the reads
                // below and be missed by them.
                let by_watchdog = watchdog.disarm();
                // The wait is INFINITE, so there is no expiry to tell from a stop and `Ok` is one.
                let arrived = result.is_ok();
                (result, arrived, by_watchdog)
            }
        };
        // Taken whatever the outcome, so nothing this operation was asked for outlives it.
        let asked = operation.took_break_request();
        if by_watchdog {
            return Ok(WaitOutcome::Deadline);
        }
        if asked {
            return Ok(WaitOutcome::OnRequest);
        }
        result.map_err(DbgEngError::CommandFailed)?;
        if !arrived {
            return Ok(WaitOutcome::Expired);
        }
        Ok(WaitOutcome::Stopped {
            process: self.record_where_it_stopped(),
        })
    }

    /// Delivers this stop to the open that was waiting for it, and answers which process it was.
    ///
    /// **Reached from [`WaitOutcome::Stopped`]'s arm and nowhere else**, which is the point of the
    /// arm: the two ways a wait comes back having stopped on nothing -- an expiry, and a break of
    /// either origin -- are other variants of the same value, so there is no gate here to forget.
    /// Nine of #133's twenty-two findings were that gate being added one writer at a time.
    ///
    /// **Delivered, where this used to broadcast** (dbgscope#136 stage 3). It wrote into an
    /// engine-wide set of every process the engine had ever stopped on, which every guard then
    /// polled; that set outlived the opens that read it, so it needed pruning for pid reuse and
    /// clearing at two teardowns, each of which arrived as a review finding. Now the stop goes to
    /// the one open that wants it and to nothing else, and there is no record left over to go
    /// stale.
    ///
    /// **On every wait, whoever made it**, because the fact it carries is destroyed by the *next*
    /// wait from any source: a caller driving the engine itself -- the documented way to complete a
    /// target whose guard is still held -- must deliver as [`Self::wait_for_live_target`]'s own
    /// pumping does, or that guard reads its own arrival as a target still coming. Since the
    /// register is per **client** rather than per wrapper, that now holds through a second
    /// `DebugEngine` around the same session as well.
    ///
    /// Best-effort: an engine with no event to name, a dump, an event belonging to no process this
    /// session lists. Every one of those is "nothing to deliver" rather than a failure, and this is
    /// on the path of every wait in the crate, so none of them may fail one.
    fn record_where_it_stopped(&self) -> Option<(u32, u32)> {
        let (Ok(id), Ok(held)) = (self.last_event_process(), self.session_processes()) else {
            return None;
        };
        // Every stop is a listing of the session, and the only one that happens between an
        // attach's wait and the next opener's prune -- see `note_attachments_present`.
        self.note_attachments_present(&held);
        let entry = held.iter().copied().find(|(held, _)| *held == id)?;
        let attached = self.attached_pids();
        self.state
            .arrivals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .deliver(entry, &attached);
        Some(entry)
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
    /// `cut_short` says which of the three things happened, and a caller that ignores it reports
    /// "the target stopped here" for two cases where it did not. [`Interruption::OnRequest`] is a
    /// host asking through an [`InterruptHandle`]; [`Interruption::Deadline`] is `timeout_ms`
    /// passing with the target still going, so the break is this crate's own and the position is
    /// wherever the target happened to be; `None` is the target stopping on its own.
    ///
    /// **The wait is [`Bound::Watchdog`] for every target type, and that is load
    /// bearing rather than uniform-for-neatness.** A live kernel needs the INFINITE wait because a
    /// finite one returns `E_NOTIMPL` there — but a finite `WaitForEvent` is not usable on the
    /// others either, and fails far more quietly: on expiry it returns `S_FALSE` with the target
    /// **still running** and the engine holding no current process/thread, and nothing recovers
    /// from that. [`Self::run_to_address`] has said so since it was written, and used the bounded
    /// wait everywhere for that reason, while this function kept the finite one for user-mode,
    /// dumps and TTD. Measured on a user-mode target: one `go` with nothing to stop it left every
    /// later command — `bl`, `r`, `? @$ip` — failing with `0x80040205`, permanently.
    pub fn execute_and_wait(
        &self,
        command: &str,
        timeout_ms: u32,
    ) -> Result<CommandRun, DbgEngError> {
        // A break asked for from here on names this operation; see `execute_command_bounded`.
        let operation = self.begin_operation();
        // Nothing to run against is refused up front rather than driven into DbgEng, which
        // faults the process on it — see `refuse_without_a_debuggee`. It is also what makes the
        // check *after* the wait mean what it says: a debuggee missing there left during this
        // call.
        self.refuse_without_a_debuggee()?;

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
        let pumped = exec
            .is_ok()
            .then(|| self.pump(Bound::Watchdog(timeout_ms), &operation));

        unsafe {
            let _ = self.client.SetOutputCallbacks(None);
        }

        // A break — either origin's — makes both of these fail, exactly as it does in
        // `execute_command_bounded` — and for the same reason the output must survive it, since a
        // `go` stopped on request has still moved the target and the caller needs to see where to.
        //
        // **The origin is the pump's answer**, and since stage 2 the watchdog no longer files a
        // request of its own, so there is no second reading to reconcile it with. Before that, one
        // deadline had two representations and reading the shared one alone reported it as "a host
        // asked" — which it did on the live-kernel path for as long as that path was the only
        // bounded one.
        let (waited, cut_short) = match pumped {
            Some(Ok(outcome)) => (Ok(()), outcome.cut_short(timeout_ms)),
            Some(Err(err)) => (Err(err), None),
            // `Execute` failed, so no pump ran and nothing has attributed anything. A request a
            // host raised while the command was being issued is still filed against this
            // operation, and it is this one's to account for rather than the next one's.
            None => (Ok(()), operation.cut_short_by(false, timeout_ms)),
        };
        let interrupted = cut_short.is_some();
        // Asked before either error is propagated, because the target running out is what makes
        // both of them fail: a debuggee that exits during the wait leaves `WaitForEvent`
        // answering `E_UNEXPECTED`, and reporting that is reporting a program's ordinary ending
        // as a catastrophe — while discarding the output the run had already captured.
        let target_gone = self.lost_its_target();
        if interrupted {
            // As there: consume anything the engine did not, so the next operation starts clean.
            let _ = self.interrupted();
        } else if !target_gone {
            exec.map_err(DbgEngError::CommandFailed)?;
            waited?;
        }

        Ok(CommandRun {
            output: String::from_utf8_lossy(&output_buffer).to_string(),
            cut_short,
            target_gone,
        })
    }

    /// Whether the engine has been *told to run* and is waiting to be pumped.
    ///
    /// This is the state a plain [`Self::execute_command`] leaves behind when the text it was
    /// given happened to be execution control — `g`, `p`, `t`, a `;` list ending in one, a script
    /// that reaches one. `Execute` sets the run state and returns; only a `WaitForEvent` moves the
    /// target. Until one does, the engine answers read-only commands normally and refuses every
    /// execution-control command with `0x80040205`, which reads as a half-alive session.
    ///
    /// Ask the engine rather than reading the command, because no list of command names can be
    /// exhaustive — the data model, an alias, and `.if` all reach execution without saying so.
    pub fn is_running(&self) -> Result<bool, DbgEngError> {
        Ok(is_running_status(self.execution_status()?))
    }

    /// Whether the engine is holding a target at all.
    ///
    /// One status value answers it, and it is the same value whether the engine has never had a
    /// target or has just lost one. Measured on dbgeng 10.0.26100.1 (ARM64): a debuggee that
    /// exits during a wait leaves `GetExecutionStatus` reading `DEBUG_STATUS_NO_DEBUGGEE`, with
    /// `GetNumberProcesses`, `GetCurrentProcessSystemId` and `GetExitCode` all failing
    /// `E_UNEXPECTED` beside it and `.lastevent` answering `<no event>` — so the status is the
    /// only one of them that says anything, and what it says is reliable.
    ///
    /// An unreadable status is not an answer, and this does not collapse one into `true`: what to
    /// do when the engine cannot be asked differs by caller, and each one below decides.
    ///
    /// Public because a caller holding a session needs it for the same reason this crate does —
    /// once the answer is `false`, nothing but teardown will work, and every road in refuses.
    pub fn has_target(&self) -> Result<bool, DbgEngError> {
        Ok(self.execution_status()? != DEBUG_STATUS_NO_DEBUGGEE)
    }

    /// Refuses an operation that would drive DbgEng with nothing behind it.
    ///
    /// **This is what stands between a caller's text and an access violation**, not a tidiness
    /// check. Execution control reaching an engine that holds no debuggee faults *inside* DbgEng
    /// — a structured exception, which `catch_unwind` cannot trap, so it takes the whole process
    /// down instead of failing the call. Measured twice on dbgeng 10.0.26100.1 (ARM64), each
    /// time a `STATUS_ACCESS_VIOLATION` exit: once on an engine whose debuggee had just exited,
    /// and once on a **fresh** engine that never had one. The second is what says the trigger is
    /// the missing debuggee rather than the departure.
    ///
    /// So it cannot be narrowed to text that looks like execution control: `g`, an alias, a
    /// `.if` branch and `dx …ExecuteCommand("g")` all reach it, and the list that would catch
    /// them cannot be finished — the same reason [`Self::settle`] asks the engine instead of
    /// reading the command. What the breadth costs is the few engine-level commands that do work
    /// without a target (`version`, `.echo`, `.sympath`), which are refused too.
    ///
    /// **And one of this crate's own openers is in that group**, which is not obvious and is why
    /// [`Self::execute_fixed_command`] exists: arming the initial break runs `sxe ibp` on an
    /// engine that by definition holds nothing yet, so guarding it refuses every
    /// [`Self::launch_process`] and [`Self::attach_process`] on the machine. The guard is about
    /// text a *caller* supplied; a literal written here is not that.
    fn refuse_without_a_debuggee(&self) -> Result<(), DbgEngError> {
        match self.has_target()? {
            true => Ok(()),
            false => Err(DbgEngError::NoDebuggee),
        }
    }

    /// Whether the engine has lost its target, asked after an operation that could have taken it.
    ///
    /// Asked of the engine rather than read off a `WaitForEvent` result, because that result is
    /// `E_UNEXPECTED` — "Catastrophic failure", which names nothing and is also what a genuinely
    /// broken engine answers — and because two of the four callers do not wait at all. Every one
    /// of them refuses to *start* without a debuggee, so a missing one here means the target left
    /// during this call.
    ///
    /// An unreadable status answers `false`. This decides whether to **suppress** the wait's
    /// error, and suppressing one on a guess would report a broken engine as a program that
    /// finished.
    fn lost_its_target(&self) -> bool {
        !self.has_target().unwrap_or(true)
    }

    /// Pumps the engine to a stop if a command left it running, and reports what happened:
    /// `Ok(None)` when there was nothing to settle, `Ok(Some(run))` with the output the pump
    /// captured otherwise — `cut_short` being [`Interruption::Deadline`] when the target had not
    /// stopped by `timeout_ms` and was broken in at the bound, and [`CommandRun::target_gone`]
    /// when the pump ended because the target *left* rather than stopped.
    ///
    /// That third answer is not a failure and must not be reported as one: running a program to
    /// completion is what a `g` is for, and it is the case where the pump's own output is the
    /// only copy there will ever be.
    ///
    /// This is the recovery for the state [`Self::is_running`] describes, and it is why that state
    /// need not be prevented by inspecting command text. Calling it after every plain `Execute`
    /// costs one `GetExecutionStatus` in the ordinary case.
    ///
    /// A `timeout_ms` of zero breaks the target in at once rather than disabling the bound — the
    /// same meaning it has for [`Self::run_to_address`], and the opposite of
    /// [`Self::execute_command_bounded`]'s. There is no "wait for ever" here on purpose: this runs
    /// on a path whose caller has already spent most of its budget.
    pub fn settle(&self, timeout_ms: u32) -> Result<Option<CommandRun>, DbgEngError> {
        if !self.is_running()? {
            return Ok(None);
        }
        // A break asked for from here on names this operation; see `execute_command_bounded`.
        let operation = self.begin_operation();

        // Captured, because the pump is where the interesting output is: the command that set the
        // run state printed only its own echo, and the breakpoint banner, module loads and stop
        // reason all arrive here.
        let mut output_buffer = Vec::<u8>::with_capacity(4096);
        let output_callbacks = OutputCallbacks::new(&mut output_buffer);
        let output_interface: IDebugOutputCallbacks = output_callbacks.into();
        unsafe {
            self.client
                .SetOutputCallbacks(Some(&output_interface))
                .map_err(DbgEngError::CommandFailed)?;
        }

        let pumped = self.pump(Bound::Watchdog(timeout_ms), &operation);

        unsafe {
            let _ = self.client.SetOutputCallbacks(None);
        }

        // The same three-way origin as `execute_and_wait`, and now for the same reason as well as
        // by the same rule: the pump attributed it, and the watchdog no longer shares a channel
        // with a host for anything here to re-read.
        let (waited, cut_short) = match pumped {
            Ok(outcome) => (Ok(()), outcome.cut_short(timeout_ms)),
            Err(err) => (Err(err), None),
        };
        let interrupted = cut_short.is_some();
        // And the same question after the wait, for the same reason — with more riding on it
        // here, because the pump is where the output is. A target that runs out mid-pump fails
        // the wait with `E_UNEXPECTED`, and propagating that threw away the breakpoint banner,
        // the module loads and anything an embedded script printed, precisely on the run that
        // has no successor to print them again.
        let target_gone = self.lost_its_target();
        if interrupted {
            let _ = self.interrupted();
        } else if !target_gone {
            waited?;
        }

        Ok(Some(CommandRun {
            output: String::from_utf8_lossy(&output_buffer).to_string(),
            cut_short,
            target_gone,
        }))
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
        // A break asked for from here on names this operation. This function is the one bounded
        // path that had neither a clear on the way in nor a consume on the way out, which stopped
        // mattering to itself -- it classified by the watchdog's own flag -- and started mattering
        // to everyone else once the recorder began reading the shared one. Both are now properties
        // of the operation rather than lines here.
        let operation = self.begin_operation();
        // Refuse when there's nothing to run: driving `g` with no debuggee faults DbgEng in a
        // way `catch_unwind` cannot trap — see `refuse_without_a_debuggee`.
        self.refuse_without_a_debuggee()?;
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
        // engine is no longer pumping events.
        //
        // The pump takes the request filed against this operation, which is the half review round
        // 12 of #133 was about: the watchdog used to raise the shared flag through
        // `InterruptHandle::interrupt` like any host, and a `run_to_address` that timed out left it
        // set for good -- so the next wait read a stale interrupt, declined to record a real
        // initial break, and left a held guard pumping. Since stage 2 the watchdog files nothing
        // and a request cannot outlive the operation it names, so neither half can recur.
        let pumped = exec
            .is_ok()
            .then(|| self.pump(Bound::Watchdog(timeout_ms), &operation));
        // A break's error is the break's, not the target's, so only a genuine failure propagates.
        // A host's counts as well as the watchdog's now, where before only the watchdog's did:
        // narrow -- `SetInterrupt` ends a wait with `S_OK`, so it takes the target failing in the
        // same window -- and one rule instead of two.
        let (waited, cut_short) = match pumped {
            Some(Ok(outcome)) => (Ok(()), outcome.cut_short(timeout_ms)),
            Some(Err(err)) => (Err(err), None),
            // No pump ran, so the request a failing `Execute` may have been aborted by is still
            // filed here. Nothing below reads it -- this outcome has no `cut_short` field -- but it
            // is this operation's to take, and it was the one path that left one behind.
            None => (Ok(()), operation.cut_short_by(false, timeout_ms)),
        };
        // "The watchdog fired": a host's break leaves the target stopped somewhere, which the
        // instruction-pointer read below reports as it always did.
        let expired = matches!(cut_short, Some(Interruption::Deadline { .. }));

        unsafe {
            let _ = self.client.SetOutputCallbacks(None);
        }

        let output = String::from_utf8_lossy(&output_buffer).to_string();

        // Read before the two errors below, which is what an exit makes of them: a target can
        // run out on the way to `address` as readily as during a plain `go`, and the same
        // `E_UNEXPECTED` comes back. Reported as an outcome with its output rather than as a
        // failure — see `RunToOutcome::TargetGone`.
        if self.lost_its_target() {
            return Ok(RunToResult {
                outcome: RunToOutcome::TargetGone,
                output,
            });
        }
        exec.map_err(DbgEngError::CommandFailed)?;
        waited?;

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
    /// # use dbgscope::dbgeng::DebugEngine;
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

    /// Every register's **description**, without reading a value for any of them.
    ///
    /// The same enumeration [`Self::register_values`] performs, minus the per-register `GetValue`
    /// — so it is cheap, and it answers a different question: not "what is in this register" but
    /// "what does the engine say this register is". A caller that wants to know whether `w0` is a
    /// view of `x0`, or whether `xmm0/0` is a piece of `xmm0`, has to be able to look at
    /// `SubregMaster` and decide for itself, because the flag beside it does not say so on either
    /// architecture.
    ///
    /// Indexes are positions in this list, which is the engine's own register order — so
    /// [`RegisterDescription::subreg_master`] indexes the same `Vec` it came from.
    pub fn register_descriptions(&self) -> Result<Vec<RegisterDescription>, DbgEngError> {
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
            out.push(RegisterDescription {
                name,
                kind: description.Type,
                flags: description.Flags,
                subreg_master: description.SubregMaster,
                subreg_length: description.SubregLength,
                subreg_mask: description.SubregMask,
                subreg_shift: description.SubregShift,
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
    /// The **PDB** identity for a loaded module — the `GUID` + `age` a symbol server is keyed by.
    ///
    /// `Ok(None)` when the engine has no PDB signature for the module, which is the ordinary case
    /// for one whose symbols are still deferred: this reports what the engine *has*, and it has
    /// nothing until something has made it look. It is not an error, and it is not "this module
    /// has no symbols" either — the two are told apart by [`Module::symbols`].
    ///
    /// Read through `IDebugAdvanced2::GetSymbolInformation`, which fills dbghelp's own
    /// `IMAGEHLP_MODULEW64`. The interface is cast per call rather than held: this is asked once
    /// per module that has symbols, not once per operation, and a `QueryInterface` is cheaper than
    /// another field on every engine that never asks.
    pub fn module_pdb(&self, base: u64) -> Result<Option<PdbIdentity>, DbgEngError> {
        let advanced =
            self.client
                .cast::<IDebugAdvanced2>()
                .map_err(|source| DbgEngError::Context {
                    operation: "querying IDebugAdvanced2".into(),
                    source,
                })?;
        let mut info = IMAGEHLP_MODULEW64 {
            SizeOfStruct: std::mem::size_of::<IMAGEHLP_MODULEW64>() as u32,
            ..Default::default()
        };
        let filled = unsafe {
            advanced.GetSymbolInformation(
                DEBUG_SYMINFO_IMAGEHLP_MODULEW64,
                base,
                0,
                Some((&raw mut info).cast()),
                std::mem::size_of::<IMAGEHLP_MODULEW64>() as u32,
                None,
                None,
                None,
            )
        };
        // **No not-found mapping here, deliberately.** `module_at` treats `E_INVALIDARG` as "no
        // module holds this offset" because that is measurably what the engine means *there*, and
        // copying the convention across looked natural. It is wrong here: this call's plausible
        // failures are the call itself being wrong — a struct size this dbghelp does not
        // recognise, an interface it does not implement — and reporting those as "this module has
        // no PDB" would be a quiet, believable claim about the target made out of a broken call.
        // An engine with nothing to say fills the struct and leaves the signature zeroed, which is
        // the check below; it does not fail.
        filled.map_err(|source| DbgEngError::Context {
            operation: format!("reading the PDB identity of the module at {base:#x}"),
            source,
        })?;
        let guid = info.PdbSig70;
        // An all-zero signature is the engine saying it has none — a module whose symbols are
        // deferred fills the struct and leaves this empty rather than failing the call.
        if guid.data1 == 0 && guid.data2 == 0 && guid.data3 == 0 && guid.data4 == [0; 8] {
            return Ok(None);
        }
        Ok(Some(PdbIdentity {
            guid: format_pdb_guid(&guid),
            age: info.PdbAge,
            unmatched: info.PdbUnmatched.as_bool(),
            file: wide_to_string(&info.LoadedPdbName),
        }))
    }

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

    /// The event the engine last saw — what `.lastevent` prints, as values.
    ///
    /// The user-mode counterpart to [`Self::bug_check`], and the typed form of `.exr -1`: on a
    /// target stopped by a fault, [`DebugEvent::exception`] is the record that stopped it.
    ///
    /// **This is the engine's last event, not the session's history.** It is whatever stopped the
    /// engine most recently, so a caller who has stepped, gone, or hit a breakpoint since the fault
    /// gets *that* event and not the fault. On a freshly opened dump it is the event the dump was
    /// written for; [`Self::stored_event`] is the one that stays that way.
    ///
    /// `Ok(None)` where the engine has seen no event, which is every engine before its first wait
    /// — including a dump that `open_dump` has *named* but nothing has pumped, since the engine
    /// reads one on the first wait and not at the open.
    ///
    /// **That case is `None` rather than an error because the engine does not fail it.** It
    /// answers `S_OK` with kind `0` and `DEBUG_ANY_ID` for both ids, and kind `0` is not a
    /// `DEBUG_EVENT_*` value — there is no event, and the engine is saying so. Returning that
    /// event as if it were one would hand a caller a `DebugEvent` whose `kind` means "nothing
    /// happened yet" and let "the target is not loaded" read as an event kind this build does not
    /// recognise (dbgscope#144). Measured by `examples/stored_event_probe.rs`'s `empty` and
    /// `unwaited` arms.
    pub fn last_event(&self) -> Result<Option<DebugEvent>, DbgEngError> {
        let mut kind = 0u32;
        let mut process = 0u32;
        let mut thread = 0u32;
        // Sized for the largest `DEBUG_LAST_EVENT_INFO_*` there is, which is the exception one by a
        // wide margin, and `u64`-aligned because the engine writes an `EXCEPTION_RECORD64` into it.
        // The engine reports how much it used, and nothing below reads past that.
        let mut extra = ExtraEventInfo::default();
        let mut used = 0u32;
        unsafe {
            self.control.GetLastEventInformation(
                &mut kind,
                &mut process,
                &mut thread,
                Some(extra.as_mut_ptr()),
                ExtraEventInfo::SIZE,
                Some(&mut used),
                // The description is text — "Break instruction exception - code 80000003 (first
                // chance)" — and every fact in it is in the fields beside it. Asking for it would
                // be a second buffer for a second rendering of what this already returns.
                None,
                None,
            )
        }
        .map_err(|source| DbgEngError::Context {
            operation: "reading the engine's last event".into(),
            source,
        })?;
        // See the doc comment: an engine with nothing to report succeeds and says so with a kind
        // that is not an event kind, rather than failing.
        if kind == NO_EVENT_KIND {
            return Ok(None);
        }
        let exception = extra.exception(kind, used);
        Ok(Some(DebugEvent {
            kind,
            process,
            thread,
            first_chance: exception.as_ref().is_some_and(|(_, first)| *first),
            exception: exception.map(|(record, _)| record),
            // `GetLastEventInformation` carries no context. `.ecxr` works on a dump because the
            // *stored* event has one, which is why the two calls are not one.
            context: None,
        }))
    }

    /// The event a dump was written for, with the register context it was written with — what
    /// `.ecxr` adopts, as values.
    ///
    /// **The difference from [`Self::last_event`] is that this one does not move.** It is the
    /// event the target was *stored* on, so it still answers after a caller has stepped, gone, or
    /// changed threads — which is exactly the state a triage runs in on any session somebody has
    /// already been working in. [`DebugEvent::context`] is what makes that usable: hand it to
    /// [`Self::stack_frames_from`] and the crash stack comes back without `.ecxr`'s side effect on
    /// the session's selected scope.
    ///
    /// `Ok(None)` where the target has no stored event, which is every live target and every dump
    /// not written for a fault. That is a fact about the target rather than a failure, and it is
    /// read off the engine's own refusal rather than probed for — see [`no_stored_event`].
    pub fn stored_event(&self) -> Result<Option<DebugEvent>, DbgEngError> {
        let mut kind = 0u32;
        let mut process = 0u32;
        let mut thread = 0u32;
        let mut refusal = None;
        for (rung, &size) in STORED_CONTEXT_SIZES.iter().enumerate() {
            let mut context = vec![0u8; size as usize];
            let mut context_used = 0u32;
            let mut extra = ExtraEventInfo::default();
            let mut extra_used = 0u32;
            match unsafe {
                self.control.GetStoredEventInformation(
                    &mut kind,
                    &mut process,
                    &mut thread,
                    Some(context.as_mut_ptr().cast()),
                    size,
                    Some(&mut context_used),
                    Some(extra.as_mut_ptr()),
                    ExtraEventInfo::SIZE,
                    Some(&mut extra_used),
                )
            } {
                // **Filled to the brim means it may have had more to write**, which is the only
                // signal this call gives that the buffer was too small — see
                // [`STORED_CONTEXT_SIZES`]. Grow while there is a rung left; on the last one, take
                // what there is rather than returning nothing.
                Ok(())
                    if context_used as usize >= context.len()
                        && rung + 1 < STORED_CONTEXT_SIZES.len() =>
                {
                    continue;
                }
                Ok(()) => {
                    // Clamped to the buffer as well as to the engine's own count, the same trust
                    // decision `stack_frames` makes about `filled`.
                    context.truncate((context_used as usize).min(context.len()));
                    let exception = extra.exception(kind, extra_used);
                    return Ok(Some(DebugEvent {
                        kind,
                        process,
                        thread,
                        first_chance: exception.as_ref().is_some_and(|(_, first)| *first),
                        exception: exception.map(|(record, _)| record),
                        context: (!context.is_empty()).then(|| ThreadContext {
                            bytes: context,
                            target: self.target_identity(),
                        }),
                    }));
                }
                // **Checked before the retry, not after it.** "There is no stored event" is an
                // answer, and climbing the whole ladder to rediscover it four more times would
                // turn one refusal into five engine calls.
                Err(why) if no_stored_event(why.code()) => return Ok(None),
                // Not what this engine does — it truncates rather than refusing, which is what the
                // ladder above is shaped around — but a refusal for being too small is still worth
                // one more rung rather than an error.
                Err(why) if why.code() == E_INVALIDARG => refusal = Some(why),
                Err(why) => {
                    refusal = Some(why);
                    break;
                }
            }
        }
        Err(DbgEngError::Context {
            operation: "reading the event this target was stored on".into(),
            // Unreachable with a non-empty ladder: the only arm that does not return records a
            // refusal, and the one that continues cannot be the last rung. Spelled as a fallback
            // rather than an `expect` because a panic here would be this crate breaking its own
            // rule about library code — and as `E_FAIL` rather than `E_UNEXPECTED`, which is the
            // code [`no_stored_event`] reads as "there is no stored event" and would be a lie.
            source: refusal.unwrap_or_else(|| windows::core::Error::from(E_FAIL)),
        })
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
        Ok(self.resolve_frames(&raw))
    }

    /// The stack a recorded register context was in, rather than the one the session's **current
    /// thread** is in — what `.ecxr` followed by `k` renders, without the `.ecxr`.
    ///
    /// Given [`DebugEvent::context`] from [`Self::stored_event`], this is the crash stack of a
    /// dump, walked on any session whatever thread it has selected, and it leaves that selection
    /// exactly where it found it — so a triage built on this is still a read of the target.
    ///
    /// **The difference from [`Self::stack_frames`] is the selected thread, and only that.**
    /// Measured on the two-thread fail-fast dump in `examples/stored_event_probe.rs`: after `~1s`
    /// the other walk returns the parked thread's six frames while this one still returns the
    /// crash's twelve. What does *not* move it is `.frame`, `.cxr` or `.ecxr` — all three change
    /// the symbol scope, and `GetStackTrace` walks from the thread's registers rather than from
    /// the scope, so both walks agree across all three. That is worth knowing before reaching for
    /// this one: on a freshly opened dump, whose current thread is the faulting thread, the two
    /// answers are identical, and the reason to prefer this is that it stays identical.
    ///
    /// The context is passed through to `GetContextStackTrace` untouched — its size is the
    /// engine's own [`ThreadContext::len`], not a size this code believes in — so a target whose
    /// `CONTEXT` this crate has never seen walks the same as one it has.
    ///
    /// `max_frames` bounds the walk, and zero frames is a legitimate ask answered without touching
    /// the engine, both exactly as [`Self::stack_frames`].
    pub fn stack_frames_from(
        &self,
        context: &ThreadContext,
        max_frames: usize,
    ) -> Result<Vec<StackFrame>, DbgEngError> {
        if max_frames == 0 {
            return Ok(Vec::new());
        }
        // **Refused before the engine sees it, exactly as `set_scope` refuses a stale scope.**
        // The check is cheap and the failure it prevents is not detectable afterwards: a context
        // from a released target unwinds whatever its addresses reach in the new one and comes
        // back as a plausible stack.
        if context.target != self.target_identity() {
            return Err(DbgEngError::ContextFromAnotherTarget);
        }
        // An empty context would be read by the engine as "walk from the current one", which is
        // the question `stack_frames` answers and the opposite of what this was called for. A
        // caller holding one has a `stored_event` that reported no context; say so.
        if context.is_empty() {
            return Err(DbgEngError::Context {
                operation: "walking the stack of a recorded context that has no registers".into(),
                source: windows::core::Error::from(E_INVALIDARG),
            });
        }
        let mut raw = vec![DEBUG_STACK_FRAME::default(); max_frames];
        let mut filled = 0u32;
        unsafe {
            self.control.GetContextStackTrace(
                Some(context.as_bytes().as_ptr().cast()),
                context.len() as u32,
                Some(&mut raw),
                None,
                0,
                0,
                Some(&mut filled),
            )
        }
        .map_err(|source| DbgEngError::Context {
            operation: "walking the stack of a recorded register context".into(),
            source,
        })?;
        raw.truncate((filled as usize).min(max_frames));
        Ok(self.resolve_frames(&raw))
    }

    /// The engine's raw frames with each one's symbol resolved — shared by the two stack walks, so
    /// that a frame from either is the same record and joins the other.
    fn resolve_frames(&self, raw: &[DEBUG_STACK_FRAME]) -> Vec<StackFrame> {
        raw.iter()
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
            .collect()
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
        // Asked once for the whole walk: the target's architecture cannot change inside one, and
        // asking per instruction would put a COM call between every pair of them.
        let set = self.instruction_set();
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
            out.push(split_instruction(at, &line, set));
            // An engine that does not advance would spin here forever rendering one instruction.
            if next <= at {
                break;
            }
            at = next;
        }
        Ok(out)
    }

    /// Decodes a **range** of code from one memory read, instead of one engine call per
    /// instruction.
    ///
    /// [`Self::disassemble`] asks the engine to render each instruction and walks forward by the
    /// end it reports, which is right for a listing and wrong for an analysis: a bounded walk over
    /// a whole routine makes one COM call per instruction, and a traversal over a hundred
    /// functions makes tens of thousands. This reads the span once and decodes it locally.
    ///
    /// **The instructions carry no [`Instruction::text`].** Nothing rendered them, and this crate
    /// has always promised that field is the engine's own output — filling it from a second
    /// formatter would put two renderings of one instruction into one type, which is worse than an
    /// empty string. A caller that needs a rendering for the few instructions it displays asks
    /// [`Self::disassemble`] for those.
    ///
    /// Decoding resynchronises the way a linear read must: a span that begins mid-instruction, or
    /// runs into data, decodes as whatever those bytes are. Bound it with a function's own extent
    /// where there is one, and read [`Flow`] rather than trusting a listing's shape.
    ///
    /// **ARM64 answers everything but the text**, [`crate::arm64`] decoding the word rather than a
    /// rendering — so this path is the one that gains most from it, being the one with no
    /// rendering to fall back on. A64 being fixed-width, nothing resynchronises there and a span
    /// that begins mid-instruction cannot: it begins at a word boundary or it begins at the wrong
    /// place for every instruction in it.
    pub fn decode_range(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<Instruction>, DbgEngError> {
        let set = InstructionSet::from_processor_type(self.effective_processor_type()?);
        let bitness = match set {
            InstructionSet::X86 => 32,
            InstructionSet::Amd64 => 64,
            InstructionSet::Arm64 => return self.decode_range_arm64(address, length),
            InstructionSet::Other(machine) => {
                return Err(DbgEngError::UndecodedInstructionSet { machine });
            }
        };
        let bytes = self.read_memory(address, length)?;
        let mut decoder =
            iced_x86::Decoder::with_ip(bitness, &bytes, address, iced_x86::DecoderOptions::NONE);
        let mut out = Vec::new();
        while decoder.can_decode() {
            let at = decoder.ip();
            let decoded = decoder.decode();
            let offset = (at - address) as usize;
            let encoding = bytes
                .get(offset..offset + decoded.len())
                .unwrap_or_default();
            // Empty for bytes that did not decode, for the same reason the flow below is
            // `Unknown` there: nothing was read, so nothing is claimed about what was touched.
            let (reads, writes) = match decoded.is_invalid() {
                true => (Vec::new(), Vec::new()),
                false => touched_registers(&decoded, bitness),
            };
            out.push(Instruction {
                address: at,
                bytes: hex::encode(encoding),
                text: String::new(),
                mnemonic: if decoded.is_invalid() {
                    String::new()
                } else {
                    format!("{:?}", decoded.mnemonic()).to_lowercase()
                },
                operands: if decoded.is_invalid() {
                    Vec::new()
                } else {
                    (0..decoded.op_count())
                        .map(|index| read_decoded_operand(&decoded, index, bitness))
                        .collect()
                },
                // Bytes that were read and did not decode: `Unknown`, not `Unreadable`. A linear
                // read runs into data and into the middle of instructions as a matter of course,
                // and neither is "there is nothing here".
                flow: if decoded.is_invalid() {
                    Flow::Unknown
                } else {
                    decoded_flow(&decoded)
                },
                // `false` for bytes that did not decode, for the same reason the flow is
                // `Unknown` there: nothing was read, so nothing is claimed.
                privileged: !decoded.is_invalid() && decoded.is_privileged(),
                effect: if decoded.is_invalid() {
                    Effect::Other
                } else {
                    decoded_effect(&decoded)
                },
                condition: (!decoded.is_invalid())
                    .then(|| decoded_condition(&decoded))
                    .flatten(),
                writes_flags: !decoded.is_invalid() && decoded.rflags_written() != 0,
                writes,
                reads,
            });
        }
        Ok(out)
    }

    /// [`Self::decode_range`]'s A64 half: fixed-width words, decoded whole.
    ///
    /// **The bytes are assembled little-endian here and big-endian in
    /// [`split_instruction`]**, and both are right. This reads memory, where A64 stores a word
    /// least significant byte first; that one reads the engine's rendering, which prints the word.
    /// [`Instruction::bytes`] is filled with the **word**, matching the rendering rather than the
    /// memory, so the two paths describe one instruction the same way — `examples/typed_disassembly.rs`
    /// compares them field by field, and a byte string in memory order would report every
    /// instruction on this architecture as a disagreement.
    fn decode_range_arm64(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<Instruction>, DbgEngError> {
        let bytes = self.read_memory(address, length)?;
        Ok(bytes
            .chunks_exact(crate::arm64::INSTRUCTION_BYTES)
            .enumerate()
            .map(|(index, chunk)| {
                let at = address + (index * crate::arm64::INSTRUCTION_BYTES) as u64;
                let word = u32::from_le_bytes(chunk.try_into().expect("chunks_exact gives four"));
                let decoded = crate::arm64::decode(word, at);
                Instruction {
                    address: at,
                    bytes: hex::encode(word.to_be_bytes()),
                    text: String::new(),
                    mnemonic: decoded.mnemonic,
                    operands: decoded.operands,
                    flow: decoded.flow,
                    privileged: decoded.privileged,
                    effect: decoded.effect,
                    condition: decoded.condition,
                    writes_flags: decoded.writes_flags,
                    writes: decoded.writes,
                    reads: decoded.reads,
                }
            })
            .collect())
    }

    /// The instruction set the target's disassembly is rendered in.
    ///
    /// The **effective** processor type and not the physical one, because that is what
    /// `Disassemble` renders with: the two diverge wherever one machine runs another's code — a
    /// WOW64 process on x64, x64 emulated on ARM64, or any target after `.effmach` — and
    /// discriminating a rendering by the machine underneath it reads x86 output with x64 rules,
    /// or refuses operands the engine did render. It also picks the unwind-entry layout in
    /// [`Self::function_extent`], where the same divergence chooses the wrong record shape.
    ///
    /// Falls back to [`InstructionSet::Other`] when the engine will not say, which reads operands
    /// out of nothing rather than reading them wrongly — a target that cannot name its processor
    /// is not one to guess x86 for. That fold is deliberate **here** and not everywhere: a
    /// disassembly whose processor query failed still has a rendering to hand back, with its
    /// operands unread and its flow [`Flow::Unknown`], so there is a partial answer to give.
    /// [`Self::function_extent`] has none, so it asks the processor directly and returns a failed
    /// query as an error rather than as an unsupported architecture.
    pub fn instruction_set(&self) -> InstructionSet {
        match self.effective_processor_type() {
            Ok(machine) => InstructionSet::from_processor_type(machine),
            Err(_) => InstructionSet::Other(0),
        }
    }

    /// Where the unwind **region** containing `address` begins and ends, from the target's own
    /// unwind data rather than from a guess or a symbol's extent.
    ///
    /// `IDebugSymbols3::GetFunctionEntryByOffset` reads the `RUNTIME_FUNCTION` the image's
    /// `.pdata` carries, so it is exact for the x64 code this crate walks, and the table is in a
    /// read-only section — which is why it still answers on a dump whose data pages were never
    /// captured.
    ///
    /// # A region is not a function, and using it as one loses code
    ///
    /// MSVC splits a function into **several** `RUNTIME_FUNCTION` entries whenever it separates
    /// cold or shared blocks, and each entry bounds only its own region. Measured against
    /// `mountmgr!MountMgrDeviceControl` on a 26100 image: this answers `0x14750..0x147a3`, an
    /// 83-byte region of 23 instructions, and `.fnent` agrees exactly — while the routine's IOCTL
    /// compare chain lives past `0x147dd`, in regions this entry says nothing about. Bounding a
    /// walk with it recovered **zero** control codes where following the flow recovered twelve.
    ///
    /// So this is a sanity bound and a "which region is this" answer, **not** a function's extent.
    /// A walk over a whole function follows [`Instruction::flow`] from its entry.
    ///
    /// # Three outcomes, because collapsing them hides two different wrong answers
    ///
    /// [`FunctionExtent::NoEntry`] is a fact rather than a failure — a leaf function has no entry,
    /// and neither has an address that is not code. It is reported for the **one** measured
    /// failure that means it, `E_NOINTERFACE` (`0x80004002`), which is what a real dbgeng 10.x
    /// answers for address zero and for a module's header page. Any other failure is returned as
    /// one, so a broken engine is not read as a leaf.
    ///
    /// **x86 answers [`FunctionExtent::Unsupported`], not `NoEntry`**, and an earlier draft of
    /// this paragraph promised the opposite — which the gate below has never done. Both readings
    /// are defensible and only one can be true, so: 32-bit Windows has no unwind table, and every
    /// x86 address measured here answers `E_NOINTERFACE` (`cppthrow-fastfail-x86.dmp`), so
    /// implementing x86 would buy nothing. But that is a fact about a *platform*, and returning
    /// `NoEntry` would assert it about an *address* this never asked about. x86's record is also a
    /// different structure — `IMAGE_FUNCTION_ENTRY`, whose fields are addresses rather than the
    /// RVAs rebased below — and nothing here has measured one. So the rule is the same rule
    /// everywhere: decode the one layout that has been measured, and refuse the rest by name.
    ///
    /// [`FunctionExtent::Unsupported`] is every instruction set but x64 and ARM64, and it is not
    /// caution — it is the two record layouts that have been measured, and no third.
    ///
    /// # ARM64's record is two words, and the second one is not an end address
    ///
    /// Measured on a 26100 ARM64 kernel dump, `nt!KeBugCheckEx` fills `needed = 8` with
    /// `[0x0025df60, 0x0005f218]`. Read with the x64 rules that second word is an end, which is a
    /// bogus extent — and for any function whose `BeginAddress` is below the `.xdata` RVA it is a
    /// bogus extent that **contains the address asked about**, so it passes every sanity check
    /// below and is returned as a confident wrong answer. That is why the gate is on the
    /// instruction set and the record size rather than on a tighter sanity check.
    ///
    /// What the second word actually is, its low two bits decide ([`crate::arm64::unwind_record`]):
    /// unwind data packed into the word, or an RVA into `.xdata` whose first word carries the
    /// length. Either way the answer is `BeginAddress + FunctionLength * 4`, so this is a shift —
    /// plus, on the `.xdata` path, one more read. **That read is of `.xdata`, which is read-only**,
    /// and so is available on a dump for the same reason `.pdata` itself is. One that would not
    /// read is returned as an **error** and not as [`FunctionExtent::NoEntry`]: the image has an
    /// entry for that address and this could not finish reading it, which is
    /// [Unknown, not absent](https://github.com/glslang/dbgscope/blob/main/docs/unknown-not-absent.md)
    /// exactly — and `NoEntry` is the answer a caller reads as "a leaf function".
    ///
    /// Both forms occur in one image and both are pinned against `.fnent`'s own decode:
    /// `nt!EtwpDestructIptData` is packed (`Flag=1 FuncLen=78`) and `nt!KeBugCheckEx` is `.xdata`
    /// (six instructions, `0x25df60..0x25df78`, which is exactly where the engine's listing ends).
    ///
    /// # The shape, which is not the one the name suggests
    ///
    /// On x64 the engine fills an `IMAGE_RUNTIME_FUNCTION_ENTRY` — **three `u32` RVAs**
    /// (`BeginAddress`, `EndAddress`, `UnwindInfoAddress`), not the 64-bit addresses
    /// `IMAGE_FUNCTION_ENTRY64` would carry. Reading them as `u64` packs two RVAs into one number
    /// and yields an extent that fails its own sanity check, which is how this was first written
    /// and how it reported "no entry" for a 2,108-byte dispatch routine that plainly had one.
    /// They are also relative, so they are rebased here against the module that holds the address
    /// — what `.fnent` prints, at the RVAs it prints them. The engine's own `needed` is checked
    /// against that shape rather than assumed, since it is the field that says ARM64's is
    /// different.
    pub fn function_extent(&self, address: u64) -> Result<FunctionExtent, DbgEngError> {
        // Asked directly rather than through `instruction_set`, which folds a failed query into
        // `Other(0)`. That fold is right where a rendering still exists to hand back with its
        // operands unread; here there is no partial answer, so a processor query that fails is an
        // error and `Unsupported` is left meaning "a real architecture this does not decode".
        let set = InstructionSet::from_processor_type(self.effective_processor_type()?);
        // Three `u32`s for x64, two for ARM64 — and the buffer is three either way, so that the
        // engine's own `needed` can be checked against the width this architecture's record is
        // *expected* to be rather than against the width of the buffer it was given.
        let expected = match set {
            InstructionSet::Amd64 => 3 * std::mem::size_of::<u32>(),
            InstructionSet::Arm64 => 2 * std::mem::size_of::<u32>(),
            InstructionSet::X86 | InstructionSet::Other(_) => {
                return Ok(FunctionExtent::Unsupported(set));
            }
        };
        let mut entry = [0u32; 3];
        let mut needed = 0u32;
        if let Err(source) = unsafe {
            self.symbols.GetFunctionEntryByOffset(
                address,
                0,
                Some(entry.as_mut_ptr().cast()),
                std::mem::size_of_val(&entry) as u32,
                Some(&mut needed),
            )
        } {
            // The one failure that means "this address has no unwind entry".
            if source.code() == E_NOINTERFACE {
                return Ok(FunctionExtent::NoEntry);
            }
            return Err(DbgEngError::Context {
                operation: format!("reading the function entry for {address:#x}"),
                source,
            });
        }
        // The engine says how big the record it filled is. Anything but this architecture's own
        // width is a layout this does not decode, whatever the processor said.
        if needed as usize != expected {
            return Ok(FunctionExtent::Unsupported(set));
        }
        let begin = entry[0] as u64;
        if begin == 0 {
            return Ok(FunctionExtent::NoEntry);
        }
        // Read **before** the length on both paths, because ARM64's `.xdata` word is at an RVA and
        // needs the base to reach. x64 pays one module lookup it used to make after its sanity
        // checks; the lookup is the same one either way and the outcome for an address in no
        // module is the same `NoEntry`.
        let Some(module) = self.module_at(address)? else {
            return Ok(FunctionExtent::NoEntry);
        };
        let Some(length) = (match set {
            // x64's second word is the end RVA outright, so the length is the difference —
            // `checked_sub` rather than a subtraction, an entry whose end precedes its begin being
            // the bogus record the sanity check below exists for and not a panic.
            InstructionSet::Amd64 => (entry[1] as u64).checked_sub(begin),
            InstructionSet::Arm64 => self.arm64_function_length(module.base, entry[1])?,
            InstructionSet::X86 | InstructionSet::Other(_) => None,
        }) else {
            return Ok(FunctionExtent::NoEntry);
        };
        let end = begin + length;
        if end <= begin {
            return Ok(FunctionExtent::NoEntry);
        }
        let (begin, end) = (module.base + begin, module.base + end);
        // The region has to contain the address it was asked about; anything else means the entry
        // read back does not describe this code and is not worth returning.
        if !(begin..end).contains(&address) {
            return Ok(FunctionExtent::NoEntry);
        }
        Ok(FunctionExtent::Region { begin, end })
    }

    /// An ARM64 function's length in bytes, from the second word of its `RUNTIME_FUNCTION`.
    ///
    /// `None` is "there is no length to be had from this record" — the reserved `Flag` value, and
    /// an `.xdata` header of a version this does not decode. A read that *fails* is an error
    /// rather than a `None`, because those two are different facts and only one of them is about
    /// the record. See [`crate::arm64::unwind_record`] for the layout and the measurements.
    fn arm64_function_length(
        &self,
        module_base: u64,
        second_word: u32,
    ) -> Result<Option<u64>, DbgEngError> {
        let rva = match crate::arm64::unwind_record(second_word) {
            crate::arm64::UnwindRecord::PackedLength(length) => return Ok(Some(length)),
            crate::arm64::UnwindRecord::Reserved => return Ok(None),
            crate::arm64::UnwindRecord::XdataAt(rva) => rva,
        };
        let at = module_base + rva as u64;
        let header = self.read_memory(at, std::mem::size_of::<u32>())?;
        let header = <[u8; 4]>::try_from(header.as_slice()).map_err(|_| DbgEngError::Context {
            operation: format!("reading the unwind header at {at:#x}"),
            source: S_FALSE.into(),
        })?;
        Ok(crate::arm64::xdata_length(u32::from_le_bytes(header)))
    }

    /// The `module!Symbol` an address resolves to and how far past it the address is.
    ///
    /// The public half of [`Self::symbol_at`]: what names a call's destination once a walk has
    /// one. Infallible for the same reason — an address that resolves to nothing is the normal
    /// case for a driver with no PDB, and a caller reads `None` rather than an error.
    pub fn symbol_for(&self, address: u64) -> Option<(String, u64)> {
        let (name, displacement) = self.symbol_at(address);
        name.map(|name| (name, displacement))
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
                unsafe { self.control.GetBreakpointByIndex2(index) }.map_err(|source| {
                    DbgEngError::Context {
                        operation: format!("reading breakpoint at index {index}"),
                        source,
                    }
                })?;
            // Never released: DbgEng owns breakpoint objects and hands out borrowed interfaces, so
            // letting the generated wrapper `Release()` one is a call on an object this code does
            // not own. There is nothing to leak — the engine frees them with the session.
            let breakpoint = std::mem::ManuallyDrop::new(breakpoint);
            out.push(breakpoint_info(&breakpoint, &format!("at index {index}"))?);
        }
        Ok(out)
    }

    /// Creates a breakpoint from `spec` and reports what the engine ended up holding.
    ///
    /// The typed half of `bp`/`ba`/`bu`. Every parameter arrives as a **parameter** rather than as
    /// text spliced into a command line, so a caller has nothing to quote and nothing to screen:
    /// the [command](BreakpointSpec::command) a breakpoint runs on each hit is the case that makes
    /// this worth having, since building it as text means escaping a quoted string inside a
    /// command whose separator is `;`.
    ///
    /// **Unbounded.** A [`BreakpointAt::Expression`] resolves eagerly and can therefore block on a
    /// symbol-server fetch with the engine held; [`Self::set_breakpoint_bounded`] is the same call
    /// with a watchdog. This one is right where the location is an address, where the module's
    /// symbols are known to be local, or where the caller has no deadline to keep.
    pub fn set_breakpoint(&self, spec: &BreakpointSpec) -> Result<BreakpointSet, DbgEngError> {
        self.set_breakpoint_bounded(spec, 0)
    }

    /// [`Self::set_breakpoint`], with the location resolve bounded at `timeout_ms`.
    ///
    /// A zero `timeout_ms` arms nothing, which is how [`Self::set_breakpoint`] is spelled.
    ///
    /// The bound covers **the location step alone**, and only when the location is an
    /// [expression](BreakpointAt::Expression): that is the one call here that can block, because
    /// it makes the engine evaluate a symbol. Creating the breakpoint, setting its flags, its
    /// command, its pass count and its thread are all local bookkeeping, and an address is a
    /// number. So a watchdog around the rest would be a bound on nothing, advertising a promise
    /// this cannot keep.
    ///
    /// **A break here does not fail the call**, for the reason [`BreakpointSet::cut_short`] gives:
    /// the breakpoint exists, and an error is the shape a caller retries. What it does is leave
    /// the location possibly unresolved — read it off the returned record rather than assuming.
    pub fn set_breakpoint_bounded(
        &self,
        spec: &BreakpointSpec,
        timeout_ms: u32,
    ) -> Result<BreakpointSet, DbgEngError> {
        spec.validated()?;
        // Built before anything is created, so a bad command string fails with nothing to undo.
        let command = spec
            .command
            .as_deref()
            .map(|text| CString::new(text).map_err(|_| DbgEngError::InvalidCommand))
            .transpose()?;

        let (breakpoint, cut_short) = self.new_breakpoint(spec, timeout_ms)?;

        // Where the location resolved, that is the first point an *expression*'s address exists —
        // so it is where a data breakpoint's alignment is judged. `validated()` above can only
        // check an address the caller supplied, and skipping the check here would let
        // `ba` on `nt!Foo+1` with an 8-byte watch through: accepted now, refused at the next
        // resume, which is the delayed failure both checks exist to prevent.
        //
        // A **deferred** data breakpoint keeps the gap and cannot close it: the engine resolves it
        // on a later module load, with nothing of this crate's on the stack to check the result.
        let resolved = match unsafe { breakpoint.breakpoint.GetOffset() } {
            Ok(address) if address != DEBUG_INVALID_OFFSET => Some(address),
            _ => None,
        };
        if let (Some(watch), Some(address)) = (spec.data, resolved)
            && !address.is_multiple_of(u64::from(watch.size))
        {
            return Err(DbgEngError::InvalidBreakpoint(format!(
                "a {}-byte data breakpoint must be {}-byte aligned, and this location resolved to \
                 {address:#x}, which is not",
                watch.size, watch.size
            )));
        }

        unsafe {
            if let Some(command) = &command {
                breakpoint
                    .breakpoint
                    .SetCommand(PCSTR::from_raw(command.as_ptr().cast()))
                    .map_err(DbgEngError::BreakpointFailed)?;
            }
            if let Some(passes) = spec.pass_count {
                breakpoint
                    .breakpoint
                    .SetPassCount(passes)
                    .map_err(DbgEngError::BreakpointFailed)?;
            }
            if let Some(thread) = spec.thread {
                breakpoint
                    .breakpoint
                    .SetMatchThreadId(thread)
                    .map_err(DbgEngError::BreakpointFailed)?;
            }
            if let Some(watch) = spec.data {
                breakpoint
                    .breakpoint
                    .SetDataParameters(watch.size, watch.access.to_engine())
                    .map_err(DbgEngError::BreakpointFailed)?;
            }
        }

        // Armed once everything above has landed. A breakpoint enabled before its command is set
        // can be hit in between and *stop* the target rather than run the command — on a live
        // target that is a halted machine where the caller asked for a log line. Every failure
        // above therefore removes it rather than leaving a bare breakpoint where a command
        // breakpoint was asked for.
        if spec.flags() != 0 {
            unsafe { breakpoint.breakpoint.AddFlags(spec.flags()) }
                .map_err(DbgEngError::BreakpointFailed)?;
        }

        // Read back through the same getters `breakpoints()` uses, so what is reported is what the
        // engine holds rather than an echo of the spec — the difference being whether the
        // expression resolved, and to what.
        //
        // Before the removal below, because it is fallible and the removal is destructive. It
        // reports the new breakpoint's own fields, none of which the removal can change, so
        // nothing is lost by asking early.
        let info = breakpoint_info(&breakpoint.breakpoint, "just set")?;
        // The last thing that can fail is now behind us, so the breakpoint belongs to the session
        // whatever happens next.
        breakpoint.keep();

        // **After every step that can fail, and nothing fallible follows it** — which is what makes
        // replacing safe, rather than the search for a position in the middle where it is least
        // unsafe. Review found the caller's breakpoints destroyed by a later failure *four* times,
        // at four positions for this block, because each fix moved it past one fallible step and
        // left the next one behind it — the last of them past `AddFlags`, leaving it in front of
        // this function's own read-back. The property wanted is "nothing is destroyed unless the
        // replacement is certain", which is a statement about the end of the sequence; the only way
        // to hold it is to have nothing after, and that is now checkable by looking rather than by
        // reasoning: below this line there is no `?`.
        //
        // What that gives up is the ordering's original reason — that the address is never armed
        // twice — and it is worth less than it sounds. The window is between `AddFlags` and here,
        // and the engine is not pumping in it: nothing in this call resumes the target, and a
        // `DebugEngine` drives one engine from one thread, so the target cannot execute across it.
        // An unobservable double-arm against a caller permanently losing breakpoints is not a close
        // trade.
        //
        // Best-effort, and `replaced` reports what was actually taken rather than what was
        // intended. A failure here cannot be raised: the mutation this call exists for has
        // *happened*, it is armed, and reporting a cleanup failure as the call failing is what gets
        // a caller to retry and set a second breakpoint — the same rule the openers follow when a
        // post-commit step fails. One that could not be removed is simply still in `breakpoints()`
        // and absent from `replaced`, where the caller can see it.
        let replaced = match (spec.on_existing, resolved) {
            // Deferred resolves to `None`, so there is nothing to replace — the asymmetry `bp` has
            // too: duplicates pile up exactly where the expression does not resolve.
            (OnExisting::Replace, Some(address)) => self.remove_breakpoints_at(address, info.id),
            _ => Vec::new(),
        };

        Ok(BreakpointSet {
            breakpoint: info,
            replaced,
            cut_short,
        })
    }

    /// Creates the breakpoint and gives it its location, bounded — the two steps that must either
    /// both happen or leave nothing behind.
    ///
    /// Returns the guard **un-kept**, so every `?` from here to the end of
    /// [`Self::set_breakpoint_bounded`] removes the half-built breakpoint rather than leaking one
    /// into the session for a caller who was told the call failed.
    fn new_breakpoint(
        &self,
        spec: &BreakpointSpec,
        timeout_ms: u32,
    ) -> Result<(ScopedBreakpoint<'_>, Option<Interruption>), DbgEngError> {
        let kind = match spec.data {
            Some(_) => DEBUG_BREAKPOINT_DATA,
            None => DEBUG_BREAKPOINT_CODE,
        };
        let breakpoint = ScopedBreakpoint::new(self, kind)?;
        let cut_short = match &spec.at {
            BreakpointAt::Address(address) => {
                unsafe { breakpoint.breakpoint.SetOffset(*address) }
                    .map_err(DbgEngError::BreakpointFailed)?;
                None
            }
            BreakpointAt::Expression(expression) => {
                let text =
                    CString::new(expression.as_str()).map_err(|_| DbgEngError::InvalidCommand)?;
                // Same shape as `execute_command_bounded`: open an operation, arm, run, then
                // account for a break by either origin. A request aimed at an earlier operation is
                // invisible to this resolve, which is what the clear that used to stand here was
                // for -- and, unlike the clear, it cannot erase one still on its way.
                let operation = self.begin_operation();
                let watchdog = (timeout_ms > 0).then(|| {
                    let handle = self.interrupt_handle();
                    Watchdog::arm(Duration::from_millis(u64::from(timeout_ms)), move || {
                        let _ = handle.break_in_only();
                    })
                });
                let result = unsafe {
                    breakpoint
                        .breakpoint
                        .SetOffsetExpression(PCSTR::from_raw(text.as_ptr().cast()))
                };
                let by_watchdog = watchdog.is_some_and(Watchdog::disarm);
                // Nothing here waited, so this is the operation's `cut_short_by` rather than a
                // [`WaitOutcome`] — the same rule, read from the only two things a non-pumping
                // bound has.
                let cut_short = operation.cut_short_by(by_watchdog, timeout_ms);
                let interrupted = cut_short.is_some();
                if interrupted {
                    // Consume a break that may still be pending, exactly as the bounded command
                    // path does and for the same reason: the watchdog can raise one as the call
                    // returns, and a flag left set belongs to no operation.
                    let _ = self.interrupted();
                }
                // A break makes the resolve give up part-way, and the engine reports that
                // variously — measured, `Ok(())` with the module left on export symbols. So an
                // error is only propagated when nothing interrupted it; otherwise the breakpoint
                // stands and the record read back below says where it ended up.
                if !interrupted {
                    result.map_err(DbgEngError::BreakpointFailed)?;
                }
                cut_short
            }
        };
        Ok((breakpoint, cut_short))
    }

    /// Removes every breakpoint at `address` except `keep`, reporting the ids actually taken.
    ///
    /// The engine's list is walked by index, so the ids are collected first and removed after: a
    /// removal renumbers the indices under a walk in progress, which would skip the entry that
    /// moved into the slot just vacated.
    ///
    /// **Best-effort, and it reports rather than raises**, because its one caller runs it after the
    /// mutation it exists for has already happened and been armed — see the comment there. A list
    /// that cannot be read means nothing is removed and nothing is claimed; a breakpoint that
    /// cannot be removed is left out of the return, so it stays visible in [`Self::breakpoints`]
    /// instead of being reported as gone.
    fn remove_breakpoints_at(&self, address: u64, keep: u32) -> Vec<u32> {
        let Ok(held) = self.breakpoints() else {
            return Vec::new();
        };
        held.into_iter()
            .filter(|held| held.id != keep && held.address == Some(address))
            .map(|held| held.id)
            .filter(|id| self.remove_breakpoint(*id).is_ok())
            .collect()
    }

    /// Removes the breakpoint with this id — `bc`.
    ///
    /// **An id names a breakpoint only while it exists.** The engine reuses the ids of removed
    /// breakpoints, so an id stored across a removal may by then name a different breakpoint
    /// entirely. Nothing can be checked here that would catch it — an id is the only identity a
    /// breakpoint has — so the rule is a caller's: read an id and use it, do not keep one.
    pub fn remove_breakpoint(&self, id: u32) -> Result<(), DbgEngError> {
        let breakpoint = self.breakpoint_by_id(id)?;
        unsafe { self.control.RemoveBreakpoint2(&*breakpoint) }.map_err(|source| {
            DbgEngError::Context {
                operation: format!("removing breakpoint {id}"),
                source,
            }
        })
        // `breakpoint` is a `ManuallyDrop` and is deliberately not dropped: `RemoveBreakpoint2`
        // destroys the object, so releasing it afterwards is a use-after-free. See
        // [`ScopedBreakpoint::drop`], where that showed up as a dead host process.
    }

    /// Arms or disarms the breakpoint with this id — `be` and `bd`.
    ///
    /// Disabling keeps the breakpoint and its parameters; only `DEBUG_BREAKPOINT_ENABLED` moves.
    pub fn enable_breakpoint(&self, id: u32, enabled: bool) -> Result<(), DbgEngError> {
        let breakpoint = self.breakpoint_by_id(id)?;
        let result = unsafe {
            match enabled {
                true => breakpoint.AddFlags(DEBUG_BREAKPOINT_ENABLED),
                false => breakpoint.RemoveFlags(DEBUG_BREAKPOINT_ENABLED),
            }
        };
        result.map_err(|source| DbgEngError::Context {
            operation: format!(
                "{} breakpoint {id}",
                if enabled { "enabling" } else { "disabling" }
            ),
            source,
        })
    }

    /// The engine's breakpoint object for `id`, borrowed.
    ///
    /// `ManuallyDrop` for the reason given wherever one of these is held: the engine owns the
    /// object and hands out a borrowed interface.
    fn breakpoint_by_id(
        &self,
        id: u32,
    ) -> Result<std::mem::ManuallyDrop<IDebugBreakpoint2>, DbgEngError> {
        let breakpoint = unsafe { self.control.GetBreakpointById2(id) }.map_err(|source| {
            DbgEngError::Context {
                operation: format!("looking up breakpoint {id}"),
                source,
            }
        })?;
        Ok(std::mem::ManuallyDrop::new(breakpoint))
    }

    /// Ensures the engine breaks at the initial (loader) breakpoint. A bare
    /// `DebugCreate` host defaults this event filter to "ignore", so a freshly
    /// launched/attached target would run free and the engine would never establish a
    /// current process/thread (register/stack commands then fail with `0x80040205`).
    fn enable_initial_break(&self) -> Result<(), DbgEngError> {
        // Unguarded on purpose: this runs *before* the target exists, which is exactly the state
        // `refuse_without_a_debuggee` refuses. See [`Self::execute_fixed_command`].
        self.execute_fixed_command("sxe ibp").map(|_| ())
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
        // Before the spawn, so a pid the operating system is about to hand this process cannot
        // still be sitting in the record from an attach that ended. See `prune_processes_that_left`.
        self.prune_processes_that_left();
        self.enable_initial_break()?;
        // What the launched process is told apart from, since the create hands back no pid: see
        // `Arrival`. Taken here rather than at the wait, because by then the process this open is
        // waiting for may already be in the list and would be eliminated as one of its own
        // predecessors.
        let before = self.session_processes().ok();
        let mut wide = to_wide(command_line);
        unsafe {
            self.client.CreateProcessWide(
                0,
                PWSTR::from_raw(wide.as_mut_ptr()),
                DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW,
            )
        }
        .map_err(DbgEngError::OperationFailed)?;

        // `CreateProcessWide` is deferred: the engine doesn't actually spawn the process
        // until the next `WaitForEvent`, and it reads the command-line buffer (`wide`) at
        // that point — so `wide` moves into the guard, which owns it until the wait
        // returns. With the initial-breakpoint filter enabled above, that wait stops at
        // the loader breakpoint.
        self.retain_deferred_input(TargetInput::Wide(wide));
        Ok(PendingTarget::live(self, Arrival::Launched(before)))
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
        // Recorded at the same moment the attach becomes irreversible, and for the same reason
        // this returns a guard: from here on the process is ours to let go of properly, whether
        // or not the break-in wait below ever succeeds. A wait that fails still leaves a debugger
        // attached to somebody else's process.
        self.prune_processes_that_left();
        self.claim_attached(pid);
        // The attach completes during `WaitForEvent`, which breaks the target in.
        Ok(PendingTarget::live(self, Arrival::Attached(pid)))
    }

    /// Opens a crash dump (`.dmp`) or a Time Travel Debugging trace (`.run`).
    /// Call [`Self::wait_for_event`] afterward to finish loading the target.
    pub fn open_dump(&self, path: &str) -> Result<(), DbgEngError> {
        let wide = to_wide(path);
        unsafe {
            self.client
                .OpenDumpFileWide(PCWSTR::from_raw(wide.as_ptr()), 0)
        }
        .map_err(DbgEngError::OperationFailed)?;
        self.forget_the_previous_session();
        Ok(())
    }

    /// Opens a TTD trace (`.run`); alias for [`Self::open_dump`].
    pub fn open_trace(&self, path: &str) -> Result<(), DbgEngError> {
        self.open_dump(path)
    }

    /// Parks an input buffer for the life of the session, so DbgEng can still read it when
    /// it completes a deferred spawn or dial. See [`DebugEngine::deferred_inputs`].
    fn retain_deferred_input(&self, input: TargetInput) {
        self.deferred_inputs.borrow_mut().push(input);
    }

    /// Releases the parked input buffers. Only sound once the session is over: until then
    /// the engine may still owe a deferred spawn or dial that reads them.
    fn release_deferred_inputs(&self) {
        self.deferred_inputs.borrow_mut().clear();
    }

    /// Records that `pid` is a process this engine attached to, so the teardown detaches from it
    /// instead of taking it.
    ///
    /// [`Attachment::Deferred`], because `AttachProcess` joins the process at the next
    /// `WaitForEvent` rather than here; [`Self::prune_processes_that_left`] promotes it once it has
    /// been seen.
    fn claim_attached(&self, pid: u32) {
        self.state
            .attached_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(pid, Attachment::Deferred);
    }

    /// Forgets recorded attachments this session no longer holds.
    ///
    /// **Called by the openers, and it is about pid reuse rather than tidiness.** A pid outlives
    /// the process it named, so an attached process that exits leaves a record that matches
    /// nothing — harmless, since the teardown walks the session and a pid it does not hold cannot
    /// match — right up until the operating system hands that number to a process this engine then
    /// **launches**. That process would be detached and left running by a session that is supposed
    /// to take it. Pruning at the opener is what closes it, and it has to prune rather than clear:
    /// a session can hold an attached process *and* be about to launch one, and clearing would
    /// forget the live attachment and kill somebody else's process to prevent an unlikely one.
    ///
    /// A session with no target holds nothing, so this correctly forgets everything there.
    ///
    /// **It narrows the window rather than closing it, which review asked about and which is
    /// declined on purpose.** `CreateProcessWide` is deferred, so the launched process gets its
    /// pid at the next `WaitForEvent`: an attached process that exits *after* this prune and
    /// whose number is then handed to that launch is still misread. Closing it needs something
    /// identifying the process **instance** rather than its number, and the one that would work is
    /// a retained handle — which also stops Windows reusing the pid at all, so it is the real
    /// answer if this is ever worth closing. It is not yet: reaching it needs an exit inside a
    /// window of milliseconds *and* an immediate reuse of that exact number, and what it costs is
    /// a launched process outliving its session — a stray process, where the bug this whole path
    /// exists for was killing somebody else's. Handle lifetimes across four teardown paths are a
    /// worse risk than that.
    /// **It used to prune the arrival record too, and no longer has one to prune.** That record
    /// was an engine-wide set of `(engine id, system pid)` pairs, and a stale pair was matched
    /// whenever both numbers came back together -- which sounds like a coincidence and was instead
    /// the ordinary shape of detaching a process and attaching to it again: measured on this
    /// engine, detaching engine id 0 and attaching another process hands the freed 0 straight
    /// back, so `presence_of` answered `Arrived` for a target whose initial breakpoint had not
    /// happened. Since dbgscope#136 stage 3 an arrival is *delivered* to a registered open rather
    /// than broadcast into a set, and an entry dies with the guard that made it, so there is no
    /// record for a reused pair to match and nothing here to prune. Only the attachment half is
    /// left, and it is about the teardown decision rather than about an open.
    ///
    /// Here rather than at the departure, because there is nowhere else to put it -- a `.detach`
    /// arrives as raw command text -- and nowhere else it needs to be.
    fn prune_processes_that_left(&self) {
        let Ok(held) = self.session_processes() else {
            return;
        };
        self.note_attachments_present(&held);
        // The same question of the arrival register: a claim on a process that has left must stop
        // excluding the next one to inherit its numbers. See `Arrivals::forget_departed`.
        self.state
            .arrivals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .forget_departed(&held);
        // A pid the session does not hold has either left -- `Joined`, so drop it, which is what
        // this function is for -- or not yet joined, which is `Deferred` and must be kept: it
        // cannot have left a session it has never been in.
        self.state
            .attached_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|pid, state| {
                *state == Attachment::Deferred || held.iter().any(|(_, held)| held == pid)
            });
    }

    /// Promotes every recorded attachment this listing shows to [`Attachment::Joined`].
    ///
    /// **Called wherever the session is listed on the engine's own account**, which is the prune
    /// and the pump. The prune alone is not enough and the failing test says why: an attach
    /// completes at its wait, and nothing lists the session again until the *next* opener prunes --
    /// by which time a `.detach` may have taken the process, leaving a pid that has joined and left
    /// still marked `Deferred` and so kept for ever. The pump lists the session on every stop, so
    /// promoting there closes the gap without a listing of its own.
    fn note_attachments_present(&self, held: &[(u32, u32)]) {
        for (pid, state) in self
            .state
            .attached_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter_mut()
        {
            if held.iter().any(|(_, held)| held == pid) {
                *state = Attachment::Joined;
            }
        }
    }

    /// Forgets every open still waiting on a session that has ended.
    ///
    /// Shared by [`Self::end_session`] and by `Drop`, which tears down inline rather than calling
    /// it -- so this is the one line both have to run and only one of them used to.
    fn forget_pending_opens(&self) {
        self.state
            .arrivals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .forget_all();
    }

    /// Forgets every recorded attach, and every open still waiting on the session being replaced.
    ///
    /// Called when the session ends, and by the openers that **create** a target -- a dump, a
    /// trace, a kernel connection. Those replace the session outright, so a pid recorded against
    /// the previous one is stale, and the one way a stale pid could matter is the one that would
    /// hurt: the operating system reusing it for a process this engine went on to launch, which
    /// would then be detached from and survive a session that is supposed to take it.
    ///
    /// The pending opens go for a narrower reason than the record they replace did. An entry
    /// cannot outlive its guard, so nothing here is about staleness across time; what it is about
    /// is a guard held *across* a session replacement, whose `(engine id, pid)` predicate would
    /// otherwise be evaluated against a session it never asked about. Forgetting the entry leaves
    /// [`Arrivals::presence`] answering [`Presence::Absent`] for it, which is the truth.
    ///
    /// **And it reissues the target identity, which is why that lives here rather than in the
    /// openers.** [`Scope`] and [`ThreadContext`] both carry the identity they were read from and
    /// are refused by an engine that no longer holds it — a check worth nothing if the identity
    /// survives a replacement. It did: only [`Self::end_session`] reissued, so a caller who opened
    /// dump A, saved a context, and opened dump B *through this engine* got the same identity back
    /// and the stale registers were accepted (dbgscope#144). Doing it in the three openers would
    /// have been a fourth thing for the next opener to remember; doing it here makes "the previous
    /// session is gone" mean all of what it says, once.
    fn forget_the_previous_session(&self) {
        // Ordered before the clears only so that a reader meets the invalidation first; nothing
        // observes this function part-way through, since every caller holds `&self`.
        reissue_identity(&self.client);
        self.state
            .attached_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.state
            .arrivals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .forget_all();
    }

    /// Whether this engine holds a live user-mode process it **attached** to rather than
    /// launched — one [`Self::end_session`] will detach from and leave running.
    ///
    /// Exposed so a caller can *say* what its teardown is about to do. The teardown itself needs
    /// no help: `end_session` decides for itself, and so does `Drop`.
    ///
    /// **Asked of the session, not of the record**, and the difference is a wrong sentence rather
    /// than a wrong teardown: an attached process can leave on its own, so a pid recorded here is
    /// not proof the engine still holds it, and a caller reading this to describe what it did
    /// would say "detached and left running" about a session that launched and killed one.
    pub fn attached_to_a_live_process(&self) -> bool {
        let attached = self
            .state
            .attached_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        !attached.is_empty()
            && self
                .session_processes()
                .is_ok_and(|held| held.iter().any(|(_, pid)| attached.contains_key(pid)))
    }

    /// Ends the current debug session without destroying the client, so it can be
    /// reused for another target.
    ///
    /// **What "ending" does to a target depends on where that target came from**, and the two
    /// exceptions are both about not destroying something this engine did not create:
    ///
    /// - a **live kernel** is resumed and actively detached, or it stays frozen at its last break;
    /// - every user-mode process this engine **attached** to is detached first and left running,
    ///   because a passive end destroys the debug port and the kernel then kills the debuggees
    ///   hanging off it (`DebugSetProcessKillOnExit` defaults to true);
    /// - everything else — a dump, a trace, a kernel dump, and any process this engine *launched*
    ///   — goes with the session.
    ///
    /// The first two are **per process**, not per session: DbgEng holds several user-mode targets
    /// at once (`|` lists them), so an engine can hold a service somebody else is running beside a
    /// program it launched itself, and each is let go of on its own terms.
    pub fn end_session(&self) -> Result<TargetLeft, DbgEngError> {
        // The target is going away, so anything cached against it must not be reused for
        // whatever this engine holds next — nor by any other wrapper around this same client,
        // which is why the identity is recorded against the client rather than in this engine.
        reissue_identity(&self.client);
        // A live kernel left halted (at a break) and detached *passively* stays FROZEN —
        // one CPU halted, the rest spinning — because a passive detach never tells the
        // target to run. Resume it and actively detach instead, leaving it running.
        let (left, session_ended, ended) = if self.is_live_kernel() {
            let (resumed, detached) = self.resume_and_detach_live_kernel();
            // **A failed resume is a disposition, not an error.** The session ended either way, so
            // returning `Err` here would tell a caller the teardown failed and leave it no way to
            // learn the one fact it has to act on. `TargetLeft::KernelHalted` is that fact, and the
            // caller can name the remedy -- attach again and `qd`. `Err` stays for a detach that
            // did not happen, which is a session still holding its target.
            let left = match resumed {
                Ok(()) => TargetLeft::KernelRunning,
                Err(_) => TargetLeft::KernelHalted,
            };
            (left, detached.is_ok(), detached)
        } else {
            // Detached one by one *before* the session ends, which is what makes a mixed session
            // come apart correctly: `EndSession` takes one flag for the whole session, so no
            // choice of flag can both keep an attached process and take a launched one. Anything
            // still in the session when the passive end runs is a target this engine created.
            let detached = self.detach_attached_processes();
            let ended = unsafe { self.client.EndSession(DEBUG_END_PASSIVE) }
                .map_err(DbgEngError::OperationFailed);
            (TargetLeft::Unspoken, ended.is_ok(), ended.and(detached))
        };
        // Both of these are the session's, and both are let go of once it is *confirmed* gone.
        //
        // The buffers, because an outstanding deferred spawn or dial dies with the session and
        // nothing can read them afterwards, while a session still live may still owe that read —
        // retaining a few bytes for the life of the engine beats a use-after-free.
        //
        // The pending opens, because an open waiting on a session that has ended is waiting for
        // something that cannot arrive: forgetting the entry leaves `Arrivals::presence` answering
        // `Absent` for a guard still held, which is the truth. This used to be an engine-wide
        // record of every process the session had stopped on, and it had to be cleared here for a
        // sharper reason -- engine process ids are handed out from zero again for the next
        // session, so a pair that outlived this one was matched by a later process that inherited
        // both numbers, which for two `attach_process` calls to the same pid on one engine is the
        // ordinary case rather than a coincidence. Nothing outlives its guard any more, so what is
        // left here is tidiness rather than a hazard. (`detach_attached_processes` already takes
        // the attach record; this is the other half of what a session owns.)
        //
        // **The condition is `EndSession`'s own outcome and not the value this returns**, which
        // are two different facts wherever a detach fails: the `.and` above reports that failure to
        // the caller, and rightly, but a process this engine could not detach from is a process
        // left attached and running — it does not keep the session alive. Gating on the combined
        // result held both releases back on a session that had definitely gone, which for the
        // buffers is a leak and for the opens is a guard left waiting on a session that has gone.
        if session_ended {
            self.release_deferred_inputs();
            self.forget_pending_opens();
        }
        ended.map(|()| left)
    }

    /// Uses the engine's quit path before releasing the session. `SetExecutionStatus(GO)` only
    /// requests execution; following it with `EndSession(ACTIVE_DETACH)` is not the same path as
    /// native KD's `qd`. The former left a 29671 hypervisor unresponsive while reporting success;
    /// the latter recovered it. Keep the fixed command here, behind the typed teardown, rather
    /// than making callers drive execution-control text themselves.
    ///
    /// No event wait: a finite kernel wait is unsupported and an infinite one can park forever.
    /// On failure, passive cleanup releases the session without a second, unverified resume.
    /// The caller then gets `KernelHalted`, even if cleanup itself succeeded.
    fn resume_and_detach_live_kernel(&self) -> (Result<(), DbgEngError>, Result<(), DbgEngError>) {
        let resumed = self.quit_and_detach_target();
        let detached = unsafe { self.client.EndSession(DEBUG_END_PASSIVE) }
            .map_err(DbgEngError::OperationFailed);
        (resumed, detached)
    }

    fn quit_and_detach_target(&self) -> Result<(), DbgEngError> {
        self.refuse_without_a_debuggee()?;
        self.clear_all_breakpoints()?;
        // **Between the clear and the quit, and that placement is the whole of it.** See
        // [`Self::spend_pending_break_ins`]: the clear above has succeeded, so the target holds no
        // breakpoint a drain resume could stop at, and `qd` below has not yet spent the target's
        // one continue. Neither neighbour is incidental — a drain before the clear cannot tell a
        // caller's breakpoint from the break-in it is hunting, and one after `qd` is too late.
        self.spend_pending_break_ins();
        // A fixed literal, but still use the guarded command path: this can reach execution.
        self.execute_command("qd")?;
        require_detached(self.has_target()?)
    }

    /// How long each drain resume gives a leftover break-in to show itself.
    ///
    /// It fires on the *first instruction* of the resume, so this bounds a thing that either
    /// happens at once or not at all rather than budgeting for work. With nothing pending the
    /// target simply runs for this long and is broken back in, which is measurably harmless: a
    /// forced break leaves no artifact of its own.
    const DRAIN_RESUME_MS: u32 = 500;

    /// The fewest resumes a drain will spend, and how many consecutive *free* ones end it.
    ///
    /// **Two in a row, because one is not evidence.** A resume that reaches its deadline says the
    /// target ran that whole window without stopping — but a break-in merely slow to arrive reads
    /// exactly the same, and stopping there leaves it pending for `qd`. Measured by hand against
    /// the hypervisor below: draining once survived 2 detach cycles of 3, with the third freezing
    /// the guest; draining to two consecutive free resumes survived 5 of 5.
    ///
    /// **`DRAIN_ATTEMPTS` is a floor rather than the cap**, which [`Drain::for_processors`] sets
    /// from the target's own processor count. The attempt count keeps a target that breaks on
    /// every resume — its own `int 3` in a loop, say — from making a teardown unbounded, and
    /// [`Self::DRAIN_BUDGET`] bounds the wall clock the same way. Reaching either is not an error:
    /// the quit runs regardless, exactly as it did before any of this.
    const DRAIN_ATTEMPTS: usize = 5;
    const DRAIN_FREE_RUNS: usize = 2;

    /// How long the whole drain may take before the quit goes ahead without it.
    ///
    /// **It bounds the clock where the attempt count bounds the resumes**, and the two are not the
    /// same bound once the cap scales with the processor count: a delivered break returns at once
    /// and costs nothing, while a free run costs [`Self::DRAIN_RESUME_MS`], so a target
    /// alternating between the two spends real time per attempt. A server-class kernel with scores
    /// of processors would otherwise make the teardown long enough to matter to whoever is waiting
    /// on it — including `windbg-mcp`'s supervisor-loss release, which gives the whole teardown
    /// eight seconds.
    const DRAIN_BUDGET: Duration = Duration::from_secs(4);

    /// Spends the stops this target still owes, before `qd` spends its only continue on one.
    ///
    /// **Two things leave one behind, and only the first is about the attach** — which is why
    /// nothing here asks how the session was opened:
    ///
    /// 1. `DEBUG_ENGOPT_INITIAL_BREAK`, described below, leaves one pending host break-in.
    /// 2. **A software breakpoint in code every processor runs is hit by more than one of them**
    ///    before the debugger takes it off, and each of the others' break exceptions is delivered
    ///    on a later resume. Measured 2026-09-21 on a four-processor hypervisor: a `run_to_address`
    ///    that reported `hit` and an empty breakpoint inventory left exactly three, one per other
    ///    processor, each at the breakpoint's own address and on that processor's own stack.
    ///
    /// The second owes nothing to the attach, so gating the drain on the attach shape — which this
    /// did, on [`ClientState::kd_initial_break_attach`] — left it unrun on exactly the path that
    /// needed it most. Measured the same day: that hit followed by a reported-clean detach through
    /// an announcement attach left the four-processor guest unreachable, black at the console, and
    /// a fresh attach found it stopped at the breakpoint's own address. Draining it released the
    /// guest on the same boot with no reset.
    ///
    /// The price of dropping the gate is [`Self::DRAIN_FREE_RUNS`] bounded resumes on a live
    /// kernel that owes nothing — this is the live-kernel quit path and no other — against a
    /// frozen machine when the guess is wrong. A **local** kernel is the one target that used to
    /// be excluded by construction and now is not, and it owes nothing: there is no
    /// `DbgKdContinue` to lose on a machine that was never halted, and a resume is one of the
    /// commands local kernel debugging refuses outright, so its first drain resume errors and the
    /// `Err` arm below ends the loop there.
    ///
    /// **Measured on a Microsoft hypervisor, 2026-09-20.** `DEBUG_ENGOPT_INITIAL_BREAK` leaves a
    /// pending host break-in behind it, and [`Self::absorb_initial_break_artifact`] consumes
    /// exactly *one* with a single `g` — which is right for NT, whose artifact that comment names,
    /// and one short on that target. What is left over is invisible in the attach's result: the
    /// session looks ordinary. It is spent at the worst possible moment instead. `qd` sends one
    /// `DbgKdContinue`, the pending break-in takes it, and the target stops again with **no
    /// debugger attached** — a frozen guest, while the teardown reports a clean release.
    ///
    /// How it was pinned down, because the obvious reading is wrong: a plain attach leaves that
    /// hypervisor halted *on its own* `int 3`, and stepping past it before detaching still froze
    /// the guest — so it is not where the instruction pointer sits. What shows the leftover is a
    /// resume. The first `g` after a completed attach returns **immediately** with the CTRL+BREAK
    /// banner, while every later one runs to its bound and has to be broken in. One pending
    /// break-in, exactly.
    ///
    /// Best-effort throughout and deliberately not a `?`: this sits on a teardown, where a session
    /// that will not close is worse than a resume that did not happen. The quit runs either way.
    fn spend_pending_break_ins(&self) {
        // The target's processors, not this host's. A count that cannot be read falls back to the
        // floor rather than to nothing: an unsized drain still spends the one an INITIAL_BREAK
        // attach owes, which is what this path did for every target before it was sized at all.
        let mut drain = match unsafe { self.control.GetNumberProcessors() } {
            Ok(processors) => Drain::for_processors(processors),
            Err(_) => Drain::default(),
        };
        let started = Instant::now();
        while drain.resume_again() && started.elapsed() < Self::DRAIN_BUDGET {
            match self.execute_and_wait("g", Self::DRAIN_RESUME_MS) {
                Ok(run) => drain.saw(Resumed::of(&run)),
                // The engine refused the resume — a target that has gone, most likely. Nothing
                // left to drain, and nothing to report about it.
                Err(_) => break,
            }
        }
    }

    fn clear_all_breakpoints(&self) -> Result<(), DbgEngError> {
        let count = unsafe { self.control.GetNumberBreakpoints() }
            .map_err(DbgEngError::BreakpointFailed)?;
        for _ in 0..count {
            // Removal compacts the indices. These interfaces are borrowed, and removal destroys
            // the object, so never Release one afterwards (see `remove_breakpoint`).
            let breakpoint = std::mem::ManuallyDrop::new(
                unsafe { self.control.GetBreakpointByIndex2(0) }
                    .map_err(DbgEngError::BreakpointFailed)?,
            );
            unsafe { self.control.RemoveBreakpoint2(&*breakpoint) }
                .map_err(DbgEngError::BreakpointFailed)?;
        }
        Ok(())
    }

    /// Detaches from every user-mode process this engine **attached** to, leaving each running,
    /// and forgets them. Processes this engine created are left in the session for the passive
    /// end to take.
    ///
    /// `bc *` first, for a sharper version of the kernel reason: an `int3` this engine patched in
    /// stays patched in a process that goes on running, and the first thread to reach it takes an
    /// exception with no debugger left to handle it. A target that dies minutes after the session
    /// ended is worse than one that never survived it, because nothing connects the two. It is
    /// session-wide, so it also clears breakpoints in a process about to be taken — which costs
    /// nothing, since that process is about to be taken.
    ///
    /// No resume beside it, which is the one step the kernel path has and this does not: the
    /// kernel needs telling to run because its detach only disconnects, while
    /// `DetachCurrentProcess` resumes the threads the debug port suspended.
    ///
    /// **Best-effort per process, and the session ends either way.** This sits on a teardown that
    /// a client disconnect and a lease expiry both run, where a session that will not close is
    /// worse than a debuggee that was killed. It still **reports** the first failure, because a
    /// caller told "released" would have no reason to go and look at a process that had just been
    /// taken by the passive end instead.
    fn detach_attached_processes(&self) -> Result<(), DbgEngError> {
        let attached = std::mem::take(
            &mut *self
                .state
                .attached_processes
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        if attached.is_empty() {
            return Ok(());
        }
        let _ = self.execute_command("bc *");
        let mut failure = None;
        // Walked by engine id rather than by the recorded pid, because `SetCurrentProcessId` takes
        // the engine's id and a pid this engine no longer holds — the process exited, a raw
        // `.detach` took it — is simply not in this list. So a stale entry costs nothing and needs
        // no separate check.
        for (id, pid) in self.session_processes()? {
            if !attached.contains_key(&pid) {
                continue;
            }
            if let Err(e) = unsafe {
                self.system_objects()?
                    .SetCurrentProcessId(id)
                    .and_then(|()| self.client.DetachCurrentProcess())
            } {
                failure.get_or_insert(DbgEngError::OperationFailed(e));
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// The user-mode processes in this session, as `(engine id, system pid)`.
    ///
    /// The engine id is what `SetCurrentProcessId` takes and the pid is what a caller knows a
    /// process by, and they are not the same number — `GetProcessIdsByIndex` is the one call that
    /// answers both, which is why this returns pairs rather than either alone.
    ///
    /// **Public because it is the only stable answer to "which processes is this session
    /// debugging".** [`Self::current_process_system_id`] answers a different question that reads
    /// like the same one: it is the *selection*, which DbgEng moves on its own at a child-process
    /// event and which `|Ns` moves by hand, neither of which changes what the session holds. A
    /// caller comparing two readings to notice a target being swapped wants this one; one
    /// reporting where the debugger is pointing wants that one.
    pub fn session_processes(&self) -> Result<Vec<(u32, u32)>, DbgEngError> {
        // An engine with no debuggee holds no processes, and answering that rather than asking is
        // not a shortcut: `GetNumberProcesses` fails `E_UNEXPECTED` ("Catastrophic failure") in
        // that state — measured — which would turn "the program had already finished" into a
        // failed teardown. `has_target` is the one call that answers reliably there; see its docs.
        if !self.has_target()? {
            return Ok(Vec::new());
        }
        let system = self.system_objects()?;
        let count =
            unsafe { system.GetNumberProcesses() }.map_err(|source| DbgEngError::Context {
                operation: "counting the processes in this session".into(),
                source,
            })? as usize;
        let mut ids = vec![0u32; count];
        let mut pids = vec![0u32; count];
        unsafe {
            system.GetProcessIdsByIndex(
                0,
                count as u32,
                Some(ids.as_mut_ptr()),
                Some(pids.as_mut_ptr()),
            )
        }
        .map_err(|source| DbgEngError::Context {
            operation: "listing the processes in this session".into(),
            source,
        })?;
        Ok(ids.into_iter().zip(pids).collect())
    }

    /// `IDebugSystemObjects` off this engine's client.
    fn system_objects(&self) -> Result<IDebugSystemObjects, DbgEngError> {
        self.client.cast().map_err(|source| DbgEngError::Context {
            operation: "querying IDebugSystemObjects".into(),
            source,
        })
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
            // `get_mut` rather than `borrow_mut`: `drop` has `&mut self`, so the borrow is
            // checked at compile time and this path cannot panic on one.
            std::mem::forget(std::mem::take(self.deferred_inputs.get_mut()));
            return;
        }
        // Don't leave a live kernel frozen at a break if we're torn down without an
        // explicit end_session (e.g. the process exits): resume + actively detach.
        if self.is_live_kernel() {
            // The *detach*'s answer, matching what `end_session` gates on: a resume that did not
            // take leaves the guest halted, which is a thing to report and not a session still
            // holding its target -- and there is nobody to report it to on this path anyway.
            let (_, detached) = self.resume_and_detach_live_kernel();
            if detached.is_ok() {
                self.forget_pending_opens();
            }
            return;
        }
        // And don't take somebody else's process down with us — the same asymmetry as the kernel
        // above, handled in the same place and for the same reason: a teardown that is nobody's
        // call to make still has to leave a target this engine did not create alive. Before the
        // end rather than instead of it: what this detaches is only the processes this engine
        // attached to, and the session still has to be ended for the rest.
        let _ = self.detach_attached_processes();
        // Best-effort teardown; ignore errors (e.g. when no session is active).
        let ended = unsafe { self.client.EndSession(DEBUG_END_PASSIVE) };
        // The session's pending opens go with it, exactly as `end_session` does it and gated on
        // the same fact -- `EndSession`'s own outcome. Since the register is per *client*, a guard
        // held by another wrapper outlives this drop, and one left registered against a session
        // that has ended is first in line to claim the next launch's stop through that wrapper,
        // leaving the new guard to time out on a target that stopped. Raised in review on
        // dbgscope#139; `Drop` tears down inline rather than calling `end_session`, so it did not
        // inherit that line.
        if ended.is_ok() {
            self.forget_pending_opens();
        }
    }
}

/// Which initial-break wait completes a [`PendingTarget`].
enum WaitKind<'a> {
    /// User-mode launch/attach: finite `WaitForEvent`s until the open registered here has been
    /// delivered its target's stop.
    Live(Registered<'a>),
    /// Kernel attach: the bounded INFINITE wait plus its INITIAL_BREAK bookkeeping.
    KernelBreakIn,
    /// Explicit opt-in; the observer is removed when this pending attach is dropped.
    KernelAnnouncement(kernel_attach::AnnouncementGuard<'a>),
}

/// One open's entry in the session's arrival register, live for as long as this exists.
///
/// **Registered by the opener rather than by the wait**, which is what makes an outside pump able
/// to complete a guard that is still held: [`PendingTarget`] documents driving the engine yourself
/// as a thing to do, and until the entry exists there is nobody for a stop to be delivered to.
///
/// **Forgotten on drop, and that is the whole of the lifecycle** the record it replaces needed
/// pruning, clearing and a review round each for. An entry cannot outlive the open that made it,
/// so there is no stale arrival for a reused engine id or a reused pid to match.
struct Registered<'a> {
    engine: &'a DebugEngine,
    id: ArrivalId,
}

impl Drop for Registered<'_> {
    fn drop(&mut self) {
        self.engine
            .state
            .arrivals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .forget(self.id);
    }
}

/// The user-mode process a live open is waiting to see join the session and stop.
///
/// **One `WaitForEvent` is one *event*, and not necessarily this target's.** The spawn a
/// `CreateProcessWide` defers is realised inside that wait, but so is everything else the session
/// is holding, and an engine that already has a target can return from the wait on *that* target's
/// event — measured (dbgscope#128): an `AttachProcess` break-in whose injected thread is slow to be
/// scheduled lands a whole wait late, and the `launch_process` that follows spends its single wait
/// on it. The launch then reported success with its process absent from the session, which is what
/// made a test fail on its own guard rather than on the property it was written for.
///
/// So the wait pumps instead, which is sound because the event is queued rather than lost:
/// `examples/deferred_arrival.rs` under CPU load came up short 3 times in 40 rounds and the
/// missing process was there on the *next* wait every time, never later than that.
///
/// **A launch is identified by elimination and an attach by name**, because `CreateProcessWide`
/// hands back no pid — the process does not exist yet — while `AttachProcess` is given one. Naming
/// the process is only half of it: what ends the wait is that process having **stopped**, which is
/// the weaker claim membership is not — a process is registered when its create event is
/// processed and its initial break comes later. That is what [`Arrivals`] delivers, and taking it
/// from the pump that observed it rather than reading `GetLastEventInformation` in the moment is
/// the part that took three rounds of review to get right: the last event is one session-wide slot,
/// so any rule built on the reading alone answers the same way for a target still coming and for
/// one that stopped before this guard was waited on.
///
/// **The elimination used to be ambiguous for two launches pending at once**, where the first
/// arrival is new to both snapshots and so ended both waits — including, since the ask precedes
/// the first wait, without waiting at all. It was documented as accepted, because the fix as it
/// then had to be built cost more than the ambiguity: telling the launches apart needed the engine
/// to *record* which arrivals earlier waits had claimed, which meant new engine-wide state,
/// cleared everywhere a session is replaced and pruned for pid reuse the way
/// `prune_processes_that_left` was — and there a stale claim makes a legitimate launch wait out
/// `LIVE_WAIT_MS` and fail.
///
/// dbgscope#136 stage 3 removes most of it, and removes that cost with it. An arrival is delivered
/// to a registered open ([`Arrivals`]) and **claimed** by it, so the second launch is still waiting
/// when the next one comes; and because an entry cannot outlive the guard that made it, there is no
/// stale claim to prune or clear. The record whose lifecycle made the fix expensive was the thing
/// the fix would have joined. A guard that finishes and is dropped hands its claim to the opens
/// still waiting ([`Arrivals::forget`]), so the two live guards and the delivered-then-dropped case
/// are both exact.
///
/// **What is left is a launch abandoned before it is delivered anything**, and it is dbgscope#141
/// rather than this change: dropping such a guard takes a `Waiting` entry out of the register and
/// leaves no exclusion, so the process the deferred `CreateProcessWide` still produces is new to
/// the *next* launch's snapshot and is claimed by it. Keeping the entry is not simply the fix —
/// nothing would ever retire one whose launch failed to start (`deferred_arrival` arm C: an image
/// that does not exist fails inside the wait), and it would then take the next launch's process
/// and time that guard out instead. A wrong `Ok` for a wrong timeout is a trade rather than a fix,
/// and it wants deciding on its own.
#[derive(Debug)]
enum Arrival {
    /// A process this engine launched: one the session did not hold when the launch was issued and
    /// that this engine did not attach to. The attach half of that is what keeps a launch and an
    /// attach pending together from satisfying each other.
    ///
    /// `None` when the snapshot could not be read, which leaves the wait as it was — a
    /// postcondition that cannot be evaluated must not be asserted.
    Launched(Option<Vec<(u32, u32)>>),
    /// A process this engine attached to, known by the pid the caller named.
    Attached(u32),
}

/// Whether the target a live open is waiting for has joined the session and stopped yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    /// In the session, and this engine has been seen to stop on it.
    Arrived,
    /// In the session, and not yet seen to stop. Worth pumping for, and **not** worth reporting as
    /// a missing target at the bound: a process is registered when its create event is processed
    /// and its initial break comes later, so this is as much "on its way" as it is "stopped while
    /// nobody was recording".
    Listed,
    /// Not held by this session — including a session holding nothing at all, which is an answer
    /// and not a failure to ask.
    Absent,
    /// **Not answerable**, which is only ever the ask itself failing: `has_target` unreadable,
    /// the process list unreadable, or a launch with no snapshot to diff its arrival against.
    /// An empty session is [`Self::Absent`], not this. It ends the wait where a single
    /// `WaitForEvent` used to end it, rather than pumping, because a probe that failed is no
    /// evidence the target is missing.
    Unknown,
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
/// # use dbgscope::dbgeng::DebugEngine;
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
///
/// **Experimental announcement attach is an exception:** its scoped observer is removed when
/// this guard is dropped. The transport claim is not cancelled, but an abandoned guard no longer
/// requests a break. Call `wait()` directly; do not substitute another output-capturing operation.
#[must_use = "the target was created but never waited for; call `wait()` to reach the initial break"]
pub struct PendingTarget<'a> {
    engine: &'a DebugEngine,
    kind: WaitKind<'a>,
}

impl<'a> PendingTarget<'a> {
    fn new(engine: &'a DebugEngine, kind: WaitKind<'a>) -> Self {
        Self { engine, kind }
    }

    /// A live open, registered with the session so a pump from anywhere can deliver its target's
    /// stop to it.
    fn live(engine: &'a DebugEngine, arrival: Arrival) -> Self {
        let id = engine
            .state
            .arrivals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .register(arrival);
        Self::new(engine, WaitKind::Live(Registered { engine, id }))
    }

    /// Waits for the target's initial break, completing the open.
    ///
    /// For a kernel attach this can block **without bound** when the target never connects;
    /// see [`DebugEngine::attach_kernel`]. User-mode waits are bounded by `LIVE_WAIT_MS` — for the
    /// whole open rather than per wait, since a live open pumps until the event it stopped on is
    /// its own target's (see [`Arrival`]) instead of returning on the first event to arrive.
    pub fn wait(self) -> Result<(), DbgEngError> {
        // Borrowed rather than moved out, so the registration is forgotten when this guard drops
        // at the end of the call -- on the error paths as much as the successful one.
        match &self.kind {
            WaitKind::Live(registered) => self.engine.wait_for_live_target(registered),
            WaitKind::KernelBreakIn => self.engine.wait_for_kernel_break_in(),
            WaitKind::KernelAnnouncement(observer) => observer.wait(),
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

/// Reads one breakpoint's every field through the getters, for [`DebugEngine::breakpoints`] and
/// for the read-back at the end of [`DebugEngine::set_breakpoint_bounded`].
///
/// One function rather than two so a setter cannot report a breakpoint in a shape the lister would
/// never produce. `where` names the breakpoint in an error — an index for a walk, "just set" for
/// the read-back — since a failure here has no id to quote yet.
fn breakpoint_info(
    breakpoint: &IDebugBreakpoint2,
    location: &str,
) -> Result<BreakpointInfo, DbgEngError> {
    let id = unsafe { breakpoint.GetId() }.map_err(|source| DbgEngError::Context {
        operation: format!("reading the id of breakpoint {location}"),
        source,
    })?;
    let mut kind = 0u32;
    let mut _processor = 0u32;
    let kind = match unsafe { breakpoint.GetType(&mut kind, &mut _processor) } {
        Ok(()) => BreakpointKind::from_engine(kind),
        Err(_) => BreakpointKind::Other(DEBUG_ANY_ID),
    };
    let flags = unsafe { breakpoint.GetFlags() }.unwrap_or(0);
    // A deferred breakpoint answers `GetOffset` with an error, and one whose expression resolved
    // to nothing answers with `DEBUG_INVALID_OFFSET`. Both mean "no address yet", and neither
    // means address zero.
    let address = match unsafe { breakpoint.GetOffset() } {
        Ok(offset) if offset != DEBUG_INVALID_OFFSET => Some(offset),
        _ => None,
    };
    let expression =
        read_engine_string(|buffer, size| unsafe { breakpoint.GetOffsetExpression(buffer, size) })
            .ok()
            .filter(|text| !text.is_empty());
    let command = read_engine_string(|buffer, size| unsafe { breakpoint.GetCommand(buffer, size) })
        .ok()
        .filter(|text| !text.is_empty());
    let thread = unsafe { breakpoint.GetMatchThreadId() }
        .ok()
        .filter(|id| *id != DEBUG_ANY_ID);
    // Asked only of a data breakpoint. A code breakpoint has no watched region, and the engine is
    // under no obligation to answer meaningfully for one — so a size and an access read off it
    // would be an invention rather than a reading.
    let data = (kind == BreakpointKind::Data)
        .then(|| {
            let mut size = 0u32;
            let mut access = 0u32;
            unsafe { breakpoint.GetDataParameters(&mut size, &mut access) }
                .ok()
                .map(|()| DataWatch {
                    access: DataAccess::from_engine(access),
                    size,
                })
        })
        .flatten();
    Ok(BreakpointInfo {
        id,
        kind,
        address,
        expression,
        command,
        thread,
        data,
        enabled: flags & DEBUG_BREAKPOINT_ENABLED != 0,
        deferred: flags & DEBUG_BREAKPOINT_DEFERRED != 0,
        one_shot: flags & DEBUG_BREAKPOINT_ONE_SHOT != 0,
        pass_count: unsafe { breakpoint.GetPassCount() }.unwrap_or(0),
        passes_remaining: unsafe { breakpoint.GetCurrentPassCount() }.unwrap_or(0),
    })
}

/// A breakpoint that is removed when this guard drops, unless [`Self::keep`] has said otherwise —
/// on success, on an early `?`, and on an unwind alike.
///
/// **One lifetime story for every breakpoint this crate creates**, which is the point of it being
/// the only wrapper left. Two used to disagree: this one removed on drop, and a public
/// `Breakpoint` did not remove at all unless a caller remembered to, having first handed them a
/// breakpoint that was disabled and pointed at address zero. Everything a caller keeps is now
/// named by **id** instead ([`DebugEngine::remove_breakpoint`],
/// [`DebugEngine::enable_breakpoint`]), which is what `bc`/`be`/`bd` take and what
/// [`BreakpointInfo`] already reports — and an id cannot dangle.
///
/// The two uses are opposite and both wanted. [`DebugEngine::run_to_address`] takes one and lets
/// it drop, because a breakpoint that outlived that call would stop a later unrelated `g`;
/// [`DebugEngine::set_breakpoint_bounded`] builds one and keeps it, because the caller asked for a
/// breakpoint. What they share is that a failure part-way through configuration removes it, rather
/// than leaving a half-built breakpoint in a session whose caller was told the call failed.
struct ScopedBreakpoint<'a> {
    control: &'a IDebugControl4,
    breakpoint: std::mem::ManuallyDrop<IDebugBreakpoint2>,
    /// Set by [`Self::keep`] once the breakpoint is fully configured and belongs to the caller.
    keep: bool,
}

impl<'a> ScopedBreakpoint<'a> {
    /// Creates an unconfigured breakpoint of `kind`, already guarded.
    ///
    /// It is created **disabled and at address zero** — the engine's documented initial state, not
    /// a choice made here — so every caller has to give it a location before it means anything,
    /// and arming it is the last step rather than the first.
    fn new(engine: &'a DebugEngine, kind: u32) -> Result<Self, DbgEngError> {
        let breakpoint = unsafe { engine.control.AddBreakpoint2(kind, DEBUG_ANY_ID) }
            .map_err(DbgEngError::BreakpointFailed)?;
        // Wrapped before it is configured, so a failure below still removes it.
        Ok(Self {
            control: &engine.control,
            breakpoint: std::mem::ManuallyDrop::new(breakpoint),
            keep: false,
        })
    }

    /// Adds an enabled code breakpoint at `address`, removed when the guard drops.
    fn at(engine: &'a DebugEngine, address: u64) -> Result<Self, DbgEngError> {
        let scoped = Self::new(engine, DEBUG_BREAKPOINT_CODE)?;
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

    /// Hands the breakpoint to the session: it survives this guard's drop.
    fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for ScopedBreakpoint<'_> {
    fn drop(&mut self) {
        if !self.keep {
            // Best-effort: a failure here has nowhere to go, and this runs on unwind paths where
            // panicking would abort the process.
            unsafe {
                let _ = self.control.RemoveBreakpoint2(&*self.breakpoint);
            }
        }
        // `breakpoint` is deliberately not dropped, on **either** path. DbgEng owns breakpoint
        // objects and hands out borrowed interfaces, so releasing one is a call on an object this
        // code does not own — and where `RemoveBreakpoint2` has just destroyed it, letting the
        // generated wrapper `Release()` it afterwards dereferences freed memory, observed as an
        // access violation that took down the host process rather than as an error return.
        // `ManuallyDrop` is what stops both.
    }
}

// ---- MIRI AND THE DECODER ------------------------------------------------
//
// The twenty-eight tests below that decode an **x86** encoding are `#[cfg_attr(miri, ignore)]`,
// and this is
// the reason. `iced-x86`'s byte reader casts an integer to a pointer (`mk_read_xx`, an
// `unsafe { ptr::read_unaligned(data_ptr as *const _) }`), so the pointer it produces carries no
// provenance and Stacked Borrows refuses to retag it — inside the crate's own handler tables, on
// every decode. Measured three ways on nightly, one test each:
//
// | `MIRIFLAGS`                                             | result |
// |---------------------------------------------------------|--------|
// | the workflow's (Stacked Borrows)                         | fail   |
// | ... plus `-Zmiri-permissive-provenance`                  | fail   |
// | ... plus `-Zmiri-tree-borrows` instead                   | **pass** |
//
// So it is an aliasing-model disagreement about a dependency's internals rather than a defect in
// this crate: nothing on that path is `unsafe` code of ours — `decode_operation` is safe Rust
// calling a safe API — and there is nothing here to fix.
//
// Excluding these tests rather than moving the whole job to Tree Borrows is deliberate. This job
// exists for *this* crate's unsafe code, which `miri.yml` names as `dbgeng.rs` and `pool/**`
// decoding raw kernel structures out of byte slices, and switching the model would relax the
// check for all of that in order to cover a dependency's tables that we cannot change either way.
// Excluding costs no coverage of any `unsafe` block in this crate.
//
// If iced-x86 ever needs Miri coverage here, the answer is a second job with `-Zmiri-tree-borrows`
// rather than weakening this one. And a new decoding test that forgets the attribute turns `main`
// red, which is how this one was found — a self-correcting omission, not a silent one. It found
// the next one too, on the merge of dbgscope#171: `decode_instruction`'s own test forgot it, the
// PR was green because this job runs on `main`, and the count in the first line of this note had
// been stale since long before either.
//
// **The attribute is per *architecture*, not per decoding test**, which is the distinction that
// note did not have to make until A64 arrived. `crate::arm64` is this crate's own safe Rust and
// reaches no dependency at all, so a test that decodes only A64 keeps its Miri coverage and
// should — it is exactly the kind of code this job is for. A test covering both has to be split
// rather than ignored whole, which is why `decode_instruction` has two.

#[cfg(test)]
mod tests {
    use windows::Win32::System::Diagnostics::Debug::Extensions::{
        DEBUG_CLASS_UNINITIALIZED, DEBUG_CLASS_USER_WINDOWS, DEBUG_KERNEL_CONNECTION,
        DEBUG_KERNEL_DUMP, DEBUG_KERNEL_FULL_DUMP, DEBUG_KERNEL_LOCAL, DEBUG_STATUS_BREAK,
        DEBUG_STATUS_IGNORE_EVENT, DEBUG_STATUS_NO_CHANGE, DEBUG_STATUS_OUT_OF_SYNC,
        DEBUG_STATUS_RESTART_REQUESTED, DEBUG_STATUS_TIMEOUT, DEBUG_STATUS_WAIT_INPUT,
        DEBUG_USER_WINDOWS_PROCESS, DEBUG_USER_WINDOWS_SMALL_DUMP, DEBUG_VALUE_0,
        DEBUG_VALUE_INVALID, DEBUG_VALUE_TYPES,
    };

    use super::*;

    /// The two predicates over `GetDebuggeeType`'s pair, against the qualifiers DbgEng defines.
    ///
    /// The boundary is the whole of it: `DEBUG_KERNEL_SMALL_DUMP` is the *lowest dump* qualifier,
    /// so the live connections are the ones strictly below it. Reading it as "less than or equal"
    /// would call a small kernel dump a live connection, and a live connection is the one target
    /// whose `WaitForEvent` must be INFINITE — a finite one there answers `E_NOTIMPL`, so the
    /// mistake surfaces as a teardown that will not run rather than as a wrong label.
    #[test]
    fn test_a_kernel_dump_is_a_kernel_target_and_not_a_live_one() {
        let kind = |class, qualifier| DebuggeeType { class, qualifier };

        let live = kind(DEBUG_CLASS_KERNEL, DEBUG_KERNEL_CONNECTION);
        assert!(live.is_kernel() && live.is_live_kernel());
        let local = kind(DEBUG_CLASS_KERNEL, DEBUG_KERNEL_LOCAL);
        assert!(local.is_kernel() && local.is_live_kernel());

        for qualifier in [
            DEBUG_KERNEL_SMALL_DUMP,
            DEBUG_KERNEL_DUMP,
            DEBUG_KERNEL_FULL_DUMP,
        ] {
            let dump = kind(DEBUG_CLASS_KERNEL, qualifier);
            assert!(dump.is_kernel(), "{qualifier} is a kernel target");
            assert!(!dump.is_live_kernel(), "{qualifier} is a dump, not a link");
        }

        // A user-mode target is neither, whatever its qualifier — including the process
        // qualifier, which is numerically below `DEBUG_KERNEL_SMALL_DUMP` and would pass the
        // comparison on its own.
        for qualifier in [DEBUG_USER_WINDOWS_PROCESS, DEBUG_USER_WINDOWS_SMALL_DUMP] {
            let user = kind(DEBUG_CLASS_USER_WINDOWS, qualifier);
            assert!(!user.is_kernel() && !user.is_live_kernel());
        }

        // An engine holding nothing says so, and says it as a class rather than as a failure.
        let nothing = kind(DEBUG_CLASS_UNINITIALIZED, 0);
        assert!(!nothing.is_kernel() && !nothing.is_live_kernel());

        // The pair compares whole, which is what a caller watching for a target being swapped
        // underneath it reads: a live kernel and a kernel dump are both kernel targets and are
        // not the same target.
        assert_ne!(live, kind(DEBUG_CLASS_KERNEL, DEBUG_KERNEL_FULL_DUMP));
        assert_ne!(
            kind(DEBUG_CLASS_USER_WINDOWS, DEBUG_USER_WINDOWS_PROCESS),
            kind(DEBUG_CLASS_USER_WINDOWS, DEBUG_USER_WINDOWS_SMALL_DUMP)
        );
    }

    #[test]
    fn test_quit_must_release_the_target_before_reporting_resume() {
        assert!(require_detached(false).is_ok());
        assert!(matches!(
            require_detached(true),
            Err(DbgEngError::IncompleteKernelDetach)
        ));
    }

    fn ran(cut_short: Option<Interruption>, target_gone: bool) -> CommandRun {
        CommandRun {
            output: String::new(),
            cut_short,
            target_gone,
        }
    }

    /// Runs a drain over a scripted sequence of resumes, as [`DebugEngine::spend_pending_break_ins`]
    /// does over real ones, and answers with the state it stopped in.
    ///
    /// The whole loop rather than one step, because the rule under test *is* the loop: how many
    /// resumes it spends, and on what evidence it stops.
    fn drain_over(resumes: &[Resumed]) -> Drain {
        let mut drain = Drain::default();
        let mut next = resumes.iter();
        while drain.resume_again() {
            match next.next() {
                Some(resumed) => drain.saw(*resumed),
                None => panic!(
                    "the drain asked for resume {} and the script had none",
                    drain.spent + 1
                ),
            }
        }
        drain
    }

    /// **One free run is not evidence, and this is the rule that was measured.**
    ///
    /// A break-in merely slow to arrive reads exactly like a target running freely, so a drain
    /// that stopped at the first free resume left it pending for `qd`. Measured by hand on the
    /// hypervisor: draining once survived 2 detach cycles of 3, with the third freezing the guest;
    /// draining to two consecutive free resumes survived 5 of 5.
    #[test]
    fn test_one_free_resume_does_not_end_the_break_in_drain() {
        let mut drain = Drain::default();
        drain.saw(Resumed::OnABreak);
        drain.saw(Resumed::Freely);
        assert!(
            drain.resume_again(),
            "stopping on a single free resume is the version that froze the guest"
        );
        drain.saw(Resumed::Freely);
        assert!(!drain.resume_again(), "two in a row is what ends it");
        assert_eq!(drain.delivered, 1, "one break-in was spent, not three");
    }

    /// A delivered break-in starts the count again: the two free runs have to be *consecutive*,
    /// or a drain could stop having seen one free resume before a break and one after it.
    #[test]
    fn test_a_break_in_between_two_free_resumes_restarts_the_count() {
        let drain = drain_over(&[
            Resumed::Freely,
            Resumed::OnABreak,
            Resumed::Freely,
            Resumed::Freely,
        ]);
        assert_eq!(drain.spent, 4);
        assert_eq!(drain.delivered, 1);
    }

    /// **A drain has to outlast one stop per processor**, which is what a breakpoint in code every
    /// processor runs leaves behind: measured on four, three further stops after the hit, one per
    /// other processor. So the loop must still be resuming after `processors - 1` breaks and one
    /// free run, or the last one is handed to `qd` and the guest freezes.
    ///
    /// Six counts rather than the lab's four, because four is the number the old fixed cap of five
    /// happened to fit — three breaks plus two free runs is exactly five — so a test written at
    /// the lab's topology passes against the bug it is for.
    #[test]
    fn test_a_drain_outlasts_one_stop_per_processor() {
        // Fed one resume at a time rather than through `drain_over`, because what this asks is
        // whether the drain is *still* resuming part-way through a script — which is a state to
        // read, not a loop to run to the end.
        let feed = |processors: u32, resumes: &[Resumed]| {
            let mut drain = Drain::for_processors(processors);
            for resumed in resumes {
                assert!(
                    drain.resume_again(),
                    "{processors} processors: the drain gave up after {} of {} resumes with the \
                     script still owing",
                    drain.spent,
                    drain.attempts
                );
                drain.saw(*resumed);
            }
            drain
        };
        for processors in [1u32, 2, 4, 5, 8, 64] {
            let owed = usize::try_from(processors).unwrap() - 1;
            let mut script = vec![Resumed::OnABreak; owed];
            script.push(Resumed::Freely);
            let part_way = feed(processors, &script);
            assert!(
                part_way.resume_again(),
                "{processors} processors owe {owed} stops, and one free run after them is not \
                 evidence the last was delivered"
            );
            script.push(Resumed::Freely);
            let drained = feed(processors, &script);
            assert_eq!(drained.delivered, owed, "every owed stop is spent");
            assert!(
                !drained.resume_again(),
                "two consecutive free runs end it, whatever the processor count"
            );
        }
    }

    /// The floor holds under the sizing: a one- or two-processor target still gets the five
    /// resumes the hypervisor drain was measured with, rather than the two or three its own
    /// processor count would buy.
    #[test]
    fn test_a_small_target_still_gets_the_measured_floor() {
        for processors in [0u32, 1, 2, 3] {
            assert_eq!(
                Drain::for_processors(processors).attempts,
                DebugEngine::DRAIN_ATTEMPTS,
                "{processors} processors must not shrink the drain below its floor"
            );
        }
        assert_eq!(
            Drain::for_processors(4).attempts,
            DebugEngine::DRAIN_ATTEMPTS + 1,
            "and above the floor it is one per processor plus the free runs"
        );
    }

    /// The attempt cap keeps a target that breaks on every resume — its own `int 3` in a loop,
    /// say — from turning a teardown into an unbounded one.
    #[test]
    fn test_a_target_that_breaks_every_time_still_ends_the_drain() {
        let drain = drain_over(&[Resumed::OnABreak; DebugEngine::DRAIN_ATTEMPTS]);
        assert_eq!(drain.spent, DebugEngine::DRAIN_ATTEMPTS);
        assert_eq!(drain.delivered, DebugEngine::DRAIN_ATTEMPTS);
    }

    /// **A host's interrupt is not a free run.** It says the caller asked, and nothing about
    /// whether a break-in was pending — so counting it as one is how a drain stops early and hands
    /// the leftover back to `qd`.
    #[test]
    fn test_a_host_interrupt_is_not_counted_as_a_free_resume() {
        let mut drain = Drain::default();
        drain.saw(Resumed::Freely);
        drain.saw(Resumed::OnRequest);
        assert!(
            drain.resume_again(),
            "an interrupt and a deadline are not two free runs"
        );
        assert_eq!(drain.free_runs, 1, "and it does not reset the count either");
        assert_eq!(drain.delivered, 0, "nor is it a break-in delivered");
    }

    /// A target that goes during the drain ends it there: nothing is owed by a target that is
    /// gone, and the quit has nothing left to protect.
    #[test]
    fn test_a_target_that_goes_ends_the_break_in_drain() {
        let drain = drain_over(&[Resumed::Gone]);
        assert_eq!(drain.spent, 1);
        assert_eq!(drain.delivered, 0);
    }

    /// The two facts the engine contributes, read the one way round that matters: a run that lost
    /// its target may *also* have been cut short, and which of the two happened decides whether
    /// another resume is worth anything.
    #[test]
    fn test_a_resume_that_lost_its_target_is_read_as_gone_however_it_ended() {
        assert_eq!(Resumed::of(&ran(None, true)), Resumed::Gone);
        assert_eq!(
            Resumed::of(&ran(Some(Interruption::Deadline { after_ms: 500 }), true)),
            Resumed::Gone,
            "a deadline on a run whose target went is not evidence the target ran freely"
        );
        assert_eq!(
            Resumed::of(&ran(Some(Interruption::Deadline { after_ms: 500 }), false)),
            Resumed::Freely
        );
        assert_eq!(
            Resumed::of(&ran(Some(Interruption::OnRequest), false)),
            Resumed::OnRequest
        );
        assert_eq!(Resumed::of(&ran(None, false)), Resumed::OnABreak);
    }

    /// An exit deadline is not an observed stop, regardless of GetExecutionStatus afterward.
    /// This measures a local process, not KDNET or the target's independent liveness.
    #[test]
    #[cfg(not(miri))]
    fn test_exit_watchdog_reports_a_deadline_not_an_observed_stop() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        e.launch_process("ping.exe -n 30 127.0.0.1")
            .expect("launch failed");
        unsafe { e.control.SetExecutionStatus(DEBUG_STATUS_GO) }.unwrap();
        {
            let operation = e.begin_operation();
            assert_eq!(
                e.pump(Bound::WatchdogExit(100), &operation).unwrap(),
                WaitOutcome::Deadline
            );
        }
        e.end_session().expect("test process cleanup failed");
    }

    #[test]
    #[cfg(not(miri))]
    fn test_quit_detach_refuses_an_engine_without_a_target() {
        let _debuggee = one_debuggee();
        let engine = DebugEngine::new();
        assert!(matches!(
            engine.quit_and_detach_target(),
            Err(DbgEngError::NoDebuggee)
        ));
    }

    // Exercises the fixed command and breakpoint cleanup on a disposable local process.
    // It does not establish hypervisor resume; that needs an independent guest-health check.
    #[test]
    #[cfg(not(miri))]
    fn test_quit_detach_removes_breakpoints_and_leaves_an_attached_process_alive() {
        let _debuggee = one_debuggee();
        let mut target = a_process_to_attach_to();
        let pid = target.id();
        let result = std::panic::catch_unwind(|| {
            let engine = DebugEngine::new();
            engine.attach_process(pid).expect("attach failed");
            let pc = engine
                .instruction_pointer()
                .expect("no instruction pointer");
            for _ in 0..2 {
                engine
                    .set_breakpoint(&BreakpointSpec::code(BreakpointAt::Address(pc)))
                    .expect("set breakpoint failed");
            }
            assert_eq!(engine.breakpoints().expect("list failed").len(), 2);
            engine.clear_all_breakpoints().expect("clear failed");
            assert!(engine.breakpoints().expect("list failed").is_empty());
            engine
                .set_breakpoint(&BreakpointSpec::code(BreakpointAt::Address(pc)))
                .expect("set breakpoint failed");
            engine.quit_and_detach_target().expect("quit failed");
            assert!(!engine.has_target().expect("status failed"));
            assert_eq!(exit_code_of(pid), Some(STILL_RUNNING));
            engine.end_session().expect("cleanup failed");
            assert_eq!(exit_code_of(pid), Some(STILL_RUNNING));
        });
        let _ = target.kill();
        let _ = target.wait();
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    /// [`decode_instruction`] reports the bytes the instruction occupies, not the buffer it was
    /// handed.
    ///
    /// An x86 caller cannot know an instruction's length before decoding it -- that is most of why
    /// they are calling -- so they pass whatever they have. `[0x90, 0xcc]` came back as a `nop`
    /// carrying `90cc`, and a walker stepping by that length stepped over the `int3` behind it.
    /// Raised on dbgscope#171; every length below is iced's own reading of the same bytes.
    ///
    /// The A64 half is a test of its own, so that it keeps running under Miri -- see the note
    /// above.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_a_standalone_decode_reports_only_the_bytes_it_consumed() {
        // One `nop`, then an `int3` that is not part of it.
        let nop = decode_instruction(&[0x90, 0xcc], 0x1000, InstructionSet::Amd64);
        assert_eq!(nop.mnemonic, "nop");
        assert_eq!(nop.bytes, "90");
        // And stepping by that length reaches the second one rather than past it, which is the
        // property the field exists to support.
        let int3 = decode_instruction(&[0xcc], 0x1001, InstructionSet::Amd64);
        assert_eq!(int3.mnemonic, "int3");
        // **Not "always the first byte"**: `48 8b 05 <disp32>` is a seven-byte
        // `mov rax,[rip+disp]`, with a trailing `nop` here that is again not part of it.
        let load = decode_instruction(
            &[0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00, 0x90],
            0x1000,
            InstructionSet::Amd64,
        );
        assert_eq!(load.mnemonic, "mov");
        assert_eq!(load.bytes, "488b0500000000");
    }

    /// The same rule on A64, which is a **separate test so that Miri still runs it**.
    ///
    /// `crate::arm64` is this crate's own safe Rust and reaches no dependency, so there is nothing
    /// here for the iced-x86 exclusion to be about -- and this job exists for exactly this kind of
    /// code. Folding these assertions into the test above would have ignored them on the one
    /// architecture the exclusion has no claim over.
    #[test]
    fn test_a_standalone_a64_decode_reports_one_word() {
        // A64 is fixed-width, so a caller with two words gets the first.
        // `a9bf7bfd  stp fp,lr,[sp,#-0x10]!` followed by `d503201f  nop`.
        let stp = decode_instruction(
            &[0xa9, 0xbf, 0x7b, 0xfd, 0xd5, 0x03, 0x20, 0x1f],
            0x1000,
            InstructionSet::Arm64,
        );
        assert_eq!(stp.mnemonic, "stp");
        assert_eq!(stp.bytes, "a9bf7bfd");
        // **Bytes that decode to nothing still report what the caller passed.** There is no extent
        // to report, the caller's buffer is the only honest answer, and `Flow::Unknown` beside it
        // already says nothing was claimed -- so this is a deliberate exception rather than the
        // rule leaking.
        let unknown = decode_instruction(&[0x0f, 0x0b], 0x1000, InstructionSet::Other(0x1234));
        assert_eq!(unknown.bytes, "0f0b");
        assert_eq!(unknown.flow, Flow::Unknown);
    }

    /// **An arrival is delivered to one open, in registration order, and claimed.**
    ///
    /// The four rules the register exists for, asserted where they live rather than through an
    /// engine -- so they run under Miri, and so a mutation to one fails the assertion written for
    /// it rather than whichever end-to-end test happened to notice.
    #[test]
    fn test_an_arrival_is_delivered_to_one_open_and_claimed() {
        let none = HashSet::new();
        let mut arrivals = Arrivals::default();
        // Two launches pending at once, both with the same empty snapshot: the ambiguity
        // `Arrival` used to document as accepted.
        let first = arrivals.register(Arrival::Launched(Some(Vec::new())));
        let second = arrivals.register(Arrival::Launched(Some(Vec::new())));

        arrivals.deliver((0, 100), &none);
        assert_eq!(
            arrivals.presence(first, &[(0, 100)], &none),
            Presence::Arrived,
            "the first-registered open did not get the first arrival"
        );
        assert_ne!(
            arrivals.presence(second, &[(0, 100)], &none),
            Presence::Arrived,
            "both launches were given one arrival, which is the ambiguity this removes"
        );

        // **A claimed process is offered to nobody**, which is a different rule from the one
        // above: a target stops more than once in a session, and the second stop on a process
        // already delivered must not be handed to an open waiting for a different one.
        arrivals.deliver((0, 100), &none);
        assert_ne!(
            arrivals.presence(second, &[(0, 100)], &none),
            Presence::Arrived,
            "a repeat stop on an already-delivered process was given to the next open in line"
        );

        // The next genuine arrival is the second open's.
        arrivals.deliver((1, 200), &none);
        assert_eq!(
            arrivals.presence(second, &[(0, 100), (1, 200)], &none),
            Presence::Arrived,
            "the second launch was not given the arrival nobody had claimed"
        );

        // An entry dies with its guard, and an id that names nothing is `Absent` -- which is what
        // a guard held across a session replacement reads, and the whole of the lifecycle the
        // record this replaces needed a prune and two clears for.
        arrivals.forget(first);
        assert_eq!(
            arrivals.presence(first, &[(0, 100)], &none),
            Presence::Absent,
            "a forgotten open still answered about a process"
        );
    }

    /// **A claim stops excluding once its process leaves**, or a reattach is refused its own stop.
    ///
    /// Engine ids are handed back immediately -- measured, detaching id 0 and attaching another
    /// process hands the freed 0 straight back -- so a `.detach` and a reattach of the same pid
    /// reproduce a `(engine id, pid)` pair exactly. That is the reuse the record this replaced was
    /// pruned for, and it arrives here from the other side: a stale entry in the old set made a
    /// new open read `Arrived` for a target that had not stopped, where a stale *claim* makes it
    /// read the opposite. Raised in review on dbgscope#139.
    #[test]
    fn test_a_claim_stops_excluding_once_its_process_leaves() {
        let none = HashSet::new();
        let mut arrivals = Arrivals::default();
        let held_open = arrivals.register(Arrival::Launched(Some(Vec::new())));
        arrivals.deliver((0, 100), &none);
        assert_eq!(
            arrivals.presence(held_open, &[(0, 100)], &none),
            Presence::Arrived,
            "the launch was not given its process, so nothing here is under test"
        );

        // The process leaves -- a raw `.detach`, or an exit -- and the same pair comes back.
        arrivals.forget_departed(&[]);
        let reattach = arrivals.register(Arrival::Attached(100));
        arrivals.deliver((0, 100), &none);
        assert_eq!(
            arrivals.presence(reattach, &[(0, 100)], &none),
            Presence::Arrived,
            "the reattach was refused its own stop as another open's claim, so its wait() times \
             out on a target sitting in front of it"
        );

        // And the open that held the departed claim no longer says it arrived, which is what the
        // old prune did and is the honest answer about a process that is gone.
        assert_ne!(
            arrivals.presence(held_open, &[(0, 100)], &none),
            Presence::Arrived,
            "an open whose target left the session still reports it as arrived"
        );
    }

    /// **An open whose process left does not go back to waiting**, which the test above cannot
    /// say because its held open is a launch.
    ///
    /// A launch is kept off a reattached process by an unrelated rule — a pending attach keeps its
    /// process from a pending launch — so that pairing passes whether the departed claim is a
    /// tombstone or a clear. Put to *two attaches* it does not: an [`Arrival::Attached`] open wants
    /// any stop bearing its pid, the finished one is registered first, and [`Arrivals::deliver`]
    /// offers in registration order. Cleared back to waiting it takes the reattach's own stop and
    /// the new guard times out on a target sitting in front of it. Raised in review on
    /// dbgscope#139, as the regression that retiring the stale claim opened.
    ///
    /// The first phase is the same open with nobody beside it, reached through the raw hatch
    /// (`.detach` and an attach that registers nothing). That is what pins the answer
    /// [`Arrivals::presence`] gives a departed claim: with a second open in the register the pair
    /// is spoken for and the reply is `Absent` either way, so `Listed` — keep waiting, your target
    /// is here — needs asking where there is no one else.
    #[test]
    fn test_a_departed_claim_does_not_reopen_the_open_that_held_it() {
        let none = HashSet::new();

        // Alone: the pair comes back through the raw hatch, with no second open to hold it off.
        let mut arrivals = Arrivals::default();
        let alone = arrivals.register(Arrival::Attached(100));
        arrivals.deliver((0, 100), &none);
        arrivals.forget_departed(&[]);
        assert_eq!(
            arrivals.presence(alone, &[(0, 100)], &none),
            Presence::Absent,
            "an open that finished reported a reattached process as its own still to come, so its \
             wait() pumps for an initial break that has already happened"
        );

        let mut arrivals = Arrivals::default();
        let finished = arrivals.register(Arrival::Attached(100));
        arrivals.deliver((0, 100), &none);
        assert_eq!(
            arrivals.presence(finished, &[(0, 100)], &none),
            Presence::Arrived,
            "the attach was not given its process, so nothing here is under test"
        );

        // It leaves -- a raw `.detach`, or an exit -- and the same pid is attached again, which is
        // where the engine hands the freed engine id straight back.
        arrivals.forget_departed(&[]);
        let reattach = arrivals.register(Arrival::Attached(100));
        arrivals.deliver((0, 100), &none);
        assert_eq!(
            arrivals.presence(reattach, &[(0, 100)], &none),
            Presence::Arrived,
            "the reattach's own stop went to the open whose process had left, so its wait() times \
             out on a target sitting in front of it"
        );
        assert_eq!(
            arrivals.presence(finished, &[(0, 100)], &none),
            Presence::Absent,
            "an open that finished and whose target then left took somebody else's process rather \
             than staying finished"
        );
    }

    /// **An attach that is finished with a pid does not keep a launch from it.**
    ///
    /// The exclusion beside it — a pending attach keeps its process from a pending launch — reads
    /// the *registration*, which says which pid the open named and not whether it can still have
    /// it. An attach whose process has left is done, and Windows reuses pids: leaving it to exclude
    /// means a later launch that inherits the number is refused its own stop by an open that will
    /// never claim anything again, nobody else wants it, and that guard times out with its target
    /// stopped in front of it. Raised in review on dbgscope#139.
    ///
    /// The attach's guard is deliberately still held here. Dropping it takes the entry out of the
    /// register and the question with it, which is a different test.
    #[test]
    fn test_a_finished_attach_does_not_keep_a_launch_from_a_reused_pid() {
        let none = HashSet::new();
        let mut arrivals = Arrivals::default();
        let attach = arrivals.register(Arrival::Attached(100));
        arrivals.deliver((0, 100), &none);
        arrivals.forget_departed(&[]);

        // A launch begun after that, and the pid comes back around on its process.
        let launch = arrivals.register(Arrival::Launched(Some(Vec::new())));
        arrivals.deliver((1, 100), &none);
        assert_eq!(
            arrivals.presence(launch, &[(1, 100)], &none),
            Presence::Arrived,
            "the launch was refused its own stop by an attach that is finished with the pid, so \
             nobody claimed it and the guard times out on a target in front of it"
        );
        assert_eq!(
            arrivals.presence(attach, &[(1, 100)], &none),
            Presence::Absent,
            "the finished attach took a process it did not attach to"
        );
    }

    /// **An arrival is read against what the session holds, not believed on its own.**
    ///
    /// [`Arrivals::forget_departed`] runs from the openers, so a session that opens nothing more
    /// never prunes: a claim outlives its process by however long that is, which is unbounded. The
    /// shape this replaced could not have the bug — `presence_of` located the process in the
    /// session first and asked whether it had stopped second — and answering from the claim alone
    /// let `Arrived` outlive the target, so a guard's `wait()` returned `Ok(())` for a process the
    /// caller could not read. Raised in review on dbgscope#139.
    ///
    /// The second process is not decoration: an engine holding nothing at all is refused by
    /// `presence_of` before the register is asked, so a session kept alive by somebody else is
    /// the only way this question reaches here.
    #[test]
    fn test_an_arrived_claim_is_read_against_what_the_session_holds() {
        let none = HashSet::new();
        let mut arrivals = Arrivals::default();
        let open = arrivals.register(Arrival::Attached(100));
        arrivals.deliver((0, 100), &none);
        assert_eq!(
            arrivals.presence(open, &[(0, 100), (1, 200)], &none),
            Presence::Arrived,
            "the attach was not given its process, so nothing here is under test"
        );

        // It leaves, and nothing has pruned -- the other process keeps the session alive, so no
        // opener has run and `forget_departed` has not been called.
        assert_eq!(
            arrivals.presence(open, &[(1, 200)], &none),
            Presence::Absent,
            "a claim on a process that has left the session still reported it as arrived, so the \
             guard's wait() returns Ok for a target the caller cannot read"
        );
    }

    /// **An abandoned launch keeps its place in the queue; an abandoned attach does not.**
    ///
    /// dbgscope#141. Dropping a launch guard does not un-queue its `CreateProcessWide`, so that
    /// process still arrives — new to the next launch's snapshot, because it did not exist when
    /// that snapshot was taken. Removing the entry therefore hands it to the next launch.
    ///
    /// The attach half is the other rule and is asserted here rather than assumed, because it is
    /// the one that says why this is not "keep every abandoned entry": an attach names a pid, and
    /// the engine's own `attached_processes` already covers one whose guard has gone — which is
    /// what [`Pending::wants`] reads that set for. Keeping the entry as well would leave
    /// [`Arrivals::presence`] answering `Listed` for an id nobody holds.
    #[test]
    fn test_an_abandoned_launch_keeps_its_place_and_an_attach_does_not() {
        let none = HashSet::new();
        let mut arrivals = Arrivals::default();

        let abandoned = arrivals.register(Arrival::Launched(Some(Vec::new())));
        arrivals.forget(abandoned);
        let mine = arrivals.register(Arrival::Launched(Some(Vec::new())));

        // The abandoned launch's own process, arriving after its guard has gone.
        arrivals.deliver((0, 100), &none);
        assert_ne!(
            arrivals.presence(mine, &[(0, 100)], &none),
            Presence::Arrived,
            "the next launch was given the abandoned launch's process, so its wait() returns for a \
             target it never asked for"
        );

        // And its own still reaches it, or the entry is refusing arrivals wholesale.
        arrivals.deliver((1, 200), &none);
        assert_eq!(
            arrivals.presence(mine, &[(0, 100), (1, 200)], &none),
            Presence::Arrived,
            "the next launch was refused a process nobody else was entitled to"
        );

        // An abandoned attach is removed: `attached_processes` covers it, and a kept entry would
        // answer `Listed` for an id nobody holds.
        let attach = arrivals.register(Arrival::Attached(300));
        arrivals.forget(attach);
        assert_eq!(
            arrivals.presence(attach, &[(2, 300)], &none),
            Presence::Absent,
            "an abandoned attach was kept in the register, where the engine's own attachment record \
             is what covers it"
        );

        // And a launch whose wait ended saying nothing is coming is discarded rather than kept,
        // or it survives to take the *next* launch's stop — the failure keeping an abandoned entry
        // exists to prevent, reached from the other side. Raised in review on dbgscope#143.
        let timed_out = arrivals.register(Arrival::Launched(Some(Vec::new())));
        arrivals.discard(timed_out);
        let after = arrivals.register(Arrival::Launched(Some(Vec::new())));
        arrivals.deliver((3, 400), &none);
        assert_eq!(
            arrivals.presence(after, &[(3, 400)], &none),
            Presence::Arrived,
            "a launch whose wait timed out kept its place in the queue and took the next launch's \
             process"
        );
    }

    /// **A claim is inherited by every open still waiting, not handed along one at a time.**
    ///
    /// Put to *three* launches, because with two "every remaining open" and "the next one" are the
    /// same set — so a handoff written as a chain passes every other test here. Raised in review on
    /// dbgscope#139 as a non-transitive handoff, where the second launch finishing would forward
    /// its own claim and drop the only record of the one it had inherited. It does not, because the
    /// first [`Arrivals::forget`] gave the third launch a copy of its own; nothing pinned that
    /// until now.
    ///
    /// The last two steps are the other half: the exclusion is *targeted*, so a genuinely new
    /// process still reaches the open that is waiting. Without them a register that refused
    /// everything would pass.
    #[test]
    fn test_a_claim_is_inherited_by_every_open_still_waiting() {
        let none = HashSet::new();
        let mut arrivals = Arrivals::default();
        let first = arrivals.register(Arrival::Launched(Some(Vec::new())));
        let second = arrivals.register(Arrival::Launched(Some(Vec::new())));
        let third = arrivals.register(Arrival::Launched(Some(Vec::new())));

        arrivals.deliver((0, 100), &none);
        arrivals.forget(first);
        arrivals.deliver((1, 200), &none);
        arrivals.forget(second);

        // Both targets stopping again, which is what every later break in either of them is.
        let held = [(0, 100), (1, 200)];
        arrivals.deliver((0, 100), &none);
        arrivals.deliver((1, 200), &none);
        assert_ne!(
            arrivals.presence(third, &held, &none),
            Presence::Arrived,
            "the third launch was given a process one of its predecessors had already been given, \
             so its wait() returns Ok for a target that never stopped"
        );

        // And its own arrival still reaches it.
        let held = [(0, 100), (1, 200), (2, 300)];
        arrivals.deliver((2, 300), &none);
        assert_eq!(
            arrivals.presence(third, &held, &none),
            Presence::Arrived,
            "the third launch was refused a process nobody else had been given, so an inheritance \
             is refusing arrivals wholesale rather than the ones it names"
        );
    }

    /// **A claim outlives the open that made it, for as long as anything is still waiting.**
    ///
    /// The first launch is delivered its process and then finishes, which takes its entry -- and
    /// with it the only record that the process was spoken for. Its target's *next* genuine stop
    /// is then claimed by nobody, and is absent from the second launch's snapshot because it did
    /// not exist when that snapshot was taken, so it is delivered to the second launch, whose
    /// `wait()` returns `Ok` for a process that never stopped. Raised in review on dbgscope#139,
    /// where the ambiguity this stage closes turned out to be closed only while both guards were
    /// held.
    ///
    /// **Not a lifecycle creeping back in**, which is the thing to check rather than take on
    /// trust: the claim is inherited by the opens that exist at that moment and goes when they do,
    /// where the record this replaced lived for the whole session and needed a prune and two
    /// clears. The last assertion is that half -- once nothing is pending, nothing is remembered.
    #[test]
    fn test_a_claim_outlives_the_open_that_made_it() {
        let none = HashSet::new();
        let mut arrivals = Arrivals::default();
        let first = arrivals.register(Arrival::Launched(Some(Vec::new())));
        let second = arrivals.register(Arrival::Launched(Some(Vec::new())));

        arrivals.deliver((0, 100), &none);
        arrivals.forget(first);

        // The same process stopping again, which is what every later break in its target is.
        arrivals.deliver((0, 100), &none);
        assert_ne!(
            arrivals.presence(second, &[(0, 100)], &none),
            Presence::Arrived,
            "a process the first launch had been given was handed to the second once the first \
             guard was gone, so its wait() returns Ok for a target that never stopped"
        );

        // And the inheritance goes when the opens that hold it do.
        arrivals.forget(second);
        let third = arrivals.register(Arrival::Launched(Some(Vec::new())));
        arrivals.deliver((0, 100), &none);
        assert_eq!(
            arrivals.presence(third, &[(0, 100)], &none),
            Presence::Arrived,
            "an open registered after everything else had finished inherited a claim that should \
             have gone with them, which is the lifecycle this shape exists not to have"
        );
    }

    /// **A pending attach's process is not claimed by a pending launch**, or an open registered
    /// first takes the arrival the other one named.
    ///
    /// A launch is identified by elimination, so the process an attach is waiting for is new to
    /// the launch's snapshot and looks like the launch's own. Reading the engine's
    /// `attached_processes` covered that and is kept, but it is per wrapper where the register is
    /// per client -- so the register asks itself as well, which is exact and travels.
    #[test]
    fn test_a_pending_attach_keeps_its_process_from_a_pending_launch() {
        let none = HashSet::new();
        let mut arrivals = Arrivals::default();
        // Registered first, so without the rule it would take whatever arrived.
        let launch = arrivals.register(Arrival::Launched(Some(Vec::new())));
        let attach = arrivals.register(Arrival::Attached(200));

        arrivals.deliver((0, 200), &none);
        assert_ne!(
            arrivals.presence(launch, &[(0, 200)], &none),
            Presence::Arrived,
            "the launch claimed the process a pending attach had named"
        );
        assert_eq!(
            arrivals.presence(attach, &[(0, 200)], &none),
            Presence::Arrived,
            "the attach did not get its own process"
        );
    }

    /// **The engine does not cross threads and the handle does**, which is the whole of this
    /// crate's threading model and is now a property of the types rather than a sentence.
    ///
    /// dbgscope#136 stage 4 deleted `unsafe impl Send`/`Sync for DebugEngine`. They asserted the
    /// opposite of what [`InterruptHandle`]'s own doc says — `SetInterrupt` is the one DbgEng call
    /// safe from any thread *because the rest of the engine is single-thread-affine* — and neither
    /// carried a safety comment, because neither could have been given a true one.
    ///
    /// **Asserted rather than left to the absence of an `unsafe impl`**, since re-adding one is a
    /// single line that compiles, reads as a fix for whatever error it silences, and puts the
    /// engine back on threads it cannot take. `Send` is checked as well as `Sync`: a move is the
    /// same claim as a share one step weaker, and equally unsupported.
    ///
    /// The negative half needs the inherent-method trick, because Rust has no `T: !Send`: an
    /// inherent `impl` is preferred to a trait one during method resolution, so `CAN` is reached
    /// only when the bound holds and the blanket trait answers for everything else. Needs no
    /// engine, so it runs under Miri.
    #[test]
    fn test_the_engine_does_not_cross_threads_and_the_handle_does() {
        struct Ask<T>(std::marker::PhantomData<T>);
        trait Cannot {
            const CAN: bool = false;
        }
        impl<T> Cannot for Ask<T> {}
        impl<T: Send> Ask<T> {
            const CAN: bool = true;
        }
        struct AskShared<T>(std::marker::PhantomData<T>);
        trait CannotShare {
            const CAN: bool = false;
        }
        impl<T> CannotShare for AskShared<T> {}
        impl<T: Sync> AskShared<T> {
            const CAN: bool = true;
        }

        assert!(
            !<Ask<DebugEngine>>::CAN,
            "DebugEngine is Send again, so an engine can be moved to a thread that is not the one \
             it is affine to"
        );
        assert!(
            !<AskShared<DebugEngine>>::CAN,
            "DebugEngine is Sync again, so two threads can make concurrent &self calls into an \
             engine that cannot take them"
        );

        // And the one affordance that is meant to cross, or the watchdogs and every host that
        // stops a runaway command have no way to reach the engine at all.
        assert!(
            <Ask<InterruptHandle>>::CAN,
            "InterruptHandle is no longer Send"
        );
        assert!(
            <AskShared<InterruptHandle>>::CAN,
            "InterruptHandle is no longer Sync"
        );
    }

    /// **A request names an operation, and only that operation can be charged with it.**
    ///
    /// This is dbgscope#135 half A as a value rather than as a race. The old shape was an
    /// engine-wide `AtomicBool` that six operations cleared as they opened, so *whose* request it
    /// was could not be asked — a request lodged for the operation running was indistinguishable
    /// from one left over by its predecessor, and the clear was how the difference was papered
    /// over. `BreakScope` is the whole of the fix and none of it needs an engine, so this runs
    /// under Miri too.
    #[test]
    fn test_a_break_request_names_the_operation_it_is_for() {
        let mut scope = BreakScope::default();

        // Nothing running: a break would stop nobody, and filing one would leave it for whatever
        // came next -- the "erased or left standing" pair, from the other end.
        assert_eq!(scope.innermost(), None, "an idle scope named an operation");

        let first = scope.begin();
        assert_eq!(scope.innermost(), Some(first));
        scope.record(first);
        assert!(scope.take(first), "the operation asked for did not see it");
        assert!(
            !scope.take(first),
            "a request was taken twice, so it could be charged to two operations"
        );

        // The successor sees nothing of its predecessor's, which is what makes the clear at each
        // operation's head unnecessary rather than merely absent.
        scope.record(first);
        scope.end(first);
        let second = scope.begin();
        assert!(
            !scope.take(second),
            "a request filed against {first:?} was answered for {second:?}"
        );
        scope.end(second);
        assert!(
            scope.running.is_empty() && scope.asked.is_empty(),
            "closing every operation left {scope:?} behind"
        );
    }

    /// **Operations nest, and a break belongs to the innermost.**
    ///
    /// Not hypothetical: `wait_for_kernel_break_in` holds one across
    /// `absorb_initial_break_artifact`, which runs a whole `execute_and_wait` -- so before this
    /// there was an inner operation clearing the outer one's request as a matter of course, which
    /// is #135 half A reached from inside the crate rather than by a host.
    ///
    /// A single slot would answer the first two assertions and fail the third; a `bool` could not
    /// express any of them.
    #[test]
    fn test_a_nested_operation_does_not_take_its_parents_request() {
        let mut scope = BreakScope::default();
        let outer = scope.begin();
        scope.record(outer);

        let inner = scope.begin();
        assert_eq!(
            scope.innermost(),
            Some(inner),
            "a break raised now would stop the inner operation, so it must be filed against it"
        );
        assert!(
            !scope.take(inner),
            "the inner operation was handed the outer one's request"
        );

        scope.end(inner);
        assert_eq!(
            scope.innermost(),
            Some(outer),
            "the outer operation did not resume when the inner one ended"
        );
        assert!(
            scope.take(outer),
            "the outer operation's request did not survive an inner operation"
        );
        scope.end(outer);
    }

    /// **A request the engine hands out is scoped to what is running when it is asked for**, which
    /// is the half of the fix that lives on the engine rather than in the bookkeeping.
    ///
    /// Asserted through [`DebugEngine::begin_operation`] and [`Operation`] rather than on
    /// `BreakScope` directly, because the guard's `Drop` is what makes "nothing left standing" a
    /// property of every path rather than a line each of them has to remember.
    ///
    /// No debuggee: `SetInterrupt` is not called here, so this is the bookkeeping seen through the
    /// engine's own API and nothing that needs a target.
    #[test]
    #[cfg(not(miri))]
    fn test_an_operations_request_dies_with_it() {
        // Even without a target, dropping this client ends the process-wide session. Keep it
        // serialized with the live-debuggee tests that share this process under `cargo test`.
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        {
            let operation = e.begin_operation();
            e.state
                .breaks
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .record(operation.id);
            // Deliberately not taken: an operation that ends without reading its request is the
            // ordinary case on the paths where a break arrives too late to end anything.
        }
        let scope = e.state.breaks.lock().unwrap_or_else(|err| err.into_inner());
        assert!(
            scope.running.is_empty() && scope.asked.is_empty(),
            "an operation that never read its request left {scope:?} for the next one"
        );
    }

    /// **A request nobody read takes the engine's pending break with it**, or the `SetInterrupt`
    /// behind it stops whatever runs next with nothing to explain it.
    ///
    /// An operation accepts requests for slightly longer than it reads them -- everything from its
    /// last `took_break_request` to its guard dropping -- and that window cannot be closed from
    /// this side, because whether the engine thread has a read left is not knowable to the calling
    /// thread. What *can* be done is what every other site in this crate already does when a break
    /// belongs to no operation: drain it. `Operation::drop` does that, and only when it is
    /// discarding a record nobody read.
    ///
    /// **Paired against a control**, or the assertion is unfalsifiable: `GetInterrupt` is itself a
    /// consuming read, so "reads `false`" needs a case in the same test that reads `true` to say
    /// the probe works at all. That control is the first half -- a request filed against nothing,
    /// which no guard discards and no drain touches.
    ///
    /// Ignored for the reason the other `GetInterrupt` tests are: it needs a live debuggee.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 test_a_discarded_request`
    #[test]
    #[cfg(not(miri))]
    #[ignore = "needs a live debuggee; run manually with --ignored"]
    fn test_a_discarded_request_drains_the_engines_pending_break() {
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c exit").expect("launch failed");

        // Control: nothing running, so nothing discards a record and nothing drains.
        let filed = e.interrupt_handle().interrupt().expect("interrupt failed");
        assert_eq!(
            filed,
            BreakRequest::NothingRunning,
            "an engine between operations filed the request as {filed:?}"
        );
        assert!(
            e.interrupted().expect("GetInterrupt failed"),
            "the engine holds no pending request, so this test cannot tell a drain from a no-op"
        );

        // The case: filed against an operation that closes without reading it.
        {
            let operation = e.begin_operation();
            let filed = e.interrupt_handle().interrupt().expect("interrupt failed");
            assert_eq!(
                filed,
                BreakRequest::Raised {
                    operation: operation.id
                },
                "the request was not filed against the operation that was running"
            );
        }
        assert!(
            !e.interrupted().expect("GetInterrupt failed"),
            "an operation closed on a request nobody read and left the engine's own break pending, \
             so the next operation is stopped by it with nothing to say why"
        );

        let _ = e.end_session();
    }

    /// **A bounded read answers exactly what an unbounded one does**, and what the extra calls cost.
    ///
    /// Reading in pieces is only invisible if it is: the same bytes, and nothing reported cut short
    /// for a read that finished. The timing is the other half — [`READ_CHUNK_BYTES`] and
    /// [`DebugEngine::read_memory_bounded`] both quote it, and a figure quoted in prose has to come
    /// from somewhere that can be re-run.
    ///
    /// **Not a performance gate.** It prints the two times rather than asserting a ratio between
    /// them: the number is an observation about one machine and one target, and a threshold here
    /// would fail on a slower host for no defect. What it asserts is the equivalence, which is the
    /// property. A regression that made chunking *expensive* — a sleep, a lock per chunk — shows up
    /// in the printed figure, which is what it is printed for.
    ///
    /// **Run it `--release` when quoting it**, which the doc comments that quote it say. A debug
    /// `Vec::resize` fills a buffer an element at a time, so the unbounded read's own allocation
    /// measures at five times its optimised cost and the comparison becomes one between profiles
    /// rather than between designs.
    ///
    /// Ignored: needs a live target; see the note by the other live-debuggee tests.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 test_a_bounded_read_costs_little`
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs a live debuggee; run manually with --ignored"]
    fn test_a_bounded_read_costs_little_against_an_unbounded_one() {
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");

        // Its own image: mapped all the way down, and large enough to be the megabyte-scale read
        // the bound exists for. A heap range would be neither reliably.
        let ntdll = e
            .modules()
            .expect("modules failed")
            .into_iter()
            .find(|module| module.name.to_ascii_lowercase().contains("ntdll"))
            .expect("the target has no ntdll to read");
        let size = (ntdll.size as usize).min(1024 * 1024);
        assert!(
            size > 16 * READ_CHUNK_BYTES,
            "ntdll is {size} bytes here, which is too few chunks to measure"
        );

        // Warmed, so the figures compare two reads of the same cached range rather than the first
        // read of it against the second.
        let _ = e
            .read_memory(ntdll.base, size)
            .expect("ntdll's image did not read whole");

        let at = Instant::now();
        let whole = e
            .read_memory(ntdll.base, size)
            .expect("unbounded read failed");
        let unbounded = at.elapsed();

        let at = Instant::now();
        let pieces = e
            .read_memory_bounded(ntdll.base, size, 60_000)
            .expect("bounded read failed");
        let bounded = at.elapsed();

        assert_eq!(
            pieces.cut_short, None,
            "a read that finished well inside a 60s budget reported itself cut short"
        );
        assert_eq!(
            pieces.bytes, whole,
            "reading in pieces did not produce the bytes one call does"
        );

        println!(
            "{size} bytes in {} chunks: one call {unbounded:?}, chunked {bounded:?}",
            size.div_ceil(READ_CHUNK_BYTES)
        );

        let _ = e.end_session();
    }

    /// A reader that fills every byte with a function of **its own address**, and records what it
    /// was asked for.
    ///
    /// The address-derived fill is what makes the assembled buffer testable: a `read_chunked` that
    /// dropped a chunk, repeated one, or wrote it at the wrong offset produces bytes that no
    /// longer match the range, where a constant fill would look identical either way.
    fn recording_reader(
        calls: &RefCell<Vec<(u64, usize)>>,
    ) -> impl FnMut(u64, &mut [u8]) -> Result<usize, DbgEngError> + '_ {
        move |at, into| {
            calls.borrow_mut().push((at, into.len()));
            for (offset, byte) in into.iter_mut().enumerate() {
                *byte = at.wrapping_add(offset as u64) as u8;
            }
            Ok(into.len())
        }
    }

    /// What [`recording_reader`] must have produced for `size` bytes from `address`.
    fn expected_bytes(address: u64, size: usize) -> Vec<u8> {
        (0..size)
            .map(|offset| address.wrapping_add(offset as u64) as u8)
            .collect()
    }

    /// **A bounded read stops between chunks, keeps what it had, and says why there is no more.**
    ///
    /// The three halves of [`MemoryRead`]'s contract in one case, asserted over a fake reader so
    /// they run under Miri and so the stop can be placed exactly rather than raced for: a real
    /// deadline on a real target either fires between two chunks nobody chose or does not fire at
    /// all.
    ///
    /// The bytes are compared against the whole prefix rather than counted, because the count
    /// alone passes for a reader whose chunks were assembled out of order — the one failure
    /// reading in pieces can have that a single `ReadVirtual` cannot.
    #[test]
    fn test_a_bounded_read_stops_between_chunks_and_keeps_what_it_had() {
        const BASE: u64 = 0x1_0000;
        let calls = RefCell::new(Vec::new());
        let polls = RefCell::new(0usize);
        let read = read_chunked(
            BASE,
            4 * READ_CHUNK_BYTES,
            || {
                let mut polls = polls.borrow_mut();
                *polls += 1;
                // Two chunks read, then out of time.
                (*polls == 3).then_some(Interruption::Deadline { after_ms: 250 })
            },
            recording_reader(&calls),
        )
        .expect("a read cut short reports its stop rather than failing");

        assert_eq!(
            read.cut_short,
            Some(Interruption::Deadline { after_ms: 250 }),
            "a read that stopped on its deadline did not say so, so its caller reads a short \
             buffer as the range it asked for"
        );
        assert_eq!(
            read.bytes,
            expected_bytes(BASE, 2 * READ_CHUNK_BYTES),
            "the bytes read before the stop are not the prefix of the range asked for"
        );
        assert_eq!(
            *calls.borrow(),
            vec![
                (BASE, READ_CHUNK_BYTES),
                (BASE + READ_CHUNK_BYTES as u64, READ_CHUNK_BYTES)
            ],
            "the stop did not land between two chunks"
        );
    }

    /// **A read cut short holds what it read, not what it asked for.**
    ///
    /// The buffer follows the read rather than the request, which is two facts and only one of
    /// them is memory. The other is *time*: allocating and zeroing the request up front happens
    /// before the first deadline check, so a large `size` spends time outside the one-chunk
    /// residual [`DebugEngine::read_memory_bounded`] promises — and near the `u32` ceiling it is an
    /// abort inside the allocator on a path whose contract is a `Result`. Raised in review on
    /// dbgscope#168.
    ///
    /// Asserted on capacity, which is the only observable a `Vec` offers here. It is deliberately
    /// a wide margin rather than an exact figure: a growing `Vec` is entitled to over-allocate,
    /// and what this is about is 64 MiB against a few pages.
    #[test]
    fn test_a_read_cut_short_holds_what_it_read_not_what_it_asked_for() {
        const HUGE: usize = 64 * 1024 * 1024;
        let calls = RefCell::new(Vec::new());
        let polls = RefCell::new(0usize);
        let read = read_chunked(
            0x6_0000,
            HUGE,
            || {
                let mut polls = polls.borrow_mut();
                *polls += 1;
                (*polls == 3).then_some(Interruption::Deadline { after_ms: 1 })
            },
            recording_reader(&calls),
        )
        .expect("read failed");

        assert_eq!(read.bytes.len(), 2 * READ_CHUNK_BYTES);
        assert!(
            read.bytes.capacity() < HUGE / 8,
            "a read cut short after {} bytes is holding a buffer of {} — sized from the request, \
             which is also an allocation made before the first deadline check",
            read.bytes.len(),
            read.bytes.capacity()
        );
    }

    /// **A buffer the host cannot give is an error, not an abort**, and it names the read it was
    /// for.
    ///
    /// Rust's default reaction to a failed allocation is to take the process down, which on a path
    /// whose whole contract is `Result<_, DbgEngError>` turns a caller's bad number into a dead
    /// host. Raised in review on dbgscope#168, twice: once for the buffer sized from the request
    /// and once for the growth that replaced it.
    ///
    /// **What this can drive is the reservation refusing, not the allocator failing.** A length
    /// past what a `Vec` can even index is turned away by `try_reserve_exact` without asking the
    /// allocator anything, so what is asserted is that the refusal becomes this error rather than
    /// a panic — the mechanism, at the one point a test can reach it. A genuine out-of-memory needs
    /// a host that is out of memory, and nothing here stages one.
    #[test]
    fn test_a_buffer_the_host_cannot_give_is_an_error_not_an_abort() {
        let error = try_buffer(usize::MAX, 0x7_0000, 1024)
            .expect_err("a buffer larger than the address space was handed back as a buffer");

        match error {
            DbgEngError::OutOfMemory {
                address,
                requested,
                read,
            } => {
                assert_eq!(
                    address, 0x7_0000,
                    "the error did not name the read it was for"
                );
                assert_eq!(requested, 1024);
                assert_eq!(
                    read, 0,
                    "nothing had been read when the buffer was asked for"
                );
            }
            other => panic!("a buffer that could not be reserved was reported as {other:?}"),
        }
    }

    /// **A read that finished is never reported cut short**, however close to the bound it ran.
    ///
    /// The other side of "the check sits before each read": a check *after* the last chunk would
    /// make this `Some` for a read with nothing missing, and a caller acting on that discards a
    /// complete answer.
    #[test]
    fn test_a_read_that_finished_is_never_reported_cut_short() {
        const BASE: u64 = 0x2_0000;
        const SIZE: usize = 3 * READ_CHUNK_BYTES;
        let calls = RefCell::new(Vec::new());
        // Halts the moment it is asked — so the only way this read completes is by not being asked
        // again once the last chunk is in.
        let read = read_chunked(
            BASE,
            SIZE,
            {
                let polls = RefCell::new(0usize);
                move || {
                    let mut polls = polls.borrow_mut();
                    *polls += 1;
                    (*polls > 3).then_some(Interruption::OnRequest)
                }
            },
            recording_reader(&calls),
        )
        .expect("read failed");

        assert_eq!(
            read.cut_short, None,
            "a complete read reported itself cut short"
        );
        assert_eq!(read.bytes, expected_bytes(BASE, SIZE));
    }

    /// **A read inside one page is one transfer, and the bound cannot reach into it.**
    ///
    /// The limit [`DebugEngine::read_memory_bounded`] states, pinned rather than left to the
    /// prose: a caller reading sixteen bytes gets a `ReadVirtual` with nothing between its start
    /// and its return. It is asserted because it is the shape of the guarantee — a later change
    /// that "fixed" it by splitting sub-page reads would buy nothing and cost every small read an
    /// extra call.
    #[test]
    fn test_a_read_inside_one_page_is_one_transfer_the_bound_cannot_reach() {
        let calls = RefCell::new(Vec::new());
        let read =
            read_chunked(0x3_0010, 16, || None, recording_reader(&calls)).expect("read failed");

        assert_eq!(read.bytes.len(), 16);
        assert_eq!(
            *calls.borrow(),
            vec![(0x3_0010, 16)],
            "a sub-page read was split, which costs a call and bounds nothing"
        );
    }

    /// **Every chunk lies within one page**, whatever the range's alignment — including the first,
    /// which is what its trim to the page boundary buys.
    ///
    /// Asserted over the alignments that can go wrong rather than one: a plan that took a full
    /// [`READ_CHUNK_BYTES`] every time passes at offset zero and straddles a page at every other
    /// offset.
    #[test]
    fn test_every_chunk_lies_within_one_page() {
        let page = READ_CHUNK_BYTES as u64;
        for base in [0u64, 1, 8, page - 1, page, page + 1, 3 * page - 8] {
            for size in [1usize, 16, READ_CHUNK_BYTES, 5 * READ_CHUNK_BYTES + 3] {
                let address = 0x10_0000 + base;
                let mut done = 0usize;
                let mut chunks = Vec::new();
                while done < size {
                    let len = read_chunk_len(address, done, size);
                    assert!(
                        len > 0,
                        "a zero-length chunk would never finish {address:#x}+{size}"
                    );
                    chunks.push((address + done as u64, len));
                    done += len;
                }
                assert_eq!(
                    done, size,
                    "the chunks of {address:#x}+{size} do not cover it"
                );
                for (index, (at, len)) in chunks.iter().enumerate() {
                    assert!(
                        at / page == (at + *len as u64 - 1) / page,
                        "chunk {index} of {address:#x}+{size} straddles a page: {at:#x}+{len}"
                    );
                    assert!(*len <= READ_CHUNK_BYTES);
                }
                // The trim is what buys that, so the first chunk is short exactly when the range
                // starts unaligned and is long enough to reach the boundary.
                let (_, first) = chunks[0];
                assert_eq!(
                    first,
                    size.min((page - address % page) as usize),
                    "the first chunk of {address:#x}+{size} was not trimmed to the page boundary"
                );
            }
        }
    }

    /// **A short chunk is the short read a single `ReadVirtual` of the whole range would have
    /// been** — same `requested`, same `actual`.
    ///
    /// Which is the point of reading in pieces at all being invisible: a caller that hands a range
    /// running into a hole must not be able to tell [`DebugEngine::read_memory`] from
    /// [`DebugEngine::read_memory_bounded`] by the error it gets back.
    #[test]
    fn test_a_short_chunk_is_the_short_read_a_single_call_would_have_reported() {
        const BASE: u64 = 0x4_0000;
        const SIZE: usize = 4 * READ_CHUNK_BYTES;
        // The third chunk runs into a hole a third of the way in.
        const GOT: usize = READ_CHUNK_BYTES / 3;
        let reads = RefCell::new(0usize);
        let error = read_chunked(
            BASE,
            SIZE,
            || None,
            |_, into| {
                let mut reads = reads.borrow_mut();
                *reads += 1;
                Ok(if *reads == 3 { GOT } else { into.len() })
            },
        )
        .expect_err("a range the target cannot answer for is an error, not a cut-short read");

        match error {
            DbgEngError::ShortRead {
                address,
                requested,
                actual,
            } => {
                assert_eq!(address, BASE, "the short read named a chunk, not the range");
                assert_eq!(
                    requested, SIZE,
                    "the short read named a chunk's size, not the range's"
                );
                assert_eq!(
                    actual,
                    2 * READ_CHUNK_BYTES + GOT,
                    "the bytes already read were not counted"
                );
            }
            other => panic!("a short chunk was reported as {other:?}"),
        }
    }

    /// **A failure on the first chunk is its own error; one after it is the short read.**
    ///
    /// The two are different facts and a caller does different things with them: the first says
    /// the engine refused the read, which a range starting in a hole does and which carries the
    /// engine's own `HRESULT`; the second says the read got that far, which is all a single call
    /// would have said either.
    #[test]
    fn test_a_first_chunk_that_fails_is_its_own_error_and_a_later_one_is_a_short_read() {
        const BASE: u64 = 0x5_0000;
        const SIZE: usize = 3 * READ_CHUNK_BYTES;
        let fail_at = |nth: usize| {
            let reads = RefCell::new(0usize);
            read_chunked(
                BASE,
                SIZE,
                || None,
                move |_, into| {
                    let mut reads = reads.borrow_mut();
                    *reads += 1;
                    if *reads == nth {
                        Err(DbgEngError::NoDebuggee)
                    } else {
                        Ok(into.len())
                    }
                },
            )
        };

        assert!(
            matches!(fail_at(1), Err(DbgEngError::NoDebuggee)),
            "a read that never got a byte swallowed the engine's reason for refusing it"
        );
        assert!(
            matches!(
                fail_at(2),
                Err(DbgEngError::ShortRead {
                    requested: SIZE,
                    actual: READ_CHUNK_BYTES,
                    ..
                })
            ),
            "a chunk that failed with bytes already read was not reported as the short read it is"
        );
    }

    /// **A range whose end wraps past the top of the address space stops at the wrap**, rather
    /// than reading whatever lives at the wrapped address.
    ///
    /// Reading in pieces is what makes this reachable at all — a single `ReadVirtual` hands the
    /// whole range to the engine and lets it refuse — so the guard belongs with the pieces. The
    /// failure it prevents is silent: bytes taken from address zero, assembled into a buffer whose
    /// caller believes they came from the top of memory.
    #[test]
    fn test_a_range_whose_end_wraps_stops_at_the_wrap() {
        let address = u64::MAX - READ_CHUNK_BYTES as u64 + 1;
        let calls = RefCell::new(Vec::new());
        let error = read_chunked(
            address,
            2 * READ_CHUNK_BYTES,
            || None,
            recording_reader(&calls),
        )
        .expect_err("a range that wraps was read as though it did not");

        assert!(
            matches!(
                error,
                DbgEngError::ShortRead {
                    actual: READ_CHUNK_BYTES,
                    ..
                }
            ),
            "a wrapping range reported {error:?} rather than the bytes it did read"
        );
        assert_eq!(
            calls.borrow().len(),
            1,
            "the read carried on past the top of the address space"
        );
    }

    /// A spec is born **armed**, which is the opposite of what the engine does and the whole
    /// reason this type exists.
    ///
    /// `AddBreakpoint2` yields a breakpoint that is disabled *and* sitting at address zero — the
    /// documented initial state — so the wrapper this replaced handed callers a breakpoint on the
    /// null page that never fired, and its `enable` was one of three methods that panicked. A
    /// caller wanting the engine's default asks for it by name.
    #[test]
    fn test_a_code_breakpoint_spec_is_armed_and_adds_rather_than_replaces() {
        let spec = BreakpointSpec::code(BreakpointAt::Address(0x1000));
        assert!(spec.enabled);
        assert!(!spec.one_shot);
        assert_eq!(spec.data, None);
        assert_eq!(spec.on_existing, OnExisting::Add);
        assert_eq!(spec.flags(), DEBUG_BREAKPOINT_ENABLED);

        let disabled = BreakpointSpec::code(BreakpointAt::Address(0x1000)).disabled();
        assert_eq!(disabled.flags(), 0);
    }

    /// `DEBUG_BREAKPOINT_DEFERRED` is the engine's to set and no spec may send it.
    ///
    /// The flag says an expression would not evaluate, and the documentation is explicit that it
    /// "cannot be modified by any client" — so it is read back on [`BreakpointInfo`] and is
    /// deliberately absent from [`BreakpointSpec`]. This pins the bits that *are* sent, so a flag
    /// added to `flags()` later has to be a deliberate edit here too.
    #[test]
    fn test_a_spec_sends_only_the_two_flags_a_client_owns() {
        let spec = BreakpointSpec::code(BreakpointAt::Expression("nt!Foo".into())).one_shot();
        assert_eq!(
            spec.flags(),
            DEBUG_BREAKPOINT_ENABLED | DEBUG_BREAKPOINT_ONE_SHOT
        );
        assert_eq!(spec.flags() & DEBUG_BREAKPOINT_DEFERRED, 0);
    }

    /// The builder narrows a code spec into a data one without losing the rest of it.
    ///
    /// `data` is `Some` exactly when the breakpoint is a processor breakpoint, which is why the
    /// kind is not a field of its own: there is no way to spell a data breakpoint with no watched
    /// region, or a code one with a size.
    #[test]
    fn test_a_data_spec_keeps_the_code_defaults_and_carries_its_watch() {
        let watch = DataWatch {
            access: DataAccess::Write,
            size: 8,
        };
        let spec = BreakpointSpec::data(BreakpointAt::Address(0x2000), watch)
            .with_command(".echo hit; gc")
            .on_thread(7)
            .with_pass_count(3)
            .replacing_existing();
        assert_eq!(spec.data, Some(watch));
        assert!(spec.enabled);
        assert_eq!(spec.command.as_deref(), Some(".echo hit; gc"));
        assert_eq!(spec.thread, Some(7));
        assert_eq!(spec.pass_count, Some(3));
        assert_eq!(spec.on_existing, OnExisting::Replace);
    }

    /// `Read` is not silently widened to `Read | Write`.
    ///
    /// It *behaves* as both on x86 and x64, which is a fact about those processors rather than
    /// about this mapping — so the engine is told what the caller said and the widening is left
    /// where it belongs. Folding the two here would make `Read` and `ReadWrite` indistinguishable
    /// on an architecture that honours the difference.
    #[test]
    fn test_each_data_access_maps_to_its_own_engine_flags() {
        assert_eq!(DataAccess::Read.to_engine(), DEBUG_BREAK_READ);
        assert_eq!(DataAccess::Write.to_engine(), DEBUG_BREAK_WRITE);
        assert_eq!(
            DataAccess::ReadWrite.to_engine(),
            DEBUG_BREAK_READ | DEBUG_BREAK_WRITE
        );
        assert_eq!(DataAccess::Execute.to_engine(), DEBUG_BREAK_EXECUTE);
        assert_eq!(DataAccess::Io.to_engine(), DEBUG_BREAK_IO);
        assert_ne!(
            DataAccess::Read.to_engine(),
            DataAccess::ReadWrite.to_engine()
        );
    }

    /// Every access survives the trip to the engine and back, including one this build cannot name.
    ///
    /// The round trip is the property that matters, because `BreakpointInfo::data` is read back
    /// through `GetDataParameters` and compared against the spec that set it: a mapping that is
    /// merely *a* function each way would let a breakpoint read back as something it is not.
    /// `Other` carries bits rather than discarding them, as [`BreakpointKind::Other`] does, so an
    /// engine reporting a combination this build has never heard of still reports it.
    #[test]
    fn test_a_data_access_survives_the_round_trip_to_the_engine() {
        for access in [
            DataAccess::Read,
            DataAccess::Write,
            DataAccess::ReadWrite,
            DataAccess::Execute,
            DataAccess::Io,
        ] {
            assert_eq!(
                DataAccess::from_engine(access.to_engine()),
                access,
                "{access:?} did not survive"
            );
        }
        // Bits with no name are kept, not folded into a plausible neighbour.
        let odd = DEBUG_BREAK_EXECUTE | DEBUG_BREAK_WRITE;
        assert_eq!(DataAccess::from_engine(odd), DataAccess::Other(odd));
        assert_eq!(DataAccess::Other(odd).to_engine(), odd);
    }

    /// A processor breakpoint's size and alignment are refused *here*, before one exists.
    ///
    /// The engine accepts a bad pair at the set and rejects it when the target is resumed, so
    /// leaving it to the engine reports the mistake against a `go` that did nothing wrong. A code
    /// breakpoint has neither constraint and is never refused for them.
    #[test]
    fn test_a_data_breakpoint_is_refused_for_a_bad_size_or_alignment() {
        let watch = |size| DataWatch {
            access: DataAccess::ReadWrite,
            size,
        };
        for size in [0, 3, 5, 16] {
            assert!(
                BreakpointSpec::data(BreakpointAt::Address(0x1000), watch(size))
                    .validated()
                    .is_err(),
                "a {size}-byte data breakpoint should be refused"
            );
        }
        for size in [1, 2, 4, 8] {
            assert!(
                BreakpointSpec::data(BreakpointAt::Address(0x1000), watch(size))
                    .validated()
                    .is_ok(),
                "a {size}-byte data breakpoint at an aligned address should be accepted"
            );
        }
        assert!(
            BreakpointSpec::data(BreakpointAt::Address(0x1004), watch(8))
                .validated()
                .is_err()
        );
        // An expression has no address until the engine resolves it, so alignment cannot be judged
        // *here* — `set_breakpoint_bounded` checks it again on the resolved offset, which is where
        // this one is caught. Refusing it here would refuse specs that are fine.
        assert!(
            BreakpointSpec::data(BreakpointAt::Expression("nt!Foo+1".into()), watch(8))
                .validated()
                .is_ok()
        );
        // A code breakpoint has no size and no alignment rule, at any address.
        assert!(
            BreakpointSpec::code(BreakpointAt::Address(0x1001))
                .validated()
                .is_ok()
        );
    }

    /// The spelling a symbol server path uses, which is **not** the braced, dashed form `Debug`
    /// prints and not a byte-order-preserving dump either: the first three fields are written as
    /// the numbers they are, and only the trailing eight bytes are laid out in order.
    ///
    /// The value is `ntkrnlmp.pdb`'s for the ARM64 kernel in windbg-mcp's own sample dump, taken
    /// from the image's CodeView record — so this test pins the convention against a string that
    /// is known to fetch the right file rather than against a hand-built one.
    #[test]
    fn test_a_pdb_guid_is_spelled_the_way_a_symbol_server_path_is() {
        let guid = windows::core::GUID {
            data1: 0xFE3F_58BD,
            data2: 0xA39D,
            data3: 0x2FC1,
            data4: [0x3C, 0x37, 0x06, 0x18, 0xD1, 0xDB, 0xDF, 0x22],
        };
        assert_eq!(format_pdb_guid(&guid), "FE3F58BDA39D2FC13C370618D1DBDF22");
    }

    /// The engine renders one instruction as three columns. The split has to survive both
    /// architectures' padding, and it must take the address from the walk rather than from the
    /// line — the point of the record is that it is not a re-parse of a rendering.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_instruction_splits_into_its_encoding_and_its_mnemonic() {
        let x64 = split_instruction(
            0xfffff803_89201234,
            "fffff803`89201234 48895c2408      mov     qword ptr [rsp+8],rbx\n",
            InstructionSet::Amd64,
        );
        assert_eq!(x64.address, 0xfffff803_89201234);
        assert_eq!(x64.bytes, "48895c2408");
        assert_eq!(x64.text, "mov qword ptr [rsp+8],rbx");

        let arm64 = split_instruction(
            0xfffff803_89201234,
            "fffff803`89201234 a9bf7bfd     stp         fp,lr,[sp,#-0x10]!\n",
            InstructionSet::Arm64,
        );
        assert_eq!(arm64.bytes, "a9bf7bfd");
        assert_eq!(arm64.text, "stp fp,lr,[sp,#-0x10]!");
    }

    /// The A64 byte column is the instruction **word**, and reading it as memory order inverts
    /// every branch.
    ///
    /// The engine prints `a9bf7bfd` for `stp fp,lr,[sp,#-0x10]!`, whose encoding is `0xa9bf7bfd`;
    /// the same four bytes read out of memory come back `fd 7b bf a9`, A64 being little-endian.
    /// So this column assembles big-endian and [`DebugEngine::decode_range`]'s does not, and
    /// getting it backwards is silent — the reversed word decodes to *something*, and here it
    /// decodes to a branch. `0x97fffcc4` is `bl` to 3312 bytes back; reversed it is `0xc4fcff97`,
    /// which matches nothing and would fall through, so the two readings differ by a call edge.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_a64_byte_column_is_the_word_and_not_the_memory() {
        let call = split_instruction(
            0xfffff802_e9e5df70,
            "fffff802`e9e5df70 97fffcc4     bl          nt!KeBugCheck2 (fffff802`e9e5d280)",
            InstructionSet::Arm64,
        );
        assert_eq!(
            call.flow,
            Flow::Call(Some(0xfffff802_e9e5d280)),
            "the destination the engine itself printed: {call:?}"
        );
        assert_eq!(call.mnemonic, "bl");
        assert_eq!(call.operands, [Operand::Target(0xfffff802_e9e5d280)]);
        assert!(InstructionSet::Arm64.operands_are_read());
        assert!(InstructionSet::Arm64.flow_is_read());
    }

    /// A64's operands arrive through this path too, and the gate that used to separate them from
    /// the flow now answers yes.
    ///
    /// The fields themselves are [`crate::arm64`]'s, and are tested against the engine's own
    /// renderings there. What is asserted here is the **wiring**: that `split_instruction` hands
    /// the word to that decoder rather than to `Decoded::nothing`, and that the rendering still
    /// sits beside the fields untouched.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_a64_rendering_carries_decoded_operands_beside_it() {
        let load = split_instruction(
            0xfffff802_e9e5d5b8,
            "fffff802`e9e5d5b8 f9426909     ldr         x9,[x8,#0x4D0]",
            InstructionSet::Arm64,
        );
        assert_eq!(
            load.text, "ldr x9,[x8,#0x4D0]",
            "the engine's own, verbatim"
        );
        assert_eq!(load.mnemonic, "ldr");
        assert_eq!(load.effect, Effect::Move);
        assert_eq!(load.flow, Flow::Fallthrough);
        let Some(Operand::Memory(memory)) = load.operands.get(1) else {
            panic!("the memory operand was not read: {load:?}");
        };
        assert_eq!(memory.displacement, 0x4d0);
        assert_eq!(memory.base.as_deref(), Some("x8"));
        // A 32-bit write reaches the whole register on A64 as it does on x64, which is what makes
        // `full` the field to match these against.
        assert_eq!(load.writes.len(), 1, "{load:?}");
        assert_eq!(load.writes[0].full, "x9");
        assert_eq!(load.reads.len(), 1, "{load:?}");
        assert_eq!(load.reads[0].full, "x8");
    }

    /// A register operand as a fixture writes one: the printed name, and the full-width register
    /// it belongs to.
    fn register(name: &str, full: &str, width: u32) -> RegisterOperand {
        RegisterOperand {
            name: name.to_string(),
            full: full.to_string(),
            width,
        }
    }

    /// A register is one value across its widths, and the **decoder** says which.
    ///
    /// The mapping is per bitness, not per name: `eax` is part of `rax` on x64 and is itself the
    /// full register on x86, so a table of names is wrong on one of the two whatever it says. The
    /// cases here are the ones such a table forgets — a numbered register's `d` suffix, a legacy
    /// high byte, and the same name read under both bitnesses.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_a_register_operand_carries_the_full_width_register_the_decoder_names() {
        let decode = |bytes: &str, text: &str, set| {
            split_instruction(0x1000, &format!("00001000`00000000 {bytes}    {text}"), set)
        };
        let register = |one: &Instruction, index: usize| match &one.operands[index] {
            Operand::Register(register) => {
                (register.name.clone(), register.full.clone(), register.width)
            }
            other => panic!("expected a register operand: {other:?}"),
        };

        // `mov r13d,eax` on x64: two spellings, two different full registers.
        let wide = decode("4189c5", "mov r13d,eax", InstructionSet::Amd64);
        assert_eq!(
            register(&wide, 0),
            ("r13d".to_string(), "r13".to_string(), 4),
            "{wide:?}"
        );
        assert_eq!(
            register(&wide, 1),
            ("eax".to_string(), "rax".to_string(), 4)
        );

        // `mov ah,al`: the legacy high byte belongs to the same register as the low one.
        let bytes = decode("88c4", "mov ah,al", InstructionSet::Amd64);
        assert_eq!(
            register(&bytes, 0),
            ("ah".to_string(), "rax".to_string(), 1),
            "and the width is what says a copy of it is not the whole value"
        );

        // **The width is the register's, not the instruction's access**, and the two differ on a
        // vector register: `movss` copies four bytes of an `xmm`, which is sixteen. Asserted
        // because a caller reading this field for "did I keep the whole value" has to know where
        // that question stops being answerable from it.
        let scalar = decode("f30f10c1", "movss xmm0,xmm1", InstructionSet::Amd64);
        assert_eq!(
            register(&scalar, 1),
            ("xmm1".to_string(), "zmm1".to_string(), 16),
            "the register is sixteen bytes however many the copy moves, and it is part of a              `zmm` for the same reason `eax` is part of `rax`: {scalar:?}"
        );

        // And the same instruction decoded as 32-bit code: there is no `rax` on that target.
        let narrow = decode("8bc1", "mov eax,ecx", InstructionSet::X86);
        assert_eq!(
            register(&narrow, 0),
            ("eax".to_string(), "eax".to_string(), 4)
        );
        assert_eq!(
            register(&narrow, 1),
            ("ecx".to_string(), "ecx".to_string(), 4)
        );
    }

    /// A branch's condition carries its **signedness**, which its mnemonic reads like but does not
    /// say.
    ///
    /// `ja` and `jg` are the same word in English. Only the first bounds an unsigned index, so a
    /// consumer sizing a jump table from a signed comparison sizes it from nothing — and a
    /// consumer matching mnemonics has no way to see the difference without knowing this table by
    /// heart, which is the knowledge this field exists to stop being everybody's.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_a_conditional_branch_carries_its_condition_and_its_signedness() {
        let decode = |bytes: &str, text: &str| {
            split_instruction(
                0x1000,
                &format!("00001000`00000000 {bytes}    {text}"),
                InstructionSet::Amd64,
            )
        };
        for (bytes, text, expected) in [
            ("7402", "je 1004", Condition::Equal),
            ("7502", "jne 1004", Condition::NotEqual),
            ("7702", "ja 1004", Condition::UnsignedAbove),
            ("7302", "jae 1004", Condition::UnsignedAboveOrEqual),
            ("7202", "jb 1004", Condition::UnsignedBelow),
            ("7602", "jbe 1004", Condition::UnsignedBelowOrEqual),
            ("7f02", "jg 1004", Condition::SignedGreater),
            ("7d02", "jge 1004", Condition::SignedGreaterOrEqual),
            ("7c02", "jl 1004", Condition::SignedLess),
            ("7e02", "jle 1004", Condition::SignedLessOrEqual),
        ] {
            let one = decode(bytes, text);
            assert_ne!(
                one.flow,
                Flow::Unknown,
                "`{text}` must decode, or the condition is about nothing: {one:?}"
            );
            assert_eq!(one.condition, Some(expected), "`{text}`: {one:?}");
        }

        // Everything that is not a conditional branch claims nothing.
        let unconditional = decode("eb02", "jmp 1004");
        assert_eq!(unconditional.condition, None, "{unconditional:?}");
        let arithmetic = decode("83e804", "sub eax,4");
        assert_eq!(arithmetic.condition, None, "{arithmetic:?}");
    }

    /// What an instruction does to its operands is a class the decoder answers, and whether it set
    /// the flags is the decoder's too.
    ///
    /// Both replace a list of mnemonics in a consumer. The flags case is the one such a list keeps
    /// getting wrong: `cmp` and `test` are obvious, and `bt`, `neg` and `cmpxchg` are the ones
    /// nobody writes down — while `lea`, which looks like arithmetic, sets none.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_instruction_carries_what_it_does_and_whether_it_set_the_flags() {
        let decode = |bytes: &str, text: &str| {
            split_instruction(
                0x1000,
                &format!("00001000`00000000 {bytes}    {text}"),
                InstructionSet::Amd64,
            )
        };
        for (bytes, text, effect, flags) in [
            ("8bc1", "mov eax,ecx", Effect::Move, false),
            ("0fb6c1", "movzx eax,cl", Effect::Move, false),
            // Apart from the zero-extending copy above, because what the value means afterwards
            // differs: `movsxd` makes a dword a signed displacement, and a caller adding it to a
            // base lands four gigabytes away if it reads the two the same.
            ("4863c1", "movsxd rax,ecx", Effect::MoveSigned, false),
            ("488d0c10", "lea rcx,[rax+rdx]", Effect::LoadAddress, false),
            ("83f804", "cmp eax,4", Effect::Compare, true),
            ("85c0", "test eax,eax", Effect::Test, true),
            ("83c004", "add eax,4", Effect::Add, true),
            ("83e804", "sub eax,4", Effect::Subtract, true),
            ("c1e802", "shr eax,2", Effect::ShiftRight, true),
            ("c1e002", "shl eax,2", Effect::ShiftLeft, true),
            ("83e00f", "and eax,0Fh", Effect::BitAnd, true),
            ("50", "push rax", Effect::Push, false),
            ("58", "pop rax", Effect::Pop, false),
            ("c3", "ret", Effect::Other, false),
            // The flag-setters a hand-written list forgets.
            ("0fa3c1", "bt ecx,eax", Effect::Other, true),
            ("f7d8", "neg eax", Effect::Other, true),
        ] {
            let one = decode(bytes, text);
            assert_ne!(one.flow, Flow::Unknown, "`{text}` must decode: {one:?}");
            assert_eq!(one.effect, effect, "`{text}`: {one:?}");
            assert_eq!(one.writes_flags, flags, "`{text}` flags: {one:?}");
        }
    }

    /// An instruction says which registers it **writes**, which its operands do not.
    ///
    /// A consumer tracking a value has to know when to stop believing in it, and the obvious
    /// implementation -- the first operand -- is right for the shapes a compiler emits and wrong
    /// for two it also emits. Both are here: `xchg` writes its *second* operand as well, and `mul`,
    /// `cpuid` and the string instructions write registers they do not name at all. A consumer
    /// that clears the first operand goes on believing whatever it knew about the rest, which is
    /// how a stale control code becomes a code a driver is reported to accept.
    ///
    /// `cmovne` is in the list because its write is **conditional**: what a consumer asks is
    /// whether a register may have changed, and the only safe answer to that is yes.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_instruction_says_which_registers_it_writes() {
        let writes = |bytes: &str| {
            let raw = hex::decode(bytes).expect("the fixture is hex");
            let decoded = decode_operation(&raw, 0x1000, InstructionSet::Amd64);
            assert_ne!(
                decoded.flow,
                Flow::Unknown,
                "`{bytes}` must decode: {decoded:?}"
            );
            let mut full: Vec<String> = decoded.writes.iter().map(|w| w.full.clone()).collect();
            full.sort();
            (decoded.mnemonic.clone(), full)
        };

        // A plain move, and the asymmetry worth knowing: the operand is `eax` and the write
        // reaches the whole of `rax`, because a 32-bit write zeroes the upper half.
        assert_eq!(
            writes("b801000000"),
            ("mov".to_string(), vec!["rax".to_string()])
        );

        // Both operands, which is what an instruction's *first* one cannot say.
        assert_eq!(
            writes("91"),
            (
                "xchg".to_string(),
                vec!["rax".to_string(), "rcx".to_string()]
            )
        );
        assert_eq!(
            writes("4195"),
            (
                "xchg".to_string(),
                vec!["r13".to_string(), "rax".to_string()]
            )
        );

        // And the ones that name none of what they write.
        assert_eq!(
            writes("f7e1"),
            (
                "mul".to_string(),
                vec!["rax".to_string(), "rdx".to_string()]
            ),
            "`mul ecx` names `ecx` and writes neither of these"
        );
        assert_eq!(
            writes("0fa2"),
            (
                "cpuid".to_string(),
                vec![
                    "rax".to_string(),
                    "rbx".to_string(),
                    "rcx".to_string(),
                    "rdx".to_string()
                ]
            )
        );
        assert_eq!(
            writes("f3a5"),
            (
                "movsd".to_string(),
                vec!["rcx".to_string(), "rdi".to_string(), "rsi".to_string()]
            ),
            "a repeated string move walks both pointers and the count"
        );

        // A conditional write counts, because "may this have changed" is the question.
        assert_eq!(
            writes("0f45c1"),
            ("cmovne".to_string(), vec!["rax".to_string()])
        );

        // And an instruction that writes only the flags writes no register.
        assert_eq!(writes("3bc1"), ("cmp".to_string(), Vec::new()));

        // An instruction set this build does not decode claims nothing, as its flow says.
        let undecoded = decode_operation(
            &[0x00, 0x01, 0x02, 0x03],
            0x1000,
            InstructionSet::Other(0xaa64),
        );
        assert_eq!(undecoded.flow, Flow::Unknown);
        assert!(undecoded.writes.is_empty(), "{undecoded:?}");
    }

    /// An instruction says which registers it **reads**, which its operands do not.
    ///
    /// The write side's argument, mirrored: the operand list is what an instruction was written
    /// with, and the reads it does not name are the ones a consumer tracking a value through a
    /// routine most needs. Every assertion below is a shape where the two answers differ, and the
    /// operand list is asserted alongside so that the *gap* is what is pinned rather than the
    /// reads alone -- a regression that made `operands` complete would otherwise leave this test
    /// passing for a reason it is not about.
    ///
    /// `scasd` is the shape that costs a consumer most and is the reason this is not covered by
    /// [`Instruction::writes`] already: it reads `eax`, writes the flags, and does **not** write
    /// `rax` -- so a pass watching for the value to be overwritten sees nothing, and a pass
    /// reading the operand list sees the `eax` it happens to name. Its neighbour `repne scasb`
    /// reads `rcx` and names it nowhere at all.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_instruction_says_which_registers_it_reads() {
        let reads = |bytes: &str| {
            let raw = hex::decode(bytes).expect("the fixture is hex");
            let decoded = decode_operation(&raw, 0x1000, InstructionSet::Amd64);
            assert_ne!(
                decoded.flow,
                Flow::Unknown,
                "`{bytes}` must decode: {decoded:?}"
            );
            let mut full: Vec<String> = decoded.reads.iter().map(|r| r.full.clone()).collect();
            full.sort();
            (decoded.mnemonic.clone(), full)
        };
        // What the operand list names as a register, for the same encoding -- the answer this
        // field exists because a consumer cannot use.
        let named = |bytes: &str| {
            let raw = hex::decode(bytes).expect("the fixture is hex");
            let decoded = decode_operation(&raw, 0x1000, InstructionSet::Amd64);
            let mut full: Vec<String> = decoded
                .operands
                .iter()
                .filter_map(|operand| match operand {
                    Operand::Register(register) => Some(register.full.clone()),
                    _ => None,
                })
                .collect();
            full.sort();
            full
        };

        // **The implicit read beside the implicit write.** `mul ecx` names `ecx` and reads `eax`.
        assert_eq!(
            reads("f7e1"),
            (
                "mul".to_string(),
                vec!["rax".to_string(), "rcx".to_string()]
            )
        );
        assert_eq!(named("f7e1"), vec!["rcx".to_string()]);

        // `cmpxchg edx,ecx` names two registers and reads three.
        assert_eq!(
            reads("0fb1ca"),
            (
                "cmpxchg".to_string(),
                vec!["rax".to_string(), "rcx".to_string(), "rdx".to_string()]
            )
        );
        assert_eq!(named("0fb1ca"), vec!["rcx".to_string(), "rdx".to_string()]);

        // **A read with no matching write**, which is what makes this field more than a
        // restatement of `writes`: `scasd` compares `eax` against `es:[rdi]` and leaves `rax`
        // alone, so nothing about the write side says the value was looked at.
        let scasd = decode_operation(
            &hex::decode("af").expect("hex"),
            0x1000,
            InstructionSet::Amd64,
        );
        assert_eq!(
            scasd
                .reads
                .iter()
                .map(|r| r.full.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            ["rax", "rdi"].into_iter().collect()
        );
        assert!(
            !scasd.writes.iter().any(|w| w.full == "rax"),
            "scasd reads eax and writes no part of rax: {scasd:?}"
        );
        assert!(scasd.writes_flags, "{scasd:?}");

        // And the same family with the count in it, which the operand list never names.
        assert_eq!(
            reads("f2ae"),
            (
                "scasb".to_string(),
                vec!["rax".to_string(), "rcx".to_string(), "rdi".to_string()]
            )
        );
        assert_eq!(named("f2ae"), vec!["rax".to_string()]);

        // **A register read to form an address is a read**, and it is not in the operand list as
        // a register -- it is the base of a memory operand there. `cmp dword ptr [rcx+8],5`.
        assert_eq!(
            reads("83790805"),
            ("cmp".to_string(), vec!["rcx".to_string()])
        );
        assert!(named("83790805").is_empty());

        // A read-write operand is on both lists, those being different questions.
        assert_eq!(
            reads("23c1"),
            (
                "and".to_string(),
                vec!["rax".to_string(), "rcx".to_string()]
            )
        );

        // A conditional read counts, for the mirror of the reason a conditional write does.
        assert_eq!(
            reads("0f45c1"),
            (
                "cmovne".to_string(),
                vec!["rax".to_string(), "rcx".to_string()]
            )
        );

        // **The width asymmetry with `writes`.** A 32-bit write reaches the whole of `rax`, so
        // `mov eax,1` writes `rax` and reads nothing; a 32-bit read reads four bytes, so
        // `mov eax,ecx` reports the `ecx` it read rather than the `rcx` around it.
        assert_eq!(reads("b801000000"), ("mov".to_string(), Vec::new()));
        let copy = decode_operation(
            &hex::decode("8bc1").expect("hex"),
            0x1000,
            InstructionSet::Amd64,
        );
        assert_eq!(copy.reads.len(), 1, "{copy:?}");
        assert_eq!(copy.reads[0].name, "ecx");
        assert_eq!(copy.reads[0].full, "rcx");
        assert_eq!(copy.reads[0].width, 4);

        // An instruction set this build does not decode claims nothing, as its flow says --
        // empty here is "not decoded" and not "reads nothing".
        let undecoded = decode_operation(
            &[0x00, 0x01, 0x02, 0x03],
            0x1000,
            InstructionSet::Other(0xaa64),
        );
        assert_eq!(undecoded.flow, Flow::Unknown);
        assert!(undecoded.reads.is_empty(), "{undecoded:?}");
    }

    /// Privilege is the **decoder's** answer, which is the whole point of carrying it.
    ///
    /// A caller asking "does this driver touch the machine" wants the entire set, and the obvious
    /// implementation — a list of mnemonics — answers "none" for a driver containing exactly the
    /// ones nobody remembered. The cases below are chosen to be the ones such a list misses:
    /// `cli` and `sti` are IOPL-sensitive rather than CPL=0 and read like ordinary flag
    /// instructions; `clts` and `lmsw` are rare enough to be forgotten; `vmlaunch` is a family of
    /// its own. iced's table is generated from the instruction set, so all of them answer without
    /// anyone maintaining a list.
    ///
    /// Every encoding here is asserted to have **decoded**, which is not pedantry: the first draft
    /// used a `vmxon` encoding that was not one, and it failed as `privileged: false` — the same
    /// answer a genuinely unprivileged instruction gives, and the same one this whole field exists
    /// to stop being silent.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_privilege_is_the_decoders_answer_rather_than_a_list_of_mnemonics() {
        let decode = |bytes: &str, text: &str| {
            split_instruction(
                0x1000,
                &format!("00001000`00000000 {bytes}    {text}"),
                InstructionSet::Amd64,
            )
        };

        for (bytes, text) in [
            ("fa", "cli"),
            ("fb", "sti"),
            ("0f06", "clts"),
            ("0f01f0", "lmsw ax"),
            ("0f01c2", "vmlaunch"),
            ("0f32", "rdmsr"),
            ("0f20d8", "mov rax,cr3"),
        ] {
            let one = decode(bytes, text);
            assert_ne!(
                one.flow,
                Flow::Unknown,
                "`{text}` must actually decode, or `privileged` is answering about nothing: {one:?}"
            );
            assert!(
                one.privileged,
                "`{text}` requires privilege and the decoder knows it: {one:?}"
            );
        }

        for (bytes, text) in [
            ("90", "nop"),
            ("4889d8", "mov rax,rbx"),
            ("c3", "ret"),
            // Reads a counter, needs no privilege, and sits next to `rdmsr` in every list a person
            // writes from memory.
            ("0f31", "rdtsc"),
        ] {
            let one = decode(bytes, text);
            assert_ne!(one.flow, Flow::Unknown, "`{text}` must decode: {one:?}");
            assert!(!one.privileged, "`{text}` needs no privilege: {one:?}");
        }

        // A64 answers this from `op1` rather than from a mnemonic, and `hvc` is one of the few
        // outside the system class that needs privilege: it calls into the hypervisor and returns
        // to the following word, so the flow beside it is a real `Fallthrough`.
        let arm64 = split_instruction(
            0x1000,
            "00001000`00000000 d4000002     hvc #0",
            InstructionSet::Arm64,
        );
        assert!(arm64.privileged, "{arm64:?}");
        assert_eq!(arm64.flow, Flow::Fallthrough);
        // And the ordinary instruction beside it does not: `d503201f nop`.
        let nop = split_instruction(
            0x1000,
            "00001000`00000000 d503201f     nop",
            InstructionSet::Arm64,
        );
        assert!(!nop.privileged, "{nop:?}");

        // An instruction set with nothing decoded at all still answers the old way.
        let arm32 = split_instruction(
            0x1000,
            "00001000`00000000 ef000000     svc #0",
            InstructionSet::Other(0x01c4),
        );
        assert!(!arm32.privileged);
        assert_eq!(arm32.flow, Flow::Unknown);
    }

    /// The address is the walk's, not the line's. Asserted against a line that disagrees, because
    /// agreeing lines cannot tell the two sources apart.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_instructions_address_comes_from_the_walk_not_the_rendering() {
        let one = split_instruction(0x1000, "deadbeef`deadbeef 90    nop", InstructionSet::Amd64);
        assert_eq!(one.address, 0x1000);
        assert_eq!(one.text, "nop");
        assert_eq!(one.mnemonic, "nop");
    }

    /// An engine that renders a shape this does not know loses a column, never an instruction:
    /// the remainder is kept as text and nothing is presented as an encoding that is not one.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_unrecognised_line_keeps_its_text_rather_than_inventing_an_encoding() {
        let two_columns =
            split_instruction(0x1000, "fffff803`89201234 ????", InstructionSet::Amd64);
        assert!(two_columns.bytes.is_empty(), "{two_columns:?}");
        assert_eq!(two_columns.text, "????");

        let one_column = split_instruction(0x1000, "???", InstructionSet::Amd64);
        assert!(one_column.bytes.is_empty(), "{one_column:?}");
        assert_eq!(one_column.text, "???");
    }

    /// `???` is not an instruction, and a walk must not step through it.
    ///
    /// The engine prints it where the bytes could not be read — an unmapped page, or a dump with
    /// no code pages. There is nothing to decode, so there is no fall-through either: a walk that
    /// took one would step through *bytes*, one address at a time, inventing every one of them
    /// until it hit its own cap. That is a different fact from an instruction set whose operands
    /// are not decoded, where there is a real instruction and continuing is the right best-effort,
    /// and the two are separate variants for exactly that reason.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_unreadable_rendering_is_not_walked_through() {
        for set in [
            InstructionSet::Amd64,
            InstructionSet::X86,
            InstructionSet::Other(0xaa64),
        ] {
            let nothing = split_instruction(0x1000, "fffff803`89201234 ????", set);
            assert_eq!(nothing.flow, Flow::Unreadable, "{set:?}: {nothing:?}");
            assert!(
                !nothing.flow.falls_through(),
                "{set:?}: a walk would step through unreadable bytes"
            );
            assert_eq!(nothing.mnemonic, "????");
        }
    }

    /// An instruction set whose encoding this does not decode refuses rather than guesses.
    ///
    /// The mnemonic survives — the first token is the mnemonic in every syntax the engine renders
    /// — and nothing else is claimed. The flow matters most: reporting the `Fallthrough` an unread
    /// instruction would otherwise default to hands a caller one edge of two and calls the walk
    /// complete. Unlike an unreadable rendering, this one still falls through, because there
    /// **is** an instruction there.
    ///
    /// ARM32 rather than ARM64, which used to be the example here and is now decoded — that change
    /// is the test below.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_unread_instruction_set_reports_no_operands_and_no_flow() {
        let arm32 = split_instruction(
            0xfffff803_89201234,
            "fffff803`89201234 0a000001     beq         nt!KiFoo+0x1c (fffff803`89201240)",
            InstructionSet::Other(0x01c4),
        );
        assert_eq!(arm32.mnemonic, "beq");
        assert!(arm32.operands.is_empty(), "{arm32:?}");
        assert_eq!(arm32.flow, Flow::Unknown);
        assert!(arm32.flow.falls_through());
        assert!(
            arm32.text.contains("nt!KiFoo"),
            "the rendering is still the rendering: {arm32:?}"
        );
    }

    /// A64's flow **is** read, and a conditional branch there keeps both of its edges.
    ///
    /// The rendering carries the destination too, and it is **not** where this reads it from —
    /// that is the same rule the x64 side keeps, and the reason the rendered target is asserted
    /// against here rather than parsed. The destination reaches the caller twice, as the flow's
    /// and as an [`Operand::Target`], and they are one value: the flow answers a walk and the
    /// operand answers a listing.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_a64_conditional_branch_keeps_both_edges() {
        let arm64 = split_instruction(
            0xfffff803_89201234,
            "fffff803`89201234 54000060     b.eq        nt!KiFoo+0x1c (fffff803`89201240)",
            InstructionSet::Arm64,
        );
        assert_eq!(arm64.mnemonic, "b.eq");
        assert_eq!(arm64.operands, [Operand::Target(0xfffff803_89201240)]);
        assert_eq!(arm64.condition, Some(Condition::Equal));
        assert_eq!(arm64.flow, Flow::Branch(Some(0xfffff803_89201240)));
        assert!(arm64.flow.falls_through());
        assert!(
            arm64.text.contains("nt!KiFoo"),
            "the rendering is still the rendering: {arm64:?}"
        );

        // A `ret` ends the walk, and an unmapped rendering still stops it before an `Unknown`
        // would let it step through — the byte column is what separates those, on every
        // architecture.
        let ret = split_instruction(
            0x1000,
            "00001000`00000000 d65f03c0     ret",
            InstructionSet::Arm64,
        );
        assert_eq!(ret.flow, Flow::Return);
        let unreadable = split_instruction(
            0x1000,
            "00001000`00000000 ??     ???",
            InstructionSet::Arm64,
        );
        assert_eq!(unreadable.flow, Flow::Unreadable);
        assert!(!unreadable.flow.falls_through());
    }

    /// A rendering plays no part in what the operands are.
    ///
    /// This is the property the decoder bought, and the one worth a test of its own: every
    /// operand comes from the encoding, so a symbol's own punctuation cannot take one apart.
    /// While operands were read out of the third column, `std::map<int,int>` severed a call at its
    /// comma, `operator()` at its parenthesis and `operator[]` at its bracket — three rounds of
    /// review, three characters, one defect. Here the rendering is **deliberately a lie** and the
    /// fields are still right.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_the_operands_come_from_the_encoding_and_not_from_the_rendering() {
        let lied_to = split_instruction(
            0x1000,
            // `e8 0b 00 00 00` is `call +0xb`, which from 0x1000 lands at 0x1010. The text says
            // something else entirely, and carries every character that used to break the reading.
            "00001000 e80b000000  call module!std::map<int,int>::operator[]() (deadbeef`deadbeef)",
            InstructionSet::Amd64,
        );
        assert_eq!(lied_to.flow, Flow::Call(Some(0x1010)), "{lied_to:?}");
        assert_eq!(lied_to.operands, vec![Operand::Target(0x1010)]);
        assert_eq!(lied_to.mnemonic, "call");
    }

    /// The operands of the shapes this crate's callers actually walk, decoded from real
    /// encodings — the compare against an IOCTL code, the `IO_STACK_LOCATION` field load, the
    /// direct call, the import thunk, the scaled index of a jump table, and the KPCR read through
    /// a segment override.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_x64_operands_are_read_as_values() {
        let one = |encoding: &str, at: u64| {
            split_instruction(at, &format!("00001000 {encoding} x"), InstructionSet::Amd64)
        };

        // `41 81 fd 30 00 6d 00` — cmp r13d,6D0030h. The compare an IOCTL map is recovered from.
        let cmp = one("4181fd30006d00", 0x1000);
        assert_eq!(cmp.mnemonic, "cmp");
        assert_eq!(
            cmp.operands,
            vec![
                Operand::Register(register("r13d", "r13", 4)),
                Operand::Immediate(0x6d_0030)
            ]
        );
        assert_eq!(cmp.flow, Flow::Fallthrough);

        // `48 8b 82 b8 00 00 00` — mov rax,qword ptr [rdx+0B8h]. `IRP_SP = [Irp+0xb8]`, the load
        // every dispatch routine opens with. Taken verbatim from a walk of mountmgr.
        let load = one("488b82b8000000", 0x1000);
        let Some(Operand::Memory(memory)) = load.operands.get(1) else {
            panic!("the memory operand was not read: {load:?}");
        };
        assert_eq!(memory.size, Some(8));
        assert_eq!(memory.base.as_deref(), Some("rdx"));
        assert_eq!(memory.displacement, 0xb8);
        assert_eq!(memory.index, None);
        assert_eq!(
            memory.address, None,
            "a based reference has no static address"
        );

        // `e8 fb 0f 00 00` — call +0xffb, which from 0x1000 lands at 0x2000.
        let call = one("e8fb0f0000", 0x1000);
        assert_eq!(call.flow, Flow::Call(Some(0x2000)));
        assert_eq!(call.operands, vec![Operand::Target(0x2000)]);

        // `ff 15 fa 0f 00 00` — call qword ptr [rip+0xffa], an import thunk. Indirect, so no
        // destination; the slot's address is what names it, computed against the instruction's end.
        let thunk = one("ff15fa0f0000", 0x1000);
        assert_eq!(thunk.flow, Flow::Call(None));
        let Some(Operand::Memory(slot)) = thunk.operands.first() else {
            panic!("the thunk's operand was not read as memory: {thunk:?}");
        };
        assert_eq!(slot.base.as_deref(), Some("rip"));
        assert_eq!(slot.address, Some(0x2000), "{slot:?}");

        // `ff 24 c5 00 20 00 00` — jmp qword ptr [rax*8+0x2000], a jump table.
        let table = one("ff24c500200000", 0x1000);
        assert_eq!(table.flow, Flow::Jmp(None));
        let Some(Operand::Memory(entry)) = table.operands.first() else {
            panic!("the jump table's operand was not read as memory: {table:?}");
        };
        assert_eq!(entry.index.as_deref(), Some("rax"));
        assert_eq!(entry.scale, 8);
        assert_eq!(entry.displacement, 0x2000);

        // `65 48 8b 04 25 88 01 00 00` — mov rax,qword ptr gs:[188h]. How kernel code reaches the
        // KPCR, and the one place a segment override shows up.
        let kpcr = one("65488b042588010000", 0x1000);
        let Some(Operand::Memory(pcr)) = kpcr.operands.get(1) else {
            panic!("the segment-overridden operand was not read: {kpcr:?}");
        };
        assert_eq!(pcr.segment.as_deref(), Some("gs"));
        assert_eq!(pcr.displacement, 0x188);
        assert_eq!(pcr.base, None);

        // `b4 05` — mov ah,5. A byte register and a small literal, which the text reading had to
        // order carefully because `ah` is also well-formed `h`-suffixed hexadecimal. The encoding
        // has no such collision.
        let byte_register = one("b405", 0x1000);
        assert_eq!(
            byte_register.operands,
            vec![
                Operand::Register(register("ah", "rax", 1)),
                Operand::Immediate(5)
            ]
        );

        // `48 b8 00 00 00 00 00 00 00 80` — mov rax,8000000000000000h. A literal that does not fit
        // a signed 64-bit integer is still a literal; a real routine renders this one.
        let wide = one("48b80000000000000080", 0x1000);
        assert_eq!(
            wide.operands.get(1),
            Some(&Operand::Immediate(0x8000_0000_0000_0000))
        );
    }

    /// The flow classification, including the endings a walk must not fall through and the ones
    /// that only look like endings.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_flow_separates_the_edges_a_walk_may_take() {
        let one = |encoding: &str| {
            split_instruction(
                0x1000,
                &format!("00001000 {encoding} x"),
                InstructionSet::Amd64,
            )
            .flow
        };

        assert_eq!(one("c3"), Flow::Return, "ret");
        assert_eq!(one("0f0b"), Flow::Trap, "ud2");
        assert_eq!(one("ffd0"), Flow::Call(None), "call rax");
        assert_eq!(one("ffe0"), Flow::Jmp(None), "jmp rax");
        assert_eq!(one("31db"), Flow::Fallthrough, "xor ebx,ebx");
        // `74 0e` — je +0xe, which from 0x1000 lands at 0x1010.
        assert_eq!(one("740e"), Flow::Branch(Some(0x1010)), "je");
        // `eb 0e` — jmp +0xe.
        assert_eq!(one("eb0e"), Flow::Jmp(Some(0x1010)), "jmp short");

        // A prefix is not the operation, and skipping it must not lose the operation's flow.
        let locked = split_instruction(0x1000, "00001000 f0ff00 x", InstructionSet::Amd64);
        assert_eq!(locked.mnemonic, "inc", "lock inc dword ptr [rax]");
        assert_eq!(locked.flow, Flow::Fallthrough);
    }

    /// Bytes that were read and did not decode are `Unknown`, never `Unreadable`.
    ///
    /// The two are separate facts and only one of them stops a walk. `Unreadable` means there is
    /// no instruction here; if the engine rendered one and this decoder does not know it — an
    /// extension newer than the pinned version, or a span entered mid-instruction — there *is* an
    /// instruction and the walk should carry on. Getting that backwards discards the rest of a
    /// routine over a version skew.
    ///
    /// `06` is the case with no version skew needed: `push es`, a perfectly good 32-bit
    /// instruction and not an encoding at all in 64-bit mode.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_bytes_that_do_not_decode_are_unknown_rather_than_unreadable() {
        let in_64 = split_instruction(0x1000, "00001000 06 x", InstructionSet::Amd64);
        assert_eq!(in_64.flow, Flow::Unknown, "{in_64:?}");
        assert!(
            in_64.flow.falls_through(),
            "a walk must not stop at an instruction this decoder does not know"
        );

        // And the same byte in the mode where it is an instruction.
        let in_32 = split_instruction(0x1000, "00001000 06 x", InstructionSet::X86);
        assert_eq!(in_32.mnemonic, "push");
        assert_eq!(in_32.flow, Flow::Fallthrough);
    }

    /// A segment override rules out a static address, and a RIP-relative operand keeps the
    /// displacement it encodes rather than a copy of its target.
    ///
    /// `gs:[188h]` is the KPCR and emphatically not address `0x188`: the linear address is the
    /// segment base plus that, and the base is a runtime fact. Reporting one would invite a
    /// consumer to read or symbolise a low address that means nothing.
    ///
    /// The RIP case is the mirror image. The decoder normalises a RIP-relative displacement to its
    /// target, so taking it verbatim reports `[rip+0xffa]` at `0x1000` as `0x2000` — a duplicate
    /// of `address`, where the addressing expression should be.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_a_static_address_is_only_claimed_where_one_exists() {
        let one = |encoding: &str| {
            let decoded = split_instruction(
                0x1000,
                &format!("00001000 {encoding} x"),
                InstructionSet::Amd64,
            );
            decoded
                .operands
                .iter()
                .find_map(|operand| match operand {
                    Operand::Memory(memory) => Some(memory.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no memory operand in {decoded:?}"))
        };

        // `65 48 8b 04 25 88 01 00 00` — mov rax,qword ptr gs:[188h].
        let kpcr = one("65488b042588010000");
        assert_eq!(kpcr.segment.as_deref(), Some("gs"));
        assert_eq!(kpcr.displacement, 0x188);
        assert_eq!(
            kpcr.address, None,
            "a segment override has no address the instruction alone knows: {kpcr:?}"
        );

        // `ff 15 fa 0f 00 00` — call qword ptr [rip+0xffa], six bytes, so the next IP is 0x1006
        // and the target is 0x2000.
        let thunk = one("ff15fa0f0000");
        assert_eq!(thunk.base.as_deref(), Some("rip"));
        assert_eq!(thunk.address, Some(0x2000), "{thunk:?}");
        assert_eq!(
            thunk.displacement, 0xffa,
            "the encoded displacement, not a second copy of the target: {thunk:?}"
        );

        // An absolute reference with no override still has one.
        // `48 8b 04 25 00 20 00 00` — mov rax,qword ptr [2000h].
        let absolute = one("488b042500200000");
        assert_eq!(absolute.address, Some(0x2000));
        assert_eq!(absolute.displacement, 0x2000);
        assert_eq!(absolute.segment, None);

        // And an absolute address is canonicalised into its instruction's space exactly as a
        // branch target is. Absolute globals and import slots are ordinary in x86 kernel code,
        // so this is the field a consumer follows.
        // `a1 00 20 00 80` — mov eax,dword ptr [80002000h], in 32-bit code at a high address.
        let high = split_instruction(
            0xffffffff_80001000,
            "ffffffff`80001000 a100200080 x",
            InstructionSet::X86,
        );
        let Some(Operand::Memory(global)) = high.operands.get(1) else {
            panic!("no absolute operand in {high:?}");
        };
        assert_eq!(
            global.address,
            Some(0xffffffff_80002000),
            "the high half was dropped: {global:?}"
        );
    }

    /// A negative displacement is negative, whatever the address width.
    ///
    /// The decoder keeps a 32-bit effective address in its 32-bit representation, so `[ebp-8]`
    /// comes back as `0xfffffff8` and a straight widening cast reports it as four billion. The
    /// field promises a *signed* displacement, and `[ebp-8]` is the commonest local-variable
    /// reference there is.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_a_negative_displacement_survives_a_narrow_address_width() {
        let memory = |encoding: &str, set: InstructionSet| {
            let decoded = split_instruction(0x1000, &format!("00001000 {encoding} x"), set);
            decoded
                .operands
                .iter()
                .find_map(|operand| match operand {
                    Operand::Memory(memory) => Some(memory.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no memory operand in {decoded:?}"))
        };

        // `8b 45 f8` — mov eax,dword ptr [ebp-8], in 32-bit code.
        let local32 = memory("8b45f8", InstructionSet::X86);
        assert_eq!(local32.base.as_deref(), Some("ebp"));
        assert_eq!(local32.displacement, -8, "{local32:?}");

        // `48 8b 45 f8` — mov rax,qword ptr [rbp-8], the 64-bit form, which was already right.
        let local64 = memory("488b45f8", InstructionSet::Amd64);
        assert_eq!(local64.base.as_deref(), Some("rbp"));
        assert_eq!(local64.displacement, -8, "{local64:?}");

        // And a positive one is unchanged in both.
        assert_eq!(memory("8b4508", InstructionSet::X86).displacement, 8);
        assert_eq!(memory("488b4508", InstructionSet::Amd64).displacement, 8);

        // A scaled index does not change the reading either.
        // `8b 44 88 f8` — mov eax,dword ptr [eax+ecx*4-8].
        let scaled = memory("8b4488f8", InstructionSet::X86);
        assert_eq!(scaled.index.as_deref(), Some("ecx"));
        assert_eq!(scaled.scale, 4);
        assert_eq!(scaled.displacement, -8, "{scaled:?}");

        // The width comes from the **displacement field**, not from the address registers, and a
        // VSIB gather is where that matters: its index is a vector register, so a width taken
        // from the index would be 128 bits or more, the sign extension would be a no-op, and a
        // negative displacement would come back as four billion.
        // `c4 e2 79 92 0c 95 f8 ff ff ff` — vgatherdps xmm1,dword ptr [xmm2*4-8],xmm0.
        let gather = memory("c4e279920c95f8ffffff", InstructionSet::X86);
        assert!(
            gather
                .index
                .as_deref()
                .is_some_and(|r| r.starts_with("xmm")),
            "not the VSIB form this is about: {gather:?}"
        );
        assert_eq!(gather.base, None);
        assert_eq!(gather.displacement, -8, "{gather:?}");

        // And the mirror of that: an EVEX operand's `disp8` is **compressed**, so the decoder
        // hands back the displacement already multiplied by the tuple's scale while the encoded
        // field is still one byte. Sign-extending the expanded value from eight bits turns a
        // legitimate `+128` into `-128`, which is why the width cannot come from the field either.
        // `62 f1 7c 48 28 41 02` — vmovaps zmm0,zmmword ptr [rcx+80h]: an encoded `disp8` of 2,
        // scaled by the 64-byte tuple.
        let evex = memory("62f17c48284102", InstructionSet::Amd64);
        assert_eq!(evex.base.as_deref(), Some("rcx"), "{evex:?}");
        assert_eq!(evex.displacement, 128, "{evex:?}");
    }

    /// An address-size override makes a 64-bit instruction's relative operand `EIP`-relative, and
    /// the two halves of the subtraction stop being the same width.
    ///
    /// The decoder wraps the target to 32 bits while the instruction's own next address stays 64,
    /// so subtracting them directly reports an enormous negative displacement rather than the
    /// small number the instruction encodes.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_eip_relative_displacement_is_computed_at_its_own_width() {
        let operand = |at: u64, encoding: &str| {
            let decoded =
                split_instruction(at, &format!("00001000 {encoding} x"), InstructionSet::Amd64);
            decoded
                .operands
                .iter()
                .find_map(|operand| match operand {
                    Operand::Memory(memory) => Some(memory.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no memory operand in {decoded:?}"))
        };

        // `67 48 8b 05 fa 0f 00 00` — mov rax,qword ptr [eip+0xffa], eight bytes.
        let overridden = operand(0xffffffff_80001000, "67488b05fa0f0000");
        assert_eq!(overridden.base.as_deref(), Some("eip"), "{overridden:?}");
        assert_eq!(overridden.displacement, 0xffa, "{overridden:?}");

        // The ordinary 64-bit form is unchanged: `48 8b 05 fa 0f 00 00`, seven bytes.
        let plain = operand(0xfffff805_5ec04750, "488b05fa0f0000");
        assert_eq!(plain.base.as_deref(), Some("rip"));
        assert_eq!(plain.displacement, 0xffa, "{plain:?}");
    }

    /// A 32-bit branch target lands in the address space its instruction was given.
    ///
    /// Decoding 32-bit code computes a 32-bit target, so an instruction whose own address carries
    /// high bits — a 32-bit effective machine over a 64-bit address, which is what `.effmach x86`
    /// produces, and any target whose addresses the engine hands out sign-extended — gets a
    /// destination in a different address space from the instruction that names it. A module-bounds
    /// check then rejects the edge, and anything reading or symbolising it reads the wrong place.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_a_32_bit_target_stays_in_its_instructions_address_space() {
        // `e8 fb 0f 00 00` — call +0xffb. Five bytes, so from `…1000` the next IP is `…1005` and
        // the destination is `…2000`, whatever the high half is.
        let high = split_instruction(
            0xffffffff_80001000,
            "ffffffff`80001000 e8fb0f0000 x",
            InstructionSet::X86,
        );
        assert_eq!(
            high.flow,
            Flow::Call(Some(0xffffffff_80002000)),
            "the high half of the address was dropped: {high:?}"
        );
        assert_eq!(high.operands, vec![Operand::Target(0xffffffff_80002000)]);

        // And an ordinary low 32-bit address is untouched.
        let low = split_instruction(0x00401000, "00401000 e8fb0f0000 x", InstructionSet::X86);
        assert_eq!(low.flow, Flow::Call(Some(0x00402000)), "{low:?}");

        // 64-bit decoding was never affected: its own arithmetic is already 64-bit.
        let wide = split_instruction(
            0xfffff805_5ec04750,
            "fffff805`5ec04750 e8fb0f0000 x",
            InstructionSet::Amd64,
        );
        assert_eq!(wide.flow, Flow::Call(Some(0xfffff805_5ec05750)), "{wide:?}");

        // And 64-bit must **not** inherit a high half, because a `rel32` reaches ±2 GB and so can
        // legitimately cross a 4 GB boundary. From `…f805`fffffff0` the destination is in
        // `…f806`, and masking it back into `…f805` would move it four gigabytes.
        let crossing = split_instruction(
            0xfffff805_fffffff0,
            "fffff805`fffffff0 e8fb0f0000 x",
            InstructionSet::Amd64,
        );
        assert_eq!(
            crossing.flow,
            Flow::Call(Some(0xfffff806_00000ff0)),
            "a 64-bit branch across a 4 GB boundary was dragged back: {crossing:?}"
        );
    }

    /// A 32-bit address keeps the half its instruction is in, and is **not** sign-extended.
    ///
    /// Sign-extending has been proposed twice, on the theory that the engine hands out high x86
    /// addresses in sign-extended form. Measured on this build against a 32-bit user target
    /// (`cppthrow-fastfail-x86.dmp`): `? 80002000` evaluates to `80002000` and `.formats` prints
    /// `Hex: 80002000` — eight digits, unextended. So sign-extending would invent
    /// `ffffffff80002000` for an address the engine calls `80002000`, and on a 32-bit kernel,
    /// where most code is above bit 31, it would do so for nearly every address.
    ///
    /// The cost of inheriting instead is one straddling case, asserted here so the choice is
    /// pinned rather than merely written down: a low instruction reaching a high absolute keeps
    /// the low half. That is the narrower exposure of the two, and the doc on `canonical_target`
    /// says what would reopen it.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_a_32_bit_address_is_not_sign_extended() {
        // `a1 00 20 00 80` — mov eax,dword ptr [80002000h], from a *low* instruction address.
        let straddling =
            split_instruction(0x00401000, "00401000 a100200080 x", InstructionSet::X86);
        let Some(Operand::Memory(global)) = straddling.operands.get(1) else {
            panic!("no absolute operand in {straddling:?}");
        };
        assert_eq!(
            global.address,
            Some(0x0000_0000_8000_2000),
            "a 32-bit address was sign-extended into a space the engine does not use: {global:?}"
        );

        // And a genuine 32-bit target's addresses are all in the low half anyway, which is why
        // inheriting reproduces the measurement exactly.
        let ordinary = split_instruction(0x00401000, "00401000 e8fb0f0000 x", InstructionSet::X86);
        assert_eq!(ordinary.flow, Flow::Call(Some(0x00402000)));
    }

    /// `hlt` is not an ending, though it is grouped with one in every mnemonic list.
    ///
    /// A halted processor resumes at the next instruction when an interrupt or NMI wakes it, and
    /// kernel idle loops are built on exactly that. Classifying it with the undefined-instruction
    /// traps truncates every one of them at the halt.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_hlt_keeps_its_wake_up_edge() {
        let halt = split_instruction(0x1000, "00001000 f4 hlt", InstructionSet::Amd64);
        assert_eq!(halt.mnemonic, "hlt");
        assert_eq!(halt.flow, Flow::Fallthrough);
        assert!(
            halt.flow.falls_through(),
            "an idle loop continues past its halt"
        );
    }

    /// A software interrupt is classified by its vector, because most of them return.
    ///
    /// `int 2eh` is the 32-bit system-call path: a walk that stops there discards every
    /// instruction after a syscall, which on that architecture is most of a function. The two that
    /// do not return are `int 29h` (`__fastfail`) and `int 3` — the breakpoint a compiler emits as
    /// padding behind unreachable code, which encodes as the one-byte `0xcc` as well as the
    /// two-byte `cd 03`, so both have to be caught.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_a_software_interrupt_is_classified_by_its_vector() {
        let one = |encoding: &str| {
            split_instruction(
                0x1000,
                &format!("00001000 {encoding} x"),
                InstructionSet::Amd64,
            )
            .flow
        };

        assert_eq!(one("cd29"), Flow::Trap, "int 29h — __fastfail");
        assert_eq!(one("cc"), Flow::Trap, "int 3 — the one-byte breakpoint");
        assert_eq!(one("cd03"), Flow::Trap, "int 3 — the two-byte form");
        assert_eq!(
            one("cd2e"),
            Flow::Fallthrough,
            "the 32-bit system call returns, and the walk must go on past it"
        );
        assert_eq!(one("cd2d"), Flow::Fallthrough);

        assert!(one("cd2e").falls_through());
        assert!(!one("cd29").falls_through());
    }

    /// `xbegin` starts a transaction and takes its operand on an abort, so it has both edges.
    ///
    /// The abort path is commonly where the lock-based fallback lives, so a walk that only falls
    /// through misses a whole implementation of the routine rather than a branch of it. `xabort`
    /// is the opposite call and is deliberate: the SDM makes it a NOP outside a transaction, so
    /// treating it as a transfer would drop everything after it wherever RTM is inactive.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_the_transactional_instructions_keep_the_edges_they_have() {
        // `c7 f8 0a 00 00 00` — xbegin +0xa, which from 0x1000 lands at 0x1010.
        let begin = split_instruction(0x1000, "00001000 c7f80a000000 x", InstructionSet::Amd64);
        assert_eq!(begin.mnemonic, "xbegin");
        assert_eq!(begin.flow, Flow::Branch(Some(0x1010)));
        assert!(
            begin.flow.falls_through(),
            "a transaction that starts goes on"
        );

        // `c6 f8 00` — xabort 0.
        let abort = split_instruction(0x1000, "00001000 c6f800 x", InstructionSet::Amd64);
        assert_eq!(abort.mnemonic, "xabort");
        assert_eq!(abort.flow, Flow::Fallthrough);
    }

    /// An operand's width is the encoding's, and the two vector families are the ones worth
    /// pinning: an MMX operand is 64 bits and the `xmm` beside it is 128, so a reading that folds
    /// them doubles every MMX access while nothing about it looks wrong.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "decodes through iced-x86; see MIRI AND THE DECODER above"
    )]
    fn test_an_operand_width_comes_from_the_encoding() {
        let width = |encoding: &str, index: u32| {
            let one = split_instruction(
                0x1000,
                &format!("00001000 {encoding} x"),
                InstructionSet::Amd64,
            );
            match one.operands.get(index as usize) {
                Some(Operand::Memory(memory)) => memory.size,
                other => panic!("{encoding} operand {index} was not memory: {other:?} in {one:?}"),
            }
        };

        // `88 18` — mov byte ptr [rax],bl.
        assert_eq!(width("8818", 0), Some(1));
        // `66 89 18` — mov word ptr [rax],bx.
        assert_eq!(width("668918", 0), Some(2));
        // `89 18` — mov dword ptr [rax],ebx.
        assert_eq!(width("8918", 0), Some(4));
        // `48 89 18` — mov qword ptr [rax],rbx.
        assert_eq!(width("488918", 0), Some(8));
        // `0f 6f 00` — movq mm0,mmword ptr [rax]. Sixty-four bits.
        assert_eq!(width("0f6f00", 1), Some(8), "an MMX operand is 64 bits");
        // `66 0f 6f 00` — movdqa xmm0,xmmword ptr [rax]. A hundred and twenty-eight.
        assert_eq!(width("660f6f00", 1), Some(16));
        // `c5 fd 6f 00` — vmovdqa ymm0,ymmword ptr [rax].
        assert_eq!(width("c5fd6f00", 1), Some(32));
    }

    /// glslang/dbgscope#82: a borrowed engine's lifecycle used to die with the wrapper.
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

    /// Connecting to a server that is not there is an **error**, not a panic and not a wait.
    ///
    /// Worth pinning because [`DebugEngine::connect`] is the one constructor whose failure comes
    /// from outside this process — the host may be absent, refusing, or running an engine the
    /// local one will not talk to — where the constructors beside it (`new`,
    /// `from_windbg_client`) answer that class of problem with `expect`. A caller that gets a
    /// panic here cannot report which server it failed to reach, and one that blocks cannot
    /// report anything at all.
    #[cfg(not(miri))]
    #[test]
    fn test_connecting_to_a_server_that_is_not_there_is_an_error() {
        // A pipe nothing publishes. This path creates no session — the connection fails before
        // there is one — so unlike the engine tests below it needs no serialization against the
        // process-wide debuggee.
        let options = "npipe:pipe=dbgscope-no-such-server-2f9c41d8,server=localhost";
        // `let else` rather than `expect_err`, which would want `DebugEngine: Debug`.
        let Err(err) = DebugEngine::connect(options) else {
            panic!("nothing is serving `{options}`, so connecting to it must fail");
        };
        // The connection string travels in the message. This is the one error whose cause is a
        // thing the caller named, and a log line that omits it says only that *a* server was
        // unreachable.
        assert!(err.to_string().contains(options), "{err}");
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

    /// The half of glslang/dbgscope#82 that a registry alone does not close, and the reason the
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

    /// **A pump through one wrapper completes an open held by another**, which is the scope half
    /// of dbgscope#136 stage 3 and was written down as a known gap for two releases before it.
    ///
    /// Two `DebugEngine`s can be live around one `IDebugClient6` -- what
    /// `from_client_interface` is for, and what the test above asserts about identity. The arrival
    /// record was a field on each, so a `wait_for_event` through wrapper B that pumped wrapper A's
    /// held target to its initial break recorded it in B alone: A then read `Listed`, waited again,
    /// and spent its whole bound on an event that had already happened. That is
    /// `examples/deferred_arrival.rs` arm F -- 29.36s against 8.6us -- undone by a wrapper
    /// boundary rather than by a missing record.
    ///
    /// The construction that closes it is `ClientState`, keyed by client pointer and held by
    /// `Arc`, so both wrappers register into and deliver from the same table.
    ///
    /// The assertion is on `Presence` rather than on a duration, because the duration is the
    /// symptom and this is the mechanism: A's open is `Arrived` without A having waited at all.
    #[cfg(not(miri))]
    #[test]
    fn test_a_pump_through_one_wrapper_completes_an_open_held_by_another() {
        let _debuggee = one_debuggee();
        let owner = DebugEngine::new();
        let pending = owner
            .launch_process_begin("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");

        // A second wrapper around the *same* client, which is what an extension builds per
        // command. It knows nothing of the guard above.
        let borrowed = DebugEngine::from_client_interface(owner.client.clone());
        let outcome = borrowed
            .wait_for_event(LIVE_WAIT_MS)
            .expect("the outside pump failed");
        assert!(
            matches!(outcome, WaitOutcome::Stopped { .. }),
            "the pump that realises the launch answered {outcome:?}, so nothing was delivered"
        );

        let WaitKind::Live(registered) = &pending.kind else {
            panic!("a launch guard is not a live open");
        };
        assert!(
            matches!(owner.presence_of(registered), Presence::Arrived),
            "a stop pumped through the second wrapper did not reach the open the first is holding, \
             so its wait() will spend the whole bound on an event that has happened"
        );

        drop(pending);
        owner.end_session().expect("end_session failed");
    }

    /// **A drop lets go of the session's pending opens**, which `end_session` did and `Drop` did
    /// not.
    ///
    /// `Drop` tears down inline rather than calling `end_session`, so it never inherited the line
    /// that forgets them -- which cost nothing while the register was a field on each wrapper and
    /// costs a stale entry now that it is the session's. A guard held by a second wrapper outlives
    /// the owner's drop, and one left registered against a session that has ended is **first in
    /// line** for the next launch's stop through that wrapper, leaving the new guard to time out
    /// on a target that stopped. Raised in review on dbgscope#139.
    #[cfg(not(miri))]
    #[test]
    fn test_a_drop_lets_go_of_the_sessions_pending_opens() {
        let _debuggee = one_debuggee();
        let borrowed = {
            let owner = DebugEngine::new();
            // A second wrapper around the same client, and a guard registered through the owner
            // that the second wrapper knows nothing about.
            let borrowed = DebugEngine::from_client_interface(owner.client.clone());
            let pending = owner
                .launch_process_begin("cmd.exe /c ping -n 30 127.0.0.1")
                .expect("launch failed");
            // Leaked deliberately: this is a guard that outlives the owner's drop, which is the
            // whole shape under test. Its `Registered` never runs, so only the teardown can
            // forget the entry.
            std::mem::forget(pending);
            assert_eq!(
                borrowed
                    .state
                    .arrivals
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .pending
                    .len(),
                1,
                "the open was not registered, so nothing here is under test"
            );
            borrowed
        };

        assert!(
            borrowed
                .state
                .arrivals
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .pending
                .is_empty(),
            "an open registered against a session the owner's drop ended is still first in line, \
             so the next launch through this wrapper loses its stop to it"
        );
    }

    /// **A session's attachments are visible through every wrapper**, both to delivery and to the
    /// teardown that has to let them go.
    ///
    /// Raised in review on dbgscope#139 against the delivery half: wrapper A attaches, drops that
    /// guard, and holds a pending launch; an outside pump through wrapper B then read B's own empty
    /// set, so the attached process -- new to the launch's snapshot, since it had not joined when
    /// that snapshot was taken -- was delivered to A's launch, whose `wait()` returned `Ok` before
    /// its own target stopped.
    ///
    /// The fix is that the record is the **session's**, and the sentence that used to keep it per
    /// wrapper was arguing against the wrong thing: it said sharing would put this decision "behind
    /// an eviction policy", which is true of the identity cache and not of a `Weak` map whose entry
    /// dies with the last wrapper holding it.
    ///
    /// The second half asserted here was not raised and is the sharper one. An `end_session`
    /// through a wrapper that did not perform the attach used to see no attachment to detach, so
    /// its passive end **killed** somebody else's process -- the exact failure the record exists
    /// to prevent, reached through the wrapper boundary. `STILL_RUNNING` is what separates the two
    /// endings; `Child::try_wait` cannot, for the reason `exit_code_of` records.
    #[cfg(not(miri))]
    #[test]
    fn test_a_sessions_attachments_are_visible_through_every_wrapper() {
        let _debuggee = one_debuggee();
        let mut theirs = a_process_to_attach_to();
        {
            let owner = DebugEngine::new();
            owner.attach_process(theirs.id()).expect("attach failed");
            // A second wrapper around the *same* client, as an extension builds per command.
            let borrowed = DebugEngine::from_client_interface(owner.client.clone());
            assert!(
                borrowed.attached_to_a_live_process(),
                "a wrapper that did not perform the attach cannot see it, so its teardown will \
                 take a process it was only looking at"
            );

            // The teardown through that second wrapper has to detach rather than kill.
            let _ = borrowed.end_session();
        }
        assert_eq!(
            exit_code_of(theirs.id()),
            Some(STILL_RUNNING),
            "the attached process was taken by a teardown through the wrapper that did not attach \
             to it"
        );

        let _ = theirs.kill();
        let _ = theirs.wait();
    }

    /// **Two launches pending at once are told apart**, which [`Arrival`] used to document as an
    /// accepted ambiguity.
    ///
    /// A launch is identified by elimination -- `CreateProcessWide` hands back no pid -- so with
    /// two of them pending the first arrival is new to both snapshots and satisfied both waits.
    /// The fix was weighed and rejected at the time because it needed "new engine-wide state,
    /// cleared everywhere a session is replaced and pruned for pid reuse", which is exactly the
    /// lifecycle the record it would have joined already had. A register of *pending opens* has no
    /// such lifecycle: an arrival is **claimed** by the open it is delivered to, so the second
    /// launch is still waiting when the next one comes.
    ///
    /// Asserted on the pair each open was given, which is the only thing that distinguishes them:
    /// both waited for "a process nobody named", and they must not have been given the same one.
    #[cfg(not(miri))]
    #[test]
    fn test_two_launches_pending_at_once_are_told_apart() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        let first = e
            .launch_process_begin("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("first launch failed");
        let second = e
            .launch_process_begin("cmd.exe /c ping -n 30 127.0.0.2")
            .expect("second launch failed");

        // Both spawns are deferred, so each is realised by one wait.
        for _ in 0..2 {
            e.wait_for_event(LIVE_WAIT_MS).expect("a pump failed");
        }

        let (WaitKind::Live(one), WaitKind::Live(two)) = (&first.kind, &second.kind) else {
            panic!("a launch guard is not a live open");
        };
        let arrivals = e
            .state
            .arrivals
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let claimed = |id: ArrivalId| {
            arrivals
                .pending
                .iter()
                .find(|pending| pending.id == id)
                .and_then(|pending| pending.claim.held())
        };
        let (a, b) = (claimed(one.id), claimed(two.id));
        assert!(
            a.is_some() && b.is_some(),
            "two waits realised {a:?} and {b:?}, so one launch was never delivered anything and \
             this says nothing about telling them apart"
        );
        assert_ne!(
            a, b,
            "both launches were given the same arrival, which is the ambiguity a register of \
             pending opens exists to remove"
        );
        drop(arrivals);

        drop(first);
        drop(second);
        e.end_session().expect("end_session failed");
    }

    /// **A launch abandoned before anything pumps does not hand its process to the next launch**
    /// (dbgscope#141).
    ///
    /// Dropping a guard takes a `Waiting` entry out of the register and leaves no exclusion behind
    /// — there is nothing to leave, since nothing was ever delivered to it. The queued
    /// `CreateProcessWide` still produces a process, and it is new to the *next* launch's snapshot
    /// because it did not exist when that snapshot was taken.
    ///
    /// **This has to read which process was delivered, not what the session holds.** Two attempts
    /// through the public surface both passed while the defect was live, which is why the assertion
    /// is where it is: counting processes when `wait()` returns says nothing, because **one pump
    /// realises both queued creates** (measured: session 0 → 2 on a single `WaitForEvent`); and
    /// asking whether the second program is *listed* says nothing either, because membership is the
    /// weaker claim this whole module is built on not confusing with having stopped.
    ///
    /// So it reads the register rather than the session, and asserts the property the fix actually
    /// delivers: **the abandoned entry absorbs an arrival of its own**, distinct from the next
    /// launch's. Before the fix nothing accounted for the abandoned create, so the next launch was
    /// satisfied by the first stop to arrive and no one was waiting for the other process at all.
    ///
    /// **It deliberately does not assert that the next launch got its *own* process, because that
    /// is not true and cannot be made true by this change.** `deliver` offers in registration
    /// order and the abandoned entry is first, so it takes whichever process arrives first — and
    /// one `WaitForEvent` realises *both* queued creates (measured: session 0 → 2 on a single
    /// pump), so which one the event names is a coin flip. Asserting the image name here failed
    /// about half of all runs with the fix in place, which is how this was found. Identifying a
    /// launch by arrival order is the residual ambiguity [`Arrival`] has always documented for two
    /// launches pending at once; dbgscope#139 closed "both guards get the same arrival", not "each
    /// guard gets its own", and closing the second needs something to match on rather than an
    /// order. See dbgscope#141.
    ///
    /// **Several rounds, because one is racy in the direction that matters.** Measured with the fix
    /// backed out, a single round catches the defect 9 times in 10 and passes the other time — a
    /// guard that goes green on broken code one run in ten is the wrong way round.
    #[test]
    #[cfg(not(miri))]
    fn test_an_abandoned_launch_does_not_hand_its_process_to_the_next_one() {
        let _debuggee = one_debuggee();
        for round in 1..=5 {
            an_abandoned_launch_round(round);
        }
    }

    /// One round of [`test_an_abandoned_launch_does_not_hand_its_process_to_the_next_one`], in its
    /// own session so a round cannot inherit the previous one's processes.
    #[cfg(not(miri))]
    fn an_abandoned_launch_round(round: usize) {
        let e = DebugEngine::new();

        // Abandoned before anything pumps, so its create is still queued.
        let abandoned = e
            .launch_process_begin("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("the first launch would not begin");
        drop(abandoned);

        let mine = e
            .launch_process_begin("ping.exe -n 30 127.0.0.2")
            .expect("the second launch would not begin");
        let WaitKind::Live(registered) = &mine.kind else {
            panic!("a launch guard is not a live open");
        };
        let id = registered.id;

        // **Pumped directly rather than through `wait()`**, which consumes the guard and takes the
        // registration with it — the claim has to be read while the open is still alive, and the
        // first draft of this test read it afterwards and found nothing at all. Bounded rather than
        // once, for the reason `test_the_openers_prune_clears_a_claim_on_a_departed_process` gives:
        // one `WaitForEvent` is one *event*, however many creates it happens to realise.
        let claim_of = |id: ArrivalId| {
            e.state
                .arrivals
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .pending
                .iter()
                .find(|pending| pending.id == id)
                .and_then(|pending| pending.claim.held())
        };
        let mut claimed = None;
        for _ in 0..5 {
            claimed = claim_of(id);
            if claimed.is_some() {
                break;
            }
            e.wait_for_event(LIVE_WAIT_MS).expect("a pump failed");
        }
        let mine = claimed.expect("nothing was delivered to the second launch in five pumps");

        // The abandoned entry absorbed an arrival of its own, and a different one. **That** is
        // what the fix delivers: before it, no entry accounted for the abandoned create, so the
        // second launch was satisfied by the first stop to arrive and nothing was waiting for the
        // other process at all.
        let absorbed = e
            .state
            .arrivals
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .pending
            .iter()
            .find(|pending| pending.abandoned)
            .and_then(|pending| pending.claim.held());
        let absorbed = absorbed.unwrap_or_else(|| {
            panic!(
                "round {round}: the abandoned launch's entry was given nothing, so its process was \
                 left for whoever asked next"
            )
        });
        assert_ne!(
            absorbed, mine,
            "round {round}: the abandoned launch and the one after it were given the same process"
        );

        let _ = e.end_session();
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

    /// Every status the engine can be in while it is waiting to be pumped, and every one it
    /// cannot — pinned by value, because the whole point of asking the engine instead of reading
    /// the command is that this predicate is the only thing standing between a half-alive session
    /// and a settled one.
    #[test]
    fn every_go_and_step_status_is_a_running_one_and_nothing_else_is() {
        for status in [
            DEBUG_STATUS_GO,
            DEBUG_STATUS_GO_HANDLED,
            DEBUG_STATUS_GO_NOT_HANDLED,
            DEBUG_STATUS_STEP_OVER,
            DEBUG_STATUS_STEP_INTO,
            DEBUG_STATUS_STEP_BRANCH,
            DEBUG_STATUS_REVERSE_GO,
            DEBUG_STATUS_REVERSE_STEP_BRANCH,
            DEBUG_STATUS_REVERSE_STEP_OVER,
            DEBUG_STATUS_REVERSE_STEP_INTO,
        ] {
            assert!(
                is_running_status(status),
                "status {status} reads as stopped"
            );
        }
        for status in [
            DEBUG_STATUS_NO_CHANGE,
            DEBUG_STATUS_BREAK,
            DEBUG_STATUS_NO_DEBUGGEE,
            DEBUG_STATUS_IGNORE_EVENT,
            DEBUG_STATUS_RESTART_REQUESTED,
            DEBUG_STATUS_OUT_OF_SYNC,
            DEBUG_STATUS_WAIT_INPUT,
            DEBUG_STATUS_TIMEOUT,
        ] {
            assert!(
                !is_running_status(status),
                "status {status} reads as running"
            );
        }
    }

    /// A watchdog that is disarmed before its deadline returns **at once** and never fires.
    ///
    /// The "at once" is the assertion that matters, and it is a regression test rather than a
    /// tautology: both bounded paths here used to poll a flag on a 200/300ms sleep, so `join` sat
    /// out the rest of that interval on every call — the tax that made a finite `WaitForEvent`
    /// look like the cheaper option for user-mode targets, which is the bug the condvar fixed.
    ///
    /// **Three things keep it from measuring the machine instead** (dbgscope#128, where it failed
    /// on the coverage job of a docs-only PR), and the first is why it was not measuring the
    /// property at all.
    ///
    /// **The thread is shown to be running before it is timed.** Armed and disarmed back to back,
    /// the flag is usually set before the watchdog's thread has run at all, so it sees it at the
    /// top of its loop and returns without ever reaching a wait — the disarm is then immediate
    /// whether it wakes a condvar or waits out a nap. Checked by reverting the condvar (a
    /// `WATCHDOG_REPEAT` nap, `notify_all` removed): the test passed, in 0.00s. So the timing is
    /// taken on a watchdog whose deadline has **passed**, after its own counter says it has fired.
    ///
    /// That counter is incremented inside the closure, which runs a few instructions *before* the
    /// thread re-takes the lock and naps, so it says the thread is running its loop and not that it
    /// is parked in the wait; `SETTLE` covers the rest, and here it is arithmetic rather than the
    /// hope it replaced. A round is only misleading if the thread is descheduled across that gap
    /// for longer than `SETTLE`, and the median then needs **three of five** rounds to be so —
    /// while a regression pays `WATCHDOG_REPEAT - SETTLE`, half again the bound, on every round.
    /// Measured against the reverted condvar: 177-182ms across all five, no fast outlier at all.
    /// Closing the gap outright needs the watchdog to signal from inside the wait, which is
    /// production surface added for a test bound, and this is the cheaper half of that trade. It is
    /// the same condvar, woken by the same `stop`, so nothing is given up by measuring it there —
    /// what is gained is that "parked" is a reading rather than a hope. The never-fires half is
    /// asserted separately, on a watchdog 30s from its deadline, where nothing can say when the
    /// thread got there.
    ///
    /// The bound is [`WATCHDOG_REPEAT`] halved rather than a number of milliseconds: it is the
    /// poll interval the condvar replaced, so it is the only figure here the property is actually
    /// about — "a wake-up, not a poll interval" is a comparison, and it was written as an absolute.
    /// Half of it, because the regression waits out a *whole* interval and being under half is
    /// therefore still an unambiguous verdict.
    ///
    /// And it is the **median** of several rounds rather than one sample or the best of them. A
    /// loaded two-core runner makes *some* rounds slow, so the maximum measures the machine; a
    /// thread caught in the instant between firing and re-entering its wait makes one round fast
    /// whatever the implementation, so the minimum lets a regression through on a single unlucky
    /// round. The median needs three of five to agree, which neither a burst of load nor a stray
    /// unparked round can produce on its own.
    #[cfg(not(miri))]
    #[test]
    fn a_watchdog_disarmed_before_its_deadline_costs_nothing() {
        /// Margin across the few instructions between the closure returning and the thread
        /// parking, and short enough that a regression still pays `WATCHDOG_REPEAT - SETTLE` —
        /// half again the bound below — on a round this does cover.
        const SETTLE: Duration = WATCHDOG_REPEAT.checked_div(4).expect("a nonzero divisor");
        const ROUNDS: usize = 5;

        // Never fires when it is disarmed first, which is the half no handshake can be had for.
        let fires = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&fires);
        let watchdog = Watchdog::arm(Duration::from_secs(30), move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        assert!(
            !watchdog.disarm(),
            "a watchdog 30s from its deadline reported firing"
        );
        assert_eq!(fires.load(Ordering::SeqCst), 0);

        // And disarming a parked one wakes it rather than waiting out its nap.
        let mut took = Vec::with_capacity(ROUNDS);
        for _ in 0..ROUNDS {
            let fires = Arc::new(AtomicU64::new(0));
            let counted = Arc::clone(&fires);
            let watchdog = Watchdog::arm(Duration::ZERO, move || {
                counted.fetch_add(1, Ordering::SeqCst);
            });
            // The handshake: a zero deadline fires on the thread's first pass, so a count of one
            // is that thread reporting it has run and is now napping.
            let armed = Instant::now();
            while fires.load(Ordering::SeqCst) == 0 {
                assert!(
                    armed.elapsed() < Duration::from_secs(10),
                    "a watchdog armed with no time at all never fired"
                );
                thread::yield_now();
            }
            thread::sleep(SETTLE);

            let started = Instant::now();
            let fired = watchdog.disarm();
            took.push(started.elapsed());
            assert!(fired, "a watchdog past its deadline reported not firing");
        }

        took.sort_unstable();
        let median = took[ROUNDS / 2];
        assert!(
            median < WATCHDOG_REPEAT / 2,
            "the median of {ROUNDS} disarms was {median:?} ({took:?}), against a \
             {WATCHDOG_REPEAT:?} poll interval; it waits for a wake-up, not for a poll"
        );
    }

    /// Past its deadline a watchdog fires, and keeps firing until it is disarmed.
    ///
    /// The repeat is not decoration: one `SetInterrupt` is a request the engine acts on at its
    /// next poll, and a busy operation can be between polls when it arrives.
    #[cfg(not(miri))]
    #[test]
    fn a_watchdog_past_its_deadline_keeps_raising_the_break() {
        let fires = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&fires);
        // Zero means "no time at all", so the first raise is immediate.
        let watchdog = Watchdog::arm(Duration::ZERO, move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        thread::sleep(WATCHDOG_REPEAT * 3);
        assert!(
            watchdog.disarm(),
            "a watchdog past its deadline reported not firing"
        );
        let fires = fires.load(Ordering::SeqCst);
        assert!(
            fires >= 2,
            "raised the break {fires} time(s) over three repeat intervals; it must repeat"
        );
    }

    /// A `go` that reaches no stop leaves the engine **usable** — the regression this branch is
    /// named for.
    ///
    /// Before it, `execute_and_wait` used a finite `WaitForEvent` for everything that was not a
    /// live kernel. On expiry that returns `S_FALSE` with the target still running and the engine
    /// holding no current process/thread, so this test's `command_took_effect` was `false` and
    /// stayed `false` for the life of the session — while the call itself reported success, which
    /// is what made it invisible. `run_to_address` has used the bounded wait for every target
    /// since it was written, and documents exactly this; only this path did not.
    ///
    /// Ignored: needs a live target; see the note above these tests.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 a_go_that_never_stops`
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs a live debuggee; run manually with --ignored"]
    fn a_go_that_never_stops_is_reported_and_leaves_the_engine_usable() {
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");

        // No breakpoints, and a target that runs for half a minute: nothing will stop this.
        let run = e
            .execute_and_wait("g", 2_000)
            .expect("execute_and_wait errored");
        assert_eq!(
            run.cut_short,
            Some(Interruption::Deadline { after_ms: 2_000 }),
            "a `g` broken in at its own bound must say so rather than pass for a stop: {}",
            run.output
        );
        assert!(
            command_took_effect(&e, 0x67),
            "the engine is unusable after a `g` that did not stop — the target was left running \
             with no current process/thread"
        );
        let _ = e.end_session();
    }

    /// The same for the two step commands, which take the identical path and were identically
    /// broken. A step on a target that is about to spend thirty seconds inside one `ping` still
    /// completes, so this asserts the *shape*: the call reports what happened, and the engine is
    /// usable afterwards either way.
    ///
    /// Ignored: needs a live target; see the note above these tests.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 stepping_leaves`
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs a live debuggee; run manually with --ignored"]
    fn stepping_leaves_the_engine_usable_whether_or_not_it_reaches_a_stop() {
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");

        for command in ["p", "t"] {
            let run = e
                .execute_and_wait(command, 2_000)
                .unwrap_or_else(|why| panic!("`{command}` errored: {why}"));
            assert!(
                !matches!(run.cut_short, Some(Interruption::OnRequest)),
                "`{command}` reported a break somebody asked for; nobody did"
            );
            assert!(
                command_took_effect(&e, 0x68),
                "the engine is unusable after `{command}`: {}",
                run.output
            );
        }
        let _ = e.end_session();
    }

    /// `settle` is the other half, and this is the reported bug end to end: a plain `Execute` of
    /// execution-control text sets the run state and returns, and until something pumps it the
    /// session refuses every later `g`/`p`/`t` with `0x80040205` while answering read-only
    /// commands normally.
    ///
    /// All three commands, because all three are doors to the same state and a fix that closed one
    /// would look identical from the outside. Asserted in the order that makes each step mean
    /// something: the engine reads as running *only* after the raw command, the pump reports what
    /// the target did, and execution control works again afterwards — which it does not without
    /// the settle.
    ///
    /// Ignored: needs a live target; see the note above these tests.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 settle`
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs a live debuggee; run manually with --ignored"]
    fn settle_pumps_the_run_state_a_raw_command_left_behind() {
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");

        assert!(
            !e.is_running().expect("could not read the execution status"),
            "a freshly launched target is stopped at its initial breakpoint"
        );
        assert!(
            e.settle(2_000).expect("settle errored").is_none(),
            "settle pumped a target that was already stopped"
        );

        for (command, sentinel) in [("g", 0x67u64), ("p", 0x68), ("t", 0x69)] {
            // The bug, in one call: a plain `Execute` sets the run state and moves nothing.
            e.execute_command_bounded(command, 0).unwrap_or_else(|why| {
                panic!("the raw `{command}` itself should succeed — it is the pump that is missing: {why}")
            });
            assert!(
                e.is_running().expect("could not read the execution status"),
                "a raw `{command}` left the engine reading as stopped, so there is nothing here to settle"
            );

            let settled = e
                .settle(2_000)
                .expect("settle errored")
                .unwrap_or_else(|| panic!("settle found nothing to pump after a raw `{command}`"));
            assert!(
                !e.is_running().expect("could not read the execution status"),
                "settle returned with the engine still running after `{command}`: {}",
                settled.output
            );

            // The property the whole thing is for: execution control works again. Before the
            // settle this call fails with 0x80040205, and so does every one after it.
            let run = e.execute_and_wait("g", 2_000).unwrap_or_else(|why| {
                panic!("execution control is still refused after settling `{command}`: {why}")
            });
            assert!(
                command_took_effect(&e, sentinel),
                "the engine is unusable after settling `{command}` and running `g`: {}",
                run.output
            );
        }
        let _ = e.end_session();
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
            "run_to_address left its breakpoint armed after a timeout — a later `g` passing that \
             address would stop there spuriously"
        );
        assert!(
            command_took_effect(&e, 0x63),
            "the engine is unusable after a timeout — the target was left running, or the current \
             process/thread was never restored"
        );
        let _ = e.end_session();
    }

    /// The processes attached to this process's console, or nothing when it has none.
    #[cfg(not(miri))]
    fn console_process_list() -> Vec<u32> {
        use windows::Win32::System::Console::GetConsoleProcessList;
        let mut buf = vec![0u32; 64];
        loop {
            // SAFETY: a valid, writable buffer, described to the call at its true length.
            let n = unsafe { GetConsoleProcessList(&mut buf) } as usize;
            if n == 0 {
                return Vec::new(); // No console: `ERROR_INVALID_HANDLE`.
            }
            if n <= buf.len() {
                buf.truncate(n);
                return buf;
            }
            // Too small — the call stored nothing and answered how many there are.
            buf = vec![0u32; n];
        }
    }

    /// Whether `pid` owns a visible top-level window, which for a console process is its console.
    ///
    /// **The console window is attributed to the console's *client*, not to its host**, which is
    /// the opposite of what the architecture suggests — `conhost.exe` creates the window, and a
    /// reviewer will say so. Measured on this bench: a `cmd.exe` spawned with
    /// `CREATE_NEW_CONSOLE` has exactly one visible top-level window whose
    /// `GetWindowThreadProcessId` is `cmd.exe`'s own pid, titled with its image path, while every
    /// `conhost.exe` on the machine owns none. It is also what `Process.MainWindowHandle` reports
    /// for a console process, and what the caller's calibration re-checks at run time on the host
    /// in front of it — so a host that does attribute the window elsewhere (a terminal that hosts
    /// new consoles as tabs of its own) is caught there rather than assumed away here.
    #[cfg(not(miri))]
    fn has_a_visible_window(pid: u32) -> bool {
        use windows::Win32::Foundation::{HWND, LPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetWindowThreadProcessId, IsWindowVisible,
        };
        use windows::core::BOOL;

        unsafe extern "system" fn visit(window: HWND, state: LPARAM) -> BOOL {
            // SAFETY: `state` is the `Search` the enumeration below was started with, alive for
            // the whole of it.
            let search = unsafe { &mut *(state.0 as *mut Search) };
            let mut owner = 0u32;
            // SAFETY: a window handed to us by the enumeration, and a valid out-parameter.
            unsafe { GetWindowThreadProcessId(window, Some(&mut owner)) };
            // SAFETY: as above.
            if owner == search.pid && unsafe { IsWindowVisible(window) }.as_bool() {
                search.found = true;
                return BOOL(0); // Stop: one is enough.
            }
            BOOL(1)
        }
        struct Search {
            pid: u32,
            found: bool,
        }

        let mut search = Search { pid, found: false };
        // SAFETY: the callback is valid for the call, and the pointer outlives the enumeration.
        let _ = unsafe { EnumWindows(Some(visit), LPARAM(&raw mut search as isize)) };
        search.found
    }

    /// A launched target gets a console of its **own**, and that console has **no window**.
    ///
    /// Three claims, because two of them are what an onlooker doubts about
    /// [`CREATE_NO_WINDOW`]: that the target has a console *at all*, and that the console is not
    /// this process's. They fail in opposite directions. With no console, a console target's
    /// prints land in the *launching* process's stdout — which for an MCP host is its JSON-RPC
    /// channel — and `GetConsoleMode`, `ReadConsole` and the rest fail outright. With a console on
    /// the desktop, which is `CREATE_NEW_CONSOLE` and what this passed until
    /// [#129](https://github.com/glslang/dbgscope/issues/129), every launch opens a window and
    /// takes the foreground.
    ///
    /// **The console is asked for by the target, not inferred here.** `mode con` is stock Windows
    /// and queries `CON` directly, so its own stdout being redirected to a file says nothing about
    /// which console answered: it prints a status with dimensions and a code page where there is
    /// one, and fails where there is not. Measured against all four flags on this bench — no
    /// flags, `CREATE_NEW_CONSOLE` and `CREATE_NO_WINDOW` all report `Status for device CON`, and
    /// `DETACHED_PROCESS` writes nothing, which is what a process with genuinely no console looks
    /// like and is a different flag from this one. That is the check `!ours.contains(&target)`
    /// cannot make on its own, since a target with no console passes it too.
    ///
    /// The window claim is a *negative*, so it is calibrated rather than asserted into the void: a
    /// control spawned here with `CREATE_NEW_CONSOLE` has to show its window first, and only then
    /// is the debuggee — launched earlier, and by now stopped at its loader breakpoint — asked
    /// whether it has one. A host that shows no window for the control (no interactive desktop, or
    /// a default terminal that hosts new consoles as tabs of its own) **fails** rather than
    /// standing down: by then the other two claims have been checked, so nothing is lost by
    /// failing, and a skip here would be a green test that did not check the thing it is named
    /// for. The message says which it is.
    ///
    /// Ignored: needs a live target, which CI has no way to provide. See the note above these
    /// tests on why they must not run in parallel.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 test_a_launched_target`
    #[cfg(not(miri))]
    #[test]
    #[ignore = "needs a live debuggee; run manually with --ignored"]
    fn test_a_launched_target_has_a_console_of_its_own_and_no_window() {
        use std::os::windows::process::CommandExt;

        let probe =
            std::env::temp_dir().join(format!("dbgscope-console-probe-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&probe);

        let e = DebugEngine::new();
        e.launch_process(&format!("cmd.exe /c mode con > \"{}\"", probe.display()))
            .expect("launch failed");
        let target = e
            .current_process_system_id()
            .expect("the debuggee's system id");

        // Its own console, which is what keeps its stdout off ours.
        let ours = console_process_list();
        assert!(
            !ours.contains(&target),
            "the debuggee ({target}) joined this process's console ({ours:?}), so its stdout is \
             this process's stdout — which for an MCP host is the JSON-RPC channel"
        );

        // The calibration: a window this desktop *does* show, spawned after the debuggee so that
        // by the time it appears the debuggee has had at least as long to open one.
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        let mut control = std::process::Command::new("ping.exe")
            .args(["-n", "30", "127.0.0.1"])
            // `ping.exe` itself rather than `cmd.exe /c ping`, because the control has to be
            // *killable*. `kill` ends the process it spawned and nothing beneath it, so a `cmd`
            // wrapper leaves the `ping` grandchild attached to the new console — and a console
            // outlives its creator for as long as any client is still in it, so the window this
            // test opens stays on the desktop for the rest of the thirty seconds, with ownership
            // passing to `ping` as the remaining client. Measured before this: the window
            // outlived a 0.36s run by 29.3s, which stacked one per run on a desktop this test
            // exists to keep clear. Unwrapped, the control is its console's only client and
            // killing it takes the window with it.
            //
            // Its own handles, not ours: `Command` inherits by default, and this one is spawned
            // by the test rather than by the engine — so without this its replies would print
            // into the test's output and read exactly like a debuggee whose stdout leaked.
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NEW_CONSOLE)
            .spawn()
            .expect("spawn the control");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut calibrated = false;
        while std::time::Instant::now() < deadline {
            if has_a_visible_window(control.id()) {
                calibrated = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let debuggee_has_one = has_a_visible_window(target);
        let _ = control.kill();
        let _ = control.wait();

        // Let it run: the probe is written by the target, and the target has not run yet. Its
        // ending is the expected outcome rather than a failure, and is reported as one.
        let _ = e.execute_and_wait("g", 30_000);
        let reported = std::fs::read_to_string(&probe).unwrap_or_default();
        let _ = std::fs::remove_file(&probe);
        assert!(
            reported.contains("Status for device CON"),
            "`mode con` in the debuggee reported no console (`{}`), so the target was launched \
             with none at all rather than with one of its own — which is `DETACHED_PROCESS`, not \
             this flag, and would take its console APIs with it",
            reported.trim()
        );

        // A failure and not a printed stand-down, deliberately: everything above has already run,
        // so nothing is lost by failing here, and the alternative is a green test that did not
        // check the thing it is named for. The two states that reach this are an environment
        // rather than a regression — no interactive desktop, or a default terminal that hosts new
        // consoles as tabs of its own, where the window belongs to the terminal and no window is
        // attributable to any console client — and the message says so.
        let _ = e.end_session();
        assert!(
            calibrated,
            "a control spawned with CREATE_NEW_CONSOLE showed no window of its own either, so \
             this host cannot tell the two flags apart and the window half of this test did not \
             run. Not a regression in `launch_process`: run it on a desktop whose default \
             terminal is the console host."
        );
        assert!(
            !debuggee_has_one,
            "the debuggee ({target}) has a visible window, so it was given a console on the \
             desktop — every launch then steals the foreground (#129)"
        );
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
    pub(super) fn one_debuggee() -> std::sync::MutexGuard<'static, ()> {
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

    /// A debuggee that runs to completion during a `go` is an **ending**, not a catastrophe —
    /// and what the run captured on the way survives it.
    ///
    /// Before this, the `E_UNEXPECTED` `WaitForEvent` answers once the target is gone was
    /// propagated verbatim: `Debug command failed: Catastrophic failure (0x8000FFFF)` for a
    /// program exiting normally, the captured output discarded with it, and the *next* call
    /// saying "No active debuggee" — the accurate half, one call late.
    ///
    /// The tail is the chain that made the session read as wedged rather than finished: `k`
    /// answering a bare `0x80040205` while `.echo` still worked.
    #[test]
    #[cfg(not(miri))]
    fn test_a_target_that_exits_during_a_go_is_an_ending_rather_than_a_catastrophe() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c exit").expect("launch failed");

        let run = e
            .execute_and_wait("g", 30_000)
            .expect("a target running to completion was reported as a failure");
        assert!(
            run.target_gone,
            "the target is gone and the run does not say so: {run:?}"
        );
        assert!(
            run.cut_short.is_none(),
            "nothing interrupted this run — the target simply ended: {run:?}"
        );
        // What the `Err` path used to throw away. *That* it arrived, not which lines it holds:
        // which modules a `cmd.exe` loads on its way out is the host's business, while the echo
        // `DEBUG_EXECUTE_ECHO` puts at the front is always there.
        assert!(
            !run.output.is_empty(),
            "the run captured nothing, so the ending discarded it after all"
        );
        println!("captured across the ending: {:?}", run.output);

        // The chain, now that the engine holds nothing: one error naming the state, on every
        // road in, instead of `0x80040205` from the commands that need a thread and success
        // from the ones that do not.
        for command in ["k 3", "r", "lm", ".echo alive"] {
            assert!(
                matches!(
                    e.execute_command_bounded(command, 5_000),
                    Err(DbgEngError::NoDebuggee)
                ),
                "`{command}` did not answer that there is no debuggee"
            );
        }
        assert!(
            matches!(e.execute_and_wait("g", 5_000), Err(DbgEngError::NoDebuggee)),
            "a second resume was not refused"
        );
        // And the session is still the caller's to end, which is the only thing left to do.
        e.end_session()
            .expect("end_session failed after the ending");
    }

    /// The same ending reached through [`DebugEngine::settle`], which is the corner
    /// [windbg-mcp#226]'s fix left open: a raw `Execute` sets the run state, and the pump that
    /// recovers it is where the target runs out.
    ///
    /// The pump's buffer is the whole of what is at stake here — the command itself printed only
    /// its own echo, and everything the run produced (module loads, a breakpoint banner, an
    /// embedded script's prints) arrives during the wait this used to fail. It is printed rather
    /// than asserted on: what a `cmd.exe` prints on its way out belongs to the host, while the
    /// answer being `Ok(Some(_))` at all is the fix.
    ///
    /// [windbg-mcp#226]: https://github.com/glslang/windbg-mcp/issues/226
    #[test]
    #[cfg(not(miri))]
    fn test_a_target_that_exits_during_the_settle_pump_reports_the_ending_with_its_output() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c exit").expect("launch failed");

        e.execute_command_bounded("g", 0)
            .expect("the raw `g` itself should succeed — it is the pump that follows it");
        assert!(
            e.is_running().expect("could not read the execution status"),
            "a raw `g` left the engine reading as stopped, so there is nothing here to settle"
        );

        let settled = e
            .settle(30_000)
            .expect("the pump reported the target's ending as a failure")
            .expect("settle found nothing to pump after a raw `g`");
        assert!(
            settled.target_gone,
            "the pump ended because the target did, and did not say so: {settled:?}"
        );
        println!("captured by the pump: {:?}", settled.output);

        // Settling again finds nothing rather than pumping a target that is not there.
        assert!(
            e.settle(5_000).expect("a second settle errored").is_none(),
            "settle pumped an engine that holds no target"
        );
        e.end_session()
            .expect("end_session failed after the ending");
    }

    /// A command can take the target away *itself*, and the two that do it differ in a way worth
    /// pinning: `.detach` leaves nothing behind at once, while `.kill` leaves a target that is
    /// still readable and goes away on the **next** resume.
    ///
    /// Both measured on dbgeng 10.0.26100.1 (ARM64), and the asymmetry is the reason
    /// [`CommandRun::target_gone`] is answered from the engine's state after every command rather
    /// than from a list of command names: a list would have to put `.detach` and `q` on it and
    /// leave `.kill` off, and be re-derived for every engine version.
    #[test]
    #[cfg(not(miri))]
    fn test_a_command_that_takes_the_target_away_says_so_and_kill_is_not_one_of_them() {
        let _debuggee = one_debuggee();

        // `.kill`: the target is terminated but the exit events have not been pumped, so the
        // engine still holds it and a stack still reads.
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");
        let killed = e
            .execute_command_bounded(".kill", 10_000)
            .expect("`.kill` failed");
        assert!(
            !killed.target_gone,
            "`.kill` reported the target gone, but the exit events have not been pumped yet: \
             {killed:?}"
        );
        assert!(
            e.execute_command_bounded("k 3", 5_000).is_ok(),
            "the target should still be readable after `.kill`"
        );
        let resumed = e
            .execute_and_wait("g", 30_000)
            .expect("the resume after `.kill` was reported as a failure");
        assert!(
            resumed.target_gone,
            "the resume after `.kill` is where the target goes away: {resumed:?}"
        );
        e.end_session().expect("end_session failed after `.kill`");

        // `.detach`: gone the moment the command returns, with nothing left to pump — so if this
        // were left to `settle` it would be reported by nobody.
        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");
        let detached = e
            .execute_command_bounded(".detach", 10_000)
            .expect("`.detach` failed");
        assert!(
            detached.target_gone,
            "`.detach` did not report that it took the target away: {detached:?}"
        );
        assert!(
            e.settle(5_000).expect("settle errored").is_none(),
            "there is nothing to pump after a detach"
        );
        assert!(
            matches!(
                e.execute_command_bounded("k 3", 5_000),
                Err(DbgEngError::NoDebuggee)
            ),
            "a command after a detach was not refused"
        );
        e.end_session().expect("end_session failed after `.detach`");
    }

    /// A long-lived process to attach to, so a teardown test has something it did not create.
    ///
    /// `ping` rather than `cmd.exe /c ping`, which every launch test here uses: those want a
    /// debuggee and do not care what happens to the `ping` underneath it, while this has to ask
    /// afterwards whether *the process the engine attached to* is still alive — and through a
    /// `cmd` the answer would be about the parent either way round.
    #[cfg(not(miri))]
    /// Registers an open watching the one process this session holds, so a test can see whether a
    /// wait **delivered** a stop to it.
    ///
    /// This is what replaced reading an engine-wide record of every process the engine had stopped
    /// on. The old assertion was "the set is empty"; the new one is "the open waiting for this
    /// process was not given anything", which is the same claim asked of the thing that now does
    /// the work -- and asked through the real predicate rather than around it.
    ///
    /// `Arrival::Attached` because the pid is the identity a test can name. It does not attach:
    /// nothing here touches the engine, only the register.
    #[cfg(not(miri))]
    fn watching_the_only_process(e: &DebugEngine) -> Registered<'_> {
        let held = e.session_processes().expect("could not list the session");
        let [(_, pid)] = held[..] else {
            panic!("this session holds {held:?}, and the helper wants exactly one process");
        };
        registered(e, Arrival::Attached(pid))
    }

    /// Registers `what` and hands back the guard, for the tests that drive `presence_of` or
    /// `wait_for_live_target` directly rather than through an opener.
    #[cfg(not(miri))]
    fn registered(e: &DebugEngine, what: Arrival) -> Registered<'_> {
        let id = e
            .state
            .arrivals
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .register(what);
        Registered { engine: e, id }
    }

    fn a_process_to_attach_to() -> std::process::Child {
        std::process::Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("could not start a process to attach to")
    }

    /// `STILL_ACTIVE` — what `GetExitCodeProcess` answers for a process that has not exited. The
    /// `windows` crate has it as an `NTSTATUS`, which is not the `u32` that call writes.
    #[cfg(not(miri))]
    const STILL_RUNNING: u32 = 259;

    /// What became of `pid`, asked the way a bystander has to ask it — there is no `Child` for a
    /// process DbgEng created, and `Child::try_wait` is the wrong question even where there is
    /// one. **Measured**: a debuggee the kernel kills at `EndSession` has its exit status set
    /// before the call returns, while its process object is not signalled yet, so `try_wait`
    /// answers `Ok(None)` — "still running" — for a process that is already dead.
    ///
    /// `None` when the pid cannot be opened at all, which the callers below treat as a failure
    /// rather than as an answer: both of them want to know *which* ending happened.
    #[cfg(not(miri))]
    fn exit_code_of(pid: u32) -> Option<u32> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_INFORMATION,
        };
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).ok()?;
            let mut code = 0u32;
            let read = GetExitCodeProcess(handle, &mut code).is_ok();
            let _ = CloseHandle(handle);
            read.then_some(code)
        }
    }

    /// **Ending a session must not take a process this engine did not create.**
    ///
    /// The bug this pins, found on windbg-mcp's benches on 2026-08-27: attach to a running
    /// process, end the session, and the process is *gone* — not suspended, not detached,
    /// terminated. Two defaults meeting, neither wrong on its own: `end_session` ended passively,
    /// which disconnects without detaching, and a debuggee whose debug port is destroyed is killed
    /// by the kernel, because `DebugSetProcessKillOnExit` defaults to true.
    ///
    /// **The kill is synchronous with `end_session`**, which is worth knowing because it is not
    /// what the report assumed (it read as the *debugger's* exit doing it, one step later) and
    /// because it is what lets this be a test at all: measured on dbgeng 10.0.26100.1 (ARM64),
    /// the exit code is `0xC0000354` — `STATUS_DEBUGGER_INACTIVE` — the moment the call returns,
    /// against `STILL_ACTIVE` with the detach in place. Ten runs each way, no overlap, so there
    /// is no poll loop here: a bound would only make a failure slower.
    ///
    /// What is **not** a discriminator, and would look like the obvious one:
    /// `CheckRemoteDebuggerPresent` reads `false` after either ending. The passive end does tear
    /// the debug port down — that is precisely why the process dies — so "is it still being
    /// debugged" cannot tell the two apart. Only the target's own fate can.
    #[test]
    #[cfg(not(miri))]
    fn test_ending_a_session_detaches_from_a_process_it_attached_to_rather_than_killing_it() {
        let _debuggee = one_debuggee();
        let mut target = a_process_to_attach_to();
        let pid = target.id();

        let e = DebugEngine::new();
        e.attach_process(pid).expect("attach failed");
        assert!(
            e.attached_to_a_live_process(),
            "the engine attached to a process and does not know it"
        );
        // A target that is really there to be let go of, rather than one that ended under us and
        // would pass this by having had nothing left to kill.
        assert!(
            e.execute_command_bounded("k 3", 5_000).is_ok(),
            "the attached process should be readable before the session ends"
        );

        e.end_session().expect("end_session failed after an attach");
        assert!(
            !e.attached_to_a_live_process(),
            "the engine still believes it holds the process it just let go of"
        );
        assert_eq!(
            exit_code_of(pid),
            Some(STILL_RUNNING),
            "`end_session` did not leave the process it attached to running"
        );

        target.kill().expect("could not clean up the target");
        let _ = target.wait();
    }

    /// The other half of the same rule, and the reason it is a rule about the **opener** rather
    /// than about live user-mode targets: a process the engine *created* still goes with the
    /// session.
    ///
    /// Not symmetry for its own sake — it is the half that says the fix above is a change of
    /// *policy* and not of mechanism. A launch whose debuggee outlived it would leave a process
    /// nobody holds a handle to, started by a debugger that is gone; a caller who wants one kept
    /// is asking for something this crate has no way to be told.
    #[test]
    #[cfg(not(miri))]
    fn test_a_process_the_engine_launched_still_goes_with_its_session() {
        let _debuggee = one_debuggee();

        let e = DebugEngine::new();
        e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");
        assert!(
            !e.attached_to_a_live_process(),
            "a launched process is not one this engine attached to"
        );
        // Read out of the engine rather than tracked from outside: `CreateProcessWide` is the
        // engine's own spawn, so this is the only side that ever knows the pid.
        let pid = eval_expression(&e, "@$tpid").expect("could not read the launched process id");

        e.end_session().expect("end_session failed after a launch");
        // The status is not pinned, only the ending: `STATUS_DEBUGGER_INACTIVE` is what this
        // engine writes today, and what matters is that the process did not survive its session.
        assert_ne!(
            exit_code_of(pid as u32),
            Some(STILL_RUNNING),
            "the process this engine launched (pid {pid}) outlived its session"
        );
    }

    /// **An attachment that can never join is retired**, or its pid is held against a later process
    /// for the life of the session.
    ///
    /// `Attachment::Deferred` is kept precisely because a deferred attach has not arrived and so
    /// cannot have left — but only a successful listing promotes one, so an `AttachProcess` the
    /// engine accepted for a process that then exited before the first `WaitForEvent` left a pid
    /// recorded for good. If Windows handed that number to a process this engine went on to launch,
    /// the launch's own stop was excluded from delivery as somebody else's and its teardown
    /// *detached* from it instead of taking it. Raised in review on dbgscope#139.
    ///
    /// Asserted here on the rule rather than end to end, because reaching it through a real open
    /// costs `LIVE_WAIT_MS` — thirty seconds — and
    /// `test_an_open_that_waits_out_its_bound_retires_a_deferred_attachment` is the `#[ignore]`d
    /// end-to-end half.
    #[test]
    #[cfg(not(miri))]
    fn test_only_a_deferred_attachment_is_retired() {
        let _debuggee = one_debuggee();
        let mut theirs = a_process_to_attach_to();
        {
            let e = DebugEngine::new();
            let attaching = e.attach_process_begin(theirs.id()).expect("attach failed");
            let WaitKind::Live(registered) = &attaching.kind else {
                panic!("an attach guard is not a live open");
            };

            // Joined is the prune's business, not this one's: the attachment is there and may
            // simply have left, which is a different question.
            e.state
                .attached_processes
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .insert(theirs.id(), Attachment::Joined);
            e.retire_deferred_attachment(registered);
            assert!(
                e.state
                    .attached_processes
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .contains_key(&theirs.id()),
                "a joined attachment was retired, so its teardown will take somebody else's process"
            );

            // Deferred is this one's: the open waited its bound and the process never arrived.
            e.state
                .attached_processes
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .insert(theirs.id(), Attachment::Deferred);
            e.retire_deferred_attachment(registered);
            assert!(
                !e.state
                    .attached_processes
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .contains_key(&theirs.id()),
                "an attachment that can never join was kept, so a later process inheriting its pid \
                 is treated as one this engine only attached to"
            );

            drop(attaching);
            let _ = e.end_session();
        }
        let _ = theirs.kill();
        let _ = theirs.wait();
    }

    /// **What counts as proof that an attach produced nothing**, pinned both ways because the
    /// branch that reads it can only be built one way.
    ///
    /// A pump that fails with a session holding nothing is the reviewer's scenario and is what
    /// `test_a_failed_pump_retires_a_deferred_attachment` drives. A pump that fails with a live
    /// session must *not* retire -- the open may have pumped nothing, so the engine has not had a
    /// chance to process the attach -- and that ending is not constructible here. This is the half
    /// of it that is.
    #[test]
    #[cfg(not(miri))]
    fn test_only_an_empty_session_proves_an_attach_produced_nothing() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        assert!(
            e.holds_nothing_at_all(),
            "a fresh engine holds a target, so nothing here means what it says"
        );
        e.launch_process("ping.exe -n 30 127.0.0.1")
            .expect("launch failed");
        assert!(
            !e.holds_nothing_at_all(),
            "a session with a live target read as holding nothing, so a failed pump would retire \
             an attach the engine has not yet had a chance to process"
        );
        let _ = e.end_session();
    }

    /// **A failed pump retires the record too**, which is the ending the bound's version cannot
    /// reach and the one the reviewer's scenario actually takes.
    ///
    /// `AttachProcess` is accepted, the target exits before the first `WaitForEvent`, and the
    /// session then holds nothing -- so the pump fails `E_UNEXPECTED` rather than expiring
    /// (`test_a_wait_with_no_debuggee_fails_rather_than_expiring`), the open returns through its
    /// `?`, and the bound is never reached. Retiring only there left the pid recorded for the life
    /// of the session. Raised in review on dbgscope#139.
    ///
    /// Fast, unlike the bound's version, because the failure is immediate: no debuggee, no wait.
    #[test]
    #[cfg(not(miri))]
    fn test_a_failed_pump_retires_a_deferred_attachment() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        // No target at all, which is what a session whose only process exited before its attach
        // joined looks like -- and is what makes the pump fail instead of expiring.
        assert!(
            !e.has_target().expect("could not read the execution status"),
            "this engine holds a target, so the pump will not fail and nothing is under test"
        );
        let absent = 0x7FFF_FFF0;
        e.claim_attached(absent);
        let waiting = registered(&e, Arrival::Attached(absent));

        let outcome = e.wait_for_live_target(&waiting);
        assert!(
            matches!(outcome, Err(DbgEngError::CommandFailed(_))),
            "the open answered {outcome:?} rather than failing, so it did not take the ending this \
             test is about"
        );
        assert!(
            !e.state
                .attached_processes
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .contains_key(&absent),
            "a pump that failed with the session holding nothing left the record behind, so a \
             later process inheriting that pid is treated as one this engine only attached to"
        );
    }

    /// The end-to-end half of the test above: a live open really does retire the record when it
    /// waits out its bound.
    ///
    /// `#[ignore]`d because it costs `LIVE_WAIT_MS` -- thirty seconds of pumping for a process that
    /// will never arrive -- which is the shape every other test here goes out of its way to avoid.
    /// `cargo test --lib -- --ignored --nocapture --test-threads=1 test_an_open_that_waits_out`
    #[test]
    #[cfg(not(miri))]
    #[ignore = "waits out LIVE_WAIT_MS; run manually with --ignored"]
    fn test_an_open_that_waits_out_its_bound_retires_a_deferred_attachment() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        // A target, so the pump has a session to run against: a wait on an engine with no debuggee
        // *fails* rather than expiring, which ends the open before it reaches its bound
        // (`test_a_wait_with_no_debuggee_fails_rather_than_expiring`).
        e.launch_process("ping.exe -n 60 127.0.0.1")
            .expect("launch failed");
        // A pid this session does not hold, recorded as if an attach to it had been accepted: the
        // open below pumps its whole bound and never sees it.
        let absent = e
            .session_processes()
            .expect("could not list the session")
            .iter()
            .map(|(_, pid)| *pid)
            .max()
            .unwrap_or(4)
            + 1000;
        e.claim_attached(absent);
        let waiting = registered(&e, Arrival::Attached(absent));

        let outcome = e.wait_for_live_target(&waiting);
        assert!(
            matches!(outcome, Err(DbgEngError::LiveTargetTimeout)),
            "the open answered {outcome:?} rather than timing out, so it did not reach the branch \
             that retires the record"
        );
        assert!(
            !e.state
                .attached_processes
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .contains_key(&absent),
            "the open waited its whole bound and left the record behind"
        );

        let _ = e.end_session();
    }

    /// **A prune does not take an attachment that has not joined yet**, which it did, and which
    /// costs somebody else's process.
    ///
    /// `AttachProcess` joins its process at the next `WaitForEvent`, not at the call -- measured,
    /// and printed by `examples/deferred_arrival.rs` arm E. So between `attach_process_begin` and
    /// the wait that completes it, the pid is recorded and the session does not list it; a
    /// `launch_process_begin` in that window prunes on "is it held", finds it is not, and drops the
    /// record. The launch then has no reason to exclude that process, and -- worse -- the teardown
    /// has no reason to detach from it, so the passive end takes a process this engine only
    /// attached to. Raised in review on dbgscope#139.
    ///
    /// `Attachment::Deferred` is what separates "has not arrived" from "has left". The assertion is
    /// on the ending rather than on the record, because the record is the mechanism and the process
    /// surviving is the point.
    #[test]
    #[cfg(not(miri))]
    fn test_a_prune_does_not_take_an_attachment_that_has_not_joined() {
        let _debuggee = one_debuggee();
        let mut theirs = a_process_to_attach_to();
        {
            let e = DebugEngine::new();
            // Begun and *not* waited, so the attach is still deferred: the pid is recorded and the
            // session does not list it yet.
            let attaching = e.attach_process_begin(theirs.id()).expect("attach failed");
            assert!(
                !e.session_processes()
                    .expect("could not list the session")
                    .iter()
                    .any(|(_, pid)| *pid == theirs.id()),
                "the attached process is already listed, so this window does not exist here and \
                 the test is asserting nothing"
            );

            // The opener that prunes, in that window.
            let launching = e
                .launch_process_begin("cmd.exe /c ping -n 30 127.0.0.1")
                .expect("launch failed");
            assert_eq!(
                e.state
                    .attached_processes
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .get(&theirs.id()),
                Some(&Attachment::Deferred),
                "the prune took a record of an attachment that had not joined yet, so the teardown \
                 will treat somebody else's process as one this engine launched"
            );

            attaching.wait().expect("the attach should complete");
            launching.wait().expect("the launch should complete");
            let _ = e.end_session();
        }
        assert_eq!(
            exit_code_of(theirs.id()),
            Some(STILL_RUNNING),
            "the attached process was taken by the session it was only being looked at from"
        );

        let _ = theirs.kill();
        let _ = theirs.wait();
    }

    /// **An engine is reusable, so where its target came from is answered by the last opener and
    /// not by the last attach** — the gap review found in the first version of the fix above
    /// ([glslang/dbgscope#121](https://github.com/glslang/dbgscope/pull/121)).
    ///
    /// The sequence is reachable without a teardown anywhere in it: attach, lose the target (here
    /// a raw `.detach`, which takes it the moment the command returns; a process exiting on its
    /// own does the same), then launch something else on the same engine. With only
    /// `attach_process_begin` recording anything, the flag was still set, and the *launched*
    /// process took the detach branch and survived a session that is supposed to take it.
    ///
    /// Two claims, and the second is the one that generalises: the launched process goes, and the
    /// engine no longer believes it is holding an attached one.
    #[test]
    #[cfg(not(miri))]
    fn test_a_launch_after_a_lost_attach_is_still_a_launch() {
        let _debuggee = one_debuggee();
        let mut target = a_process_to_attach_to();

        let e = DebugEngine::new();
        e.attach_process(target.id()).expect("attach failed");
        let detached = e
            .execute_command_bounded(".detach", 10_000)
            .expect("`.detach` failed");
        assert!(
            detached.target_gone,
            "`.detach` left a target behind, so this is not the state under test: {detached:?}"
        );

        e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch after a lost attach failed");
        assert!(
            !e.attached_to_a_live_process(),
            "the engine still believes it holds an attached process after launching one"
        );
        // **And the record itself was pruned**, which the assertion above cannot see — it asks the
        // session, so a stale pid naming nothing reads as "no attachment" either way. What the
        // pruning is for is the coincidence that cannot be staged in a test: Windows handing the
        // dead process's number to the one this engine just launched, which would then be detached
        // and left running. Reading the field directly is the only way to say the record is clean
        // rather than merely unmatched.
        assert!(
            e.state
                .attached_processes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "the launch left a dead process's pid in the record, where a reused pid can alias it"
        );
        let launched = eval_expression(&e, "@$tpid").expect("could not read the launched pid");

        e.end_session().expect("end_session failed");
        assert_ne!(
            exit_code_of(launched as u32),
            Some(STILL_RUNNING),
            "the process this engine launched (pid {launched}) outlived its session, because the \
             engine was still carrying the previous attach"
        );

        let _ = target.kill();
        let _ = target.wait();
    }

    /// **A target that leaves on its own does not turn its teardown into an error.**
    ///
    /// The other half of the same finding, and the one with a caller-visible cost: an attached
    /// process can exit under the debugger, and if the active detach then failed, ending that
    /// session would report "the debugger reported an error releasing the target" for a program
    /// that had simply finished.
    ///
    /// **It does not fail** — measured on dbgeng 10.0.26100.1 (ARM64): `EndSession` with
    /// `DEBUG_END_ACTIVE_DETACH` succeeds on an engine holding no debuggee. That is why
    /// `end_session` does *not* check `has_target` before taking this branch: the check was
    /// written, measured to change nothing, and removed. This test is what stands in its place —
    /// an engine that ever does refuse fails here, and the guard is one line away.
    ///
    /// `.detach` stands in for the process exiting because it is instantaneous and leaves the
    /// engine in the same state (`DEBUG_STATUS_NO_DEBUGGEE`); what the teardown meets is that
    /// state, not how the target came to be missing.
    #[test]
    #[cfg(not(miri))]
    fn test_ending_a_session_whose_attached_target_already_left_is_not_an_error() {
        let _debuggee = one_debuggee();
        let mut target = a_process_to_attach_to();

        let e = DebugEngine::new();
        e.attach_process(target.id()).expect("attach failed");
        assert!(
            e.execute_command_bounded(".detach", 10_000)
                .expect("`.detach` failed")
                .target_gone,
            "`.detach` left a target behind, so this is not the state under test"
        );
        // And the engine says so, because this asks the session rather than the record: the pid
        // is still written down, and the process it named is gone.
        assert!(
            !e.attached_to_a_live_process(),
            "the engine reports holding an attached process after that process has gone"
        );

        e.end_session()
            .expect("end_session failed on a session whose attached target had already gone");

        let _ = target.kill();
        let _ = target.wait();
    }

    /// The system pids of the processes in this session, read by **selecting each one in turn**.
    ///
    /// `@$tpid` answers for whichever process is *current*, and which process that is after a
    /// launch is not something to assume: measured, a fresh engine leaves the process it just
    /// created current, while one that has held a target before leaves the earlier process
    /// current — so a test reading `@$tpid` straight after a launch gets the launched pid or the
    /// attached one depending on what ran before it in the same binary. That cost a whole round of
    /// "the fix does not work" against a fix that did.
    #[cfg(not(miri))]
    fn session_pids(e: &DebugEngine, count: usize) -> Vec<u64> {
        (0..count)
            .filter_map(|index| {
                e.execute_command(&format!("|{index}s")).ok()?;
                eval_expression(e, "@$tpid")
            })
            .collect()
    }

    /// **A session holding both kinds of process comes apart by where each one came from.**
    ///
    /// The second thing review found, and the one that made the record a set of pids: DbgEng keeps
    /// several user-mode targets in one session — `|` lists them and says `attach` or `create`
    /// against each — so an engine can hold somebody's running service *and* a program it launched
    /// itself. `EndSession` takes one flag for the whole session, so **no choice of flag is
    /// right**: a passive end kills the attached process, an active detach lets the launched one
    /// survive. Detaching the attached ones first, one at a time, is what makes both true at once.
    ///
    /// Both orderings, because what the first version got wrong was an ordering: with one
    /// session-wide flag written by whichever opener ran last, attach-then-launch killed the
    /// service and launch-then-attach let the launched program outlive its session.
    #[test]
    #[cfg(not(miri))]
    fn test_a_mixed_session_comes_apart_by_where_each_process_came_from() {
        let _debuggee = one_debuggee();

        for attach_first in [true, false] {
            let mut theirs = a_process_to_attach_to();
            let e = DebugEngine::new();
            if attach_first {
                e.attach_process(theirs.id()).expect("attach failed");
                e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
                    .expect("launch failed");
            } else {
                e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
                    .expect("launch failed");
                e.attach_process(theirs.id()).expect("attach failed");
            }

            // The state under test is a session holding two processes; if the second opener did
            // not add one, this test is asserting about something else entirely.
            let listed = e.execute_command("|").expect("`|` failed");
            let pids = session_pids(&e, 2);
            assert_eq!(
                pids.len(),
                2,
                "attach_first={attach_first}: this is not a two-process session:\n{listed}"
            );
            // Identified by elimination rather than by asking which is current, for the reason
            // `session_pids` gives.
            let ours = *pids
                .iter()
                .find(|pid| **pid != u64::from(theirs.id()))
                .unwrap_or_else(|| {
                    panic!(
                        "attach_first={attach_first}: the launched process is not here: {pids:?}"
                    )
                });

            e.end_session()
                .expect("end_session failed on a mixed session");
            assert_eq!(
                exit_code_of(theirs.id()),
                Some(STILL_RUNNING),
                "attach_first={attach_first}: the session's end killed the process it had only \
                 attached to"
            );
            assert_ne!(
                exit_code_of(ours as u32),
                Some(STILL_RUNNING),
                "attach_first={attach_first}: the process this engine launched (pid {ours}) \
                 outlived its session"
            );

            let _ = theirs.kill();
            let _ = theirs.wait();
        }
    }

    /// **A guard whose target arrived before its `wait()` returns at once, not on the next event.**
    ///
    /// [`PendingTarget`] documents dropping a guard and letting the target materialize at the next
    /// `WaitForEvent` from any source. A guard still *held* when that happens is the same
    /// situation, and until [`Arrival`] the wait had no way to notice: it made its one
    /// `WaitForEvent` regardless, which on an arrived target resumes it and waits for whatever
    /// happens next. Measured across this fix — **29.36s and `E_UNEXPECTED`** (the `ping` outran
    /// its own bound and took the target with it) against **8.6µs and `Ok`**.
    ///
    /// Two phases, because they differ in what the engine's last event says at the moment of the
    /// wait: with one target it is still this one's, and with a second target arrived since it is
    /// not. Both must pass, and that they can is the argument for an arrival being **delivered by
    /// the wait that observed it** rather than read from one session-wide slot afterwards — which
    /// is where three rounds of review on that branch ended up.
    ///
    /// The deterministic half of dbgscope#128, and the only half that is: the issue's own failure
    /// is a race that reproduces a few times in forty rounds under CPU load and never on a quiet
    /// machine, so it is `test_a_mixed_session_comes_apart_by_where_each_process_came_from` that
    /// carries it, exactly as it did when it found it. This asks the same question — does a live
    /// open end when *its* target is in the session — of a state that can be built rather than
    /// waited for.
    ///
    /// The bound is a tenth of the open's own, since what is being separated is "returned without
    /// waiting" from "waited out the whole of `LIVE_WAIT_MS`", and there is three orders of
    /// magnitude between them to spend on a slow runner.
    #[test]
    #[cfg(not(miri))]
    fn test_a_guard_whose_target_already_arrived_does_not_wait_for_another_event() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        let pending = e
            .launch_process_begin("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");
        // Somebody else's pump — `execute_and_wait`, `run_to_address`, another guard — brings the
        // deferred spawn in before this guard is waited on.
        e.wait_for_event(LIVE_WAIT_MS)
            .expect("the outside pump failed");

        let started = Instant::now();
        pending.wait().expect("wait on an arrived target failed");
        let took = started.elapsed();

        assert!(
            took < Duration::from_millis(u64::from(LIVE_WAIT_MS / 10)),
            "wait() took {took:?} on a target already in the session; it waited for another event \
             rather than asking whether its own had arrived"
        );
        assert_eq!(
            e.session_processes()
                .expect("could not list the session's processes")
                .len(),
            1,
            "the launched process is not in the session the wait said it had joined"
        );
        e.end_session().expect("end_session failed");

        // And again with the engine's last event no longer this target's. `GetLastEventInformation`
        // is one session-wide slot, so a second target arriving overwrites the evidence that this
        // one ever stopped — which is why a stop is delivered by the wait that observed it rather
        // than being read back from that slot later. Measured across that record: 29.4s and
        // `E_UNEXPECTED` without it, single-digit µs with.
        let mut theirs = a_process_to_attach_to();
        let e = DebugEngine::new();
        let pending = e
            .launch_process_begin("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");
        e.wait_for_event(LIVE_WAIT_MS)
            .expect("the outside pump failed");
        e.attach_process(theirs.id()).expect("attach failed");

        let started = Instant::now();
        pending
            .wait()
            .expect("wait on an arrived target whose stop was overwritten failed");
        let took = started.elapsed();

        assert!(
            took < Duration::from_millis(u64::from(LIVE_WAIT_MS / 10)),
            "wait() took {took:?} on a target already in the session; a later target's event is \
             not evidence that this one never arrived"
        );
        e.end_session().expect("end_session failed");
        let _ = theirs.kill();
        let _ = theirs.wait();
    }

    /// **A stop says which process it was, and is delivered to the open waiting for it.**
    ///
    /// The wait here is the "outside pump" [`PendingTarget`] documents: a guard is begun and left
    /// held while somebody else drives the engine, so this `wait_for_event` is the call that
    /// realises the deferred spawn and stops on its initial break. That makes it the shape where
    /// delivery does the work -- the pump belongs to nobody, and the open it completes is one the
    /// pumping caller has never heard of.
    ///
    /// Asserted against `session_processes` rather than against a literal, because the pair is two
    /// numbers the engine hands out and neither is predictable; and against the register as well,
    /// because the value the pump answers and the delivery it makes are one read and must not be
    /// able to disagree.
    #[test]
    #[cfg(not(miri))]
    fn test_a_stop_says_which_process_it_stopped_on() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        let pending = e
            .launch_process_begin("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");

        let outcome = e
            .wait_for_event(LIVE_WAIT_MS)
            .expect("the outside pump failed");
        let WaitOutcome::Stopped { process } = outcome else {
            panic!("the pump that realised the launch answered {outcome:?} rather than a stop");
        };
        let held = e.session_processes().expect("could not list the session");
        assert_eq!(
            process.map(|pair| vec![pair]).unwrap_or_default(),
            held,
            "the stop named {process:?}, which is not the one process this session holds"
        );
        let WaitKind::Live(registered) = &pending.kind else {
            panic!("a launch guard is not a live open");
        };
        assert!(
            matches!(e.presence_of(registered), Presence::Arrived),
            "the stop was not delivered to the open that was waiting for it, so its `wait()` would \
             pump again for an event that has already happened"
        );

        drop(pending);
        e.end_session().expect("end_session failed");
    }

    /// **A wait cannot expire on an engine with no debuggee**, which is the fact that keeps a
    /// live open from ever ending `Ok` with nothing behind it.
    ///
    /// Review round 6 on #133 read the two halves as meeting: a finite `WaitForEvent` that expires
    /// returns `S_FALSE`, which the generated wrapper maps to `Ok`, and `presence_of` answering
    /// `Unknown` for an empty session would then end the open successfully. The first half is
    /// true — a 300ms wait on a target with nothing to report returns `Ok` at 312ms — and the
    /// composite is not, because the wait *errors* rather than expiring once the debuggee is gone.
    /// Pinned here rather than argued, since it is a claim about an engine build and the next one
    /// is free to disagree; if it ever does, the arm below becomes a road rather than a mapping.
    #[test]
    #[cfg(not(miri))]
    fn test_a_wait_with_no_debuggee_fails_rather_than_expiring() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        assert!(
            !e.has_target().expect("could not read the execution status"),
            "a fresh engine reported a debuggee"
        );
        let waited = e.wait_for_event(300);
        assert!(
            waited.is_err(),
            "a wait on an engine with no debuggee returned {waited:?} instead of failing — if it \
             now expires, `presence_of`'s empty-session arm is reachable and wants a bound test"
        );
    }

    /// **An expired wait says so, and only [`WaitOutcome::Stopped`] records** -- which is now one
    /// assertion about a value where it used to be two about state.
    ///
    /// Review round 7 of #133 read the gate as missing: an expired `WaitForEvent` answers
    /// `S_FALSE`, the generated wrapper flattens it into the same `Ok` a stop gets, and the
    /// recorder would then read the engine's *previous* event and join a stale engine id to
    /// whatever process now holds it. The first three steps are exactly right. The last was not,
    /// on the engine measured: an expired wait leaves `GetLastEventInformation` reporting
    /// `DEBUG_ANY_ID` rather than the event before it, so the join found no process and recorded
    /// nothing. The bug was unreachable and the safety was **incidental** -- resting on an
    /// undocumented sentinel, in the one function whose output a guard trusts to end an
    /// initial-break wait early. A gate at the call site made it deliberate; the gate is now the
    /// [`WaitOutcome::Expired`] arm, which does not reach the recorder at all.
    ///
    /// So the first assertion is the one that matters and the sentinel is no longer load-bearing:
    /// an engine that started reporting the previous event there would change nothing, because
    /// nothing on this path reads it. The record is asserted after it to pin that the arm and the
    /// recorder have not been rewired.
    #[test]
    #[cfg(not(miri))]
    fn test_an_expired_wait_records_no_stop() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        // `ping.exe` and not `cmd.exe /c ping`, for the reason
        // `test_a_launched_target_has_a_console_of_its_own_and_no_window` records: the passive
        // end takes the process this engine launched and nothing beneath it, so the wrapper
        // leaves a `ping` grandchild running for the rest of its thirty seconds.
        e.launch_process("ping.exe -n 30 127.0.0.1")
            .expect("launch failed");
        let watcher = watching_the_only_process(&e);

        let outcome = e
            .wait_for_event(300)
            .expect("the wait should expire, not fail");
        assert_eq!(
            outcome,
            WaitOutcome::Expired,
            "a wait with nothing to report answered {outcome:?}, so the bound did not expire and \
             nothing here is under test"
        );
        assert!(
            !matches!(e.presence_of(&watcher), Presence::Arrived),
            "a wait that stopped on nothing delivered a stop to an open waiting for one"
        );
    }

    /// **Nor is a host-requested one**, which is the same break arriving through the other door.
    ///
    /// `InterruptHandle::interrupt` and the watchdog both reach the engine through `SetInterrupt`
    /// and produce the same stop; only the advice to the caller differs, which is what
    /// `Interruption`'s two variants carry. Gating on the watchdog's flag alone left this half
    /// open -- the fix for the forced break, applied to one of its two origins.
    #[test]
    #[cfg(not(miri))]
    fn test_a_host_requested_break_records_no_stop() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        e.launch_process("ping.exe -n 30 127.0.0.1")
            .expect("launch failed");
        let watcher = watching_the_only_process(&e);

        let handle = e.interrupt_handle();
        let asked = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            handle.interrupt()
        });
        // Long enough that the watchdog cannot be what ends this: the assertion below is that the
        // *host* origin stands down, and a deadline would satisfy the old gate as well.
        let run = e
            .execute_and_wait("g", 30_000)
            .expect("the go should return");
        asked.join().expect("interrupting thread panicked").ok();
        assert!(
            matches!(run.cut_short, Some(Interruption::OnRequest)),
            "the run ended as {:?}, so no host-requested break was under test",
            run.cut_short
        );
        assert!(
            !matches!(e.presence_of(&watcher), Presence::Arrived),
            "a break a host asked for was delivered as the target arriving"
        );
    }

    /// **No operation leaves an interrupt standing behind it**, which is the precondition
    /// [`DebugEngine::pump`] attributes its outcome under.
    ///
    /// `run_to_address` was the one bounded path that neither cleared it on the way in nor
    /// consumed it on the way out. That cost it nothing -- it classified by the watchdog's own
    /// flag -- right up until the recorder began reading the shared one, at which point a single
    /// timed-out `run_to_address` left every later wait declining to record a real initial break,
    /// and any guard still held pumping to its bound for a target that had already stopped. Round
    /// 12 of #133; the comment claiming this precondition held was written in round 9.
    ///
    /// It is now two properties of every bounded path rather than a line in one of them. The pump
    /// *takes* the request filed against its operation, because the request belongs to the wait it
    /// ended; and the operation's guard closes the scope on the way out whether it was read or not.
    /// So this asserts the scope is **empty** — nothing running and nothing asked — rather than
    /// that one flag came back down.
    ///
    /// `timeout_ms` of 0 is an immediate timeout by that function's own contract, so the watchdog
    /// fires and raises the flag -- which the outcome assertion is here to confirm, since a run
    /// that ended some other way would leave nothing to have been cleared and pass regardless.
    #[test]
    #[cfg(not(miri))]
    fn test_a_timed_out_run_leaves_no_interrupt_standing() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        e.launch_process("ping.exe -n 30 127.0.0.1")
            .expect("launch failed");
        // The current pc: an address a breakpoint certainly takes, and one a resumed target does
        // not immediately hit again, so the run reaches its deadline rather than the address.
        let here = e
            .instruction_pointer()
            .expect("could not read the instruction pointer");

        let run = e.run_to_address(here, 0).expect("run_to_address failed");
        assert!(
            matches!(run.outcome, RunToOutcome::Timeout),
            "the run ended as {:?}, so its watchdog never raised the flag under test",
            run.outcome
        );
        let scope = e.state.breaks.lock().unwrap_or_else(|err| err.into_inner());
        assert!(
            scope.running.is_empty() && scope.asked.is_empty(),
            "a timed-out run left {scope:?} behind, so the next operation inherits it"
        );
    }

    /// **A host that asks for control back gets it**, rather than being held for the rest of the
    /// bound while the loop pumps through the break it asked for.
    ///
    /// This is a regression the pumping introduced and review round 10 caught: before it, a live
    /// open was a single `WaitForEvent`, so an interrupt ended the wait and `wait()` returned. The
    /// arrival below never arrives -- the pid is not in the session and nothing will put it there
    /// -- so without the check the loop spends the whole bound. Measured with it backed out: 29.5s
    /// and `CommandFailed(0x8000FFFF)`, because the pumping let the debuggee run to completion and
    /// there was no session left to ask. That is worse than the delay the review described, and it
    /// is why the assertion is on the variant rather than on the timing -- every ending here is an
    /// error, and only the variant says which one happened.
    #[test]
    #[cfg(not(miri))]
    fn test_a_host_interrupt_ends_a_live_open_rather_than_pumping_through_it() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        e.launch_process("ping.exe -n 30 127.0.0.1")
            .expect("launch failed");
        // Running, so the break a host asks for is an event this wait can return on.
        unsafe { e.control.SetExecutionStatus(DEBUG_STATUS_GO) }.expect("could not set it running");

        let handle = e.interrupt_handle();
        let asked = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            handle.interrupt()
        });
        let absent = e
            .session_processes()
            .expect("could not list the session")
            .iter()
            .map(|(_, pid)| *pid)
            .max()
            .unwrap_or(4)
            + 1000;
        // Registered directly, because this test drives the wait rather than an opener: nothing
        // is attached to `absent` and nothing will be.
        let waiting = registered(&e, Arrival::Attached(absent));
        let outcome = e.wait_for_live_target(&waiting);
        asked.join().expect("interrupting thread panicked").ok();

        assert!(
            matches!(outcome, Err(DbgEngError::LiveTargetInterrupted)),
            "a live open a host interrupted answered {outcome:?}, so it pumped through the break"
        );
    }

    /// **The finite wait too**, which is the one a live open pumps with -- so of the three doors
    /// onto this record it is the one where a false arrival reaches the guard directly.
    ///
    /// `execute_command("g")` sets the run state and returns; the target does not move until a
    /// wait pumps it, and here that wait is the plain finite one rather than the bounded path the
    /// other two tests take. A host break during it returns `S_OK`, so neither the error check nor
    /// the `S_FALSE` check tells it from an arrival -- only reading the request does, which the
    /// pump now does once and answers as [`WaitOutcome::OnRequest`].
    ///
    /// Two assertions before the record, either of which stops this passing vacuously: the outcome
    /// says the break is what ended *this* wait, and the status says it landed at all. Without
    /// them a wait that simply expired with the target still running would record nothing and
    /// satisfy the rest.
    #[test]
    #[cfg(not(miri))]
    fn test_a_host_requested_break_records_no_stop_on_the_finite_wait() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        e.launch_process("ping.exe -n 30 127.0.0.1")
            .expect("launch failed");
        let watcher = watching_the_only_process(&e);

        unsafe { e.control.SetExecutionStatus(DEBUG_STATUS_GO) }.expect("could not set it running");
        let handle = e.interrupt_handle();
        let asked = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            handle.interrupt()
        });
        let outcome = e
            .wait_for_event(10_000)
            .expect("the wait should return on the break");
        asked.join().expect("interrupting thread panicked").ok();

        assert_eq!(
            outcome,
            WaitOutcome::OnRequest,
            "the finite wait answered {outcome:?} for a break a host asked for"
        );
        assert_eq!(
            e.execution_status().ok(),
            Some(DEBUG_STATUS_BREAK),
            "the target is not stopped, so no break landed and nothing here is under test"
        );
        assert!(
            !matches!(e.presence_of(&watcher), Presence::Arrived),
            "a break a host asked for was delivered as an arrival by the finite wait"
        );
    }

    /// **The opener's prune is what asks the register about departures**, which the rule test
    /// beside it cannot say.
    ///
    /// `test_a_claim_stops_excluding_once_its_process_leaves` pins the rule and calls it directly,
    /// so removing the call from `prune_processes_that_left` leaves it green -- measured, by making
    /// that removal. This is the wiring: a launch delivered while its guard is held, its process
    /// detached, and then an opener, whose prune has to clear the claim before the reattach can be
    /// given the pair back.
    ///
    /// The second process is what keeps the session alive across the detach, so nothing else
    /// clears anything; and the pair is asserted to come back, or a run where DbgEng handed out a
    /// different engine id would pass without meeting the collision at all.
    #[test]
    #[cfg(not(miri))]
    fn test_the_openers_prune_clears_a_claim_on_a_departed_process() {
        let _debuggee = one_debuggee();
        let mut stays = a_process_to_attach_to();
        {
            let e = DebugEngine::new();
            e.attach_process(stays.id()).expect("attach failed");

            // A launch delivered by an outside pump, with its guard still held.
            let launched = e
                .launch_process_begin("cmd.exe /c ping -n 30 127.0.0.1")
                .expect("launch failed");
            let WaitKind::Live(registered) = &launched.kind else {
                panic!("a launch guard is not a live open");
            };
            // **Pumped until delivered, not once.** One `WaitForEvent` is one *event*, and this
            // session already holds an attached process whose own events compete -- which is the
            // whole of `Arrival` and of dbgscope#128. A single pump was enough on the bench and
            // was not on the instrumented coverage runner, which is exactly the shape that finding
            // is about.
            for _ in 0..5 {
                if matches!(e.presence_of(registered), Presence::Arrived) {
                    break;
                }
                e.wait_for_event(LIVE_WAIT_MS)
                    .expect("the outside pump failed");
            }
            assert!(
                matches!(e.presence_of(registered), Presence::Arrived),
                "the launch was not delivered its process, so nothing here is under test"
            );

            let held = e.session_processes().expect("could not list the session");
            let (id, pid) = *held
                .iter()
                .find(|(_, pid)| *pid != stays.id())
                .expect("the launched process is not in the session");

            // It leaves, and the same pid is attached again -- which is where DbgEng hands the
            // engine id straight back.
            e.execute_command(&format!("|{id}s"))
                .expect("could not select the process to detach");
            e.execute_command(".detach").expect("could not detach it");
            let reattached = e.attach_process_begin(pid).expect("reattach failed");
            reattached.wait().expect("the reattach should complete");

            let back = e
                .session_processes()
                .expect("could not list the session")
                .iter()
                .any(|entry| *entry == (id, pid));
            assert!(
                back,
                "the reattach did not get the pair ({id}, {pid}) back, so this run never met the \
                 collision and asserts nothing"
            );
            assert!(
                !matches!(e.presence_of(registered), Presence::Arrived),
                "the departed process's claim survived the opener's prune, so the pair it holds \
                 refuses the next open its own stop"
            );

            drop(launched);
            let _ = e.end_session();
        }
        let _ = stays.kill();
        let _ = stays.wait();
    }

    /// **Reclaiming a departed process's engine id does not reclaim its arrival**, which used to
    /// be a hazard with a prune to guard it and is now a property of the shape.
    ///
    /// Engine ids are reused immediately: measured on this engine, detaching engine id 0 and
    /// attaching another process hands the freed 0 straight back. When arrivals were an
    /// engine-wide set of `(engine id, pid)` pairs, a session that detached a process through the
    /// raw hatch and attached the same pid again got the whole pair back, and `presence_of`
    /// answered `Arrived` for a target whose initial breakpoint had not happened -- the
    /// postcondition the live open exists to hold. `prune_processes_that_left` was the guard, and
    /// it was review that put it there.
    ///
    /// **The construction that makes it unreachable** is that an arrival is delivered to a
    /// registered open rather than broadcast into a set: an entry cannot outlive the guard that
    /// made it, so the reattach's open starts with nothing delivered to it whatever numbers it
    /// inherits. There is no record left to prune, and the prune's arrival half is gone with it.
    ///
    /// Kept as an end-to-end statement of that rather than deleted, since it costs one attach: the
    /// second process is what makes this a *detach* rather than a teardown, so nothing else could
    /// have cleared a record even if there were one.
    #[test]
    #[cfg(not(miri))]
    fn test_reclaiming_an_engine_id_does_not_reclaim_its_arrival() {
        let _debuggee = one_debuggee();
        let mut leaves = a_process_to_attach_to();
        let mut stays = a_process_to_attach_to();
        {
            let e = DebugEngine::new();
            e.attach_process(leaves.id()).expect("first attach failed");
            e.attach_process(stays.id()).expect("second attach failed");

            let held = e.session_processes().expect("could not list the session");
            let (id, _) = *held
                .iter()
                .find(|(_, pid)| *pid == leaves.id())
                .expect("the first process is not in the session");
            e.execute_command(&format!("|{id}s"))
                .expect("could not select the process to detach");
            e.execute_command(".detach").expect("could not detach it");

            let guard = e
                .attach_process_begin(leaves.id())
                .expect("reattach failed");
            let WaitKind::Live(registered) = &guard.kind else {
                panic!("an attach guard is not a live open");
            };
            assert!(
                !matches!(e.presence_of(registered), Presence::Arrived),
                "the reattach's open was arrived before its wait, so it inherited an answer about \
                 the process that left"
            );
            guard.wait().expect("the reattach should complete");
        }
        for p in [&mut leaves, &mut stays] {
            let _ = p.kill();
            let _ = p.wait();
        }
    }

    /// **A watchdog-forced break is not an arrival**, which the bounded wait promised its callers
    /// two paragraphs above the call that was breaking it, and which is now
    /// [`WaitOutcome::Deadline`] being a different arm from [`WaitOutcome::Stopped`].
    ///
    /// The Ctrl+Break stops whatever was running, so in a mixed session it can stop a deferred
    /// target *before* its initial breakpoint; recorded, that target's guard would report an
    /// initial-break wait that never happened. `cut_short` is asserted first, or this passes by
    /// the watchdog never firing -- the run has to be genuinely cut short for the rest to mean
    /// anything.
    #[test]
    #[cfg(not(miri))]
    fn test_a_watchdog_forced_break_records_no_stop() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        // `ping.exe` and not `cmd.exe /c ping`, for the reason
        // `test_a_launched_target_has_a_console_of_its_own_and_no_window` records: the passive
        // end takes the process this engine launched and nothing beneath it, so the wrapper
        // leaves a `ping` grandchild running for the rest of its thirty seconds.
        e.launch_process("ping.exe -n 30 127.0.0.1")
            .expect("launch failed");
        let watcher = watching_the_only_process(&e);

        let run = e.execute_and_wait("g", 300).expect("the go should return");
        assert!(
            matches!(run.cut_short, Some(Interruption::Deadline { .. })),
            "the target stopped on its own ({:?}), so no forced break was under test",
            run.cut_short
        );
        assert!(
            !matches!(e.presence_of(&watcher), Presence::Arrived),
            "the watchdog's own Ctrl+Break was delivered as the target arriving"
        );
    }

    /// **An empty session is an answer**, so `presence_of` calls it [`Presence::Absent`] and not
    /// [`Presence::Unknown`].
    ///
    /// The two are indistinguishable at the top of the loop — both pump — and differ only at the
    /// bound, where `Absent` is [`DbgEngError::LiveTargetTimeout`] and `Unknown` is `Ok`. So this
    /// asserts the mapping rather than a behaviour: the state cannot be held at the bound while
    /// the test above holds, and the point of writing it down is that the two are pinned together.
    /// Both arrivals, because `has_target` is asked before either is looked at and a launch with
    /// no snapshot must not reach its own `Unknown` by a different road.
    #[test]
    #[cfg(not(miri))]
    fn test_a_session_holding_nothing_is_absence_rather_than_a_question() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        assert!(
            matches!(
                e.presence_of(&registered(&e, Arrival::Attached(4))),
                Presence::Absent
            ),
            "an engine with no debuggee could not say an attached pid was missing"
        );
        assert!(
            matches!(
                e.presence_of(&registered(&e, Arrival::Launched(None))),
                Presence::Absent
            ),
            "an engine with no debuggee deferred to the launch snapshot it does not have"
        );
    }

    /// **The last event names its process by *engine* id**, which is the join `presence_of` makes.
    ///
    /// Measured rather than taken from the documentation, because the two numbers a process has
    /// here are nothing alike and comparing against the wrong one fails *silently* in the worst
    /// direction: no arrival would ever match, so every live open would pump to `LIVE_WAIT_MS` and
    /// answer `LiveTargetTimeout` on a target sitting in front of it. In a two-process session the
    /// engine ids are 0 and 1 while the pids are five digits, so this cannot agree by coincidence.
    ///
    /// The second assertion is the tightened terminal condition itself: in a session that also
    /// holds an attached process, the wait `launch_process` makes ends on the **launched**
    /// process's event and not the attached one's.
    #[test]
    #[cfg(not(miri))]
    fn test_the_last_event_names_its_process_by_engine_id() {
        let _debuggee = one_debuggee();
        let mut theirs = a_process_to_attach_to();
        let e = DebugEngine::new();
        e.attach_process(theirs.id()).expect("attach failed");
        e.launch_process("cmd.exe /c ping -n 30 127.0.0.1")
            .expect("launch failed");

        let held = e
            .session_processes()
            .expect("could not list the session's processes");
        let stopped_on = e
            .last_event_process()
            .expect("the engine names no last event after a launch");
        let (_, pid) = held
            .iter()
            .find(|(id, _)| *id == stopped_on)
            .unwrap_or_else(|| {
                panic!("the last event's process {stopped_on} is no engine id in {held:?}")
            });
        assert_ne!(
            *pid,
            theirs.id(),
            "the launch's wait ended on the attached process's event rather than its own: {held:?}"
        );

        e.end_session().expect("end_session failed");
        let _ = theirs.kill();
        let _ = theirs.wait();
    }

    /// Execution control with no debuggee is **refused**, because letting it reach DbgEng takes
    /// the process down.
    ///
    /// Measured before this guard existed, on dbgeng 10.0.26100.1 (ARM64): a raw `g` through
    /// `execute_command_bounded` exits the process with `STATUS_ACCESS_VIOLATION` — both on an
    /// engine whose debuggee had just exited *and* on this one, which has never held a target.
    /// The second case is why the guard is keyed on the missing debuggee rather than on the
    /// departure, and why it sits in the primitive rather than in the caller that met it first.
    ///
    /// A structured exception is not a panic, so there is no `#[should_panic]` shape for the
    /// regression: what this test asserts by *returning at all* is that the fault is gone. Under
    /// `cargo nextest`, which gives each test its own process, a regression takes this one down
    /// and nothing else.
    #[test]
    #[cfg(not(miri))]
    fn test_execution_control_with_no_debuggee_is_refused_rather_than_faulting_the_process() {
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        assert!(
            matches!(e.has_target(), Ok(false)),
            "a fresh engine is supposed to be holding no target"
        );

        // Four spellings of one thing, and the point is that the guard reads none of them: an
        // alias and a `.if` branch reach execution without saying so, which is why the check is
        // on the engine's state rather than on the text.
        for command in ["g", "p", "t", ".if (1) { g }"] {
            assert!(
                matches!(
                    e.execute_command_bounded(command, 5_000),
                    Err(DbgEngError::NoDebuggee)
                ),
                "`{command}` was not refused on the bounded path"
            );
            assert!(
                matches!(e.execute_command(command), Err(DbgEngError::NoDebuggee)),
                "`{command}` was not refused on the unbounded path"
            );
        }

        // The two typed paths, one of which had the guard already. Named here so all three ways
        // in are pinned in one place rather than one of them being covered by a target's exit.
        assert!(
            matches!(e.execute_and_wait("g", 5_000), Err(DbgEngError::NoDebuggee)),
            "execute_and_wait was not refused"
        );
        assert!(
            matches!(
                e.run_to_address(0x1000, 5_000),
                Err(DbgEngError::NoDebuggee)
            ),
            "run_to_address was not refused"
        );
    }

    /// A record carries as many parameters as it says it filled, and no more.
    ///
    /// The count is the field the two shapes of a `0xc0000409` are told apart by -- one parameter
    /// is the CRT's `abort`, three is WIL's, whose second is the `HRESULT` -- so reading a
    /// leftover as a parameter would not be a cosmetic error. It would answer the question.
    #[test]
    fn test_a_record_carries_only_the_parameters_it_filled() {
        let mut raw = EXCEPTION_RECORD64 {
            ExceptionCode: windows::Win32::Foundation::NTSTATUS(0xc000_0409_u32 as i32),
            ExceptionFlags: EXCEPTION_NONCONTINUABLE,
            ExceptionRecord: 0,
            ExceptionAddress: 0x7ff6_3074_28f9,
            NumberParameters: 3,
            __unusedAlignment: 0,
            ExceptionInformation: [0; 15],
        };
        // WIL's shape, and a fourth slot holding whatever the last exception on this thread left.
        raw.ExceptionInformation[0] = 0x7;
        raw.ExceptionInformation[1] = 0xffff_ffff_8000_ffff;
        raw.ExceptionInformation[2] = 0x28f;
        raw.ExceptionInformation[3] = 0xdead_beef;

        let record = ExceptionRecord::from_raw(&raw);
        assert_eq!(record.code, 0xc000_0409, "the code was not read as a u32");
        assert_eq!(
            record.parameters,
            vec![0x7, 0xffff_ffff_8000_ffff, 0x28f],
            "the leftover in slot 3 was read as a parameter"
        );
        assert!(record.noncontinuable(), "the flag was not decoded");
        assert_eq!(
            record.nested, None,
            "a zero nested pointer is no nested record, not a record at address zero"
        );

        // **A record claiming more than it can hold is corrupt, not an excuse to read past the
        // array.** Fifteen is how many slots there are; sixteen is a fact about the dump.
        raw.NumberParameters = 99;
        assert_eq!(
            ExceptionRecord::from_raw(&raw).parameters.len(),
            15,
            "an over-large NumberParameters was not clamped to the array"
        );

        // A nested record is a pointer into the target, reported as one rather than chased.
        raw.NumberParameters = 0;
        raw.ExceptionRecord = 0x1234;
        let nested = ExceptionRecord::from_raw(&raw);
        assert_eq!(nested.nested, Some(0x1234));
        assert!(
            nested.parameters.is_empty(),
            "a zero-parameter record carried parameters"
        );
    }

    /// The extra-information buffer is read as an exception only when it holds one.
    ///
    /// Both guards, because they fail in the same silent direction: for any other event kind these
    /// same bytes are an exit code or a module base, and a short write is not this struct however
    /// the kind reads. Either one missing invents a record out of whatever was in the buffer.
    #[test]
    fn test_extra_event_info_is_read_as_an_exception_only_when_it_holds_one() {
        let mut extra = ExtraEventInfo::default();
        let info = DEBUG_LAST_EVENT_INFO_EXCEPTION {
            ExceptionRecord: EXCEPTION_RECORD64 {
                ExceptionCode: windows::Win32::Foundation::NTSTATUS(0x8000_0003_u32 as i32),
                ExceptionFlags: 0,
                ExceptionRecord: 0,
                ExceptionAddress: 0x7ffc_9b83_d78d,
                NumberParameters: 1,
                __unusedAlignment: 0,
                ExceptionInformation: [0; 15],
            },
            FirstChance: 1,
        };
        // SAFETY: writing the struct the engine would have written, into a buffer sized and
        // aligned for exactly it.
        unsafe { std::ptr::write(extra.as_mut_ptr().cast(), info) };

        let (record, first_chance) = extra
            .exception(DEBUG_EVENT_EXCEPTION, ExtraEventInfo::SIZE)
            .expect("an exception event with a full write reported no exception");
        assert_eq!(record.code, 0x8000_0003);
        assert_eq!(record.address, 0x7ffc_9b83_d78d);
        assert_eq!(record.parameters, vec![0]);
        assert!(first_chance, "the first-chance flag was dropped");

        assert!(
            extra
                .exception(DEBUG_EVENT_BREAKPOINT, ExtraEventInfo::SIZE)
                .is_none(),
            "a breakpoint event's extra information was read as an exception record"
        );
        assert!(
            extra
                .exception(DEBUG_EVENT_EXCEPTION, ExtraEventInfo::SIZE - 1)
                .is_none(),
            "a write shorter than the struct was read as the whole struct"
        );
    }

    /// An engine that has seen no event reports no event, rather than an event kind of nothing.
    ///
    /// The engine does **not** fail this call before its first wait: it answers `S_OK` with kind
    /// `0` and `DEBUG_ANY_ID` for both ids. Without the check that turns that into `None`, a
    /// caller is handed a `DebugEvent` whose `kind` is not a `DEBUG_EVENT_*` value at all, and
    /// "the target is not loaded yet" reads as an event kind this build does not recognise
    /// (dbgscope#144). An engine holding nothing is the cheapest way to reach that state; the
    /// other is a dump named but not pumped, which needs a file and is in the probe.
    #[test]
    #[cfg(not(miri))]
    fn test_an_engine_with_no_event_reports_none_rather_than_a_kind_of_zero() {
        // **Even a test that opens no target needs this.** `DebugEngine::drop` ends the process's
        // debuggee session, so an engine built and dropped beside another test's live target ends
        // *that* target's session -- which surfaces over there as a pump failing `E_UNEXPECTED`,
        // with nothing pointing back here. Found exactly that way (dbgscope#144, round two): the
        // suite was green single-threaded and red under the default harness.
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        assert!(
            matches!(e.last_event(), Ok(None)),
            "an engine that has seen no event did not report none — which means either it failed \
             the call, or kind 0 was dressed up as an event"
        );
    }

    /// **An opener that replaces the session invalidates the contexts read from the old one.**
    ///
    /// The check that `stack_frames_from` and `set_scope` make is worth exactly nothing if the
    /// identity survives a replacement, and it did: only `end_session` reissued, so a caller who
    /// opened dump A, saved a context and opened dump B *through this engine* got the same
    /// identity back and the stale registers were accepted (dbgscope#144, round two).
    ///
    /// **The dump is written by the engine rather than checked in**, which is what makes this a
    /// test rather than a probe: `.dump /m` on a launched target gives a real dump to reopen, so
    /// nothing here depends on a fixture or on this host having one.
    #[test]
    #[cfg(not(miri))]
    fn test_an_opener_that_replaces_the_session_invalidates_the_old_contexts() {
        let _guard = one_debuggee();
        let dump = std::env::temp_dir().join(format!(
            "dbgscope-replace-{}-{}.dmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::remove_file(&dump);

        // A target to dump. Any stopped process will do; this one exits on its own if the test
        // dies holding it.
        let e = DebugEngine::new();
        if e.launch_process("cmd.exe /c ping -n 30 127.0.0.1").is_err() {
            // No engine on this host is a reason to skip, not to fail -- same standing rule as
            // the other tests that need a real `dbgeng.dll`.
            println!("SKIPPED: could not launch a target to dump");
            return;
        }
        let written = e.execute_command(&format!(".dump /m \"{}\"", dump.display()));
        let _ = e.end_session();
        drop(e);
        if written.is_err() || !dump.exists() {
            println!("SKIPPED: this engine would not write a dump ({written:?})");
            return;
        }

        let e = DebugEngine::new();
        let path = dump.display().to_string();
        assert!(
            e.open_dump(&path).is_ok(),
            "could not open the dump written"
        );
        let _ = e.wait_for_event(60_000);
        let first = e.target_identity();
        let stale = ThreadContext {
            bytes: vec![0u8; 1232],
            target: first,
        };

        // The same engine, opening a target again. This is the replacement path: no
        // `end_session` between them, which is exactly the case that was accepted before.
        assert!(
            e.open_dump(&path).is_ok(),
            "could not reopen the dump through the same engine"
        );
        let _ = e.wait_for_event(60_000);
        assert_ne!(
            e.target_identity(),
            first,
            "an opener replaced the session without reissuing the identity, so every context and \
             scope saved from the previous target is still accepted against this one"
        );
        assert!(
            matches!(
                e.stack_frames_from(&stale, 8),
                Err(DbgEngError::ContextFromAnotherTarget)
            ),
            "a context from the replaced target was walked against the new one"
        );

        let _ = e.end_session();
        drop(e);
        let _ = std::fs::remove_file(&dump);
    }

    /// A context is refused by an engine that no longer holds the target it was read from.
    ///
    /// The sibling of the `set_scope` rule, and the more important of the two: a stale scope points
    /// the session somewhere visibly wrong, while a stale context comes back as *frames* — an
    /// answer indistinguishable from the right one. Asserted against a real engine because
    /// `target_identity` is engine state, and with **no target at all**, since the check has to
    /// come before the engine sees the bytes rather than after it declines them.
    #[test]
    #[cfg(not(miri))]
    fn test_a_context_from_another_target_is_refused() {
        // **Even a test that opens no target needs this.** `DebugEngine::drop` ends the process's
        // debuggee session, so an engine built and dropped beside another test's live target ends
        // *that* target's session -- which surfaces over there as a pump failing `E_UNEXPECTED`,
        // with nothing pointing back here. Found exactly that way (dbgscope#144, round two): the
        // suite was green single-threaded and red under the default harness.
        let _debuggee = one_debuggee();
        let e = DebugEngine::new();
        // Read from an engine whose identity is whatever it is now, and then invalidated the only
        // way this crate can: by construction, since `target_identity` is per-engine.
        let stale = ThreadContext {
            bytes: vec![0u8; 1232],
            target: e.target_identity().wrapping_add(1),
        };
        assert!(
            matches!(
                e.stack_frames_from(&stale, 8),
                Err(DbgEngError::ContextFromAnotherTarget)
            ),
            "a context from another target was walked rather than refused"
        );

        // **And the refusal is about identity, not about there being no target.** A context whose
        // identity matches gets past this check and fails on the engine instead, which is what
        // shows the check is not passing everything through.
        let current = ThreadContext {
            bytes: vec![0u8; 1232],
            target: e.target_identity(),
        };
        assert!(
            !matches!(
                e.stack_frames_from(&current, 8),
                Err(DbgEngError::ContextFromAnotherTarget)
            ),
            "a context from this very engine was refused as another target's"
        );
    }

    /// `E_UNEXPECTED` is "no stored event"; nothing else is.
    ///
    /// Pinned by `examples/stored_event_probe.rs` against a live process and a kernel crash dump,
    /// and asserted here so that widening it to "any failure" -- which would turn every real error
    /// into a silent `Ok(None)` -- fails a test rather than a user.
    #[test]
    fn test_only_e_unexpected_means_there_is_no_stored_event() {
        assert!(no_stored_event(E_UNEXPECTED));
        for other in [E_INVALIDARG, E_NOINTERFACE, S_OK, S_FALSE] {
            assert!(
                !no_stored_event(other),
                "{other:?} was taken for the absence of a stored event"
            );
        }
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
