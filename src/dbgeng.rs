use std::ffi::CString;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;
use windows::core::{IUnknown, Interface, PCSTR, PCWSTR, PWSTR};

// Import the necessary Windows Debug Engine interfaces
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_ANY_ID, DEBUG_ATTACH_KERNEL_CONNECTION, DEBUG_ATTACH_LOCAL_KERNEL, DEBUG_BREAKPOINT_CODE,
    DEBUG_BREAKPOINT_ENABLED, DEBUG_CLASS_KERNEL, DEBUG_ENGOPT_INITIAL_BREAK,
    DEBUG_EVENT_BREAKPOINT, DEBUG_EXECUTE_ECHO, DEBUG_INTERRUPT_ACTIVE, DEBUG_KERNEL_SMALL_DUMP,
    DEBUG_OUTCTL_THIS_CLIENT, DEBUG_OUTPUT_NORMAL, DEBUG_STATUS_GO, DEBUG_STATUS_NO_DEBUGGEE,
    IDebugBreakpoint, IDebugBreakpoint2, IDebugClient6, IDebugControl4, IDebugDataSpaces4,
    IDebugEventContextCallbacks, IDebugOutputCallbacks, IDebugSymbols3,
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
}

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
/// it to return after this long — the single engine thread must not hang forever on an
/// unreachable/unresponsive target. Generous, to allow a KDNET resync (~25s observed).
const KERNEL_ATTACH_WAIT_MS: u32 = 60_000;

/// Carries a raw `IDebugControl` pointer to a watchdog thread solely to call
/// `SetInterrupt`, which DbgEng documents as safe to call from any thread (the rest of
/// the engine is single-thread-affine). Not otherwise dereferenced off-thread.
struct InterruptHandle(*mut core::ffi::c_void);
// SAFETY: only used to invoke SetInterrupt, the one cross-thread-safe DbgEng call.
unsafe impl Send for InterruptHandle {}

/// Encodes a `&str` as a NUL-terminated UTF-16 buffer for the `*Wide` DbgEng APIs.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
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
        engine
    }

    pub fn from_windbg_client(client: &IUnknown) -> Self {
        let client: IDebugClient6 = client.cast().expect("[-] Failed to cast debug client");
        Self::from_client_interface(client)
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
        Self::from_client_interface(new_client)
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
        }
    }

    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>, DbgEngError> {
        let mut buffer = vec![0; size];
        unsafe {
            self.dataspaces
                .ReadVirtual(address, buffer.as_mut_ptr() as *mut _, size as u32, None)
                .expect("[-] Failed to read memory")
        };

        Ok(buffer)
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
    pub fn attach_local_kernel(&self) -> Result<(), DbgEngError> {
        self.request_initial_break()?;
        unsafe {
            self.client
                .AttachKernel(DEBUG_ATTACH_LOCAL_KERNEL, None)
                .map_err(DbgEngError::AttachFailed)?;
        }
        // A live kernel needs an INFINITE WaitForEvent (a finite timeout returns
        // E_NOTIMPL); INITIAL_BREAK makes it stop at the first event. Bound it so an
        // unresponsive target can't hang the engine thread forever.
        self.wait_for_kernel_break_in()
    }

    /// Attaches to a kernel over a connection string (e.g. `net:port=50000,key=...`)
    /// and breaks in.
    ///
    /// Returns an error rather than panicking when the connection string is invalid or
    /// the attach fails (e.g. the transport/port is already owned by another debugger).
    pub fn attach_kernel(&self, connection_string: &str) -> Result<(), DbgEngError> {
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
        // above makes the engine stop once the KDNET link establishes. Bound it so an
        // unreachable target can't hang the engine thread forever.
        self.wait_for_kernel_break_in()
    }

    /// Shared tail of the kernel attach paths: wait (bounded) for the INITIAL_BREAK stop,
    /// clear the option, and absorb the one spurious re-break it leaves. Returns
    /// [`DbgEngError::KernelBreakTimeout`] if the target never broke in within the bound
    /// (e.g. unreachable or not in debug mode), rather than reporting a false success.
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

    /// Sets the symbol path
    pub fn set_symbol_path(&self, symbol_path: &str) {
        let path = CString::new(symbol_path).expect("[-] Invalid symbol path");

        unsafe {
            self.symbols
                .SetSymbolPath(PCSTR::from_raw(path.as_ptr() as *const u8))
                .expect("[-] Failed to set symbol path")
        };
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
    fn wait_for_event_bounded(&self, timeout_ms: u32) -> (windows::core::Result<()>, bool) {
        let done = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        let done_watch = Arc::clone(&done);
        let fired_watch = Arc::clone(&fired);
        let handle = InterruptHandle(self.control.as_raw());
        let deadline = Duration::from_millis(timeout_ms as u64);
        let watchdog = thread::spawn(move || {
            let handle = handle; // capture the whole (Send) handle, not just the raw field
            let start = Instant::now();
            loop {
                if done_watch.load(Ordering::SeqCst) {
                    return;
                }
                if start.elapsed() >= deadline
                    && let Some(ctl) = unsafe { IDebugControl4::from_raw_borrowed(&handle.0) }
                {
                    // Ctrl+Break a connected target so the engine thread's WaitForEvent
                    // returns with a stop. Repeat in case a busy target ignores one.
                    let _ = unsafe { ctl.SetInterrupt(DEBUG_INTERRUPT_ACTIVE) };
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
    pub fn execute_and_wait(&self, command: &str, timeout_ms: u32) -> Result<String, DbgEngError> {
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

        exec.map_err(DbgEngError::CommandFailed)?;
        waited.map_err(DbgEngError::CommandFailed)?;

        Ok(String::from_utf8_lossy(&output_buffer).to_string())
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

    pub fn reload_symbols(&self, module: &str) {
        let module = CString::new(module).expect("Failed to create CString");
        let module = PCSTR::from_raw(module.as_ptr() as *const u8);
        unsafe { self.symbols.Reload(module) }.expect("[-] Failed to reload symbols");
    }

    /// Returns the current register set as formatted text (`r`).
    pub fn registers(&self) -> Result<String, DbgEngError> {
        self.execute_command("r")
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
    pub fn launch_process(&self, command_line: &str) -> Result<(), DbgEngError> {
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
        // until the next `WaitForEvent`, and it reads the command-line buffer (`wide`)
        // at that point — so drive the wait here, while `wide` is still alive. With the
        // initial-breakpoint filter enabled above, this stops at the loader breakpoint.
        self.wait_for_event(LIVE_WAIT_MS)
    }

    /// Attaches to an existing user-mode process by PID and waits for the break-in,
    /// leaving a current process/thread ready to inspect.
    pub fn attach_process(&self, pid: u32) -> Result<(), DbgEngError> {
        self.enable_initial_break()?;
        unsafe { self.client.AttachProcess(0, pid, DEBUG_ATTACH_DEFAULT) }
            .map_err(DbgEngError::OperationFailed)?;
        // The attach completes during `WaitForEvent`, which breaks the target in.
        self.wait_for_event(LIVE_WAIT_MS)
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

    /// Ends the current debug session without destroying the client, so it can be
    /// reused for another target.
    pub fn end_session(&self) -> Result<(), DbgEngError> {
        // A live kernel left halted (at a break) and detached *passively* stays FROZEN —
        // one CPU halted, the rest spinning — because a passive detach never tells the
        // target to run. Resume it and actively detach instead, leaving it running.
        if self.is_live_kernel() {
            return self.resume_and_detach_live_kernel();
        }
        unsafe { self.client.EndSession(DEBUG_END_PASSIVE) }.map_err(DbgEngError::OperationFailed)
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

pub struct Breakpoint<'a> {
    control: &'a IDebugControl4,
    breakpoint: IDebugBreakpoint,
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
            breakpoint: breakpoint.unwrap(),
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
                .RemoveBreakpoint(&self.breakpoint)
                .expect("[-] Failed to remove breakpoint");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(miri))]
    #[test]
    fn test_create_debug_engine() {
        // Create new debug engine instance
        let _ = DebugEngine::new();

        println!("Debug engine created successfully");

        // DebugEngine's Drop impl will handle cleanup and detach
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
