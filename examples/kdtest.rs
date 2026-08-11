//! Scratch experiment (not part of the public API). Two experiments, both needing a live
//! kernel target — in practice a **KDNET** one. Remote is what kernel debugging here
//! actually runs on, which is why the dev host keeps local KD disabled; `local` below is
//! present only because #73 names `attach_local_kernel_begin` too, and on a host without
//! debug mode it can exercise nothing past the `begin`-half failure. Point this at a
//! snapshot-restorable VM over `net:` — that is the run that settles #73.
//!
//! 1. **#73 — the opener split (#71) on the kernel path.** `attach_kernel_begin()` +
//!    `wait()` beside the fused `attach_kernel()`. `examples/split_open.rs` already proves
//!    the seam in user mode; two things are specific to the kernel path and cannot be
//!    proven there:
//!    - *The connection string outlives the seam.* `attach_kernel_begin` parks its
//!      `CString` on the engine because a KDNET link is only established during the wait,
//!      so DbgEng may read the string after `AttachKernel` has returned. A link that comes
//!      up, and a `vertarget` that reads the real target, is the evidence.
//!    - *`wait_for_kernel_break_in`'s bookkeeping still runs on the `wait()` side.* It
//!      clears `INITIAL_BREAK`, absorbs the spurious re-break, and maps a watchdog-forced
//!      return to `KernelBreakTimeout`. A `RunToOutcome::Hit` on the first resume proves the
//!      first two. The third needs a target that connects and then fails to break in — see
//!      [`timeout_probe`] for why an unreachable one will not do.
//!
//! 2. Verify `end_session` leaves a live kernel RUNNING (not frozen). attach -> bp -> go ->
//!    end_session (resume+detach), wait, then re-attach: if System Uptime advanced by ~the
//!    wait, the target was running.
//!
//! Run:
//!   cargo run --example kdtest -- "net:port=50000,key=w.x.y.z"   # the one that matters
//!   cargo run --example kdtest -- local             # only if the host has local KD on
//!   cargo run --example kdtest -- --timeout-probe   # no target; hangs on purpose, Ctrl+C

use std::thread::sleep;
use std::time::{Duration, Instant};

use win_kexp::dbgeng::{DbgEngError, DebugEngine, PendingTarget, RunToOutcome};

/// A connection nothing will ever answer: the debugger listens, the target never dials.
/// Used only by [`timeout_probe`].
const DEAD_CONN: &str = "net:port=50999,key=1.2.3.4";

/// How the kernel is reached. Both variants have the same `begin`/`wait` shape, so one
/// script covers both openers #73 names — but only [`Target::Connection`] can carry the
/// experiments through, since it is the one that establishes a link during the wait.
enum Target {
    Local,
    Connection(String),
}

impl Target {
    fn begin<'a>(&self, e: &'a DebugEngine) -> Result<PendingTarget<'a>, DbgEngError> {
        match self {
            Target::Local => e.attach_local_kernel_begin(),
            Target::Connection(conn) => e.attach_kernel_begin(conn),
        }
    }

    fn fused(&self, e: &DebugEngine) -> Result<(), DbgEngError> {
        match self {
            Target::Local => e.attach_local_kernel(),
            Target::Connection(conn) => e.attach_kernel(conn),
        }
    }

    /// The opener being exercised, so the section headings name what actually ran.
    fn opener(&self) -> &'static str {
        match self {
            Target::Local => "attach_local_kernel",
            Target::Connection(_) => "attach_kernel",
        }
    }
}

fn run(e: &DebugEngine, cmd: &str) {
    println!("--- {cmd} ---");
    match e.execute_command(cmd) {
        Ok(out) => print!("{out}"),
        Err(err) => println!("ERR: {err}"),
    }
    println!();
}

/// Where the first `g` after a break-in lands is what proves `wait()`'s bookkeeping ran.
/// `INITIAL_BREAK` left armed — or its one spurious re-break left unabsorbed — stops the
/// target immediately at `nt!DbgBreakPointWithStatus` instead of at the breakpoint asked
/// for. Both of those clears moved behind `PendingTarget::wait`, so this is the check that
/// they did not get stranded on the `begin` side.
fn check_break_in_bookkeeping(e: &DebugEngine) {
    // Resolve first. A `bp` on an unresolvable symbol installs nothing, so the `g` below would
    // run to the 60s bound and be forced to stop — landing at nt!DbgBreakPointWithStatus, which
    // is *also* where a stranded INITIAL_BREAK lands. Failing here instead keeps "no symbols"
    // from being reported as "the bookkeeping is broken".
    let address = match e.symbol_offset("nt!NtCreateFile") {
        Ok(address) => {
            println!("nt!NtCreateFile resolved to {address:#x}");
            address
        }
        Err(err) => {
            println!("[??] cannot resolve nt!NtCreateFile: {err} — symbols unavailable, skipping");
            return;
        }
    };

    println!("=== run to nt!NtCreateFile (expect Hit, not the initial-break artifact) ===");
    // `run_to_address`, not `execute_and_wait("g")`: the latter discards the watchdog-fired
    // flag (it treats a forced break as a fine outcome for go/step), so its caller cannot tell
    // "hit the breakpoint" from "the bound expired and we Ctrl+Break'd ourselves". Both stop at
    // nt!DbgBreakPointWithStatus, so classifying on the stop site alone reports a timeout as a
    // bookkeeping failure. `run_to_address` keeps the flag and surfaces it as `Timeout`.
    let result = match e.run_to_address(address, 60_000) {
        Ok(result) => result,
        Err(err) => {
            println!("ERR: {err}");
            return;
        }
    };
    print!("{}", result.output);
    println!();

    match result.outcome {
        RunToOutcome::Hit => {
            println!("[ok] reached the real breakpoint — INITIAL_BREAK cleared, artifact absorbed")
        }
        RunToOutcome::StoppedElsewhere { stopped_at } => {
            let site = e
                .execute_command(&format!("ln {stopped_at:#x}"))
                .unwrap_or_default();
            print!("{site}");
            if site.contains("DbgBreakPointWithStatus") {
                println!(
                    "[FAIL] stopped at the initial-break artifact — wait()'s bookkeeping did not run"
                );
            } else {
                println!(
                    "[??] stopped at {stopped_at:#x}, not the breakpoint — read the output above"
                );
            }
        }
        // Deliberately not [FAIL]. The watchdog's own Ctrl+Break lands at
        // nt!DbgBreakPointWithStatus exactly like a stranded INITIAL_BREAK does, so a stop
        // reached this way carries no information about the bookkeeping either way.
        RunToOutcome::Timeout => println!(
            "[??] inconclusive — the 60s bound expired and the watchdog forced the stop, which \
             is indistinguishable from the artifact. Re-run against a target that reaches \
             nt!NtCreateFile (any file I/O on the guest will do)."
        ),
    }
}

/// #73, part 1: the split attach. The `begin`/`wait` seam is the whole subject, so the
/// commit point is called out explicitly — that is where a session-tracking caller would
/// record the target as its own, before a wait that can still fail.
fn split_attach(e: &DebugEngine, target: &Target) {
    println!(
        "=== 1. {}_begin / wait (the split path) ===",
        target.opener()
    );
    let began = Instant::now();
    match target.begin(e) {
        Ok(pending) => {
            println!(
                "[commit] AttachKernel returned OK in {:?} — the target is ours from here, \
                 even though the link is not up yet",
                began.elapsed()
            );
            let waited = Instant::now();
            match pending.wait() {
                Ok(()) => println!("wait OK in {:?} — target broken in", waited.elapsed()),
                Err(err) => {
                    println!("wait ERR: {err}  (the attach still happened — do not retry it)");
                    return;
                }
            }
        }
        Err(err) => {
            println!("begin ERR: {err}  (nothing was claimed; retry is clean)");
            return;
        }
    }
    // If the connection string had been freed at the end of `attach_kernel_begin`, the dial
    // that happens inside `wait()` would have read freed memory. A `vertarget` that names
    // the real machine is the evidence that it did not.
    run(e, "vertarget");
    check_break_in_bookkeeping(e);
}

/// Experiment 2 (the example's original purpose): `end_session` must leave the kernel
/// running, not frozen at the break. Uses the fused opener, which also re-checks that
/// `attach_kernel` still behaves as it did before the split.
///
/// Returns whether both uptime readings were taken, i.e. whether there is anything to
/// compare.
fn end_session_leaves_target_running(e: &DebugEngine, target: &Target) -> bool {
    println!(
        "\n=== 2. {} (fused) -> end_session -> re-attach ===",
        target.opener()
    );
    match target.fused(e) {
        Ok(()) => println!("attach #1 OK"),
        Err(err) => {
            println!("attach #1 ERR: {err}");
            return false;
        }
    }
    run(e, "vertarget"); // UPTIME #1

    run(e, "bp nt!NtCreateFile");
    println!("=== go (to nt!NtCreateFile) ===");
    match e.execute_and_wait("g", 60_000) {
        Ok(run) => print!("{}", run.output),
        Err(err) => println!("ERR: {err}"),
    }
    println!();

    println!("=== end_session (should resume + detach, leaving target RUNNING) ===");
    match e.end_session() {
        Ok(()) => println!("end_session ok"),
        Err(err) => println!("end_session ERR: {err}"),
    }

    println!("--- sleeping 8s; if the fix works the guest is RUNNING during this ---");
    sleep(Duration::from_secs(8));

    println!("=== re-attach to read uptime again ===");
    match target.fused(e) {
        Ok(()) => println!("attach #2 OK"),
        Err(err) => {
            println!("attach #2 ERR: {err}  (=> target was frozen/wedged, fix FAILED)");
            return false;
        }
    }
    run(e, "vertarget"); // UPTIME #2 — compare to #1: ~8s+ greater => target was RUNNING
    true
}

/// #73 suggested reaching the third piece of `wait_for_kernel_break_in`'s bookkeeping — the
/// watchdog-forced return that becomes `KernelBreakTimeout` — by dialing an unreachable
/// target, which needs no VM. **It does not work, and this probe is what shows why.**
///
/// `wait_for_event_bounded` documents the reason: `SetInterrupt` can only unblock a wait
/// once the target is *connected*. A dial that never connects blocks in the transport, like
/// `kd` on a dead connection, and the watchdog's Ctrl+Break at `KERNEL_ATTACH_WAIT_MS` (60s)
/// cannot reach it. Measured 2026-08-02 against the in-box dbgeng on Windows 11 26200:
/// `AttachKernel` returned in ~8ms and `wait()` was still blocked when the run was killed at
/// 300s — five times the bound, with no return.
///
/// So `KernelBreakTimeout` is reachable only from a target that *connects* and then fails to
/// break in (wrong/absent debug mode, a wedged target), which needs real hardware. This probe
/// stays as the executable record of the limitation: run it, watch it hang, Ctrl+C. If it
/// ever prints `KernelBreakTimeout`, the engine's behaviour changed and the doc comment on
/// `wait_for_event_bounded` is stale.
fn timeout_probe() {
    let e = DebugEngine::new();
    println!("=== deliberate timeout: dial {DEAD_CONN}; nothing will ever answer ===");
    let began = Instant::now();
    match e.attach_kernel_begin(DEAD_CONN) {
        Ok(pending) => {
            println!(
                "[commit] AttachKernel OK in {:?} — the transport is claimed, the link is not up",
                began.elapsed()
            );
            println!(
                "waiting; expect this to block indefinitely (measured: past 300s, bound is 60s) \
                 because SetInterrupt cannot cancel a dial that never connected. Ctrl+C to stop."
            );
            let waited = Instant::now();
            match pending.wait() {
                Err(DbgEngError::KernelBreakTimeout) => println!(
                    "[!] wait() -> KernelBreakTimeout after {:?} — the bound fired, which it did \
                     not when this was measured; wait_for_event_bounded's doc comment is stale",
                    waited.elapsed()
                ),
                Ok(()) => println!(
                    "[FAIL] wait() reported success after {:?} with no target on the wire",
                    waited.elapsed()
                ),
                Err(err) => println!("[??] wait() -> {err} after {:?}", waited.elapsed()),
            }
        }
        Err(err) => println!("begin ERR: {err}"),
    }
    let _ = e.end_session();
}

fn main() {
    let Some(arg) = std::env::args().nth(1) else {
        eprintln!(
            "usage: kdtest <connection-string> | local | --timeout-probe\n  \
             e.g. kdtest \"net:port=50000,key=w.x.y.z\""
        );
        return;
    };

    if arg == "--timeout-probe" {
        timeout_probe();
        return;
    }

    let target = if arg == "local" {
        Target::Local
    } else {
        Target::Connection(arg)
    };

    let e = DebugEngine::new();
    split_attach(&e, &target);
    let _ = e.end_session();

    let compared = end_session_leaves_target_running(&e, &target);
    let _ = e.end_session();

    if compared {
        println!("\ndone (compare the two 'System Uptime' lines from section 2)");
    } else {
        println!("\ndone (section 2 did not complete — no uptimes to compare)");
    }
}
