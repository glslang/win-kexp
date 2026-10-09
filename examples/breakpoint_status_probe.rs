//! Scratch experiment (not part of the public API): what a breakpoint callback's
//! [`BreakpointAction`] does against a real engine, and what letting a hit go past costs.
//!
//! It answers the questions a callback that **lets the target run on** stands on, none of which a
//! unit test can, because each is about what a real `dbgeng.dll` does with the status:
//!
//! 1. **Is `Default` what no callback is?** A callback answering it on every hit must leave the
//!    breakpoint stopping on the first one, exactly as it would with nothing registered.
//! 2. **Is `Go` honoured?** A callback answering `Go` for hits `1..n` and `Break` on hit `n` must
//!    stop once, at the breakpoint, having seen exactly `n` hits. Before `BreakpointAction` the
//!    callback could not say this at all: its `Result<()>` reached the engine as `S_OK`, which is
//!    `DEBUG_STATUS_NO_CHANGE`.
//! 3. **Can the callback use the engine?** On every hit it reads through the hit's own view
//!    ([`BreakpointHit::engine`]): the instruction pointer, the thread, three argument registers
//!    and the stack pointer, and the bytes at the breakpoint and at the stack. A recorder that
//!    cannot read the arguments of the call it trapped records nothing.
//! 4. **What does a hit cost each way?** The same `n` hits let through four ways: a **pass count**,
//!    which the engine applies itself and so is the bare cost of a trap; the callback answering
//!    `Go`; the callback reading the engine on every hit; and **command text** -- an `.if` on a
//!    pseudo-register ending in `gc`, the shape `ioctl_trace` in windbg-mcp uses today. And whether
//!    a breakpoint's command still runs on a hit the callback lets through.
//!
//! Every hit is a trap whichever way it is let through: a software breakpoint is an `int 3` in the
//! target's code, so the target stops and the host decides. On a live kernel that is a round trip
//! over the KD link per hit, which is why the `kernel` arm takes a time cap as well as a count --
//! and why its location should be a call site in one module rather than the allocator itself.
//!
//! ```text
//! cargo run --example breakpoint_status_probe -- user [location] [--hits <n>]
//! cargo run --example breakpoint_status_probe -- kernel <connection> [location] [--hits <n>] [--seconds <s>]
//! ```
//!
//! `user` launches its own target (`cmd.exe /c ping`) and defaults to `ntdll!RtlAllocateHeap`.
//! `kernel` attaches to a live kernel and defaults to `nt!ExAllocatePool2`; it leaves the kernel
//! running when it ends, and removes its breakpoint on every path it can.
//!
//! **The engine has to be in `target/debug/examples`, not `target/debug`** -- see
//! `breakpoint_probe.rs` for what a run on System32's engine quietly measures instead.
//!
//! Measured 2026-10-08 on dbgeng 10.0.26100.1742, ARM64, debugger Windows 26100, against a launched
//! `cmd.exe` and against a live Windows 26200 ARM64 kernel over **115200-baud serial**:
//!
//! | | user mode, `RtlAllocateHeap` | kernel over serial, `ExAllocatePool2` |
//! |---|---|---|
//! | 1. `Default` on every hit | stops on hit 1 | stops on hit 1 |
//! | 2. `Go`, then `Break` | 200 of 200, stops at it | 100 of 100 and 50 of 50, stops at it |
//! | pass count | 0.204 ms/hit | 22.9 / 26.5 ms/hit |
//! | callback `Go` | 0.167 ms/hit | 23.4 / 23.2 ms/hit |
//! | callback `Go` reading the engine | 0.177 ms/hit | 23.5 / 24.3 ms/hit |
//! | command text | 0.190 ms/hit | 27.0 / 26.4 ms/hit |
//! | command beside a `Go` | ran on all 3 hits | ran on all 3 hits |
//!
//! Two kernel runs, so read a difference between ways against the 3.6 ms the pass count moved
//! between them: what is measured is that **a hit costs one trap whichever way it is let through**,
//! and on this link a trap is a ~25 ms round trip. Reads inside the callback cost microseconds --
//! the view, the instruction pointer and three argument registers together under 10 us, a full
//! `register_values()` (194 registers user-mode, 214 kernel) 0.1 ms -- because the stop already
//! carried them; **8 bytes the engine had not cached cost 1.05 ms** over serial, a link round trip of
//! its own. `ExAllocatePool2` is saturated at that rate: 100 hits arrive in 2.3 s, back to back.
//!
//! `current_thread_data_offset` equals the engine's own `@$thread` at the stop on both: the TEB
//! user-mode (`0xa79cf3b000`) and the KTHREAD on the kernel (`0xffffc386c48ed080`), measured
//! 2026-10-09 through the hit view, where every kernel figure above repeated within its noise.
//!
//! One trap measured nothing the first time and is worth knowing: every phase on **one** launched
//! process read the later ways as up to 2000x slower, because the first phases spent `cmd.exe`'s
//! startup burst of allocations and the rest waited on a process that had gone quiet. The rate was
//! the target's, not the way's -- hence a fresh process per phase.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dbgscope::dbgeng::{
    BreakpointAction, BreakpointAt, BreakpointCallback, BreakpointHit, BreakpointSpec, DebugEngine,
};

/// A user-mode target that allocates, and exits on its own if this program dies holding it.
///
/// Ten minutes, because an arm that runs to its cap must not take the target with it: at 60s the
/// arm after a capped one found the process already gone.
const TARGET: &str = "cmd.exe /c ping -n 600 127.0.0.1";

const USER_LOCATION: &str = "ntdll!RtlAllocateHeap";
const KERNEL_LOCATION: &str = "nt!ExAllocatePool2";

/// What one hit's callback saw when it read the engine.
#[derive(Default)]
struct EngineReads {
    /// Hits on which every read succeeded and the instruction pointer was the breakpoint's.
    clean: u32,
    /// Hits on which a read failed or answered something else, and the first such answer.
    failed: u32,
    first_failure: Option<String>,
    /// Time spent in each step, summed over the clean hits.
    ip: Duration,
    /// `current_thread_data_offset`, and the distinct answers it gave.
    thread: Duration,
    threads: BTreeSet<u64>,
    arguments: Duration,
    memory: Duration,
    /// Eight bytes at the stack pointer: memory the engine has not cached for this stop, which on
    /// a live kernel is a round trip over the link -- what reading a return address or a pool
    /// header costs, where the code at the instruction pointer was read when the breakpoint went in.
    stack: Duration,
    /// One full `register_values()`, taken on the first hit only, and how many it returned.
    full_bank: Option<(Duration, usize)>,
}

/// The registers a call's first three integer arguments arrive in -- what a recorder reads -- and
/// the stack pointer.
fn argument_registers(engine: &DebugEngine) -> [&'static str; 4] {
    match engine.processor_type() {
        Ok(0xaa64) => ["x0", "x1", "x2", "sp"],
        _ => ["rcx", "rdx", "r8", "rsp"],
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let arm = args.next().unwrap_or_default();
    let mut positional = Vec::new();
    let mut hits = 200u32;
    let mut seconds = 30u32;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--hits" => hits = args.next().and_then(|n| n.parse().ok()).unwrap_or(hits),
            "--seconds" => seconds = args.next().and_then(|n| n.parse().ok()).unwrap_or(seconds),
            other => positional.push(other.to_string()),
        }
    }
    let hits = hits.max(2);

    let phases = |engine: &DebugEngine, location: &str, phase: Phase| match phase {
        Phase::DefaultIsNone => default_is_no_callback(engine, location, seconds),
        Phase::Through(way) => let_hits_through(engine, location, hits, seconds, way),
        Phase::CommandBeside => command_beside_callback(engine, location, seconds),
    };
    match arm.as_str() {
        // **A fresh process per phase**, so each one is measured on the same stream of hits. Run on
        // one target, the first phases spent `cmd.exe`'s startup burst of allocations and the
        // later ones waited on a process that had gone quiet -- which read as the later *way*
        // being slow, when it was the target's own call rate.
        "user" => {
            let location = positional
                .first()
                .cloned()
                .unwrap_or_else(|| USER_LOCATION.into());
            println!("location {location}, {hits} hits, {seconds}s cap, a fresh target per phase");
            for phase in Phase::ALL {
                let engine = DebugEngine::new();
                if let Err(e) = engine.launch_process(TARGET) {
                    println!("could not launch {TARGET}: {e}");
                    return;
                }
                phases(&engine, &location, phase);
                if let Err(e) = engine.end_session() {
                    println!("  end_session failed: {e}");
                }
            }
        }
        // One attach for every phase: a kernel cannot be relaunched, and its allocations do not
        // come in a burst that a phase can use up.
        "kernel" => {
            let Some(connection) = positional.first() else {
                println!("kernel needs a connection string");
                return;
            };
            let location = positional
                .get(1)
                .cloned()
                .unwrap_or_else(|| KERNEL_LOCATION.into());
            let engine = DebugEngine::new();
            if let Err(e) = engine.attach_kernel(connection) {
                println!("could not attach to {connection}: {e}");
                return;
            }
            println!("location {location}, {hits} hits, {seconds}s cap");
            for phase in Phase::ALL {
                phases(&engine, &location, phase);
            }
            // Leaves the kernel running and detached.
            match engine.end_session() {
                Ok(left) => println!("\nended: {left:?}"),
                Err(e) => println!("\nend_session failed: {e}"),
            }
        }
        _ => println!("arms: user [location], kernel <connection> [location]"),
    }
}

#[derive(Clone, Copy)]
enum Phase {
    DefaultIsNone,
    Through(Way),
    CommandBeside,
}

impl Phase {
    const ALL: [Self; 6] = [
        Self::DefaultIsNone,
        Self::Through(Way::PassCount),
        Self::Through(Way::Go),
        Self::Through(Way::GoReadingEngine),
        Self::Through(Way::CommandText),
        Self::CommandBeside,
    ];
}

/// Question 1: a callback answering `Default` on every hit stops on the first one.
fn default_is_no_callback(engine: &DebugEngine, location: &str, seconds: u32) {
    println!("\n======== 1. Default is what no callback is ========");
    let seen = Rc::new(Cell::new(0u32));
    let counter = Rc::clone(&seen);
    let callback: BreakpointCallback = Box::new(move |_: &BreakpointHit<'_>| {
        counter.set(counter.get() + 1);
        BreakpointAction::Default
    });
    let Some(armed) = Armed::new(engine, location, None, None, Some(callback)) else {
        return;
    };
    let ran = run(engine, seconds);
    println!(
        "  hits seen {} (want 1), stopped at {} (breakpoint {:#x}), {:.1} ms",
        seen.get(),
        ran.stopped_at
            .map_or_else(|| "?".into(), |a| format!("{a:#x}")),
        armed.address,
        ran.elapsed
    );
}

#[derive(Clone, Copy, Debug)]
enum Way {
    /// The engine's own pass count: the bare cost of a trap.
    PassCount,
    /// The callback answering `Go`, then `Break` on the last hit.
    Go,
    /// The same, reading the engine on every hit.
    GoReadingEngine,
    /// Command text: an `.if` on `$t19` ending in `gc`.
    CommandText,
}

/// Questions 2-4: let `hits - 1` hits through one way, stop on the last, and time it.
fn let_hits_through(engine: &DebugEngine, location: &str, hits: u32, seconds: u32, way: Way) {
    println!("\n======== {way:?} ========");
    let seen = Rc::new(Cell::new(0u32));
    let reads = Rc::new(RefCell::new(EngineReads::default()));
    let (pass_count, command, callback): (Option<u32>, Option<String>, Option<BreakpointCallback>) =
        match way {
            Way::PassCount => (Some(hits), None, None),
            Way::CommandText => (
                None,
                Some(format!(
                    "r $t19 = @$t19 + 1; .if (@$t19 < 0n{hits}) {{ gc }} .else {{ .echo stopped }}"
                )),
                None,
            ),
            Way::Go | Way::GoReadingEngine => {
                let counter = Rc::clone(&seen);
                let reads = Rc::clone(&reads);
                let read_engine = matches!(way, Way::GoReadingEngine);
                let arguments = argument_registers(engine);
                (
                    None,
                    None,
                    Some(Box::new(move |hit: &BreakpointHit<'_>| {
                        let n = counter.get() + 1;
                        counter.set(n);
                        if read_engine {
                            let result =
                                read_through(hit, &arguments, &mut reads.borrow_mut(), n == 1);
                            match result {
                                Ok(()) => reads.borrow_mut().clean += 1,
                                Err(why) => {
                                    let mut reads = reads.borrow_mut();
                                    reads.failed += 1;
                                    reads.first_failure.get_or_insert(why);
                                }
                            }
                        }
                        if n < hits {
                            BreakpointAction::Go
                        } else {
                            BreakpointAction::Break
                        }
                    })),
                )
            }
        };
    if matches!(way, Way::CommandText) {
        let _ = engine.execute_command("r $t19 = 0");
    }
    let Some(armed) = Armed::new(engine, location, pass_count, command, callback) else {
        return;
    };
    let ran = run(engine, seconds);
    let elapsed = ran.elapsed;
    let counted = match way {
        Way::Go | Way::GoReadingEngine => Some(seen.get()),
        Way::CommandText => {
            let read = pseudo_register(engine, "$t19");
            if read.is_none() {
                println!("  could not read $t19, so the hits are unknown");
            }
            read
        }
        Way::PassCount => None,
    };
    // A pass count reports no count of its own: it is `hits` exactly when the phase finished,
    // and unknown otherwise.
    let counted = counted.or(ran.finished_at(armed.address).then_some(hits));
    let shown = counted.map_or_else(|| "?".into(), |n| n.to_string());
    match counted {
        Some(n) if n > 0 && ran.finished_at(armed.address) => println!(
            "  {n} hits in {elapsed:.1} ms = {:.3} ms/hit; stopped at the breakpoint on the last",
            elapsed / f64::from(n)
        ),
        _ => println!(
            "  INCOMPLETE: {shown} hits in {elapsed:.1} ms without stopping at the breakpoint, so \
             no per-hit figure"
        ),
    }
    if matches!(way, Way::GoReadingEngine) {
        let reads = reads.borrow();
        println!(
            "  engine reads inside the callback: {} clean, {} failed{}",
            reads.clean,
            reads.failed,
            reads
                .first_failure
                .as_ref()
                .map_or_else(String::new, |why| format!(" (first: {why})"))
        );
        let per_hit = |d: Duration| d.as_secs_f64() * 1000.0 / f64::from(reads.clean.max(1));
        println!(
            "  per clean hit: ip {:.3} ms, thread {:.3} ms, three argument registers and sp \
             {:.3} ms, memory at ip {:.3} ms, 8 bytes at sp {:.3} ms",
            per_hit(reads.ip),
            per_hit(reads.thread),
            per_hit(reads.arguments),
            per_hit(reads.memory),
            per_hit(reads.stack)
        );
        if let Some((took, count)) = reads.full_bank {
            println!(
                "  one register_values() inside the callback: {count} registers in {:.1} ms",
                took.as_secs_f64() * 1000.0
            );
        }
        // What `current_thread_data_offset` names, checked against the engine's own `@$thread`
        // at the stop: the KTHREAD on a kernel, the TEB in user mode.
        println!(
            "  distinct threads hit: {}; at the stop current_thread_data_offset {} against \
             @$thread {}",
            reads.threads.len(),
            engine
                .current_thread_data_offset()
                .map_or_else(|e| e.to_string(), |at| format!("{at:#x}")),
            pseudo_register_u64(engine, "$thread")
                .map_or_else(|| "?".into(), |at| format!("{at:#x}"))
        );
    }
}

/// Whether a breakpoint's command still runs on a hit the callback lets through.
fn command_beside_callback(engine: &DebugEngine, location: &str, seconds: u32) {
    println!("\n======== a command beside a callback that answers Go ========");
    let seen = Rc::new(Cell::new(0u32));
    let counter = Rc::clone(&seen);
    let callback: BreakpointCallback = Box::new(move |_: &BreakpointHit<'_>| {
        let n = counter.get() + 1;
        counter.set(n);
        if n < 3 {
            BreakpointAction::Go
        } else {
            BreakpointAction::Break
        }
    });
    let Some(_armed) = Armed::new(
        engine,
        location,
        None,
        Some(".echo PROBE-COMMAND-RAN".into()),
        Some(callback),
    ) else {
        return;
    };
    let started = Instant::now();
    match engine.execute_and_wait("g", seconds * 1000) {
        Ok(run) => println!(
            "  callback saw {} hits; the command ran {} times; {:.1} ms; cut_short={:?}",
            seen.get(),
            run.output.matches("PROBE-COMMAND-RAN").count(),
            started.elapsed().as_secs_f64() * 1000.0,
            run.cut_short
        ),
        Err(e) => println!("  g failed: {e}"),
    }
}

/// Reads the engine from inside a callback, through the hit's own view, timing each step.
/// `full_bank` additionally times one `register_values()`, the read a recorder should not make per
/// hit.
fn read_through(
    hit: &BreakpointHit<'_>,
    registers: &[&str],
    reads: &mut EngineReads,
    full_bank: bool,
) -> Result<(), String> {
    let engine = hit.engine();
    let started = Instant::now();
    let offset = hit.address().map_err(|e| e.to_string())?;
    let ip = engine
        .instruction_pointer()
        .map_err(|e| format!("ip: {e}"))?;
    if ip != offset {
        return Err(format!("ip {ip:#x} is not the breakpoint's {offset:#x}"));
    }
    let ip_read = Instant::now();

    let thread = engine
        .current_thread_data_offset()
        .map_err(|e| format!("thread: {e}"))?;
    let thread_read = Instant::now();

    // The last name is the stack pointer.
    let mut stack_pointer = 0;
    for name in registers {
        stack_pointer = engine.integer_register(name).map_err(|e| e.to_string())?;
    }
    let arguments_read = Instant::now();

    engine
        .read_memory(ip, 4)
        .map_err(|e| format!("memory at ip: {e}"))?;
    let memory_read = Instant::now();

    engine
        .read_memory(stack_pointer, 8)
        .map_err(|e| format!("memory at sp {stack_pointer:#x}: {e}"))?;
    let stack_read = Instant::now();

    reads.ip += ip_read - started;
    reads.thread += thread_read - ip_read;
    reads.threads.insert(thread);
    reads.arguments += arguments_read - thread_read;
    reads.memory += memory_read - arguments_read;
    reads.stack += stack_read - memory_read;
    if full_bank {
        let bank_started = Instant::now();
        let count = engine
            .register_values()
            .map_err(|e| format!("register_values: {e}"))?
            .len();
        reads.full_bank = Some((bank_started.elapsed(), count));
    }
    Ok(())
}

/// A pseudo-register's full value, read from `?`'s `Evaluate expression: <dec> = <hex>`.
fn pseudo_register_u64(engine: &DebugEngine, name: &str) -> Option<u64> {
    let text = engine.execute_command(&format!("? @{name}")).ok()?;
    let hex = text.split('=').nth(1)?.trim();
    u64::from_str_radix(&hex.replace('`', ""), 16).ok()
}

/// A pseudo-register's value, read from `?`'s `Evaluate expression: <dec> = <hex>`.
fn pseudo_register(engine: &DebugEngine, name: &str) -> Option<u32> {
    let text = engine.execute_command(&format!("? @{name}")).ok()?;
    let value = text
        .split("Evaluate expression:")
        .nth(1)?
        .split('=')
        .next()?;
    value.trim().parse().ok()
}

/// Resumes and waits for the next stop, bounded; answers the time taken and where it stopped.
fn run(engine: &DebugEngine, seconds: u32) -> Ran {
    let started = Instant::now();
    let on_its_own = match engine.execute_and_wait("g", seconds * 1000) {
        Ok(run) => {
            if run.cut_short.is_some() {
                println!(
                    "  the wait was cut short ({:?}): the cap, not a stop",
                    run.cut_short
                );
            }
            if run.target_gone {
                println!("  the target is gone");
            }
            run.cut_short.is_none() && !run.target_gone
        }
        Err(e) => {
            println!("  g failed: {e}");
            false
        }
    };
    Ran {
        elapsed: started.elapsed().as_secs_f64() * 1000.0,
        stopped_at: engine.instruction_pointer().ok(),
        on_its_own,
    }
}

/// One resume: how long it took, where the target stopped, and whether the wait ended because the
/// target stopped -- rather than on the cap, a lost target or a failed wait.
struct Ran {
    elapsed: f64,
    stopped_at: Option<u64>,
    on_its_own: bool,
}

impl Ran {
    /// A phase finished only if the target stopped itself, at the breakpoint: that stop is the last
    /// hit, so the count is the whole phase and the elapsed time is spent on hits. Anything else
    /// leaves a time that includes waiting on a target that was not hitting -- which is how a 60s
    /// cap once read as 331 ms a hit -- so it gets no per-hit figure at all.
    fn finished_at(&self, address: u64) -> bool {
        self.on_its_own && self.stopped_at == Some(address)
    }
}

/// One breakpoint and its callbacks, removed and unregistered when it goes out of scope.
struct Armed<'a> {
    engine: &'a DebugEngine,
    id: u32,
    address: u64,
}

impl<'a> Armed<'a> {
    fn new(
        engine: &'a DebugEngine,
        location: &str,
        pass_count: Option<u32>,
        command: Option<String>,
        callback: Option<BreakpointCallback>,
    ) -> Option<Self> {
        let mut spec = BreakpointSpec::code(BreakpointAt::Expression(location.into()));
        if let Some(command) = command {
            spec = spec.with_command(command);
        }
        if let Some(passes) = pass_count {
            spec = spec.with_pass_count(passes);
        }
        let set = match engine.set_breakpoint(&spec) {
            Ok(set) => set,
            Err(e) => {
                println!("  could not set a breakpoint at {location}: {e}");
                return None;
            }
        };
        let Some(address) = set.breakpoint.address else {
            println!("  {location} did not resolve");
            let _ = engine.remove_breakpoint(set.breakpoint.id);
            return None;
        };
        let armed = Self {
            engine,
            id: set.breakpoint.id,
            address,
        };
        if let Some(callback) = callback {
            if let Err(e) = engine.set_breakpoint_callback(callback) {
                println!("  could not register the callbacks: {e}");
                return None;
            }
        }
        Some(armed)
    }
}

impl Drop for Armed<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.engine.clear_breakpoint_callback() {
            println!("  could not unregister the callbacks: {e}");
        }
        if let Err(e) = self.engine.remove_breakpoint(self.id) {
            println!("  could not remove breakpoint {}: {e}", self.id);
        }
    }
}
