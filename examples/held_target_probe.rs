//! Scratch experiment (not part of the public API): what [`DebugEngine::debuggee_type`] and
//! [`DebugEngine::dump_files`] answer for each kind of target, and what they do in the state a
//! caller has to guard against.
//!
//! It exists because those two are the crate's answer to *has the target been swapped?* — read
//! off the engine on every call, unlike `target_identity`, which this crate moves at its own
//! openers and teardowns and which therefore does not move for a `.opendump` typed straight at
//! the engine. Anything comparing two readings needs to know which fields stand still, which
//! change, and which take the process down.
//!
//! ```text
//! cargo run --example held_target_probe -- [<dump path>]
//! ```
//!
//! **The engine has to be in `target/debug/examples`**, for the reason `breakpoint_probe`'s
//! header gives at length: an example runs from its own directory, so a `dbgeng.dll` beside the
//! library's output is not the one it loads.
//!
//! Measured on dbgeng 10.0.26100.1 (ARM64, 2026-09-25):
//!
//! ```text
//! target                                has_target  class/qualifier  dump_files   process id
//! a fresh engine, no target             false       0 / 0            *refused*    0x8000FFFF
//! a launched process at its first break true        2 / 0            []           4688
//! the same, once it has exited          false       0 / 0            *refused*    0x8000FFFF
//! a kernel dump, before the load wait   false       1 / 1024         *refused*    0x80004001
//! the same kernel dump, loaded          true        1 / 1024         [<the path>] 0x80004001
//! ```
//!
//! Four things in that table are worth carrying:
//!
//! 1. **`dump_files` on an engine with no debuggee is a `STATUS_ACCESS_VIOLATION` inside DbgEng**,
//!    not an error — exit code `0xC0000005`, taking the process with it. That is why the method
//!    guards, and this probe is where it was found: its first run died on the very first arm.
//! 2. **`debuggee_type` does not**, on the same engine in the same state, and answers
//!    `DEBUG_CLASS_UNINITIALIZED`. Two queries sitting beside each other behave differently,
//!    which is exactly how a caller comes to ask both in one place and lose the process.
//! 3. **A dump's class and qualifier are known before the load wait and its file name is not**, so
//!    a reading taken between `open_dump` and the `WaitForEvent` that loads it is not the reading
//!    a later one will be compared against.
//! 4. **A kernel target has no process id to read** (`E_NOTIMPL`), which is the hard half of a
//!    rule that also holds softly: on a kernel target the current process is whatever the machine
//!    was last running, so it is not a fingerprint of the target even where it does answer.
//!
//! The live-kernel arm (`DBGSCOPE_PROBE_KERNEL`) answers the question those four leave open —
//! *what tells two live kernel targets apart?* Measured the same day against a serial target
//! (`com:port=COM1,baud=115200`, ARM64 26100):
//!
//! ```text
//!   a live kernel connection
//!     has_target     = Ok(true)
//!     debuggee_type  = class 1 qualifier 0 (kernel true, live kernel true)
//!     dump_files     = []
//!     process id     = ERR ... Not implemented (0x80004001)
//!     kernel conn    = scheme "KdSrv", 75 chars, hash c938bc08b2a5f280
//!     released: KernelRunning
//! ```
//!
//! **Nothing but the connection options distinguishes one**: the class and qualifier are what
//! every live kernel has, there are no dump files, and there is no process set. And the string is
//! **DbgEng's own canonical form** rather than what was dialled — a 30-character `com:` string
//! came back as 75 characters of `KdSrv:…`. That is better for identity, being normalised, and it
//! means it cannot be compared against a connection string a caller holds. The probe prints a
//! length and a hash and never the string itself, because a KDNET form carries the target's
//! `key=`.

use dbgscope::dbgeng::DebugEngine;

fn show(tag: &str, e: &DebugEngine) {
    println!("--- {tag}");
    println!("  has_target     = {:?}", e.has_target());
    match e.debuggee_type() {
        Ok(t) => println!(
            "  debuggee_type  = class {} qualifier {} (kernel {}, live kernel {})",
            t.class,
            t.qualifier,
            t.is_kernel(),
            t.is_live_kernel()
        ),
        Err(err) => println!("  debuggee_type  = ERR {err}"),
    }
    match e.dump_files() {
        Ok(files) => println!("  dump_files     = {files:?}"),
        Err(err) => println!("  dump_files     = ERR {err}"),
    }
    match e.current_process_system_id() {
        Ok(pid) => println!("  process id     = {pid}"),
        Err(err) => println!("  process id     = ERR {err}"),
    }
    // **Length and a hash, never the string.** A KDNET connection string carries the target's
    // debug `key=`, and this probe's output is pasted into pull requests.
    match e.kernel_connection_options() {
        Ok(options) => {
            let scheme = options.split(':').next().unwrap_or("").to_string();
            println!(
                "  kernel conn    = scheme {:?}, {} chars, hash {:016x}",
                scheme,
                options.len(),
                fnv(&options)
            );
        }
        Err(err) => println!("  kernel conn    = ERR {err}"),
    }
}

/// FNV-1a, so two readings can be compared in this probe's output without printing either.
fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

fn main() {
    // A live kernel arm, off by default: it dials a real target and detaches it again, which is
    // not something an ordinary run of this probe should do. The connection string is taken from
    // the environment rather than the command line so it stays out of the process table.
    if let Ok(connection) = std::env::var("DBGSCOPE_PROBE_KERNEL") {
        let e = DebugEngine::new();
        match e.attach_kernel(&connection) {
            Ok(()) => {
                show("a live kernel connection", &e);
                // Let go of it explicitly rather than on drop, so a failure to resume is visible
                // here rather than in whatever the guest does next.
                match e.end_session() {
                    Ok(left) => println!("  released: {left:?}"),
                    Err(err) => println!("  release ERR: {err}"),
                }
            }
            // Never printed with the connection string beside it.
            Err(err) => println!("kernel attach failed: {err}"),
        }
        return;
    }

    let dump = std::env::args().nth(1);

    {
        let e = DebugEngine::new();
        show("a fresh engine, no target at all", &e);
    }

    {
        let e = DebugEngine::new();
        match e.launch_process("cmd.exe /c ping -n 3 127.0.0.1") {
            Ok(()) => {
                show("a launched live process, stopped at its initial break", &e);
                // Run it to completion and look again. This is the state that took a caller's
                // process down before `dump_files` guarded, and it is not an exotic one: it is
                // how every launched debuggee ends.
                println!("--- running it to completion");
                match e.execute_and_wait("g", 30_000) {
                    Ok(run) => println!("  g -> target_gone {}", run.target_gone),
                    Err(err) => println!("  g -> ERR {err}"),
                }
                show("the same engine once its debuggee has exited", &e);
            }
            Err(err) => println!("launch failed: {err}"),
        }
    }

    let Some(path) = dump else {
        return;
    };
    let e = DebugEngine::new();
    match e.open_dump(&path) {
        Ok(()) => {
            show(&format!("a dump opened but not yet loaded: {path}"), &e);
            // `open_dump` is `OpenDumpFileWide` alone; the load is deferred to the next
            // `WaitForEvent`, which is what every caller runs straight afterwards.
            match e.wait_for_event(60_000) {
                Ok(outcome) => println!("--- load wait: {outcome:?}"),
                Err(err) => println!("--- load wait ERR: {err}"),
            }
            show(&format!("the same dump, loaded: {path}"), &e);
        }
        Err(err) => println!("open_dump failed: {err}"),
    }
}
