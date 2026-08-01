//! Scratch experiment (not part of the public API): verify the opener split from #71 —
//! that the target-creating side effect and the initial-break wait are separable, and
//! that the input buffers survive the seam.
//!
//! The buffer is the part worth proving. `CreateProcessWide` defers the spawn to the next
//! `WaitForEvent` and reads the command line *then*, so if `PendingTarget` did not own that
//! buffer the engine would read freed memory during `wait()` — and would do it silently.
//! A launch that lands the right image, with arguments intact, is the evidence.
//!
//! Run: cargo run --example split_open

use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use win_kexp::dbgeng::DebugEngine;

/// A command line long enough that a freed buffer is likely to read as garbage rather
/// than happening to survive in place, and distinctive enough to recognize in `|` output.
const LAUNCH_CMD: &str = "cmd.exe /c exit 42";

fn show(e: &DebugEngine, cmd: &str) {
    match e.execute_command(cmd) {
        Ok(out) => print!("{out}"),
        Err(err) => println!("ERR: {err}"),
    }
}

fn main() {
    let e = DebugEngine::new();

    // --- 1. launch, split ---------------------------------------------------------
    println!("=== 1. launch_process_begin / wait (the split path) ===");
    match e.launch_process_begin(LAUNCH_CMD) {
        Ok(pending) => {
            // This is the seam the issue is about: the side effect has succeeded, so a
            // session-tracking caller commits its handle *here* — before a wait that may
            // still fail. Re-running the open from this point would spawn a second process.
            println!("[commit] side effect OK — handle would be committed now");
            match pending.wait() {
                Ok(()) => println!("wait OK — target stopped at the loader breakpoint"),
                Err(err) => println!("wait ERR: {err}  (target may still exist!)"),
            }
        }
        Err(err) => println!("begin ERR: {err}  (nothing was created; retry is clean)"),
    }
    // If the command-line buffer had dangled, this is where it shows: a wrong image, a
    // failed spawn, or garbage. Expect cmd.exe.
    show(&e, "|");
    let _ = e.end_session();

    // --- 2. launch, fused (regression: unchanged behavior) ------------------------
    println!("\n=== 2. launch_process (the fused wrapper, now begin+wait) ===");
    match e.launch_process(LAUNCH_CMD) {
        Ok(()) => println!("launch_process OK"),
        Err(err) => println!("launch_process ERR: {err}"),
    }
    show(&e, "|");
    let _ = e.end_session();

    // --- 3. attach, split ---------------------------------------------------------
    println!("\n=== 3. attach_process_begin / wait ===");
    // `ping`, not `timeout`: the latter refuses to run with redirected stdin ("Input
    // redirection is not supported") and exits instantly, so the attach races its death.
    let mut victim = Command::new("cmd.exe")
        .args(["/c", "ping", "-n", "30", "127.0.0.1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn victim process");
    let pid = victim.id();
    println!("spawned victim pid {pid}");
    sleep(Duration::from_millis(500)); // let it finish initializing

    match e.attach_process_begin(pid) {
        Ok(pending) => {
            println!("[commit] attached to {pid} — handle would be committed now");
            match pending.wait() {
                Ok(()) => println!("wait OK — target broken in"),
                Err(err) => println!("wait ERR: {err}  (still attached!)"),
            }
        }
        Err(err) => println!("begin ERR: {err}  (not attached; retry is clean)"),
    }
    show(&e, "|");
    let _ = e.end_session();
    let _ = victim.kill();
    let _ = victim.wait();

    println!("\ndone — expect cmd.exe as the current process in 1, 2 and 3");
}
