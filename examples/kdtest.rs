//! Scratch experiment (not part of the public API): exercise the win-kexp DebugEngine
//! live-kernel path — attach+break, set a breakpoint, resume to it, and verify a `go`
//! with no breakpoint returns within its bound instead of hanging the engine thread.
//!
//! Run: cargo run --example kdtest -- "net:port=50000,key=w.x.y.z"

use std::time::Instant;

use win_kexp::dbgeng::DebugEngine;

/// Runs a command, prints its output, and reports whether it succeeded so callers can
/// stop early instead of validating bounded-wait behaviour from a broken state.
fn run(e: &DebugEngine, cmd: &str) -> bool {
    println!("--- {cmd} ---");
    let ok = match e.execute_command(cmd) {
        Ok(out) => {
            print!("{out}");
            true
        }
        Err(err) => {
            println!("ERR: {err}");
            false
        }
    };
    println!();
    ok
}

fn main() {
    let conn = std::env::args().nth(1).expect("usage: kdtest <conn>");
    let e = DebugEngine::new();

    let t = Instant::now();
    match e.attach_kernel(&conn) {
        Ok(()) => println!("attach_kernel OK in {:.1}s", t.elapsed().as_secs_f32()),
        Err(err) => {
            println!("attach_kernel ERR: {err}");
            return;
        }
    }

    if !run(&e, "bp nt!NtCreateFile") || !run(&e, "bl") {
        eprintln!("failed to set/list the breakpoint; aborting");
        return;
    }

    println!("=== g (expect Breakpoint 0 hit at nt!NtCreateFile) ===");
    let t = Instant::now();
    match e.execute_and_wait("g", 60_000) {
        Ok(out) => print!("{out}"),
        Err(err) => println!("ERR: {err}"),
    }
    println!("[g returned in {:.1}s]", t.elapsed().as_secs_f32());
    run(&e, "r");

    // Now clear the bp and `go` with NO breakpoint: the bounded wait must force a return
    // around the 5s timeout instead of hanging the engine thread forever.
    if !run(&e, "bc *") {
        eprintln!("failed to clear breakpoints; aborting");
        return;
    }
    println!("=== g with no breakpoint (expect a bounded return ~5s, NOT a hang) ===");
    let t = Instant::now();
    match e.execute_and_wait("g", 5_000) {
        Ok(out) => print!("[ok] {out}"),
        Err(err) => println!("[err] {err}"),
    }
    println!("[bounded g returned in {:.1}s]", t.elapsed().as_secs_f32());

    // Leave the target running; detach.
    if let Err(err) = e.execute_command("g") {
        eprintln!("resume before detach failed: {err}");
    }
    match e.end_session() {
        Ok(()) => println!("done"),
        Err(err) => eprintln!("end_session failed: {err}"),
    }
}
