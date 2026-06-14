//! Scratch experiment (not part of the public API): exercise the win-kexp DebugEngine
//! live-kernel path — attach+break, set a breakpoint, resume to it, and verify a `go`
//! with no breakpoint returns within its bound instead of hanging the engine thread.
//!
//! Run: cargo run --example kdtest -- "net:port=50000,key=w.x.y.z"

use std::time::Instant;

use win_kexp::dbgeng::DebugEngine;

fn run(e: &DebugEngine, cmd: &str) {
    println!("--- {cmd} ---");
    match e.execute_command(cmd) {
        Ok(out) => print!("{out}"),
        Err(err) => println!("ERR: {err}"),
    }
    println!();
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

    run(&e, "bp nt!NtCreateFile");
    run(&e, "bl");

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
    run(&e, "bc *");
    println!("=== g with no breakpoint (expect a bounded return ~5s, NOT a hang) ===");
    let t = Instant::now();
    match e.execute_and_wait("g", 5_000) {
        Ok(out) => print!("[ok] {out}"),
        Err(err) => println!("[err] {err}"),
    }
    println!("[bounded g returned in {:.1}s]", t.elapsed().as_secs_f32());

    // Leave the target running; detach.
    let _ = e.execute_command("g");
    let _ = e.end_session();
    println!("done");
}
