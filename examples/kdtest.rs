//! Scratch experiment (not part of the public API): verify that end_session leaves a
//! live kernel RUNNING (not frozen). attach -> bp -> go -> end_session (resume+detach),
//! wait, then re-attach: if System Uptime advanced by ~the wait, the target was running.
//!
//! Run: cargo run --example kdtest -- "net:port=50000,key=w.x.y.z"

use std::thread::sleep;
use std::time::Duration;

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

    match e.attach_kernel(&conn) {
        Ok(()) => println!("attach #1 OK"),
        Err(err) => {
            println!("attach #1 ERR: {err}");
            return;
        }
    }
    run(&e, "vertarget"); // UPTIME #1

    run(&e, "bp nt!NtCreateFile");
    println!("=== go (to nt!NtCreateFile) ===");
    match e.execute_and_wait("g", 60_000) {
        Ok(out) => print!("{out}"),
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
    match e.attach_kernel(&conn) {
        Ok(()) => println!("attach #2 OK"),
        Err(err) => {
            println!("attach #2 ERR: {err}  (=> target was frozen/wedged, fix FAILED)");
            return;
        }
    }
    run(&e, "vertarget"); // UPTIME #2 — compare to #1: ~8s+ greater => target was RUNNING

    let _ = e.end_session();
    println!("done (compare the two 'System Uptime' lines)");
}
