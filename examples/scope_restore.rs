//! Scratch experiment (not part of the public API): verify the scope save/restore from #98 —
//! that a command which moves the debugger's scope can be made observably scope-neutral.
//!
//! The claim worth proving is not "SetScope compiles" but "the session ends where it started,
//! on every path". So this runs `!analyze -v` three ways against the same dump — unguarded,
//! guarded, and guarded with a panic unwinding through it — and compares the [`Scope`] before
//! and after each. It also shows what a *stale* scope does, since a guard outliving its target
//! is the one case where putting the scope back would be wrong.
//!
//! `!analyze` is the interesting mover because nothing it does writes to the debuggee: the
//! scope is the only thing it disturbs, which is what made the host tool that runs it declare
//! itself a mutating call.
//!
//! Run: cargo run --example scope_restore -- <dump-or-trace>
//!
//! Note the engine needs its extensions on hand to run `!analyze` at all — run this from a
//! directory holding a full `dbgeng.dll` + `winext\ext.dll`, or the analysis half is skipped
//! and only the frame moves are exercised.

use std::panic::{AssertUnwindSafe, catch_unwind};

use win_kexp::dbgeng::{DebugEngine, Scope};

/// Commands that move the scope without touching the target. Which of them *can* move it is a
/// property of the dump, not of the engine: `.frame 3` needs a stack four frames deep, `.ecxr`
/// needs a stored exception context. So they are tried in turn until the scope actually differs,
/// rather than assumed to have worked — a scope that never moved would make every "restored"
/// below vacuously true.
const MOVERS: &[&str] = &[".frame 3", ".ecxr", ".frame 1"];

/// Puts the session in a non-default scope, and reports which command managed it.
fn move_the_scope(e: &DebugEngine) -> Option<&'static str> {
    let before = e.scope().ok()?;
    for command in MOVERS {
        let _ = e.execute_command(command);
        if e.scope().ok()? != before {
            return Some(command);
        }
    }
    None
}

fn frame(e: &DebugEngine) -> String {
    e.execute_command(".frame")
        .unwrap_or_else(|err| format!("ERR: {err}"))
        .trim()
        .replace('\n', " / ")
}

fn describe(scope: &Scope) -> String {
    format!(
        "ip={:#x} frame={} context={}",
        scope.instruction_offset(),
        scope.frame().FrameNumber,
        if scope.has_context() { "yes" } else { "none" }
    )
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: scope_restore <dump-or-trace>");

    // --- 0. no target: a scope cannot be read, and does not pretend to be empty ---------
    let e = DebugEngine::new();
    println!("=== 0. no target ===");
    match e.scope() {
        Ok(scope) => println!("unexpectedly read a scope: {}", describe(&scope)),
        Err(err) => println!("scope() with no target: {err}"),
    }

    e.open_dump(&path).expect("open failed");
    e.wait_for_event(120_000).expect("load failed");
    // `!analyze` lives in ext.dll, which this engine does not load on its own.
    let has_analyze = e.execute_command(".load ext").is_ok_and(|_| {
        e.execute_command("!analyze -v")
            .is_ok_and(|out| out.len() > 1000)
    });
    println!("\ntarget: {path}\nanalysis available: {has_analyze}");

    // --- 1. unguarded: the scope the caller chose does not survive ----------------------
    println!("\n=== 1. !analyze -v with no guard ===");
    match move_the_scope(&e) {
        Some(command) => println!(
            "moved off the default scope with `{command}`: {}",
            frame(&e)
        ),
        None => println!("nothing moved this target's scope — sections 1-3 prove nothing here"),
    }
    let before = e.scope().expect("scope() failed");
    println!("before: {}", describe(&before));
    let _ = e.execute_command("!analyze -v");
    let after = e.scope().expect("scope() failed");
    println!("after : {}  [{}]", describe(&after), frame(&e));
    println!("moved : {}", if after == before { "no" } else { "YES" });

    // --- 2. guarded: same command, same session, scope put back -------------------------
    println!("\n=== 2. !analyze -v inside a scope guard ===");
    move_the_scope(&e);
    let before = e.scope().expect("scope() failed");
    println!("before: {}  [{}]", describe(&before), frame(&e));
    {
        let guard = e.scope_guard().expect("scope_guard() failed");
        let _ = e.execute_command("!analyze -v");
        let inside = e.scope().expect("scope() failed");
        println!(
            "inside: {}  (analysis moved it: {})",
            describe(&inside),
            if inside == before { "no" } else { "yes" }
        );
        drop(guard);
    }
    let after = e.scope().expect("scope() failed");
    println!("after : {}  [{}]", describe(&after), frame(&e));
    println!("restored: {}", if after == before { "YES" } else { "no" });

    // --- 3. the path a hand-written restore misses: an unwind ---------------------------
    println!("\n=== 3. a panic unwinding through the guard ===");
    move_the_scope(&e);
    let before = e.scope().expect("scope() failed");
    println!("before: {}", describe(&before));
    let panicked = catch_unwind(AssertUnwindSafe(|| {
        let _guard = e.scope_guard().expect("scope_guard() failed");
        let _ = e.execute_command("!analyze -v");
        // Not only the analysis: on an engine with no `ext.dll` that command does nothing at
        // all, and a guard that restored a scope nothing had moved would prove nothing. This
        // moves it whatever the analysis did.
        let _ = e.execute_command(".frame 0");
        println!(
            "inside: {}  (moved: {})",
            describe(&e.scope().expect("scope() failed")),
            e.scope().expect("scope() failed") != before
        );
        panic!("the command's caller gave up here");
    }))
    .is_err();
    let after = e.scope().expect("scope() failed");
    println!("panicked: {panicked}");
    println!("after : {}  [{}]", describe(&after), frame(&e));
    println!("restored: {}", if after == before { "YES" } else { "no" });

    // --- 4. a scope that outlived its target is refused, not applied --------------------
    println!("\n=== 4. restoring a scope after the target is gone ===");
    let stale = e.scope().expect("scope() failed");
    let _ = e.end_session();
    e.open_dump(&path).expect("reopen failed");
    e.wait_for_event(120_000).expect("reload failed");
    match e.set_scope(&stale) {
        Ok(()) => println!("applied a stale scope — that should not happen"),
        Err(err) => println!("refused: {err}"),
    }
    // The freshly opened target still has a scope of its own, and it still round-trips.
    let fresh = e.scope().expect("scope() failed");
    move_the_scope(&e);
    e.set_scope(&fresh).expect("set_scope failed");
    println!(
        "fresh target round-trips: {}",
        e.scope().expect("scope() failed") == fresh
    );

    let _ = e.end_session();
}
