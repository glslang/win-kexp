//! Scratch experiment (not part of the public API): what `DEBUG_REGISTER_DESCRIPTION` actually
//! says about the registers a caller would want to leave out of a default listing.
//!
//! The question it exists to answer. A host filtering "the registers" from "views of them" reaches
//! for `DEBUG_REGISTER_SUB_REGISTER`, and that flag is clear for two sets of registers that are
//! views by every other measure: `xmm0/0`…`xmm15/3` on x64 (four int64 pieces of each 128-bit
//! vector register) and `w0`–`w30` on ARM64 (the 32-bit halves of `x0`–`x30`). Is there anything
//! else in the description that identifies them — a `SubregMaster` populated even where the flag
//! is clear, a narrower `SubregLength`, a distinguishing `Type`?
//!
//! Run: cargo run --example register_description -- <dump path>

use win_kexp::dbgeng::DebugEngine;

/// `DEBUG_VALUE_*`, so the `Type` column reads as something.
///
/// Note `FLOAT82` at 8, which is easy to leave out and shifts every label above it by one — this
/// table did, and printed `VECTOR64` as `vector128`.
fn kind(value: u32) -> &'static str {
    match value {
        1 => "int8",
        2 => "int16",
        3 => "int32",
        4 => "int64",
        5 => "float32",
        6 => "float64",
        7 => "float80",
        8 => "float82",
        9 => "float128",
        10 => "vector64",
        11 => "vector128",
        other => Box::leak(format!("type{other}").into_boxed_str()),
    }
}

const SUB_REGISTER: u32 = 0x1;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: cargo run --example register_description -- <dump path>");
        std::process::exit(2);
    };

    let e = DebugEngine::new();
    if let Err(why) = e.open_dump(&path) {
        eprintln!("could not open {path}: {why}");
        std::process::exit(1);
    }
    // `open_dump` commits the session; the engine has no current process or thread until it has
    // been pumped, and `GetNumberRegisters` answers `0x8000FFFF` until it does.
    if let Err(why) = e.wait_for_event(60_000) {
        eprintln!("the dump never settled: {why}");
        std::process::exit(1);
    }

    let descriptions = match e.register_descriptions() {
        Ok(descriptions) => descriptions,
        Err(why) => {
            eprintln!("could not describe the registers: {why}");
            std::process::exit(1);
        }
    };

    println!("{} registers\n", descriptions.len());
    println!(
        "{:<12} {:>9} {:>7} {:>7} {:>12} {:>7} {:>7}",
        "name", "kind", "flags", "sub?", "master", "length", "shift"
    );
    for description in &descriptions {
        let flagged = description.flags & SUB_REGISTER != 0;
        let master = descriptions
            .get(description.subreg_master as usize)
            .map(|master| master.name.as_str())
            .unwrap_or("-");
        println!(
            "{:<12} {:>9} {:>#7x} {:>7} {:>12} {:>7} {:>7}",
            description.name,
            kind(description.kind),
            description.flags,
            if flagged { "yes" } else { "" },
            // Printed for every register, flagged or not: whether it is *meaningful* where the
            // flag is clear is the whole question.
            format!("{}({})", master, description.subreg_master),
            description.subreg_length,
            description.subreg_shift,
        );
    }

    // The summary that answers the question without reading two hundred rows.
    let flagged = descriptions
        .iter()
        .filter(|d| d.flags & SUB_REGISTER != 0)
        .count();
    // **Not `subreg_master != 0`.** Index 0 is a real register — `rax` on x64, `x0` on ARM64 — and
    // it is precisely the master the interesting rows would name if they named one, so a test that
    // treats 0 as "unset" throws away the case it was written to find. What says "the engine filled
    // nothing in here" is the whole sub-register group being zero.
    let unflagged_carrying_anything = descriptions
        .iter()
        .filter(|d| {
            d.flags & SUB_REGISTER == 0
                && (d.subreg_master != 0
                    || d.subreg_length != 0
                    || d.subreg_shift != 0
                    || d.subreg_mask != 0)
        })
        .count();
    println!(
        "\nflagged as sub-registers: {flagged}\nunflagged, with any sub-register field set: \
         {unflagged_carrying_anything}"
    );
    for name in ["xmm0/0", "w0", "eax"] {
        if let Some(d) = descriptions.iter().find(|d| d.name == name) {
            let master = descriptions
                .get(d.subreg_master as usize)
                .map(|m| m.name.as_str())
                .unwrap_or("-");
            println!(
                "  {name}: flags={:#x} kind={} master={master}({}) length={} shift={}",
                d.flags,
                kind(d.kind),
                d.subreg_master,
                d.subreg_length,
                d.subreg_shift
            );
        }
    }
}
