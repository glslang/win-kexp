//! Scratch experiment (not part of the public API): check the typed context readers —
//! `register_values`, `modules` and `breakpoints` — against the text the debugger prints for
//! the same state.
//!
//! Each of the three replaces a parse a host would otherwise have to do on `r`, `lm` or `bl`,
//! and the failure mode being checked for is the quiet one: a union arm read by the wrong tag,
//! a name buffer truncated, a deferred breakpoint reported as an address. So every section
//! prints the engine's own rendering next to the values, and the two are compared by eye.
//!
//! Run against a launched process:  cargo run --example typed_context
//! Run against a crash dump:        cargo run --example typed_context -- C:\path\to\dump.dmp

use win_kexp::dbgeng::{DebugEngine, RegisterValue};

fn show(e: &DebugEngine, cmd: &str) {
    match e.execute_command(cmd) {
        Ok(out) => print!("{out}"),
        Err(err) => println!("ERR: {err}"),
    }
}

fn rendered(value: &RegisterValue) -> String {
    match value {
        RegisterValue::Int(v) => format!("{v:#018x}"),
        RegisterValue::Float(v) => format!("{v}"),
        RegisterValue::Bytes(bytes) => hex::encode(bytes),
        RegisterValue::Unavailable => "(unavailable)".to_string(),
    }
}

fn main() {
    let e = DebugEngine::new();

    let target = std::env::args().nth(1);
    match &target {
        Some(dump) => {
            println!("=== opening dump {dump} ===");
            if let Err(err) = e.open_dump(dump) {
                println!("open_dump ERR: {err}");
                return;
            }
            if let Err(err) = e.wait_for_event(60_000) {
                println!("load wait ERR: {err}");
                return;
            }
        }
        None => {
            println!("=== launching cmd.exe ===");
            if let Err(err) = e.launch_process("cmd.exe /c exit 42") {
                println!("launch ERR: {err}");
                return;
            }
        }
    }

    // --- registers ------------------------------------------------------------------
    println!("\n=== r (what a host would have had to parse) ===");
    show(&e, "r");
    println!("\n=== register_values() ===");
    match e.register_values() {
        Ok(registers) => {
            let subs = registers.iter().filter(|r| r.subregister).count();
            println!(
                "{} registers ({subs} subregisters), {} unavailable",
                registers.len(),
                registers
                    .iter()
                    .filter(|r| r.value == RegisterValue::Unavailable)
                    .count()
            );
            // The general-purpose set, then a sample of everything else: the whole bank is
            // hundreds of entries and the point is the shape, not the volume.
            for register in registers.iter().filter(|r| !r.subregister).take(24) {
                println!("  {:<10} {}", register.name, rendered(&register.value));
            }
            for name in ["xmm0", "st0", "efl", "cs"] {
                match registers.iter().find(|r| r.name == name) {
                    Some(register) => {
                        println!("  {:<10} {}", register.name, rendered(&register.value))
                    }
                    None => println!("  {name:<10} (not present on this target)"),
                }
            }
        }
        Err(err) => println!("register_values ERR: {err}"),
    }
    // Compare against the same value the engine prints as the current instruction's address.
    match e.instruction_pointer() {
        Ok(ip) => println!("  instruction_pointer() = {ip:#018x}"),
        Err(err) => println!("  instruction_pointer ERR: {err}"),
    }

    // --- modules --------------------------------------------------------------------
    println!("\n=== lm ===");
    show(&e, "lm");
    println!("\n=== modules() ===");
    match e.modules() {
        Ok(modules) => {
            println!("{} loaded modules", modules.len());
            for module in modules.iter().take(12) {
                println!(
                    "  {:#018x}-{:#018x}  {:<16} {:<24} {:?}{}",
                    module.base,
                    module.end(),
                    module.name,
                    module.image_name,
                    module.symbols,
                    if module.user_mode { " [user]" } else { "" }
                );
            }
            // A name that came back empty is the truncation bug this section is here to catch.
            let nameless = modules.iter().filter(|m| m.name.is_empty()).count();
            println!("modules with no name: {nameless} (expected 0)");
        }
        Err(err) => println!("modules ERR: {err}"),
    }

    // --- unloaded modules -----------------------------------------------------------
    //
    // The tail `lm` prints under `Unloaded modules:`, which `modules()` deliberately does not
    // carry. Compared against that text by eye like everything else here: the count, the names
    // and the ranges have to be the rows `lm` printed above.
    println!("\n=== unloaded_modules() ===");
    match e.unloaded_modules() {
        Ok(modules) => {
            println!("{} unloaded modules", modules.len());
            for module in modules.iter().take(8) {
                println!(
                    "  {:#018x}-{:#018x}  {:<16} {:<24} {:?}",
                    module.base,
                    module.end(),
                    module.name,
                    module.image_name,
                    module.symbols,
                );
            }
            // `name` is empty for these *by design* — nothing is left to qualify a symbol with —
            // so the name to check is the image's, which is what `lm` prints in its place and
            // what the kernel truncates to twelve characters.
            let nameless = modules.iter().filter(|m| m.image_name.is_empty()).count();
            println!("unloaded modules with no image name: {nameless} (expected 0)");
            let named = modules.iter().filter(|m| !m.name.is_empty()).count();
            println!("unloaded modules with a module name: {named} (expected 0)");
            let flagged = modules.iter().filter(|m| m.unloaded).count();
            println!(
                "flagged unloaded by the engine: {flagged} (expected {})",
                modules.len()
            );
        }
        Err(err) => println!("unloaded_modules ERR: {err}"),
    }

    // --- breakpoints ----------------------------------------------------------------
    //
    // Two on purpose: one that resolves now, and one on a module nothing has loaded, which is
    // the case where the address is *absent* rather than zero.
    println!("\n=== breakpoints ===");
    let resolvable = match target {
        Some(_) => "nt!KeBugCheckEx",
        None => "ntdll!NtCreateFile",
    };
    show(&e, &format!("bp {resolvable}"));
    show(&e, "bp nosuchmodule!NoSuchSymbol");
    show(&e, "bl");
    match e.breakpoints() {
        Ok(breakpoints) => {
            println!("{} breakpoints", breakpoints.len());
            for bp in &breakpoints {
                println!(
                    "  #{} {:?} address={} expr={:?} enabled={} deferred={} passes={}/{}",
                    bp.id,
                    bp.kind,
                    bp.address
                        .map_or_else(|| "(unresolved)".to_string(), |a| format!("{a:#018x}")),
                    bp.expression,
                    bp.enabled,
                    bp.deferred,
                    bp.passes_remaining,
                    bp.pass_count,
                );
            }
        }
        Err(err) => println!("breakpoints ERR: {err}"),
    }

    let _ = e.end_session();
}
