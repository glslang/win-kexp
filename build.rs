use std::io;
use std::path::Path;
use std::process::{Command, Output};

fn main() {
    // A build script is compiled for the *host*, so `cfg!(target_arch)` in here
    // describes the machine doing the build, not the machine the shellcode will
    // run on. `src/shellcode.rs` gates its `include_bytes!` on the real target,
    // so anything host-gated silently disagrees with it under `--target`: an x64
    // host cross-building for aarch64 assembled the x64 sources and handed them
    // to the ARM64 code path. Read Cargo's description of the target instead.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    // The ARM64 sources branch on this, and Cargo tracks no environment read it
    // is not told about. Without this line `WINDOWS_VERSION=23H2 cargo build`
    // after a 24H2 build reuses the 24H2 objects and reports success.
    println!("cargo:rerun-if-env-changed=WINDOWS_VERSION");

    if target_os != "windows" {
        return;
    }

    let assembler_available = match target_arch.as_str() {
        "x86_64" => assembler_responds("ml64", "/?"),
        "aarch64" => assembler_responds("armasm64", "-help"),
        _ => false,
    };

    if assembler_available {
        println!("[+] Assembler found, compiling assembly files");
        compile_asm_files(&target_arch);
    } else {
        println!("[-] No assembler found, using fallback shellcode");
        println!("cargo:rustc-cfg=feature=\"shellcode_fallback\"");
    }
}

fn assembler_responds(tool: &str, help_flag: &str) -> bool {
    Command::new(tool)
        .arg(help_flag)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn compile_asm_files(target_arch: &str) {
    let windows_version_original =
        std::env::var("WINDOWS_VERSION").unwrap_or_else(|_| "24H2".to_string());
    let windows_version = windows_version_original.trim();

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");

    let arm64 = target_arch == "aarch64";

    if arm64 && !["23H2", "24H2"].contains(&windows_version) {
        eprintln!(
            "[-] Invalid Windows version: {}. Must be either 23H2 or 24H2",
            windows_version
        );
        println!("cargo:rustc-cfg=feature=\"shellcode_fallback\"");
        return;
    }

    // Source, and the object stem `src/shellcode.rs` expects to `include_bytes!`.
    let asm_files: &[(&str, &str)] = if arm64 {
        &[
            ("src/asm/token_stealing_arm64.asm", "token_stealing"),
            ("src/asm/acl_edit_arm64.asm", "acl_edit"),
            ("src/asm/spawn_cmd_arm64.asm", "spawn_cmd"),
        ]
    } else {
        &[
            ("src/asm/token_stealing.asm", "token_stealing"),
            ("src/asm/acl_edit.asm", "acl_edit"),
            ("src/asm/spawn_cmd.asm", "spawn_cmd"),
            (
                "src/asm/token_stealing_shellcode_smep_no_kvashadow.asm",
                "token_stealing_shellcode_smep_no_kvashadow",
            ),
            (
                "src/asm/token_stealing_shellcode_smep_no_kvashadow_pte.asm",
                "token_stealing_shellcode_smep_no_kvashadow_pte",
            ),
        ]
    };

    // Declare every source before assembling any of them. Emitting this only for
    // the ones that assembled left a rejected file untracked, so editing it to
    // fix the error did not re-run the build script.
    for (source, _) in asm_files {
        println!("cargo:rerun-if-changed={}", source);
    }

    for (source, _) in asm_files {
        if !Path::new(source).exists() {
            eprintln!("[-] Assembly file not found: {}", source);
            println!("cargo:rustc-cfg=feature=\"shellcode_fallback\"");
            return;
        }
    }

    for (source, stem) in asm_files {
        let obj_file = format!("{}/{}.obj", out_dir, stem);

        let assembled = if arm64 {
            compile_asm_arm64(source, &obj_file, windows_version)
        } else {
            compile_asm_x64(source, &obj_file)
        };

        // One rejected source poisons the whole set: `shellcode.rs` reads the
        // objects or the fallback arrays, never a mix of the two.
        if !assembled {
            println!("cargo:rustc-cfg=feature=\"shellcode_fallback\"");
            return;
        }
    }
}

fn compile_asm_x64(asm_file: &str, obj_file: &str) -> bool {
    println!("[*] Starting to compile x64: {}", asm_file);

    let result = Command::new("ml64")
        .args(["/Fo", obj_file])
        .args(["/c", asm_file])
        .output();

    report("ml64", asm_file, result)
}

fn compile_asm_arm64(asm_file: &str, obj_file: &str, windows_version: &str) -> bool {
    println!(
        "[*] Starting to compile ARM64: {} (Windows {})",
        asm_file, windows_version
    );

    let result = Command::new("armasm64")
        .arg(asm_file)
        .arg(obj_file)
        .arg("-pd")
        .arg(format!("WINDOWS_VERSION SETS \"{}\"", windows_version))
        .output();

    report("armasm64", asm_file, result)
}

fn report(tool: &str, asm_file: &str, result: io::Result<Output>) -> bool {
    match result {
        // The assemblers write in the console's OEM code page, which is not
        // guaranteed to be UTF-8 -- a strict decode would panic the build over
        // nothing more than a message it was about to print.
        Ok(output) if output.status.success() => {
            println!(
                "[+] Successfully compiled {}: {}",
                asm_file,
                String::from_utf8_lossy(&output.stdout).trim()
            );
            true
        }
        Ok(output) => {
            // ml64 reports diagnostics on stdout, armasm64 on stderr. Reading
            // only stderr left an ml64 rejection with an empty reason.
            eprintln!(
                "[-] Failed to compile {}: {} {}",
                asm_file,
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
            false
        }
        Err(msg) => {
            eprintln!("[-] Error running {} for {}: {}", tool, asm_file, msg);
            false
        }
    }
}
