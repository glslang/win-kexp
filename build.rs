use std::process::Command;

fn main() {
    #[cfg(target_os = "windows")]
    {
        let ml64_available = if cfg!(target_arch = "aarch64") {
            false
        } else {
            Command::new("ml64")
                .arg("/?")
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        };

        let armasm64_available = if cfg!(target_arch = "x86_64") {
            false
        } else {
            Command::new("armasm64")
                .arg("-help")
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        };

        if ml64_available || armasm64_available {
            println!("[+] Assembler found, compiling assembly files");
            compile_asm_files();
        } else {
            println!("[-] No assembler found, using fallback shellcode");
            println!("cargo:rustc-cfg=feature=\"shellcode_fallback\"");
        }
    }
}

#[cfg(target_os = "windows")]
fn compile_asm_files() {
    #[cfg(target_arch = "x86_64")]
    let asm_files = [
        "src/asm/token_stealing.asm",
        "src/asm/acl_edit.asm",
        "src/asm/spawn_cmd.asm",
    ];

    #[cfg(target_arch = "aarch64")]
    let asm_files = [
        "src/asm/token_stealing_arm64.asm",
        "src/asm/acl_edit_arm64.asm",
        "src/asm/spawn_cmd_arm64.asm",
    ];

    for file in &asm_files {
        if !std::path::Path::new(file).exists() {
            eprintln!("[-] Assembly file not found: {}", file);
            println!("cargo:rustc-cfg=feature=\"shellcode_fallback\"");
            return;
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        compile_asm_x64("src/asm/token_stealing.asm", "src/asm/token_stealing.obj");
        compile_asm_x64("src/asm/acl_edit.asm", "src/asm/acl_edit.obj");
        compile_asm_x64("src/asm/spawn_cmd.asm", "src/asm/spawn_cmd.obj");
    }

    #[cfg(target_arch = "aarch64")]
    {
        compile_asm_arm64(
            "src/asm/token_stealing_arm64.asm",
            "src/asm/token_stealing.obj",
        );
        compile_asm_arm64("src/asm/acl_edit_arm64.asm", "src/asm/acl_edit.obj");
        compile_asm_arm64("src/asm/spawn_cmd_arm64.asm", "src/asm/spawn_cmd.obj");
    }
}

#[cfg(target_os = "windows")]
#[cfg(target_arch = "x86_64")]
fn compile_asm_x64(asm_file: &str, obj_file: &str) {
    println!("[*] Starting to compile x64: {}", asm_file);

    let status = Command::new("ml64")
        .args(["/Fo", obj_file])
        .args(["/c", asm_file])
        .env("PATH", std::env::var("PATH").unwrap())
        .output();

    match status {
        Ok(output) => {
            if output.status.success() {
                let out = String::from_utf8(output.stdout).unwrap();
                println!("[+] Successfully compiled {}: {}", asm_file, out);
                println!("cargo:rerun-if-changed={}", asm_file);
            } else {
                let err = String::from_utf8(output.stderr).unwrap();
                eprintln!("[-] Failed to compile {}: {}", asm_file, err);
                println!("cargo:rustc-cfg=feature=\"shellcode_fallback\"");
            }
        }
        Err(msg) => {
            eprintln!("[-] Error running ml64 for {}: {}", asm_file, msg);
            println!("cargo:rustc-cfg=feature=\"shellcode_fallback\"");
        }
    }
}

#[cfg(target_os = "windows")]
#[cfg(target_arch = "aarch64")]
fn compile_asm_arm64(asm_file: &str, obj_file: &str) {
    println!("[*] Starting to compile ARM64: {}", asm_file);

    let status = Command::new("armasm64")
        .arg(asm_file)
        .arg(obj_file)
        .env("PATH", std::env::var("PATH").unwrap())
        .output();

    match status {
        Ok(output) => {
            if output.status.success() {
                let out = String::from_utf8(output.stdout).unwrap();
                println!("[+] Successfully compiled {}: {}", asm_file, out);
                println!("cargo:rerun-if-changed={}", asm_file);
            } else {
                let err = String::from_utf8(output.stderr).unwrap();
                eprintln!("[-] Failed to compile {}: {}", asm_file, err);
                println!("cargo:rustc-cfg=feature=\"shellcode_fallback\"");
            }
        }
        Err(msg) => {
            eprintln!("[-] Error running armasm64 for {}: {}", asm_file, msg);
            println!("cargo:rustc-cfg=feature=\"shellcode_fallback\"");
        }
    }
}
