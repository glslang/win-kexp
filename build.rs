use std::process::Command;

fn main() {
    #[cfg(target_os = "windows")]
    {
        for file in &[
            "src/asm/token_stealing.asm",
            "src/asm/acl_edit.asm",
            "src/asm/spawn_cmd.asm",
        ] {
            if !std::path::Path::new(file).exists() {
                eprintln!("[-] Assembly file not found: {}", file);
            }
        }

        compile_asm("src/asm/token_stealing.asm", "src/asm/token_stealing.obj");
        compile_asm("src/asm/acl_edit.asm", "src/asm/acl_edit.obj");
        compile_asm("src/asm/spawn_cmd.asm", "src/asm/spawn_cmd.obj");
    }
}

#[cfg(target_os = "windows")]
fn compile_asm(asm_file: &str, obj_file: &str) {
    println!("[*] Starting to compile: {}", asm_file);

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
            }
        }
        Err(msg) => eprintln!("[-] Error running ml64 for {}: {}", asm_file, msg),
    }
}
