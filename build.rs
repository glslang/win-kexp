use std::process::Command;

fn main() {
    #[cfg(target_os = "windows")]
    compile_asm();
}

#[cfg(target_os = "windows")]
fn compile_asm() {
    let asm_file = "src/token_stealing.asm";
    let obj_file = "src/token_stealing.obj";

    let status = Command::new("ml64")
        .args(["/Fo", obj_file])
        .args(["/c", asm_file])
        .env("PATH", std::env::var("PATH").unwrap())
        .output();

    match status {
        Ok(output) => {
            if output.status.success() {
                let out = String::from_utf8(output.stdout).unwrap();
                println!("[+] {out}");
                println!("cargo:rerun-if-changed={}", asm_file);
            } else {
                let err = String::from_utf8(output.stderr).unwrap();
                eprintln!("[-] {err}");
            }
        }
        Err(msg) => eprintln!("[-] Ignoring assembly files ({msg})."),
    }
}
