# win-kexp ![Build Status](https://github.com/glslang/win-kexp/actions/workflows/ci.yml/badge.svg) [![codecov](https://codecov.io/gh/glslang/win-kexp/branch/main/graph/badge.svg)](https://codecov.io/gh/glslang/win-kexp) [![Dependency status](https://deps.rs/repo/github/glslang/win-kexp/status.svg)](https://deps.rs/repo/github/glslang/win-kexp)

A Rust library of utilities for Windows kernel exploitation research. Provides ready-to-use shellcode, process injection, ROP chain construction, and kernel debug engine integration targeting Windows x86\_64 and ARM64.

## Features

- **Shellcode**: Token stealing, ACL editing, and `cmd.exe` spawning — available as compiled MASM/ARMASM or hardcoded fallback byte arrays
- **Process injection**: Remote memory allocation and shellcode injection via `CreateRemoteThread`
- **ROP chains**: Macros for building and writing ROP chains, plus PE section parsing for gadget search
- **Kernel pool**: Kernel pool/heap manipulation helpers
- **Win32k**: Win32k kernel API wrappers
- **Debug engine**: Windows Debug Engine (`dbgeng`) integration

## Requirements

- Windows (x86\_64 or ARM64)
- Rust stable toolchain
- `ml64` (x86\_64) or `armasm64` (ARM64) for compiling assembly — without them the library automatically falls back to hardcoded byte arrays

CI installs assemblers via [`glslang/setup-masm`](https://github.com/glslang/setup-masm). For local builds without assemblers, `shellcode_fallback` is activated silently.

## Building

```bash
# Standard build
cargo build --verbose

# ARM64 targeting Windows 23H2 (default is 24H2)
WINDOWS_VERSION=23H2 cargo build --target aarch64-pc-windows-msvc

# Check formatting (required by CI)
cargo fmt --all -- --check

# Run tests
cargo nextest run --verbose
```

## Modules

| Module | Description |
|---|---|
| `shellcode` | Shellcode loading and extraction; fallback byte arrays for assembler-free builds |
| `process` | Process enumeration, remote memory allocation, shellcode injection via `CreateRemoteThread` |
| `rop` | `create_rop_chain!`, `create_rop_chain_to_buffer!`, `concat_rop_chain_to_buffer!` macros; PE section parsing for gadget search |
| `pool` | Kernel pool/heap manipulation |
| `win32k` | Win32k kernel API wrappers |
| `dbgeng` | Windows Debug Engine integration |
| `util` | Miscellaneous helpers (pause, debug break, hex utilities) |

## Shellcode

Three shellcodes are provided for x86\_64 and ARM64:

| Shellcode | Description |
|---|---|
| `token_stealing_shellcode()` | Walks the EPROCESS list and copies the SYSTEM token to the current process |
| `acl_edit_shellcode()` | Edits the ACL of the current process to grant full access |
| `spawn_cmd_shellcode()` | Locates `kernel32` in the PEB and calls `CreateProcessA` to spawn `cmd.exe` |

x86\_64 also includes SMEP bypass variants:

| Shellcode | Description |
|---|---|
| `token_stealing_shellcode_smep_no_kvashadow()` | Token steal with SMEP bypass (no KVAS) |
| `token_stealing_shellcode_smep_no_kvashadow_pte()` | Token steal with SMEP bypass via PTE manipulation |

### Dual-path shellcode system

`build.rs` detects `ml64` (x86\_64) or `armasm64` (ARM64) at build time:

- **Assembler present**: `.asm` files in `src/asm/` are compiled to COFF `.obj` files; at runtime `goblin` extracts the executable section bytes.
- **No assembler**: `cargo:rustc-cfg=feature="shellcode_fallback"` is emitted and hardcoded byte arrays are returned directly.

The CI test `test_shellcodes_match_fallback` enforces that both paths produce identical bytes.

### ARM64 version targeting

ARM64 shellcode is Windows-version-specific. Set `WINDOWS_VERSION` to `23H2` or `24H2` (default `24H2`) before building:

```bash
WINDOWS_VERSION=23H2 cargo build --target aarch64-pc-windows-msvc
```

## Usage

```rust
use win_kexp::shellcode::token_stealing_shellcode;
use win_kexp::process::inject_shellcode_to_target_process;
use win_kexp::rop::{find_gadget_offset, get_executable_sections};

// Inject token-stealing shellcode into a target process
let shellcode = token_stealing_shellcode();
let pid = inject_shellcode_to_target_process("target.exe", &shellcode);

// Find a ROP gadget (pop rax; ret) in ntoskrnl
let sections = get_executable_sections(ntoskrnl_module)?;
let gadget = find_gadget_offset(&sections, &[0x58, 0xC3], ntoskrnl_base);
```

## CI

Three workflows run on Windows runners only:

| Workflow | Steps |
|---|---|
| `ci.yml` | fmt check → build → `cargo nextest run` on `windows-latest` (x64) and `windows-11-arm` (ARM64) |
| `coverage.yml` | grcov + llvm instrumentation → Codecov upload |
| `miri.yml` | `cargo miri test` on nightly (`MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-ignore-leaks"`) |
