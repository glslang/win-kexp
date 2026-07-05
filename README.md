# win-kexp ![Build Status](https://github.com/glslang/win-kexp/actions/workflows/ci.yml/badge.svg) [![codecov](https://codecov.io/gh/glslang/win-kexp/branch/main/graph/badge.svg)](https://codecov.io/gh/glslang/win-kexp) [![Dependency status](https://deps.rs/repo/github/glslang/win-kexp/status.svg)](https://deps.rs/repo/github/glslang/win-kexp)

`win-kexp` is a Rust 2024 library for Windows kernel exploitation research. It collects shellcode helpers, process injection utilities, ROP-chain tooling, kernel pool helpers, Win32k wrappers, and Windows Debug Engine integration for controlled x86_64 and ARM64 lab environments.

## Safety Scope

This repository is intended for exploit research in isolated Windows test systems. Do not run the examples or payloads against systems you do not own or have explicit permission to test.

## Features

- **Shellcode**: token stealing, ACL editing, and `cmd.exe` spawning payloads.
- **Assembly fallback**: MASM/ARMASM-built shellcode when assemblers are available, hardcoded byte arrays otherwise.
- **Process utilities**: process lookup, remote allocation, shellcode writes, and `CreateRemoteThread` launch.
- **ROP helpers**: chain-writing macros and executable PE section scanning for gadget lookup.
- **Kernel tooling**: pool helpers, Win32k/device I/O wrappers, and driver base discovery.
- **Debug engine**: `dbgeng` wrappers for local/kernel attach, command execution, breakpoints, symbols, dumps, traces, and session cleanup.

## Requirements

- Windows x86_64 or Windows ARM64.
- Rust stable for normal builds and nightly for Miri.
- MSVC build tools.
- Optional assembler: `ml64` for x86_64 or `armasm64` for ARM64.
- Optional local test runner: `cargo nextest`.

The crate is Windows-only in practice because public modules call Windows APIs directly. CI installs assemblers with [`glslang/setup-masm`](https://github.com/glslang/setup-masm). Local builds without an assembler silently enable the `shellcode_fallback` cfg path.

## Build and Test

```bash
# Build for the active Windows target.
cargo build --verbose

# Build ARM64 shellcode for Windows 23H2. Default is 24H2.
WINDOWS_VERSION=23H2 cargo build --target aarch64-pc-windows-msvc

# Match the CI formatter gate.
cargo fmt --all -- --check

# Preferred test runner.
cargo nextest run --verbose

# Fallback test runner.
cargo test

# Nightly unsafe-code check used by CI.
cargo miri test --verbose
```

Supported ARM64 shellcode versions are `23H2` and `24H2`; unset `WINDOWS_VERSION` defaults to `24H2`.

## Modules

| Module | Purpose |
|---|---|
| `shellcode` | Payload loaders and fallback byte arrays. |
| `process` | Target process discovery and remote shellcode execution. |
| `rop` | ROP macros plus PE executable-section and gadget search helpers. |
| `pool` | Anonymous pipe helpers for kernel pool shaping experiments. |
| `win32k` | Device handles, IOCTL helpers, allocation helpers, and kernel driver lookup. |
| `dbgeng` | Windows Debug Engine sessions, commands, breakpoints, symbols, dumps, and traces. |
| `util` | Pause, debug break, and byte-formatting helpers. |

## Shellcode Pipeline

Assembly sources live in `src/asm/`. On Windows, `build.rs` checks for the target assembler:

- If found, `.asm` files are compiled into COFF `.obj` files and `goblin` extracts executable bytes.
- If missing, `cargo:rustc-cfg=feature="shellcode_fallback"` is emitted and the matching byte arrays in `src/shellcode.rs` are used.

`test_shellcodes_match_fallback` verifies that assembled payloads and fallback bytes match. When changing `src/asm/`, update the corresponding fallback byte array in `src/shellcode.rs`.

Available payloads:

| Function | Architectures | Description |
|---|---:|---|
| `token_stealing_shellcode()` | x86_64, ARM64 | Copies the SYSTEM token to the current process. |
| `acl_edit_shellcode()` | x86_64, ARM64 | Edits the current process ACL. |
| `spawn_cmd_shellcode()` | x86_64, ARM64 | Resolves `CreateProcessA` and spawns `cmd.exe`. |
| `token_stealing_shellcode_smep_no_kvashadow()` | x86_64 | Token stealing with SMEP bypass. |
| `token_stealing_shellcode_smep_no_kvashadow_pte()` | x86_64 | Token stealing with PTE-based SMEP bypass. |

## Usage Sketches

```rust
use win_kexp::process::inject_shellcode_to_target_process;
use win_kexp::shellcode::token_stealing_shellcode;

let shellcode = token_stealing_shellcode();
let pid = inject_shellcode_to_target_process("target.exe", &shellcode);
println!("started remote thread in pid {pid}");
```

```rust
use win_kexp::rop::{find_gadget_offset, get_executable_sections};

let sections = get_executable_sections(ntoskrnl_module)?;
let pop_rax_ret = find_gadget_offset(&sections, &[0x58, 0xC3], ntoskrnl_base);
```

For a debugger smoke test, see `examples/kdtest.rs`:

```bash
cargo run --example kdtest -- "net:port=50000,key=w.x.y.z"
```

## CI

The repository uses Windows-only GitHub Actions workflows:

| Workflow | What it does |
|---|---|
| `ci.yml` | Runs `cargo fmt --all -- --check`, `cargo build --verbose`, and `cargo nextest run --verbose` on `windows-latest` and `windows-11-arm`. |
| `coverage.yml` | Runs instrumented `cargo test`, generates LCOV with `grcov`, and uploads to Codecov. |
| `miri.yml` | Runs `cargo miri test --verbose` on nightly with `-Zmiri-disable-isolation -Zmiri-ignore-leaks`. |

## Contributing

Use `rustfmt` defaults and keep unsafe Windows FFI blocks small. Add focused unit tests next to the code under `#[cfg(test)]`; existing test names use `test_*`. Commit subjects use lowercase prefixes such as `fix:`, `feat:`, `docs:`, `style:`, `refactor:`, `test:`, `perf:`, and `chore:`.
