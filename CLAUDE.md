# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`win-kexp` is a Rust library (edition 2024) of utilities for Windows kernel exploitation research. It provides shellcode (token stealing, ACL editing, command spawning), process injection, ROP chain construction, kernel pool/win32k helpers, and Windows Debug Engine integration targeting Windows **x86_64** and **ARM64**.

The library is Windows-only by design: `src/lib.rs` exports every module (`dbgeng`, `pool`, `process`, `rop`, `shellcode`, `util`, `win32k`) unconditionally, and most modules call the `windows` crate APIs directly without `#[cfg]` gating. The crate is meant to be built for Windows targets; it is not designed to compile on other platforms. The only significant `#[cfg(target_os = "windows")]`/`target_arch` gating lives in `src/shellcode.rs`, where it selects between the assembled-object and hardcoded-fallback shellcode paths.

## Commands

```bash
# Build
cargo build --verbose

# Format check (required by CI)
cargo fmt --all -- --check

# Auto-format
cargo fmt --all

# Run tests (preferred — matches CI)
cargo nextest run --verbose

# Run a single test by name
cargo nextest run test_find_gadget_offset

# Standard test runner (alternative)
cargo test

# Build for ARM64 with specific Windows version (23H2 or 24H2, default 24H2)
WINDOWS_VERSION=23H2 cargo build --target aarch64-pc-windows-msvc
```

## Architecture

### Shellcode Compilation Pipeline

The most important architectural detail is the **dual-path shellcode system** controlled by `build.rs`:

1. **Primary path**: `build.rs` detects `ml64` (x86_64) or `armasm64` (ARM64) at build time and compiles the `.asm` files in `src/asm/` into `.obj` COFF files placed in `OUT_DIR`. At runtime `goblin` parses those COFF objects and `extract_shellcode_from_obj` pulls out the executable section bytes.
2. **Fallback path**: If no assembler is found (or assembly fails, a source file is missing, or an invalid `WINDOWS_VERSION` is requested on ARM64), `build.rs` emits `cargo:rustc-cfg=feature="shellcode_fallback"`, activating the `shellcode_fallback` feature flag. Hardcoded byte arrays are then returned directly.

`src/shellcode.rs` uses `#[cfg]` gates on `feature = "shellcode_fallback"` (and on `target_arch`) throughout. Each public `*_shellcode()` function has a primary and a fallback variant selected by these gates.

The test `test_shellcodes_match_fallback` (in `src/shellcode.rs`) verifies that both paths produce identical bytes — **this is the contract that must be maintained when modifying any assembly file**. If you change an `.asm` file, update the corresponding hardcoded fallback array in `src/shellcode.rs` so the test stays green.

The SMEP/KVAShadow token-stealing variants (`token_stealing_shellcode_smep_no_kvashadow`, `token_stealing_shellcode_smep_no_kvashadow_pte`) are **x86_64-only** — they have no ARM64 equivalent and are `#[cfg(target_arch = "x86_64")]` gated.

### ARM64 Version Targeting

ARM64 shellcode is version-specific. `build.rs` passes `-pd "WINDOWS_VERSION SETS \"<ver>\""` to `armasm64`, making the `WINDOWS_VERSION` preprocessor symbol available inside `.asm` files. Supported values: `23H2`, `24H2` (default `24H2`). An invalid version forces `shellcode_fallback`. See `TOKEN_STEALING_ARM64.md` for the ARM64 token-stealing walkthrough.

### Module Map

| Module | Purpose |
|---|---|
| `src/lib.rs` | Crate root; declares the public modules below |
| `src/shellcode.rs` | Shellcode loading/extraction; COFF parsing via `goblin`; hardcoded fallback byte arrays; the `test_shellcodes_match_fallback` contract test |
| `src/process.rs` | Process enumeration (`CreateToolhelp32Snapshot`), remote memory alloc, shellcode injection into a target process via `CreateRemoteThread` (`inject_shellcode_to_target_process`) |
| `src/rop.rs` | ROP chain macros (`create_rop_chain!`, `create_rop_chain_to_buffer!`, `concat_rop_chain_to_buffer!`); PE section parsing (`get_executable_sections`) and gadget search (`find_gadget_offset`) |
| `src/pool.rs` | Kernel pool/heap manipulation; `AnonymousPipe` RAII wrapper |
| `src/win32k.rs` | Win32k/kernel API wrappers: device handles, `IOCTL`/`CTL_CODE` macros, `io_device_control`, driver/`ntoskrnl` base resolution (`KernelError`), memory alloc/lock, function-address lookup |
| `src/dbgeng.rs` | Windows Debug Engine (DbgEng) integration — see below |
| `src/util.rs` | Misc helpers: `pause`, `debug_break`, `bytes_to_hex_string` |
| `src/asm/` | MASM (x86_64) and ARMASM (ARM64) shellcode source |
| `build.rs` | Conditional assembly compilation; assembler detection; fallback activation |

### Debug Engine (`src/dbgeng.rs`)

`DebugEngine` wraps the DbgEng COM interfaces (`IDebugClient6`, `IDebugControl4`, `IDebugDataSpaces4`, `IDebugSymbols3`). It can either create and own its own session (`DebugEngine::new` / `Default`, via `DebugCreate`) or borrow an existing WinDbg client (`from_windbg_client` / `from_client_interface`). The `owns_session` flag governs whether `Drop` ends the session — a borrowed WinDbg client is never torn down. Errors are modeled with `DbgEngError` (`thiserror`).

Key capabilities:
- **Kernel debugging**: `attach_local_kernel`, `attach_kernel(connection_string)`.
- **Live targets**: `launch_process` (launches with `DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE`), `attach_process(pid)`. `CREATE_NEW_CONSOLE` is deliberate — a console target must not inherit the host's stdout, which may be an MCP/JSON-RPC channel.
- **Post-mortem**: `open_dump(path)`, `open_trace(path)`.
- **Commands & events**: `execute_command`, `wait_for_event`, `execute_and_wait`; output is captured through `OutputCallbacks` (an `IDebugOutputCallbacks` impl).
- **Symbols/memory**: `set_symbol_path`, `reload_symbols`, `read_memory`, `registers`.
- **Breakpoints**: the `Breakpoint<'a>` RAII type (borrows the engine), plus `BreakpointCallback` and `DebugEventContextCallbacks` for event-driven breakpoint handling.

When touching this module, mind the `owns_session` invariant and the stdout-isolation rationale above — both are load-bearing and documented inline.

## Conventions

### Assembly
- x86_64: MASM syntax (`ml64`)
- ARM64: ARMASM syntax (`armasm64`) with the `WINDOWS_VERSION` preprocessor variable
- Changing an `.asm` file requires updating the matching fallback array in `src/shellcode.rs` (see the contract test above)

### Rust
- `snake_case` for functions/variables, `PascalCase` for types/structs
- Custom error types use `thiserror`; prefer `Result`/`Option` over panics in library code
- Windows API via the `windows` crate (currently `0.62`); add required feature flags in `Cargo.toml` under `[dependencies.windows]`
- `unsafe` is expected at Windows FFI boundaries; keep unsafe blocks minimal and localized
- Key dependencies: `windows`/`windows-core`/`windows-strings` (FFI), `goblin` (COFF/PE parsing), `thiserror` (errors), `byte-strings` (NUL-terminated literals), `hex`

### Git Commit Prefixes
`fix:`, `feat:`, `perf:`, `docs:`, `style:`, `refactor:`, `test:`, `chore:` — lowercase, concise summary line.

## CI

Three workflows run on **Windows runners only**:
- **ci.yml**: fmt check → build → `cargo nextest run` on both `windows-latest` (x64) and `windows-11-arm` (ARM64) with stable Rust
- **coverage.yml**: grcov + LLVM instrumentation → Codecov upload
- **miri.yml**: `cargo miri test` on nightly with `MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-ignore-leaks"`

CI uses `glslang/setup-masm@v1.2` to install MASM/ARMASM tooling, so assemblers are always available there. Local builds without assemblers silently activate `shellcode_fallback`.

## Related Docs

- `README.md` — user-facing overview, feature list, and shellcode reference
- `TOKEN_STEALING_ARM64.md` — ARM64 token-stealing shellcode walkthrough
- `.cursor/rules/*.mdc` — Cursor editor rules; they defer to this file for build commands and the module map
