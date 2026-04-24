# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`win-kexp` is a Rust library of utilities for Windows kernel exploitation. It provides shellcode (token stealing, ACL editing, command spawning), process injection, ROP chain construction, and kernel debug engine integration targeting Windows x86_64 and ARM64.

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

1. **Primary path**: `build.rs` detects `ml64` (x86_64) or `armasm64` (ARM64) at build time and compiles `.asm` files in `src/asm/` into `.obj` COFF files placed in `OUT_DIR`.
2. **Fallback path**: If no assembler is found, `build.rs` emits `cargo:rustc-cfg=feature="shellcode_fallback"`, activating the `shellcode_fallback` feature flag.

`src/shellcode.rs` uses `#[cfg]` gates on `feature = "shellcode_fallback"` throughout. When the assembler path is used, `goblin` parses the COFF `.obj` files and extracts executable sections at runtime. When fallback is active, hardcoded byte arrays are returned directly.

The CI test `test_shellcodes_match_fallback` verifies that both paths produce identical bytes — this is the contract that must be maintained when modifying assembly files.

### ARM64 Version Targeting

ARM64 shellcode is version-specific. `build.rs` passes `-pd "WINDOWS_VERSION SETS \"<ver>\""` to `armasm64`, making the `WINDOWS_VERSION` preprocessor symbol available inside `.asm` files. Supported values: `23H2`, `24H2`. An invalid version forces `shellcode_fallback`.

### Module Map

| Module | Purpose |
|---|---|
| `src/shellcode.rs` | Shellcode loading/extraction; fallback byte arrays |
| `src/process.rs` | Process enumeration, remote memory alloc, shellcode injection via `CreateRemoteThread` |
| `src/rop.rs` | ROP chain macros (`create_rop_chain!`, `create_rop_chain_to_buffer!`, `concat_rop_chain_to_buffer!`); PE section parsing for gadget search |
| `src/pool.rs` | Kernel pool/heap manipulation |
| `src/win32k.rs` | Win32k kernel API wrappers |
| `src/dbgeng.rs` | Windows Debug Engine integration |
| `src/util.rs` | Misc helpers (pause, debug break, hex utilities) |
| `src/asm/` | MASM (x86_64) and ARMASM (ARM64) source files |
| `build.rs` | Conditional assembly compilation; assembler detection |

## Conventions

### Assembly
- x86_64: MASM syntax (`ml64`)
- ARM64: ARMASM syntax (`armasm64`) with `WINDOWS_VERSION` preprocessor variable

### Rust
- snake_case for functions/variables, PascalCase for types/structs
- Custom error types use `thiserror`; prefer `Result`/`Option` over panics in library code
- Windows API via the `windows` crate; add required feature flags in `Cargo.toml` under `[dependencies.windows]`
- `unsafe` is expected at Windows FFI boundaries; keep unsafe blocks minimal and localized

### Git Commit Prefixes
`fix:`, `feat:`, `perf:`, `docs:`, `style:`, `refactor:`, `test:`, `chore:` — lowercase, concise summary line.

## CI

Three workflows run on Windows runners only:
- **ci.yml**: fmt check → build → `cargo nextest run` on both `windows-latest` (x64) and `windows-11-arm` (ARM64) with stable Rust
- **coverage.yml**: grcov + llvm instrumentation → Codecov upload
- **miri.yml**: `cargo miri test` on nightly with `MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-ignore-leaks"`

The CI uses `glslang/setup-masm@v1.2` to install MASM/ARMASM tooling, so assemblers are always available there. Local builds without assemblers will silently activate `shellcode_fallback`.
