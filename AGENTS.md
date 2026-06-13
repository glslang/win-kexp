# Repository Guidelines

## Project Structure & Module Organization

This is a Rust 2024 library for Windows kernel exploitation research. Public modules live in `src/`: `shellcode.rs`, `process.rs`, `rop.rs`, `pool.rs`, `win32k.rs`, `dbgeng.rs`, and `util.rs`, all exported by `src/lib.rs`. Assembly payloads are in `src/asm/` and are compiled conditionally by `build.rs`. Repository docs include `README.md`, `CLAUDE.md`, and `TOKEN_STEALING_ARM64.md`.

The crate is Windows-only in practice: most modules use the `windows` crate directly and are not broadly `cfg`-gated for non-Windows hosts.

## Build, Test, and Development Commands

- `cargo build --verbose`: build the library for the active Windows target.
- `WINDOWS_VERSION=23H2 cargo build --target aarch64-pc-windows-msvc`: build ARM64 shellcode for Windows 23H2. Supported values are `23H2` and `24H2`; default is `24H2`.
- `cargo fmt --all -- --check`: verify formatting, matching CI.
- `cargo fmt --all`: apply Rust formatting.
- `cargo nextest run --verbose`: preferred test runner and CI path.
- `cargo test`: standard fallback test runner.
- `cargo miri test --verbose`: nightly/Miri check used by CI for unsafe-code issues.

Local builds use `ml64` for x86_64 or `armasm64` for ARM64 when available. Without assemblers, `build.rs` silently enables the shellcode fallback path.

## Coding Style & Naming Conventions

Use `rustfmt` defaults. Prefer `snake_case` for functions and variables, `PascalCase` for types, and concise module-level APIs. Model library failures with `Result`/`Option` and `thiserror` instead of panics. Keep `unsafe` blocks small, localized, and tied directly to Windows FFI calls. When adding Windows APIs, update the feature list under `[dependencies.windows]` in `Cargo.toml`.

Assembly uses MASM syntax for x86_64 and ARMASM syntax for ARM64.

## Testing Guidelines

Place focused unit tests in the module being tested under `#[cfg(test)]`. Existing test names use `test_*`, for example `test_find_gadget_offset`. If you change any file in `src/asm/`, update the matching fallback byte array in `src/shellcode.rs`; `test_shellcodes_match_fallback` enforces byte-for-byte equivalence.

## Commit & Pull Request Guidelines

Commit subjects use lowercase prefixes seen in history, such as `fix:`, `feat:`, `docs:`, `style:`, `refactor:`, `test:`, `perf:`, and `chore:`. Keep the summary imperative and specific.

Pull requests should describe the behavioral change, call out architecture or shellcode-impacting changes, link related issues when applicable, and include the commands run. Ensure formatting and relevant Windows tests pass before requesting review.

## Security & Configuration Notes

This repository contains exploit-research utilities. Keep examples scoped to controlled research environments, avoid committing generated build artifacts or local debugger state, and document any new environment variables alongside the command that consumes them.
