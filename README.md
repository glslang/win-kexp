# dbgscope

[![Build Status](https://github.com/glslang/dbgscope/actions/workflows/ci.yml/badge.svg)](https://github.com/glslang/dbgscope/actions/workflows/ci.yml)
[![Miri](https://github.com/glslang/dbgscope/actions/workflows/miri.yml/badge.svg)](https://github.com/glslang/dbgscope/actions/workflows/miri.yml)
[![codecov](https://codecov.io/gh/glslang/dbgscope/branch/main/graph/badge.svg)](https://codecov.io/gh/glslang/dbgscope)
[![crates.io](https://img.shields.io/crates/v/dbgscope.svg)](https://crates.io/crates/dbgscope)
[![docs.rs](https://docs.rs/dbgscope/badge.svg)](https://docs.rs/dbgscope)
[![Dependency status](https://deps.rs/repo/github/glslang/dbgscope/status.svg)](https://deps.rs/repo/github/glslang/dbgscope)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Typed access to a WinDbg/DbgEng debug session from Rust, and kernel-pool and user-heap walkers
built on one. It opens a target — a live kernel over KD, a local kernel, a launched or attached
user-mode process, a crash dump, a TTD trace — and answers in **values** rather than in the text
`r`, `lm` and `bl` print, so a host does not parse a debugger's output to find out what the
machine is doing.

The organising idea is smaller than the API and worth stating first: **every answer carries what
the answering cost.** A pool walk against a live kernel is normally incomplete, a bounded command
may have been Ctrl+Broken at its deadline, and a four-byte pool tag has renderings that name no
particular tag. Each of those is reported as itself rather than passed off as a clean result —
see [Unknown, not absent](docs/unknown-not-absent.md).

## What it provides

- **Session drivers** for every target DbgEng opens: `attach_kernel`, `attach_local_kernel`,
  `launch_process`, `attach_process`, `open_dump`, `open_trace`, plus `connect` for an existing
  debugging server. `open_dump` and `open_trace` commit the session and leave the pump to the
  caller — the engine has no current process or thread until `wait_for_event` has run.
- **Two-step opening** on the four *live* openers, each a thin `x_begin()?.wait()`. `x_begin`
  does only the side effect that creates or claims the target and hands back a `PendingTarget`;
  `wait` completes the initial break. The split lets a caller tell "nothing happened, retry is
  clean" from "the target exists and only the wait failed" — opposite recoveries, since
  re-running the second spawns a second process or re-dials a live KD link.
- **Typed reads of session state**: `register_values` (a tagged `RegisterValue`, not a string),
  `register_descriptions`, `modules` / `unloaded_modules` / `module_at`, `module_pdb`,
  `stack_frames` carrying the module each frame belongs to, `bug_check` as fields, `breakpoints`,
  `disassemble` as `Instruction` records.
- **Bounded execution control.** `execute_command_bounded`, `execute_and_wait`, `settle` and
  `run_to_address` are waits with a condition-variable watchdog behind them. A break at the bound
  comes back as `Interruption::Deadline`, distinct from a host's own `Interruption::OnRequest`.
- **`InterruptHandle`** — a `Send + Sync` handle that Ctrl+Breaks an engine from another thread,
  built on `SetInterrupt`, the one DbgEng call documented as safe there.
- **Per-process teardown.** DbgEng holds several user-mode targets at once and `EndSession` takes
  one flag for the whole session, so provenance is tracked per pid: a process this engine
  *attached* to is detached individually before the session ends, or a passive end kills somebody
  else's service. A live kernel is resumed and actively detached, or it stays frozen at its last
  break. See [kernel teardown](docs/kernel-detach.md) for the quit path and its validation limits.
- **Scope save/restore** (`scope`, `set_scope`, `scope_guard`) for running a command that moves
  the debugger's scope — measured: `!analyze -v` discards a frame or `.ecxr` context the caller
  had selected — without the session ending up somewhere else. A `Scope` carries the target it
  was read from and is refused rather than applied to a later one.
- **Kernel pool walking** (`pool::query`): `find_tag`, `chunk_at` with neighbours, `tag_census`,
  `snapshot_report` — every answer paired with the coverage of the walk it came from.
- **User-mode Segment Heap walking** (`heap`): version-aware queries over the same page-segment,
  LFH, VS and backend decoding, because the two allocators are the same machinery either side of
  the ring boundary — nearly: `ntdll` and `nt` pack an LFH block bitmap differently. x64 and
  ARM64 processes, including x64 emulated on ARM64; a WoW64 process is refused.
- **A WinDbg extension**, `!dbgscope.poolmap`, over the same walker and the same caches, so the
  interactive and programmatic entry points cannot drift apart.

## The design rule

The usual Rust advice is to make illegal states unrepresentable, which assumes you know which
states are legal. A debugger reads a machine bigger than any one read of it, so the harder
problem is the inverse: **when the ground truth is genuinely unknowable, the type has to carry
its own incompleteness.** Three places where that shows up in the public API:

**Coverage.** Paged pool is partly on disk, and a page the memory manager has paged out cannot
be read through the debugger either. So an incomplete walk is the normal case, not a fault.
Those ranges come back as `sparse virtual range` diagnostics, the chunks inside them are absent
from the snapshot, and the report says which of three things happened:

```rust
pub enum WalkCoverage { Complete, BudgetExpired, Partial }
```

Not a `bool`, because the two ways of falling short need opposite responses: `BudgetExpired`
reaches more of the pool if given more time, `Partial` reports the same gaps however long it
runs. Running out of the wall-clock budget is therefore not an error — the walk returns what it
reached, with `coverage` saying so.

**Forced breaks.** A bounded command that was Ctrl+Broken at its deadline comes back as a
`CommandRun` whose `cut_short` is `Some(Interruption::Deadline { after_ms })`, **keeping the
output captured up to the break**. Not an `Err` — that would discard the output, which is the
whole reason to interrupt rather than end the session — and not a bare `String`, because a
search cut short prints the hits it reached and nothing to say there were more.

**Tags.** A pool tag is four bytes; its printed form is a lossy rendering, since every
unprintable byte becomes `.` and so does a literal `.`. The tag stays raw internally, and every
output site prints through `tag_label`, which shows the raw form wherever the rendering would
not survive being handed back.

The part that took the work is making that bearable — `PoolAnswer<T>` pairs an answer with its
walk so the two cannot come from different walks, `impl From<bool> for PoolWalk` leaves the
ordinary call site unchanged, and `WalkCoverage::complete()` is the one-word escape hatch.
[Unknown, not absent](docs/unknown-not-absent.md) is the long form, with the wrong answer each
simpler shape produced.

## Example

Open a dump and read its modules as values:

```rust
use dbgscope::dbgeng::DebugEngine;

let engine = DebugEngine::new();
engine.open_dump(r"C:\dumps\MEMORY.DMP")?;
// `open_dump` only commits the session. The engine has no current process or thread until
// it has been pumped, so every read below fails without this.
engine.wait_for_event(60_000)?;

for module in engine.modules()? {
    println!("{:#018x}  {:<24} {:?}", module.base, module.name, module.symbols);
}

if let Some(bug_check) = engine.bug_check()? {
    println!("bug check {:#x} {:x?}", bug_check.code, bug_check.parameters);
}
```

Run a command under a deadline, and report the deadline as one:

```rust
use dbgscope::dbgeng::Interruption;

let run = engine.execute_command_bounded("!process 0 f", 30_000)?;
print!("{}", run.output);          // real output either way
match run.cut_short {
    None => {}
    Some(Interruption::Deadline { after_ms }) =>
        eprintln!("cut short after {after_ms}ms — scope the command and retry"),
    Some(Interruption::OnRequest) => eprintln!("interrupted on request"),
}
if run.target_gone {
    eprintln!("the target is gone; retire this engine");
}
```

### Walking the pool

```rust
use dbgscope::pool::{query, tag_label};

// `false` converts into a PoolWalk meaning "reuse any snapshot cached for this target";
// `true` rebuilds. Either picks up DEFAULT_WALK_BUDGET.
let answer = query::find_tag(&engine, "Pipe", None, None, false)?;

for span in &answer.found {
    println!("{:#018x} {:>8} {}", span.usable_address, span.size, tag_label(span.raw_tag));
}

// The count and the coverage come from the same walk, by construction.
if !answer.walk.coverage.complete() {
    eprintln!(
        "{} spans is a floor, not a total ({:?}); {} diagnostics across {} shapes",
        answer.found.len(),
        answer.walk.coverage,
        answer.walk.diagnostics.emitted(),
        answer.walk.diagnostics.shapes().len(),
    );
}
```

Ask for a specific deadline instead of the default, and take the census:

```rust
use std::time::Duration;
use dbgscope::pool::query::{self, PoolWalk};

let census = query::tag_census(&engine, PoolWalk::refreshed().within(Duration::from_secs(30)))?;
for row in census.found.iter().take(20) {
    println!("{:<10} {:>8} allocations  {:>12} bytes", tag_label(row.raw_tag), row.allocations, row.total_bytes);
}
```

Read `answer.walk.diagnostics` by **shape** rather than by kept-line count: a live walk carries
thousands of messages, one stale list pointer or one paged-out region yields one message per
node, and `PoolDiagnostics` keeps eight verbatim examples per shape with the totals as numbers
beside them. `emitted()` describes the walk; `examples().len()` describes the struct, and on a
busy target the two differ by two orders of magnitude.

### Naming a tag

`find_tag` accepts one to four ASCII bytes (`"Tgsm"`), or the **raw form** — `0x` and the four
bytes as hex in memory order, so it reads in the same direction as the printed tag and as the
debugger's own output (`Tgsm` is `0x5467736d`, not `0x6d736754`).

```rust
use dbgscope::pool::{display_is_ambiguous, raw_tag_hex, tag_label};

let binary = u32::from_le_bytes([0x00, 0x01, 0x80, 0xff]);
let dots   = u32::from_le_bytes(*b"....");

// Both render as "....", so the rendering names neither of them.
assert!(display_is_ambiguous(binary) && display_is_ambiguous(dots));
assert_ne!(raw_tag_hex(binary), raw_tag_hex(dots));

// tag_label is what every output site prints: the readable form where it can be handed
// back, the raw form where it cannot.
assert_eq!(tag_label(u32::from_le_bytes(*b"Tgsm")), "Tgsm");
assert_eq!(tag_label(binary), "0x000180ff");
```

The two forms cannot collide, which is what makes accepting both safe rather than a guess: the
raw form is exactly ten characters and a printed tag is at most four, so `"0x2e"` is still the
ordinary four-byte tag `0x2e`.

## Requirements

- Windows x86_64 or Windows ARM64. The crate calls Windows APIs directly with no `#[cfg]`
  gating and is not designed to build elsewhere. Heap and pool walking both take x64 and ARM64
  targets.
- Rust 1.88 or later (let-chains, used in the pool walker); nightly for Miri.
- MSVC build tools.
- Optional: `cargo nextest` as the local test runner.

Symbols must be on the **debugger** host — PDBs are never fetched from a target over KD — and
resolving them at all needs `msdia140.dll` beside the engine (`symsrv.dll` finds a PDB, that one
parses it). Without it every module reports `Symbol Type: EXPORT - PDB not found`, and on a
kernel dump that presents not as missing symbols but as a memory read failing, since virtual
addresses are translated through structures the engine locates with `nt`'s symbols.

## The `!dbgscope.poolmap` extension

Building the library for the native x64 MSVC target produces both the rlib and
`target\debug\dbgscope.dll` — that is what `crate-type = ["rlib", "cdylib"]` is for:

```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --lib
```

Run that from an x64 MSVC Rust host. If an explicit `--target x86_64-pc-windows-msvc` is
supplied instead, the DLL lands in `target\x86_64-pc-windows-msvc\debug\` and the `.load` path
must use that target-qualified directory.

The walker assumes Windows 10 19H1 or later allocator algorithms and needs full private type
information for `nt`. Configure a symbol server, break in, and force-load kernel symbols first:

```text
.symfix
.reload /f nt
.load C:\path\to\dbgscope\target\debug\dbgscope.dll
!dbgscope.help
```

```text
!dbgscope.poolmap -tag Pipe
!dbgscope.poolmap -tag ABC -paged
!dbgscope.poolmap -tag Test -nonpaged -refresh
!dbgscope.poolmap -tag 0x5467736d
!dbgscope.poolmap ffff800012345678
```

`-tag` takes either tag form, and a tag only ever arrives through it: a bare positional
argument is always parsed as an address, so `!dbgscope.poolmap 0x5467736d` asks about that
address rather than about `Tgsm`. `-paged` and `-nonpaged` filter exact pool identities and
cannot be combined; the map retains nearby unrelated allocations and holes. An address argument
prints detail for the allocation or hole containing it. `-refresh` discards the cached snapshot
and walks again. Where WinDbg accepts DML, map cells have colours and clickable address links;
the same rows use ASCII glyphs and carry a legend when DML is stripped or the output is
captured as plain text.

"Snapshot" is literal: the extension examines current allocations, reusable frees, and
cached/delay-free spans while the target is stopped. It does not install allocation breakpoints
or reconstruct history. The cache is invalidated when execution resumes or the session changes.
A walk cut short — by Ctrl+C, by its budget or by a match threshold — is never cached; one that
reached the end of the pool is kept even where some of it would not read, because a page the
target has trimmed reads no better on the next walk, and on a live kernel some always are.

A walk is thousands of debugger reads plus every committed pool page, so over a live KDNET link
it can run for minutes. The extension lets it run to completion, because there is an operator at
a prompt who can Ctrl+Break. `pool::query` cannot assume anyone is watching the clock, so its
walks carry a wall-clock budget (`DEFAULT_WALK_BUDGET`, 120s), and a walk that runs out of it
returns what it reached rather than failing.

A host that *is* watching can stop one itself. `engine.interrupt_handle()` hands back a
`Send + Sync` handle whose `interrupt()` sets the same flag Ctrl+Break does, the walk polls it,
and the query comes back as `PoolQueryError::Interrupted` — a variant of its own, because an
interrupt somebody asked for is not a walk that failed. That is what makes
`PoolWalk::unbounded()` usable away from an interactive prompt.

Per-session paged heaps are outside the initial pool-map scope, and the command says so.

## Documentation

- [Unknown, not absent](docs/unknown-not-absent.md) — the long-form design guide: coverage,
  budgets, forced breaks, tag rendering, and what carrying incompleteness in the types costs.
- [API documentation on docs.rs](https://docs.rs/dbgscope) — built for the MSVC targets, since
  the crate does not compile on docs.rs' Linux default.
- [CHANGELOG.md](CHANGELOG.md) — what each release contains, and the standing limitations.
- `CLAUDE.md` / `AGENTS.md` — the load-bearing invariants, for anyone changing `dbgeng`.

## Layout

| Path | Purpose |
|---|---|
| `src/lib.rs` | Crate root; declares the four public modules. |
| `src/dbgeng.rs` | Sessions, execution control, breakpoints, symbols, modules, scopes, dumps, traces. |
| `src/pool.rs`, `src/pool/` | Kernel pool walking: `decode`, `index`, `layout`, `query`, `render`, `snapshot`. |
| `src/heap.rs` | Version-aware queries over user-mode Segment Heaps. |
| `src/allocator.rs` | Layout provenance and VS semantic families shared by both walkers. |
| `src/pool_extension.rs` | The `!dbgscope.poolmap` exports. |
| `examples/kdtest.rs` | Live-kernel exercise of the opener split over KDNET. |
| `examples/session_fuzz.rs` | Seeded randomised command sequences checking the session invariant after every step. |
| `examples/scope_restore.rs` | Re-validates scope save/restore against a dump. |
| `examples/split_open.rs` | Re-validates the two-step openers, including a guard dropped before the engine is pumped. |
| `examples/typed_context.rs` | Typed reads next to the debugger's own text for the same state. |
| `examples/user_heap_smoke.rs` | Launches a child, allocates across size regimes, walks its Segment Heap and checks it against the child's own `HeapWalk`. |
| `examples/heap_coverage.rs` | What, if anything, holds a user heap walk short of `Complete` — every gap it filed, against the memory manager's own record of what is behind it. |
| `examples/register_description.rs` | The full register description, not one flag of it. |

## Building

```bash
cargo build --verbose            # build for the active Windows target
cargo fmt --all -- --check       # the CI formatter gate
cargo nextest run --verbose      # preferred test runner
cargo test                       # fallback
cargo miri nextest run           # nightly unsafe-code check, as miri.yml runs it
cargo miri test --doc            # the doctests nextest cannot run
```

Run `examples/session_fuzz.rs` after touching anything in the wait/settle/guard seam. It is
seeded, so a failing sequence replays.

## Scope

This crate reads and drives a debug session; it does not exploit one. Everything here is
analysis — walking allocator metadata, resolving symbols, stepping a target. Corrupt or
unreadable allocator metadata is reported conservatively rather than treated as an exploitable
condition. The exploitation half — shellcode, ROP, process injection, win32k wrappers, pool
spraying — left for a separate crate, nothing here depends on it, and nothing here should grow
back toward it.

## CI

Windows runners only.

| Workflow | What it does |
|---|---|
| `ci.yml` | `cargo fmt --check`, `cargo build`, `cargo nextest run` on `windows-latest` (x64) and `windows-11-arm` (ARM64), stable. |
| `coverage.yml` | Instrumented build, LCOV via `grcov`, upload to Codecov. |
| `miri.yml` | `cargo miri nextest run` on nightly plus `cargo miri test --doc`. **Not on pull requests** — it is the longest job by a wide margin, so it runs on merge to `main`, weekly for toolchain drift, and on `workflow_dispatch`. A green PR says nothing about Miri; run it by hand when a change is one Miri would have something to say about. |

## Contributing

`rustfmt` defaults, small and localised `unsafe` blocks at the FFI boundary, focused
`#[cfg(test)]` tests next to the code (`test_*`). Commit subjects use lowercase prefixes:
`fix:`, `feat:`, `perf:`, `docs:`, `style:`, `refactor:`, `test:`, `chore:`.

When a change makes an answer less complete than it looks, say so in the type. That is the one
rule this crate has.

## License

MIT — see [LICENSE](LICENSE).
