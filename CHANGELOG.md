# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **A breakpoint callback decides whether the target stops.** `BreakpointCallback` returns a
  `BreakpointAction` -- `Default`, `Go` or `Break`, the `DEBUG_STATUS_*` an
  `IDebugEventContextCallbacks::Breakpoint` answers with -- where it returned
  `windows::core::Result<()>`. That type could not say it: the engine reads the status out of the
  callback's `HRESULT`, every status is a success code, and a `Result`'s `Ok` reaches the engine as
  `S_OK`, which is `DEBUG_STATUS_NO_CHANGE`; the dispatch discarded what the callback returned
  besides. So a callback could watch a breakpoint but never let one go past. **Breaking** for a caller
  that implements one; nothing in this crate or in `windbg-mcp` does.

  The status leaves through one function, `event_status`, as an `Err` carrying the code, because
  `windows` gives an implementer no other way to return a success `HRESULT`: `From<Result<T>> for
  HRESULT` passes the code through unchanged. That is pinned by
  `test_a_breakpoint_action_reaches_the_engine_as_its_status`, which fails against an
  `event_status` that answers `Ok(())` (mutated and run on ARM64). Upstream:
  microsoft/win32metadata#2075.

  Two hazards in the same dispatch went with it: a callback that **panics** now answers `Default`
  rather than unwinding into `dbgeng.dll`, which aborts the process, and a null breakpoint is no
  longer `unwrap`ped. `set_breakpoint_event_callbacks` returns `Result<(), DbgEngError>` rather
  than panicking, and `clear_breakpoint_event_callbacks` unregisters them.

  `examples/breakpoint_status_probe.rs` is the measurement against a real engine, user-mode and
  live kernel over serial: `Default` stops exactly as no callback does, `Go` lets every hit through
  and stops on the one answered `Break`, the callback can read the engine from inside the hit, and a
  hit costs one trap however it is let through.

- **CI's ARM64 entry names an image rather than the moving `windows-11-arm` label**, and the
  architecture is a matrix value rather than that label matched a second time. Both entries here
  drive a real engine — 46 of this crate's non-ignored tests reach `DebugCreate`, and several
  launch or attach to a live process — so a run is a reading of that runner image's inbox
  `dbgeng.dll`. A label is not that: GitHub migrated `windows-11-arm` onto the Visual Studio 2026
  ARM64 image on 2026-09-23, and this workflow's own runs report `Image: windows-11-arm64` on
  2026-09-22T19:45Z against `windows-11-vs2026-arm64`, `Version: 20260920.164.1` on run
  36040398859 — a different OS build and therefore a different engine, under an unchanged
  workflow and with nothing printed to say so. The entry is `windows-11-vs2026-arm` now, and a
  step records which image answered.

  **The hazard was in the step that reads the label, not in the label.** `vs-architecture` was
  `${{ matrix.os == 'windows-11-arm' && 'arm64' || 'x64' }}`, so renaming the runner without
  touching it would have selected the **x64** toolchain on an ARM64 machine — wrong, and green.
  `arch` is now stated per entry through an `include` that adds a key to an existing combination
  rather than creating new ones, and the job name is `build (<arch>, <toolchain>)`, which no
  image migration can move. Nothing was stranded by the rename: the repository ruleset protects
  deletion, non-fast-forward and linear history and requires **no status check contexts**, which
  was read rather than assumed.

  Sibling to `windbg-mcp`'s `FOLLOWUPS.md` item 32, which was the same migration met by a repo
  that had run the two labels side by side through it. This one had not, so the migration landed
  here unobserved — which is the argument for the recording step.

### Added

- **`Instruction::privilege`: which family a privileged instruction reaches** (#153) — an I/O
  port, a model-specific register, a control or debug register, a descriptor table, the interrupt
  mask, a cache or TLB, hardware virtualisation, or `Privilege::Other` for the rest. It is `Some`
  exactly when `privileged` is `true`, and that is how both are built rather than a property to
  hope for: each decoder produces the family and `privileged` is whether there is one. So a
  privileged instruction no family names is `Other`, with its mnemonic beside it, rather than
  absent.

  **From the decoder rather than from a table of mnemonics**, for the reason `privileged` is.
  #151 took membership out of `windbg-mcp`'s `driver_hazards`, and the family stayed behind as a
  per-architecture list — the next architecture would have needed one of its own, and x86's `str`
  and A64's `str` already collide. On x86 the family is read from iced: its CPUID features for the
  VMX, SVM, SEV-SNP and TDX families and for the MSR instructions; the registers an instruction
  uses, which is how `clts` and `lmsw` are control-register writes by a `cr0` neither names; and
  the flags it **sets or clears**, which keeps `sysret`, `rsm` and `erets` — which *write* `IF`,
  restoring every flag at once — out of the interrupt-mask family. Port I/O, the descriptor-table
  loads and cache or TLB maintenance have no such signal and are matched on iced's typed
  `Mnemonic`, as is `xsetbv`, whose `XCR0` iced does not model. Measured
  over iced 1.21's whole table: of the 156 encodings it calls privileged, the 132 that decode
  without a decoder option each answer exactly one family, except `skinit`, which clears `IF` and
  is placed by its SVM feature.

  On A64 it is the encoding. A system register is a control register unless it is `DAIF` or
  `ALLINT` — the interrupt masks, by either encoding — or lies in the IMPLEMENTATION DEFINED space,
  `op0` 3 with `CRn` 11 or 15, which is A64's model-specific registers (none of the 1,118
  registers `disarm64`'s generated table names is there). `dc`, `ic` and `tlbi` are cache or TLB
  maintenance; `hvc` and `smc` are virtualisation; `eret`, `at` and the rest of the `sys` space are
  `Other`. Over the executable sections of the 26100 ARM64 `ntoskrnl.exe`, 2,084 of 2,448,790
  words are privileged: 956 interrupt-mask, 841 control-register, 206 cache or TLB, 41
  virtualisation and 40 other — 32 of those the `cfp`/`dvp`/`cpp rctx` speculation restrictions —
  and no model-specific register access at all.

  It is not a severity, and not membership: `sgdt` reads the descriptor table from user mode,
  needs no privilege, and answers `None`. A consumer that reports it anyway is making its own call.

- **`DebugEngine::debuggee_type` and `DebugEngine::dump_files`** — the two engine queries that
  answer *what is this engine holding right now*, rather than what the opener asked for.
  `debuggee_type` is `GetDebuggeeType`'s `(class, qualifier)` pair as a `DebuggeeType`, with
  `is_kernel` and `is_live_kernel` over it; `dump_files` is `GetNumberDumpFiles` plus
  `GetDumpFileWide`, the files the session is open on, in the engine's order.

  **Both were already here and neither was reachable.** `is_kernel_target` read the pair and threw
  the qualifier away, and `is_live_kernel` read it again privately — so a caller could learn that a
  target was a kernel one and had no way to learn whether it was a live link or a dump. It now goes
  through `debuggee_type` like everything else, which is one read of `GetDebuggeeType` in the crate
  instead of three.

  **What they are for is a question no other query here answers: has the target been swapped?**
  `target_identity` reads as though it would, and does not — it is a generation *this crate* hands
  out at its own openers and teardowns, so a `.opendump` typed straight at the engine, or reached
  through a `.if` or an alias, leaves it exactly where it was. These two are read off the engine on
  every call, so a caller can take a reading when it opens a target and compare it after each
  command. `dump_files` returns an error rather than an empty list where the engine will not
  answer, for that reason: a failure folded into "no dump files" matches every live target, and
  would report a swapped target as an unchanged one.

  **`dump_files` refuses an engine with no debuggee**, and that guard was measured rather than
  anticipated: `GetNumberDumpFiles` on one is a `STATUS_ACCESS_VIOLATION` *inside* DbgEng — a
  structured exception `catch_unwind` cannot trap, so it takes the calling process down instead
  of failing the call. It killed `windbg-mcp`'s engine worker on the first run of the tier that
  exercises it, as a launched program running to completion. `debuggee_type` in the same state
  answers `DEBUG_CLASS_UNINITIALIZED` perfectly happily, which is how two queries sitting beside
  each other come to be asked in one place. `examples/held_target_probe.rs` is the record: it
  prints both, plus `has_target` and the process id, for a fresh engine, a launched process, that
  process once it has exited, and a dump either side of its load wait — which is where the other
  two things worth knowing came from too. **A dump's class and qualifier are known before the
  load wait and its file name is not**, so a reading taken between `open_dump` and the
  `WaitForEvent` that loads it is not comparable with a later one. And a **kernel** target has no
  process id to read at all (`E_NOTIMPL`).

- **`DebugEngine::session_processes` is public**, having been the crate's own answer to which
  user-mode processes a session holds since the teardown needed it. It is the stable half of a
  pair whose other half reads like the same question and is not:
  `current_process_system_id` is the *selection*, which DbgEng moves by itself at a child-process
  event and which `|Ns` moves by hand — neither of which changes what the session is debugging.
  Exposed for a caller fingerprinting its target, where using the selection retires a perfectly
  good session the first time the debugger points somewhere else.

- **`DebugEngine::virtual_region`** — `IDebugDataSpaces2::QueryVirtual` as a typed answer
  (`VirtualRegion`, `VirtualState`), which is what the memory manager says about a run of pages
  rather than what the debugger can read there. `VirtualState::Unknown(u32)` keeps a state this
  crate does not name instead of folding it into reserved or committed, because either guess is
  what would make the primitive lie. User-mode only; a kernel session has no answer to give and
  says so as an error.

  **Its output buffer must be 16-byte aligned**, which `MEMORY_BASIC_INFORMATION64` is not: the
  engine's live-target path copies the 48-byte answer out with three `movaps` stores and takes
  an access violation *inside dbgeng* otherwise. The dump path copies field by field, so the
  same call against a full dump answered 22 queries from an 8-aligned buffer without complaint —
  testing this on a dump proves nothing about it. Measured on 26200, 2026-09-24
  (`dbgeng!Ordinal367+0x14f96`, `movaps xmmword ptr [rbx],xmm0`).

- **`examples/user_heap_smoke.rs` creates its Segment Heap through `RtlCreateHeap`**, because
  `HeapCreate` will not pass the flag on. `HEAP_CREATE_SEGMENT_HEAP` is documented as a
  `HeapCreate` option and is not one: `KERNELBASE!HeapCreate` opens with `and ecx,40005h` —
  `HEAP_CREATE_ENABLE_EXECUTE | HEAP_GENERATE_EXCEPTIONS | HEAP_NO_SERIALIZE` — so 0x100 is
  dropped before `RtlCreateHeap` is reached. Measured on x64 26200 (2026-09-24): growable, with
  an initial size and with a fixed maximum all came back a classic NT heap through `HeapCreate`,
  and the direct call returned a Segment Heap **in the same process moments later**, so the
  wrapper is the whole of the difference. Until now this example built an NT heap on such a host
  and failed two hundred lines later saying the created heap was not among the roots — which
  reads as a defect in root enumeration and is not one, and which is why an earlier note here
  blamed ARM64 and the debug heap. It now reads the heap's signature back at creation and says
  so there instead. The separate per-process switch, which governs the heaps an image gets
  *without* asking, is `ntdll!RtlpHpHeapFeatures` bit 0: 1 in `sihost`, whose four heaps are
  Segment, and 0 in `cmd.exe`.

- **`examples/heap_coverage.rs`** — what, if anything, holds a user heap walk short of
  `Complete`: every gap it filed, put back to the memory manager, with an allocated chunk and a
  free one as controls. An address as a second argument answers that one question, which is how
  the dump direction is checked.

### Changed

- **A walk that reached the end of the pool is cached even where some of it would not read.**
  Only a `complete` snapshot was kept, and on a live kernel no walk is complete — paged pool the
  memory manager has trimmed does not read over KD, and 3,442 extents on one 29671 guest were in
  that state — so every query walked the whole pool again: four questions on `ctf-vm` were four
  walks of ~80 s each, and windbg-mcp's live pool tier, twenty-odd questions against one halted
  target, took 2,665 s. A trimmed page reads no better on the next walk, and the target has not
  moved between questions, so the snapshot is kept. What is still never cached is a walk **cut
  short** — by its budget or by a match threshold — because what it did not reach is unwalked
  rather than unreadable; the index carries `complete`, `budget_expired` and
  `stopped_after_matches` with it, and `refresh` walks again as before. Same sequence afterwards:
  the second `pool_chunk` 79.8 s → 0 s, `pool_find_tag` 76.8 s → 0.1 s, and that tier
  2,665 s → 1,032 s.

- **A heap walk no longer calls reserved address space a hole in its own coverage.** A user-mode
  walk came back `coverage: Partial` on every healthy live process, because the tails of
  subsegments and page ranges — reserved and never committed — read the same way a paged-out
  page does, and *would not read* was the only thing the walk could observe. `PoolState` gains
  `Uncommitted` (and `HeapState` with it), and `PoolState::is_coverage_gap` is now the single
  definition of which gap costs a walk its `complete`.

  What separates them is `virtual_region`, not the allocator's records: `CommittedPageCount`,
  `CommitBitmap` and the LFH commit state are three structures that move between builds and say
  what one allocator believes, while the memory manager answers about the target in one call.
  Only a positive `MEM_RESERVE`/`MEM_FREE` excuses a gap — a failed query, a run that cannot
  advance, an unnamed state and a source that cannot be asked are each conservative, so the
  excuse is never granted by an absence of evidence. The kernel pool walk is not asked at all, so
  it **classifies** exactly as before — not quite the same as *unchanged*, which this entry said
  until a live kernel was walked on the new pin: the `walk_vs` site below is silent on a kernel
  too, and now names what it drops. On `ctf-vm` (live 26100 over KDNET, 2026-09-24, 633,665
  chunks walked, `coverage: partial`, 42.3s) that is the largest diagnostic shape on the target,
  2,768 occurrences, beside 2,617 of the unchanged `region # is only committed through #`. Those
  chunks were dropped before this change as well and already cleared `complete`; nothing in the
  answer said which, or how many. So coverage is unchanged on a kernel and
  `PoolDiagnostics::emitted` rises. Which also fixes what `Unreadable` *means*: it is now
  everything that could not be established as empty, including every case nothing could be asked
  about, so it is the conservative bucket rather than a claim that the target has the memory.

  A free chunk whose middle the allocator decommitted is the same question reached another way:
  it runs past the committed extent it starts in, and `walk_vs` emitted no span for it and
  cleared `complete` **without a diagnostic**. A span is geometry and state, both of which are
  known there, so where the tail holds nothing the chunk is now reported; where it is memory the
  process has, it is still refused, and the walk now names the chunk it dropped.

  Measured on a live 26200 process (`sihost`, four Segment Heaps, 20,426 chunks, 2026-09-24):
  every one of its 33 gaps `MEM_RESERVE`, both controls `MEM_COMMIT`, and an answer that had
  been `Partial` is `Complete`. Checked from the other end on a thin dump of the same process:
  an address whose page the dump does not carry still answers `Committed`, the read still fails,
  and the walk still counts it. `HeapWalkReport` gains `uncommitted_gaps` so that what a
  `Complete` answer forgave is still on the report. windbg-mcp `FOLLOWUPS.md` item 98.

- **The kernel pool walker takes ARM64 targets.** `pool::query` accepted
  `IMAGE_FILE_MACHINE_AMD64` and nothing else, so every `pool_*` query against an ARM64 kernel
  came back `pool walking supports x64 targets only (machine 0xaa64)`. It now admits ARM64
  alongside x64, from the same `IMAGE_FILE_MACHINE_*` constants `heap::validate_target` uses.
  The gate was waiting on a walk rather than an argument, and the walk was run: on a live ARM64
  kernel (26100, AArch64), 18 LFH subsegments whose `BlockBitmap` reproduced `FreeCount` exactly
  under `LfhBitmap::ContiguousBits`, the big-page hash landing on each in-use entry's own slot
  where the truncating one landed on none, and — with the gate lifted — a walk agreeing with
  `!pool` block for block on two subsegments (59/59 and 7/7 allocated blocks), where the
  pre-fix decoder reported 25 of those live blocks as free. Still a list of two machines rather
  than "anything 64-bit": x86 and ARM32 have neither the pointer width the decoders assume nor a
  kernel segment heap, and admitting them would produce confident wrong answers instead of an
  error. windbg-mcp `FOLLOWUPS.md` item 96.

### Fixed

- **A64's cache, TLB and address-translation operations are named from their whole encoding,
  not from their cell**, and the cell rule was wrong in both directions. Every word in a `dc`,
  `ic`, `at` or `tlbi` cell was given that name, though only some `op1`/`op2` pairs there are
  allocated — 85 of the 1,024 combinations in `CRn` 8 are `tlbi` operations — and the rest are
  generic `sys` words; a `sysl` in one was named the same way. And three cells were missed outright:
  `CRn` 9 (`tlbi`'s `nXS` forms), `CRm` 9 (`at s1e1rp`, `s1e1wp`, `s1e1a`) and `CRm` 15
  (`dc civaps`, `cigdvaps`, `civaoc`, `cigdvaoc`). Each cell now carries a mask of its allocated
  pairs, generated by disassembling every word of `CRn` 7, 8 and 9 with LLVM, so an operation that
  disassembler does not know reads as `sys` — a lost name rather than a wrong one.

  It matters more now because `Instruction::privilege` comes out of the same decision. The first
  draft of that change named the three missed cells wholesale, and one `sysl` word in the 26100
  ARM64 kernel came out `tlbi` and cache maintenance (review on #192).

- **A big-pool allocation on a page the memory manager had trimmed lost its name, in both of the
  places the table names one.** The table was consulted correctly — on two live guests the hash
  landed on each failing entry's own slot, zero probes — and the walk then never asked it for a
  span it could not *read*. A segment page range the table names was read anyway, only to run a
  decoder the name makes unnecessary, and where the read failed the range was filed as an untagged
  unreadable gap. A VS chunk the table names whose tail runs into a trimmed page was dropped by the
  "runs past the committed extent" rule before the containment match could run, and its pages
  filed the same way; `pool_chunk` at the allocation's own address then answered `....`, 4096
  bytes, `unreadable`. Measured on 2026-10-07: `Gcac` at `0xffffa4b05e1b5000` (8 KB, segment) on a
  29671 lab kernel and `CIcr` at `0xffffa9099c86f000` (0x12a0 bytes, 0x20 into a 0x12c0-byte VS
  chunk with a resident header) on `ctf-vm` 26100.33438, `!pool` naming both from the table.
  Neither is a regression: the code was identical at every pin since the entries below, and the
  same test had passed on the same guests' previous boots — which allocation the oracle samples,
  and whether its page is resident, is a property of the boot. A named segment range is now
  answered from the table without reading its pages at all, and a VS chunk is matched against the
  table *before* the extent check, with the extent loop told not to file the hole a matched chunk
  covers as a gap. The first of those is also most of a walk's wasted reads: the live entries
  summed to 111 MB on the 29671 guest and 89 MB on `ctf-vm`, every byte read and then discarded.
  Same guest, same sequence, the previous build against this one on `ctf-vm`: a full walk
  82.8 s → 61.9 s, and `pool_find_tag CIcr` 40 matches → 104, the other 64 having been dropped
  over trimmed tails; on the 29671 guest a full walk 136 s → 79.7 s. One of the five entries
  windbg-mcp's tier sampled there still has no span, and it is not this case: `smCB` at
  `0xffffe67bde598000`, a nonpaged 0x1000-byte entry, lies in no region the walk discovers at
  all — `pool_chunk` answers `covered: false` and `pool_find_tag smCB` finds nothing — which is a
  discovery gap, reported by that tier rather than asserted. windbg-mcp `FOLLOWUPS.md` item 99.

- **And a big-pool allocation served out of a VS subsegment kept no tag either.** The fix above
  asked the page range descriptor which allocations have no `_POOL_HEADER`, and that is only where
  *most* of them are: `nt` also puts them inside VS subsegments, where the descriptor says `0x0f`
  and the chunk chain runs straight through them. The size answers it instead, and structurally
  rather than by measurement — `_POOL_HEADER.BlockSize` is **eight bits** of sixteen-byte units
  (`dt nt!_POOL_HEADER`, x64 26100.33438), so 4080 bytes of chunk is the most it can describe and
  an allocation needing a page has nowhere to record its own length. That is why every one of the
  7,639 live entries on a 26100 guest recorded `NumberOfBytes` of `0x1000` or more, and none
  fewer. A chunk past that limit is now matched against the entries discovery found inside its
  region, **by containment and length** rather than by arithmetic on the chunk header: the table's
  `Va` is where the allocation starts and `NumberOfBytes` is how long it is, and taking both as
  given assumes nothing about what sits between the chunk header and the data — which on that
  guest is 0x10 that is measured and not yet explained. Measured there: `!pool` calls
  `0xffffac09da29f000` an `MiRr` allocation of `0xe1c0` bytes and the walk called it 57,792
  untagged bytes — the same length, with only the name lost. windbg-mcp `FOLLOWUPS.md` item 99.

- **Every big-pool allocation was reported with a tag read out of the caller's own data.**
  `ExAllocatePoolWithTag` sends anything that will not fit inside a page to `ExpAllocateBigPool`,
  which takes whole pages from the segment allocator and records the tag and length in
  `nt!PoolBigPageTable` **instead of** in a `_POOL_HEADER`. Nothing in the page range descriptor
  distinguishes one from a plain page-range allocation — both are `RangeFlags` `0x03` — so the
  walker decoded the page as though a header were there, which reads the caller's first sixteen
  bytes as `PreviousSize`/`BlockSize`/`PoolType`/`PoolTag` and then reports the block as starting
  0x10 in and 0x10 short. Measured on a live 26100.33438 kernel (2026-09-24): `!pool` calls
  `ffffac09dd0f5000` a 0x1000-byte `CM25` allocation and the walk called it a 4080-byte block at
  `+0x10` tagged `..N.` — those being the bytes of the registry hive bin's own `hbin` header. An
  allocated kernel page range is now looked up in that table, and where it is named it carries the
  table's tag, no header, and the length the caller asked for rather than the pages it was given.
  `windbg-mcp` `FOLLOWUPS.md` item 99.

- **A freed big-page entry answered for its address, with the tag it used to have.** The lookup
  matched on `Va & !1`, and bit 0 of `Va` is `POOL_BIG_TABLE_ENTRY_FREE`: `ExpRemoveTagForBigPages`
  frees an entry with `lock inc qword ptr [rax]`, so a released allocation stays in the table under
  `address | 1` with its old tag and size until something claims the slot. `nt`'s own comparison is
  `cmp rcx,rdi` — exact — and so is this one now. On the same kernel `ffffac09e50f5001` sat one slot
  from a live entry and its page would not even read.

- **The probe's stop condition never fired, so a miss read the whole table.** It stopped at
  `Va == 0`, and a slot the allocator has never used reads `1`, not `0`. Every lookup that found
  nothing therefore scanned all 32,768 entries. It stops at a never-used slot now, which is sound
  because `ExpAddTagForBigPages` claims the first bit-0-set slot from the hash and so cannot have
  walked past one. The table is also read a batch at a time and **kept**, which is what makes
  asking this question of every page range affordable rather than of large allocations only.

- **The heap walker read an LFH subsegment's busy blocks from the wrong bits, on every current
  build.** `_HEAP_LFH_SUBSEGMENT.BlockBitmap` was read as two adjacent bits per block, busy the
  lower. `ntdll` packs it otherwise: each 64-bit word covers 32 blocks, busy bits in its low half
  and each block's unused-bytes bit 32 above — read out of `ntdll!RtlpHpLfhSubsegmentWalk`, the
  routine `HeapWalk` reaches, identically on x64 26100.8972 and ARM64 26100.1. Measured on a live
  ARM64 subsegment of 62 blocks, the old reading reported fifteen busy, eight of which were free,
  and missed nine that were busy. The heap queries now agree with `HeapWalk` block for block on
  the heap `user_heap_smoke` creates, which now asserts exactly that, live and over its dump. The
  arrangement is chosen by the allocator the schema was resolved from (`is_user`), never by a
  build. **The kernel pool walker keeps its reading unchanged**, and it is not `nt`'s either:
  `nt!RtlpHpLfhBlockBitmapInitialize` (x64 26100.32995) and
  `nt!RtlpHpLfhBlockBitmapAllocateNonAtomic` (ARM64 26100) use one bit per block, 64 to a word.
  That wants a live pool to check against and is `windbg-mcp` `FOLLOWUPS.md` item 96.

- **A segment list whose head is 8-aligned was walked one entry too far.** Its links were masked
  to 16 bytes, and on current `ntdll` the head is not 16-aligned — `SegContexts` at +0x140 of the
  heap and `SegmentListHead` at +0x48 of a context, on x64 and ARM64 alike — so the last segment's
  link back never matched the head, and the walk read the heap's own fields as a segment header.
  Nothing was lost, but every heap said `cannot read segment header` twice and called its walk
  partial. The links are compared exactly now.

- **Every free page range in a segment's free-page tree was dropped.** The descriptor check
  asked a range's first descriptor for `TreeSignature` before asking whether it was a node of
  the free-page tree, and the two share bytes: a free range in the tree holds its node's links
  there. Tree membership is now that range's evidence, and it is reported as free.

- **The VS free tree was walked from the wrong address.** A free VS chunk's `Node` is at +0x8 of
  its 16-aligned header, and tree links and roots were masked to 16 bytes, which moved every node
  onto the chunk's encoded `Sizes` word: the walk followed that word as a left link, took the real
  left link for the right one, and reported the result as unreadable nodes (`0x84a23d…` on ARM64
  26100.1). It changed no chunk's state — a VS header carries its own — but it was the rest of
  why a user-mode walk was partial.

  These last three are in code the kernel pool walker shares, so it has them too. They were
  measured in user mode only; checking them against a live pool is `windbg-mcp` `FOLLOWUPS.md`
  item 96, with the LFH bitmap above.

- **The heap tools saw one heap in processes that have several.** `heap::list` and everything
  built on it took its roots from the PEB's `ProcessHeaps`, and on current Windows that array names
  the process heap and nothing else: `RtlpProcessHeapsInsert` writes it for the first heap only and
  links every heap — the first included — onto a list in `ntdll`'s data, which is what
  `GetProcessHeaps` walks. So a `HeapCreate` return value was never a root, and the answer still
  called itself complete. Measured 2026-09-22 on a live ARM64 26100.1 process holding three heaps
  against a PEB naming one, the missing two including the heap it had just created; and on two
  x64 26200 dumps whose list head links two entries against a PEB naming one. Roots now come from
  that list, in its order, reached through the process heap's typed `UserContext` — which names
  its entry on both builds, where only 26200's PDB names the list head. Every entry is checked
  rather than trusted: its heap has to name it back, its `Blink` has to be the entry before it,
  and exactly one entry, the head, lies inside `ntdll`. An entry that fails any of those ends the
  walk as **unseen** rather than absent — the roots before it stay listed, the walk reports
  `Partial`, and a diagnostic names the entry. A build whose process heap names no entry keeps no
  list and gets the PEB answer exactly as before. `HeapRoot::index` is now the position in that
  order, and the user-mode layout fingerprint moves on every build that carries `UserContext`,
  because the schema reads it; the kernel schema does not, so no pool fingerprint moves.
  `windbg-mcp` `FOLLOWUPS.md` item 79.

- **A KD attach left break-ins owing, and the teardown paid one with the target's only continue.**
  `DEBUG_ENGOPT_INITIAL_BREAK` leaves a pending host break-in behind it, and
  `absorb_initial_break_artifact` consumes exactly *one* with a single `g` — right for NT, whose
  `nt!DbgBreakPointWithStatus` artifact its comment names, and one short on a Microsoft hypervisor.
  The leftover is invisible in the attach's result, and `end_session` spends it: `qd` sends one
  `DbgKdContinue`, the pending break-in takes it, and the target stops again with **no debugger
  attached** — a frozen guest, reported as a clean release. `quit_and_detach_target` now spends
  them first, resuming with a 500 ms bound until **two consecutive** resumes run free. One free run
  is not evidence: a break-in merely slow to arrive reads exactly the same, and a version draining
  once survived 2 detach cycles of 3 where draining to two survived 5 of 5 — each confirmed over
  WinRM as the same boot with advancing uptime. NT is unaffected, checked across two pool-walk
  cycles on a four-processor guest.

  **Between `clear_all_breakpoints` and `qd`, and that placement is the whole of it.** The clear has
  already succeeded, so the target holds no breakpoint a drain resume could stop at — and a resume
  cannot otherwise tell a caller's breakpoint from the break-in it is hunting, both coming back with
  no `cut_short`. The quit has not yet spent the target's one continue. It runs on **every**
  live-kernel quit, whatever the attach shape — it was gated on the KD-connection attach, and the
  entry below is what that gate cost. Two
  readings pinned the cause, one of them ruling out the obvious answer — stepping past the
  hypervisor's own `int 3` before detaching does *not* help, so it is not where the instruction
  pointer sits; and the first `g` after a completed attach returns at once with the CTRL+BREAK
  banner while every later one runs to its bound.

- **A breakpoint in code every processor runs owes a stop to each of the others, and the drain is
  now sized for them.** Measured on a four-processor Microsoft hypervisor, 2026-09-21: a
  `run_to_address` that returned `verdict: hit` with an empty breakpoint inventory after it left
  **three** further stops behind it — processors 2, 3 and 1 where the hit was on 0, each a
  first-chance `0x80000003` at the breakpoint's own address and on that processor's own stack,
  delivered one per resume in 1–3 ms, after which the target ran free. The others reach the patched
  instruction before the debugger removes it, and `qd`'s single continue is then taken by the first
  of them: the guest stops with no debugger attached. It races the quit, so it is intermittent —
  **2 of 4** hit-then-detach runs froze, both leaving the guest black with a pending stop at that
  address, each released by one attach and one `end_session` whose drain ran.

  Two changes follow, and the first is why the entry above no longer names an attach shape. These
  stops owe nothing to the attach, so the gate left the drain unrun on exactly the
  `experimental_break_on_connect` path a running hypervisor has to be attached with. And the
  attempt cap is now `GetNumberProcessors` plus the two free runs rather than a fixed five, which
  four processors met exactly by coincidence — three stops plus two free runs — so one more
  processor would have exhausted it with a stop still owing. `DRAIN_BUDGET` bounds the wall clock
  at four seconds where the attempt count no longer does. **Ten of ten** four-processor
  hit-then-detach cycles then came back clean, each confirmed over WinRM as the same boot with
  uptime advancing afterwards. A **local** kernel is the one target the old gate excluded by
  construction: it owes nothing, and its first drain resume errors out because local kernel
  debugging refuses execution control, which ends the loop there.

- **A slot that names its VS context by displacement is decoded, so current Windows builds walk
  again.** `_HEAP_VS_AFFINITY_SLOT::VsContext` — a back-pointer to the owning `_HEAP_VS_CONTEXT` —
  is spelled `VsContextOffset` on 26100.33438 and 26200, and holds `slot - context` rather than an
  address. Because the old name sat in a *required* field list, one rename took the whole type down
  and the family's other fields with it, so every pool and heap query on such a build refused with
  `unsupported allocator layout … no recognized VS structural family is complete`. Measured rather
  than inferred: `RtlpHpVsSlotCreate` stores `sub rax,rdi` against the context the slot was created
  for, and a live slot's `0xa80` was both `slot - context` and `SlotRef << 6`. The slot-map
  arithmetic itself is unchanged — `RtlpHpVsContextGetSlotInfo` still reads `ctx + (word[ctx] << 6)`
  over `byte[ctx+2] + 1` four-byte entries.
- Both older shapes are **unchanged**, which is the point rather than a side effect: selection is by
  the fields a target's own PDB carries and never by a build number, and their resolved schemas —
  fingerprints included — are pinned against values recorded before this change.

### Added

- **The heap queries walk ARM64 processes.** `heap::*` refused any processor but AMD64. It now
  accepts ARM64 as well — native processes, and x64 processes emulated on ARM64, whose heaps
  are the ARM64X `ntdll`'s like any other's. Nothing else in the walker was specific to either
  architecture: the four fixes above are x64's as much as ARM64's, and were found by running
  `user_heap_smoke` on ARM64 for the first time. What it does refuse, on both, is a **WoW64**
  process (`HeapQueryError::Wow64Process`): the PEB and `ntdll` a 64-bit engine sees there are
  the emulation layer's, so a walk would list those heaps and call itself complete while the
  program's own, 32-bit, heaps were absent. No processor type says so — the effective one is
  still 64-bit at a WoW64 launch's first break — so it is read from `_TEB.WowTebOffset`, which
  was `+0x2000` at both of that launch's breaks and zero in native and emulated-x64 processes.
  A TEB that cannot be read is `HeapQueryError::InvalidTeb`, not a pass.

- **`DebugEngine::current_thread_teb`**, beside `current_process_peb`.

- **ARM64 operands, registers, effect, condition and privilege are decoded**, so
  `InstructionSet::operands_are_read` answers `true` there and every `Instruction` field is a real
  answer on that architecture rather than an empty one. A64's flow landed on its own (#148); this
  is the half two static analyses in `windbg-mcp` were waiting on (#170) — an IOCTL map, which
  needs the immediate a compare holds, and a hazard scan, which needs `privileged`.

  What is decoded is the general-purpose architecture in full, with the aliases a compiler emits
  resolved out of their base forms (`cmp` from `subs`, `mov` from `orr`, `lsr` from `ubfm`) because
  an alias changes the operand *list* and not only the spelling. The vector spaces are named rather
  than shaped — as a single `Operand::Undecoded` carrying the space's name, which is a caller's
  tell that nothing was read — with one exception: in **Advanced SIMD and scalar floating-point**, every
  encoding that reaches a general-purpose register or the flags is decoded, and the list is short
  enough to give in full (the floating-point conversions, `fmov` between the register files
  including its upper-lane form, `umov`/`smov`/`ins`/`dup`, `fcmp`/`fccmp` and `fjcvtzs`, and a
  vector load's base-register writeback). The Reserved space's one allocated member, `udf #imm16`,
  is decoded too — the engine renders that whole space `???`, so this is one of the few places the
  decode says more than the rendering it was checked against.

  A **vector-structure access carries the width it transfers** on its memory operand, that being
  the one thing its register list does not give a caller: `ld1 {v0.16b},[x1]` reports 16 bytes,
  `ld2 {v0.b,v1.b}[0],[x1]` reports 2, and a replicating `ld1r {v3.4s},[x4]` reports **4** — one
  element read and splatted, rather than the sixteen bytes it writes. More generally, **every
  access whose width is encoded reports it**, and the four positions that report none each have a
  reason the module documents: `adr`/`adrp` perform no access, a prefetch has no architectural
  width, and the MOPS copies and the whole-granule tag forms move an amount only a register holds
  at run time.

  **SVE and SME have no such exception**, so an `incb x0` there comes back claiming nothing about
  `x0`. That is deliberate rather than an oversight: a partial decode of that space would remove
  the marker from the encodings it shaped while leaving the gather loads and `ctermeq`'s flags
  unread, handing back an access list that looks complete and is not. Closing it means enumerating
  that space's general-purpose surface and shaping all of it at once.
- **Four A64 encodings that the architecture does not allocate no longer decode as though it did**,
  and one that it does allocate is no longer refused. A prefetch exists only in the unscaled form,
  so the post-indexed and pre-indexed rows of its slot were instructions this decoder invented and
  the unprivileged row came back as `sttr` — a real mnemonic wearing a prefetch's semantics, with
  no transfer width, `Effect::Other` for a store and its `Rt` rendered as a prefetch operation. The
  unprivileged mode has no vector form either, where `ldtr b0,[x0]` and `sttr b0,[x0]` were being
  produced. In the other direction, every `ldg` with a nonzero displacement was refused as
  unallocated, and the one that survived reported no access width, because the flag separating the
  whole-granule tag forms from their neighbours was reading the wrong field.

  All five were found by auditing which memory operands report no access width, rather than by
  review or by either existing harness — a corpus contains none of these encodings, and the family
  enumeration compares *definitions* and so cannot see a field nobody constrained. Each was then
  settled against the generated instruction table rather than a recalled one.
- **A register-branch form now refuses the words that leave its fixed fields set**, `0xd61f0001`
  having decoded as `br x0` and an authenticated return with a stray `Rn` having reported reads of
  the link register and the stack pointer its word does not name. The rule was already written in
  the comment above the code that did not apply it. Settled by differencing that whole encoding
  space against a generated instruction table, which now agrees with it exactly but for `texit`,
  an extension this declines. The same check refuses an unauthenticated `braa`/`blraa`, which has
  no encoding: `0xd71f0000` was a `br x0` that also read `x0` as a modifier.

- **Every A64 system operation is reported privileged**, where `sys`, `dc`, `ic` and `tlbi`
  previously took their answer from `op1` alone and so called the `op1`-three encodings EL0's.
  They are not: there is no unconditionally-EL0 member of that family. `SCTLR_EL1.UCI` gates
  `dc cvau`, `dc civac`, `dc cvac`, `dc cvap`, `dc cvadp` and `ic ivau`; `SCTLR_EL1.DZE` gates
  `dc zva` and the MTE zeroing forms; `GCSCRE0_EL1` gates the guarded-stack pushes. A hazard scan
  was seeing none of the 74 by-address cache maintenance instructions in this bench's kernel.

  The same argument had already carved `DAIF` out of the system *register* space one round
  earlier. That carve-out stays, registers under `op1` three being mostly EL0's own; for
  operations the exception is the whole set, so that arm now reads no `op1` at all rather than
  growing a second list a round at a time.

- **`examples/undecoded_families.rs` reports both directions of the differential.** Beside the
  families this decoder leaves unread, it now lists the words it *shapes* that the generated table
  refuses — a field nobody constrained rather than a family nobody decoded, which the first listing
  structurally cannot find because it compares definitions. It is the same sweep and costs nothing
  extra. Five of this release's decoder fixes came out of running it, none of which any corpus
  contains an instance of.

- **Three more A64 encodings read the field they were actually given.** `isb`'s `CRm` is an option
  and shared `dsb`'s shareability table, so `isb #7` was spelled `isb nsh` — a domain `isb` has no
  concept of. `dsb #0` and `dsb #4` are `ssbb` and `pssbb`, the speculative-store-bypass barriers,
  which a caller matching mnemonics for a speculation mitigation could not find and which take no
  operand. And `casp` built each pair's second register with `rs | 1`, which is the successor only
  where the field is even — an odd one came back as a pair of a register with itself, where the
  architecture makes it CONSTRAINED UNPREDICTABLE and there is nothing to read.

- **`Operand::Undecoded`**, which is how an instruction says its fields are defaults rather than
  answers. `InstructionSet::operands_are_read` answers for a *set*, and that was enough while every
  decoder here was complete over its own; A64's is the first that is not, and the distinction
  previously lived in a convention about what an `Operand::Other` contained — which a consumer had
  to know the space names to apply. It is the whole operand list wherever it appears.

  **Migration:** an exhaustive `match` on `Operand` gains an arm. A consumer that must not believe
  a stale value treats `Undecoded` as clobbering whatever it is tracking; one that would rather
  lose a finding than invent one stops at it.

  Measured against the engine's own rendering of all 1,233,502 words of a 26100 ARM64 kernel's
  `nt` (`.text` and `PAGE`): 5,019 instructions — 0.42% of the 1,189,047 the engine could render —
  are left unshaped, all of them in those vector spaces; every register a rendering names is in the
  decode's reads or writes but one, whose `Rn` field the engine prints as `sp` where the encoding
  says the zero register; all 42,244 resolved addresses match the engine's; and thirty mnemonics
  differ, each of them the debugger's own spelling rather than the architecture's.

  Two shapes worth knowing about before reading A64 fields with an x64 habit. A **store names its
  source first**, so `operands[0]` is not the destination there — `writes` is the field that
  answers what changed. And a **shift or extension folded into an arithmetic operand** is named as
  an `Operand::Other` and drops the effect to `Effect::Other`, rather than being reported as an
  immediate a consumer would add: `add x8,x9,x10,lsl #3` is not `x9 + 3`. A shifted *immediate* is
  folded into its value instead, `sub w0,w0,#0x222,lsl #12` carrying `0x222000`, since that is a
  number the operand can hold.
- **`decode_instruction`**, which decodes one instruction from bytes a caller already has, with no
  debug session anywhere. `Instruction::bytes` carries the bytes the instruction **occupies**
  rather than the buffer it was handed — an x86 caller cannot know an instruction's length before
  decoding it, so `[0x90, 0xcc]` answers `nop` with `90`, and a walker may step by that length.
  Bytes that decode to nothing report the whole input, there being no extent to report and
  `Flow::Unknown` beside them saying so. Everything else here reaches an instruction through a target;
  this is the same decoding for a caller holding the encoding — bytes out of a file, an image
  mapped by something else, or a word under test. `Instruction::text` is empty, nothing having
  rendered it.
- `examples/undecoded_families.rs`, which decodes every 32-bit word twice — once with this crate's
  A64 decoder and once with tables generated from the architecture — and lists the instruction
  families the second knows and the first does not. Seven review rounds each found one or two of
  those by hand, because a corpus finds only what a target contains and no Windows ARM64 image
  contains memory tagging, `brab`, `subps` or `cpyfp`; this answers the whole question in fifty
  seconds. It is what found MOPS' guarded forms and CSSC's literal minimum and maximum, and what
  turned this crate's coverage claim from a sentence into a table.
- `examples/decode_against_rendering.rs`, which decodes every word of an image's executable
  sections and cross-checks each one against the engine's own rendering of the same bytes. The
  rendering is the only independent reading of those bytes this crate has, and a corpus of a
  million real instructions finds shapes a hand-written fixture never contains: it found seven
  defects in the A64 decoder above, including a no-allocate pair load decoded out of an `opc` that
  form does not allocate, which only a sweep past `.text` reaches. Nothing in it is a pass or a
  fail — every count has a floor that is not a defect, so the run prints *what* each one was.
- `VsSemanticFamily::AffinitySlotsSelfRelative` (`affinity_slot_vs_offset`), reported apart from
  `AffinitySlots` because the two are *checked* differently — an address against the context, a
  displacement against `slot - context` — and reading one as the other rejects every slot silently
  rather than failing. A PDB carrying both spellings is refused as ambiguous rather than resolved by
  precedence.
- An unsupported layout now **names the fields each candidate family wanted and which were
  missing**. The previous message said only that no family was complete, which reads as a symbol
  problem: the first diagnosis of this rename went to `.reload /f nt` and a PDB check before anyone
  compared a field name.

## [0.2.0] - 2026-09-13

This release adds typed instruction analysis, kernel object namespace queries, breakpoint
management and crash-event reads, and fixes live-target arrival and interrupt handling.

### Migration from 0.1

- `DebugEngine` is no longer `Send` or `Sync`. Create and use it on the same thread; send an
  `InterruptHandle` to another thread when it needs to interrupt the engine.
- The public `Breakpoint` wrapper is removed. Use `set_breakpoint`, `remove_breakpoint` and
  `enable_breakpoint` with breakpoint IDs.
- `Instruction` and `BreakpointInfo` gain fields, and public enums gain variants. Update
  struct literals and exhaustive matches when upgrading.

### Added

- **Kernel object namespace queries** through the new `object` module:
  `DebugEngine::object_at`, `objects_in` and `symbolic_link_target` resolve names, list directory
  entries and read symbolic-link targets as values. Layouts come from target symbols and are
  validated before walking. Listings report unreadable and malformed entries separately;
  failed lookups distinguish absence from an incomplete search. `Namespace::halting` lets a
  caller stop the walk and reports that stop explicitly. Names use ASCII case folding, and
  queries require the target's namespace data pages.
- **Instruction semantics** include privilege requirements, effects, conditions, register
  identity and width, and registers written. These accompany the operands and control flow
  decoded from x86/x64 instruction bytes.
- **Disassembly carries its operands as values, decoded from the encoding.** `Instruction` gains
  `mnemonic`, `operands` and `flow` beside the `text` it already had, so a caller asking what an
  instruction *compares against* or *branches to* reads a field instead of re-parsing a rendering
  downstream. They come from decoding `bytes` — the engine's own read of the instruction, so no
  extra round trip — with `iced-x86`, and the rendering stays verbatim in `text` because it is what
  a listing prints.
  **Decoding, rather than reading the rendering, is the whole design and was arrived at the hard
  way.** The first implementation parsed the third column, and a symbol's own punctuation kept
  taking operands apart: a comma inside `std::map<int,int>`, a parenthesis inside `operator()`, a
  bracket inside `operator[]` — three review rounds, three characters, each severing a direct call
  edge that a walk then dropped as indirect. The mnemonic table had the same shape, growing an
  entry a round for `int` by vector, `xbegin`, `xabort` and `hlt`, because a hand-written list of
  what transfers control is never finished. An encoding has neither ambiguity, and a decoder's
  flow control is complete by construction. Symbols leave the picture entirely: a destination is an
  address, and naming it is `symbol_for`'s job.
  `Operand` is `Register`, `Immediate`, `Memory`, `Target` or `Other`. `Flow` carries every
  destination as an `Option`, because a direct transfer encodes a displacement and an indirect one
  encodes a register, and a caller treating `None` as "no edge" stays sound. `Unknown` and
  `Unreadable` are separate, and the line between them is whether there are bytes: a `???`
  rendering has none and stops a walk, while an instruction set this does not decode — or an
  encoding newer than the pinned decoder — has an instruction there and falls through. A walk that
  fell through the first would step through *bytes*, one address at a time, to its own cap; one
  that stopped at the second would discard the rest of a routine over a version skew.
  A memory operand claims a static `address` only where the instruction alone determines one. A
  segment override does not: `gs:[188h]` is the KPCR, its linear address is the segment base plus
  the displacement, and that base is a runtime fact. A RIP-relative operand keeps the displacement
  it **encodes** rather than the decoder's normalised target, which would otherwise report
  `[rip+0xffa]` at `0x1000` as a displacement of `0x2000` — a second copy of `address` where the
  addressing expression should be. A displacement is signed at the width its *address registers*
  are: the decoder keeps a 32-bit effective address in 32 bits, so `[ebp-8]` arrives as
  `0xfffffff8` and a straight widening cast reported the commonest local-variable reference there
  is as 4,294,967,288. An absolute reference with no register stays unsigned, a 32-bit
  `[0xfffff000]` being a high address rather than a negative offset.
  A near branch's destination lands in the address space its instruction came from. Decoding 32-bit
  code computes a 32-bit target, so an instruction whose own address carries a high half — a narrow
  effective machine over a wide address, which `.effmach x86` produces — would otherwise name a
  destination in a different address space from itself, which a module-bounds check rejects and a
  reader follows to the wrong place. The high half is inherited from the instruction rather than
  sign-extended, taking the address form from the caller's own value instead of assuming the
  engine's. 64-bit decoding is left alone deliberately: a `rel32` reaches ±2 GB and so may cross a
  4 GB boundary, where inheriting would drag a correct target back four gigabytes. An **absolute**
  memory address is canonicalised the same way and for the same reason, absolute globals and
  import slots being ordinary in x86 kernel code.
  Inherited rather than sign-extended, and that is measured rather than preferred: against a
  32-bit target, `? 80002000` evaluates to `80002000` and `.formats` prints `Hex: 80002000` —
  eight digits, unextended — so sign-extending would invent `ffffffff80002000` for an address the
  engine calls `80002000`, and on a 32-bit kernel would do so for nearly every address. The cost
  is one straddling case, a low instruction reaching a high absolute, which keeps the low half and
  is pinned by a test naming the measurement.
  A displacement's signed width is the **effective address width**, and neither of the two simpler
  readings of that survives: the *index register's* width breaks a VSIB gather, whose index is an
  `xmm`/`ymm`/`zmm`, so the extension becomes a no-op and a negative displacement comes back as
  four billion; the *encoded field's* width breaks EVEX, whose `disp8` is compressed, so the
  decoder returns it already scaled by the tuple while the field is still one byte and extending
  from eight bits turns a real `+128` into `-128`. The address registers give the width where
  there are any, an address-size override being exactly what makes them narrow, and the encoded
  field gives it for a pure VSIB form, where compression cannot arise because it needs a base. All
  three readings are pinned, so the two wrong ones fail a test rather than being re-proposed.
  An `EIP`-relative operand — a 64-bit instruction under an address-size override — has its
  displacement computed at 32 bits, the decoder wrapping the target to that width while the
  instruction's own next address stays 64, which otherwise puts the delta four gigabytes out.
  Reading is gated on `InstructionSet`: x86 and x64 are decoded, and anything else — ARM64 today —
  reports its mnemonic, no operands and `Flow::Unknown`.
  Measured against a whole real dispatch routine rather than composed lines
  (`examples/typed_disassembly.rs`): 376 instructions of `mountmgr!MountMgrDeviceControl` on a
  26100 image, **zero** unrecognised operands, zero unknown flows, and its eleven control-code
  compares recovered as values — identical before and after the decoder replaced the parser.
- `DebugEngine::decode_range` decodes a span from **one** memory read instead of one engine call
  per instruction, which is what a bounded traversal over a hundred functions needs. Its
  instructions carry no `text`, nothing having rendered them; a caller needing a rendering for the
  few it displays asks `disassemble` for those. The two paths are compared against each other in
  the example over a real function's first region: 23 instructions, 23 compared, 0 disagreements.
- `DebugEngine::effective_processor_type` reports the processor the engine is **rendering** in, as
  against the physical one `processor_type` already answered. The two diverge wherever one machine
  runs another's code — a WOW64 process, x64 emulated on ARM64, any target after `.effmach` — and
  it is the effective one that discriminates a *rendering*, so `instruction_set` reads it. Measured
  by forcing the divergence: `.effmach x86` on an x64 kernel dump moves the effective type to
  `0x14c` while the physical stays `0x8664`, and the reading follows it rather than decoding an x64
  unwind record against x86 output. Anything reading the target's **structures** still wants the
  physical type, a pointer's width being a fact about the machine rather than about a rendering,
  so the pool and heap walkers are unchanged.
- `DebugEngine::function_extent` returns the unwind **region** containing an address, from the
  image's `.pdata`, rebased. A region is **not** a function, and using it as one loses code: MSVC
  splits a function across several entries, and this answers `0x14750..0x147a3` for
  `mountmgr!MountMgrDeviceControl` — 83 bytes, which `.fnent` confirms — while that routine's
  compare chain lives past `0x147dd`. Bounding a walk with it recovered zero control codes where
  following the flow recovered twelve. The x64 entry is three `u32` RVAs and not the 64-bit
  addresses the API's name suggests; reading them as `u64` reports "no entry" for a function that
  plainly has one.
  It answers a three-state `FunctionExtent` rather than an `Option`, because the two non-answers
  are different facts. `NoEntry` is reported for the one measured failure that means it —
  `E_NOINTERFACE`, which a real dbgeng 10.x gives for address zero, for a header page, and for
  every x86 address, 32-bit Windows having no unwind table — and any other failure is returned as
  an error rather than read as a leaf. `Unsupported` covers every instruction set but x64:
  ARM64's record is two words whose second is packed unwind data, measured as `needed = 8` with
  `[0x0025df60, 0x0005f218]` for `nt!KeBugCheckEx` on an ARM64 kernel dump, and read as an end
  address that is a bogus region which — for any function below the `.xdata` RVA — contains the
  address asked about and passes every sanity check. The engine's own `needed` is checked against
  the x64 shape rather than assumed.
- `DebugEngine::symbol_for` is the public half of the existing symbol lookup: the `module!Symbol`
  an address resolves to and how far past it, or `None` for a driver with no PDB.
- **Exception events are readable as values.** `DebugEngine::last_event` returns a `DebugEvent` —
  kind, engine process and thread, and, when the event carried one, an `ExceptionRecord` with the
  code, flags, faulting address and parameters. That is `.exr -1` typed, and it is the user-mode
  counterpart to `bug_check`: on a target stopped by a fault it is the record that stopped it.
  `Ok(None)` where the engine has seen no event, which is any engine before its first wait —
  including a dump `open_dump` has *named* but nothing has pumped. That case is `None` rather than
  an error because the engine does not fail it: it answers `S_OK` with kind `0` and `DEBUG_ANY_ID`
  for both ids, and kind `0` is not a `DEBUG_EVENT_*` value.
  `ExceptionRecord::parameters` arrives already cut to the record's own `NumberParameters` (and
  clamped to the fifteen slots there are), because the count is the field that tells the two shapes
  of a `0xc0000409` apart — one parameter is the CRT's `abort`, three is WIL's, whose second is the
  `HRESULT` — and a leftover read as a parameter would answer the question wrongly rather than
  cosmetically.
- `DebugEngine::stored_event` returns the event a dump was **written for**, with the register
  context it was written with, as an opaque `ThreadContext`. Unlike `last_event` it does not move:
  it still answers after a caller has stepped, gone, or changed threads. `Ok(None)` where there is
  no stored event — every live target, and every dump not written for a fault, including kernel
  crash dumps, whose bug check `ReadBugCheckData` reads instead. That is read off the engine's own
  refusal (`E_UNEXPECTED`, measured on both) rather than probed for, so a genuine failure still
  reaches the caller as one.
- `DebugEngine::stack_frames_from` walks the stack a recorded context was in, which is what
  `.ecxr; k` produces without `.ecxr`'s effect on the session: the caller's selected thread and
  frame are left exactly where they were, so a triage built on it is still a read. **What makes it
  differ from `stack_frames` is the selected thread and only that** — measured on a two-thread
  fail-fast dump, after `~1s` the other walk returns the parked thread's six frames while this one
  still returns the crash's twelve, while `.frame`, `.cxr` and `.ecxr` move neither, since they
  change the symbol scope and `GetStackTrace` walks from the thread's registers.
  A `ThreadContext` carries the target it was read from and is refused
  (`DbgEngError::ContextFromAnotherTarget`) by an engine that no longer holds it, exactly as
  `set_scope` refuses a stale `Scope` — and for a sharper reason: a stale scope points the session
  somewhere visibly wrong, while a stale context comes back as frames, which is an answer a caller
  cannot tell from the right one.

### Fixed

- **An opener that replaces the session now reissues the target identity.** Only `end_session` did,
  so a caller who opened dump A, saved a `Scope` or a `ThreadContext`, and opened dump B *through
  the same engine* got the same identity back — and the stale registers were accepted against the
  new target. The three openers that replace a session (`open_dump`, which `open_trace` delegates
  to, and both kernel attaches) already funnel through `forget_the_previous_session`, so the
  reissue lives there rather than in each of them: "the previous session is gone" now means all of
  what it says, and the next opener gets it without remembering to.
- `examples/stored_event_probe.rs`, the measurements behind the three. It also caught the one that
  would otherwise have shipped: `GetStoredEventInformation` does **not** refuse a context buffer
  that is too small the way `GetScope` does. It truncates — offered 716 bytes for an x64 dump it
  writes 716, reports 716 and returns success, and the damage surfaces three calls later when
  `GetContextStackTrace` rejects the truncated context with `E_INVALIDARG`. So the context ladder
  here starts *above* every real `CONTEXT` rather than below it, and grows only on the one signal
  the call gives that there was more to write.
- Breakpoints can be **set**, not only listed. `DebugEngine::set_breakpoint` and
  `set_breakpoint_bounded` take a `BreakpointSpec` — a location (`BreakpointAt::Address` or
  `::Expression`), an optional command, match thread, pass count, one-shot flag, and a `DataWatch`
  that makes it a data breakpoint (`ba`) — and answer with a `BreakpointSet` carrying the new
  breakpoint **as the engine holds it**, read back through the same getters `breakpoints()` uses.
  `remove_breakpoint` and `enable_breakpoint` take an id, as `bc`/`be`/`bd` do. Previously the only
  write path was the `execute` text hatch, so a caller building `bp <expr> "<command>"` had to
  escape a quoted string inside a `;`-separated command line and then screen the operand for both
  characters; a command now arrives as a parameter, and `examples/breakpoint_probe.rs` checks that
  one containing both survives byte-identical.
- `set_breakpoint_bounded` bounds the **location resolve**, the one step that can block: a symbolic
  location is evaluated eagerly, so on a module whose PDB is not local it is a symbol-server fetch
  with the engine held. Measured on dbgeng 10.0.29547.1002 — 2445 ms for a cold
  `KERNELBASE!CreateFileW` against an empty store, 151 ms warm, 0 ms for an address, and 0 ms to
  defer when the module is absent. `SetInterrupt` reaches it, so the bound is real; and because a
  break is otherwise **silent** — it returns `Ok` with a breakpoint, having abandoned the symbol
  load and left the module on export symbols for the rest of the session — the result carries
  `cut_short` rather than being a bare `Result<(), _>`.
- `OnExisting` says what to do about breakpoints already at the resolved address. The engine
  deduplicates nothing: three typed sets on one address leave three breakpoints. What deduplicates
  is the command layer — `bp` and `bu` resolve and then remove whatever is there, printing
  `breakpoint N redefined` — keyed by the resolved address, so a *deferred* expression duplicates
  freely. `OnExisting::Replace` reproduces that as a value, reporting the removed ids as
  `BreakpointSet::replaced`; `Add` is the default, since a primitive should not destroy what the
  caller did not name. Worth choosing deliberately: duplicates at one address stop the target
  **once** but activate every breakpoint there, so each one's command runs, and removing one by id
  leaves the address armed by the others. Nothing is removed until the replacement is fully
  configured and certain to be armed, so a call that fails part-way leaves the caller's existing
  breakpoints alone rather than handing them an error and an address they had already lost.
- `BreakpointInfo::data` reports a data breakpoint's watched region — what access, over how many
  bytes — read through `GetDataParameters`. The read side could previously say a breakpoint *was* a
  data breakpoint and not what it watched, which left the new read-back unable to confirm the half
  of a spec most worth confirming. `DataAccess::Other` keeps an access combination this build does
  not name rather than folding it into a plausible neighbour, as `BreakpointKind::Other` does.
- `examples/breakpoint_probe.rs`, the record behind all of the above.

### Removed

- **`unsafe impl Send` and `unsafe impl Sync` for `DebugEngine`** (#136 stage 4). They asserted
  the opposite of what this crate says about its own threading: `SetInterrupt` is the one DbgEng
  call documented as safe from any thread *because the rest of the engine is
  single-thread-affine*, so `Sync` promised concurrent `&self` calls into an engine that cannot
  take them and `Send` promised a move to another thread, which is the same claim one step
  weaker. Neither carried a safety comment, and neither could have been given a true one.

  **Semver-visible, and measured against both consumers before it was made**: removing each and
  building leaves this crate (`--all-targets`, tests and examples included) and windbg-mcp
  compiling unchanged, because both already create the engine on the thread that uses it. A
  consumer that did move an engine between threads is the case this breaks, and it was relying
  on an unsound impl to do it.

  `InterruptHandle` is untouched and is now the crate's only `Send + Sync` type — one
  `SetInterrupt` from anywhere, and nothing else. `deferred_inputs` becomes a `RefCell` rather
  than a `Mutex`, since `&self` now implies one thread. And
  `test_the_engine_does_not_cross_threads_and_the_handle_does` asserts all four bounds, because
  re-adding an `unsafe impl` is one line that compiles and reads as a fix for whatever error it
  silences.

- The public `Breakpoint<'a>` type, which had no caller in `src/` or `examples/` and was a trap for
  anyone who found it: built on the v1 `IDebugBreakpoint` where the read path uses v2, offering no
  setter but `set_offset_expression`, and panicking in three of its four methods — `enable`'s
  message was a copy of `set_offset_expression`'s. A breakpoint is created *disabled and at address
  zero*, so its documented use left a breakpoint on the null page that never fired, and the method
  that would have armed it was one of the three that panicked. Superseded by `set_breakpoint` and
  the id-taking `remove_breakpoint`/`enable_breakpoint`; the private `ScopedBreakpoint` is now the
  only wrapper over a raw breakpoint object, so there is one answer to who removes a breakpoint and
  when rather than two that disagreed.

### Changed

- **An arrival is delivered to the open waiting for it, instead of broadcast into a set every
  guard polls.** An opener registers what it is waiting for (`Registered`), the pump routes a stop
  to the first open that wants it and has nothing yet (`Arrivals`), and the entry dies with its
  guard. Stage 3 of [#136](https://github.com/glslang/dbgscope/issues/136).

  What it replaces, `stopped_on`, was an engine-wide set of every `(engine id, system pid)` the
  engine had ever stopped on. Because it outlived the opens that read it, it needed a lifecycle of
  its own — pruned at both openers for pid reuse, cleared where a session is replaced, and cleared
  again where one is ended — and each of those three arrived as a review finding on
  [#133](https://github.com/glslang/dbgscope/pull/133) rather than as a design. None of them is
  needed now: nothing outlives its reader, so nothing can go stale.
  `prune_processes_that_left` is down to the attachment record, which is about the teardown
  decision rather than about an open.

  **Two launches pending at once are told apart**, which `Arrival` documented as an accepted
  ambiguity: a launch is identified by elimination, so the first arrival was new to both snapshots
  and ended both waits. An arrival is now *claimed* by the open it is delivered to, so the second
  launch is still waiting when the next one comes. That fix was weighed and rejected at the time
  because it needed "new engine-wide state, cleared everywhere a session is replaced and pruned for
  pid reuse" — which was the cost of the record it would have joined, and is the cost this shape
  does not have.

  **A claim outlives the open that made it**, for as long as anything is still waiting: when a
  guard goes, the process it was given is inherited by the opens that remain. Without it the
  ambiguity above is closed only while both guards are held: the first launch's target stops
  again, nobody has it claimed any more, and it is absent from the second launch's snapshot because
  it did not exist when that snapshot was taken. Not a lifecycle creeping back in: the claim goes
  when the opens holding it do, where the record this replaces lived for the whole session.

  **The state is per client rather than per wrapper**, in a new `ClientState` held by `Arc` and
  keyed by client pointer in a `Weak` map. Two `DebugEngine`s can be live around one
  `IDebugClient6`, and a `wait_for_event` through one used to complete an open held by the other in
  its own copy of the record alone — the other then read `Listed`, waited again, and spent its
  whole bound on an event that had already happened. That was written down as a known gap for two
  releases; the interrupt scope from stage 2 had the mirror of it and moves into the same `Arc`,
  because it is the same field. A `Weak` map needs no equivalent of `reissue_identity`: a dead entry
  identifies itself, where a stale *identity* costs only a re-read and a stale *arrival* would
  answer `Arrived` for a target that never stopped.

  **`attached_processes` moves with them**, which was not planned and is the sharper of the two
  gaps that placement had. Delivery reads it to keep an attach's process from being claimed by a
  pending launch, and a pump through a second wrapper read an empty set; but an `end_session`
  through a wrapper that did not perform the attach also saw no attachment to detach, so its
  passive end **killed** somebody else's process — the exact failure that record exists to
  prevent, reached through the wrapper boundary. The sentence that used to defend the old
  placement argued that sharing would put the decision "behind an eviction policy" -- true of the
  identity cache, and not of a `Weak` map whose entry dies with the last wrapper holding it.

  **Two more from review, one of them pre-existing.** "Somebody else has this process" is now one
  rule in `Pending::wants`, so `presence` applies it as well as `deliver` did. A second launch was
  otherwise told `Listed` on the strength of a process the first had been given, and `Listed` is
  not `Absent`, so an interrupted wait answered `Ok(())` instead of `LiveTargetInterrupted`.

  And `prune_processes_that_left` no longer drops an attachment that has not joined yet.
  `AttachProcess` joins its process at the next `WaitForEvent`, so between `attach_process_begin`
  and that wait the pid is recorded and the session does not list it. An opener pruning in that
  window dropped the record — after which the teardown treats somebody else's process as one this
  engine launched, and takes it. An attachment now carries whether it has been seen
  (`Attachment::Deferred` / `Joined`), promoted wherever the engine lists the session on its own
  account: the prune, and the pump.

  And a third round on the state that introduced: `Deferred` is kept because a deferred attach has
  not arrived and so cannot have left, but only a listing promotes one — so an `AttachProcess` the
  engine accepted for a process that then exited before the first `WaitForEvent` left a pid
  recorded for the life of the session, where the prune used to bound it. A live open that waits
  out `LIVE_WAIT_MS` and never sees its process now retires the record, which is the only party
  that can say the attach cannot join. Not on an *interrupted* open, which says nothing about
  whether the attach is still coming.

  And a fourth round, both halves of it about the register being shared where it used to be a
  field. `Drop` tears the session down inline rather than calling `end_session`, so it never
  inherited the line that forgets the pending opens — which cost nothing while each wrapper had its
  own register and leaves a stale entry now, first in line for the next launch's stop through a
  wrapper that outlived the owner. And a **claim** now stops excluding once its process leaves the
  session: engine ids are handed back immediately, so a `.detach` and a reattach of the same pid
  reproduce a pair exactly, and a stale claim made the reattach refuse its own stop as somebody
  else's. That is the reuse the old record was pruned for, arriving from the opposite side — where
  a stale entry there made a new open read `Arrived` for a target that had not stopped, a stale
  claim makes it read `Absent` for one that had.

  A fifth round on the retirement above: it covered the *bound* and not the ending the scenario
  actually takes. When the target exits before the first `WaitForEvent` the session holds nothing,
  so the pump **fails** rather than expiring and the open returns through its `?` without ever
  reaching the bound. The error ending retires too, on the narrower condition that the session
  holds nothing at all — at the bound an open has pumped for `LIVE_WAIT_MS`, so a pid still not
  listed is not coming, where on a failed pump it may have pumped nothing and the same reading
  would retire an attach the engine had not yet had a chance to process.

  No public API changes. Two tests are gone rather than passing, and the constructions that make
  them unreachable are named where they were:
  `test_ending_a_session_forgets_which_processes_it_stopped_on` had no record to forget, and
  `test_a_process_that_left_takes_its_stop_with_it` is now
  `test_reclaiming_an_engine_id_does_not_reclaim_its_arrival`, which asserts the property
  end to end instead of the guard that used to hold it.

- **A break request names the operation it is for.** `InterruptHandle::interrupt` answers a
  `BreakRequest` — `Raised { operation }` or `NothingRunning` — instead of `Result<(), _>`, and
  files the request against the bounded operation the engine is running **under the same lock it
  delivers `SetInterrupt` on**. `DebugEngine::begin_operation` opens one; its guard discards an
  unread request when it drops. Stage 2 of
  [#136](https://github.com/glslang/dbgscope/issues/136), closing
  [#135](https://github.com/glslang/dbgscope/issues/135).

  What it replaced was an engine-wide `AtomicBool` answering *has an interrupt been requested*,
  where every reader wanted *was **this** operation asked to stop*. Six operations cleared it as
  they opened, so a request lodged between an operation's clear and its wait was **erased while its
  break was still on the way** — and the synthetic Ctrl+Break that arrived next was then reported
  as the target's own stop, up to and including being recorded in `stopped_on` as a target's
  initial break, which is the exact misattribution that record's gate exists to prevent, reached
  around it rather than through it. That is #135 half A. Half B — a request outliving the wait it
  ended — was closed by stage 1, which made every pump *take* what it read.

  **The lock is the fix, not the identity.** A generation counter does not close it: if
  `interrupt()` bumps and the operation samples after the bump but before `SetInterrupt`, the
  request is erased exactly as before. The window is between two writes, not between two values, so
  what closes it is making the record and the operation boundary mutually exclusive. The id earns
  its place elsewhere — operations **nest**, since `wait_for_kernel_break_in` holds one across an
  `absorb_initial_break_artifact` that runs a whole `execute_and_wait`, so `running` is a stack and
  `asked` a set and a `bool` could not express either.

  Two consequences. **Delivery stays engine-wide and only attribution is scoped**: `SetInterrupt`
  cannot be aimed, so the break is issued unconditionally — that is what lets a host abort a long
  unbounded `execute_command` that no bounded operation covers — and `NothingRunning` is the
  honest answer when nothing will report it. And **the watchdog files nothing**, reaching the engine
  through a private `break_in_only`, which deletes the `by_watchdog | flag` reconciliation from five
  sites: a deadline and a host request are now independent signals rather than two readings of one
  bit.

  **The residue is named rather than closed**, and it is two shapes of one fact — `SetInterrupt`
  is engine-wide, so which operation a break *lands* on is not this crate's to decide. A break
  aimed at operation N can land on N+1, because N ended between the host reading what was running
  and the break arriving; and a request can be filed against N *after* N's last read of one, since
  an operation accepts requests for slightly longer than it reads them. Neither is reportable. What
  the second one gets is a **drain**: an operation closing on a request nobody read consumes the
  engine's own pending break, so it cannot go on to stop the next operation with nothing to explain
  it — the policy `execute_and_wait`, `settle` and the bounded command path already applied
  wherever a break belonged to no operation, generalised to the one window with no site to put it
  at. `BreakRequest::Raised` says which operation a request was filed against and deliberately does
  not promise that operation will report it: whether the engine thread has a read left is not
  knowable to the calling thread. `examples/interrupt_provenance.rs`
  is the measurement #136 asked for before anything relies on one: a request that *ended* a wait is
  consumed before the wait returns (`[false; 5]`), one that did not is still readable
  (`[true, false, …]`), two back to back are one flag rather than two, and one lodged after the
  wait it was too late for belongs to the next operation. So a post-wait `GetInterrupt` is a
  **forward** signal, which is stage 3's to use.

- **A wait returns what it did.** `DebugEngine::wait_for_event` answers a `WaitOutcome` —
  `Stopped { process }`, `Expired`, `Deadline` or `OnRequest` — instead of `Result<(), _>`, and
  every wait in the crate now goes through one private `pump(bound)` that produces that value
  before anything downstream can look. `Bound` says how a pump is bounded: `Finite(ms)` is a plain
  `WaitForEvent(ms)` whose expiry leaves the target running, and `Watchdog(ms)` is
  `WaitForEvent(INFINITE)` with the Ctrl+Break watchdog the old private
  `wait_for_event_bounded` provided. Stage 1 of
  [#136](https://github.com/glslang/dbgscope/issues/136).

  The engine offers four endings and three of them were invisible from outside the wait: `S_OK` and
  `S_FALSE` are flattened into one `Ok(())` by the generated wrapper, and a break has been serviced
  by the time anything else could look. So the outcome used to be reconstructed *afterwards*, by
  three parties, out of shared mutable state — the last-event slot and the session's process list
  each read twice, the interrupt flag read twice, and the `HRESULT` only the waiting call ever saw
  discarded. #136's evidence that this is one root rather than twenty defects: **15 of the 22
  findings** on the [#133](https://github.com/glslang/dbgscope/pull/133) review were one of
  those reads moving, and **9** of them were a single question — may this writer record a stop?
  — asked once per writer. Those nine are now unreachable rather than guarded: an expiry and a
  break are *arms* of the value, and only `Stopped` reaches the recorder.

  Behaviour is otherwise unchanged, with two deliberate exceptions, both of them one rule replacing
  three. **A break outranks the wait's own error**, either origin's — which `execute_and_wait` and
  `settle` already did ("a break makes both of these fail"), `run_to_address` did for the watchdog's
  break alone, and `wait_for_event` did not do at all. Narrow in practice, since `SetInterrupt` ends
  a wait with `S_OK`: it takes the target failing in the same window. And **the request is taken
  rather than read**, by the pump, so no path can leave one standing for the next operation to be
  charged with; `run_to_address` had a line for that and `wait_for_kernel_break_in` had neither that
  nor the clear on the way in.

  `examples/deferred_arrival.rs` is the measurement #133 is held to and it is unmoved: arm A 0 short
  in 40 rounds under load, arm F 4.2 µs, arm H 5.6 µs (x64 bench, Windows 11 26200, 24 spinners).
  `examples/session_fuzz.rs` is clean over seeds 1, 2, 7 and 13. One thing #136 makes visible
  without changing: a **host's** break during a kernel attach is still reported as a clean break-in
  rather than as a timeout, because naming it wants an error of its own — stage 2's.

- `launch_process` launches with `CREATE_NO_WINDOW` instead of `CREATE_NEW_CONSOLE`, so a launched
  console target no longer opens a window on the desktop and takes the foreground with it. The
  guarantee the old flag was there for is unchanged and is what `CREATE_NO_WINDOW` also provides:
  the target gets a console of its **own**, so its prints cannot reach the launching process's
  stdout — which for an MCP host is its JSON-RPC channel. Measured with a `STARTUPINFO` carrying no
  `STARTF_USESTDHANDLES`, the shape DbgEng uses: with no flag at all the target's `echo` lands in
  the launching process's stdout, and with either console flag it does not, `bInheritHandles` either
  way. What is lost is a debuggee's console output being readable on the desktop — it was never
  captured, and a caller that wants it can redirect (`cmd.exe /c prog > file`) rather than have
  every launch open a window on the chance someone is looking. A driver launching targets
  repeatedly made the machine unusable ([#129](https://github.com/glslang/dbgscope/issues/129)).
  `test_a_launched_target_has_a_console_of_its_own_and_no_window` asserts three things: that the
  target's console is not this process's, that it *has* one (`mode con` in the target has to report
  `Status for device CON`, which is what separates this flag from `DETACHED_PROCESS`), and that it
  owns no visible window. The last is a negative, so it is calibrated against a control the test
  spawns with `CREATE_NEW_CONSOLE`; a host where that control shows no window either fails the test
  rather than skipping the check, since by then the other two have been made.

### Fixed

- A **user-mode open now waits for its own target**, rather than for one event. `launch_process`
  and `attach_process` completed on a single `WaitForEvent`, which is one event and not necessarily
  theirs: `CreateProcessWide` defers the spawn into that wait, and an engine already holding a
  target can return from it on *that* target's event instead. Measured
  (`examples/deferred_arrival.rs`, 40 rounds under CPU load): an `AttachProcess` break-in whose
  injected thread is slow to be scheduled lands a whole wait late, and the `launch_process` after
  it spends its only wait on that break — returning `Ok` with its process absent from the session,
  3 times in 40, and 0 in 40 on a quiet machine. `PendingTarget::wait` now pumps until the event it
  stopped on belongs to the process the open created or claimed, within the same `LIVE_WAIT_MS`
  bound for the whole open; the event is queued rather than lost, so it arrived on the very next
  wait every time it was observed. **Membership in the session is not the terminal condition** —
  `cpr` is an ignored filter, so a process is registered when its create event is processed and its
  initial breakpoint arrives later, and a competing break in between would leave the open's process
  listed but not where the open promised to leave it — so the pump waits for the process to have
  **stopped**. That is read from a record the engine keeps (`stopped_on`, written by both waits
  from `GetLastEventInformation`, by engine id, which
  `test_the_last_event_names_its_process_by_engine_id` pins against `session_processes`) rather
  than from that call in the moment: it is a single session-wide slot every later event
  overwrites, so read directly it answers the same way for a target still coming and for one that
  stopped before its guard was waited on. A wait that cannot evaluate its own postcondition — a
  snapshot that would not read, a status or process list that would not answer — returns as it did
  before, and only a process demonstrably not in the session by the bound answers the new
  `DbgEngError::LiveTargetTimeout`; one that is there but was never seen to stop ends the wait
  `Ok`, because "not observed to stop" is not "never arrived". A session holding *nothing* is
  absence rather than a question that could not be put, which is a mapping and not a road: a wait
  with no debuggee fails (`E_UNEXPECTED`, 200µs) instead of expiring, so an open never reaches its
  bound holding nothing — measured, and pinned alongside the mapping so that an engine which
  starts expiring instead fails a test rather than a caller. The record is cleared when the session
  is replaced *and* when it is ended, since the next session hands engine ids out from zero again
  — two `attach_process` calls to one pid on one engine would otherwise have the second inherit
  the first's answer. With the fix, 0 short in 40 rounds under the same load. Reported as
  [dbgscope#128](https://github.com/glslang/dbgscope/issues/128), where it had been failing
  `test_a_mixed_session_comes_apart_by_where_each_process_came_from` on CI's coverage job.
- **`run_to_address` no longer leaves its watchdog's interrupt raised.** It was the one bounded
  path that neither cleared the shared flag when it began nor consumed it when it ended, which
  cost it nothing of its own -- it classifies by the watchdog's private flag -- and cost everything
  else once the arrival record began reading the shared one: a single timed-out run left every
  later wait declining to record a real initial break, and any live open still held pumping to its
  bound for a target that had already stopped. All five paths that pump now clear on the way in,
  and this one consumes on the way out.
- **A live open a host interrupts now ends, instead of pumping through the break.** New:
  `DbgEngError::LiveTargetInterrupted`. The pumping this release introduces made an interrupt
  something the open ignored -- before it, a live open was a single `WaitForEvent`, so the break
  ended the wait and `wait()` returned. What that costs is not only the caller's time: measured
  with the check backed out, an interrupted open spends the whole 30s bound and answers
  `CommandFailed(0x8000FFFF)`, because the pumping let the debuggee run to completion and left no
  session to ask. The ending is the same rule the bound uses -- a process visibly in the session
  ends the wait `Ok` -- except that a process which is not there is reported as interrupted rather
  than as a timeout the open never reached, since a timeout says the target is not coming and this
  says nothing about the target at all.
- **A break nobody's target asked for is not an arrival, whichever origin raised it and whichever
  wait took it.** The watchdog's deadline and a host's `InterruptHandle` reach the engine through
  the same `SetInterrupt` and produce the same stop; only the advice differs, which is what
  `Interruption`'s two variants are for. Recording it lets a guard report an initial-break wait
  that never happened, because a Ctrl+Break stops whatever was running -- in a mixed session, a
  deferred target that has not reached its loader breakpoint. This arrived as three review rounds,
  one door at a time: the watchdog on the bounded wait, then a host on the bounded wait, then a
  host on the finite wait -- which is the one a live open pumps with, so the false arrival reaches
  the guard directly. The rule is therefore inside `note_where_it_stopped` and not at its call
  sites: both origins raise the same flag, so one question covers every wait in the crate and a
  new one cannot forget it. It reads the flag rather than consuming it, since the callers still
  need it to say which origin asked, and `wait_for_live_target` now clears it when an open begins
  -- the line `execute_and_wait` and `settle` already carry, without which a stale flag would
  leave an open pumping to its bound for an answer it had.
- **A process that leaves a session takes its recorded stop with it.** `stopped_on` is keyed by
  `(engine id, pid)`, and engine ids are reused immediately -- measured: detaching engine id 0 and
  attaching another process hands the freed 0 straight back. So a session that `.detach`es one of
  its processes through the raw hatch and attaches to the same pid again gets the whole pair back,
  and `presence_of` would answer `Arrived` for a target whose initial breakpoint had not happened.
  Pruned alongside the attach record it sits beside, at the two openers, which is the only cadence
  it needs: nothing reads either record outside an open. `prune_dead_attachments` is
  `prune_processes_that_left`, since it no longer prunes only attachments.
- **A wait that stopped on nothing no longer records a stop.** `stopped_on` is written as each
  wait observes a stop, and two kinds of wait come back having observed none. A **watchdog-forced**
  Ctrl+Break was being recorded, which `wait_for_event_bounded` documents as something callers must
  not treat as a normal completion: it stops whatever was running, so an `execute_and_wait` or
  `run_to_address` pumping a mixed session could stop a deferred target before its initial
  breakpoint and leave that target's still-held guard reporting an initial-break wait that never
  happened. The other is an **expiry**, which `WaitForEvent` reports as `S_FALSE` and the generated
  wrapper flattens into the same `Ok` a stop gets; that one was never reaching the record, because
  an expired wait leaves `GetLastEventInformation` reporting `DEBUG_ANY_ID` rather than the event
  before it -- measured, and so the safety rested on an undocumented sentinel in the one function a
  guard trusts to end its wait early. Both are now gated, the expiry by reading the raw `HRESULT`
  through the vtable as `interrupted` already does, and the sentinel is pinned so that an engine
  which stops supplying it fails a test rather than an open.
- **What a teardown lets go of now turns on `EndSession`'s own outcome**, not on the value
  `end_session` returns. The two differ exactly when a detach fails: `end_session` reports that
  failure to its caller, and rightly, but a process this engine could not detach from is one left
  attached and running — it does not keep the session alive. Gating on the combined result held
  back both things the session owns on a session that had definitely gone: the deferred input
  buffers, where the cost is a leak, and the record of which processes this engine stopped on,
  where the cost is the stale entry the previous entry is about, reached by a second road. Found by
  review rather than by a test, and it stays that way: the split cannot be staged, because the
  detach loop *skips* a process the engine no longer lists rather than failing on it.
- A `PendingTarget` **waited after something else pumped its target in** no longer waits for the
  next event. The guard's own docs describe dropping one and letting the target materialize at the
  next `WaitForEvent` from any source; a guard still held when that happened made its wait anyway,
  which resumes an arrived target and waits out whatever comes next. Measured across the fix:
  **29.36s and `E_UNEXPECTED`** — the debuggee outran the bound and took the session with it —
  against **8.6µs and `Ok`**. Neither opener lists its process before the wait that completes it
  (measured), so the ordinary open still waits exactly once. The same measurement with a *second*
  target arrived since — which overwrites the one slot recording where the engine stopped — is
  29.4s and `E_UNEXPECTED` when the ask reads that slot against single-digit µs when it reads the
  record, and is the argument for `stopped_on` existing at all.
- `a_watchdog_disarmed_before_its_deadline_costs_nothing` measured the machine rather than the
  watchdog, and failed on the coverage job of a docs-only PR. Three things were wrong with it, and
  the first meant it was not testing the property at all: armed and disarmed back to back, the
  watchdog's thread usually had not run yet, so it saw the flag at the top of its loop and returned
  without ever reaching a wait — **the test passed with the condvar reverted**. The timing is now
  taken on a watchdog whose deadline has passed, after its own counter says it fired, so the parked
  thread is a **reading rather than an assumption** (a fixed sleep only makes an unparked thread
  unlikely, and a runner slow enough to matter is where that assumption fails). It bounds the
  disarm by `WATCHDOG_REPEAT` — the poll interval the condvar replaced — halved, rather than by an
  absolute 50ms, and takes the **median** of five rounds: the maximum measures the machine, and the
  minimum lets one stray round excuse a regression. The never-fires half is asserted separately, on
  a watchdog 30s from its deadline, where no handshake is available. Checked both ways: 0.13s
  green, and red against the reverted condvar with all five rounds at 177-182ms.
- `BreakpointInfo::expression`'s documentation described only what `bp` does. A breakpoint whose
  location was set through `SetOffsetExpression` **keeps** its expression beside a resolved address,
  where one set by `bp` has the text discarded once it resolves — so `None` there is not the
  universal case for a live breakpoint. `deferred` is the field that answers whether a breakpoint
  has an address yet.
- `breakpoints()` reads through `GetBreakpointByIndex2`, putting the whole breakpoint path on
  `IDebugBreakpoint2` rather than mixing the two interface versions.
- `examples/session_fuzz.rs` no longer forces its seed odd, which had silently halved what
  `--seed` can name: `Rng::new` did `seed | 1`, so `42` and `43` were one run and `6` and `7` were
  one run. The flag exists so a failing sequence can be reproduced and then *varied*, and a seed
  that aliases another looks like a new sequence while covering nothing new. The forbidden state
  for xorshift64* is zero rather than "even", so that is now the only case handled, and the
  clock-derived default is taken as it comes instead of being forced odd as well. Measured over
  the first 512 seeds, ten corpus draws each: **256** distinct walks before, **512** after. Seeds
  that were already odd — including the `1` this example's notes are written against — walk
  exactly what they walked. Found downstream in
  [windbg-mcp#268](https://github.com/glslang/windbg-mcp/pull/268), which ported this example to
  drive that server's tool surface, where the seed is a small integer someone types while
  scanning.

### Added

- Pool tag queries accept an optional nonzero match threshold. A new walk stops immediately after
  that many in-scope allocated chunks, reports the fired threshold separately from deadline and
  diagnostic truncation, and never caches the intentionally partial snapshot. A complete cached
  snapshot still answers exhaustively without being discarded.

### Added

- `DebugEngine::current_thread_system_id` and `DebugEngine::current_processor` — which thread the
  engine's answers are about, and which of a kernel target's processors it is on. Typed rather
  than parsed out of `~.`, whose text is one shape for a user-mode thread, another for a kernel
  processor, and a third when there is no thread context at all. `current_processor` answers
  `None` for *no processor number applies here* — a user-mode target, a dump of one and a TTD trace,
  by construction — and it is not an answer about the register context, since `.thread` and `.trap`
  change what the debugger displays without changing which processor it is stopped on. It resolves
  through `GetThreadIdByProcessor` rather
  than reading the current thread index as a processor number, so nothing is inferred about the
  mapping it is asking about — the index is tried first, and confirmed by that same call, so the
  ordinary case costs one call rather than one per processor. A lookup that **fails** is not a
  processor that does not match: a match wins whatever else failed, and no match with a failure
  among the lookups is an `Err` rather than an `Ok(None)` that would report absence where the truth
  is unknown. Exercised beside `~.` in `examples/typed_context.rs`.

## [0.1.0] - 2026-08-29

First release. `dbgscope` gives typed access to a WinDbg/DbgEng debug session, and kernel-pool
and user-heap walkers built on one. The organising rule, and the thing to know before reading
the API, is that every answer carries what the answering cost — see
[Unknown, not absent](docs/unknown-not-absent.md).

### Added — debug sessions

- `DebugEngine` over `IDebugClient6` / `IDebugControl4` / `IDebugDataSpaces4` /
  `IDebugSymbols3`, owning its own session (`new`, `Default`) or borrowing an existing WinDbg
  client (`from_windbg_client`, `from_client_interface`, and their `try_` forms). `owns_session`
  governs teardown, so a borrowed client is never ended.
- Openers for every target DbgEng handles: `attach_kernel`, `attach_local_kernel`,
  `launch_process`, `attach_process`, `open_dump`, `open_trace`. The two post-mortem openers
  commit the session and leave the pump to the caller: the engine has no current process or
  thread — and `GetNumberRegisters` answers `0x8000FFFF` — until `wait_for_event` has run.
- `connect(remote_options)` for an existing debugging server, so an extension can load out of
  process.
- **Two-step opening** on the four *live* openers, each a thin `x_begin()?.wait()`. `x_begin`
  performs only the side effect that creates or claims the target and returns a `PendingTarget`;
  `wait` completes the initial break. The split lets a caller distinguish "nothing happened,
  retry is clean" from "the target exists and only the wait failed" — opposite recoveries, since
  re-running the second spawns a second process, attaches twice, or re-dials a live KD link.
  Dropping a guard is safe and non-blocking: deferred input buffers are parked on the engine
  rather than the guard, because `CreateProcessWide` reads the command line at the *next*
  `WaitForEvent`.
- **Per-process teardown.** DbgEng holds several user-mode targets at once and `EndSession`
  takes one flag for the whole session, so provenance is recorded per pid at open time. A
  process this engine *attached* to is detached individually before the session ends — otherwise
  a passive end kills somebody else's service. A live kernel is resumed and actively detached,
  or it stays frozen at its last break with one CPU halted. Failures are per process and
  reported without stopping the teardown.
- `launch_process` uses `DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE`, so a console target
  cannot inherit a host's stdout — which may be a JSON-RPC channel.

### Added — execution control

- `execute_command_bounded`, `execute_and_wait`, `settle` and `run_to_address`: bounded waits
  with a condition-variable watchdog behind them. The watchdog stops the moment it is disarmed
  rather than at the end of a poll interval, so a bound costs nothing until it is reached.
- `CommandRun { output, cut_short, target_gone }` — the output *and* whether the command
  finished. A `String` alone cannot answer "did this run?", and an `Err` would discard the
  output, which on an interrupted search is all there was.
- `Interruption::Deadline { after_ms }` distinguished from `Interruption::OnRequest`, because
  the advice differs and only the first needs saying. The origin is decided by the watchdog's
  own flag, not by the shared interrupt bit that the watchdog also sets.
- `RunToOutcome` names four endings — `Hit`, `StoppedElsewhere { stopped_at }`, `Timeout`,
  `TargetGone` — rather than a boolean.
- `InterruptHandle`: a `Send + Sync` handle that Ctrl+Breaks an engine from another thread, over
  `SetInterrupt`, the one DbgEng call documented as safe there. It holds an owned interface
  reference, so it may outlive the `DebugEngine` it came from.
- **A target that ends is an ending, not a failure.** A debuggee running to completion is
  reported as `CommandRun::target_gone` / `RunToOutcome::TargetGone`, each keeping the output the
  run captured — the module loads, the breakpoint banner, an embedded script's prints, none of
  which a successor will print again. It is terminal, and callers are told so.
- **Nothing runs on an engine with no debuggee.** Driving DbgEng without a target faults inside
  it with a `STATUS_ACCESS_VIOLATION` that `catch_unwind` cannot trap, so `execute_command`,
  `execute_command_bounded`, `execute_and_wait` and `run_to_address` all refuse first.

### Added — typed session state

- `register_values` returning `RegisterValue`, decoded once from `DEBUG_VALUE`'s own tag:
  `Int`, `Float`, `Bytes` for x87 and vector registers that no `f64` can hold, and
  `Unavailable` for state a minidump does not carry — which is not `0`.
- `register_descriptions` for the whole register description rather than one flag of it.
- `modules`, `unloaded_modules`, `module`, `module_at`, `module_identity`, `module_pdb`,
  `module_symbol_file`. `SymbolKind` keeps `Deferred` separate from `None` and preserves an
  unrecognised provider as `Other(u32)`; `has_type_info()` answers the narrow question the pool
  walker actually asks.
- `stack_frames`, `bug_check` as the engine's five values, `breakpoints` as `BreakpointInfo`,
  `disassemble` as `Instruction` records with a line the split does not recognise kept whole
  rather than guessed at.
- Scope save and restore: `scope`, `set_scope`, `scope_guard` and the `ScopeGuard` RAII type,
  for running a command that moves the debugger's scope — measured: `!analyze -v` discards a
  frame or `.ecxr` context the caller had selected. A `Scope` carries the target identity it was
  read from and is refused rather than applied to a later target.
- Memory and symbols: `read_memory`, `valid_virtual_region`, `symbol_offset`, `type_id`,
  `type_size`, `field_offset`, `field_type_and_offset`, `field_names`, `set_symbol_path`,
  `append_symbol_path`, `reload_symbols`.
- Breakpoints: the `Breakpoint<'a>` RAII type, `BreakpointCallback`, and
  `DebugEventContextCallbacks` for event-driven handling.

### Added — kernel pool

- `pool::query`: `find_tag`, `chunk_at` with immediate neighbours, `tag_census`,
  `snapshot_report`, and cache invalidation hooks for a host that resumes or replaces a target.
- `PoolAnswer<T>` pairs every answer with the `PoolSnapshotReport` of the walk it came from, so
  a count and a coverage figure can never be drawn from two different walks — which is what
  happens otherwise, since an incomplete walk is deliberately not cached.
- `WalkCoverage { Complete, BudgetExpired, Partial }`, computed in one place from the walk's own
  two bits. Not a `bool`, because a walk that ran out of time reaches more of the pool if given
  more, and one that met unreadable regions reports the same gaps however long it runs.
- `PoolWalk` with `cached()`, `refreshed()`, `within(Duration)` and `unbounded()`, plus
  `impl From<bool>` so existing `refresh: bool` call sites are unchanged and pick up
  `DEFAULT_WALK_BUDGET` (120s). A walk that runs out of its budget is not an error: it returns
  the chunks it reached with the coverage saying so.
- `PoolDiagnostics` groups complaints by shape — the message with every number standing in for
  itself — keeping `DIAGNOSTIC_EXAMPLES` (8) verbatim per shape and the totals as numbers.
  `emitted()` describes the walk; `examples().len()` describes the struct, and on a busy target
  the two differ by two orders of magnitude.
- `WalkStalls`, `refused_chunks` and `unplaced_bytes` size what conservative decoding cost, so a
  refusal to guess is auditable rather than invisible.
- Both tag forms: one to four ASCII bytes, or the raw form `0x` plus eight hex digits in memory
  order, so it reads in the same direction as the printed tag (`Tgsm` is `0x5467736d`). The two
  cannot collide — the raw form is exactly ten characters and a printed tag at most four.
  `display_is_ambiguous` and `display_round_trips` separate the two distinct ways a rendering
  fails, and `tag_label` is the one rule every output site prints through.
- `PoolKind`'s eight variants are not collapsed to paged/nonpaged, because crossing one of those
  boundaries creates false holes. `PoolState::Unreadable` is distinct from allocated and from
  the two free states, and `chunk_at` returns `Ok(None)` for "not covered by the snapshot",
  which is a different answer from "it is a free hole".
- `find_tag` indexes allocated chunks only: a freed chunk's tag is not reliably preserved by the
  allocator, so returning freed chunks by tag would be inventing information.

### Added — user-mode Segment Heap

- `heap`: `list`, `allocations`, `chunk_at`, `census`, `diagnostics`, `diagnostics_for_heap`,
  with `HeapWalk` mirroring `PoolWalk` and `HeapAnswer<T>` mirroring `PoolAnswer<T>`.
- `HeapScope` names the roots that were skipped and why — `nt_heaps_skipped`,
  `unknown_heaps_skipped`, `unreadable_heaps_skipped` — rather than reporting only the ones that
  worked.
- Shared page-segment, LFH, VS, backend and large-allocation decoding with the pool walker,
  because the two allocators are the same machinery either side of the ring boundary.
- `allocator::LayoutProvenance` carries the image, PDB and a fingerprint of every resolved type
  size and field offset actually used — deliberately with no build-number policy in it.
- `requested_size` is `Option<u64>`, set only where allocator metadata validates it, rather than
  guessed from capacity.

### Added — WinDbg extension

- `!dbgscope.poolmap`, built from the `cdylib` crate type, over the same walker and the same
  caches as `pool::query`, so the interactive and programmatic entry points cannot drift apart.
- `-tag` (either form), `-paged` / `-nonpaged`, `-refresh`, and an address argument for detail
  on the allocation or hole containing it.
- DML colours and clickable address links where WinDbg accepts DML; meaningful ASCII glyphs and
  a legend where it is stripped or the output is captured as plain text.
- The extension lets a walk run to completion, because there is an operator at a prompt who can
  Ctrl+Break. `pool::query` cannot assume anyone is watching the clock, which is why its walks
  carry a budget — and a host that *is* watching can cancel one through `interrupt_handle()`,
  which the walk polls and reports as `PoolQueryError::Interrupted`.

### Known limitations

- **Windows only.** The public surface calls Windows APIs with no `#[cfg]` gating; the crate is
  not designed to build elsewhere. docs.rs is configured for the MSVC targets accordingly.
- **Pool walking is x64 only**, because the allocator encodings it consults are. The rest of the
  crate builds for ARM64, and CI covers both.
- **Windows 10 19H1 or later** allocator algorithms, and full private type information for `nt`.
  Symbols must be on the debugger host — PDBs are never fetched from a target over KD — and
  resolving them needs `msdia140.dll` beside the engine. Without it, a kernel dump presents not
  as missing symbols but as memory reads failing.
- **A live-kernel walk is normally incomplete.** Paged pool is partly on disk, and a page the
  memory manager has paged out cannot be read through the debugger either.
- **`KERNEL_ATTACH_WAIT_MS` bounds less than it looks like.** The watchdog works by
  `SetInterrupt`, which only reaches a target that has *connected*, so it caps a
  connected-but-unresponsive target and nothing else. One that never dials in — powered off,
  wrong key, not booted with `bcdedit /debug on` — blocks past the bound indefinitely.
- **Snapshots are snapshots.** The walkers examine current allocations, reusable frees and
  cached/delay-free spans while the target is stopped. They install no allocation breakpoints
  and reconstruct no history.
- **Per-session paged heaps** are outside the initial pool-map scope, and the command says so.
- **Pre-1.0.** The `dbgeng` surface is large and expected to change; breaking changes may land
  in any `0.x` release.

[Unreleased]: https://github.com/glslang/dbgscope/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/glslang/dbgscope/releases/tag/v0.2.0
[0.1.0]: https://github.com/glslang/dbgscope/releases/tag/v0.1.0
