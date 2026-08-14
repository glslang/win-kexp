//! Opt-in live x64 smoke helper for the typed user Segment Heap walker.
//!
//! `cargo run --example user_heap_smoke` launches a child under DbgEng. The child creates a
//! Segment Heap and allocations spanning the usual size regimes, then breaks in; the controller
//! lists roots and verifies that every returned pointer is covered. This requires DbgEng and the
//! matching `ntdll` PDB. Set `WIN_KEXP_USER_HEAP_SYMBOLS` to a WinDbg symbol path such as
//! `srv*C:\ProgramData\dbg\sym*https://msdl.microsoft.com/download/symbols`; when it is unset,
//! the helper uses `_NT_SYMBOL_PATH` and then that public-server path.

use std::ffi::CString;
use std::hint::black_box;
use std::time::Duration;

use win_kexp::dbgeng::DebugEngine;
use win_kexp::heap::{self, HeapAllocation, HeapBackend, HeapKind, HeapWalk};
use windows::Win32::System::Diagnostics::Debug::{DebugBreak, OutputDebugStringA};
use windows::Win32::System::Memory::{HEAP_FLAGS, HeapAlloc, HeapCreate};
use windows::core::PCSTR;

const SEGMENT_HEAP_FLAG: HEAP_FLAGS = HEAP_FLAGS(0x100);

fn target() {
    let heap = unsafe { HeapCreate(SEGMENT_HEAP_FLAG, 0, 0) }.expect("create Segment Heap");
    let mut keep_alive = Vec::new();
    // Exercise the 0x20 bucket until it transitions to LFH, then retain the last slot as the
    // LFH witness. The other sizes exercise the three progressively larger paths.
    for _ in 0..32 {
        let pointer = unsafe { HeapAlloc(heap, HEAP_FLAGS(0), 0x20) } as u64;
        assert_ne!(pointer, 0, "allocate 0x20");
        keep_alive.push(pointer);
    }
    let mut allocations = vec![("lfh", *keep_alive.last().unwrap())];
    allocations.extend(
        [("vs", 0x400usize), ("segment", 0x4000), ("large", 0x20_000)]
            .into_iter()
            .map(|(backend, size)| {
                let pointer = unsafe { HeapAlloc(heap, HEAP_FLAGS(0), size) } as u64;
                assert_ne!(pointer, 0, "allocate {size:#x}");
                keep_alive.push(pointer);
                (backend, pointer)
            }),
    );
    // A debugger captures OutputDebugString without needing to inherit the target's console.
    let message = CString::new(format!(
        "WIN_KEXP_HEAP={:#x} ALLOCS={}\n",
        heap.0 as usize,
        allocations
            .iter()
            .map(|(backend, pointer)| format!("{backend}:{pointer:#x}"))
            .collect::<Vec<_>>()
            .join(",")
    ))
    .unwrap();
    unsafe { OutputDebugStringA(PCSTR(message.as_ptr().cast())) };
    black_box((&heap, &keep_alive));
    unsafe { DebugBreak() };
    std::thread::sleep(Duration::from_secs(30));
}

fn expected(output: &str) -> (u64, Vec<(HeapBackend, u64)>) {
    let marker = output
        .lines()
        .find_map(|line| line.split_once("WIN_KEXP_HEAP=").map(|(_, tail)| tail))
        .expect("the target emitted no heap witness");
    let (heap, allocations) = marker
        .split_once(" ALLOCS=")
        .expect("malformed heap witness");
    let parse_hex = |value: &str| {
        u64::from_str_radix(value.trim().trim_start_matches("0x"), 16)
            .expect("malformed witness address")
    };
    let allocations = allocations
        .trim()
        .split(',')
        .map(|entry| {
            let (backend, address) = entry.split_once(':').expect("malformed allocation witness");
            let backend = match backend {
                "lfh" => HeapBackend::Lfh,
                "vs" => HeapBackend::Vs,
                "segment" => HeapBackend::Segment,
                "large" => HeapBackend::Large,
                other => panic!("unknown witness backend {other}"),
            };
            (backend, parse_hex(address))
        })
        .collect();
    (parse_hex(heap), allocations)
}

fn verify(heap: u64, expected: &[(HeapBackend, u64)], allocations: &[HeapAllocation], phase: &str) {
    for &(backend, pointer) in expected {
        let allocation = allocations
            .iter()
            .find(|allocation| allocation.heap == heap && allocation.contains(pointer))
            .unwrap_or_else(|| panic!("{phase}: pointer {pointer:#x} is not covered"));
        assert_eq!(
            allocation.backend, backend,
            "{phase}: pointer {pointer:#x} used an unexpected backend"
        );
    }
}

fn load_ntdll_symbols(engine: &DebugEngine) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("{}", engine.execute_command(".reload /f ntdll.dll")?);
    eprintln!("{}", engine.execute_command("lm m ntdll")?);
    Ok(())
}

fn controller() -> Result<(), Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let engine = DebugEngine::new();
    let symbol_path = std::env::var("WIN_KEXP_USER_HEAP_SYMBOLS")
        .or_else(|_| std::env::var("_NT_SYMBOL_PATH"))
        .unwrap_or_else(|_| {
            "srv*C:\\ProgramData\\dbg\\sym*https://msdl.microsoft.com/download/symbols".into()
        });
    engine.set_symbol_path(&symbol_path)?;
    engine.launch_process(&format!("\"{}\" --target", executable.display()))?;
    let run = engine.execute_and_wait("g", 30_000)?;
    eprintln!("{}", run.output);
    let (heap, witnesses) = expected(&run.output);
    load_ntdll_symbols(&engine)?;
    let listed = heap::list(
        &engine,
        HeapWalk::refreshed().within(Duration::from_secs(30)),
    )?;
    assert!(
        listed
            .found
            .iter()
            .any(|root| root.kind == HeapKind::Segment),
        "the child created no detected Segment Heap: {:?}",
        listed.found
    );
    let allocations = heap::allocations(&engine, HeapWalk::cached())?;
    verify(heap, &witnesses, &allocations.found, "live target");
    eprintln!(
        "{} roots, {} chunks, coverage {:?}, layout {} ({})",
        listed.found.len(),
        allocations.found.len(),
        allocations.walk.coverage,
        allocations.layout.fingerprint,
        allocations.layout.semantic_family.as_str()
    );

    let dump = std::env::temp_dir().join(format!("win-kexp-user-heap-{}.dmp", std::process::id()));
    engine.execute_command(&format!(".dump /ma \"{}\"", dump.display()))?;
    engine.end_session()?;
    heap::invalidate_caches();
    engine.open_dump(&dump.display().to_string())?;
    engine.wait_for_event(30_000)?;
    load_ntdll_symbols(&engine)?;
    let from_dump = heap::allocations(
        &engine,
        HeapWalk::refreshed().within(Duration::from_secs(30)),
    )?;
    verify(heap, &witnesses, &from_dump.found, "full-memory dump");
    engine.end_session()?;
    std::fs::remove_file(&dump)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|argument| argument == "--target") {
        target();
        Ok(())
    } else {
        controller()
    }
}
