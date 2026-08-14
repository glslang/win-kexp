//! Typed, version-aware queries over user-mode Segment Heaps.
//!
//! Root discovery is user-specific (PEB and `ntdll`); page-segment, LFH, VS, backend, and
//! large-allocation decoding is shared with the kernel-pool walker.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use thiserror::Error;
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_STATUS_BREAK, DEBUG_STATUS_NO_DEBUGGEE,
};

use crate::allocator::LayoutProvenance;
use crate::dbgeng::{DbgEngError, DebugEngine, KernelImage};
use crate::pool::layout::{LayoutKey, PoolLayout};
use crate::pool::query::WalkCoverage;
use crate::pool::snapshot::{PoolSnapshot, SnapshotError, walk_user_segment_heaps};
use crate::pool::{DiagnosticShape, PoolBackend, PoolState, WalkStalls};

const IMAGE_FILE_MACHINE_AMD64: u32 = 0x8664;
const SEGMENT_HEAP_SIGNATURE: u32 = 0xddee_ddee;
const NT_HEAP_SIGNATURE: u32 = 0xeeff_eeff;
const MAX_PROCESS_HEAPS: usize = 4096;
pub const DEFAULT_WALK_BUDGET: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeapWalk {
    pub refresh: bool,
    pub budget: Option<Duration>,
}

impl HeapWalk {
    pub fn cached() -> Self {
        Self {
            refresh: false,
            budget: Some(DEFAULT_WALK_BUDGET),
        }
    }

    pub fn refreshed() -> Self {
        Self {
            refresh: true,
            ..Self::cached()
        }
    }

    pub fn within(self, budget: Duration) -> Self {
        Self {
            budget: Some(budget),
            ..self
        }
    }
}

impl From<bool> for HeapWalk {
    fn from(refresh: bool) -> Self {
        if refresh {
            Self::refreshed()
        } else {
            Self::cached()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HeapKind {
    Segment,
    Nt,
    Unknown,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapRoot {
    pub index: usize,
    pub address: u64,
    pub kind: HeapKind,
    pub supported: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HeapBackend {
    Lfh,
    Vs,
    Segment,
    Large,
}

impl From<PoolBackend> for HeapBackend {
    fn from(value: PoolBackend) -> Self {
        match value {
            PoolBackend::Lfh => Self::Lfh,
            PoolBackend::Vs => Self::Vs,
            PoolBackend::Segment => Self::Segment,
            PoolBackend::Large => Self::Large,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HeapState {
    Allocated,
    ReusableFree,
    CachedFree,
    Unreadable,
}

impl From<PoolState> for HeapState {
    fn from(value: PoolState) -> Self {
        match value {
            PoolState::Allocated => Self::Allocated,
            PoolState::ReusableFree => Self::ReusableFree,
            PoolState::CachedFree => Self::CachedFree,
            PoolState::Unreadable => Self::Unreadable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapAllocation {
    pub heap: u64,
    pub backend: HeapBackend,
    pub state: HeapState,
    pub header_address: u64,
    pub user_address: u64,
    pub capacity: u64,
    /// Exact only when the selected schema validates the allocator's unused-byte metadata.
    pub requested_size: Option<u64>,
    pub subsegment: Option<u64>,
    pub size_class: u32,
}

impl HeapAllocation {
    pub fn end(&self) -> u64 {
        self.user_address.saturating_add(self.capacity)
    }

    pub fn contains(&self, address: u64) -> bool {
        address >= self.header_address && address < self.end()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeapScope {
    pub segment_heaps_walked: Vec<u64>,
    pub nt_heaps_skipped: Vec<u64>,
    pub unknown_heaps_skipped: Vec<u64>,
    pub unreadable_heaps_skipped: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapWalkReport {
    pub coverage: WalkCoverage,
    pub total_chunks: usize,
    pub allocated_chunks: usize,
    pub diagnostic_count: usize,
    pub unreadable_gaps: usize,
    pub refused_headers: u64,
    pub stalls: WalkStalls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapDiagnosticReport {
    pub categories: Vec<DiagnosticShape>,
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapNeighbourhood {
    pub allocation: HeapAllocation,
    /// Signed displacement from `user_address`; addresses in the allocator header are negative.
    pub offset: i64,
    pub previous: Option<HeapAllocation>,
    pub next: Option<HeapAllocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HeapCensusRow {
    pub heap: u64,
    pub backend: HeapBackend,
    pub state: HeapState,
    pub size_class: u32,
    pub chunks: usize,
    pub total_capacity: u64,
}

#[derive(Debug, Clone)]
pub struct HeapAnswer<T> {
    pub found: T,
    pub layout: LayoutProvenance,
    pub scope: HeapScope,
    pub walk: HeapWalkReport,
}

#[derive(Debug, Error)]
pub enum HeapQueryError {
    #[error("heap queries require a user-mode target")]
    NotUserTarget,
    #[error("no debuggee is loaded")]
    NoDebuggee,
    #[error("the target is running; break in before walking heaps")]
    TargetRunning,
    #[error("heap walking supports x64 targets only (machine {machine:#x})")]
    UnsupportedArchitecture { machine: u32 },
    #[error("invalid PEB heap metadata: {0}")]
    InvalidPeb(String),
    #[error(
        "missing or unsupported ntdll allocator layout ({0}); run `.reload /f ntdll.dll` and retry"
    )]
    Layout(String),
    #[error("the heap walk was interrupted on request")]
    Interrupted,
    #[error("walking the heap failed: {0}")]
    Walk(String),
    #[error(transparent)]
    Engine(#[from] DbgEngError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SnapshotKey {
    target: u64,
    peb: u64,
    image: KernelImage,
    generation: u64,
}

#[derive(Debug, Clone)]
struct HeapSnapshot {
    roots: Vec<HeapRoot>,
    allocations: Vec<HeapAllocation>,
    layout: LayoutProvenance,
    scope: HeapScope,
    walk: HeapWalkReport,
    diagnostics: HeapDiagnosticReport,
}

#[derive(Default)]
struct SnapshotCache {
    entry: Mutex<Option<(SnapshotKey, HeapSnapshot)>>,
}

impl SnapshotCache {
    fn get(&self, key: SnapshotKey) -> Option<HeapSnapshot> {
        self.entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .filter(|(cached, _)| *cached == key)
            .map(|(_, snapshot)| snapshot.clone())
    }

    fn put(&self, key: SnapshotKey, snapshot: HeapSnapshot) {
        *self
            .entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((key, snapshot));
    }

    fn invalidate(&self) {
        *self
            .entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

fn snapshots() -> &'static SnapshotCache {
    static CACHE: OnceLock<SnapshotCache> = OnceLock::new();
    CACHE.get_or_init(SnapshotCache::default)
}

#[derive(Default)]
struct UserLayoutCache {
    entries: Mutex<HashMap<LayoutKey, PoolLayout>>,
}

impl UserLayoutCache {
    fn global() -> &'static Self {
        static CACHE: OnceLock<UserLayoutCache> = OnceLock::new();
        CACHE.get_or_init(UserLayoutCache::default)
    }

    fn get_or_resolve(
        &self,
        engine: &DebugEngine,
        key: LayoutKey,
    ) -> Result<PoolLayout, HeapQueryError> {
        if let Some(layout) = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .cloned()
        {
            return Ok(layout);
        }
        let layout = PoolLayout::resolve_user(engine, key)
            .map_err(|error| HeapQueryError::Layout(error.to_string()))?;
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, layout.clone());
        Ok(layout)
    }

    fn invalidate(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

/// Drop the user-heap snapshot while retaining the image-keyed `ntdll` schema.
pub fn invalidate_snapshot() {
    snapshots().invalidate();
}

/// Drop every user-heap snapshot and resolved `ntdll` schema.
pub fn invalidate_caches() {
    invalidate_snapshot();
    UserLayoutCache::global().invalidate();
}

fn read_u32(engine: &DebugEngine, address: u64) -> Result<u32, DbgEngError> {
    Ok(u32::from_le_bytes(
        engine.read_memory(address, 4)?.try_into().unwrap(),
    ))
}

fn read_u64(engine: &DebugEngine, address: u64) -> Result<u64, DbgEngError> {
    Ok(u64::from_le_bytes(
        engine.read_memory(address, 8)?.try_into().unwrap(),
    ))
}

fn user_pointer(address: u64) -> bool {
    (0x1_0000..0x0000_8000_0000_0000).contains(&address)
}

fn classify_root(
    segment: Result<u32, String>,
    nt: Result<u32, String>,
) -> (HeapKind, Option<String>) {
    match (segment, nt) {
        (Ok(SEGMENT_HEAP_SIGNATURE), Ok(NT_HEAP_SIGNATURE)) => (
            HeapKind::Unknown,
            Some("root ambiguously matches both Segment and NT heap signatures".into()),
        ),
        (Ok(SEGMENT_HEAP_SIGNATURE), _) => (HeapKind::Segment, None),
        (_, Ok(NT_HEAP_SIGNATURE)) => (
            HeapKind::Nt,
            Some("classic NT heap decoding is outside the v1 Segment Heap walker".into()),
        ),
        (Err(segment), Err(nt)) => (
            HeapKind::Unreadable,
            Some(format!(
                "cannot read Segment signature ({segment}) or NT signature ({nt})"
            )),
        ),
        _ => (
            HeapKind::Unknown,
            Some("root matches neither the PDB-resolved Segment nor NT heap signature".into()),
        ),
    }
}

fn enumerate_roots(
    engine: &DebugEngine,
    layout: &PoolLayout,
    peb: u64,
) -> Result<Vec<HeapRoot>, HeapQueryError> {
    let count = read_u32(
        engine,
        peb + layout
            .field("_PEB", "NumberOfHeaps")
            .map_err(|error| HeapQueryError::Layout(error.to_string()))? as u64,
    )? as usize;
    if count > MAX_PROCESS_HEAPS {
        return Err(HeapQueryError::InvalidPeb(format!(
            "NumberOfHeaps is {count}, maximum is {MAX_PROCESS_HEAPS}"
        )));
    }
    let array = read_u64(
        engine,
        peb + layout
            .field("_PEB", "ProcessHeaps")
            .map_err(|error| HeapQueryError::Layout(error.to_string()))? as u64,
    )?;
    if count != 0 && array == 0 {
        return Err(HeapQueryError::InvalidPeb(
            "ProcessHeaps is null while NumberOfHeaps is nonzero".into(),
        ));
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    if !user_pointer(array) {
        return Err(HeapQueryError::InvalidPeb(format!(
            "ProcessHeaps {array:#x} is outside the x64 user address range"
        )));
    }
    let bytes = engine.read_memory(array, count.saturating_mul(8))?;
    let segment_offset = layout
        .field("_SEGMENT_HEAP", "Signature")
        .map_err(|error| HeapQueryError::Layout(error.to_string()))?
        as u64;
    let nt_offset = layout
        .field("_HEAP", "Signature")
        .map_err(|error| HeapQueryError::Layout(error.to_string()))? as u64;
    let mut roots = Vec::with_capacity(count);
    for (index, entry) in bytes.chunks_exact(8).enumerate() {
        let address = u64::from_le_bytes(entry.try_into().unwrap());
        if address == 0 {
            roots.push(HeapRoot {
                index,
                address,
                kind: HeapKind::Unknown,
                supported: false,
                reason: Some("null heap root".into()),
            });
            continue;
        }
        if !user_pointer(address) {
            roots.push(HeapRoot {
                index,
                address,
                kind: HeapKind::Unknown,
                supported: false,
                reason: Some("heap root is outside the x64 user address range".into()),
            });
            continue;
        }
        let segment = address
            .checked_add(segment_offset)
            .ok_or_else(|| "Segment signature address overflow".into())
            .and_then(|address| read_u32(engine, address).map_err(|error| error.to_string()));
        let nt = address
            .checked_add(nt_offset)
            .ok_or_else(|| "NT signature address overflow".into())
            .and_then(|address| read_u32(engine, address).map_err(|error| error.to_string()));
        let (kind, reason) = classify_root(segment, nt);
        roots.push(HeapRoot {
            index,
            address,
            kind,
            supported: kind == HeapKind::Segment,
            reason,
        });
    }
    Ok(roots)
}

fn scope_of(roots: &[HeapRoot]) -> HeapScope {
    let mut scope = HeapScope::default();
    for root in roots {
        match root.kind {
            HeapKind::Segment => scope.segment_heaps_walked.push(root.address),
            HeapKind::Nt => scope.nt_heaps_skipped.push(root.address),
            HeapKind::Unknown => scope.unknown_heaps_skipped.push(root.address),
            HeapKind::Unreadable => scope.unreadable_heaps_skipped.push(root.address),
        }
    }
    scope
}

fn from_pool_snapshot(
    snapshot: PoolSnapshot,
) -> (Vec<HeapAllocation>, HeapWalkReport, HeapDiagnosticReport) {
    let allocations: Vec<_> = snapshot
        .spans
        .iter()
        .map(|span| HeapAllocation {
            heap: span.heap.heap,
            backend: span.backend.into(),
            state: span.state.into(),
            header_address: span.header_address,
            user_address: span.usable_address,
            capacity: span.size,
            requested_size: span.requested_size,
            subsegment: span.subsegment,
            size_class: span.size_class,
        })
        .collect();
    let walk = HeapWalkReport {
        coverage: match (snapshot.complete, snapshot.budget_expired) {
            (true, _) => WalkCoverage::Complete,
            (false, true) => WalkCoverage::BudgetExpired,
            (false, false) => WalkCoverage::Partial,
        },
        total_chunks: allocations.len(),
        allocated_chunks: allocations
            .iter()
            .filter(|allocation| allocation.state == HeapState::Allocated)
            .count(),
        diagnostic_count: snapshot.diagnostics.emitted(),
        unreadable_gaps: allocations
            .iter()
            .filter(|allocation| allocation.state == HeapState::Unreadable)
            .count(),
        refused_headers: snapshot.refused_chunks,
        stalls: snapshot.stalls,
    };
    let diagnostics = HeapDiagnosticReport {
        categories: snapshot.diagnostics.shapes().to_vec(),
        examples: snapshot.diagnostics.examples().to_vec(),
    };
    (allocations, walk, diagnostics)
}

fn prepare(engine: &DebugEngine, walk: HeapWalk) -> Result<HeapSnapshot, HeapQueryError> {
    let started = Instant::now();
    if engine.is_kernel_target()? {
        return Err(HeapQueryError::NotUserTarget);
    }
    match engine.execution_status()? {
        DEBUG_STATUS_NO_DEBUGGEE => return Err(HeapQueryError::NoDebuggee),
        DEBUG_STATUS_BREAK => {}
        _ => return Err(HeapQueryError::TargetRunning),
    }
    let machine = engine.processor_type()?;
    if machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(HeapQueryError::UnsupportedArchitecture { machine });
    }
    let peb = engine.current_process_peb()?;
    if peb == 0 {
        return Err(HeapQueryError::InvalidPeb(
            "DbgEng returned a null PEB".into(),
        ));
    }
    let loaded_module = engine.module("ntdll")?;
    let image = KernelImage {
        base: loaded_module.base,
        size: loaded_module.size,
        timestamp: loaded_module.timestamp,
        checksum: loaded_module.checksum,
    };
    let generation = crate::pool::query::generation();
    let layout_key = LayoutKey {
        image,
        session: generation,
    };
    let layout = UserLayoutCache::global().get_or_resolve(engine, layout_key)?;
    // Type lookups above force a deferred module to load. Check provenance afterwards so
    // export-only symbols fail explicitly without preventing the normal deferred-load path.
    let module = engine.module_identity("ntdll")?;
    if !module.symbols.has_type_info() || module.symbol_file.is_empty() {
        return Err(HeapQueryError::Layout(
            "DbgEng did not load private PDB type information for ntdll".into(),
        ));
    }
    let provenance = layout
        .provenance(module)
        .map_err(|error| HeapQueryError::Layout(error.to_string()))?;
    let key = SnapshotKey {
        target: engine.target_identity(),
        peb,
        image,
        generation,
    };
    if walk.refresh {
        snapshots().invalidate();
    } else if let Some(snapshot) = snapshots().get(key) {
        return Ok(snapshot);
    }

    let roots = enumerate_roots(engine, &layout, peb)?;
    let scope = scope_of(&roots);
    let remaining = walk
        .budget
        .map(|budget| budget.saturating_sub(started.elapsed()));
    let pool = walk_user_segment_heaps(
        engine,
        &layout,
        peb,
        &scope.segment_heaps_walked,
        remaining,
        1_000_000,
    )
    .map_err(|error| match error {
        SnapshotError::Interrupted => HeapQueryError::Interrupted,
        other => HeapQueryError::Walk(other.to_string()),
    })?;
    let (allocations, report, diagnostics) = from_pool_snapshot(pool);
    let snapshot = HeapSnapshot {
        roots,
        allocations,
        layout: provenance,
        scope,
        walk: report,
        diagnostics,
    };
    if snapshot.walk.coverage == WalkCoverage::Complete {
        snapshots().put(key, snapshot.clone());
    }
    Ok(snapshot)
}

fn answer<T>(snapshot: &HeapSnapshot, found: T) -> HeapAnswer<T> {
    HeapAnswer {
        found,
        layout: snapshot.layout.clone(),
        scope: snapshot.scope.clone(),
        walk: snapshot.walk.clone(),
    }
}

pub fn list(
    engine: &DebugEngine,
    walk: impl Into<HeapWalk>,
) -> Result<HeapAnswer<Vec<HeapRoot>>, HeapQueryError> {
    let snapshot = prepare(engine, walk.into())?;
    Ok(answer(&snapshot, snapshot.roots.clone()))
}

pub fn allocations(
    engine: &DebugEngine,
    walk: impl Into<HeapWalk>,
) -> Result<HeapAnswer<Vec<HeapAllocation>>, HeapQueryError> {
    let snapshot = prepare(engine, walk.into())?;
    Ok(answer(&snapshot, snapshot.allocations.clone()))
}

pub fn chunk_at(
    engine: &DebugEngine,
    address: u64,
    walk: impl Into<HeapWalk>,
) -> Result<HeapAnswer<Option<HeapNeighbourhood>>, HeapQueryError> {
    let snapshot = prepare(engine, walk.into())?;
    let found = neighbourhood_at(&snapshot.allocations, address);
    Ok(answer(&snapshot, found))
}

fn neighbourhood_at(allocations: &[HeapAllocation], address: u64) -> Option<HeapNeighbourhood> {
    let position = allocations
        .iter()
        .position(|allocation| allocation.contains(address))?;
    let allocation = allocations[position].clone();
    let same_heap = |candidate: &HeapAllocation| {
        candidate.heap == allocation.heap
            && candidate.backend == allocation.backend
            && candidate.subsegment == allocation.subsegment
            && candidate.state != HeapState::Unreadable
    };
    let previous = position
        .checked_sub(1)
        .and_then(|index| allocations.get(index))
        .filter(|candidate| same_heap(candidate) && candidate.end() == allocation.header_address)
        .cloned();
    let next = allocations
        .get(position + 1)
        .filter(|candidate| same_heap(candidate) && allocation.end() == candidate.header_address)
        .cloned();
    Some(HeapNeighbourhood {
        offset: i64::try_from(i128::from(address) - i128::from(allocation.user_address)).unwrap_or(
            if address < allocation.user_address {
                i64::MIN
            } else {
                i64::MAX
            },
        ),
        allocation,
        previous,
        next,
    })
}

fn census_of(allocations: &[HeapAllocation]) -> Vec<HeapCensusRow> {
    let mut rows: HashMap<(u64, HeapBackend, HeapState, u32), HeapCensusRow> = HashMap::new();
    for allocation in allocations {
        let key = (
            allocation.heap,
            allocation.backend,
            allocation.state,
            allocation.size_class,
        );
        let row = rows.entry(key).or_insert(HeapCensusRow {
            heap: allocation.heap,
            backend: allocation.backend,
            state: allocation.state,
            size_class: allocation.size_class,
            chunks: 0,
            total_capacity: 0,
        });
        row.chunks += 1;
        row.total_capacity = row.total_capacity.saturating_add(allocation.capacity);
    }
    let mut rows: Vec<_> = rows.into_values().collect();
    rows.sort_by(|left, right| {
        right
            .total_capacity
            .cmp(&left.total_capacity)
            .then_with(|| right.chunks.cmp(&left.chunks))
            .then_with(|| left.cmp(right))
    });
    rows
}

pub fn census(
    engine: &DebugEngine,
    walk: impl Into<HeapWalk>,
) -> Result<HeapAnswer<Vec<HeapCensusRow>>, HeapQueryError> {
    let snapshot = prepare(engine, walk.into())?;
    let found = census_of(&snapshot.allocations);
    Ok(answer(&snapshot, found))
}

pub fn diagnostics(
    engine: &DebugEngine,
    walk: impl Into<HeapWalk>,
) -> Result<HeapAnswer<HeapDiagnosticReport>, HeapQueryError> {
    let snapshot = prepare(engine, walk.into())?;
    Ok(answer(&snapshot, snapshot.diagnostics.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocation(heap: u64, backend: HeapBackend, address: u64, capacity: u64) -> HeapAllocation {
        HeapAllocation {
            heap,
            backend,
            state: HeapState::Allocated,
            header_address: address,
            user_address: address + 0x10,
            capacity,
            requested_size: None,
            subsegment: Some(heap + 0x1000),
            size_class: capacity as u32,
        }
    }

    #[test]
    fn test_segment_and_nt_signatures_are_not_interchangeable() {
        assert_ne!(SEGMENT_HEAP_SIGNATURE, NT_HEAP_SIGNATURE);
        assert_eq!(SEGMENT_HEAP_SIGNATURE, 0xddee_ddee);
        assert_eq!(NT_HEAP_SIGNATURE, 0xeeff_eeff);
    }

    #[test]
    fn test_root_classification_skips_nt_unknown_unreadable_and_ambiguous_roots() {
        assert_eq!(
            classify_root(Ok(SEGMENT_HEAP_SIGNATURE), Ok(0)),
            (HeapKind::Segment, None)
        );
        assert_eq!(classify_root(Ok(0), Ok(NT_HEAP_SIGNATURE)).0, HeapKind::Nt);
        assert_eq!(classify_root(Ok(0), Ok(0)).0, HeapKind::Unknown);
        assert_eq!(
            classify_root(Err("first read".into()), Err("second read".into())).0,
            HeapKind::Unreadable
        );
        assert_eq!(
            classify_root(Ok(SEGMENT_HEAP_SIGNATURE), Ok(NT_HEAP_SIGNATURE)).0,
            HeapKind::Unknown,
            "conflicting structural evidence must fail closed"
        );
    }

    #[test]
    fn test_user_pointer_bounds_reject_null_kernel_and_noncanonical_roots() {
        assert!(user_pointer(0x1_0000));
        assert!(user_pointer(0x0000_7fff_ffff_ffff));
        assert!(!user_pointer(0));
        assert!(!user_pointer(0xffff_8000_0000_0000));
        assert!(!user_pointer(0x0000_8000_0000_0000));
    }

    #[test]
    fn test_user_allocation_contains_header_and_payload_addresses() {
        let allocation = allocation(0x1000, HeapBackend::Vs, 0x2000, 0x40);
        assert!(allocation.contains(0x2000));
        assert!(allocation.contains(0x204f));
        assert!(!allocation.contains(0x2050));
    }

    #[test]
    fn test_scope_lists_unsupported_heaps_explicitly() {
        let roots = vec![
            HeapRoot {
                index: 0,
                address: 1,
                kind: HeapKind::Segment,
                supported: true,
                reason: None,
            },
            HeapRoot {
                index: 1,
                address: 2,
                kind: HeapKind::Nt,
                supported: false,
                reason: Some("classic".into()),
            },
            HeapRoot {
                index: 2,
                address: 3,
                kind: HeapKind::Unknown,
                supported: false,
                reason: Some("unknown".into()),
            },
            HeapRoot {
                index: 3,
                address: 4,
                kind: HeapKind::Unreadable,
                supported: false,
                reason: Some("unreadable".into()),
            },
        ];
        let scope = scope_of(&roots);
        assert_eq!(scope.segment_heaps_walked, vec![1]);
        assert_eq!(scope.nt_heaps_skipped, vec![2]);
        assert_eq!(scope.unknown_heaps_skipped, vec![3]);
        assert_eq!(scope.unreadable_heaps_skipped, vec![4]);
    }

    #[test]
    fn test_census_key_separates_heap_backend_state_and_size_class() {
        let left = allocation(1, HeapBackend::Lfh, 0x1000, 0x20);
        let mut right = allocation(2, HeapBackend::Lfh, 0x2000, 0x20);
        right.state = HeapState::ReusableFree;
        assert_ne!(
            (left.heap, left.backend, left.state, left.size_class),
            (right.heap, right.backend, right.state, right.size_class)
        );
    }

    #[test]
    fn test_neighbourhood_requires_contiguity_and_same_allocator_identity() {
        let previous = allocation(1, HeapBackend::Vs, 0x2000, 0x20);
        let current = allocation(1, HeapBackend::Vs, previous.end(), 0x20);
        let next = allocation(1, HeapBackend::Vs, current.end(), 0x20);
        let found = neighbourhood_at(
            &[previous.clone(), current.clone(), next.clone()],
            current.user_address + 3,
        )
        .unwrap();
        assert_eq!(found.offset, 3);
        assert_eq!(found.previous, Some(previous));
        assert_eq!(found.next, Some(next));

        let header =
            neighbourhood_at(std::slice::from_ref(&current), current.header_address).unwrap();
        assert_eq!(header.offset, -0x10);

        let other_heap = allocation(2, HeapBackend::Vs, current.end(), 0x20);
        let found = neighbourhood_at(&[current.clone(), other_heap], current.user_address).unwrap();
        assert!(found.next.is_none(), "neighbours may not cross a heap root");
    }

    #[test]
    fn test_census_totals_and_sorts_heaviest_first() {
        let allocations = vec![
            allocation(1, HeapBackend::Lfh, 0x1000, 0x20),
            allocation(1, HeapBackend::Lfh, 0x2000, 0x20),
            allocation(2, HeapBackend::Large, 0x3000, 0x1000),
        ];
        let rows = census_of(&allocations);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].backend, HeapBackend::Large);
        assert_eq!(rows[0].total_capacity, 0x1000);
        assert_eq!(rows[1].chunks, 2);
        assert_eq!(rows[1].total_capacity, 0x40);
    }
}
