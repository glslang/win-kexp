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
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;

use crate::allocator::LayoutProvenance;
use crate::dbgeng::{DbgEngError, DebugEngine, KernelImage};
use crate::pool::layout::{LayoutCache, LayoutError, LayoutKey, LayoutTarget, PoolLayout, Symbols};
use crate::pool::query::WalkCoverage;
use crate::pool::snapshot::{PoolSnapshot, SnapshotError, walk_user_segment_heaps};
use crate::pool::{DiagnosticShape, PoolBackend, PoolState, WalkStalls};

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
    /// Committed VS bytes the walk declined to decode because it could not place a chunk
    /// boundary in them; see [`crate::pool::PoolSnapshot::unplaced_bytes`].
    pub unplaced_bytes: u64,
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
    #[error(
        "the target is not stopped (execution status {status:#x}); break in before walking heaps"
    )]
    TargetRunning { status: u32 },
    #[error("heap walking supports x64 targets only (machine {machine:#x})")]
    UnsupportedArchitecture { machine: u32 },
    #[error("invalid PEB heap metadata: {0}")]
    InvalidPeb(String),
    #[error("heap selector {heap:#x} is not a supported Segment Heap root in the current PEB")]
    UnsupportedHeap { heap: u64 },
    #[error(
        "missing or unsupported ntdll allocator layout ({0}); run `.reload /f ntdll.dll` and retry"
    )]
    Layout(String),
    #[error("the heap walk was interrupted on request")]
    Interrupted,
    #[error("the heap walk ran out of its budget while resolving the ntdll allocator layout")]
    BudgetExpired,
    #[error("walking the heap failed: {0}")]
    Walk(String),
    #[error(transparent)]
    Engine(#[from] DbgEngError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SnapshotKey {
    target: u64,
    process_system_id: u32,
    peb: u64,
    image: KernelImage,
    generation: u64,
    /// A scoped diagnostic walk is a different snapshot from the all-heaps walk.
    heap: Option<u64>,
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

#[derive(Debug, Clone, Copy)]
struct ValidatedTarget {
    target: u64,
    process_system_id: u32,
    peb: u64,
    generation: u64,
}

struct ResolvedSchema {
    layout: PoolLayout,
    provenance: LayoutProvenance,
    image: KernelImage,
}

struct BudgetedSymbols<'a> {
    engine: &'a DebugEngine,
    deadline: Option<Instant>,
}

impl BudgetedSymbols<'_> {
    fn check(&self) -> Result<(), HeapQueryError> {
        self.poll().map_err(map_layout_error)
    }
}

impl Symbols for BudgetedSymbols<'_> {
    fn poll(&self) -> Result<(), LayoutError> {
        if self
            .engine
            .interrupted()
            .map_err(|error| LayoutError::Poll {
                detail: error.to_string(),
            })?
        {
            return Err(LayoutError::Interrupted);
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(LayoutError::BudgetExpired);
        }
        Ok(())
    }

    fn symbol(&self, name: &str) -> Result<u64, DbgEngError> {
        self.engine.symbol_offset(name)
    }

    fn type_id(&self, module: u64, name: &str) -> Result<u32, DbgEngError> {
        self.engine.type_id(module, name)
    }

    fn type_size(&self, module: u64, type_id: u32) -> Result<u32, DbgEngError> {
        self.engine.type_size(module, type_id)
    }

    fn field(&self, module: u64, type_id: u32, name: &str) -> Result<u32, DbgEngError> {
        self.engine.field_offset(module, type_id, name)
    }
}

fn map_layout_error(error: LayoutError) -> HeapQueryError {
    match error {
        LayoutError::Interrupted => HeapQueryError::Interrupted,
        LayoutError::BudgetExpired => HeapQueryError::BudgetExpired,
        other => HeapQueryError::Layout(other.to_string()),
    }
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

/// Drop the user-heap snapshot while retaining the image-keyed `ntdll` schema.
pub fn invalidate_snapshot() {
    snapshots().invalidate();
}

/// Drop every user-heap snapshot and resolved `ntdll` schema.
pub fn invalidate_caches() {
    invalidate_snapshot();
    LayoutCache::global().invalidate();
}

fn read_u32(engine: &DebugEngine, address: u64) -> Result<u32, DbgEngError> {
    Ok(u32::from_le_bytes(
        engine
            .read_memory(address, 4)?
            .try_into()
            .expect("read_memory returns exactly four bytes or a ShortRead error"),
    ))
}

fn read_u64(engine: &DebugEngine, address: u64) -> Result<u64, DbgEngError> {
    Ok(u64::from_le_bytes(
        engine
            .read_memory(address, 8)?
            .try_into()
            .expect("read_memory returns exactly eight bytes or a ShortRead error"),
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

fn read_root_signatures(
    engine: &DebugEngine,
    address: u64,
    segment_offset: u64,
    nt_offset: u64,
) -> (Result<u32, String>, Result<u32, String>) {
    let start_offset = segment_offset.min(nt_offset);
    let end_offset = segment_offset.max(nt_offset).saturating_add(4);
    let Some(start) = address.checked_add(start_offset) else {
        let error = "heap signature address overflow".to_string();
        return (Err(error.clone()), Err(error));
    };
    let size = usize::try_from(end_offset.saturating_sub(start_offset))
        .expect("two u32 PDB fields fit in a host-sized read buffer");
    let bytes = match engine.read_memory(start, size) {
        Ok(bytes) => bytes,
        Err(error) => {
            let error = error.to_string();
            return (Err(error.clone()), Err(error));
        }
    };
    let decode = |offset: u64| {
        let relative = usize::try_from(offset - start_offset)
            .expect("a field within the signature buffer has a host-sized offset");
        let value = bytes
            .get(relative..relative + 4)
            .expect("read_memory returns the complete signature buffer or a ShortRead error")
            .try_into()
            .expect("a signature slice is exactly four bytes");
        Ok(u32::from_le_bytes(value))
    };
    (decode(segment_offset), decode(nt_offset))
}

struct RootEnumeration {
    roots: Vec<HeapRoot>,
    total: Option<usize>,
    budget_expired: bool,
}

impl RootEnumeration {
    fn expired(roots: Vec<HeapRoot>, total: Option<usize>) -> Self {
        Self {
            roots,
            total,
            budget_expired: true,
        }
    }

    fn complete(roots: Vec<HeapRoot>, total: usize) -> Self {
        Self {
            roots,
            total: Some(total),
            budget_expired: false,
        }
    }
}

fn root_read_budget_expired(
    engine: &DebugEngine,
    deadline: Option<Instant>,
) -> Result<bool, HeapQueryError> {
    if engine.interrupted()? {
        return Err(HeapQueryError::Interrupted);
    }
    Ok(deadline.is_some_and(|deadline| Instant::now() >= deadline))
}

fn truncated_root_snapshot(
    classified: usize,
    total: Option<usize>,
    budget: Option<Duration>,
) -> PoolSnapshot {
    let mut snapshot = PoolSnapshot {
        complete: false,
        budget_expired: true,
        ..PoolSnapshot::default()
    };
    let allowed = budget.map_or_else(
        || "walk budget".into(),
        |budget| format!("{budget:?} budget"),
    );
    let coverage = total.map_or_else(
        || format!("{classified} roots classified before the PEB heap count was read"),
        |total| format!("{classified} of {total} PEB heap roots classified"),
    );
    snapshot.diagnostics.push(format!(
        "the walk ran out of its {allowed} while enumerating heap roots: {coverage}; what is \
         missing is unknown, not absent"
    ));
    snapshot
}

fn enumerate_roots(
    engine: &DebugEngine,
    layout: &PoolLayout,
    peb: u64,
    deadline: Option<Instant>,
) -> Result<RootEnumeration, HeapQueryError> {
    if root_read_budget_expired(engine, deadline)? {
        return Ok(RootEnumeration::expired(Vec::new(), None));
    }
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
    if root_read_budget_expired(engine, deadline)? {
        return Ok(RootEnumeration::expired(Vec::new(), Some(count)));
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
        return Ok(RootEnumeration::complete(Vec::new(), 0));
    }
    if !user_pointer(array) {
        return Err(HeapQueryError::InvalidPeb(format!(
            "ProcessHeaps {array:#x} is outside the x64 user address range"
        )));
    }
    if root_read_budget_expired(engine, deadline)? {
        return Ok(RootEnumeration::expired(Vec::new(), Some(count)));
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
        let address = u64::from_le_bytes(
            entry
                .try_into()
                .expect("ProcessHeaps is read as a whole number of pointer-sized entries"),
        );
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
        if root_read_budget_expired(engine, deadline)? {
            return Ok(RootEnumeration::expired(roots, Some(count)));
        }
        let (segment, nt) = read_root_signatures(engine, address, segment_offset, nt_offset);
        let (kind, reason) = classify_root(segment, nt);
        roots.push(HeapRoot {
            index,
            address,
            kind,
            supported: kind == HeapKind::Segment,
            reason,
        });
    }
    Ok(RootEnumeration::complete(roots, count))
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

fn scope_for(
    roots: &[HeapRoot],
    heap: Option<u64>,
    enumeration_complete: bool,
) -> Result<HeapScope, HeapQueryError> {
    let mut scope = scope_of(roots);
    if let Some(heap) = heap {
        let selected = roots.iter().find(|root| root.address == heap);
        if selected.is_some_and(|root| root.kind != HeapKind::Segment)
            || (selected.is_none() && enumeration_complete)
        {
            return Err(HeapQueryError::UnsupportedHeap { heap });
        }
        // Diagnostic shapes deliberately generalise addresses. Narrow the roots handed to the
        // walker so complaints from another heap never enter this snapshot's aggregation.
        scope.segment_heaps_walked.retain(|root| *root == heap);
    }
    Ok(scope)
}

fn from_pool_snapshot(
    snapshot: PoolSnapshot,
) -> (Vec<HeapAllocation>, HeapWalkReport, HeapDiagnosticReport) {
    let mut allocations: Vec<_> = snapshot
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
    allocations.sort_by_key(|allocation| (allocation.user_address, allocation.heap));
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
        unplaced_bytes: snapshot.unplaced_bytes,
        stalls: snapshot.stalls,
    };
    let diagnostics = HeapDiagnosticReport {
        categories: snapshot.diagnostics.shapes().to_vec(),
        examples: snapshot.diagnostics.examples().to_vec(),
    };
    (allocations, walk, diagnostics)
}

fn validate_target(engine: &DebugEngine) -> Result<ValidatedTarget, HeapQueryError> {
    if engine.is_kernel_target()? {
        return Err(HeapQueryError::NotUserTarget);
    }
    match engine.execution_status()? {
        DEBUG_STATUS_NO_DEBUGGEE => return Err(HeapQueryError::NoDebuggee),
        DEBUG_STATUS_BREAK => {}
        status => return Err(HeapQueryError::TargetRunning { status }),
    }
    let machine = engine.processor_type()?;
    if machine != u32::from(IMAGE_FILE_MACHINE_AMD64.0) {
        return Err(HeapQueryError::UnsupportedArchitecture { machine });
    }
    let peb = engine.current_process_peb()?;
    if peb == 0 {
        return Err(HeapQueryError::InvalidPeb(
            "DbgEng returned a null PEB".into(),
        ));
    }
    Ok(ValidatedTarget {
        target: engine.target_identity(),
        process_system_id: engine.current_process_system_id()?,
        peb,
        generation: crate::pool::query::generation(),
    })
}

fn resolve_schema(
    engine: &DebugEngine,
    target: ValidatedTarget,
    deadline: Option<Instant>,
) -> Result<ResolvedSchema, HeapQueryError> {
    let symbols = BudgetedSymbols { engine, deadline };
    symbols.check()?;
    let loaded_module = engine.module("ntdll");
    symbols.check()?;
    let loaded_module = loaded_module?;
    let image = KernelImage {
        base: loaded_module.base,
        size: loaded_module.size,
        timestamp: loaded_module.timestamp,
        checksum: loaded_module.checksum,
    };
    let layout_key = LayoutKey {
        image,
        session: target.generation,
    };
    let layout = LayoutCache::global()
        .get_or_resolve(&symbols, layout_key, LayoutTarget::User)
        .map_err(map_layout_error)?;
    // Type lookups above force a deferred module to load. Check provenance afterwards so
    // export-only symbols fail explicitly without preventing the normal deferred-load path.
    symbols.check()?;
    let module = engine.module_identity("ntdll");
    symbols.check()?;
    let module = module?;
    if !module.symbols.has_type_info() || module.symbol_file.is_empty() {
        return Err(HeapQueryError::Layout(
            "DbgEng did not load private PDB type information for ntdll".into(),
        ));
    }
    let provenance = layout.provenance(module).map_err(map_layout_error)?;
    Ok(ResolvedSchema {
        layout,
        provenance,
        image,
    })
}

fn walk_snapshot(
    engine: &DebugEngine,
    walk: HeapWalk,
    started: Instant,
    target: ValidatedTarget,
    schema: ResolvedSchema,
    heap: Option<u64>,
) -> Result<HeapSnapshot, HeapQueryError> {
    let key = SnapshotKey {
        target: target.target,
        process_system_id: target.process_system_id,
        peb: target.peb,
        image: schema.image,
        generation: target.generation,
        heap,
    };
    if walk.refresh {
        snapshots().invalidate();
    } else if let Some(snapshot) = snapshots().get(key) {
        return Ok(snapshot);
    }

    // The absolute deadline keeps schema resolution and PEB enumeration inside the caller's
    // one budget. An unrepresentably large duration has the same unbounded meaning as the
    // shared walker gives it.
    let deadline = walk.budget.and_then(|budget| started.checked_add(budget));
    let RootEnumeration {
        roots,
        total,
        budget_expired,
    } = enumerate_roots(engine, &schema.layout, target.peb, deadline)?;
    let mut scope = scope_for(&roots, heap, !budget_expired)?;
    let pool = if budget_expired {
        // These roots were identified but no allocator region was walked after the deadline.
        scope.segment_heaps_walked.clear();
        truncated_root_snapshot(roots.len(), total, walk.budget)
    } else {
        let remaining = walk
            .budget
            .map(|budget| budget.saturating_sub(started.elapsed()));
        walk_user_segment_heaps(
            engine,
            &schema.layout,
            target.peb,
            &scope.segment_heaps_walked,
            remaining,
            1_000_000,
        )
        .map_err(|error| match error {
            SnapshotError::Interrupted => HeapQueryError::Interrupted,
            other => HeapQueryError::Walk(other.to_string()),
        })?
    };
    let (allocations, report, diagnostics) = from_pool_snapshot(pool);
    let snapshot = HeapSnapshot {
        roots,
        allocations,
        layout: schema.provenance,
        scope,
        walk: report,
        diagnostics,
    };
    if snapshot.walk.coverage == WalkCoverage::Complete {
        snapshots().put(key, snapshot.clone());
    }
    Ok(snapshot)
}

fn prepare(engine: &DebugEngine, walk: HeapWalk) -> Result<HeapSnapshot, HeapQueryError> {
    prepare_for_heap(engine, None, walk)
}

fn prepare_for_heap(
    engine: &DebugEngine,
    heap: Option<u64>,
    walk: HeapWalk,
) -> Result<HeapSnapshot, HeapQueryError> {
    let started = Instant::now();
    let deadline = walk.budget.and_then(|budget| started.checked_add(budget));
    let target = validate_target(engine)?;
    let schema = resolve_schema(engine, target, deadline)?;
    walk_snapshot(engine, walk, started, target, schema, heap)
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
    let split = allocations.partition_point(|allocation| allocation.user_address <= address);
    let position = split
        .checked_sub(1)
        .filter(|&index| allocations[index].contains(address))
        .or_else(|| {
            allocations
                .get(split)
                .filter(|allocation| allocation.contains(address))
                .map(|_| split)
        })?;
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

/// Reports diagnostics from one Segment Heap root.
///
/// The heap is selected before walking and before diagnostic shapes generalise addresses, so
/// category totals and examples both describe only this root. Use [`diagnostics`] for all roots.
pub fn diagnostics_for_heap(
    engine: &DebugEngine,
    heap: u64,
    walk: impl Into<HeapWalk>,
) -> Result<HeapAnswer<HeapDiagnosticReport>, HeapQueryError> {
    let snapshot = prepare_for_heap(engine, Some(heap), walk.into())?;
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
    fn test_snapshot_identity_separates_current_processes() {
        let image = KernelImage {
            base: 0x0000_7ffb_0000_0000,
            size: 0x20_0000,
            timestamp: 0x1234_5678,
            checksum: 0x9876,
        };
        let key = |process_system_id, heap| SnapshotKey {
            target: 7,
            process_system_id,
            peb: 0x0000_7fff_0000_1000,
            image,
            generation: 3,
            heap,
        };

        assert_ne!(
            key(100, None),
            key(200, None),
            "two current processes may share virtual addresses but never a heap snapshot"
        );
        assert_eq!(key(100, None), key(100, None));
    }

    #[test]
    fn test_snapshot_identity_separates_scoped_diagnostic_walks() {
        let image = KernelImage {
            base: 0x0000_7ffb_0000_0000,
            size: 0x20_0000,
            timestamp: 0x1234_5678,
            checksum: 0x9876,
        };
        let key = |heap| SnapshotKey {
            target: 7,
            process_system_id: 100,
            peb: 0x0000_7fff_0000_1000,
            image,
            generation: 3,
            heap,
        };

        assert_ne!(key(None), key(Some(0x10000)));
        assert_ne!(key(Some(0x10000)), key(Some(0x20000)));
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
    fn test_scoped_diagnostics_select_one_heap_before_the_walk() {
        let roots = vec![
            HeapRoot {
                index: 0,
                address: 0x10000,
                kind: HeapKind::Segment,
                supported: true,
                reason: None,
            },
            HeapRoot {
                index: 1,
                address: 0x20000,
                kind: HeapKind::Segment,
                supported: true,
                reason: None,
            },
        ];
        let scope = scope_for(&roots, Some(0x20000), true).unwrap();

        assert_eq!(scope.segment_heaps_walked, vec![0x20000]);
    }

    #[test]
    fn test_scoped_diagnostics_reject_unsupported_or_missing_heap() {
        let roots = vec![
            HeapRoot {
                index: 0,
                address: 0x10000,
                kind: HeapKind::Nt,
                supported: false,
                reason: Some("classic".into()),
            },
            HeapRoot {
                index: 1,
                address: 0x20000,
                kind: HeapKind::Unreadable,
                supported: false,
                reason: Some("unreadable".into()),
            },
        ];

        for heap in [0x10000, 0x20000, 0x30000] {
            assert!(matches!(
                scope_for(&roots, Some(heap), true),
                Err(HeapQueryError::UnsupportedHeap { heap: rejected }) if rejected == heap
            ));
        }
    }

    #[test]
    fn test_scoped_diagnostics_leave_unseen_heap_unknown_when_enumeration_expires() {
        let scope = scope_for(&[], Some(0x30000), false).unwrap();

        assert!(scope.segment_heaps_walked.is_empty());
    }

    #[test]
    fn test_root_enumeration_deadline_reports_partial_coverage() {
        let snapshot = truncated_root_snapshot(3, Some(12), Some(Duration::from_secs(2)));
        let (allocations, walk, diagnostics) = from_pool_snapshot(snapshot);

        assert!(allocations.is_empty());
        assert_eq!(walk.coverage, WalkCoverage::BudgetExpired);
        assert_eq!(walk.diagnostic_count, 1);
        assert_eq!(diagnostics.examples.len(), 1);
        assert!(diagnostics.examples[0].contains("2s budget"));
        assert!(diagnostics.examples[0].contains("3 of 12 PEB heap roots classified"));
        assert!(diagnostics.examples[0].contains("unknown, not absent"));
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
