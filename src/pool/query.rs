//! Public, typed queries over the pool walker.
//!
//! The walker itself is reached two ways: interactively through the
//! `!win_kexp.poolmap` extension command, and programmatically through this module
//! by a host that already owns a [`DebugEngine`] (windbg-mcp does exactly that).
//! Both go through [`prepare_index`], so the validation rules, the layout cache and
//! the snapshot cache cannot drift apart between the two entry points.
//!
//! Everything here returns typed values — [`PoolSpan`]s, not rendered text — because
//! the programmatic caller re-serializes them (as JSON, say) and scraping the DML the
//! extension prints would be lossy and brittle.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::time::Instant;

use thiserror::Error;
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_STATUS_BREAK, DEBUG_STATUS_NO_DEBUGGEE,
};

use super::decode::parse_tag;
use super::index::{PoolIndex, SnapshotCache};
use super::layout::{LayoutCache, LayoutTarget, SessionKey};
use super::snapshot::{SnapshotError, SnapshotWalker, WalkStalls};
use super::{PoolBackend, PoolDiagnostics, PoolSpan, PoolState};
use crate::dbgeng::{DbgEngError, DebugEngine};

const IMAGE_FILE_MACHINE_AMD64: u32 = 0x8664;

/// Bumped whenever the debugger tells us the session changed, and whenever a caller
/// forces a refresh. Both caches key on it, so a stale walk can never outlive the
/// target it described.
static SESSION_GENERATION: AtomicU64 = AtomicU64::new(1);

pub(crate) fn generation() -> u64 {
    SESSION_GENERATION.load(Ordering::Acquire)
}

/// Invalidate every cached view. Called on debugger session transitions.
pub(crate) fn bump_generation() {
    SESSION_GENERATION.fetch_add(1, Ordering::AcqRel);
}

pub(crate) fn snapshots() -> &'static SnapshotCache {
    static CACHE: std::sync::OnceLock<SnapshotCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(SnapshotCache::default)
}

/// Drop every cached view of the target: the generation, the snapshot and the layout.
///
/// Called when the debugger reports a session transition. Both the extension command
/// and the programmatic API read through these caches, so this has to clear all three
/// together — keeping a layout resolved against a kernel base that has since changed
/// would silently mis-decode every header.
pub(crate) fn invalidate_session() {
    bump_generation();
    snapshots().invalidate();
    LayoutCache::global().invalidate();
}

/// Invalidate every cached allocator snapshot and schema for a programmatic host.
///
/// WinDbg extensions receive session notifications and do this automatically. A host that
/// resumes or replaces a target through the API knows about that transition directly and calls
/// this at the same boundary.
pub fn invalidate_allocator_caches() {
    invalidate_session();
    crate::heap::invalidate_caches();
}

/// Invalidate target-memory snapshots after execution while retaining immutable PDB layouts.
pub fn invalidate_allocator_snapshots() {
    snapshots().invalidate();
    crate::heap::invalidate_snapshot();
}

/// Why a pool query could not be answered.
///
/// These are deliberately distinct variants rather than one string: a caller needs to
/// tell "you are pointed at the wrong kind of target" (never going to work) from
/// "the target is running" (break in and retry).
#[derive(Debug, Error)]
pub enum PoolQueryError {
    #[error("pool queries require a kernel target")]
    NotKernelTarget,

    #[error("no accessible target is attached")]
    NoDebuggee,

    #[error("target is running; break in before taking a pool snapshot")]
    TargetRunning,

    #[error("pool walking supports x64 targets only (machine {machine:#x})")]
    UnsupportedArchitecture { machine: u32 },

    #[error(
        "tag must be 1..4 ASCII bytes (\"Tgsm\") or the raw form 0x + 8 hex digits (\"0x5467736d\")"
    )]
    InvalidTag,

    #[error("resolving pool layout failed ({0}); run `.reload /f nt` and retry")]
    Layout(String),

    /// The walk was stopped on request (Ctrl+C / `SetInterrupt`) and its snapshot discarded.
    ///
    /// Its own variant rather than a [`Self::Walk`] string because it is not a failure of the
    /// walk at all: somebody asked for it to stop, and a host that reports "walking the pool
    /// failed" for an interrupt it raised itself is telling its user the target is broken.
    #[error("the pool walk was interrupted on request")]
    Interrupted,

    #[error("walking the pool failed: {0}")]
    Walk(String),

    #[error(transparent)]
    Engine(#[from] DbgEngError),
}

/// How long a walk may run before it stops and reports what it reached.
///
/// A walk is thousands of debugger reads plus every committed pool page, and over a live
/// KDNET link each of those crosses the wire; on a busy kernel that is minutes. Nothing used
/// to stop it. The walk polls for Ctrl+C, but **only a human at a WinDbg prompt ever sets
/// that flag** — a programmatic caller has no way to say "that is long enough". Its own
/// timeout frees the caller and leaves the engine walking, and since one engine serves one
/// target one call at a time, every later call to that target queues behind the walk; the
/// session is wedged until it is killed, which on a live kernel leaves the guest halted.
///
/// 120s is sized to fit inside a typical host's per-call budget with room for the answer to
/// travel back. A host that knows its own deadline should pass that instead of taking this.
pub const DEFAULT_WALK_BUDGET: Duration = Duration::from_secs(120);

/// How a query is allowed to reach the pool: reuse or rebuild, and for how long.
///
/// `bool` converts into this — `true` meaning refresh — so the ordinary call reads as it
/// always did and picks up [`DEFAULT_WALK_BUDGET`] without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolWalk {
    /// Rebuild rather than reuse the snapshot cached for this target.
    pub refresh: bool,
    /// Wall-clock ceiling on a rebuild, or `None` to run to completion.
    ///
    /// `None` is correct only where something else can stop the walk — an operator at an
    /// interactive prompt, who can Ctrl+C. Everywhere else it is the wedge described on
    /// [`DEFAULT_WALK_BUDGET`].
    pub budget: Option<Duration>,
}

impl PoolWalk {
    /// Reuse the cached snapshot if there is one; otherwise walk under the default budget.
    pub fn cached() -> Self {
        Self {
            refresh: false,
            budget: Some(DEFAULT_WALK_BUDGET),
        }
    }

    /// Discard the cached snapshot and walk again, under the default budget.
    pub fn refreshed() -> Self {
        Self {
            refresh: true,
            ..Self::cached()
        }
    }

    /// Replace the budget with the caller's own deadline.
    pub fn within(self, budget: Duration) -> Self {
        Self {
            budget: Some(budget),
            ..self
        }
    }

    /// Let the walk run to completion. Only for a caller that can interrupt it.
    pub fn unbounded(self) -> Self {
        Self {
            budget: None,
            ..self
        }
    }
}

impl From<bool> for PoolWalk {
    fn from(refresh: bool) -> Self {
        Self {
            refresh,
            ..Self::cached()
        }
    }
}

/// Restrict results to one side of the paged/nonpaged split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolPageFilter {
    Paged,
    NonPaged,
}

/// A chunk plus the allocations either side of it.
///
/// The neighbours are the point: judging a use-after-free or a grooming attempt means
/// asking what now sits where the victim used to, and what borders it.
#[derive(Debug, Clone)]
pub struct PoolNeighbourhood {
    pub chunk: PoolSpan,
    pub previous: Option<PoolSpan>,
    pub next: Option<PoolSpan>,
}

/// Coarse totals for a snapshot, for callers that want a census rather than a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolTagSummary {
    pub display_tag: String,
    pub raw_tag: u32,
    pub allocations: usize,
    pub total_bytes: u64,
    pub paged_allocations: usize,
    pub nonpaged_allocations: usize,
}

/// What the walk itself managed, independent of any particular query.
///
/// Exists so an empty answer can say *why* it is empty. A caller that asked for a tag and
/// got nothing needs to distinguish "the pool genuinely holds no such chunk" from "the walk
/// reached almost none of the pool" — those look identical without the walk's own diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSnapshotReport {
    pub layout: crate::allocator::LayoutProvenance,
    pub total_chunks: usize,
    pub allocated_chunks: usize,
    /// How much of the pool the walk actually covered, and — when it fell short — what stopped
    /// it. See [`WalkCoverage`]; [`WalkCoverage::complete`] is the plain bool.
    pub coverage: WalkCoverage,
    /// What the walk complained about, grouped by shape.
    ///
    /// Ask it for [`PoolDiagnostics::emitted`] when reporting how much the walk complained:
    /// the messages it carries verbatim are a capped sample, so counting them measures the
    /// cap rather than the target.
    pub diagnostics: PoolDiagnostics,
    /// What the walk stepped over rather than gave up on, in bytes; see [`WalkStalls`].
    pub stalls: WalkStalls,
    /// Chunk headers the walk refused and resynchronised past; see
    /// [`crate::pool::PoolSnapshot::refused_chunks`] for why this is not read off a diagnostic.
    pub refused_chunks: u64,
    /// Committed VS bytes the walk declined to decode because it could not place a chunk
    /// boundary in them; see [`crate::pool::PoolSnapshot::unplaced_bytes`].
    pub unplaced_bytes: u64,
}

/// How much of the pool a walk covered.
///
/// A count taken from a partial walk is a floor, not a total, so every answer built on a
/// snapshot has to be able to say which of these it came from — and "not complete" alone is not
/// enough, because the two ways of falling short need opposite responses from the caller.
///
/// Not implied by the diagnostics: a walk can end incomplete without saying anything (`walk_vs`
/// clears completeness when a readable region stops mid-chunk), so a caller that wants to reject
/// partial results consults this and not the message list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkCoverage {
    /// The walk covered everything it set out to.
    Complete,
    /// It stopped early because its **deadline** passed. What it reached was really there;
    /// what is missing is unknown rather than absent, and a longer budget reaches more of it.
    BudgetExpired,
    /// It ran to the end without covering all of it — unreadable regions, a region that stopped
    /// mid-chunk, a traversal cap. The diagnostics say which. Unlike [`Self::BudgetExpired`],
    /// more time changes nothing.
    Partial,
}

impl WalkCoverage {
    /// Whether the walk covered everything it set out to.
    pub fn complete(self) -> bool {
        self == Self::Complete
    }
}

/// An answer and the walk it came from.
///
/// The two travel together because they have to be *the same walk*. A query that walks and a
/// caller that then asks for the walk's state are two calls, and between them the snapshot may
/// not exist: an incomplete walk is deliberately not cached, so the second call finds nothing and
/// walks again. The caller then holds a count from one walk and a coverage figure from another,
/// and reports them as if they described each other — which is exactly the mistake coverage
/// exists to prevent, arriving through the reporting instead of through the walk.
///
/// So the pairing is made here, where both come from one `PoolIndex`, and cannot be made anywhere
/// else.
#[derive(Debug, Clone)]
pub struct PoolAnswer<T> {
    /// What was asked for.
    pub found: T,
    /// The state of the walk it was drawn from.
    pub walk: PoolSnapshotReport,
}

/// Summarises the cached snapshot: how much was walked, and what the walk could not do.
pub fn snapshot_report(
    engine: &DebugEngine,
    walk: impl Into<PoolWalk>,
) -> Result<PoolSnapshotReport, PoolQueryError> {
    let index = prepare_index(engine, walk.into())?;
    Ok(report_of(&index))
}

fn report_of(index: &PoolIndex) -> PoolSnapshotReport {
    PoolSnapshotReport {
        layout: index.layout.clone(),
        total_chunks: index.spans.len(),
        allocated_chunks: index
            .spans
            .iter()
            .filter(|span| span.state == PoolState::Allocated)
            .count(),
        // Computed in one place, from the walk's own two bits, so no caller has to know that
        // "incomplete" has more than one cause — or invent the distinction from the diagnostics.
        coverage: match (index.complete, index.budget_expired) {
            (true, _) => WalkCoverage::Complete,
            (false, true) => WalkCoverage::BudgetExpired,
            (false, false) => WalkCoverage::Partial,
        },
        diagnostics: index.diagnostics.clone(),
        stalls: index.stalls,
        refused_chunks: index.refused_chunks,
        unplaced_bytes: index.unplaced_bytes,
    }
}

/// Validate the target, resolve the layout, and take (or reuse) a pool snapshot.
///
/// `walk.refresh` forces a fresh walk; otherwise a snapshot cached for this session is
/// reused, because walking every pool page is far too expensive to repeat per query.
/// `walk.budget` bounds a walk that does happen — see [`DEFAULT_WALK_BUDGET`].
pub(crate) fn prepare_index(
    engine: &DebugEngine,
    walk: PoolWalk,
) -> Result<PoolIndex, PoolQueryError> {
    let started = Instant::now();
    if !engine.is_kernel_target()? {
        return Err(PoolQueryError::NotKernelTarget);
    }
    let status = engine.execution_status()?;
    if status == DEBUG_STATUS_NO_DEBUGGEE {
        return Err(PoolQueryError::NoDebuggee);
    }
    if status != DEBUG_STATUS_BREAK {
        return Err(PoolQueryError::TargetRunning);
    }
    let machine = engine.processor_type()?;
    if machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(PoolQueryError::UnsupportedArchitecture { machine });
    }

    // Deliberately *not* bumping the generation on refresh. The generation is part of
    // `SessionKey`, which keys the layout cache — bumping it per refresh would re-resolve
    // every PDB symbol and leak a fresh cache entry each time, so a long-lived host that
    // refreshes regularly would accumulate layouts without bound and pay the symbol
    // latency over and over. The snapshot cache takes `refresh` directly and invalidates
    // itself; the generation only has to move when the *target* changes, which is what
    // `invalidate_session` is for.
    let key = SessionKey {
        image: engine.kernel_image()?,
        session: generation(),
        target: engine.target_identity(),
    };
    // The layout cache takes the same key and narrows it to a `LayoutKey` itself — a layout
    // describes the *image*, not which target instance is loaded, and the two ways of getting
    // that wrong are opposite. Keyed on the target it grew an entry per engine and per
    // `end_session` that nothing pruned; keyed on the base alone, two Windows builds whose
    // kernels load at one address share a layout, which is not a leak but wrong data reported
    // confidently.
    let layout = LayoutCache::global()
        .get_or_resolve(engine, key, LayoutTarget::Kernel)
        .map_err(|error| PoolQueryError::Layout(error.to_string()))?;
    let module = engine.module_identity("nt")?;
    if !module.symbols.has_type_info() || module.symbol_file.is_empty() {
        return Err(PoolQueryError::Layout(
            "DbgEng did not load private PDB type information for nt".into(),
        ));
    }
    let provenance = layout
        .provenance(module)
        .map_err(|error| PoolQueryError::Layout(error.to_string()))?;
    let remaining = walk
        .budget
        .map(|budget| budget.saturating_sub(started.elapsed()));

    // Keyed on the whole `SessionKey`: a programmatic host receives no session
    // notifications, so the generation alone would let a snapshot outlive its target.
    snapshots()
        .get_or_refresh(key, walk.refresh, || {
            let mut snapshot = SnapshotWalker {
                memory: engine,
                layout: &layout,
                traversal_limit: 1_000_000,
            }
            .walk(remaining)?;
            snapshot.layout = provenance;
            Ok(snapshot)
        })
        // Mapped from the walk's own error type rather than from a string it was flattened
        // into: an interrupt is the one stop here that is not a failure, and a `to_string()`
        // at the cache boundary is where that used to be lost.
        .map_err(|error| match error {
            SnapshotError::Interrupted => PoolQueryError::Interrupted,
            other => PoolQueryError::Walk(other.to_string()),
        })
}

/// Every *allocated* chunk carrying `tag`, named either way [`crate::pool::parse_tag`] accepts:
/// 1..4 ASCII bytes (`"Tgsm"`), or the raw form `0x` + 8 hex digits (`"0x5467736d"`).
///
/// Prefer the raw form for anything read back out of a [`PoolSpan`], because the displayed one
/// is lossy — a tag with an unprintable byte renders as `.` and so does a literal `.`, and
/// feeding *that* rendering back here finds a different tag rather than failing. See
/// [`crate::pool::display_is_ambiguous`].
///
/// Only allocated chunks are indexed by tag: a freed chunk's tag is not reliably
/// preserved by the allocator, so returning "freed chunks with this tag" would be
/// inventing information. Use [`chunk_at`] to ask about a specific freed address.
pub fn find_tag(
    engine: &DebugEngine,
    tag: &str,
    filter: Option<PoolPageFilter>,
    walk: impl Into<PoolWalk>,
) -> Result<PoolAnswer<Vec<PoolSpan>>, PoolQueryError> {
    let raw_tag = parse_tag(tag).ok_or(PoolQueryError::InvalidTag)?;
    let index = prepare_index(engine, walk.into())?;
    Ok(PoolAnswer {
        found: collect_tag(&index, raw_tag, filter),
        walk: report_of(&index),
    })
}

fn collect_tag(index: &PoolIndex, raw_tag: u32, filter: Option<PoolPageFilter>) -> Vec<PoolSpan> {
    index
        .postings
        .get(&raw_tag)
        .into_iter()
        .flatten()
        .filter_map(|&position| index.spans.get(position))
        .filter(|span| match filter {
            None => true,
            Some(PoolPageFilter::Paged) => span.pool_kind.is_paged(),
            Some(PoolPageFilter::NonPaged) => !span.pool_kind.is_paged(),
        })
        .cloned()
        .collect()
}

/// The chunk containing `address`, with its immediate neighbours.
///
/// `Ok(None)` means the address is not covered by the snapshot at all — a different
/// answer from "it is a free hole", which comes back as a chunk whose
/// [`PoolState`] is not `Allocated`.
pub fn chunk_at(
    engine: &DebugEngine,
    address: u64,
    walk: impl Into<PoolWalk>,
) -> Result<PoolAnswer<Option<PoolNeighbourhood>>, PoolQueryError> {
    let index = prepare_index(engine, walk.into())?;
    Ok(PoolAnswer {
        found: neighbourhood_at(&index, address),
        walk: report_of(&index),
    })
}

fn neighbourhood_at(index: &PoolIndex, address: u64) -> Option<PoolNeighbourhood> {
    let position = index
        .spans
        .iter()
        .position(|span| span.contains_address(address))?;
    // Two conditions, and both are needed. `predecessor`/`successor` enforce allocator
    // identity — same heap, backend and subsegment, neither side unreadable — which a bare
    // "next entry in the vector" check does not.
    //
    // On top of that the spans must actually touch. The allocator leaves slack wherever a
    // block would straddle a page, and `walk_lfh` omits that slot, so two spans can pass
    // the identity check with a gap between them. Reporting those as bordering would
    // misstate the very geometry this API exists to describe.
    let chunk = index.spans[position].clone();
    // Contiguity compares one span's end with the next one's start. `end()` is the raw chunk
    // end for every backend, and `header_address` is the raw chunk *start* for every backend
    // but VS, where the chunk header sits in front of the pool header this records. Comparing
    // across that offset would reject every genuine VS neighbour, so VS is exempt and LFH —
    // the only backend where the allocator leaves slack — keeps the check.
    //
    // Exempting it by backend, and not by testing `header_address == usable_address` as this
    // did: no walker emits a span where those are equal. `walk_lfh` and `walk_page_ranges` put
    // the usable bytes a pool header past the header exactly as `walk_vs` does, so that test
    // was false for every real span and the check it gated never ran outside the fixtures.
    // Only the `#[cfg(test)]` `PoolSpan::allocation` builds spans it held for.
    let touching = |left: &PoolSpan, right: &PoolSpan| {
        // `predecessor`/`successor` pair spans from one backend, so testing either is both.
        left.backend == PoolBackend::Vs || left.end() == right.header_address
    };
    Some(PoolNeighbourhood {
        previous: index
            .predecessor(position)
            .and_then(|previous| index.spans.get(previous))
            .filter(|previous| touching(previous, &chunk))
            .cloned(),
        next: index
            .successor(position)
            .and_then(|next| index.spans.get(next))
            .filter(|next| touching(&chunk, next))
            .cloned(),
        chunk,
    })
}

/// A per-tag census of the snapshot, heaviest consumer first.
///
/// This is the structured answer to the question `!poolused` renders as text, but
/// taken from our own walk, so it stays consistent with [`find_tag`] and [`chunk_at`].
pub fn tag_census(
    engine: &DebugEngine,
    walk: impl Into<PoolWalk>,
) -> Result<PoolAnswer<Vec<PoolTagSummary>>, PoolQueryError> {
    let index = prepare_index(engine, walk.into())?;
    Ok(PoolAnswer {
        found: summarize_tags(&index),
        walk: report_of(&index),
    })
}

fn summarize_tags(index: &PoolIndex) -> Vec<PoolTagSummary> {
    let mut summaries: std::collections::HashMap<u32, PoolTagSummary> =
        std::collections::HashMap::new();
    for span in index
        .spans
        .iter()
        .filter(|span| span.state == PoolState::Allocated)
    {
        let entry = summaries
            .entry(span.raw_tag)
            .or_insert_with(|| PoolTagSummary {
                display_tag: span.display_tag.clone(),
                raw_tag: span.raw_tag,
                allocations: 0,
                total_bytes: 0,
                paged_allocations: 0,
                nonpaged_allocations: 0,
            });
        entry.allocations += 1;
        entry.total_bytes = entry.total_bytes.saturating_add(span.size);
        if span.pool_kind.is_paged() {
            entry.paged_allocations += 1;
        } else {
            entry.nonpaged_allocations += 1;
        }
    }
    let mut census: Vec<_> = summaries.into_values().collect();
    census.sort_by(|left, right| {
        right
            .total_bytes
            .cmp(&left.total_bytes)
            .then_with(|| left.display_tag.cmp(&right.display_tag))
    });
    census
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{HeapIdentity, PoolKind};

    fn heap(id: u64) -> HeapIdentity {
        HeapIdentity {
            pool_state: id,
            heap: id,
            special: false,
        }
    }

    fn index_of(spans: Vec<PoolSpan>) -> PoolIndex {
        PoolIndex::build(crate::pool::PoolSnapshot {
            spans,
            complete: true,
            ..crate::pool::PoolSnapshot::default()
        })
    }

    fn allocation(
        address: u64,
        size: u64,
        tag: &[u8; 4],
        kind: PoolKind,
        heap_id: u64,
    ) -> PoolSpan {
        PoolSpan::allocation(
            address,
            size,
            u32::from_le_bytes(*tag),
            kind,
            heap(heap_id),
            PoolBackend::Lfh,
        )
    }

    #[test]
    fn test_unsupported_architecture_names_the_machine() {
        // The extension used to own this check; the message is load-bearing for the
        // E_INVALIDARG/E_FAIL mapping, so pin it here now that it lives in the API.
        assert_eq!(
            PoolQueryError::UnsupportedArchitecture { machine: 0xaa64 }.to_string(),
            "pool walking supports x64 targets only (machine 0xaa64)"
        );
    }

    /// The conversion is what keeps a plain `refresh` argument safe: every caller that never
    /// heard of a budget gets one anyway, which is the whole reason the wedge is closed
    /// without each of them having to opt in.
    #[test]
    fn test_a_bare_refresh_flag_still_carries_a_budget() {
        assert_eq!(
            PoolWalk::from(false),
            PoolWalk {
                refresh: false,
                budget: Some(DEFAULT_WALK_BUDGET)
            }
        );
        assert_eq!(PoolWalk::from(true), PoolWalk::refreshed());
        assert_eq!(
            PoolWalk::cached().within(Duration::from_secs(5)).budget,
            Some(Duration::from_secs(5))
        );
        // Only for a caller that can interrupt the walk itself — the extension command.
        assert_eq!(
            PoolWalk::refreshed().unbounded(),
            PoolWalk {
                refresh: true,
                budget: None
            }
        );
    }

    #[test]
    fn test_find_tag_returns_only_matching_allocations() {
        let index = index_of(vec![
            allocation(0x1000, 0x68, b"Tgsm", PoolKind::NonPagedNx, 1),
            allocation(0x2000, 0x40, b"Tfub", PoolKind::Paged, 1),
            allocation(0x3000, 0x68, b"Tgsm", PoolKind::NonPagedNx, 1),
        ]);
        let found = collect_tag(&index, u32::from_le_bytes(*b"Tgsm"), None);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|span| span.display_tag == "Tgsm"));
    }

    /// A tag nothing can print is still a tag, and only the raw form can ask for it.
    ///
    /// Both allocations below render `....`, so the rendering cannot be the key: handed back as
    /// a tag it parses as four literal `.` bytes and finds the *other* allocation — an answer,
    /// not an error, which is what made this worth a test rather than a doc note.
    #[test]
    fn test_a_binary_tag_is_found_by_its_bytes_not_by_its_rendering() {
        let binary = [0x00u8, 0x01, 0x80, 0xff];
        let index = index_of(vec![
            allocation(0x1000, 0x68, &binary, PoolKind::NonPagedNx, 1),
            allocation(0x2000, 0x40, b"....", PoolKind::NonPagedNx, 1),
        ]);
        assert_eq!(
            crate::pool::decode::display_tag(u32::from_le_bytes(binary)),
            crate::pool::decode::display_tag(u32::from_le_bytes(*b"....")),
            "the premise: these two are indistinguishable once rendered"
        );

        // The rendering finds the literal dots, and says nothing about the tag above it.
        let rendered = parse_tag("....").expect("four ASCII bytes parse");
        let by_rendering = collect_tag(&index, rendered, None);
        assert_eq!(by_rendering.len(), 1);
        assert_eq!(by_rendering[0].usable_address, 0x2000);

        // The raw form finds the one that has no other name.
        let raw = parse_tag(&crate::pool::raw_tag_hex(u32::from_le_bytes(binary)))
            .expect("the raw form parses");
        let by_bytes = collect_tag(&index, raw, None);
        assert_eq!(by_bytes.len(), 1);
        assert_eq!(by_bytes[0].usable_address, 0x1000);
    }

    #[test]
    fn test_page_filter_splits_paged_from_nonpaged() {
        let index = index_of(vec![
            allocation(0x1000, 0x68, b"Tsst", PoolKind::NonPagedNx, 1),
            allocation(0x2000, 0x40, b"Tsst", PoolKind::Paged, 1),
        ]);
        let raw = u32::from_le_bytes(*b"Tsst");
        assert_eq!(
            collect_tag(&index, raw, Some(PoolPageFilter::NonPaged)).len(),
            1
        );
        assert_eq!(
            collect_tag(&index, raw, Some(PoolPageFilter::Paged)).len(),
            1
        );
        assert_eq!(collect_tag(&index, raw, None).len(), 2);
    }

    #[test]
    fn test_unknown_tag_yields_no_matches() {
        let index = index_of(vec![allocation(
            0x1000,
            0x68,
            b"Tgsm",
            PoolKind::NonPagedNx,
            1,
        )]);
        assert!(collect_tag(&index, u32::from_le_bytes(*b"zzzz"), None).is_empty());
    }

    #[test]
    fn test_chunk_lookup_reports_neighbours_within_one_heap() {
        let index = index_of(vec![
            allocation(0x1000, 0x100, b"Aaaa", PoolKind::NonPagedNx, 1),
            allocation(0x1100, 0x100, b"Bbbb", PoolKind::NonPagedNx, 1),
            allocation(0x1200, 0x100, b"Cccc", PoolKind::NonPagedNx, 1),
        ]);
        let found = neighbourhood_at(&index, 0x1180).expect("address is covered");
        assert_eq!(found.chunk.display_tag, "Bbbb");
        assert_eq!(found.previous.unwrap().display_tag, "Aaaa");
        assert_eq!(found.next.unwrap().display_tag, "Cccc");
    }

    /// A VS chunk as `walk_vs` reports one: the physical `_POOL_HEADER` sits a chunk header
    /// into the chunk, and the usable bytes a pool header past that. So the raw chunk start,
    /// `header_address` and `usable_address` are three different addresses — the geometry
    /// `PoolSpan::allocation` cannot build, and the reason glslang/win-kexp#85 went unnoticed.
    fn vs_allocation(chunk: u64, chunk_size: u64, tag: &[u8; 4], heap_id: u64) -> PoolSpan {
        const VS_HEADER: u64 = 0x10;
        const POOL_HEADER: u64 = 0x10;
        let raw_tag = u32::from_le_bytes(*tag);
        PoolSpan {
            header_address: chunk + VS_HEADER,
            usable_address: chunk + VS_HEADER + POOL_HEADER,
            size: chunk_size - VS_HEADER - POOL_HEADER,
            requested_size: None,
            raw_tag,
            display_tag: crate::pool::decode::display_tag(raw_tag),
            pool_kind: PoolKind::NonPagedNx,
            numa_node: 0,
            heap: heap(heap_id),
            subsegment: Some(0x9000),
            backend: PoolBackend::Vs,
            state: PoolState::Allocated,
            size_class: chunk_size as u32,
        }
    }

    /// glslang/win-kexp#85: the contiguity check compared `end()` — which lands on the raw
    /// chunk end — with the next span's `header_address`, which for a VS chunk is a chunk
    /// header *past* its start. The two differ by exactly that header for every genuinely
    /// adjacent pair, so `previous` and `next` came back `None` for every VS allocation there
    /// is: the one question `chunk_at` exists to answer, disabled for a whole backend.
    #[test]
    fn test_vs_neighbours_are_reported_despite_their_chunk_header() {
        let index = index_of(vec![
            vs_allocation(0x1000, 0x100, b"Aaaa", 1),
            vs_allocation(0x1100, 0x100, b"Bbbb", 1),
            vs_allocation(0x1200, 0x100, b"Cccc", 1),
        ]);
        let found = neighbourhood_at(&index, 0x1150).expect("address is covered");
        assert_eq!(found.chunk.display_tag, "Bbbb");
        assert_eq!(found.previous.unwrap().display_tag, "Aaaa");
        assert_eq!(found.next.unwrap().display_tag, "Cccc");
    }

    /// An LFH block as `walk_lfh` reports one: the slot start is the header, and the usable
    /// bytes begin a pool header past it. `PoolSpan::allocation` puts both at the same
    /// address, which no walker ever does.
    fn lfh_allocation(slot: u64, unit: u64, tag: &[u8; 4], heap_id: u64) -> PoolSpan {
        const POOL_HEADER: u64 = 0x10;
        let raw_tag = u32::from_le_bytes(*tag);
        PoolSpan {
            header_address: slot,
            usable_address: slot + POOL_HEADER,
            size: unit - POOL_HEADER,
            requested_size: None,
            raw_tag,
            display_tag: crate::pool::decode::display_tag(raw_tag),
            pool_kind: PoolKind::NonPagedNx,
            numa_node: 0,
            heap: heap(heap_id),
            subsegment: Some(0x8000),
            backend: PoolBackend::Lfh,
            state: PoolState::Allocated,
            size_class: unit as u32,
        }
    }

    /// Allocator slack separates these two: `walk_lfh` omits a slot that would straddle a
    /// page, so spans can share every allocator identity and still not touch. Reporting
    /// them as bordering would misstate the grooming geometry this API exists to describe.
    ///
    /// With **real** LFH geometry, which is the whole point. Gating the check on
    /// `header_address == usable_address` — as it was — turned it off for every span a walker
    /// emits, since all of them put the usable bytes a pool header past the header. The
    /// fixture was the only thing that ever satisfied the gate, so the check passed its test
    /// and did nothing on a target.
    #[test]
    fn test_neighbours_must_actually_touch() {
        let index = index_of(vec![
            lfh_allocation(0x1000, 0x100, b"Aaaa", 1),
            // 0x1100..0x1200 is the slot the allocator skipped.
            lfh_allocation(0x1200, 0x100, b"Bbbb", 1),
        ]);
        let found = neighbourhood_at(&index, 0x1250).expect("address is covered");
        assert_eq!(found.chunk.display_tag, "Bbbb");
        assert!(
            found.previous.is_none(),
            "slack between spans must not count as bordering"
        );

        // And the check has to stay off the other foot: two LFH slots that really do abut are
        // neighbours, or the fix for the above is just the VS bug moved one backend over.
        let index = index_of(vec![
            lfh_allocation(0x1000, 0x100, b"Aaaa", 1),
            lfh_allocation(0x1100, 0x100, b"Bbbb", 1),
        ]);
        let found = neighbourhood_at(&index, 0x1150).expect("address is covered");
        assert_eq!(found.previous.unwrap().display_tag, "Aaaa");
    }

    #[test]
    fn test_neighbours_do_not_cross_a_heap_boundary() {
        let index = index_of(vec![
            allocation(0x1000, 0x100, b"Aaaa", PoolKind::NonPagedNx, 1),
            allocation(0x1100, 0x100, b"Bbbb", PoolKind::NonPagedNx, 2),
        ]);
        // Spans sort by (heap, address), so these are adjacent in the vector but
        // belong to different heaps — reporting them as neighbours would be a lie.
        let found = neighbourhood_at(&index, 0x1150).expect("address is covered");
        assert_eq!(found.chunk.display_tag, "Bbbb");
        assert!(found.previous.is_none());
    }

    #[test]
    fn test_address_outside_every_span_is_not_found() {
        let index = index_of(vec![allocation(
            0x1000,
            0x100,
            b"Aaaa",
            PoolKind::NonPagedNx,
            1,
        )]);
        assert!(neighbourhood_at(&index, 0x9999).is_none());
    }

    /// The case that motivated the report: a walk that reached nothing must still hand
    /// back its reasons, or an empty result is indistinguishable from an empty pool.
    #[test]
    fn test_empty_walk_still_reports_why() {
        let index = PoolIndex::build(crate::pool::PoolSnapshot {
            diagnostics: PoolDiagnostics::from_iter(["cannot read pool node 0 heap 2".to_string()]),
            ..crate::pool::PoolSnapshot::default()
        });
        let report = report_of(&index);
        assert_eq!(report.total_chunks, 0);
        assert_eq!(report.allocated_chunks, 0);
        assert_eq!(
            report.diagnostics.examples(),
            ["cannot read pool node 0 heap 2"]
        );
        assert_eq!(report.diagnostics.emitted(), 1);
    }

    /// The three ways a walk can end are three values, and the two that fall short are not
    /// the same answer.
    ///
    /// A caller reads them for opposite reasons: `BudgetExpired` says "ask again with more
    /// time and you will see more"; `Partial` says "this is all there is to see, however long
    /// you wait". Collapsing both into `complete: false` — which is what this replaced — makes
    /// the difference unrecoverable, because by the time anyone holds the snapshot both look
    /// like a short list.
    #[test]
    fn test_coverage_says_which_way_a_walk_fell_short() {
        let walked = |complete, budget_expired| {
            report_of(&PoolIndex::build(crate::pool::PoolSnapshot {
                complete,
                budget_expired,
                ..crate::pool::PoolSnapshot::default()
            }))
            .coverage
        };
        assert_eq!(walked(true, false), WalkCoverage::Complete);
        assert_eq!(walked(false, true), WalkCoverage::BudgetExpired);
        assert_eq!(walked(false, false), WalkCoverage::Partial);
        assert!(WalkCoverage::Complete.complete());
        assert!(!WalkCoverage::BudgetExpired.complete());
        assert!(!WalkCoverage::Partial.complete());
    }

    #[test]
    fn test_report_counts_allocated_separately_from_total() {
        let index = index_of(vec![
            allocation(0x1000, 0x68, b"Tgsm", PoolKind::NonPagedNx, 1),
            allocation(0x1100, 0x68, b"Tgsm", PoolKind::NonPagedNx, 1),
        ]);
        let report = report_of(&index);
        assert_eq!(report.total_chunks, 2);
        assert_eq!(report.allocated_chunks, 2);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn test_census_totals_by_tag_and_sorts_by_bytes() {
        let index = index_of(vec![
            allocation(0x1000, 0x68, b"Tgsm", PoolKind::NonPagedNx, 1),
            allocation(0x1100, 0x68, b"Tgsm", PoolKind::NonPagedNx, 1),
            allocation(0x1200, 0x400, b"Tfub", PoolKind::Paged, 1),
        ]);
        let census = summarize_tags(&index);
        assert_eq!(census[0].display_tag, "Tfub");
        assert_eq!(census[0].total_bytes, 0x400);
        assert_eq!(census[0].paged_allocations, 1);
        assert_eq!(census[1].display_tag, "Tgsm");
        assert_eq!(census[1].allocations, 2);
        assert_eq!(census[1].total_bytes, 0xd0);
        assert_eq!(census[1].nonpaged_allocations, 2);
    }
}
