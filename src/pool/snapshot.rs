use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

use super::decode::{
    DESCRIPTOR_FLAG_LFH, DESCRIPTOR_FLAG_VS, PAGE_SIZE, PoolHeaderLayout, adjust_page_end_header,
    big_page_probe, decode_descriptor_at, decode_large_allocation, decode_lfh_offsets,
    decode_pool_header, decode_rb_root, decode_slist_header_next, decode_vs_sizes,
    lfh_bitmap_state, read_u16, read_u32, read_u64, valid_descriptor_tree_signature,
    valid_page_segment_signature, valid_vs_signature,
};
use super::{
    HeapIdentity, PoolBackend, PoolKind, PoolSpan, PoolState,
    layout::{LayoutError, PoolLayout},
};

type SnapshotSource = Box<dyn std::error::Error + Send + Sync>;

/// A set of chunk addresses shared by every region one heap's evidence covers.
///
/// Shared rather than owned per region: see [`PoolRegion::reusable_chunks`].
type SharedChunks = Arc<HashSet<u64>>;

#[derive(Debug, Error)]
pub(crate) enum SnapshotError {
    #[error("read at {address:#x}+{size:#x}: {source}")]
    Read {
        address: u64,
        size: usize,
        #[source]
        source: SnapshotSource,
    },
    #[error("valid-region query at {address:#x}+{size:#x}: {source}")]
    RegionQuery {
        address: u64,
        size: usize,
        #[source]
        source: SnapshotSource,
    },
    #[error(
        "sparse virtual range at {address:#x}+{size:#x} (valid {valid_base:#x}+{valid_size:#x})"
    )]
    RegionValidation {
        address: u64,
        size: usize,
        valid_base: u64,
        valid_size: usize,
    },
    #[error("snapshot layout lookup failed: {source}")]
    Layout {
        #[source]
        source: LayoutError,
    },
    #[error("pool snapshot interrupted by Ctrl+C")]
    Interrupted,
    #[error("pool snapshot ran out of its walk budget")]
    BudgetExpired,
    #[error("interrupt-status query failed: {source}")]
    InterruptQuery {
        #[source]
        source: SnapshotSource,
    },
    #[error("invalid snapshot data: {detail}")]
    InvalidData { detail: String },
}

impl SnapshotError {
    /// Whether this ends the whole walk rather than one step of it.
    ///
    /// Every other variant is local — a node that would not read, a region that is not
    /// committed — so the walk records it and carries on. These two are not: carrying on
    /// would ignore the operator's Ctrl+C, or run past the deadline that exists precisely
    /// so nobody is left waiting on a walk they have already given up on.
    ///
    /// **Every site that swallows an error into a diagnostic has to re-raise these**, or
    /// the stop signal is absorbed by the first enclosing loop and the walk keeps going —
    /// which is the failure this predicate exists to make hard to reintroduce.
    fn halts_walk(&self) -> bool {
        matches!(self, Self::Interrupted | Self::BudgetExpired)
    }
}

impl From<LayoutError> for SnapshotError {
    fn from(source: LayoutError) -> Self {
        Self::Layout { source }
    }
}

fn missing_layout(item: impl Into<String>) -> SnapshotError {
    LayoutError::Missing { item: item.into() }.into()
}

#[derive(Debug, Clone)]
pub(crate) struct PoolRegion {
    pub address: u64,
    pub size: usize,
    pub pool_kind: PoolKind,
    pub numa_node: u16,
    pub heap: HeapIdentity,
    pub subsegment: Option<u64>,
    pub backend: PoolBackend,
    pub unit_size: u32,
    pub bitmap: Vec<u8>,
    pub heap_key: u64,
    pub pool_header: PoolHeaderLayout,
    pub vs_header_size: usize,
    pub vs_sizes_offset: usize,
    pub known_tag: Option<u32>,
    /// Allocator-derived states for segment/page-range cells.
    pub states: Vec<PoolState>,
    /// VS chunk-header addresses present in the free tree.
    ///
    /// Shared, not owned: one region is created per page-range descriptor, so on a real
    /// kernel there are thousands of them, and they all carry the *same* evidence — the one
    /// set their heap's free tree produced. Cloning the set per region copied it thousands
    /// of times over, entirely off the wire and so invisible when the walk was blamed on
    /// debugger reads.
    pub reusable_chunks: SharedChunks,
    /// VS chunk-header addresses present in delay-free/lookaside lists. Shared for the
    /// reason [`Self::reusable_chunks`] is.
    pub cached_chunks: SharedChunks,
}

pub(crate) trait PoolMemory {
    fn read_exact(&self, address: u64, size: usize) -> Result<Vec<u8>, SnapshotError>;
    fn valid_region(&self, address: u64, size: usize) -> Result<(u64, usize), SnapshotError>;
    fn interrupted(&self) -> Result<bool, SnapshotError>;

    /// Whether this walk's wall-clock deadline has passed.
    ///
    /// Defaulted to "never" so a plain memory source carries no clock; [`Budgeted`] is what
    /// puts one in front of it, and [`SnapshotWalker::walk`] is what wraps it.
    fn out_of_budget(&self) -> bool {
        false
    }
}

/// A memory source with a deadline attached.
///
/// The walk already polled for Ctrl+C, but **only a human at a WinDbg prompt ever sets
/// that**. A programmatic caller — an MCP server driving the query API — has no way to say
/// "that is long enough", so its own timeout frees the caller and leaves the engine
/// walking; since one engine serves one target one call at a time, every later call to that
/// target queues behind the walk. The session is then wedged until it is killed, which on a
/// live kernel leaves the guest halted. This is the clock that makes that impossible.
struct Budgeted<'a, M> {
    inner: &'a M,
    /// `None` runs to completion — correct only where something else can stop the walk.
    deadline: Option<Instant>,
}

impl<'a, M> Budgeted<'a, M> {
    fn new(inner: &'a M, deadline: Option<Instant>) -> Self {
        Self { inner, deadline }
    }
}

impl<M: PoolMemory> PoolMemory for Budgeted<'_, M> {
    fn read_exact(&self, address: u64, size: usize) -> Result<Vec<u8>, SnapshotError> {
        self.inner.read_exact(address, size)
    }

    fn valid_region(&self, address: u64, size: usize) -> Result<(u64, usize), SnapshotError> {
        self.inner.valid_region(address, size)
    }

    fn interrupted(&self) -> Result<bool, SnapshotError> {
        self.inner.interrupted()
    }

    /// This wrapper *adds* a deadline; it does not replace whatever the source already had,
    /// so wrapping can only ever make a walk stop sooner.
    fn out_of_budget(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
            || self.inner.out_of_budget()
    }
}

impl PoolMemory for crate::dbgeng::DebugEngine {
    fn read_exact(&self, address: u64, size: usize) -> Result<Vec<u8>, SnapshotError> {
        self.read_memory(address, size)
            .map_err(|source| SnapshotError::Read {
                address,
                size,
                source: Box::new(source),
            })
    }

    fn valid_region(&self, address: u64, size: usize) -> Result<(u64, usize), SnapshotError> {
        self.valid_virtual_region(address, size)
            .map_err(|source| SnapshotError::RegionQuery {
                address,
                size,
                source: Box::new(source),
            })
    }

    fn interrupted(&self) -> Result<bool, SnapshotError> {
        crate::dbgeng::DebugEngine::interrupted(self).map_err(|source| {
            SnapshotError::InterruptQuery {
                source: Box::new(source),
            }
        })
    }
}

/// The one place a walk asks whether it is still allowed to run.
///
/// Called from every loop that can iterate an unbounded number of times, so the cost of one
/// runaway step is a step and not a walk. Both answers halt (see
/// [`SnapshotError::halts_walk`]); they differ in what the caller does with the halt, which
/// [`SnapshotWalker::walk`] decides.
fn check_budget(memory: &impl PoolMemory) -> Result<(), SnapshotError> {
    if memory.interrupted()? {
        return Err(SnapshotError::Interrupted);
    }
    if memory.out_of_budget() {
        return Err(SnapshotError::BudgetExpired);
    }
    Ok(())
}

fn guarded_read(
    memory: &impl PoolMemory,
    address: u64,
    size: usize,
) -> Result<Vec<u8>, SnapshotError> {
    if size == 0 {
        return Ok(Vec::new());
    }
    let (valid_base, valid_size) = memory.valid_region(address, size)?;
    if valid_base != address || valid_size < size {
        return Err(SnapshotError::RegionValidation {
            address,
            size,
            valid_base,
            valid_size,
        });
    }
    memory.read_exact(address, size)
}

fn scalar(memory: &impl PoolMemory, address: u64, size: usize) -> Result<u64, SnapshotError> {
    let bytes = guarded_read(memory, address, size)?;
    match size {
        1 => bytes
            .first()
            .map(|&byte| byte as u64)
            .ok_or_else(|| SnapshotError::InvalidData {
                detail: "short u8".into(),
            }),
        2 => Ok(
            u16::from_le_bytes(bytes.try_into().map_err(|_| SnapshotError::InvalidData {
                detail: "short u16".into(),
            })?) as u64,
        ),
        4 => Ok(
            u32::from_le_bytes(bytes.try_into().map_err(|_| SnapshotError::InvalidData {
                detail: "short u32".into(),
            })?) as u64,
        ),
        8 => Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| {
            SnapshotError::InvalidData {
                detail: "short u64".into(),
            }
        })?)),
        _ => Err(SnapshotError::InvalidData {
            detail: format!("unsupported scalar size {size}"),
        }),
    }
}

fn walk_tree_nodes(
    memory: &impl PoolMemory,
    root: u64,
    left_offset: usize,
    right_offset: usize,
    limit: usize,
    label: &str,
    diagnostics: &mut Vec<String>,
) -> Result<Vec<u64>, SnapshotError> {
    let mut nodes = Vec::new();
    let mut stack = vec![root];
    let mut seen = HashSet::new();
    while let Some(node) = stack.pop() {
        let node = node & !0xf;
        if node == 0 {
            continue;
        }
        check_budget(memory)?;
        if !seen.insert(node) {
            diagnostics.push(format!("{label} cycle detected at {node:#x}"));
            continue;
        }
        if nodes.len() >= limit {
            diagnostics.push(format!("{label} traversal limit reached"));
            break;
        }
        let size = left_offset.max(right_offset).saturating_add(8);
        match guarded_read(memory, node, size) {
            Ok(bytes) => {
                nodes.push(node);
                if let Some(right) = read_u64(&bytes, right_offset) {
                    stack.push(right);
                }
                if let Some(left) = read_u64(&bytes, left_offset) {
                    stack.push(left);
                }
            }
            Err(error) => diagnostics.push(format!("unreadable {label} node {node:#x}: {error}")),
        }
    }
    Ok(nodes)
}

fn tree_nodes(
    memory: &impl PoolMemory,
    layout: &PoolLayout,
    tree_address: u64,
    limit: usize,
    label: &str,
    diagnostics: &mut Vec<String>,
) -> Result<Vec<u64>, SnapshotError> {
    let Ok(root_offset) = layout.field("_RTL_RB_TREE", "Root") else {
        diagnostics.push(format!("cannot resolve {label} root field"));
        return Ok(Vec::new());
    };
    let root_value = match scalar(memory, tree_address + root_offset as u64, 8) {
        Ok(value) => value,
        Err(error) => {
            diagnostics.push(format!("cannot read {label} root: {error}"));
            return Ok(Vec::new());
        }
    };
    let encoded = if let Ok(encoded_offset) = layout.field("_RTL_RB_TREE", "Encoded") {
        match scalar(memory, tree_address + encoded_offset as u64, 1) {
            Ok(value) => value & 1 != 0,
            Err(error) => {
                diagnostics.push(format!("cannot read {label} encoded flag: {error}"));
                return Ok(Vec::new());
            }
        }
    } else {
        false
    };
    let Some(root) = decode_rb_root(root_value, tree_address, encoded) else {
        diagnostics.push(format!("rejecting corrupt {label} root {root_value:#x}"));
        return Ok(Vec::new());
    };
    let Ok(left) = layout.field("_RTL_BALANCED_NODE", "Left") else {
        return Ok(Vec::new());
    };
    let Ok(right) = layout.field("_RTL_BALANCED_NODE", "Right") else {
        return Ok(Vec::new());
    };
    walk_tree_nodes(memory, root, left, right, limit, label, diagnostics)
}

fn walk_slist_nodes(
    memory: &impl PoolMemory,
    layout: &PoolLayout,
    head: u64,
    limit: usize,
    label: &str,
    diagnostics: &mut Vec<String>,
) -> Result<Vec<u64>, SnapshotError> {
    let mut nodes = Vec::new();
    let mut seen = HashSet::new();
    let Ok(header) = layout.type_layout("_SLIST_HEADER") else {
        diagnostics.push(format!("cannot resolve {label} SLIST header type"));
        return Ok(nodes);
    };
    let Ok(alignment_offset) = layout.field("_SLIST_HEADER", "Alignment") else {
        diagnostics.push(format!("cannot resolve {label} SLIST depth field"));
        return Ok(nodes);
    };
    let Ok(region_offset) = layout.field("_SLIST_HEADER", "Region") else {
        diagnostics.push(format!("cannot resolve {label} SLIST next field"));
        return Ok(nodes);
    };
    let bytes = match guarded_read(memory, head, header.size as usize) {
        Ok(value) => value,
        Err(error) => {
            diagnostics.push(format!("cannot read {label} list head: {error}"));
            return Ok(nodes);
        }
    };
    let depth = read_u16(&bytes, alignment_offset).map_or(0, usize::from);
    let mut entry = read_u64(&bytes, region_offset)
        .map(decode_slist_header_next)
        .unwrap_or(0);
    let expected = depth.min(limit);
    while entry != 0 && nodes.len() < expected {
        check_budget(memory)?;
        if !seen.insert(entry) {
            diagnostics.push(format!("{label} list cycle detected at {entry:#x}"));
            break;
        }
        nodes.push(entry);
        match scalar(memory, entry, 8) {
            Ok(next) => entry = next & !0xf,
            Err(error) => {
                diagnostics.push(format!("unreadable {label} list entry {entry:#x}: {error}"));
                break;
            }
        }
    }
    if depth > limit {
        diagnostics.push(format!("{label} list traversal limit reached"));
    } else if nodes.len() != depth {
        diagnostics.push(format!(
            "{label} list depth is {depth}, but only {} entries were readable",
            nodes.len()
        ));
    }
    Ok(nodes)
}

fn insert_cached_chunk_candidates(
    cached: &mut HashSet<u64>,
    entry: u64,
    pool_header_size: u64,
    vs_header_size: u64,
) {
    cached.insert(entry);
    let overhead = pool_header_size.saturating_add(vs_header_size);
    if let Some(header) = entry.checked_sub(overhead) {
        cached.insert(header);
        if header & (PAGE_SIZE - 1) == PAGE_SIZE - pool_header_size {
            cached.insert(header.saturating_sub(16));
        }
    }
}

#[derive(Default)]
struct Discovery {
    regions: Vec<PoolRegion>,
    diagnostics: Vec<String>,
}

const SPECIAL_POOL_KINDS: [PoolKind; 4] = [
    PoolKind::SpecialNonPaged,
    PoolKind::SpecialNonPagedNx,
    PoolKind::SpecialPaged,
    PoolKind::SpecialPrototypePaged,
];

/// Enumerates every pool region, appending to `discovery`.
///
/// Takes `discovery` by reference rather than returning it so that a walk which halts
/// part-way still hands back the regions it *did* find. Returning `Result<Discovery, _>`
/// threw them away on the one path where they matter most — the caller can then walk what
/// discovery reached instead of reporting an empty pool.
fn discover_pool_regions(
    memory: &impl PoolMemory,
    layout: &PoolLayout,
    traversal_limit: usize,
    discovery: &mut Discovery,
) -> Result<(), SnapshotError> {
    let state_address = *layout
        .globals
        .get("ExPoolState")
        .ok_or_else(|| missing_layout("ExPoolState"))?;
    let state = layout.type_layout("_EX_POOL_HEAP_MANAGER_STATE")?;
    let node = layout.type_layout("_EX_HEAP_POOL_NODE")?;
    let number_offset = layout.field("_EX_POOL_HEAP_MANAGER_STATE", "NumberOfPools")?;
    let node_offset = layout.field("_EX_POOL_HEAP_MANAGER_STATE", "PoolNode")?;
    let special_offset = layout.field("_EX_POOL_HEAP_MANAGER_STATE", "SpecialHeaps")?;
    let heaps_offset = layout.field("_EX_HEAP_POOL_NODE", "Heaps")?;
    let lookasides_offset = layout.field("_EX_HEAP_POOL_NODE", "Lookasides").ok();
    let dynamic_lookaside_size = layout
        .type_layout("_RTL_DYNAMIC_LOOKASIDE")
        .ok()
        .map(|lookaside| lookaside.size as u64);
    let number = scalar(memory, state_address + number_offset as u64, 4)? as usize;
    if number == 0 || number > 256 {
        return Err(SnapshotError::InvalidData {
            detail: format!("implausible ExPoolState.NumberOfPools {number}"),
        });
    }
    let mut heaps = Vec::new();
    for numa_node in 0..number {
        let Some(node_address) = state_address
            .checked_add(node_offset as u64)
            .and_then(|address| address.checked_add(numa_node as u64 * node.size as u64))
        else {
            discovery
                .diagnostics
                .push("pool-node address overflow".into());
            continue;
        };
        for heap_index in 0..4usize {
            let pointer_address = node_address + heaps_offset as u64 + heap_index as u64 * 8;
            let heap = match scalar(memory, pointer_address, 8) {
                Ok(value) => value,
                Err(error) => {
                    discovery.diagnostics.push(format!(
                        "cannot read pool node {numa_node} heap {heap_index}: {error}"
                    ));
                    continue;
                }
            };
            if heap != 0 {
                let pool_kind = match heap_index {
                    0 => PoolKind::NonPagedExecutable,
                    1 => PoolKind::NonPagedNx,
                    2 => PoolKind::Paged,
                    _ => PoolKind::PrototypePaged,
                };
                let dynamic_lookaside =
                    lookasides_offset
                        .zip(dynamic_lookaside_size)
                        .and_then(|(offset, size)| {
                            node_address.checked_add(offset as u64).and_then(|base| {
                                base.checked_add(u64::from(pool_kind.is_paged()) * size)
                            })
                        });
                heaps.push((heap, numa_node as u16, pool_kind, false, dynamic_lookaside));
            }
        }
    }
    for (special_index, pool_kind) in SPECIAL_POOL_KINDS.into_iter().enumerate() {
        let pointer_address = state_address + special_offset as u64 + special_index as u64 * 8;
        match scalar(memory, pointer_address, 8) {
            Ok(heap) if heap != 0 => heaps.push((heap, 0, pool_kind, true, None)),
            Ok(_) => {}
            Err(error) => discovery.diagnostics.push(format!(
                "cannot read special pool heap {special_index}: {error}"
            )),
        }
    }

    let globals_address = *layout
        .globals
        .get("RtlpHpHeapGlobals")
        .ok_or_else(|| missing_layout("RtlpHpHeapGlobals"))?;
    let heap_key = scalar(
        memory,
        globals_address + layout.field("_RTLP_HP_HEAP_GLOBALS", "HeapKey")? as u64,
        8,
    )?;
    let lfh_key = scalar(
        memory,
        globals_address + layout.field("_RTLP_HP_HEAP_GLOBALS", "LfhKey")? as u64,
        8,
    )?;
    for (heap_address, numa_node, pool_kind, special, dynamic_lookaside) in heaps {
        let identity = HeapIdentity {
            pool_state: state_address,
            heap: heap_address,
            special,
        };
        if let Err(error) = discover_heap_regions(
            memory,
            layout,
            heap_address,
            numa_node,
            pool_kind,
            identity,
            dynamic_lookaside,
            heap_key,
            lfh_key,
            traversal_limit,
            discovery,
        ) {
            // A halt is about the walk, not about this heap. Recorded as a per-heap failure
            // it would read as "heap 3 is unreadable" and — worse — the loop would carry on
            // to heaps 4..n, each stopping the same way, so the deadline would bound one
            // heap instead of the walk.
            if error.halts_walk() {
                return Err(error);
            }
            discovery.diagnostics.push(format!(
                "cannot fully discover heap {heap_address:#x}: {error}"
            ));
        }
    }
    let _ = state.size;
    Ok(())
}

/// One place carrying VS free-chunk state.
struct VsRoot {
    base: u64,
    tree_offset: usize,
    delay_offset: Option<usize>,
}

/// Resolves where a VS context keeps its free-chunk state. Both shapes are supported,
/// because a debugger host does not get to choose which build it is pointed at:
///
/// * **pre-26100** — `FreeChunkTree`/`DelayFreeContext` are inline in `_HEAP_VS_CONTEXT`,
///   so there is exactly one root: the context itself.
/// * **26100+** — they moved into `_HEAP_VS_AFFINITY_SLOT`s reached through a slot map.
///   `SlotMapRef` and each `SlotRef` are offsets *from the context*, scaled by 64 bytes,
///   and the map holds `AffinityMask + 1` entries. Entries routinely share a slot, so the
///   result is deduplicated.
///
/// Returning an empty vector means neither shape resolved; the caller then walks no VS
/// evidence rather than guessing at an address.
fn vs_roots(
    memory: &impl PoolMemory,
    layout: &PoolLayout,
    context: u64,
    diagnostics: &mut Vec<String>,
) -> Vec<VsRoot> {
    // Legacy shape wins when present: a context that still carries the tree has no slots.
    if let Ok(tree_offset) = layout.field("_HEAP_VS_CONTEXT", "FreeChunkTree") {
        return vec![VsRoot {
            base: context,
            tree_offset,
            delay_offset: layout.field("_HEAP_VS_CONTEXT", "DelayFreeContext").ok(),
        }];
    }

    let (Ok(tree_offset), Ok(back_offset), Ok(slot_map_ref_offset), Ok(affinity_offset)) = (
        layout.field("_HEAP_VS_AFFINITY_SLOT", "FreeChunkTree"),
        layout.field("_HEAP_VS_AFFINITY_SLOT", "VsContext"),
        layout.field("_HEAP_VS_CONTEXT", "SlotMapRef"),
        layout.field("_HEAP_VS_CONTEXT", "AffinityMask"),
    ) else {
        diagnostics
            .push("VS free-chunk state is in neither the context nor an affinity slot".into());
        return Vec::new();
    };

    let (Ok(slot_map_ref), Ok(affinity_mask)) = (
        scalar(memory, context + slot_map_ref_offset as u64, 2),
        scalar(memory, context + affinity_offset as u64, 1),
    ) else {
        diagnostics.push(format!(
            "cannot read the VS slot map of context {context:#x}"
        ));
        return Vec::new();
    };

    let entries = affinity_mask as usize + 1;
    // A zero ref would alias the context, and the entry count is bounded by the affinity
    // mask; both would otherwise walk arbitrary memory.
    if slot_map_ref == 0 || entries > 256 {
        diagnostics.push(format!(
            "implausible VS slot map for context {context:#x}: ref {slot_map_ref:#x}, {entries} entries"
        ));
        return Vec::new();
    }

    let entry_size = layout
        .type_layout("_HEAP_VS_SLOT_MAP")
        .map_or(4, |map| map.size as u64);
    let slot_ref_offset = layout.field("_HEAP_VS_SLOT_MAP", "SlotRef").unwrap_or(0);
    let delay_offset = layout
        .field("_HEAP_VS_AFFINITY_SLOT", "DelayFreeContext")
        .ok();
    let slot_map = context + (slot_map_ref << 6);

    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    for index in 0..entries {
        let entry = slot_map + index as u64 * entry_size;
        let Ok(slot_ref) = scalar(memory, entry + slot_ref_offset as u64, 2) else {
            // Skipping silently would drop that slot's free tree and delay-free list, so
            // its chunks get misclassified with nothing to say why.
            diagnostics.push(format!(
                "cannot read VS slot map entry {index} at {entry:#x}; its affinity slot is omitted"
            ));
            continue;
        };
        if slot_ref == 0 {
            continue;
        }
        let slot = context + (slot_ref << 6);
        if !seen.insert(slot) {
            continue;
        }
        // Require the slot to name the context we came from. A misdecoded SlotRef would
        // otherwise point the tree walk at unrelated memory that happens to be readable.
        match scalar(memory, slot + back_offset as u64, 8) {
            Ok(owner) if owner == context => roots.push(VsRoot {
                base: slot,
                tree_offset,
                delay_offset,
            }),
            Ok(owner) => diagnostics.push(format!(
                "VS affinity slot {slot:#x} claims context {owner:#x}, not {context:#x}; skipped"
            )),
            Err(error) => {
                diagnostics.push(format!("cannot read VS affinity slot {slot:#x}: {error}"))
            }
        }
    }
    roots
}

fn discover_vs_evidence(
    memory: &impl PoolMemory,
    layout: &PoolLayout,
    heap_address: u64,
    dynamic_lookaside: Option<u64>,
    limit: usize,
    diagnostics: &mut Vec<String>,
) -> Result<(SharedChunks, SharedChunks), SnapshotError> {
    let Ok(vs_context_offset) = layout.field("_SEGMENT_HEAP", "VsContext") else {
        return Ok(Default::default());
    };
    let context = heap_address + vs_context_offset as u64;
    let roots = vs_roots(memory, layout, context, diagnostics);
    if roots.is_empty() {
        return Ok(Default::default());
    }
    let tree_node_offset = layout
        .field("_HEAP_VS_CHUNK_FREE_HEADER", "TreeNode")
        .unwrap_or(0);
    let mut reusable = HashSet::new();
    for root in &roots {
        reusable.extend(
            tree_nodes(
                memory,
                layout,
                root.base + root.tree_offset as u64,
                limit,
                "VS free tree",
                diagnostics,
            )?
            .into_iter()
            .map(|node| node.saturating_sub(tree_node_offset as u64)),
        );
    }

    let mut cached = HashSet::new();
    let pool_header_size = layout
        .type_layout("_POOL_HEADER")
        .map_or(0, |value| value.size as u64);
    let vs_header_size = layout
        .type_layout("_HEAP_VS_CHUNK_HEADER")
        .map_or(0, |value| value.size as u64);
    if let Ok(list_offset) = layout.field("_HEAP_VS_DELAY_FREE_CONTEXT", "ListHead") {
        for root in &roots {
            // Pre-26100 the delay-free list sits beside the tree in the context; from
            // 26100 it is per-slot. Either way it is a known offset from `root.base`.
            let Some(delay_offset) = root.delay_offset else {
                continue;
            };
            for entry in walk_slist_nodes(
                memory,
                layout,
                root.base + delay_offset as u64 + list_offset as u64,
                limit,
                "VS delay-free",
                diagnostics,
            )? {
                insert_cached_chunk_candidates(
                    &mut cached,
                    entry,
                    pool_header_size,
                    vs_header_size,
                );
            }
        }
    }

    if let Some(dynamic) = dynamic_lookaside {
        let bucket_count = layout
            .field("_RTL_DYNAMIC_LOOKASIDE", "BucketCount")
            .ok()
            .and_then(|offset| scalar(memory, dynamic + offset as u64, 4).ok())
            .unwrap_or(0) as usize;
        let buckets_offset = layout.field("_RTL_DYNAMIC_LOOKASIDE", "Buckets").ok();
        let lookaside = layout.type_layout("_RTL_LOOKASIDE").ok();
        let list_offset = layout.field("_RTL_LOOKASIDE", "ListHead").ok();
        if bucket_count > 64 {
            diagnostics.push(format!(
                "rejecting implausible VS dynamic-lookaside bucket count {bucket_count}"
            ));
        } else if let (Some(buckets_offset), Some(lookaside), Some(list_offset)) =
            (buckets_offset, lookaside, list_offset)
        {
            for bucket in 0..bucket_count {
                let Some(bucket_address) = dynamic
                    .checked_add(buckets_offset as u64)
                    .and_then(|value| value.checked_add(bucket as u64 * u64::from(lookaside.size)))
                else {
                    diagnostics.push("VS dynamic-lookaside bucket address overflow".into());
                    break;
                };
                if let Ok(size_offset) = layout.field("_RTL_LOOKASIDE", "Size") {
                    match scalar(memory, bucket_address + size_offset as u64, 4) {
                        Ok(0) => continue,
                        Ok(size) if size > 0x1_0000 => {
                            diagnostics.push(format!(
                                "rejecting VS dynamic-lookaside bucket {bucket} size {size:#x}"
                            ));
                            continue;
                        }
                        Ok(_) => {}
                        Err(error) => {
                            diagnostics.push(format!(
                                "cannot read VS dynamic-lookaside bucket {bucket} size: {error}"
                            ));
                            continue;
                        }
                    }
                }
                for entry in walk_slist_nodes(
                    memory,
                    layout,
                    bucket_address + list_offset as u64,
                    limit,
                    "VS dynamic-lookaside",
                    diagnostics,
                )? {
                    // Lookaside links point at usable data, while delay-free links
                    // point at the VS chunk header. Keep both page-end header
                    // candidates; only a decoded chunk at that address can match.
                    insert_cached_chunk_candidates(
                        &mut cached,
                        entry,
                        pool_header_size,
                        vs_header_size,
                    );
                }
            }
        }
    }
    Ok((Arc::new(reusable), Arc::new(cached)))
}

#[allow(clippy::too_many_arguments)]
fn discover_heap_regions(
    memory: &impl PoolMemory,
    layout: &PoolLayout,
    heap_address: u64,
    numa_node: u16,
    pool_kind: PoolKind,
    identity: HeapIdentity,
    dynamic_lookaside: Option<u64>,
    heap_key: u64,
    lfh_key: u64,
    traversal_limit: usize,
    discovery: &mut Discovery,
) -> Result<(), SnapshotError> {
    let heap = layout.type_layout("_SEGMENT_HEAP")?;
    let context = layout.type_layout("_HEAP_SEG_CONTEXT")?;
    let contexts_offset = layout.field("_SEGMENT_HEAP", "SegContexts")?;
    let (reusable_chunks, cached_chunks) = discover_vs_evidence(
        memory,
        layout,
        heap_address,
        dynamic_lookaside,
        traversal_limit,
        &mut discovery.diagnostics,
    )?;

    // Touch both LFH roots through guarded reads. Descriptor metadata remains the
    // authoritative source of active subsegments, while these probes make corrupt
    // bucket/affinity metadata an isolated diagnostic instead of a fatal read.
    if let Ok(lfh_offset) = layout.field("_SEGMENT_HEAP", "LfhContext") {
        let lfh = heap_address + lfh_offset as u64;
        for (field, label) in [
            ("Buckets", "LFH buckets"),
            ("AffinitySlots", "LFH affinity slots"),
        ] {
            if let Ok(offset) = layout.field("_HEAP_LFH_CONTEXT", field)
                && let Err(error) = guarded_read(memory, lfh + offset as u64, 8)
            {
                discovery
                    .diagnostics
                    .push(format!("cannot read {label}: {error}"));
            }
        }
    }

    for context_index in 0..2usize {
        check_budget(memory)?;
        let context_address =
            heap_address + contexts_offset as u64 + context_index as u64 * context.size as u64;
        if let Err(error) = discover_segment_context(
            memory,
            layout,
            context_address,
            numa_node,
            pool_kind,
            identity,
            heap_key,
            lfh_key,
            traversal_limit,
            &reusable_chunks,
            &cached_chunks,
            discovery,
        ) {
            // As in `discover_pool_regions`: a halt is about the walk, not about this
            // context. Absorbed here it would read as "context 1 is unreadable", and on the
            // *last* context index it would be absorbed entirely — `discover_heap_regions`
            // would carry on into `discover_large_allocations` and return `Ok`, so even a
            // Ctrl+C would only stop the walk if some later site happened to raise it again.
            if error.halts_walk() {
                return Err(error);
            }
            discovery.diagnostics.push(format!(
                "cannot discover segment context {context_index} at {context_address:#x}: {error}"
            ));
        }
    }
    discover_large_allocations(
        memory,
        layout,
        heap_address,
        numa_node,
        pool_kind,
        identity,
        heap_key,
        traversal_limit,
        discovery,
    )?;
    let _ = heap.size;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn discover_segment_context(
    memory: &impl PoolMemory,
    layout: &PoolLayout,
    context_address: u64,
    numa_node: u16,
    pool_kind: PoolKind,
    identity: HeapIdentity,
    heap_key: u64,
    lfh_key: u64,
    traversal_limit: usize,
    reusable_chunks: &SharedChunks,
    cached_chunks: &SharedChunks,
    discovery: &mut Discovery,
) -> Result<(), SnapshotError> {
    let segment = layout.type_layout("_HEAP_PAGE_SEGMENT")?;
    let descriptor = layout.type_layout("_HEAP_PAGE_RANGE_DESCRIPTOR")?;
    let shift = scalar(
        memory,
        context_address + layout.field("_HEAP_SEG_CONTEXT", "UnitShift")? as u64,
        1,
    )? as u32;
    if !(12..=20).contains(&shift) {
        return Ok(());
    }
    let first_descriptor = scalar(
        memory,
        context_address + layout.field("_HEAP_SEG_CONTEXT", "FirstDescriptorIndex")? as u64,
        1,
    )? as usize;
    let segment_mask = scalar(
        memory,
        context_address + layout.field("_HEAP_SEG_CONTEXT", "SegmentMask")? as u64,
        8,
    )?;
    let segment_size = (!segment_mask).wrapping_add(1);
    let descriptor_count = (segment_size >> shift).min(4096) as usize;
    if descriptor_count == 0 || first_descriptor >= descriptor_count {
        return Ok(());
    }

    let free_tree = context_address + layout.field("_HEAP_SEG_CONTEXT", "FreePageRanges")? as u64;
    let free_nodes: HashSet<_> = tree_nodes(
        memory,
        layout,
        free_tree,
        traversal_limit,
        "free-page tree",
        &mut discovery.diagnostics,
    )?
    .into_iter()
    .collect();

    let list_head = context_address + layout.field("_HEAP_SEG_CONTEXT", "SegmentListHead")? as u64;
    let list_entry = layout.field("_HEAP_PAGE_SEGMENT", "ListEntry")?;
    let desc_array = layout.field("_HEAP_PAGE_SEGMENT", "DescArray")?;
    let signature_offset = layout.field("_HEAP_PAGE_SEGMENT", "Signature")?;
    let unit_offset = layout.field("_HEAP_PAGE_RANGE_DESCRIPTOR", "UnitSize")?;
    let flags_offset = layout.field("_HEAP_PAGE_RANGE_DESCRIPTOR", "RangeFlags")?;
    let tree_signature_offset = layout.field("_HEAP_PAGE_RANGE_DESCRIPTOR", "TreeSignature")?;
    let tree_node_offset = layout.field("_HEAP_PAGE_RANGE_DESCRIPTOR", "TreeNode")?;
    let metadata_size = descriptor_count
        .checked_mul(descriptor.size as usize)
        .ok_or_else(|| SnapshotError::InvalidData {
            detail: "descriptor metadata size overflow".into(),
        })?;
    let mut entry = scalar(memory, list_head, 8)? & !0xf;
    let mut seen = HashSet::new();
    while entry != 0 && entry != list_head && seen.len() < traversal_limit {
        check_budget(memory)?;
        if !seen.insert(entry) {
            discovery
                .diagnostics
                .push(format!("segment-list cycle at {entry:#x}"));
            break;
        }
        let segment_address = entry.saturating_sub(list_entry as u64);
        let segment_header = match guarded_read(memory, segment_address, segment.size as usize) {
            Ok(bytes) => bytes,
            Err(error) => {
                discovery.diagnostics.push(format!(
                    "cannot read segment header {segment_address:#x}: {error}"
                ));
                match scalar(memory, entry, 8) {
                    Ok(next) => entry = next & !0xf,
                    Err(_) => break,
                }
                continue;
            }
        };
        let signature = read_u64(&segment_header, signature_offset)
            .or_else(|| read_u32(&segment_header, signature_offset).map(u64::from))
            .unwrap_or(0);
        if !valid_page_segment_signature(signature, segment_address, context_address, heap_key) {
            discovery.diagnostics.push(format!(
                "rejecting page segment {segment_address:#x} with invalid signature {signature:#x}"
            ));
            entry = read_u64(&segment_header, list_entry).unwrap_or(0) & !0xf;
            continue;
        }
        let metadata_address = segment_address + desc_array as u64;
        let metadata = match guarded_read(memory, metadata_address, metadata_size) {
            Ok(bytes) => bytes,
            Err(error) => {
                discovery.diagnostics.push(format!(
                    "cannot read descriptors at {metadata_address:#x}: {error}"
                ));
                entry = read_u64(&segment_header, list_entry).unwrap_or(0) & !0xf;
                continue;
            }
        };
        let mut descriptor_index = first_descriptor;
        while descriptor_index < descriptor_count {
            let offset = descriptor_index * descriptor.size as usize;
            let Some(decoded) = decode_descriptor_at(
                &metadata,
                offset,
                descriptor.size as usize,
                unit_offset,
                flags_offset,
            ) else {
                descriptor_index += 1;
                continue;
            };
            if decoded.committed
                && !read_u32(&metadata, offset + tree_signature_offset)
                    .is_some_and(valid_descriptor_tree_signature)
            {
                discovery.diagnostics.push(format!(
                    "rejecting descriptor {descriptor_index} at {:#x} with invalid tree signature",
                    metadata_address + offset as u64
                ));
                descriptor_index += decoded.unit_size.max(1) as usize;
                continue;
            }
            let unit_size = decoded.unit_size as usize;
            let Some(address) = segment_address.checked_add((descriptor_index as u64) << shift)
            else {
                break;
            };
            let size = unit_size.checked_shl(shift).unwrap_or(0);
            if size == 0 {
                descriptor_index += unit_size.max(1);
                continue;
            }
            // Verifier special pool sets DESCRIPTOR_FLAG_LFH on its page-range descriptors,
            // but the page holds a pool header plus fill rather than a subsegment. Parsing
            // it as LFH rejects the range outright ("implausible LFH metadata") *during
            // region creation*, so the allocation never reaches the walk at all — which is
            // why classifying it correctly here, and not just at dispatch time, is what
            // makes special-pool chunks visible. `walk_region` routes on `heap.special`.
            let backend = if identity.special {
                PoolBackend::Segment
            } else if decoded.flags & DESCRIPTOR_FLAG_LFH != 0 {
                PoolBackend::Lfh
            } else if decoded.flags & DESCRIPTOR_FLAG_VS != 0 {
                PoolBackend::Vs
            } else {
                PoolBackend::Segment
            };
            let mut region_address = address;
            let mut region_size = size;
            let mut bitmap = Vec::new();
            let mut block_size = size.min(u32::MAX as usize) as u32;
            if backend == PoolBackend::Lfh {
                let subsegment = layout.type_layout("_HEAP_LFH_SUBSEGMENT")?;
                let offsets = layout.field("_HEAP_LFH_SUBSEGMENT", "BlockOffsets")?
                    + layout.field("_HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS", "EncodedData")?;
                let count_offset = layout.field("_HEAP_LFH_SUBSEGMENT", "BlockCount")?;
                let bitmap_offset = layout.field("_HEAP_LFH_SUBSEGMENT", "BlockBitmap")?;
                let header = match guarded_read(memory, address, subsegment.size as usize) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        discovery
                            .diagnostics
                            .push(format!("cannot read LFH subsegment {address:#x}: {error}"));
                        descriptor_index += unit_size;
                        continue;
                    }
                };
                let encoded = read_u32(&header, offsets).unwrap_or(0);
                let (decoded_block_size, decoded_first) =
                    decode_lfh_offsets(encoded, address, lfh_key as u32);
                block_size = u32::from(decoded_block_size);
                let first = usize::from(decoded_first);
                let blocks = read_u16(&header, count_offset)
                    .map(usize::from)
                    .unwrap_or(0);
                if block_size < 8
                    || blocks == 0
                    || first >= region_size
                    || blocks.saturating_mul(block_size as usize) > region_size - first
                {
                    discovery.diagnostics.push(format!(
                        "rejecting implausible LFH metadata at {address:#x}"
                    ));
                    descriptor_index += unit_size;
                    continue;
                }
                bitmap = match guarded_read(
                    memory,
                    address + bitmap_offset as u64,
                    blocks.div_ceil(4),
                ) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        discovery
                            .diagnostics
                            .push(format!("cannot read LFH bitmap at {address:#x}: {error}"));
                        descriptor_index += unit_size;
                        continue;
                    }
                };
                region_address += first as u64;
                region_size = blocks * block_size as usize;
            } else if backend == PoolBackend::Vs {
                let vs = layout.type_layout("_HEAP_VS_SUBSEGMENT")?;
                let header = match guarded_read(memory, address, vs.size as usize) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        discovery
                            .diagnostics
                            .push(format!("cannot read VS subsegment {address:#x}: {error}"));
                        descriptor_index += unit_size;
                        continue;
                    }
                };
                let signature =
                    read_u16(&header, layout.field("_HEAP_VS_SUBSEGMENT", "Signature")?)
                        .unwrap_or(0)
                        & 0x7fff;
                let declared =
                    read_u16(&header, layout.field("_HEAP_VS_SUBSEGMENT", "Size")?).unwrap_or(0);
                if !valid_vs_signature(signature ^ declared) {
                    discovery.diagnostics.push(format!(
                        "rejecting VS subsegment {address:#x} with invalid signature"
                    ));
                    descriptor_index += unit_size;
                    continue;
                }
                let first = (vs.size as usize).next_multiple_of(16);
                if first >= region_size {
                    descriptor_index += unit_size;
                    continue;
                }
                region_address += first as u64;
                region_size -= first;
                block_size = 0;
            }
            let descriptor_node = metadata_address + offset as u64 + tree_node_offset as u64;
            let state = if free_nodes.contains(&descriptor_node) || !decoded.committed {
                PoolState::ReusableFree
            } else {
                PoolState::Allocated
            };
            discovery.regions.push(PoolRegion {
                address: region_address,
                size: region_size,
                pool_kind,
                numa_node,
                heap: identity,
                subsegment: Some(address),
                backend,
                unit_size: block_size,
                bitmap,
                heap_key,
                pool_header: layout.pool_header_layout()?,
                vs_header_size: layout.type_layout("_HEAP_VS_CHUNK_HEADER")?.size as usize,
                vs_sizes_offset: layout.field("_HEAP_VS_CHUNK_HEADER", "Sizes")?,
                known_tag: None,
                states: vec![state],
                reusable_chunks: Arc::clone(reusable_chunks),
                cached_chunks: Arc::clone(cached_chunks),
            });
            descriptor_index += unit_size;
        }
        entry = read_u64(&segment_header, list_entry).unwrap_or(0) & !0xf;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn discover_large_allocations(
    memory: &impl PoolMemory,
    layout: &PoolLayout,
    heap_address: u64,
    numa_node: u16,
    pool_kind: PoolKind,
    identity: HeapIdentity,
    heap_key: u64,
    traversal_limit: usize,
    discovery: &mut Discovery,
) -> Result<(), SnapshotError> {
    let Ok(tree_offset) = layout.field("_SEGMENT_HEAP", "LargeAllocMetadata") else {
        return Ok(());
    };
    let Ok(large) = layout.type_layout("_HEAP_LARGE_ALLOC_DATA") else {
        return Ok(());
    };
    let Ok(tree_node) = layout.field("_HEAP_LARGE_ALLOC_DATA", "TreeNode") else {
        return Ok(());
    };
    let Ok(virtual_offset) = layout.field("_HEAP_LARGE_ALLOC_DATA", "VirtualAddress") else {
        return Ok(());
    };
    let Ok(pages_offset) = layout.field("_HEAP_LARGE_ALLOC_DATA", "AllocatedPages") else {
        return Ok(());
    };
    let tree_address = heap_address + tree_offset as u64;
    let nodes = tree_nodes(
        memory,
        layout,
        tree_address,
        traversal_limit,
        "large-allocation tree",
        &mut discovery.diagnostics,
    )?;
    for node in nodes {
        let allocation_address = node.saturating_sub(tree_node as u64);
        let allocation = match guarded_read(memory, allocation_address, large.size as usize) {
            Ok(bytes) => bytes,
            Err(error) => {
                discovery.diagnostics.push(format!(
                    "cannot read large-allocation metadata {allocation_address:#x}: {error}"
                ));
                continue;
            }
        };
        let Some((virtual_address, pages)) = read_u64(&allocation, virtual_offset)
            .zip(read_u64(&allocation, pages_offset))
            .and_then(|(virtual_address, pages)| decode_large_allocation(virtual_address, pages))
        else {
            continue;
        };
        if pages > 0x10_0000 {
            discovery.diagnostics.push(format!(
                "rejecting implausible large allocation at {allocation_address:#x}"
            ));
            continue;
        }
        let bytes = pages.saturating_mul(PAGE_SIZE);
        let (tag, tracked_size) = match lookup_big_page_target(
            memory,
            layout,
            virtual_address,
            &mut discovery.diagnostics,
        )? {
            Some(value) => value,
            None => (0, bytes),
        };
        let size = tracked_size.min(bytes).min(usize::MAX as u64) as usize;
        let Ok(pool_header) = layout.pool_header_layout() else {
            continue;
        };
        discovery.regions.push(PoolRegion {
            address: virtual_address,
            size,
            pool_kind,
            numa_node,
            heap: identity,
            subsegment: None,
            backend: PoolBackend::Large,
            unit_size: size.min(u32::MAX as usize) as u32,
            bitmap: Vec::new(),
            heap_key,
            pool_header,
            vs_header_size: 0,
            vs_sizes_offset: 0,
            known_tag: Some(tag),
            states: vec![PoolState::Allocated],
            reusable_chunks: Arc::default(),
            cached_chunks: Arc::default(),
        });
    }
    Ok(())
}

const BIG_PAGE_PROBE_BATCH: usize = 256;

fn lookup_big_page_target(
    memory: &impl PoolMemory,
    layout: &PoolLayout,
    address: u64,
    diagnostics: &mut Vec<String>,
) -> Result<Option<(u32, u64)>, SnapshotError> {
    let Ok(entry) = layout.type_layout("_POOL_TRACKER_BIG_PAGES") else {
        return Ok(None);
    };
    let entry_size = entry.size as usize;
    let Ok(va_offset) = layout.field("_POOL_TRACKER_BIG_PAGES", "Va") else {
        return Ok(None);
    };
    let Ok(tag_offset) = layout.field("_POOL_TRACKER_BIG_PAGES", "Key") else {
        return Ok(None);
    };
    let Ok(size_offset) = layout.field("_POOL_TRACKER_BIG_PAGES", "NumberOfBytes") else {
        return Ok(None);
    };
    let Some(&table_pointer_address) = layout.globals.get("PoolBigPageTable") else {
        return Ok(None);
    };
    let table = match scalar(memory, table_pointer_address, 8) {
        Ok(value) => value,
        Err(error) => {
            diagnostics.push(format!("cannot read big-page table pointer: {error}"));
            return Ok(None);
        }
    };
    let Some(&size_address) = layout.globals.get("PoolBigPageTableSize") else {
        return Ok(None);
    };
    let count = match scalar(memory, size_address, 4).or_else(|_| scalar(memory, size_address, 8)) {
        Ok(value) => value as usize,
        Err(error) => {
            diagnostics.push(format!("cannot read big-page table size: {error}"));
            return Ok(None);
        }
    };
    if table == 0 || count == 0 || count > 0x10_0000 || !count.is_power_of_two() {
        diagnostics.push(format!("rejecting implausible big-page table size {count}"));
        return Ok(None);
    }
    let mut probes = big_page_probe(address, count).ok_or_else(|| SnapshotError::InvalidData {
        detail: format!("invalid big-page table size {count}"),
    })?;
    let mut remaining = count;
    'probe: while let Some(first_index) = probes.next() {
        check_budget(memory)?;
        let batch_len = BIG_PAGE_PROBE_BATCH.min(remaining).min(count - first_index);
        let byte_len =
            entry_size
                .checked_mul(batch_len)
                .ok_or_else(|| SnapshotError::InvalidData {
                    detail: "big-page probe batch size overflow".into(),
                })?;
        let entry_address = table
            .checked_add(first_index as u64 * entry.size as u64)
            .ok_or_else(|| SnapshotError::InvalidData {
                detail: "big-page probe address overflow".into(),
            })?;
        let bytes = match guarded_read(memory, entry_address, byte_len) {
            Ok(bytes) => bytes,
            Err(error) => {
                diagnostics.push(format!(
                    "cannot read big-page entries {first_index}..{} at {entry_address:#x}: {error}",
                    first_index + batch_len
                ));
                for _ in 1..batch_len {
                    let _ = probes.next();
                }
                remaining -= batch_len;
                continue;
            }
        };
        for batch_index in 0..batch_len {
            let offset = batch_index * entry_size;
            let index = first_index + batch_index;
            let Some(candidate) = read_u64(&bytes, offset + va_offset) else {
                diagnostics.push(format!("truncated big-page entry {index}"));
                continue;
            };
            if candidate == 0 {
                break 'probe;
            }
            if candidate & !1 == address {
                let Some(tag) = read_u32(&bytes, offset + tag_offset) else {
                    diagnostics.push(format!("truncated big-page tag at entry {index}"));
                    continue;
                };
                let Some(size) = read_u64(&bytes, offset + size_offset) else {
                    diagnostics.push(format!("truncated big-page size at entry {index}"));
                    continue;
                };
                return Ok(Some((tag, size)));
            }
        }
        for _ in 1..batch_len {
            let _ = probes.next();
        }
        remaining -= batch_len;
    }
    diagnostics.push(format!(
        "no validated big-page entry for large allocation {address:#x}"
    ));
    Ok(None)
}

/// How many verbatim examples of one kind of diagnostic to keep.
const DIAGNOSTIC_EXAMPLES: usize = 8;

/// The shape of a diagnostic: the message with every number standing in for itself.
///
/// "unreadable VS free tree node 0xffffc00f6ec02f90" and the same complaint about a
/// different node share a shape; a genuinely different complaint does not.
fn diagnostic_shape(message: &str) -> String {
    message
        .split_whitespace()
        .map(|token| {
            if token.contains(|character: char| character.is_ascii_digit()) {
                "#"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Collapse floods of near-identical diagnostics into examples plus a count.
///
/// A live target keeps allocating between the reads that make up one walk, so a single
/// stale list pointer yields one "unreadable ... node" line per node — 14k of them measured
/// on a busy kernel. That buries the handful of *distinct* problems a reader needs, and
/// every consumer truncates the list anyway, so which ones survive is decided by position
/// rather than by significance.
///
/// Nothing is dropped silently: each group keeps its first [`DIAGNOSTIC_EXAMPLES`] verbatim
/// and the rest become a count, so the volume — the number that says the walk was fighting a
/// moving target — is still on the page. Summaries go at the end, in the order the groups
/// first appeared, rather than interleaved where a group's last member happened to land.
fn collapse_repeats(diagnostics: Vec<String>) -> Vec<String> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    for message in diagnostics {
        let shape = diagnostic_shape(&message);
        let count = counts.entry(shape.clone()).or_insert_with(|| {
            order.push(shape);
            0
        });
        *count += 1;
        if *count <= DIAGNOSTIC_EXAMPLES {
            kept.push(message);
        }
    }
    for shape in order {
        let total = counts[&shape];
        if let Some(collapsed) = total.checked_sub(DIAGNOSTIC_EXAMPLES).filter(|n| *n > 0) {
            kept.push(format!("... and {collapsed} more like `{shape}`"));
        }
    }
    kept
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PoolSnapshot {
    pub spans: Vec<PoolSpan>,
    pub diagnostics: Vec<String>,
    pub complete: bool,
}

pub(crate) struct SnapshotWalker<'a, M> {
    pub memory: &'a M,
    pub layout: &'a PoolLayout,
    pub traversal_limit: usize,
}

/// Where a special-pool block sits, and whether that could be corroborated.
struct SpecialPlacement {
    usable: u64,
    size: u64,
    /// The size could not be confirmed, so `size` is a conservative upper bound covering
    /// the rest of the page rather than the allocation's real length. Callers must not
    /// treat it as a measurement — it inflates byte totals if they do.
    approximate: bool,
}

/// The byte Driver Verifier fills unused special-pool space with.
const SPECIAL_POOL_FILL: u8 = 0xfd;

/// Where a special-pool block sits inside its page, and how big it is.
///
/// Returns `(usable_address, size)`. The block is normally butted against the page end at
/// `page + PAGE_SIZE - align_up(size, 16)`; the 16-byte rounding matters, since a plain
/// `PAGE_SIZE - size` lands 8 bytes past the real block for a 0x68 allocation.
///
/// The size comes from `_POOL_HEADER.PreviousSize`, which is **8 bits wide and so cannot
/// describe every legal block**. A 0x140 allocation stores 0x40 there, and a bare range
/// check cannot tell that from a genuine 0x40 — both fit the page comfortably. The
/// placement is therefore corroborated against the fill: everything between the header and
/// the block must be Verifier's `0xfd`. A truncated size puts the block too close to the
/// page end, leaving real data where fill should be, and is rejected.
///
/// The same check declines rather than lies in the two other cases that break the
/// assumption: a page read only in part (nothing corroborates the tail), and a
/// start-aligned page (`nt!MmSpecialPoolCatchOverruns` clear), where the block sits
/// against the *preceding* guard page instead.
///
/// The fallback reports the whole page after the header. An over-broad chunk still answers
/// "was this freed, and which tag owned it"; a confidently wrong offset does not.
fn special_pool_placement(
    page: u64,
    requested: u64,
    header_size: u64,
    page_bytes: &[u8],
) -> SpecialPlacement {
    let available = page_bytes.len() as u64;
    let aligned = requested.next_multiple_of(16);
    if requested != 0 && available == PAGE_SIZE && aligned + header_size <= PAGE_SIZE {
        let start = (PAGE_SIZE - aligned) as usize;
        if page_bytes[header_size as usize..start]
            .iter()
            .all(|byte| *byte == SPECIAL_POOL_FILL)
        {
            return SpecialPlacement {
                usable: page + PAGE_SIZE - aligned,
                size: requested,
                approximate: false,
            };
        }
    }
    SpecialPlacement {
        usable: page + header_size,
        size: available.saturating_sub(header_size),
        approximate: true,
    }
}

/// The share of the budget discovery may spend before the region walk claims the rest.
///
/// The two halves are useless apart: discovery finds the regions, the walk reads what is in
/// them, and a snapshot with neither half finished is an empty pool. Discovery is also the
/// pointer-chasing half — one read per free-tree node, per list entry, per subsegment — so
/// on a live link it is the half that runs long, and left unchecked it would spend the whole
/// budget and leave nothing to walk. Holding it to two thirds means a walk that runs out of
/// time still reports the chunks in the regions it did reach, which is the answer a caller
/// asked a pool query for.
const DISCOVERY_BUDGET_SHARE: (u32, u32) = (2, 3);

/// Splits a walk budget into the deadline discovery works to and the one the whole walk
/// works to. `None` in gives `None` out for both: no budget, no deadlines.
///
/// A budget too large for `Instant` to represent — `PoolWalk::within` takes any `Duration`,
/// so a caller can hand over `Duration::MAX` — also yields `None` for both. Adding it would
/// panic, and "longer than this machine can measure" is a request to run unbounded, so
/// answering it that way is the caller's own meaning rather than a substitution for it.
///
/// Both halves stand or fall together, keyed on the whole-walk deadline. Deciding them
/// independently would pass `Duration::MAX` as a *bounded* discovery share (two thirds of it
/// still fits) against an unbounded walk — a state with no meaning behind it.
fn budget_deadlines(
    start: Instant,
    budget: Option<Duration>,
) -> (Option<Instant>, Option<Instant>) {
    let (numerator, denominator) = DISCOVERY_BUDGET_SHARE;
    let Some(whole) = budget.and_then(|full| start.checked_add(full)) else {
        return (None, None);
    };
    (
        budget.and_then(|full| start.checked_add(full / denominator * numerator)),
        Some(whole),
    )
}

impl<'a, M: PoolMemory> SnapshotWalker<'a, M> {
    /// Walks the pool, giving up after `budget` rather than running as long as it takes.
    ///
    /// `None` runs to completion. That is right only where something *else* can stop the
    /// walk — an operator's Ctrl+C at a WinDbg prompt — and wrong for a programmatic caller,
    /// where nothing sets that flag; see [`Budgeted`].
    ///
    /// Running out of time is **not** an error. It comes back as a snapshot that says what
    /// it reached, with `complete` cleared and a diagnostic naming the budget, because a
    /// partial walk still answers "here is a chunk carrying that tag" — and the alternative,
    /// an error, discards minutes of work to say nothing at all. A Ctrl+C is the opposite
    /// and still errors: an operator who interrupts is asking for the walk to stop, not for
    /// whatever it happened to have.
    pub(crate) fn walk(&self, budget: Option<Duration>) -> Result<PoolSnapshot, SnapshotError> {
        let (discovery_deadline, walk_deadline) = budget_deadlines(Instant::now(), budget);
        let mut snapshot = PoolSnapshot {
            diagnostics: vec!["per-session paged heaps are not included".into()],
            complete: true,
            ..PoolSnapshot::default()
        };

        let discovery_clock = Budgeted::new(self.memory, discovery_deadline);
        let mut discovery = Discovery::default();
        let mut expired = match discover_pool_regions(
            &discovery_clock,
            self.layout,
            self.traversal_limit,
            &mut discovery,
        ) {
            Ok(()) => false,
            Err(SnapshotError::BudgetExpired) => true,
            Err(error) => return Err(error),
        };
        if !discovery.diagnostics.is_empty() {
            snapshot.complete = false;
        }
        snapshot.diagnostics.append(&mut discovery.diagnostics);

        // The full deadline, so regions found before discovery ran out of its share still get
        // walked with the time discovery did not use.
        let walk_clock = Budgeted::new(self.memory, walk_deadline);
        let walker = SnapshotWalker {
            memory: &walk_clock,
            layout: self.layout,
            traversal_limit: self.traversal_limit,
        };
        let discovered = discovery.regions.len();
        let mut walked = 0usize;
        for region in discovery.regions {
            let outcome = if region.backend == PoolBackend::Large {
                // No reads of its own: the span comes from metadata discovery already did.
                walker.walk_large(&region, &mut snapshot);
                Ok(())
            } else {
                walker.walk_region(&region, &mut snapshot)
            };
            match outcome {
                // Counted only when the region was walked *through*. A region abandoned
                // part-way is exactly what the caveat below is for.
                Ok(()) => walked += 1,
                Err(SnapshotError::BudgetExpired) => {
                    expired = true;
                    break;
                }
                Err(error) => return Err(error),
            }
        }

        if expired {
            snapshot.complete = false;
            let allowed = match budget {
                Some(budget) => format!("{budget:?} budget"),
                None => "walk budget".to_string(),
            };
            snapshot.diagnostics.push(format!(
                "the walk ran out of its {allowed}: {walked} of {discovered} discovered regions \
                 were walked, and region discovery itself may not have finished. What is \
                 reported was really there; what is missing is unknown, not absent. Allow a \
                 longer budget for full coverage."
            ));
        }
        snapshot
            .spans
            .sort_by_key(|span| (span.heap, span.usable_address));
        snapshot.diagnostics = collapse_repeats(snapshot.diagnostics);
        Ok(snapshot)
    }

    /// Reads one region and decodes its chunks, stopping if the walk's time runs out.
    ///
    /// Checked per *extent*, not just per region: a region the allocator left with holes
    /// costs one `valid_region` and one `read_exact` per committed run, so a fragmented
    /// region is many round trips and checking only on the way in would let one region
    /// overrun the deadline by an unbounded amount. The backend decoders below need no such
    /// check — they run over bytes already in hand, off the wire entirely.
    fn walk_region(
        &self,
        region: &PoolRegion,
        snapshot: &mut PoolSnapshot,
    ) -> Result<(), SnapshotError> {
        let requested_end = region.address.saturating_add(region.size as u64);
        let mut cursor = region.address;
        while cursor < requested_end {
            check_budget(self.memory)?;
            let remaining = requested_end.saturating_sub(cursor).min(usize::MAX as u64) as usize;
            let (reported_base, reported_size) = match self.memory.valid_region(cursor, remaining) {
                Ok(valid) => valid,
                Err(error) => {
                    snapshot.diagnostics.push(format!(
                        "cannot query region {cursor:#x}+{remaining:#x}: {error}"
                    ));
                    self.unreadable(region, cursor, requested_end - cursor, snapshot);
                    break;
                }
            };
            let valid_base = reported_base.max(cursor).min(requested_end);
            if valid_base > cursor {
                snapshot.diagnostics.push(format!(
                    "region {:#x}+{:#x} is only committed through {cursor:#x}; unreadable space extends {:#x} bytes",
                    region.address,
                    region.size,
                    valid_base - cursor
                ));
                self.unreadable(region, cursor, valid_base - cursor, snapshot);
            }
            let valid_end = reported_base
                .saturating_add(reported_size as u64)
                .min(requested_end);
            if valid_end <= valid_base {
                snapshot.diagnostics.push(format!(
                    "valid-region query made no progress at {cursor:#x}"
                ));
                self.unreadable(region, valid_base, requested_end - valid_base, snapshot);
                break;
            }
            let bytes = match self
                .memory
                .read_exact(valid_base, (valid_end - valid_base) as usize)
            {
                Ok(bytes) => bytes,
                Err(error) => {
                    snapshot
                        .diagnostics
                        .push(format!("cannot read region {valid_base:#x}: {error}"));
                    self.unreadable(region, valid_base, valid_end - valid_base, snapshot);
                    cursor = valid_end;
                    continue;
                }
            };
            // Verifier special pool is page-granular, and its page-range descriptors still
            // carry DESCRIPTOR_FLAG_LFH — so this has to come *before* the backend
            // dispatch. Left to `walk_lfh`, the range's "subsegment header" is really a
            // pool header plus fill, the block bitmap is nonsense, and every allocation in
            // the heap silently disappears from the snapshot.
            if region.heap.special {
                self.walk_special_pool(region, valid_base, &bytes, snapshot);
                cursor = valid_end;
                continue;
            }
            match region.backend {
                PoolBackend::Lfh => self.walk_lfh(region, valid_base, &bytes, snapshot),
                PoolBackend::Vs => self.walk_vs(region, valid_base, &bytes, snapshot),
                PoolBackend::Segment => self.walk_page_ranges(region, valid_base, &bytes, snapshot),
                PoolBackend::Large => return Ok(()),
            }
            cursor = valid_end;
        }
        Ok(())
    }

    fn walk_large(&self, region: &PoolRegion, snapshot: &mut PoolSnapshot) {
        if region.size == 0 {
            return;
        }
        snapshot.spans.push(
            self.base_span(
                region,
                region.address,
                region.address,
                region.size as u64,
                region.known_tag.unwrap_or(0),
                region
                    .states
                    .first()
                    .copied()
                    .unwrap_or(PoolState::Allocated),
            ),
        );
    }

    fn base_span(
        &self,
        region: &PoolRegion,
        header: u64,
        usable: u64,
        size: u64,
        tag: u32,
        state: PoolState,
    ) -> PoolSpan {
        PoolSpan {
            header_address: header,
            usable_address: usable,
            size,
            raw_tag: tag,
            display_tag: super::decode::display_tag(tag),
            pool_kind: region.pool_kind,
            numa_node: region.numa_node,
            heap: region.heap,
            subsegment: region.subsegment,
            backend: region.backend,
            state,
            size_class: region.unit_size,
        }
    }

    fn unreadable(
        &self,
        region: &PoolRegion,
        address: u64,
        size: u64,
        snapshot: &mut PoolSnapshot,
    ) {
        if size != 0 {
            snapshot.complete = false;
            snapshot.spans.push(self.base_span(
                region,
                address,
                address,
                size,
                0,
                PoolState::Unreadable,
            ));
        }
    }

    /// Decodes a Driver Verifier special-pool region, one allocation per page.
    ///
    /// Special pool gives every allocation its own page: a `_POOL_HEADER` at the page
    /// start, `0xfd` fill, then the caller's block pushed up against the page end so an
    /// overrun lands on the following guard page. The guard page is unmapped, which is
    /// why `valid_region` stops after the data page and why a *freed* allocation simply
    /// vanishes — both are the mechanism working, not read failures.
    ///
    /// The block is placed at `page + PAGE_SIZE - align_up(size, 16)`; the 16-byte
    /// alignment is easy to miss, and dropping it puts the reported address 8 bytes past
    /// the real one (`0xf98` instead of `0xf90` for a 0x68 allocation).
    fn walk_special_pool(
        &self,
        region: &PoolRegion,
        base: u64,
        bytes: &[u8],
        snapshot: &mut PoolSnapshot,
    ) {
        let header_size = region.pool_header.size as u64;
        let mut page = base.next_multiple_of(PAGE_SIZE);
        while let Some(offset) = page.checked_sub(base).map(|delta| delta as usize) {
            if offset >= bytes.len() {
                break;
            }
            let available = (bytes.len() - offset).min(PAGE_SIZE as usize);
            let page_bytes = &bytes[offset..offset + available];
            let Some(header) = decode_pool_header(bytes, offset, region.pool_header) else {
                // Special pool is page-granular: one undecodable page says nothing about
                // the next, so stopping here would silently drop the rest of the region —
                // and leaving `complete` set would cache that truncated result and re-serve
                // it. Every other rejection path in this file reports and continues.
                snapshot.diagnostics.push(format!(
                    "special-pool page {page:#x}: pool header did not decode; page skipped"
                ));
                snapshot.complete = false;
                let Some(next) = page.checked_add(PAGE_SIZE) else {
                    break;
                };
                page = next;
                continue;
            };
            // An untagged page is not an allocation. Freed special-pool pages are
            // unmapped rather than zeroed, so anything readable here should carry a tag.
            if header.tag != 0 {
                let placement = special_pool_placement(
                    page,
                    u64::from(header.previous_size),
                    header_size,
                    page_bytes,
                );
                // Say so when the size is a bound rather than a measurement. Otherwise a
                // conservative page-sized range is indistinguishable from a real
                // allocation: `tag_census` would fold it into `total_bytes` — reporting a
                // 0x68 block as 0xff0 — while the report still claimed to be complete.
                if placement.approximate {
                    snapshot.diagnostics.push(format!(
                        "special-pool page {page:#x} tag `{}`: size not corroborated by the \
                         fill pattern; reporting the rest of the page as an upper bound",
                        super::decode::display_tag(header.tag)
                    ));
                    snapshot.complete = false;
                }
                let (usable, size) = (placement.usable, placement.size);
                snapshot.spans.push(self.base_span(
                    region,
                    page,
                    usable,
                    size,
                    header.tag,
                    PoolState::Allocated,
                ));
            }
            let Some(next) = page.checked_add(PAGE_SIZE) else {
                break;
            };
            page = next;
        }
    }

    fn walk_lfh(&self, region: &PoolRegion, base: u64, bytes: &[u8], snapshot: &mut PoolSnapshot) {
        let unit = region.unit_size as usize;
        if unit < region.pool_header.size {
            snapshot.diagnostics.push(format!(
                "rejecting implausible LFH unit size {} at {base:#x}",
                region.unit_size
            ));
            snapshot.complete = false;
            return;
        }
        let slice_offset = base.saturating_sub(region.address) as usize;
        let first_slot = slice_offset.div_ceil(unit);
        let slice_end = slice_offset.saturating_add(bytes.len());
        let mut slot = first_slot;
        while let Some(slot_offset) = slot.checked_mul(unit) {
            if slot_offset.saturating_add(unit) > slice_end {
                break;
            }
            let offset = slot_offset - slice_offset;
            let address = region.address + slot_offset as u64;
            // A block never straddles a page: the allocator skips the slot that would and
            // resumes at the next one, leaving the tail of the page as slack. Verified
            // against `!pool` on Server 26100 — with a 0x1a0 unit, blocks fill a page to
            // +0xef0 and the next block sits at +0x1090, which is exactly the following
            // slot, so linear indexing stays correct across the gap.
            //
            // Ordinary layout, then, not damage. Reporting it cost ~11.6k diagnostics on
            // an idle machine — drowning out the ones that meant something — and wrongly
            // cleared `complete` on essentially every snapshot taken.
            if address / PAGE_SIZE != (address + unit as u64 - 1) / PAGE_SIZE {
                slot += 1;
                continue;
            }
            let Some(state) = lfh_bitmap_state(&region.bitmap, slot) else {
                snapshot
                    .diagnostics
                    .push(format!("truncated LFH bitmap at slot {slot}"));
                snapshot.complete = false;
                break;
            };
            let tag = decode_pool_header(bytes, offset, region.pool_header)
                .map_or(0, |header| header.tag);
            let usable = address + region.pool_header.size as u64;
            snapshot.spans.push(self.base_span(
                region,
                address,
                usable,
                unit as u64 - region.pool_header.size as u64,
                tag,
                state,
            ));
            slot += 1;
        }
    }

    fn walk_vs(&self, region: &PoolRegion, base: u64, bytes: &[u8], snapshot: &mut PoolSnapshot) {
        let mut offset = ((16 - (base as usize & 0xf)) & 0xf).min(bytes.len());
        let mut chunks = 0usize;
        let mut reported_corruption = false;
        while offset
            .saturating_add(region.vs_header_size)
            .saturating_add(region.pool_header.size)
            <= bytes.len()
            && chunks < self.traversal_limit
        {
            let header_address = base + offset as u64;
            let Some(encoded) = read_u64(bytes, offset + region.vs_sizes_offset) else {
                break;
            };
            let Some(sizes) = decode_vs_sizes(encoded, header_address, region.heap_key) else {
                if !reported_corruption {
                    snapshot.diagnostics.push(format!(
                        "rejecting corrupt VS metadata beginning at {header_address:#x}"
                    ));
                    reported_corruption = true;
                }
                snapshot.complete = false;
                offset = offset.saturating_add(16);
                continue;
            };
            let chunk_size = (sizes.size as usize).saturating_mul(16);
            if chunk_size < region.vs_header_size + region.pool_header.size
                || header_address.saturating_add(chunk_size as u64)
                    > region.address.saturating_add(region.size as u64)
            {
                if !reported_corruption {
                    snapshot.diagnostics.push(format!(
                        "rejecting implausible VS chunk size {chunk_size:#x} at {header_address:#x}"
                    ));
                    reported_corruption = true;
                }
                snapshot.complete = false;
                offset = offset.saturating_add(16);
                continue;
            }
            if offset.saturating_add(chunk_size) > bytes.len() {
                snapshot.complete = false;
                break;
            }
            let candidate = header_address + region.vs_header_size as u64;
            let Some(physical_header) =
                adjust_page_end_header(candidate, region.pool_header.size as u64)
            else {
                snapshot.complete = false;
                break;
            };
            let pool_offset = physical_header.saturating_sub(base) as usize;
            let tag = decode_pool_header(bytes, pool_offset, region.pool_header)
                .map_or(0, |header| header.tag);
            let state = if region.cached_chunks.contains(&header_address) {
                PoolState::CachedFree
            } else if region.reusable_chunks.contains(&header_address) {
                PoolState::ReusableFree
            } else if sizes.allocated {
                PoolState::Allocated
            } else {
                PoolState::ReusableFree
            };
            let overhead = physical_header
                .saturating_sub(header_address)
                .saturating_add(region.pool_header.size as u64);
            let mut span = self.base_span(
                region,
                physical_header,
                physical_header + region.pool_header.size as u64,
                (chunk_size as u64).saturating_sub(overhead),
                tag,
                state,
            );
            span.size_class = chunk_size.min(u32::MAX as usize) as u32;
            snapshot.spans.push(span);
            let _ = sizes.previous_size;
            offset += chunk_size;
            chunks += 1;
        }
        if chunks >= self.traversal_limit {
            snapshot.complete = false;
            snapshot
                .diagnostics
                .push(format!("VS traversal limit reached at {base:#x}"));
        }
    }

    fn walk_page_ranges(
        &self,
        region: &PoolRegion,
        base: u64,
        bytes: &[u8],
        snapshot: &mut PoolSnapshot,
    ) {
        let unit = region.unit_size.max(1) as usize;
        let slice_offset = base.saturating_sub(region.address) as usize;
        let first_slot = slice_offset.div_ceil(unit);
        let slice_end = slice_offset.saturating_add(bytes.len());
        let mut slot = first_slot;
        while let Some(slot_offset) = slot.checked_mul(unit) {
            if slot_offset >= slice_end {
                break;
            }
            let offset = slot_offset - slice_offset;
            let remaining = bytes.len() - offset;
            let size = unit.min(remaining);
            let state = region
                .states
                .get(slot)
                .copied()
                .or_else(|| region.states.first().copied())
                .unwrap_or(PoolState::Unreadable);
            let tag = region.known_tag.or_else(|| {
                decode_pool_header(bytes, offset, region.pool_header).map(|header| header.tag)
            });
            let address = region.address + slot_offset as u64;
            let header_size = region.pool_header.size.min(size);
            snapshot.spans.push(self.base_span(
                region,
                address,
                address + header_size as u64,
                size.saturating_sub(header_size) as u64,
                tag.unwrap_or(0),
                state,
            ));
            slot += 1;
        }
    }

    #[cfg(test)]
    pub(crate) fn lookup_big_page(
        &self,
        table: &[u8],
        entry_size: usize,
        address: u64,
    ) -> Option<(u32, u64)> {
        if entry_size < 20 || !table.len().is_multiple_of(entry_size) {
            return None;
        }
        let count = table.len() / entry_size;
        for index in big_page_probe(address, count)? {
            let offset = index * entry_size;
            let candidate = read_u64(table, offset)?;
            if candidate == 0 {
                break;
            }
            if candidate & !1 == address {
                return Some((read_u32(table, offset + 8)?, read_u64(table, offset + 12)?));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::HashMap};

    use super::*;

    // ---- LFH slots that would straddle a page ---------------------------------------

    fn lfh_region(address: u64, unit_size: u32) -> PoolRegion {
        PoolRegion {
            address,
            size: 0x1000,
            pool_kind: PoolKind::NonPagedNx,
            numa_node: 0,
            heap: HeapIdentity {
                pool_state: 0,
                heap: 0,
                special: false,
            },
            subsegment: None,
            backend: PoolBackend::Lfh,
            unit_size,
            // Two slots' worth, both marked allocated.
            bitmap: vec![0xff],
            heap_key: 0,
            pool_header: PoolHeaderLayout {
                size: 0x10,
                previous_size: 0,
                pool_index: 1,
                block_size: 2,
                pool_type: 3,
                tag: 4,
            },
            vs_header_size: 0,
            vs_sizes_offset: 0,
            known_tag: None,
            states: Vec::new(),
            reusable_chunks: Arc::default(),
            cached_chunks: Arc::default(),
        }
    }

    /// The allocator refuses to let a block straddle a page: it skips that slot, leaves the
    /// page tail as slack, and resumes at the next slot. Confirmed against `!pool` on
    /// Server 26100. So the straddling slot must be skipped **silently** — it is ordinary
    /// layout, and reporting it once cost ~11.6k diagnostics on an idle machine.
    #[test]
    fn test_page_straddling_lfh_slot_is_skipped_without_complaint() {
        // Slot 0 at 0x1f80 spans 0x1f80..0x2080 and crosses; slot 1 at 0x2080 does not.
        let region = lfh_region(0x1f80, 0x100);
        let memory = FlatMemory::new(0x1f80, 0x200);
        let layout = vs_layout(false);
        let walker = SnapshotWalker {
            memory: &memory,
            layout: &layout,
            traversal_limit: 1000,
        };
        let mut snapshot = PoolSnapshot {
            spans: Vec::new(),
            diagnostics: Vec::new(),
            complete: true,
        };
        walker.walk_lfh(&region, 0x1f80, &memory.bytes, &mut snapshot);

        // The straddling slot is dropped, the following one is still reported: skipping
        // must not desynchronise the linear slot indexing.
        assert_eq!(snapshot.spans.len(), 1);
        assert_eq!(snapshot.spans[0].header_address, 0x2080);
        // The two properties that were wrong: silence, and an intact `complete`.
        assert!(
            snapshot.diagnostics.is_empty(),
            "normal layout must not be reported: {:?}",
            snapshot.diagnostics
        );
        assert!(
            snapshot.complete,
            "a straddling slot is expected layout and must not mark the snapshot incomplete"
        );
    }

    // ---- VS roots: legacy in-context shape vs 26100 affinity slots ------------------

    /// Memory backed by one contiguous buffer. Anything outside it fails to read, the way
    /// an unmapped page does.
    struct FlatMemory {
        base: u64,
        bytes: Vec<u8>,
    }

    impl FlatMemory {
        fn new(base: u64, len: usize) -> Self {
            Self {
                base,
                bytes: vec![0; len],
            }
        }

        fn put(&mut self, address: u64, data: &[u8]) {
            let offset = (address - self.base) as usize;
            self.bytes[offset..offset + data.len()].copy_from_slice(data);
        }

        fn put_u16(&mut self, address: u64, value: u16) {
            self.put(address, &value.to_le_bytes());
        }

        fn put_u64(&mut self, address: u64, value: u64) {
            self.put(address, &value.to_le_bytes());
        }
    }

    impl PoolMemory for FlatMemory {
        fn read_exact(&self, address: u64, size: usize) -> Result<Vec<u8>, SnapshotError> {
            let offset = address
                .checked_sub(self.base)
                .and_then(|offset| usize::try_from(offset).ok())
                .ok_or_else(|| SnapshotError::InvalidData {
                    detail: format!("read below the fixture at {address:#x}"),
                })?;
            self.bytes
                .get(offset..offset + size)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| SnapshotError::InvalidData {
                    detail: format!("read past the fixture at {address:#x}+{size:#x}"),
                })
        }

        fn valid_region(&self, address: u64, size: usize) -> Result<(u64, usize), SnapshotError> {
            Ok((address, size))
        }

        fn interrupted(&self) -> Result<bool, SnapshotError> {
            Ok(false)
        }
    }

    const VS_CONTEXT: u64 = 0x1000;

    /// A layout carrying only what `vs_roots` consults. `affinity` picks the shape: with
    /// it, the 26100 slot types exist and `_HEAP_VS_CONTEXT` has no `FreeChunkTree`;
    /// without it, the legacy in-context fields are present instead.
    fn vs_layout(affinity: bool) -> PoolLayout {
        let mut types = HashMap::new();
        types.insert(
            "_HEAP_VS_CONTEXT",
            if affinity {
                type_layout(0x60, &[("SlotMapRef", 0), ("AffinityMask", 2)])
            } else {
                type_layout(0x80, &[("FreeChunkTree", 0x10), ("DelayFreeContext", 0x30)])
            },
        );
        if affinity {
            types.insert(
                "_HEAP_VS_AFFINITY_SLOT",
                type_layout(
                    0x80,
                    &[
                        ("VsContext", 0),
                        ("FreeChunkTree", 0x10),
                        ("DelayFreeContext", 0x40),
                    ],
                ),
            );
            types.insert("_HEAP_VS_SLOT_MAP", type_layout(4, &[("SlotRef", 0)]));
        }
        PoolLayout {
            key: crate::pool::layout::SessionKey {
                kernel_base: 0,
                session: 1,
                target: 1,
            },
            globals: HashMap::new(),
            types,
        }
    }

    /// Four affinity entries over three distinct slots: two whose back-pointer agrees (one
    /// of them referenced twice, so dedup is exercised) and one that names another context.
    fn affinity_fixture() -> FlatMemory {
        let mut memory = FlatMemory::new(VS_CONTEXT, 0x1200);
        memory.put_u16(VS_CONTEXT, 0x10); // SlotMapRef -> map at ctx + 0x10*64
        memory.put(VS_CONTEXT + 2, &[3]); // AffinityMask -> 4 entries
        let map = VS_CONTEXT + 0x400;
        for (index, slot_ref) in [0x20u16, 0x30, 0x20, 0x40].into_iter().enumerate() {
            memory.put_u16(map + index as u64 * 4, slot_ref);
        }
        memory.put_u64(VS_CONTEXT + 0x800, VS_CONTEXT); // 0x20 << 6, owner agrees
        memory.put_u64(VS_CONTEXT + 0xc00, VS_CONTEXT); // 0x30 << 6, owner agrees
        memory.put_u64(VS_CONTEXT + 0x1000, 0xdead_beef); // 0x40 << 6, owner disagrees
        memory
    }

    /// Pre-26100: the tree is inline in the context, so there is exactly one root and no
    /// slot map is consulted at all.
    #[test]
    fn test_vs_roots_reads_the_legacy_in_context_shape() {
        let memory = FlatMemory::new(VS_CONTEXT, 0x100);
        let mut diagnostics = Vec::new();
        let roots = vs_roots(&memory, &vs_layout(false), VS_CONTEXT, &mut diagnostics);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].base, VS_CONTEXT);
        assert_eq!(roots[0].tree_offset, 0x10);
        assert_eq!(roots[0].delay_offset, Some(0x30));
        assert!(diagnostics.is_empty());
    }

    /// 26100: `slot = VsContext + (SlotRef << 6)`, and entries routinely share a slot.
    #[test]
    fn test_vs_roots_walks_the_affinity_slots_and_dedups_them() {
        let memory = affinity_fixture();
        let mut diagnostics = Vec::new();
        let roots = vs_roots(&memory, &vs_layout(true), VS_CONTEXT, &mut diagnostics);
        let bases: Vec<u64> = roots.iter().map(|root| root.base).collect();
        // Four entries, one repeat, one rejected -> two roots.
        assert_eq!(bases, vec![VS_CONTEXT + 0x800, VS_CONTEXT + 0xc00]);
        assert!(roots.iter().all(|root| root.tree_offset == 0x10));
        assert!(roots.iter().all(|root| root.delay_offset == Some(0x40)));
    }

    /// A slot whose back-pointer names a different context is not this context's slot.
    /// Trusting it would aim the tree walk at unrelated but readable memory.
    #[test]
    fn test_vs_roots_rejects_a_slot_whose_back_pointer_disagrees() {
        let memory = affinity_fixture();
        let mut diagnostics = Vec::new();
        let roots = vs_roots(&memory, &vs_layout(true), VS_CONTEXT, &mut diagnostics);
        assert!(roots.iter().all(|root| root.base != VS_CONTEXT + 0x1000));
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].contains("claims context"));
    }

    /// A zero `SlotMapRef` would alias the context itself; refuse rather than walk it.
    #[test]
    fn test_vs_roots_refuses_an_implausible_slot_map() {
        let mut memory = affinity_fixture();
        memory.put_u16(VS_CONTEXT, 0);
        let mut diagnostics = Vec::new();
        let roots = vs_roots(&memory, &vs_layout(true), VS_CONTEXT, &mut diagnostics);
        assert!(roots.is_empty());
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].contains("implausible VS slot map"));
    }

    /// Neither shape resolving is a reportable condition, not a silently empty walk — that
    /// ambiguity is exactly what made the 26100 breakage so hard to see.
    #[test]
    fn test_vs_roots_reports_when_neither_shape_resolves() {
        let memory = FlatMemory::new(VS_CONTEXT, 0x100);
        let layout = PoolLayout {
            key: crate::pool::layout::SessionKey {
                kernel_base: 0,
                session: 1,
                target: 1,
            },
            globals: HashMap::new(),
            types: HashMap::new(),
        };
        let mut diagnostics = Vec::new();
        let roots = vs_roots(&memory, &layout, VS_CONTEXT, &mut diagnostics);
        assert!(roots.is_empty());
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].contains("neither the context nor an affinity slot"));
    }

    const SPECIAL_PAGE: u64 = 0xffff_8c8f_13a0_2000;

    /// `(usable, size, approximate)` — flattened so the assertions below stay readable and
    /// so every case states whether the size was corroborated or merely bounded.
    fn placed(placement: SpecialPlacement) -> (u64, u64, bool) {
        (placement.usable, placement.size, placement.approximate)
    }

    /// A special-pool page holding a block of `requested` bytes: header, then Verifier
    /// fill, then the block itself pushed against the page end.
    fn special_page(requested: usize, header_size: usize) -> Vec<u8> {
        let mut page = vec![0u8; PAGE_SIZE as usize];
        let start = PAGE_SIZE as usize - requested.next_multiple_of(16);
        page[header_size..start].fill(SPECIAL_POOL_FILL);
        page[start..].fill(0x41);
        page
    }

    /// The real values read off Server 26100.32995: a 0x68 message in special pool sits at
    /// page+0xf90, not page+0xf98. Rounding the request up to 16 is what makes the
    /// difference, and getting it wrong reports an address 8 bytes into the block.
    #[test]
    fn test_special_pool_block_is_pushed_against_the_page_end() {
        assert_eq!(
            placed(special_pool_placement(
                SPECIAL_PAGE,
                0x68,
                0x10,
                &special_page(0x68, 0x10)
            )),
            (SPECIAL_PAGE + 0xf90, 0x68, false)
        );
        // Already a multiple of 16: no rounding, block ends exactly at the page end.
        assert_eq!(
            placed(special_pool_placement(
                SPECIAL_PAGE,
                0x40,
                0x10,
                &special_page(0x40, 0x10)
            )),
            (SPECIAL_PAGE + 0xfc0, 0x40, false)
        );
    }

    /// The case a range check cannot catch: `PreviousSize` is 8 bits, so a 0x140 block
    /// stores 0x40 there — a value that fits the page perfectly well and is indistinguishable
    /// from a real 0x40 by size alone. Only the fill gives it away: placing a 0x40 block at
    /// the page end would leave the real block's bytes sitting where fill should be.
    #[test]
    fn test_special_pool_detects_a_truncated_size_via_the_fill() {
        // The page really holds 0x140 bytes of data; the header claims 0x40.
        let page = special_page(0x140, 0x10);
        assert_eq!(
            placed(special_pool_placement(SPECIAL_PAGE, 0x40, 0x10, &page)),
            (SPECIAL_PAGE + 0x10, PAGE_SIZE - 0x10, true),
            "a truncated PreviousSize must fall back, not report a block at the page end"
        );
        // Sanity: told the truth, the same page resolves precisely.
        assert_eq!(
            placed(special_pool_placement(SPECIAL_PAGE, 0x140, 0x10, &page)),
            (SPECIAL_PAGE + 0xec0, 0x140, false)
        );
    }

    /// A start-aligned page (`MmSpecialPoolCatchOverruns` clear) puts the block next to the
    /// preceding guard page, so the end-of-page formula would be wrong. The fill check
    /// declines instead of reporting a bogus address.
    #[test]
    fn test_special_pool_declines_a_start_aligned_page() {
        let mut page = vec![0u8; PAGE_SIZE as usize];
        page[0x10..0x78].fill(0x41); // block immediately after the header
        page[0x78..].fill(SPECIAL_POOL_FILL); // fill trails it
        assert_eq!(
            placed(special_pool_placement(SPECIAL_PAGE, 0x68, 0x10, &page)),
            (SPECIAL_PAGE + 0x10, PAGE_SIZE - 0x10, true)
        );
    }

    #[test]
    fn test_special_pool_falls_back_when_the_size_is_untrustworthy() {
        let page = special_page(0x68, 0x10);
        assert_eq!(
            placed(special_pool_placement(SPECIAL_PAGE, 0, 0x10, &page)),
            (SPECIAL_PAGE + 0x10, PAGE_SIZE - 0x10, true)
        );
        // A request that cannot share the page with its own header is not believable.
        assert_eq!(
            placed(special_pool_placement(SPECIAL_PAGE, PAGE_SIZE, 0x10, &page)),
            (SPECIAL_PAGE + 0x10, PAGE_SIZE - 0x10, true)
        );
    }

    /// A partially readable page corroborates nothing about where the block sits, so the
    /// end-of-page placement must not be used and the size must not exceed what was read.
    #[test]
    fn test_special_pool_fallback_respects_the_readable_length() {
        let partial = vec![SPECIAL_POOL_FILL; 0x200];
        assert_eq!(
            placed(special_pool_placement(SPECIAL_PAGE, 0x68, 0x10, &partial)),
            (SPECIAL_PAGE + 0x10, 0x1f0, true)
        );
    }
    use crate::pool::{
        decode::DESCRIPTOR_FLAG_COMMITTED,
        layout::{SessionKey, TypeLayout},
    };

    const K: u64 = 0xffff_8000_0000_0000;
    const STATE: u64 = K + 0x10_0000;
    const GLOBALS: u64 = K + 0x11_0000;
    const BIG_TABLE_POINTER: u64 = K + 0x12_0000;
    const BIG_TABLE_COUNT: u64 = K + 0x12_0010;
    const HEAP: u64 = K + 0x20_0000;
    const POOL_NODE: u64 = STATE + 0x40;
    const DYNAMIC_LOOKASIDE: u64 = POOL_NODE + 0x20;
    const SEGMENT: u64 = K + 0x30_0000;
    const LARGE_META: u64 = K + 0x80_0000;
    const LARGE_VA: u64 = K + 0x90_0000;
    const BIG_TABLE: u64 = K + 0xa0_0000;

    /// Sparse synthetic memory, stored as coalesced contiguous runs.
    ///
    /// Both the read and the write path are shaped to keep Miri off per-byte work, and the two
    /// were found in separate rounds.
    ///
    /// Reads resolve through a binary search over runs, not the `BTreeMap<u64, u8>` this began
    /// as with one `get` per byte. Semantics are unchanged — a byte is readable iff it was
    /// written, so a read spanning a gap still fails — and that was worth 2.0x.
    ///
    /// Writes go through [`Writes`], a log replayed in bulk, rather than building that byte map
    /// at all. The read fix left the two pool snapshot tests at 398s and 369s of an 849s CI job,
    /// and the second of them is three assertions over a fixture — so what remained was never
    /// "Miri interpreting the walk", which is what the previous round of this comment concluded.
    /// It was the ~22k `BTreeMap` inserts `fill`/`put` performed to build the fixture in the
    /// first place, each a fully interpreted, borrow-checked trip through `NodeRef` and raw
    /// pointers. Bulk `copy_from_slice` over a handful of runs is one Miri operation per write.
    ///
    /// Measured, not assumed: on one machine that second test alone took 178.4s before the
    /// write fix; both tests together now take 6.1s.
    struct SyntheticMemory {
        /// `(start, bytes)` for each contiguous written range, sorted by `start` and never
        /// overlapping or abutting.
        runs: Vec<(u64, Vec<u8>)>,
        holes: Vec<(u64, u64)>,
    }

    /// The fixture's write log: `(address, bytes)` in the order written, later writes winning.
    ///
    /// A plain append-only `Vec`, one entry per `put`/`fill` call rather than per byte, so the
    /// whole fixture is a few dozen pushes and bulk copies instead of ~22k `BTreeMap` inserts.
    #[derive(Default)]
    struct Writes(Vec<(u64, Vec<u8>)>);

    impl SyntheticMemory {
        fn new(writes: Writes, holes: Vec<(u64, u64)>) -> Self {
            // Extents first: merge every written interval that overlaps or abuts a neighbour,
            // which yields exactly the runs the byte map used to produce by iterating in key
            // order. Sorting is safe here because an extent carries no value to be overwritten.
            let mut extents: Vec<(u64, u64)> = writes
                .0
                .iter()
                .filter(|(_, data)| !data.is_empty())
                .map(|(address, data)| (*address, address + data.len() as u64))
                .collect();
            extents.sort_unstable();
            let mut runs: Vec<(u64, Vec<u8>)> = Vec::new();
            for (start, end) in extents {
                match runs.last_mut() {
                    Some((run_start, data)) if start <= *run_start + data.len() as u64 => {
                        let len = (end - *run_start) as usize;
                        // A contained write leaves the run as it is; only a write reaching past
                        // the current end grows it.
                        if len > data.len() {
                            data.resize(len, 0);
                        }
                    }
                    _ => runs.push((start, vec![0; (end - start) as usize])),
                }
            }
            // Then replay in write order, so the last write to an address wins — the property
            // that re-inserting into the byte map used to provide.
            for (address, data) in writes.0.into_iter().filter(|(_, data)| !data.is_empty()) {
                let index = runs
                    .partition_point(|(start, _)| *start <= address)
                    .checked_sub(1)
                    .expect("every non-empty write contributed an extent");
                let (start, run) = &mut runs[index];
                let offset = (address - *start) as usize;
                run[offset..offset + data.len()].copy_from_slice(&data);
            }
            Self { runs, holes }
        }

        /// The run containing `address`, if any.
        fn run_at(&self, address: u64) -> Option<&(u64, Vec<u8>)> {
            let index = self
                .runs
                .partition_point(|(start, _)| *start <= address)
                .checked_sub(1)?;
            let run = &self.runs[index];
            (address < run.0 + run.1.len() as u64).then_some(run)
        }

        /// Whether a single byte was written — the fixture's own sanity checks ask this.
        fn contains(&self, address: u64) -> bool {
            self.run_at(address).is_some()
        }
    }

    struct ShortMemory;

    struct BigPageMemory {
        table: Vec<u8>,
        count: usize,
        read_calls: Cell<usize>,
        interrupt_checks: Cell<usize>,
        interrupt_after_checks: Option<usize>,
    }

    impl PoolMemory for ShortMemory {
        fn read_exact(&self, _address: u64, _size: usize) -> Result<Vec<u8>, SnapshotError> {
            Ok(Vec::new())
        }

        fn valid_region(&self, address: u64, size: usize) -> Result<(u64, usize), SnapshotError> {
            Ok((address, size))
        }

        fn interrupted(&self) -> Result<bool, SnapshotError> {
            Ok(false)
        }
    }

    impl PoolMemory for BigPageMemory {
        fn read_exact(&self, address: u64, size: usize) -> Result<Vec<u8>, SnapshotError> {
            self.read_calls.set(self.read_calls.get() + 1);
            if address == BIG_TABLE_POINTER && size == 8 {
                return Ok(BIG_TABLE.to_le_bytes().to_vec());
            }
            if address == BIG_TABLE_COUNT && size == 4 {
                return Ok((self.count as u32).to_le_bytes().to_vec());
            }
            if address == BIG_TABLE_COUNT && size == 8 {
                return Ok(((1u64 << 32) | self.count as u64).to_le_bytes().to_vec());
            }
            let offset = address
                .checked_sub(BIG_TABLE)
                .and_then(|value| usize::try_from(value).ok());
            if let Some(bytes) = offset
                .and_then(|offset| offset.checked_add(size).map(|end| (offset, end)))
                .and_then(|(offset, end)| self.table.get(offset..end))
            {
                return Ok(bytes.to_vec());
            }
            Err(SnapshotError::Read {
                address,
                size,
                source: Box::new(std::io::Error::other("sparse big-page memory")),
            })
        }

        fn valid_region(&self, address: u64, size: usize) -> Result<(u64, usize), SnapshotError> {
            Ok((address, size))
        }

        fn interrupted(&self) -> Result<bool, SnapshotError> {
            let checks = self.interrupt_checks.get();
            self.interrupt_checks.set(checks + 1);
            Ok(self
                .interrupt_after_checks
                .is_some_and(|limit| checks >= limit))
        }
    }

    impl PoolMemory for SyntheticMemory {
        fn read_exact(&self, address: u64, size: usize) -> Result<Vec<u8>, SnapshotError> {
            let unreadable = || SnapshotError::Read {
                address,
                size,
                source: Box::new(std::io::Error::other("sparse synthetic memory")),
            };
            let (start, data) = self.run_at(address).ok_or_else(unreadable)?;
            let offset = (address - start) as usize;
            // One run must cover the whole read: runs never abut, so a read that runs off the
            // end of one has hit a gap, exactly as the per-byte lookup used to report.
            data.get(offset..offset + size)
                .map(<[u8]>::to_vec)
                .ok_or_else(unreadable)
        }

        fn valid_region(&self, address: u64, size: usize) -> Result<(u64, usize), SnapshotError> {
            let end = address.saturating_add(size as u64);
            for &(hole_start, hole_end) in &self.holes {
                if address >= hole_start && address < hole_end {
                    return Ok((hole_end, end.saturating_sub(hole_end) as usize));
                }
                if address < hole_start && end > hole_start {
                    return Ok((address, hole_start.saturating_sub(address) as usize));
                }
            }
            Ok((address, size))
        }

        fn interrupted(&self) -> Result<bool, SnapshotError> {
            Ok(false)
        }
    }

    fn type_layout(size: u32, fields: &[(&'static str, u32)]) -> TypeLayout {
        TypeLayout {
            size,
            fields: fields.iter().copied().collect(),
        }
    }

    fn synthetic_layout() -> PoolLayout {
        let mut types = HashMap::new();
        types.insert(
            "_EX_POOL_HEAP_MANAGER_STATE",
            type_layout(
                0x200,
                &[
                    ("HeapManager", 8),
                    ("PoolNode", 0x40),
                    ("NumberOfPools", 0),
                    ("SpecialHeaps", 0x20),
                ],
            ),
        );
        types.insert(
            "_EX_HEAP_POOL_NODE",
            type_layout(0x120, &[("Heaps", 0), ("Lookasides", 0x20)]),
        );
        types.insert(
            "_SEGMENT_HEAP",
            type_layout(
                0x800,
                &[
                    ("SegContexts", 0x100),
                    ("VsContext", 0x300),
                    ("LfhContext", 0x380),
                    ("LargeAllocMetadata", 0x400),
                ],
            ),
        );
        types.insert(
            "_HEAP_SEG_CONTEXT",
            type_layout(
                0x80,
                &[
                    ("SegmentListHead", 0),
                    ("FreePageRanges", 0x10),
                    ("UnitShift", 0x20),
                    ("FirstDescriptorIndex", 0x21),
                    ("SegmentMask", 0x28),
                    ("PagesPerUnitShift", 0x30),
                ],
            ),
        );
        types.insert(
            "_HEAP_PAGE_SEGMENT",
            type_layout(
                0x100,
                &[("ListEntry", 0), ("Signature", 0x20), ("DescArray", 0x100)],
            ),
        );
        types.insert(
            "_HEAP_PAGE_RANGE_DESCRIPTOR",
            type_layout(
                0x20,
                &[
                    ("UnitSize", 0x1f),
                    ("RangeFlags", 0x18),
                    ("TreeNode", 0),
                    ("TreeSignature", 0),
                ],
            ),
        );
        types.insert(
            "_HEAP_VS_CONTEXT",
            type_layout(
                0x40,
                &[
                    ("FreeChunkTree", 0),
                    ("DelayFreeContext", 0x10),
                    ("SubsegmentList", 0x30),
                ],
            ),
        );
        types.insert(
            "_HEAP_VS_DELAY_FREE_CONTEXT",
            type_layout(0x10, &[("ListHead", 0)]),
        );
        types.insert(
            "_HEAP_VS_SUBSEGMENT",
            type_layout(0xfe0, &[("Signature", 0), ("Size", 2), ("ListEntry", 8)]),
        );
        types.insert(
            "_HEAP_VS_CHUNK_HEADER",
            type_layout(0x10, &[("Sizes", 0), ("EncodedSegmentPageOffset", 8)]),
        );
        types.insert(
            "_HEAP_VS_CHUNK_FREE_HEADER",
            type_layout(0x20, &[("TreeNode", 8)]),
        );
        types.insert("_HEAP_LFH_CONTEXT", type_layout(0x20, &[("Buckets", 0)]));
        types.insert(
            "_HEAP_LFH_SUBSEGMENT",
            type_layout(
                0x20,
                &[
                    ("BlockOffsets", 0),
                    ("BlockCount", 4),
                    ("BlockBitmap", 8),
                    ("ListEntry", 0x10),
                ],
            ),
        );
        types.insert(
            "_HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS",
            type_layout(4, &[("EncodedData", 0)]),
        );
        types.insert(
            "_RTLP_HP_HEAP_GLOBALS",
            type_layout(0x10, &[("HeapKey", 0), ("LfhKey", 8)]),
        );
        types.insert(
            "_RTL_RB_TREE",
            type_layout(0x10, &[("Root", 0), ("Encoded", 8)]),
        );
        types.insert(
            "_RTL_BALANCED_NODE",
            type_layout(0x10, &[("Left", 0), ("Right", 8)]),
        );
        types.insert(
            "_RTL_DYNAMIC_LOOKASIDE",
            type_layout(0x80, &[("BucketCount", 8), ("Buckets", 0x40)]),
        );
        types.insert(
            "_RTL_LOOKASIDE",
            type_layout(0x40, &[("ListHead", 0), ("Size", 0x30)]),
        );
        types.insert(
            "_SLIST_HEADER",
            type_layout(0x10, &[("Alignment", 0), ("Region", 8)]),
        );
        types.insert(
            "_POOL_HEADER",
            type_layout(
                0x10,
                &[
                    ("PreviousSize", 0),
                    ("PoolIndex", 0),
                    ("BlockSize", 2),
                    ("PoolType", 2),
                    ("PoolTag", 8),
                ],
            ),
        );
        types.insert(
            "_HEAP_LARGE_ALLOC_DATA",
            type_layout(
                0x28,
                &[
                    ("TreeNode", 0),
                    ("VirtualAddress", 0x18),
                    ("AllocatedPages", 0x20),
                ],
            ),
        );
        types.insert(
            "_POOL_TRACKER_BIG_PAGES",
            type_layout(0x20, &[("Va", 0), ("Key", 8), ("NumberOfBytes", 0x10)]),
        );
        PoolLayout {
            key: SessionKey {
                kernel_base: K,
                session: 1,
                target: 1,
            },
            globals: [
                ("ExPoolState", STATE),
                ("RtlpHpHeapGlobals", GLOBALS),
                ("PoolBigPageTable", BIG_TABLE_POINTER),
                ("PoolBigPageTableSize", BIG_TABLE_COUNT),
            ]
            .into_iter()
            .collect(),
            types,
        }
    }

    fn put(bytes: &mut Writes, address: u64, data: &[u8]) {
        bytes.0.push((address, data.to_vec()));
    }

    fn fill(bytes: &mut Writes, address: u64, size: usize) {
        bytes.0.push((address, vec![0; size]));
    }

    fn put_u16(bytes: &mut Writes, address: u64, value: u16) {
        put(bytes, address, &value.to_le_bytes());
    }

    fn put_u32(bytes: &mut Writes, address: u64, value: u32) {
        put(bytes, address, &value.to_le_bytes());
    }

    fn put_u64(bytes: &mut Writes, address: u64, value: u64) {
        put(bytes, address, &value.to_le_bytes());
    }

    fn packed_slist_next(entry: u64) -> u64 {
        (entry << 4) | 3
    }

    fn pool_header(bytes: &mut Writes, address: u64, tag: &[u8; 4]) {
        fill(bytes, address, 0x10);
        put(bytes, address, &[1, 0, 4, 1]);
        put(bytes, address + 8, tag);
    }

    fn synthetic_memory() -> SyntheticMemory {
        let mut bytes = Writes::default();
        fill(&mut bytes, STATE, 0x200);
        put_u32(&mut bytes, STATE, 1);
        for heap_index in 0..4 {
            put_u64(&mut bytes, STATE + 0x40 + heap_index * 8, HEAP);
        }
        fill(&mut bytes, GLOBALS, 0x10);
        let heap_key = 0x55aa_1234_9876_0000;
        let lfh_key = 0xa5c3_1357;
        put_u64(&mut bytes, GLOBALS, heap_key);
        put_u64(&mut bytes, GLOBALS + 8, lfh_key);
        fill(&mut bytes, HEAP, 0x800);

        let context = HEAP + 0x100;
        let list_head = context;
        put_u64(&mut bytes, list_head, SEGMENT);
        put_u64(&mut bytes, context + 0x10, SEGMENT + 0x100 + 6 * 0x20);
        put(&mut bytes, context + 0x20, &[12, 1]);
        put_u64(&mut bytes, context + 0x28, !0xffffu64);

        fill(&mut bytes, SEGMENT, 0x100);
        put_u64(&mut bytes, SEGMENT, list_head);
        put_u64(
            &mut bytes,
            SEGMENT + 0x20,
            SEGMENT ^ context ^ heap_key ^ super::super::decode::PAGE_SEGMENT_SIGNATURE,
        );
        fill(&mut bytes, SEGMENT + 0x100, 16 * 0x20);
        for (index, units, flags) in [
            (
                1u64,
                2u8,
                DESCRIPTOR_FLAG_LFH | DESCRIPTOR_FLAG_COMMITTED | 0x0c,
            ),
            (3, 2, DESCRIPTOR_FLAG_VS | DESCRIPTOR_FLAG_COMMITTED | 0x0c),
            (5, 1, DESCRIPTOR_FLAG_COMMITTED | 0x0c),
            (6, 1, 0x00),
            (7, 1, DESCRIPTOR_FLAG_COMMITTED | 0x0c),
        ] {
            let descriptor = SEGMENT + 0x100 + index * 0x20;
            if flags & DESCRIPTOR_FLAG_COMMITTED != 0 {
                put_u32(
                    &mut bytes,
                    descriptor,
                    super::super::decode::DESCRIPTOR_TREE_SIGNATURE,
                );
            }
            put(&mut bytes, descriptor + 0x18, &[flags]);
            put(&mut bytes, descriptor + 0x1f, &[units]);
        }

        let lfh = SEGMENT + 0x1000;
        fill(&mut bytes, lfh, 0x20);
        let decoded_offsets = u32::from(0x40u16) | (u32::from(0x40u16) << 16);
        put_u32(
            &mut bytes,
            lfh,
            decoded_offsets ^ lfh_key as u32 ^ (lfh >> 12) as u32,
        );
        put_u16(&mut bytes, lfh + 4, 4);
        put(&mut bytes, lfh + 8, &[0x49]);
        fill(&mut bytes, lfh + 0x40, 0x100);
        pool_header(&mut bytes, lfh + 0x40, b"LFH!");
        pool_header(&mut bytes, lfh + 0x80, b"LFHC");
        pool_header(&mut bytes, lfh + 0xc0, b"LFHF");
        pool_header(&mut bytes, lfh + 0x100, b"LFH2");

        let vs = SEGMENT + 0x3000;
        fill(&mut bytes, vs, 0x2000);
        put_u16(&mut bytes, vs, 0x8000 | (0x2bed ^ 2));
        put_u16(&mut bytes, vs + 2, 2);
        let first_chunk = vs + 0xfe0;
        let cached_chunk = first_chunk + 0x40;
        let free_chunk = cached_chunk + 0x40;
        for (address, allocated) in [
            (first_chunk, true),
            (cached_chunk, false),
            (free_chunk, false),
        ] {
            let decoded = (4u64 << 16) | (u64::from(allocated) << 48);
            put_u64(&mut bytes, address, decoded ^ address ^ heap_key);
        }
        pool_header(&mut bytes, first_chunk + 0x10, b"VS!!");
        let vs_context = HEAP + 0x300;
        put_u64(&mut bytes, vs_context, free_chunk + 8);
        put_u64(&mut bytes, free_chunk + 8, 0);
        put_u64(&mut bytes, free_chunk + 16, 0);
        let delay_head = vs_context + 0x10;
        put_u16(&mut bytes, delay_head, 1);
        put_u64(
            &mut bytes,
            delay_head + 8,
            packed_slist_next(cached_chunk + 0x20),
        );
        put_u64(&mut bytes, cached_chunk + 0x20, 0);

        fill(&mut bytes, DYNAMIC_LOOKASIDE, 0x80);
        put_u32(&mut bytes, DYNAMIC_LOOKASIDE + 8, 1);
        let lookaside_chunk = free_chunk + 0x40;
        let decoded = 4u64 << 16;
        put_u64(
            &mut bytes,
            lookaside_chunk,
            decoded ^ lookaside_chunk ^ heap_key,
        );
        let lookaside_head = DYNAMIC_LOOKASIDE + 0x40;
        put_u16(&mut bytes, lookaside_head, 1);
        put_u64(
            &mut bytes,
            lookaside_head + 8,
            packed_slist_next(lookaside_chunk + 0x20),
        );
        put_u64(&mut bytes, lookaside_chunk + 0x20, 0);
        put_u32(&mut bytes, lookaside_head + 0x30, 0x40);

        fill(&mut bytes, SEGMENT + 0x5000, 0x1000);
        pool_header(&mut bytes, SEGMENT + 0x5000, b"SEGM");
        fill(&mut bytes, SEGMENT + 0x6000, 0x1000);
        fill(&mut bytes, SEGMENT + 0x7000, 0x800);
        pool_header(&mut bytes, SEGMENT + 0x7000, b"SPRS");

        let large_tree = HEAP + 0x400;
        put_u64(&mut bytes, large_tree, LARGE_META ^ large_tree);
        put(&mut bytes, large_tree + 8, &[1]);
        fill(&mut bytes, LARGE_META, 0x28);
        put_u64(&mut bytes, LARGE_META + 0x18, LARGE_VA | 0x1800);
        put_u64(&mut bytes, LARGE_META + 0x20, (2u64 << 12) | 0x5a5);
        // Large allocations are described entirely by allocator metadata; leave
        // their payload absent so the walker cannot accidentally read it.
        put_u64(&mut bytes, BIG_TABLE_POINTER, BIG_TABLE);
        put_u64(&mut bytes, BIG_TABLE_COUNT, 4);
        fill(&mut bytes, BIG_TABLE, 4 * 0x20);
        let first = super::super::decode::big_page_hash(LARGE_VA, 4).unwrap();
        let adjacent = (first + 1) % 4;
        let collision = BIG_TABLE + first as u64 * 0x20;
        put_u64(&mut bytes, collision, LARGE_VA + 0x10_0000);
        let entry = BIG_TABLE + adjacent as u64 * 0x20;
        put_u64(&mut bytes, entry, LARGE_VA);
        put(&mut bytes, entry + 8, b"BIG!");
        put_u64(&mut bytes, entry + 0x10, 0x1800);

        SyntheticMemory::new(bytes, vec![(SEGMENT + 0x7800, SEGMENT + 0x8000)])
    }

    fn big_page_memory(address: u64, count: usize, collision_distance: usize) -> BigPageMemory {
        let mut table = vec![0; count * 0x20];
        let first = super::super::decode::big_page_hash(address, count).unwrap();
        for distance in 0..collision_distance {
            let index = (first + distance) % count;
            let offset = index * 0x20;
            table[offset..offset + 8]
                .copy_from_slice(&(address + (distance as u64 + 1) * 0x10_0000).to_le_bytes());
        }
        let index = (first + collision_distance) % count;
        let offset = index * 0x20;
        table[offset..offset + 8].copy_from_slice(&address.to_le_bytes());
        table[offset + 8..offset + 12].copy_from_slice(b"BTCH");
        table[offset + 0x10..offset + 0x18].copy_from_slice(&0x9000u64.to_le_bytes());
        BigPageMemory {
            table,
            count,
            read_calls: Cell::new(0),
            interrupt_checks: Cell::new(0),
            interrupt_after_checks: None,
        }
    }

    #[test]
    fn test_pool_snapshot_walks_all_backends() {
        let memory = synthetic_memory();
        assert!(!memory.contains(LARGE_VA));
        let layout = synthetic_layout();
        let walker = SnapshotWalker {
            memory: &memory,
            layout: &layout,
            traversal_limit: 1024,
        };
        let snapshot = walker.walk(None).unwrap();
        for backend in [
            PoolBackend::Lfh,
            PoolBackend::Vs,
            PoolBackend::Segment,
            PoolBackend::Large,
        ] {
            assert!(
                snapshot.spans.iter().any(|span| span.backend == backend),
                "missing {backend:?}"
            );
        }
        assert!(snapshot.spans.iter().any(|span| span.pool_kind.is_paged()));
        assert!(snapshot.spans.iter().any(|span| {
            span.raw_tag == u32::from_le_bytes(*b"LFH!") && span.state == PoolState::Allocated
        }));
        assert!(snapshot.spans.iter().any(|span| {
            span.backend == PoolBackend::Vs && span.state == PoolState::CachedFree
        }));
        assert!(snapshot.spans.iter().any(|span| {
            span.backend == PoolBackend::Vs
                && span.header_address == SEGMENT + 0x40b0
                && span.state == PoolState::CachedFree
        }));
        assert!(
            snapshot
                .spans
                .iter()
                .filter(|span| span.backend == PoolBackend::Vs)
                .all(|span| span.size_class == 0x40)
        );
        assert!(snapshot.spans.iter().any(|span| {
            span.backend == PoolBackend::Segment && span.state == PoolState::ReusableFree
        }));
        assert!(
            snapshot
                .spans
                .iter()
                .any(|span| span.state == PoolState::Unreadable)
        );
        assert!(snapshot.spans.iter().any(|span| {
            span.backend == PoolBackend::Vs
                && span.header_address == SEGMENT + 0x3ff0
                && span.usable_address == SEGMENT + 0x4000
                && span.raw_tag == u32::from_le_bytes(*b"VS!!")
        }));
        assert!(snapshot.spans.iter().any(|span| {
            span.backend == PoolBackend::Large
                && span.raw_tag == u32::from_le_bytes(*b"BIG!")
                && span.size == 0x1800
        }));
        assert!(
            snapshot
                .diagnostics
                .iter()
                .any(|message| { message.contains("per-session paged heaps are not included") })
        );
        assert!(
            snapshot
                .diagnostics
                .iter()
                .any(|message| message.contains("only committed through"))
        );

        let mut table = vec![0u8; 8 * 24];
        let address = K + 0xb0_0000;
        let first = super::super::decode::big_page_hash(address, 8).unwrap();
        for distance in 0..2 {
            let collision = ((first + distance) % 8) * 24;
            table[collision..collision + 8]
                .copy_from_slice(&(address + (distance as u64 + 1) * 0x10_0000).to_le_bytes());
        }
        let third = ((first + 2) % 8) * 24;
        table[third..third + 8].copy_from_slice(&address.to_le_bytes());
        table[third + 8..third + 12].copy_from_slice(b"NEXT");
        table[third + 12..third + 20].copy_from_slice(&0x7000u64.to_le_bytes());
        assert_eq!(
            walker.lookup_big_page(&table, 24, address),
            Some((u32::from_le_bytes(*b"NEXT"), 0x7000))
        );
    }

    // ---- the walk budget --------------------------------------------------------------

    /// The synthetic fixture, with a budget that runs out after a fixed number of reads.
    ///
    /// The real budget is wall-clock, which is untestable without making the test a race
    /// against the machine it runs on. Reads are the honest stand-in: they are what the
    /// budget exists to bound — over a live KD link every one crosses the wire — and their
    /// count is exactly what differs between a dump that walks in a second and a live kernel
    /// that takes minutes.
    struct Impatient {
        inner: SyntheticMemory,
        reads: Cell<usize>,
        allowance: usize,
    }

    impl Impatient {
        fn new(allowance: usize) -> Self {
            Self {
                inner: synthetic_memory(),
                reads: Cell::new(0),
                allowance,
            }
        }
    }

    impl PoolMemory for Impatient {
        fn read_exact(&self, address: u64, size: usize) -> Result<Vec<u8>, SnapshotError> {
            self.reads.set(self.reads.get() + 1);
            self.inner.read_exact(address, size)
        }

        fn valid_region(&self, address: u64, size: usize) -> Result<(u64, usize), SnapshotError> {
            self.inner.valid_region(address, size)
        }

        fn interrupted(&self) -> Result<bool, SnapshotError> {
            Ok(false)
        }

        fn out_of_budget(&self) -> bool {
            self.reads.get() >= self.allowance
        }
    }

    fn walk_impatiently(allowance: usize) -> PoolSnapshot {
        let memory = Impatient::new(allowance);
        let layout = synthetic_layout();
        SnapshotWalker {
            memory: &memory,
            layout: &layout,
            traversal_limit: 1024,
        }
        .walk(None)
        .expect("running out of budget is an outcome, not an error")
    }

    /// The wedge this budget exists to prevent: with nothing to stop it, the walk ran on
    /// past the caller's timeout and every later call to that target queued behind it. So
    /// the deadline has to produce an *answer* — a snapshot that says what it reached and
    /// admits what it did not. An `Err` would discard the work and say nothing.
    #[test]
    fn test_a_walk_that_runs_out_of_budget_reports_what_it_reached() {
        let snapshot = walk_impatiently(40);

        assert!(
            !snapshot.complete,
            "a truncated walk that claims completeness is the lie this whole API guards against"
        );
        assert!(
            snapshot
                .diagnostics
                .iter()
                .any(|message| message.contains("ran out of its")
                    && message.contains("discovered regions")),
            "the snapshot has to say why it is short: {:?}",
            snapshot.diagnostics
        );
    }

    /// Running out of time is about the walk, not about whichever unit happened to be under
    /// the cursor. Recorded as a per-unit failure it reads as "heap 3 is unreadable", and —
    /// the real damage — the enclosing loop swallows it and carries on to the next unit,
    /// each stopping the same way, so the deadline bounds one unit instead of the walk. On
    /// the *last* iteration it is absorbed outright and the walk simply continues.
    ///
    /// Swept over budgets because where the halt lands decides which handler sees it: an
    /// early one stops inside a heap's VS evidence, a later one inside a segment context.
    /// Both swallow errors into diagnostics, so both have to re-raise.
    #[test]
    fn test_running_out_of_budget_is_never_reported_as_a_broken_unit() {
        for allowance in [10, 25, 40, 80, 120, 200, 400] {
            let snapshot = walk_impatiently(allowance);
            for absorbed in [
                "cannot fully discover heap",
                "cannot discover segment context",
            ] {
                assert!(
                    !snapshot
                        .diagnostics
                        .iter()
                        .any(|message| message.contains(absorbed)),
                    "budget {allowance}: a per-unit handler absorbed the halt as \
                     `{absorbed}`: {:?}",
                    snapshot.diagnostics
                );
            }
        }
    }

    /// Discovery finds the regions and the walk reads what is in them, so a budget spent
    /// entirely on the first half yields an empty pool. Two things keep that from happening:
    /// discovery is held to a share of the budget, and — pinned here — the regions it found
    /// before stopping survive the halt instead of being dropped with the error.
    #[test]
    fn test_regions_found_before_the_halt_are_not_thrown_away() {
        // Enough reads to get past VS evidence and into the segment walk, not enough to
        // finish it.
        let snapshot = walk_impatiently(120);
        let summary = snapshot
            .diagnostics
            .iter()
            .find(|message| message.contains("discovered regions"))
            .expect("the walk stopped short and must say so");
        let tokens: Vec<&str> = summary.split_whitespace().collect();
        let discovered: usize = tokens
            .iter()
            .position(|token| *token == "discovered")
            .and_then(|index| index.checked_sub(1))
            .and_then(|index| tokens[index].parse().ok())
            .unwrap_or_else(|| panic!("no region count in `{summary}`"));

        assert!(
            discovered > 0,
            "discovery's partial results were discarded with the halt: `{summary}`"
        );
    }

    /// Neither half of the walk is useful without the other, so discovery gets a share of
    /// the budget rather than all of it — and the whole walk still stops at the deadline it
    /// was given.
    #[test]
    fn test_discovery_gets_a_share_of_the_budget_and_the_walk_the_rest() {
        let start = Instant::now();
        let budget = Duration::from_secs(120);
        let (discovery, whole) = budget_deadlines(start, Some(budget));
        let (discovery, whole) = (discovery.unwrap(), whole.unwrap());

        assert_eq!(whole, start + budget);
        assert!(
            discovery < whole,
            "discovery must yield before the deadline"
        );
        assert!(
            discovery > start,
            "discovery must get real time, not a token slice"
        );
        assert_eq!(budget_deadlines(start, None), (None, None));
        // `PoolWalk::within` accepts any `Duration`, so a budget longer than `Instant` can
        // represent is reachable from safe public API. Adding it would panic; a budget
        // beyond measuring is a request to run unbounded, and is answered as one.
        assert_eq!(budget_deadlines(start, Some(Duration::MAX)), (None, None));
    }

    /// A budget and a Ctrl+C both halt the walk, and they must not be confused. Running out
    /// of time means "here is what I got"; an operator interrupting means "stop" — handing
    /// them a snapshot they cancelled, which then renders as a full table, is not that.
    #[test]
    fn test_an_interrupt_still_stops_the_walk_outright() {
        struct Interrupting(SyntheticMemory);

        impl PoolMemory for Interrupting {
            fn read_exact(&self, address: u64, size: usize) -> Result<Vec<u8>, SnapshotError> {
                self.0.read_exact(address, size)
            }

            fn valid_region(
                &self,
                address: u64,
                size: usize,
            ) -> Result<(u64, usize), SnapshotError> {
                self.0.valid_region(address, size)
            }

            fn interrupted(&self) -> Result<bool, SnapshotError> {
                Ok(true)
            }
        }

        let memory = Interrupting(synthetic_memory());
        let layout = synthetic_layout();

        assert!(matches!(
            SnapshotWalker {
                memory: &memory,
                layout: &layout,
                traversal_limit: 1024,
            }
            .walk(Some(Duration::from_secs(600))),
            Err(SnapshotError::Interrupted)
        ));
    }

    /// Memory that hands back one small extent at a time and runs out of budget after a
    /// fixed number of them.
    ///
    /// This is the shape that makes a per-*region* check insufficient. A region the
    /// allocator left with holes is read one committed run at a time — a `valid_region` and
    /// a `read_exact` each, both over the wire on a live target — so checking only on the
    /// way in lets a single region overrun the deadline by as many round trips as it has
    /// extents.
    struct Fragmented {
        extent: usize,
        allowance: usize,
        extents_read: Cell<usize>,
    }

    impl PoolMemory for Fragmented {
        fn read_exact(&self, _address: u64, size: usize) -> Result<Vec<u8>, SnapshotError> {
            Ok(vec![0; size])
        }

        fn valid_region(&self, address: u64, size: usize) -> Result<(u64, usize), SnapshotError> {
            self.extents_read.set(self.extents_read.get() + 1);
            Ok((address, size.min(self.extent)))
        }

        fn interrupted(&self) -> Result<bool, SnapshotError> {
            Ok(false)
        }

        fn out_of_budget(&self) -> bool {
            self.extents_read.get() >= self.allowance
        }
    }

    #[test]
    fn test_a_fragmented_region_checks_the_budget_between_extents() {
        // 0x1000 of region in 0x400 extents is four round trips; the budget allows three.
        let memory = Fragmented {
            extent: 0x400,
            allowance: 3,
            extents_read: Cell::new(0),
        };
        let layout = vs_layout(false);
        let mut region = lfh_region(0x1000, 0x100);
        region.bitmap = vec![0xff; 16];
        let walker = SnapshotWalker {
            memory: &memory,
            layout: &layout,
            traversal_limit: 1000,
        };

        let outcome = walker.walk_region(&region, &mut PoolSnapshot::default());

        assert!(
            matches!(outcome, Err(SnapshotError::BudgetExpired)),
            "the region walk has to report the halt, not absorb it: {outcome:?}"
        );
        assert_eq!(
            memory.extents_read.get(),
            3,
            "the region went on reading past its deadline"
        );
    }

    /// A budget nobody comes close to spending must not change the answer.
    #[test]
    fn test_a_generous_budget_walks_exactly_as_an_unbounded_one_does() {
        let memory = synthetic_memory();
        let layout = synthetic_layout();
        let walker = SnapshotWalker {
            memory: &memory,
            layout: &layout,
            traversal_limit: 1024,
        };

        let unbounded = walker.walk(None).unwrap();
        let budgeted = walker.walk(Some(Duration::from_secs(600))).unwrap();

        assert_eq!(budgeted.spans, unbounded.spans);
        assert_eq!(budgeted.complete, unbounded.complete);
        assert_eq!(budgeted.diagnostics, unbounded.diagnostics);
    }

    // ---- diagnostic floods -------------------------------------------------------------

    /// A live target keeps allocating between the reads of one walk, so a single stale list
    /// pointer yields one complaint per node — 14k of them measured on a busy kernel, which
    /// buries the few distinct problems and leaves every consumer truncating by position.
    /// Collapsing keeps examples and, crucially, the *count*: the volume is itself the
    /// finding, so it must survive.
    #[test]
    fn test_a_flood_of_one_complaint_becomes_examples_plus_a_count() {
        let mut diagnostics: Vec<String> = (0..1000)
            .map(|node| format!("unreadable VS free tree node {node:#x}: sparse memory"))
            .collect();
        diagnostics.push("rejecting implausible LFH unit size 3 at 0x1000".into());

        let collapsed = collapse_repeats(diagnostics);

        assert_eq!(
            collapsed.len(),
            DIAGNOSTIC_EXAMPLES + 2,
            "expected {DIAGNOSTIC_EXAMPLES} examples, the distinct message, and one summary"
        );
        assert!(collapsed[0].contains("unreadable VS free tree node 0x0"));
        assert!(
            collapsed
                .iter()
                .any(|message| message.contains("rejecting implausible LFH unit size")),
            "a distinct complaint must not be collapsed away by a flood of another"
        );
        assert!(
            collapsed.last().is_some_and(
                |message| message.contains(&format!("and {} more", 1000 - DIAGNOSTIC_EXAMPLES))
            ),
            "the count is the finding and has to survive: {collapsed:?}"
        );
    }

    /// Grouping is by shape, so the same complaint about different addresses is one group
    /// while genuinely different complaints stay apart.
    #[test]
    fn test_diagnostic_shape_ignores_numbers_but_not_wording() {
        assert_eq!(
            diagnostic_shape("unreadable VS free tree node 0xdeadbeef: sparse"),
            diagnostic_shape("unreadable VS free tree node 0x41414141: sparse")
        );
        assert_ne!(
            diagnostic_shape("unreadable VS free tree node 0xdeadbeef"),
            diagnostic_shape("unreadable VS delay-free node 0xdeadbeef")
        );
    }

    #[test]
    fn test_special_pool_kinds_cover_all_heap_slots() {
        assert_eq!(SPECIAL_POOL_KINDS.len(), 4);
        assert_eq!(SPECIAL_POOL_KINDS[3], PoolKind::SpecialPrototypePaged);
        assert!(SPECIAL_POOL_KINDS[3].is_paged());
    }

    #[test]
    fn test_discovery_skips_missing_optional_large_layout() {
        let memory = big_page_memory(LARGE_VA, 4, 0);
        let mut layout = synthetic_layout();
        layout.types.remove("_HEAP_LARGE_ALLOC_DATA");
        let mut discovery = Discovery::default();

        discover_large_allocations(
            &memory,
            &layout,
            HEAP,
            0,
            PoolKind::NonPagedNx,
            HeapIdentity {
                pool_state: STATE,
                heap: HEAP,
                special: false,
            },
            0,
            1024,
            &mut discovery,
        )
        .unwrap();

        assert!(discovery.regions.is_empty());
        assert_eq!(memory.read_calls.get(), 0);
    }

    #[test]
    fn test_big_page_lookup_skips_missing_optional_layout() {
        let memory = big_page_memory(LARGE_VA, 4, 0);
        let mut layout = synthetic_layout();
        layout.types.remove("_POOL_TRACKER_BIG_PAGES");

        assert_eq!(
            lookup_big_page_target(&memory, &layout, LARGE_VA, &mut Vec::new()).unwrap(),
            None
        );
        assert_eq!(memory.read_calls.get(), 0);
    }

    #[test]
    fn test_big_page_lookup_batches_collision_chain() {
        let memory = big_page_memory(LARGE_VA, 512, 300);
        let layout = synthetic_layout();
        let reads_before = memory.read_calls.get();
        let mut diagnostics = Vec::new();

        assert_eq!(
            lookup_big_page_target(&memory, &layout, LARGE_VA, &mut diagnostics).unwrap(),
            Some((u32::from_le_bytes(*b"BTCH"), 0x9000))
        );
        assert!(memory.read_calls.get() - reads_before <= 5);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn test_big_page_lookup_honors_interrupt_between_batches() {
        let mut memory = big_page_memory(LARGE_VA, 512, 300);
        let layout = synthetic_layout();
        memory.interrupt_after_checks = Some(1);

        assert!(matches!(
            lookup_big_page_target(&memory, &layout, LARGE_VA, &mut Vec::new()),
            Err(SnapshotError::Interrupted)
        ));
        assert_eq!(memory.interrupt_checks.get(), 2);
    }

    #[test]
    fn test_snapshot_errors_preserve_category_and_source() {
        let memory = synthetic_memory();
        let error = memory.read_exact(0, 1).unwrap_err();
        assert!(matches!(&error, SnapshotError::Read { .. }));
        assert!(std::error::Error::source(&error).is_some());

        let error = guarded_read(&memory, SEGMENT + 0x7800, 0x10).unwrap_err();
        assert!(matches!(error, SnapshotError::RegionValidation { .. }));

        let error = scalar(&ShortMemory, 0x1000, 1).unwrap_err();
        assert!(matches!(
            error,
            SnapshotError::InvalidData { detail } if detail == "short u8"
        ));
    }
}
