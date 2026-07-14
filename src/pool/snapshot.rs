use std::collections::HashSet;

use thiserror::Error;

use super::decode::{
    PAGE_SIZE, PoolHeaderLayout, adjust_page_end_header, big_page_probe, decode_descriptor_at,
    decode_large_allocation, decode_lfh_offsets, decode_pool_header, decode_rb_root,
    decode_vs_sizes, lfh_bitmap_state, read_u16, read_u32, read_u64,
    valid_descriptor_tree_signature, valid_page_segment_signature, valid_vs_signature,
};
use super::{
    HeapIdentity, PoolBackend, PoolKind, PoolSpan, PoolState,
    layout::{LayoutError, PoolLayout},
};

type SnapshotSource = Box<dyn std::error::Error + Send + Sync>;

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
    #[error("interrupt-status query failed: {source}")]
    InterruptQuery {
        #[source]
        source: SnapshotSource,
    },
    #[error("invalid snapshot data: {detail}")]
    InvalidData { detail: String },
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
    pub reusable_chunks: HashSet<u64>,
    /// VS chunk-header addresses present in delay-free/lookaside lists.
    pub cached_chunks: HashSet<u64>,
}

pub(crate) trait PoolMemory {
    fn read_exact(&self, address: u64, size: usize) -> Result<Vec<u8>, SnapshotError>;
    fn valid_region(&self, address: u64, size: usize) -> Result<(u64, usize), SnapshotError>;
    fn interrupted(&self) -> Result<bool, SnapshotError>;
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

fn check_interrupted(memory: &impl PoolMemory) -> Result<(), SnapshotError> {
    if memory.interrupted()? {
        Err(SnapshotError::Interrupted)
    } else {
        Ok(())
    }
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
        check_interrupted(memory)?;
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
    let encoded = match scalar(memory, tree_address + root_offset as u64, 8) {
        Ok(value) => value,
        Err(error) => {
            diagnostics.push(format!("cannot read {label} root: {error}"));
            return Ok(Vec::new());
        }
    };
    let Some(root) = decode_rb_root(encoded, tree_address) else {
        diagnostics.push(format!(
            "rejecting corrupt encoded {label} root {encoded:#x}"
        ));
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
    let mut entry = read_u64(&bytes, region_offset).unwrap_or(0) & !0xf;
    let expected = depth.min(limit);
    while entry != 0 && nodes.len() < expected {
        check_interrupted(memory)?;
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

fn discover_pool_regions(
    memory: &impl PoolMemory,
    layout: &PoolLayout,
    traversal_limit: usize,
) -> Result<Discovery, SnapshotError> {
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
    let number = scalar(memory, state_address + number_offset as u64, 4)? as usize;
    if number == 0 || number > 256 {
        return Err(SnapshotError::InvalidData {
            detail: format!("implausible ExPoolState.NumberOfPools {number}"),
        });
    }
    let mut discovery = Discovery::default();
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
                heaps.push((
                    heap,
                    numa_node as u16,
                    match heap_index {
                        0 => PoolKind::NonPagedExecutable,
                        1 => PoolKind::NonPagedNx,
                        2 => PoolKind::Paged,
                        _ => PoolKind::PrototypePaged,
                    },
                    false,
                ));
            }
        }
    }
    for special_index in 0..3usize {
        let pointer_address = state_address + special_offset as u64 + special_index as u64 * 8;
        match scalar(memory, pointer_address, 8) {
            Ok(heap) if heap != 0 => heaps.push((
                heap,
                0,
                match special_index {
                    0 => PoolKind::SpecialNonPaged,
                    1 => PoolKind::SpecialNonPagedNx,
                    _ => PoolKind::SpecialPaged,
                },
                true,
            )),
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
    for (heap_address, numa_node, pool_kind, special) in heaps {
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
            heap_key,
            lfh_key,
            traversal_limit,
            &mut discovery,
        ) {
            discovery.diagnostics.push(format!(
                "cannot fully discover heap {heap_address:#x}: {error}"
            ));
        }
    }
    let _ = state.size;
    Ok(discovery)
}

fn discover_vs_evidence(
    memory: &impl PoolMemory,
    layout: &PoolLayout,
    heap_address: u64,
    limit: usize,
    diagnostics: &mut Vec<String>,
) -> Result<(HashSet<u64>, HashSet<u64>), SnapshotError> {
    let Ok(vs_context_offset) = layout.field("_SEGMENT_HEAP", "VsContext") else {
        return Ok(Default::default());
    };
    let context = heap_address + vs_context_offset as u64;
    let Ok(tree_offset) = layout.field("_HEAP_VS_CONTEXT", "FreeChunkTree") else {
        return Ok(Default::default());
    };
    let tree_node_offset = layout
        .field("_HEAP_VS_CHUNK_FREE_HEADER", "TreeNode")
        .unwrap_or(0);
    let reusable = tree_nodes(
        memory,
        layout,
        context + tree_offset as u64,
        limit,
        "VS free tree",
        diagnostics,
    )?
    .into_iter()
    .map(|node| node.saturating_sub(tree_node_offset as u64))
    .collect();

    let mut cached = HashSet::new();
    let pool_header_size = layout
        .type_layout("_POOL_HEADER")
        .map_or(0, |value| value.size as u64);
    let vs_header_size = layout
        .type_layout("_HEAP_VS_CHUNK_HEADER")
        .map_or(0, |value| value.size as u64);
    if let (Ok(delay_offset), Ok(list_offset)) = (
        layout.field("_HEAP_VS_CONTEXT", "DelayFreeContext"),
        layout.field("_HEAP_VS_DELAY_FREE_CONTEXT", "ListHead"),
    ) {
        for entry in walk_slist_nodes(
            memory,
            layout,
            context + delay_offset as u64 + list_offset as u64,
            limit,
            "VS delay-free",
            diagnostics,
        )? {
            insert_cached_chunk_candidates(&mut cached, entry, pool_header_size, vs_header_size);
        }
    }

    let dynamic = layout
        .field("_SEGMENT_HEAP", "UserContext")
        .ok()
        .and_then(|offset| scalar(memory, heap_address + offset as u64, 8).ok())
        .unwrap_or(0);
    if dynamic != 0 {
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
    Ok((reusable, cached))
}

#[allow(clippy::too_many_arguments)]
fn discover_heap_regions(
    memory: &impl PoolMemory,
    layout: &PoolLayout,
    heap_address: u64,
    numa_node: u16,
    pool_kind: PoolKind,
    identity: HeapIdentity,
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
        check_interrupted(memory)?;
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
    reusable_chunks: &HashSet<u64>,
    cached_chunks: &HashSet<u64>,
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
        check_interrupted(memory)?;
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
        let heap_globals = *layout
            .globals
            .get("RtlpHpHeapGlobals")
            .ok_or_else(|| missing_layout("RtlpHpHeapGlobals"))?;
        if !valid_page_segment_signature(signature, segment_address, context_address, heap_globals)
        {
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
            let backend = match decoded.flags & 0x0c {
                0x08 => PoolBackend::Lfh,
                0x0c => PoolBackend::Vs,
                _ => PoolBackend::Segment,
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
                        .unwrap_or(0);
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
                reusable_chunks: reusable_chunks.clone(),
                cached_chunks: cached_chunks.clone(),
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
    let tree_address = heap_address + tree_offset as u64;
    let nodes = tree_nodes(
        memory,
        layout,
        tree_address,
        traversal_limit,
        "large-allocation tree",
        &mut discovery.diagnostics,
    )?;
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
            reusable_chunks: HashSet::new(),
            cached_chunks: HashSet::new(),
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
    let table_pointer_address = *layout
        .globals
        .get("PoolBigPageTable")
        .ok_or_else(|| missing_layout("PoolBigPageTable"))?;
    let table = match scalar(memory, table_pointer_address, 8) {
        Ok(value) => value,
        Err(error) => {
            diagnostics.push(format!("cannot read big-page table pointer: {error}"));
            return Ok(None);
        }
    };
    let size_address = *layout
        .globals
        .get("PoolBigPageTableSize")
        .ok_or_else(|| missing_layout("PoolBigPageTableSize"))?;
    let count = match scalar(memory, size_address, 8).or_else(|_| scalar(memory, size_address, 4)) {
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
    let entry = layout.type_layout("_POOL_TRACKER_BIG_PAGES")?;
    let entry_size = entry.size as usize;
    let va_offset = layout.field("_POOL_TRACKER_BIG_PAGES", "Va")?;
    let tag_offset = layout.field("_POOL_TRACKER_BIG_PAGES", "Key")?;
    let size_offset = layout.field("_POOL_TRACKER_BIG_PAGES", "NumberOfBytes")?;
    let mut probes = big_page_probe(address, count).ok_or_else(|| SnapshotError::InvalidData {
        detail: format!("invalid big-page table size {count}"),
    })?;
    let mut remaining = count;
    'probe: while let Some(first_index) = probes.next() {
        check_interrupted(memory)?;
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

impl<'a, M: PoolMemory> SnapshotWalker<'a, M> {
    pub(crate) fn walk(&self) -> Result<PoolSnapshot, SnapshotError> {
        let mut snapshot = PoolSnapshot {
            diagnostics: vec!["per-session paged heaps are not included".into()],
            complete: true,
            ..PoolSnapshot::default()
        };
        let discovery = discover_pool_regions(self.memory, self.layout, self.traversal_limit)?;
        if !discovery.diagnostics.is_empty() {
            snapshot.complete = false;
        }
        snapshot.diagnostics.extend(discovery.diagnostics);
        for region in discovery.regions {
            check_interrupted(self.memory)?;
            self.walk_region(&region, &mut snapshot);
        }
        snapshot
            .spans
            .sort_by_key(|span| (span.heap, span.usable_address));
        Ok(snapshot)
    }

    fn walk_region(&self, region: &PoolRegion, snapshot: &mut PoolSnapshot) {
        let requested_end = region.address.saturating_add(region.size as u64);
        let mut cursor = region.address;
        while cursor < requested_end {
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
            match region.backend {
                PoolBackend::Lfh => self.walk_lfh(region, valid_base, &bytes, snapshot),
                PoolBackend::Vs => self.walk_vs(region, valid_base, &bytes, snapshot),
                PoolBackend::Segment | PoolBackend::Large => {
                    self.walk_page_ranges(region, valid_base, &bytes, snapshot)
                }
            }
            cursor = valid_end;
        }
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
            if address / PAGE_SIZE != (address + unit as u64 - 1) / PAGE_SIZE {
                snapshot.diagnostics.push(format!(
                    "LFH slot {address:#x}+{unit:#x} would cross a page"
                ));
                snapshot.complete = false;
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
            let header_size = if region.backend == PoolBackend::Large {
                0
            } else {
                region.pool_header.size.min(size)
            };
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
    use std::{
        cell::Cell,
        collections::{BTreeMap, HashMap},
    };

    use super::*;
    use crate::pool::layout::{SessionKey, TypeLayout};

    const K: u64 = 0xffff_8000_0000_0000;
    const STATE: u64 = K + 0x10_0000;
    const GLOBALS: u64 = K + 0x11_0000;
    const BIG_TABLE_POINTER: u64 = K + 0x12_0000;
    const BIG_TABLE_COUNT: u64 = K + 0x12_0010;
    const HEAP: u64 = K + 0x20_0000;
    const DYNAMIC_LOOKASIDE: u64 = K + 0x21_0000;
    const SEGMENT: u64 = K + 0x30_0000;
    const LARGE_META: u64 = K + 0x80_0000;
    const LARGE_VA: u64 = K + 0x90_0000;
    const BIG_TABLE: u64 = K + 0xa0_0000;

    struct SyntheticMemory {
        bytes: BTreeMap<u64, u8>,
        holes: Vec<(u64, u64)>,
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
            if address == BIG_TABLE_COUNT && size == 8 {
                return Ok((self.count as u64).to_le_bytes().to_vec());
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
            (0..size)
                .map(|offset| {
                    self.bytes
                        .get(&(address + offset as u64))
                        .copied()
                        .ok_or_else(|| SnapshotError::Read {
                            address,
                            size,
                            source: Box::new(std::io::Error::other("sparse synthetic memory")),
                        })
                })
                .collect()
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
                0x100,
                &[
                    ("HeapManager", 8),
                    ("PoolNode", 0x40),
                    ("NumberOfPools", 0),
                    ("SpecialHeaps", 0x20),
                ],
            ),
        );
        types.insert("_EX_HEAP_POOL_NODE", type_layout(0x40, &[("Heaps", 0)]));
        types.insert(
            "_SEGMENT_HEAP",
            type_layout(
                0x800,
                &[
                    ("SegContexts", 0x100),
                    ("VsContext", 0x300),
                    ("LfhContext", 0x380),
                    ("LargeAllocMetadata", 0x400),
                    ("UserContext", 0x500),
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
        types.insert(
            "_HEAP_LFH_CONTEXT",
            type_layout(0x20, &[("Buckets", 0), ("AffinitySlots", 8)]),
        );
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
            type_layout(0x10, &[("Root", 0), ("Min", 8)]),
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

    fn put(bytes: &mut BTreeMap<u64, u8>, address: u64, data: &[u8]) {
        bytes.extend(
            data.iter()
                .enumerate()
                .map(|(offset, byte)| (address + offset as u64, *byte)),
        );
    }

    fn fill(bytes: &mut BTreeMap<u64, u8>, address: u64, size: usize) {
        put(bytes, address, &vec![0; size]);
    }

    fn put_u16(bytes: &mut BTreeMap<u64, u8>, address: u64, value: u16) {
        put(bytes, address, &value.to_le_bytes());
    }

    fn put_u32(bytes: &mut BTreeMap<u64, u8>, address: u64, value: u32) {
        put(bytes, address, &value.to_le_bytes());
    }

    fn put_u64(bytes: &mut BTreeMap<u64, u8>, address: u64, value: u64) {
        put(bytes, address, &value.to_le_bytes());
    }

    fn pool_header(bytes: &mut BTreeMap<u64, u8>, address: u64, tag: &[u8; 4]) {
        fill(bytes, address, 0x10);
        put(bytes, address, &[1, 0, 4, 1]);
        put(bytes, address + 8, tag);
    }

    fn synthetic_memory() -> SyntheticMemory {
        let mut bytes = BTreeMap::new();
        fill(&mut bytes, STATE, 0x100);
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
            SEGMENT ^ context ^ GLOBALS ^ super::super::decode::PAGE_SEGMENT_SIGNATURE,
        );
        fill(&mut bytes, SEGMENT + 0x100, 16 * 0x20);
        for (index, units, flags) in [
            (1u64, 2u8, 0x09u8),
            (3, 2, 0x0d),
            (5, 1, 0x01),
            (6, 1, 0x00),
            (7, 1, 0x01),
        ] {
            let descriptor = SEGMENT + 0x100 + index * 0x20;
            if flags & 1 != 0 {
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
        put_u16(&mut bytes, vs, 0x2bed ^ 2);
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
        pool_header(&mut bytes, first_chunk + 0x20, b"VS!!");
        let vs_context = HEAP + 0x300;
        put_u64(&mut bytes, vs_context, free_chunk + 8);
        put_u64(&mut bytes, free_chunk + 8, 0);
        put_u64(&mut bytes, free_chunk + 16, 0);
        let delay_head = vs_context + 0x10;
        put_u16(&mut bytes, delay_head, 1);
        put_u64(&mut bytes, delay_head + 8, cached_chunk + 0x20);
        put_u64(&mut bytes, cached_chunk + 0x20, 0);

        put_u64(&mut bytes, HEAP + 0x500, DYNAMIC_LOOKASIDE);
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
        put_u64(&mut bytes, lookaside_head + 8, lookaside_chunk + 0x20);
        put_u64(&mut bytes, lookaside_chunk + 0x20, 0);
        put_u32(&mut bytes, lookaside_head + 0x30, 0x40);

        fill(&mut bytes, SEGMENT + 0x5000, 0x1000);
        pool_header(&mut bytes, SEGMENT + 0x5000, b"SEGM");
        fill(&mut bytes, SEGMENT + 0x6000, 0x1000);
        fill(&mut bytes, SEGMENT + 0x7000, 0x800);
        pool_header(&mut bytes, SEGMENT + 0x7000, b"SPRS");

        let large_tree = HEAP + 0x400;
        put_u64(&mut bytes, large_tree, (LARGE_META ^ large_tree) | 1);
        fill(&mut bytes, LARGE_META, 0x28);
        put_u64(&mut bytes, LARGE_META + 0x18, LARGE_VA | 0x1800);
        put_u64(&mut bytes, LARGE_META + 0x20, (2u64 << 12) | 0x5a5);
        fill(&mut bytes, LARGE_VA, 0x2000);
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

        SyntheticMemory {
            bytes,
            holes: vec![(SEGMENT + 0x7800, SEGMENT + 0x8000)],
        }
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
        let layout = synthetic_layout();
        let walker = SnapshotWalker {
            memory: &memory,
            layout: &layout,
            traversal_limit: 1024,
        };
        let snapshot = walker.walk().unwrap();
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
            span.backend == PoolBackend::Vs && span.header_address == SEGMENT + 0x4000
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
