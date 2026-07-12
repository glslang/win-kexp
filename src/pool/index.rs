use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use super::{PoolSpan, PoolState, snapshot::PoolSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    Underflow,
    Overflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hole {
    pub span_index: usize,
    pub address: u64,
    pub size: u64,
    pub state: PoolState,
    pub distance: u64,
    pub immediate: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PoolIndex {
    pub spans: Vec<PoolSpan>,
    pub postings: HashMap<u32, Vec<usize>>,
    pub diagnostics: Vec<String>,
    row_postings: HashMap<RowIdentity, Vec<usize>>,
    span_rows: Vec<RowIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RowIdentity {
    pool_kind: super::PoolKind,
    numa_node: u16,
    heap: super::HeapIdentity,
    backend: super::PoolBackend,
    subsegment: Option<u64>,
    size_class: u32,
}

impl From<&PoolSpan> for RowIdentity {
    fn from(span: &PoolSpan) -> Self {
        Self {
            pool_kind: span.pool_kind,
            numa_node: span.numa_node,
            heap: span.heap,
            backend: span.backend,
            subsegment: span.subsegment,
            size_class: span.size_class,
        }
    }
}

impl PoolIndex {
    pub(crate) fn build(mut snapshot: PoolSnapshot) -> Self {
        snapshot
            .spans
            .sort_by_key(|span| (span.heap, span.usable_address));
        let mut postings: HashMap<u32, Vec<usize>> = HashMap::new();
        let mut row_postings: HashMap<RowIdentity, Vec<usize>> = HashMap::new();
        let mut span_rows = Vec::with_capacity(snapshot.spans.len());
        for (index, span) in snapshot.spans.iter().enumerate() {
            if span.state == PoolState::Allocated {
                postings.entry(span.raw_tag).or_default().push(index);
            }
            let row = RowIdentity::from(span);
            row_postings.entry(row).or_default().push(index);
            span_rows.push(row);
        }
        Self {
            spans: snapshot.spans,
            postings,
            diagnostics: snapshot.diagnostics,
            row_postings,
            span_rows,
        }
    }

    fn same_boundary(left: &PoolSpan, right: &PoolSpan) -> bool {
        left.pool_kind == right.pool_kind
            && left.numa_node == right.numa_node
            && left.heap == right.heap
            && left.backend == right.backend
            && left.subsegment == right.subsegment
            && left.state != PoolState::Unreadable
            && right.state != PoolState::Unreadable
    }

    pub(crate) fn predecessor(&self, index: usize) -> Option<usize> {
        let previous = index.checked_sub(1)?;
        Self::same_boundary(self.spans.get(previous)?, self.spans.get(index)?).then_some(previous)
    }

    pub(crate) fn successor(&self, index: usize) -> Option<usize> {
        let next = index.checked_add(1)?;
        Self::same_boundary(self.spans.get(index)?, self.spans.get(next)?).then_some(next)
    }

    pub(crate) fn holes(&self, allocation: usize, direction: Direction) -> Vec<Hole> {
        let Some(origin) = self.spans.get(allocation) else {
            return Vec::new();
        };
        let mut holes = Vec::new();
        let mut cursor = allocation;
        loop {
            let next = match direction {
                Direction::Underflow => self.predecessor(cursor),
                Direction::Overflow => self.successor(cursor),
            };
            let Some(index) = next else { break };
            let span = &self.spans[index];
            if span.state == PoolState::Allocated {
                break;
            }
            let distance = match direction {
                Direction::Underflow => origin.usable_address.saturating_sub(span.end()),
                Direction::Overflow => span.usable_address.saturating_sub(origin.end()),
            };
            holes.push(Hole {
                span_index: index,
                address: span.usable_address,
                size: span.size,
                state: span.state,
                distance,
                immediate: holes.is_empty() && distance == 0,
            });
            cursor = index;
        }
        holes
    }

    /// Matching allocations plus their local geometry. Unrelated allocations and
    /// free spans are deliberately retained so tag filtering never erases a hole.
    pub(crate) fn context_for_tag(&self, tag: u32) -> Vec<usize> {
        let mut selected_rows = HashSet::new();
        for &index in self.postings.get(&tag).into_iter().flatten() {
            if let Some(row) = self.span_rows.get(index) {
                selected_rows.insert(*row);
            }
        }
        let mut result: Vec<_> = selected_rows
            .into_iter()
            .flat_map(|row| self.row_postings.get(&row).into_iter().flatten().copied())
            .collect();
        result.sort_unstable();
        result
    }

    pub(crate) fn ranked_holes(&self, allocation: usize, direction: Direction) -> Vec<Hole> {
        let Some(origin) = self.spans.get(allocation) else {
            return Vec::new();
        };
        let mut holes = self.holes(allocation, direction);
        holes.sort_by_key(|hole| {
            let span = &self.spans[hole.span_index];
            (
                !hole.immediate,
                hole.state != PoolState::ReusableFree,
                span.backend != origin.backend || span.size_class != origin.size_class,
                hole.distance,
                u64::MAX - hole.size,
                hole.address,
            )
        });
        holes
    }
}

#[derive(Debug, Clone)]
struct CachedSnapshot {
    session: u64,
    index: PoolIndex,
}

#[derive(Default)]
pub(crate) struct SnapshotCache {
    entry: Mutex<Option<CachedSnapshot>>,
}

impl SnapshotCache {
    pub(crate) fn get_or_refresh<F>(
        &self,
        session: u64,
        refresh: bool,
        build: F,
    ) -> Result<PoolIndex, String>
    where
        F: FnOnce() -> Result<PoolSnapshot, String>,
    {
        if !refresh
            && let Some(cached) = self.entry.lock().unwrap().as_ref()
            && cached.session == session
        {
            return Ok(cached.index.clone());
        }
        let snapshot = build()?;
        let complete = snapshot.complete;
        let index = PoolIndex::build(snapshot);
        if complete {
            *self.entry.lock().unwrap() = Some(CachedSnapshot {
                session,
                index: index.clone(),
            });
        }
        Ok(index)
    }

    pub(crate) fn invalidate(&self) {
        *self.entry.lock().unwrap() = None;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::pool::{HeapIdentity, PoolBackend, PoolKind};

    fn span(address: u64, tag: u32, state: PoolState, heap: u64) -> PoolSpan {
        let mut span = PoolSpan::allocation(
            address,
            0x20,
            tag,
            PoolKind::NonPagedNx,
            HeapIdentity {
                pool_state: 1,
                heap,
                special: false,
            },
            PoolBackend::Lfh,
        );
        span.state = state;
        span
    }

    #[test]
    fn test_pool_snapshot_index_and_cache_invalidation() {
        let tag = u32::from_le_bytes(*b"TEST");
        let other = u32::from_le_bytes(*b"OTHR");
        let snapshot = PoolSnapshot {
            spans: vec![
                span(0x1000, other, PoolState::Allocated, 1),
                span(0x1020, tag, PoolState::Allocated, 1),
                span(0x1040, 0, PoolState::ReusableFree, 1),
                span(0x1060, 0, PoolState::CachedFree, 1),
                span(0x1080, tag, PoolState::Allocated, 2),
            ],
            complete: true,
            diagnostics: vec![],
        };
        let index = PoolIndex::build(snapshot.clone());
        assert_eq!(index.postings[&tag], vec![1, 4]);
        assert_eq!(index.successor(1), Some(2));
        assert_eq!(index.successor(3), None); // heap boundary
        let holes = index.ranked_holes(1, Direction::Overflow);
        assert_eq!(holes[0].address, 0x1040);
        assert!(holes[0].immediate);
        assert!(index.context_for_tag(tag).contains(&0)); // unrelated neighbor preserved

        let mut unreadable = span(0x1060, 0, PoolState::Unreadable, 1);
        unreadable.size_class = 0x20;
        let contextual = PoolIndex::build(PoolSnapshot {
            spans: vec![
                span(0x1000, tag, PoolState::Allocated, 1),
                span(0x1020, other, PoolState::Allocated, 1),
                span(0x1040, 0, PoolState::ReusableFree, 1),
                unreadable,
                span(0x1080, other, PoolState::Allocated, 1),
            ],
            complete: true,
            diagnostics: vec![],
        });
        assert_eq!(contextual.context_for_tag(tag), vec![0, 1, 2, 3, 4]);
        assert_eq!(contextual.successor(2), None);

        let cache = SnapshotCache::default();
        let builds = AtomicUsize::new(0);
        let make = || {
            builds.fetch_add(1, Ordering::SeqCst);
            Ok(snapshot.clone())
        };
        cache.get_or_refresh(7, false, make).unwrap();
        cache.get_or_refresh(7, false, make).unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        cache.get_or_refresh(7, true, make).unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        cache.invalidate();
        cache.get_or_refresh(7, false, make).unwrap();
        cache.get_or_refresh(8, false, make).unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 4);

        let incomplete_builds = AtomicUsize::new(0);
        let make_incomplete = || {
            incomplete_builds.fetch_add(1, Ordering::SeqCst);
            let mut value = snapshot.clone();
            value.complete = false;
            Ok(value)
        };
        cache.invalidate();
        cache.get_or_refresh(9, false, make_incomplete).unwrap();
        cache.get_or_refresh(9, false, make_incomplete).unwrap();
        assert_eq!(incomplete_builds.load(Ordering::SeqCst), 2);
    }
}
