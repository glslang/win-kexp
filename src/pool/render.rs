use std::collections::BTreeMap;

use super::index::{Direction, PoolIndex};
use super::{HeapIdentity, PoolBackend, PoolKind, PoolSpan, PoolState};

const OUTPUT_CHUNK: usize = 7_500;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RenderOptions {
    pub tag: Option<u32>,
    pub dml: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RowKey {
    kind: PoolKind,
    node: u16,
    heap: HeapIdentity,
    backend: PoolBackend,
    subsegment: Option<u64>,
    size_class: u32,
}

pub(crate) fn escape_dml(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&apos;".to_string(),
            _ => character.to_string(),
        })
        .collect()
}

fn kind_name(kind: PoolKind) -> &'static str {
    match kind {
        PoolKind::NonPagedExecutable => "nonpaged-exec",
        PoolKind::NonPagedNx => "nonpaged-nx",
        PoolKind::Paged => "paged",
        PoolKind::PrototypePaged => "prototype-paged",
        PoolKind::SpecialNonPaged => "special-nonpaged",
        PoolKind::SpecialNonPagedNx => "special-nonpaged-nx",
        PoolKind::SpecialPaged => "special-paged",
    }
}

fn backend_name(backend: PoolBackend) -> &'static str {
    match backend {
        PoolBackend::Lfh => "LFH",
        PoolBackend::Vs => "VS",
        PoolBackend::Segment => "segment",
        PoolBackend::Large => "large",
    }
}

fn glyph(span: &PoolSpan, selected: bool) -> (char, &'static str) {
    if selected {
        ('S', "0x00ff00")
    } else {
        match span.state {
            PoolState::Allocated => ('A', "0x5dade2"),
            PoolState::ReusableFree => ('.', "0xf4d03f"),
            PoolState::CachedFree => ('c', "0xe67e22"),
            PoolState::Unreadable => ('?', "0x7f8c8d"),
        }
    }
}

fn cell(span: &PoolSpan, selected: bool, dml: bool) -> String {
    let (glyph, color) = glyph(span, selected);
    if !dml {
        return glyph.to_string();
    }
    let command = format!("!win_kexp.poolmap {:#x}", span.usable_address);
    format!(
        "<link cmd=\"{}\"><col fg=\"{color}\">{glyph}</col></link>",
        escape_dml(&command)
    )
}

fn push_chunked(chunks: &mut Vec<String>, text: &str, dml: bool) {
    for fragment in text.split_inclusive('\n') {
        push_atomic(chunks, fragment, dml);
    }
}

fn push_atomic(chunks: &mut Vec<String>, fragment: &str, dml: bool) {
    if fragment.is_empty() {
        return;
    }
    if fragment.len() > OUTPUT_CHUNK {
        let mut remaining = fragment;
        while !remaining.is_empty() {
            let take = if dml {
                safe_dml_boundary(remaining, OUTPUT_CHUNK)
            } else {
                safe_text_boundary(remaining, OUTPUT_CHUNK)
            };
            debug_assert!(take != 0, "a single DML element exceeds the output limit");
            if take == 0 {
                return;
            }
            push_atomic(chunks, &remaining[..take], dml);
            remaining = &remaining[take..];
        }
        return;
    }
    if chunks.is_empty() || chunks.last().map_or(0, String::len) + fragment.len() > OUTPUT_CHUNK {
        chunks.push(String::new());
    }
    chunks.last_mut().unwrap().push_str(fragment);
}

fn safe_text_boundary(text: &str, limit: usize) -> usize {
    text.char_indices()
        .map(|(offset, character)| offset + character.len_utf8())
        .take_while(|end| *end <= limit)
        .last()
        .unwrap_or(0)
}

fn safe_dml_boundary(text: &str, limit: usize) -> usize {
    let mut tag_start = None;
    let mut in_entity = false;
    let mut depth = 0usize;
    let mut boundary = 0;
    for (offset, character) in text.char_indices() {
        let end = offset + character.len_utf8();
        if end > limit {
            break;
        }
        if let Some(start) = tag_start {
            if character == '>' {
                let tag = &text[start..end];
                if tag.starts_with("</") {
                    depth = depth.saturating_sub(1);
                } else if !tag.ends_with("/>") && !tag.starts_with("<!") && !tag.starts_with("<?") {
                    depth += 1;
                }
                tag_start = None;
            }
        } else if in_entity {
            if character == ';' {
                in_entity = false;
            }
        } else {
            match character {
                '<' => tag_start = Some(offset),
                '&' => in_entity = true,
                _ => {}
            }
        }
        if tag_start.is_none() && !in_entity && depth == 0 {
            boundary = end;
        }
    }
    boundary
}

pub(crate) fn render_pool_map(index: &PoolIndex, options: RenderOptions) -> Vec<String> {
    let selected_indices = options
        .tag
        .map(|tag| index.context_for_tag(tag))
        .unwrap_or_else(|| (0..index.spans.len()).collect());
    let mut rows: BTreeMap<RowKey, Vec<usize>> = BTreeMap::new();
    for span_index in selected_indices {
        let span = &index.spans[span_index];
        rows.entry(RowKey {
            kind: span.pool_kind,
            node: span.numa_node,
            heap: span.heap,
            backend: span.backend,
            subsegment: span.subsegment,
            size_class: span.size_class,
        })
        .or_default()
        .push(span_index);
    }

    let mut chunks = Vec::new();
    for diagnostic in &index.diagnostics {
        let diagnostic = if options.dml {
            escape_dml(diagnostic)
        } else {
            diagnostic.clone()
        };
        push_chunked(
            &mut chunks,
            &format!("Diagnostic: {diagnostic}\n"),
            options.dml,
        );
    }
    if rows.is_empty() {
        push_chunked(
            &mut chunks,
            "No matching pool allocations in the stopped-target snapshot.\n",
            options.dml,
        );
        return chunks;
    }
    for (key, indices) in rows {
        let first = &index.spans[indices[0]];
        push_atomic(
            &mut chunks,
            &format!(
                "{} node={} {} heap={:#x} base={:#x} class={:#x}: ",
                kind_name(key.kind),
                key.node,
                backend_name(key.backend),
                key.heap.heap,
                first.usable_address,
                key.size_class
            ),
            options.dml,
        );
        let mut previous_index = None;
        for index_value in indices {
            let span = &index.spans[index_value];
            if previous_index.is_some_and(|index| index + 1 != index_value) {
                push_atomic(&mut chunks, "|", options.dml);
            }
            push_atomic(
                &mut chunks,
                &cell(
                    span,
                    options.tag == Some(span.raw_tag) && span.state == PoolState::Allocated,
                    options.dml,
                ),
                options.dml,
            );
            previous_index = Some(index_value);
        }
        push_atomic(&mut chunks, "\n", options.dml);
    }
    push_chunked(
        &mut chunks,
        "Legend: S selected tag, A unrelated allocation, . reusable hole, c cached/delay-free, ? unreadable\n",
        options.dml,
    );
    if let Some(tag) = options.tag {
        push_chunked(
            &mut chunks,
            &render_advice(index, tag, options.dml),
            options.dml,
        );
    }
    chunks
}

pub(crate) fn render_advice(index: &PoolIndex, tag: u32, dml: bool) -> String {
    let mut output = String::from("Observed geometry:\n");
    for &allocation in index.postings.get(&tag).into_iter().flatten() {
        let span = &index.spans[allocation];
        let overflow = index.ranked_holes(allocation, Direction::Overflow);
        let underflow = index.ranked_holes(allocation, Direction::Underflow);
        output.push_str(&format!(
            "- {} {} allocation {} at {:#x}+{:#x}; header distance {:#x}, page offset {:#x}.\n",
            kind_name(span.pool_kind),
            backend_name(span.backend),
            if dml {
                escape_dml(&span.display_tag)
            } else {
                span.display_tag.clone()
            },
            span.usable_address,
            span.size,
            span.usable_address.saturating_sub(span.header_address),
            span.usable_address & 0xfff
        ));
        for (name, holes) in [("overflow", overflow), ("underflow", underflow)] {
            if let Some(hole) = holes.first() {
                output.push_str(&format!(
                    "  {name}: {} hole at {:#x}+{:#x}, distance {:#x}.\n",
                    match hole.state {
                        PoolState::ReusableFree => "reusable",
                        PoolState::CachedFree => "cached/delay-free",
                        PoolState::Unreadable => "unreadable",
                        PoolState::Allocated => "allocated",
                    },
                    hole.address,
                    hole.size,
                    hole.distance
                ));
            }
        }
        match span.backend {
            PoolBackend::Lfh => output.push_str(
                "  LFH: account for bucket size, affinity, and randomized slot selection; bitmap reuse is evidence, not a deterministic placement guarantee.\n",
            ),
            PoolBackend::Vs => output.push_str(
                "  VS: consider splitting/coalescing, dynamic-lookaside retention, delay-free state, extra-header distance, and page boundaries.\n",
            ),
            PoolBackend::Segment => output.push_str(
                "  Segment backend: descriptor/page-range adjacency is shown; validate commitment boundaries before relying on it.\n",
            ),
            PoolBackend::Large => output.push_str(
                "  Large backend: geometry is page-granular and the tag/size evidence comes from the validated big-page entry.\n",
            ),
        }
        output.push_str(if span.pool_kind == PoolKind::NonPagedExecutable {
            "  This allocation is in executable nonpaged pool.\n"
        } else if !span.pool_kind.is_paged() {
            "  This allocation is in NX nonpaged pool; data adjacency does not imply executable memory.\n"
        } else {
            "  This allocation is in paged pool and can be unavailable at elevated IRQL.\n"
        });
        let spray_backend = matches!(span.backend, PoolBackend::Lfh | PoolBackend::Vs);
        let spray_size = (0x40..=0x1_0000).contains(&span.size_class);
        if span.pool_kind == PoolKind::Paged && spray_backend && spray_size {
            output.push_str(
                "  AnonymousPipe-driven PipeAttribute spraying uses normal paged pool and can be shaped to this LFH/VS size class; verify the exact observed bucket before use.\n",
            );
        } else if span.pool_kind == PoolKind::NonPagedNx && spray_backend && spray_size {
            output.push_str(
                "  AnonymousPipe-driven PipeQueueEntry spraying uses normal NX nonpaged pool and can be shaped to this LFH/VS size class; verify the exact observed bucket before use.\n",
            );
        }
    }
    output.push_str(
        "Historical caveat: BlockSize confusion, CacheAligned/PreviousSize confusion, quota-pointer overwrite, and ghost-chunk techniques are 19H1-era observations, not guarantees on current Windows builds.\n",
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::snapshot::PoolSnapshot;

    fn span(
        address: u64,
        tag: u32,
        kind: PoolKind,
        backend: PoolBackend,
        state: PoolState,
    ) -> PoolSpan {
        let mut value = PoolSpan::allocation(
            address,
            0x40,
            tag,
            kind,
            HeapIdentity {
                pool_state: 1,
                heap: 2,
                special: false,
            },
            backend,
        );
        value.state = state;
        value
    }

    #[test]
    fn test_poolmap_heatmap_and_advice() {
        let tag = u32::from_le_bytes(*b"A<&\"");
        let mut spans = vec![
            span(
                0x1000,
                tag,
                PoolKind::NonPagedNx,
                PoolBackend::Lfh,
                PoolState::Allocated,
            ),
            span(
                0x1040,
                0,
                PoolKind::NonPagedNx,
                PoolBackend::Lfh,
                PoolState::ReusableFree,
            ),
            span(
                0x1080,
                0,
                PoolKind::NonPagedNx,
                PoolBackend::Lfh,
                PoolState::CachedFree,
            ),
            span(
                0x2000,
                tag,
                PoolKind::Paged,
                PoolBackend::Vs,
                PoolState::Allocated,
            ),
            span(
                0x2040,
                0,
                PoolKind::Paged,
                PoolBackend::Vs,
                PoolState::Unreadable,
            ),
        ];
        spans[0].subsegment = Some(1);
        spans[1].subsegment = Some(1);
        spans[2].subsegment = Some(1);
        spans[3].subsegment = Some(2);
        spans[4].subsegment = Some(2);
        let index = PoolIndex::build(PoolSnapshot {
            spans,
            complete: true,
            diagnostics: vec!["per-session paged heaps are not included".into()],
        });
        let plain = render_pool_map(
            &index,
            RenderOptions {
                tag: Some(tag),
                dml: false,
            },
        )
        .join("");
        assert!(plain.contains("S.c"));
        assert!(plain.contains("nonpaged-nx"));
        assert!(plain.contains("paged"));
        assert!(plain.contains("reusable hole at 0x1040+0x40"));
        assert!(plain.contains("LFH: account for bucket"));
        assert!(plain.contains("VS: consider splitting/coalescing"));
        assert!(plain.contains("PipeAttribute"));
        assert!(plain.contains("PipeQueueEntry"));
        assert!(plain.contains("19H1-era observations"));
        assert!(plain.contains("per-session paged heaps are not included"));
        assert!(plain.contains("allocation A<&\" at"));
        assert!(!plain.contains("A&lt;&amp;&quot;"));
        let dml = render_pool_map(
            &index,
            RenderOptions {
                tag: Some(tag),
                dml: true,
            },
        )
        .join("");
        assert!(dml.contains("<link cmd="));
        assert!(dml.contains("A&lt;&amp;&quot;"));
        assert!(escape_dml("<&\"").contains("&lt;&amp;&quot;"));

        let complete_cell = cell(&index.spans[0], true, true);
        let two_cells = complete_cell.repeat(2);
        assert_eq!(
            safe_dml_boundary(&two_cells, complete_cell.len() + complete_cell.len() / 2),
            complete_cell.len()
        );
        let mut atomic_chunks = Vec::new();
        let oversized_cells = complete_cell.repeat(200);
        push_atomic(&mut atomic_chunks, &oversized_cells, true);
        assert!(atomic_chunks.len() > 1);
        assert_eq!(atomic_chunks.concat(), oversized_cells);
        for chunk in &atomic_chunks {
            assert_eq!(
                chunk.matches("<link ").count(),
                chunk.matches("</link>").count()
            );
            assert_eq!(
                chunk.matches("<col ").count(),
                chunk.matches("</col>").count()
            );
            assert!(chunk.len() <= OUTPUT_CHUNK);
        }

        assert!(
            render_pool_map(
                &index,
                RenderOptions {
                    tag: Some(tag),
                    dml: true
                }
            )
            .iter()
            .all(|chunk| chunk.len() <= OUTPUT_CHUNK)
        );

        let mut many = Vec::new();
        for slot in 0..180u64 {
            let mut value = span(
                0x10_0000 + slot * 0x40,
                if slot == 0 { tag } else { 0 },
                PoolKind::NonPagedNx,
                PoolBackend::Lfh,
                if slot == 0 {
                    PoolState::Allocated
                } else {
                    PoolState::ReusableFree
                },
            );
            value.subsegment = Some(7);
            many.push(value);
        }
        let many_index = PoolIndex::build(PoolSnapshot {
            spans: many,
            complete: true,
            diagnostics: vec![],
        });
        let dml_chunks = render_pool_map(
            &many_index,
            RenderOptions {
                tag: Some(tag),
                dml: true,
            },
        );
        assert!(dml_chunks.len() > 1);
        for chunk in dml_chunks {
            assert_eq!(
                chunk.matches("<link ").count(),
                chunk.matches("</link>").count()
            );
            assert_eq!(
                chunk.matches("<col ").count(),
                chunk.matches("</col>").count()
            );
            assert!(chunk.len() <= OUTPUT_CHUNK);
        }
    }
}
