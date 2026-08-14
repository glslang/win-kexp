use std::fmt;

use super::{PoolBackend, PoolState};

pub(crate) const PAGE_SIZE: u64 = 0x1000;
pub(crate) const VS_SIGNATURE: u16 = 0x2bed;
pub(crate) const PAGE_SEGMENT_SIGNATURE: u64 = 0xa2e6_4ead_a2e6_4ead;
pub(crate) const DESCRIPTOR_TREE_SIGNATURE: u32 = 0xccdd_ccdd;

/// `_HEAP_PAGE_RANGE_DESCRIPTOR.RangeFlags`: the page range is in use.
///
/// Set on **every** unit descriptor of the range, not just its first, so on its own it says
/// nothing about what formats the range's contents — see [`descriptor_backend`].
pub(crate) const DESCRIPTOR_FLAG_ALLOCATED: u8 = 0x01;
/// This descriptor is the first of its page range, so its `UnitSize`, `Key` and
/// `TreeSignature` are the range's own. Interior units carry `UnitOffset` back to it instead.
pub(crate) const DESCRIPTOR_FLAG_FIRST: u8 = 0x02;
/// The subsegment is a VS one. Only meaningful together with [`DESCRIPTOR_FLAG_SUBSEGMENT`].
pub(crate) const DESCRIPTOR_FLAG_VS: u8 = 0x04;
/// The range holds a subsegment — an `_HEAP_LFH_SUBSEGMENT`, or an `_HEAP_VS_SUBSEGMENT`
/// when [`DESCRIPTOR_FLAG_VS`] is set too — rather than one plain page-range allocation.
pub(crate) const DESCRIPTOR_FLAG_SUBSEGMENT: u8 = 0x08;

/// Which allocator formats the contents of a page range, from its descriptor's `RangeFlags`.
///
/// These four bits are the kernel's own reading, taken from `nt` on Server 26100:
/// `nt!RtlpHpFreeHeap` walks back to the range's first descriptor and dispatches on the flags
/// byte, requiring `0x0b` for the LFH path, exactly `0x0f` for `RtlpHpVsContextFree`, and only
/// `flags & 3 == 3` for a plain page range. The two producers agree: `RtlpHpSegLfhAllocate`
/// asks `RtlpHpSegPageRangeAllocate` for `0x08` and `RtlpHpSegVsAllocate` for `0x0c`, and the
/// allocator masks the caller's request with `0x0c` before adding `0x01` to every unit of the
/// range.
///
/// Reading `0x01` as "LFH" instead — as this did until it was measured — makes *every*
/// allocated range look like an LFH subsegment: VS subsegments (`0x0f`), page-range and large
/// allocations (`0x03`) and Verifier special pool (`0x03`) all have it set. Their contents
/// then fail to decode as a subsegment header and the whole range is dropped, which is the
/// silent coverage loss behind glslang/win-kexp#90.
pub(crate) fn descriptor_backend(flags: u8) -> PoolBackend {
    if flags & DESCRIPTOR_FLAG_SUBSEGMENT == 0 {
        PoolBackend::Segment
    } else if flags & DESCRIPTOR_FLAG_VS != 0 {
        PoolBackend::Vs
    } else {
        PoolBackend::Lfh
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Descriptor {
    pub unit_size: u32,
    pub flags: u8,
    /// Whether this descriptor is the first of its page range, and so whether the fields
    /// decoded from it describe a range at all.
    pub first: bool,
}

impl Descriptor {
    /// Whether the range this descriptor belongs to is in use.
    pub(crate) fn allocated(&self) -> bool {
        self.flags & DESCRIPTOR_FLAG_ALLOCATED != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VsSizes {
    pub size: u16,
    pub previous_size: u16,
    pub allocated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PoolHeader {
    pub previous_size: u8,
    pub block_size: u8,
    pub pool_type: u8,
    pub pool_index: u8,
    pub tag: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PoolHeaderLayout {
    pub size: usize,
    pub previous_size: usize,
    pub pool_index: usize,
    pub block_size: usize,
    pub pool_type: usize,
    pub tag: usize,
}

fn range(bytes: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    bytes.get(offset..offset.checked_add(size)?)
}

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        range(bytes, offset, 2)?.try_into().ok()?,
    ))
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        range(bytes, offset, 4)?.try_into().ok()?,
    ))
}

pub(crate) fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        range(bytes, offset, 8)?.try_into().ok()?,
    ))
}

pub(crate) fn decode_descriptor(word: u32) -> Option<Descriptor> {
    let unit_size = word & 0x00ff_ffff;
    let flags = (word >> 24) as u8;
    (unit_size != 0).then_some(Descriptor {
        unit_size,
        flags,
        first: flags & DESCRIPTOR_FLAG_FIRST != 0,
    })
}

pub(crate) fn decode_descriptor_at(
    bytes: &[u8],
    offset: usize,
    descriptor_size: usize,
    unit_size_offset: usize,
    flags_offset: usize,
) -> Option<Descriptor> {
    let descriptor = range(bytes, offset, descriptor_size)?;
    let unit_width = descriptor_size.checked_sub(unit_size_offset)?.min(3);
    if unit_width == 0 {
        return None;
    }
    let unit_bytes = range(descriptor, unit_size_offset, unit_width)?;
    let unit_size = unit_bytes
        .iter()
        .enumerate()
        .fold(0u32, |value, (shift, byte)| {
            value | (u32::from(*byte) << (shift * 8))
        });
    let flags = *descriptor.get(flags_offset)? as u32;
    decode_descriptor(unit_size | (flags << 24))
}

/// Whether a `_HEAP_PAGE_SEGMENT.Signature` authenticates the segment.
///
/// Two mixes exist in the wild and both are accepted, because rejecting a segment is not a
/// soft failure — it discards every chunk inside it, and rejecting *all* segments makes the
/// walk quietly return an empty pool:
///
/// * older builds fold [`PAGE_SEGMENT_SIGNATURE`] into the mix;
/// * **Windows 26100** dropped it, leaving `segment ^ context ^ heap_key`.
///
/// Accepting either is safe: both are exact 64-bit comparisons against values derived from
/// the segment's own address and the per-boot heap key, so a false accept is not a practical
/// risk. Verified on Server 26100.32995, where two independent segments matched the
/// constant-free form exactly and the constant-bearing form not at all.
pub(crate) fn valid_page_segment_signature(
    signature: u64,
    segment: u64,
    context: u64,
    heap_key: u64,
) -> bool {
    let mixed = segment ^ context ^ heap_key;
    signature == mixed ^ PAGE_SEGMENT_SIGNATURE || signature == mixed
}

pub(crate) fn valid_descriptor_tree_signature(signature: u32) -> bool {
    signature == DESCRIPTOR_TREE_SIGNATURE
}

/// Windows VS headers encode both size words with the heap key and header address.
///
/// Unconditional: whether the values are believable is [`decode_vs_chunk`]'s question, and a
/// header refused there still has to be able to say what it decoded to.
pub(crate) fn decode_vs_sizes(encoded: u64, header: u64, heap_key: u64) -> VsSizes {
    let decoded = encoded ^ heap_key ^ header;
    VsSizes {
        size: (decoded >> 16) as u16,
        previous_size: (decoded >> 32) as u16,
        allocated: (decoded >> 48) as u8 != 0,
    }
}

/// One `_HEAP_VS_CHUNK_HEADER`, in bytes rather than in the sixteen-byte units it stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VsChunk {
    /// The chunk's whole extent, its own headers included.
    pub size: usize,
    /// What this header says the chunk *before* it measured.
    ///
    /// The kernel keeps the chain so a free can coalesce backwards, which makes it a
    /// corroboration of the walk's own forward stride that costs nothing: walking forward, the
    /// next chunk's `previous_size` must equal this chunk's `size`. It is also the check that
    /// separates the two explanations for a refused header — a chain that holds either side of
    /// one bad chunk is a header rewritten while we read it, a chain that never holds says the
    /// field or the starting offset is wrong and everything decoded after it is fiction.
    pub previous_size: usize,
    pub allocated: bool,
}

/// Why a VS chunk header was not believed, and the decoded values that say so.
///
/// Same division of labour as [`LfhRejection`]: the failing predicate is prose with no digits
/// in it, so `PoolDiagnostics` keeps the shapes apart while folding the numbers, and the values
/// travel as numbers so a sample of each shape carries real ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VsRejection {
    /// The predicate that failed, as prose with no digits in it.
    pub reason: &'static str,
    pub size: usize,
    pub previous_size: usize,
    /// The `Sizes` word as read, so a refused header can be re-decoded by hand against another
    /// candidate mix without another walk of the target.
    pub encoded: u64,
}

impl fmt::Display for VsRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (size {:#x}, previous size {:#x}, encoded {:#018x})",
            self.reason, self.size, self.previous_size, self.encoded
        )
    }
}

/// Decodes a VS chunk header, or says which plausibility check it failed.
///
/// `header_bytes` is the chunk header plus the pool header it carries — the smallest extent a
/// chunk can occupy and still be one. `subsegment_end` is one past the last byte of the
/// subsegment the chunk belongs to.
///
/// The end test is `>` and not `>=` deliberately: a subsegment's last chunk reaches its
/// boundary exactly, and refusing that would reject a well-formed chunk from every subsegment
/// that is fully occupied.
pub(crate) fn decode_vs_chunk(
    encoded: u64,
    header_address: u64,
    heap_key: u64,
    header_bytes: usize,
    subsegment_end: u64,
) -> Result<VsChunk, VsRejection> {
    let sizes = decode_vs_sizes(encoded, header_address, heap_key);
    let size = usize::from(sizes.size).saturating_mul(16);
    let previous_size = usize::from(sizes.previous_size).saturating_mul(16);
    let reject = |reason| {
        Err(VsRejection {
            reason,
            size,
            previous_size,
            encoded,
        })
    };
    // Its own reason rather than a case of "smaller than its headers": a zero size is what an
    // uninitialised or wrongly keyed word decodes to, and it is also the one value the walk
    // could not stride by even if it believed it.
    if size == 0 {
        return reject("the size word decodes to zero");
    }
    if size < header_bytes {
        return reject("the chunk is smaller than its own headers");
    }
    if header_address.saturating_add(size as u64) > subsegment_end {
        return reject("the chunk runs past the end of its subsegment");
    }
    Ok(VsChunk {
        size,
        previous_size,
        allocated: sizes.allocated,
    })
}

pub(crate) fn valid_vs_signature(signature: u16) -> bool {
    signature == VS_SIGNATURE
}

pub(crate) fn decode_lfh_offsets(encoded: u32, subsegment: u64, lfh_key: u32) -> (u16, u16) {
    // EncodedData is one 32-bit value. Decoding the halves independently loses
    // the upper half of LfhKey and produces a bogus FirstBlockOffset.
    let decoded = encoded ^ lfh_key ^ (subsegment >> 12) as u32;
    (decoded as u16, (decoded >> 16) as u16)
}

/// The smallest LFH block the kernel buckets. Anything under it is a misread, not a bucket.
const LFH_MIN_BLOCK_SIZE: u32 = 8;

/// How an `_HEAP_LFH_SUBSEGMENT` header divides its page range into blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LfhSubsegment {
    pub block_size: u32,
    /// Where the first block starts, past the header and block bitmap.
    pub first: usize,
    pub blocks: usize,
}

/// Why an LFH subsegment header was not believed, and the decoded values that say so.
///
/// The failing predicate is spelled out in words while the values stay numbers, because
/// `PoolDiagnostics` collapses messages by shape — numbers fold into `#`, words do not. A walk
/// therefore reports how many subsegments failed *each* check, and keeps a verbatim sample of
/// each with its numbers intact. That is what separates the two explanations for a rejection
/// that a bare count cannot: a header rewritten by the running target between our reads fails
/// the way a half-built subsegment does and in varying ways, while a field we are decoding
/// wrongly fails the same way every time, with values that never look like a bucket size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LfhRejection {
    /// The predicate that failed, as prose with no digits in it.
    pub reason: &'static str,
    pub block_size: u32,
    pub blocks: usize,
    pub first: usize,
    pub region_size: usize,
    /// `BlockOffsets.EncodedData` as read, so a rejected header can be re-decoded by hand
    /// against another candidate mix without another walk of the target.
    pub encoded: u32,
}

impl fmt::Display for LfhRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (block size {:#x}, {} blocks at offset {:#x} of a {:#x} byte range, encoded {:#010x})",
            self.reason, self.block_size, self.blocks, self.first, self.region_size, self.encoded
        )
    }
}

/// Decodes an LFH subsegment header, or says which plausibility check it failed.
///
/// `region_size` is the byte length the page-range descriptor gave for this range.
/// `nt!RtlpHpLfhSubsegmentInitialize` picks `BlockCount` by dividing exactly that range by the
/// bucket's block size after reserving `FirstBlockOffset` for the header and block bitmap, so
/// `first + blocks * block_size <= region_size` holds by construction. A header that does not
/// fit is one we misread or one that was mid-rewrite while we read it.
pub(crate) fn decode_lfh_subsegment(
    encoded: u32,
    subsegment: u64,
    lfh_key: u32,
    blocks: usize,
    region_size: usize,
) -> Result<LfhSubsegment, LfhRejection> {
    let (decoded_block_size, decoded_first) = decode_lfh_offsets(encoded, subsegment, lfh_key);
    let block_size = u32::from(decoded_block_size);
    let first = usize::from(decoded_first);
    let reject = |reason| {
        Err(LfhRejection {
            reason,
            block_size,
            blocks,
            first,
            region_size,
            encoded,
        })
    };

    // Both fields zero is a range committed but not yet made into a subsegment: the encoding
    // mixes in the subsegment's own address, so an initialised header practically cannot
    // encode to zero. Worth its own reason — it is the shape of a race, not of a misdecode.
    if encoded == 0 && blocks == 0 {
        return reject("header is not initialised");
    }
    if blocks == 0 {
        return reject("block count is zero");
    }
    if block_size < LFH_MIN_BLOCK_SIZE {
        return reject("block size is below the eight byte minimum");
    }
    if first >= region_size {
        return reject("first block offset is past the end of the range");
    }
    if blocks.saturating_mul(block_size as usize) > region_size - first {
        return reject("the blocks overrun the range");
    }
    Ok(LfhSubsegment {
        block_size,
        first,
        blocks,
    })
}

/// Each LFH slot uses two bits. Bit 0 is the busy state, while bit 1 records
/// unused-byte metadata and does not affect whether the block is allocated.
pub(crate) fn lfh_bitmap_state(bitmap: &[u8], slot: usize) -> Option<PoolState> {
    let bit = slot.checked_mul(2)?;
    let byte = *bitmap.get(bit / 8)?;
    Some(if (byte >> (bit % 8)) & 1 == 0 {
        PoolState::ReusableFree
    } else {
        PoolState::Allocated
    })
}

/// A header that would straddle the page boundary is stored at the end of the
/// preceding page.  Return the physical header location, checking all arithmetic.
pub(crate) fn adjust_page_end_header(candidate: u64, header_size: u64) -> Option<u64> {
    if header_size == 0 || header_size > PAGE_SIZE {
        return None;
    }
    let page_offset = candidate & (PAGE_SIZE - 1);
    let last_header_start = PAGE_SIZE - header_size;
    if page_offset > last_header_start {
        candidate.checked_sub(page_offset - last_header_start)
    } else {
        Some(candidate)
    }
}

pub(crate) fn decode_pool_header(
    bytes: &[u8],
    offset: usize,
    layout: PoolHeaderLayout,
) -> Option<PoolHeader> {
    // User Segment Heap blocks have no kernel `_POOL_HEADER`; their shared-decoder adapter is
    // deliberately zero-sized and must not reinterpret payload bytes as header fields or tags.
    if layout.size == 0 {
        return None;
    }
    range(bytes, offset, layout.size)?;
    // PDB field offsets for the two bitfield pairs can both name the containing
    // USHORT. In that representation the second member occupies its high byte.
    let pool_index_lane = usize::from(layout.pool_index == layout.previous_size);
    let pool_type_lane = usize::from(layout.pool_type == layout.block_size);
    let header = PoolHeader {
        previous_size: *bytes.get(offset.checked_add(layout.previous_size)?)?,
        pool_index: *bytes.get(
            offset
                .checked_add(layout.pool_index)?
                .checked_add(pool_index_lane)?,
        )?,
        block_size: *bytes.get(offset.checked_add(layout.block_size)?)?,
        pool_type: *bytes.get(
            offset
                .checked_add(layout.pool_type)?
                .checked_add(pool_type_lane)?,
        )?,
        tag: read_u32(bytes, offset.checked_add(layout.tag)?)?,
    };
    // Zero-sized blocks and impossible pool types are corrupt metadata.
    (header.block_size != 0 && header.pool_type <= 0x7f).then_some(header)
}

/// The low bits of a special-pool page's `Ulong1` that hold the requested byte count.
///
/// Thirteen, not the eight of `_POOL_HEADER.PreviousSize` — which is why a size below 0x100
/// used to read correctly and everything above it wrapped. 0x1fff spans any allocation a page
/// can hold several times over, so nothing a special-pool page can describe truncates.
const SPECIAL_POOL_SIZE_MASK: u32 = 0x1fff;
/// Set in the same word when Verifier is tracking the allocation, which puts eight more bytes
/// of its own between the pool header and where the fill starts.
const SPECIAL_POOL_TRACKED: u32 = 0x4000;

/// What a Driver Verifier special-pool page records about the one allocation it holds.
///
/// Special pool reuses `_POOL_HEADER`'s bytes for its own fields, so the ordinary
/// [`decode_pool_header`] reading of them is meaningless here: `BlockSize`'s byte holds the
/// fill pattern, and the size spans `PreviousSize` *and* the low bits of `PoolIndex`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpecialPoolHeader {
    pub tag: u32,
    /// The byte count the caller asked `ExAllocatePool` for. The block occupies
    /// `next_multiple_of(16)` of that.
    pub requested: u32,
    /// Where the fill starts: past the pool header, and past Verifier's tracking block when
    /// [`SPECIAL_POOL_TRACKED`] says there is one.
    pub header_size: usize,
    /// The byte the unused space either side of the block is filled with.
    ///
    /// Read from the page rather than assumed to be `0xfd`, because that is what the kernel
    /// itself compares against — see [`decode_special_pool_header`].
    pub fill: u8,
}

/// Decodes a special-pool page header the way `nt!ExpFreeHeapSpecialPool` does.
///
/// That function is the authority worth copying: it is handed the block pointer and
/// **bug checks** (`0xc1`, subcode `0x21`) unless the page's own fields place the block exactly
/// where the pointer says it is, so its reading *defines* a well-formed special-pool page.
/// Measured on Server 26100.32995 (`nt` 0x65f57999), where it does, in order:
///
/// ```text
///   movzx edx, word ptr [rbx]        ; the first half of Ulong1
///   and   edx, 1FFFh                 ; ... is the requested size, in thirteen bits
///   lea   r14, [rdx+0Fh]
///   and   r14, 0FFFFFFFFFFFFFFF0h    ; the block occupies that, rounded up to 16
///   cmp   r14, rbp                   ; rbp = 0x1000 - (block & 0xfff): or bug check 0xc1/0x21
///   ...
///   mov   ecx, dword ptr [rbx]
///   lea   r8, [rbx+10h]
///   and   r10d, 4000h                ; tracked by Verifier?
///   je    ...
///   lea   r8, [rbx+18h]              ; ... then its tracking block sits after the header
///   ...
///   mov   al, byte ptr [rbx+2]       ; the fill byte is recorded on the page, not assumed
///   cmp   byte ptr [r8], al          ; and checked from the header's end up to the block
/// ```
///
/// `Ulong1` overlays the bitfields from `PreviousSize` on, and the fill byte occupies
/// `BlockSize`'s, so both are located from the PDB layout rather than from the constant
/// offsets the kernel compiles in.
///
/// `None` means the page does not describe an allocation that could fit in it — an unreadable
/// or garbage page, not a special-pool one.
pub(crate) fn decode_special_pool_header(
    bytes: &[u8],
    offset: usize,
    layout: PoolHeaderLayout,
) -> Option<SpecialPoolHeader> {
    range(bytes, offset, layout.size)?;
    let word = read_u32(bytes, offset.checked_add(layout.previous_size)?)?;
    let requested = word & SPECIAL_POOL_SIZE_MASK;
    // The extra eight bytes are Verifier's, and on x64 `_POOL_HEADER` is 0x10, which is the
    // `[rbx+10h]`/`[rbx+18h]` pair above.
    let header_size = layout.size
        + if word & SPECIAL_POOL_TRACKED != 0 {
            8
        } else {
            0
        };
    let aligned = u64::from(requested).next_multiple_of(16);
    // The kernel's own placement identity, which is the check it bug checks on. A page whose
    // block could not share it with its own header is not a special-pool page we read correctly.
    if requested == 0 || aligned + header_size as u64 > PAGE_SIZE {
        return None;
    }
    Some(SpecialPoolHeader {
        tag: read_u32(bytes, offset.checked_add(layout.tag)?)?,
        requested,
        header_size,
        fill: *bytes.get(offset.checked_add(layout.block_size)?)?,
    })
}

pub(crate) fn decode_rb_root(root: u64, tree_address: u64, encoded: bool) -> Option<u64> {
    decode_rb_root_for(root, tree_address, encoded, false)
}

pub(crate) fn decode_rb_root_for(
    root: u64,
    tree_address: u64,
    encoded: bool,
    user: bool,
) -> Option<u64> {
    let pointer = if encoded { root ^ tree_address } else { root } & !0xf;
    (pointer == 0
        || if user {
            is_user_pointer(pointer)
        } else {
            is_kernel_pointer(pointer)
        })
    .then_some(pointer)
}

/// Decode the 60-bit `NextEntry` field packed above the low four reserved bits
/// in the x64 and ARM64 `_SLIST_HEADER.Region` word.
pub(crate) fn decode_slist_header_next(region: u64) -> u64 {
    (region as i64 >> 4) as u64
}

/// Decode the two packed words in `_HEAP_LARGE_ALLOC_DATA`.
///
/// `VirtualAddress` shares its low 16 bits with `UnusedBytes`, while
/// `AllocatedPages` occupies bits 12..63 of its containing word.
pub(crate) fn decode_large_allocation(
    virtual_address_field: u64,
    allocated_pages_field: u64,
) -> Option<(u64, u64)> {
    decode_large_allocation_for(virtual_address_field, allocated_pages_field, false)
}

pub(crate) fn decode_large_allocation_for(
    virtual_address_field: u64,
    allocated_pages_field: u64,
    user: bool,
) -> Option<(u64, u64)> {
    let virtual_address = virtual_address_field & !0xffff;
    let allocated_pages = allocated_pages_field >> 12;
    (virtual_address != 0
        && if user {
            is_user_pointer(virtual_address)
        } else {
            is_kernel_pointer(virtual_address)
        }
        && allocated_pages != 0)
        .then_some((virtual_address, allocated_pages))
}

/// Recover the exact request encoded in the low sixteen bits of the large-allocation address
/// word. Callers must pass `validated_alias` only when the selected PDB reports `UnusedBytes`
/// at the same offset as `VirtualAddress`.
pub(crate) fn decode_large_requested_size(
    virtual_address_field: u64,
    allocated_bytes: u64,
    validated_alias: bool,
) -> Option<u64> {
    if !validated_alias {
        return None;
    }
    let unused = virtual_address_field & 0xffff;
    allocated_bytes.checked_sub(unused)
}

pub(crate) fn is_kernel_pointer(pointer: u64) -> bool {
    pointer == 0 || pointer >= 0xffff_8000_0000_0000
}

pub(crate) fn is_user_pointer(pointer: u64) -> bool {
    (0x1_0000..0x0000_8000_0000_0000).contains(&pointer)
}

pub(crate) fn big_page_hash(address: u64, table_size: usize) -> Option<usize> {
    if !table_size.is_power_of_two() {
        None
    } else {
        // The allocator truncates the page number to ULONG before multiplying.
        let mut hash = u64::from((address >> 12) as u32).wrapping_mul(0x9e5f);
        hash ^= hash >> 32;
        Some(hash as usize & (table_size - 1))
    }
}

pub(crate) struct BigPageProbe {
    next: usize,
    remaining: usize,
    mask: usize,
}

impl Iterator for BigPageProbe {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let current = self.next;
        self.next = (self.next + 1) & self.mask;
        self.remaining -= 1;
        Some(current)
    }
}

pub(crate) fn big_page_probe(address: u64, table_size: usize) -> Option<BigPageProbe> {
    Some(BigPageProbe {
        next: big_page_hash(address, table_size)?,
        remaining: table_size,
        mask: table_size - 1,
    })
}

pub(crate) fn display_tag(tag: u32) -> String {
    tag.to_le_bytes()
        .into_iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || byte == b' ' {
                byte as char
            } else {
                '.'
            }
        })
        .collect()
}

pub(crate) fn parse_tag(text: &str) -> Option<u32> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 4 || !bytes.iter().all(u8::is_ascii) {
        return None;
    }
    let mut raw = [b' '; 4];
    raw[..bytes.len()].copy_from_slice(bytes);
    Some(u32::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_decoder_bounds_and_shifted_offsets() {
        assert_eq!(read_u32(&[0, 1, 2, 3, 4], 1), Some(0x0403_0201));
        assert_eq!(read_u64(&[0; 7], 0), None);
        let first = decode_descriptor(0x0200_0020).unwrap();
        assert_eq!(first.unit_size, 0x20);
        assert!(first.first);
        assert!(!first.allocated());
        let interior = decode_descriptor(0x0100_0020).unwrap();
        assert!(
            !interior.first,
            "0x01 marks a unit in use, not a range start"
        );
        assert!(interior.allocated());
        assert_eq!(decode_descriptor(0), None);
        let mut descriptor = [0u8; 12];
        descriptor[7] = 0x20;
        descriptor[3] = DESCRIPTOR_FLAG_FIRST;
        assert_eq!(
            decode_descriptor_at(&descriptor, 2, 10, 5, 1),
            Some(Descriptor {
                unit_size: 0x20,
                flags: DESCRIPTOR_FLAG_FIRST,
                first: true
            })
        );
        let mut wide_descriptor = [0u8; 16];
        wide_descriptor[5..8].copy_from_slice(&[0x56, 0x34, 0x12]);
        wide_descriptor[2] = DESCRIPTOR_FLAG_FIRST;
        assert_eq!(
            decode_descriptor_at(&wide_descriptor, 0, 8, 5, 2)
                .unwrap()
                .unit_size,
            0x12_3456
        );
        assert_eq!(decode_descriptor_at(&wide_descriptor, 12, 8, 5, 2), None);
        let decoded = decode_vs_sizes((4u64 << 16) ^ 0x1234 ^ 0x55, 0x1234, 0x55);
        assert_eq!(decoded.size, 4);
        assert!(!decoded.allocated);
        let lfh_key = 0xa5c3_0010;
        let subsegment = 0x7000;
        let decoded_offsets = u32::from(0x30u16) | (u32::from(0x248u16) << 16);
        let encoded_offsets = decoded_offsets ^ lfh_key ^ (subsegment >> 12) as u32;
        assert_eq!(
            decode_lfh_offsets(encoded_offsets, subsegment, lfh_key),
            (0x30, 0x248)
        );
        let lfh_bitmap = [0b1110_0100];
        assert_eq!(
            lfh_bitmap_state(&lfh_bitmap, 0),
            Some(PoolState::ReusableFree)
        );
        assert_eq!(lfh_bitmap_state(&lfh_bitmap, 1), Some(PoolState::Allocated));
        assert_eq!(
            lfh_bitmap_state(&lfh_bitmap, 2),
            Some(PoolState::ReusableFree)
        );
        assert_eq!(lfh_bitmap_state(&lfh_bitmap, 3), Some(PoolState::Allocated));
        assert_eq!(lfh_bitmap_state(&[], 0), None);

        let mut shifted = [0u8; 24];
        shifted[7..11].copy_from_slice(&[2, 3, 4, 1]);
        shifted[15..19].copy_from_slice(b"TAG!");
        let layout = PoolHeaderLayout {
            size: 16,
            previous_size: 0,
            pool_index: 1,
            block_size: 2,
            pool_type: 3,
            tag: 8,
        };
        let header = decode_pool_header(&shifted, 7, layout).unwrap();
        assert_eq!(header.previous_size, 2);
        assert_eq!(header.pool_index, 3);
        assert_eq!(header.block_size, 4);
        assert_eq!(header.tag, u32::from_le_bytes(*b"TAG!"));

        let packed_layout = PoolHeaderLayout {
            size: 8,
            previous_size: 0,
            pool_index: 0,
            block_size: 2,
            pool_type: 2,
            tag: 4,
        };
        assert_eq!(
            decode_pool_header(&[2, 3, 4, 1, b'P', b'A', b'C', b'K'], 0, packed_layout)
                .unwrap()
                .pool_index,
            3
        );

        let no_pool_header = PoolHeaderLayout {
            size: 0,
            previous_size: 0,
            pool_index: 0,
            block_size: 0,
            pool_type: 0,
            tag: 0,
        };
        assert_eq!(decode_pool_header(b"DATA", 0, no_pool_header), None);
    }

    /// The flag combinations the kernel itself dispatches on, as read out of `nt` on Server
    /// 26100: `0x0b` reaches the LFH free path, exactly `0x0f` reaches `RtlpHpVsContextFree`,
    /// and `flags & 3 == 3` on its own is a plain page-range allocation. Reading the low bit
    /// as "LFH" made the last two cases parse as LFH subsegments and vanish.
    #[test]
    fn test_range_flags_name_the_allocator_that_owns_the_range() {
        const ALLOCATED: u8 = DESCRIPTOR_FLAG_ALLOCATED | DESCRIPTOR_FLAG_FIRST;
        assert_eq!(
            descriptor_backend(ALLOCATED | DESCRIPTOR_FLAG_SUBSEGMENT),
            PoolBackend::Lfh
        );
        assert_eq!(
            descriptor_backend(ALLOCATED | DESCRIPTOR_FLAG_SUBSEGMENT | DESCRIPTOR_FLAG_VS),
            PoolBackend::Vs
        );
        assert_eq!(descriptor_backend(ALLOCATED), PoolBackend::Segment);
        // Verifier special pool: an ordinary allocated page range, told apart by its heap.
        assert_eq!(descriptor_backend(0x03), PoolBackend::Segment);
        // An interior unit of an allocated range, and a free range: neither is a subsegment.
        assert_eq!(
            descriptor_backend(DESCRIPTOR_FLAG_ALLOCATED),
            PoolBackend::Segment
        );
        assert_eq!(
            descriptor_backend(DESCRIPTOR_FLAG_FIRST),
            PoolBackend::Segment
        );
    }

    /// Every rejection has to name the check it failed and carry the values that failed it.
    /// A walk against a live 26100 kernel rejected 5.5k subsegments as one undifferentiated
    /// "implausible", which cannot distinguish a header rewritten under us from a field we
    /// decode wrongly — the whole point of glslang/win-kexp#90.
    #[test]
    fn test_lfh_rejections_name_their_predicate_and_carry_their_values() {
        let subsegment = 0xffff_8c8f_0d60_2000;
        let lfh_key = 0xa5c3_1357u32;
        let encode = |block_size: u16, first: u16| {
            (u32::from(block_size) | (u32::from(first) << 16)) ^ lfh_key ^ (subsegment >> 12) as u32
        };
        let decode = |encoded, blocks, region_size| {
            decode_lfh_subsegment(encoded, subsegment, lfh_key, blocks, region_size)
        };

        assert_eq!(
            decode(encode(0x70, 0x40), 0x24, 0x1000),
            Ok(LfhSubsegment {
                block_size: 0x70,
                first: 0x40,
                blocks: 0x24
            })
        );
        // The kernel divides the range exactly, so a header that fills it is not suspicious.
        assert!(decode(encode(0x40, 0x40), 0x3f, 0x1000).is_ok());

        let reasons = |cases: &[(u32, usize, usize)]| {
            cases
                .iter()
                .map(|&(encoded, blocks, region_size)| {
                    decode(encoded, blocks, region_size).unwrap_err().reason
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            reasons(&[
                (0, 0, 0x1000),
                (encode(0x70, 0x40), 0, 0x1000),
                (encode(4, 0x40), 0x24, 0x1000),
                (encode(0x70, 0x2000), 0x24, 0x1000),
                (encode(0x70, 0x40), 0x100, 0x1000),
            ]),
            [
                "header is not initialised",
                "block count is zero",
                "block size is below the eight byte minimum",
                "first block offset is past the end of the range",
                "the blocks overrun the range",
            ]
        );

        let rejection = decode(encode(0x70, 0x40), 0x100, 0x1000).unwrap_err();
        let message = rejection.to_string();
        assert!(
            message.contains("0x70") && message.contains("256") && message.contains("0x40"),
            "a rejection has to show what it decoded: {message}"
        );
        assert!(
            message.contains(&format!("{:#010x}", rejection.encoded)),
            "and the raw word, so it can be re-decoded without another walk: {message}"
        );
    }

    /// Windows 26100 dropped the constant from the page-segment signature mix. Both forms
    /// must authenticate, or the walk rejects every segment on one build family or the
    /// other and reports an empty pool instead of an error.
    #[test]
    fn test_page_segment_signature_accepts_both_build_families() {
        let segment = 0xffff_8c8f_0d60_0000;
        let context = 0xffff_8c8f_0d10_0140;
        let heap_key = 0x44c4_da45_347b_5d48;
        let mixed = segment ^ context ^ heap_key;

        // Pre-26100: the constant is folded in.
        assert!(valid_page_segment_signature(
            mixed ^ PAGE_SEGMENT_SIGNATURE,
            segment,
            context,
            heap_key
        ));
        // 26100: it is not. These are the real values read off Server 26100.32995.
        assert_eq!(mixed, 0x44c4_da45_340b_5c08);
        assert!(valid_page_segment_signature(
            mixed, segment, context, heap_key
        ));
        // Anything else is still rejected.
        assert!(!valid_page_segment_signature(
            mixed ^ 1,
            segment,
            context,
            heap_key
        ));
    }

    #[test]
    fn test_pool_tag_and_allocator_algorithms() {
        let tag = parse_tag("AB").unwrap();
        assert_eq!(tag.to_le_bytes(), *b"AB  ");
        assert_eq!(display_tag(u32::from_le_bytes(*b"A\0C ")), "A.C ");
        assert!(valid_vs_signature(VS_SIGNATURE));
        let segment = 0xffff_8000_1234_0000;
        let context = 0xffff_8000_1000_0000;
        let heap_key = 0x55aa_1234_9876_0000;
        let signature = segment ^ context ^ heap_key ^ PAGE_SEGMENT_SIGNATURE;
        assert!(valid_page_segment_signature(
            signature, segment, context, heap_key
        ));
        assert!(!valid_page_segment_signature(
            signature,
            segment,
            context,
            0xffff_8000_0100_0000
        ));
        assert!(valid_descriptor_tree_signature(DESCRIPTOR_TREE_SIGNATURE));
        let first = big_page_hash(0x9000, 8).unwrap();
        assert_eq!(
            big_page_probe(0x9000, 8).unwrap().collect::<Vec<_>>(),
            (0..8)
                .map(|offset| (first + offset) % 8)
                .collect::<Vec<_>>()
        );
        assert_eq!(big_page_hash(0, 0), None);
        assert_eq!(big_page_hash(0x9000, 3), None);
        assert!(big_page_probe(0x9000, 3).is_none());
        let high_address = 0xffff_8000_1234_5000;
        let mut expected = u64::from((high_address >> 12) as u32) * 0x9e5f;
        expected ^= expected >> 32;
        assert_eq!(
            big_page_hash(high_address, 0x100),
            Some(expected as usize & 0xff)
        );
        assert_eq!(adjust_page_end_header(0x1ff0, 0x10), Some(0x1ff0));
        assert_eq!(adjust_page_end_header(0x1ff8, 0x10), Some(0x1ff0));
        assert_eq!(adjust_page_end_header(0x2000, 0x10), Some(0x2000));
        let tree = 0xffff_8000_0001_0000;
        let root = 0xffff_8000_0002_0000;
        assert_eq!(decode_rb_root(root, tree, false), Some(root));
        assert_eq!(decode_rb_root(root ^ tree, tree, true), Some(root));
        assert_eq!(decode_rb_root(tree, tree, true), Some(0));
        let slist_entry = 0xffff_8000_0012_3fe0;
        assert_eq!(
            decode_slist_header_next((slist_entry << 4) | 3),
            slist_entry
        );
        assert_eq!(
            decode_large_allocation(root | 0x1234, (0x2345u64 << 12) | 0xabc),
            Some((root, 0x2345))
        );
        assert_eq!(
            decode_large_requested_size(root | 0x1234, 0x20_000, true),
            Some(0x1_edcc)
        );
        assert_eq!(
            decode_large_requested_size(root | 0x1234, 0x20_000, false),
            None,
            "without a PDB-validated alias capacity must not be presented as an exact request"
        );
        assert_eq!(
            decode_large_requested_size(root | 0xffff, 0x1000, true),
            None
        );
    }
}
