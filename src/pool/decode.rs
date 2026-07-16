use super::PoolState;

pub(crate) const PAGE_SIZE: u64 = 0x1000;
pub(crate) const VS_SIGNATURE: u16 = 0x2bed;
pub(crate) const PAGE_SEGMENT_SIGNATURE: u64 = 0xa2e6_4ead_a2e6_4ead;
pub(crate) const DESCRIPTOR_TREE_SIGNATURE: u32 = 0xccdd_ccdd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Descriptor {
    pub unit_size: u32,
    pub flags: u8,
    pub committed: bool,
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
        committed: flags & 1 != 0,
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

pub(crate) fn valid_page_segment_signature(
    signature: u64,
    segment: u64,
    context: u64,
    heap_globals: u64,
) -> bool {
    signature == segment ^ context ^ heap_globals ^ PAGE_SEGMENT_SIGNATURE
}

pub(crate) fn valid_descriptor_tree_signature(signature: u32) -> bool {
    signature == DESCRIPTOR_TREE_SIGNATURE
}

/// Windows VS headers encode both size words with the heap key and header address.
pub(crate) fn decode_vs_sizes(encoded: u64, header: u64, heap_key: u64) -> Option<VsSizes> {
    let decoded = encoded ^ heap_key ^ header;
    let size = (decoded >> 16) as u16;
    let previous_size = (decoded >> 32) as u16;
    (size != 0).then_some(VsSizes {
        size,
        previous_size,
        allocated: (decoded >> 48) as u8 != 0,
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

pub(crate) fn decode_rb_root(root: u64, tree_address: u64, encoded: bool) -> Option<u64> {
    let pointer = if encoded { root ^ tree_address } else { root } & !0xf;
    (pointer == 0 || is_kernel_pointer(pointer)).then_some(pointer)
}

/// Decode the two packed words in `_HEAP_LARGE_ALLOC_DATA`.
///
/// `VirtualAddress` shares its low 16 bits with `UnusedBytes`, while
/// `AllocatedPages` occupies bits 12..63 of its containing word.
pub(crate) fn decode_large_allocation(
    virtual_address_field: u64,
    allocated_pages_field: u64,
) -> Option<(u64, u64)> {
    let virtual_address = virtual_address_field & !0xffff;
    let allocated_pages = allocated_pages_field >> 12;
    (virtual_address != 0 && is_kernel_pointer(virtual_address) && allocated_pages != 0)
        .then_some((virtual_address, allocated_pages))
}

pub(crate) fn is_kernel_pointer(pointer: u64) -> bool {
    pointer == 0 || pointer >= 0xffff_8000_0000_0000
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
        assert_eq!(decode_descriptor(0x0100_0020).unwrap().unit_size, 0x20);
        assert_eq!(decode_descriptor(0), None);
        let mut descriptor = [0u8; 12];
        descriptor[7] = 0x20;
        descriptor[3] = 1;
        assert_eq!(
            decode_descriptor_at(&descriptor, 2, 10, 5, 1),
            Some(Descriptor {
                unit_size: 0x20,
                flags: 1,
                committed: true
            })
        );
        let mut wide_descriptor = [0u8; 16];
        wide_descriptor[5..8].copy_from_slice(&[0x56, 0x34, 0x12]);
        wide_descriptor[2] = 1;
        assert_eq!(
            decode_descriptor_at(&wide_descriptor, 0, 8, 5, 2)
                .unwrap()
                .unit_size,
            0x12_3456
        );
        assert_eq!(decode_descriptor_at(&wide_descriptor, 12, 8, 5, 2), None);
        let decoded = decode_vs_sizes((4u64 << 16) ^ 0x1234 ^ 0x55, 0x1234, 0x55).unwrap();
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
    }

    #[test]
    fn test_pool_tag_and_allocator_algorithms() {
        let tag = parse_tag("AB").unwrap();
        assert_eq!(tag.to_le_bytes(), *b"AB  ");
        assert_eq!(display_tag(u32::from_le_bytes(*b"A\0C ")), "A.C ");
        assert!(valid_vs_signature(VS_SIGNATURE));
        let segment = 0xffff_8000_1234_0000;
        let context = 0xffff_8000_1000_0000;
        let globals = 0xffff_8000_0100_0000;
        assert!(valid_page_segment_signature(
            segment ^ context ^ globals ^ PAGE_SEGMENT_SIGNATURE,
            segment,
            context,
            globals
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
        assert_eq!(
            decode_large_allocation(root | 0x1234, (0x2345u64 << 12) | 0xabc),
            Some((root, 0x2345))
        );
    }
}
