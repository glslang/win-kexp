use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Pipes::CreatePipe;

use crate::win32k::close_handle;

pub(crate) mod decode;
pub(crate) mod index;
pub(crate) mod layout;
pub(crate) mod render;
pub(crate) mod snapshot;

pub mod query;

/// The two forms a pool tag takes, and the question of which one identifies it.
///
/// A caller that renders [`PoolSpan::display_tag`] and hands the result back to
/// [`query::find_tag`] has a round trip that silently breaks on any tag `display_tag` cannot
/// render — so a consumer showing tags to a human should show [`raw_tag_hex`] wherever
/// [`display_is_ambiguous`] holds, and `parse_tag` takes either form back.
pub use decode::{
    display_is_ambiguous, display_round_trips, parse_raw_tag, parse_tag, raw_tag_hex, tag_label,
};
pub(crate) use index::PoolIndex;
pub(crate) use snapshot::PoolSnapshot;
pub use snapshot::{DIAGNOSTIC_EXAMPLES, DiagnosticShape, PoolDiagnostics, WalkStalls};

/// Exact allocator identity.  Values are deliberately not collapsed into just
/// paged/nonpaged because crossing one of these boundaries creates false holes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PoolKind {
    NonPagedExecutable,
    NonPagedNx,
    Paged,
    PrototypePaged,
    SpecialNonPaged,
    SpecialNonPagedNx,
    SpecialPaged,
    SpecialPrototypePaged,
}

impl PoolKind {
    pub fn is_paged(self) -> bool {
        matches!(
            self,
            Self::Paged | Self::PrototypePaged | Self::SpecialPaged | Self::SpecialPrototypePaged
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PoolBackend {
    Lfh,
    Vs,
    Segment,
    Large,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoolState {
    Allocated,
    ReusableFree,
    CachedFree,
    Unreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HeapIdentity {
    pub pool_state: u64,
    pub heap: u64,
    pub special: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSpan {
    pub header_address: u64,
    pub usable_address: u64,
    pub size: u64,
    /// Exact requested size when allocator metadata validates it. Kernel pool and user LFH/VS
    /// spans leave this unset rather than guessing from capacity.
    pub requested_size: Option<u64>,
    pub raw_tag: u32,
    pub display_tag: String,
    pub pool_kind: PoolKind,
    pub numa_node: u16,
    pub heap: HeapIdentity,
    pub subsegment: Option<u64>,
    pub backend: PoolBackend,
    pub state: PoolState,
    pub size_class: u32,
}

impl PoolSpan {
    pub fn end(&self) -> u64 {
        self.usable_address.saturating_add(self.size)
    }

    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.header_address && address < self.end()
    }

    /// A span with **synthetic geometry**: `header_address == usable_address`, which no walker
    /// ever emits — `walk_lfh`, `walk_vs` and `walk_page_ranges` all put the usable bytes a
    /// pool header past the header.
    ///
    /// Fine for tests about tags, filters and identity. Not fine for a test about *geometry*,
    /// and this has now hidden two bugs in `chunk_at`'s contiguity check by being the only
    /// thing that satisfied it (glslang/win-kexp#85, then the gate that replaced it). Build a
    /// backend-shaped span by hand for those, as `query`'s `lfh_allocation` and `vs_allocation`
    /// do.
    #[cfg(test)]
    pub(crate) fn allocation(
        address: u64,
        size: u64,
        tag: u32,
        pool_kind: PoolKind,
        heap: HeapIdentity,
        backend: PoolBackend,
    ) -> Self {
        Self {
            header_address: address,
            usable_address: address,
            size,
            requested_size: None,
            raw_tag: tag,
            display_tag: decode::display_tag(tag),
            pool_kind,
            numa_node: 0,
            heap,
            subsegment: None,
            backend,
            state: PoolState::Allocated,
            size_class: size.min(u32::MAX as u64) as u32,
        }
    }
}

pub struct AnonymousPipe {
    read_handle: HANDLE,
    write_handle: HANDLE,
    buf_size: u32,
}

impl AnonymousPipe {
    pub fn new(buffer_size: u32) -> Self {
        let mut read_handle = HANDLE::default();
        let mut write_handle = HANDLE::default();
        let buf_size = buffer_size;

        // Create the anonymous pipe with specified buffer size
        unsafe {
            CreatePipe(&mut read_handle, &mut write_handle, None, buffer_size)
                .expect("[-] Failed to create anonymous pipe");
        }

        Self {
            read_handle,
            write_handle,
            buf_size,
        }
    }

    pub fn get_read_handle(&self) -> HANDLE {
        self.read_handle
    }

    pub fn get_write_handle(&self) -> HANDLE {
        self.write_handle
    }

    pub fn write(&self, data: &[u8]) -> u32 {
        let mut bytes_written: u32 = 0;

        unsafe {
            WriteFile(
                self.write_handle,
                Some(data),
                Some(&mut bytes_written),
                None,
            )
            .expect("[-] Failed to write to anonymous pipe");
        }

        bytes_written
    }

    pub fn read(&self, buffer: &mut [u8]) -> u32 {
        let mut bytes_read: u32 = 0;

        unsafe {
            ReadFile(self.read_handle, Some(buffer), Some(&mut bytes_read), None)
                .expect("[-] Failed to read from anonymous pipe");
        }
        bytes_read
    }

    pub fn drain(&self) {
        let mut buffer = vec![0; self.buf_size as usize];
        self.read(&mut buffer);
    }
}

impl Drop for AnonymousPipe {
    fn drop(&mut self) {
        if self.read_handle != INVALID_HANDLE_VALUE {
            close_handle(self.read_handle);
        }
        if self.write_handle != INVALID_HANDLE_VALUE {
            close_handle(self.write_handle);
        }
    }
}
