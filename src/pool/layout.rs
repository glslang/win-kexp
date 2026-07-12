use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use thiserror::Error;

use super::decode::PoolHeaderLayout;
use crate::dbgeng::{DbgEngError, DebugEngine};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionKey {
    pub kernel_base: u64,
    pub session: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypeLayout {
    pub size: u32,
    pub fields: HashMap<&'static str, u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PoolLayout {
    pub key: SessionKey,
    pub globals: HashMap<&'static str, u64>,
    pub types: HashMap<&'static str, TypeLayout>,
}

#[derive(Debug, Error)]
pub(crate) enum LayoutError {
    #[error("missing kernel pool symbols ({item}); run `.reload /f nt` and retry")]
    Missing { item: String },
}

pub(crate) trait Symbols {
    fn symbol(&self, name: &str) -> Result<u64, DbgEngError>;
    fn type_id(&self, module: u64, name: &str) -> Result<u32, DbgEngError>;
    fn type_size(&self, module: u64, type_id: u32) -> Result<u32, DbgEngError>;
    fn field(&self, module: u64, type_id: u32, name: &str) -> Result<u32, DbgEngError>;
}

impl Symbols for DebugEngine {
    fn symbol(&self, name: &str) -> Result<u64, DbgEngError> {
        self.symbol_offset(name)
    }
    fn type_id(&self, module: u64, name: &str) -> Result<u32, DbgEngError> {
        self.type_id(module, name)
    }
    fn type_size(&self, module: u64, type_id: u32) -> Result<u32, DbgEngError> {
        self.type_size(module, type_id)
    }
    fn field(&self, module: u64, type_id: u32, name: &str) -> Result<u32, DbgEngError> {
        self.field_offset(module, type_id, name)
    }
}

struct TypeSpec {
    name: &'static str,
    fields: &'static [(&'static str, &'static [&'static str])],
}

const TYPES: &[TypeSpec] = &[
    TypeSpec {
        name: "_EX_POOL_HEAP_MANAGER_STATE",
        fields: &[
            ("HeapManager", &["HeapManager"]),
            ("PoolNode", &["PoolNode", "PoolNodes"]),
            ("NumberOfPools", &["NumberOfPools"]),
            ("SpecialHeaps", &["SpecialHeaps"]),
        ],
    },
    TypeSpec {
        name: "_EX_HEAP_POOL_NODE",
        fields: &[("Heaps", &["Heaps"])],
    },
    TypeSpec {
        name: "_RTLP_HP_HEAP_MANAGER",
        fields: &[("AllocTracker", &["AllocTracker"])],
    },
    TypeSpec {
        name: "_RTLP_HP_ALLOC_TRACKER",
        fields: &[("Tracker", &["Tracker", "AllocationTracker"])],
    },
    TypeSpec {
        name: "_RTL_CSPARSE_BITMAP",
        fields: &[
            ("CommitDirectory", &["CommitDirectory"]),
            ("UserData", &["UserData"]),
        ],
    },
    TypeSpec {
        name: "_SEGMENT_HEAP",
        fields: &[
            ("SegContexts", &["SegContexts", "SegmentContexts"]),
            ("VsContext", &["VsContext"]),
            ("LfhContext", &["LfhContext"]),
            ("LargeAllocMetadata", &["LargeAllocMetadata"]),
            ("UserContext", &["UserContext"]),
        ],
    },
    TypeSpec {
        name: "_HEAP_SEG_CONTEXT",
        fields: &[
            ("SegmentListHead", &["SegmentListHead"]),
            ("FreePageRanges", &["FreePageRanges", "FreePageRangeTree"]),
            ("UnitShift", &["UnitShift"]),
            ("FirstDescriptorIndex", &["FirstDescriptorIndex"]),
            ("SegmentMask", &["SegmentMask"]),
            ("PagesPerUnitShift", &["PagesPerUnitShift"]),
        ],
    },
    TypeSpec {
        name: "_HEAP_PAGE_SEGMENT",
        fields: &[
            ("ListEntry", &["ListEntry"]),
            ("DescArray", &["DescArray", "Descriptors"]),
            ("Signature", &["Signature"]),
        ],
    },
    TypeSpec {
        name: "_HEAP_PAGE_RANGE_DESCRIPTOR",
        fields: &[
            ("UnitSize", &["UnitSize"]),
            ("RangeFlags", &["RangeFlags", "Flags"]),
            ("TreeNode", &["TreeNode"]),
            ("TreeSignature", &["TreeSignature"]),
        ],
    },
    TypeSpec {
        name: "_HEAP_VS_CONTEXT",
        fields: &[
            ("SubsegmentList", &["SubsegmentList"]),
            ("FreeChunkTree", &["FreeChunkTree"]),
            ("DelayFreeContext", &["DelayFreeContext"]),
        ],
    },
    TypeSpec {
        name: "_HEAP_VS_DELAY_FREE_CONTEXT",
        fields: &[("ListHead", &["ListHead"])],
    },
    TypeSpec {
        name: "_HEAP_VS_SUBSEGMENT",
        fields: &[
            ("ListEntry", &["ListEntry"]),
            ("Size", &["Size"]),
            ("Signature", &["Signature"]),
        ],
    },
    TypeSpec {
        name: "_HEAP_VS_CHUNK_HEADER",
        fields: &[
            ("Sizes", &["Sizes", "HeaderBits"]),
            ("EncodedSegmentPageOffset", &["EncodedSegmentPageOffset"]),
        ],
    },
    TypeSpec {
        name: "_HEAP_VS_CHUNK_FREE_HEADER",
        fields: &[("TreeNode", &["TreeNode", "Node"])],
    },
    TypeSpec {
        name: "_HEAP_LFH_CONTEXT",
        fields: &[
            ("Buckets", &["Buckets"]),
            ("AffinitySlots", &["AffinitySlots", "AffinitizedInfoArrays"]),
        ],
    },
    TypeSpec {
        name: "_HEAP_LFH_SUBSEGMENT",
        fields: &[
            ("ListEntry", &["ListEntry", "AffinityListEntry"]),
            ("BlockOffsets", &["BlockOffsets"]),
            ("BlockBitmap", &["BlockBitmap"]),
            ("BlockCount", &["BlockCount"]),
        ],
    },
    TypeSpec {
        name: "_HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS",
        fields: &[("EncodedData", &["EncodedData"])],
    },
    TypeSpec {
        name: "_RTLP_HP_HEAP_GLOBALS",
        fields: &[("HeapKey", &["HeapKey"]), ("LfhKey", &["LfhKey"])],
    },
    TypeSpec {
        name: "_RTL_RB_TREE",
        fields: &[("Root", &["Root", "EncodedRoot"]), ("Min", &["Min"])],
    },
    TypeSpec {
        name: "_RTL_BALANCED_NODE",
        fields: &[("Left", &["Left"]), ("Right", &["Right"])],
    },
    TypeSpec {
        name: "_POOL_HEADER",
        fields: &[
            ("PreviousSize", &["PreviousSize"]),
            ("PoolIndex", &["PoolIndex"]),
            ("BlockSize", &["BlockSize"]),
            ("PoolType", &["PoolType"]),
            ("PoolTag", &["PoolTag"]),
        ],
    },
    TypeSpec {
        name: "_POOL_TRACKER_BIG_PAGES",
        fields: &[
            ("Va", &["Va"]),
            ("Key", &["Key", "PoolTag"]),
            ("NumberOfBytes", &["NumberOfBytes", "Size"]),
        ],
    },
    TypeSpec {
        name: "_HEAP_LARGE_ALLOC_DATA",
        fields: &[
            ("TreeNode", &["TreeNode"]),
            ("VirtualAddress", &["VirtualAddress", "Address"]),
            ("AllocatedPages", &["AllocatedPages", "NumberOfPages"]),
        ],
    },
    TypeSpec {
        name: "_RTL_DYNAMIC_LOOKASIDE",
        fields: &[("BucketCount", &["BucketCount"]), ("Buckets", &["Buckets"])],
    },
    TypeSpec {
        name: "_RTL_LOOKASIDE",
        fields: &[("ListHead", &["ListHead"])],
    },
    TypeSpec {
        name: "_SLIST_HEADER",
        fields: &[("Alignment", &["Alignment"]), ("Region", &["Region"])],
    },
];

const OPTIONAL_FIELDS: &[(&str, &str, &[&str])] = &[
    ("_RTL_LOOKASIDE", "Size", &["Size", "SizeClass"]),
    ("_RTL_DYNAMIC_LOOKASIDE", "ListHead", &["ListHead"]),
    ("_RTL_DYNAMIC_LOOKASIDE", "Size", &["Size", "SizeClass"]),
];

const GLOBALS: &[(&str, &[&str])] = &[
    ("ExPoolState", &["nt!ExPoolState"]),
    ("RtlpHpHeapGlobals", &["nt!RtlpHpHeapGlobals"]),
    ("PoolBigPageTable", &["nt!PoolBigPageTable"]),
    ("PoolBigPageTableSize", &["nt!PoolBigPageTableSize"]),
    ("RtlpLfhBucketIndexMap", &["nt!RtlpLfhBucketIndexMap"]),
    ("RtlpBucketBlockSizes", &["nt!RtlpBucketBlockSizes"]),
];

impl PoolLayout {
    pub(crate) fn type_layout(&self, name: &str) -> Result<&TypeLayout, String> {
        self.types
            .get(name)
            .ok_or_else(|| format!("resolved layout is missing type {name}"))
    }

    pub(crate) fn field(&self, type_name: &str, field: &str) -> Result<usize, String> {
        self.type_layout(type_name)?
            .fields
            .get(field)
            .copied()
            .map(|value| value as usize)
            .ok_or_else(|| format!("resolved layout is missing {type_name}.{field}"))
    }

    pub(crate) fn pool_header_layout(&self) -> Result<PoolHeaderLayout, String> {
        Ok(PoolHeaderLayout {
            size: self.type_layout("_POOL_HEADER")?.size as usize,
            previous_size: self.field("_POOL_HEADER", "PreviousSize")?,
            pool_index: self.field("_POOL_HEADER", "PoolIndex")?,
            block_size: self.field("_POOL_HEADER", "BlockSize")?,
            pool_type: self.field("_POOL_HEADER", "PoolType")?,
            tag: self.field("_POOL_HEADER", "PoolTag")?,
        })
    }

    pub(crate) fn resolve(symbols: &impl Symbols, key: SessionKey) -> Result<Self, LayoutError> {
        let mut globals = HashMap::new();
        for &(canonical, aliases) in GLOBALS {
            let value = aliases
                .iter()
                .find_map(|name| symbols.symbol(name).ok())
                .ok_or_else(|| LayoutError::Missing {
                    item: canonical.into(),
                })?;
            globals.insert(canonical, value);
        }
        let mut types = HashMap::new();
        for spec in TYPES {
            let type_id =
                symbols
                    .type_id(key.kernel_base, spec.name)
                    .map_err(|_| LayoutError::Missing {
                        item: spec.name.into(),
                    })?;
            let size =
                symbols
                    .type_size(key.kernel_base, type_id)
                    .map_err(|_| LayoutError::Missing {
                        item: spec.name.into(),
                    })?;
            let mut fields = HashMap::new();
            for &(canonical, aliases) in spec.fields {
                let offset = aliases
                    .iter()
                    .find_map(|field| symbols.field(key.kernel_base, type_id, field).ok())
                    .ok_or_else(|| LayoutError::Missing {
                        item: format!("{}.{canonical}", spec.name),
                    })?;
                fields.insert(canonical, offset);
            }
            types.insert(spec.name, TypeLayout { size, fields });
        }
        for &(type_name, canonical, aliases) in OPTIONAL_FIELDS {
            let Some(layout) = types.get_mut(type_name) else {
                continue;
            };
            let Ok(type_id) = symbols.type_id(key.kernel_base, type_name) else {
                continue;
            };
            if let Some(offset) = aliases
                .iter()
                .find_map(|field| symbols.field(key.kernel_base, type_id, field).ok())
            {
                layout.fields.insert(canonical, offset);
            }
        }
        Ok(Self {
            key,
            globals,
            types,
        })
    }
}

#[derive(Default)]
pub(crate) struct LayoutCache {
    entries: Mutex<HashMap<SessionKey, PoolLayout>>,
}

impl LayoutCache {
    pub(crate) fn global() -> &'static Self {
        static CACHE: OnceLock<LayoutCache> = OnceLock::new();
        CACHE.get_or_init(Self::default)
    }

    pub(crate) fn get_or_resolve(
        &self,
        symbols: &impl Symbols,
        key: SessionKey,
    ) -> Result<PoolLayout, LayoutError> {
        if let Some(layout) = self.entries.lock().unwrap().get(&key).cloned() {
            return Ok(layout);
        }
        let layout = PoolLayout::resolve(symbols, key)?;
        self.entries.lock().unwrap().insert(key, layout.clone());
        Ok(layout)
    }

    pub(crate) fn invalidate(&self) {
        self.entries.lock().unwrap().clear();
    }
}
