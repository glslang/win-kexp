use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use thiserror::Error;

use super::decode::PoolHeaderLayout;
use crate::dbgeng::{DbgEngError, DebugEngine, KernelImage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionKey {
    /// Where the kernel is loaded **and which build it is**, from
    /// [crate::dbgeng::DebugEngine::kernel_image].
    ///
    /// The base alone is not enough for the layout cache, which is keyed on this and not on
    /// `target`. A programmatic host that switches to a different Windows build whose kernel
    /// happens to load at the same address receives no notification, so a base-keyed lookup
    /// hands back the previous build's type offsets and globals and the walker decodes the new
    /// target with them — silently, and confidently. Keyed on the image, entries are shared
    /// across engines looking at the same build, which is what keeps the cache from growing one
    /// entry per engine, and never shared across two builds.
    pub image: KernelImage,
    pub session: u64,
    /// Which target this is, from [crate::dbgeng::DebugEngine::target_identity].
    /// The kernel image does not distinguish two dumps from the same boot, and the
    /// generation only moves on debugger notifications a programmatic host never gets.
    pub target: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypeLayout {
    pub size: u32,
    pub fields: HashMap<&'static str, u32>,
}

/// What a resolved [`PoolLayout`] actually depends on: the kernel image it was read out of.
///
/// Deliberately not a whole [`SessionKey`]. A layout describes the *image*, not which target
/// instance happens to be loaded, and keying it on the target inserted an entry per engine and
/// per `end_session` that nothing ever pruned (glslang/win-kexp#84). Deriving the key here
/// rather than asking each caller to blank a field is what keeps that from being one call
/// site's discipline — there is no key a caller can hand this cache that reintroduces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct LayoutKey {
    pub image: KernelImage,
    pub session: u64,
}

impl From<SessionKey> for LayoutKey {
    fn from(key: SessionKey) -> Self {
        Self {
            image: key.image,
            session: key.session,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PoolLayout {
    pub key: LayoutKey,
    pub globals: HashMap<&'static str, u64>,
    pub types: HashMap<&'static str, TypeLayout>,
}

#[derive(Debug, Error, PartialEq, Eq)]
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
        DebugEngine::type_id(self, module, name)
    }
    fn type_size(&self, module: u64, type_id: u32) -> Result<u32, DbgEngError> {
        DebugEngine::type_size(self, module, type_id)
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
        name: "_SEGMENT_HEAP",
        fields: &[
            ("SegContexts", &["SegContexts", "SegmentContexts"]),
            ("VsContext", &["VsContext"]),
            ("LfhContext", &["LfhContext"]),
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
    // Deliberately no *required* fields. The VS free-chunk state lives inside this
    // struct on older builds, and from Windows 26100 it moved into a separately
    // addressed _HEAP_VS_AFFINITY_SLOT. Both shapes are resolved optionally below;
    // requiring either one here would refuse to walk half the world.
    TypeSpec {
        name: "_HEAP_VS_CONTEXT",
        fields: &[],
    },
    TypeSpec {
        name: "_HEAP_VS_DELAY_FREE_CONTEXT",
        fields: &[("ListHead", &["ListHead"])],
    },
    TypeSpec {
        name: "_HEAP_VS_SUBSEGMENT",
        fields: &[("Size", &["Size"]), ("Signature", &["Signature"])],
    },
    TypeSpec {
        name: "_HEAP_VS_CHUNK_HEADER",
        fields: &[("Sizes", &["Sizes", "HeaderBits"])],
    },
    TypeSpec {
        name: "_HEAP_VS_CHUNK_FREE_HEADER",
        fields: &[("TreeNode", &["TreeNode", "Node"])],
    },
    TypeSpec {
        name: "_HEAP_LFH_CONTEXT",
        fields: &[("Buckets", &["Buckets"])],
    },
    TypeSpec {
        name: "_HEAP_LFH_SUBSEGMENT",
        fields: &[
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
        fields: &[("Root", &["Root", "EncodedRoot"])],
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
        name: "_SLIST_HEADER",
        fields: &[("Alignment", &["Alignment"]), ("Region", &["Region"])],
    },
];

const OPTIONAL_TYPES: &[TypeSpec] = &[
    // Windows 26100+: the VS free-chunk tree, subsegment list and delay-free list moved
    // out of _HEAP_VS_CONTEXT into one of these per-affinity slots. Absent on older
    // builds, where the same state is inline in the context.
    TypeSpec {
        name: "_HEAP_VS_AFFINITY_SLOT",
        fields: &[
            ("VsContext", &["VsContext"]),
            ("FreeChunkTree", &["FreeChunkTree"]),
            ("DelayFreeContext", &["DelayFreeContext"]),
        ],
    },
    // One entry per affinity; SlotRef locates the slot itself.
    TypeSpec {
        name: "_HEAP_VS_SLOT_MAP",
        fields: &[("SlotRef", &["SlotRef"])],
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
];

const OPTIONAL_FIELDS: &[(&str, &str, &[&str])] = &[
    ("_EX_HEAP_POOL_NODE", "Lookasides", &["Lookasides"]),
    ("_RTL_RB_TREE", "Encoded", &["Encoded"]),
    (
        "_SEGMENT_HEAP",
        "LargeAllocMetadata",
        &["LargeAllocMetadata"],
    ),
    (
        "_HEAP_LFH_CONTEXT",
        "AffinitySlots",
        &["AffinitySlots", "AffinitizedInfoArrays"],
    ),
    ("_RTL_LOOKASIDE", "Size", &["Size", "SizeClass"]),
    // Legacy (pre-26100) in-context VS state.
    ("_HEAP_VS_CONTEXT", "FreeChunkTree", &["FreeChunkTree"]),
    (
        "_HEAP_VS_CONTEXT",
        "DelayFreeContext",
        &["DelayFreeContext"],
    ),
    // 26100+: locate the affinity slots. Both are self-relative to the VS context and
    // scaled by 64 bytes; the slot map holds AffinityMask + 1 entries.
    ("_HEAP_VS_CONTEXT", "SlotMapRef", &["SlotMapRef"]),
    ("_HEAP_VS_CONTEXT", "AffinityMask", &["AffinityMask"]),
];

const GLOBALS: &[(&str, &[&str])] = &[
    ("ExPoolState", &["nt!ExPoolState"]),
    ("RtlpHpHeapGlobals", &["nt!RtlpHpHeapGlobals"]),
];

const OPTIONAL_GLOBALS: &[(&str, &[&str])] = &[
    ("PoolBigPageTable", &["nt!PoolBigPageTable"]),
    ("PoolBigPageTableSize", &["nt!PoolBigPageTableSize"]),
];

fn resolve_type(
    symbols: &impl Symbols,
    module: u64,
    spec: &TypeSpec,
) -> Result<TypeLayout, LayoutError> {
    let type_id = symbols
        .type_id(module, spec.name)
        .map_err(|_| LayoutError::Missing {
            item: spec.name.into(),
        })?;
    let size = symbols
        .type_size(module, type_id)
        .map_err(|_| LayoutError::Missing {
            item: spec.name.into(),
        })?;
    let mut fields = HashMap::new();
    for &(canonical, aliases) in spec.fields {
        let offset = aliases
            .iter()
            .find_map(|field| symbols.field(module, type_id, field).ok())
            .ok_or_else(|| LayoutError::Missing {
                item: format!("{}.{canonical}", spec.name),
            })?;
        fields.insert(canonical, offset);
    }
    Ok(TypeLayout { size, fields })
}

impl PoolLayout {
    pub(crate) fn type_layout(&self, name: &str) -> Result<&TypeLayout, LayoutError> {
        self.types
            .get(name)
            .ok_or_else(|| LayoutError::Missing { item: name.into() })
    }

    pub(crate) fn field(&self, type_name: &str, field: &str) -> Result<usize, LayoutError> {
        self.type_layout(type_name)?
            .fields
            .get(field)
            .copied()
            .map(|value| value as usize)
            .ok_or_else(|| LayoutError::Missing {
                item: format!("{type_name}.{field}"),
            })
    }

    pub(crate) fn pool_header_layout(&self) -> Result<PoolHeaderLayout, LayoutError> {
        Ok(PoolHeaderLayout {
            size: self.type_layout("_POOL_HEADER")?.size as usize,
            previous_size: self.field("_POOL_HEADER", "PreviousSize")?,
            pool_index: self.field("_POOL_HEADER", "PoolIndex")?,
            block_size: self.field("_POOL_HEADER", "BlockSize")?,
            pool_type: self.field("_POOL_HEADER", "PoolType")?,
            tag: self.field("_POOL_HEADER", "PoolTag")?,
        })
    }

    pub(crate) fn resolve(symbols: &impl Symbols, key: LayoutKey) -> Result<Self, LayoutError> {
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
        for &(canonical, aliases) in OPTIONAL_GLOBALS {
            if let Some(value) = aliases.iter().find_map(|name| symbols.symbol(name).ok()) {
                globals.insert(canonical, value);
            }
        }
        let mut types = HashMap::new();
        for spec in TYPES {
            types.insert(spec.name, resolve_type(symbols, key.image.base, spec)?);
        }
        for spec in OPTIONAL_TYPES {
            if let Ok(layout) = resolve_type(symbols, key.image.base, spec) {
                types.insert(spec.name, layout);
            }
        }
        for &(type_name, canonical, aliases) in OPTIONAL_FIELDS {
            let Some(layout) = types.get_mut(type_name) else {
                continue;
            };
            let Ok(type_id) = symbols.type_id(key.image.base, type_name) else {
                continue;
            };
            if let Some(offset) = aliases
                .iter()
                .find_map(|field| symbols.field(key.image.base, type_id, field).ok())
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
    entries: Mutex<HashMap<LayoutKey, PoolLayout>>,
}

impl LayoutCache {
    pub(crate) fn global() -> &'static Self {
        static CACHE: OnceLock<LayoutCache> = OnceLock::new();
        CACHE.get_or_init(Self::default)
    }

    pub(crate) fn get_or_resolve(
        &self,
        symbols: &impl Symbols,
        key: impl Into<LayoutKey>,
    ) -> Result<PoolLayout, LayoutError> {
        let key = key.into();
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[derive(Default)]
    struct FakeSymbols {
        /// How many times a layout has actually been resolved through these symbols, so a
        /// cache hit can be told from a re-resolution rather than inferred from equal results.
        resolutions: Cell<usize>,
        fallback_aliases: bool,
        optional_fields: bool,
        missing_global: Option<&'static str>,
        missing_type: Option<&'static str>,
        missing_field: Option<(&'static str, &'static str)>,
    }

    impl FakeSymbols {
        fn error<T>() -> Result<T, DbgEngError> {
            Err(DbgEngError::InvalidCommand)
        }

        fn field_value(name: &str) -> u32 {
            name.bytes().map(u32::from).sum()
        }

        fn type_spec(type_id: u32) -> Option<&'static TypeSpec> {
            type_id
                .checked_sub(1)
                .and_then(|index| TYPES.iter().chain(OPTIONAL_TYPES).nth(index as usize))
        }

        fn resolve_field(&self, spec: &TypeSpec, name: &str) -> Result<u32, DbgEngError> {
            if let Some(&(canonical, aliases)) = spec
                .fields
                .iter()
                .find(|(_, aliases)| aliases.contains(&name))
            {
                if self.missing_field == Some((spec.name, canonical))
                    || (self.fallback_aliases && aliases.len() > 1 && name == aliases[0])
                {
                    return Self::error();
                }
                return Ok(Self::field_value(name));
            }

            if self.optional_fields
                && let Some(&(_, canonical, aliases)) =
                    OPTIONAL_FIELDS.iter().find(|(type_name, _, aliases)| {
                        *type_name == spec.name && aliases.contains(&name)
                    })
            {
                if self.missing_field == Some((spec.name, canonical))
                    || (self.fallback_aliases && aliases.len() > 1 && name == aliases[0])
                {
                    return Self::error();
                }
                return Ok(Self::field_value(name));
            }

            Self::error()
        }
    }

    impl Symbols for FakeSymbols {
        fn symbol(&self, name: &str) -> Result<u64, DbgEngError> {
            self.resolutions.set(self.resolutions.get() + 1);
            if self.missing_global == Some(name) {
                return Self::error();
            }
            GLOBALS
                .iter()
                .chain(OPTIONAL_GLOBALS)
                .position(|(_, aliases)| aliases.contains(&name))
                .map(|index| 0xffff_8000_0000_0000 + (index as u64 + 1) * 0x1000)
                .ok_or(DbgEngError::InvalidCommand)
        }

        fn type_id(&self, _module: u64, name: &str) -> Result<u32, DbgEngError> {
            if self.missing_type == Some(name) {
                return Self::error();
            }
            TYPES
                .iter()
                .chain(OPTIONAL_TYPES)
                .position(|spec| spec.name == name)
                .map(|index| index as u32 + 1)
                .ok_or(DbgEngError::InvalidCommand)
        }

        fn type_size(&self, _module: u64, type_id: u32) -> Result<u32, DbgEngError> {
            Self::type_spec(type_id)
                .map(|_| 0x20 + type_id)
                .ok_or(DbgEngError::InvalidCommand)
        }

        fn field(&self, _module: u64, type_id: u32, name: &str) -> Result<u32, DbgEngError> {
            let Some(spec) = Self::type_spec(type_id) else {
                return Self::error();
            };
            self.resolve_field(spec, name)
        }
    }

    fn key() -> LayoutKey {
        LayoutKey {
            image: KernelImage {
                base: 0xffff_f800_0000_0000,
                size: 0x145_0000,
                timestamp: 0x65f5_7999,
                checksum: 0xc6f_ee6,
            },
            session: 7,
        }
    }

    /// glslang/win-kexp#84 and #87 are the two ways one key can be wrong, and the image
    /// answers both. Keyed on the target, the cache grew an entry per engine and per
    /// `end_session` that nothing ever pruned. Keyed on the base alone — which is what fixing
    /// that left — two Windows builds whose kernels load at the same address share a layout,
    /// and nothing tells a programmatic host the target changed, so the walker decodes one
    /// build with the other's type offsets and globals and says nothing about it.
    #[test]
    fn test_layouts_are_shared_by_image_and_never_across_builds() {
        let symbols = FakeSymbols::default();
        let cache = LayoutCache::default();
        let resolve = |key: LayoutKey| {
            let layout = cache.get_or_resolve(&symbols, key).unwrap();
            (symbols.resolutions.get(), layout.key.image)
        };
        let through_an_engine = |key: SessionKey| {
            let layout = cache.get_or_resolve(&symbols, key).unwrap();
            (symbols.resolutions.get(), layout.key.image)
        };

        let (first, image) = resolve(key());
        assert!(first > 0);
        assert_eq!(image, key().image);

        // The same image reached through a second engine, whose `SessionKey` carries a target
        // of its own. One entry, shared: keying on the target is the growth #84 was about, and
        // the narrowing that prevents it is the cache's, not the caller's.
        assert_eq!(
            through_an_engine(SessionKey {
                image: key().image,
                session: key().session,
                target: 99,
            }),
            (first, key().image)
        );

        // The same *address*, a different build.
        let other_build = KernelImage {
            timestamp: 0x1122_3344,
            ..key().image
        };
        let (again, resolved) = resolve(LayoutKey {
            image: other_build,
            ..key()
        });
        assert!(
            again > first,
            "a second build at one base must not be served the first build's layout"
        );
        assert_eq!(resolved, other_build);
    }

    fn missing_item(result: Result<PoolLayout, LayoutError>) -> String {
        match result.unwrap_err() {
            LayoutError::Missing { item } => item,
        }
    }

    #[test]
    fn test_resolve_required_layout_and_optional_absence() {
        let layout = PoolLayout::resolve(&FakeSymbols::default(), key()).unwrap();

        assert_eq!(layout.key, key());
        assert_eq!(layout.globals.len(), GLOBALS.len() + OPTIONAL_GLOBALS.len());
        assert_eq!(layout.types.len(), TYPES.len() + OPTIONAL_TYPES.len());
        assert_eq!(
            layout.field("_POOL_HEADER", "PoolTag"),
            Ok(FakeSymbols::field_value("PoolTag") as usize)
        );
        assert!(layout.field("_RTL_LOOKASIDE", "Size").is_err());
    }

    #[test]
    fn test_resolve_alias_fallback_and_optional_fields() {
        let symbols = FakeSymbols {
            fallback_aliases: true,
            optional_fields: true,
            ..FakeSymbols::default()
        };
        let layout = PoolLayout::resolve(&symbols, key()).unwrap();

        assert_eq!(
            layout.field("_EX_POOL_HEAP_MANAGER_STATE", "PoolNode"),
            Ok(FakeSymbols::field_value("PoolNodes") as usize)
        );
        assert_eq!(
            layout.field("_RTL_LOOKASIDE", "Size"),
            Ok(FakeSymbols::field_value("SizeClass") as usize)
        );
        assert_eq!(
            layout.field("_HEAP_LFH_CONTEXT", "AffinitySlots"),
            Ok(FakeSymbols::field_value("AffinitizedInfoArrays") as usize)
        );
        assert_eq!(
            layout.field("_RTL_RB_TREE", "Encoded"),
            Ok(FakeSymbols::field_value("Encoded") as usize)
        );
    }

    #[test]
    fn test_resolve_reports_missing_required_items() {
        assert_eq!(
            missing_item(PoolLayout::resolve(
                &FakeSymbols {
                    missing_global: Some("nt!ExPoolState"),
                    ..FakeSymbols::default()
                },
                key(),
            )),
            "ExPoolState"
        );
        assert_eq!(
            missing_item(PoolLayout::resolve(
                &FakeSymbols {
                    missing_type: Some("_POOL_HEADER"),
                    ..FakeSymbols::default()
                },
                key(),
            )),
            "_POOL_HEADER"
        );
        assert_eq!(
            missing_item(PoolLayout::resolve(
                &FakeSymbols {
                    missing_field: Some(("_POOL_HEADER", "PoolTag")),
                    ..FakeSymbols::default()
                },
                key(),
            )),
            "_POOL_HEADER.PoolTag"
        );
    }

    #[test]
    fn test_layout_accessors_report_typed_missing_items() {
        let mut layout = PoolLayout::resolve(&FakeSymbols::default(), key()).unwrap();

        assert_eq!(
            layout.type_layout("_MISSING").unwrap_err(),
            LayoutError::Missing {
                item: "_MISSING".into()
            }
        );
        assert_eq!(
            layout.field("_POOL_HEADER", "Missing").unwrap_err(),
            LayoutError::Missing {
                item: "_POOL_HEADER.Missing".into()
            }
        );

        layout.types.remove("_POOL_HEADER");
        assert_eq!(
            layout.pool_header_layout().unwrap_err(),
            LayoutError::Missing {
                item: "_POOL_HEADER".into()
            }
        );
    }

    #[test]
    fn test_resolve_does_not_require_unused_metadata() {
        for unused_type in [
            "_RTLP_HP_HEAP_MANAGER",
            "_RTLP_HP_ALLOC_TRACKER",
            "_RTL_CSPARSE_BITMAP",
        ] {
            PoolLayout::resolve(
                &FakeSymbols {
                    missing_type: Some(unused_type),
                    ..FakeSymbols::default()
                },
                key(),
            )
            .unwrap();
        }

        for (unused_type, unused_field) in [
            ("_EX_POOL_HEAP_MANAGER_STATE", "HeapManager"),
            ("_HEAP_SEG_CONTEXT", "PagesPerUnitShift"),
            ("_HEAP_VS_CONTEXT", "SubsegmentList"),
            ("_HEAP_VS_SUBSEGMENT", "ListEntry"),
            ("_HEAP_VS_CHUNK_HEADER", "EncodedSegmentPageOffset"),
            ("_HEAP_LFH_SUBSEGMENT", "ListEntry"),
            ("_RTL_RB_TREE", "Min"),
        ] {
            PoolLayout::resolve(
                &FakeSymbols {
                    missing_field: Some((unused_type, unused_field)),
                    ..FakeSymbols::default()
                },
                key(),
            )
            .unwrap();
        }

        for unused_global in ["nt!RtlpLfhBucketIndexMap", "nt!RtlpBucketBlockSizes"] {
            PoolLayout::resolve(
                &FakeSymbols {
                    missing_global: Some(unused_global),
                    ..FakeSymbols::default()
                },
                key(),
            )
            .unwrap();
        }
    }

    #[test]
    fn test_resolve_tolerates_missing_optional_large_metadata() {
        for missing_type in ["_HEAP_LARGE_ALLOC_DATA", "_POOL_TRACKER_BIG_PAGES"] {
            let layout = PoolLayout::resolve(
                &FakeSymbols {
                    optional_fields: true,
                    missing_type: Some(missing_type),
                    ..FakeSymbols::default()
                },
                key(),
            )
            .unwrap();

            assert!(layout.type_layout(missing_type).is_err());
            assert!(layout.type_layout("_POOL_HEADER").is_ok());
        }

        for missing_global in ["nt!PoolBigPageTable", "nt!PoolBigPageTableSize"] {
            let canonical = OPTIONAL_GLOBALS
                .iter()
                .find(|(_, aliases)| aliases.contains(&missing_global))
                .unwrap()
                .0;
            let layout = PoolLayout::resolve(
                &FakeSymbols {
                    missing_global: Some(missing_global),
                    ..FakeSymbols::default()
                },
                key(),
            )
            .unwrap();

            assert!(!layout.globals.contains_key(canonical));
        }

        let layout = PoolLayout::resolve(
            &FakeSymbols {
                optional_fields: true,
                missing_field: Some(("_SEGMENT_HEAP", "LargeAllocMetadata")),
                ..FakeSymbols::default()
            },
            key(),
        )
        .unwrap();
        assert!(layout.field("_SEGMENT_HEAP", "LargeAllocMetadata").is_err());

        let layout = PoolLayout::resolve(
            &FakeSymbols {
                missing_field: Some(("_HEAP_LARGE_ALLOC_DATA", "TreeNode")),
                ..FakeSymbols::default()
            },
            key(),
        )
        .unwrap();
        assert!(layout.type_layout("_HEAP_LARGE_ALLOC_DATA").is_err());
    }

    #[test]
    fn test_resolve_tolerates_missing_optional_cache_metadata() {
        for missing_type in ["_RTL_DYNAMIC_LOOKASIDE", "_RTL_LOOKASIDE"] {
            let layout = PoolLayout::resolve(
                &FakeSymbols {
                    missing_type: Some(missing_type),
                    ..FakeSymbols::default()
                },
                key(),
            )
            .unwrap();

            assert!(layout.type_layout(missing_type).is_err());
        }

        for missing_field in [
            ("_EX_HEAP_POOL_NODE", "Lookasides"),
            ("_HEAP_LFH_CONTEXT", "AffinitySlots"),
        ] {
            let layout = PoolLayout::resolve(
                &FakeSymbols {
                    optional_fields: true,
                    missing_field: Some(missing_field),
                    ..FakeSymbols::default()
                },
                key(),
            )
            .unwrap();

            assert!(layout.field(missing_field.0, missing_field.1).is_err());
        }
    }
}
