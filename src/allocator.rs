//! Version-aware provenance shared by the kernel-pool and user Segment Heap walkers.

use crate::dbgeng::ModuleIdentity;

/// Which structurally validated VS representation a schema contains.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum VsSemanticFamily {
    /// The VS context owns its free tree and delay-free state directly.
    #[default]
    Inline,
    /// VS state is reached through the context's affinity-slot map.
    AffinitySlots,
}

impl VsSemanticFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline_vs",
            Self::AffinitySlots => "affinity_slot_vs",
        }
    }
}

/// The image, PDB, and validated structural family used to decode an allocator.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct LayoutProvenance {
    pub module: ModuleIdentity,
    /// A deterministic digest of every resolved type size, field offset, and optional-field
    /// presence used by the decoder. It deliberately contains no build-number policy.
    pub fingerprint: String,
    pub semantic_family: VsSemanticFamily,
}

/// Stable FNV-1a fingerprint over an already canonicalized stream of schema facts.
///
/// This is an identity token, not a cryptographic authenticator. Callers sort facts before
/// feeding them so map iteration order never changes the value.
pub(crate) fn fingerprint<'a>(facts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for fact in facts {
        for byte in fact.as_bytes().iter().copied().chain([0xff]) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("fnv1a64:{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_fingerprint_is_stable_and_boundary_aware() {
        assert_eq!(fingerprint(["a", "b"]), fingerprint(["a", "b"]));
        assert_ne!(fingerprint(["ab"]), fingerprint(["a", "b"]));
        assert_ne!(fingerprint(["a", "b"]), fingerprint(["b", "a"]));
    }
}
