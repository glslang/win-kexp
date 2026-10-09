//! A loaded image's PE structures, read through a memory reader.
//!
//! What this is for is naming the imports of a **driver with no symbols**. A call site in a driver
//! reads `call qword ptr [driver+0x9018]`, and turning that into `ExAllocatePool2` is what
//! separates a hazard scan that works on a stripped third-party binary from one that only works
//! where a PDB happens to exist.
//!
//! # Never dereference the IAT
//!
//! The obvious implementation reads the pointer in the import address table and asks the engine
//! what symbol it resolves to. **That does not work on a dump**, and the measurement is worth
//! keeping: against `docs/samples/081226-2187-01.dmp`, `db mountmgr+0x9000` is rows of `????????`
//! on a session where every other RVA probed across the same image reads and the code
//! disassembles perfectly. The IAT is writable, its runtime contents were never captured, and no
//! image file can stand in for them — whatever supplies the code, that page is gone.
//!
//! Which is the durable half of it. Whether a driver's *code* reads on a dump varies with what the
//! engine can obtain, and is not predicted by the dump's type: the same minidump reads mountmgr's
//! whole image with no executable image path set at all. So the rule below is not a workaround for
//! a cold session — it is the only way a slot is ever named, on a live target as much as on a dump.
//!
//! So a slot is named **structurally**. `OriginalFirstThunk` — the import *lookup* table — lives
//! in a read-only section and holds one entry per import, in the same order as the IAT, so the
//! slot at `FirstThunk + i * ptr` is the name at index `i` of the lookup table. No pointer is
//! read, no symbol is resolved, and the answer is the same on a live target, a dump, and a
//! stripped driver.
//!
//! # Engine-free
//!
//! Every entry point here takes a reader closure rather than a [`crate::dbgeng::DebugEngine`],
//! for the reason [`crate::object`] takes a [`crate::object::Memory`]: the parsing is then testable
//! against a fake address space, and exactly one closure at the edge touches DbgEng. A read that
//! fails is [`PeError::Unreadable`] naming what could not be read, never a zero silently parsed as
//! a structure.
//!
//! # Why not a third-party parser
//!
//! `goblin`, `object` and `pelite` all parse a **contiguous byte slice**, and a loaded image in a
//! dump has holes in it. Materialising one first means either failing the whole parse over a hole
//! or zero-filling it, and zeros parsed as structures is the failure this module is written to
//! avoid — see the IAT measurement above, where one page of an otherwise readable image is gone
//! for good.
//!
//! So the shape is a **reader**, and the properties that follow from it are not incidental:
//! [`PeError::Unreadable`] and [`PeError::Malformed`] stay separate because their remedies are (an
//! image the engine could not obtain, against an image that does not hold together); a halt closure
//! is polled inside the import walk so a caller's deadline reaches it; every bound **refuses rather
//! than truncates**, because a hazard scan reading a short list concludes a dangerous import is
//! absent when it is merely past the cut; and [`Image::checked_va`] is one door that bounds an RVA
//! whether it is read or merely *reported*, since a slot this never dereferences is still an
//! address a caller will attribute to this image.
//!
//! # What is trusted, and what is not
//!
//! Every field below is the *image's* claim about itself, and an image is data this crate did not
//! write -- on an untrusted driver, data that driver's own code can reach. So each one is either
//! constrained before it is used or deliberately not, and this is the list rather than a habit,
//! because eleven review rounds on this module were eleven fields found one at a time.
//!
//! **Constrained:** `e_magic` and the PE signature are exact; `e_lfanew` is inside the header
//! page; `Machine` must agree with `Magic` where the machine's width is known; `NumberOfSections`
//! is bounded and its table must fit `SizeOfImage`; `SizeOfOptionalHeader` must cover the fields
//! read out of it; `SectionAlignment` must be a power of two; `NumberOfRvaAndSizes` is bounded by
//! the optional header's own length; the import directory's declared span must fit the image; a
//! descriptor's `Name` and `FirstThunk` must be non-zero and in the image; a thunk is an ordinal
//! with no other bit set, or a name RVA whose hint fits; and a name is text or an error.
//!
//! **Not constrained, on purpose:**
//!
//! - **`SizeOfImage` itself**, which is the bound every other offset is checked against and is
//!   therefore the one figure with nothing above it to check. A driver declaring four gigabytes
//!   makes its own bounds permissive; that is why `windbg-mcp` narrows it to the loader's extent,
//!   which is the smaller and more trustworthy of the two. A caller that cares should do the same.
//! - **The export directory**, which is carried as `(rva, size)` and parsed by nothing here. It is
//!   not bounded because bounding a span this never reads would refuse images over a field with no
//!   consequence -- a caller that starts parsing it owns that check, the way [`read_imports`] owns
//!   the import directory's.
//!
//! # Where it came from
//!
//! Written in `windbg-mcp` ([#296](https://github.com/glslang/windbg-mcp/pull/296)) and lifted here
//! once its four driver tools — `ioctl_map`, `device_security`, `driver_hazards`, `driver_surface`
//! — had exercised the shape, which is what [dbgscope#150] made the condition rather than lifting
//! a shape whose only consumer was its own tests. Exports are declared and unparsed; relocations,
//! resources and unwind data are not here at all.
//!
//! [dbgscope#150]: https://github.com/glslang/dbgscope/issues/150

use std::collections::BTreeMap;

use thiserror::Error;

/// What went wrong, in terms a caller can render as an outcome rather than a message.
///
/// **A [`std::error::Error`], not only a [`Display`](std::fmt::Display).** This was a hand-written
/// `Display` while the module lived behind one binary's module tree, where nothing ever asked it to
/// be a source. It is public API of a library now, so a caller propagating it into `anyhow` or
/// naming it as a `source()` is an ordinary thing to want -- and the other public errors here
/// ([`crate::object::ObjectError`], [`crate::dbgeng::DbgEngError`]) are `thiserror` enums, which
/// `AGENTS.md` asks for. The messages are the ones the hand-written impl produced.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PeError {
    /// A read the parse needed did not come back. On a dump this is the ordinary answer for
    /// anything outside the read-only sections an image file can supply.
    #[error("{len} bytes at {at:#x} could not be read")]
    Unreadable { at: u64, len: usize },
    /// The bytes are readable and are not a PE image.
    #[error("not a PE image: {reason}")]
    NotAnImage { reason: &'static str },
    /// A PE image whose structures do not hold together — a directory pointing outside the
    /// image, a count past its bound.
    #[error("malformed PE image: {reason}")]
    Malformed { reason: &'static str },
    /// The caller's halt closure asked for a stop.
    #[error("interrupted")]
    Interrupted,
}

/// Whether the image is PE32 or PE32+, which is the pointer width its thunks are in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bitness {
    Bits32,
    Bits64,
}

impl Bitness {
    /// The width of one thunk entry.
    pub fn pointer(self) -> usize {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }
}

/// One section of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The eight-byte name, trimmed — `.text`, `.rdata`, `PAGE`.
    pub name: String,
    pub rva: u32,
    /// The size the section occupies once loaded.
    pub virtual_size: u32,
    pub characteristics: u32,
}

impl Section {
    /// `IMAGE_SCN_MEM_EXECUTE`.
    pub fn executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    /// `IMAGE_SCN_MEM_DISCARDABLE` -- pages the loader **frees** once the driver has started.
    ///
    /// A read into one on a live target does not fail because the bytes are paged out; it fails
    /// because they are gone, and only the image file still has them. The distinction decides
    /// what a caller is told to do, and a driver whose import directory is linked into `INIT`
    /// (HEVD's is) cannot be scanned from memory at all.
    pub fn discardable(&self) -> bool {
        self.characteristics & 0x0200_0000 != 0
    }
}

/// The image's headers, as much as naming imports and bounding a code scan needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub base: u64,
    pub bitness: Bitness,
    /// `IMAGE_FILE_MACHINE_*`.
    pub machine: u16,
    pub size_of_image: u32,
    /// `SectionAlignment` -- the unit the loader maps and protects a section in.
    ///
    /// Carried because a section's `VirtualSize` is its exact byte count and the loader does not
    /// map exact byte counts: see [`Self::executable_ranges`], which is the one thing that reads
    /// it. Zero, or anything that is not a power of two, is not an alignment a loader used and is
    /// treated as absent rather than trusted.
    pub section_alignment: u32,
    pub sections: Vec<Section>,
    /// `(rva, size)` of the export directory; both zero when the image has none, which is the
    /// ordinary case for a driver.
    pub export_directory: (u32, u32),
    /// `(rva, size)` of the import directory.
    pub import_directory: (u32, u32),
    /// `(rva, size)` of the import address table (`IMAGE_DIRECTORY_ENTRY_IAT`); both zero when the
    /// image declares none. See [`read_import_address_table`] for why it is read at all.
    pub iat_directory: (u32, u32),
}

impl Image {
    /// The section holding an RVA, where one does.
    ///
    /// For saying **why** a read failed rather than only that it did: a section's own
    /// characteristics are the difference between bytes that are paged out and bytes the loader
    /// discarded.
    pub fn section_at(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|section| {
            let end = section.rva.saturating_add(section.virtual_size.max(1));
            (section.rva..end).contains(&rva)
        })
    }

    /// The executable sections, which is what a linear code scan is bounded by.
    pub fn code_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|section| section.executable())
    }

    /// The virtual ranges this image's **executable** sections occupy.
    ///
    /// What an address recovered as code is checked against. The loader's extent is not that
    /// question: `.rdata`, `.data` and the headers are all inside it, so a jump-table entry that
    /// lands there is data being reported as a case.
    ///
    /// **A section running past `SizeOfImage` is clipped to it, not dropped**, and the difference
    /// is the one this module's rules are about. Dropping it was a silent truncation of exactly
    /// the shape the import walk refuses: a caller gets a list that looks complete, an entire
    /// executable section is missing from it, and an address inside that section answers "not
    /// code" -- so a scan reports nothing dangerous in a region it never looked at. Clipping loses
    /// nothing real, because what is past `SizeOfImage` is not this image's code whatever the
    /// header says; it is whatever is mapped next, and a range reaching into that is the other
    /// failure this guards.
    ///
    /// A section starting outside the image contributes no range, and that is not a truncation
    /// either: none of it is inside the image to report.
    ///
    /// This matters more than the header alone suggests, because a caller may narrow
    /// `size_of_image` *after* parsing -- `windbg-mcp` clamps it to the loader's extent, which is
    /// the smaller and more trustworthy of the two on an untrusted driver -- so a section that was
    /// in bounds at parse time can be out of them here.
    pub fn executable_ranges(&self) -> Vec<std::ops::Range<u64>> {
        self.code_sections()
            .filter_map(|section| {
                // **The loader's unit, not the header's byte count.** `VirtualSize` is exact and
                // sections are mapped and protected in `SectionAlignment` units, so a `.text` of
                // 0x1234 bytes occupies 0x2000 of executable address space. Stopping at 0x1234
                // puts the tail outside every range -- and the one thing that reads these is a
                // containment test for jump-table targets, which would then call an address in
                // mapped, executable memory "not code" and drop the case.
                //
                // Only the alignment, not `SizeOfRawData`. That is a *file* size, trimmed or
                // padded by `FileAlignment`, and it is not what the loader gives a section in
                // memory: where it exceeds the rounded virtual size the excess is not separately
                // mapped, and treating it as extent would run this section into the next one's.
                //
                // The power-of-two guard is not the fallback it looks like: `read_image` refuses
                // an image whose alignment is not one, so this is reachable only for an `Image` a
                // caller built by hand out of these public fields. It is here so that does not
                // panic, not as an answer for a corrupt header.
                let extent = self
                    .section_alignment
                    .is_power_of_two()
                    .then(|| {
                        section
                            .virtual_size
                            .checked_next_multiple_of(self.section_alignment)
                    })
                    .flatten()
                    .unwrap_or(section.virtual_size);
                // Clipped the way `read_imports` clips a read: the start must be inside, and the
                // length is whatever room is left.
                let room = self.size_of_image.saturating_sub(section.rva);
                let len = extent.min(room);
                let start = self.checked_va(section.rva, len as usize).ok()?;
                Some(start..start + u64::from(len))
            })
            .filter(|range| range.start < range.end)
            .collect()
    }

    /// An RVA as a virtual address in this image, **checked against the image's own bounds**.
    ///
    /// The one door. An RVA past `SizeOfImage` added to the base lands in whatever is mapped next
    /// — on a live target, the next module — and every use of that address is then about some
    /// other image with nothing to say so. Whether the address is *read* or merely *reported* does
    /// not change that: an import slot this crate never dereferences is still an address a caller
    /// will attribute to this image, so it comes through here too. `len` is what will be reached
    /// from it, and zero asks only whether the start is inside.
    pub fn checked_va(&self, rva: u32, len: usize) -> Result<u64, PeError> {
        let end = u64::from(rva)
            .checked_add(len as u64)
            .ok_or(PeError::Malformed {
                reason: "an image offset and length overflowed",
            })?;
        if rva >= self.size_of_image || end > u64::from(self.size_of_image) {
            return Err(PeError::Malformed {
                reason: "an image offset points outside the image",
            });
        }
        // **The whole span is checked, and the start is what comes back.** Checking only
        // `base + rva` left the length out of it, so a base near the top of the address space
        // returned `Ok` for a range whose *end* wraps -- and the callers that add the length back
        // on are the ones that would notice: `executable_ranges` builds `start..start + size`,
        // which panics in debug and wraps in release into a range that starts above where it ends.
        // Validating the end here and returning the start means no caller has to know that.
        va(self.base, u64::from(rva), len)
    }
}

/// What an import is called. An ordinal import has no name in the image at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportName {
    Named(String),
    Ordinal(u16),
}

impl std::fmt::Display for ImportName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Named(name) => f.write_str(name),
            Self::Ordinal(ordinal) => write!(f, "#{ordinal}"),
        }
    }
}

/// What an image's import table yielded, and what it could not.
///
/// The second field exists because an empty answer and an unanswerable one must not look alike.
/// A descriptor whose `OriginalFirstThunk` is zero — a **bound** import — has real slots and no
/// lookup table, so its names live only in the import address table, which this deliberately does
/// not read. Reporting nothing for it would tell a hazard scan that the driver imports fewer
/// functions than it does, and "imports no dangerous API" is exactly the answer that must never
/// be produced by silence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportTable {
    pub imports: Vec<Import>,
    /// Libraries whose imports could not be named, and why they could not: bound imports, whose
    /// names are only in the table this cannot read.
    pub unnamed_libraries: Vec<String>,
}

/// One imported function, and the address of the slot a call goes through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The library as the image spells it — `ntoskrnl.exe`.
    pub library: String,
    pub name: ImportName,
    /// The virtual address of this import's IAT slot. **Not read**: it is
    /// `base + FirstThunk + index * pointer`, which is why this answers on an image whose
    /// writable pages were never captured.
    pub slot: u64,
}

/// Bounds. Every one of these is a refusal rather than a truncation: a structure that exceeds one
/// is [`PeError::Malformed`], because a plausible image does not, and a walk that quietly stopped
/// would report a driver as importing less than it does.
const MAX_SECTIONS: usize = 96;
const MAX_LIBRARIES: usize = 64;
const MAX_IMPORTS_PER_LIBRARY: usize = 8192;
/// And the **total**, which the two above do not bound: multiplied out they permit half a million
/// imports, each an owned name and an owned library string, which is hundreds of megabytes held
/// before any consumer sees a single one. A plausible driver imports a few hundred; the largest
/// system components a few thousand. This is far past both and bounds the absurd.
const MAX_IMPORTS_TOTAL: usize = 16 * 1024;
const MAX_NAME: usize = 512;

/// The boundary a name read never spans: **512 bytes, not a page**, because not every hole is
/// page-granular.
///
/// A minidump's are, and a page was the granule until an **image-file** target -- a `.sys` opened
/// as a dump -- turned up one that is not. The engine maps each of its sections only as far as the
/// section's `SizeOfRawData`, so the readable bytes stop where the section's file data does, which
/// is a multiple of `FileAlignment` and can be mid-page. Measured on HEVD's ARM64 build, whose
/// import directory and names are in `INIT` (VA `0x8D000`, raw size `0x800`): `0x8D7FF` reads and
/// `0x8D800` does not, the library name `ntoskrnl.exe` sits at `0x8D68C`, and a 512-byte read of it
/// -- inside one page -- crossed `0x8D800` and failed, so a driver whose every import byte was there
/// answered "could not be read".
///
/// 512 is `FileAlignment`'s smallest legal value for an image whose sections are page-aligned, so
/// every such raw-data end falls on a granule boundary and no chunk crosses one. A page is a
/// multiple of 512, so the page-granular holes this was first written for stay covered. The cost
/// is a second read for a name that straddles a 512-byte boundary rather than a 4 KiB one.
const NAME_READ_GRANULE: usize = 0x200;

/// A span the **image itself declares**, checked against the image whole rather than clipped to
/// it.
///
/// **The distinction the readers here do not make, and could not.** `at` clips a read to the image
/// because that is right for the reads this module chooses the length of: a name is variable and
/// [`MAX_NAME`] is our bound, not the image's, so a name near the end is legitimately shorter than
/// the ask. It is exactly wrong for a length the *image* states. A declared span that does not fit
/// is an image contradicting itself, and clipping it answers the question anyway out of the part
/// that fits -- an import directory at `SizeOfImage - 20` declaring forty bytes is read as one
/// descriptor, and if those twenty bytes are zero the answer is a confident "this driver imports
/// nothing". Half the directory was outside the image and nothing said so.
///
/// So every span the image declares comes through here, and every span this module chose the
/// length of goes through the clipping reader. Two rules, told apart by whose number the length is.
fn declared_fits(
    rva: u32,
    len: u32,
    size_of_image: u32,
    reason: &'static str,
) -> Result<(), PeError> {
    match u64::from(rva).saturating_add(u64::from(len)) <= u64::from(size_of_image) {
        true => Ok(()),
        false => Err(PeError::Malformed { reason }),
    }
}

/// An offset from a base, refused rather than wrapped.
///
/// **The header phase's half of [`Image::checked_va`]'s job, and the reason that one is described
/// as the only door with a qualifier now.** It cannot be the only one: a header read happens before
/// there is an [`Image`] to bound anything against, so [`read_image`] necessarily does its own
/// address arithmetic. What it does not have to do is that arithmetic *unchecked* -- `base` is the
/// caller's `u64`, and a base near the top of the address space turned a plain `base + offset` into
/// a debug-build panic, in a parser whose whole contract is to answer with [`PeError`]. Every
/// addition of an offset to a base in this module goes through here.
fn va(base: u64, offset: u64, len: usize) -> Result<u64, PeError> {
    let start = base.checked_add(offset).ok_or(PeError::Malformed {
        reason: "an image address overflowed",
    })?;
    // **The length is a parameter so that no caller can check only the start.** It was not, and
    // the result was this rule being applied to one of the two readers: `checked_va` validated its
    // whole span while `read_image`'s header reader validated a start and then handed `read` a
    // span running off the end of the address space. Taking `len` here is what makes that
    // impossible to get half-right -- a caller that has an address to compute has a length in hand
    // to give.
    start.checked_add(len as u64).ok_or(PeError::Malformed {
        reason: "an image address overflowed",
    })?;
    Ok(start)
}

/// Reads an image's headers and section table.
pub fn read_image(
    base: u64,
    mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
) -> Result<Image, PeError> {
    let mut at = |offset: u64, len: usize| -> Result<Vec<u8>, PeError> {
        let address = va(base, offset, len)?;
        read(address, len).ok_or(PeError::Unreadable { at: address, len })
    };

    let dos = at(0, 0x40)?;
    if u16(&dos, 0)? != 0x5a4d {
        return Err(PeError::NotAnImage {
            reason: "no MZ signature",
        });
    }
    let lfanew = u32(&dos, 0x3c)? as u64;
    if lfanew > 0x1000 {
        return Err(PeError::NotAnImage {
            reason: "e_lfanew is outside the header page",
        });
    }

    // COFF header, then as much optional header as the data directories need. Read in one go: the
    // header page is one read on any target that can answer at all.
    let headers = at(lfanew, 0x108)?;
    if u32(&headers, 0)? != 0x0000_4550 {
        return Err(PeError::NotAnImage {
            reason: "no PE signature",
        });
    }
    let machine = u16(&headers, 4)?;
    let section_count = u16(&headers, 6)? as usize;
    let optional_size = u16(&headers, 20)? as usize;
    let optional = 24usize;

    let bitness = match u16(&headers, optional)? {
        0x10b => Bitness::Bits32,
        0x20b => Bitness::Bits64,
        _ => {
            return Err(PeError::NotAnImage {
                reason: "the optional header names neither PE32 nor PE32+",
            });
        }
    };
    // **`Machine` and `Magic` have to agree, where this knows what the machine implies.** They are
    // two independent declarations of one fact, and everything below is keyed on the second alone:
    // the directory count, the directories themselves and the width of a thunk. So flipping the
    // magic of an x64 image to PE32 -- one byte, in a header an untrusted driver's own code can
    // reach -- sends the directory count to `optional + 92`, which in a PE32+ header is part of a
    // field that is zero there, and the image is then reported as importing nothing. Confidently,
    // with no read having failed: the same silent wrong answer the import directory's own bound is
    // for.
    //
    // An unrecognised machine is **not** refused. This list is the machines whose width is known,
    // not the machines that exist, and refusing everything absent from it would turn a future
    // architecture into a corrupt image.
    let implied = match machine {
        0x014c | 0x01c4 => Some(Bitness::Bits32), // I386, ARMNT
        0x8664 | 0xaa64 | 0x0200 => Some(Bitness::Bits64), // AMD64, ARM64, IA64
        _ => None,
    };

    if implied.is_some_and(|width| width != bitness) {
        return Err(PeError::Malformed {
            reason: "the machine and the optional header disagree about the image's width",
        });
    }

    // `SizeOfImage`, the directory count and the directories themselves sit at different offsets
    // in the two shapes, because PE32+ widens five fields between them.
    let (size_of_image_at, count_at, directories_at) = match bitness {
        Bitness::Bits32 => (optional + 56, optional + 92, optional + 96),
        Bitness::Bits64 => (optional + 56, optional + 108, optional + 112),
    };
    // The optional header must be long enough to hold the fields read out of it, and
    // `NumberOfRvaAndSizes` is the last of them in both shapes — so a header ending before it is
    // not an optional header, and is refused rather than read. Its declared length is also where
    // the **section table** begins, which is what makes a read past it a read of something else
    // entirely rather than of a zero: a garbage directory count would otherwise be a section
    // header's name.
    let optional_end = optional + optional_size;
    if optional_end < count_at + 4 {
        return Err(PeError::NotAnImage {
            reason: "the optional header is too short to hold its own fields",
        });
    }
    let size_of_image = u32(&headers, size_of_image_at)?;

    // `SectionAlignment` sits at the same offset in both shapes, as `SizeOfImage` does: the five
    // fields PE32+ widens are all after it.
    let section_alignment = u32(&headers, optional + 32)?;
    // **Refused rather than fallen back from.** A loader maps in powers of two and will not load
    // an image whose alignment is not one, so this is a header that cannot be what it says. The
    // fallback that was here -- treat it as absent and use each section's exact `VirtualSize` --
    // reproduced the very under-reporting the alignment is read for: an executable tail in no
    // range, and a scan that looks complete without it. There is no figure to answer with when
    // the unit is unknown, so this answers with none.
    if !section_alignment.is_power_of_two() {
        return Err(PeError::Malformed {
            reason: "the section alignment is not a unit a loader maps in",
        });
    }

    // **The data directories are declared, not assumed.** `NumberOfRvaAndSizes` says how many the
    // image carries and `SizeOfOptionalHeader` says how much room there is for them; an entry is
    // present only when both cover it. Read unconditionally, an undeclared entry is read out of
    // the section table that begins immediately after the optional header — so a section header's
    // `VirtualSize` and `VirtualAddress` become an import directory's RVA and size, and a valid
    // image with no import directory is reported as importing whatever they spell. The smaller of
    // the two bounds wins rather than their disagreement being an error: a header with no room for
    // an entry does not contain one, whatever it declares, and that reading needs no guess.
    let declared = u32(&headers, count_at)? as usize;
    let directory = |index: usize| -> Result<(u32, u32), PeError> {
        let entry = directories_at + index * 8;
        if index >= declared || entry + 8 > optional_end {
            return Ok((0, 0));
        }
        Ok((u32(&headers, entry)?, u32(&headers, entry + 4)?))
    };
    let export_directory = directory(0)?;
    let import_directory = directory(1)?;
    let iat_directory = directory(12)?;

    if section_count > MAX_SECTIONS {
        return Err(PeError::Malformed {
            reason: "more sections than an image plausibly has",
        });
    }
    let table = lfanew + 24 + optional_size as u64;
    // **Bounded by `SizeOfImage`, because past it is the next module.** `SizeOfOptionalHeader` is
    // a `u16` the image declares and `table` is derived from it, so a header claiming 64 KiB of
    // optional header inside an image that declares 4 KiB puts the section table beyond the image
    // -- where, on a live target, the read succeeds against whatever is mapped next and its bytes
    // come back as this image's sections. `code_sections` and `executable_ranges` would then bound
    // a scan by a neighbour's layout, with nothing in the result to say so. This is the same rule
    // `checked_va` applies to every RVA; it is here as well because the section table is read
    // before there is an `Image` to ask.
    let table_rva = u32::try_from(table).map_err(|_| PeError::Malformed {
        reason: "the section table lies outside a 32-bit image offset",
    })?;
    declared_fits(
        table_rva,
        (section_count * 40) as u32,
        size_of_image,
        "the section table runs past the end of the image",
    )?;
    let raw = at(table, section_count * 40)?;
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = index * 40;
        let name = raw
            .get(offset..offset + 8)
            .ok_or(PeError::Malformed {
                reason: "the section table is shorter than its count",
            })?
            .iter()
            .take_while(|&&byte| byte != 0)
            .map(|&byte| byte as char)
            .collect::<String>();
        sections.push(Section {
            name,
            virtual_size: u32(&raw, offset + 8)?,
            rva: u32(&raw, offset + 12)?,
            characteristics: u32(&raw, offset + 36)?,
        });
    }

    Ok(Image {
        base,
        bitness,
        machine,
        size_of_image,
        section_alignment,
        sections,
        export_directory,
        import_directory,
        iat_directory,
    })
}

/// A reader of image offsets, for the reads whose length this module chooses.
///
/// Clipped to the image rather than refused for overrunning it: a name near the end is
/// legitimately shorter than the bounded read asks for, and a fixed-size structure that comes back
/// short fails its own field parse. The *start* is still bounded, by [`Image::checked_va`].
fn clipped_reader<'a>(
    image: &'a Image,
    read: &'a mut impl FnMut(u64, usize) -> Option<Vec<u8>>,
) -> impl FnMut(u32, usize) -> Result<Vec<u8>, PeError> + 'a {
    move |rva: u32, len: usize| {
        let room = image.size_of_image.saturating_sub(rva) as usize;
        let len = len.min(room);
        let address = image.checked_va(rva, len)?;
        read(address, len).ok_or(PeError::Unreadable { at: address, len })
    }
}

/// One slot of the import address table, and what it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IatSlot {
    /// The slot's virtual address -- the same `slot` [`Import`] carries for the import it holds.
    pub slot: u64,
    /// What the slot holds. In a loaded image that is the address the loader bound the import to;
    /// in an image file it is an unbound thunk, which is why this is asked of a live target.
    pub value: u64,
}

/// Reads the import address table (`IMAGE_DIRECTORY_ENTRY_IAT`), slot by slot, leaving out the
/// zero that ends each library's run.
///
/// **The import table's other half, and the one a loaded driver keeps.** [`read_imports`] names
/// imports from the import directory, which a linker may put in a discardable section, and the
/// loader frees that section once the driver has started -- so on a live target there is nothing
/// left to name them from. HEVD's ARM64 build is the case: its import directory is in `INIT`, which
/// on a live ARM64 kernel reads `??`, while its fifteen slots at `.rdata+0` read and hold
/// `nt!ExAllocatePoolWithTag` and the rest (measured 2026-10-09). The address table is what the
/// driver's own calls go through, so it is kept. Naming what a slot holds is the caller's: it needs
/// the module the address is in, which an engine knows and this parser does not.
///
/// The span is the image's own declaration, so it is checked against the image whole rather than
/// clipped, and bounded like the import table: refused rather than truncated.
pub fn read_import_address_table(
    image: &Image,
    mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
) -> Result<Vec<IatSlot>, PeError> {
    let (rva, size) = image.iat_directory;
    match (rva, size) {
        (0, 0) => return Ok(Vec::new()),
        (0, _) | (_, 0) => {
            return Err(PeError::Malformed {
                reason: "the import address table has a size without an address, or the reverse",
            });
        }
        _ => {}
    }
    let pointer = image.bitness.pointer();
    let len = size as usize;
    if !len.is_multiple_of(pointer) {
        return Err(PeError::Malformed {
            reason: "the import address table is not a whole number of slots",
        });
    }
    if len / pointer > MAX_IMPORTS_TOTAL + MAX_LIBRARIES {
        return Err(PeError::Malformed {
            reason: "more import address slots than an image plausibly has",
        });
    }
    // `checked_va` refuses the whole span, end included, so a table running past the image is
    // `Malformed` here rather than clipped.
    let address = image.checked_va(rva, len)?;
    let bytes = read(address, len)
        .filter(|bytes| bytes.len() == len)
        .ok_or(PeError::Unreadable { at: address, len })?;
    let mut slots = Vec::new();
    for (index, raw) in bytes.chunks_exact(pointer).enumerate() {
        let value = match image.bitness {
            Bitness::Bits64 => u64_at(raw, 0)?,
            Bitness::Bits32 => u64::from(u32(raw, 0)?),
        };
        if value != 0 {
            slots.push(IatSlot {
                slot: address + (index * pointer) as u64,
                value,
            });
        }
    }
    Ok(slots)
}

/// The library name an image's export directory gives itself (`IMAGE_EXPORT_DIRECTORY.Name`), or
/// `None` for an image that exports nothing.
///
/// **The spelling an importer uses**, which is the reason to read it rather than take a module's
/// image name: the kernel is loaded as `ntkrnlmp.exe` and imported as `ntoskrnl.exe`, and naming
/// an import from the address it was bound to has to land on the second to match anything keyed
/// by an import table.
pub fn read_export_library_name(
    image: &Image,
    mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
) -> Result<Option<String>, PeError> {
    let (rva, size) = image.export_directory;
    match (rva, size) {
        (0, 0) => return Ok(None),
        (0, _) | (_, 0) => {
            return Err(PeError::Malformed {
                reason: "the export directory has a size without an address, or the reverse",
            });
        }
        _ => {}
    }
    // `IMAGE_EXPORT_DIRECTORY` is forty bytes; its `Name` is the RVA at offset twelve.
    declared_fits(
        rva,
        40,
        image.size_of_image,
        "the export directory runs past the end of the image",
    )?;
    let mut at = clipped_reader(image, &mut read);
    let name_rva = u32(&at(rva + 12, 4)?, 0)?;
    read_c_string(name_rva, &mut at).map(Some)
}

/// Reads the import table, naming every slot without reading one.
///
/// The ordering rule this rests on is the PE specification's: the import lookup table and the
/// import address table are parallel arrays, so entry `i` of the lookup table names the slot at
/// `FirstThunk + i * pointer`. An image whose `OriginalFirstThunk` is zero — bound imports, which
/// a driver does not normally ship — has only the IAT to read names from, and this reports the
/// slots it can place with [`ImportName::Ordinal`] rather than reading a pointer that may not be
/// there.
pub fn read_imports(
    image: &Image,
    mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
    mut halt: impl FnMut() -> bool,
) -> Result<ImportTable, PeError> {
    let (directory, size) = image.import_directory;
    // Absent means **both** are zero. One of the two alone is a directory whose coordinates
    // disagree, and reading that as "no imports" is the silent wrong answer this module keeps
    // being asked not to give: a nonzero RVA with a zero size hides a real descriptor table, and a
    // hazard scan over it reports no dangerous imports.
    match (directory, size) {
        (0, 0) => return Ok(ImportTable::default()),
        (0, _) | (_, 0) => {
            return Err(PeError::Malformed {
                reason: "the import directory has a size without an address, or the reverse",
            });
        }
        _ => {}
    }
    // Every read is bounded by the image, and the arithmetic is checked.
    //
    // Without this, an RVA past `SizeOfImage` is added to the base and handed to the reader — and
    // on a live target the memory just past a driver is *the next module*, which reads perfectly
    // well. A malformed or adversarial image would then have its "imports" answered out of a
    // neighbour's bytes, with nothing in the result to say so. A start outside the image is
    // refused; a length that would run past its end is clipped to it, because a name near the end
    // is legitimately shorter than the bounded read asks for, and a structure that comes back
    // short fails its own field parse.
    let mut at = clipped_reader(image, &mut read);

    // Refused rather than truncated, which is this module's stated rule and was not followed
    // here: reading the first `MAX_LIBRARIES` and returning `Ok` drops the rest in silence, and a
    // hazard scan reading that concludes a dangerous import is absent when it is merely past the
    // cut. A plausible image does not have this many.
    //
    // The `+ 1` is the **terminator**, which is a descriptor and is not a library. Without it the
    // limit is off by one against its own sentence: an image importing exactly `MAX_LIBRARIES`
    // libraries carries `MAX_LIBRARIES + 1` descriptors and would be refused for having one more
    // library than it has.
    if size as usize / 20 > MAX_LIBRARIES + 1 {
        return Err(PeError::Malformed {
            reason: "the import directory names more libraries than an image plausibly has",
        });
    }
    // The directory's length is `NumberOfRvaAndSizes`' business, not this module's, so it is
    // validated rather than clipped -- see `declared_fits` for what clipping it answered instead.
    declared_fits(
        directory,
        size,
        image.size_of_image,
        "the import directory runs past the end of the image",
    )?;
    let descriptors = at(directory, size as usize)?;
    let mut table = ImportTable::default();
    // **A slot belongs to one import.** It holds one function pointer, so two names claiming it is
    // a structure that does not hold together — and continuing would make every call through it an
    // arbitrary choice between the two, reported as a fact. Refused here rather than resolved
    // downstream, because a consumer indexing by slot can only silently keep the last one.
    let mut claimed: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut terminated = false;
    for index in 0..(descriptors.len() / 20) {
        if halt() {
            return Err(PeError::Interrupted);
        }
        let offset = index * 20;
        let lookup = u32(&descriptors, offset)?;
        let name_rva = u32(&descriptors, offset + 12)?;
        let iat = u32(&descriptors, offset + 16)?;
        // The table ends at an **all-zero** descriptor, which is all five fields and not the
        // three that happen to be read above: a descriptor with a stamp or a forwarder chain left
        // over would otherwise end the table early and drop every library after it.
        let stamp = u32(&descriptors, offset + 4)?;
        let forwarder = u32(&descriptors, offset + 8)?;
        if lookup == 0 && name_rva == 0 && iat == 0 && stamp == 0 && forwarder == 0 {
            terminated = true;
            break;
        }
        // **A descriptor that is not the terminator has a name and an address table.** Zero is
        // not an RVA a real one carries, and neither field is optional -- but both were read as
        // offsets, so a zero answered rather than refused. A zero `Name` reads RVA 0, which is the
        // `MZ` header, and the library comes back called `MZ`; a zero `FirstThunk` puts every slot
        // of that library at the image base, which a call-site scanner matches against nothing.
        // Either way the walk returns `Ok` and the driver's real imports are not in it.
        //
        // `OriginalFirstThunk` is different and is checked below rather than here: zero there is a
        // bound import, which is a real shape with an answer of its own.
        if name_rva == 0 {
            return Err(PeError::Malformed {
                reason: "an import descriptor names no library",
            });
        }
        if iat == 0 {
            return Err(PeError::Malformed {
                reason: "an import descriptor has no import address table",
            });
        }
        let library = read_c_string(name_rva, &mut at)?;
        // Bound imports leave no lookup table; the IAT is then the only array there is, and its
        // entries are addresses rather than name RVAs.
        // A bound import: real slots, no lookup table, names only in the IAT. Recorded by name
        // rather than skipped, so a caller can say "this library's imports are not nameable here"
        // instead of reporting a driver that imports less than it does.
        let pointer = image.bitness.pointer();
        if lookup == 0 {
            // **Bounded before it is believed, though nothing here reads it.** This branch used to
            // return with only the zero check behind it, so a bound import whose `FirstThunk`
            // points past the image was reported as a library this could not name rather than as
            // an image that does not hold together. That is the same rule the named path follows
            // one loop below, where a slot is checked *because a caller attributes the address to
            // this image* -- and it is no less true of a descriptor whose slots are never listed.
            image.checked_va(iat, pointer)?;
            table.unnamed_libraries.push(library);
            continue;
        }

        let mut library_terminated = false;
        for slot_index in 0..MAX_IMPORTS_PER_LIBRARY {
            if halt() {
                return Err(PeError::Interrupted);
            }
            // Never dereferenced, and still bounded: a caller attributes this address to *this*
            // image, so a `FirstThunk` outside it would have an indirect call into a neighbour
            // reported as this driver's import.
            // **Both of these are computed in `u64` and narrowed once**, and neither is a
            // `u32 + u32`. The lookup side used to be exactly that, which a malformed image with
            // an RVA near `u32::MAX` turns into a debug-build panic -- unacceptable in a library
            // whose contract is to return `Malformed` -- and, in release, a *wrap* to a low RVA
            // that `checked_va` then passes, because a wrapped offset is inside the image. The
            // answer is imports read out of the image's own header, with nothing having failed.
            //
            // The IAT side above it was already narrowed, but through `usize`, which is only wide
            // enough on a 64-bit host: this crate builds a 32-bit worker too, and there
            // `iat as usize + slot_index * pointer` is the same overflow by another route. `u64`
            // is the width that does not depend on who is running.
            let offset = (slot_index * pointer) as u64;
            let narrow = |rva: u64, reason: &'static str| -> Result<u32, PeError> {
                u32::try_from(rva).map_err(|_| PeError::Malformed { reason })
            };
            let slot_rva = narrow(
                u64::from(iat) + offset,
                "an import address table entry lies outside a 32-bit image offset",
            )?;
            let slot = image.checked_va(slot_rva, pointer)?;
            let entry_rva = narrow(
                u64::from(lookup) + offset,
                "an import lookup table entry lies outside a 32-bit image offset",
            )?;
            let entry = at(entry_rva, pointer)?;
            let value = match image.bitness {
                Bitness::Bits32 => u32(&entry, 0)? as u64,
                Bitness::Bits64 => u64_at(&entry, 0)?,
            };
            if value == 0 {
                library_terminated = true;
                break;
            }
            let ordinal_flag = match image.bitness {
                Bitness::Bits32 => 1u64 << 31,
                Bitness::Bits64 => 1u64 << 63,
            };
            let name = if value & ordinal_flag != 0 {
                // **Everything between the flag and the ordinal has to be zero.** Masking to the
                // low sixteen bits answered for any thunk with the flag set, so flipping that one
                // bit on a *named* thunk of `0x2110` produced ordinal `#8464` -- a number no
                // import has, returned as one, with the name that was really there lost. An
                // exact-name scan then misses that API and nothing says why.
                if value & !(ordinal_flag | 0xffff) != 0 {
                    return Err(PeError::Malformed {
                        reason: "an ordinal import sets bits that are neither its flag nor its \
                                 ordinal",
                    });
                }
                ImportName::Ordinal((value & 0xffff) as u16)
            } else {
                // IMAGE_IMPORT_BY_NAME: a two-byte hint, then the name.
                //
                // **Converted rather than truncated, and added rather than wrapped.** A PE32+
                // thunk is 64 bits and its name RVA lives in the low 31, so `value as u32` was
                // silently discarding whatever a malformed image put above them -- and then `+ 2`
                // on a low word of `0xffff_fffe` wrapped to RVA 0, where `read_c_string` reads the
                // MZ header and returns it as an import name. Two refusals instead: a thunk that
                // is not an image offset, and a hint that runs off the end of one.
                let hint = u32::try_from(value).map_err(|_| PeError::Malformed {
                    reason: "an import name table entry is not a 32-bit image offset",
                })?;
                let name_rva = hint.checked_add(2).ok_or(PeError::Malformed {
                    reason: "an import name's hint runs past the end of a 32-bit image offset",
                })?;
                ImportName::Named(read_c_string(name_rva, &mut at)?)
            };
            // Checked as the table grows rather than after it, which is the whole point: a limit
            // enforced on a finished list is a limit enforced after the memory was spent.
            if !claimed.insert(slot) {
                return Err(PeError::Malformed {
                    reason: "two imports claim the same import address table slot",
                });
            }
            if table.imports.len() >= MAX_IMPORTS_TOTAL {
                return Err(PeError::Malformed {
                    reason: "the image imports more functions in total than a plausible one does",
                });
            }
            table.imports.push(Import {
                library: library.clone(),
                name,
                slot,
            });
        }
        // Running out of entries is not the same as reaching the end of them. Stopping here and
        // returning `Ok` drops every later import of this library in silence, which is how a
        // hazard scan comes to report that a dangerous API is absent when it is merely past the
        // cut — the same defect as the directory bound above, one level down.
        if !library_terminated {
            return Err(PeError::Malformed {
                reason: "a library imports more functions than an image plausibly does",
            });
        }
    }
    // A directory that ran out before its null descriptor is one whose size does not describe it,
    // and the libraries past the end are exactly the ones a truncating read would have dropped.
    if !terminated {
        return Err(PeError::Malformed {
            reason: "the import directory ends without a null descriptor",
        });
    }
    Ok(table)
}

/// The imports indexed by the slot a call goes through, which is how a call site is named.
pub fn imports_by_slot(imports: &[Import]) -> BTreeMap<u64, &Import> {
    imports.iter().map(|import| (import.slot, import)).collect()
}

/// A NUL-terminated ASCII string at an RVA, read in one bounded go.
/// A name, read **up to its terminator** rather than in one demand for [`MAX_NAME`] bytes.
///
/// **The single 512-byte read undid this module's reason for existing.** A hole in a loaded image
/// is what the reader shape is for, and holes are page-granular -- so a perfectly readable
/// fifteen-byte name sitting within 512 bytes of one had its read span the hole and fail, and the
/// import came back [`PeError::Unreadable`] though every byte of it was there. That is not
/// hypothetical for the natural adapter: [`crate::dbgeng::DebugEngine::read_memory`] answers
/// `ShortRead` rather than a short buffer, so `|at, len| engine.read_memory(at, len).ok()` is
/// `None` for any request that crosses into a gap.
///
/// So a read never spans a [`NAME_READ_GRANULE`]. The chunk is whatever is left before the next
/// granule boundary, capped by the remaining name budget -- which is one read for a name that does
/// not straddle one, and two for a name that does. An image's base is page-aligned by the loader,
/// so an RVA boundary is an address boundary.
fn read_c_string(
    rva: u32,
    at: &mut impl FnMut(u32, usize) -> Result<Vec<u8>, PeError>,
) -> Result<String, PeError> {
    let mut raw: Vec<u8> = Vec::new();
    while raw.len() < MAX_NAME {
        let taken = u32::try_from(raw.len()).map_err(|_| PeError::Malformed {
            reason: "an import or library name runs past the length a name may have",
        })?;
        let here = rva.checked_add(taken).ok_or(PeError::Malformed {
            reason: "an import name runs past the end of a 32-bit image offset",
        })?;
        let want =
            (NAME_READ_GRANULE - (here as usize % NAME_READ_GRANULE)).min(MAX_NAME - raw.len());
        let chunk = at(here, want)?;
        // Clipped to nothing means the image ended before the name did, which is the same answer
        // as no terminator: the loop below says so rather than returning a truncated name.
        if chunk.is_empty() {
            break;
        }
        if let Some(end) = chunk.iter().position(|&byte| byte == 0) {
            raw.extend_from_slice(&chunk[..end]);
            // **A name that is not text is an error, not a name with the bad bytes rewritten.**
            // `from_utf8_lossy` was here, and what it produces is a *rendering*: one corrupt byte
            // in `ExAllocatePool2` came back as a different string, returned as the name with
            // nothing saying it had been altered. The one consumer matches these against a sink
            // list by exact name, so the rendering silently fails to match and a hazardous import
            // reads as absent -- a lossy form standing in as a key, which is the failure this
            // crate has already fixed once for pool tags and once for object names.
            return String::from_utf8(raw).map_err(|_| PeError::Malformed {
                reason: "an import or library name is not text",
            });
        }
        raw.extend_from_slice(&chunk);
    }
    // No terminator inside the bound means this is not a name that fits the bound — and taking
    // the buffer as one turns a hazardous import into a *different*, unmatched string, which a
    // sink list then fails to recognise. The truncation would be invisible in the result.
    Err(PeError::Malformed {
        reason: "an import or library name runs past the length a name may have",
    })
}

fn u16(bytes: &[u8], offset: usize) -> Result<u16, PeError> {
    let raw = bytes.get(offset..offset + 2).ok_or(PeError::Malformed {
        reason: "short read of a 16-bit field",
    })?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn u32(bytes: &[u8], offset: usize) -> Result<u32, PeError> {
    let raw = bytes.get(offset..offset + 4).ok_or(PeError::Malformed {
        reason: "short read of a 32-bit field",
    })?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, PeError> {
    let raw = bytes.get(offset..offset + 8).ok_or(PeError::Malformed {
        reason: "short read of a 64-bit field",
    })?;
    let mut value = [0u8; 8];
    value.copy_from_slice(raw);
    Ok(u64::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake address space holding one loaded image, with ranges that can be made unreadable.
    ///
    /// Every offset below is written as a **literal** rather than computed the way the parser
    /// reads it: a fixture that derives its layout from the parser's own arithmetic agrees with
    /// the parser about a wrong layout, and pins nothing.
    struct FakeImage {
        base: u64,
        bytes: Vec<u8>,
        unreadable: Vec<(u64, u64)>,
    }

    impl FakeImage {
        fn read(&self, at: u64, len: usize) -> Option<Vec<u8>> {
            let end = at.checked_add(len as u64)?;
            if self
                .unreadable
                .iter()
                .any(|&(low, high)| at < high && end > low)
            {
                return None;
            }
            let offset = at.checked_sub(self.base)? as usize;
            // A read running off the end comes back short rather than absent, which is what a
            // real reader does at the last mapped page.
            let slice = self.bytes.get(offset..)?;
            Some(slice[..slice.len().min(len)].to_vec())
        }
    }

    fn put(bytes: &mut Vec<u8>, offset: usize, value: &[u8]) {
        if bytes.len() < offset + value.len() {
            bytes.resize(offset + value.len(), 0);
        }
        bytes[offset..offset + value.len()].copy_from_slice(value);
    }

    const BASE: u64 = 0xffff_f800_0000_0000;

    /// A PE32+ driver: three sections, one imported library, three imports — two by name and one
    /// by ordinal — with the import address table in the writable section.
    fn driver_image() -> FakeImage {
        let mut bytes = vec![0u8; 0x4000];

        // DOS header: `MZ`, and e_lfanew at 0x3c.
        put(&mut bytes, 0x00, b"MZ");
        put(&mut bytes, 0x3c, &0xe0u32.to_le_bytes());

        // COFF header at 0xe0.
        put(&mut bytes, 0xe0, b"PE\0\0");
        put(&mut bytes, 0xe4, &0x8664u16.to_le_bytes()); // Machine
        put(&mut bytes, 0xe6, &3u16.to_le_bytes()); // NumberOfSections
        put(&mut bytes, 0xf4, &0xf0u16.to_le_bytes()); // SizeOfOptionalHeader

        // Optional header at 0xf8 (0xe0 + 24), PE32+.
        put(&mut bytes, 0xf8, &0x20bu16.to_le_bytes()); // Magic
        put(&mut bytes, 0xf8 + 32, &0x1000u32.to_le_bytes()); // SectionAlignment
        put(&mut bytes, 0xf8 + 56, &0x4000u32.to_le_bytes()); // SizeOfImage
        // NumberOfRvaAndSizes at 0xf8 + 108 = 0x164. Sixteen is what every real image writes, and
        // a directory is only read when this says it is there.
        put(&mut bytes, 0x164, &16u32.to_le_bytes());
        // Data directories at 0xf8 + 112 = 0x168: export is [0], import is [1].
        put(&mut bytes, 0x170, &0x2000u32.to_le_bytes()); // import rva
        put(&mut bytes, 0x174, &40u32.to_le_bytes()); // import size

        // Section table at 0x1e8 (0xe0 + 24 + 0xf0), forty bytes an entry.
        let mut section = |index: usize, name: &[u8], rva: u32, characteristics: u32| {
            let at = 0x1e8 + index * 40;
            put(&mut bytes, at, name);
            put(&mut bytes, at + 8, &0x1000u32.to_le_bytes()); // VirtualSize
            put(&mut bytes, at + 12, &rva.to_le_bytes()); // VirtualAddress
            put(&mut bytes, at + 36, &characteristics.to_le_bytes());
        };
        section(0, b".text\0\0\0", 0x1000, 0x6000_0020); // CODE | EXECUTE | READ
        section(1, b".rdata\0\0", 0x2000, 0x4000_0040); // INITIALIZED_DATA | READ
        section(2, b".data\0\0\0", 0x3000, 0xc000_0040); // READ | WRITE

        // Import descriptor at 0x2000; the table ends at the all-zero one at 0x2014.
        put(&mut bytes, 0x2000, &0x2040u32.to_le_bytes()); // OriginalFirstThunk
        put(&mut bytes, 0x200c, &0x2100u32.to_le_bytes()); // Name
        put(&mut bytes, 0x2010, &0x3000u32.to_le_bytes()); // FirstThunk — in .data

        // Import lookup table at 0x2040, eight bytes an entry, zero-terminated.
        put(&mut bytes, 0x2040, &0x2110u64.to_le_bytes());
        put(&mut bytes, 0x2048, &0x2120u64.to_le_bytes());
        put(&mut bytes, 0x2050, &0x8000_0000_0000_0007u64.to_le_bytes()); // ordinal 7

        // Names. An IMAGE_IMPORT_BY_NAME is a two-byte hint and then the string.
        put(&mut bytes, 0x2100, b"ntoskrnl.exe\0");
        put(&mut bytes, 0x2112, b"ExAllocatePool2\0");
        put(&mut bytes, 0x2122, b"ProbeForRead\0");

        FakeImage {
            base: BASE,
            bytes,
            unreadable: Vec::new(),
        }
    }

    /// A name thunk whose hint would run off the end of the RVA space is refused, not wrapped.
    ///
    /// `IMAGE_IMPORT_BY_NAME` is a two-byte hint and then the string, so the name starts at
    /// `thunk + 2`. A malformed PE32+ thunk of `0xffff_fffe` made that addition wrap to RVA 0 --
    /// where `read_c_string` reads the `MZ` header and hands back whatever is there as an import
    /// name, with nothing having failed. This is reachable straight from target bytes: the thunk
    /// is read out of the lookup table and used, so nothing upstream constrains it.
    #[test]
    fn test_a_name_thunk_whose_hint_overflows_is_refused() {
        let mut fake = driver_image();
        // The first lookup entry, with the ordinal flag clear so it is read as a name.
        put(
            &mut fake.bytes,
            0x2040,
            &0x0000_0000_ffff_fffeu64.to_le_bytes(),
        );

        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        assert_eq!(
            read_imports(&image, |at, len| fake.read(at, len), || false),
            Err(PeError::Malformed {
                reason: "an import name's hint runs past the end of a 32-bit image offset",
            })
        );
    }

    /// And a thunk that is not a 32-bit offset at all is refused rather than truncated.
    ///
    /// A PE32+ thunk is eight bytes and its name RVA lives in the low 31. `value as u32` discarded
    /// whatever a malformed image put above them, so a thunk of `0x1_0000_1000` was read as RVA
    /// `0x1000` -- a real offset in this image, answered with a real name, and wrong.
    #[test]
    fn test_a_name_thunk_above_the_32_bit_offset_space_is_refused() {
        let mut fake = driver_image();
        put(
            &mut fake.bytes,
            0x2040,
            &0x0000_0001_0000_1000u64.to_le_bytes(),
        );

        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        assert_eq!(
            read_imports(&image, |at, len| fake.read(at, len), || false),
            Err(PeError::Malformed {
                reason: "an import name table entry is not a 32-bit image offset",
            })
        );
    }

    /// **The table-walk arithmetic cannot be driven off the end of the RVA space, and this is the
    /// measurement rather than the argument.**
    ///
    /// Review on #164 asked for checked arithmetic on `lookup + slot_index * pointer`, on the
    /// reading that an image declaring nearly 4 GiB and a table near the top of it would wrap.
    /// The checked form is in place -- it costs nothing and does not depend on a non-local
    /// invariant holding -- but the scenario turns out to be **unreachable**, and it is worth
    /// pinning why so that a later edit which makes it reachable fails here.
    ///
    /// The reason is that each iteration's own bounded read constrains the next iteration's
    /// arithmetic. An entry is eight bytes; `at` clips a read to the image and a short slice fails
    /// its own field parse, so an iteration only *completes* when its entry sat at least eight
    /// bytes below `SizeOfImage` -- which leaves the next RVA no higher than `SizeOfImage`, and
    /// that is a `u32`. The walk therefore stops at the bound before the addition can reach it.
    ///
    /// So the assertion is about **which** refusal arrives. It is the image bound, not the
    /// narrowing -- and if a future change lets the narrowing fire first, this says so.
    #[test]
    fn test_the_import_walk_stops_at_the_image_bound_before_its_arithmetic_could_wrap() {
        // Declared, not allocated: nothing is materialised, the reader answers from arithmetic.
        let image = Image {
            base: BASE,
            bitness: Bitness::Bits64,
            machine: 0x8664,
            size_of_image: 0xffff_ffff,
            section_alignment: 0x1000,
            sections: Vec::new(),
            export_directory: (0, 0),
            import_directory: (0x1000, 40),
            iat_directory: (0, 0),
        };
        // One descriptor whose lookup and address tables both sit at the very top of the image,
        // then a terminator. Every thunk read comes back as an ordinal, so the walk never stops
        // for a name and runs until something bounds it.
        let read = |address: u64, len: usize| -> Option<Vec<u8>> {
            let rva = address.checked_sub(BASE)? as u32;
            let mut out = vec![0u8; len];
            if rva == 0x1000 {
                // OriginalFirstThunk, then Name at +12, then FirstThunk at +16.
                out[0..4].copy_from_slice(&0xffff_f000u32.to_le_bytes());
                out[12..16].copy_from_slice(&0x2000u32.to_le_bytes());
                out[16..20].copy_from_slice(&0xffff_f000u32.to_le_bytes());
                return Some(out);
            }
            if rva == 0x2000 {
                out[..8].copy_from_slice(b"drv.sys\0");
                return Some(out);
            }
            // Anything in the tables reads as an ordinal thunk, so the walk keeps going.
            out[..len.min(8)]
                .copy_from_slice(&0x8000_0000_0000_0007u64.to_le_bytes()[..len.min(8)]);
            Some(out)
        };

        let outcome = read_imports(&image, read, || false);
        assert_eq!(
            outcome,
            Err(PeError::Malformed {
                reason: "an image offset points outside the image",
            }),
            "the walk is stopped by the image bound, not by the narrowing -- if this becomes an \
             arithmetic refusal, the reachability argument in this test has stopped holding"
        );
    }

    /// A section table reaching past `SizeOfImage` is refused, not read out of the next module.
    ///
    /// `SizeOfOptionalHeader` is a `u16` the image declares and the table's offset is derived from
    /// it, so a header can put its own section table beyond the image it describes. On a live
    /// target that read *succeeds* -- what is mapped after a driver is another module -- and its
    /// bytes come back as this image's sections, which is then what `code_sections` and
    /// `executable_ranges` bound a scan by. Nothing in the result would say so.
    #[test]
    fn test_a_section_table_past_the_end_of_the_image_is_refused() {
        let mut fake = driver_image();
        // The table sits at 0x1e8 and runs 120 bytes for three sections; declare an image that
        // ends before it does.
        put(&mut fake.bytes, 0xf8 + 56, &0x200u32.to_le_bytes());

        assert_eq!(
            read_image(BASE, |at, len| fake.read(at, len)),
            Err(PeError::Malformed {
                reason: "the section table runs past the end of the image",
            })
        );
    }

    /// A base near the top of the address space is an error, not a panic.
    ///
    /// `read_image` takes the base as a `u64` from its caller, and the header offsets it adds are
    /// the image's own. A plain `base + offset` there is a debug-build panic inside a parser whose
    /// entire contract is to answer with a `PeError` -- the one failure mode a caller cannot catch.
    #[test]
    fn test_a_base_that_would_wrap_the_address_space_is_refused() {
        let read = |_address: u64, len: usize| -> Option<Vec<u8>> {
            // Never called now: the very first read's span is rejected before the reader sees it.
            let mut out = vec![0u8; len];
            out[0..2].copy_from_slice(b"MZ");
            if len > 0x3f {
                out[0x3c..0x40].copy_from_slice(&0xe0u32.to_le_bytes());
            }
            Some(out)
        };

        assert_eq!(
            read_image(u64::MAX - 0x10, read),
            Err(PeError::Malformed {
                reason: "an image address overflowed",
            })
        );
    }

    /// An RVA whose **span** wraps the address space is refused, though its start does not.
    ///
    /// `checked_va` bounds an RVA against `SizeOfImage` and then turns it into an address. Checking
    /// only `base + rva` left the length out: the start is fine and the end is not, and the
    /// callers that add the length back on are exactly the ones that would meet it.
    /// `executable_ranges` builds `start..start + virtual_size`, which panics in debug and in
    /// release yields a range starting above where it ends -- a range every `contains` answers
    /// `false` for, so a code scan silently covers nothing.
    #[test]
    fn test_an_rva_whose_span_wraps_the_address_space_is_refused() {
        let image = Image {
            base: u64::MAX - 0x1000,
            bitness: Bitness::Bits64,
            machine: 0x8664,
            size_of_image: 0x2000,
            section_alignment: 0x1000,
            sections: vec![Section {
                name: ".text".to_string(),
                rva: 0x1000,
                virtual_size: 0x1000,
                characteristics: 0x6000_0020,
            }],
            export_directory: (0, 0),
            import_directory: (0, 0),
            iat_directory: (0, 0),
        };

        // The start is inside the image and inside the address space; the end is not.
        assert_eq!(
            image.checked_va(0x1000, 0x1000),
            Err(PeError::Malformed {
                reason: "an image address overflowed",
            })
        );
        // So the range is dropped rather than built inverted, and nothing panics.
        assert!(image.executable_ranges().is_empty());
    }

    /// A name beside a hole is read, because a read never spans a page.
    ///
    /// **This is the module's own reason for existing, and the single 512-byte demand broke it.**
    /// The library name sits sixteen bytes before an unreadable page -- which is what a kernel
    /// minidump looks like, holes being page-granular -- and every byte of the name is there. Ask
    /// for 512 bytes and the request crosses the hole and fails, so a fully readable import comes
    /// back `Unreadable`. Ask only as far as the page ends and it reads.
    ///
    /// Not hypothetical for the natural adapter: `DebugEngine::read_memory` answers `ShortRead`
    /// rather than a short buffer, so `|at, len| engine.read_memory(at, len).ok()` is `None` for
    /// any request reaching into a gap.
    #[test]
    fn test_a_name_beside_an_unreadable_page_is_still_read() {
        let mut fake = driver_image();
        // Move the library name to the last sixteen bytes of the .rdata page.
        put(&mut fake.bytes, 0x200c, &0x2ff0u32.to_le_bytes());
        put(&mut fake.bytes, 0x2ff0, b"ntoskrnl.exe\0");
        // The next page is gone, exactly as the import address table's page is on a minidump.
        fake.unreadable.push((BASE + 0x3000, BASE + 0x4000));

        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        let table = read_imports(&image, |at, len| fake.read(at, len), || false)
            .expect("the name is beside the hole, not inside it");

        assert_eq!(table.imports.len(), 3, "{table:#?}");
        assert!(
            table
                .imports
                .iter()
                .all(|import| import.library == "ntoskrnl.exe"),
            "{table:#?}"
        );
    }

    /// A name beside a hole that starts **mid-page** is read too.
    ///
    /// The shape an image-file target produces: a section is mapped only as far as its raw data,
    /// so the readable bytes stop at a `FileAlignment` boundary inside a page. This is HEVD's
    /// `INIT` in miniature -- the name `0x174` bytes before the end of the mapped data -- and a read
    /// granule of a page asked for 512 bytes there and failed, though every byte of the name read.
    #[test]
    fn test_a_name_beside_a_hole_inside_a_page_is_still_read() {
        let mut fake = driver_image();
        put(&mut fake.bytes, 0x200c, &0x2c8cu32.to_le_bytes());
        put(&mut fake.bytes, 0x2c8c, b"ntoskrnl.exe\0");
        // Unreadable from 0x2e00 to the end of the page: the section's raw data ended there.
        fake.unreadable.push((BASE + 0x2e00, BASE + 0x3000));

        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        let table = read_imports(&image, |at, len| fake.read(at, len), || false)
            .expect("the name ends before the hole, inside the same page");

        assert_eq!(table.imports.len(), 3, "{table:#?}");
        assert!(
            table
                .imports
                .iter()
                .all(|import| import.library == "ntoskrnl.exe"),
            "{table:#?}"
        );
    }

    /// The import address table is read slot by slot, leaving out the zeros that end a library.
    ///
    /// The shape of a live driver whose import directory the loader has freed: only the address
    /// table is left, and on a loaded image its slots hold bound addresses. Values are HEVD's,
    /// read off a live ARM64 kernel. The zero in the middle is where one library's slots end and
    /// the next one's begin, and the slot addresses are the ones [`Import::slot`] uses.
    #[test]
    fn test_the_import_address_table_is_read_slot_by_slot() {
        let mut fake = driver_image();
        // IMAGE_DIRECTORY_ENTRY_IAT is directory [12], at 0x168 + 12 * 8.
        put(&mut fake.bytes, 0x1c8, &0x3000u32.to_le_bytes());
        put(&mut fake.bytes, 0x1cc, &0x20u32.to_le_bytes());
        put(
            &mut fake.bytes,
            0x3000,
            &0xffff_f801_cdeb_8670u64.to_le_bytes(),
        );
        put(
            &mut fake.bytes,
            0x3008,
            &0xffff_f801_cdd8_4f30u64.to_le_bytes(),
        );
        put(
            &mut fake.bytes,
            0x3018,
            &0xffff_f801_cd60_0638u64.to_le_bytes(),
        );

        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        assert_eq!(image.iat_directory, (0x3000, 0x20));
        let slots = read_import_address_table(&image, |at, len| fake.read(at, len))
            .expect("the table reads");
        assert_eq!(
            slots,
            vec![
                IatSlot {
                    slot: BASE + 0x3000,
                    value: 0xffff_f801_cdeb_8670
                },
                IatSlot {
                    slot: BASE + 0x3008,
                    value: 0xffff_f801_cdd8_4f30
                },
                IatSlot {
                    slot: BASE + 0x3018,
                    value: 0xffff_f801_cd60_0638
                },
            ]
        );
    }

    /// An image that declares no address table has none, and one whose declaration does not
    /// describe a table is refused rather than read as an empty one.
    #[test]
    fn test_an_import_address_table_that_does_not_fit_is_refused() {
        let fake = driver_image();
        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        assert_eq!(
            read_import_address_table(&image, |at, len| fake.read(at, len)),
            Ok(Vec::new()),
            "no directory, no slots"
        );

        let refused = |rva: u32, size: u32| {
            let mut image = image.clone();
            image.iat_directory = (rva, size);
            read_import_address_table(&image, |at, len| fake.read(at, len))
        };
        for (rva, size, why) in [
            (0x3000, 0, "an address without a size"),
            (0, 0x20, "a size without an address"),
            (0x3000, 0x1c, "a size that is not a whole number of slots"),
            (0x3ff0, 0x20, "a table running past the end of the image"),
        ] {
            assert!(
                matches!(refused(rva, size), Err(PeError::Malformed { .. })),
                "{why} was read: {:?}",
                refused(rva, size)
            );
        }
    }

    /// An address table that cannot be read says where, rather than coming back empty.
    #[test]
    fn test_an_unreadable_import_address_table_says_where() {
        let mut fake = driver_image();
        put(&mut fake.bytes, 0x1c8, &0x3000u32.to_le_bytes());
        put(&mut fake.bytes, 0x1cc, &0x20u32.to_le_bytes());
        fake.unreadable.push((BASE + 0x3000, BASE + 0x4000));

        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        assert_eq!(
            read_import_address_table(&image, |at, len| fake.read(at, len)),
            Err(PeError::Unreadable {
                at: BASE + 0x3000,
                len: 0x20
            })
        );
    }

    /// The export directory names its own library -- the spelling an importer uses -- and an
    /// image without one has no name to give.
    #[test]
    fn test_the_export_directory_names_its_library() {
        let mut fake = driver_image();
        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        assert_eq!(
            read_export_library_name(&image, |at, len| fake.read(at, len)),
            Ok(None)
        );

        // Export directory [0] at 0x168, forty bytes at 0x2200; its Name RVA is at +12.
        put(&mut fake.bytes, 0x168, &0x2200u32.to_le_bytes());
        put(&mut fake.bytes, 0x16c, &40u32.to_le_bytes());
        put(&mut fake.bytes, 0x220c, &0x2240u32.to_le_bytes());
        put(&mut fake.bytes, 0x2240, b"ntoskrnl.exe\0");
        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        assert_eq!(
            read_export_library_name(&image, |at, len| fake.read(at, len)),
            Ok(Some("ntoskrnl.exe".to_string()))
        );
    }

    /// An executable section running past the image is **clipped**, not dropped.
    ///
    /// Dropping it is a silent truncation of the shape this module refuses everywhere else: the
    /// caller gets a list that looks complete, a whole executable section is missing from it, and
    /// an address inside that section answers "not code" -- so a scan reports nothing dangerous in
    /// a region it never examined. What is past `SizeOfImage` is not this image's code whatever
    /// its header says, so clipping loses nothing and keeps the part that is real.
    ///
    /// Reachable without a malformed header at all: `windbg-mcp` narrows `size_of_image` to the
    /// loader's extent after parsing, which is the smaller and more trustworthy figure on an
    /// untrusted driver, so a section in bounds at parse time is out of them here.
    #[test]
    fn test_an_executable_section_past_the_image_is_clipped_rather_than_dropped() {
        let image = Image {
            base: BASE,
            bitness: Bitness::Bits64,
            machine: 0x8664,
            size_of_image: 0x2000,
            section_alignment: 0x1000,
            sections: vec![
                Section {
                    name: ".text".to_string(),
                    rva: 0x1000,
                    virtual_size: 0x2000, // runs 0x1000 past the end
                    characteristics: 0x6000_0020,
                },
                Section {
                    name: ".gone".to_string(),
                    rva: 0x5000, // starts outside it entirely
                    virtual_size: 0x1000,
                    characteristics: 0x6000_0020,
                },
            ],
            export_directory: (0, 0),
            import_directory: (0, 0),
            iat_directory: (0, 0),
        };

        assert_eq!(
            image.executable_ranges(),
            vec![BASE + 0x1000..BASE + 0x2000],
            "the overrunning section keeps the half that is inside the image, and the one that \
             starts outside it contributes nothing because none of it is inside"
        );
    }

    /// A declared import directory that does not fit the image is refused, not clipped.
    ///
    /// **The silent wrong answer this module is written to avoid, reached without a single read
    /// failing.** The directory starts inside the image and its declared size runs past the end,
    /// so the clipping reader answered out of the part that fit -- twenty bytes, one descriptor,
    /// and if those bytes are zero that is a terminator and the answer is a confident "this driver
    /// imports nothing". Half the directory was outside the image and nothing in the result said
    /// so; a hazard scan over it reports no dangerous imports.
    ///
    /// The length here is the *image's* number, not this module's, which is what separates it from
    /// a name read: `MAX_NAME` is our bound, so a short answer there is legitimate.
    #[test]
    fn test_an_import_directory_running_past_the_image_is_refused_not_clipped() {
        let mut fake = driver_image();
        // Twenty bytes short of the end, declaring forty.
        put(&mut fake.bytes, 0x170, &0x3fecu32.to_le_bytes());
        put(&mut fake.bytes, 0x174, &40u32.to_le_bytes());

        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        assert_eq!(
            read_imports(&image, |at, len| fake.read(at, len), || false),
            Err(PeError::Malformed {
                reason: "the import directory runs past the end of the image",
            })
        );
    }

    /// A header whose machine and magic disagree is refused, not read as the magic says.
    ///
    /// **One byte, and the driver imports nothing.** `Machine` and `Magic` declare the same fact
    /// twice, and everything downstream is keyed on the second alone -- the directory count, the
    /// directories, the width of a thunk. Flip an x64 image's magic to PE32 and the count is read
    /// from `optional + 92`, which in a PE32+ header is inside a field that is zero there, so the
    /// image reports no data directories and therefore no imports. Nothing fails; a hazard scan
    /// sees a driver that imports nothing.
    ///
    /// An unrecognised machine is deliberately *not* refused -- see the list in `read_image`,
    /// which is the machines whose width is known rather than the machines that exist.
    #[test]
    fn test_a_machine_and_magic_that_disagree_are_refused() {
        let mut fake = driver_image();
        // The fixture is AMD64; say PE32 in the optional header and leave the machine alone.
        put(&mut fake.bytes, 0xf8, &0x10bu16.to_le_bytes());

        assert_eq!(
            read_image(BASE, |at, len| fake.read(at, len)),
            Err(PeError::Malformed {
                reason: "the machine and the optional header disagree about the image's width",
            })
        );
    }

    /// And a machine this does not recognise is still parsed, on the magic's word.
    ///
    /// The pair above is a contradiction between two things this knows; an unknown machine is not
    /// a contradiction, and refusing it would make a future architecture a corrupt image.
    #[test]
    fn test_an_unrecognised_machine_is_read_rather_than_refused() {
        let mut fake = driver_image();
        put(&mut fake.bytes, 0xe4, &0x5032u16.to_le_bytes());

        let image = read_image(BASE, |at, len| fake.read(at, len))
            .expect("an unknown machine is not a contradiction");
        assert_eq!(image.machine, 0x5032);
        assert_eq!(image.bitness, Bitness::Bits64);
    }

    /// A descriptor with no name, or no address table, is refused rather than read as RVA zero.
    ///
    /// **Zero is not an RVA a real descriptor carries, and both fields were read as offsets.** A
    /// zero `Name` reads RVA 0 -- the `MZ` header -- so the library comes back called `MZ`. A zero
    /// `FirstThunk` puts every one of that library's slots at the image base, which a call-site
    /// scanner matches against nothing. Both return `Ok`, and the driver's real imports are simply
    /// not in the answer.
    ///
    /// A zero `OriginalFirstThunk` is deliberately not in this rule: that is a bound import, which
    /// has an answer of its own -- see the `unnamed_libraries` test.
    #[test]
    fn test_a_descriptor_missing_its_name_or_its_address_table_is_refused() {
        let mut without_name = driver_image();
        put(&mut without_name.bytes, 0x200c, &0u32.to_le_bytes());
        let image = read_image(BASE, |at, len| without_name.read(at, len)).expect("headers read");
        assert_eq!(
            read_imports(&image, |at, len| without_name.read(at, len), || false),
            Err(PeError::Malformed {
                reason: "an import descriptor names no library",
            })
        );

        let mut without_iat = driver_image();
        put(&mut without_iat.bytes, 0x2010, &0u32.to_le_bytes());
        let image = read_image(BASE, |at, len| without_iat.read(at, len)).expect("headers read");
        assert_eq!(
            read_imports(&image, |at, len| without_iat.read(at, len), || false),
            Err(PeError::Malformed {
                reason: "an import descriptor has no import address table",
            })
        );
    }

    /// A header read whose **span** leaves the address space is refused before the reader sees it.
    ///
    /// **The other half of the rule `checked_va` already followed, and the half that was missed.**
    /// Round three made `checked_va` validate a whole span; the header reader kept checking only
    /// where a read *starts*, so a base thirty-two bytes below the top of the address space passed
    /// the check and then asked `read` for sixty-four bytes that do not exist. A reader computing
    /// the end panics or wraps; the DbgEng adapter merely answers `Unreadable`, which reports a
    /// malformed address as a memory that would not read.
    ///
    /// `va` takes the length now, so neither reader can check a start alone.
    #[test]
    fn test_a_header_read_running_off_the_address_space_is_refused() {
        let mut asked = 0usize;
        let outcome = {
            let read = |_address: u64, len: usize| -> Option<Vec<u8>> {
                asked += 1;
                Some(vec![0u8; len])
            };
            // The first read is the DOS header: sixty-four bytes, from thirty-two below the top.
            read_image(u64::MAX - 32, read)
        };

        assert_eq!(
            outcome,
            Err(PeError::Malformed {
                reason: "an image address overflowed",
            })
        );
        assert_eq!(
            asked, 0,
            "the reader is never asked for a span that cannot exist"
        );
    }

    /// An executable section covers what the **loader** maps, not its exact byte count.
    ///
    /// `VirtualSize` is the section's exact size and the loader maps and protects in
    /// `SectionAlignment` units, so a `.text` of `0x1234` bytes occupies `0x2000` of executable
    /// address space. Stopping at `0x1234` leaves that tail in no range at all -- and the one
    /// thing that reads these ranges is a containment test for jump-table targets, so an address
    /// in mapped, executable memory would answer "not code" and the case would be dropped.
    ///
    /// **`SizeOfRawData` is deliberately not part of this.** It is a file size, padded or trimmed
    /// by `FileAlignment`; where it exceeds the rounded virtual size the excess is not separately
    /// mapped, and taking it as extent would run one section into the next one's address space.
    #[test]
    fn test_an_executable_section_covers_the_extent_the_loader_maps() {
        let image = |alignment: u32, virtual_size: u32| Image {
            base: BASE,
            bitness: Bitness::Bits64,
            machine: 0x8664,
            size_of_image: 0x8000,
            section_alignment: alignment,
            sections: vec![Section {
                name: ".text".to_string(),
                rva: 0x1000,
                virtual_size,
                characteristics: 0x6000_0020,
            }],
            export_directory: (0, 0),
            import_directory: (0, 0),
            iat_directory: (0, 0),
        };

        assert_eq!(
            image(0x1000, 0x1234).executable_ranges(),
            vec![BASE + 0x1000..BASE + 0x3000],
            "0x1234 bytes occupy two aligned pages"
        );
        assert_eq!(
            image(0x1000, 0x1000).executable_ranges(),
            vec![BASE + 0x1000..BASE + 0x2000],
            "an already-aligned size is not rounded up a page"
        );

        // A malformed alignment is not an alignment the loader used, so nothing is rounded to it
        // -- and nothing divides by it either.
        for bad in [0, 3, 0x1001] {
            assert_eq!(
                image(bad, 0x1234).executable_ranges(),
                vec![BASE + 0x1000..BASE + 0x2234],
                "alignment {bad:#x} is not one to round to"
            );
        }

        // And the rounded extent is still the image's to bound.
        let mut narrow = image(0x1000, 0x1234);
        narrow.size_of_image = 0x2800;
        assert_eq!(
            narrow.executable_ranges(),
            vec![BASE + 0x1000..BASE + 0x2800],
            "rounding up does not escape SizeOfImage"
        );
    }

    /// A bound import's address table is bounded too, though its slots are never listed.
    ///
    /// A descriptor with no lookup table is a bound import, and this records the library by name
    /// rather than skipping it. It used to record it with nothing having checked `FirstThunk`
    /// beyond its being non-zero, so an image pointing that table past its own end came back as
    /// one this merely could not name every import of. The named path one loop below bounds a slot
    /// *because a caller attributes the address to this image*, which is no less true of a
    /// descriptor whose slots are never listed.
    #[test]
    fn test_a_bound_imports_address_table_is_bounded_as_well() {
        let mut fake = driver_image();
        put(&mut fake.bytes, 0x2000, &0u32.to_le_bytes()); // no lookup table: a bound import
        put(&mut fake.bytes, 0x2010, &0x9000u32.to_le_bytes()); // an IAT past SizeOfImage

        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        assert_eq!(
            read_imports(&image, |at, len| fake.read(at, len), || false),
            Err(PeError::Malformed {
                reason: "an image offset points outside the image",
            })
        );
    }

    /// A section alignment that is not a unit a loader maps in refuses the image.
    ///
    /// **Not a fallback to `VirtualSize`, which is what this did first.** Falling back reproduced
    /// the under-reporting the alignment is read for: the mapped executable tail in no range, and
    /// a scan that looks complete without it. There is no figure to answer with when the unit is
    /// unknown, so the answer is none.
    #[test]
    fn test_a_section_alignment_that_is_not_a_power_of_two_is_refused() {
        for bad in [0u32, 3, 0x1001] {
            let mut fake = driver_image();
            put(&mut fake.bytes, 0xf8 + 32, &bad.to_le_bytes());
            assert_eq!(
                read_image(BASE, |at, len| fake.read(at, len)),
                Err(PeError::Malformed {
                    reason: "the section alignment is not a unit a loader maps in",
                }),
                "alignment {bad:#x}"
            );
        }
    }

    /// A name that is not text is an error, not a name with the bad bytes rewritten.
    ///
    /// **A lossy rendering standing in as a key**, which this crate has now got wrong three times
    /// in three places -- pool tags, object names, and here. `from_utf8_lossy` turns one corrupt
    /// byte in `ExAllocatePool2` into a *different* string and returns it as the name, with
    /// nothing marking it altered. The only consumer matches these against a sink list by exact
    /// name, so the rewritten form fails to match and a hazardous import reads as absent.
    #[test]
    fn test_a_name_that_is_not_text_is_refused_rather_than_rewritten() {
        let mut fake = driver_image();
        // One byte of `ExAllocatePool2`, replaced by a lone continuation byte.
        put(&mut fake.bytes, 0x2112 + 2, &[0x80]);

        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        assert_eq!(
            read_imports(&image, |at, len| fake.read(at, len), || false),
            Err(PeError::Malformed {
                reason: "an import or library name is not text",
            })
        );
    }

    /// An ordinal thunk carries its flag and its ordinal, and nothing in between.
    ///
    /// Masking to the low sixteen bits answered for *any* thunk with the flag set, so a thunk
    /// carrying a name RVA above `0xffff` -- which is every real one -- came back as a fabricated
    /// ordinal made of its low half, and the name that was really there was lost. An exact-name
    /// scan then misses that API with nothing to say why.
    ///
    /// **The review that found this proposed `0x2110` with the flag set, and that is not the
    /// case**: `0x2110` fits the low sixteen bits, so flag-plus-`0x2110` is an ordinary ordinal
    /// thunk for ordinal 8464 and has to keep reading as one. The rule is about the bits *between*
    /// the flag and the ordinal, so the fixture sets one -- and the reviewer's own value is pinned
    /// below as a thunk that must still read, since a fix that refused it would be a new defect.
    #[test]
    fn test_an_ordinal_thunk_with_reserved_bits_set_is_refused() {
        let mut fake = driver_image();
        // Ordinal flag, a reserved bit at 32, and a low half that would pass for an ordinal.
        put(
            &mut fake.bytes,
            0x2040,
            &0x8000_0001_0000_2110u64.to_le_bytes(),
        );

        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        assert_eq!(
            read_imports(&image, |at, len| fake.read(at, len), || false),
            Err(PeError::Malformed {
                reason: "an ordinal import sets bits that are neither its flag nor its ordinal",
            })
        );

        // Flag and low bits only still reads, including the value the review took for malformed.
        for (thunk, ordinal) in [
            (0x8000_0000_0000_0007u64, 7u16),
            (0x8000_0000_0000_2110u64, 0x2110),
        ] {
            let mut good = driver_image();
            put(&mut good.bytes, 0x2040, &thunk.to_le_bytes());
            let image = read_image(BASE, |at, len| good.read(at, len)).expect("the headers read");
            let table =
                read_imports(&image, |at, len| good.read(at, len), || false).expect("reads");
            assert_eq!(table.imports[0].name, ImportName::Ordinal(ordinal));
        }
    }

    /// The rule this module exists for: an import is named without its slot ever being read.
    ///
    /// The import address table is unreadable here, which is not contrived — it is what a kernel
    /// minidump does. Measured against `docs/samples/081226-2187-01.dmp`: the driver's code and
    /// read-only data come back once an image search path is set, and `dps mountmgr+0x9000 L6` is
    /// six rows of `????????` on that same session, because the table is writable and its runtime
    /// contents were never captured.
    #[test]
    fn test_imports_are_named_without_reading_the_import_address_table() {
        let mut fake = driver_image();
        fake.unreadable.push((BASE + 0x3000, BASE + 0x4000));

        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        let imports = read_imports(&image, |at, len| fake.read(at, len), || false)
            .expect("imports read")
            .imports;

        assert_eq!(imports.len(), 3, "{imports:#?}");
        assert!(imports.iter().all(|i| i.library == "ntoskrnl.exe"));
        assert_eq!(
            imports
                .iter()
                .map(|i| i.name.to_string())
                .collect::<Vec<_>>(),
            vec!["ExAllocatePool2", "ProbeForRead", "#7"]
        );
        // The slots are arithmetic over FirstThunk, which is why they are answerable at all.
        assert_eq!(
            imports.iter().map(|i| i.slot).collect::<Vec<_>>(),
            vec![BASE + 0x3000, BASE + 0x3008, BASE + 0x3010]
        );
    }

    /// The inverse: with the *lookup* table unreadable there is nothing to name a slot with, and
    /// that is an error rather than an empty list.
    ///
    /// An empty list renders as "this driver imports nothing", which is the one answer a hazard
    /// scan must never give for a driver whose pages were simply not captured.
    #[test]
    fn test_an_unreadable_lookup_table_is_an_error_rather_than_no_imports() {
        let mut fake = driver_image();
        fake.unreadable.push((BASE + 0x2040, BASE + 0x2060));

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let error = read_imports(&image, |at, len| fake.read(at, len), || false)
            .expect_err("an unreadable lookup table must not read as an empty import table");
        assert!(matches!(error, PeError::Unreadable { .. }), "{error:?}");
    }

    /// The section table, with the two flags the analyses branch on.
    #[test]
    fn test_sections_carry_the_flags_a_scan_is_bounded_by() {
        let fake = driver_image();
        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();

        assert_eq!(image.bitness, Bitness::Bits64);
        assert_eq!(image.machine, 0x8664);
        assert_eq!(image.size_of_image, 0x4000);
        assert_eq!(
            image
                .sections
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec![".text", ".rdata", ".data"]
        );

        let code = image.code_sections().collect::<Vec<_>>();
        assert_eq!(code.len(), 1);
        assert_eq!(code[0].name, ".text");
        assert!(
            !code.iter().any(|s| s.name == ".data"),
            "a writable section is not code and is never decoded: {code:?}"
        );

        // And as ranges, which is what an address recovered as code is checked against. The end
        // is the start plus the section's size: `checked_va` answers with the **start** and
        // validates the span, so reading its answer as the end makes every section empty -- which
        // is how this first shipped, and it took `mountmgr`'s two switch tables with it.
        let ranges = image.executable_ranges();
        assert_eq!(ranges, vec![BASE + 0x1000..BASE + 0x2000]);
        assert!(ranges.iter().any(|range| range.contains(&(BASE + 0x1500))));
        assert!(
            !ranges.iter().any(|range| range.contains(&(BASE + 0x2500))),
            "`.rdata` is inside the module and is not code"
        );
    }

    /// A driver with no import directory imports nothing, and that is not an error — but it is
    /// reported only for a directory the headers say is absent, never for one that would not read.
    #[test]
    fn test_an_absent_import_directory_is_no_imports() {
        let mut fake = driver_image();
        put(&mut fake.bytes, 0x170, &0u32.to_le_bytes());
        put(&mut fake.bytes, 0x174, &0u32.to_le_bytes());

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        assert_eq!(
            read_imports(&image, |at, len| fake.read(at, len), || false).unwrap(),
            ImportTable::default()
        );
    }

    /// A slot belongs to **one** import, and two claiming it is refused.
    ///
    /// A slot holds one function pointer, so two names claiming it is a structure that does not
    /// hold together — and an index keyed by slot can only silently keep the last one, which makes
    /// every call through that address an arbitrary choice between the two, reported as a fact.
    /// The other name then reports no call sites at all, which reads as an import the driver never
    /// uses.
    #[test]
    fn test_two_imports_claiming_one_slot_are_refused() {
        let mut fake = driver_image();
        // A second library whose `FirstThunk` is the first one's, so their slots collide.
        put(&mut fake.bytes, 0x2014, &0x2060u32.to_le_bytes()); // OriginalFirstThunk
        put(&mut fake.bytes, 0x2014 + 12, &0x2100u32.to_le_bytes()); // Name
        put(&mut fake.bytes, 0x2014 + 16, &0x3000u32.to_le_bytes()); // FirstThunk: the same
        put(&mut fake.bytes, 0x2028, &[0u8; 20]); // terminator moves along
        put(&mut fake.bytes, 0x174, &60u32.to_le_bytes()); // three descriptor slots
        // Its lookup table names one import and ends.
        put(&mut fake.bytes, 0x2060, &0x2120u64.to_le_bytes());
        put(&mut fake.bytes, 0x2068, &0u64.to_le_bytes());

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let read = read_imports(&image, |at, len| fake.read(at, len), || false);
        assert!(
            matches!(read, Err(PeError::Malformed { .. })),
            "a slot claimed twice is refused rather than resolved to whichever came last: {read:?}"
        );
    }

    /// The **total** is bounded too, which neither of the other two limits does.
    ///
    /// Sixty-four libraries of eight thousand imports each is within both of them and is half a
    /// million owned names and library strings — hundreds of megabytes held before a consumer sees
    /// one, on an image nobody chose to trust. The bound is checked as the table grows rather than
    /// after it, because a limit enforced on a finished list is a limit enforced after the memory
    /// was already spent.
    #[test]
    fn test_the_total_number_of_imports_is_bounded_as_the_table_grows() {
        // **Three libraries**, each just inside the per-library limit and summing past the total.
        // One library cannot test this: a table long enough to cross the total runs into
        // `MAX_IMPORTS_PER_LIBRARY` first, so the first draft of this fixture was green against a
        // build with no total bound at all -- passing on the neighbouring rule.
        let per_library = MAX_IMPORTS_PER_LIBRARY - 1;
        assert!(
            per_library * 3 > MAX_IMPORTS_TOTAL,
            "the fixture must be able to cross the total without crossing the per-library limit"
        );
        let mut fake = driver_image();
        fake.bytes.resize(0x80000, 0);
        put(&mut fake.bytes, 0xf8 + 56, &0x80000u32.to_le_bytes()); // SizeOfImage
        put(&mut fake.bytes, 0x174, &80u32.to_le_bytes()); // import directory size: four slots
        for library in 0..3usize {
            let descriptor = 0x2000 + library * 20;
            let lookup = 0x10000 + library * 0x20000;
            put(&mut fake.bytes, descriptor, &(lookup as u32).to_le_bytes());
            put(&mut fake.bytes, descriptor + 12, &0x2100u32.to_le_bytes());
            put(
                &mut fake.bytes,
                descriptor + 16,
                &((0x60000 + library * 0x8000) as u32).to_le_bytes(),
            );
            for index in 0..per_library {
                put(
                    &mut fake.bytes,
                    lookup + index * 8,
                    &0x2110u64.to_le_bytes(),
                );
            }
            put(
                &mut fake.bytes,
                lookup + per_library * 8,
                &0u64.to_le_bytes(),
            );
        }
        put(&mut fake.bytes, 0x2000 + 3 * 20, &[0u8; 20]);

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let read = read_imports(&image, |at, len| fake.read(at, len), || false);
        assert!(
            matches!(read, Err(PeError::Malformed { .. })),
            "a table this large is refused rather than built: {read:?}"
        );
    }

    /// The library limit counts libraries, and the terminator is not one.
    ///
    /// An import directory holding `MAX_LIBRARIES` libraries has `MAX_LIBRARIES + 1` descriptors,
    /// the all-zero one that ends the array being a descriptor and not a library. A bound compared
    /// against the raw slot count is therefore off by one against the sentence it enforces, and
    /// refuses the very image the limit was written to permit — reported as malformed, which is
    /// the answer that stops a hazard scan rather than shortening it.
    #[test]
    fn test_the_library_limit_leaves_room_for_the_descriptor_that_ends_the_array() {
        /// Builds an image whose import directory holds `libraries` real descriptors plus the
        /// terminator, every one of them naming the same library and the same single import.
        fn image_importing(libraries: usize) -> FakeImage {
            let mut fake = driver_image();
            let size = (libraries + 1) * 20;
            put(&mut fake.bytes, 0x170, &0x2000u32.to_le_bytes());
            put(&mut fake.bytes, 0x174, &(size as u32).to_le_bytes());
            for index in 0..libraries {
                let at = 0x2000 + index * 20;
                put(&mut fake.bytes, at, &0x2600u32.to_le_bytes()); // OriginalFirstThunk
                put(&mut fake.bytes, at + 12, &0x2700u32.to_le_bytes()); // Name
                let iat = 0x3000 + (index as u32) * 8;
                put(&mut fake.bytes, at + 16, &iat.to_le_bytes()); // FirstThunk
            }
            // The terminator, and the one lookup table and name every descriptor shares.
            put(&mut fake.bytes, 0x2000 + libraries * 20, &[0u8; 20]);
            put(&mut fake.bytes, 0x2600, &0x2710u64.to_le_bytes());
            put(&mut fake.bytes, 0x2608, &0u64.to_le_bytes());
            put(&mut fake.bytes, 0x2700, b"lib.sys\0");
            put(&mut fake.bytes, 0x2712, b"Func\0");
            fake
        }

        let fake = image_importing(MAX_LIBRARIES);
        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let table = read_imports(&image, |at, len| fake.read(at, len), || false)
            .expect("an image with exactly the permitted number of libraries is not malformed");
        assert_eq!(table.imports.len(), MAX_LIBRARIES);

        // One more library is one more than the limit, and is refused as it always was.
        let fake = image_importing(MAX_LIBRARIES + 1);
        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        assert!(matches!(
            read_imports(&image, |at, len| fake.read(at, len), || false),
            Err(PeError::Malformed { .. })
        ));
    }

    /// An image that declares no data directories has none, and the section table is not one.
    ///
    /// `NumberOfRvaAndSizes` and `SizeOfOptionalHeader` both bound where the directories stop, and
    /// what sits immediately after the optional header is the **section table** — so reading a
    /// directory index unconditionally does not read a zero, it reads a section header. Here the
    /// bytes that would be taken for the import directory are `.text`'s `VirtualSize` and
    /// `VirtualAddress`, which spell a 4 KB directory naming 204 libraries: a perfectly valid
    /// driver reported as malformed. Turn those two fields into a plausible descriptor table
    /// instead and it is reported as importing functions it does not import.
    #[test]
    fn test_an_image_declaring_no_data_directories_has_none() {
        let mut fake = driver_image();
        // A PE32+ optional header carrying the standard fields and no directories at all: 112
        // bytes, which puts the section table exactly where directory [0] used to be.
        put(&mut fake.bytes, 0xf4, &112u16.to_le_bytes()); // SizeOfOptionalHeader
        put(&mut fake.bytes, 0x164, &0u32.to_le_bytes()); // NumberOfRvaAndSizes
        // The section table moves with it, to 0xe0 + 24 + 112 = 0x168.
        let section = |bytes: &mut Vec<u8>, index: usize, name: &[u8], rva: u32| {
            let at = 0x168 + index * 40;
            put(bytes, at, name);
            put(bytes, at + 8, &0x1000u32.to_le_bytes()); // VirtualSize
            put(bytes, at + 12, &rva.to_le_bytes()); // VirtualAddress
            put(bytes, at + 36, &0x6000_0020u32.to_le_bytes());
        };
        section(&mut fake.bytes, 0, b".text\0\0\0", 0x1000);
        section(&mut fake.bytes, 1, b".rdata\0\0", 0x2000);
        section(&mut fake.bytes, 2, b".data\0\0\0", 0x3000);

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        assert_eq!(
            image.import_directory,
            (0, 0),
            "the first section header is not a data directory"
        );
        assert_eq!(image.export_directory, (0, 0));
        assert_eq!(image.sections.len(), 3, "and the sections still read");
        assert_eq!(
            read_imports(&image, |at, len| fake.read(at, len), || false).unwrap(),
            ImportTable::default(),
            "a valid image with no import directory imports nothing, and is not malformed"
        );

        // The two bounds are independent, and this is the case where they disagree: a header
        // declaring sixteen directories in a space with room for none. The count is not the last
        // word — the room is — so the entry is still absent rather than read out of the section
        // table behind it.
        put(&mut fake.bytes, 0x164, &16u32.to_le_bytes());
        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        assert_eq!(
            image.import_directory,
            (0, 0),
            "a directory the header has no room for is not there, whatever it declares"
        );

        // And a header ending before `NumberOfRvaAndSizes` is not an optional header at all. Read
        // anyway, the count itself would come out of the section table — here the four bytes of
        // `.text`'s name — so this is refused rather than parsed around.
        put(&mut fake.bytes, 0xf4, &108u16.to_le_bytes());
        assert!(
            matches!(
                read_image(BASE, |at, len| fake.read(at, len)),
                Err(PeError::NotAnImage { .. })
            ),
            "an optional header too short to hold its own fields is not one"
        );
    }

    /// Absent is **both** coordinates zero. One without the other is a contradiction, and the
    /// tempting reading of it — "close enough to absent" — is the silent wrong answer: a nonzero
    /// RVA with a zero size hides a real descriptor table, and a hazard scan over the result
    /// reports a driver that imports nothing dangerous because it read nothing at all.
    #[test]
    fn test_an_import_directory_with_one_coordinate_missing_is_refused() {
        for (rva, size, what) in [
            (0x2000u32, 0u32, "an address with no size"),
            (0, 40, "a size with no address"),
        ] {
            let mut fake = driver_image();
            put(&mut fake.bytes, 0x170, &rva.to_le_bytes());
            put(&mut fake.bytes, 0x174, &size.to_le_bytes());

            let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
            let read = read_imports(&image, |at, len| fake.read(at, len), || false);
            assert!(
                matches!(read, Err(PeError::Malformed { .. })),
                "{what} is not an absent directory: {read:?}"
            );
        }
    }

    /// A slot this crate never dereferences is still bounded by the image.
    ///
    /// The import address table is the one address here that is *reported* rather than read, and
    /// that is exactly why the bound is easy to leave off it. It does not help: a caller matching
    /// an indirect call against these slots attributes them to this image, so a `FirstThunk`
    /// running past the end would name a neighbouring module's memory as this driver's import.
    /// The read side cannot catch it, because there is no read.
    #[test]
    fn test_an_import_slot_past_the_end_of_the_image_is_refused_though_it_is_never_read() {
        let mut fake = driver_image();
        // Eight bytes short of the end: the first slot fits exactly, the second does not.
        put(&mut fake.bytes, 0x2010, &0x3ff8u32.to_le_bytes());
        // And nothing in that range reads, which is what says the refusal came from the bound.
        fake.unreadable.push((BASE + 0x3ff8, BASE + 0x4008));

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        assert_eq!(image.size_of_image, 0x4000);
        let read = read_imports(&image, |at, len| fake.read(at, len), || false);
        assert!(
            matches!(read, Err(PeError::Malformed { .. })),
            "a slot past the image must not be handed back as this image's: {read:?}"
        );
    }

    /// A library with no lookup table is **named as unnameable**, not silently skipped.
    ///
    /// A bound import has real slots and no `OriginalFirstThunk`, so its names live only in the
    /// import address table this deliberately does not read. Dropping it would tell a hazard scan
    /// that the driver imports fewer functions than it does — and "imports no dangerous API" is
    /// exactly the answer that must never come from silence.
    #[test]
    fn test_a_library_with_no_lookup_table_is_reported_rather_than_skipped() {
        let mut fake = driver_image();
        // Clear OriginalFirstThunk, leaving the name and the IAT: a bound import.
        put(&mut fake.bytes, 0x2000, &0u32.to_le_bytes());

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let table = read_imports(&image, |at, len| fake.read(at, len), || false).unwrap();

        assert!(
            table.imports.is_empty(),
            "nothing can be named without a lookup table: {table:?}"
        );
        assert_eq!(
            table.unnamed_libraries,
            vec!["ntoskrnl.exe".to_string()],
            "the library must be reported, not dropped: {table:?}"
        );
    }

    /// An import directory that overruns its bound is refused, not truncated.
    ///
    /// Reading the first `MAX_LIBRARIES` and returning `Ok` drops the rest in silence, and a
    /// hazard scan reading that concludes a dangerous import is absent when it is merely past the
    /// cut. Same for a directory whose size runs out before its null descriptor: the libraries
    /// past the end are exactly the ones a truncating read would have lost.
    #[test]
    fn test_an_import_directory_that_overruns_its_bound_is_refused() {
        // A size claiming far more descriptors than an image plausibly has.
        let mut oversized = driver_image();
        put(&mut oversized.bytes, 0x174, &(20u32 * 4096).to_le_bytes());
        let image = read_image(BASE, |at, len| oversized.read(at, len)).unwrap();
        assert!(
            matches!(
                read_imports(&image, |at, len| oversized.read(at, len), || false),
                Err(PeError::Malformed { .. })
            ),
            "an oversized directory must not read as a short one"
        );

        // A size that stops before the null descriptor: exactly one descriptor, no terminator.
        let mut unterminated = driver_image();
        put(&mut unterminated.bytes, 0x174, &20u32.to_le_bytes());
        let image = read_image(BASE, |at, len| unterminated.read(at, len)).unwrap();
        assert!(
            matches!(
                read_imports(&image, |at, len| unterminated.read(at, len), || false),
                Err(PeError::Malformed { .. })
            ),
            "a directory with no terminator inside its size must not read as complete"
        );
    }

    /// A per-library list that runs out of entries, and a name that runs out of bytes, are both
    /// refused rather than shortened.
    ///
    /// Same rule as the directory bound, one level down, and the same consequence for a hazard
    /// scan: an import list cut at its cap omits every later function in silence, and a name taken
    /// without its terminator becomes a *different* string that a sink list will not match. Either
    /// way the answer is "that API is not imported" and the truncation leaves no trace.
    #[test]
    fn test_a_list_or_a_name_that_overruns_its_bound_is_refused() {
        // A lookup table with no zero terminator inside the per-library cap. Filled with a valid
        // ordinal entry so every entry decodes and only the missing terminator is at issue.
        let mut endless = driver_image();
        let ordinal = 0x8000_0000_0000_0007u64.to_le_bytes();
        for slot in 0..(MAX_IMPORTS_PER_LIBRARY + 1) {
            put(&mut endless.bytes, 0x2040 + slot * 8, &ordinal);
        }
        let image = read_image(BASE, |at, len| endless.read(at, len)).unwrap();
        assert!(
            matches!(
                read_imports(&image, |at, len| endless.read(at, len), || false),
                Err(PeError::Malformed { .. })
            ),
            "an import list that fills its cap must not read as a complete one"
        );

        // A name with no NUL for the whole bounded read.
        let mut endless_name = driver_image();
        for offset in 0..(MAX_NAME + 8) {
            put(&mut endless_name.bytes, 0x2112 + offset, b"A");
        }
        let image = read_image(BASE, |at, len| endless_name.read(at, len)).unwrap();
        assert!(
            matches!(
                read_imports(&image, |at, len| endless_name.read(at, len), || false),
                Err(PeError::Malformed { .. })
            ),
            "a name with no terminator must not be accepted truncated"
        );
    }

    /// An import table that points outside the image is refused, not answered from a neighbour.
    ///
    /// On a live target the memory just past a driver is *the next module*, which reads perfectly
    /// well — so an RVA past `SizeOfImage` added blindly to the base gives a read that succeeds
    /// and describes something else entirely. The image's "imports" would then be another
    /// module's bytes, with nothing in the answer to say so.
    #[test]
    fn test_an_import_table_pointing_outside_the_image_is_refused() {
        // The lookup table moved past the end of the image, into what would be the next module.
        let mut outside = driver_image();
        put(&mut outside.bytes, 0x2000, &0x9000u32.to_le_bytes());
        let image = read_image(BASE, |at, len| outside.read(at, len)).unwrap();
        assert_eq!(image.size_of_image, 0x4000);
        assert!(
            matches!(
                read_imports(&image, |at, len| outside.read(at, len), || false),
                Err(PeError::Malformed { .. })
            ),
            "an RVA past the image must not be read from whatever is mapped there"
        );
    }

    /// The table ends at an **all-zero** descriptor, which is five fields and not three.
    ///
    /// A descriptor with a leftover stamp or forwarder chain, and zeroes elsewhere, would end the
    /// table early — dropping every library after it in the silence this module keeps promising
    /// not to.
    #[test]
    fn test_a_descriptor_is_a_terminator_only_when_every_field_is_zero() {
        let mut stamped = driver_image();
        // The terminator at 0x2014 keeps a nonzero TimeDateStamp, and a second real library
        // follows it, so ending early is visible as a missing import rather than as an error.
        put(&mut stamped.bytes, 0x2014 + 4, &1u32.to_le_bytes());

        let image = read_image(BASE, |at, len| stamped.read(at, len)).unwrap();
        let read = read_imports(&image, |at, len| stamped.read(at, len), || false);
        assert!(
            matches!(read, Err(PeError::Malformed { .. })),
            "a descriptor that is not all-zero must not end the table: {read:?}"
        );
    }

    /// Headers that will not read are unreadable; bytes that are not an image are refused. The
    /// two are different outcomes because their remedies are — one is an image search path, the
    /// other is a wrong address.
    #[test]
    fn test_an_unreadable_header_and_a_non_image_are_told_apart() {
        let nothing =
            read_image(BASE, |_, _| None).expect_err("a reader answering nothing must not parse");
        assert!(matches!(nothing, PeError::Unreadable { .. }), "{nothing:?}");

        let mut rubbish = driver_image();
        put(&mut rubbish.bytes, 0x00, b"XX");
        let refused = read_image(BASE, |at, len| rubbish.read(at, len))
            .expect_err("bytes with no MZ must not parse");
        assert!(matches!(refused, PeError::NotAnImage { .. }), "{refused:?}");
    }

    /// PE32 puts its data directories sixteen bytes earlier than PE32+ does. Reading a 32-bit
    /// driver at the 64-bit offset finds an import directory of zero — no imports and no error,
    /// with nothing to say a whole architecture was misread.
    #[test]
    fn test_a_32_bit_image_reads_its_directories_at_the_32_bit_offset() {
        let mut fake = driver_image();
        put(&mut fake.bytes, 0xf8, &0x10bu16.to_le_bytes()); // PE32
        put(&mut fake.bytes, 0xe4, &0x014cu16.to_le_bytes()); // i386
        // NumberOfRvaAndSizes moves with them, to 0xf8 + 92 = 0x154; the 64-bit slot is cleared
        // for the same reason the directories below are.
        put(&mut fake.bytes, 0x154, &16u32.to_le_bytes());
        put(&mut fake.bytes, 0x164, &0u32.to_le_bytes());
        // Directories move to 0xf8 + 96 = 0x158, and the 64-bit slot is cleared, so a parser
        // reading the wrong one finds nothing rather than the right answer by accident.
        put(&mut fake.bytes, 0x158 + 8, &0x2000u32.to_le_bytes());
        put(&mut fake.bytes, 0x158 + 12, &40u32.to_le_bytes());
        put(&mut fake.bytes, 0x170, &0u32.to_le_bytes());
        put(&mut fake.bytes, 0x174, &0u32.to_le_bytes());
        // A 32-bit lookup table is four bytes an entry.
        put(&mut fake.bytes, 0x2040, &0x2110u32.to_le_bytes());
        put(&mut fake.bytes, 0x2044, &0x2120u32.to_le_bytes());
        put(&mut fake.bytes, 0x2048, &0u32.to_le_bytes());

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        assert_eq!(image.bitness, Bitness::Bits32);
        assert_eq!(image.import_directory, (0x2000, 40));

        let imports = read_imports(&image, |at, len| fake.read(at, len), || false)
            .unwrap()
            .imports;
        assert_eq!(
            imports
                .iter()
                .map(|i| i.name.to_string())
                .collect::<Vec<_>>(),
            vec!["ExAllocatePool2", "ProbeForRead"]
        );
        // Four-byte slots, not eight.
        assert_eq!(
            imports.iter().map(|i| i.slot).collect::<Vec<_>>(),
            vec![BASE + 0x3000, BASE + 0x3004]
        );
    }

    /// A halt is honoured inside the walk, because a bounded loop still needs a check in it.
    #[test]
    fn test_a_halt_stops_the_import_walk() {
        let fake = driver_image();
        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let error = read_imports(&image, |at, len| fake.read(at, len), || true)
            .expect_err("a halt should stop the walk");
        assert_eq!(error, PeError::Interrupted);
    }

    /// The slot index is what names a call site, so it is built once and looked up by address.
    #[test]
    fn test_imports_index_by_the_slot_a_call_goes_through() {
        let fake = driver_image();
        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let imports = read_imports(&image, |at, len| fake.read(at, len), || false)
            .unwrap()
            .imports;
        let index = imports_by_slot(&imports);

        assert_eq!(
            index.get(&(BASE + 0x3008)).map(|i| i.name.to_string()),
            Some("ProbeForRead".to_string())
        );
        assert!(!index.contains_key(&(BASE + 0x3018)));
    }
}
