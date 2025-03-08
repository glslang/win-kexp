use goblin::pe::{options::ParseOptions, section_table::IMAGE_SCN_CNT_CODE};
use thiserror::Error;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;

#[macro_export]
macro_rules! create_rop_chain {
    ($base:expr, $($value:expr),+ $(,)?) => {{
        let mut chain = Vec::new();
        chain.extend(iter::repeat(0x90u8).take($base));
        $(
            chain.extend($value.to_le_bytes().iter().cloned());
        )*
        chain
    }};
}

#[macro_export]
macro_rules! create_rop_chain_to_buffer {
    ($buffer:expr, $($value:expr),+ $(,)?) => {{
        let mut offset = 0;
        $(
            let bytes = $value.to_le_bytes();
            $buffer[offset..offset + bytes.len()].copy_from_slice(&bytes);
            offset += bytes.len();
        )*
        offset // Return total bytes written
    }};
}

#[macro_export]
macro_rules! concat_rop_chain_to_buffer {
    ($buffer:expr, $($chain:expr),+ $(,)?) => {{
        let mut total_offset = 0;
        $(
            let chain_bytes = $chain;
            $buffer[total_offset..total_offset + chain_bytes.len()].copy_from_slice(&chain_bytes);
            total_offset += chain_bytes.len();
        )*
        total_offset // Return total bytes written
    }};
}

#[derive(Error, Debug)]
pub enum PeError {
    #[error("Failed to find executable sections")]
    NoExecutableSections,
}

pub fn get_executable_sections(module: HMODULE) -> Result<Vec<(u64, Vec<u8>)>, PeError> {
    let mut sections = Vec::new();

    // Get module information using VirtualQuery
    let dos_header = unsafe { *(module.0 as *const IMAGE_DOS_HEADER) };
    let nt_headers =
        unsafe { *(module.0.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64) };
    let image_size = nt_headers.OptionalHeader.SizeOfImage as usize;

    // Convert module to bytes
    let pe_bytes = unsafe { std::slice::from_raw_parts(module.0 as *const u8, image_size) };

    match goblin::pe::PE::parse_with_opts(
        pe_bytes,
        &ParseOptions {
            resolve_rva: true,
            parse_attribute_certificates: false,
        },
    ) {
        Ok(pe) => {
            for section in pe.sections {
                if section.characteristics & IMAGE_SCN_CNT_CODE != 0 {
                    let start = section.pointer_to_raw_data as usize;
                    let size = section.size_of_raw_data as usize;
                    if start + size <= pe_bytes.len() {
                        let section_data = pe_bytes[start..start + size].to_vec();
                        sections.push((start as u64, section_data));
                    }
                }
            }
        }
        Err(e) => eprintln!("[-] Failed to parse PE file: {}", e),
    }

    if sections.is_empty() {
        return Err(PeError::NoExecutableSections);
    } else {
        println!("[+] Found {} executable sections", sections.len());
    }

    Ok(sections)
}

pub fn find_gadget_offset(
    sections: &Vec<(u64, Vec<u8>)>,
    opcodes: &[u8],
    ntoskrnl_base: u64,
) -> Option<u64> {
    for section in sections {
        if let Some(pos) = section
            .1
            .windows(opcodes.len())
            .position(|window| window == opcodes)
        {
            return Some(section.0 + pos as u64 + ntoskrnl_base);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_gadget_offset() {
        // Create test sections with known gadget
        let test_bytes = vec![
            0x90, 0x90, 0x58, 0xC3, // nop; nop; pop rax; ret
            0x90, 0x90, // padding
        ];
        let sections = vec![(0x1000, test_bytes)];

        // Search for pop rax; ret
        let gadget = &[0x58, 0xC3];
        let ntoskrnl_base = 0xfffff80000000000;

        let result = find_gadget_offset(&sections, gadget, ntoskrnl_base);

        assert!(result.is_some());
        assert_eq!(result.unwrap(), 0xfffff80000001002); // Base + section offset + gadget offset
    }

    #[test]
    fn test_find_gadget_offset_not_found() {
        let test_bytes = vec![0x90, 0x90]; // Just NOPs
        let sections = vec![(0x1000, test_bytes)];

        let gadget = &[0x58, 0xC3]; // pop rax; ret
        let ntoskrnl_base = 0xfffff80000000000;

        let result = find_gadget_offset(&sections, gadget, ntoskrnl_base);

        assert!(result.is_none());
    }

    #[test]
    fn test_concat_rop_chain_to_buffer() {
        let mut buffer = [0u8; 16];
        let chain1 = vec![1u8, 2u8, 3u8, 4u8];
        let chain2 = vec![5u8, 6u8, 7u8, 8u8];

        let written = concat_rop_chain_to_buffer!(&mut buffer, chain1, chain2);

        assert_eq!(written, 8);
        assert_eq!(&buffer[0..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&buffer[8..], &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_concat_rop_chain_to_buffer_single() {
        let mut buffer = [0u8; 8];
        let chain = vec![1u8, 2u8, 3u8, 4u8];

        let written = concat_rop_chain_to_buffer!(&mut buffer, chain);

        assert_eq!(written, 4);
        assert_eq!(&buffer[0..4], &[1, 2, 3, 4]);
        assert_eq!(&buffer[4..], &[0, 0, 0, 0]);
    }
}
