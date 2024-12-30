use goblin::pe::section_table::IMAGE_SCN_CNT_CODE;
use goblin::Object;

pub fn get_executable_sections(pe_bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut sections = Vec::new();

    match Object::parse(pe_bytes) {
        Ok(Object::PE(pe)) => {
            for section in pe.sections {
                if section.characteristics & IMAGE_SCN_CNT_CODE != 0 {
                    // Extract section data
                    let start = section.pointer_to_raw_data as usize;
                    let size = section.size_of_raw_data as usize;
                    if start + size <= pe_bytes.len() {
                        let section_data = pe_bytes[start..start + size].to_vec();
                        sections.push(section_data);
                    }
                }
            }
        }
        Ok(_) => eprintln!("[-] Not a PE file"),
        Err(e) => eprintln!("[-] Failed to parse PE file: {}", e),
    }

    if sections.is_empty() {
        eprintln!("[-] No executable sections found");
    } else {
        println!("[+] Found {} executable sections", sections.len());
    }

    sections
}

fn find_gadget_offset(sections: &[Vec<u8>], opcodes: &[u8], kernel_base: usize) -> Option<usize> {
    for section in sections {
        if let Some(pos) = section
            .windows(opcodes.len())
            .position(|window| window == opcodes)
        {
            return Some(pos + kernel_base);
        }
    }
    None
}

pub fn get_gadget_offset(
    sections: &[Vec<u8>],
    opcodes: &[u8],
    kernel_base: usize,
) -> Option<usize> {
    find_gadget_offset(sections, opcodes, kernel_base)
}
