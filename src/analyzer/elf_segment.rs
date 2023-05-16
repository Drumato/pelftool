use super::Analyzer;

impl Analyzer {
    pub(super) fn elf_program_header_table_info_as_json(
        &self,
        pht: Option<elf::segment::SegmentTable<elf::endian::AnyEndian>>,
    ) -> serde_json::Value {
        let Some(pht) = pht else {
            return serde_json::json!({
                "entries": 0,
                "headers": Vec::<serde_json::Value>::new(),
                "exist": false,
            });
        };

        serde_json::json!({
            "entries": pht.len(),
            "headers": pht.iter().map(|ph| self.elf_program_header_info_as_json(ph)).collect::<Vec<serde_json::Value>>(),
            "exist": true,
        })
    }

    fn elf_program_header_info_as_json(
        &self,
        ph: elf::segment::ProgramHeader,
    ) -> serde_json::Value {
        serde_json::json!({
            "type": elf_segment_type_to_string(ph.p_type),
            "flags": elf_segment_flags_to_string(ph.p_type),
            "offset": format!("0x{:x}", ph.p_offset),
            "virtual_address": format!("0x{:x}", ph.p_vaddr),
            "physical_address": format!("0x{:x}", ph.p_paddr),
            "size_in_file": format!("0x{:x}", ph.p_filesz),
            "size_in_memory": format!("0x{:x}", ph.p_memsz),
            "alignment": format!("0x{:x}", ph.p_align),
        })
    }
}

fn elf_segment_type_to_string(p_type: u32) -> String {
    match p_type {
        elf::abi::PT_NULL => "NULL".to_string(),
        elf::abi::PT_LOAD => "LOAD".to_string(),
        elf::abi::PT_DYNAMIC => "DYNAMIC".to_string(),
        elf::abi::PT_INTERP => "INTERP".to_string(),
        elf::abi::PT_NOTE => "NOTE".to_string(),
        elf::abi::PT_SHLIB => "SHLIB".to_string(),
        elf::abi::PT_PHDR => "PHDR".to_string(),
        elf::abi::PT_TLS => "TLS".to_string(),
        elf::abi::PT_GNU_EH_FRAME => "GNU_EH_FRAME".to_string(),
        elf::abi::PT_GNU_STACK => "GNU_STACK".to_string(),
        elf::abi::PT_GNU_RELRO => "GNU_RELRO".to_string(),
        elf::abi::PT_GNU_PROPERTY => "GNU_PROPERTY".to_string(),
        elf::abi::PT_LOOS..=elf::abi::PT_HIOS => "[LOOS, HIOS]".to_string(),
        elf::abi::PT_LOPROC..=elf::abi::PT_HIPROC => "[LOPROC, HIPROC]".to_string(),
        _ => format!("UNKNOWN!(0x{:x})", p_type),
    }
}

const ELF_SEGMENT_FLAG_STRINGS: [(u32, &str); 3] = [
    (elf::abi::PF_R, "READABLE"),
    (elf::abi::PF_W, "WRITABLE"),
    (elf::abi::PF_X, "EXECUTABLE"),
];

fn elf_segment_flags_to_string(p_flags: u32) -> Vec<String> {
    ELF_SEGMENT_FLAG_STRINGS
        .iter()
        .filter(|(flag, _)| {
            if p_flags & flag == 0 {
                return false;
            }

            true
        })
        .map(|(_, s)| s.to_string())
        .collect()
}
