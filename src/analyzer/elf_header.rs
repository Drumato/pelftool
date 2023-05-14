use super::Analyzer;

impl Analyzer {
    pub(super) fn elf_header_info_as_json(
        &self,
        elf_file: &elf::ElfBytes<elf::endian::AnyEndian>,
    ) -> serde_json::Value {
        serde_json::json!({
            "class": elf_class_to_string(&elf_file.ehdr.class),
            "data": elf_data_to_string(&elf_file.ehdr.endianness),
            "version": elf_version_to_string(elf_file.ehdr.version),
            "osabi": elf_osabi_to_string(elf_file.ehdr.osabi),
            "abi_version": elf_abiversion_to_string(elf_file.ehdr.abiversion),
            "type": elf_type_to_string(elf_file.ehdr.e_type),
            "machine": elf_machine_to_string(elf_file.ehdr.e_machine),
            "entry": format!("0x{:x}", elf_file.ehdr.e_entry),
            "program_header_table_offset": format!("0x{:x}", elf_file.ehdr.e_phoff),
            "section_header_table_offset": format!("0x{:x}", elf_file.ehdr.e_shoff),
            "flags": format!("0x{:x}", elf_file.ehdr.e_flags),
            "elf_header_size": format!("0x{:x}", elf_file.ehdr.e_ehsize),
            "program_header_table_entry_size": format!("0x{:x}", elf_file.ehdr.e_phentsize),
            "program_header_table_entries": format!("0x{:x}", elf_file.ehdr.e_phnum),
            "section_header_table_entry_size": format!("0x{:x}", elf_file.ehdr.e_shentsize),
            "section_header_table_entries": format!("0x{:x}", elf_file.ehdr.e_shnum),
            "section_name_strtab_index": format!("0x{:x}", elf_file.ehdr.e_shstrndx),
        })
    }
}

fn elf_class_to_string(class: &elf::file::Class) -> &str {
    match class {
        elf::file::Class::ELF32 => "ELF32",
        elf::file::Class::ELF64 => "ELF64",
    }
}

fn elf_data_to_string<E: elf::endian::EndianParse>(endianness: &E) -> &str {
    if endianness.is_big() {
        "2's complement MSB"
    } else {
        "2's complement LSB"
    }
}

fn elf_version_to_string(version: u32) -> String {
    if version == elf::abi::EV_CURRENT as u32 {
        return "EV_CURRENT".to_string();
    }

    format!("UNKNOWN!(0x{:1})", version)
}

fn elf_osabi_to_string(osabi: u8) -> String {
    // TODO: cover all cases defined in elf::abi.
    match osabi {
        elf::abi::ELFOSABI_SYSV => "UNIX System V".to_string(),
        _ => format!("UNKNOWN!(0x{:x})", osabi),
    }
}

fn elf_abiversion_to_string(abi_version: u8) -> String {
    abi_version.to_string()
}

fn elf_type_to_string(elf_type: u16) -> String {
    match elf_type {
        elf::abi::ET_NONE => "NONE".to_string(),
        elf::abi::ET_REL => "REL".to_string(),
        elf::abi::ET_EXEC => "EXEC".to_string(),
        elf::abi::ET_DYN => "DYN".to_string(),
        elf::abi::ET_CORE => "CORE".to_string(),
        elf::abi::ET_LOOS..=elf::abi::ET_HIOS => "[LOOS, HIOS]".to_string(),
        elf::abi::ET_LOPROC..=elf::abi::ET_HIPROC => "[LOPROC, HIPROC]".to_string(),
        _ => format!("UNKNOWN!(0x{:x})", elf_type),
    }
}

fn elf_machine_to_string(machine: u16) -> String {
    // TODO: cover all cases defined in elf::abi.
    match machine {
        elf::abi::EM_NONE => "NONE".to_string(),
        elf::abi::EM_386 => "Intel 80386".to_string(),
        elf::abi::EM_X86_64 => "AMD x86_64 architecture".to_string(),
        _ => format!("UNKNOWN!(0x{:x})", machine),
    }
}
