use super::Analyzer;

impl Analyzer {
    pub(super) fn elf_section_header_table_info_as_json(
        &self,
        elf_file: &elf::ElfBytes<elf::endian::AnyEndian>,
    ) -> anyhow::Result<serde_json::Value> {
        let s = match elf_file.section_headers_with_strtab() {
            // construct information with section name string
            Ok((sht, sht_names)) => {
                self.elf_named_section_header_table_info_as_json(sht, sht_names)
            }
            // each section information has the raw sh_name as its name
            Err(e) => {
                log::info!("{}", e);

                self.elf_noname_section_header_table_info_as_json(elf_file.section_headers())
            }
        };

        Ok(s)
    }

    fn elf_named_section_header_table_info_as_json(
        &self,
        sht: Option<elf::parse::ParsingTable<elf::endian::AnyEndian, elf::section::SectionHeader>>,
        sht_names: Option<elf::string_table::StringTable>,
    ) -> serde_json::Value {
        let Some(sht) = sht else {
            return serde_json::json!({
                "headers": Vec::<serde_json::Value>::new(),
                "entries": 0,
                "exist": false,
            });
        };

        serde_json::json!({
            "entries": sht.len(),
            "headers": sht.iter().map(|sh| self.elf_named_section_header_info_as_json(sh, sht_names.unwrap())).collect::<Vec<serde_json::Value>>(),
            "exist": true,
        })
    }

    fn elf_noname_section_header_table_info_as_json(
        &self,
        sht: Option<elf::parse::ParsingTable<elf::endian::AnyEndian, elf::section::SectionHeader>>,
    ) -> serde_json::Value {
        let Some(sht) = sht else {
            return serde_json::json!({
                "headers": Vec::<serde_json::Value>::new(),
                "entries": 0,
                "exist": false,
            });
        };

        serde_json::json!({
            "entries": sht.len(),
            "headers": sht.iter().map(|sh| self.elf_section_header_info_as_json(sh, sh.sh_name.to_string())).collect::<Vec<serde_json::Value>>(),
            "exist": true,
        })
    }

    fn elf_named_section_header_info_as_json(
        &self,
        sh: elf::section::SectionHeader,
        sht_names: elf::string_table::StringTable,
    ) -> serde_json::Value {
        let name = sht_names.get(sh.sh_name as usize).unwrap().to_string();
        self.elf_section_header_info_as_json(sh, name)
    }

    fn elf_section_header_info_as_json(
        &self,
        sh: elf::section::SectionHeader,
        name: String,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "type": elf_section_type_to_string(sh.sh_type),
            "flags": elf_section_flags_to_string(sh.sh_flags),
            "address": format!("0x{:x}", sh.sh_addr),
            "offset": format!("0x{:x}", sh.sh_offset),
            "size": format!("0x{:x}", sh.sh_size),
            "address_alignment": format!("0x{:x}", sh.sh_addralign),
            "entry_size": format!("0x{:x}", sh.sh_entsize),

        })
    }
}

fn elf_section_type_to_string(sh_type: u32) -> String {
    match sh_type {
        elf::abi::SHT_NULL => "NULL".to_string(),
        elf::abi::SHT_PROGBITS => "PROGBITS".to_string(),
        elf::abi::SHT_SYMTAB => "SYMTAB".to_string(),
        elf::abi::SHT_STRTAB => "STRTAB".to_string(),
        elf::abi::SHT_RELA => "RELA".to_string(),
        elf::abi::SHT_HASH => "HASH".to_string(),
        elf::abi::SHT_DYNAMIC => "DYNAMIC".to_string(),
        elf::abi::SHT_NOTE => "NOTE".to_string(),
        elf::abi::SHT_NOBITS => "NOBITS".to_string(),
        elf::abi::SHT_REL => "SHLIB".to_string(),
        elf::abi::SHT_DYNSYM => "DYNSYM".to_string(),
        elf::abi::SHT_INIT_ARRAY => "INIT_ARRAY".to_string(),
        elf::abi::SHT_FINI_ARRAY => "FINI_ARRAY".to_string(),
        elf::abi::SHT_PREINIT_ARRAY => "PREINIT_ARRAY".to_string(),
        elf::abi::SHT_GROUP => "GROUP".to_string(),
        elf::abi::SHT_SYMTAB_SHNDX => "SYMTAB_SHNDX".to_string(),
        elf::abi::SHT_GNU_ATTRIBUTES => "GNU_ATTRIBUTES".to_string(),
        elf::abi::SHT_GNU_HASH => "GNU_HASH".to_string(),
        elf::abi::SHT_GNU_LIBLIST => "GNU_LIBLIST".to_string(),
        elf::abi::SHT_GNU_VERDEF => "GNU_VERDEF".to_string(),
        elf::abi::SHT_GNU_VERNEED => "GNU_VERNEED".to_string(),
        elf::abi::SHT_GNU_VERSYM => "GNU_VERSYM".to_string(),
        elf::abi::SHT_LOOS..=elf::abi::SHT_HIOS => "[LOOS, HIOS]".to_string(),
        elf::abi::SHT_LOPROC..=elf::abi::SHT_HIPROC => "[LOPROC, HIPROC]".to_string(),
        elf::abi::SHT_LOUSER..=elf::abi::SHT_HIUSER => "[LOUSER, HIUSER]".to_string(),
        _ => format!("UNKNOWN!(0x{:x})", sh_type),
    }
}

const ELF_SECTION_FLAGS_STRINGS: [(u32, &str); 11] = [
    (elf::abi::SHF_WRITE, "WRITE"),
    (elf::abi::SHF_ALLOC, "ALLOC"),
    (elf::abi::SHF_EXECINSTR, "EXECINSTR"),
    (elf::abi::SHF_MERGE, "MERGE"),
    (elf::abi::SHF_STRINGS, "STRINGS"),
    (elf::abi::SHF_INFO_LINK, "INFO_LINK"),
    (elf::abi::SHF_LINK_ORDER, "LINK_ORDER"),
    (elf::abi::SHF_OS_NONCONFORMING, "OS_NONCONFORMING"),
    (elf::abi::SHF_GROUP, "GROUP"),
    (elf::abi::SHF_TLS, "TLS"),
    (elf::abi::SHF_COMPRESSED, "COMPRESSED"),
];

fn elf_section_flags_to_string(sh_flags: u64) -> Vec<String> {
    ELF_SECTION_FLAGS_STRINGS
        .iter()
        .filter(|(flag, _)| {
            if sh_flags & (*flag as u64) == 0 {
                return false;
            }

            true
        })
        .map(|(_, s)| s.to_string())
        .collect()
}
