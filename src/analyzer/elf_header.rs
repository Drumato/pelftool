use super::Analyzer;

impl Analyzer {
    pub(super) fn elf_header_info_as_json(
        &self, 
        elf_file: &elf::ElfBytes<elf::endian::AnyEndian>,
    ) -> anyhow::Result<serde_json::Value>{
        let s = serde_json::json!({
            "class": elf_class_to_string(&elf_file.ehdr.class),
        });
        Ok(s)
    }
}

fn elf_class_to_string(
    class: &elf::file::Class,
) -> String {
    (match class {
        elf::file::Class::ELF32 => "ELF32",
        elf::file::Class::ELF64 => "ELF64",
    }).to_string()
}
