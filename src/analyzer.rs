mod elf_header;
mod elf_section;

pub struct Analyzer {
    pub config: AnalyzerConfig,
}

impl Analyzer {
    pub fn elf_info(
        &self,
        elf_file: &elf::ElfBytes<elf::endian::AnyEndian>,
    ) -> anyhow::Result<serde_json::Value> {
        match self.config.output_format {
            AnalyzerOutputFormat::Json => self.elf_info_as_json(elf_file),
        }
    }

    fn elf_info_as_json(
        &self,
        elf_file: &elf::ElfBytes<elf::endian::AnyEndian>,
    ) -> anyhow::Result<serde_json::Value> {
        let ehdr_value = if self.config.ehdr {
            self.elf_header_info_as_json(elf_file)
        } else {
            serde_json::json!({})
        };

        let shdrs_value = if self.config.shdrs {
            self.elf_section_header_table_info_as_json(elf_file)?
        } else {
            serde_json::json!({})
        };

        Ok(serde_json::json!({
            "elf_header": ehdr_value,
            "section_header_table": shdrs_value,
        }))
    }
}

pub struct AnalyzerConfig {
    pub ehdr: bool,
    pub shdrs: bool,
    pub output_format: AnalyzerOutputFormat,
}

impl AnalyzerConfig {
    pub fn new() -> Self {
        Self {
            ehdr: false,
            shdrs: false,
            output_format: AnalyzerOutputFormat::Json,
        }
    }

    pub fn ehdr(mut self, ehdr: bool) -> Self {
        self.ehdr = ehdr;
        self
    }

    pub fn shdrs(mut self, shdrs: bool) -> Self {
        self.shdrs = shdrs;
        self
    }
    pub fn build(self) -> Analyzer {
        Analyzer { config: self }
    }
}

pub enum AnalyzerOutputFormat {
    Json,
}
