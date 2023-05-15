mod elf_header;
mod elf_section;
mod elf_segment;

/// component about the ELF analysis.
/// it recognizes multiple output-format.
pub struct Analyzer {
    /// configurations about ELF analysis.
    pub config: AnalyzerConfig,
}

impl Analyzer {
    /// construct the json-object from given ELF file.
    pub fn elf_info_as_json(
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

        let phdrs_value = if self.config.phdrs {
            self.elf_program_header_table_info_as_json(elf_file)
        } else {
            serde_json::json!({})
        };

        Ok(serde_json::json!({
            "elf_header": ehdr_value,
            "section_header_table": shdrs_value,
            "program_header_table": phdrs_value,
        }))
    }
}

pub struct AnalyzerConfig {
    /// determines the analyzer tries to construct the information about elf header.
    pub ehdr: bool,
    /// determines the analyzer tries to construct the information about elf section header table.
    pub shdrs: bool,
    /// determines the analyzer tries to construct the information about elf program header table.
    pub phdrs: bool,
    /// determines the output format of elf information.
    pub output_format: AnalyzerOutputFormat,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            ehdr: false,
            shdrs: false,
            phdrs: false,
            output_format: AnalyzerOutputFormat::Json,
        }
    }
}

impl AnalyzerConfig {
    pub fn ehdr(mut self, ehdr: bool) -> Self {
        self.ehdr = ehdr;
        self
    }

    pub fn shdrs(mut self, shdrs: bool) -> Self {
        self.shdrs = shdrs;
        self
    }

    pub fn phdrs(mut self, phdrs: bool) -> Self {
        self.phdrs = phdrs;
        self
    }

    /// construct an analyzer with the configuration.
    pub fn build(self) -> Analyzer {
        Analyzer { config: self }
    }
}

/// determines the output format of the ELF analyzer's result.
pub enum AnalyzerOutputFormat {
    /// JSON
    Json,
    // Yaml
    // Tui
}
