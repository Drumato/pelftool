mod analyzer;
mod cli;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let matches = cli::root_command().get_matches();
    let Some(filepath): Option<&String> = matches.get_one("filepath") else {
        panic!("filepath argument must be given");
    };
    let path = std::path::PathBuf::from(filepath);
    let file_data = std::fs::read(path)?;
    let elf_file = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(file_data.as_slice())?;

    let elf_analyzer = analyzer::AnalyzerConfig::new()
        .ehdr(*matches.get_one("parse-elf-header").unwrap())
        .shdrs(*matches.get_one("parse-elf-section-headers").unwrap())
        .phdrs(*matches.get_one("parse-elf-program-headers").unwrap())
        .build();
    println!("{}", elf_analyzer.elf_info(&elf_file)?.to_string());

    Ok(())
}
