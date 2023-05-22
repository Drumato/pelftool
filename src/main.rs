use analyzer::AnalyzerOutputFormat;

mod analyzer;
mod cli;
mod tui;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let matches = cli::root_command().get_matches();
    let Some(filepath): Option<&String> = matches.get_one("filepath") else {
        panic!("filepath argument must be given");
    };
    let path = std::path::PathBuf::from(filepath);
    let file_data = std::fs::read(path)?;
    let elf_file = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(file_data.as_slice())?;

    let output_format = {
        let json_option = "json".to_string();
        let format: &String = matches
            .get_one::<String>("output-format")
            .unwrap_or(&json_option);
        match format.as_str() {
            "json" => AnalyzerOutputFormat::Json,
            "tui" => AnalyzerOutputFormat::Tui,
            _ => unreachable!(),
        }
    };

    let elf_analyzer = analyzer::AnalyzerConfig::default()
        .ehdr(*matches.get_one("parse-elf-header").unwrap())
        .shdrs(*matches.get_one("parse-elf-section-headers").unwrap())
        .phdrs(*matches.get_one("parse-elf-program-headers").unwrap())
        .output_format(output_format)
        .build();

    match elf_analyzer.config.output_format {
        analyzer::AnalyzerOutputFormat::Json => {
            let json_value = elf_analyzer.elf_info_as_json(&elf_file)?;
            println!("{}", json_value);
        }
        analyzer::AnalyzerOutputFormat::Tui => {
            tui::main()?;
        }
    }

    Ok(())
}
