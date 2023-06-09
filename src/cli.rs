pub fn root_command() -> clap::Command {
    clap::Command::new("pelftool").args(&[
        file_path_arg(),
        output_format_arg(),
        parse_elf_header_arg(),
        parse_elf_section_headers_arg(),
        parse_elf_program_headers_arg(),
    ])
}

fn file_path_arg() -> clap::Arg {
    clap::Arg::new("filepath")
        .short('f')
        .long("filepath")
        .required(true)
}

fn output_format_arg() -> clap::Arg {
    clap::Arg::new("output-format")
        .short('o')
        .long("output-format")
        .default_value("json")
        .value_parser(["json", "tui"])
}

fn parse_elf_header_arg() -> clap::Arg {
    clap::Arg::new("parse-elf-header")
        .long("parse-elf-header")
        .default_value("true")
        .value_parser(clap::value_parser!(bool))
}

fn parse_elf_section_headers_arg() -> clap::Arg {
    clap::Arg::new("parse-elf-section-headers")
        .long("parse-elf-section-headers")
        .default_value("true")
        .value_parser(clap::value_parser!(bool))
}

fn parse_elf_program_headers_arg() -> clap::Arg {
    clap::Arg::new("parse-elf-program-headers")
        .long("parse-elf-program-headers")
        .default_value("true")
        .value_parser(clap::value_parser!(bool))
}
