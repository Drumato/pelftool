pub fn root_command() -> clap::Command {
    clap::Command::new("pelftool")
        .args(&[
            file_path_arg(),
            output_format_arg(),
            parse_elf_header_arg(),
        ])
}

fn file_path_arg() -> clap::Arg {
    clap::Arg::new("filepath").short('f').long("filepath").required(true)
}

fn output_format_arg() -> clap::Arg {
    clap::Arg::new("output-format").short('o').long("output-format").default_value("json").value_parser(["json"])
}

fn parse_elf_header_arg() -> clap::Arg {
    clap::Arg::new("parse-elf-header").long("parse-elf-header").default_value("true").value_parser(clap::value_parser!(bool))
}
