# pelftool

An experimental analyzer tool that replaces GNU binutils readelf.

## Features

- support multiple output-format
  - [x] json
  - [ ] yaml
  - [ ] human-readable
- analyzer features
  - [x] ELF header
  - [x] section header table
  - [x] program header table
  - [ ] symbol table
  - [ ] relocation table
  - [ ] hexdump output
  - in TUI
    - [ ] filtering by key


## Usage

```plain-text
Usage: pelftool [OPTIONS] --filepath <filepath>

Options:
  -f, --filepath <filepath>
          
  -o, --output-format <output-format>
          [default: json] [possible values: json]
      --parse-elf-header <parse-elf-header>
          [default: true] [possible values: true, false]
      --parse-elf-section-headers <parse-elf-section-headers>
          [default: true] [possible values: true, false]
      --parse-elf-program-headers <parse-elf-program-headers>
          [default: true] [possible values: true, false]
  -h, --help
          Print help
```

## Examples

this examples shows the names of section header table in the `ls` executable.

```shell
$ ./target/debug/pelftool --filepath "$(which ls)" | jq .section_header_table.headers[].name
""
".interp"
".note.gnu.property"
".note.gnu.build-id"
".note.ABI-tag"
".gnu.hash"
".dynsym"
".dynstr"
".gnu.version"
".gnu.version_r"
".rela.dyn"
".rela.plt"
".init"
".plt"
".plt.got"
".plt.sec"
".text"
".fini"
".rodata"
".eh_frame_hdr"
".eh_frame"
".ctors"
".dtors"
".data.rel.ro"
".dynamic"
".got"
".data"
".bss"
".gnu_debugaltlink"
".gnu_debuglink"
".shstrtab"
```

