from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.sections import SymbolTableSection
from typing import Any, cast


def parse_header(elf_path: str) -> dict[str, Any]:
    """Parses ELF header fields.

    Args:
        elf_path: Path to the ELF file.

    Returns:
        A dict containing the following fields:
            - file_type: The type of the ELF file
            (e.g., executable, shared object, etc.).

            - architecture: The target architecture (e.g., x86, ARM, etc.).

            - entry_point: The entry point address of the ELF file.

            - bit_depth: The bit depth of the ELF file (e.g., 32-bit or 64-bit).

            - byte_order: The byte order of the ELF file
            (e.g., little-endian or big-endian).

            - _abi: The ABI (Application Binary Interface) of the ELF file.

            - magic: The magic number of the ELF file,
            represented as a hexadecimal string.
    Raises:
        FileNotFoundError: If the specified ELF file does not exist.
        Exception: If there is an error while parsing the ELF file.
    """

    with open(elf_path, "rb") as f:

        elf = ELFFile(f)
        header = elf.header

        headers = {
            "file_type": header["e_type"],
            "architecture": header["e_machine"],
            "entry_point": hex(header["e_entry"]),
            "bit_depth": header["e_ident"]["EI_CLASS"],
            "byte_order": header["e_ident"]["EI_DATA"],
            "_abi": header["e_ident"]["EI_OSABI"],
            "magic": bytes(header["e_ident"]["EI_MAG"]).hex(),
        }

    return headers


def _parse_sections_flags(flags: int) -> str:
    """Parses section flags from the ELF file.

    Args:
        flags: The section flags as an integer.

    Returns:
        A string representation of the section flags, where:
            - 'W' indicates the section is writable (SHF_WRITE).

            - 'A' indicates the section is allocatable (SHF_ALLOC).

            - 'X' indicates the section contains executable instructions
            (SHF_EXECINSTR).
    Raises:
        Exception: If there is an error while parsing the section flags.
    """

    result = ""
    if flags & 0x1:  # SHF_WRITE
        result += "W"
    if flags & 0x2:  # SHF_ALLOC
        result += "A"
    if flags & 0x4:  # SHF_EXECINSTR
        result += "X"
    return result


def parse_sections(elf_path: str) -> list[dict[str, Any]]:
    """Parses ELF sections and their attributes.

    Args:
        elf_path: Path to the ELF file.

    Returns:
        A list of dictionaries, where each dictionary represents a section
        with the following fields:

            - name: The name of the section.

            - type: The type of the section
            (e.g., SHT_PROGBITS, SHT_SYMTAB, etc.).

            - flags: A string representation of the section flags
            (e.g., 'WA' for writable and allocatable).

            - address: The virtual address of the section in hexadecimal format.

            - size: The size of the section in bytes.

            - offset: The file offset of the section in hexadecimal format.
    Raises:
        FileNotFoundError: If the specified ELF file does not exist.
        Exception: If there is an error
        while parsing the ELF file or its sections.
    """

    with open(elf_path, "rb") as f:

        elf = ELFFile(f)
        sections = []

        for section in elf.iter_sections():
            sections.append(
                {
                    "name": section.name,
                    "type": section["sh_type"],
                    "flags": _parse_sections_flags(section["sh_flags"]),
                    "address": hex(section["sh_addr"]),
                    "size": section["sh_size"],
                    "offset": hex(section["sh_offset"]),
                }
            )

    return sections


def _parse_segments_flags(flags: int) -> str:
    """Parses segment flags from the ELF file.

    Args:
        flags: The segment flags as an integer.

    Returns:
        A string representation of the segment flags, where:

            - 'R' indicates the segment is readable (PF_R).

            - 'W' indicates the segment is writable (PF_W).

            - 'X' indicates the segment is executable (PF_X).
    Raises:
        Exception: If there is an error while parsing the segment flags.
    """

    result = ""
    if flags & 0x4:  # read
        result += "R"
    if flags & 0x2:  # write
        result += "W"
    if flags & 0x1:  # execute
        result += "X"

    return result


def parse_segments(elf_path: str) -> list[dict[str, Any]]:
    """Parses ELF segments and their attributes.

    Args:
        elf_path: Path to the ELF file.

    Returns:
        A list of dictionaries, where each dictionary represents a segment
        with the following fields:

            - type: The type of the segment (e.g., PT_LOAD, PT_DYNAMIC, etc.).

            - flags: A string representation of the segment flags
            (e.g., 'RW' for readable and writable).

            - virtual_address: The virtual address of the segment
            in hexadecimal format.

            - physical_address: The physical address of the segment
            in hexadecimal format.

            - file_size: The size of the segment in the file in bytes.

            - memory_size: The size of the segment in memory in bytes.

            - offset: The file offset of the segment in hexadecimal format.
    Raises:
        FileNotFoundError: If the specified ELF file does not exist.
        Exception: If there is an error while parsing
        the ELF file or its segments.
    """
    with open(elf_path, "rb") as f:

        elf = ELFFile(f)
        segments = []

        for segment in elf.iter_segments():
            segments.append(
                {
                    "type": segment["p_type"],
                    "flags": _parse_segments_flags(segment["p_flags"]),
                    "virtual_address": hex(segment["p_vaddr"]),
                    "physical_address": hex(segment["p_paddr"]),
                    "file_size": segment["p_filesz"],
                    "memory_size": segment["p_memsz"],
                    "offset": hex(segment["p_offset"]),
                }
            )

    return segments


def parse_dynamic(elf_path: str) -> dict[str, Any]:
    """Parses the dynamic section of an ELF file to extract
    dynamic linking information.

    Args:
        elf_path: Path to the ELF file.

    Returns:
        A dictionary containing the following fields:

            - needed: A list of shared libraries that the ELF file
            depends on (DT_NEEDED).

            - soname: The name of the shared object (DT_SONAME).

            - rpath: The runtime library search path (DT_RPATH).

            - init: The address of the initialization function (DT_INIT)
            in hexadecimal format.

            - fini: The address of the finalization function (DT_FINI)
            in hexadecimal format.

            - flags: A list of flags associated with
            the dynamic section (DT_FLAGS).

    Raises:
        FileNotFoundError: If the specified ELF file does not exist.
    """

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)

        dynamic: dict[str, Any] = {
            "needed": [],
            "soname": None,
            "rpath": None,
            "init": None,
            "fini": None,
            "flags": [],
        }

        for section in elf.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        dynamic["needed"].append(cast(Any, tag).needed)
                    if tag.entry.d_tag == "DT_SONAME":
                        dynamic["soname"] = cast(Any, tag).soname
                    if tag.entry.d_tag == "DT_RPATH":
                        dynamic["rpath"] = cast(Any, tag).rpath
                    if tag.entry.d_tag == "DT_INIT":
                        dynamic["init"] = hex(cast(Any, tag).entry.d_val)
                    if tag.entry.d_tag == "DT_FINI":
                        dynamic["fini"] = hex(cast(Any, tag).entry.d_val)
                    if tag.entry.d_tag == "DT_FLAGS":
                        dynamic["flags"].append(cast(Any, tag).flags)

    return dynamic


def parse_imports(elf_path: str) -> list[str]:
    """Parses the symbol table of an ELF file to extract imported functions.

    Args:
        elf_path (str): Path to the ELF file.

    Returns:
        A list of imported function names that are referenced in the ELF file
        but not defined within it
        (i.e., symbols of type STT_FUNC with section index SHN_UNDEF).

    Raises:
        FileNotFoundError: If the specified ELF file does not exist.
    """

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        imports = []

        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if (
                        symbol["st_info"]["type"] == "STT_FUNC"
                        and symbol["st_shndx"] == "SHN_UNDEF"
                    ):
                        imports.append(symbol.name)

    return imports


parsed_header = parse_header(
    "C:/Users/golor/OneDrive/Desktop/MrPink(Auto-YARA)" "/corpus/clean/bat"
)

print(parsed_header)

parsed_sections = parse_sections(
    "C:/Users/golor/OneDrive/Desktop/MrPink(Auto-YARA)" "/corpus/clean/bat"
)

print(parsed_sections)

parsed_segments = parse_segments(
    "C:/Users/golor/OneDrive/Desktop/MrPink(Auto-YARA)" "/corpus/clean/bat"
)

print(parsed_segments)

parsed_dynamic = parse_dynamic(
    "C:/Users/golor/OneDrive/Desktop/MrPink(Auto-YARA)" "/corpus/clean/bat"
)
print(parsed_dynamic)

parsed_imports = parse_imports(
    "C:/Users/golor/OneDrive/Desktop/MrPink(Auto-YARA)" "/corpus/clean/bat",
)
print(parsed_imports)
