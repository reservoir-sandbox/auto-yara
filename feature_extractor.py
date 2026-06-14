import json
import re
from typing import Any

from elftools.elf.elffile import ELFFile

from elf_parser import parse_imports

_TARGET_SECTIONS = [".rodata", ".data"]

_IMPORT_CATEGORIES: dict[str, list[str]] = {
    "network": [
        "socket",
        "connect",
        "bind",
        "send",
        "recv",
        "sendto",
        "recvfrom",
    ],
    "process": [
        "fork",
        "execve",
        "system",
        "popen",
        "execl",
        "execvp",
        "waitpid",
    ],
    "memory": ["mmap", "mprotect", "memfd_create", "munmap", "dlsym"],
    "antidebug": ["ptrace", "prctl", "alarm"],
    "filesystem": ["open", "write", "unlink", "chmod", "mkdir"],
    "privileges": [
        "setuid",
        "setgid",
        "getuid",
        "geteuid",
        "chroot",
        "setgroups",
    ],
}


def extract_strings(elf_path: str, min_length: int = 8) -> list[dict[str, Any]]:
    """
    Extracts strings from an ELF file.

    Args:
        elf_path (str): The path to the ELF file.
        min_length (int): The minimum length of strings to extract.

    Returns:
        list[dict[str, Any]]: A list of dictionaries
        containing the extracted strings and their offsets.
    """
    strings = []
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        for name in _TARGET_SECTIONS:
            sec = elf.get_section_by_name(name)
            if sec is None:
                continue
            data = sec.data()
            base_offset = sec["sh_offset"]
            pattern = re.compile(rb"[ -~]{" + str(min_length).encode() + rb",}")
            for match in pattern.finditer(data):
                strings.append(
                    {
                        "value": match.group().decode("ascii"),
                        "section": name,
                        "offset": hex(base_offset + match.start()),
                    }
                )

    return strings


def extract_imports(elf_path: str) -> dict[str, list[str]]:
    """
    Extracts imported symbols from an ELF file.

    Args:
        elf_path (str): The path to the ELF file.
    Returns:
        dict[str, list[str]]: A dictionary containing the imported symbols
        categorized by their type (e.g., functions, variables).
    """

    result: dict[str, list[str]] = {
        "network": [],
        "process": [],
        "memory": [],
        "antidebug": [],
        "filesystem": [],
        "privileges": [],
        "other": [],
    }
    parsed_imports = parse_imports(elf_path)

    for imp in parsed_imports:
        categorized = False
        for category, keywords in _IMPORT_CATEGORIES.items():
            if any(imp == keyword for keyword in keywords):
                result[category].append(imp)
                categorized = True
                break
        if not categorized:
            result["other"].append(imp)

    return result


def extract_metadata(elf_path: str) -> dict[str, Any]:
    """Extracts metadata flags from an ELF binary.

    Args:
        elf_path: Path to the ELF file.

    Returns:
        A dictionary containing:
            - is_stripped: True if .symtab section is absent.
            - has_upx: True if UPX packer sections are present.
            - has_rwx_segment: True if any segment has RWX flags.
            - has_exec_stack: True if PT_GNU_STACK is executable.
            - is_static: True if no PT_INTERP segment found.

    Raises:
        FileNotFoundError: If elf_path does not exist.
    """

    result: dict[str, Any] = {
        "is_stripped": True,
        "has_upx": False,
        "has_rwx_segment": False,
        "has_exec_stack": False,
        "is_static": True,
    }

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)

        # Check for .symtab section
        if elf.get_section_by_name(".symtab") is not None:
            result["is_stripped"] = False

        # Check for UPX sections
        if (
            elf.get_section_by_name("UPX0") is not None
            or elf.get_section_by_name("UPX1") is not None
        ):
            result["has_upx"] = True

        # Check for RWX segments and PT_GNU_STACK
        for segment in elf.iter_segments():
            flags = segment["p_flags"]
            if flags & 0x7 == 0x7:  # RWX
                result["has_rwx_segment"] = True
            if segment["p_type"] == "PT_GNU_STACK":
                if flags & 0x1:  # Executable
                    result["has_exec_stack"] = True

        # Check for PT_INTERP segment
        if any(
            segment["p_type"] == "PT_INTERP" for segment in elf.iter_segments()
        ):
            result["is_static"] = False

    return result


def save_to_json(data: dict[str, Any], output_path: str) -> None:
    """Saves extracted ELF features to a JSON file.

    Args:
        data: Dictionary containing extracted features.
        output_path: Path to the output JSON file.
    """
    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract features from ELF binary"
    )
    parser.add_argument("--input", required=True, help="Path to ELF binary")
    parser.add_argument(
        "--output", required=True, help="Path to output JSON file"
    )
    args = parser.parse_args()

    data = {
        "strings": extract_strings(args.input),
        "imports": extract_imports(args.input),
        "metadata": extract_metadata(args.input),
    }

    save_to_json(data, args.output)
