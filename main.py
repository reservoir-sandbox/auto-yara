from elf_parser import parse_header
from rule_builder import YaraRuleBuilder
from string_filter import filter_strings
from elftools.elf.elffile import ELFFile
from entropy import classify_entropy

_ELF_MAGIC_CHECK = "uint32(0) == 0x464C457F"


def build_string_condition(num_strings: int) -> str:
    """Determines the minimum-match condition based on string count.

    Args:
        num_strings: Number of string patterns in the rule.

    Returns:
        A YARA condition fragment like "2 of ($s*)", or empty string
        if no strings are available.
    """
    if num_strings == 0:
        return ""
    elif num_strings == 1:
        return "1 of ($s*)"
    else:
        return "2 of ($s*)"


def build_arch_condition(architecture: str) -> str:
    """Builds an architecture-check condition.

    Args:
        architecture: Machine type string from parse_header()
            (e.g. "EM_X86_64", "EM_386").

    Returns:
        A YARA condition fragment like "elf.machine == elf.EM_X86_64".
    """
    return f"elf.machine == elf.{architecture}"


def get_rodata_entropy_label(elf_path: str) -> str:
    """Classifies the entropy of the .rodata section.

    Args:
        elf_path: Path to the ELF binary.

    Returns:
        Entropy classification string ("normal", "suspicious",
        or "likely_packed"), or "unknown" if .rodata is absent.
    """
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        rodata_section = elf.get_section_by_name(".rodata")
        if not rodata_section:
            return "unknown"

        data = rodata_section.data()

    return classify_entropy(data)


def build_rule_from_features(
    elf_path: str,
    rule_name: str,
    filtered_strings: list[dict[str, str]],
) -> YaraRuleBuilder:
    """..."""
    architecture = parse_header(elf_path)["architecture"]
    rule_name = f"{rule_name}_{architecture}"

    builder = YaraRuleBuilder(rule_name)
    builder.set_meta("author", "auto-yara")
    builder.set_meta("entropy", get_rodata_entropy_label(elf_path))

    for index, string in enumerate(filtered_strings, start=1):
        builder.add_string(f"s{index}", string["value"])

    string_condition = build_string_condition(len(filtered_strings))
    arch_condition = build_arch_condition(architecture)

    if string_condition:
        full_condition = (
            f"{_ELF_MAGIC_CHECK} and {arch_condition} and {string_condition}"
        )
    else:
        full_condition = f"{_ELF_MAGIC_CHECK} and {arch_condition}"

    builder.set_condition(full_condition)
    builder.add_import("elf")

    return builder


if __name__ == "__main__":
    import argparse
    import json
    from feature_extractor import (
        extract_strings,
        extract_imports,
        extract_metadata,
    )
    from string_filter import load_whitelist
    from suspicious_imports import detect_suspicious_combinations

    parser = argparse.ArgumentParser(
        description="Generate a YARA rule from an ELF binary"
    )
    parser.add_argument("--input", required=True, help="Path to ELF binary")
    parser.add_argument("--name", required=False, help="Name for the YARA rule")
    parser.add_argument(
        "--output", required=False, help="Path to save the .yar file"
    )
    parser.add_argument(
        "--whitelist",
        default="whitelist/clean_strings.txt",
        help="Path to whitelist file",
    )
    parser.add_argument(
        "--features-only",
        action="store_true",
        help="Only extract and print features, skip rule generation",
    )
    args = parser.parse_args()

    whitelist = load_whitelist(args.whitelist)
    raw_strings = extract_strings(args.input)
    filtered = filter_strings(raw_strings, whitelist)

    if args.features_only:
        imports = extract_imports(args.input)
        features = {
            "strings_filtered": filtered,
            "imports": imports,
            "metadata": extract_metadata(args.input),
            "rodata_entropy": get_rodata_entropy_label(args.input),
            "suspicious_imports": detect_suspicious_combinations(imports),
        }
        print(json.dumps(features, indent=4))
    else:
        if not args.name or not args.output:
            parser.error(
                "--name and --output are required unless --features-only is set"
            )

        builder = build_rule_from_features(args.input, args.name, filtered)
        rule_text = builder.build()

        with open(args.output, "w") as f:
            f.write(rule_text)
        print(rule_text)
        print()
        print("Valid:", builder.validate())
        print(f"Rule saved to {args.output}")
