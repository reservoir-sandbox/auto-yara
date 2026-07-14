from elf_parser import parse_header
from feature_extractor import save_to_json
from rule_builder import YaraRuleBuilder
from string_filter import filter_strings
from elftools.elf.elffile import ELFFile
from entropy import classify_entropy

_ELF_MAGIC_CHECK = "uint32(0) == 0x464C457F"
_BYTE_PATTERNS_PREVIEW_LIMIT = 5
_MAX_BYTE_PATTERNS_IN_RULE = 5


def select_byte_patterns_for_rule(
    patterns: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Selects a bounded, prioritized subset of byte patterns for a rule,
    renaming identifiers to a single "bp" prefix so they can be
    referenced as one group in a YARA condition (e.g. "1 of ($bp*)").

    Prioritizes syscall-based patterns over prologue patterns, since
    syscall matches are more specific and less prone to false positives
    — a prologue like "48 83 EC ??" alone is common across most
    compiled binaries.

    Args:
        patterns: Full list of patterns from extract_byte_patterns(),
            each with the original "identifier" (e.g. "p12",
            "direct_syscall_execve_1") and "hex_bytes".

    Returns:
        At most _MAX_BYTE_PATTERNS_IN_RULE patterns, syscall patterns
        first, each with a fresh "bp{n}" identifier and its original
        "hex_bytes" unchanged.
    """
    syscall_patterns = [
        p for p in patterns if p["identifier"].startswith("direct_syscall_")
    ]
    other_patterns = [
        p for p in patterns if not p["identifier"].startswith("direct_syscall_")
    ]
    selected = (syscall_patterns + other_patterns)[:_MAX_BYTE_PATTERNS_IN_RULE]

    return [
        {"identifier": f"bp{index}", "hex_bytes": pattern["hex_bytes"]}
        for index, pattern in enumerate(selected, start=1)
    ]


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

    byte_patterns_result = extract_byte_patterns(elf_path)
    selected_patterns = select_byte_patterns_for_rule(
        byte_patterns_result["patterns"]
    )
    for pattern in selected_patterns:
        builder.add_hex_pattern(pattern["identifier"], pattern["hex_bytes"])

    string_condition = build_string_condition(len(filtered_strings))
    arch_condition = build_arch_condition(architecture)

    conditions = [_ELF_MAGIC_CHECK, arch_condition]
    if string_condition:
        conditions.append(string_condition)
    if selected_patterns:
        conditions.append("1 of ($bp*)")

    builder.set_condition(" and ".join(conditions))
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
    from ranker import rank_features
    from byte_pattern_extractor import extract_byte_patterns
    from validator import improve_rule

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
    parser.add_argument(
        "--rank-output",
        required=False,
        help="Path to save the ranked features report (JSON)",
    )
    parser.add_argument(
        "--full-byte-patterns",
        action="store_true",
        help="Show all extracted byte patterns instead of a truncated preview",
    )
    parser.add_argument(
        "--auto-improve",
        action="store_true",
        help="Run auto-improvement loop before saving the rule",
    )
    args = parser.parse_args()

    whitelist = load_whitelist(args.whitelist)
    raw_strings = extract_strings(args.input)
    filtered = filter_strings(raw_strings, whitelist)
    imports = extract_imports(args.input)

    if args.rank_output:
        ranked = rank_features(filtered, imports, whitelist)
        save_to_json(ranked, args.rank_output)
        print(f"Ranked features saved to {args.rank_output}")

    if args.features_only:
        imports = extract_imports(args.input)
        byte_patterns = extract_byte_patterns(args.input)

        if (
            not args.full_byte_patterns
            and len(byte_patterns["patterns"]) > _BYTE_PATTERNS_PREVIEW_LIMIT
        ):
            byte_patterns = {
                **byte_patterns,
                "patterns": byte_patterns["patterns"][
                    :_BYTE_PATTERNS_PREVIEW_LIMIT
                ],
                "patterns_truncated": True,
                "patterns_total": len(byte_patterns["patterns"]),
            }

        features = {
            "strings_filtered": filtered,
            "imports": imports,
            "metadata": extract_metadata(args.input),
            "rodata_entropy": get_rodata_entropy_label(args.input),
            "suspicious_imports": detect_suspicious_combinations(imports),
            "byte_patterns": byte_patterns,
        }
        print(json.dumps(features, indent=4))
    else:
        if not args.name or not args.output:
            parser.error(
                "--name and --output are required unless --features-only is set"
            )

        builder = build_rule_from_features(args.input, args.name, filtered)
        if args.auto_improve:
            final_builder = improve_rule(builder, [args.input], None)
            rule_text = final_builder.build()
        else:
            final_builder = builder
            rule_text = final_builder.build()

        with open(args.output, "w") as f:
            f.write(rule_text)
        print(rule_text)
        print()
        print("Valid:", final_builder.validate())
        print(f"Rule saved to {args.output}")
