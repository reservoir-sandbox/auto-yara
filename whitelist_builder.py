import os
from collections import Counter
from feature_extractor import extract_strings

_SYSTEM_BINARIES_DIR = "corpus/clean_system"
_MIN_OCCURRENCES = 3


def build_whitelist(directory: str, min_occurrences: int) -> set[str]:
    """Builds a whitelist of strings from ELF binaries in the
    specified directory.

    Args:
        directory: Path to the directory containing ELF binaries.
        min_occurrences: Minimum number of occurrences for a
        string to be included in the whitelist.

    Returns:
        A set of strings that appear at least `min_occurrences`
        times across all binaries in the directory.
    """

    all_strings: list[str] = []

    for root, _, files in os.walk(directory):
        for file in files:
            strings = extract_strings(os.path.join(root, file))
            unique_in_file = set(s["value"] for s in strings)
            all_strings.extend(unique_in_file)

    string_counts = Counter(all_strings)

    return {
        string
        for string, count in string_counts.items()
        if count >= min_occurrences
    }


def save_whitelist(whitelist: set[str], output_path: str) -> None:
    """Saves whitelist strings to a text file, one per line.

    Args:
        whitelist: Set of strings to save.
        output_path: Path to the output text file.
    Returns:
        None
    """
    with open(output_path, "w") as f:
        for string in sorted(whitelist):
            f.write(f"{string}\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Build a string whitelist from clean system binaries"
    )
    parser.add_argument(
        "--input",
        default=_SYSTEM_BINARIES_DIR,
        help="Directory containing clean ELF binaries",
    )
    parser.add_argument(
        "--output",
        default="whitelist/clean_strings.txt",
        help="Path to output whitelist file",
    )
    parser.add_argument(
        "--min-occurrences",
        type=int,
        default=_MIN_OCCURRENCES,
        help="Minimum number of binaries a string must appear in",
    )
    args = parser.parse_args()

    whitelist = build_whitelist(args.input, args.min_occurrences)
    save_whitelist(whitelist, args.output)
    print(f"Whitelist size: {len(whitelist)}")
