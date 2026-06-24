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

    string_counts = Counter(all_strings)  # один раз, после всех файлов

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
    whitelist = build_whitelist(_SYSTEM_BINARIES_DIR, _MIN_OCCURRENCES)
    save_whitelist(whitelist, "whitelist/clean_strings.txt")
    print(f"Whitelist size: {len(whitelist)}")
