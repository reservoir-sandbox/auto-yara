import re
from typing import Any

from feature_extractor import extract_strings, save_to_json

_IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_URL_PATTERN = re.compile(r"(https?|ftp|irc)://")
_PATH_PATTERN = re.compile(r"^/(etc|proc|dev|tmp|var|bin|usr|sys|root|run)/")
_EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def filter_strings(
    strings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Filters extracted strings using an allow-list strategy.

    Keeps only strings that match known malware-relevant patterns
    such as IP addresses, URLs, file system paths, and email addresses.

    Args:
        strings: List of string dictionaries from extract_strings(),
            each containing 'value', 'section', and 'offset' keys.

    Returns:
        Filtered list containing only strings matching
        at least one malware-relevant pattern.
    """

    filtered_strings = []
    for string in strings:
        value = string["value"]

        if _IP_PATTERN.search(value):
            filtered_strings.append(string)
        elif _URL_PATTERN.search(value):
            filtered_strings.append(string)
        elif _PATH_PATTERN.search(value):
            filtered_strings.append(string)
        elif _EMAIL_PATTERN.search(value):
            filtered_strings.append(string)

    return filtered_strings


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Filter strings from ELF binary"
    )
    parser.add_argument("--input", required=True, help="Path to ELF binary")
    parser.add_argument(
        "--output", required=True, help="Path to output JSON file"
    )
    args = parser.parse_args()

    data = {
        "filtered_strings": filter_strings(extract_strings(args.input)),
    }

    save_to_json(data, args.output)
