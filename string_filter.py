import re
from typing import Any

from feature_extractor import extract_strings, save_to_json

_IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_URL_PATTERN = re.compile(r"(https?|ftp|irc)://")
_PATH_PATTERN = re.compile(r"^/(etc|proc|dev|tmp|var|bin|usr|sys|root|run)/")
_EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def filter_strings(
    strings: list[dict[str, Any]],
    whitelist: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Filters strings based on patterns and an optional whitelist.

    Args:
        strings: A list of dictionaries containing strings and their metadata.
        whitelist: An optional set of strings to exclude from the results.

    Returns:
        A list of dictionaries containing filtered strings and their metadata.
    """

    filtered_strings = []
    for string in strings:
        value = string["value"]

        matched = (
            _IP_PATTERN.search(value)
            or _URL_PATTERN.search(value)
            or _PATH_PATTERN.search(value)
            or _EMAIL_PATTERN.search(value)
        )

        if not matched:
            continue

        if whitelist and value in whitelist:
            continue

        filtered_strings.append(string)

    return filtered_strings


def load_whitelist(path: str) -> set[str]:
    """Loads whitelist strings from a text file.

    Args:
        path: Path to the whitelist text file.

    Returns:
        Set of whitelisted strings.
    """
    with open(path, "r") as f:
        return {line.strip() for line in f}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Filter strings from ELF binary"
    )
    parser.add_argument("--input", required=True, help="Path to ELF binary")
    parser.add_argument(
        "--output", required=True, help="Path to output JSON file"
    )
    parser.add_argument(
        "--whitelist",
        default="whitelist/clean_strings.txt",
        help="Path to whitelist file",
    )
    args = parser.parse_args()

    whitelist = load_whitelist(args.whitelist)

    data = {
        "filtered_strings": filter_strings(
            extract_strings(args.input), whitelist
        ),
    }

    save_to_json(data, args.output)
