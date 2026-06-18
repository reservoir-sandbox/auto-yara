import re
from typing import Any
from feature_extractor import extract_strings

_IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_URL_PATTERN = re.compile(r"(https?|ftp|irc)://")
_PATH_PATTERN = re.compile(r"^/(etc|proc|dev|tmp|var|bin|usr|sys|root|run)/")
_EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def filter_strings(
    strings: list[dict[str, Any]],
) -> list[dict[str, Any]]:

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


output = filter_strings(
    extract_strings(
        "C:/Users/golor/OneDrive/Desktop/MrPink(Auto-YARA)"
        "/corpus/malware/mirai.elf",
    )
)

print(f"Total after filter: {len(output)}")

print(output[:20])
