import re
from typing import Any

from suspicious_imports import detect_suspicious_combinations

_IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_URL_PATTERN = re.compile(r"(https?|ftp|irc)://")
_EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_NONSTANDARD_PATH_PATTERN = re.compile(r"^/(proc|dev|tmp|var/run|root)/")
_LONG_STRING_THRESHOLD = 20

# Case-insensitive botnet command tokens (Week 3 whitelist/string_filter
# keeps these as "useful" signal; here they earn points instead of just
# being kept).
_BOTNET_COMMANDS = {"ATTACK", "SCAN", "KILL"}

# Points awarded per scoring rule (Week 5 plan).
_SCORE_IP_OR_URL = 3.0
_SCORE_EMAIL = 3.0
_SCORE_BOTNET_COMMAND = 2.5
_SCORE_NONSTANDARD_PATH_OR_LONG = 2.0
_SCORE_WHITELISTED = -5.0

# Per-category weight for scoring individual imports. Categories not
# listed default to 0.0 (e.g. "other").
_IMPORT_CATEGORY_WEIGHTS: dict[str, float] = {
    "antidebug": 2.0,
    "memory": 1.5,
    "process": 1.5,
    "network": 1.0,
    "privileges": 1.0,
    "filesystem": 0.5,
}

# Bonus awarded per detected suspicious combination (e.g.
# "antidebug+network"), on top of individual import scores.
_SUSPICIOUS_COMBO_BONUS = 3.0


def score_string(value: str, whitelist: set[str] | None = None) -> float:
    """Scores a single extracted string for rule-worthiness.

    Args:
        value: The raw string value to score.
        whitelist: Optional set of known-clean strings. A match here
            is a strong signal the string is generic noise.

    Returns:
        A float score. Higher is more rule-worthy; negative scores
        indicate the string should likely be excluded entirely.
    """
    score = 0.0

    if _IP_PATTERN.search(value) or _URL_PATTERN.search(value):
        score += _SCORE_IP_OR_URL

    if _EMAIL_PATTERN.search(value):
        score += _SCORE_EMAIL

    upper_value = value.upper()
    if any(command in upper_value for command in _BOTNET_COMMANDS):
        score += _SCORE_BOTNET_COMMAND

    if _NONSTANDARD_PATH_PATTERN.match(value) or len(value) > (
        _LONG_STRING_THRESHOLD
    ):
        score += _SCORE_NONSTANDARD_PATH_OR_LONG

    if whitelist and value in whitelist:
        score += _SCORE_WHITELISTED

    return score


def rank_strings(
    strings: list[dict[str, Any]],
    whitelist: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Scores and ranks extracted strings, returning the best candidates.

    Args:
        strings: List of string dicts as returned by
            feature_extractor.extract_strings() (each with at least a
            "value" key).
        whitelist: Optional set of known-clean strings to penalize.

    Returns:
        A list of string dicts (copies of the input dicts, each with
        an added "score" key), sorted by score descending.
    """
    scored = []
    for string in strings:
        score = score_string(string["value"], whitelist)
        scored.append({**string, "score": score})

    scored.sort(key=lambda item: item["score"], reverse=True)
    return scored


def score_import(name: str, category: str) -> float:
    """Scores a single imported symbol based on its category.

    Args:
        name: The imported function name (currently unused in scoring
            but kept for future per-symbol overrides).
        category: The category the import falls under, as assigned by
            feature_extractor.extract_imports() (e.g. "antidebug").

    Returns:
        A float score based on the category's known malicious weight.
        Uncategorized imports ("other") score 0.0.
    """
    del name  # Reserved for future per-symbol scoring rules.
    return _IMPORT_CATEGORY_WEIGHTS.get(category, 0.0)


def rank_imports(
    imports: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Scores and ranks imported symbols by malicious likelihood.

    Individual imports are scored by category weight. Any known
    suspicious combination detected across the full import set (e.g.
    ptrace + socket) is appended as its own high-scoring entry, since
    it represents a signal beyond any single import.

    Args:
        imports: Categorized import dict as returned by
            feature_extractor.extract_imports().

    Returns:
        A list of dicts sorted by score descending. Symbol entries
        have {"name", "category", "score"}; combo entries have
        {"name", "category": "combo", "score"}.
    """
    scored: list[dict[str, Any]] = []

    for category, names in imports.items():
        for name in names:
            score = score_import(name, category)
            scored.append({"name": name, "category": category, "score": score})

    for combo in detect_suspicious_combinations(imports):
        scored.append(
            {
                "name": combo,
                "category": "combo",
                "score": _SUSPICIOUS_COMBO_BONUS,
            }
        )

    scored.sort(key=lambda item: item["score"], reverse=True)
    return scored


def rank_features(
    strings: list[dict[str, Any]],
    imports: dict[str, list[str]],
    whitelist: set[str] | None = None,
) -> dict[str, Any]:
    """Ranks the best strings and imports for rule generation.

    Args:
        strings: List of string dicts as returned by
            feature_extractor.extract_strings().
        imports: Categorized import dict as returned by
            feature_extractor.extract_imports().
        whitelist: Optional set of known-clean strings to penalize.

    Returns:
        A dict with:
            - ranked_strings: ranked string dicts (see rank_strings())
            - ranked_imports: ranked import/combo dicts (see
              rank_imports())
            - byte_patterns: reserved for Week 6
              (byte_pattern_extractor.py); always empty for now.
    """
    ranked_strings = rank_strings(strings, whitelist)
    ranked_imports = rank_imports(imports)

    return {
        "ranked_strings": ranked_strings,
        "ranked_imports": ranked_imports,
        "byte_patterns": [],
    }


if __name__ == "__main__":
    import argparse
    import json

    from feature_extractor import extract_imports, extract_strings, save_to_json
    from string_filter import load_whitelist

    parser = argparse.ArgumentParser(
        description="Rank the best features from an ELF binary"
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
    raw_strings = extract_strings(args.input)
    raw_imports = extract_imports(args.input)

    result = rank_features(raw_strings, raw_imports, whitelist)

    print(json.dumps(result, indent=4))
    save_to_json(result, args.output)
