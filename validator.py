from pathlib import Path
from typing import Any
from rule_builder import YaraRuleBuilder
import yara
import re

_THRESHOLD_PATTERN = re.compile(r"(\d+) of \(\$s\*\)")
_CLEAN_CORPUS_DIR = "corpus/clean"
_STRING_CONDITION_FRAGMENT = re.compile(r"\s*and\s+\d+\s+of\s+\(\$s\*\)")
_BP_CONDITION_FRAGMENT = re.compile(r"\s*and\s+\d+\s+of\s+\(\$bp\*\)")


def _strip_empty_condition_fragments(builder: YaraRuleBuilder) -> None:
    """Removes 'N of ($s*)'/'N of ($bp*)' from the condition if the
    corresponding feature list is now empty (removing the fragment
    entirely, not just lowering N, since a reference to zero strings
    fails YARA compilation rather than harmlessly matching nothing).

    Args:
        builder: The YaraRuleBuilder to mutate in place.
    """
    if not builder.strings:
        builder.set_condition(
            _STRING_CONDITION_FRAGMENT.sub("", builder.condition)
        )
    if not builder.hex_patterns:
        builder.set_condition(_BP_CONDITION_FRAGMENT.sub("", builder.condition))


def check_false_positives(
    rule_source: str, clean_paths: list[str] | None = None
) -> list[dict[str, Any]]:
    """Checks if a string is a known false positive.

    Args:
        rule_source: The source code of the YARA rule.
        clean_paths: Optional list of paths to known clean samples.

    Returns:
        A list of dictionaries containing information about
        false positive matches.
    """
    fp_matches = []
    rule = yara.compile(source=rule_source)

    for clean_path in clean_paths or [_CLEAN_CORPUS_DIR]:
        white_path = Path(clean_path)
        if white_path.is_dir():
            for file in white_path.iterdir():
                if file.is_file():
                    matches = rule.match(str(file))
                    if matches:
                        fp_matches.append(
                            {"file": str(file), "matches": matches}
                        )
        elif white_path.is_file():
            matches = rule.match(str(white_path))
            if matches:
                fp_matches.append({"file": str(white_path), "matches": matches})

    return fp_matches


def check_true_positives(
    rule_source: str, malware_paths: list[str]
) -> dict[str, Any]:
    """Checks if a string is a known true positive.

    Args:
        rule_source: The source code of the YARA rule.
        malware_paths: List of paths to known malware samples.

    Returns:
        A dictionary containing information about
        true positive matches and misses  .
    """
    matched = []
    missed = []
    rule = yara.compile(source=rule_source)

    for malware_path in malware_paths:
        file_matches = rule.match(malware_path)
        if file_matches:
            matched.append({"file": malware_path, "matches": file_matches})
        else:
            missed.append({"file": malware_path})

    return {"matches": matched, "misses": missed}


def get_quality_report(
    rule_source: str,
    malware_paths: list[str],
    clean_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Generates a quality report for a YARA rule.

    Args:
        rule_source: The source code of the YARA rule.
        malware_paths: List of paths to known malware samples.
        clean_paths: Optional list of paths to known clean samples.
    Returns:
        A dictionary containing the quality report, including true positives,
        false positives, and other relevant metrics.
    """
    true_positives = check_true_positives(rule_source, malware_paths)
    false_positives = check_false_positives(rule_source, clean_paths)

    fp_count = len(false_positives)
    tp_rate = (
        len(true_positives["matches"]) / len(malware_paths)
        if malware_paths
        else 0
    )

    if fp_count == 0 and tp_rate == 1:
        verdict = "Good"
    elif fp_count == 0 and tp_rate <= 1.0:
        verdict = "Needs review"
    elif fp_count > 0:
        verdict = "Unusable"
    else:
        verdict = "Unknown"

    report = {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_positive_count": fp_count,
        "true_positive_rate": tp_rate,
        "verdict": verdict,
    }

    return report


def _extract_culprit_identifiers(fp_matches: list[dict[str, Any]]) -> set[str]:
    """Extracts the identifiers of strings that caused false positives.

    Args:
        fp_matches: List of false positive match dictionaries.

    Returns:
        A set of string identifiers that caused false positives.
    """
    culprit_identifiers = set()
    for match in fp_matches:
        for rule_match in match["matches"]:
            for string_match in rule_match.strings:
                if hasattr(string_match, "identifier"):
                    culprit_identifiers.add(string_match.identifier.lstrip("$"))
    return culprit_identifiers


def improve_rule(
    builder: YaraRuleBuilder,
    malware_paths: list[str],
    clean_paths: list[str] | None = None,
) -> YaraRuleBuilder:
    """..."""
    baseline_tp = check_true_positives(builder.build(), malware_paths)
    if len(malware_paths) == 0:
        baseline_tp_rate = 0.0
    else:
        baseline_tp_rate = len(baseline_tp["matches"]) / len(malware_paths)

    rejected_culprits: set[str] = set()

    while True:
        rule_source = builder.build()
        fp_matches = check_false_positives(rule_source, clean_paths)

        if not fp_matches:
            break

        culprits = _extract_culprit_identifiers(fp_matches) - rejected_culprits
        if not culprits:
            if _bump_string_threshold(builder):
                continue
            else:
                break

        culprit = sorted(culprits)[0]

        strings_backup = builder.strings.copy()
        hex_patterns_backup = builder.hex_patterns.copy()

        builder.remove_feature(culprit)

        _strip_empty_condition_fragments(builder)

        new_tp = check_true_positives(builder.build(), malware_paths)
        if len(malware_paths) == 0:
            new_tp_rate = 0.0
        else:
            new_tp_rate = len(new_tp["matches"]) / len(malware_paths)

        if new_tp_rate < baseline_tp_rate:
            builder.strings = strings_backup
            builder.hex_patterns = hex_patterns_backup
            rejected_culprits.add(culprit)

        else:
            baseline_tp_rate = new_tp_rate

    return builder


def _bump_string_threshold(builder: YaraRuleBuilder) -> bool:
    """Increases the 'N of ($s*)' threshold in the rule's condition by 1.

    Args:
        builder: The YaraRuleBuilder whose condition should be tightened.

    Returns:
        True if the threshold was raised, False if it's already at the
        maximum possible (equal to the number of available strings) or
        if no such pattern was found in the condition.
    """
    condition = builder.condition
    if not condition:
        return False

    match = _THRESHOLD_PATTERN.search(condition)
    if not match:
        return False

    current_threshold = int(match.group(1))
    num_strings = len(builder.strings)

    if current_threshold >= num_strings:
        return False

    new_threshold = current_threshold + 1
    new_condition = _THRESHOLD_PATTERN.sub(
        f"{new_threshold} of ($s*)", condition
    )
    builder.set_condition(new_condition)
    return True


if __name__ == "__main__":

    rule_builder = YaraRuleBuilder("TestFallbackRule")
    rule_builder.add_string("s1", "/dev/null")
    rule_builder.add_string("s2", "totally_fake_xyz123")
    rule_builder.add_string("s3", "another_fake_abc456")
    rule_builder.set_condition("uint32(0) == 0x464C457F and 1 of ($s*)")

    rule_builder.set_condition("uint32(0) == 0x464C457F and 1 of ($s*)")

    malware_samples = ["corpus/malware/Mirai_64.elf"]
    clean_samples = ["corpus/clean/bat", "corpus/clean/busybox_x86_64"]

    before_report = get_quality_report(
        rule_builder.build(), malware_samples, clean_samples
    )
    print(
        "BEFORE:",
        before_report["false_positive_count"],
        before_report["true_positive_rate"],
        before_report["verdict"],
    )

    improved_builder = improve_rule(
        rule_builder, malware_samples, clean_samples
    )

    after_report = get_quality_report(
        improved_builder.build(), malware_samples, clean_samples
    )
    print(
        "AFTER:",
        after_report["false_positive_count"],
        after_report["true_positive_rate"],
        after_report["verdict"],
    )

    print(improved_builder.build())
