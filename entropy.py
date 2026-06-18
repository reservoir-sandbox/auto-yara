import math
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte sequence.

    Args:
        data: Raw bytes to analyze.

    Returns:
        Shannon entropy value between 0.0 and 8.0.
        Higher values indicate more randomness.
    """
    counts = Counter(data)
    entropy = 0.0

    for byte, count in counts.items():

        probability = count / len(data)
        entropy -= probability * math.log2(probability)

    return entropy


def is_high_entropy(data: bytes, threshold: float = 7.0) -> bool:
    """Checks if the entropy of a byte sequence exceeds a given threshold.

    Args:
        data: Raw bytes to analyze.
        threshold: Entropy threshold above which data is considered
            high entropy. Defaults to 7.0.

    Returns:
        True if entropy exceeds threshold, False otherwise.
    """

    entropy = calculate_entropy(data)
    return entropy > threshold


if __name__ == "__main__":
    from elftools.elf.elffile import ELFFile

    for path in [
        "corpus/clean/bat",
        "corpus/malware/mirai.elf",
    ]:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for section_name in [".rodata", ".text", ".data"]:
                sec = elf.get_section_by_name(section_name)
                if sec is None:
                    continue
                entropy = calculate_entropy(sec.data())
                high = is_high_entropy(sec.data())
                print(
                    f"{path} | {section_name}: {entropy:.4f} |"
                    f"high_entropy: {high}"
                )
