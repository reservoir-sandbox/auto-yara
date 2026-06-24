from feature_extractor import extract_imports


def _flatten_imports(imports: dict[str, list[str]]) -> set[str]:
    """Flattens categorized imports into a single set of function names.

    Args:
        imports: Dictionary mapping category names to lists of
            imported function names, as returned by extract_imports().

    Returns:
        A single set containing all imported function names,
        regardless of category.
    """
    all_functions = set()

    for functions in imports.values():

        all_functions.update(functions)

    return all_functions


def detect_suspicious_combinations(
    imports: dict[str, list[str]],
) -> list[str]:
    """Detects known suspicious import combinations.

    Checks for specific function combinations that together suggest
    malicious capability beyond what any single import indicates:
        - ptrace + socket: anti-debugging combined with networking
        - memfd_create + execve: fileless execution (in-memory exec)
        - init_module: kernel module loading (potential rootkit)

    Limitation:
        Only effective on dynamically linked binaries. Statically
        linked binaries (common in IoT malware such as Mirai) have
        no .dynsym entries for these calls, since they are compiled
        directly into the binary rather than imported at runtime.
        Check extract_metadata()['is_static'] before relying on
        this function's results.

    Args:
        imports: Dictionary mapping category names to lists of
            imported function names, as returned by extract_imports().

    Returns:
        List of matched suspicious pattern names. Empty if none found.
    """

    found = _flatten_imports(imports)
    suspicious = []

    if "ptrace" in found and "socket" in found:
        suspicious.append("antidebug+network")

    if "memfd_create" in found and "execve" in found:
        suspicious.append("fileless_execution")

    if "init_module" in found:
        suspicious.append("kernel_rootkit")

    return suspicious


if __name__ == "__main__":
    for path in ["corpus/clean/bat", "corpus/malware/mirai.elf"]:
        imports = extract_imports(path)
        flat = _flatten_imports(imports)
        print(f"{path} imports: {sorted(flat)}")
        result = detect_suspicious_combinations(imports)
        print(f"{path} suspicious: {result}")
