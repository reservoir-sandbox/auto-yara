"""Extracts byte-level instruction patterns from x86_64 ELF binaries.

Uses Capstone to disassemble the .text section and identify function
prologues and suspicious instruction sequences (direct syscalls) that
can be converted into YARA hex patterns with wildcards for variable
operands.

Limitation: only x86_64 is supported. Other architectures return a
"not supported" result rather than raising, so the pipeline can
continue and report the limitation explicitly in output.
"""

from typing import Any
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elf_parser import parse_header

_SUPPORTED_ARCHITECTURES = {"EM_X86_64"}


def is_architecture_supported(architecture: str) -> bool:
    """Checks whether byte-pattern analysis supports this architecture.

    Args:
        architecture: Machine type string as returned by
            parse_header()["architecture"] (e.g. "EM_X86_64", "EM_ARM").

    Returns:
        True if the architecture is supported for disassembly-based
        analysis, False otherwise.
    """
    arch = architecture.upper()
    return arch in _SUPPORTED_ARCHITECTURES


def disassemble_section(
    elf_path: str, section_name: str = ".text"
) -> list[dict[str, Any]]:
    """Disassembles a section of an x86_64 ELF binary into instructions.

    Reads the raw bytes and virtual address of the given section and
    disassembles them linearly using Capstone.

    Args:
        elf_path: Path to the ELF file. Must be x86_64
            (caller is responsible for checking is_architecture_supported
            beforehand, or via extract_byte_patterns()).
        section_name: Name of the section to disassemble (default ".text").

    Returns:
        A list of dictionaries, each representing one disassembled
        instruction, in address order:
            - address: int, virtual address of the instruction
            - mnemonic: str, instruction mnemonic (e.g. "mov", "xor")
            - operands: str, operand string as disassembled
            - bytes: bytes, raw bytes of this instruction
            - size: int, length of the instruction in bytes

    Raises:
        FileNotFoundError: If elf_path does not exist.
        ValueError: If the section is absent, or Capstone cannot be
            configured for the binary's architecture.

    Limitation:
        Uses linear disassembly (sequential byte-by-byte decoding from
        section start). Does not follow control flow. If .text contains
        embedded non-code data (e.g. jump tables), disassembly may
        misinterpret those bytes as instructions past that point.
    """
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        section = elf.get_section_by_name(section_name)
        if not section:
            raise ValueError(f"Section {section_name} not found in ELF")

        raw_bytes = section.data()
        virtual_address = section["sh_addr"]
        capstone_arch = CS_ARCH_X86
        capstone_mode = CS_MODE_64
        cs = Cs(capstone_arch, capstone_mode)

        disassembled = []
        for insn in cs.disasm(raw_bytes, virtual_address):
            disassembled.append(
                {
                    "address": insn.address,
                    "mnemonic": insn.mnemonic,
                    "operands": insn.op_str,
                    "bytes": insn.bytes,
                    "size": insn.size,
                }
            )

        return disassembled


def find_function_prologues(
    instructions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Finds likely function start points via prologue pattern matching.

    Scans the instruction list for a sequence of 0-6 consecutive `push`
    instructions followed by a `sub rsp, N` instruction — the pattern
    observed on real x86_64 binaries (Rust/LLVM-compiled and gcc/musl
    -compiled malware alike), which replaces the classic
    "push rbp; mov rbp, rsp" frame-pointer prologue that modern
    compilers often omit (-fomit-frame-pointer).

    Args:
        instructions: Instruction list as returned by
            disassemble_section().

    Returns:
        A list of dictionaries, one per match:
            - start_address: int, address of the first matched instruction
            - end_address: int, address immediately after the last
              matched instruction
            - bytes: bytes, concatenated bytes of the matched
              instructions

    Limitation:
        Heuristic, not exhaustive. Will miss functions whose prologue
        doesn't fit this shape at all. May also match "sub rsp, N"
        instructions that aren't actually function-start prologues
        (e.g. mid-function stack adjustments), since the check doesn't
        verify this is truly the first instruction of a function.
    """
    _MAX_PROLOGUE_PUSHES = 6

    function_prologues: list[dict[str, Any]] = []
    i = 0

    while i < len(instructions):
        push_count = 0
        while (
            i + push_count < len(instructions)
            and instructions[i + push_count]["mnemonic"] == "push"
            and push_count < _MAX_PROLOGUE_PUSHES
        ):
            push_count += 1

        sub_index = i + push_count

        if (
            sub_index < len(instructions)
            and instructions[sub_index]["mnemonic"] == "sub"
            and instructions[sub_index]["operands"].startswith("rsp, ")
        ):
            function_prologues.append(
                {
                    "start_address": instructions[i]["address"],
                    "end_address": instructions[sub_index]["address"]
                    + len(instructions[sub_index]["bytes"]),
                    "bytes": b"".join(
                        ins["bytes"] for ins in instructions[i : sub_index + 1]
                    ),
                }
            )

            i = sub_index + 1
        else:
            i += 1

    return function_prologues


# Syscall numbers considered suspicious for direct invocation
# (bypassing libc wrappers, which would normally show up in
# suspicious_imports.py via .dynsym — not available on static binaries).
# Values confirmed against the Linux kernel's syscall_64.tbl.
_SUSPICIOUS_SYSCALLS = {
    0x3B: "execve",
    0x65: "ptrace",
    0x38: "clone",
    0x13F: "memfd_create",
    0xAF: "init_module",
    0x139: "finit_module",
}

# How far back to look from a `syscall` instruction for the
# "mov (e|r)ax, N" that sets up its number. Real-world examples showed
# argument setup (mov rdi, ..., xor edx, edx, etc.) between the two.
_MAX_LOOKBACK = 10


def find_suspicious_sequences(
    instructions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Finds direct syscall invocations for a small set of suspicious
    syscall numbers.

    Detects direct syscall invocations for syscalls associated with
    suspicious behavior (process execution, anti-debugging, fileless
    execution, kernel module loading) — the same capability categories
    suspicious_imports.py flags via .dynsym, but reachable here even on
    statically linked binaries where .dynsym is empty.

    Args:
        instructions: Instruction list as returned by
            disassemble_section().

    Returns:
        A list of dictionaries, one per match:
            - start_address: int, address of the "mov eax/rax, N" instruction
            - end_address: int, address immediately after the "syscall"
              instruction
            - bytes: bytes, concatenated bytes from the mov to the syscall
              (NOTE: may include unrelated argument-setup instructions
              in between — see limitation below)
            - pattern_name: str, e.g. "direct_syscall_execve"

    Limitation:
        Only flags a fixed set of syscall numbers (see
        _SUSPICIOUS_SYSCALLS), not all syscalls — most direct syscalls
        in a statically linked binary are routine libc-internal
        behavior (futex, mmap, rt_sigprocmask, etc.) and would be pure
        noise if flagged indiscriminately. Also: matching "mov eax, N"
        without tracking register writes in between means the matched
        mov is not guaranteed to be the one that actually determines
        the syscall number at runtime (e.g. if eax is overwritten again
        before the syscall) — a heuristic, not a guarantee.

        This detection is only meaningful for statically linked
        binaries. Dynamically linked binaries route these operations
        through libc calls (which show up in suspicious_imports.py via
        .dynsym instead), so direct syscall instructions specific to
        our list are rare or absent there — confirmed empirically on
        RedXOR.elf and Wirenet.elf (both dynamic, 0 matches). Check
        extract_metadata()['is_static'] before relying on this result,
        the same caveat suspicious_imports.py already documents in
        reverse.
    """
    suspicious_sequences: list[dict[str, Any]] = []

    for i, insn in enumerate(instructions):

        if insn["mnemonic"] != "syscall":
            continue

        lookback_start = max(0, i - _MAX_LOOKBACK)
        for j in range(i - 1, lookback_start - 1, -1):
            candidate = instructions[j]

            is_mov_to_ax = candidate["mnemonic"] == "mov" and (
                candidate["operands"].startswith("eax, ")
                or candidate["operands"].startswith("rax, ")
            )

            if not is_mov_to_ax:
                continue

            value_str = candidate["operands"].split(", ")[1]

            try:
                syscall_number = int(value_str, 0)
            except ValueError:
                break

            if syscall_number in _SUSPICIOUS_SYSCALLS:
                pattern_name = (
                    f"direct_syscall_{_SUSPICIOUS_SYSCALLS[syscall_number]}"
                )
                suspicious_sequences.append(
                    {
                        "start_address": candidate["address"],
                        "end_address": insn["address"] + len(insn["bytes"]),
                        "bytes": b"".join(
                            ins["bytes"] for ins in instructions[j : i + 1]
                        ),
                        "pattern_name": pattern_name,
                    }
                )

            break

    return suspicious_sequences


def apply_wildcards(
    instructions: list[dict[str, Any]], match: dict[str, Any]
) -> str:
    """Converts a matched instruction range into a YARA hex pattern.

    Replaces operand bytes considered variable between builds (stack
    sizes in prologues, argument setup in syscall patterns) with `??`
    wildcards, keeping opcode bytes and the pattern-defining immediate
    (e.g. the syscall number) fixed.

    Uses Capstone's detailed disassembly mode to identify immediate
    operands and their byte length, then assumes the immediate is
    encoded in the trailing bytes of the instruction — true for the
    vast majority of x86_64 instruction forms (ModRM/SIB/displacement
    precede the immediate).

    Args:
        instructions: Full instruction list the match was found in
            (currently unused directly — kept for API symmetry/future
            use; match["bytes"] is re-disassembled instead, see below).
        match: A single match dict as returned by find_function_prologues()
            (no "pattern_name" key) or find_suspicious_sequences()
            (has "pattern_name" like "direct_syscall_execve").

    Returns:
        A YARA-compatible hex string, e.g. "55 48 89 ?? ?? 3D 00".

    Limitation:
        Assumes immediates are trailing bytes — not true for a small
        number of exotic x86_64 encodings. Only wildcards immediate
        operands, not memory-displacement or RIP-relative addresses
        that aren't modeled as a plain immediate by Capstone.
    """
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True

    match_instructions = list(cs.disasm(match["bytes"], match["start_address"]))

    is_syscall_pattern = "pattern_name" in match

    hex_parts: list[str] = []

    for idx, insn in enumerate(match_instructions):
        insn_bytes = insn.bytes

        if is_syscall_pattern:
            should_wildcard_this_insn = idx > 0 and insn.mnemonic != "syscall"
        else:
            should_wildcard_this_insn = idx == len(match_instructions) - 1

        if not should_wildcard_this_insn or insn.imm_size == 0:
            hex_parts.append(insn_bytes.hex(" ").upper())
            continue

        before = insn_bytes[: insn.imm_offset]
        wildcard_part = " ".join(["??"] * insn.imm_size)
        after = insn_bytes[insn.imm_offset + insn.imm_size :]

        parts = [before.hex(" ").upper(), wildcard_part, after.hex(" ").upper()]
        hex_parts.append(" ".join(p for p in parts if p))

    return " ".join(hex_parts)


def extract_byte_patterns(elf_path: str) -> dict[str, Any]:
    """Entry point: extracts all byte-level patterns from an ELF binary.

    Checks architecture support first. If unsupported, returns a result
    indicating so instead of raising, so callers (e.g. main.py) can
    continue the rest of the pipeline and report the limitation.

    Args:
        elf_path: Path to the ELF binary.

    Returns:
        A dictionary:
            - supported: bool, whether byte-pattern analysis ran
            - architecture: str, architecture string from parse_header()
            - patterns: list of dicts, each with "identifier" and
              "hex_bytes" ready for YaraRuleBuilder.add_hex_pattern().
              Empty list if unsupported or no patterns found.
    """
    architecture = parse_header(elf_path)["architecture"]

    if not is_architecture_supported(architecture):
        return {
            "supported": False,
            "architecture": architecture,
            "patterns": [],
        }

    instructions = disassemble_section(elf_path)
    prologues = find_function_prologues(instructions)
    suspicious = find_suspicious_sequences(instructions)

    patterns: list[dict[str, str]] = []

    for index, match in enumerate(prologues, start=1):
        identifier = f"p{index}"
        hex_bytes = apply_wildcards(instructions, match)
        patterns.append({"identifier": identifier, "hex_bytes": hex_bytes})
        pass

    for index, match in enumerate(suspicious, start=1):
        identifier = f"{match['pattern_name']}_{index}"
        hex_bytes = apply_wildcards(instructions, match)
        patterns.append({"identifier": identifier, "hex_bytes": hex_bytes})
        pass

    return {
        "supported": True,
        "architecture": architecture,
        "patterns": patterns,
    }


if __name__ == "__main__":
    result = extract_byte_patterns("corpus/malware/Mirai_64.elf")
    print(f"supported: {result['supported']}")
    print(f"architecture: {result['architecture']}")
    print(f"total patterns: {len(result['patterns'])}")
    for p in result["patterns"]:
        if "syscall" in p["identifier"]:
            print(p)
    print(result["patterns"][0])
