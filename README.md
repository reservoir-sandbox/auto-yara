# Auto-YARA

Automatic YARA rule generator for ELF malware binaries.


## Contents

- [main.py — Full Pipeline (MVP)](#mainpy--full-pipeline-mvp)
- [feature_extractor.py](#feature_extractorpy)
- [string_filter.py](#string_filterpy)
- [ranker.py](#rankerpy)
- [entropy.py](#entropypy)
- [whitelist_builder.py](#whitelist_builderpy)
- [suspicious_imports.py](#suspicious_importspy)
- [byte_pattern_extractor.py](#byte_pattern_extractorpy)
- [rule_builder.py](#rule_builderpy)
- [validator.py](#validatorpy)

---

## main.py — Full Pipeline (MVP)

Generates a complete, syntax-validated YARA rule from a raw ELF binary
in one command. Internally it extracts strings, filters them against
known malware-relevant patterns and a clean-binary whitelist, extracts
a small set of byte-level patterns (function prologues, direct
syscalls — see [byte_pattern_extractor.py](#byte_pattern_extractorpy)),
and assembles a rule with a condition that adapts to how many
indicators were found, plus a dynamically detected architecture check.
Optionally, the assembled rule can be run through an empirical
auto-improvement loop before being saved (see
[validator.py](#validatorpy)).

**Usage**

```bash
python main.py --input <path_to_elf> --name <rule_name> --output <path_to_yar>
```

**Arguments**

| Argument | Required | Description |
|---|---|---|
| `--input` | Yes | Path to the ELF binary to analyze |
| `--name` | Yes, unless `--features-only` | Name to give the generated YARA rule (architecture is auto-appended, e.g. `Mirai` becomes `Mirai_EM_X86_64`) |
| `--output` | Yes, unless `--features-only` | Path to save the generated `.yar` file |
| `--whitelist` | No | Path to clean-string whitelist (default: `whitelist/clean_strings.txt`) |
| `--features-only` | No | Skip rule generation; print all extracted features as JSON instead |
| `--rank-output` | No | Path to save the ranked features report (JSON) |
| `--full-byte-patterns` | No | With `--features-only`, print every extracted byte pattern instead of a 5-item preview |
| `--auto-improve` | No | Run the empirical auto-improvement loop (`validator.improve_rule`) on the generated rule before saving |

**Example**

```bash
python main.py --input corpus/malware/Mirai_64.elf --name Mirai --output output/mirai_auto.yar --auto-improve
```

```yara
import "elf"
rule Mirai_EM_X86_64
{
    meta:
        author = "auto-yara"
        entropy = "normal"

    strings:
        $s2 = "185.247.224.41"
        $s3 = "/proc/%d"
        $s4 = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        $s5 = "/bin/systemd-daemon"
        $s6 = "/etc/init/systemd-agent.conf"
        $s7 = "/dev/urandom"
        $s8 = "87.98.162.88"
        $s9 = "82.221.103.244"
        $s10 = "67.215.246.10"
        $bp4 = {41 56 41 55 41 54 55 53 48 83 EC ??}
        $bp5 = {41 56 41 55 41 54 55 53 48 81 EC ?? ?? ?? ??}

    condition:
        uint32(0) == 0x464C457F and elf.machine == elf.EM_X86_64 and 2 of ($s*) and 1 of ($bp*)
}
```

Note the gap at `$s1` — that identifier was removed by `--auto-improve`
because it caused a false positive against the clean corpus. See
[validator.py](#validatorpy) for how this decision gets made.

**Condition logic**

| Signal | Condition fragment |
|---|---|
| Strings: 0 found | (nothing added) |
| Strings: 1 found | `1 of ($s*)` |
| Strings: 2+ found | `2 of ($s*)` |
| Byte patterns: any found | `1 of ($bp*)` |

Architecture is detected automatically from the binary's ELF header
(`elf.machine == elf.EM_X86_64`, `elf.EM_386`, etc.) rather than
hardcoded — this matters because a fixed architecture check would
silently break detection on binaries compiled for a different
architecture than expected.

**Byte pattern selection**

Up to 5 byte patterns are included per rule (`select_byte_patterns_for_rule()`
in `main.py`), prioritizing direct-syscall patterns over function
prologues — a syscall match like `direct_syscall_execve` is far more
specific than a generic prologue like `48 83 EC ??`, which alone is
common across most compiled binaries. All selected patterns are
renamed to a shared `$bp` prefix so the condition can reference them
as one group (`1 of ($bp*)`).

Every generated rule is validated for syntax correctness via
`yara-python` before being saved.

**--features-only mode**

For debugging or inspection without generating a rule, run with
`--features-only` to print every extracted feature as JSON:

```bash
python main.py --input corpus/malware/Mirai_64.elf --features-only
```

```json
{
    "strings_filtered": [...],
    "imports": {
        "network": [], "process": [], "memory": [], "antidebug": [],
        "filesystem": [], "privileges": [], "other": []
    },
    "metadata": {
        "is_stripped": true, "has_upx": false, "has_rwx_segment": false,
        "has_exec_stack": false, "is_static": true
    },
    "rodata_entropy": "normal",
    "suspicious_imports": [],
    "byte_patterns": {
        "supported": true,
        "architecture": "EM_X86_64",
        "patterns": [
            { "identifier": "p1", "hex_bytes": "41 55 41 54 55 53 48 81 EC ?? ?? ?? ??" },
            { "identifier": "direct_syscall_execve_1", "hex_bytes": "B8 3B 00 00 00 0F 05" }
        ],
        "patterns_truncated": true,
        "patterns_total": 538
    }
}
```

> Note: statically linked binaries (like the Mirai sample above) will
> show empty `imports` and `suspicious_imports` — this is expected,
> not a bug. See [suspicious_imports.py](#suspicious_importspy) for why.

> By default, `byte_patterns.patterns` is truncated to 5 entries with
> `patterns_truncated: true` and `patterns_total` showing the real
> count. Pass `--full-byte-patterns` to print every extracted pattern.

**Known limitations (MVP scope)**

- **Batch mode**: only a single binary can be analyzed per run.
  Generating one rule from multiple samples of the same malware
  family (to capture variant-resistant indicators) was deferred —
  with only a handful of real malware samples available for testing,
  this logic couldn't be meaningfully validated.

---

## feature_extractor.py

Extracts strings, imports, and metadata from an ELF binary and saves
the result to JSON.

**Usage**

```bash
python feature_extractor.py --input <path_to_elf> --output <path_to_json>
```

**Example**

```bash
python feature_extractor.py --input corpus/clean/bat --output output/results.json
```

**Output format**

```json
{
    "strings": [
        { "value": "...", "section": ".rodata", "offset": "0x..." }
    ],
    "imports": {
        "network": ["socket", "connect"],
        "process": ["fork", "execve"],
        "memory": [],
        "antidebug": [],
        "filesystem": [],
        "privileges": [],
        "other": []
    },
    "metadata": {
        "is_stripped": true,
        "has_upx": false,
        "has_rwx_segment": false,
        "has_exec_stack": false,
        "is_static": false
    }
}
```

---

## string_filter.py

Filters raw extracted strings down to malware-relevant candidates
using an allow-list strategy (IP addresses, URLs, system paths,
email addresses), then removes any string that also appears in a
clean-binary whitelist.

**Usage**

```bash
python string_filter.py --input <path_to_elf> --output <path_to_json> [--whitelist <path>]
```

**Example**

```bash
python string_filter.py --input corpus/malware/mirai.elf --output output/mirai_filtered.json
```

**Output format**

```json
{
    "filtered_strings": [
        { "value": "/etc/config/hosts", "section": ".rodata", "offset": "0x14187" }
    ]
}
```

---
## ranker.py

Scores every extracted string and import with a numeric relevance
score, without filtering or truncating anything. Ranker's job is to
*annotate*, not *select* — the actual inclusion decision for a
generated rule is deferred to `validator.py` (Week 7), which can test
candidate feature sets empirically against the clean and malware
corpora rather than relying on a fixed heuristic threshold.

**Usage**

```bash
python ranker.py --input <path_to_elf> --output <path_to_json> [--whitelist <path>]
```

**Example**

```bash
python ranker.py --input corpus/malware/mirai.elf --output output/mirai_ranked.json
```

Also available as an optional flag on the main pipeline:

```bash
python main.py --input corpus/malware/mirai.elf --name Mirai --output output/mirai_auto.yar --rank-output output/mirai_ranked.json
```

**Scoring rules — strings**

| Signal | Score |
|---|---|
| IP address or URL | `+3.0` |
| Email address | `+3.0` |
| Botnet command (`ATTACK`, `SCAN`, `KILL`) | `+2.5` |
| Non-standard path (`/proc`, `/dev`, `/tmp`, `/var/run`, `/root`) or length > 20 | `+2.0` |
| Found in clean-string whitelist | `-5.0` |

**Scoring rules — imports**

Each imported symbol is scored by its `feature_extractor` category
weight (`antidebug` 2.0, `memory`/`process` 1.5, `network`/`privileges`
1.0, `filesystem` 0.5, `other` 0.0). Any suspicious combination
detected by `suspicious_imports.detect_suspicious_combinations()` (see
[suspicious_imports.py](#suspicious_importspy)) is added as its own
high-scoring entry (`+3.0`), separate from the individual imports
involved.

**Output format**

```json
{
    "ranked_strings": [
        { "value": "...", "section": ".rodata", "offset": "0x...", "score": 5.0 }
    ],
    "ranked_imports": [
        { "name": "ptrace", "category": "antidebug", "score": 2.0 },
        { "name": "antidebug+network", "category": "combo", "score": 3.0 }
    ],
    "byte_patterns": []
}
```

> `byte_patterns` here is a placeholder field, always empty — ranker
> does not yet score the byte patterns produced by
> `byte_pattern_extractor.py`. Scoring these (e.g. weighting
> `direct_syscall_*` patterns above generic prologues) is deferred to
> a future iteration.

**Known limitations**

Scoring is a context-free heuristic — it has no way to distinguish an
actual indicator (e.g. a real C2 IP) from incidental pattern matches
inside unrelated data, or from legitimate code that happens to
reference a URL or validate IP-like syntax. Testing against a clean
binary (`corpus/clean/bat`) surfaced concrete false positives:
IP-pattern matches inside concatenated version strings, botnet-command
substring matches inside unrelated text blobs, and import scores with
no clean-binary baseline. These are documented as known limitations
rather than patched ad hoc, since fixing them without an empirical
feedback loop (Week 7's `validator.py`) risks over-fitting to a single
sample. `main.py` currently builds rules from `string_filter` output
directly — `ranked_strings`/`ranked_imports` have no effect on
generated rules yet.

---

## entropy.py

Calculates Shannon entropy per ELF section to flag possible packing
or encryption.

**Usage**

```bash
python entropy.py
```

(Currently runs against a fixed set of test binaries defined at the
bottom of the file — pass paths as arguments in a future version.)

**Classification thresholds**

| Entropy | Classification |
|---|---|
| < 6.5 | `normal` |
| 6.5 – 7.0 | `suspicious` |
| ≥ 7.0 | `likely_packed` |

> Note: high entropy alone is not proof of malware — legitimate
> binaries with embedded data tables (fonts, Unicode tables, etc.)
> can also score high. Combine with other indicators.

---

## whitelist_builder.py

Builds a whitelist of strings common to clean Linux system binaries,
to filter out generic noise (e.g. `/dev/null`, GNU copyright notices)
that would otherwise pass the string_filter allow-list.

**Usage**

```bash
python whitelist_builder.py [--input <dir>] [--output <path>] [--min-occurrences <N>]
```

**Example**

```bash
python whitelist_builder.py --input corpus/clean_system --output whitelist/clean_strings.txt --min-occurrences 3
```

A string is included only if it appears in at least `min-occurrences`
different binaries in the input directory — this avoids over-counting
a string that simply repeats many times within a single file.

> On Windows, source binaries can be copied out of WSL2
> (e.g. `/bin/ls`, `/usr/bin/grep`) into the input directory first.

---

## suspicious_imports.py

Detects specific import combinations that together suggest malicious
capability beyond what any single import indicates.

| Combination | Flag |
|---|---|
| `ptrace` + `socket` | `antidebug+network` |
| `memfd_create` + `execve` | `fileless_execution` |
| `init_module` | `kernel_rootkit` |

```bash
python suspicious_imports.py
```

> **Limitation:** only effective on dynamically linked binaries.
> Statically linked binaries (common in IoT malware such as Mirai)
> have no `.dynsym` entries for these calls, since they're compiled
> directly into the binary. Check
> `extract_metadata()['is_static']` before relying on this result.
> See [byte_pattern_extractor.py](#byte_pattern_extractorpy) for the
> static-binary equivalent of this check.

---

## byte_pattern_extractor.py

Disassembles a binary's `.text` section (via Capstone) to extract
byte-level patterns: function prologues and direct syscall invocations
associated with suspicious behavior. Unlike string- or import-based
detection, these patterns target the actual executed code, which is
harder for malware authors to remove or obfuscate than plaintext
strings or dynamic-symbol imports.

**Usage**

```python
from byte_pattern_extractor import extract_byte_patterns

result = extract_byte_patterns("corpus/malware/Mirai_64.elf")
```

**Output format**

```json
{
    "supported": true,
    "architecture": "EM_X86_64",
    "patterns": [
        { "identifier": "p1", "hex_bytes": "41 55 41 54 55 53 48 81 EC ?? ?? ?? ??" },
        { "identifier": "direct_syscall_execve_1", "hex_bytes": "B8 3B 00 00 00 0F 05" }
    ]
}
```

**Scope**

- **Architecture**: x86_64 only. Any other architecture (e.g. `EM_ARM`,
  `EM_MIPS`) returns `{"supported": false, "architecture": ..., "patterns": []}`
  rather than raising, so the rest of the pipeline can continue.
  Multi-architecture support (MIPS/ARM) is not a design goal for this
  project — the 32-bit x86 Mirai sample encountered during development
  was incidental, not a deliberate target.
- **Function prologues** (`find_function_prologues`): heuristically
  matches 0–6 consecutive `push` instructions followed by
  `sub rsp, N`. This replaces the classic `push rbp; mov rbp, rsp`
  frame-pointer prologue, which failed to match on a real Rust/LLVM
  -compiled test binary — modern compilers frequently omit the frame
  pointer (`-fomit-frame-pointer`).
- **Direct syscalls** (`find_suspicious_sequences`): looks for
  `mov eax/rax, N` followed (within 10 instructions) by a `syscall`,
  for a fixed set of syscall numbers associated with suspicious
  capability — the same categories `suspicious_imports.py` flags via
  `.dynsym`, but reachable here even when `.dynsym` is empty:

  | Syscall | Number |
  |---|---|
  | `execve` | `0x3b` (59) |
  | `ptrace` | `0x65` (101) |
  | `clone` | `0x38` (56) |
  | `memfd_create` | `0x13f` (319) |
  | `init_module` | `0xaf` (175) |
  | `finit_module` | `0x139` (313) |

- **Wildcards** (`apply_wildcards`): converts a matched instruction
  range into a YARA hex pattern, replacing build-specific immediate
  values with `??` while keeping opcode bytes and (for syscall
  patterns) the syscall number itself fixed. Uses Capstone's
  `insn.imm_offset`/`insn.imm_size` to locate the immediate's exact
  bytes within the instruction — `operand.size` was tried first but
  reflects operation width (e.g. 8 for a 64-bit register), not the
  immediate's actual encoded byte length, and produced wrong wildcard
  ranges.

**Known limitations**

- **Direct syscall detection is only meaningful for static binaries.**
  Dynamically linked binaries route these operations through libc
  calls instead (which `suspicious_imports.py` catches via `.dynsym`),
  so direct syscall instructions specific to our list are rare or
  absent there — confirmed empirically on `RedXOR.elf` and
  `Wirenet.elf` (both dynamically linked, 0 matches). Check
  `extract_metadata()['is_static']` before relying on this result.
- Several malware samples (`Wraith.elf`, `Prometei.elf` — different
  files/hashes, same corrupted `e_shoff` value pointing past EOF) use
  deliberately corrupted ELF section headers as an anti-analysis
  technique; `pyelftools`' section-based APIs cannot process these
  files, including `parse_segments()` which internally needs a section
  for the dynamic string table. Not a bug in this codebase.
- Uses linear disassembly (sequential decoding from `.text` start), not
  control-flow-aware disassembly. Embedded non-code data in `.text`
  could be misread as instructions past that point.
- Prologue matching may flag `sub rsp, N` instructions that aren't
  actually at a function's start (e.g. mid-function stack
  adjustments), since there's no verification against symbol
  boundaries.
- XOR-decryption-loop detection (originally planned for this module)
  was dropped from scope: no available sample qualified after
  checking `Mirai_64.elf` (C2 strings are plaintext), `RedXOR.elf`
  (dynamically linked, normal entropy, plaintext strings — no visible
  XOR logic despite the name), and `Wirenet.elf` (has genuinely
  encrypted-looking strings in `.data`, but is dynamically linked,
  deprioritized in favor of the static-binary syscall detector).

---

## rule_builder.py

`YaraRuleBuilder` — a class for assembling YARA rule text
programmatically, with built-in syntax validation via `yara-python`.

```python
from rule_builder import YaraRuleBuilder

builder = YaraRuleBuilder("ExampleRule")
builder.set_meta("author", "auto-yara")
builder.add_string("s1", "example string")
builder.set_condition("uint32(0) == 0x464C457F and 1 of ($s*)")

print(builder.build())
print("Valid:", builder.validate())
```

**Methods**

| Method | Description |
|---|---|
| `set_meta(key, value)` | Adds a metadata field |
| `add_string(id, value, modifiers="")` | Adds a string pattern (auto-escaped, auto-prefixed with `$`) |
| `add_hex_pattern(id, hex_bytes)` | Adds a raw hex byte pattern (auto-prefixed with `$`) |
| `set_condition(text)` | Sets the rule's condition |
| `remove_feature(identifier)` | Removes a string or hex pattern by identifier (no leading `$`); returns `True` if something was removed |
| `build()` | Returns the complete rule as text |
| `validate()` | Compiles the rule via `yara-python`; returns `True`/`False` |

---

## validator.py

Measures a generated rule's real-world quality by compiling it and
running it against actual files, instead of trusting the heuristics
that built it. Where `ranker.py` scores features in the abstract
(*"IP addresses are usually suspicious"*), `validator.py` checks the
concrete fact (*"does this exact rule actually fire on this exact
file?"*) — and, when it doesn't like the answer, can rewrite the rule
itself.

**Usage**

```python
from rule_builder import YaraRuleBuilder
from validator import get_quality_report, improve_rule

builder = YaraRuleBuilder("Mirai_EM_X86_64")
# ... populate builder via add_string / add_hex_pattern / set_condition ...

report = get_quality_report(
    builder.build(),
    malware_paths=["corpus/malware/Mirai_64.elf"],
)
print(report["verdict"])  # "Good" / "Needs review" / "Unusable"

improved_builder = improve_rule(builder, ["corpus/malware/Mirai_64.elf"])
```

Also available on the main pipeline via `--auto-improve` (see
[main.py](#mainpy--full-pipeline-mvp)).

**Functions**

| Function | Description |
|---|---|
| `check_false_positives(rule_source, clean_paths=None)` | Compiles the rule and matches it against every file in `clean_paths` (a list of files/dirs, or the full `corpus/clean/` by default). Returns matched clean files with details on which `$s*`/`$bp*` identifiers fired. |
| `check_true_positives(rule_source, malware_paths)` | Matches the rule against an explicit list of malware files. Returns `{"matches": [...], "misses": [...]}` — files the rule caught vs. missed. |
| `get_quality_report(rule_source, malware_paths, clean_paths=None)` | Runs both checks and summarizes: `false_positive_count`, `true_positive_rate`, and a `verdict`. |
| `improve_rule(builder, malware_paths, clean_paths=None)` | Auto-improvement loop (see below). Mutates and returns the same `YaraRuleBuilder`. |

**Why `malware_paths` is explicit, not a directory scan**

Unlike the clean corpus (a fixed asset shipped with the tool, used to
validate *any* rule), the malware corpus in `corpus/malware/` holds
several unrelated families (Mirai, Chapros, RedXOR, Wirenet). A rule
generated from one file isn't expected to match a different family, so
scanning the whole directory would produce meaningless "misses" for
files the rule was never meant to catch. Callers pass the specific
file(s) that *should* match — in the CLI (`--auto-improve`), that's
just the file the rule was generated from
(`malware_paths=[args.input]`), since there is no user-supplied
malware corpus in the real deployment scenario (a user uploads one
file; the clean corpus is the tool's own asset, not something the user
provides).

**Quality verdicts**

| Condition | Verdict |
|---|---|
| `fp_count == 0` and `tp_rate == 1.0` | `Good` |
| `fp_count == 0` and `tp_rate < 1.0` | `Needs review` |
| `fp_count > 0` | `Unusable` |

**Auto-improvement loop (`improve_rule`)**

On each iteration:

1. Compile the current rule and check false positives.
2. If none — done.
3. Otherwise, extract the offending identifiers
   (`_extract_culprit_identifiers`, via YARA's `match.strings[i].identifier`,
   stripped of its leading `$`) minus any already rejected this run.
4. If candidates remain: remove one (`builder.remove_feature`), then
   immediately re-check true positives. If the removal dropped the
   rule's ability to catch its own malware sample, roll the removal
   back (restore from a `list.copy()` snapshot) and mark that
   identifier as rejected, so the same culprit isn't retried forever.
   Otherwise, keep the change and continue.
5. If no candidates remain (all have been tried and rejected):
   fall back to raising the `N of ($s*)` threshold in the condition by
   one (`_bump_string_threshold`, a regex-based rewrite of the
   condition text, capped at the number of available strings). If the
   threshold could be raised, loop again; if it was already at the
   maximum, stop — nothing left to try.

The loop always terminates: removal candidates strictly shrink
(rejected identifiers are never retried) and the threshold has a hard
ceiling, so there's no path to infinite looping.

**A rule that can't be fixed without trade-offs is reported honestly**

If the only string that produces a false positive is also the *only*
string that matches the malware sample, removing it drops true
positives to zero — `improve_rule` correctly refuses that trade,
rejects the culprit, and falls back to raising the match threshold.
If that still can't separate the malware sample from the clean corpus
(because there's no remaining distinguishing feature at all), the loop
exits with `false_positive_count == 0` but `true_positive_rate == 0.0`
— a `"Needs review"` verdict, not a silently "fixed" rule. This was
verified directly: a rule built from a single string that occurs in
both the malware sample and the clean corpus (`/dev/null`) alongside
two non-matching decoy strings ends up with an unsatisfiable
`2 of ($s*)` condition, honestly reported as `Needs review` rather
than `Good`.

**Verified on real corpus**

Run against a real Mirai_64.elf-derived rule with three strings
(`/proc/self/exe`, `rsa_encrypt`, `/dev/null`) against the real clean
corpus: `BEFORE: 2 fp, 1.0 tp, Unusable` →
`AFTER: 0 fp, 1.0 tp, Good`, with `/proc/self/exe` and `/dev/null`
removed as culprits (both independently confirmed present in
`corpus/clean/busybox_x86_64`) and `rsa_encrypt` — a real,
distinguishing indicator — retained.

**Known limitations**

- `yara.StringMatch`/`yara.StringMatchInstance` structure was
  confirmed empirically against the installed `yara-python` version
  (`.identifier`, `.instances`, `.is_xor` on the former;
  `.matched_data`, `.matched_length`, `.offset`, `.plaintext`,
  `.xor_key` on the latter) rather than assumed, since this API has
  changed across `yara-python` versions.
- `improve_rule` removes one culprit per iteration and re-validates
  both directions (FP and TP) each time, rather than removing all
  flagged identifiers at once — slower, but avoids over-removing
  features whose combined loss would hurt TP even if no single one
  does.
- The threshold-bump fallback only tightens `N of ($s*)`; it has no
  equivalent adjustment for `$bp*` (byte pattern) conditions, and does
  not attempt to combine string and byte-pattern conditions in new
  ways.
