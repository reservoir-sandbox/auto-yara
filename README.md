# Auto-YARA

Automatic YARA rule generator for ELF malware binaries.

> 🚧 Work in progress — MVP complete (Week 4 of 7)

## Contents

- [main.py — Full Pipeline (MVP)](#mainpy--full-pipeline-mvp)
- [feature_extractor.py](#feature_extractorpy)
- [string_filter.py](#string_filterpy)
- [ranker.py](#rankerpy)
- [entropy.py](#entropypy)
- [whitelist_builder.py](#whitelist_builderpy)
- [suspicious_imports.py](#suspicious_importspy)
- [rule_builder.py](#rule_builderpy)

---

## main.py — Full Pipeline (MVP)

Generates a complete, syntax-validated YARA rule from a raw ELF binary
in one command. Internally it extracts strings, filters them against
known malware-relevant patterns and a clean-binary whitelist, and
assembles a rule with a condition that adapts to how many indicators
were found, plus a dynamically detected architecture check.

**Usage**

```bash
python main.py --input <path_to_elf> --name <rule_name> --output <path_to_yar>
```

**Arguments**

| Argument | Required | Description |
|---|---|---|
| `--input` | Yes | Path to the ELF binary to analyze |
| `--name` | Yes, unless `--features-only` | Name to give the generated YARA rule (architecture is auto-appended, e.g. `Mirai` becomes `Mirai_EM_386`) |
| `--output` | Yes, unless `--features-only` | Path to save the generated `.yar` file |
| `--whitelist` | No | Path to clean-string whitelist (default: `whitelist/clean_strings.txt`) |
| `--features-only` | No | Skip rule generation; print all extracted features as JSON instead |

**Example**

```bash
python main.py --input corpus/malware/mirai.elf --name Mirai --output output/mirai_auto.yar
```

```yara
import "elf"
rule Mirai_EM_386
{
    meta:
        author = "auto-yara"
        entropy = "normal"

    strings:
        $s1 = "wget -O /tmp/dvrHelper http://"
        $s2 = "/etc/services"
        $s3 = "/etc/resolv.conf"
        $s4 = "/etc/config/resolv.conf"
        $s5 = "/etc/hosts"
        $s6 = "/etc/config/hosts"

    condition:
        uint32(0) == 0x464C457F and elf.machine == elf.EM_386 and 2 of ($s*)
}
```

**Condition logic**

| Strings found | Condition used |
|---|---|
| 0 | `magic and arch` only |
| 1 | `magic and arch and 1 of ($s*)` |
| 2+ | `magic and arch and 2 of ($s*)` |

Architecture is detected automatically from the binary's ELF header
(`elf.machine == elf.EM_X86_64`, `elf.EM_386`, etc.) rather than
hardcoded — this matters because a fixed architecture check would
silently break detection on binaries compiled for a different
architecture than expected.

Every generated rule is validated for syntax correctness via
`yara-python` before being saved.

**--features-only mode**

For debugging or inspection without generating a rule, run with
`--features-only` to print every extracted feature as JSON:

```bash
python main.py --input corpus/malware/mirai.elf --features-only
```

```json
{
    "strings_filtered": [...],
    "imports": {
        "network": [], "process": [], "memory": [], "antidebug": [],
        "filesystem": [], "privileges": [], "other": []
    },
    "metadata": {
        "is_stripped": false, "has_upx": false, "has_rwx_segment": false,
        "has_exec_stack": false, "is_static": true
    },
    "rodata_entropy": "normal",
    "suspicious_imports": []
}
```

> Note: statically linked binaries (like the Mirai sample above) will
> show empty `imports` and `suspicious_imports` — this is expected,
> not a bug. See [suspicious_imports.py](#suspicious_importspy) for why.

**Known limitations (MVP scope)**

- **Hex byte patterns**: `YaraRuleBuilder.add_hex_pattern()` exists
  and is tested, but `main.py` doesn't generate hex patterns
  automatically. A simple "first N bytes of the file" approach was
  considered and rejected — it just duplicates the existing ELF
  magic check without adding signal. Meaningful hex patterns would
  require disassembly-level analysis of unique malware code/data,
  which is out of scope for this MVP.
- **Batch mode**: only a single binary can be analyzed per run.
  Generating one rule from multiple samples of the same malware
  family (to capture variant-resistant indicators) was deferred —
  with only one real malware sample available for testing, this
  logic couldn't be meaningfully validated.

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

> `byte_patterns` is reserved for Week 6 (`byte_pattern_extractor.py`)
> and is always empty for now.

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
| `add_hex_pattern(id, hex_bytes)` | Adds a raw hex byte pattern |
| `set_condition(text)` | Sets the rule's condition |
| `build()` | Returns the complete rule as text |
| `validate()` | Compiles the rule via `yara-python`; returns `True`/`False` |
