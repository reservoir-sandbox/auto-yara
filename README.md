# Auto-YARA

Automatic YARA rule generator for ELF malware binaries.

> 🚧 Work in progress — MVP complete (Week 4 of 7)

## Contents

- [main.py — Full Pipeline (MVP)](#mainpy--full-pipeline-mvp)
- [feature_extractor.py](#feature_extractorpy)
- [string_filter.py](#string_filterpy)
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
were found.

**Usage**

```bash
python main.py --input <path_to_elf> --name <rule_name> --output <path_to_yar>
```

**Arguments**

| Argument | Required | Description |
|---|---|---|
| `--input` | Yes | Path to the ELF binary to analyze |
| `--name` | Yes | Name to give the generated YARA rule |
| `--output` | Yes | Path to save the generated `.yar` file |
| `--whitelist` | No | Path to clean-string whitelist (default: `whitelist/clean_strings.txt`) |

**Example**

```bash
python main.py --input corpus/malware/mirai.elf --name ELF_Mirai_Auto --output output/mirai_auto.yar
```

```yara
rule ELF_Mirai_Auto
{
    meta:
        author = "auto-yara"

    strings:
        $s1 = "wget -O /tmp/dvrHelper http://"
        $s2 = "/etc/services"
        $s3 = "/etc/resolv.conf"
        $s4 = "/etc/config/resolv.conf"
        $s5 = "/etc/hosts"
        $s6 = "/etc/config/hosts"

    condition:
        uint32(0) == 0x464C457F and 2 of ($s*)
}
```

**Condition logic**

| Strings found | Condition used |
|---|---|
| 0 | `uint32(0) == 0x464C457F` only |
| 1 | `... and 1 of ($s*)` |
| 2+ | `... and 2 of ($s*)` |

Every generated rule is validated for syntax correctness via
`yara-python` before being saved to disk.

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
