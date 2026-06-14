Auto-YARA

Automatic YARA rule generator for ELF malware binaries.

> Work in progress

---

## feature_extractor.py

Extracts strings, imports, and metadata from an ELF binary and saves to JSON.

**Usage:**
```bash
python feature_extractor.py --input <path_to_elf> --output <path_to_json>
```

**Example:**
```bash
python feature_extractor.py --input corpus/clean/bat --output output/results.json
```

**Output format:**
```json
{
    "strings": [...],
    "imports": {...},
    "metadata": {...}
}
```
