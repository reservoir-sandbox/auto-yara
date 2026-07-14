import yara


class YaraRuleBuilder:
    """Builds YARA rule text from extracted ELF features."""

    def __init__(self, rule_name: str) -> None:
        """..."""
        self.rule_name = rule_name
        self.meta: dict[str, str] = {}
        self.strings: list[tuple[str, str, str]] = []  # id, value, modifiers
        self.hex_patterns: list[tuple[str, str]] = []  # id, hex bytes
        self.condition: str = ""
        self.imports: set[str] = set()

    def add_import(self, module_name: str) -> None:
        """Adds a YARA module import (e.g. "math", "elf", "pe").

        Args:
            module_name: Name of the YARA module to import.
        """
        self.imports.add(module_name)

    def add_string(
        self, identifier: str, value: str, modifiers: str = ""
    ) -> None:
        """Adds a string to the YARA rule.

        Args:
            identifier: Unique identifier for the string (e.g., "$s1").
            value: The string value to match.
            modifiers: Optional YARA string modifiers (e.g., "nocase").
        """
        escaped_value = value.replace("\\", "\\\\").replace('"', '\\"')
        self.strings.append((identifier, escaped_value, modifiers))

    def set_meta(self, key: str, value: str) -> None:
        """Sets a metadata field for the YARA rule.

        Args:
            key: Metadata key (e.g., "author").
            value: Metadata value.
        """
        self.meta[key] = value

    def add_hex_pattern(self, identifier: str, hex_bytes: str) -> None:
        """Adds a hexadecimal pattern to the YARA rule.

        Args:
            identifier: Unique identifier for the pattern (e.g., "$h1").
            hex_bytes: The hexadecimal bytes to match.
        """
        self.hex_patterns.append((identifier, hex_bytes))

    def set_condition(self, condition_text: str) -> None:
        """Sets the condition for the YARA rule.

        Args:
            condition_text: The condition text to set.
        """
        self.condition = condition_text

    def build(self) -> str:
        """Builds the complete YARA rule text."""
        lines = []

        for module in sorted(self.imports):
            lines.append(f'import "{module}"')

        if self.imports:
            lines.append("")

        lines.append(f"rule {self.rule_name}")
        lines.append("{")

        if self.meta:
            lines.append("    meta:")
            for key, value in self.meta.items():
                lines.append(f'        {key} = "{value}"')
            lines.append("")

        if self.strings or self.hex_patterns:
            lines.append("    strings:")
            for identifier, value, modifiers in self.strings:
                mod_str = f" {modifiers}" if modifiers else ""
                lines.append(f'        ${identifier} = "{value}"{mod_str}')
            for identifier, hex_bytes in self.hex_patterns:
                lines.append(f"        ${identifier} = {{{hex_bytes}}}")
            lines.append("")

        if self.condition:
            lines.append("    condition:")
            lines.append(f"        {self.condition}")

        lines.append("}")

        return "\n".join(lines)

    def remove_feature(self, identifier: str) -> bool:
        """Removes a string or hex pattern by identifier.

        Args:
            identifier: The identifier to remove (without leading "$").

        Returns:
            True if a feature was removed, False if no match was found.
        """
        original_string_count = len(self.strings)
        original_hex_count = len(self.hex_patterns)

        self.strings = [s for s in self.strings if s[0] != identifier]
        self.hex_patterns = [h for h in self.hex_patterns if h[0] != identifier]

        if len(self.strings) < original_string_count:
            return True
        if len(self.hex_patterns) < original_hex_count:
            return True
        return False

    def validate(self) -> bool:
        """Validates the YARA rule for basic correctness.

        Returns:
            True if the rule is valid, False otherwise.
        """
        try:
            yara.compile(source=self.build())
            return True
        except yara.SyntaxError as e:
            print(f"YARA rule validation error: {e}")
            return False


if __name__ == "__main__":
    builder = YaraRuleBuilder("ExampleRule")
    builder.add_import("math")
    builder.set_meta("author", "auto-yara")
    builder.add_string("s1", "example string")
    builder.set_condition(
        "uint32(0) == 0x464C457F and 1 of ($s*) and "
        "math.entropy(0, filesize) > 7.0"
    )

    print(repr(builder.build()))
    print("Valid:", builder.validate())
