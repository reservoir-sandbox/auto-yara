import yara  # type: ignore


class YaraRuleBuilder:
    """Builds YARA rule text from extracted ELF features."""

    def __init__(self, rule_name: str) -> None:
        """..."""
        self.rule_name = rule_name
        self.meta: dict[str, str] = {}
        self.strings: list[tuple[str, str, str]] = []  # id, value, modifiers
        self.hex_patterns: list[tuple[str, str]] = []  # id, hex bytes
        self.condition: str = ""

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
        lines = [f"rule {self.rule_name}", "{"]

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
    builder = YaraRuleBuilder("ELF_Mirai_x86_Test")
    builder.set_meta("author", "auto-yara")
    builder.set_meta("family", "Mirai")

    builder.add_string("s1", "wget -O /tmp/dvrHelper http://")
    builder.add_string("s2", "/etc/config/resolv.conf")
    builder.add_string("s3", "/etc/config/hosts")

    builder.set_condition("uint32(0) == 0x464C457F and 2 of ($s*)")

    rule_text = builder.build()
    print(rule_text)
    print()
    print("Valid:", builder.validate())

    # Проверка матчинга на реальном файле
    compiled_rule = yara.compile(source=rule_text)
    matches = compiled_rule.match("corpus/malware/mirai.elf")
    print("Matches on Mirai:", matches)

    # Контрольная проверка — НЕ должно сработать на чистом бинаре
    matches_clean = compiled_rule.match("corpus/clean/bat")
    print("Matches on bat (should be empty):", matches_clean)
