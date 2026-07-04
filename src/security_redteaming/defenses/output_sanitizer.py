"""
Output sanitization defense module for securing LLM-generated content.

Detects and neutralizes dangerous content in LLM outputs including
XSS payloads, SQL injection strings, command injection patterns,
and other executable content that could compromise downstream systems.
"""

import re

from security_redteaming.models.schemas import AttackPayload, DefenseResult
from security_redteaming.utils.logger import get_logger

# Initialize logger for this module
logger = get_logger(__name__)

# Dangerous output patterns that should be sanitized
DANGEROUS_OUTPUT_PATTERNS = {
    "xss": [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=\s*[\"']",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
    ],
    "sql_injection": [
        r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+.*(?:FROM|INTO|TABLE|SET)",
        r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|AND\s+1\s*=\s*1)",
        r"--\s*$",
        r";\s*(?:DROP|DELETE|UPDATE)\s",
    ],
    "command_injection": [
        r"\$\(.*\)",
        r"`[^`]+`",
        r"\|\s*(?:rm|cat|wget|curl|nc)\s",
        r"&&\s*(?:rm|cat|wget|curl)\s",
        r";\s*(?:rm|cat|wget|curl|chmod)\s",
    ],
    "csv_injection": [
        r"^[=+@\-]",
        r"=CMD\(",
        r"\+SYSTEM\(",
        r"=HYPERLINK\(",
    ],
}


class OutputSanitizer:
    """
    Sanitizes LLM output to prevent dangerous content from reaching downstream systems.

    Detects XSS, SQL injection, command injection, CSV injection, and other
    patterns that could be exploited when the output is rendered or processed.
    """

    def __init__(self, strict_mode: bool = False) -> None:
        """
        Initialize the output sanitizer.

        Args:
            strict_mode: If True, block any output with suspicious patterns.
                        If False, sanitize patterns but allow modified output through.
        """
        # Whether to block entirely or just sanitize
        self._strict_mode = strict_mode
        # Compile all patterns for efficient matching
        self._compiled_patterns: dict[str, list[re.Pattern]] = {}
        for category, patterns in DANGEROUS_OUTPUT_PATTERNS.items():
            self._compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns
            ]

    async def sanitize(self, attack: AttackPayload, llm_output: str) -> DefenseResult:
        """
        Sanitize LLM output for dangerous content.

        Args:
            attack: The attack that produced this output.
            llm_output: The raw LLM output to sanitize.

        Returns:
            DefenseResult with sanitized output and detection details.
        """
        logger.debug("sanitizing_output", output_length=len(llm_output))

        # Track all detected patterns
        detections: list[dict[str, str]] = []

        # Check output against all pattern categories
        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(llm_output)
                if matches:
                    for match in matches:
                        detections.append({"category": category, "match": str(match)[:100]})

        # If no dangerous patterns found, pass through
        if not detections:
            return DefenseResult(
                defense_name="output_sanitizer",
                attack=attack,
                blocked=False,
                filtered_output=llm_output,
                analysis="No dangerous patterns detected in output.",
            )

        # Dangerous patterns detected
        logger.warning(
            "dangerous_output_detected",
            detection_count=len(detections),
            categories=list(set(d["category"] for d in detections)),
        )

        # In strict mode, block entirely
        if self._strict_mode:
            return DefenseResult(
                defense_name="output_sanitizer_strict",
                attack=attack,
                blocked=True,
                filtered_output="[BLOCKED] Output contained potentially dangerous content.",
                analysis=f"Detected {len(detections)} dangerous patterns: "
                + ", ".join(f"{d['category']}:{d['match'][:30]}" for d in detections[:5]),
            )

        # In permissive mode, sanitize the dangerous patterns
        sanitized_output = self._sanitize_content(llm_output)

        return DefenseResult(
            defense_name="output_sanitizer_permissive",
            attack=attack,
            blocked=True,
            filtered_output=sanitized_output,
            analysis=f"Sanitized {len(detections)} dangerous patterns from output.",
        )

    def _sanitize_content(self, content: str) -> str:
        """
        Remove or neutralize dangerous patterns from content.

        Args:
            content: Raw content to sanitize.

        Returns:
            Sanitized content with dangerous patterns neutralized.
        """
        sanitized = content

        # Remove script tags and their content
        sanitized = re.sub(r"<script[^>]*>.*?</script>", "[REMOVED_SCRIPT]", sanitized, flags=re.IGNORECASE | re.DOTALL)

        # Neutralize javascript: protocol
        sanitized = re.sub(r"javascript:", "javascript-disabled:", sanitized, flags=re.IGNORECASE)

        # Neutralize event handlers
        sanitized = re.sub(r"(on\w+)\s*=\s*([\"'])", r"data-disabled-\1=\2", sanitized, flags=re.IGNORECASE)

        # Remove iframe and object tags
        sanitized = re.sub(r"<iframe[^>]*>.*?</iframe>", "[REMOVED_IFRAME]", sanitized, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r"<object[^>]*>.*?</object>", "[REMOVED_OBJECT]", sanitized, flags=re.IGNORECASE | re.DOTALL)

        # Neutralize CSV injection prefixes
        sanitized = re.sub(r"^([=+@\-])", r"'\1", sanitized, flags=re.MULTILINE)

        return sanitized

    def detect_patterns(self, content: str) -> list[dict[str, str]]:
        """
        Detect dangerous patterns in content without modifying it.

        Useful for analysis and reporting purposes.

        Args:
            content: Content to analyze.

        Returns:
            List of detected pattern dictionaries with category and match.
        """
        detections = []

        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(content)
                for match in matches:
                    detections.append({"category": category, "match": str(match)[:100]})

        return detections
