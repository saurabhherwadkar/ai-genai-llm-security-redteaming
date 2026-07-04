"""
Pydantic schema definitions for security red-teaming data models.

Defines the data structures for attack payloads, vulnerability reports,
scan results, and defense evaluations based on OWASP LLM Top 10.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class VulnerabilityCategory(str, Enum):
    """
    OWASP Top 10 for LLM Applications vulnerability categories.

    Based on the 2025 edition of the OWASP LLM security framework.
    """

    # LLM01: Manipulation of model behavior through crafted inputs
    PROMPT_INJECTION = "prompt_injection"
    # LLM02: Bypassing safety guardrails to produce harmful content
    JAILBREAK = "jailbreak"
    # LLM03: Extracting training data or sensitive information
    DATA_LEAKAGE = "data_leakage"
    # LLM04: Granting LLM unchecked ability to take actions
    EXCESSIVE_AGENCY = "excessive_agency"
    # LLM05: Generating unsafe code, scripts, or formatted output
    INSECURE_OUTPUT = "insecure_output"


class Severity(str, Enum):
    """Severity classification for discovered vulnerabilities."""

    # Immediate threat requiring urgent remediation
    CRITICAL = "critical"
    # Significant risk that should be addressed quickly
    HIGH = "high"
    # Moderate risk that should be planned for remediation
    MEDIUM = "medium"
    # Minor risk with limited impact
    LOW = "low"


class AttackPayload(BaseModel):
    """
    Represents a single attack payload to test against a target LLM.

    Contains the attack prompt, metadata about the attack category,
    and the expected behavior if the attack succeeds.
    """

    # The attack prompt to send to the target LLM
    prompt: str = Field(description="Attack prompt payload")
    # Category of vulnerability being targeted
    category: VulnerabilityCategory = Field(description="Attack category")
    # Human-readable name for this attack technique
    technique_name: str = Field(description="Name of the attack technique")
    # Description of what a successful attack would look like
    success_criteria: str = Field(description="What constitutes a successful attack")
    # Optional system message to use with the attack
    system_message: str = Field(
        default="You are a helpful assistant.",
        description="System message context for the attack",
    )


class AttackResult(BaseModel):
    """
    Result of executing a single attack against the target LLM.

    Records whether the attack succeeded, the target's response,
    and classification details.
    """

    # The original attack payload that was executed
    payload: AttackPayload = Field(description="The attack that was executed")
    # Whether the attack bypassed the target's defenses
    success: bool = Field(description="Whether the attack succeeded")
    # The target LLM's response to the attack
    target_response: str = Field(description="Target LLM response")
    # Confidence score that the attack succeeded (0.0 to 1.0)
    confidence: float = Field(default=0.0, description="Confidence in success assessment")
    # Severity if the attack succeeded
    severity: Severity = Field(default=Severity.LOW, description="Severity if successful")
    # Explanation of why the attack succeeded or failed
    analysis: str = Field(default="", description="Analysis of the result")
    # Response latency from the target
    latency_ms: float = Field(default=0.0, description="Target response latency")


class Vulnerability(BaseModel):
    """
    A confirmed vulnerability discovered during red-teaming.

    Contains the evidence, severity, and recommended remediation.
    """

    # Unique identifier for this vulnerability
    vuln_id: str = Field(description="Vulnerability identifier")
    # Category from OWASP LLM Top 10
    category: VulnerabilityCategory = Field(description="Vulnerability category")
    # Severity classification
    severity: Severity = Field(description="Severity level")
    # Short title describing the vulnerability
    title: str = Field(description="Vulnerability title")
    # Detailed description of the vulnerability
    description: str = Field(description="Detailed description")
    # The attack that exposed this vulnerability
    evidence: AttackResult = Field(description="Evidence from successful attack")
    # Recommended remediation steps
    remediation: str = Field(description="Suggested fix or mitigation")
    # OWASP reference identifier
    owasp_reference: str = Field(default="", description="OWASP LLM Top 10 reference")


class DefenseResult(BaseModel):
    """
    Result of testing a defense mechanism against an attack.

    Records whether the defense successfully blocked the attack.
    """

    # Name of the defense mechanism tested
    defense_name: str = Field(description="Defense mechanism name")
    # The attack that was used to test the defense
    attack: AttackPayload = Field(description="Attack used for testing")
    # Whether the defense successfully blocked the attack
    blocked: bool = Field(description="Whether the defense blocked the attack")
    # The filtered/modified output after defense processing
    filtered_output: str = Field(default="", description="Output after defense filtering")
    # Explanation of the defense result
    analysis: str = Field(default="", description="Analysis of defense effectiveness")


class ScanRequest(BaseModel):
    """
    Request to initiate a security scan against a target LLM.

    Specifies which categories to test and the target's system prompt.
    """

    # System message/prompt of the target LLM being tested
    target_system_prompt: str = Field(description="Target LLM system prompt")
    # Categories to test (defaults to all)
    categories: list[VulnerabilityCategory] = Field(
        default_factory=lambda: list(VulnerabilityCategory),
        description="Categories to test",
    )
    # Maximum attack attempts per category
    max_attempts_per_category: int = Field(default=5, description="Max attempts per category")
    # Whether to test defenses after finding vulnerabilities
    test_defenses: bool = Field(default=True, description="Whether to test defenses")


class ScanResult(BaseModel):
    """
    Complete result of a security scan session.

    Contains all attack results, confirmed vulnerabilities, and summary metrics.
    """

    # Unique identifier for this scan
    scan_id: str = Field(description="Unique scan identifier")
    # Timestamp when the scan started
    started_at: datetime = Field(description="Scan start time")
    # Timestamp when the scan completed
    completed_at: datetime | None = Field(default=None, description="Scan completion time")
    # Target system prompt that was tested
    target_system_prompt: str = Field(description="Target system prompt")
    # All attack results from the scan
    attack_results: list[AttackResult] = Field(
        default_factory=list, description="All attack results"
    )
    # Confirmed vulnerabilities found
    vulnerabilities: list[Vulnerability] = Field(
        default_factory=list, description="Confirmed vulnerabilities"
    )
    # Defense test results
    defense_results: list[DefenseResult] = Field(
        default_factory=list, description="Defense test results"
    )
    # Total attacks executed
    total_attacks: int = Field(default=0, description="Total attacks attempted")
    # Number of successful attacks
    successful_attacks: int = Field(default=0, description="Successful attacks")
    # Overall risk score (0.0 to 10.0)
    risk_score: float = Field(default=0.0, description="Overall risk score")
