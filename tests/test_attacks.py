"""
Unit tests for attack generators.

Tests payload generation, result evaluation, and category classification
for all supported attack types.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from security_redteaming.attacks.prompt_injection import PromptInjectionAttackGenerator
from security_redteaming.attacks.jailbreak import JailbreakAttackGenerator
from security_redteaming.attacks.data_leakage import DataLeakageAttackGenerator
from security_redteaming.attacks.excessive_agency import ExcessiveAgencyAttackGenerator
from security_redteaming.attacks.insecure_output import InsecureOutputAttackGenerator
from security_redteaming.models.schemas import AttackPayload, VulnerabilityCategory


class TestPromptInjectionGenerator:
    """Tests for the Prompt Injection attack generator."""

    @pytest.fixture
    def generator(self, mock_attacker_client: MagicMock) -> PromptInjectionAttackGenerator:
        """Create a generator with mock client."""
        return PromptInjectionAttackGenerator(attacker_client=mock_attacker_client)

    @pytest.mark.asyncio
    async def test_generates_correct_number_of_payloads(
        self, generator: PromptInjectionAttackGenerator
    ) -> None:
        """Test that the correct number of payloads is generated."""
        payloads = await generator.generate_payloads(
            target_system_prompt="You are helpful.", num_payloads=3
        )
        assert len(payloads) == 3

    @pytest.mark.asyncio
    async def test_all_payloads_have_correct_category(
        self, generator: PromptInjectionAttackGenerator
    ) -> None:
        """Test that all generated payloads have the correct category."""
        payloads = await generator.generate_payloads(
            target_system_prompt="You are helpful.", num_payloads=5
        )
        for payload in payloads:
            assert payload.category == VulnerabilityCategory.PROMPT_INJECTION

    @pytest.mark.asyncio
    async def test_payloads_contain_injection_content(
        self, generator: PromptInjectionAttackGenerator
    ) -> None:
        """Test that payloads contain actual injection attempt content."""
        payloads = await generator.generate_payloads(
            target_system_prompt="You are helpful.", num_payloads=5
        )
        for payload in payloads:
            assert len(payload.prompt) > 20
            assert payload.technique_name != ""

    def test_category_property(self, generator: PromptInjectionAttackGenerator) -> None:
        """Test the category property returns correct value."""
        assert generator.category == VulnerabilityCategory.PROMPT_INJECTION

    def test_technique_names_property(self, generator: PromptInjectionAttackGenerator) -> None:
        """Test that technique names are defined."""
        assert len(generator.technique_names) >= 3

    @pytest.mark.asyncio
    async def test_evaluate_result_blocked(
        self, generator: PromptInjectionAttackGenerator, sample_attack_payload: AttackPayload
    ) -> None:
        """Test evaluation of a blocked attack."""
        result = await generator.evaluate_result(
            payload=sample_attack_payload,
            target_response="I cannot help with that request.",
            latency_ms=250.0,
        )
        assert result.success is False
        assert result.confidence <= 0.5


class TestJailbreakGenerator:
    """Tests for the Jailbreak attack generator."""

    @pytest.fixture
    def generator(self, mock_attacker_client: MagicMock) -> JailbreakAttackGenerator:
        """Create a generator with mock client."""
        return JailbreakAttackGenerator(attacker_client=mock_attacker_client)

    @pytest.mark.asyncio
    async def test_generates_payloads(self, generator: JailbreakAttackGenerator) -> None:
        """Test jailbreak payload generation."""
        payloads = await generator.generate_payloads(
            target_system_prompt="You are a safe assistant.", num_payloads=5
        )
        assert len(payloads) == 5
        for payload in payloads:
            assert payload.category == VulnerabilityCategory.JAILBREAK

    def test_category_property(self, generator: JailbreakAttackGenerator) -> None:
        """Test category property."""
        assert generator.category == VulnerabilityCategory.JAILBREAK


class TestDataLeakageGenerator:
    """Tests for the Data Leakage attack generator."""

    @pytest.fixture
    def generator(self, mock_attacker_client: MagicMock) -> DataLeakageAttackGenerator:
        """Create a generator with mock client."""
        return DataLeakageAttackGenerator(attacker_client=mock_attacker_client)

    @pytest.mark.asyncio
    async def test_generates_payloads(self, generator: DataLeakageAttackGenerator) -> None:
        """Test data leakage payload generation."""
        payloads = await generator.generate_payloads(
            target_system_prompt="Secret: password123", num_payloads=5
        )
        assert len(payloads) == 5
        for payload in payloads:
            assert payload.category == VulnerabilityCategory.DATA_LEAKAGE


class TestExcessiveAgencyGenerator:
    """Tests for the Excessive Agency attack generator."""

    @pytest.fixture
    def generator(self, mock_attacker_client: MagicMock) -> ExcessiveAgencyAttackGenerator:
        """Create a generator with mock client."""
        return ExcessiveAgencyAttackGenerator(attacker_client=mock_attacker_client)

    @pytest.mark.asyncio
    async def test_generates_payloads(self, generator: ExcessiveAgencyAttackGenerator) -> None:
        """Test excessive agency payload generation."""
        payloads = await generator.generate_payloads(
            target_system_prompt="You can help with queries.", num_payloads=5
        )
        assert len(payloads) == 5
        for payload in payloads:
            assert payload.category == VulnerabilityCategory.EXCESSIVE_AGENCY


class TestInsecureOutputGenerator:
    """Tests for the Insecure Output attack generator."""

    @pytest.fixture
    def generator(self, mock_attacker_client: MagicMock) -> InsecureOutputAttackGenerator:
        """Create a generator with mock client."""
        return InsecureOutputAttackGenerator(attacker_client=mock_attacker_client)

    @pytest.mark.asyncio
    async def test_generates_payloads(self, generator: InsecureOutputAttackGenerator) -> None:
        """Test insecure output payload generation."""
        payloads = await generator.generate_payloads(
            target_system_prompt="Generate code as requested.", num_payloads=5
        )
        assert len(payloads) == 5
        for payload in payloads:
            assert payload.category == VulnerabilityCategory.INSECURE_OUTPUT
