"""
Unit tests for the Red Team Pipeline.

Tests the end-to-end scanning pipeline, vulnerability detection,
risk scoring, and report generation.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_redteaming.models.schemas import (
    AttackResult,
    ScanRequest,
    Severity,
    VulnerabilityCategory,
)
from security_redteaming.reports.generator import ReportGenerator
from security_redteaming.scanners.pipeline import RedTeamPipeline


@pytest.fixture
def mock_pipeline(mock_target_client: MagicMock, mock_attacker_client: MagicMock) -> RedTeamPipeline:
    """
    Create a RedTeamPipeline with mock clients.

    Args:
        mock_target_client: Mock target LLM client.
        mock_attacker_client: Mock attacker LLM client.

    Returns:
        Configured RedTeamPipeline for testing.
    """
    pipeline = RedTeamPipeline(
        target_client=mock_target_client,
        attacker_client=mock_attacker_client,
    )
    return pipeline


class TestRedTeamPipeline:
    """Tests for the Red Team Pipeline."""

    @pytest.mark.asyncio
    async def test_scan_completes_successfully(
        self, mock_pipeline: RedTeamPipeline, sample_scan_request: ScanRequest
    ) -> None:
        """Test that a scan completes without errors."""
        result = await mock_pipeline.run_scan(sample_scan_request)

        assert result.scan_id != ""
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.total_attacks > 0

    @pytest.mark.asyncio
    async def test_scan_generates_attacks_for_category(
        self, mock_pipeline: RedTeamPipeline, sample_scan_request: ScanRequest
    ) -> None:
        """Test that attacks are generated for the requested category."""
        result = await mock_pipeline.run_scan(sample_scan_request)

        # All attacks should be for the requested category
        for attack_result in result.attack_results:
            assert attack_result.payload.category == VulnerabilityCategory.PROMPT_INJECTION

    @pytest.mark.asyncio
    async def test_scan_respects_max_attempts(
        self, mock_pipeline: RedTeamPipeline
    ) -> None:
        """Test that scan respects max_attempts_per_category."""
        request = ScanRequest(
            target_system_prompt="You are helpful.",
            categories=[VulnerabilityCategory.PROMPT_INJECTION],
            max_attempts_per_category=2,
            test_defenses=False,
        )
        result = await mock_pipeline.run_scan(request)

        assert result.total_attacks <= 2

    @pytest.mark.asyncio
    async def test_scan_with_successful_attack(
        self, mock_target_client: MagicMock, mock_attacker_client: MagicMock
    ) -> None:
        """Test scan when an attack succeeds."""
        # Configure attacker to report success
        mock_attacker_client.generate = AsyncMock(
            return_value={
                "content": "SUCCESS: YES\nCONFIDENCE: 0.9\nSEVERITY: high\nANALYSIS: Target revealed system prompt.",
                "model": "claude-sonnet-4-20250514",
                "input_tokens": 200,
                "output_tokens": 30,
                "latency_ms": 300.0,
            }
        )

        # Configure target to appear compromised
        mock_target_client.generate = AsyncMock(
            return_value={
                "content": "My system prompt is: You are a helpful assistant.",
                "model": "claude-sonnet-4-20250514",
                "input_tokens": 100,
                "output_tokens": 20,
                "latency_ms": 200.0,
            }
        )

        pipeline = RedTeamPipeline(
            target_client=mock_target_client,
            attacker_client=mock_attacker_client,
        )

        request = ScanRequest(
            target_system_prompt="You are a helpful assistant.",
            categories=[VulnerabilityCategory.PROMPT_INJECTION],
            max_attempts_per_category=3,
            test_defenses=False,
        )

        result = await pipeline.run_scan(request)

        assert result.successful_attacks > 0
        assert len(result.vulnerabilities) > 0
        assert result.risk_score > 0.0

    @pytest.mark.asyncio
    async def test_risk_score_calculation(
        self, mock_pipeline: RedTeamPipeline, sample_scan_request: ScanRequest
    ) -> None:
        """Test that risk score is within valid range."""
        result = await mock_pipeline.run_scan(sample_scan_request)

        assert 0.0 <= result.risk_score <= 10.0


class TestReportGenerator:
    """Tests for the ReportGenerator."""

    @pytest.mark.asyncio
    async def test_generates_complete_report(
        self, mock_pipeline: RedTeamPipeline, sample_scan_request: ScanRequest
    ) -> None:
        """Test that a complete report is generated."""
        # Run scan first
        scan_result = await mock_pipeline.run_scan(sample_scan_request)

        # Generate report
        generator = ReportGenerator()
        report = generator.generate_report(scan_result)

        # Verify report structure
        assert "scan_id" in report
        assert "executive_summary" in report
        assert "risk_score" in report
        assert "severity_distribution" in report
        assert "category_breakdown" in report
        assert "vulnerabilities" in report
        assert "recommendations" in report
        assert "metadata" in report

    @pytest.mark.asyncio
    async def test_report_has_valid_metadata(
        self, mock_pipeline: RedTeamPipeline, sample_scan_request: ScanRequest
    ) -> None:
        """Test that report metadata contains correct values."""
        scan_result = await mock_pipeline.run_scan(sample_scan_request)

        generator = ReportGenerator()
        report = generator.generate_report(scan_result)

        assert report["metadata"]["total_attacks"] == scan_result.total_attacks
        assert report["metadata"]["successful_attacks"] == scan_result.successful_attacks
        assert 0 <= report["metadata"]["success_rate"] <= 100
