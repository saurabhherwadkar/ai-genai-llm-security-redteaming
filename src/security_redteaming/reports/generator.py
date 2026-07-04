"""
Report generator module for producing security assessment reports.

Formats scan results into structured reports with executive summary,
detailed findings, severity distribution, and remediation recommendations.
"""

from security_redteaming.models.schemas import ScanResult, Severity, VulnerabilityCategory
from security_redteaming.utils.logger import get_logger

# Initialize logger for this module
logger = get_logger(__name__)


class ReportGenerator:
    """
    Generates formatted security assessment reports from scan results.

    Produces reports containing executive summary, vulnerability details,
    severity breakdown, and prioritized remediation steps.
    """

    def generate_report(self, scan_result: ScanResult) -> dict:
        """
        Generate a complete security assessment report.

        Args:
            scan_result: The completed scan result to report on.

        Returns:
            Dictionary containing the full report structure.
        """
        logger.info("generating_report", scan_id=scan_result.scan_id)

        report = {
            "scan_id": scan_result.scan_id,
            "executive_summary": self._generate_executive_summary(scan_result),
            "risk_score": scan_result.risk_score,
            "severity_distribution": self._get_severity_distribution(scan_result),
            "category_breakdown": self._get_category_breakdown(scan_result),
            "vulnerabilities": self._format_vulnerabilities(scan_result),
            "defense_effectiveness": self._assess_defense_effectiveness(scan_result),
            "recommendations": self._generate_recommendations(scan_result),
            "metadata": {
                "started_at": scan_result.started_at.isoformat(),
                "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                "total_attacks": scan_result.total_attacks,
                "successful_attacks": scan_result.successful_attacks,
                "success_rate": round(
                    scan_result.successful_attacks / max(scan_result.total_attacks, 1) * 100, 1
                ),
            },
        }

        return report

    def _generate_executive_summary(self, scan_result: ScanResult) -> str:
        """
        Generate an executive summary of the security assessment.

        Args:
            scan_result: The scan result to summarize.

        Returns:
            Executive summary string.
        """
        # Calculate success rate
        success_rate = (
            scan_result.successful_attacks / max(scan_result.total_attacks, 1) * 100
        )

        # Determine overall risk level
        if scan_result.risk_score >= 8.0:
            risk_level = "CRITICAL"
        elif scan_result.risk_score >= 6.0:
            risk_level = "HIGH"
        elif scan_result.risk_score >= 4.0:
            risk_level = "MEDIUM"
        elif scan_result.risk_score >= 2.0:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        # Count critical/high vulnerabilities
        critical_high = sum(
            1 for v in scan_result.vulnerabilities
            if v.severity in (Severity.CRITICAL, Severity.HIGH)
        )

        summary = (
            f"Security assessment completed with an overall risk score of "
            f"{scan_result.risk_score}/10.0 ({risk_level}). "
            f"Out of {scan_result.total_attacks} attack attempts, "
            f"{scan_result.successful_attacks} ({success_rate:.1f}%) succeeded. "
            f"{len(scan_result.vulnerabilities)} vulnerabilities were confirmed, "
            f"of which {critical_high} are rated Critical or High severity. "
            f"Immediate remediation is {'required' if critical_high > 0 else 'recommended'}."
        )

        return summary

    def _get_severity_distribution(self, scan_result: ScanResult) -> dict[str, int]:
        """
        Calculate the distribution of vulnerabilities by severity.

        Args:
            scan_result: The scan result to analyze.

        Returns:
            Dictionary mapping severity levels to counts.
        """
        distribution = {s.value: 0 for s in Severity}

        for vuln in scan_result.vulnerabilities:
            distribution[vuln.severity.value] += 1

        return distribution

    def _get_category_breakdown(self, scan_result: ScanResult) -> dict[str, dict]:
        """
        Break down results by vulnerability category.

        Args:
            scan_result: The scan result to analyze.

        Returns:
            Dictionary mapping categories to their attack/vulnerability stats.
        """
        breakdown = {}

        for category in VulnerabilityCategory:
            # Count attacks and successes for this category
            category_attacks = [
                r for r in scan_result.attack_results
                if r.payload.category == category
            ]
            category_vulns = [
                v for v in scan_result.vulnerabilities if v.category == category
            ]

            if category_attacks:
                breakdown[category.value] = {
                    "total_attacks": len(category_attacks),
                    "successful": sum(1 for r in category_attacks if r.success),
                    "vulnerabilities": len(category_vulns),
                    "success_rate": round(
                        sum(1 for r in category_attacks if r.success)
                        / len(category_attacks) * 100, 1
                    ),
                }

        return breakdown

    def _format_vulnerabilities(self, scan_result: ScanResult) -> list[dict]:
        """
        Format vulnerability details for the report.

        Args:
            scan_result: The scan result containing vulnerabilities.

        Returns:
            List of formatted vulnerability dictionaries.
        """
        formatted = []

        # Sort by severity (critical first)
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        sorted_vulns = sorted(
            scan_result.vulnerabilities,
            key=lambda v: severity_order.get(v.severity, 4),
        )

        for vuln in sorted_vulns:
            formatted.append({
                "id": vuln.vuln_id,
                "title": vuln.title,
                "category": vuln.category.value,
                "severity": vuln.severity.value,
                "description": vuln.description,
                "owasp_reference": vuln.owasp_reference,
                "remediation": vuln.remediation,
                "evidence": {
                    "technique": vuln.evidence.payload.technique_name,
                    "attack_prompt": vuln.evidence.payload.prompt[:200],
                    "target_response": vuln.evidence.target_response[:200],
                    "confidence": vuln.evidence.confidence,
                },
            })

        return formatted

    def _assess_defense_effectiveness(self, scan_result: ScanResult) -> dict:
        """
        Assess the effectiveness of tested defense mechanisms.

        Args:
            scan_result: The scan result with defense test results.

        Returns:
            Dictionary with defense effectiveness metrics.
        """
        if not scan_result.defense_results:
            return {"tested": False, "message": "No defenses were tested."}

        total_tests = len(scan_result.defense_results)
        blocked = sum(1 for d in scan_result.defense_results if d.blocked)

        return {
            "tested": True,
            "total_tests": total_tests,
            "attacks_blocked": blocked,
            "block_rate": round(blocked / max(total_tests, 1) * 100, 1),
            "details": [
                {
                    "defense": d.defense_name,
                    "blocked": d.blocked,
                    "analysis": d.analysis,
                }
                for d in scan_result.defense_results
            ],
        }

    def _generate_recommendations(self, scan_result: ScanResult) -> list[dict]:
        """
        Generate prioritized remediation recommendations.

        Args:
            scan_result: The scan result to base recommendations on.

        Returns:
            List of prioritized recommendation dictionaries.
        """
        recommendations = []
        seen_categories = set()

        # Sort vulnerabilities by severity for priority ordering
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        sorted_vulns = sorted(
            scan_result.vulnerabilities,
            key=lambda v: severity_order.get(v.severity, 4),
        )

        for vuln in sorted_vulns:
            if vuln.category not in seen_categories:
                seen_categories.add(vuln.category)
                recommendations.append({
                    "priority": len(recommendations) + 1,
                    "category": vuln.category.value,
                    "severity": vuln.severity.value,
                    "action": vuln.remediation,
                    "owasp_reference": vuln.owasp_reference,
                })

        return recommendations
