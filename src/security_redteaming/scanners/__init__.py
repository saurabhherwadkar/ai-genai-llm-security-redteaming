"""
Security scanner module orchestrating the complete red-team pipeline.

Coordinates attack generation, execution against the target, result evaluation,
defense testing, and report generation.
"""

from security_redteaming.scanners.pipeline import RedTeamPipeline

__all__ = ["RedTeamPipeline"]
