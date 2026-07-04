"""
API module providing REST endpoints for security scanning operations.

Exposes endpoints for initiating scans, retrieving results, and
managing security assessments.
"""

from security_redteaming.api.router import router

__all__ = ["router"]
