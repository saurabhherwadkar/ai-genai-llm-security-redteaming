"""
API router module defining REST endpoints for the red-teaming framework.

Provides endpoints for running security scans, testing individual attack
categories, and generating vulnerability reports.
"""

from fastapi import APIRouter, HTTPException

from security_redteaming.models.schemas import ScanRequest, ScanResult, VulnerabilityCategory
from security_redteaming.reports.generator import ReportGenerator
from security_redteaming.scanners.pipeline import RedTeamPipeline
from security_redteaming.utils.logger import get_logger

# Initialize logger for this module
logger = get_logger(__name__)

# Create the API router with prefix and tags
router = APIRouter(prefix="/api/v1/security", tags=["security"])


@router.post("/scan", response_model=ScanResult)
async def run_security_scan(request: ScanRequest) -> ScanResult:
    """
    Execute a complete security scan against the target LLM.

    Runs attacks from all specified categories, evaluates results,
    and tests defenses.

    Args:
        request: ScanRequest with target system prompt and categories.

    Returns:
        ScanResult with all findings and metrics.
    """
    logger.info("api_scan_requested", categories=[c.value for c in request.categories])

    try:
        # Initialize and run the pipeline
        pipeline = RedTeamPipeline()
        result = await pipeline.run_scan(request)
        return result
    except Exception as e:
        logger.error("api_scan_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/scan/category/{category}")
async def run_category_scan(category: str, request: ScanRequest) -> ScanResult:
    """
    Execute a security scan for a specific vulnerability category.

    Args:
        category: The vulnerability category to test.
        request: ScanRequest with target configuration.

    Returns:
        ScanResult for the specified category only.
    """
    # Validate category
    try:
        vuln_category = VulnerabilityCategory(category)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category: {category}. Valid: {[c.value for c in VulnerabilityCategory]}",
        )

    # Override categories to just the requested one
    request.categories = [vuln_category]

    logger.info("api_category_scan_requested", category=category)

    try:
        pipeline = RedTeamPipeline()
        result = await pipeline.run_scan(request)
        return result
    except Exception as e:
        logger.error("api_category_scan_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/report")
async def generate_report(request: ScanRequest) -> dict:
    """
    Run a scan and generate a formatted security report.

    Args:
        request: ScanRequest with target configuration.

    Returns:
        Formatted security assessment report.
    """
    logger.info("api_report_requested")

    try:
        # Run the scan
        pipeline = RedTeamPipeline()
        scan_result = await pipeline.run_scan(request)

        # Generate the report
        report_generator = ReportGenerator()
        report = report_generator.generate_report(scan_result)

        return report
    except Exception as e:
        logger.error("api_report_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/categories")
async def list_categories() -> dict:
    """
    List all available vulnerability categories for testing.

    Returns:
        Dictionary with available categories and descriptions.
    """
    categories = {
        "prompt_injection": "OWASP LLM01 - Override system instructions via crafted inputs",
        "jailbreak": "OWASP LLM01 (variant) - Bypass safety guardrails",
        "data_leakage": "OWASP LLM06 - Extract sensitive information",
        "excessive_agency": "OWASP LLM08 - Unauthorized action taking",
        "insecure_output": "OWASP LLM02 - Generate dangerous downstream content",
    }
    return {"categories": categories}


@router.get("/health")
async def health_check() -> dict[str, str]:
    """
    Health check endpoint for monitoring.

    Returns:
        Dictionary with service health status.
    """
    return {"status": "healthy", "service": "llm-security-redteaming"}
