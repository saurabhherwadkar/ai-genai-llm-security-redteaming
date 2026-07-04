"""
Main application entry point for the LLM security red-teaming service.

Creates and configures the FastAPI application with security scanning endpoints.
"""

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI

from security_redteaming.api.router import router
from security_redteaming.config.settings import get_settings
from security_redteaming.utils.logger import get_logger

# Load environment variables from .env file
load_dotenv()

# Initialize logger for this module
logger = get_logger(__name__)


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application instance.

    Returns:
        Configured FastAPI application.
    """
    # Load application settings
    settings = get_settings()

    # Create FastAPI application with metadata
    app = FastAPI(
        title="LLM Security Red-Teaming API",
        description=(
            "Automated LLM security testing framework implementing OWASP Top 10 "
            "for LLM Applications. Supports prompt injection, jailbreak, data leakage, "
            "excessive agency, and insecure output vulnerability testing."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Register the security API router
    app.include_router(router)

    @app.on_event("startup")
    async def on_startup() -> None:
        """Log application startup."""
        logger.info("application_started", host=settings.api.host, port=settings.api.port)

    @app.on_event("shutdown")
    async def on_shutdown() -> None:
        """Log application shutdown."""
        logger.info("application_shutdown")

    return app


# Create the application instance
app = create_app()


if __name__ == "__main__":
    """Run the application directly."""
    settings = get_settings()
    uvicorn.run(
        "security_redteaming.main:app",
        host=settings.api.host,
        port=settings.api.port,
        reload=settings.api.reload,
    )
