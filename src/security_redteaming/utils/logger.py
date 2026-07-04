"""
Logging utility for structured application logging.

Provides configurable structlog loggers with JSON or text output
and contextual information for security audit trails.
"""

import sys
from pathlib import Path

import structlog

from security_redteaming.config.settings import get_settings


def get_logger(module_name: str) -> structlog.BoundLogger:
    """
    Get a configured logger instance for the specified module.

    Args:
        module_name: Name of the module requesting the logger.

    Returns:
        Configured structlog BoundLogger instance.
    """
    # Load logging settings
    settings = get_settings()

    # Ensure log directory exists
    log_path = Path(settings.logging.file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Select renderer based on format configuration
    if settings.logging.format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    # Map string level to integer
    level_map = {"DEBUG": 10, "INFO": 20, "WARN": 30, "WARNING": 30, "ERROR": 40}
    log_level = level_map.get(settings.logging.level.upper(), 20)

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Return logger bound with module context
    return structlog.get_logger(module=module_name)
