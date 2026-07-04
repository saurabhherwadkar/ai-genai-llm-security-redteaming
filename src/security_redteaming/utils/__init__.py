"""
Utility module providing shared helpers for the security red-teaming framework.

Includes structured logging and the LLM client wrapper.
"""

from security_redteaming.utils.logger import get_logger
from security_redteaming.utils.llm_client import LLMClient

__all__ = ["get_logger", "LLMClient"]
