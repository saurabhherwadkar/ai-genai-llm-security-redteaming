"""
Configuration module for the security red-teaming framework.

Handles loading environment-specific settings for target and attacker LLMs,
red team pipeline parameters, and application configuration.
"""

from security_redteaming.config.settings import Settings, get_settings

__all__ = ["Settings", "get_settings"]
