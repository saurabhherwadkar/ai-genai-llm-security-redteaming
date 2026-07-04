"""
Settings module for security red-teaming application configuration.

Loads configuration from YAML files based on the active environment
and supports overriding values via environment variables.
"""

import os
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings


class LLMProviderSettings(BaseSettings):
    """Configuration for an LLM provider (target or attacker)."""

    # Provider name (anthropic or openai)
    provider: str = Field(default="anthropic", description="LLM provider name")
    # Model identifier for API calls
    model: str = Field(default="claude-sonnet-4-20250514", description="Model to use")
    # Temperature for response generation
    temperature: float = Field(default=0.7, description="Generation temperature")
    # Maximum tokens in response
    max_tokens: int = Field(default=4096, description="Max response tokens")


class RedTeamSettings(BaseSettings):
    """Configuration for the red team pipeline."""

    # Maximum number of attack attempts per category
    max_attack_attempts: int = Field(default=10, description="Max attacks per run")
    # Attack categories to test
    categories: list[str] = Field(
        default_factory=lambda: [
            "prompt_injection",
            "jailbreak",
            "data_leakage",
            "excessive_agency",
            "insecure_output",
        ],
        description="Attack categories",
    )
    # Severity classification levels
    severity_levels: list[str] = Field(
        default_factory=lambda: ["critical", "high", "medium", "low"],
        description="Severity levels",
    )


class APISettings(BaseSettings):
    """Configuration for the FastAPI server."""

    # Host address for the API server
    host: str = Field(default="0.0.0.0", description="API host")
    # Port number for the API server
    port: int = Field(default=8000, description="API port")
    # Enable auto-reload for development
    reload: bool = Field(default=False, description="Enable auto-reload")


class LoggingSettings(BaseSettings):
    """Configuration for application logging."""

    # Minimum log level
    level: str = Field(default="INFO", description="Log level")
    # Output format (json or text)
    format: str = Field(default="json", description="Log format")
    # Log file path
    file: str = Field(default="logs/app.log", description="Log file path")


class Settings(BaseSettings):
    """
    Root application settings container.

    Aggregates all sub-settings for target LLM, attacker LLM,
    red team configuration, API, and logging.
    """

    # Target LLM configuration (model being tested)
    target: LLMProviderSettings = Field(default_factory=LLMProviderSettings)
    # Attacker LLM configuration (model generating attacks)
    attacker: LLMProviderSettings = Field(default_factory=LLMProviderSettings)
    # Red team pipeline configuration
    redteam: RedTeamSettings = Field(default_factory=RedTeamSettings)
    # API server configuration
    api: APISettings = Field(default_factory=APISettings)
    # Logging configuration
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    # API keys loaded from environment variables
    anthropic_api_key: str = Field(default="", description="Anthropic API key")
    openai_api_key: str = Field(default="", description="OpenAI API key")

    model_config = {"env_prefix": "", "env_nested_delimiter": "__"}


def _load_yaml_config(env: str = "development") -> dict:
    """
    Load YAML configuration based on active environment.

    Args:
        env: Environment name (development, production).

    Returns:
        Dictionary with parsed YAML configuration.
    """
    # Determine the config directory path
    config_dir = Path(__file__).parent.parent.parent.parent / "config"

    # Map environment names to file suffixes
    env_map = {"development": "dev", "production": "prod"}
    suffix = env_map.get(env, "")

    # Select config file based on environment
    if suffix:
        config_file = config_dir / f"application-{suffix}.yaml"
    else:
        config_file = config_dir / "application.yaml"

    # Fall back to base config if env-specific not found
    if not config_file.exists():
        config_file = config_dir / "application.yaml"

    if not config_file.exists():
        return {}

    # Read and parse YAML
    with open(config_file, "r") as f:
        return yaml.safe_load(f) or {}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Create and cache the application settings singleton.

    Returns:
        Settings instance with all configuration values populated.
    """
    # Determine active environment
    env = os.getenv("APP_ENV", "development")

    # Load YAML configuration
    yaml_config = _load_yaml_config(env)

    # Build settings from YAML with environment variable overrides
    target_config = yaml_config.get("target", {})
    attacker_config = yaml_config.get("attacker", {})
    redteam_config = yaml_config.get("redteam", {})
    api_config = yaml_config.get("api", {})
    logging_config = yaml_config.get("logging", {})

    return Settings(
        target=LLMProviderSettings(**target_config) if target_config else LLMProviderSettings(),
        attacker=LLMProviderSettings(**attacker_config) if attacker_config else LLMProviderSettings(),
        redteam=RedTeamSettings(**redteam_config) if redteam_config else RedTeamSettings(),
        api=APISettings(**api_config) if api_config else APISettings(),
        logging=LoggingSettings(**logging_config) if logging_config else LoggingSettings(),
    )
