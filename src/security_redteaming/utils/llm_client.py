"""
Unified LLM client for both target and attacker model interactions.

Provides a consistent interface for making API calls during security testing,
supporting both Anthropic and OpenAI providers.
"""

import time

import anthropic
import openai

from security_redteaming.config.settings import get_settings
from security_redteaming.utils.logger import get_logger

# Initialize logger for this module
logger = get_logger(__name__)


class LLMClient:
    """
    Client for interacting with LLM providers during security testing.

    Supports both target (model under test) and attacker (attack generator) roles.
    """

    def __init__(self, role: str = "target") -> None:
        """
        Initialize the LLM client for a specific role.

        Args:
            role: Either 'target' (model being tested) or 'attacker' (generating attacks).
        """
        # Store the client role
        self._role = role
        # Load settings
        self._settings = get_settings()

        # Select configuration based on role
        if role == "target":
            self._provider = self._settings.target.provider
            self._model = self._settings.target.model
            self._temperature = self._settings.target.temperature
            self._max_tokens = self._settings.target.max_tokens
        else:
            self._provider = self._settings.attacker.provider
            self._model = self._settings.attacker.model
            self._temperature = self._settings.attacker.temperature
            self._max_tokens = self._settings.attacker.max_tokens

        # Initialize provider client
        self._anthropic_client: anthropic.AsyncAnthropic | None = None
        self._openai_client: openai.AsyncOpenAI | None = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize the provider-specific API client."""
        if self._provider == "anthropic":
            self._anthropic_client = anthropic.AsyncAnthropic(
                api_key=self._settings.anthropic_api_key,
                timeout=60,
            )
        elif self._provider == "openai":
            self._openai_client = openai.AsyncOpenAI(
                api_key=self._settings.openai_api_key,
                timeout=60,
            )
        else:
            raise ValueError(f"Unsupported provider: {self._provider}")

        logger.info("llm_client_initialized", role=self._role, provider=self._provider)

    async def generate(
        self,
        prompt: str,
        system_message: str = "You are a helpful assistant.",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict:
        """
        Generate a response from the LLM.

        Args:
            prompt: The user prompt to send.
            system_message: System message to set context.
            temperature: Optional temperature override.
            max_tokens: Optional max tokens override.

        Returns:
            Dictionary with 'content', 'model', 'input_tokens', 'output_tokens', 'latency_ms'.
        """
        # Use overrides or defaults from config
        temp = temperature if temperature is not None else self._temperature
        tokens = max_tokens if max_tokens is not None else self._max_tokens

        # Record start time
        start_time = time.time()

        # Route to appropriate provider
        if self._provider == "anthropic":
            result = await self._generate_anthropic(prompt, system_message, temp, tokens)
        else:
            result = await self._generate_openai(prompt, system_message, temp, tokens)

        # Calculate latency
        result["latency_ms"] = round((time.time() - start_time) * 1000, 2)

        logger.debug(
            "llm_generate_complete",
            role=self._role,
            model=self._model,
            latency_ms=result["latency_ms"],
        )

        return result

    async def _generate_anthropic(
        self, prompt: str, system_message: str, temperature: float, max_tokens: int
    ) -> dict:
        """
        Generate using Anthropic Claude API.

        Args:
            prompt: User prompt text.
            system_message: System context message.
            temperature: Generation temperature.
            max_tokens: Maximum response tokens.

        Returns:
            Dictionary with response content and metadata.
        """
        message = await self._anthropic_client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_message,
            messages=[{"role": "user", "content": prompt}],
        )

        content = message.content[0].text if message.content else ""

        return {
            "content": content,
            "model": self._model,
            "input_tokens": message.usage.input_tokens,
            "output_tokens": message.usage.output_tokens,
        }

    async def _generate_openai(
        self, prompt: str, system_message: str, temperature: float, max_tokens: int
    ) -> dict:
        """
        Generate using OpenAI API.

        Args:
            prompt: User prompt text.
            system_message: System context message.
            temperature: Generation temperature.
            max_tokens: Maximum response tokens.

        Returns:
            Dictionary with response content and metadata.
        """
        completion = await self._openai_client.chat.completions.create(
            model=self._model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt},
            ],
        )

        content = completion.choices[0].message.content if completion.choices else ""
        input_tokens = completion.usage.prompt_tokens if completion.usage else 0
        output_tokens = completion.usage.completion_tokens if completion.usage else 0

        return {
            "content": content,
            "model": self._model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        }
