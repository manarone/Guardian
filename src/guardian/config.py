"""Runtime configuration, read from the environment or a local .env file."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="GUARDIAN_", extra="ignore")

    # Provider settings are intentionally unset by default. This keeps the
    # scaffold provider agnostic: configure any OpenAI-compatible or native
    # Anthropic endpoint explicitly in the environment.
    provider: Literal["openai", "anthropic"] | None = None
    base_url: str = ""
    api_key: str = Field(default="", validation_alias=AliasChoices("GUARDIAN_API_KEY", "api_key"))
    anthropic_api_key: str = Field(
        default="", validation_alias=AliasChoices("ANTHROPIC_API_KEY", "anthropic_api_key")
    )
    model: str = ""
    effort: str = "high"
    max_tokens: int = 16000
    max_tool_iterations: int = Field(default=12, ge=1)

    # SentinelOne
    s1_base_url: str = ""
    s1_api_token: str = ""
    s1_poll_interval: int = Field(default=60, ge=1)
    s1_poll_enabled: bool = True
    s1_page_limit: int = 100

    # Service
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"
    webhook_token: str = ""
    allow_unauthenticated: bool = False

    @field_validator("log_level")
    @classmethod
    def _known_log_level(cls, value: str) -> str:
        level = value.lower()
        if level not in {"critical", "error", "warning", "info", "debug"}:
            raise ValueError(
                f"GUARDIAN_LOG_LEVEL={value!r} is not one of critical, error, warning, info, debug"
            )
        return level

    @property
    def sentinelone_configured(self) -> bool:
        return bool(self.s1_base_url and self.s1_api_token)

    @property
    def model_api_key(self) -> str:
        """Return the configured key, honoring the native Anthropic env name."""
        return self.api_key or self.anthropic_api_key

    def validate_auth(self) -> None:
        if not self.webhook_token and not self.allow_unauthenticated:
            raise RuntimeError(
                "GUARDIAN_WEBHOOK_TOKEN is not set, so the write endpoints would "
                "accept anonymous alerts. Set a token, or set "
                "GUARDIAN_ALLOW_UNAUTHENTICATED=true for local development."
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
