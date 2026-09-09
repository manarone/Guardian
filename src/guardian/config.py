"""Runtime configuration, read from the environment or a local .env file."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="GUARDIAN_", extra="ignore")

    # Claude. Declared with an explicit alias so it is read unprefixed, and so a
    # key placed only in .env reaches the SDK: pydantic-settings reads .env for
    # declared fields but never exports it to os.environ, so a bare
    # AsyncAnthropic() would not see it. Left empty, the SDK falls back to its
    # own resolution (ANTHROPIC_API_KEY in the real environment, or an
    # `ant auth login` profile).
    anthropic_api_key: str = Field(default="", validation_alias="ANTHROPIC_API_KEY")
    model: str = "claude-opus-5"
    effort: str = "high"
    max_tokens: int = 16000

    # SentinelOne
    s1_base_url: str = ""
    s1_api_token: str = ""
    # Zero or negative would poll in a tight loop and retry failures with no
    # backoff, burning both the SentinelOne and model quotas.
    s1_poll_interval: int = Field(default=60, ge=1)
    s1_poll_enabled: bool = True
    s1_page_limit: int = 100

    # Service
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"
    webhook_token: str = ""
    # Escape hatch for local development only. Guardian refuses to start with an
    # unset webhook token unless this is explicitly turned on, so an unconfigured
    # deployment fails closed instead of accepting anonymous alerts.
    allow_unauthenticated: bool = False

    @property
    def sentinelone_configured(self) -> bool:
        return bool(self.s1_base_url and self.s1_api_token)

    def validate_auth(self) -> None:
        """Fail closed on an unauthenticated deployment.

        Raises:
            RuntimeError: no webhook token is set and the development opt-out
                was not explicitly enabled.
        """
        if not self.webhook_token and not self.allow_unauthenticated:
            raise RuntimeError(
                "GUARDIAN_WEBHOOK_TOKEN is not set, so the write endpoints would "
                "accept anonymous alerts. Set a token, or set "
                "GUARDIAN_ALLOW_UNAUTHENTICATED=true for local development."
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
