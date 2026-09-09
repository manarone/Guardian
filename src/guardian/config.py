"""Runtime configuration, read from the environment or a local .env file."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="GUARDIAN_", extra="ignore")

    # Claude. The API key itself is read by the SDK from ANTHROPIC_API_KEY (or an
    # `ant auth login` profile), so it is deliberately not duplicated here.
    model: str = "claude-opus-5"
    effort: str = "high"
    max_tokens: int = 16000

    # SentinelOne
    s1_base_url: str = ""
    s1_api_token: str = ""
    s1_poll_interval: int = 60
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
