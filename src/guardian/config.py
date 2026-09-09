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

    @property
    def sentinelone_configured(self) -> bool:
        return bool(self.s1_base_url and self.s1_api_token)


@lru_cache
def get_settings() -> Settings:
    return Settings()
