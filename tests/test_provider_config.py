from guardian.agent.analyst import Analyst
from guardian.config import Settings
from guardian.models import Alert
from guardian.store import InMemoryStore


def test_model_provider_is_not_defaulted():
    settings = Settings(_env_file=None)
    assert settings.provider is None
    assert settings.base_url == ""
    assert settings.model == ""


def test_provider_key_aliases_are_supported():
    settings = Settings(
        _env_file=None,
        provider="openai",
        base_url="https://api.example.test/v1",
        model="example-model",
        api_key="generic-key",
    )
    assert settings.model_api_key == "generic-key"


def test_unconfigured_analyst_fails_an_alert_without_network_call():
    settings = Settings(_env_file=None)
    result = __import__("asyncio").run(
        Analyst(settings, InMemoryStore()).triage(Alert(source="test", title="x"))
    )
    assert result.status == "failed"
    assert "GUARDIAN_PROVIDER" in (result.error or "")
