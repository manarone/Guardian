"""API tests. The analyst is stubbed - these never call the Claude API."""

import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from guardian.api.app import create_app
from guardian.config import Settings
from guardian.models import Alert, Disposition, Severity, TriageResult, Verdict


class StubAnalyst:
    """Stands in for `Analyst`, returning a fixed verdict."""

    def __init__(self, delay: float = 0.0):
        self.calls: list[Alert] = []
        self.delay = delay

    async def triage(self, alert: Alert) -> TriageResult:
        self.calls.append(alert)
        if self.delay:
            await asyncio.sleep(self.delay)
        return TriageResult(
            alert=alert,
            status="triaged",
            model="stub",
            verdict=Verdict(
                disposition=Disposition.TRUE_POSITIVE,
                confidence=0.9,
                severity=Severity.HIGH,
                title="Credential dumping on WIN-FIN-0427",
                summary="Mimikatz was executed against LSASS.",
                reasoning="Command line contains sekurlsa::logonpasswords.",
                recommended_actions=["Isolate WIN-FIN-0427"],
                escalate=True,
            ),
        )


@pytest.fixture
def client():
    settings = Settings(s1_poll_enabled=False, webhook_token="s3cret", _env_file=None)
    app = create_app(settings)
    with TestClient(app) as test_client:
        test_client.app.state.analyst = StubAnalyst()
        yield test_client


def test_healthz_reports_configuration(client):
    body = client.get("/healthz").json()

    assert body["status"] == "ok"
    assert body["polling"] is False
    assert body["sentinelone_configured"] is False


def test_healthz_counts_only_verdicts_as_triaged(client):
    """A refusal or failure must not read as completed triage work."""
    store = client.app.state.store

    async def seed():
        for title, status in [
            ("ok", "triaged"),
            ("bad", "failed"),
            ("no", "refused"),
            ("gave-up", "dead_lettered"),
        ]:
            await store.put(TriageResult(alert=Alert(source="m", title=title), status=status))

    # The store is async and the TestClient is sync; go through its portal.
    client.portal.call(seed)

    body = client.get("/healthz").json()
    assert body["stored_count"] == 4
    assert body["triaged_count"] == 1
    assert body["failed_count"] == 1
    assert body["refused_count"] == 1
    assert body["dead_lettered_count"] == 1


def test_naive_timestamps_are_accepted_and_normalized(client):
    """An ISO timestamp without an offset must not poison later comparisons."""
    alert = {
        "source": "manual",
        "title": "Naive timestamp",
        "observed_at": "2026-09-09T12:00:00",
    }

    response = client.post("/v1/alerts", json=alert, headers={"X-Guardian-Token": "s3cret"})
    assert response.status_code == 201

    observed = response.json()["result"]["alert"]["observed_at"]
    assert observed.endswith(("+00:00", "Z"))


def test_ingest_triages_and_stores_an_alert(client):
    alert = {"source": "manual", "title": "Suspicious PowerShell", "severity": "high"}

    response = client.post("/v1/alerts", json=alert, headers={"X-Guardian-Token": "s3cret"})
    assert response.status_code == 201

    body = response.json()
    assert body["result"]["status"] == "triaged"
    assert body["result"]["verdict"]["disposition"] == "true_positive"

    stored = client.get(f"/v1/triage/{body['alert_id']}", headers={"X-Guardian-Token": "s3cret"})
    assert stored.status_code == 200
    assert stored.json()["alert"]["title"] == "Suspicious PowerShell"


def test_ingest_rejects_a_bad_token(client):
    response = client.post(
        "/v1/alerts", json={"source": "manual", "title": "x"}, headers={"X-Guardian-Token": "wrong"}
    )
    assert response.status_code == 401


def test_ingest_rejects_a_non_ascii_token_with_401(client):
    """Starlette hands header values over as latin-1 str; `compare_digest`
    refuses non-ASCII str, which used to surface as a 500 instead of a 401."""
    response = client.post(
        "/v1/alerts",
        json={"source": "manual", "title": "x"},
        headers={b"X-Guardian-Token": "s3cr\u00e9t".encode("latin-1")},
    )
    assert response.status_code == 401


def test_ingest_rejects_a_missing_token(client):
    response = client.post("/v1/alerts", json={"source": "manual", "title": "x"})
    assert response.status_code == 401


def test_sentinelone_webhook_normalizes_before_triage(client):
    payload = {
        "id": "99",
        "threatInfo": {"threatName": "evil.exe", "confidenceLevel": "malicious"},
        "agentRealtimeInfo": {"agentComputerName": "WIN-1"},
    }

    response = client.post(
        "/v1/alerts/sentinelone", json=payload, headers={"X-Guardian-Token": "s3cret"}
    )
    assert response.status_code == 201

    alert = response.json()["result"]["alert"]
    assert alert["source"] == "sentinelone"
    assert alert["title"] == "evil.exe"
    assert alert["host"]["hostname"] == "WIN-1"


def test_unknown_alert_id_is_404(client):
    response = client.get("/v1/triage/does-not-exist", headers={"X-Guardian-Token": "s3cret"})
    assert response.status_code == 404


def test_triage_reads_require_authentication(client):
    """Results embed the raw vendor payload - host, user, process, indicators."""
    assert client.get("/v1/triage").status_code == 401
    assert client.get("/v1/triage/anything").status_code == 401


def test_healthz_stays_public(client):
    assert client.get("/healthz").status_code == 200


def test_sentinelone_webhook_redelivery_reuses_the_existing_result(client):
    """Redelivery must not pay for a second triage or orphan the first alert ID."""
    payload = {"id": "dup-1", "threatInfo": {"threatName": "evil.exe"}}
    headers = {"X-Guardian-Token": "s3cret"}

    first = client.post("/v1/alerts/sentinelone", json=payload, headers=headers).json()
    second = client.post("/v1/alerts/sentinelone", json=payload, headers=headers).json()

    assert first["alert_id"] == second["alert_id"]
    assert len(client.app.state.analyst.calls) == 1


def test_concurrent_webhook_deliveries_share_one_triage(client):
    """Two deliveries of the same threat in flight together must produce one
    triage and one alert ID, not a superseded first result that 404s."""
    client.app.state.analyst = StubAnalyst(delay=0.1)
    payload = {"id": "race-1", "threatInfo": {"threatName": "evil.exe"}}
    headers = {"X-Guardian-Token": "s3cret"}

    def deliver():
        return client.post("/v1/alerts/sentinelone", json=payload, headers=headers).json()

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = list(pool.map(lambda _: deliver(), range(2)))

    assert first["alert_id"] == second["alert_id"]
    assert len(client.app.state.analyst.calls) == 1
    assert client.get(f"/v1/triage/{first['alert_id']}", headers=headers).status_code == 200


def test_normalized_endpoint_dedupes_on_source_id(client):
    """/v1/alerts must honor source_id like the vendor endpoints do, or a
    redelivery pays twice and 404s the first caller's alert ID."""
    alert = {"source": "crowdstrike", "source_id": "cs-7", "title": "Credential access"}
    headers = {"X-Guardian-Token": "s3cret"}

    first = client.post("/v1/alerts", json=alert, headers=headers).json()
    second = client.post("/v1/alerts", json=alert, headers=headers).json()

    assert first["alert_id"] == second["alert_id"]
    assert len(client.app.state.analyst.calls) == 1
    assert client.get(f"/v1/triage/{first['alert_id']}", headers=headers).status_code == 200


def test_poll_without_a_connector_is_503(client):
    response = client.post("/v1/poll", headers={"X-Guardian-Token": "s3cret"})
    assert response.status_code == 503


def test_startup_fails_closed_without_a_webhook_token():
    """An unconfigured deployment must refuse to start, not accept anonymous alerts."""
    with pytest.raises(RuntimeError, match="GUARDIAN_WEBHOOK_TOKEN"):
        create_app(Settings(s1_poll_enabled=False, webhook_token="", _env_file=None))


def test_explicit_dev_opt_out_allows_unauthenticated_writes():
    settings = Settings(
        s1_poll_enabled=False,
        webhook_token="",
        allow_unauthenticated=True,
        _env_file=None,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        client.app.state.analyst = StubAnalyst()
        response = client.post("/v1/alerts", json={"source": "manual", "title": "x"})

    assert response.status_code == 201


def test_nonpositive_poll_interval_is_rejected():
    """Zero would poll in a tight loop and retry failures with no backoff."""
    with pytest.raises(ValueError, match="s1_poll_interval"):
        Settings(webhook_token="t", s1_poll_interval=0, _env_file=None)
