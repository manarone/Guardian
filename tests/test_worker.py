"""Worker tests: deduplication, cursor advancement, retry, and concurrency."""

import asyncio
from datetime import UTC, datetime, timedelta

from guardian.models import Alert, TriageResult
from guardian.store import InMemoryStore
from guardian.worker import PollingWorker


class FakeConnector:
    """Serves canned payloads and records the watermark it was asked for."""

    name = "sentinelone"

    def __init__(self, batches: list[list[dict]]):
        self._batches = list(batches)
        self.since_calls: list[datetime] = []

    async def fetch_since(self, since):
        self.since_calls.append(since)
        return self._batches.pop(0) if self._batches else []

    def normalize(self, raw):
        return Alert(
            source=self.name,
            source_id=raw["id"],
            title=raw["id"],
            observed_at=raw["observed_at"],
            cursor_at=raw.get("cursor_at"),
        )

    async def aclose(self):
        pass


class FakeAnalyst:
    """Returns a configurable status, and can block to simulate a slow call."""

    def __init__(self, status: str = "triaged", delay: float = 0.0):
        self.status = status
        self.delay = delay
        self.calls: list[str] = []

    async def triage(self, alert: Alert) -> TriageResult:
        self.calls.append(alert.source_id)
        if self.delay:
            await asyncio.sleep(self.delay)
        return TriageResult(alert=alert, status=self.status)


def _worker(connector, analyst, store=None):
    return PollingWorker(
        connector=connector,
        analyst=analyst,
        store=store or InMemoryStore(),
        interval=3600,
        lookback=timedelta(hours=1),
    )


async def test_cursor_advances_on_cursor_at_not_observed_at():
    """The watermark must speak the source's pagination field, or polls loop."""
    # Inside the worker's lookback window, or the initial watermark wins.
    observed = datetime.now(UTC) - timedelta(minutes=10)
    created = observed + timedelta(seconds=4)
    connector = FakeConnector([[{"id": "a", "observed_at": observed, "cursor_at": created}], []])
    worker = _worker(connector, FakeAnalyst())

    await worker.poll_once()
    await worker.poll_once()

    assert connector.since_calls[1] == created


async def test_failed_triage_is_retried_on_the_next_poll():
    """A transient API failure must not permanently skip the alert."""
    payload = {"id": "a", "observed_at": datetime.now(UTC)}
    connector = FakeConnector([[payload], [payload]])
    store = InMemoryStore()

    failing = FakeAnalyst(status="failed")
    worker = _worker(connector, failing, store)
    await worker.poll_once()
    assert failing.calls == ["a"]

    # Same alert comes back on the next poll; this time triage succeeds.
    worker.analyst = succeeding = FakeAnalyst(status="triaged")
    await worker.poll_once()

    assert succeeding.calls == ["a"]
    assert await store.has_seen("sentinelone", "a")


async def test_terminal_result_is_not_retriaged():
    payload = {"id": "a", "observed_at": datetime.now(UTC)}
    connector = FakeConnector([[payload], [payload]])
    analyst = FakeAnalyst()
    worker = _worker(connector, analyst)

    await worker.poll_once()
    await worker.poll_once()

    assert analyst.calls == ["a"]


async def test_concurrent_polls_do_not_double_triage():
    """A manual POST /v1/poll racing the scheduled loop must not duplicate work."""
    payload = {"id": "a", "observed_at": datetime.now(UTC)}
    connector = FakeConnector([[payload], [payload]])
    analyst = FakeAnalyst(delay=0.05)
    worker = _worker(connector, analyst)

    await asyncio.gather(worker.poll_once(), worker.poll_once())

    assert analyst.calls == ["a"]


async def test_cursor_is_not_committed_when_the_batch_raises():
    """A mid-batch failure must leave the watermark alone so nothing is skipped."""
    connector = FakeConnector([])
    original_since = None

    async def boom(since):
        nonlocal original_since
        original_since = since
        raise RuntimeError("connector exploded")

    connector.fetch_since = boom
    worker = _worker(connector, FakeAnalyst())

    try:
        await worker.poll_once()
    except RuntimeError:
        pass

    assert worker._since == original_since
