"""Worker tests: deduplication, cursor advancement, retry, and concurrency."""

import asyncio
from datetime import UTC, datetime, timedelta

from guardian.models import Alert, TriageResult
from guardian.store import InMemoryStore
from guardian.worker import MAX_RETRY_ATTEMPTS, PollingWorker


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


def _worker(connector, analyst, store=None, interval=3600):
    # interval=0 makes retry backoff zero, so a queued retry is due immediately.
    return PollingWorker(
        connector=connector,
        analyst=analyst,
        store=store or InMemoryStore(),
        interval=interval,
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


async def test_failed_triage_is_retried_from_the_queue():
    """A transient failure is retried from the queue, not by refetching."""
    payload = {"id": "a", "observed_at": datetime.now(UTC)}
    # Second batch is empty: the retry must come from the queue, not the source.
    connector = FakeConnector([[payload], []])
    store = InMemoryStore()

    failing = FakeAnalyst(status="failed")
    worker = _worker(connector, failing, store, interval=0)
    await worker.poll_once()
    assert failing.calls == ["a"]

    worker.analyst = succeeding = FakeAnalyst(status="triaged")
    await worker.poll_once()

    assert succeeding.calls == ["a"]
    assert await store.has_seen("sentinelone", "a")
    assert worker._retries == {}


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


async def test_cursor_advances_past_failures_while_they_stay_queued():
    """A failure must not pin the cursor - that refetches history every cycle."""
    base = datetime.now(UTC) - timedelta(minutes=10)
    later = base + timedelta(seconds=30)
    batch = [
        {"id": "fails", "observed_at": base, "cursor_at": base},
        {"id": "works", "observed_at": base, "cursor_at": later},
    ]

    class Selective(FakeAnalyst):
        async def triage(self, alert):
            self.calls.append(alert.source_id)
            status = "failed" if alert.source_id == "fails" else "triaged"
            return TriageResult(alert=alert, status=status)

    connector = FakeConnector([batch, []])
    worker = _worker(connector, Selective(), interval=0)

    await worker.poll_once()

    # Cursor moved to the newest alert, and the failure is queued instead.
    assert worker._since == later
    assert "sentinelone:fails" in worker._retries

    await worker.poll_once()
    assert connector.since_calls[1] == later


async def test_retry_backoff_defers_the_next_attempt():
    """Retries must not fire every cycle during an outage."""
    payload = {"id": "a", "observed_at": datetime.now(UTC)}
    connector = FakeConnector([[payload], []])
    analyst = FakeAnalyst(status="failed")
    worker = _worker(connector, analyst, interval=3600)

    await worker.poll_once()
    await worker.poll_once()

    # Backoff has not elapsed, so no second attempt was made.
    assert analyst.calls == ["a"]
    assert worker._retries["sentinelone:a"].attempts == 1


async def test_persistent_failure_is_dead_lettered():
    """A deterministically failing alert must stop consuming API calls."""
    payload = {"id": "a", "observed_at": datetime.now(UTC)}
    connector = FakeConnector([[payload]] + [[] for _ in range(10)])
    analyst = FakeAnalyst(status="failed")
    worker = _worker(connector, analyst, interval=0)

    summaries = [await worker.poll_once() for _ in range(6)]

    assert len(analyst.calls) == 5  # MAX_RETRY_ATTEMPTS
    assert worker._retries == {}
    assert any(s.dead_lettered for s in summaries)


async def test_a_queued_alert_is_not_triaged_twice_when_refetched():
    """The retry queue owns a failed alert; a refetch must not duplicate it."""
    payload = {"id": "a", "observed_at": datetime.now(UTC)}
    connector = FakeConnector([[payload], [payload]])
    analyst = FakeAnalyst(status="failed")
    worker = _worker(connector, analyst, interval=3600)

    await worker.poll_once()
    await worker.poll_once()

    assert analyst.calls == ["a"]


async def test_summary_separates_failed_and_refused_from_triaged():
    base = datetime.now(UTC) - timedelta(minutes=10)
    connector = FakeConnector([[{"id": "a", "observed_at": base, "cursor_at": base}]])
    worker = _worker(connector, FakeAnalyst(status="failed"))

    summary = await worker.poll_once()

    assert summary.triaged == []
    assert summary.failed == [(await worker.store.list())[0].alert.id]
    assert summary.processed == 1


async def test_refused_is_reported_separately_and_not_retried():
    base = datetime.now(UTC) - timedelta(minutes=10)
    payload = {"id": "a", "observed_at": base, "cursor_at": base}
    connector = FakeConnector([[payload], [payload]])
    analyst = FakeAnalyst(status="refused")
    worker = _worker(connector, analyst)

    summary = await worker.poll_once()
    await worker.poll_once()

    assert len(summary.refused) == 1
    assert analyst.calls == ["a"]


async def test_dead_lettered_boundary_alert_is_not_retriaged():
    """A dead-lettered alert that sits on the inclusive cursor boundary keeps
    coming back from the source; it must be treated as seen, not restarted."""
    payload = {"id": "a", "observed_at": datetime.now(UTC)}
    connector = FakeConnector([[payload] for _ in range(12)])
    store = InMemoryStore()
    analyst = FakeAnalyst(status="failed")
    worker = _worker(connector, analyst, store, interval=0)

    for _ in range(12):
        await worker.poll_once()

    assert len(analyst.calls) == MAX_RETRY_ATTEMPTS
    assert await store.has_seen("sentinelone", "a")
    stored = await store.get_by_source("sentinelone", "a")
    assert stored is not None and stored.status == "dead_lettered"
    assert "dead-lettered" in (stored.error or "")


async def test_retry_queue_overflow_is_dead_lettered(monkeypatch):
    """An alert evicted from a full queue is gone for good, so say so."""
    monkeypatch.setattr("guardian.worker.MAX_PENDING_RETRIES", 2)
    base = datetime.now(UTC) - timedelta(minutes=10)
    batch = [
        {"id": f"f{i}", "observed_at": base, "cursor_at": base + timedelta(seconds=i)}
        for i in range(3)
    ]
    connector = FakeConnector([batch, []])
    store = InMemoryStore()
    worker = _worker(connector, FakeAnalyst(status="failed"), store, interval=3600)

    summary = await worker.poll_once()

    evicted = await store.get_by_source("sentinelone", "f0")
    assert evicted is not None and evicted.status == "dead_lettered"
    assert summary.dead_lettered == [evicted.alert.id]
    assert evicted.alert.id not in summary.failed
    assert summary.processed == 3
    assert await store.has_seen("sentinelone", "f0")
    assert list(worker._retries) == ["sentinelone:f1", "sentinelone:f2"]


async def test_worker_skips_an_alert_the_webhook_finished_under_the_lock():
    """The poller and the webhook share one lock per source alert; whoever
    gets it second must re-check instead of paying for a second triage."""
    payload = {"id": "a", "observed_at": datetime.now(UTC)}
    connector = FakeConnector([[payload]])
    store = InMemoryStore()
    analyst = FakeAnalyst()
    worker = _worker(connector, analyst, store)

    async def webhook_wins():
        async with store.lock_source("sentinelone", "a"):
            await asyncio.sleep(0.05)
            alert = Alert(source="sentinelone", source_id="a", title="a")
            await store.put(TriageResult(alert=alert, status="triaged"))

    holder = asyncio.create_task(webhook_wins())
    await asyncio.sleep(0)  # let the webhook take the lock first
    await asyncio.gather(holder, worker.poll_once())

    assert analyst.calls == []
    assert worker._retries == {}


async def test_summary_buckets_are_exclusive_when_dead_lettering():
    """One alert, one bucket: a dead-lettered ID must not also read as failed."""
    payload = {"id": "a", "observed_at": datetime.now(UTC)}
    connector = FakeConnector([[payload]] + [[] for _ in range(6)])
    worker = _worker(connector, FakeAnalyst(status="failed"), interval=0)

    summaries = [await worker.poll_once() for _ in range(MAX_RETRY_ATTEMPTS)]
    final = summaries[-1]

    assert len(final.dead_lettered) == 1
    assert final.failed == []
    assert final.processed == 1
    assert all(len(s.failed) == 1 and s.dead_lettered == [] for s in summaries[:-1])


async def test_alert_without_source_id_is_dead_lettered_not_failed():
    """With nothing stable to retry by, the only attempt is the last one."""
    connector = FakeConnector([[{"id": "", "observed_at": datetime.now(UTC)}]])
    worker = _worker(connector, FakeAnalyst(status="failed"))

    summary = await worker.poll_once()

    assert summary.failed == []
    assert len(summary.dead_lettered) == 1
    assert (await worker.store.list())[0].status == "dead_lettered"
