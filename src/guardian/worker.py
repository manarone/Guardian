"""Background poller: pulls new alerts from a connector and triages them."""

from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from guardian.agent.analyst import Analyst
from guardian.connectors.base import Connector
from guardian.models import Alert, TriageResult
from guardian.store import TERMINAL_STATUSES, InMemoryStore

logger = logging.getLogger(__name__)

# A failed alert is retried with exponential backoff up to this many times, then
# dead-lettered. Without a ceiling, a deterministically failing alert would be
# resent to the model on every cycle forever.
MAX_RETRY_ATTEMPTS = 5
MAX_RETRY_BACKOFF = timedelta(hours=1)
MAX_PENDING_RETRIES = 200


@dataclass
class PollSummary:
    """Outcome of one poll cycle, split by status.

    Kept separate so a run during a model outage cannot look like a successful
    one: only `triaged` means a verdict was produced.
    """

    triaged: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    dead_lettered: list[str] = field(default_factory=list)
    # Model calls made this cycle. Tracked directly rather than summed from the
    # lists above, because an alert can be dead-lettered by queue eviction
    # without being triaged this cycle.
    attempts: int = 0

    @property
    def processed(self) -> int:
        """Alerts this cycle made a model call for."""
        return self.attempts


@dataclass
class _PendingRetry:
    """A failed alert awaiting another attempt."""

    raw: dict[str, Any]
    attempts: int = 0
    next_attempt: datetime = field(default_factory=lambda: datetime.now(UTC))


class PollingWorker:
    """Polls a connector on an interval and triages anything new.

    The high-water mark starts one lookback window in the past so a fresh start
    picks up recent alerts rather than only those arriving from now on.

    Failures are tracked in an explicit retry queue rather than by holding the
    cursor back. Holding the cursor would make one deterministically failing
    alert refetch the entire history behind it on every cycle; a queue retries
    just the alert that failed, with backoff and a ceiling.
    """

    def __init__(
        self,
        connector: Connector,
        analyst: Analyst,
        store: InMemoryStore,
        interval: int = 60,
        lookback: timedelta = timedelta(hours=1),
    ) -> None:
        self.connector = connector
        self.analyst = analyst
        self.store = store
        self.interval = interval
        self._since = datetime.now(UTC) - lookback
        self._task: asyncio.Task | None = None
        # Serializes the scheduled loop against manual POST /v1/poll calls, so
        # two cycles cannot both see the same alert as unseen and triage it twice.
        self._poll_lock = asyncio.Lock()
        self._retries: OrderedDict[str, _PendingRetry] = OrderedDict()

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="guardian-poller")
            logger.info(
                "Started %s poller (every %ds, from %s)",
                self.connector.name,
                self.interval,
                self._since.isoformat(),
            )

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None
        await self.connector.aclose()
        logger.info("Stopped %s poller", self.connector.name)

    async def _run(self) -> None:
        while True:
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # A failing poll must not kill the loop - the next tick retries.
                logger.exception("Poll cycle failed for %s", self.connector.name)
            await asyncio.sleep(self.interval)

    async def poll_once(self) -> PollSummary:
        """Retry due failures, then fetch and triage anything new.

        Serialized against concurrent callers - the scheduled loop and a manual
        `POST /v1/poll` would otherwise race on the dedupe check.
        """
        async with self._poll_lock:
            return await self._poll_once_locked()

    async def _poll_once_locked(self) -> PollSummary:
        summary = PollSummary()

        # Retries first, so a backlog drains even while new alerts keep arriving.
        for raw in self._due_retries():
            await self._triage_one(raw, summary)

        raw_alerts = await self.connector.fetch_since(self._since)
        batch_cursor = self._since

        for raw in raw_alerts:
            alert = self.connector.normalize(raw)
            # Advance only on the source's own pagination field. An alert
            # without one holds the cursor: guessing (say, from wall-clock
            # time) could jump past alerts the source has not shown us yet.
            if alert.cursor_at is not None:
                batch_cursor = max(batch_cursor, alert.cursor_at)
            else:
                logger.warning(
                    "%s alert %s carries no cursor timestamp; not advancing past it",
                    self.connector.name,
                    alert.source_id or alert.id,
                )

            key = self._retry_key(alert)
            if key is not None and key in self._retries:
                continue  # already queued; the retry path owns it
            if alert.source_id and await self.store.has_seen(alert.source, alert.source_id):
                continue

            await self._triage_one(raw, summary, alert=alert)

        # Commit the watermark once, after the batch. If this cycle raises
        # partway, `_since` is untouched and the next cycle refetches; dedupe
        # drops whatever already landed. The cursor advances past failures
        # because the retry queue, not the watermark, is what brings them back.
        self._since = batch_cursor

        if summary.processed or summary.dead_lettered:
            logger.info(
                "%s poll: %d triaged, %d failed, %d refused, %d dead-lettered (%d awaiting retry)",
                self.connector.name,
                len(summary.triaged),
                len(summary.failed),
                len(summary.refused),
                len(summary.dead_lettered),
                len(self._retries),
            )
        return summary

    async def _triage_one(
        self, raw: dict[str, Any], summary: PollSummary, alert: Alert | None = None
    ) -> None:
        """Triage one payload under its source lock and record the outcome."""
        alert = alert if alert is not None else self.connector.normalize(raw)
        key = self._retry_key(alert)
        source_id = alert.source_id

        if key is None or not source_id:
            await self._triage_and_record(alert, raw, key, summary)
            return

        async with self.store.lock_source(alert.source, source_id):
            # Re-check now that we hold the lock: a webhook delivery of this
            # same threat may have finished while we waited for it.
            if await self.store.has_seen(alert.source, source_id):
                self._clear_retry(key)
                return
            await self._triage_and_record(alert, raw, key, summary)

    async def _triage_and_record(
        self, alert: Alert, raw: dict[str, Any], key: str | None, summary: PollSummary
    ) -> None:
        summary.attempts += 1
        result = await self.analyst.triage(alert)

        if result.status == "triaged":
            summary.triaged.append(alert.id)
            self._clear_retry(key)
        elif result.status == "refused":
            # Terminal: a refusal needs a human, and retrying only burns tokens.
            summary.refused.append(alert.id)
            self._clear_retry(key)
        else:
            attempts = self._schedule_retry(key, raw)
            if attempts is None:
                summary.failed.append(alert.id)  # another attempt is coming
            else:
                result = self._dead_letter(result, f"after {attempts} failed triage attempt(s)")
                summary.dead_lettered.append(alert.id)

        await self.store.put(result)

        # Queuing this alert may have pushed the oldest one out. That one is
        # gone from the queue and the cursor is already past it, so record it
        # as dead-lettered rather than leaving a failed result nobody revisits.
        for dropped_key, dropped in self._evict_overflow():
            await self._dead_letter_evicted(dropped_key, dropped, summary)

    def _due_retries(self) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        return [p.raw for p in list(self._retries.values()) if p.next_attempt <= now]

    def _schedule_retry(self, key: str | None, raw: dict[str, Any]) -> int | None:
        """Queue another attempt.

        Returns None when a retry is scheduled, or the attempt count when the
        alert is being given up on and must be dead-lettered instead.
        """
        if key is None:
            # No stable source ID to retry against, so this was the only try.
            return 1

        pending = self._retries.get(key) or _PendingRetry(raw=raw)
        pending.attempts += 1
        pending.raw = raw

        if pending.attempts >= MAX_RETRY_ATTEMPTS:
            self._retries.pop(key, None)
            logger.error(
                "Dead-lettering %s after %d failed triage attempts; needs a human",
                key,
                pending.attempts,
            )
            return pending.attempts

        backoff = min(timedelta(seconds=self.interval * (2**pending.attempts)), MAX_RETRY_BACKOFF)
        pending.next_attempt = datetime.now(UTC) + backoff
        self._retries[key] = pending
        self._retries.move_to_end(key)
        return None

    def _evict_overflow(self) -> list[tuple[str, _PendingRetry]]:
        evicted: list[tuple[str, _PendingRetry]] = []
        while len(self._retries) > MAX_PENDING_RETRIES:
            key, pending = self._retries.popitem(last=False)
            logger.error("Retry queue full; dead-lettering %s without a verdict", key)
            evicted.append((key, pending))
        return evicted

    async def _dead_letter_evicted(
        self, key: str, pending: _PendingRetry, summary: PollSummary
    ) -> None:
        alert = self.connector.normalize(pending.raw)
        if not alert.source_id:
            return  # cannot have been queued without one

        async with self.store.lock_source(alert.source, alert.source_id):
            existing = await self.store.get_by_source(alert.source, alert.source_id)
            if existing is not None and existing.status in TERMINAL_STATUSES:
                # A webhook finished this alert while it waited for backoff.
                # The queue entry was stale; the verdict stands.
                return

            # Prefer the stored attempt so its error and audit trail survive;
            # fall back to a fresh record only if the store already evicted it.
            result = self._dead_letter(
                existing or TriageResult(alert=alert, status="failed"),
                f"retry queue exceeded {MAX_PENDING_RETRIES}; evicted after "
                f"{pending.attempts} attempt(s)",
            )
            # It may have been counted as a retryable failure earlier this cycle.
            if result.alert.id in summary.failed:
                summary.failed.remove(result.alert.id)
            summary.dead_lettered.append(result.alert.id)
            await self.store.put(result)

    @staticmethod
    def _dead_letter(result: TriageResult, reason: str) -> TriageResult:
        """Return a terminal copy of a failed result so dedupe stops retrying it."""
        error = f"{result.error}; " if result.error else ""
        return result.model_copy(
            update={"status": "dead_lettered", "error": f"{error}dead-lettered {reason}"}
        )

    def _clear_retry(self, key: str | None) -> None:
        if key is not None:
            self._retries.pop(key, None)

    @staticmethod
    def _retry_key(alert: Alert) -> str | None:
        if not alert.source_id:
            return None
        return f"{alert.source}:{alert.source_id}"
