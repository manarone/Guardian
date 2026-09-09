"""Background poller: pulls new alerts from a connector and triages them."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from guardian.agent.analyst import Analyst
from guardian.connectors.base import Connector
from guardian.store import InMemoryStore

logger = logging.getLogger(__name__)


@dataclass
class PollSummary:
    """Outcome of one poll cycle, split by status.

    Kept separate so a run during a model outage cannot look like a successful
    one: only `triaged` means a verdict was produced.
    """

    triaged: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)

    @property
    def processed(self) -> int:
        return len(self.triaged) + len(self.failed) + len(self.refused)


class PollingWorker:
    """Polls a connector on an interval and triages anything new.

    The high-water mark starts one lookback window in the past so a fresh start
    picks up recent alerts rather than only those arriving from now on.
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
        """Fetch, deduplicate, and triage one batch.

        Serialized against concurrent callers - the scheduled loop and a manual
        `POST /v1/poll` would otherwise race on the dedupe check.
        """
        async with self._poll_lock:
            return await self._poll_once_locked()

    async def _poll_once_locked(self) -> PollSummary:
        raw_alerts = await self.connector.fetch_since(self._since)
        summary = PollSummary()
        batch_cursor = self._since
        # Earliest cursor among alerts that failed this cycle. The watermark must
        # not move past it, or the inclusive refetch can never reach them again.
        retry_floor: datetime | None = None

        for raw in raw_alerts:
            alert = self.connector.normalize(raw)
            # Track the source's own pagination field, not the detection time.
            cursor = alert.cursor_at or alert.observed_at
            batch_cursor = max(batch_cursor, cursor)

            if alert.source_id and await self.store.has_seen(alert.source, alert.source_id):
                continue

            result = await self.analyst.triage(alert)
            await self.store.put(result)

            if result.status == "triaged":
                summary.triaged.append(alert.id)
            elif result.status == "refused":
                # Terminal: a refusal needs a human, and retrying only burns tokens.
                summary.refused.append(alert.id)
            else:
                summary.failed.append(alert.id)
                retry_floor = cursor if retry_floor is None else min(retry_floor, cursor)

        # Commit the high-water mark once, after the batch. If this cycle raises
        # partway, `_since` is untouched and the next cycle refetches the batch;
        # dedupe drops whatever already landed. A failed alert holds the
        # watermark at its own cursor so the next cycle can still reach it.
        self._since = retry_floor if retry_floor is not None else batch_cursor

        if summary.processed:
            logger.info(
                "%s poll: %d triaged, %d failed, %d refused",
                self.connector.name,
                len(summary.triaged),
                len(summary.failed),
                len(summary.refused),
            )
        return summary
