"""Background poller: pulls new alerts from a connector and triages them."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from guardian.agent.analyst import Analyst
from guardian.connectors.base import Connector
from guardian.store import InMemoryStore

logger = logging.getLogger(__name__)


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

    async def poll_once(self) -> list[str]:
        """Fetch, deduplicate, and triage one batch. Returns triaged alert IDs."""
        raw_alerts = await self.connector.fetch_since(self._since)
        triaged: list[str] = []

        for raw in raw_alerts:
            alert = self.connector.normalize(raw)
            if alert.source_id and await self.store.has_seen(alert.source, alert.source_id):
                continue

            result = await self.analyst.triage(alert)
            await self.store.put(result)
            triaged.append(alert.id)

            # Advance the high-water mark as we go, so a mid-batch crash doesn't
            # re-triage everything already handled.
            self._since = max(self._since, alert.observed_at)

        if triaged:
            logger.info("Triaged %d new %s alert(s)", len(triaged), self.connector.name)
        return triaged
