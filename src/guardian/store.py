"""Triage result storage.

An in-memory store keyed by alert ID, adequate for development and for a single
process. Swap in a real backend by implementing the same interface.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime

from guardian.models import TriageResult

# Statuses that mean Guardian is done with an alert, whether or not it got a
# verdict. `failed` is deliberately absent: a transient API failure leaves the
# alert eligible for another attempt, so it never silently costs the SOC a
# verdict. `dead_lettered` is present for the opposite reason: once the retry
# ceiling is hit, a redelivery must not restart the whole sequence.
TERMINAL_STATUSES = frozenset({"triaged", "refused", "dead_lettered"})


class InMemoryStore:
    """Bounded, newest-first store of triage results."""

    def __init__(self, max_items: int = 1000) -> None:
        self._items: OrderedDict[str, TriageResult] = OrderedDict()
        # Source alert key -> the alert ID of the latest attempt at it.
        self._by_source: dict[str, str] = {}
        self._max_items = max_items
        self._lock = asyncio.Lock()
        # One lock per in-flight source alert, created on demand and dropped
        # when the last holder leaves, so the table never outgrows the work.
        self._source_locks: dict[str, asyncio.Lock] = {}
        self._source_lock_holders: dict[str, int] = {}

    async def put(self, result: TriageResult) -> None:
        """Store a result, superseding any earlier attempt at the same alert."""
        async with self._lock:
            key = self._source_key(result)

            # `/v1/alerts` accepts a caller-supplied ID, so this write may
            # replace a different source alert's record. Drop that alert's
            # source mapping, or a redelivery of it would be "seen" and handed
            # this unrelated result.
            replaced = self._items.get(result.alert.id)
            if replaced is not None:
                replaced_key = self._source_key(replaced)
                if (
                    replaced_key is not None
                    and replaced_key != key
                    and self._by_source.get(replaced_key) == result.alert.id
                ):
                    del self._by_source[replaced_key]

            if key is not None:
                previous = self._by_source.get(key)
                if previous is not None and previous != result.alert.id:
                    # A retry supersedes the failed attempt rather than piling up.
                    self._items.pop(previous, None)
                self._by_source[key] = result.alert.id

            self._items[result.alert.id] = result
            self._items.move_to_end(result.alert.id)

            while len(self._items) > self._max_items:
                _, evicted = self._items.popitem(last=False)
                evicted_key = self._source_key(evicted)
                if evicted_key is not None and self._by_source.get(evicted_key) == evicted.alert.id:
                    del self._by_source[evicted_key]

    @asynccontextmanager
    async def lock_source(self, source: str, source_id: str) -> AsyncIterator[None]:
        """Serialize triage of one source alert across every ingestion path.

        The dedupe check, the model call, and the write are not atomic on their
        own. Two webhook deliveries of the same threat, or one racing the
        poller, would both see it as unseen, both pay for triage, and the
        second `put` would supersede the first - orphaning the alert ID the
        first caller was just handed. Hold this across all three and re-check
        `has_seen` after acquiring it.
        """
        key = self._key(source, source_id)
        lock = self._source_locks.setdefault(key, asyncio.Lock())
        self._source_lock_holders[key] = self._source_lock_holders.get(key, 0) + 1
        try:
            async with lock:
                yield
        finally:
            self._source_lock_holders[key] -= 1
            if self._source_lock_holders[key] == 0:
                del self._source_lock_holders[key]
                del self._source_locks[key]

    async def get(self, alert_id: str) -> TriageResult | None:
        """Return one result by alert ID, or None if it is not stored."""
        async with self._lock:
            return self._items.get(alert_id)

    async def list(self, limit: int = 50) -> list[TriageResult]:
        """Return the most recent results, newest first."""
        async with self._lock:
            return list(reversed(list(self._items.values())))[:limit]

    async def find_by_host(
        self, hostname: str, since: datetime, limit: int = 50
    ) -> list[TriageResult]:
        """Return results for a host observed since `since`, newest first.

        Filters before it limits. Taking the newest N and then filtering would
        let a burst of alerts from other hosts hide a genuinely related one.
        """
        wanted = hostname.lower()
        async with self._lock:
            matches = [
                r
                for r in reversed(self._items.values())
                if r.alert.host.hostname
                and r.alert.host.hostname.lower() == wanted
                and r.alert.observed_at >= since
            ]
        return matches[:limit]

    async def get_by_source(self, source: str, source_id: str) -> TriageResult | None:
        """Return the latest attempt at a source alert, whatever its status."""
        async with self._lock:
            alert_id = self._by_source.get(self._key(source, source_id))
            return self._items.get(alert_id) if alert_id else None

    async def has_seen(self, source: str, source_id: str) -> bool:
        """Report whether this source alert already reached a terminal verdict.

        A previous attempt that failed does not count as seen, so the next poll
        picks it up again instead of skipping it forever.
        """
        async with self._lock:
            alert_id = self._by_source.get(self._key(source, source_id))
            if alert_id is None:
                return False
            result = self._items.get(alert_id)
            return result is not None and result.status in TERMINAL_STATUSES

    @staticmethod
    def _key(source: str, source_id: str) -> str:
        return f"{source}:{source_id}"

    @classmethod
    def _source_key(cls, result: TriageResult) -> str | None:
        if not result.alert.source_id:
            return None
        return cls._key(result.alert.source, result.alert.source_id)
