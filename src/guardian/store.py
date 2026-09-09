"""Triage result storage.

An in-memory store keyed by alert ID, adequate for development and for a single
process. Swap in a real backend by implementing the same four methods.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict

from guardian.models import TriageResult

# Statuses that mean triage is done with an alert. Anything else - notably a
# transient API failure - leaves it eligible for another attempt, so a failed
# request never silently costs the SOC a verdict.
TERMINAL_STATUSES = frozenset({"triaged", "refused"})


class InMemoryStore:
    """Bounded, newest-first store of triage results."""

    def __init__(self, max_items: int = 1000) -> None:
        self._items: OrderedDict[str, TriageResult] = OrderedDict()
        # Source alert key -> the alert ID of the latest attempt at it.
        self._by_source: dict[str, str] = {}
        self._max_items = max_items
        self._lock = asyncio.Lock()

    async def put(self, result: TriageResult) -> None:
        """Store a result, superseding any earlier attempt at the same alert."""
        async with self._lock:
            key = self._source_key(result)
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

    async def get(self, alert_id: str) -> TriageResult | None:
        """Return one result by alert ID, or None if it is not stored."""
        async with self._lock:
            return self._items.get(alert_id)

    async def list(self, limit: int = 50) -> list[TriageResult]:
        """Return the most recent results, newest first."""
        async with self._lock:
            return list(reversed(list(self._items.values())))[:limit]

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
