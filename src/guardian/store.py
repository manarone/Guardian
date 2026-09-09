"""Triage result storage.

An in-memory store keyed by alert ID, adequate for development and for a single
process. Swap in a real backend by implementing the same four methods.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict

from guardian.models import TriageResult


class InMemoryStore:
    """Bounded, newest-first store of triage results."""

    def __init__(self, max_items: int = 1000) -> None:
        self._items: OrderedDict[str, TriageResult] = OrderedDict()
        self._seen_source_ids: set[str] = set()
        self._max_items = max_items
        self._lock = asyncio.Lock()

    async def put(self, result: TriageResult) -> None:
        async with self._lock:
            self._items[result.alert.id] = result
            self._items.move_to_end(result.alert.id)
            if result.alert.source_id:
                self._seen_source_ids.add(self._key(result.alert.source, result.alert.source_id))
            while len(self._items) > self._max_items:
                _, evicted = self._items.popitem(last=False)
                if evicted.alert.source_id:
                    self._seen_source_ids.discard(
                        self._key(evicted.alert.source, evicted.alert.source_id)
                    )

    async def get(self, alert_id: str) -> TriageResult | None:
        async with self._lock:
            return self._items.get(alert_id)

    async def list(self, limit: int = 50) -> list[TriageResult]:
        async with self._lock:
            return list(reversed(list(self._items.values())))[:limit]

    async def has_seen(self, source: str, source_id: str) -> bool:
        """Dedupe guard so repeated polls don't re-triage the same alert."""
        async with self._lock:
            return self._key(source, source_id) in self._seen_source_ids

    @staticmethod
    def _key(source: str, source_id: str) -> str:
        return f"{source}:{source_id}"
