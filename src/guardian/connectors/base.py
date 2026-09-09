"""Connector interface.

A connector pulls alerts from one security product and normalizes them into
`Alert`. Implement `fetch_since` and `normalize`; the worker handles scheduling,
deduplication, and handing results to the analyst.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from guardian.models import Alert


@runtime_checkable
class Connector(Protocol):
    name: str

    async def fetch_since(self, since: datetime) -> list[dict[str, Any]]:
        """Return raw vendor payloads created after `since`, oldest first."""
        ...

    def normalize(self, raw: dict[str, Any]) -> Alert:
        """Map one raw vendor payload into Guardian's schema."""
        ...

    async def aclose(self) -> None:
        """Release any underlying HTTP resources."""
        ...
