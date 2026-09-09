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
        """Return raw vendor payloads at or after `since`, oldest first.

        The bound is inclusive, so no alert is lost to a timestamp tie at the
        batch boundary. Re-delivered alerts are dropped by the worker's dedupe.
        Implementations should set `Alert.cursor_at` to whichever field they
        paginate on.
        """
        ...

    def normalize(self, raw: dict[str, Any]) -> Alert:
        """Map one raw vendor payload into Guardian's schema."""
        ...

    def identify(self, raw: Any) -> str | None:
        """Best-effort vendor ID for a payload `normalize` could not handle.

        Lets the worker quarantine a malformed record under a stable identity
        so it is skipped on the next fetch instead of blocking the batch.
        Return None if nothing usable can be read.
        """
        ...

    async def aclose(self) -> None:
        """Release any underlying HTTP resources."""
        ...
