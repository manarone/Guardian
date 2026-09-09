"""Enrichment tools the analyst agent can call during triage.

`search_related_alerts` is fully implemented against Guardian's own store. The
threat-intel and asset-inventory tools are wiring points: each one returns an
explicit "not configured" result the model is told how to interpret, so the
agent degrades to a lower-confidence verdict instead of hallucinating context.
Replace the marked bodies with real API calls as you connect each source.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from anthropic import beta_async_tool

from guardian.models import Alert
from guardian.store import InMemoryStore

logger = logging.getLogger(__name__)

NOT_CONFIGURED = (
    "NOT_CONFIGURED: this enrichment source is not connected in this deployment. "
    "Treat the indicator as unknown rather than benign, and lower your confidence."
)


def build_tools(store: InMemoryStore, call_log: list[str], current: Alert | None = None) -> list:
    """Build the agent's tool list, bound to a store and an audit log.

    `call_log` accumulates one line per tool call so the triage result carries a
    reviewable trail of what the agent looked at. `current` is the alert under
    triage; its own earlier attempts are hidden from `search_related_alerts` so
    a retry cannot cite itself as corroborating activity.
    """

    def record(line: str) -> None:
        logger.info("enrichment: %s", line)
        call_log.append(line)

    def is_current(candidate: Alert) -> bool:
        if current is None:
            return False
        if candidate.id == current.id:
            return True
        return bool(
            current.source_id
            and candidate.source == current.source
            and candidate.source_id == current.source_id
        )

    @beta_async_tool
    async def search_related_alerts(hostname: str, hours: int = 24) -> str:
        """Find other recent Guardian alerts involving the same host.

        Use this to tell an isolated detection apart from one step of a broader
        intrusion, and to spot noisy hosts that generate the same alert often.

        Args:
            hostname: Hostname to search for, as it appears on the alert.
            hours: How far back to look. Defaults to 24.
        """
        record(f"search_related_alerts(hostname={hostname!r}, hours={hours})")
        cutoff = datetime.now(UTC) - timedelta(hours=hours)
        results = await store.list(limit=200)

        matches = [
            r
            for r in results
            if not is_current(r.alert)
            and r.alert.host.hostname
            and r.alert.host.hostname.lower() == hostname.lower()
            and r.alert.observed_at >= cutoff
        ]
        if not matches:
            return f"No other alerts for {hostname} in the last {hours}h."

        lines = [f"{len(matches)} alert(s) for {hostname} in the last {hours}h:"]
        for r in matches[:20]:
            verdict = r.verdict.disposition.value if r.verdict else r.status
            lines.append(
                f"- [{r.alert.observed_at.isoformat()}] {r.alert.title} "
                f"(severity={r.alert.severity.value}, verdict={verdict})"
            )
        return "\n".join(lines)

    @beta_async_tool
    async def lookup_file_reputation(sha256: str) -> str:
        """Look up threat-intel reputation for a file hash.

        Args:
            sha256: SHA-256 hash of the file.
        """
        record(f"lookup_file_reputation(sha256={sha256!r})")
        # TODO: call your threat-intel provider (VirusTotal, Recorded Future,
        # an internal reputation service) and return its verdict plus first-seen
        # date and detection ratio.
        return NOT_CONFIGURED

    @beta_async_tool
    async def lookup_network_indicator(indicator: str, kind: str) -> str:
        """Look up reputation for a network indicator.

        Args:
            indicator: The IP address, domain, or URL to look up.
            kind: One of "ip", "domain", or "url".
        """
        record(f"lookup_network_indicator(indicator={indicator!r}, kind={kind!r})")
        # TODO: call your network threat-intel source and return reputation,
        # categorization, passive DNS, and whether the destination is internal.
        return NOT_CONFIGURED

    @beta_async_tool
    async def get_host_context(hostname: str) -> str:
        """Get asset-inventory context for a host: owner, role, and criticality.

        Args:
            hostname: Hostname to look up.
        """
        record(f"get_host_context(hostname={hostname!r})")
        # TODO: query your CMDB/asset inventory. Business criticality and whether
        # the host is a server, a developer workstation, or an executive laptop
        # changes both the disposition and the urgency.
        return NOT_CONFIGURED

    return [
        search_related_alerts,
        lookup_file_reputation,
        lookup_network_indicator,
        get_host_context,
    ]
