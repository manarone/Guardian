"""SentinelOne connector.

Pulls threats from the SentinelOne management console
(`GET /web/api/v2.1/threats`) and maps them into Guardian's `Alert` schema.

Auth is a console API token sent as `Authorization: ApiToken <token>`. The
mapper is deliberately defensive - SentinelOne's threat objects vary by agent
version and detection engine, so every field access tolerates absence.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from guardian.models import Alert, Host, Indicator, Process, Severity

logger = logging.getLogger(__name__)

# SentinelOne `confidenceLevel` / `analystVerdict` -> Guardian severity.
_CONFIDENCE_SEVERITY = {
    "malicious": Severity.HIGH,
    "suspicious": Severity.MEDIUM,
    "n/a": Severity.LOW,
}


class SentinelOneConnector:
    name = "sentinelone"

    def __init__(
        self,
        base_url: str,
        api_token: str,
        page_limit: int = 100,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not base_url or not api_token:
            raise ValueError("SentinelOne connector requires both base_url and api_token")
        self.base_url = base_url.rstrip("/")
        self.page_limit = page_limit
        self._client = client or httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"ApiToken {api_token}",
                "Accept": "application/json",
            },
            timeout=30.0,
        )

    async def fetch_since(self, since: datetime) -> list[dict[str, Any]]:
        """Fetch threats created at or after `since`, oldest first.

        The bound is inclusive (`createdAt__gte`). An exclusive bound would drop
        a threat sharing its createdAt with the last one processed; re-reading
        the boundary and letting the worker's dedupe discard it is the safer
        trade for security alerting, where a missed alert costs more than a
        repeated fetch.
        """
        params: dict[str, Any] = {
            "limit": self.page_limit,
            "sortBy": "createdAt",
            "sortOrder": "asc",
            "createdAt__gte": _to_s1_timestamp(since),
        }
        threats: list[dict[str, Any]] = []
        cursor: str | None = None

        while True:
            page_params = dict(params)
            if cursor:
                page_params["cursor"] = cursor
            response = await self._client.get("/web/api/v2.1/threats", params=page_params)
            response.raise_for_status()
            body = response.json()

            threats.extend(body.get("data") or [])
            cursor = (body.get("pagination") or {}).get("nextCursor")
            if not cursor:
                break

        logger.info("Fetched %d SentinelOne threats since %s", len(threats), since.isoformat())
        return threats

    def normalize(self, raw: dict[str, Any]) -> Alert:
        return normalize_threat(raw)

    async def aclose(self) -> None:
        await self._client.aclose()


def normalize_threat(raw: dict[str, Any]) -> Alert:
    """Map one SentinelOne threat object into Guardian's schema.

    Pure and credential-free, so the webhook route can normalize an inbound
    payload without a configured connector.
    """
    info = raw.get("threatInfo") or {}
    agent = raw.get("agentRealtimeInfo") or {}

    sha256 = info.get("sha256")
    file_path = info.get("filePath")

    indicators: list[Indicator] = []
    if sha256:
        indicators.append(Indicator(type="sha256", value=sha256))
    if file_path:
        indicators.append(Indicator(type="path", value=file_path))
    agent_ip = agent.get("agentIpV4")
    if agent_ip:
        # S1 can return several comma-separated addresses on multi-homed hosts.
        for ip in str(agent_ip).split(","):
            ip = ip.strip()
            if ip:
                indicators.append(Indicator(type="ip", value=ip))

    return Alert(
        source=SentinelOneConnector.name,
        source_id=str(raw.get("id")) if raw.get("id") is not None else None,
        title=info.get("threatName") or "SentinelOne threat",
        description=_build_description(info),
        severity=_map_severity(info),
        observed_at=_parse_timestamp(info.get("identifiedAt") or info.get("createdAt")),
        # Pagination is on createdAt, which trails identifiedAt - keep them apart.
        cursor_at=_parse_timestamp(info.get("createdAt") or info.get("identifiedAt")),
        classification=info.get("classification"),
        mitre_techniques=_extract_techniques(raw.get("indicators") or []),
        indicators=indicators,
        vendor_status=info.get("mitigationStatus"),
        user=info.get("processUser"),
        host=Host(
            hostname=agent.get("agentComputerName"),
            ip=str(agent_ip).split(",")[0].strip() if agent_ip else None,
            os=agent.get("agentOsName"),
            domain=agent.get("agentDomain"),
            agent_id=agent.get("agentId"),
        ),
        process=Process(
            name=info.get("originatorProcess"),
            path=file_path,
            command_line=info.get("maliciousProcessArguments"),
            sha256=sha256,
            signed=_map_signed(info.get("fileVerificationType")),
            signer=info.get("publisherName"),
            parent_name=info.get("parentProcessName"),
        ),
        raw=raw,
    )


def _build_description(info: dict[str, Any]) -> str | None:
    parts = []
    if info.get("classification"):
        parts.append(f"{info['classification']} detection")
    if info.get("detectionType"):
        parts.append(f"detection type {info['detectionType']}")
    if info.get("engines"):
        parts.append(f"engines: {', '.join(info['engines'])}")
    if info.get("initiatedByDescription"):
        parts.append(f"initiated by {info['initiatedByDescription']}")
    if info.get("storyline"):
        parts.append(f"storyline {info['storyline']}")
    return "; ".join(parts) or None


def _map_severity(info: dict[str, Any]) -> Severity:
    # Ransomware is escalated regardless of the engine's confidence label, so
    # this has to come first - a "suspicious" ransomware detection is still
    # critical.
    if "ransomware" in (info.get("classification") or "").lower():
        return Severity.CRITICAL
    confidence = (info.get("confidenceLevel") or "").lower()
    if confidence in _CONFIDENCE_SEVERITY:
        return _CONFIDENCE_SEVERITY[confidence]
    return Severity.MEDIUM


def _map_signed(verification_type: Any) -> bool | None:
    if not verification_type:
        return None
    return str(verification_type).lower() == "signed"


def _extract_techniques(indicators: list[dict[str, Any]]) -> list[str]:
    """Pull MITRE technique names out of S1's nested indicator/tactic structure."""
    techniques: list[str] = []
    for indicator in indicators:
        for tactic in indicator.get("tactics") or []:
            for technique in tactic.get("techniques") or []:
                name = technique.get("name")
                if name and name not in techniques:
                    techniques.append(name)
    return techniques


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            logger.debug("Unparseable SentinelOne timestamp: %r", value)
    return datetime.now(UTC)


def _to_s1_timestamp(value: datetime) -> str:
    """SentinelOne expects UTC ISO-8601 with milliseconds and a trailing Z."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
