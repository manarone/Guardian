"""Guardian's vendor-neutral alert and verdict schema.

Every connector normalizes its source's payload into `Alert`, so the analyst
agent and the API never encode vendor quirks. Adding a connector means writing
a mapper into these types, nothing more.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Disposition(str, Enum):
    """What the analyst concluded the alert actually is."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


class Process(BaseModel):
    name: str | None = None
    path: str | None = None
    command_line: str | None = None
    pid: int | None = None
    sha256: str | None = None
    signed: bool | None = None
    signer: str | None = None
    parent_name: str | None = None
    parent_command_line: str | None = None


class Host(BaseModel):
    hostname: str | None = None
    ip: str | None = None
    os: str | None = None
    domain: str | None = None
    agent_id: str | None = None


class Indicator(BaseModel):
    """An observable extracted from the alert, for enrichment lookups."""

    type: Literal["sha256", "md5", "sha1", "ip", "domain", "url", "path", "email"]
    value: str


class Alert(BaseModel):
    """A single security alert, normalized across sources."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    source: str = Field(description="Connector that produced this, e.g. 'sentinelone'")
    source_id: str | None = Field(default=None, description="Vendor's own alert ID")
    title: str
    description: str | None = None
    severity: Severity = Severity.MEDIUM
    observed_at: datetime = Field(default_factory=_utcnow)
    received_at: datetime = Field(default_factory=_utcnow)
    cursor_at: datetime | None = Field(
        default=None,
        description=(
            "Value of the field the source paginates on, which is not always "
            "`observed_at`. SentinelOne pages on createdAt but reports "
            "identifiedAt as the detection time, and the two differ. The worker "
            "advances its high-water mark with this so the cursor always speaks "
            "the source's own units. Leave it None when the source did not "
            "supply one; the worker then holds its cursor rather than guess."
        ),
    )

    host: Host = Field(default_factory=Host)
    process: Process = Field(default_factory=Process)
    user: str | None = None

    classification: str | None = Field(
        default=None, description="Vendor's own label, e.g. 'Malware'"
    )
    mitre_techniques: list[str] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)

    vendor_status: str | None = Field(default=None, description="e.g. mitigated, blocked, detected")
    raw: dict[str, Any] = Field(default_factory=dict, description="Original vendor payload")

    @field_validator("observed_at", "received_at", "cursor_at")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime | None) -> datetime | None:
        """Treat a naive timestamp as UTC.

        An ISO string posted to /v1/alerts without an offset parses naive, and
        comparing that against an aware cutoff raises TypeError - which would
        surface as a failed triage rather than a validation error. Normalizing
        at the schema boundary keeps every downstream comparison safe.
        """
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value

    def summary(self) -> str:
        """Compact human/model-readable rendering used in the triage prompt."""
        lines = [
            f"Alert ID: {self.id}",
            f"Source: {self.source}" + (f" (vendor ID {self.source_id})" if self.source_id else ""),
            f"Title: {self.title}",
            f"Vendor severity: {self.severity.value}",
            f"Observed at: {self.observed_at.isoformat()}",
        ]
        if self.classification:
            lines.append(f"Vendor classification: {self.classification}")
        if self.vendor_status:
            lines.append(f"Vendor status: {self.vendor_status}")
        if self.description:
            lines.append(f"Description: {self.description}")
        if self.mitre_techniques:
            lines.append(f"MITRE techniques: {', '.join(self.mitre_techniques)}")

        host = self.host.model_dump(exclude_none=True)
        if host:
            lines.append("Host: " + ", ".join(f"{k}={v}" for k, v in host.items()))

        proc = self.process.model_dump(exclude_none=True)
        if proc:
            lines.append("Process: " + ", ".join(f"{k}={v}" for k, v in proc.items()))

        if self.user:
            lines.append(f"User: {self.user}")
        if self.indicators:
            lines.append("Indicators: " + ", ".join(f"{i.type}:{i.value}" for i in self.indicators))
        return "\n".join(lines)


class Verdict(BaseModel):
    """The analyst agent's structured conclusion. Emitted via structured outputs."""

    disposition: Disposition
    confidence: float = Field(ge=0.0, le=1.0, description="0-1 confidence in the disposition")
    severity: Severity = Field(description="Analyst's severity, may differ from the vendor's")
    title: str = Field(description="One-line summary of what actually happened")
    summary: str = Field(description="2-4 sentence explanation a SOC lead can read")
    reasoning: str = Field(description="Evidence and how it supports the disposition")
    recommended_actions: list[str] = Field(
        default_factory=list, description="Concrete next steps, most important first"
    )
    escalate: bool = Field(description="True if a human analyst should look at this now")


class TriageResult(BaseModel):
    """An alert plus its verdict and the audit trail of how it was reached."""

    alert: Alert
    verdict: Verdict | None = None
    status: Literal["pending", "triaged", "failed", "refused", "dead_lettered"] = "pending"
    # `failed` means another attempt is coming; `dead_lettered` means Guardian
    # gave up (retry ceiling, queue overflow, or nothing stable to retry by)
    # and a human has to pick it up. Only the latter counts as seen.
    error: str | None = None
    enrichment_log: list[str] = Field(
        default_factory=list, description="Tool calls the agent made, for audit"
    )
    model: str | None = None
    triaged_at: datetime | None = None
