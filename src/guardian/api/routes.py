"""HTTP surface.

- `GET  /healthz`            - liveness and configuration check
- `POST /v1/alerts`          - push an alert in for triage (webhook target)
- `GET  /v1/triage`          - recent triage results
- `GET  /v1/triage/{id}`     - one triage result
- `POST /v1/poll`            - run one SentinelOne poll cycle now
"""

from __future__ import annotations

import hmac
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel

from guardian.connectors.sentinelone import normalize_threat
from guardian.models import Alert, TriageResult

logger = logging.getLogger(__name__)

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    model: str
    sentinelone_configured: bool
    polling: bool
    # Split so a refusal spike or model outage cannot read as successful work.
    stored_count: int
    triaged_count: int
    failed_count: int
    refused_count: int
    dead_lettered_count: int


class IngestResponse(BaseModel):
    alert_id: str
    result: TriageResult


def _authorize(request: Request, token: str | None) -> None:
    """Constant-time check of the shared webhook secret.

    Startup already refuses an unset token, so reaching the no-token branch here
    means the development opt-out is on; anything else is a misconfiguration and
    is rejected rather than waved through.
    """
    settings = request.app.state.settings
    expected = settings.webhook_token
    if not expected:
        if settings.allow_unauthenticated:
            return
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfigured: no webhook token is set",
        )
    # Starlette decodes header values as latin-1, so a non-ASCII token arrives
    # as a str that `compare_digest` refuses to compare. Bytes always compare.
    if not token or not hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing X-Guardian-Token"
        )


@router.get("/healthz", response_model=HealthResponse)
async def healthz(request: Request) -> HealthResponse:
    state = request.app.state
    results = await state.store.list(limit=1000)
    return HealthResponse(
        status="ok",
        model=state.settings.model,
        sentinelone_configured=state.settings.sentinelone_configured,
        polling=state.worker is not None,
        stored_count=len(results),
        triaged_count=sum(1 for r in results if r.status == "triaged"),
        failed_count=sum(1 for r in results if r.status == "failed"),
        refused_count=sum(1 for r in results if r.status == "refused"),
        dead_lettered_count=sum(1 for r in results if r.status == "dead_lettered"),
    )


@router.post("/v1/alerts", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest_alert(
    request: Request,
    alert: Alert,
    x_guardian_token: Annotated[str | None, Header()] = None,
) -> IngestResponse:
    """Triage a single alert supplied in Guardian's normalized schema.

    Triage runs inline so the caller gets the verdict back. For high-volume
    webhook sources, queue here and return 202 instead.
    """
    _authorize(request, x_guardian_token)
    result = await request.app.state.analyst.triage(alert)
    await request.app.state.store.put(result)
    return IngestResponse(alert_id=alert.id, result=result)


@router.post(
    "/v1/alerts/sentinelone", response_model=IngestResponse, status_code=status.HTTP_201_CREATED
)
async def ingest_sentinelone_alert(
    request: Request,
    payload: dict[str, Any],
    x_guardian_token: Annotated[str | None, Header()] = None,
) -> IngestResponse:
    """Triage a raw SentinelOne threat object, normalizing it on the way in.

    Redelivery is common - SentinelOne retries webhooks, and one can race the
    poller - so an already-triaged threat returns its existing result rather
    than paying for a second model call and orphaning the first alert ID.
    """
    _authorize(request, x_guardian_token)

    alert = normalize_threat(payload)
    store = request.app.state.store
    analyst = request.app.state.analyst

    if not alert.source_id:
        # Nothing stable to dedupe on; every delivery is its own alert.
        result = await analyst.triage(alert)
        await store.put(result)
        return IngestResponse(alert_id=alert.id, result=result)

    # Check, triage, and write under one per-alert lock, so two deliveries
    # arriving together (or one racing the poller) cannot both pass the check.
    async with store.lock_source(alert.source, alert.source_id):
        if await store.has_seen(alert.source, alert.source_id):
            existing = await store.get_by_source(alert.source, alert.source_id)
            if existing is not None:
                logger.info("Returning existing triage for %s:%s", alert.source, alert.source_id)
                return IngestResponse(alert_id=existing.alert.id, result=existing)

        result = await analyst.triage(alert)
        await store.put(result)
    return IngestResponse(alert_id=alert.id, result=result)


@router.get("/v1/triage", response_model=list[TriageResult])
async def list_triage(
    request: Request,
    limit: int = 50,
    x_guardian_token: Annotated[str | None, Header()] = None,
) -> list[TriageResult]:
    """List recent results. Authenticated: results carry the raw vendor payload."""
    _authorize(request, x_guardian_token)
    return await request.app.state.store.list(limit=limit)


@router.get("/v1/triage/{alert_id}", response_model=TriageResult)
async def get_triage(
    request: Request,
    alert_id: str,
    x_guardian_token: Annotated[str | None, Header()] = None,
) -> TriageResult:
    """Fetch one result. Authenticated: see `list_triage`."""
    _authorize(request, x_guardian_token)
    result = await request.app.state.store.get(alert_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown alert ID")
    return result


@router.post("/v1/poll")
async def poll_now(
    request: Request, x_guardian_token: Annotated[str | None, Header()] = None
) -> dict[str, Any]:
    """Trigger one poll cycle immediately instead of waiting for the interval."""
    _authorize(request, x_guardian_token)
    worker = request.app.state.worker
    if worker is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No connector is configured; set GUARDIAN_S1_BASE_URL and GUARDIAN_S1_API_TOKEN",
        )
    summary = await worker.poll_once()
    return {
        "processed": summary.processed,
        "triaged": summary.triaged,
        "failed": summary.failed,
        "refused": summary.refused,
        "dead_lettered": summary.dead_lettered,
    }
