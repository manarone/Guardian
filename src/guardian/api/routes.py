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
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel

from guardian.connectors.sentinelone import normalize_threat
from guardian.models import Alert, TriageResult
from guardian.store import TERMINAL_STATUSES

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
    # Starlette decodes header values as latin-1, so re-encoding as latin-1
    # recovers the exact bytes the client sent; those are compared against the
    # configured secret's UTF-8 bytes. Encoding the decoded str as UTF-8 instead
    # would mangle any non-ASCII token so it could never authenticate.
    if not token or not hmac.compare_digest(token.encode("latin-1"), expected.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing X-Guardian-Token"
        )


async def _triage_deduped(request: Request, response: Response, alert: Alert) -> IngestResponse:
    """Triage an alert once per source ID, whichever endpoint delivered it.

    Redelivery is common - vendors retry webhooks, and one can race the poller -
    so an already-finished source alert returns its existing result (as a 200,
    since nothing was created) rather than paying for a second model call and
    orphaning the first alert ID. A source alert whose earlier attempt failed
    is retried under that attempt's ID, so one alert keeps one ID across the
    poller and the webhook. The check, the model call, and the write run under
    one per-alert lock so two deliveries arriving together cannot both pass.
    """
    store = request.app.state.store
    analyst = request.app.state.analyst

    if not alert.source_id:
        # Nothing stable to dedupe on; every delivery is its own alert.
        result = await analyst.triage(alert)
        await store.put(result)
        return IngestResponse(alert_id=alert.id, result=result)

    async with store.lock_source(alert.source, alert.source_id):
        existing = await store.get_by_source(alert.source, alert.source_id)
        if existing is not None:
            if existing.status in TERMINAL_STATUSES:
                logger.info("Returning existing triage for %s:%s", alert.source, alert.source_id)
                response.status_code = status.HTTP_200_OK
                return IngestResponse(alert_id=existing.alert.id, result=existing)
            alert = alert.model_copy(update={"id": existing.alert.id})

        result = await analyst.triage(alert)
        await store.put(result)
    return IngestResponse(alert_id=alert.id, result=result)


@router.get("/healthz", response_model=HealthResponse)
async def healthz(request: Request) -> HealthResponse:
    state = request.app.state
    counts = await state.store.status_counts()
    return HealthResponse(
        status="ok",
        model=state.settings.model,
        sentinelone_configured=state.settings.sentinelone_configured,
        polling=state.worker is not None,
        stored_count=sum(counts.values()),
        triaged_count=counts.get("triaged", 0),
        failed_count=counts.get("failed", 0),
        refused_count=counts.get("refused", 0),
        dead_lettered_count=counts.get("dead_lettered", 0),
    )


@router.post("/v1/alerts", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest_alert(
    request: Request,
    response: Response,
    alert: Alert,
    x_guardian_token: Annotated[str | None, Header()] = None,
) -> IngestResponse:
    """Triage a single alert supplied in Guardian's normalized schema.

    Triage runs inline so the caller gets the verdict back. For high-volume
    webhook sources, queue here and return 202 instead. Deduplicated on
    `source_id` when one is supplied, exactly like the vendor endpoints.
    """
    _authorize(request, x_guardian_token)
    # Guardian IDs are minted here, never taken from the caller: a supplied ID
    # matching an existing record would replace that record outright.
    alert = alert.model_copy(update={"id": str(uuid4())})
    return await _triage_deduped(request, response, alert)


@router.post(
    "/v1/alerts/sentinelone", response_model=IngestResponse, status_code=status.HTTP_201_CREATED
)
async def ingest_sentinelone_alert(
    request: Request,
    response: Response,
    payload: dict[str, Any],
    x_guardian_token: Annotated[str | None, Header()] = None,
) -> IngestResponse:
    """Triage a raw SentinelOne threat object, normalizing it on the way in.

    A payload the mapper cannot handle is the caller's problem, so it is
    reported as 422 rather than surfacing as a 500 that a vendor would keep
    retrying.
    """
    _authorize(request, x_guardian_token)
    try:
        alert = normalize_threat(payload)
    except Exception as exc:
        logger.warning("Rejecting unparseable SentinelOne payload: %s: %s", type(exc).__name__, exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Payload is not a SentinelOne threat object: {type(exc).__name__}: {exc}",
        ) from exc
    return await _triage_deduped(request, response, alert)


@router.get("/v1/triage", response_model=list[TriageResult])
async def list_triage(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=1000)] = 50,
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
