"""FastAPI application factory and lifecycle wiring."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from guardian.agent.analyst import Analyst
from guardian.api.routes import router
from guardian.config import Settings, get_settings
from guardian.connectors.sentinelone import SentinelOneConnector
from guardian.store import InMemoryStore
from guardian.worker import PollingWorker

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    settings.validate_auth()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store = InMemoryStore()
        analyst = Analyst(settings, store)
        worker: PollingWorker | None = None

        if settings.s1_poll_enabled and settings.sentinelone_configured:
            connector = SentinelOneConnector(
                base_url=settings.s1_base_url,
                api_token=settings.s1_api_token,
                page_limit=settings.s1_page_limit,
            )
            worker = PollingWorker(
                connector=connector,
                analyst=analyst,
                store=store,
                interval=settings.s1_poll_interval,
            )
            worker.start()
        elif settings.s1_poll_enabled:
            logger.warning(
                "SentinelOne polling enabled but GUARDIAN_S1_BASE_URL / "
                "GUARDIAN_S1_API_TOKEN are unset - running webhook-only."
            )

        if settings.allow_unauthenticated:
            logger.warning(
                "GUARDIAN_ALLOW_UNAUTHENTICATED is on - write endpoints are "
                "unauthenticated. Never do this outside local development."
            )

        app.state.settings = settings
        app.state.store = store
        app.state.analyst = analyst
        app.state.worker = worker
        try:
            yield
        finally:
            if worker is not None:
                await worker.stop()

    app = FastAPI(
        title="Guardian",
        description="AI security analyst agent for SIEM/EDR alerts and logs",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(router)
    return app
