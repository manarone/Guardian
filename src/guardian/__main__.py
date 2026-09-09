"""`guardian` console entry point - runs the API service."""

from __future__ import annotations

import uvicorn

from guardian.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "guardian.api.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
