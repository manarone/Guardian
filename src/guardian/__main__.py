"""`guardian` console entry point - runs the API service."""

from __future__ import annotations

import uvicorn

from guardian.config import get_settings


def main() -> None:
    settings = get_settings()
    # Factory form: the app is built at startup rather than at import, so
    # importing this module never requires a fully configured environment.
    uvicorn.run(
        "guardian.api.app:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
