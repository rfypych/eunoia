#!/usr/bin/env python3
"""Eunoia REST API server — thin CLI entry point.

Real logic lives in :mod:`eunoia.api.rest` (`create_app`); this script
only exists so supervisord can run the API with uvicorn.
Run from the repo root with the venv: ``.venv/bin/python
scripts/serve_api.py``.

Bind address comes from ``EUNOIA_API_HOST`` / ``EUNOIA_API_PORT``
(defaults ``0.0.0.0`` / ``10004`` — the public port on the 0xrphy-box).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import uvicorn

from eunoia.api.rest import create_app


def main() -> None:
    host = os.environ.get("EUNOIA_API_HOST", "0.0.0.0")
    port = int(os.environ.get("EUNOIA_API_PORT", "10004"))
    uvicorn.run(create_app(), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
