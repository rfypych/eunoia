#!/usr/bin/env python3
"""Seed the `sources` table for a fresh deploy (idempotent).

The worker poller fails with "source 'hackerone' not found" on a fresh
database because nothing inserts the source row. Run once after
`alembic upgrade head`, before starting the worker:

    DATABASE_URL=postgresql+psycopg://eunoia@localhost:5432/eunoia \
        .venv/bin/python scripts/seed_sources.py

Existing rows are left untouched (only missing ids are inserted).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sqlalchemy import select

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.models import Source
from sqlalchemy.orm import Session

SOURCES = [
    {
        "id": "hackerone",
        "name": "HackerOne Hacktivity",
        "type": "api",
        "base_url": "https://api.hackerone.com",
        "feed_url": "https://api.hackerone.com/v1/hackers/hacktivity",
        "poll_interval_s": 900,
        "rate_limit_per_min": 600,
        "auth_ref": None,
        "cursor_state": {},
        "enabled": True,
    },
]


def main() -> int:
    engine = get_engine(get_settings())
    with Session(engine) as session:
        inserted = 0
        for row in SOURCES:
            if session.get(Source, row["id"]) is None:
                session.add(Source(**row))
                inserted += 1
        session.commit()
    print(f"seed_sources: inserted {inserted}, already present {len(SOURCES) - inserted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
