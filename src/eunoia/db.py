"""Database engine: one Postgres + pgvector connection, from settings."""

from __future__ import annotations

import logging

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from eunoia.config import Settings, get_settings

logger = logging.getLogger(__name__)


def get_engine(settings: Settings | None = None) -> Engine:
    """Create the SQLAlchemy engine for the configured DATABASE_URL."""
    settings = settings or get_settings()
    return create_engine(settings.DATABASE_URL)


def check_connection(engine: Engine) -> bool:
    """True if the database answers SELECT 1, else False.

    Only SQLAlchemy errors are swallowed (and logged at debug level);
    a programming error (e.g. a bad URL type) still raises instead of
    masquerading as "database down" (final review triage, Task 2).
    """
    try:
        with engine.connect() as conn:
            return conn.execute(text("SELECT 1")).scalar() == 1
    except SQLAlchemyError as exc:
        logger.debug("check_connection failed: %s", exc)
        return False
