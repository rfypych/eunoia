"""Database engine: one Postgres + pgvector connection, from settings."""

from __future__ import annotations

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from eunoia.config import Settings, get_settings


def get_engine(settings: Settings | None = None) -> Engine:
    """Create the SQLAlchemy engine for the configured DATABASE_URL."""
    settings = settings or get_settings()
    return create_engine(settings.DATABASE_URL)


def check_connection(engine: Engine) -> bool:
    """True if the database answers SELECT 1, else False."""
    try:
        with engine.connect() as conn:
            return conn.execute(text("SELECT 1")).scalar() == 1
    except Exception:
        return False
