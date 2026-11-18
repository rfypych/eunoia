"""Registry status payload (spec §5.5, Task 10; Review Focus 1).

``/v1/status`` is public (no key). Per source it reports
``last_poll_at``, ``last_success_at``, ``lag_seconds``, ``enabled``,
and the plan-gated ``blocked`` flag from ``sources.cursor_state`` —
a blocked source is visible here, never a silent empty corpus.
``error_rate`` is ``null``: the schema carries no poll-attempt
counter, so no rate can be computed honestly (unknown = null, never
invented).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from eunoia.models import Source, Writeup

__all__ = ["build_status"]


def build_status(session: Session) -> dict:
    """Assemble the status document from the ``sources`` table."""
    now = datetime.now(timezone.utc)
    sources = session.execute(select(Source).order_by(Source.id)).scalars().all()
    out_sources = []
    for source in sources:
        cursor = source.cursor_state or {}
        blocked = cursor.get("blocked")
        lag = (
            (now - source.last_success_at).total_seconds()
            if source.last_success_at is not None
            else None
        )
        if blocked:
            status = "blocked"
        elif source.last_success_at is not None:
            status = "ok"
        else:
            status = "never_polled"
        out_sources.append({
            "id": source.id,
            "name": source.name,
            "type": source.type,
            "enabled": bool(source.enabled),
            "last_poll_at": _iso(source.last_poll_at),
            "last_success_at": _iso(source.last_success_at),
            "lag_seconds": int(lag) if lag is not None else None,
            "consecutive_failures": int(source.consecutive_failures or 0),
            "error_rate": None,
            "blocked": bool(blocked),
            "blocked_reason": blocked,
            "status": status,
        })
    total = session.execute(select(func.count()).select_from(Writeup)).scalar() or 0
    active = (
        session.execute(
            select(func.count()).select_from(Writeup)
            .where(Writeup.status == "active")
        ).scalar()
        or 0
    )
    return {
        "sources": out_sources,
        "writeups_total": int(total),
        "writeups_active": int(active),
        "generated_at": now.isoformat(),
    }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None
