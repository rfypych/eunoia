"""Append-only audit log (spec §6.5).

Registry-data events go into ``writeup_events``. The append-only rule
is enforced in the database, not just by convention: migration 0005
installs a trigger that rejects UPDATE and DELETE on
``writeup_events``. ``audit_append`` is flush-only — the caller owns
the commit, matching the ingestion queue's convention.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from eunoia.models import WriteupEvent

# Single source of truth for the append-only trigger: migration 0005
# installs it, and tests apply it to the test database (create_all does
# not create triggers).
APPEND_ONLY_TRIGGER_SQL = """
CREATE OR REPLACE FUNCTION eunoia_prevent_writeup_events_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'writeup_events is append-only: % is not allowed', TG_OP;
    RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS writeup_events_append_only ON writeup_events;
CREATE TRIGGER writeup_events_append_only
BEFORE UPDATE OR DELETE ON writeup_events
FOR EACH ROW EXECUTE FUNCTION eunoia_prevent_writeup_events_mutation();
"""

_EVENT_TYPES = ("created", "updated", "retracted", "takedown", "merged")


def audit_append(session: Session, *, writeup_id, event: str, actor: str,
                 detail: dict[str, Any] | None = None) -> WriteupEvent:
    """Append one audit event; flushes, does not commit.

    Raises ``ValueError`` for an event type outside the ``writeup_events``
    enum — a typo must never silently become a row.
    """
    if event not in _EVENT_TYPES:
        raise ValueError(
            f"unknown audit event {event!r}; expected one of {_EVENT_TYPES}")
    row = WriteupEvent(writeup_id=writeup_id, event=event, actor=actor,
                       detail=detail)
    session.add(row)
    session.flush()
    return row
