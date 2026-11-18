"""DMCA / takedown handling (spec §6.4, 17 U.S.C. §512(c)(3) — not
legal advice).

A valid notice is acknowledged within 2 working days and the record is
stubbed within 5 working days. Author removal requests (any reason)
and vendor/program requests are honored the same way. A stubbed record
keeps only the stub text — no excerpt is served — and the action is
logged in ``takedowns`` and in the append-only audit log.

The 2/5-day deadlines are human-process deadlines, not code timers:
this module computes the deadline dates; a person must still act on
them. The named agent and contact below are placeholders that MUST be
replaced with the real operator's details before any public launch.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from eunoia.models import Takedown, Writeup
from eunoia.safety.audit import audit_append

DMCA_AGENT_NAME = "Eunoia DMCA Agent"
DMCA_AGENT_EMAIL = "dmca@eunoia.example"  # placeholder: set the real contact
TAKEDOWN_POLICY_PATH = "docs/policies/takedown.md"

TAKEDOWN_STUB = "removed following a takedown notice"

# The six statutory elements of a DMCA notice (§512(c)(3)).
DMCA_NOTICE_ELEMENTS = (
    "signature",
    "work_identification",
    "material_identification",
    "contact",
    "good_faith_statement",
    "accuracy_statement",
)

_TAKEDOWN_SOURCES = ("dmca", "author", "vendor")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def validate_notice(notice: dict) -> list[str]:
    """Missing/empty elements of a DMCA notice; [] when facially valid."""
    return [element for element in DMCA_NOTICE_ELEMENTS
            if not str(notice.get(element) or "").strip()]


def add_working_days(start: datetime, days: int) -> datetime:
    """``days`` working days after ``start`` (weekends skipped)."""
    current = start
    remaining = days
    while remaining > 0:
        current += timedelta(days=1)
        if current.weekday() < 5:
            remaining -= 1
    return current


def acknowledge_by(received_at: datetime) -> datetime:
    """Acknowledge a notice within 2 working days of receipt."""
    return add_working_days(received_at, 2)


def stub_by(received_at: datetime) -> datetime:
    """Stub the record within 5 working days of receipt."""
    return add_working_days(received_at, 5)


def apply_takedown(session: Session, writeup: Writeup, *, requester: str,
                   notice_ref: str, reason: str, source: str = "dmca",
                   received_at: datetime | None = None,
                   actor: str = "takedown") -> Takedown:
    """Stub a writeup, log the takedown, audit it. Flushes, no commit.

    Sets ``status='takedown'`` and replaces the excerpt with the stub
    (Ruling R10: the stub is all that is ever served afterwards).
    """
    if source not in _TAKEDOWN_SOURCES:
        raise ValueError(
            f"unknown takedown source {source!r}; "
            f"expected one of {_TAKEDOWN_SOURCES}")
    received = received_at or _now()
    now = _now()
    writeup.status = "takedown"
    writeup.excerpt = TAKEDOWN_STUB
    writeup.takedown_at = now
    writeup.takedown_reason = reason
    row = Takedown(
        writeup_id=writeup.id,
        requester=requester,
        notice_ref=notice_ref,
        received_at=received,
        action="stubbed",
        resolved_at=now,
    )
    session.add(row)
    audit_append(session, writeup_id=writeup.id, event="takedown",
                 actor=actor, detail={
                     "requester": requester,
                     "notice_ref": notice_ref,
                     "source": source,
                     "reason": reason,
                     "acknowledge_by": acknowledge_by(received).isoformat(),
                     "stub_by": stub_by(received).isoformat(),
                 })
    session.flush()
    return row


def apply_author_removal(session: Session, writeup: Writeup, *,
                         requester: str, reason: str,
                         received_at: datetime | None = None) -> Takedown:
    """An author's removal request, honored the same way as a DMCA
    notice — it is their work, any reason suffices."""
    return apply_takedown(session, writeup, requester=requester,
                          notice_ref=f"author-request-{writeup.id}",
                          reason=reason, source="author",
                          received_at=received_at)
