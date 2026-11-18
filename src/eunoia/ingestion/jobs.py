"""Durable jobs queue (spec §5.3, §5.7).

Workers claim with ``SELECT ... FOR UPDATE SKIP LOCKED``. Every job
carries an idempotency key — ``source + canonical_url`` or
``source + external_id`` — so a re-poll never creates a duplicate job.
Retries back off 1m → 1h → 1d; after ``max_attempts`` (default 5) the job
is dead-lettered (``status='dead'``).

Helpers here only flush; transaction control (commit/rollback) belongs to
the caller, so tests and the poller can share one session per run.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from eunoia.dedup import normalize_url
from eunoia.models import Job

__all__ = [
    "backoff_for_attempt",
    "claim_next_job",
    "dispatch_job",
    "enqueue_discovery",
    "idempotency_key_for",
    "mark_job_done",
    "mark_job_failed",
    "process_job",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def backoff_for_attempt(attempts: int) -> timedelta:
    """Retry back-off (§5.7): 1 minute, then 1 hour, then 1 day."""
    if attempts <= 1:
        return timedelta(minutes=1)
    if attempts == 2:
        return timedelta(hours=1)
    return timedelta(days=1)


def idempotency_key_for(source_id: str, event: dict) -> str:
    """``source + canonical_url`` or ``source + external_id`` (§5.3)."""
    canonical_url = event.get("canonical_url")
    if canonical_url:
        return f"{source_id}|{normalize_url(str(canonical_url))}"
    external_id = event.get("external_id")
    if external_id:
        return f"{source_id}|{external_id}"
    raise ValueError("discovery event has neither canonical_url nor external_id")


def enqueue_discovery(
    session: Session,
    *,
    source_id: str,
    event: dict,
    kind: str = "hackerone_discovery",
) -> Job:
    """Enqueue a discovery event; return the existing job if already queued.

    The poller only enqueues discovery events — it never fetches bodies.
    """
    key = idempotency_key_for(source_id, event)
    session.execute(
        pg_insert(Job)
        .values(
            kind=kind,
            source_id=source_id,
            idempotency_key=key,
            payload=dict(event),
            status="pending",
        )
        .on_conflict_do_nothing(index_elements=["idempotency_key"])
    )
    session.flush()
    job = session.execute(
        select(Job).where(Job.idempotency_key == key)
    ).scalar_one()
    return job


def claim_next_job(session: Session, *, kinds: list[str] | None = None) -> Job | None:
    """Claim the oldest due pending job, ``FOR UPDATE SKIP LOCKED``.

    Returns None when no job is due. The claimed job is marked
    ``running`` immediately (flushed), so a second claim in any session
    cannot pick it up again.
    """
    stmt = (
        select(Job)
        .where(Job.status == "pending")
        .where((Job.next_attempt_at.is_(None)) | (Job.next_attempt_at <= _now()))
        .order_by(Job.created_at.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if kinds:
        stmt = stmt.where(Job.kind.in_(kinds))
    job = session.execute(stmt).scalar_one_or_none()
    if job is None:
        return None
    job.status = "running"
    session.flush()
    return job


def mark_job_done(session: Session, job: Job) -> None:
    job.status = "done"
    job.error = None
    session.flush()


def mark_job_failed(session: Session, job: Job, error: str | Exception) -> None:
    """Record a failure; retry with back-off, or dead-letter at the cap."""
    job.attempts = int(job.attempts or 0) + 1
    job.error = str(error)[:2000]
    if job.attempts >= int(job.max_attempts or 5):
        job.status = "dead"
        job.next_attempt_at = None
    else:
        job.status = "pending"
        job.next_attempt_at = _now() + backoff_for_attempt(job.attempts)
    session.flush()


def dispatch_job(session: Session, job: Job, **kwargs) -> object:
    """Route one job to its handler by ``kind``.

    ``"nvd_refresh"`` → :func:`eunoia.enrich.handle_nvd_refresh_job`;
    ``"hackerone_discovery"`` / ``"discovery"`` → the discovery worker.
    Unknown kinds raise ``ValueError`` so a mis-routed job fails loudly
    instead of silently doing nothing. Extra keyword arguments
    (``model``, ``client``, ``limiter``) are forwarded to the handler —
    tests inject a stub encoder / mocked HTTP client this way; the
    production worker loop calls ``dispatch_job(session, job)`` bare.

    The handler imports are function-local: ``hackerone.py`` imports
    this module, so a top-level import would be circular.
    """
    if job.kind == "nvd_refresh":
        from eunoia.enrich import handle_nvd_refresh_job

        return handle_nvd_refresh_job(session, job, **kwargs)
    if job.kind in ("hackerone_discovery", "discovery"):
        from eunoia.ingestion.hackerone import handle_discovery_job

        return handle_discovery_job(session, job, **kwargs)
    raise ValueError(f"unknown job kind: {job.kind!r}")


def process_job(
    session: Session,
    job_id: UUID,
    handler: Callable[[Session, Job], object],
) -> object:
    """Run ``handler(session, job)`` for one job, tracking its outcome.

    Success → ``done``. Failure → failed with back-off (or dead-lettered)
    and the exception re-raised, so the caller sees it.
    """
    job = session.get(Job, job_id)
    if job is None:
        raise ValueError(f"job {job_id} not found")
    job.status = "running"
    session.flush()
    try:
        result = handler(session, job)
    except Exception as exc:
        mark_job_failed(session, job, exc)
        raise
    mark_job_done(session, job)
    return result
