"""On-demand CVE enrichment, cached in ``cve_cache`` (spec §5.4.5).

``enrich_cve`` is the single entry point: a fresh cache row is served
in <1s (target design); a stale/missing row triggers one NVD fetch and
the result is cached with a 1-day TTL. A 429 (or any NVD failure)
never blocks ingestion or lookup (Review Focus 2): the stale cached
row is served if one exists, a refresh job is queued, and the call
still returns — with ``stale=True`` when the data served is expired.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

import httpx
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.ingestion.nvd import (
    NvdError,
    NvdRateLimitedError,
    TokenBucket,
    fetch_cve,
    fetch_epss,
)
from eunoia.models import CveCache, Job

__all__ = ["CACHE_TTL", "CveRecord", "enrich_cve", "handle_nvd_refresh_job"]


def handle_nvd_refresh_job(
    session: Session,
    job: Job,
    client: httpx.Client | None = None,
    limiter: TokenBucket | None = None,
) -> CveRecord:
    """Consume one ``nvd_refresh`` job: re-fetch its CVE into ``cve_cache``.

    The job payload carries ``{"cve_id": ...}`` (queued by
    :func:`enrich_cve` when a fetch degraded). Raises ``ValueError``
    when the payload has no CVE id. ``dispatch_job`` routes to this.

    Raises when the fetch did not succeed (Ruling R8): ``enrich_cve``
    never raises on NVD failure — on 429 it serves stale cache
    (``stale=True``) and on 404 it returns an empty record — so a
    handler that returned normally would let ``process_job`` mark the
    job ``done`` while the ``nvd:<cve>`` idempotency key can never be
    queued again, leaving the stale row unrefreshed forever. Raising
    makes ``process_job`` retry with back-off instead; genuine 404s
    retry, then dead-letter visibly, rather than vanishing silently.
    """
    cve_id = (job.payload or {}).get("cve_id")
    if not cve_id:
        raise ValueError(f"nvd_refresh job {job.id} has no cve_id in payload")
    cve_id = str(cve_id).strip().upper()
    record = enrich_cve(cve_id, session=session, client=client, limiter=limiter)
    if record.stale:
        raise NvdRateLimitedError(
            f"nvd_refresh for {cve_id} degraded to stale cache; retrying"
        )
    row = session.get(CveCache, cve_id)
    if (
        row is None
        or row.expires_at is None
        or row.expires_at <= datetime.now(timezone.utc)
    ):
        # No fresh data was fetched or stored (e.g. NVD 404: unknown CVE).
        raise NvdError(f"nvd_refresh for {cve_id} fetched no fresh data; retrying")
    return record

CACHE_TTL = timedelta(days=1)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


@dataclass(frozen=True)
class CveRecord:
    cvss_score: float | None
    cvss_vector: str | None
    cwe_ids: list[str]
    kev: bool
    kev_date_added: date | None
    epss: float | None
    epss_percentile: float | None
    stale: bool = False


def _record_from_row(row: CveCache, stale: bool = False) -> CveRecord:
    return CveRecord(
        cvss_score=float(row.cvss_score) if row.cvss_score is not None else None,
        cvss_vector=row.cvss_vector,
        cwe_ids=list(row.cwe_ids or []),
        kev=bool(row.kev),
        kev_date_added=row.kev_date_added,
        epss=float(row.epss) if row.epss is not None else None,
        epss_percentile=(
            float(row.epss_percentile) if row.epss_percentile is not None else None
        ),
        stale=stale,
    )


def _empty_record() -> CveRecord:
    return CveRecord(None, None, [], False, None, None, None)


def _queue_refresh(session: Session, cve_id: str) -> None:
    """Queue an ``nvd_refresh`` job; idempotent on ``nvd:<cve_id>``."""
    session.execute(
        pg_insert(Job)
        .values(
            kind="nvd_refresh",
            source_id=None,
            idempotency_key=f"nvd:{cve_id}",
            payload={"cve_id": cve_id},
            status="pending",
        )
        .on_conflict_do_nothing(index_elements=["idempotency_key"])
    )


def _finish(session: Session, own_session: bool) -> None:
    """End a unit of work: commit when this call owns the session,
    flush only when the caller owns the transaction (the ``jobs.py``
    convention). Final review I5: ``enrich_cve`` used to commit the
    caller's session in both the degrade and success paths, so a DB
    error in any pipeline step poisoned the session
    (``PendingRollbackError``) and later steps failed despite the
    "pipeline never fails the job" claim."""
    if own_session:
        session.commit()
    else:
        session.flush()


def enrich_cve(
    cve_id: str,
    session: Session | None = None,
    client: httpx.Client | None = None,
    api_key: str | None = None,
    limiter: TokenBucket | None = None,
    include_epss: bool = False,
) -> CveRecord:
    """Enrich one CVE from cache, else NVD (cached 1 day), else stale cache.

    ``session``/``client``/``limiter`` are injectable for tests; without
    them a session is opened on the configured database and closed on
    return. ``include_epss`` opts into the (optional) FIRST EPSS fetch.
    ``api_key`` is the key *value*, resolved by the caller from the
    ``NVD_API_KEY_REF`` vault name — this module never reads secrets.
    """
    cve_id = cve_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        raise ValueError(f"not a CVE id: {cve_id!r}")

    own_session = session is None
    if own_session:
        engine = get_engine(get_settings())
        session = Session(engine)
    assert session is not None
    try:
        now = datetime.now(timezone.utc)
        row = session.get(CveCache, cve_id)
        if row is not None and row.expires_at is not None and row.expires_at > now:
            return _record_from_row(row)

        try:
            fetched = fetch_cve(cve_id, client=client, api_key=api_key, limiter=limiter)
        except (NvdRateLimitedError, NvdError):
            # Degrade, never block: serve the stale row if one exists and
            # queue a refresh; without any cache there is nothing to serve.
            _queue_refresh(session, cve_id)
            _finish(session, own_session)
            if row is not None:
                return _record_from_row(row, stale=True)
            return _empty_record()
        if fetched is None:
            # Unknown to NVD: do not cache "unknown", so a later call
            # retries instead of serving a cached empty record — but
            # return the stored row when one exists (a KEV-only row
            # must keep its kev=True flag; Task 7 triage item).
            if row is not None:
                return _record_from_row(row, stale=True)
            return _empty_record()

        epss: float | None = None
        epss_percentile: float | None = None
        if include_epss:
            epss, epss_percentile = fetch_epss(cve_id, client=client)

        if row is None:
            row = CveCache(cve_id=cve_id)
            session.add(row)
        # Preserve the KEV flag: NVD carries no KEV data, and a prior
        # KEV sync may have flagged this row.
        row.cvss_score = fetched["cvss_score"]
        row.cvss_vector = fetched["cvss_vector"]
        row.cwe_ids = fetched["cwe_ids"]
        if include_epss:
            # Task 7 triage item: with include_epss=False the locals
            # above are None, and assigning them here used to wipe a
            # stored EPSS value on every plain NVD refresh.
            row.epss = epss
            row.epss_percentile = epss_percentile
        row.fetched_at = now
        row.expires_at = now + CACHE_TTL
        _finish(session, own_session)
        return _record_from_row(row)
    finally:
        if own_session:
            session.close()
