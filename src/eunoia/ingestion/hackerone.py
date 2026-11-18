"""HackerOne Hacktivity poller + discovery worker (spec §5.3, §5.6).

Auth mode (Task 1 decision, docs/probes/hackerone-auth-2026-11-18.md):
the Hacktivity REST API works WITHOUT auth (``no_auth_ok``, HTTP 200) —
no token is sent. The default sort returns undisclosed items (title
null), so the poller sorts by ``-disclosed_at`` and only enqueues
disclosed reports.

Poller contract: the poller ONLY enqueues discovery events; it never
fetches bodies. The worker (``handle_discovery_job``) parses the event,
runs the 5-layer dedup (Task 4) and upserts — never blind-inserts.

Cursor: ``sources.cursor_state`` holds ``disclosed_at`` /
``latest_disclosable_activity_at`` (ISO strings, newest seen). The
Hacktivity API has no verified Lucene filter for ``disclosed_at``, so
the cursor is applied client-side: pages are fetched newest-first and
polling stops at the first item at or below the cursor.

429 policy (§5.7): one 429 → back off the host 60s (``SourceHost``) and
halve the source's per-minute budget; three 429s in one UTC day → the
host is paused until tomorrow (``HostPausedError``, no HTTP call).
403 → ``PlanGatedError`` and the source is flagged
``cursor_state["blocked"] = "plan_gated_403"`` so ``/status`` can show it
instead of an empty corpus looking like "no writeups exist".
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

import httpx
from sqlalchemy import or_
from sqlalchemy.orm import Session

from eunoia.db import get_engine
from eunoia.dedup import (
    content_hash,
    dedup_decision,
    normalize_text,
    simhash64,
    simhash_to_db,
    url_hash,
)
from eunoia.ingestion.jobs import enqueue_discovery, idempotency_key_for
from eunoia.models import Job, Source, SourceHost, Writeup, WriteupEvent, WriteupSource, WriteupVuln

__all__ = [
    "HACKTIVITY_URL",
    "HACKERONE_HOST",
    "HostPausedError",
    "PlanGatedError",
    "PollResult",
    "RateLimitedError",
    "handle_discovery_job",
    "parse_hacktivity_item",
    "poll_hackerone",
]

HACKTIVITY_URL = "https://api.hackerone.com/v1/hackers/hacktivity"
HACKERONE_HOST = "api.hackerone.com"
PAGE_SIZE_MAX = 100
MAX_PAGES_PER_RUN = 10
MAX_429_PER_DAY = 3

_SEVERITIES = {"none", "low", "medium", "high", "critical"}
# Strongest dedup decision first; used to pick one outcome when several
# existing rows match a candidate on different layers.
_DECISION_RANK = {
    "exact": 0,
    "external_id": 1,
    "content": 2,
    "near_dup_review": 3,
    "title_candidate": 4,
    "new": 5,
}
_MERGE_DECISIONS = {"exact", "external_id", "content"}


class PlanGatedError(RuntimeError):
    """HackerOne returned 403: API access is not in the plan (spec §9 Q1)."""


class RateLimitedError(RuntimeError):
    """HackerOne returned 429; the host budget was backed off (spec §5.7)."""


class HostPausedError(RuntimeError):
    """Three 429s today: the host is paused until tomorrow (spec §5.7)."""


@dataclass(frozen=True)
class PollResult:
    discovered: int
    enqueued: int
    last_cursor: str | None


def _default_client() -> httpx.Client:
    """Build the poller's HTTP client.

    httpx parses ``NO_PROXY`` into URL patterns at ``Client`` construction
    and crashes on bracketed IPv6 entries (``[::1]`` → ``Invalid port:
    ':1]'``) present in this VM's environment — so the proxy URL is read
    from the environment and passed explicitly with ``trust_env=False``,
    instead of letting httpx re-parse the environment itself.
    ``api.hackerone.com`` is public and never in ``NO_PROXY``, so ignoring
    ``NO_PROXY`` here loses nothing.
    """
    proxy = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )
    return httpx.Client(timeout=30.0, proxy=proxy or None, trust_env=False)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "unknown"


def _cursor(source: Source) -> dict:
    return dict(source.cursor_state or {})


def _is_paused(cursor: dict, today: date) -> bool:
    return (
        int(cursor.get("rate_429_count") or 0) >= MAX_429_PER_DAY
        and cursor.get("rate_429_date") == today.isoformat()
    )


def _record_429(session: Session, source: Source, cursor: dict, today: date) -> dict:
    """One 429: back off the host 60s, halve its budget, count the day."""
    host = session.get(SourceHost, HACKERONE_HOST)
    if host is None:
        host = SourceHost(host=HACKERONE_HOST)
        session.add(host)
    host.last_429 = _now()
    if cursor.get("rate_429_date") == today.isoformat():
        count = int(cursor.get("rate_429_count") or 0) + 1
    else:
        count = 1
    # JSONB does not track in-place mutation: always reassign the dict.
    new_cursor = {
        **cursor,
        "rate_429_count": count,
        "rate_429_date": today.isoformat(),
    }
    source.cursor_state = new_cursor
    if source.rate_limit_per_min:
        source.rate_limit_per_min = max(1, int(source.rate_limit_per_min) // 2)
    return new_cursor


# ---------------------------------------------------------------------------
# Parser: Hacktivity item -> JSON-safe discovery event (the parser's job
# includes boilerplate stripping; Hacktivity attributes are already
# structured text, so normalizing whitespace is the whole job here).
# ---------------------------------------------------------------------------

def parse_hacktivity_item(item: dict) -> dict | None:
    """Extract a disclosed Hacktivity item; None when it must be skipped.

    Skipped: undisclosed items (title/url null) and items without a URL —
    without a URL there is no canonical_url for the idempotency key.
    """
    attrs: dict[str, Any] = item.get("attributes") or {}
    if not attrs.get("disclosed"):
        return None
    canonical_url = attrs.get("url")
    if not canonical_url:
        return None
    title = attrs.get("title") or ""
    vuln_info = attrs.get("vulnerability_information") or ""
    excerpt_source = vuln_info or title
    # Display text keeps its case; only the hash input ("text") is
    # normalized (lowercased) by normalize_text.
    excerpt = re.sub(r"\s+", " ", excerpt_source).strip()[:300]
    bounty = attrs.get("total_awarded_amount")
    team = (item.get("relationships") or {}).get("team") or {}
    team_attrs = (team.get("data") or {}).get("attributes") or {}
    reporter = (item.get("relationships") or {}).get("reporter") or {}
    reporter_attrs = (reporter.get("data") or {}).get("attributes") or {}
    return {
        "canonical_url": canonical_url,
        "external_id": f"hackerone:{item.get('id')}",
        "title": title,
        "excerpt": excerpt,
        "text": normalize_text(f"{title} {vuln_info}"),
        "disclosed_at": attrs.get("disclosed_at"),
        "latest_disclosable_activity_at": attrs.get("latest_disclosable_activity_at"),
        "cwe": attrs.get("cwe"),
        "cve_ids": attrs.get("cve_ids") or [],
        "severity": attrs.get("severity_rating"),
        "bounty_amount": bounty,
        "bounty_currency": "USD" if bounty is not None else None,
        # Platform API is the source of the number, so it is verified.
        "bounty_verified": bounty is not None,
        "program": team_attrs.get("name"),
        "author_name": reporter_attrs.get("name"),
    }


# ---------------------------------------------------------------------------
# Poller
# ---------------------------------------------------------------------------

def poll_hackerone(
    source_id: str = "hackerone",
    session: Session | None = None,
    *,
    page_size: int = PAGE_SIZE_MAX,
    max_pages: int = MAX_PAGES_PER_RUN,
    client: httpx.Client | None = None,
) -> PollResult:
    """Poll Hacktivity newest-first, enqueue disclosed reports as jobs.

    ``session`` is optional: without one, a session is opened on the
    configured engine and committed at the end of the run.
    """
    if session is not None:
        result = _poll(session, source_id, page_size, max_pages, client)
        session.commit()
        return result
    engine = get_engine()
    with Session(engine) as owned:
        result = _poll(owned, source_id, page_size, max_pages, client)
        owned.commit()
        return result


def _poll(
    session: Session,
    source_id: str,
    page_size: int,
    max_pages: int,
    client: httpx.Client | None,
) -> PollResult:
    source = session.get(Source, source_id)
    if source is None:
        raise ValueError(f"source '{source_id}' not found; seed sources first")
    now = _now()
    cursor = _cursor(source)
    if _is_paused(cursor, now.date()):
        raise HostPausedError(
            f"{HACKERONE_HOST} paused after {MAX_429_PER_DAY} 429s today; "
            "retry tomorrow"
        )
    cursor_dt = _parse_dt(cursor.get("disclosed_at"))
    cursor_latest_dt = _parse_dt(cursor.get("latest_disclosable_activity_at"))
    http = client or _default_client()
    discovered = 0
    enqueued = 0
    newest: str | None = None
    newest_latest: str | None = None
    try:
        for page in range(1, max_pages + 1):
            response = http.get(
                HACKTIVITY_URL,
                params={
                    "sort": "-disclosed_at",
                    "page[size]": min(page_size, PAGE_SIZE_MAX),
                    "page[number]": page,
                },
            )
            if response.status_code == 403:
                source.consecutive_failures = int(source.consecutive_failures or 0) + 1
                source.last_poll_at = now
                source.cursor_state = {**cursor, "blocked": "plan_gated_403"}
                session.commit()
                raise PlanGatedError(
                    "HackerOne Hacktivity returned 403: API access is not "
                    "included in the current plan"
                )
            if response.status_code == 429:
                _record_429(session, source, cursor, now.date())
                source.consecutive_failures = int(source.consecutive_failures or 0) + 1
                source.last_poll_at = now
                session.commit()
                retry_after = response.headers.get("Retry-After")
                raise RateLimitedError(
                    "HackerOne Hacktivity returned 429; host backed off 60s "
                    f"and budget halved (Retry-After: {retry_after})"
                )
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError:
                source.consecutive_failures = int(source.consecutive_failures or 0) + 1
                source.last_poll_at = now
                session.commit()
                raise
            items = response.json().get("data") or []
            if not items:
                break
            stop = False
            for item in items:
                parsed = parse_hacktivity_item(item)
                if parsed is None:
                    continue
                disclosed_dt = _parse_dt(parsed["disclosed_at"])
                if cursor_dt is not None and disclosed_dt is not None and disclosed_dt <= cursor_dt:
                    stop = True
                    break
                discovered += 1
                key = idempotency_key_for(source_id, parsed)
                is_new = (
                    session.query(Job.id).filter_by(idempotency_key=key).first() is None
                )
                enqueue_discovery(session, source_id=source_id, event=parsed)
                if is_new:
                    enqueued += 1
                if parsed["disclosed_at"] and (
                    newest is None or _parse_dt(parsed["disclosed_at"]) > _parse_dt(newest)
                ):
                    newest = parsed["disclosed_at"]
                latest = parsed.get("latest_disclosable_activity_at")
                if latest and (
                    newest_latest is None or _parse_dt(latest) > _parse_dt(newest_latest)
                ):
                    newest_latest = latest
            if stop or len(items) < min(page_size, PAGE_SIZE_MAX):
                break
    finally:
        if client is None:
            http.close()
    new_cursor = dict(cursor)
    if newest and (cursor_dt is None or _parse_dt(newest) > cursor_dt):
        new_cursor["disclosed_at"] = newest
    if newest_latest and (
        cursor_latest_dt is None or _parse_dt(newest_latest) > cursor_latest_dt
    ):
        new_cursor["latest_disclosable_activity_at"] = newest_latest
    source.cursor_state = new_cursor
    source.last_poll_at = now
    source.last_success_at = now
    source.consecutive_failures = 0
    session.flush()
    return PollResult(
        discovered=discovered,
        enqueued=enqueued,
        last_cursor=newest or cursor.get("disclosed_at"),
    )


# ---------------------------------------------------------------------------
# Worker: discovery job -> upserted Writeup (never blind-insert)
# ---------------------------------------------------------------------------

def handle_discovery_job(session: Session, job: Job) -> str:
    """Process one discovery job; returns ``"created"`` or ``"merged"``."""
    payload: dict[str, Any] = dict(job.payload or {})
    canonical_url = payload["canonical_url"]
    text = payload.get("text") or f"{payload.get('title', '')} {payload.get('excerpt', '')}"
    candidate = {
        "canonical_url": canonical_url,
        "external_id": payload.get("external_id"),
        "title": payload.get("title"),
        "author_name": payload.get("author_name"),
        "disclosed_at": payload.get("disclosed_at"),
        "content_hash": content_hash(text),
        "simhash": simhash64(text),
    }
    existing = _find_existing(session, candidate)
    decision = "new"
    matched: Writeup | None = None
    for row in existing:
        d = dedup_decision(row, candidate)
        if _DECISION_RANK[d] < _DECISION_RANK[decision]:
            decision, matched = d, row
    now = _now()
    if matched is not None and decision in _MERGE_DECISIONS:
        matched.last_seen_at = now
        _add_source_url(session, matched.id, job.source_id, canonical_url)
        session.add(WriteupEvent(
            writeup_id=matched.id, event="updated", actor="hackerone-poller",
            detail={"dedup": decision, "merged_source_url": canonical_url},
        ))
        session.flush()
        return "merged"
    disclosed_at = _parse_dt(payload.get("disclosed_at"))
    writeup = Writeup(
        canonical_url=canonical_url,
        url_hash=url_hash(canonical_url),
        external_id=payload.get("external_id"),
        title=payload.get("title") or "",
        excerpt=(payload.get("excerpt") or "")[:300],
        author_name=payload.get("author_name"),
        source_id=job.source_id,
        source_type="hackerone_report",
        published_at=disclosed_at,
        disclosed_at=disclosed_at,
        fetched_at=now,
        last_seen_at=now,
        content_hash=candidate["content_hash"],
        simhash=simhash_to_db(candidate["simhash"]),
        # Hacktivity reports are English; language detection is the
        # Task 13 quality gate, not the poller.
        language="en",
        status="active",
    )
    session.add(writeup)
    session.flush()
    _add_source_url(session, writeup.id, job.source_id, canonical_url)
    severity = payload.get("severity")
    cve_ids = payload.get("cve_ids") or []
    if payload.get("cwe") or cve_ids or severity or payload.get("bounty_amount") is not None:
        program = payload.get("program")
        session.add(WriteupVuln(
            writeup_id=writeup.id,
            vuln_class=None,  # Task 6 classification assigns this
            cwe_id=payload.get("cwe"),
            cve_id=cve_ids[0] if cve_ids else None,
            severity=severity if severity in _SEVERITIES else None,
            severity_source="hackerone" if severity in _SEVERITIES else None,
            bounty_amount=payload.get("bounty_amount"),
            bounty_currency=payload.get("bounty_currency"),
            bounty_verified=bool(payload.get("bounty_verified")),
            verified_against="hackerone" if payload.get("bounty_verified") else None,
            program=program,
            program_slug=_slugify(program) if program else None,
        ))
    detail: dict[str, Any] = {"dedup": decision, "source": "hackerone"}
    if matched is not None and decision in ("near_dup_review", "title_candidate"):
        detail["candidate_of"] = matched.api_id
    session.add(WriteupEvent(
        writeup_id=writeup.id, event="created", actor="hackerone-poller",
        detail=detail,
    ))
    session.flush()
    return "created"


def _find_existing(session: Session, candidate: dict) -> list[Writeup]:
    """Rows matching the candidate on any of dedup layers 1–3."""
    clauses = [Writeup.url_hash == url_hash(candidate["canonical_url"])]
    if candidate.get("external_id"):
        clauses.append(Writeup.external_id == candidate["external_id"])
    if candidate.get("content_hash"):
        clauses.append(Writeup.content_hash == candidate["content_hash"])
    return session.query(Writeup).filter(or_(*clauses)).all()


def _add_source_url(
    session: Session, writeup_id: Any, source_id: str | None, source_url: str
) -> None:
    exists = (
        session.query(WriteupSource.id)
        .filter_by(writeup_id=writeup_id, source_url=source_url)
        .first()
    )
    if exists is None:
        session.add(WriteupSource(
            writeup_id=writeup_id, source_id=source_id, source_url=source_url
        ))
        session.flush()
