"""Golden set + recall@10 / latency measurement (Task 15, spec §8).

The golden set lives in ``docs/golden/``:

* ``corpus.json`` — 26 writeups (24 servable + 1 retracted + 1
  non-English) with deterministic UUIDv7 ids, so the same ``w_...``
  api ids exist in the dev DB and the test DB. The corpus is synthetic
  fixtures modelled on real Java/Spring writeups + CVEs (Log4Shell,
  Spring4Shell, Ghostcat); it is a benchmark corpus, not ingested
  disclosures.
* ``queries.json`` — 50 queries (39 pre-test, 11 mid-test), each with
  ``expected_writeup_ids`` naming real corpus rows.
* ``expected.json`` — the ``query_id -> expected ids`` mapping, kept
  in agreement with ``queries.json`` (tested).

No invented pass threshold: :func:`measure_recall` reports the
measured recall@10 and latencies as-is. The pass bar is decided after
the first measurement (spec §8).

The 0.7 stack-match band (Task 9 deferred minor): the ranking
implements ``_stack_match`` as 0.7 whenever the query carries no
version ("same product, version not exactly known") — NOT the spec's
range-based reading ("same product, version in affected range"),
because MVP has no OSV data to establish affected ranges. The golden
set validates the implemented reading (see
``tests/test_golden.py::test_stack_match_07_band_reading``); the
range-based reading is untestable in MVP and is recorded in the
report notes, not silently assumed.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.dedup import url_hash
from eunoia.embed import embed_writeup
from eunoia.models import CveCache, Writeup, WriteupVuln
from eunoia.search import search

__all__ = [
    "GOLDEN_DIR",
    "PerQueryResult",
    "Report",
    "load_corpus",
    "load_expected",
    "load_queries",
    "load_real_queries",
    "measure_recall",
    "measure_real_recall",
    "print_report",
    "report_to_dict",
    "seed_golden_corpus",
    "validate_real_queries",
]

GOLDEN_DIR = Path(__file__).resolve().parents[2] / "docs" / "golden"

STACK_MATCH_NOTE = (
    "stack_match 0.7 band: implemented reading is 0.7 whenever the "
    "query carries no version (no OSV affected-range data in MVP); "
    "the spec's range-based reading is NOT validated by this set."
)
NO_THRESHOLD_NOTE = (
    "No invented pass threshold: recall@10 and latencies are reported "
    "as measured; the pass bar is decided after the first measurement."
)


@dataclass
class PerQueryResult:
    """One golden query's measured outcome."""

    query_id: str
    mode: str
    recall: float
    latency_ms: float
    expected_ids: list
    returned_ids: list
    found_ids: list
    missing_ids: list


@dataclass
class Report:
    """Measured recall@10 + latency (spec §8)."""

    recall_at_10: float
    p50_ms: float
    p95_ms: float
    per_query: list = field(default_factory=list)
    pre_test: dict = field(default_factory=dict)
    mid_test: dict = field(default_factory=dict)
    measured_at: str = ""
    corpus_size: int = 0
    notes: list = field(default_factory=list)


def load_corpus() -> dict:
    return json.loads((GOLDEN_DIR / "corpus.json").read_text())


def load_queries() -> list[dict]:
    return json.loads((GOLDEN_DIR / "queries.json").read_text())


def load_real_queries(path: Path | str | None = None) -> list[dict]:
    """Load the real-corpus queries (``docs/golden/real-queries-500.json``).

    The file is data built from the live corpus, not a fixture: every
    expected id must exist, be active, and be servable — checked by
    :func:`validate_real_queries` before any measurement is trusted.
    """
    target = Path(path) if path is not None else (
        GOLDEN_DIR / "real-queries-500.json")
    return json.loads(target.read_text())


def validate_real_queries(
    queries: list[dict], session: Session
) -> list[str]:
    """Check every expected id in ``queries`` against the DB.

    Returns a list of error strings (empty = valid): an expected id
    must exist, be ``active``, and be servable — servable means the
    same thing the serving gate means (``quality_passed is not
    False``; a NULL value is servable, a False value is quarantined).
    A measurement built on a missing or quarantined id would report
    a recall the corpus cannot deliver, so validation runs before
    measuring, never after.
    """
    errors: list[str] = []
    for q in queries:
        for wid in q.get("expected_writeup_ids") or []:
            try:
                row_id = uuid.UUID(wid.removeprefix("w_"))
            except (ValueError, AttributeError):
                errors.append(f"{q.get('id')}: bad writeup id {wid!r}")
                continue
            row = session.get(Writeup, row_id)
            if row is None:
                errors.append(f"{q.get('id')}: missing writeup {wid}")
            elif row.status != "active" or row.quality_passed is False:
                errors.append(
                    f"{q.get('id')}: writeup {wid} is not servable "
                    f"(status={row.status}, "
                    f"quality_passed={row.quality_passed})")
    return errors


def load_expected() -> dict[str, list[str]]:
    return json.loads((GOLDEN_DIR / "expected.json").read_text())


def seed_golden_corpus(session: Session, model=None) -> dict:
    """Seed the golden corpus into ``session``; idempotent, flush-only.

    A row whose id already exists is UPSERTED: changed fields are
    updated (final review triage, Task 15 — the old code skipped
    existing ids without updating, so editing ``corpus.json`` after
    a first seed silently left stale rows). Embeddings are written
    for servable rows only (active + English); ``embed_writeup``
    skips when the template hash is unchanged, so re-seeding is
    cheap. The caller owns the transaction (commit/rollback).
    """
    corpus = load_corpus()
    now = datetime.now(timezone.utc)
    seeded = 0
    updated = 0
    embedded = 0
    for row in corpus["writeups"]:
        wid = uuid.UUID(row["id"])
        published = now - timedelta(days=row["days_ago"])
        existing = session.get(Writeup, wid)
        if existing is None:
            w = Writeup(
                id=wid,
                canonical_url=row["canonical_url"],
                url_hash=url_hash(row["canonical_url"]),
                title=row["title"],
                excerpt=row["excerpt"],
                language=row["language"],
                status=row["status"],
                published_at=published,
                disclosed_at=published,
                fetched_at=now,
                last_seen_at=now,
            )
            session.add(w)
            session.flush()
            session.add(WriteupVuln(
                writeup_id=wid,
                vuln_class=row["vuln_class"],
                cwe_id=row["cwe_id"],
                cve_id=row["cve_id"],
                cvss_score=row["cvss_score"],
                severity=row["severity"],
                severity_source=row["severity_source"],
                bounty_verified=row["bounty_verified"],
                bounty_amount=row["bounty_amount"],
                bounty_currency=row["bounty_currency"],
                program=row["program"],
            ))
            session.flush()
            seeded += 1
        else:
            existing.canonical_url = row["canonical_url"]
            existing.url_hash = url_hash(row["canonical_url"])
            existing.title = row["title"]
            existing.excerpt = row["excerpt"]
            existing.language = row["language"]
            existing.status = row["status"]
            existing.published_at = published
            existing.disclosed_at = published
            existing.last_seen_at = now
            vuln = session.query(WriteupVuln).filter_by(
                writeup_id=wid).first()
            if vuln is None:
                session.add(WriteupVuln(
                    writeup_id=wid,
                    vuln_class=row["vuln_class"],
                    cwe_id=row["cwe_id"],
                    cve_id=row["cve_id"],
                    cvss_score=row["cvss_score"],
                    severity=row["severity"],
                    severity_source=row["severity_source"],
                    bounty_verified=row["bounty_verified"],
                    bounty_amount=row["bounty_amount"],
                    bounty_currency=row["bounty_currency"],
                    program=row["program"],
                ))
            else:
                vuln.vuln_class = row["vuln_class"]
                vuln.cwe_id = row["cwe_id"]
                vuln.cve_id = row["cve_id"]
                vuln.cvss_score = row["cvss_score"]
                vuln.severity = row["severity"]
                vuln.severity_source = row["severity_source"]
                vuln.bounty_verified = row["bounty_verified"]
                vuln.bounty_amount = row["bounty_amount"]
                vuln.bounty_currency = row["bounty_currency"]
                vuln.program = row["program"]
            session.flush()
            updated += 1
        if row["status"] == "active" and row["language"] == "en":
            embed_writeup(wid, session=session, model=model)
            embedded += 1
    for kev in corpus["kev_cache"]:
        if session.get(CveCache, kev["cve_id"]) is not None:
            continue
        session.add(CveCache(
            cve_id=kev["cve_id"],
            kev=kev["kev"],
            epss=kev["epss"],
            epss_percentile=0.99,
            cvss_score=kev["cvss_score"],
            cwe_ids=kev.get("cwe_ids") or None,
            fetched_at=now,
            expires_at=now + timedelta(days=1),
        ))
        session.flush()
    return {"seeded": seeded, "updated": updated, "embedded": embedded,
            "total_writeups": len(corpus["writeups"])}


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = pct / 100.0 * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return ordered[low] * (1.0 - frac) + ordered[high] * frac


def _mode_summary(rows: list[PerQueryResult]) -> dict:
    if not rows:
        return {"recall_at_10": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "n": 0}
    latencies = [r.latency_ms for r in rows]
    return {
        "recall_at_10": sum(r.recall for r in rows) / len(rows),
        "p50_ms": round(_percentile(latencies, 50), 2),
        "p95_ms": round(_percentile(latencies, 95), 2),
        "n": len(rows),
    }


def _run_queries(
    session: Session, model, qs: list[dict], limit: int
) -> list[PerQueryResult]:
    """Run one query set through :func:`eunoia.search.search` once per
    query (warm-up first, untimed) and score recall@``limit``."""
    per_query: list[PerQueryResult] = []
    if qs:
        search(qs[0], limit=limit, session=session, model=model)
    for q in qs:
        expected = list(q.get("expected_writeup_ids") or [])
        t0 = time.perf_counter()
        results = search(q, limit=limit, session=session, model=model)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        returned = [r.writeup_id for r in results]
        found = [wid for wid in expected if wid in returned]
        missing = [wid for wid in expected if wid not in returned]
        recall = len(found) / len(expected) if expected else 1.0
        per_query.append(PerQueryResult(
            query_id=q["id"],
            mode=str(q.get("mode") or "pre_test"),
            recall=round(recall, 4),
            latency_ms=round(latency_ms, 2),
            expected_ids=expected,
            returned_ids=returned,
            found_ids=found,
            missing_ids=missing,
        ))
    return per_query


def _summarize(per_query: list[PerQueryResult], corpus_size: int) -> Report:
    latencies = [r.latency_ms for r in per_query]
    return Report(
        recall_at_10=round(
            sum(r.recall for r in per_query) / len(per_query), 4
        ) if per_query else 0.0,
        p50_ms=round(_percentile(latencies, 50), 2),
        p95_ms=round(_percentile(latencies, 95), 2),
        per_query=per_query,
        pre_test=_mode_summary(
            [r for r in per_query if r.mode == "pre_test"]),
        mid_test=_mode_summary(
            [r for r in per_query if r.mode == "mid_test"]),
        measured_at=datetime.now(timezone.utc).isoformat(),
        corpus_size=corpus_size,
        notes=[STACK_MATCH_NOTE, NO_THRESHOLD_NOTE],
    )


def measure_recall(
    session: Session | None = None,
    model=None,
    limit: int = 10,
    queries: list[dict] | None = None,
) -> Report:
    """Run the golden set through :func:`eunoia.search.search` once per
    query and report recall@10 + latency as measured.

    A warm-up search runs before timing so model load / first-query
    costs are not charged to any query. ``limit`` is the recall depth
    (10 by definition of recall@10).
    """
    own_session = session is None
    if own_session:
        session = Session(get_engine(get_settings()))
    assert session is not None
    try:
        qs = queries if queries is not None else load_queries()
        per_query = _run_queries(session, model, qs, limit)
        # Final review triage, Task 15: count only rows that are
        # actually in corpus.json — the old count included every
        # active writeup in the DB (e.g. rows seeded by other tests).
        corpus_ids = [uuid.UUID(w["id"]) for w in load_corpus()["writeups"]]
        corpus_size = session.execute(
            select(func.count()).select_from(Writeup).where(
                Writeup.id.in_(corpus_ids),
                Writeup.status == "active")
        ).scalar_one()
        return _summarize(per_query, corpus_size)
    finally:
        if own_session:
            session.close()


def measure_real_recall(
    session: Session | None = None,
    model=None,
    limit: int = 10,
    queries: list[dict] | None = None,
) -> Report:
    """Measure recall@10 on the REAL corpus (T7, same method as the
    19 Nov 2026 measurement).

    Same engine as :func:`measure_recall` — one ``search()`` call per
    query, recall@``limit``, latencies timed, split pre-test /
    mid-test — but the queries are the real-corpus set (default
    ``docs/golden/real-queries-500.json``) and ``corpus_size`` is the
    count of active writeups actually in this DB, not the synthetic
    fixture. Read-only: no seeding, no writes. Callers validate the
    queries first with :func:`validate_real_queries`.
    """
    own_session = session is None
    if own_session:
        session = Session(get_engine(get_settings()))
    assert session is not None
    try:
        qs = queries if queries is not None else load_real_queries()
        per_query = _run_queries(session, model, qs, limit)
        corpus_size = session.execute(
            select(func.count()).select_from(Writeup).where(
                Writeup.status == "active")
        ).scalar_one()
        return _summarize(per_query, corpus_size)
    finally:
        if own_session:
            session.close()


def report_to_dict(report: Report) -> dict:
    return {
        "recall_at_10": report.recall_at_10,
        "p50_ms": report.p50_ms,
        "p95_ms": report.p95_ms,
        "measured_at": report.measured_at,
        "corpus_size": report.corpus_size,
        "pre_test": report.pre_test,
        "mid_test": report.mid_test,
        "notes": report.notes,
        "per_query": [
            {
                "query_id": r.query_id,
                "mode": r.mode,
                "recall": r.recall,
                "latency_ms": r.latency_ms,
                "expected": len(r.expected_ids),
                "found": len(r.found_ids),
                "missing_ids": r.missing_ids,
            }
            for r in report.per_query
        ],
    }


def print_report(report: Report) -> None:
    """Print the report as-is (measured values, no pass/fail claim)."""
    print(f"golden set: {len(report.per_query)} queries "
          f"({report.pre_test.get('n', 0)} pre-test, "
          f"{report.mid_test.get('n', 0)} mid-test), "
          f"corpus: {report.corpus_size} active writeups")
    print(f"recall@10: {report.recall_at_10:.4f}")
    print(f"latency (all): p50 {report.p50_ms:.2f} ms, "
          f"p95 {report.p95_ms:.2f} ms")
    for mode in ("pre_test", "mid_test"):
        summary = getattr(report, mode)
        print(f"latency ({mode}): recall@10 {summary['recall_at_10']:.4f}, "
              f"p50 {summary['p50_ms']:.2f} ms, "
              f"p95 {summary['p95_ms']:.2f} ms "
              f"(target: {'<5000' if mode == 'pre_test' else '<3000'} ms)")
    missed = [r for r in report.per_query if r.missing_ids]
    print(f"queries with misses: {len(missed)}")
    for row in missed:
        print(f"  {row.query_id} ({row.mode}): recall {row.recall:.2f}, "
              f"missing {row.missing_ids}")
    for note in report.notes:
        print(f"note: {note}")
