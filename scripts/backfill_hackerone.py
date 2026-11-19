#!/usr/bin/env python3
"""T7: backfill the HackerOne corpus to N active writeups (default 500).

The 15-minute poller only walks forward from the cursor, so the corpus
stalls at whatever the newest pages hold (~50 rows). This script pages
BACK through older disclosed Hacktivity reports, newest-first, and
processes each one through the same pipeline as the poller
(classify -> quality gate -> NVD enrich -> embed), committing per
page. It also reclassifies rows ingested under the old taxonomy
first, so the unclassified rate reflects the current classifier.

Usage (from the repo root, with the venv):

    .venv/bin/python scripts/backfill_hackerone.py [--target 500]
        [--max-pages 100] [--dry-run]

``--dry-run`` fetches pages and reports what WOULD be ingested
(discovered / already-ingested / skipped) without writing anything.
No new sources, no new scope: HackerOne Hacktivity only, same as the
poller. The corpus this builds is NOT Java/Spring-only — measured
19 Nov 2026, 0 of the 100 newest disclosed reports mention
Java/Spring, and the existing 50-row corpus already spans WordPress,
curl, MariaDB, Qt, ... — so a Java-only 500 was never achievable
from this source, and this script continues the ingestion policy
production already runs instead of silently narrowing it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sqlalchemy import or_  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from eunoia.classify import reclassify_unclassified  # noqa: E402
from eunoia.config import get_settings  # noqa: E402
from eunoia.db import get_engine  # noqa: E402
from eunoia.embed import get_model  # noqa: E402
from eunoia.ingestion.hackerone import (  # noqa: E402
    HACKTIVITY_URL,
    apply_cached_nvd,
    backfill_hackerone,
    count_active_writeups,
    count_unclassified_writeups,
    parse_hacktivity_item,
)
from eunoia.ingestion.jobs import idempotency_key_for  # noqa: E402
from eunoia.ingestion.nvd import TokenBucket, default_http_client  # noqa: E402
from eunoia.models import Job  # noqa: E402
from eunoia.worker import run_poll_cycle  # noqa: E402


def _dry_run(session: Session, target: int, max_pages: int) -> dict:
    """Fetch pages read-only and count what backfill would do."""
    from eunoia.ingestion.hackerone import _default_client

    http = _default_client()
    would_create = would_merge = skipped = 0
    pages = 0
    try:
        for page in range(1, max_pages + 1):
            if count_active_writeups(session) + would_create >= target:
                break
            resp = http.get(
                HACKTIVITY_URL,
                params={"sort": "-disclosed_at",
                        "page[size]": 100, "page[number]": page},
            )
            resp.raise_for_status()
            items = resp.json().get("data") or []
            if not items:
                break
            pages += 1
            for item in items:
                parsed = parse_hacktivity_item(item)
                if parsed is None:
                    skipped += 1
                    continue
                key = idempotency_key_for("hackerone", parsed)
                exists = session.query(Job.id).filter_by(
                    idempotency_key=key).first() is not None
                if exists:
                    would_merge += 1
                else:
                    would_create += 1
    finally:
        http.close()
    return {
        "pages_fetched": pages,
        "would_create": would_create,
        "would_merge": would_merge,
        "skipped": skipped,
        "active_now": count_active_writeups(session),
        "unclassified_now": count_unclassified_writeups(session),
    }


def _pending_refresh_jobs(session: Session) -> int:
    return session.query(Job).filter_by(
        kind="nvd_refresh", status="pending").count()


def _due_refresh_jobs(session: Session) -> int:
    """Pending refresh jobs whose next attempt is due now. A failed
    refresh backs off (1 min, then ~1 h), so 'pending' alone never
    drains to zero — the loop must stop when nothing is due."""
    from datetime import datetime, timezone

    # Mirror the claim condition in jobs.py: a NULL next attempt
    # means "due now" (never attempted). A plain "<= now" would
    # silently skip every fresh refresh job — the box backfill
    # queued 89 of them and the drain then reported "0 due".
    return session.query(Job).filter(
        Job.kind == "nvd_refresh",
        Job.status == "pending",
        or_(
            Job.next_attempt_at.is_(None),
            Job.next_attempt_at <= datetime.now(timezone.utc),
        ),
    ).count()


def _drain_refresh_jobs(session: Session, client, limiter,
                        max_passes: int = 12) -> int:
    """Drain pending ``nvd_refresh`` jobs in paced passes (T7).

    NVD without an API key allows 5 requests / 30 s, and a failed
    refresh backs off 1 minute before it is due again — so one pass
    can only resolve a handful. Passes are 65 s apart (bucket refill
    + back-off) and stop early when no refresh job is pending. The
    poll function is a no-op: this drains only, it never polls
    HackerOne. Returns the number of passes run.
    """
    import time

    for attempt in range(1, max_passes + 1):
        pending = _pending_refresh_jobs(session)
        due = _due_refresh_jobs(session)
        print(f"nvd_refresh drain pass {attempt}/{max_passes}: "
              f"{pending} pending, {due} due", flush=True)
        if due == 0:
            return attempt - 1
        run_poll_cycle(session, poll_fn=lambda s: None,
                       client=client, limiter=limiter)
        if _due_refresh_jobs(session) == 0:
            return attempt
        if attempt < max_passes:
            time.sleep(65)
    return max_passes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=int, default=500,
                        help="active writeups to reach (default 500)")
    parser.add_argument("--max-pages", type=int, default=100,
                        help="max Hacktivity pages to walk (default 100)")
    parser.add_argument("--dry-run", action="store_true",
                        help="fetch pages and report only; write nothing")
    parser.add_argument("--skip-nvd", action="store_true",
                        help="skip the nvd_refresh drain + re-apply step")
    args = parser.parse_args(argv)

    engine = get_engine(get_settings())
    with Session(engine) as session:
        if args.dry_run:
            print(json.dumps(_dry_run(session, args.target,
                                      args.max_pages), indent=2))
            return 0
        checked, changed = reclassify_unclassified(session)
        session.commit()
        print(f"reclassified existing rows: checked {checked} "
              f"writeups, upgraded {changed}")
        model = get_model()
        client = default_http_client()
        limiter = TokenBucket(capacity=5, per_seconds=30)
        try:
            result = backfill_hackerone(
                session, target_active=args.target,
                max_pages=args.max_pages, model=model, client=client,
                limiter=limiter)
        finally:
            client.close()
        print(json.dumps({
            "pages_fetched": result.pages_fetched,
            "discovered": result.discovered,
            "created": result.created,
            "merged": result.merged,
            "skipped": result.skipped,
            "failed": result.failed,
            "active_total": result.active_total,
            "unclassified": result.unclassified,
            "unclassified_pct": round(
                100.0 * result.unclassified / result.active_total, 2
            ) if result.active_total else 0.0,
            "stopped_reason": result.stopped_reason,
        }, indent=2))
        if args.skip_nvd:
            return 0
        # NVD lags brand-new CVEs by days: the ingest-time enrich
        # degraded and queued refresh jobs. Drain them (paced), then
        # re-apply the late NVD records to rows that still lack
        # CVSS / severity / class.
        nvd_client = default_http_client()
        nvd_limiter = TokenBucket(capacity=5, per_seconds=30)
        try:
            passes = _drain_refresh_jobs(
                session, nvd_client, nvd_limiter)
            checked, updated = apply_cached_nvd(
                session, client=nvd_client, limiter=nvd_limiter)
            session.commit()
        finally:
            nvd_client.close()
        print(json.dumps({
            "nvd_drain_passes": passes,
            "nvd_reapplied_writeups": checked,
            "nvd_reapplied": updated,
            "active_total": count_active_writeups(session),
            "unclassified": count_unclassified_writeups(session),
            "unclassified_pct": round(
                100.0 * count_unclassified_writeups(session)
                / max(1, count_active_writeups(session)), 2),
        }, indent=2))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
