"""Deployment worker loop (Task 16, spec §5.3/§5.7).

The runbook schedules (15-minute poll loop, daily KEV sync) as a real
mechanism, not prose: :func:`run_poll_cycle` polls HackerOne once and
drains due jobs; :func:`run_kev_sync_once` syncs the CISA KEV catalog
once. ``scripts/worker.py`` is the thin CLI entry point;
``deploy/supervisord-eunoia.conf`` runs ``poll-loop`` under
supervisord and ``kev-sync`` from cron.

Per-kind handler kwargs: ``dispatch_job`` filters kwargs to what each
handler accepts (see ``jobs._HANDLER_KWARGS``), so the drain passes
the URL checker / encoder only to discovery jobs, and only the NVD
client/limiter to refresh jobs — a mis-routed kwarg can no longer
dead-letter a job after 5 retries.

Transaction control belongs to the worker: each cycle/sync commits
its session at the end. The poller needs no auth (Task 1 decision:
Hacktivity REST works without a token, ``no_auth_ok``).
"""

from __future__ import annotations

import argparse
import logging
import time
from functools import partial
from typing import Callable

from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.ingestion.hackerone import poll_hackerone
from eunoia.ingestion.jobs import claim_next_job, dispatch_job, process_job
from eunoia.ingestion.kev import sync_kev
from eunoia.ingestion.nvd import TokenBucket, default_http_client

__all__ = ["run_kev_sync_once", "run_poll_cycle", "main"]

logger = logging.getLogger(__name__)

_POLL_INTERVAL_MINUTES = 15
_NVD_BUCKET_CAPACITY = 5  # NVD without an API key: 5 requests / 30 s.
_NVD_BUCKET_SECONDS = 30


def _dispatch_for_worker(session: Session, job, *, model=None,
                         url_checker=None, client=None, limiter=None):
    """Route one claimed job with per-kind kwargs (see module docstring)."""
    if job.kind in ("hackerone_discovery", "discovery"):
        return dispatch_job(
            session, job, model=model, client=client, limiter=limiter,
            url_checker=url_checker)
    if job.kind == "nvd_refresh":
        return dispatch_job(session, job, client=client, limiter=limiter)
    return dispatch_job(session, job)


def run_poll_cycle(session: Session, *, poll_fn: Callable | None = None,
                   model=None, url_checker=None, client=None,
                   limiter=None) -> dict:
    """One cycle: poll HackerOne once, then drain every due job.

    ``poll_fn`` defaults to :func:`poll_hackerone` (no auth needed).
    ``url_checker`` defaults to the production HEAD/GET check inside
    :func:`handle_discovery_job` — tests must inject a stub, or the
    worker would do live HTTP. ``model`` defaults to the cached
    production encoder. Returns ``{"processed": n, "failed": m}``; a
    job that raises is counted as failed (``process_job`` already
    applied back-off / dead-letter) and the drain continues with the
    next job instead of stopping.
    """
    poller = poll_fn or (lambda s: poll_hackerone(session=s))
    try:
        poller(session)
    except Exception:
        # Final review C2: a failed poll must never kill the cycle.
        # Log it and still drain due jobs; the next cycle retries the
        # poll. (A poll failure is transient by nature — 403/429/
        # HostPausedError/network — and the drain is independent work.)
        logger.exception("HackerOne poll failed; draining due jobs anyway")
    processed = failed = 0
    handler = partial(
        _dispatch_for_worker, model=model, url_checker=url_checker,
        client=client, limiter=limiter)
    while True:
        job = claim_next_job(session)
        if job is None:
            break
        try:
            process_job(session, job.id, handler)
            processed += 1
        except Exception:
            failed += 1
    session.commit()
    return {"processed": processed, "failed": failed}


def run_kev_sync_once(session: Session, *,
                      sync_fn: Callable | None = None) -> dict:
    """One KEV sync. ``sync_fn`` defaults to :func:`sync_kev`."""
    sync = sync_fn or (lambda s: sync_kev(s))
    result = sync(session)
    session.commit()
    return dict(result)


def _open_session() -> Session:
    return Session(get_engine(get_settings()))


def main(argv: list[str] | None = None) -> None:
    """CLI: ``worker.py poll-loop | kev-sync | drain-once``."""
    parser = argparse.ArgumentParser(
        prog="eunoia-worker",
        description="Eunoia deployment worker: poll loop + KEV sync.")
    sub = parser.add_subparsers(dest="command", required=True)
    poll_loop = sub.add_parser(
        "poll-loop", help="Poll every N minutes, forever.")
    poll_loop.add_argument("--interval-minutes", type=int,
                           default=_POLL_INTERVAL_MINUTES)
    poll_loop.add_argument("--once", action="store_true",
                           help="Run one cycle and exit (for cron).")
    sub.add_parser("kev-sync", help="Sync the CISA KEV catalog once.")
    sub.add_parser("drain-once", help="Drain due jobs once, without polling.")
    args = parser.parse_args(argv)

    if args.command == "kev-sync":
        with _open_session() as session:
            print(run_kev_sync_once(session))
        return

    client = default_http_client()
    limiter = TokenBucket(capacity=_NVD_BUCKET_CAPACITY,
                          per_seconds=_NVD_BUCKET_SECONDS)
    try:
        if args.command == "drain-once":
            with _open_session() as session:
                print(run_poll_cycle(
                    session, poll_fn=lambda s: {"enqueued": 0},
                    client=client, limiter=limiter))
            return
        # poll-loop
        while True:
            try:
                with _open_session() as session:
                    result = run_poll_cycle(
                        session, client=client, limiter=limiter)
                print(result, flush=True)
            except Exception:
                # Final review C2: a failed cycle (poll, drain, or
                # commit) must never crash the loop — log it, sleep,
                # and try the next cycle. Under supervisord this is
                # what keeps the poller alive for the 7-day DoD 1 run
                # instead of hot-looping into startretries exhaustion.
                logger.exception("poll cycle failed; continuing loop")
            if args.once:
                return
            time.sleep(args.interval_minutes * 60)
    finally:
        client.close()


if __name__ == "__main__":
    main()
