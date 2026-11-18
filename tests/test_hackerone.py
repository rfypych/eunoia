"""Task 5: HackerOne poller + jobs queue (spec §5.3, §5.6).

HTTP is mocked with respx — tests never hit the live HackerOne API.
DB tests run against the dedicated ``eunoia_test`` database (same
fixture pattern as tests/test_models.py).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
import respx
from httpx import Client, Response
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.dedup import url_hash
from eunoia.ingestion.hackerone import (
    HACKTIVITY_URL,
    HostPausedError,
    PlanGatedError,
    PollResult,
    RateLimitedError,
    handle_discovery_job,
    parse_hacktivity_item,
    poll_hackerone,
)
from eunoia.ingestion.jobs import (
    backoff_for_attempt,
    claim_next_job,
    enqueue_discovery,
    mark_job_done,
    mark_job_failed,
    process_job,
)
from eunoia.models import Base, Job, Source, SourceHost, Writeup, WriteupSource

TEST_DATABASE_URL = "postgresql+psycopg://eunoia@localhost:5432/eunoia_test"


@pytest.fixture()
def session():
    engine = get_engine(get_settings(DATABASE_URL=TEST_DATABASE_URL))
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError:
        pytest.fail(
            "Test database 'eunoia_test' is missing or unreachable. "
            "Create it with: bash scripts/setup_test_db.sh"
        )
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
        s.rollback()
    Base.metadata.drop_all(engine)


@pytest.fixture()
def http_client():
    # trust_env=False: this VM's NO_PROXY contains bracketed IPv6 entries
    # ([::1]) that httpx's env-proxy parser crashes on at Client
    # construction; respx intercepts the transport either way.
    client = Client(trust_env=False)
    yield client
    client.close()


@pytest.fixture()
def hackerone_source(session):
    session.add(Source(
        id="hackerone", name="HackerOne Hacktivity", type="api",
        base_url="https://api.hackerone.com",
        feed_url=HACKTIVITY_URL, poll_interval_s=900,
        rate_limit_per_min=600, auth_ref=None, cursor_state={},
    ))
    session.commit()
    return session.query(Source).filter_by(id="hackerone").one()


def _item(id, title, disclosed=True, disclosed_at="2026-11-18T10:00:00.000Z",
          url=None, severity="critical", cwe="CWE-918", cve_ids=None,
          awarded=5000, vuln_info="SSRF via PDF parser"):
    return {
        "id": id,
        "type": "hacktivity_item",
        "attributes": {
            "title": title if disclosed else None,
            "substate": None,
            "url": url if url is not None else f"https://hackerone.com/reports/{id}",
            "disclosed_at": disclosed_at if disclosed else None,
            "vulnerability_information": vuln_info,
            "cve_ids": cve_ids,
            "cwe": cwe,
            "severity_rating": severity,
            "votes": 0,
            "total_awarded_amount": awarded,
            "latest_disclosable_activity_at": disclosed_at,
            "submitted_at": "2026-10-24T20:43:34.293Z",
            "disclosed": disclosed,
        },
        "relationships": {
            "reporter": {"data": {"type": "user", "attributes": {"name": "r"}}},
            "team": {"data": {"type": "team", "attributes": {"name": "Example"}}},
        },
    }


def _page(items, total=3):
    return {"data": items, "meta": {"total": total}}


# ---------------------------------------------------------------------------
# Poller (brief Step 1, verbatim)
# ---------------------------------------------------------------------------

def test_poller_enqueues_once_per_report(session, hackerone_source, http_client):
    items = [
        _item(111, "SSRF via PDF parser", disclosed_at="2026-11-18T10:00:00.000Z"),
        _item(222, "IDOR on profile API", disclosed_at="2026-11-18T09:00:00.000Z"),
        _item(333, None, disclosed=False),  # undisclosed: must be skipped
    ]
    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(return_value=Response(200, json=_page(items)))
        result = poll_hackerone("hackerone", session=session, client=http_client)
    assert isinstance(result, PollResult)
    assert result.discovered == 2
    assert result.enqueued == 2
    assert result.last_cursor == "2026-11-18T10:00:00.000Z"
    assert session.query(Job).count() == 2

    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(return_value=Response(200, json=_page(items)))
        assert poll_hackerone("hackerone", session=session, client=http_client).enqueued == 0


def test_poller_sorts_by_disclosed_at_and_uses_page_size_max_100(session, hackerone_source, http_client):
    with respx.mock as router:
        route = router.get(HACKTIVITY_URL).mock(
            return_value=Response(200, json=_page([])))
        poll_hackerone("hackerone", session=session, client=http_client)
    request = route.calls[0].request
    assert request.url.params["sort"] == "-disclosed_at"
    assert int(request.url.params["page[size]"]) <= 100


def test_403_plan_gated_surfaces_blocked(session, hackerone_source, http_client):
    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(return_value=Response(403, json={"error": "forbidden"}))
        with pytest.raises(PlanGatedError):
            poll_hackerone("hackerone", session=session, client=http_client)
    source = session.query(Source).filter_by(id="hackerone").one()
    assert source.consecutive_failures == 1
    assert source.cursor_state.get("blocked") == "plan_gated_403"


def test_429_backs_off_host_and_halves_budget(session, hackerone_source, http_client):
    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(return_value=Response(429, json={}))
        with pytest.raises(RateLimitedError):
            poll_hackerone("hackerone", session=session, client=http_client)
    host = session.query(SourceHost).filter_by(host="api.hackerone.com").one()
    assert host.last_429 is not None
    source = session.query(Source).filter_by(id="hackerone").one()
    assert source.rate_limit_per_min == 300  # 600 halved once


def test_three_429s_in_a_day_pause_host_until_tomorrow(session, hackerone_source, http_client):
    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(return_value=Response(429, json={}))
        for _ in range(3):
            with pytest.raises(RateLimitedError):
                poll_hackerone("hackerone", session=session, client=http_client)
    # Fourth poll must not touch the API at all.
    with respx.mock as router:
        route = router.get(HACKTIVITY_URL).mock(return_value=Response(200, json=_page([])))
        with pytest.raises(HostPausedError):
            poll_hackerone("hackerone", session=session, client=http_client)
        assert len(route.calls) == 0


def test_poller_updates_source_poll_timestamps(session, hackerone_source, http_client):
    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(return_value=Response(200, json=_page([])))
        poll_hackerone("hackerone", session=session, client=http_client)
    source = session.query(Source).filter_by(id="hackerone").one()
    assert source.last_poll_at is not None
    assert source.last_success_at is not None
    assert source.consecutive_failures == 0


# ---------------------------------------------------------------------------
# Jobs queue
# ---------------------------------------------------------------------------

def _event(canonical_url="https://hackerone.com/reports/111", external_id="hackerone:111"):
    return {"canonical_url": canonical_url, "external_id": external_id,
            "title": "SSRF via PDF parser", "disclosed_at": "2026-11-18T10:00:00.000Z"}


def test_enqueue_discovery_is_idempotent(session, hackerone_source):
    first = enqueue_discovery(session, source_id="hackerone", event=_event())
    second = enqueue_discovery(session, source_id="hackerone", event=_event())
    assert first.id == second.id
    assert session.query(Job).count() == 1


def test_claim_next_job_uses_skip_locked(session, hackerone_source):
    job = enqueue_discovery(session, source_id="hackerone", event=_event())
    claimed = claim_next_job(session)
    assert claimed is not None and claimed.id == job.id
    assert claim_next_job(session) is None  # already running, not re-claimed
    mark_job_done(session, claimed)
    assert session.query(Job).filter_by(id=job.id).one().status == "done"


def test_failed_job_retries_with_backoff_then_dead_letters(session, hackerone_source):
    job = enqueue_discovery(session, source_id="hackerone", event=_event())
    assert backoff_for_attempt(1).total_seconds() == 60
    assert backoff_for_attempt(2).total_seconds() == 3600
    assert backoff_for_attempt(3).total_seconds() == 86400
    for _ in range(4):
        mark_job_failed(session, job, "boom")
        assert session.query(Job).filter_by(id=job.id).one().status != "dead"
    mark_job_failed(session, job, "boom")
    dead = session.query(Job).filter_by(id=job.id).one()
    assert dead.status == "dead"
    assert dead.attempts == 5


def test_process_job_marks_done_on_success(session, hackerone_source):
    job = enqueue_discovery(session, source_id="hackerone", event=_event())
    seen = []
    process_job(session, job.id, lambda s, j: seen.append(j.id))
    assert seen == [job.id]
    assert session.query(Job).filter_by(id=job.id).one().status == "done"


def test_process_job_marks_failed_and_reraises(session, hackerone_source):
    job = enqueue_discovery(session, source_id="hackerone", event=_event())

    def _boom(s, j):
        raise ValueError("handler failed")

    with pytest.raises(ValueError, match="handler failed"):
        process_job(session, job.id, _boom)
    failed = session.query(Job).filter_by(id=job.id).one()
    assert failed.status == "pending"  # retryable, next_attempt_at in future
    assert failed.attempts == 1
    assert failed.next_attempt_at > datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Worker upsert (parser + dedup)
# ---------------------------------------------------------------------------

def test_parse_hacktivity_item_skips_undisclosed_and_missing_url():
    assert parse_hacktivity_item(_item(1, None, disclosed=False)) is None
    item = _item(1, "t")
    item["attributes"]["url"] = None
    assert parse_hacktivity_item(item) is None


def test_parse_hacktivity_item_extracts_platform_fields():
    parsed = parse_hacktivity_item(_item(111, "SSRF via PDF parser", cve_ids=["CVE-2021-44228"]))
    assert parsed["canonical_url"] == "https://hackerone.com/reports/111"
    assert parsed["external_id"] == "hackerone:111"
    assert parsed["severity"] == "critical"
    assert parsed["cve_ids"] == ["CVE-2021-44228"]
    assert parsed["bounty_amount"] == 5000
    assert parsed["bounty_verified"] is True  # platform API is the source
    assert len(parsed["excerpt"]) <= 300


def test_worker_creates_writeup_from_discovery_job(session, hackerone_source):
    job = enqueue_discovery(session, source_id="hackerone", event=_event())
    result = handle_discovery_job(session, job)
    assert result == "created"
    writeup = session.query(Writeup).one()
    assert writeup.canonical_url == "https://hackerone.com/reports/111"
    assert writeup.external_id == "hackerone:111"
    assert writeup.url_hash == url_hash("https://hackerone.com/reports/111")
    assert writeup.status == "active"


def test_worker_merges_mirror_url_by_external_id(session, hackerone_source):
    job1 = enqueue_discovery(session, source_id="hackerone", event=_event())
    handle_discovery_job(session, job1)
    mirror = _event(canonical_url="https://medium.com/@x/ssrf-abc",
                    external_id="hackerone:111")
    job2 = enqueue_discovery(session, source_id="hackerone", event=mirror)
    assert handle_discovery_job(session, job2) == "merged"
    assert session.query(Writeup).count() == 1  # one logical writeup
    writeup = session.query(Writeup).one()
    urls = {ws.source_url for ws in session.query(WriteupSource).filter_by(writeup_id=writeup.id)}
    assert urls == {"https://hackerone.com/reports/111", "https://medium.com/@x/ssrf-abc"}
