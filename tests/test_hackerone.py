"""Task 5: HackerOne poller + jobs queue (spec §5.3, §5.6).

HTTP is mocked with respx — tests never hit the live HackerOne API.
DB tests run against the dedicated ``eunoia_test`` database (same
fixture pattern as tests/test_models.py).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import respx
from httpx import Client, Response
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.dedup import content_hash, normalize_text, simhash64, simhash_to_db, url_hash
from eunoia.ingestion.hackerone import (
    HACKTIVITY_URL,
    HostPausedError,
    PlanGatedError,
    PollResult,
    RateLimitedError,
    handle_discovery_job,
    normalize_cwe,
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
from eunoia.models import Base, Job, Source, SourceHost, Writeup, WriteupEvent, WriteupSource, WriteupVuln

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
    # Fix round 1, finding 2: the configured budget is never mutated; the
    # halved budget lives as ephemeral state in cursor_state.
    assert source.rate_limit_per_min == 600
    assert source.cursor_state.get("backoff_rate_limit_per_min") == 300


def test_poll_within_60s_of_429_makes_no_http_call(session, hackerone_source, http_client):
    # Fix round 1, finding 1: the 60s back-off is enforced, not just recorded.
    with respx.mock as router:
        route = router.get(HACKTIVITY_URL).mock(return_value=Response(429, json={}))
        with pytest.raises(RateLimitedError):
            poll_hackerone("hackerone", session=session, client=http_client)
        with pytest.raises(RateLimitedError):
            poll_hackerone("hackerone", session=session, client=http_client)
        assert len(route.calls) == 1  # second poll never touched the API


def test_429_budget_restored_on_success(session, hackerone_source, http_client):
    # Fix round 1, finding 2: a later successful poll drops the ephemeral
    # halved budget; the configured rate is untouched throughout.
    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(return_value=Response(429, json={}))
        with pytest.raises(RateLimitedError):
            poll_hackerone("hackerone", session=session, client=http_client)
    host = session.query(SourceHost).filter_by(host="api.hackerone.com").one()
    host.last_429 = datetime.now(timezone.utc) - timedelta(seconds=61)
    session.commit()
    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(return_value=Response(200, json=_page([])))
        poll_hackerone("hackerone", session=session, client=http_client)
    source = session.query(Source).filter_by(id="hackerone").one()
    assert source.rate_limit_per_min == 600
    assert "backoff_rate_limit_per_min" not in source.cursor_state


def test_successful_poll_clears_plan_gated_blocked_flag(session, hackerone_source, http_client):
    # Fix round 1, finding 3: the blocked flag from an earlier 403 must not
    # survive a later successful poll.
    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(return_value=Response(403, json={"error": "forbidden"}))
        with pytest.raises(PlanGatedError):
            poll_hackerone("hackerone", session=session, client=http_client)
    assert session.query(Source).filter_by(id="hackerone").one().cursor_state.get("blocked") == "plan_gated_403"
    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(return_value=Response(200, json=_page([])))
        poll_hackerone("hackerone", session=session, client=http_client)
    assert "blocked" not in session.query(Source).filter_by(id="hackerone").one().cursor_state


def test_page_cap_advances_cursor_only_to_oldest(session, hackerone_source, http_client):
    # Fix round 1, finding 5: when the run ends by page cap, the cursor
    # advances to the oldest processed item, not the newest — items on
    # unprocessed pages must still be found by the next poll.
    first = [
        _item(111, "SSRF via PDF parser", disclosed_at="2026-11-18T10:00:00.000Z"),
        _item(222, "IDOR on profile API", disclosed_at="2026-11-18T09:00:00.000Z"),
    ]
    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(
            side_effect=lambda request: Response(200, json=_page(first)))
        result = poll_hackerone(
            "hackerone", session=session, client=http_client,
            page_size=2, max_pages=1)
    assert result.last_cursor == "2026-11-18T09:00:00.000Z"
    mid = [_item(333, "XSS in search", disclosed_at="2026-11-18T09:30:00.000Z")]
    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(
            side_effect=lambda request: Response(200, json=_page(mid)))
        second = poll_hackerone(
            "hackerone", session=session, client=http_client,
            page_size=2, max_pages=1)
    assert second.enqueued == 1  # the 09:30 item was not skipped


def test_three_429s_in_a_day_pause_host_until_tomorrow(session, hackerone_source, http_client):
    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(return_value=Response(429, json={}))
        for _ in range(3):
            with pytest.raises(RateLimitedError):
                poll_hackerone("hackerone", session=session, client=http_client)
            # Simulate >60s passing so the next poll is not stopped by the
            # 60s back-off: three 429s in one day must still pause the host.
            host = session.query(SourceHost).filter_by(host="api.hackerone.com").one()
            host.last_429 = datetime.now(timezone.utc) - timedelta(seconds=61)
            session.commit()
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


def test_parse_hacktivity_item_zero_bounty_is_not_verified():
    """Final review triage, Task 5: a $0 award is not a verified
    bounty — "verified" requires a positive amount."""
    parsed = parse_hacktivity_item(_item(112, "SSRF via PDF parser", awarded=0))
    assert parsed["bounty_amount"] == 0
    assert parsed["bounty_verified"] is False
    parsed_none = parse_hacktivity_item(
        _item(113, "SSRF via PDF parser", awarded=None))
    assert parsed_none["bounty_verified"] is False


def test_parse_hacktivity_item_normalizes_live_cwe_names():
    """Deploy 2026-11-19: the live API's `cwe` is a weakness NAME, not
    a CWE id — the first production poll crashed every discovery job
    (StringDataRightTruncation on VARCHAR(16) cwe_id). Values below
    are verbatim from a live Hacktivity page (50 items, 2026-11-19)."""
    assert normalize_cwe("Cross-Site Request Forgery (CSRF)") == "CWE-352"
    assert normalize_cwe("Path Traversal") == "CWE-22"
    assert normalize_cwe("Cross-site Scripting (XSS) - Reflected") == "CWE-79"
    assert normalize_cwe("Cross-site Scripting (XSS) - Stored") == "CWE-79"
    assert normalize_cwe("Improper Access Control - Generic") == "CWE-284"
    assert normalize_cwe("Uncontrolled Resource Consumption") == "CWE-400"
    assert normalize_cwe("Insecure Direct Object Reference (IDOR)") == "CWE-639"
    assert normalize_cwe("SQL Injection") == "CWE-89"
    assert normalize_cwe("Server-Side Request Forgery (SSRF)") == "CWE-918"
    assert normalize_cwe("Heap Overflow") == "CWE-122"
    assert normalize_cwe("OS Command Injection") == "CWE-78"
    parsed = parse_hacktivity_item(
        _item(114, "CSRF on settings form", cwe="Cross-Site Request Forgery (CSRF)"))
    assert parsed["cwe"] == "CWE-352"


def test_parse_hacktivity_item_cwe_id_passthrough():
    assert normalize_cwe("CWE-918") == "CWE-918"
    assert normalize_cwe("cwe-79") == "CWE-79"
    assert normalize_cwe("prefix CWE-89 suffix") == "CWE-89"
    assert normalize_cwe(None) is None
    assert normalize_cwe("") is None


def test_parse_hacktivity_item_unknown_cwe_name_is_dropped_not_stored():
    """A weakness name with no confident single-CWE mapping must not
    be stored verbatim in cwe_id — it would crash the insert and is
    not a CWE id. The row still classifies (unclassified + review)."""
    assert normalize_cwe("Business Logic Errors") is None
    parsed = parse_hacktivity_item(
        _item(115, "Logic flaw in checkout", cwe="Business Logic Errors"))
    assert parsed["cwe"] is None


def test_parse_hacktivity_item_normalizes_live_severity_case():
    """Deploy 2026-11-19: severity_rating is capitalized ("Medium",
    "Critical"); the severity enum is lowercase-only, so the raw
    value would fail the enum cast (and _SEVERITIES dropped it)."""
    assert parse_hacktivity_item(
        _item(116, "t", severity="High"))["severity"] == "high"
    assert parse_hacktivity_item(
        _item(117, "t", severity="None"))["severity"] == "none"
    assert parse_hacktivity_item(
        _item(118, "t", severity=None))["severity"] is None


def test_worker_creates_writeup_from_live_shaped_item(session, hackerone_source):
    """Deploy 2026-11-19: a discovery job built from a live-shaped
    item (weakness name + capitalized severity) must insert without
    error, with a real CWE id and severity on the vuln row."""
    parsed = parse_hacktivity_item(_item(
        201, "CSRF on settings form",
        cwe="Cross-Site Request Forgery (CSRF)", severity="High"))
    assert parsed["cwe"] == "CWE-352"
    assert parsed["severity"] == "high"
    job = enqueue_discovery(session, source_id="hackerone", event=parsed)
    assert handle_discovery_job(session, job, url_checker=lambda url: True) == "created"
    vuln = session.query(WriteupVuln).one()
    assert vuln.cwe_id == "CWE-352"
    assert vuln.severity == "high"


def test_worker_tolerates_stale_pre_fix_payload(session, hackerone_source):
    """Deploy 2026-11-19: jobs enqueued by the pre-fix parser carry
    the RAW weakness name / capitalized severity in their stored
    payload. The worker must normalize at the point of use, so the
    50 jobs already queued on the production box drain instead of
    crashing on the VARCHAR(16) / enum cast."""
    stale = _event(
        canonical_url="https://hackerone.com/reports/202",
        external_id="hackerone:202",
    )
    stale.update({
        "title": "CSRF on settings form",
        "text": "csrf on settings form",
        "cwe": "Cross-Site Request Forgery (CSRF)",
        "severity": "High",
    })
    job = enqueue_discovery(session, source_id="hackerone", event=stale)
    assert handle_discovery_job(session, job, url_checker=lambda url: True) == "created"
    vuln = session.query(WriteupVuln).one()
    assert vuln.cwe_id == "CWE-352"
    assert vuln.severity == "high"


def test_worker_creates_writeup_from_discovery_job(session, hackerone_source):
    job = enqueue_discovery(session, source_id="hackerone", event=_event())
    result = handle_discovery_job(session, job, url_checker=lambda url: True)
    assert result == "created"
    writeup = session.query(Writeup).one()
    assert writeup.canonical_url == "https://hackerone.com/reports/111"
    assert writeup.external_id == "hackerone:111"
    assert writeup.url_hash == url_hash("https://hackerone.com/reports/111")
    assert writeup.status == "active"


def test_worker_merges_mirror_url_by_external_id(session, hackerone_source):
    job1 = enqueue_discovery(session, source_id="hackerone", event=_event())
    handle_discovery_job(session, job1, url_checker=lambda url: True)
    mirror = _event(canonical_url="https://medium.com/@x/ssrf-abc",
                    external_id="hackerone:111")
    job2 = enqueue_discovery(session, source_id="hackerone", event=mirror)
    assert handle_discovery_job(session, job2, url_checker=lambda url: True) == "merged"
    assert session.query(Writeup).count() == 1  # one logical writeup
    writeup = session.query(Writeup).one()
    urls = {ws.source_url for ws in session.query(WriteupSource).filter_by(writeup_id=writeup.id)}
    assert urls == {"https://hackerone.com/reports/111", "https://medium.com/@x/ssrf-abc"}


def test_worker_records_near_dup_candidate(session, hackerone_source):
    # Fix round 1, finding 4: _find_existing must surface SimHash
    # candidates, so the near_dup_review branch is reachable. The existing
    # row's stored SimHash is set to the candidate's SimHash (distance 0)
    # while its content hash differs — a genuine near-dup, never a merge.
    job1 = enqueue_discovery(session, source_id="hackerone", event=_event())
    assert handle_discovery_job(session, job1, url_checker=lambda url: True) == "created"
    existing = session.query(Writeup).one()
    cand_text = normalize_text("IDOR on profile API")  # job2 text: title + empty excerpt
    existing.simhash = simhash_to_db(simhash64(cand_text))
    session.flush()
    job2 = enqueue_discovery(session, source_id="hackerone", event={
        "canonical_url": "https://hackerone.com/reports/222",
        "external_id": "hackerone:222",
        "title": "IDOR on profile API",
        "disclosed_at": "2026-11-18T09:00:00.000Z",
    })
    assert handle_discovery_job(session, job2, url_checker=lambda url: True) == "created"
    assert session.query(Writeup).count() == 2  # near-dup never auto-merges
    created = session.query(Writeup).filter_by(
        canonical_url="https://hackerone.com/reports/222").one()
    event = session.query(WriteupEvent).filter_by(
        writeup_id=created.id, event="created").one()
    assert event.detail["dedup"] == "near_dup_review"
    assert event.detail["candidate_of"] == existing.api_id


def test_worker_records_title_candidate(session, hackerone_source):
    # Fix round 1, finding 4: same title + author + day, different URL /
    # external id / content — a layer-5 signal, recorded, never merged.
    existing = Writeup(
        canonical_url="https://example.com/writeup/ssrf-pdf",
        url_hash=url_hash("https://example.com/writeup/ssrf-pdf"),
        external_id="blog:ssrf-pdf",
        title="SSRF via PDF parser",
        excerpt="Unrelated writeup text about something else entirely.",
        author_name="r",
        source_id="hackerone",
        source_type="blog_writeup",
        published_at=datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc),
        disclosed_at=datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc),
        fetched_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
        content_hash=content_hash("unrelated writeup text about something else entirely"),
        simhash=simhash_to_db(simhash64("unrelated writeup text about something else entirely")),
        language="en",
        status="active",
    )
    session.add(existing)
    session.flush()
    event = _event()
    event["author_name"] = "r"
    job = enqueue_discovery(session, source_id="hackerone", event=event)
    assert handle_discovery_job(session, job, url_checker=lambda url: True) == "created"
    created = session.query(Writeup).filter_by(
        canonical_url="https://hackerone.com/reports/111").one()
    ev = session.query(WriteupEvent).filter_by(
        writeup_id=created.id, event="created").one()
    assert ev.detail["dedup"] == "title_candidate"
    assert ev.detail["candidate_of"] == existing.api_id


# --- T7: backfill to 500 + NVD backfill in the pipeline --------------------
# The poller only walks forward from the cursor (newest first); the
# corpus can only grow past ~50 by paging BACK through older disclosed
# reports. Backfill does exactly that, newest-first, stopping at the
# target, on an empty page, or on the page cap — never by inventing
# rows. All HTTP is respx-mocked; the DB is the test DB.

def _nvd_payload_94265() -> dict:
    """NVD 2.0 body for CVE-2026-94265 as observed live 19 Nov 2026:
    CVSS 9.1, CWE-200. The HackerOne row carries cwe=None and no
    severity, so the pipeline must backfill all three from NVD."""
    return {
        "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
        "format": "NVD_CVE", "version": "2.0",
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2026-94265",
                "sourceIdentifier": "cve@mitre.org",
                "published": "2026-11-03T23:17:25.910",
                "lastModified": "2026-11-12T22:09:39.233",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en",
                                  "value": "Authorization header sent to foreign origin"}],
                "metrics": {"cvssMetricV31": [{
                    "source": "nvd@nist.gov", "type": "Primary",
                    "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                 "baseScore": 9.1, "baseSeverity": "CRITICAL"},
                }]},
                "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary",
                                "description": [{"lang": "en", "value": "CWE-200"}]}],
            },
        }],
    }


def test_t7_backfill_stops_at_target(session, hackerone_source, http_client):
    from eunoia.ingestion.hackerone import backfill_hackerone
    from eunoia.ingestion.nvd import NVD_API_URL

    page1 = [_item(111, "SSRF via PDF parser"),
             _item(222, "IDOR on profile API"),
             _item(333, "XSS in comment box", cwe="CWE-79")]
    page2 = [_item(444, "RCE in uploader", cwe="CWE-78"),
             _item(555, "SQLi in search", cwe="CWE-89")]
    with respx.mock as router:
        route = router.get(HACKTIVITY_URL).mock(side_effect=[
            Response(200, json=_page(page1)),
            Response(200, json=_page(page2)),
        ])
        result = backfill_hackerone(
            session, target_active=2, client=http_client,
            url_checker=lambda url: True)
    assert len(route.calls) == 1  # page 2 never fetched
    assert result.pages_fetched == 1
    assert result.created == 3
    assert result.stopped_reason == "target_reached"
    assert result.active_total == 3
    assert session.query(Writeup).filter_by(status="active").count() == 3


def test_t7_backfill_skips_ingested_and_stops_on_empty_page(
        session, hackerone_source, http_client):
    from eunoia.ingestion.hackerone import backfill_hackerone

    first = enqueue_discovery(session, source_id="hackerone",
                              event=parse_hacktivity_item(
                                  _item(111, "SSRF via PDF parser")))
    assert handle_discovery_job(session, first,
                                url_checker=lambda url: True) == "created"
    session.commit()
    page1 = [_item(111, "SSRF via PDF parser"),
             _item(222, "IDOR on profile API"),
             _item(333, None, disclosed=False)]
    with respx.mock as router:
        route = router.get(HACKTIVITY_URL).mock(side_effect=[
            Response(200, json=_page(page1)),
            Response(200, json=_page([])),
        ])
        result = backfill_hackerone(
            session, target_active=500, client=http_client,
            url_checker=lambda url: True)
    assert len(route.calls) == 2  # the empty page was fetched, then stop
    assert result.pages_fetched == 1  # only pages with items count
    assert result.created == 1
    assert result.merged == 1
    assert result.skipped == 1  # the undisclosed item
    assert result.stopped_reason == "exhausted"
    assert result.active_total == 2


def test_t7_backfill_429_raises_rate_limited(session, hackerone_source, http_client):
    from eunoia.ingestion.hackerone import backfill_hackerone

    with respx.mock as router:
        router.get(HACKTIVITY_URL).mock(return_value=Response(429, json={}))
        with pytest.raises(RateLimitedError):
            backfill_hackerone(session, target_active=500, client=http_client,
                               url_checker=lambda url: True)
    assert session.query(Writeup).count() == 0


def test_t7_pipeline_backfills_cvss_severity_and_class_from_nvd(
        session, hackerone_source, http_client):
    """CVE-2026-94265, verified live 19 Nov 2026: HackerOne gives no
    CWE and no severity; NVD gives CVSS 9.1 + CWE-200. The pipeline
    must store the CVSS, derive severity critical (source nvd), and
    classify Info Disclosure — the same data the ranking needs."""
    from eunoia.ingestion.nvd import NVD_API_URL, TokenBucket

    parsed = parse_hacktivity_item(_item(
        94265, "CVE-2026-94265: Authorization: Negotiate sent to foreign origin",
        cwe=None, cve_ids=["CVE-2026-94265"], severity=None,
        vuln_info="Authorization: Negotiate sent to foreign origin"))
    assert parsed["cwe"] is None and parsed["severity"] is None
    job = enqueue_discovery(session, source_id="hackerone", event=parsed)
    with respx.mock as router:
        router.get(NVD_API_URL).mock(
            return_value=Response(200, json=_nvd_payload_94265()))
        assert handle_discovery_job(
            session, job, client=http_client,
            limiter=TokenBucket(5, 30),
            url_checker=lambda url: True) == "created"
    vuln = session.query(WriteupVuln).one()
    assert float(vuln.cvss_score) == 9.1
    assert vuln.severity == "critical"
    assert vuln.severity_source == "nvd"
    assert vuln.vuln_class == "Info Disclosure"


def test_t7_pipeline_keeps_hackerone_severity_over_nvd(
        session, hackerone_source, http_client):
    """A HackerOne severity is platform data: NVD CVSS is stored for
    ranking (normalize_severity prefers CVSS), but the severity enum
    itself is never overwritten by the NVD-derived band."""
    from eunoia.ingestion.nvd import NVD_API_URL, TokenBucket

    parsed = parse_hacktivity_item(_item(
        94265, "CVE-2026-94265: Authorization: Negotiate sent to foreign origin",
        cwe=None, cve_ids=["CVE-2026-94265"], severity="Medium",
        vuln_info="Authorization: Negotiate sent to foreign origin"))
    job = enqueue_discovery(session, source_id="hackerone", event=parsed)
    with respx.mock as router:
        router.get(NVD_API_URL).mock(
            return_value=Response(200, json=_nvd_payload_94265()))
        handle_discovery_job(
            session, job, client=http_client,
            limiter=TokenBucket(5, 30),
            url_checker=lambda url: True)
    vuln = session.query(WriteupVuln).one()
    assert float(vuln.cvss_score) == 9.1
    assert vuln.severity == "medium"
    assert vuln.severity_source == "hackerone"


def test_t7_default_client_uses_ssl_cert_file(monkeypatch):
    """This VM's egress proxy MITMs TLS; httpx with trust_env=False
    ignores SSL_CERT_FILE, so the poller client must pass the bundle
    explicitly when the env var is set. Without it, behaviour is the
    plain default (verify=True)."""
    import os
    import ssl

    import eunoia.ingestion.hackerone as h1

    captured: dict = {}

    class FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    # A real CA bundle file: the one this environment already uses.
    ca_bundle = os.environ.get("SSL_CERT_FILE")
    assert ca_bundle and os.path.exists(ca_bundle), (
        "this test needs a real CA bundle file in SSL_CERT_FILE")
    monkeypatch.setattr(h1.httpx, "Client", FakeClient)
    monkeypatch.setenv("SSL_CERT_FILE", ca_bundle)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("http_proxy", raising=False)
    h1._default_client()
    assert isinstance(captured.get("verify"), ssl.SSLContext)
    assert captured.get("trust_env") is False
    captured.clear()
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    h1._default_client()
    assert "verify" not in captured


def test_t7_apply_cached_nvd_backfills_rows_from_cache(
        session, hackerone_source, http_client):
    """T7: the nvd_refresh drain fills cve_cache, but the writeup rows
    never saw the late NVD data (the discovery pipeline ran before
    NVD had the CVE). apply_cached_nvd closes that gap: a cached
    record backfills CVSS, severity, and class onto rows that lack
    them. No HTTP is needed when the cache row is fresh."""
    from datetime import timedelta

    import respx
    from httpx import Response

    from eunoia.ingestion.hackerone import apply_cached_nvd
    from eunoia.ingestion.nvd import NVD_API_URL, TokenBucket
    from eunoia.models import CveCache

    parsed = parse_hacktivity_item(_item(
        94265, "CVE-2026-94265: Authorization: Negotiate sent to foreign origin",
        cwe=None, cve_ids=["CVE-2026-94265"], severity=None,
        vuln_info="Authorization: Negotiate sent to foreign origin"))
    job = enqueue_discovery(session, source_id="hackerone", event=parsed)
    # Ingest with NVD mocked 404 (unknown yet): no CVSS, no CWE, the
    # row stays unclassified — the exact state apply_cached_nvd must fix.
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(404, json={}))
        assert handle_discovery_job(
            session, job, client=http_client, limiter=TokenBucket(5, 30),
            url_checker=lambda url: True) == "created"
    vuln = session.query(WriteupVuln).one()
    assert vuln.vuln_class == "unclassified"  # no NVD data at ingest
    assert vuln.cvss_score is None
    now = datetime.now(timezone.utc)
    session.add(CveCache(
        cve_id="CVE-2026-94265", cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cwe_ids=["CWE-200"], fetched_at=now,
        expires_at=now + timedelta(days=1)))
    session.commit()
    checked, updated = apply_cached_nvd(session)
    assert checked >= 1
    assert updated["cvss"] >= 1
    assert updated["severity"] >= 1
    assert updated["class"] >= 1
    session.refresh(vuln)
    assert float(vuln.cvss_score) == 9.1
    assert vuln.severity == "critical"
    assert vuln.severity_source == "nvd"
    assert vuln.vuln_class == "Info Disclosure"


def test_t7_apply_cached_nvd_leaves_rows_without_nvd_data(
        session, hackerone_source, http_client):
    """No cache row and no NVD fetch (client=None would go live, so
    the function must not fetch when there is nothing cached and no
    client is given): the row stays exactly as ingested."""
    import respx
    from httpx import Response

    from eunoia.ingestion.hackerone import apply_cached_nvd
    from eunoia.ingestion.nvd import NVD_API_URL, TokenBucket

    parsed = parse_hacktivity_item(_item(
        111950, "CVE-2026-111950: TLS session cache diff scheme reuse",
        cwe=None, cve_ids=["CVE-2026-111950"], severity=None,
        vuln_info="TLS session cache diff scheme reuse"))
    job = enqueue_discovery(session, source_id="hackerone", event=parsed)
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(404, json={}))
        assert handle_discovery_job(
            session, job, client=http_client, limiter=TokenBucket(5, 30),
            url_checker=lambda url: True) == "created"
    checked, updated = apply_cached_nvd(session, client=None)
    assert checked >= 1
    assert updated == {"cvss": 0, "severity": 0, "class": 0}
    vuln = session.query(WriteupVuln).one()
    assert vuln.vuln_class == "unclassified"
    assert vuln.cvss_score is None


# --- T7 fix: _due_refresh_jobs must count NULL next_attempt_at as due ---
def _load_backfill_script():
    """Load scripts/backfill_hackerone.py as a module (it lives in
    scripts/, not in the package)."""
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "scripts" / "backfill_hackerone.py"
    spec = importlib.util.spec_from_file_location("backfill_hackerone", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_t7_due_refresh_jobs_counts_null_next_attempt_as_due(session):
    """Regression: the box backfill queued 89 fresh nvd_refresh jobs
    and the drain reported '0 due' because a plain '<= now' missed
    every job whose next_attempt_at was NULL (never attempted). A
    NULL next attempt means 'due now', same as the claim condition
    in the jobs module. A job backed off into the future is not due,
    and 'pending' alone is not the drain's stop condition."""
    backfill = _load_backfill_script()
    now = datetime.now(timezone.utc)
    jobs = [
        Job(kind="nvd_refresh", source_id=None,
            idempotency_key="nvd:NULL", payload={"cve_id": "CVE-2026-00001"},
            status="pending", next_attempt_at=None),
        Job(kind="nvd_refresh", source_id=None,
            idempotency_key="nvd:PAST", payload={"cve_id": "CVE-2026-00002"},
            status="pending", next_attempt_at=now - timedelta(minutes=5)),
        Job(kind="nvd_refresh", source_id=None,
            idempotency_key="nvd:FUTURE", payload={"cve_id": "CVE-2026-00003"},
            status="pending", next_attempt_at=now + timedelta(hours=1)),
    ]
    session.add_all(jobs)
    session.flush()
    assert backfill._pending_refresh_jobs(session) == 3
    assert backfill._due_refresh_jobs(session) == 2
