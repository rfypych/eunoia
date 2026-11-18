"""R6 wiring: Task 6/7/8 functions wired into the ingestion flow.

Tests that the discovery worker runs classification, NVD enrichment and
embedding after the upsert, that ``nvd_refresh`` jobs are consumed via
``dispatch_job``, and that a pipeline failure never fails the job.

HTTP is mocked with respx — tests never hit the live NVD API. DB tests
run against the dedicated ``eunoia_test`` database (same fixture
pattern as tests/test_hackerone.py). The embedding model is a stub
encoder; no test downloads weights.
"""

from __future__ import annotations

from functools import partial

import pytest
import respx
from httpx import Client, Response
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.ingestion.hackerone import handle_discovery_job
from eunoia.ingestion.jobs import dispatch_job, enqueue_discovery, process_job
from eunoia.ingestion.nvd import NVD_API_URL, NvdError, NvdRateLimitedError, TokenBucket
from eunoia.models import Base, CveCache, Embedding, Job, Source, Writeup, WriteupEvent, WriteupVuln

TEST_DATABASE_URL = "postgresql://eunoia@localhost:5432/eunoia_test"

CVE_ID = "CVE-2021-44228"


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
        feed_url="https://api.hackerone.com/v1/hackers/hacktivity",
        poll_interval_s=900, rate_limit_per_min=600, auth_ref=None,
        cursor_state={},
    ))
    session.commit()
    return session.query(Source).filter_by(id="hackerone").one()


@pytest.fixture()
def limiter():
    # Generous bucket so the shared module-global NVD bucket (5/30s
    # without a key) never interferes with tests — same pattern as
    # tests/test_enrich.py. Production degrades to cache when the
    # real bucket is empty; that is the designed behavior.
    return TokenBucket(capacity=1000, per_seconds=30)


class StubEncoder:
    """Deterministic 384-dim encoder; records every call."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def encode(self, texts):
        self.calls.append(list(texts))
        return [[0.1] * 384 for _ in texts]


def _rich_event(**overrides):
    """A discovery event with CWE + CVE, so the worker creates a vuln row."""
    event = {
        "canonical_url": "https://hackerone.com/reports/111",
        "external_id": "hackerone:111",
        "title": "SSRF via PDF parser",
        "excerpt": "SSRF via PDF parser",
        "text": "ssrf via pdf parser",
        "disclosed_at": "2026-11-18T10:00:00.000Z",
        "cwe": "CWE-918",
        "cve_ids": [CVE_ID],
        "severity": "critical",
        "bounty_amount": 5000,
        "bounty_currency": "USD",
        "bounty_verified": True,
        "program": "Example",
        "author_name": "r",
    }
    event.update(overrides)
    return event


def _nvd_payload(score: float = 10.0, cwes: list[str] | None = None) -> dict:
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": CVE_ID,
                    "descriptions": [
                        {"lang": "en", "value": "Apache Log4j2 JNDI lookup RCE."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseScore": score,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "description": [
                                {"lang": "en", "value": cwe}
                                for cwe in (cwes or ["CWE-917", "CWE-502"])
                            ],
                        }
                    ],
                }
            }
        ],
    }


def _mock_nvd_200(router):
    return router.get(NVD_API_URL).mock(
        return_value=Response(200, json=_nvd_payload())
    )


# ---------------------------------------------------------------------------
# Worker pipeline: classify -> enrich -> embed
# ---------------------------------------------------------------------------

def test_worker_pipeline_fills_class_enriches_and_embeds(
    session, hackerone_source, http_client, limiter
):
    job = enqueue_discovery(session, source_id="hackerone", event=_rich_event())
    stub = StubEncoder()
    with respx.mock as router:
        _mock_nvd_200(router)
        assert handle_discovery_job(session, job, model=stub, client=http_client, limiter=limiter) == "created"
    vuln = session.query(WriteupVuln).one()
    assert vuln.vuln_class == "SSRF"  # CWE-918 -> SSRF (Task 6)
    assert vuln.cwe_id == "CWE-918"
    row = session.get(CveCache, CVE_ID)
    assert row is not None and float(row.cvss_score) == 10.0  # Task 7
    assert session.query(Embedding).count() == 1  # Task 8
    assert len(stub.calls) == 1  # encoder ran once
    writeup = session.query(Writeup).one()
    event = session.query(WriteupEvent).filter_by(
        writeup_id=writeup.id, event="created").one()
    assert event.detail["vuln_class"] == "SSRF"
    assert event.detail["cves_enriched"] == [CVE_ID]
    assert event.detail["embed"] == "embedded"
    assert event.detail["pipeline_errors"] == []


def test_worker_rerun_is_idempotent(session, hackerone_source, http_client, limiter):
    job1 = enqueue_discovery(session, source_id="hackerone", event=_rich_event())
    stub = StubEncoder()
    with respx.mock as router:
        _mock_nvd_200(router)
        assert handle_discovery_job(session, job1, model=stub, client=http_client, limiter=limiter) == "created"
    mirror = _rich_event(
        canonical_url="https://medium.com/@x/ssrf-abc",
        external_id="hackerone:111",
    )
    job2 = enqueue_discovery(session, source_id="hackerone", event=mirror)
    with respx.mock as router:
        _mock_nvd_200(router)
        assert handle_discovery_job(session, job2, model=stub, client=http_client, limiter=limiter) == "merged"
    assert session.query(Writeup).count() == 1
    assert session.query(WriteupVuln).count() == 1
    assert session.query(Embedding).count() == 1
    assert session.query(CveCache).count() == 1
    assert len(stub.calls) == 1  # second run skipped: template hash unchanged


def test_enrichment_failure_does_not_fail_job(
    session, hackerone_source, http_client, monkeypatch
):
    import eunoia.ingestion.hackerone as h1

    def _boom(*args, **kwargs):
        raise RuntimeError("nvd exploded")

    monkeypatch.setattr(h1, "enrich_cve", _boom)
    job = enqueue_discovery(session, source_id="hackerone", event=_rich_event())
    stub = StubEncoder()
    assert handle_discovery_job(session, job, model=stub) == "created"
    writeup = session.query(Writeup).one()
    assert session.query(WriteupVuln).one().vuln_class == "SSRF"
    assert session.query(Embedding).count() == 1  # embed still ran
    event = session.query(WriteupEvent).filter_by(
        writeup_id=writeup.id, event="created").one()
    assert len(event.detail["pipeline_errors"]) == 1
    assert "nvd exploded" in event.detail["pipeline_errors"][0]


def test_embedding_failure_does_not_fail_job(
    session, hackerone_source, http_client, monkeypatch, limiter
):
    import eunoia.ingestion.hackerone as h1

    def _boom(*args, **kwargs):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(h1, "embed_writeup", _boom)
    job = enqueue_discovery(session, source_id="hackerone", event=_rich_event())
    with respx.mock as router:
        _mock_nvd_200(router)
        assert handle_discovery_job(session, job, client=http_client, limiter=limiter) == "created"
    writeup = session.query(Writeup).one()
    assert session.query(WriteupVuln).one().vuln_class == "SSRF"
    assert session.get(CveCache, CVE_ID) is not None  # enrich still ran
    event = session.query(WriteupEvent).filter_by(
        writeup_id=writeup.id, event="created").one()
    assert event.detail["embed"] == "failed"
    assert any("model exploded" in e for e in event.detail["pipeline_errors"])


# ---------------------------------------------------------------------------
# dispatch_job + nvd_refresh consumer
# ---------------------------------------------------------------------------

def test_nvd_refresh_job_consumed_via_dispatch(session, http_client, limiter):
    job = Job(
        kind="nvd_refresh", source_id=None,
        idempotency_key=f"nvd:{CVE_ID}", payload={"cve_id": CVE_ID},
        status="pending",
    )
    session.add(job)
    session.flush()
    with respx.mock as router:
        _mock_nvd_200(router)
        record = dispatch_job(session, job, client=http_client, limiter=limiter)
    assert record.cvss_score == 10.0
    assert record.cwe_ids == ["CWE-917", "CWE-502"]
    row = session.get(CveCache, CVE_ID)
    assert row is not None and float(row.cvss_score) == 10.0


def test_dispatch_discovery_routes_to_worker(
    session, hackerone_source, http_client, limiter
):
    job = enqueue_discovery(session, source_id="hackerone", event=_rich_event())
    stub = StubEncoder()
    with respx.mock as router:
        _mock_nvd_200(router)
        assert dispatch_job(session, job, model=stub, client=http_client, limiter=limiter) == "created"
    assert session.query(Writeup).count() == 1
    assert session.query(WriteupVuln).one().vuln_class == "SSRF"


def test_dispatch_unknown_kind_raises(session):
    job = Job(
        kind="bogus", source_id=None,
        idempotency_key="bogus:1", payload={}, status="pending",
    )
    session.add(job)
    session.flush()
    with pytest.raises(ValueError, match="unknown job kind"):
        dispatch_job(session, job)


def test_process_job_with_dispatch_marks_nvd_refresh_done(session, http_client, limiter):
    job = Job(
        kind="nvd_refresh", source_id=None,
        idempotency_key=f"nvd:{CVE_ID}", payload={"cve_id": CVE_ID},
        status="pending",
    )
    session.add(job)
    session.flush()
    with respx.mock as router:
        _mock_nvd_200(router)
        process_job(session, job.id, partial(dispatch_job, client=http_client, limiter=limiter))
    done = session.get(Job, job.id)
    assert done.status == "done"
    assert session.get(CveCache, CVE_ID) is not None


def test_nvd_refresh_429_is_retried_not_consumed(session, http_client, limiter):
    # Ruling R8: a degraded refresh must raise so process_job retries
    # with back-off, not mark the job done (the nvd:<cve> idempotency
    # key can never be queued again, so a consumed failure would leave
    # the stale row unrefreshed forever).
    from datetime import datetime, timedelta, timezone

    session.add(
        CveCache(
            cve_id=CVE_ID,
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            cwe_ids=["CWE-917", "CWE-502"],
            fetched_at=datetime.now(timezone.utc) - timedelta(days=2),
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
    )
    session.commit()
    job = Job(
        kind="nvd_refresh", source_id=None,
        idempotency_key=f"nvd:{CVE_ID}", payload={"cve_id": CVE_ID},
        status="pending",
    )
    session.add(job)
    session.flush()
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(429, json={}))
        with pytest.raises(NvdRateLimitedError):
            process_job(session, job.id, partial(dispatch_job, client=http_client, limiter=limiter))
    retried = session.get(Job, job.id)
    assert retried.status == "pending"  # not "done"
    assert retried.attempts == 1
    assert retried.next_attempt_at is not None
    assert retried.next_attempt_at > datetime.now(timezone.utc)


def test_nvd_refresh_404_raises_and_retries(session, http_client, limiter):
    # Ruling R8: a 404 (unknown to NVD) fetches no fresh data, so the
    # handler raises — the failure is visible (retry, then dead-letter)
    # instead of silently consuming the job.
    job = Job(
        kind="nvd_refresh", source_id=None,
        idempotency_key=f"nvd:{CVE_ID}", payload={"cve_id": CVE_ID},
        status="pending",
    )
    session.add(job)
    session.flush()
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(404, json={}))
        with pytest.raises(NvdError):
            process_job(session, job.id, partial(dispatch_job, client=http_client, limiter=limiter))
    retried = session.get(Job, job.id)
    assert retried.status == "pending"  # not "done"
    assert retried.attempts == 1
    assert session.get(CveCache, CVE_ID) is None
