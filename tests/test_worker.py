"""Task 16: deployment worker loop (``eunoia.worker``) + key provisioning
(``scripts/create_api_key.py``).

No live network: the poller is an injected fake, NVD is mocked with
respx, and the create-key script is run against the test DB. The
embedding model is a stub encoder.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import respx
from httpx import Client, Response
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.api.auth import verify_api_key
from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.ingestion.jobs import enqueue_discovery
from eunoia.ingestion.nvd import NVD_API_URL, TokenBucket
from eunoia.models import Base, Job, Source, Writeup
from eunoia.worker import run_kev_sync_once, run_poll_cycle

TEST_DATABASE_URL = os.environ.get(
    "EUNOIA_TEST_DATABASE_URL", "postgresql://eunoia@localhost/eunoia_test")
REPO = Path(__file__).resolve().parent.parent

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
    return TokenBucket(capacity=1000, per_seconds=30)


class StubEncoder:
    """Deterministic 384-dim encoder; records every call."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def encode(self, texts):
        self.calls.append(list(texts))
        return [[0.1] * 384 for _ in texts]


def _rich_event(**overrides):
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


def _mock_nvd_200(router):
    return router.get(NVD_API_URL).mock(return_value=Response(200, json={
        "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": CVE_ID,
                "descriptions": [{"lang": "en", "value": "Log4j RCE."}],
                "metrics": {"cvssMetricV31": [{
                    "source": "nvd@nist.gov", "type": "Primary",
                    "cvssData": {"version": "3.1",
                                 "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                 "baseScore": 10.0, "baseSeverity": "CRITICAL"},
                }]},
                "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary",
                                "description": [{"lang": "en", "value": "CWE-917"}]}],
            },
        }],
    }))


def test_run_poll_cycle_polls_and_drains_due_jobs(
    session, hackerone_source, http_client, limiter
):
    job = enqueue_discovery(session, source_id="hackerone", event=_rich_event())
    session.commit()
    polled = []
    stub = StubEncoder()
    with respx.mock as router:
        _mock_nvd_200(router)
        result = run_poll_cycle(
            session,
            poll_fn=lambda s: polled.append("poll") or {"enqueued": 0},
            model=stub, url_checker=lambda url: True,
            client=http_client, limiter=limiter)
    assert polled == ["poll"]
    assert result["processed"] == 1
    assert result["failed"] == 0
    assert session.get(Job, job.id).status == "done"
    writeup = session.query(Writeup).one()
    assert writeup.quality_passed is True


def test_run_poll_cycle_with_no_due_jobs_processes_zero(
    session, hackerone_source
):
    polled = []
    result = run_poll_cycle(
        session, poll_fn=lambda s: polled.append("poll") or {"enqueued": 0})
    assert polled == ["poll"]
    assert result == {"processed": 0, "failed": 0}


def test_run_kev_sync_once_calls_sync(session):
    calls = []
    result = run_kev_sync_once(
        session, sync_fn=lambda s: calls.append("sync") or {"added": 2})
    assert calls == ["sync"]
    assert result == {"added": 2}


def test_create_api_key_script_prints_key_once(session, monkeypatch):
    """The provisioning script prints the plaintext once and the key
    verifies afterwards; the hash alone can never recover it."""
    env = dict(os.environ, DATABASE_URL=TEST_DATABASE_URL)
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "create_api_key.py"),
         "--owner", "worker-test"],
        capture_output=True, text=True, env=env, cwd=str(REPO))
    assert proc.returncode == 0, proc.stderr
    plaintext = next(
        token for token in proc.stdout.split() if token.startswith("eun_"))
    row = verify_api_key(session, plaintext)
    assert row is not None
    assert row.owner == "worker-test"
