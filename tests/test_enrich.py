"""Task 7: NVD enrichment + cve_cache + KEV flag (spec §5.4.5, §5.9).

HTTP is mocked with respx — tests never hit the live NVD, CISA KEV, or
FIRST EPSS APIs. DB tests run against the dedicated ``eunoia_test``
database (same fixture pattern as tests/test_hackerone.py).

Note on the brief's verbatim tests: they call ``enrich_cve(cve_id)``
with no session. This module's tests pass the test ``session``
explicitly (the established pattern in this repo) so enrichment never
touches the dev database; the assertions are the brief's.
"""

from __future__ import annotations

import time
from datetime import date, datetime, timedelta, timezone

import pytest
import respx
from httpx import Client, Response
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.enrich import CACHE_TTL, CveRecord, enrich_cve
from eunoia.ingestion.kev import KEV_URL, fetch_kev, sync_kev
from eunoia.ingestion.nvd import (
    EPSS_API_URL,
    NVD_API_URL,
    NvdError,
    NvdRateLimitedError,
    TokenBucket,
    fetch_cve,
    fetch_epss,
    parse_nvd_cve,
)
from eunoia.models import Base, CveCache, Job

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
def limiter():
    # Generous bucket so the rate limiter never interferes with tests
    # (production defaults are 5/30s without a key, 50/30s with one).
    return TokenBucket(capacity=1000, per_seconds=30)


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
                                "exploitabilityScore": 3.9,
                                "impactScore": 6.0,
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


def _kev_payload(cve_ids: list[str] | None = None) -> dict:
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.11.18",
        "dateReleased": "2026-11-18T00:00:00.000Z",
        "count": len(cve_ids or [CVE_ID]),
        "vulnerabilities": [
            {
                "cveID": cve_id,
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
                "dateAdded": "2021-12-10",
                "shortDescription": "Known exploited.",
                "requiredAction": "Apply updates.",
                "dueDate": "2021-12-24",
            }
            for cve_id in (cve_ids or [CVE_ID])
        ],
    }


# --- NVD client -----------------------------------------------------------


def test_parse_nvd_cve_prefers_primary_cvss_and_cwes():
    parsed = parse_nvd_cve(_nvd_payload())
    assert parsed is not None
    assert parsed["cvss_score"] == 10.0
    assert parsed["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert parsed["cwe_ids"] == ["CWE-917", "CWE-502"]


def test_parse_nvd_cve_empty_results_is_none():
    assert parse_nvd_cve({"totalResults": 0, "vulnerabilities": []}) is None


def test_fetch_cve_uses_cve_id_filter(http_client, limiter):
    with respx.mock as router:
        route = router.get(NVD_API_URL).mock(
            return_value=Response(200, json=_nvd_payload())
        )
        result = fetch_cve(CVE_ID, client=http_client, limiter=limiter)
    assert result is not None and result["cvss_score"] == 10.0
    params = route.calls[0].request.url.params
    assert params["cveId"] == CVE_ID
    assert int(params["resultsPerPage"]) <= 2000


def test_fetch_cve_sends_api_key_header_when_given(http_client, limiter):
    with respx.mock as router:
        route = router.get(NVD_API_URL).mock(
            return_value=Response(200, json=_nvd_payload())
        )
        fetch_cve(CVE_ID, client=http_client, api_key="free-key", limiter=limiter)
    assert route.calls[0].request.headers["apiKey"] == "free-key"


def test_fetch_cve_404_returns_none(http_client, limiter):
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(404, json={}))
        assert fetch_cve(CVE_ID, client=http_client, limiter=limiter) is None


def test_fetch_cve_429_raises_rate_limited(http_client, limiter):
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(429, json={}))
        with pytest.raises(NvdRateLimitedError):
            fetch_cve(CVE_ID, client=http_client, limiter=limiter)


def test_token_bucket_exhausts_and_refills():
    bucket = TokenBucket(capacity=2, per_seconds=30)
    assert bucket.try_acquire()
    assert bucket.try_acquire()
    assert not bucket.try_acquire()
    # After the window passes, tokens refill.
    assert bucket.try_acquire(now=time.monotonic() + 31)


def test_fetch_cve_exhausted_bucket_raises_without_http_call(http_client):
    bucket = TokenBucket(capacity=1, per_seconds=30)
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(200, json=_nvd_payload()))
        fetch_cve(CVE_ID, client=http_client, limiter=bucket)
        with pytest.raises(NvdRateLimitedError):
            fetch_cve(CVE_ID, client=http_client, limiter=bucket)
        assert len(router.calls) == 1


# --- enrich_cve -----------------------------------------------------------


def test_enrichment_from_cache_is_fast(session, http_client, limiter):
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(200, json=_nvd_payload()))
        enrich_cve(CVE_ID, session=session, client=http_client, limiter=limiter)
    # Second call: no routes registered, so any HTTP attempt raises.
    with respx.mock:
        t0 = time.monotonic()
        r = enrich_cve(CVE_ID, session=session, client=http_client, limiter=limiter)
        assert time.monotonic() - t0 < 1.0
    assert isinstance(r, CveRecord)
    assert r.cvss_score is not None and r.cwe_ids


def test_enrich_caches_row_with_one_day_ttl(session, http_client, limiter):
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(200, json=_nvd_payload()))
        r = enrich_cve(CVE_ID, session=session, client=http_client, limiter=limiter)
    assert r.cvss_score == 10.0
    assert r.cwe_ids == ["CWE-917", "CWE-502"]
    row = session.get(CveCache, CVE_ID)
    assert row is not None
    assert float(row.cvss_score) == 10.0
    assert row.cwe_ids == ["CWE-917", "CWE-502"]
    assert row.expires_at is not None
    assert row.expires_at - row.fetched_at == CACHE_TTL


def test_stale_cache_refetches(session, http_client, limiter):
    stale = CveCache(
        cve_id=CVE_ID,
        cvss_score=5.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        cwe_ids=["CWE-79"],
        fetched_at=datetime.now(timezone.utc) - timedelta(days=2),
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    session.add(stale)
    session.commit()
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(200, json=_nvd_payload()))
        r = enrich_cve(CVE_ID, session=session, client=http_client, limiter=limiter)
    assert r.cvss_score == 10.0
    assert r.cwe_ids == ["CWE-917", "CWE-502"]


def test_nvd_429_degrades_to_cache_not_block(session, http_client, limiter):
    # Seed a STALE cached row: a fresh row would be served without ever
    # touching NVD, so the 429 path would not be exercised at all.
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
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(429, json={}))
        r = enrich_cve(CVE_ID, session=session, client=http_client, limiter=limiter)
    # Served from cache, not blocked — and a refresh was queued.
    assert r.cvss_score is not None
    assert r.cvss_score == 10.0
    job = session.execute(
        text("SELECT kind FROM jobs WHERE idempotency_key = :k"),
        {"k": f"nvd:{CVE_ID}"},
    ).first()
    assert job is not None and job[0] == "nvd_refresh"


def test_nvd_429_with_no_cache_returns_empty_record(session, http_client, limiter):
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(429, json={}))
        r = enrich_cve(CVE_ID, session=session, client=http_client, limiter=limiter)
    assert r.cvss_score is None and r.cwe_ids == []
    assert r.kev is False


def test_nvd_404_returns_empty_record_without_caching(session, http_client, limiter):
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(404, json={}))
        r = enrich_cve(CVE_ID, session=session, client=http_client, limiter=limiter)
    assert r.cvss_score is None
    assert session.get(CveCache, CVE_ID) is None


def test_enrich_invalid_cve_id_raises_without_http(session, http_client, limiter):
    with respx.mock:
        with pytest.raises(ValueError):
            enrich_cve("not-a-cve", session=session, client=http_client, limiter=limiter)


def test_enrich_preserves_kev_flag_from_prior_sync(session, http_client, limiter):
    with respx.mock as router:
        router.get(KEV_URL).mock(return_value=Response(200, json=_kev_payload()))
        sync_kev(session, client=http_client)
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(200, json=_nvd_payload()))
        r = enrich_cve(CVE_ID, session=session, client=http_client, limiter=limiter)
    assert r.kev is True
    assert r.kev_date_added == date(2021, 12, 10)


# --- KEV ------------------------------------------------------------------


def test_fetch_kev_maps_cve_id_to_date_added(http_client):
    with respx.mock as router:
        router.get(KEV_URL).mock(
            return_value=Response(
                200, json=_kev_payload([CVE_ID, "CVE-2022-22965"])
            )
        )
        kev = fetch_kev(client=http_client)
    assert kev == {
        CVE_ID: date(2021, 12, 10),
        "CVE-2022-22965": date(2021, 12, 10),
    }


def test_sync_kev_flags_rows_and_is_idempotent(session, http_client):
    with respx.mock as router:
        router.get(KEV_URL).mock(return_value=Response(200, json=_kev_payload()))
        first = sync_kev(session, client=http_client)
        second = sync_kev(session, client=http_client)
    assert first == {"total": 1, "new": 1, "updated": 0}
    assert second == {"total": 1, "new": 0, "updated": 0}
    row = session.get(CveCache, CVE_ID)
    assert row is not None and row.kev is True
    assert row.kev_date_added == date(2021, 12, 10)
    # KEV-only rows carry no NVD data and no expiry, so a later enrich
    # still fetches from NVD instead of serving an empty "fresh" row.
    assert row.cvss_score is None and row.expires_at is None


def test_sync_kev_updates_existing_row(session, http_client):
    session.add(CveCache(cve_id=CVE_ID, cvss_score=10.0))
    session.commit()
    with respx.mock as router:
        router.get(KEV_URL).mock(return_value=Response(200, json=_kev_payload()))
        result = sync_kev(session, client=http_client)
    assert result == {"total": 1, "new": 0, "updated": 1}
    row = session.get(CveCache, CVE_ID)
    assert row.kev is True and float(row.cvss_score) == 10.0


# --- EPSS (optional) ------------------------------------------------------


def test_fetch_epss_returns_score_and_percentile(http_client):
    with respx.mock as router:
        route = router.get(EPSS_API_URL).mock(
            return_value=Response(
                200,
                json={"status": "OK", "data": [{"cve": CVE_ID, "epss": "0.97318", "percentile": "0.998"}]},
            )
        )
        epss, percentile = fetch_epss(CVE_ID, client=http_client)
    assert epss == 0.97318 and percentile == 0.998
    assert route.calls[0].request.url.params["cve"] == CVE_ID


def test_fetch_epss_failure_returns_nones(http_client):
    with respx.mock as router:
        router.get(EPSS_API_URL).mock(return_value=Response(500, json={}))
        assert fetch_epss(CVE_ID, client=http_client) == (None, None)


def test_enrich_with_epss_stores_values(session, http_client, limiter):
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(200, json=_nvd_payload()))
        router.get(EPSS_API_URL).mock(
            return_value=Response(
                200,
                json={"status": "OK", "data": [{"cve": CVE_ID, "epss": "0.5", "percentile": "0.9"}]},
            )
        )
        r = enrich_cve(
            CVE_ID,
            session=session,
            client=http_client,
            limiter=limiter,
            include_epss=True,
        )
    assert r.epss == 0.5 and r.epss_percentile == 0.9
    row = session.get(CveCache, CVE_ID)
    assert float(row.epss) == 0.5 and float(row.epss_percentile) == 0.9


def test_enrich_without_epss_preserves_stored_epss(session, http_client, limiter):
    """Task 7 triage item: a plain NVD refresh (include_epss=False)
    must not wipe a previously stored EPSS value."""
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(200, json=_nvd_payload()))
        router.get(EPSS_API_URL).mock(
            return_value=Response(
                200,
                json={"status": "OK", "data": [{"cve": CVE_ID, "epss": "0.5", "percentile": "0.9"}]},
            )
        )
        enrich_cve(CVE_ID, session=session, client=http_client,
                   limiter=limiter, include_epss=True)
    row = session.get(CveCache, CVE_ID)
    row.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    session.flush()
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(200, json=_nvd_payload()))
        enrich_cve(CVE_ID, session=session, client=http_client,
                   limiter=limiter, include_epss=False)
    row = session.get(CveCache, CVE_ID)
    assert float(row.epss) == 0.5 and float(row.epss_percentile) == 0.9


def test_nvd_404_keeps_kev_only_row(session, http_client, limiter):
    """Task 7 triage item: an NVD 404 must not discard a KEV-only
    row — the record keeps its kev=True flag."""
    with respx.mock as router:
        router.get(KEV_URL).mock(return_value=Response(200, json=_kev_payload()))
        sync_kev(session, client=http_client)
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(404, json={}))
        r = enrich_cve(CVE_ID, session=session, client=http_client, limiter=limiter)
    assert r.kev is True
    assert r.kev_date_added == date(2021, 12, 10)
    assert session.get(CveCache, CVE_ID) is not None


def test_fetch_cve_malformed_200_body_is_nvd_error(http_client, limiter):
    """Task 7 triage item: a malformed 200 body is an NVD failure
    (NvdError, which enrich_cve degrades on), never a bare ValueError."""
    with respx.mock as router:
        router.get(NVD_API_URL).mock(
            return_value=Response(200, text="this is not json"))
        with pytest.raises(NvdError):
            fetch_cve(CVE_ID, client=http_client, limiter=limiter)


def test_fetch_kev_skips_bad_date_added(http_client):
    """Task 7 triage item: a bad dateAdded must not crash the daily
    KEV sync — the malformed entry is skipped."""
    payload = _kev_payload([CVE_ID, "CVE-2022-22965"])
    payload["vulnerabilities"][1]["dateAdded"] = "not-a-date"
    with respx.mock as router:
        router.get(KEV_URL).mock(return_value=Response(200, json=payload))
        kev = fetch_kev(client=http_client)
    assert kev == {CVE_ID: date(2021, 12, 10)}


def test_enrich_cve_with_caller_session_does_not_commit(
    session, http_client, limiter
):
    """Final review I5: enrich_cve is flush-only for a caller-owned
    session — the caller's transaction stays open (the old code
    committed it, poisoning the worker pipeline's transaction
    control)."""
    with respx.mock as router:
        router.get(NVD_API_URL).mock(return_value=Response(200, json=_nvd_payload()))
        enrich_cve(CVE_ID, session=session, client=http_client, limiter=limiter)
    assert session.in_transaction() is True
    assert session.get(CveCache, CVE_ID) is not None
