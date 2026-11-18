"""Task 10: REST v1 + auth tiers + /status + OpenAPI.

DB tests run against the dedicated ``eunoia_test`` database (same
fixture pattern as tests/test_search.py). The embedding model is a
keyword stub encoder — no test downloads weights. The FastAPI app is
built per-test with the test engine and the stub encoder, so no request
touches the dev database or the live network.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.api.auth import create_api_key, revoke_api_key, verify_api_key
from eunoia.api.rate_limit import RateLimiter
from eunoia.api.rest import create_app
from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.dedup import url_hash
from eunoia.embed import embed_writeup
from eunoia.models import (
    Base,
    Source,
    Writeup,
    WriteupSource,
    WriteupVuln,
)

TEST_DATABASE_URL = "postgresql://eunoia@localhost:5432/eunoia_test"

NOW = datetime.now(timezone.utc)

_VOCAB = [
    "ssrf", "pdf", "parser", "spring", "boot", "tomcat", "log4j",
    "wordpress", "rce", "xss", "sqli", "deserialization", "java",
    "plugin", "remote", "code", "execution", "injection", "bypass",
    "auth", "framework", "server", "library",
]


class KeywordEncoder:
    """Deterministic 384-dim encoder (same as tests/test_search.py)."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def encode(self, texts):
        self.calls.append(list(texts))
        vectors = []
        for text in texts:
            tokens = re.findall(r"[a-z0-9]+", text.lower())
            vec = [0.0] * 384
            for i, word in enumerate(_VOCAB):
                vec[i] = float(tokens.count(word))
            vectors.append(vec)
        return vectors


def _writeup(session, *, url, title, excerpt, author, status="active",
             language="en", published=None, source_id="hackerone",
             source_type="hackerone_report"):
    w = Writeup(
        canonical_url=url,
        url_hash=url_hash(url),
        title=title,
        excerpt=excerpt,
        author_name=author,
        source_id=source_id,
        source_type=source_type,
        published_at=published,
        disclosed_at=published,
        fetched_at=NOW,
        last_seen_at=NOW,
        language=language,
        status=status,
    )
    session.add(w)
    session.flush()
    session.add(WriteupSource(writeup_id=w.id, source_id=source_id,
                              source_url=url))
    return w


def _vuln(session, writeup, **kwargs):
    row = WriteupVuln(writeup_id=writeup.id, **kwargs)
    session.add(row)
    return row


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
    encoder = KeywordEncoder()
    with Session(engine) as s:
        s.add(Source(
            id="hackerone", name="HackerOne Hacktivity", type="api",
            base_url="https://api.hackerone.com",
            poll_interval_s=900, rate_limit_per_min=600,
            cursor_state={}, last_poll_at=NOW - timedelta(minutes=5),
            last_success_at=NOW - timedelta(minutes=5),
            consecutive_failures=0, enabled=True,
        ))
        s.add(Source(
            id="portswigger", name="PortSwigger Research", type="rss",
            cursor_state={"blocked": "plan_gated_403"},
            last_poll_at=NOW - timedelta(hours=2),
            last_success_at=None, consecutive_failures=3, enabled=True,
        ))
        w1 = _writeup(
            s, url="https://hackerone.com/reports/689314",
            title="SSRF via PDF parser in Spring Boot",
            excerpt="A PDF parser fetches attacker-controlled URLs.",
            author="alice", published=datetime(2024, 5, 1, tzinfo=timezone.utc),
        )
        w1.external_id = "hackerone:689314"
        _vuln(s, w1, vuln_class="SSRF", cwe_id="CWE-918",
              cve_id="CVE-2022-22965", cvss_score=9.8,
              cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              severity="critical", severity_source="hackerone",
              bounty_amount=5000, bounty_currency="USD",
              bounty_verified=True, verified_against="hackerone",
              program="Acme", program_slug="acme")
        w2 = _writeup(
            s, url="https://hackerone.com/reports/700001",
            title="Reflected XSS in Tomcat admin console",
            excerpt="Unsanitized input reflected in the admin page.",
            author="bob", published=datetime(2023, 1, 15, tzinfo=timezone.utc),
        )
        w2.external_id = "hackerone:700001"
        _vuln(s, w2, vuln_class="XSS", cwe_id="CWE-79",
              severity="medium", severity_source="hackerone",
              bounty_amount=500, bounty_currency="USD",
              bounty_verified=False, verified_against=None,
              program="Beta", program_slug="beta")
        w3 = _writeup(
            s, url="https://hackerone.com/reports/700002",
            title="RCE in old plugin", excerpt="Retracted report.",
            author="carol", status="retracted",
            published=datetime(2022, 6, 1, tzinfo=timezone.utc),
        )
        _vuln(s, w3, vuln_class="RCE", cwe_id="CWE-94",
              severity="critical", severity_source="hackerone")
        w4 = _writeup(
            s, url="https://example.com/blog/ssrf-pdf",
            title="SSRF pada parser PDF", excerpt="Tulisan berbahasa Indonesia.",
            author="dedi", language="id", source_id=None,
            source_type="blog_writeup",
            published=datetime(2024, 2, 1, tzinfo=timezone.utc),
        )
        _vuln(s, w4, vuln_class="SSRF", cwe_id="CWE-918",
              severity="high", severity_source="author")
        embed_writeup(w1.id, session=s, model=encoder)
        s.commit()
        s.encoder = encoder  # type: ignore[attr-defined]
        yield s
        s.rollback()
    Base.metadata.drop_all(engine)


@pytest.fixture()
def client(session):
    engine = get_engine(get_settings(DATABASE_URL=TEST_DATABASE_URL))
    app = create_app(engine=engine, model=session.encoder)
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def keyed_client(session):
    engine = get_engine(get_settings(DATABASE_URL=TEST_DATABASE_URL))
    plaintext, _row = create_api_key(session, owner="test-agent", tier="free")
    session.commit()
    app = create_app(engine=engine, model=session.encoder)
    with TestClient(app, headers={"Authorization": f"Bearer {plaintext}"}) as c:
        yield c


# --- brief verbatim tests ---------------------------------------------------

def test_search_requires_no_key_but_rate_limited(client):
    r = client.get("/v1/search?q=ssrf&limit=20")
    assert r.status_code == 200 and "X-RateLimit-Remaining" in r.headers


def test_submission_never_auto_indexes(client):
    r = client.post("/v1/submissions", json={"url": "https://example.com/w"})
    assert r.json()["status"] == "in_review"
    assert client.get("/v1/writeups?q=example.com").json()["total"] == 0


# --- auth tiers -------------------------------------------------------------

def test_anon_explicit_hybrid_is_forbidden(client):
    r = client.get("/v1/search?q=ssrf&mode=hybrid")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "MODE_REQUIRES_KEY"


def test_anon_explicit_semantic_is_forbidden(client):
    r = client.get("/v1/search?q=ssrf&mode=semantic")
    assert r.status_code == 403


def test_anon_keyword_search_returns_results(client):
    r = client.get("/v1/search?q=ssrf")
    assert r.status_code == 200
    ids = [row["writeup_id"] for row in r.json()["results"]]
    assert len(ids) == 1  # non-English writeup excluded
    assert r.json()["results"][0]["verified_label"] == "platform-verified"
    assert "score_breakdown" in r.json()["results"][0]
    assert "match_reason" in r.json()["results"][0]


def test_keyed_hybrid_search_works(keyed_client):
    r = keyed_client.get("/v1/search?q=ssrf&mode=hybrid")
    assert r.status_code == 200
    assert len(r.json()["results"]) >= 1


def test_keyed_semantic_search_works(keyed_client):
    r = keyed_client.get("/v1/search?q=ssrf&mode=semantic")
    assert r.status_code == 200
    assert len(r.json()["results"]) >= 1


def test_invalid_key_is_unauthorized(client):
    r = client.get("/v1/search?q=ssrf&mode=hybrid",
                   headers={"Authorization": "Bearer eun_bogus"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "UNAUTHORIZED"


def test_rerank_maps_to_501_not_500(keyed_client):
    r = keyed_client.get("/v1/search?q=ssrf&rerank=true")
    assert r.status_code == 501
    assert r.json()["error"]["code"] == "NOT_IMPLEMENTED"


def test_limit_zero_clamps_to_one(keyed_client):
    r = keyed_client.get("/v1/search?q=ssrf&limit=0")
    assert r.status_code == 200
    assert len(r.json()["results"]) == 1


def test_limit_above_ten_clamped(keyed_client):
    r = keyed_client.get("/v1/search?q=ssrf&limit=20")
    assert r.status_code == 200
    assert len(r.json()["results"]) <= 10


# --- rate limiting ----------------------------------------------------------

def test_rate_limit_429_with_envelope_and_retry_after(session):
    engine = get_engine(get_settings(DATABASE_URL=TEST_DATABASE_URL))
    app = create_app(
        engine=engine, model=session.encoder,
        rate_limiter=RateLimiter(anon_per_minute=2, anon_per_day=1000),
    )
    with TestClient(app) as c:
        assert c.get("/v1/status").status_code == 200
        assert c.get("/v1/status").status_code == 200
        r = c.get("/v1/status")
        assert r.status_code == 429
        assert r.json()["error"]["code"] == "RATE_LIMITED"
        assert "Retry-After" in r.headers
        assert r.json()["error"]["retry_after"] is not None


def test_every_response_carries_request_id_and_rate_limit_headers(client):
    for path in ("/v1/status", "/v1/writeups", "/v1/programs"):
        r = client.get(path)
        assert r.status_code == 200
        assert "X-Request-Id" in r.headers
        assert "X-RateLimit-Limit" in r.headers
        assert "X-RateLimit-Remaining" in r.headers
        assert "X-RateLimit-Reset" in r.headers


# --- writeups list ----------------------------------------------------------

def test_writeups_default_status_active_only(client):
    r = client.get("/v1/writeups")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert all(row["status"] == "active" for row in body["items"])


def test_writeups_status_filter_can_show_retracted(client):
    r = client.get("/v1/writeups?status=retracted")
    assert r.json()["total"] == 1


def test_writeups_filters(client):
    assert client.get("/v1/writeups?vuln_class=XSS").json()["total"] == 1
    assert client.get("/v1/writeups?cwe=CWE-918").json()["total"] == 2
    assert client.get("/v1/writeups?cve=CVE-2022-22965").json()["total"] == 1
    assert client.get("/v1/writeups?program=Acme").json()["total"] == 1
    assert client.get("/v1/writeups?author=bob").json()["total"] == 1
    assert client.get("/v1/writeups?severity=critical").json()["total"] == 1
    assert client.get("/v1/writeups?source=hackerone").json()["total"] == 2
    assert client.get("/v1/writeups?bounty_verified=true").json()["total"] == 1
    assert client.get("/v1/writeups?bounty_verified=false").json()["total"] == 2
    assert client.get("/v1/writeups?q=tomcat").json()["total"] == 1
    assert client.get("/v1/writeups?published_after=2024-01-01").json()["total"] == 2
    assert client.get("/v1/writeups?published_before=2024-01-01").json()["total"] == 1


def test_writeups_sort_bounty(client):
    r = client.get("/v1/writeups?sort=bounty")
    assert r.json()["items"][0]["bounty"]["amount"] == 5000


def test_writeups_sort_published_at(client):
    r = client.get("/v1/writeups?sort=published_at")
    assert r.json()["items"][0]["title"].startswith("SSRF via PDF")


def test_writeups_cursor_pagination(client):
    first = client.get("/v1/writeups?q=ssrf&per_page=1").json()
    assert first["total"] == 2
    assert first["cursor"] is not None
    second = client.get(
        f"/v1/writeups?q=ssrf&per_page=1&cursor={first['cursor']}").json()
    assert len(second["items"]) == 1
    assert second["items"][0]["id"] != first["items"][0]["id"]
    assert second["cursor"] is None


def test_writeups_page_pagination(client):
    r = client.get("/v1/writeups?page=2&per_page=2").json()
    assert len(r["items"]) == 1
    assert r["total"] == 3


def test_writeups_per_page_capped_at_100(client):
    r = client.get("/v1/writeups?per_page=500")
    assert r.status_code == 200
    assert len(r.json()["items"]) <= 100


def test_writeup_detail_shape(client, session):
    w = session.execute(
        text("SELECT id FROM writeups WHERE canonical_url = "
             "'https://hackerone.com/reports/689314'")
    ).first()
    api_id = f"w_{w[0].hex}"
    r = client.get(f"/v1/writeups/{api_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == api_id
    assert body["canonical_url"] == "https://hackerone.com/reports/689314"
    assert body["author"]["name"] == "alice"
    assert body["source"]["id"] == "hackerone"
    assert body["vulnerability"]["classes"] == ["SSRF"]
    assert body["vulnerability"]["cwe_ids"] == ["CWE-918"]
    assert body["vulnerability"]["cve_ids"] == ["CVE-2022-22965"]
    assert body["vulnerability"]["severity"] == "critical"
    assert body["bounty"] == {
        "amount": 5000, "currency": "USD",
        "verified": True, "verified_against": "hackerone",
    }
    assert body["published_at"] == "2024-05-01T00:00:00+00:00"
    assert body["status"] == "active"
    assert body["skill_url"].endswith("/skill.md")
    assert body["markdown_url"].endswith(".md")
    assert isinstance(body["related_writeup_ids"], list)
    assert body["source_urls"][0]["url"] == "https://hackerone.com/reports/689314"


def test_writeup_detail_404_envelope(client):
    r = client.get(f"/v1/writeups/w_{'0' * 32}")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "NOT_FOUND"
    assert "request_id" in r.json()["error"]


def test_writeup_markdown(client, session):
    w = session.execute(
        text("SELECT id FROM writeups WHERE canonical_url = "
             "'https://hackerone.com/reports/689314'")
    ).first()
    r = client.get(f"/v1/writeups/w_{w[0].hex}.md")
    assert r.status_code == 200
    assert "text/markdown" in r.headers["content-type"]
    assert "SSRF via PDF parser in Spring Boot" in r.text
    assert "https://hackerone.com/reports/689314" in r.text


def test_writeup_skill_md_returns_skill(client, session):
    # Task 12 implemented get_skill_text; the route serves the real
    # skill now (the 501 placeholder from Task 10 is gone).
    w = session.execute(
        text("SELECT id FROM writeups WHERE canonical_url = "
             "'https://hackerone.com/reports/689314'")
    ).first()
    r = client.get(f"/v1/writeups/w_{w[0].hex}/skill.md")
    assert r.status_code == 200
    assert "text/markdown" in r.headers["content-type"]
    assert r.text.splitlines()[1].startswith("name: ssrf-")
    assert "authorization" in r.text.lower()
    assert "berlatih dengan aman" in r.text


def test_writeup_skill_md_retracted_is_gone(client, session):
    # Ruling R10: a retracted disclosure is removed from serving —
    # 410 Gone, never a skill and never a 500.
    w = session.execute(
        text("SELECT id FROM writeups WHERE canonical_url = "
             "'https://hackerone.com/reports/700002'")
    ).first()
    r = client.get(f"/v1/writeups/w_{w[0].hex}/skill.md")
    assert r.status_code == 410
    assert r.json()["error"]["code"] == "GONE"


def test_writeup_skill_md_secret_refusal_is_503_not_410(client, session):
    # A safety refusal is not a takedown: an active writeup whose
    # rendered skill trips the secret scan is 503, never 410 Gone.
    w = _writeup(
        session,
        url="https://example.com/reports/secret-skill",
        title="SSRF with token ghp_" + "A" * 36,
        excerpt="A parser fetches URLs.",
        author="alice",
    )
    session.commit()
    r = client.get(f"/v1/writeups/w_{w.id.hex}/skill.md")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "SECRET_FOUND"


# --- facets -----------------------------------------------------------------

def test_programs_facet(client):
    r = client.get("/v1/programs")
    names = {row["name"]: row["writeup_count"] for row in r.json()["items"]}
    assert names == {"Acme": 1, "Beta": 1}


def test_authors_facet(client):
    r = client.get("/v1/authors")
    names = {row["name"]: row["writeup_count"] for row in r.json()["items"]}
    assert names == {"alice": 1, "bob": 1, "dedi": 1}


def test_vuln_classes_facet(client):
    r = client.get("/v1/vuln-classes")
    classes = {row["vuln_class"]: row["writeup_count"]
               for row in r.json()["items"]}
    assert classes == {"SSRF": 2, "XSS": 1}


# --- status -----------------------------------------------------------------

def test_status_public_and_surfaces_blocked(client):
    r = client.get("/v1/status")
    assert r.status_code == 200
    body = r.json()
    by_id = {s["id"]: s for s in body["sources"]}
    assert by_id["hackerone"]["blocked"] is False
    assert by_id["hackerone"]["status"] == "ok"
    assert by_id["hackerone"]["lag_seconds"] is not None
    assert by_id["portswigger"]["blocked"] is True
    assert by_id["portswigger"]["status"] == "blocked"
    assert by_id["portswigger"]["blocked_reason"] == "plan_gated_403"
    assert body["writeups_total"] == 4
    assert body["writeups_active"] == 3


# --- submissions ------------------------------------------------------------

def test_submission_returns_in_review_and_id(client):
    r = client.post("/v1/submissions",
                    json={"url": "https://example.com/w",
                          "notes": "public writeup"})
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "in_review"
    assert body["submission_id"].startswith("sub_")


def test_submission_duplicate_url_returns_same_id(client):
    first = client.post("/v1/submissions",
                        json={"url": "https://example.com/dup"}).json()
    second = client.post("/v1/submissions",
                         json={"url": "https://example.com/dup"}).json()
    assert first["submission_id"] == second["submission_id"]
    assert second["status"] == "in_review"


def test_submission_validation(client):
    assert client.post("/v1/submissions", json={}).status_code == 400
    assert client.post("/v1/submissions",
                       json={"url": "not-a-url"}).status_code == 400
    assert client.post("/v1/submissions",
                       json={"url": "https://example.com/x",
                             "extra": "nope"}).status_code == 400


# --- openapi / envelope -----------------------------------------------------

def test_openapi_at_api_v1_path(client):
    r = client.get("/api/v1/openapi.json")
    assert r.status_code == 200
    body = r.json()
    assert body["openapi"].startswith("3.")
    assert "/v1/search" in body["paths"]
    assert "/v1/status" in body["paths"]


def test_unknown_route_envelope(client):
    r = client.get("/v1/nope")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "NOT_FOUND"


# --- auth unit --------------------------------------------------------------

def test_api_key_create_verify_revoke(session):
    plaintext, row = create_api_key(session, owner="agent-1", tier="free")
    assert plaintext.startswith("eun_")
    assert row.key_hash != plaintext
    session.commit()
    assert verify_api_key(session, plaintext) is not None
    assert verify_api_key(session, "eun_wrong") is None
    assert revoke_api_key(session, row.id) is True
    session.commit()
    assert verify_api_key(session, plaintext) is None


def test_rate_limiter_windows():
    limiter = RateLimiter(anon_per_minute=2, anon_per_day=3)
    assert limiter.check("anon:1.2.3.4", "anon").allowed is True
    assert limiter.check("anon:1.2.3.4", "anon").allowed is True
    result = limiter.check("anon:1.2.3.4", "anon")
    assert result.allowed is False
    assert result.retry_after is not None and result.retry_after > 0
