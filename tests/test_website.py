"""T6 (Rea-standard): website / demo live at the API root.

The root ``GET /`` must return an HTML page (200, no login) with a
search box that calls the live ``/v1/search`` endpoint, an example
search on load, and links to the API docs, ``llms.txt``, MCP, and
GitHub. The page must be honest: it shows the live corpus size from
``/v1/status`` instead of a hardcoded number, and it says the PyPI
package is not published yet instead of presenting an install
command that cannot work.

DB tests run against the dedicated ``eunoia_test`` database (same
fixture pattern as tests/test_api.py). The embedding model is a
keyword stub encoder — no test downloads weights.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.api.rest import create_app
from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.dedup import url_hash
from eunoia.embed import embed_writeup
from eunoia.models import Base, Source, Writeup, WriteupSource, WriteupVuln

TEST_DATABASE_URL = "postgresql+psycopg://eunoia@localhost:5432/eunoia_test"

NOW = datetime.now(timezone.utc)

_VOCAB = [
    "ssrf", "pdf", "parser", "spring", "boot", "tomcat", "log4j",
    "wordpress", "rce", "xss", "sqli", "deserialization", "java",
    "plugin", "remote", "code", "execution", "injection", "bypass",
    "auth", "framework", "server", "library",
]


class KeywordEncoder:
    """Deterministic 384-dim encoder (same as tests/test_api.py)."""

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
             source_type="hackerone_report", quality_passed=None):
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
        quality_passed=quality_passed,
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
        w1 = _writeup(
            s, url="https://hackerone.com/reports/689314",
            title="SSRF via PDF parser in Spring Boot",
            excerpt="A PDF parser fetches attacker-controlled URLs.",
            author="alice", published=datetime(2024, 5, 1, tzinfo=timezone.utc),
        )
        w1.external_id = "hackerone:689314"
        _vuln(s, w1, vuln_class="SSRF", cwe_id="CWE-918",
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
              severity="medium", severity_source="hackerone")
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


def test_root_returns_html_200_without_login(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Eunoia" in r.text
    assert "<form" in r.text or 'id="search"' in r.text


def test_root_search_box_calls_live_search_endpoint(client):
    body = client.get("/").text
    assert "/v1/search" in body, "page must call the live /v1/search endpoint"
    assert "fetch(" in body, "page must fetch results from the API"
    # An example search runs on load, so a first-time visitor sees
    # real results instead of an empty box.
    assert "CSRF" in body


def test_root_search_parity_with_api(client):
    api = client.get("/v1/search?q=ssrf")
    assert api.status_code == 200
    titles = [row["title"] for row in api.json()["results"]]
    assert "SSRF via PDF parser in Spring Boot" in titles
    # The page queries the same endpoint the test above just used,
    # so the results it shows are the API's results, not a copy.
    assert "/v1/search" in client.get("/").text


def test_root_links_are_live_endpoints(client):
    body = client.get("/").text
    for href in (
        "/v1/status",
        "/v1/writeups",
        "/llms.txt",
        "/api/v1/openapi.json",
        "http://129.150.57.82:10005/mcp",
        "https://github.com/rfypych/eunoia",
    ):
        assert href in body, f"root page must link to {href}"


def test_root_shows_live_corpus_size_from_status(client):
    body = client.get("/").text
    assert "/v1/status" in body, (
        "corpus size must come from the live /v1/status, not a hardcoded number"
    )
    assert "500 writeups" not in body, "page must not claim 500 writeups"


def test_root_is_honest_about_scope_and_install(client):
    body = client.get("/").text
    lowered = body.lower()
    assert "hackerone" in lowered
    assert "java/spring" in lowered
    assert "not on pypi yet" in lowered or "not published on pypi" in lowered, (
        "page must say the PyPI package is not published yet"
    )
    assert "placeholder" not in lowered
    assert "example.com" not in lowered
    assert "lorem" not in lowered


def test_root_results_are_escaped_not_inner_html(client):
    body = client.get("/").text
    # Titles come from public writeups and are untrusted input; the
    # page must render them as text, never as raw HTML.
    assert "textContent" in body
    assert "innerHTML = " not in body and "innerHTML=" not in body
