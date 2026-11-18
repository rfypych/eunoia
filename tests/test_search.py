"""Task 9: hybrid search + ranking formula (§5.9).

DB tests run against the dedicated ``eunoia_test`` database (same
fixture pattern as tests/test_wiring.py). The embedding model is a
keyword stub encoder — no test downloads weights, and cosine
similarity is deterministic term overlap.

Note on the brief's verbatim tests: they call ``search({...})`` with
no session. This module's tests pass the test ``session`` and the stub
``model`` explicitly (the established pattern in this repo) so search
never touches the dev database; the assertions are the brief's.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.dedup import url_hash
from eunoia.embed import embed_writeup
from eunoia.models import Base, CveCache, Writeup, WriteupVuln
from eunoia.search import search

TEST_DATABASE_URL = "postgresql://eunoia@localhost:5432/eunoia_test"

NOW = datetime.now(timezone.utc)

# Vocabulary for the deterministic stub encoder: cosine similarity is
# term overlap over these words, so a query about "SSRF via PDF parser"
# is near the SSRF writeup and far from the WordPress RCE writeup.
_VOCAB = [
    "ssrf", "pdf", "parser", "spring", "boot", "tomcat", "log4j",
    "wordpress", "rce", "xss", "sqli", "deserialization", "java",
    "plugin", "remote", "code", "execution", "injection", "bypass",
    "auth", "framework", "server", "library",
]


class KeywordEncoder:
    """Deterministic 384-dim encoder; records every call."""

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
def encoder():
    return KeywordEncoder()


def _writeup(session, *, title, excerpt, program, vuln_class, cwe, cve=None,
             severity=None, bounty_verified=False, bounty_amount=None,
             language="en", status="active", days_ago=5):
    """Insert one writeup + its first vuln row; returns the Writeup."""
    url = f"https://example.com/reports/{uuid.uuid4().hex[:12]}"
    published = NOW - timedelta(days=days_ago)
    w = Writeup(
        canonical_url=url,
        url_hash=url_hash(url),
        title=title,
        excerpt=excerpt,
        language=language,
        status=status,
        published_at=published,
        disclosed_at=published,
        fetched_at=NOW,
        last_seen_at=NOW,
    )
    session.add(w)
    session.flush()
    session.add(WriteupVuln(
        writeup_id=w.id,
        vuln_class=vuln_class,
        cwe_id=cwe,
        cve_id=cve,
        cvss_score=9.8 if severity == "critical" else None,
        severity=severity,
        severity_source="hackerone" if severity else None,
        bounty_verified=bounty_verified,
        bounty_amount=bounty_amount,
        bounty_currency="USD" if bounty_amount else None,
        program=program,
    ))
    session.flush()
    return w


def _kev_row(session, cve_id, *, kev=True, epss=0.9):
    session.add(CveCache(
        cve_id=cve_id, kev=kev, epss=epss, epss_percentile=0.99,
        cvss_score=9.8, fetched_at=NOW, expires_at=NOW + timedelta(days=1),
    ))
    session.flush()


@pytest.fixture()
def corpus(session, encoder):
    """Seeded corpus: Spring SSRF (KEV), Spring XSS, old Tomcat RCE,
    WordPress RCE, a Spring IDOR with no embedding, a non-English Spring
    writeup, and a retracted Spring writeup."""
    spring_ssrf = _writeup(
        session, title="SSRF via PDF parser in Spring Boot 3.2.0",
        excerpt="SSRF via PDF parser in a Spring Boot application",
        program="Example Spring Boot app", vuln_class="SSRF", cwe="CWE-918",
        cve="CVE-2021-44228", severity="critical",
        bounty_verified=True, bounty_amount=5000,
    )
    _kev_row(session, "CVE-2021-44228")
    embed_writeup(spring_ssrf.id, session=session, model=encoder)

    spring_xss = _writeup(
        session, title="Stored XSS in Spring Framework views",
        excerpt="Stored XSS via unescaped model attributes in Spring MVC",
        program="Spring Framework demo", vuln_class="XSS", cwe="CWE-79",
        severity="high",
    )
    embed_writeup(spring_xss.id, session=session, model=encoder)

    tomcat_rce = _writeup(
        session, title="RCE in Apache Tomcat 10.1 request handling",
        excerpt="Remote code execution in Tomcat 10.1 via deserialization",
        program="Apache Tomcat", vuln_class="RCE", cwe="CWE-502",
        cve="CVE-2022-22965", severity="critical",
        bounty_verified=True, bounty_amount=1000, days_ago=400,
    )
    _kev_row(session, "CVE-2022-22965", kev=False, epss=0.05)
    embed_writeup(tomcat_rce.id, session=session, model=encoder)

    wordpress_rce = _writeup(
        session, title="WordPress plugin remote code execution",
        excerpt="Unauthenticated RCE in a WordPress plugin",
        program="WordPress", vuln_class="RCE", cwe="CWE-78",
        cve="CVE-2024-12345", severity="critical",
    )
    embed_writeup(wordpress_rce.id, session=session, model=encoder)

    spring_idor = _writeup(
        session, title="IDOR in Spring Boot user API",
        excerpt="Insecure direct object reference in Spring Boot endpoints",
        program="Example Spring Boot app", vuln_class="IDOR", cwe="CWE-639",
        severity="medium",
    )
    # Deliberately no embedding: must still be retrievable by keyword.

    _writeup(
        session, title="SSRF di Spring Boot lewat parser PDF",
        excerpt="SSRF melalui parser PDF pada aplikasi Spring Boot",
        program="Contoh Spring Boot", vuln_class="SSRF", cwe="CWE-918",
        severity="critical", language="id",
    )
    _writeup(
        session, title="SSRF in Spring Boot admin panel (retracted)",
        excerpt="Retracted report, must never be served",
        program="Example Spring Boot app", vuln_class="SSRF", cwe="CWE-918",
        severity="critical", status="retracted",
    )
    session.commit()
    return {
        "spring_ssrf": spring_ssrf,
        "spring_xss": spring_xss,
        "tomcat_rce": tomcat_rce,
        "wordpress_rce": wordpress_rce,
        "spring_idor": spring_idor,
    }


# --- brief verbatim tests --------------------------------------------------


def test_wordpress_cve_never_top5_for_spring_target(session, encoder, corpus):
    results = search({"tech": ["spring-boot"], "version": "3.2.0"},
                     limit=5, session=session, model=encoder)
    assert all("wordpress" not in r.title.lower() for r in results)


def test_result_carries_breakdown_and_reason(session, encoder, corpus):
    r = search({"tech": ["spring-boot"]}, limit=1,
               session=session, model=encoder)[0]
    assert r.score_breakdown["stack_match"] is not None and r.match_reason


def test_limit_clamped_to_10(session, encoder, corpus):
    for i in range(12):
        _writeup(
            session, title=f"Spring Boot SSRF variant {i}",
            excerpt="SSRF in Spring Boot endpoints",
            program="Example Spring Boot app", vuln_class="SSRF",
            cwe="CWE-918", severity="high",
        )
    session.commit()
    assert len(search({"tech": ["spring-boot"]}, limit=20,
                      session=session, model=encoder)) <= 10


# --- hard rules ------------------------------------------------------------


def test_pre_test_excludes_stack_zero_entirely(session, encoder, corpus):
    results = search({"tech": ["spring-boot"], "version": "3.2.0"},
                     session=session, model=encoder)
    titles = [r.title.lower() for r in results]
    assert not any("wordpress" in t for t in titles)


def test_mid_test_allows_stack_zero(session, encoder, corpus):
    results = search(
        {"tech": ["spring-boot"], "mode": "mid_test",
         "evidence_pattern": "remote code execution wordpress plugin"},
        limit=10, session=session, model=encoder)
    titles = [r.title.lower() for r in results]
    assert any("wordpress" in t for t in titles)


def test_non_english_and_retracted_excluded(session, encoder, corpus):
    results = search({"tech": ["spring-boot"]}, limit=10,
                     session=session, model=encoder)
    titles = [r.title.lower() for r in results]
    assert not any("di spring boot lewat" in t for t in titles)
    assert not any("retracted" in t for t in titles)


def test_every_result_has_verified_label(session, encoder, corpus):
    results = search({"tech": ["spring-boot"]}, limit=10,
                     session=session, model=encoder)
    assert results
    for r in results:
        assert r.verified_label in (
            "platform-verified", "author-claimed, unverified", "unverified")
        assert isinstance(r.verified, bool)


def test_kev_writeup_breakdown_exploited_is_one(session, encoder, corpus):
    results = search({"tech": ["spring-boot"], "version": "3.2.0"},
                     session=session, model=encoder)
    ssrf = next(r for r in results if "PDF parser" in r.title)
    assert ssrf.score_breakdown["exploited"] == 1.0
    assert ssrf.verified is True
    assert ssrf.verified_label == "platform-verified"


def test_keyword_only_writeup_retrieved_without_embedding(session, encoder, corpus):
    results = search({"tech": ["spring-boot"]}, limit=10,
                     session=session, model=encoder)
    titles = [r.title.lower() for r in results]
    assert any("idor" in t for t in titles)


def test_no_duplicate_writeups(session, encoder, corpus):
    session.add(WriteupVuln(
        writeup_id=corpus["spring_ssrf"].id, vuln_class="SSRF",
        cwe_id="CWE-918", cve_id="CVE-2021-44228", severity="critical",
        severity_source="hackerone", program="Example Spring Boot app",
    ))
    session.commit()
    results = search({"tech": ["spring-boot"]}, limit=10,
                     session=session, model=encoder)
    ids = [r.writeup_id for r in results]
    assert len(ids) == len(set(ids))


def test_empty_query_returns_no_results(session, encoder, corpus):
    assert search({}, session=session, model=encoder) == []


def test_mid_test_breakdown_has_technique_similarity(session, encoder, corpus):
    results = search(
        {"tech": ["spring-boot"], "mode": "mid_test",
         "evidence_pattern": "SSRF via PDF parser"},
        limit=5, session=session, model=encoder)
    assert results
    for r in results:
        assert "technique_similarity" in r.score_breakdown


def test_rerank_flag_raises_not_implemented(session, encoder, corpus):
    with pytest.raises(NotImplementedError):
        search({"tech": ["spring-boot"]}, session=session, model=encoder,
               rerank=True)


def test_old_tomcat_ranks_below_recent_spring(session, encoder, corpus):
    results = search({"tech": ["spring-boot", "tomcat"]}, limit=10,
                     session=session, model=encoder)
    titles = [r.title for r in results]
    assert titles.index("SSRF via PDF parser in Spring Boot 3.2.0") < \
        titles.index("RCE in Apache Tomcat 10.1 request handling")
