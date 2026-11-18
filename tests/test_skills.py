"""Task 12: SKILL.md generator (3 layers) + llms.txt (spec §5.11).

DB tests run against the dedicated ``eunoia_test`` database (same
fixture pattern as tests/test_search.py). Skills are generated on
demand from the current writeup row, so a ``content_hash`` change is
reflected on the next call — there is no stored skill to go stale.

Note on the brief's verbatim tests: they call ``get_skill_text("w_01k")``
with no session. This module's tests seed a real writeup in the test DB
and pass the test ``session`` explicitly (the established pattern in
this repo) so generation never touches the dev database; the assertions
are the brief's.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.dedup import url_hash
from eunoia.llms import render_llms_txt
from eunoia.models import Base, Writeup, WriteupVuln
from eunoia.skills import (
    get_registry_skill,
    get_skill_text,
    get_vuln_class_skill,
)

TEST_DATABASE_URL = "postgresql://eunoia@localhost:5432/eunoia_test"

NOW = datetime.now(timezone.utc)


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


def _writeup(session, *, title, excerpt=None, vuln_class=None, cwe=None,
             cve=None, external_id=None, program=None, severity=None,
             bounty_verified=False, days_ago=5, content_hash=None,
             status="active"):
    """Insert one writeup + its first vuln row; returns the Writeup."""
    url = f"https://example.com/reports/{uuid.uuid4().hex[:12]}"
    published = NOW - timedelta(days=days_ago)
    w = Writeup(
        canonical_url=url,
        url_hash=url_hash(url),
        external_id=external_id,
        title=title,
        excerpt=excerpt,
        language="en",
        status=status,
        published_at=published,
        disclosed_at=published,
        fetched_at=NOW,
        last_seen_at=NOW,
        content_hash=content_hash or url_hash(url),
    )
    session.add(w)
    session.flush()
    session.add(WriteupVuln(
        writeup_id=w.id,
        vuln_class=vuln_class,
        cwe_id=cwe,
        cve_id=cve,
        severity=severity,
        bounty_verified=bounty_verified,
        program=program,
    ))
    session.flush()
    return w


@pytest.fixture()
def ssrf_writeup(session):
    return _writeup(
        session,
        title="SSRF via PDF parser in Spring Boot",
        excerpt="A PDF parser fetched a user-supplied URL without validation.",
        vuln_class="SSRF",
        cwe="CWE-918",
        external_id="hackerone:689314",
        program="Acme",
        severity="critical",
        bounty_verified=True,
    )


# --- per-writeup skill (verbatim brief tests, adapted to the repo pattern) --


def test_skill_has_auth_warning_and_no_payload(session, ssrf_writeup):
    s = get_skill_text(ssrf_writeup.api_id, session=session)
    assert "authorization" in s.lower() and "berlatih dengan aman" in s
    assert "curl http" not in s and "password" not in s.lower()


def test_skill_name_is_deterministic(session, ssrf_writeup):
    s = get_skill_text(ssrf_writeup.api_id, session=session)
    assert s.splitlines()[1].startswith("name: ssrf-")
    # Class slug + title slug (class prefix stripped) + platform suffix.
    assert s.splitlines()[1] == (
        "name: ssrf-via-pdf-parser-in-spring-boot-h1-689314"
    )


def test_skill_name_is_stable_across_calls(session, ssrf_writeup):
    a = get_skill_text(ssrf_writeup.api_id, session=session)
    b = get_skill_text(ssrf_writeup.api_id, session=session)
    assert a == b


def test_skill_body_under_500_lines(session, ssrf_writeup):
    s = get_skill_text(ssrf_writeup.api_id, session=session)
    assert len(s.splitlines()) < 500
    assert len(s) // 4 < 5000  # rough token estimate, spec cap is 5000


def test_skill_references_are_links_only(session, ssrf_writeup):
    s = get_skill_text(ssrf_writeup.api_id, session=session)
    # The canonical URL appears exactly once, in the References section.
    assert s.count("https://example.com/reports/") == 1
    assert "CWE-918" in s
    # No target URL outside References: no step-by-step live execution.
    assert "http://" not in s


def test_skill_regenerates_when_writeup_changes(session, ssrf_writeup):
    before = get_skill_text(ssrf_writeup.api_id, session=session)
    ssrf_writeup.title = "SSRF via image proxy in Spring Boot"
    ssrf_writeup.content_hash = url_hash("changed")
    session.flush()
    after = get_skill_text(ssrf_writeup.api_id, session=session)
    assert after != before
    assert after.splitlines()[1].startswith("name: ssrf-via-image-proxy-")


def test_skill_unknown_writeup_raises(session):
    with pytest.raises(ValueError):
        get_skill_text("w_00000000000000000000000000000000", session=session)


@pytest.mark.parametrize("status", ["retracted", "takedown"])
def test_skill_retracted_or_takedown_writeup_raises(session, status):
    # Ruling R10: a retracted or taken-down disclosure is removed from
    # serving and kept only as a stub — no skill is generated for it.
    w = _writeup(
        session,
        title="RCE in old plugin",
        vuln_class="RCE",
        cwe="CWE-94",
        status=status,
    )
    with pytest.raises(ValueError):
        get_skill_text(w.api_id, session=session)


def test_skill_updated_writeup_still_serves(session):
    w = _writeup(
        session,
        title="SSRF via PDF parser in Spring Boot",
        vuln_class="SSRF",
        cwe="CWE-918",
        external_id="hackerone:689314",
        status="updated",
    )
    s = get_skill_text(w.api_id, session=session)
    assert s.splitlines()[1].startswith("name: ssrf-")


def test_skill_name_falls_back_without_external_id(session):
    w = _writeup(
        session,
        title="XSS in comment field",
        vuln_class="XSS",
        cwe="CWE-79",
    )
    s = get_skill_text(w.api_id, session=session)
    assert s.splitlines()[1].startswith("name: xss-in-comment-field-w-")
    assert len(s.splitlines()[1]) <= len("name: ") + 64


def test_skill_name_truncated_to_64_chars(session):
    w = _writeup(
        session,
        title="Remote code execution via unsafe deserialization of "
              "untrusted Java objects in a very long legacy endpoint",
        vuln_class="Deserialization",
        cwe="CWE-502",
        external_id="hackerone:123456",
    )
    name = get_skill_text(w.api_id, session=session).splitlines()[1]
    assert len(name) - len("name: ") <= 64


def test_skill_without_vuln_class_is_unclassified(session):
    w = _writeup(session, title="Odd finding in login flow")
    s = get_skill_text(w.api_id, session=session)
    assert s.splitlines()[1].startswith("name: unclassified-")


# --- registry skill ---------------------------------------------------------


def test_registry_skill_covers_rest_mcp_and_lookups():
    s = get_registry_skill()
    assert s.splitlines()[1] == "name: writeup-registry"
    assert "authorization" in s.lower()
    assert "Lookup #1" in s and "Lookup #2" in s
    assert "limit" in s.lower() and "5" in s
    assert "berlatih dengan aman" in s
    assert len(s.splitlines()) < 500


# --- vuln-class skill -------------------------------------------------------


def test_vuln_class_skill_aggregates_verified_writeups(session, ssrf_writeup):
    _writeup(
        session,
        title="SSRF in webhook URL validation",
        vuln_class="SSRF",
        cwe="CWE-918",
        external_id="hackerone:700001",
        program="Beta",
        bounty_verified=False,
        days_ago=2,
    )
    s = get_vuln_class_skill("SSRF", session=session)
    assert s.splitlines()[1] == "name: ssrf-fundamentals"
    assert "SSRF via PDF parser in Spring Boot" in s
    assert "SSRF in webhook URL validation" in s
    assert "authorization" in s.lower()
    assert "berlatih dengan aman" in s


def test_vuln_class_skill_empty_class_raises(session):
    with pytest.raises(ValueError):
        get_vuln_class_skill("SSRF", session=session)


# --- llms.txt ---------------------------------------------------------------


def test_llms_txt_structure_and_no_full_file(session, ssrf_writeup):
    s = render_llms_txt(session=session)
    assert s.startswith("# Eunoia")
    lines = s.splitlines()
    h2s = [ln for ln in lines if ln.startswith("## ")]
    assert h2s == [
        "## API",
        "## Browse",
        "## Top writeups",
        "## Policies",
        "## Optional",
    ]
    assert "llms-full" not in s
    assert "SSRF via PDF parser in Spring Boot" in s
    # One-line summary carries scope + safety.
    assert "authorization" in lines[2].lower()


def test_llms_txt_empty_registry_still_valid(session):
    s = render_llms_txt(session=session)
    assert s.startswith("# Eunoia")
    assert "## Top writeups" in s
    assert "No writeups indexed yet." in s
